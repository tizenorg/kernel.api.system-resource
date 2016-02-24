/*
 * resourced
 *
 * Copyright (c) 2014 - 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file datausage.c
 *
 * @desc Datausage module
 *
 */

#include "config.h"
#include "const.h"
#include "counter-process.h"
#include "counter.h"
#include "cgroup.h"
#include "datausage-restriction.h"
#include "db-guard.h"
#include "generic-netlink.h"
#include "net-cls-cgroup.h"
#include "nl-helper.h"
#include "notifier.h"
#include "notification.h" /* for sending datausage dbus notification */
#include "datausage-common.h"
#include "datausage-quota.h"
#include "datausage-quota-processing.h"
#include "datausage-vconf-callbacks.h"
#include "iface-cb.h"
#include "macro.h"
#include "module-data.h"
#include "module.h"
#include "nfacct-rule.h"
#include "resourced.h"
#include "restriction-handler.h"
#include "telephony.h"
#include "tethering-restriction.h"
#include "storage.h"
#include "trace.h"
#include "proc-common.h"

#include <linux/rtnetlink.h>
#include <glib.h>
#include <inttypes.h>
#include <Ecore.h>

#ifdef CONFIG_DATAUSAGE_NFACCT


struct make_rule_context {
	struct counter_arg *carg;
	struct nfacct_rule *counter;
};

struct nfacct_key {
	u_int32_t classid;
	resourced_iface_type iftype;
	nfacct_rule_direction iotype;
	char ifname[MAX_IFACE_LENGTH];
	nfacct_rule_intend intend;
};

enum nfacct_state {
	NFACCT_STATE_ACTIVE,	/* kernel counter is applied */
	NFACCT_STATE_DEACTIVATED, /* kernel counter was removed, but this counter
		is still active, and it will be required for network interface,
		when it will be activated */
	NFACCT_STATE_DEL_DELAYED, /* kernel counters is going to be removed */
};

typedef enum {
	NFACCT_FINAL_UNKNOWN,
	NFACCT_FINAL_REMOVE = 1 << 0,
} nfacct_finalization;

struct nfacct_value {
	pid_t pid;
	enum nfacct_state state; /* used for distinguish incomplete counters,
				    when network interface not yet activated,
				    also for delayed counter deletion,
				    last is not good idea, I hope, to
				    rework it when it will be only one
				    iptable-restore call instead of
				    several*/
	resourced_ret_c(*iptables_rule)(struct nfacct_rule *counter);
	nfacct_finalization fini;
	/* restriction part */
	u_int64_t quota;
	int quota_id;
	resourced_roaming_type roaming;
	resourced_restriction_state rst_state;
	/* end restriction part */
	resourced_state_t ground; /* background/foreground state */
};

static struct nfacct_value *lookup_counter(struct nfacct_rule *counter);
static void handle_change_allowance(resourced_iface_type iftype, bool enabled);
static gboolean deactivate_each_counter_by_iftype(gpointer key, gpointer value, gpointer data);

static nfacct_rule_jump get_jump_by_intend(struct nfacct_rule *counter)
{
	if (counter->intend == NFACCT_WARN)
		return NFACCT_JUMP_ACCEPT;
	else if (counter->intend == NFACCT_BLOCK)
		return NFACCT_JUMP_REJECT;

	return NFACCT_JUMP_UNKNOWN;
}

static resourced_ret_c add_iptables_in(struct nfacct_rule *counter)
{
	return produce_net_rule(counter, 0, 0,
		NFACCT_ACTION_INSERT, get_jump_by_intend(counter),
		NFACCT_COUNTER_IN);
}

static resourced_ret_c add_iptables_out(struct nfacct_rule *counter)
{
	return produce_net_rule(counter, 0, 0,
		NFACCT_ACTION_INSERT, get_jump_by_intend(counter),
		NFACCT_COUNTER_OUT);
}

static resourced_ret_c del_iptables_in(struct nfacct_rule *counter)
{
	return produce_net_rule(counter, 0, 0,
		NFACCT_ACTION_DELETE, get_jump_by_intend(counter),
		NFACCT_COUNTER_IN);
}

static resourced_ret_c del_iptables_out(struct nfacct_rule *counter)
{
	return produce_net_rule(counter, 0, 0,
		NFACCT_ACTION_DELETE, get_jump_by_intend(counter),
		NFACCT_COUNTER_OUT);
}

#endif /* CONFIG_DATAUSAGE_NFACCT */

static int app_launch_cb(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	resourced_ret_c ret;
	ret_value_msg_if(p_data == NULL, RESOURCED_ERROR_FAIL,
		"Please provide valid argument!");
	ret = join_net_cls(p_data->appid, p_data->pid);
	if (ret != RESOURCED_ERROR_NONE)
		_D("Failed to start network counting.");
	return ret;
}

static gboolean bg_restriction(gpointer key, gpointer value,
        gpointer data)
{
	bool *bg_restriction = (bool *)data;

	struct nfacct_key *nf_key = (struct nfacct_key *)key;
	struct nfacct_value *nf_value = (struct nfacct_value *)value;

	if (nf_value->rst_state == RESOURCED_RESTRICTION_ACTIVATED &&
	    nf_key->classid == RESOURCED_BACKGROUND_APP_CLASSID) {
		*bg_restriction = true;
		return TRUE;
	}
	return FALSE;
}

bool check_bg_restriction_applied(struct counter_arg *carg)
{
	bool restriction = false;
	g_tree_foreach(carg->nf_cntrs, bg_restriction, &restriction);
	return restriction;
}

static bool check_background_applied(void)
{
	struct shared_modules_data *m_data;
	struct counter_arg *carg;

	m_data = get_shared_modules_data();
	ret_value_msg_if(m_data == NULL, RESOURCED_ERROR_FAIL,
		"Can't get module data!");

	carg = m_data->carg;
	ret_value_msg_if(carg == NULL, RESOURCED_ERROR_FAIL,
		"Cant' get counter arg!");

	return get_background_quota() || check_bg_restriction_applied(carg);
}

#ifdef CONFIG_DATAUSAGE_NFACCT

static int app_launch_srv_cb(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	resourced_ret_c ret;
	bool background_quota;
	ret_value_msg_if(p_data == NULL, RESOURCED_ERROR_FAIL,
		"Please provide valid argument!");
	ret = join_net_cls(p_data->appid, p_data->pid);
	if (ret != RESOURCED_ERROR_NONE)
		_D("Failed to start network counting.");
	mark_background(p_data->appid);

	background_quota = check_background_applied();
	if (background_quota)
		ret = place_pids_to_net_cgroup(p_data->pid, p_data->appid);

	return ret;
}

static int remove_each_counter(
	gpointer key,
	gpointer value,
	gpointer data)
{
	struct nfacct_rule *counter = (struct nfacct_rule *)data;
	resourced_iface_type iftype = (resourced_iface_type)key;
	char *ifname = (char *)value;
	struct nfacct_value *nf_value;

	if (iftype == RESOURCED_IFACE_UNKNOWN)
		return FALSE;

	counter->iftype = iftype;
	STRING_SAVE_COPY(counter->ifname, ifname);

	nf_value = lookup_counter(counter);

	ret_value_msg_if (!nf_value, FALSE, "Can't remove counter, due it's not in tree");
	SET_BIT(nf_value->fini, NFACCT_FINAL_REMOVE);

	/* move it into _answer_func_cb */
	generate_counter_name(counter);
	/**
	 * request update will be send in produce_net_rule,
	 * just by sending one get request, per name
	 */
	counter->iptables_rule(counter);
	return FALSE;
}

static void remove_nfacct_counters_for_all_iface(u_int32_t classid, struct counter_arg *carg)
{
	struct nfacct_rule counter = {
		.classid = classid,
		.iotype = NFACCT_COUNTER_IN,
		.iptables_rule = del_iptables_in,
		.carg = carg,
		.ifname = {0},
		0,
		/* .name until we don't have iftype,
		*	we couldn't get name */
	};

	/* remove for ingress counter */
	for_each_ifnames((ifnames_iterator)remove_each_counter, NULL, &counter);
	/* remove for engress counter */
	counter.iotype = NFACCT_COUNTER_OUT;
	counter.iptables_rule = del_iptables_out;
	for_each_ifnames((ifnames_iterator)remove_each_counter, NULL, &counter);
}

struct match_nftree_context
{
	u_int32_t classid;
	pid_t pid;
};

static gboolean match_pid(gpointer key,
	gpointer value,
	gpointer data)
{
	struct match_nftree_context *ctx = (struct match_nftree_context *)data;
	struct nfacct_value *nf_value = (struct nfacct_value *)value;
	struct nfacct_key *nf_key = (struct nfacct_key *)key;
	if (nf_value->pid == ctx->pid) {
		ctx->classid = nf_key->classid;
		return TRUE;
	}
	return FALSE;
}

static u_int32_t get_classid_by_pid(struct counter_arg *carg, const pid_t pid)
{
	struct match_nftree_context ctx = {
		.pid = pid,
		.classid = RESOURCED_UNKNOWN_CLASSID,
	};
	g_tree_foreach(carg->nf_cntrs, match_pid, &ctx);
	return ctx.classid;
}

struct mark_context {
	u_int32_t classid;
	resourced_state_t ground;
	int count;
	struct counter_arg *carg;
};

static gboolean mark_ground_by_classid(gpointer key, gpointer value,
		gpointer data)
{
	struct nfacct_key *nf_key = (struct nfacct_key *)key;
	struct nfacct_value *nf_value = (struct nfacct_value *)value;
	struct nfacct_rule rule = {.ifname = {0}, 0};
	struct mark_context *ctx = (struct mark_context *)data;
	if (nf_key->classid != ctx->classid)
		return FALSE;

	if (nf_value->ground != ctx->ground) {
		strncpy(rule.ifname, nf_key->ifname, sizeof(rule.ifname)-1);
		rule.ifname[sizeof(rule.ifname)-1] = 0;
		rule.classid = nf_key->classid;
		rule.iotype = nf_key->iotype;
		rule.intend = nf_key->intend;
		rule.carg = ctx->carg;
		generate_counter_name(&rule);
		nf_value->iptables_rule = 0;
		nfacct_send_get(&rule);
		nf_value->ground = ctx->ground;
	}

	if (nf_value->state != NFACCT_STATE_DEACTIVATED)
		++ctx->count;
	return FALSE;
}

static int mark_ground_state(struct counter_arg *carg, u_int32_t classid,
			      resourced_state_t ground)
{
	struct mark_context ctx = {
		.classid = classid,
		.ground = ground,
		.count = 0,
		.carg = carg};
	/* find classid in tree */
	g_tree_foreach(carg->nf_cntrs, mark_ground_by_classid, &ctx);
	return ctx.count;
}

void mark_background(const char *app_id)
{
	struct shared_modules_data *m_data;
	struct counter_arg *carg;
	int nfacct_number = 0;

	u_int32_t classid = get_classid_by_app_id(app_id, false);
	ret_msg_if(classid == RESOURCED_UNKNOWN_CLASSID,
			"Unknown classid!");
	m_data = get_shared_modules_data();
	ret_msg_if(m_data == NULL, "Can't get module data!");

	carg = m_data->carg;
	ret_msg_if(carg == NULL, "Cant' get counter arg!");

	nfacct_number = mark_ground_state(carg, classid,
			RESOURCED_STATE_BACKGROUND);
	if (!nfacct_number)
		_D("There is no entry for %s in counter tree", app_id);
}

static gboolean move_proc_background_cgroup(gpointer key, gpointer value,
		gpointer data)
{
	struct nfacct_value *nf_value = (struct nfacct_value *)value;
	struct nfacct_key *nf_key = (struct nfacct_key *)key;
	resourced_state_t state = (resourced_state_t )data;

	if (nf_value->ground != RESOURCED_STATE_BACKGROUND ||
	    nf_key->classid == RESOURCED_ALL_APP_CLASSID ||
	    nf_key->intend != NFACCT_COUNTER)
		return FALSE;

	/* move into background cgroup */
	if (state == RESOURCED_STATE_BACKGROUND)
		place_pids_to_net_cgroup(nf_value->pid, RESOURCED_BACKGROUND_APP_NAME);
	else {
		char *app_id = get_app_id_by_classid(nf_key->classid, false);
		if (app_id)
			place_pids_to_net_cgroup(nf_value->pid, app_id);
	}
	return FALSE;
}

void foreground_apps(struct counter_arg *carg)
{
	g_tree_foreach(carg->nf_cntrs, move_proc_background_cgroup, (void *)RESOURCED_STATE_FOREGROUND);
}

void background_apps(struct counter_arg *carg)
{
	g_tree_foreach(carg->nf_cntrs, move_proc_background_cgroup, (void *)RESOURCED_STATE_BACKGROUND);
}

static int app_resume_cb(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	struct shared_modules_data *m_data;
	struct counter_arg *carg;
	u_int32_t classid;
	resourced_ret_c ret = RESOURCED_ERROR_NONE;
	int nfacct_number = 0;
	bool background_quota = false;

	ret_value_msg_if(p_data == NULL, RESOURCED_ERROR_FAIL,
		"Please provide valid argument!");

	m_data = get_shared_modules_data();
	ret_value_msg_if(m_data == NULL, RESOURCED_ERROR_FAIL,
		"Can't get module data!");

	carg = m_data->carg;
	ret_value_msg_if(carg == NULL, RESOURCED_ERROR_FAIL,
		"Cant' get counter arg!");
	classid = get_classid_by_pid(carg, p_data->pid);
	ret_value_msg_if(classid == RESOURCED_UNKNOWN_CLASSID,
		RESOURCED_ERROR_FAIL, "No classid to terminate!");

	/* find in tree nf_cntr and mark it as background */

	nfacct_number = mark_ground_state(carg, classid,
			RESOURCED_STATE_FOREGROUND);
	background_quota = check_background_applied();
	if (!nfacct_number) {
		ret = join_net_cls(p_data->appid, p_data->pid);
		if (ret != RESOURCED_ERROR_NONE)
			_D("Failed to start network counting.");

	} else if(background_quota)
		place_pids_to_net_cgroup(p_data->pid, p_data->appid);

	return ret;
}

static int app_terminated_cb(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	struct shared_modules_data *m_data;
	struct counter_arg *carg;
	u_int32_t classid;
	ret_value_msg_if(p_data == NULL, RESOURCED_ERROR_FAIL,
		"Please provide valid argument!");

	m_data = get_shared_modules_data();
	ret_value_msg_if(m_data == NULL, RESOURCED_ERROR_FAIL,
		"Can't get module data!");

	carg = m_data->carg;
	ret_value_msg_if(carg == NULL, RESOURCED_ERROR_FAIL,
		"Cant' get counter arg!");
	classid = get_classid_by_pid(carg, p_data->pid);
	ret_value_msg_if(classid == RESOURCED_UNKNOWN_CLASSID,
		RESOURCED_ERROR_FAIL, "No classid to terminate!");

	remove_nfacct_counters_for_all_iface(classid, carg);
	return RESOURCED_ERROR_NONE;
}

resourced_state_t get_app_ground(struct nfacct_rule *counter)
{
	struct nfacct_value *nf_value = lookup_counter(counter);
	return nf_value ? nf_value->ground : RESOURCED_STATE_UNKNOWN;
}

static int app_backgrnd_cb(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	struct shared_modules_data *m_data;
	struct counter_arg *carg;
	u_int32_t classid;
	int nfacct_number = 0;
	bool background_quota = false;
	ret_value_msg_if(p_data == NULL, RESOURCED_ERROR_FAIL,
		"Please provide valid argument!");

	m_data = get_shared_modules_data();
	ret_value_msg_if(m_data == NULL, RESOURCED_ERROR_FAIL,
		"Can't get module data!");

	carg = m_data->carg;
	ret_value_msg_if(carg == NULL, RESOURCED_ERROR_FAIL,
		"Cant' get counter arg!");
	classid = get_classid_by_pid(carg, p_data->pid);
	ret_value_msg_if(classid == RESOURCED_UNKNOWN_CLASSID,
		RESOURCED_ERROR_FAIL, "No classid to terminate!");

	/* find in tree nf_cntr and mark it as background */

	nfacct_number = mark_ground_state(carg, classid,
			RESOURCED_STATE_BACKGROUND);
	if (nfacct_number) {
		background_quota = check_background_applied();
		/**
		 * if we have applied background quota, put current pid into
		 * background cgroup
		 */
		if (background_quota)
			place_pids_to_net_cgroup(p_data->pid, RESOURCED_BACKGROUND_APP_NAME);
	}

	if (!nfacct_number)
		_D("There wasn't any information about background application "\
		   "in nfacct counters tree");
	return RESOURCED_ERROR_NONE;
}


static gboolean populate_classid_tree(gpointer key,
	gpointer value,
	gpointer data)
{
	GTree *classid_tree = (GTree *)data;
	struct nfacct_key *nf_key = (struct nfacct_key *)key;
	struct nfacct_value *nf_value = (struct nfacct_value *)value;

	if (nf_value->state == NFACCT_STATE_ACTIVE)
		g_tree_insert(classid_tree, (const gpointer)nf_key->classid, NULL);
	return FALSE;
}

static gboolean remove_each_counter_by_classid(gpointer key,
	gpointer value,
	gpointer data)
{
	u_int32_t classid = (u_int32_t)key;
	struct counter_arg *carg = (struct counter_arg *)data;
	remove_nfacct_counters_for_all_iface(classid, carg);
	return FALSE;
}

static gint pointer_compare(gconstpointer a, gconstpointer b)
{
	return a - b;
}

static int add_one_tizen_os_counter(
	gpointer key,
	gpointer value,
	gpointer data)
{
	struct counter_arg *carg = (struct counter_arg *)data;
	struct nfacct_rule counter = {.name = {0}, .ifname = {0}, 0};
	resourced_iface_type iftype = (resourced_iface_type)key;
	char *ifname = (char *)value;

	if (iftype <= RESOURCED_IFACE_UNKNOWN ||
		iftype >= RESOURCED_IFACE_LAST_ELEM)
		return FALSE;

	counter.iotype = NFACCT_COUNTER_IN;
	counter.iftype = iftype;
	counter.carg = carg;
	STRING_SAVE_COPY(counter.ifname, ifname);
	generate_counter_name(&counter);
	if (add_iptables_in(&counter) != RESOURCED_ERROR_NONE)
		_D("Failed to add counter %s", counter.name);

	counter.iotype = NFACCT_COUNTER_OUT;
	generate_counter_name(&counter);
	if (add_iptables_out(&counter) != RESOURCED_ERROR_NONE)
		_D("Failed to add counter %s", counter.name);

	return FALSE;
}

static void add_tizen_os_counters(struct counter_arg *carg) {

	for_each_ifnames((ifnames_iterator)add_one_tizen_os_counter, NULL, carg);
}

static void reload_all_nf_counters(struct counter_arg *carg)
{
	add_tizen_os_counters(carg);
	/**
	 * it can be done by following ways:
	 * 1. just by reading existing net_cls cgroups, looks not robust because
	 *	in this case we are getting network interface type from runtime, and
	 *	it could be changed since the resourced was stopped. And it doesn't
	 *	reflect counter state
	 * 2. By reading from iptables rules. We don't have C code for retriving
	 *	it from kernel unless to use iptables cmd output, but it's not
	 *	 robust and not performance effective
	 * 3. Just by obtaining nfacct counters. We could do it without command
	 *	line tool. It reflects current counter state, but not,
	 *	 iptables rules
	 */
	carg->initiate = 1;
	nfacct_send_initiate(carg);
}

static void remove_whole_nf_counters(struct counter_arg *carg)
{
	GTree *classid_tree = g_tree_new(pointer_compare);; /* tree instead of array for avoiding
	duplication, manual sort and binary search in case of array */
	ret_msg_if(carg == NULL,
		"Cant' get counter arg!");

	/**
	 * fill classid list, due we couldn't iterate on tree and
	 * remove elements from it
	 */
	g_tree_foreach(carg->nf_cntrs, populate_classid_tree, classid_tree);
	g_tree_foreach(classid_tree, remove_each_counter_by_classid, carg);

	g_tree_destroy(carg->nf_cntrs);
	g_tree_destroy(classid_tree);
}

/**
 * TODO use following constant from kernel header
 * nfacct/include/linux/netfilter/nfnetlink.h
 */
#ifndef NFNLGRP_ACCT_QUOTA
#define NFNLGRP_ACCT_QUOTA 8
#endif
#ifndef SOL_NETLINK
#define SOL_NETLINK	270
#endif

static inline char *get_public_appid(const uint32_t classid)
{
	char *appid;

	/**
	 * following value for ALL is suitable for using in statistics
	 * what's why it's not in get_app_id_by_classid
	 */
	if (classid == RESOURCED_ALL_APP_CLASSID)
		return strdup(RESOURCED_ALL_APP);
	if (classid == RESOURCED_BACKGROUND_APP_CLASSID)
		return strdup(RESOURCED_BACKGROUND_APP_NAME);

	appid = get_app_id_by_classid(classid, true);
	return !appid ? strdup(UNKNOWN_APP) : appid;
}

static void init_nfacct(u_int32_t classid, pid_t pid,
	nfacct_rule_direction ctype, struct counter_arg *carg,
	struct nfacct_rule *counter)
{
	counter->iotype = ctype;
	counter->classid = classid;
	counter->carg = carg;
	counter->pid = pid;
	counter->intend = NFACCT_COUNTER;
	counter->quota = 0;
	counter->roaming = get_current_roaming();
	if (ctype == NFACCT_COUNTER_IN)
		counter->iptables_rule = add_iptables_in;
	else if (ctype == NFACCT_COUNTER_OUT)
		counter->iptables_rule = add_iptables_out;
}

static resourced_ret_c del_counter(struct nfacct_rule *counter)
{
	return produce_net_rule(counter, 0, 0,
		NFACCT_ACTION_DELETE, get_jump_by_intend(counter),
		counter->iotype);
}

static void fill_du_quota(const char *app_id, const char *ifname,
		const resourced_iface_type iftype, data_usage_quota *du_quota,
		int *quota_id, resourced_state_t ground)
{
	char *imsi_hash = get_imsi_hash(get_current_modem_imsi());
	resourced_roaming_type roaming = get_current_roaming();
	/* lookup in quota tree */
	resourced_ret_c ret = get_quota_by_appid(app_id, imsi_hash, iftype,
			roaming, du_quota, quota_id, ground);

	du_quota->roaming_type = roaming;
	_D("ret %d, quota id %d", ret, *quota_id);
	/**
	 * if lookup wasn't successfull, searchin restriction db,
	 * for example we could faced with restriction without quota
	 */
	if (ret != RESOURCED_ERROR_NONE || !*quota_id) {
		resourced_restriction_info rst_info = {0};
		resourced_ret_c ret;
		rst_info.ifname = ifname;
		/* TODO add roaming into restriction info request */
		ret = get_restriction_info(app_id, iftype, &rst_info);
		ret_msg_if(ret != RESOURCED_ERROR_NONE,
			"Failed to get restriction info!");

		get_quota_by_id(rst_info.quota_id, du_quota);
		du_quota->roaming_type = rst_info.roaming;
		*quota_id = rst_info.quota_id;
	}
	_D("quota rcv: % " PRId64 ", send: % " PRId64 " ", du_quota->rcv_quota,
			du_quota->snd_quota);
	_D("quota roaming: %d", du_quota->roaming_type);

}

static int fill_restriction(struct rtattr *attr_list[__NFACCT_MAX],
		void *user_data)
{
	struct counter_arg *carg = (struct counter_arg *)user_data;
	struct nfacct_rule counter = { .name = {0}, .ifname = {0}, 0, };
	char *cnt_name = (char *)RTA_DATA(
				attr_list[NFACCT_NAME]);

	/**
	 * because foreground/background property wasn't
	 * in counter
	 */
	resourced_state_t ground;
	char *app_id = 0;
	int quota_id = 0;
	int ret = 0;
	data_usage_quota du_quota = {0};

	init_nfacct(0, 0, 0, carg, &counter);
	strncpy(counter.name, cnt_name, sizeof(counter.name)-1);
	recreate_counter_by_name(cnt_name, &counter);

	ground = counter.classid == RESOURCED_BACKGROUND_APP_CLASSID ?
			RESOURCED_STATE_BACKGROUND : RESOURCED_STATE_FOREGROUND;
	app_id = get_public_appid(counter.classid);
	ret_value_msg_if(!app_id, RESOURCED_ERROR_NONE, "Unknown app_id for %d",
			counter.classid);
	fill_du_quota(app_id, counter.ifname, counter.iftype, &du_quota,
		      &quota_id, ground);

	if (counter.intend == NFACCT_BLOCK) {
		if (counter.iotype == NFACCT_COUNTER_IN) {
			struct nfacct_rule out_counter = counter;

			/* remove old ones, which were with notification */
			counter.iotype = NFACCT_COUNTER_IN | NFACCT_COUNTER_OUT;
			ret = del_counter(&counter);
			ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"Can't delete restriction%s", counter.name);

			out_counter.iotype = NFACCT_COUNTER_OUT;
			generate_counter_name(&out_counter);
			ret = add_iptables_out(&out_counter);
			ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"Can't create auxilary counter %s", out_counter.name);
			ret = apply_tethering_restriction(RST_SET);
			ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"Can't block tethering");
		}

		/**
		 * send restriction notification only in case of
		 * it was related to quota
		 */
		if (quota_id != NONE_QUOTA_ID)
			send_restriction_notification(app_id, &du_quota);
		else
			_D("No need to send restriction notification");
		update_restriction_db(app_id, counter.iftype, 0, 0,
				      RESOURCED_RESTRICTION_ACTIVATED,
				      quota_id, du_quota.roaming_type, counter.ifname);
	} else if (counter.intend == NFACCT_WARN) {
		if (quota_id != NONE_QUOTA_ID)
			send_restriction_warn_notification(app_id, &du_quota);
		/* remove both warnings */
		counter.iotype = NFACCT_COUNTER_IN | NFACCT_COUNTER_OUT;
		ret = del_counter(&counter);
		ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
			"Can't delete warning %s", counter.name);
	} else
		_E("Unkown restriction notification type");

	return 0;
}

/* notification section */
static Eina_Bool noti_func_cb(void *user_data, Ecore_Fd_Handler *fd_handler)
{
	struct counter_arg *carg = (struct counter_arg *)user_data;
	struct genl ans;
	struct netlink_serialization_params ser_param = {0};
	netlink_serialization_command *netlink_command = NULL;
	int ret;

	_D("nfacct notification");
	ret = read_netlink(carg->noti_fd, &ans, sizeof(struct genl));
	if (ret == 0)
		goto out;
	carg->ans_len = ret;
	ser_param.carg = carg;
	ser_param.ans = &ans;
	ser_param.eval_attr = fill_restriction;
	netlink_command = netlink_create_command(&ser_param);

	if (!netlink_command)
		goto out;

	netlink_command->deserialize_answer(&(netlink_command->params));

out:
	return ECORE_CALLBACK_RENEW;
}

static void init_notifier(struct counter_arg *carg)
{
	int ret = 0;
	int option = NFNLGRP_ACCT_QUOTA;
	struct sockaddr_nl addr;
	socklen_t addr_len = sizeof(struct sockaddr_nl);

	carg->noti_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	ret_msg_if(carg->noti_fd < 0, "Can't create socket");

	/* bind */
	memset(&addr, 0, sizeof(struct sockaddr_nl));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = 0;
	addr.nl_pid = 0;

	ret = bind(carg->noti_fd, (struct sockaddr *) &addr, addr_len);
	ret_msg_if(ret < 0, "Can't bind notification socket");

	ret = getsockname(carg->noti_fd, (struct sockaddr *)&addr, &addr_len);
	ret_msg_if(ret < 0, "Can't get sockname!");

	ret_msg_if(addr_len != sizeof(struct sockaddr_nl) ||
		addr.nl_family != AF_NETLINK,
		"getsockname bad argumetn");

	/* see sock opt */
	ret = setsockopt(carg->noti_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		&option, sizeof(int));
	ret_msg_if(carg->noti_fd < 0, "Can't set sock opt");

	/* register handler */
	carg->noti_fd_handler = ecore_main_fd_handler_add(
		carg->noti_fd, ECORE_FD_READ, noti_func_cb,
		carg, NULL, NULL);
	ret_msg_if(carg->noti_fd_handler == NULL,
			 "Failed to add noti callbacks\n");
}

static void fini_notifier(struct counter_arg *carg)
{
	shutdown(carg->noti_fd, SHUT_RDWR);
	ecore_main_fd_handler_del(carg->noti_fd_handler);
	close(carg->noti_fd);
}

/* end notification section */
#else
static int app_launch_srv_cb(void *data)
{
	return 0;
}

static int app_resume_cb(void *data)
{
	return 0;
}

static int app_terminate_cb(void *data)
{
	return 0;
}

iface_callback *create_counter_callback(void)
{
	return NULL;
}

#endif /* CONFIG_DATAUSAGE_NFACCT */

#define NET_RELEASE_AGENT "/usr/bin/net-cls-release"
#define NET_CLS_SUBSYS "net_cls"

static int resourced_datausage_init(void *data)
{
	struct net_counter_opts *net_opts = (struct net_counter_opts *)malloc(
						sizeof(struct net_counter_opts));
	struct shared_modules_data *m_data = NULL;

	ret_value_msg_if (net_opts == NULL, RESOURCED_ERROR_OUT_OF_MEMORY,
			  "Not enough memory");

	m_data = get_shared_modules_data();
	int ret_code;

	memset(net_opts, 0, sizeof(struct net_counter_opts));
	load_network_opts(net_opts);
	_D("Initialize network counter function\n");
	ret_value_msg_if(m_data == NULL, RESOURCED_ERROR_FAIL,
			 "Invalid shared modules data\n");

	set_release_agent(NET_CLS_SUBSYS, NET_RELEASE_AGENT);

	/* register notifier cb */
	register_notifier(RESOURCED_NOTIFIER_APP_LAUNCH, app_launch_cb);
	register_notifier(RESOURCED_NOTIFIER_APP_RESUME, app_resume_cb);
	register_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, app_launch_srv_cb);
	register_notifier(RESOURCED_NOTIFIER_APP_TERMINATED, app_terminated_cb);
	register_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, app_backgrnd_cb);
	m_data->carg = init_counter_arg(net_opts);
	ret_code = resourced_iface_init();
	ret_value_msg_if(ret_code < 0, ret_code, "resourced_iface_init failed");
	ret_code = resourced_init_counter_func(m_data->carg);
	ret_value_msg_if(ret_code < 0, ret_code, "Error init counter func\n");
	resourced_add_vconf_datausage_cb(m_data->carg);
	reactivate_restrictions();
	create_net_background_cgroup(m_data->carg);
	ret_code = resourced_init_db_guard(m_data->carg);
	ret_value_msg_if(ret_code < 0, ret_code, "Error init db guard\n");

#ifdef CONFIG_DATAUSAGE_NFACCT
	reload_all_nf_counters(m_data->carg);

	/* let's make a notification socket */
	init_notifier(m_data->carg);
	set_change_allow_cb(handle_change_allowance);
#endif
	return RESOURCED_ERROR_NONE;
}

static int resourced_datausage_finalize(void *data)
{
	struct shared_modules_data *m_data = get_shared_modules_data();

	_D("Finalize network counter function\n");
	resourced_remove_vconf_datausage_cb();
	ret_value_msg_if(m_data == NULL, RESOURCED_ERROR_FAIL,
			 "Invalid shared modules data\n");

#ifdef CONFIG_DATAUSAGE_NFACCT
	remove_whole_nf_counters(m_data->carg);
	fini_notifier(m_data->carg);
#endif
	resourced_finalize_counter_func(m_data->carg);
	free(m_data->carg->opts);/* allocation was in resourced_datausage_init */
	finalize_carg(m_data->carg);
	finalize_storage_stm();
	unregister_notifier(RESOURCED_NOTIFIER_APP_LAUNCH, app_launch_cb);
	unregister_notifier(RESOURCED_NOTIFIER_APP_RESUME, app_resume_cb);
	unregister_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, app_launch_srv_cb);
	unregister_notifier(RESOURCED_NOTIFIER_APP_TERMINATED, app_terminated_cb);
	unregister_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, app_backgrnd_cb);
	resourced_iface_finalize();
	finalize_iftypes();
	finilize_telephony();
	ecore_timer_del(m_data->carg->erase_timer);

	return RESOURCED_ERROR_NONE;
}

#ifdef CONFIG_DATAUSAGE_NFACCT

static int compare_nfcntr(gconstpointer a, gconstpointer b,
                     gpointer UNUSED user_data)
{
	struct nfacct_key *key_a = (struct nfacct_key *)a;
	struct nfacct_key *key_b = (struct nfacct_key *)b;
	int ret = key_a->classid - key_b->classid;

	if (ret)
		return ret;
	ret = key_a->iftype - key_b->iftype;
	if (ret)
		return ret;
	ret = key_a->iotype - key_b->iotype;
	if (ret)
		return ret;

	ret = key_a->intend - key_b->intend;
	if (ret)
		return ret;

	/**
	 * in case of incomplete counters ->ifname will contain
	 * empty string, if we found incomplete counter,
	 * assume it's the same as given ifname
	 */
	if (strlen(key_a->ifname) && strlen(key_b->ifname))
		return strcmp(key_a->ifname, key_b->ifname);

	return 0;
}

GTree *create_nfacct_tree(void)
{
	return g_tree_new_full(compare_nfcntr, NULL, free, free);
}

static struct nfacct_value *lookup_counter(struct nfacct_rule *counter)
{
	struct nfacct_key key = {
		.classid = counter->classid,
		.iftype = counter->iftype,
		.iotype = counter->iotype,
		.intend = counter->intend,
	};

	STRING_SAVE_COPY(key.ifname, counter->ifname);

	return (struct nfacct_value *)g_tree_lookup(counter->carg->nf_cntrs,
		&key);
}

/* Called only in case of successful kernel operation */
void keep_counter(struct nfacct_rule *counter)
{
	struct nfacct_key *key = NULL;
	struct nfacct_value *value = lookup_counter(counter);

	if (!value) {
		key = (struct nfacct_key *)malloc(sizeof(
			struct nfacct_key));
		ret_msg_if(key == NULL,
			"Can allocate memory for nfacct_key!");

		value = (struct nfacct_value *)malloc(sizeof(
			struct nfacct_value));

		if (value == NULL) {
			free(key);
			_D("Can allocate memory for nfacct_key!");
			return;
		}
		key->classid = counter->classid;
		key->iftype = counter->iftype;
		key->iotype = counter->iotype;
		key->intend = counter->intend;
		STRING_SAVE_COPY(key->ifname, counter->ifname);
		g_tree_insert(counter->carg->nf_cntrs, key, value);
	}

	value->pid =  counter->pid;
	value->state = NFACCT_STATE_ACTIVE;
	value->quota = counter->quota;
	value->iptables_rule = counter->iptables_rule;
	value->quota_id = counter->quota_id;
	value->rst_state = counter->rst_state;
	value->roaming = counter->roaming;
	value->fini = 0;
	value->ground = RESOURCED_STATE_FOREGROUND;

#ifdef DEBUG_ENABLED
	if (key && key->intend == NFACCT_BLOCK)
		_D("%p rst_state: %d", value, value->rst_state);
#endif
}

void finalize_counter(struct nfacct_rule *counter)
{
	resourced_ret_c ret;
	struct nfacct_key nf_key = {
		.classid = counter->classid,
		.iftype = counter->iftype,
		.iotype = counter->iotype,
		.intend = counter->intend,
	};
	struct nfacct_value *value;

	STRING_SAVE_COPY(nf_key.ifname, counter->ifname);
	value = (struct nfacct_value *)g_tree_lookup(counter->carg->nf_cntrs,
		&nf_key);

#ifdef DEBUG_ENABLED
	_D("counter name: %s", counter->name);
	_D("counter classid: %d", counter->classid);
	_D("counter iftype: %d", counter->iftype);
	_D("counter iotype: %d", counter->iotype);
	_D("counter ifname: %s", counter->ifname);
#endif /* DEBUG_ENABLED */

	ret_msg_if(!value, "Can't find counter", counter->name);
	if (!CHECK_BIT(value->fini, NFACCT_FINAL_REMOVE)) {
#ifdef DEBUG_ENABLED
		_D("No need to remove value %p", value);
#endif
		return;
	}
#ifdef DEBUG_ENABLED
	else {
		_D("remove value %p", value);
	}
#endif
	ret_msg_if(!value->iptables_rule, "There is no iptables_rule handler");

	ret = value->iptables_rule(counter);
	ret_msg_if (ret != RESOURCED_ERROR_NONE, "Failed to execute iptables rule");
	UNSET_BIT(value->fini, NFACCT_FINAL_REMOVE);
	value->state = NFACCT_STATE_DEACTIVATED;
#ifdef DEBUG_ENABLED
	if (nf_key.intend == NFACCT_BLOCK)
		_D("%p rst_state: %d", value, value->rst_state);
#endif
}

void set_finalize_flag(struct nfacct_rule *counter)
{
	struct nfacct_key nf_key = {
		.classid = counter->classid,
		.iftype = counter->iftype,
		.iotype = counter->iotype,
		.intend = counter->intend,
	};
	struct nfacct_value *value;

	STRING_SAVE_COPY(nf_key.ifname, counter->ifname);
	value = lookup_counter(counter);
	ret_msg_if(!value, "Can't find counter for set finalize state!");
	SET_BIT(value->fini, NFACCT_FINAL_REMOVE);
	value->iptables_rule = nfacct_send_del;
	value->rst_state = counter->rst_state;
#ifdef DEBUG_ENABLED
	if (nf_key.intend == NFACCT_BLOCK)
		_D("%p rst_state: %d", value, value->rst_state);
#endif
	if (counter->carg && counter->carg->opts)
		SET_BIT(counter->carg->opts->state, RESOURCED_FORCIBLY_FLUSH_STATE);
}

static gboolean fill_restriction_list(gpointer key, gpointer value,
		gpointer data)
{
	GSList **rst_list = (GSList **)data;
	GSList *iter = NULL;
	resourced_restriction_info *info = NULL;

	struct nfacct_key *nf_key = (struct nfacct_key *)key;
	struct nfacct_value *nf_value = (struct nfacct_value *)value;
	char *app_id;

	/* only restriction guard is needed here */
	if (nf_key->intend != NFACCT_BLOCK)
		return FALSE;

	app_id = get_public_appid(nf_key->classid);
	ret_value_msg_if(!app_id, FALSE, "Can't get appid");

	gslist_for_each_item(iter, *rst_list) {
		resourced_restriction_info *look_info = (resourced_restriction_info *)iter->data;
		if (look_info->app_id && !strcmp(look_info->app_id, app_id) &&
		    look_info->iftype == nf_key->iftype &&
		    look_info->quota_id == nf_value->quota_id &&
		    look_info->roaming == nf_value->roaming) {
			info = look_info;
			break;
		}
	}

	if (!info) {
		_D("We didn't find this restriction in list! Create new one!");
		info = (resourced_restriction_info *)malloc(sizeof(resourced_restriction_info));
		ret_value_msg_if (!info, FALSE, "Can't allocate memory");
		memset(info, 0, sizeof(resourced_restriction_info));
		*rst_list = g_slist_prepend(*rst_list, info);
	}

#ifdef DEBUG_ENABLED
	if (nf_key->intend == NFACCT_BLOCK)
		_D("%p rst_state: %d", nf_value, nf_value->rst_state);
#endif

	if (info->iftype == RESOURCED_IFACE_UNKNOWN)
		info->iftype = nf_key->iftype;
	if (info->quota_id == NONE_QUOTA_ID)
		info->quota_id = nf_value->quota_id;
	if (info->roaming == RESOURCED_ROAMING_UNKNOWN)
		info->roaming = nf_value->roaming;
	if (!info->ifname)
		info->ifname = strdup(nf_key->ifname);
	if (!info->app_id)
		info->app_id = app_id;
	if (!info->rst_state)
		info->rst_state = nf_value->rst_state == RESOURCED_RESTRICTION_REMOVED ? RESOURCED_RESTRICTION_ACTIVATED : nf_value->rst_state;

	if (nf_key->iotype == NFACCT_COUNTER_IN)
		info->rcv_limit = nf_value->quota;
	else if(nf_key->iotype == NFACCT_COUNTER_OUT)
		info->send_limit = nf_value->quota;
	else
		_D("Unknown iotype");

	return FALSE;
}

void extract_restriction_list(struct counter_arg *arg,
		GSList **rst_list)
{
	/* to avoid duplication and search while filling rst_list */
	g_tree_foreach(arg->nf_cntrs, fill_restriction_list, rst_list);
}

void update_counter_quota_value(struct nfacct_rule *counter, uint64_t bytes)
{
	struct nfacct_value *value = lookup_counter(counter);
	ret_msg_if(!value, "Can't find nfacct entry for %s", counter->name);
	if (value->quota <= bytes) {
		_D("overquoted % " PRIu64 " ", bytes);
		value->quota = 0;
	} else
		value->quota -= bytes;
}

static int create_each_iptable_rule(gpointer key, gpointer value, void *data)
{
	struct make_rule_context *ctx = (struct make_rule_context *)data;
	resourced_ret_c ret;
	resourced_iface_type iftype = (resourced_iface_type)key;
	char *ifname = (char *)value;
	struct nfacct_value *counter = NULL;

	if (iftype <= RESOURCED_IFACE_UNKNOWN ||
		iftype >= RESOURCED_IFACE_LAST_ELEM ||
		iftype == RESOURCED_IFACE_BLUETOOTH) {
		_D("Unsupported network interface type %d",
			iftype);
		return RESOURCED_ERROR_NONE;
	}

	ctx->counter->iftype = iftype;
	STRING_SAVE_COPY(ctx->counter->ifname, ifname);
	generate_counter_name(ctx->counter);
	counter = lookup_counter(ctx->counter);
	if (!counter ||
	    (counter->state != NFACCT_STATE_ACTIVE)) {
		ret = ctx->counter->iptables_rule(ctx->counter);
		ret_value_msg_if(ret != RESOURCED_ERROR_NONE, RESOURCED_ERROR_FAIL,
			         "Can't add iptables ingress rule");
	}

	return RESOURCED_ERROR_NONE;
}

static void populate_incomplete_counter(void *data)
{
	struct make_rule_context *ctx = (struct make_rule_context *)data;
	generate_counter_name(ctx->counter);

	keep_counter(ctx->counter);
}

static resourced_ret_c create_iptables_rule(const char *app_id, const pid_t pid)
{
	struct shared_modules_data *m_data = get_shared_modules_data();
	struct counter_arg *carg = m_data->carg;
	struct nfacct_rule counter = { .name = {0}, .ifname = {0}, 0, };
	struct make_rule_context ctx;
	uint32_t classid = get_classid_by_app_id(app_id, false);

	ctx.carg = carg;
	ctx.counter = &counter;
	init_nfacct(classid, pid, NFACCT_COUNTER_IN, carg, &counter);

	for_each_ifnames((ifnames_iterator)create_each_iptable_rule,
		populate_incomplete_counter, &ctx);

	counter.iotype = NFACCT_COUNTER_OUT;
	counter.iptables_rule = add_iptables_out;
	for_each_ifnames((ifnames_iterator)create_each_iptable_rule,
		populate_incomplete_counter, &ctx);

	return RESOURCED_ERROR_NONE;
}

/* iface reset section */
struct iftype_context {
	resourced_iface_type iftype;
	struct counter_arg *carg;
};

static void trace_nf_key_value(struct nfacct_key *nfacct_key, struct nfacct_value *nfacct_value)
{
#ifdef DEBUG_ENABLED
	_D("-------- NF TREE NODE -----------");
	_D("classid: %d", nfacct_key->classid);
	_D("iftype:  %d", nfacct_key->iftype);
	_D("iotype:  %d", nfacct_key->iotype);
	_D("ifname:  %s", nfacct_key->ifname);
	_D("pid:     %d", nfacct_value->pid);
	_D("state:   %d", nfacct_value->state);
	_D("fini:    %d", nfacct_value->fini);
	_D("intend:  %d", nfacct_key->intend);
	_D("quota:   %" PRIu64 " ", nfacct_value->quota);
	_D("quota_id:%d", nfacct_value->quota_id);
	_D("roaming: %d", nfacct_value->roaming);
	if (nfacct_key->intend == NFACCT_BLOCK)
		_D("%p rst_state:%d", nfacct_value, nfacct_value->rst_state);
	_D("---------NF TREE NODE -----------");
#endif /* DEBUG_ENABLED */
}

static bool is_incomplete_counter(struct nfacct_key *nfacct_key,
		                  struct nfacct_value *nfacct_value)
{
	return nfacct_key->iftype == RESOURCED_IFACE_UNKNOWN &&
		nfacct_value->state == NFACCT_STATE_ACTIVE;
			/* special incomplete status unnecessary */
}

/*
 * skip activating in case of
 * 1. it's not a counter, it's warning or block restriction
 * 2. new interface is the same as was before, but in this case
 * no need to skip in case of incomplete counter
 * 3. counting is not allowed, e.g. by security reason
 */
static bool check_skip_activating(struct nfacct_key *nfacct_key,
			          struct nfacct_value *nfacct_value,
				  struct iftype_context *ctx)
{
	/**
	 * skip restriction and warning here due there is special
	 * logic for it in restriction-handler.c,
	 * maybe it worth to merge that logic and remove
	 * handler in restriction-handler, but need to take
	 * imsi into account
	 */
	if (nfacct_key->intend == NFACCT_BLOCK ||
	    nfacct_key->intend == NFACCT_WARN) {
		_D("skip block and warning");
		return true;
	}
	/**
	 * skip if it's the same interface,
	 * and we have active counter for it,
	 * e.g from SIM1 to SIM2,
	 */
	if (ctx->iftype == nfacct_key->iftype &&
	    nfacct_value->state == NFACCT_STATE_ACTIVE &&
	    !is_incomplete_counter(nfacct_key, nfacct_value))
		return true;

	if (!is_counting_allowed(nfacct_key->iftype))
		return true;

	return false;
}

static gboolean activate_each_counter_by_iftype(gpointer key,
	gpointer value,
	gpointer data)
{
	struct nfacct_key *nfacct_key = (struct nfacct_key *)key;
	struct nfacct_value *nfacct_value = (struct nfacct_value *)value;
	struct iftype_context *ctx = (struct iftype_context *)data;
	struct nfacct_rule counter = { .name = {0}, .ifname = {0}, 0, };
	struct nfacct_value *found_counter;
	int ret = RESOURCED_ERROR_NONE;


	trace_nf_key_value(nfacct_key, nfacct_value);

	if (check_skip_activating(nfacct_key, nfacct_value, ctx)) {
		/**
		 * it means counting is not allowed
		 * or ctx->iftype was activated, but we still have
		 * active counter for another interface, assume
		 * WLAN is preffered, so lets deactivate it
		 */
		_D("skip activating");
		return FALSE; /* continue iteration */
	}

	/**
	 * counter still active it wasn't yet removed,
	 * del_counter_delayed isn't yet called,
	 * following code not in check_skip_activating,
	 * due it modifies tree value
	 */
	if (nfacct_value->state == NFACCT_STATE_DEL_DELAYED &&
	    ctx->iftype == nfacct_key->iftype) {
		/**
		 * in del_counter_delayed we'll free context
		 * and skip removing
		 */
		nfacct_value->state = NFACCT_STATE_ACTIVE;
		return FALSE;
	}

	counter.classid = nfacct_key->classid;
	counter.iotype = nfacct_key->iotype;
	counter.iftype = ctx->iftype;
	counter.carg = ctx->carg;

	generate_counter_name(&counter);

	found_counter = lookup_counter(&counter);
	ret_value_msg_if(found_counter != NULL &&
		found_counter->state == NFACCT_STATE_ACTIVE, FALSE,
		"Counter already exists and active!");

	if (counter.iotype == NFACCT_COUNTER_IN)
		ret = add_iptables_in(&counter);
	else if (counter.iotype == NFACCT_COUNTER_OUT)
		ret = add_iptables_out(&counter);
	else {
		_E("Unknown counter direction: %s", counter.name);
		return FALSE;
	}

	if (ret != RESOURCED_ERROR_NONE)
		return FALSE;

	if (found_counter != NULL && found_counter->state ==
		NFACCT_STATE_DEACTIVATED)
		found_counter->state = NFACCT_STATE_ACTIVE;

	return FALSE;
}

static void turn_on_counters(resourced_iface_type iftype, struct counter_arg *carg)
{
	struct iftype_context ctx;
	ret_msg_if(iftype == RESOURCED_IFACE_UNKNOWN,
		"Can't get iftype for remove counter");

	ctx.iftype = iftype;
	ctx.carg = carg;
	g_tree_foreach(ctx.carg->nf_cntrs, activate_each_counter_by_iftype, &ctx);
}

static void turn_off_counters(resourced_iface_type iftype, struct counter_arg *carg)
{
	struct iftype_context ctx;
	ret_msg_if(iftype == RESOURCED_IFACE_UNKNOWN,
		"Can't get iftype for remove counter");

	ctx.iftype = iftype;
	ctx.carg = carg;
	g_tree_foreach(ctx.carg->nf_cntrs, deactivate_each_counter_by_iftype, &ctx);
}

static void handle_on_iface_up(const int ifindex)
{
	/* NEW IFACE LET's add COUNTER if it DOESN"T exists */
	resourced_iface_type iftype;
	struct shared_modules_data *m_data;
	m_data = get_shared_modules_data();
	ret_msg_if(m_data == NULL,
		"Can't get module data!");
	iftype = get_iftype(ifindex);
	turn_on_counters(iftype, m_data->carg);
	add_one_tizen_os_counter((gpointer)iftype, NULL, m_data->carg);
}

static void handle_change_allowance(resourced_iface_type iftype, bool enabled)
{
	struct shared_modules_data *m_data;
	m_data = get_shared_modules_data();
	ret_msg_if(m_data == NULL,
		"Can't get module data!");
	if (enabled)
		turn_on_counters(iftype, m_data->carg);
	else
		turn_off_counters(iftype, m_data->carg);
}

struct del_counter_context
{
	struct nfacct_value *nfacct_value;
	struct nfacct_key *nfacct_key;
	struct counter_arg *carg;
};

static Eina_Bool del_counter_delayed(void *data)
{
	int ret;
	struct nfacct_rule counter = { .name = {0}, .ifname = {0}, 0, };
	struct del_counter_context *del_ctx = (struct del_counter_context *)data;
	struct nfacct_value *nfacct_value = del_ctx->nfacct_value;
	struct nfacct_key *nfacct_key = del_ctx->nfacct_key;
	if (nfacct_value->state != NFACCT_STATE_DEL_DELAYED) {
		_D("nfacct counter state is %d", nfacct_value->state);
		goto out;
	}

	counter.classid = nfacct_key->classid;
	counter.iotype = nfacct_key->iotype;
	counter.iftype = nfacct_key->iftype;
	counter.carg = del_ctx->carg;
	STRING_SAVE_COPY(counter.ifname, nfacct_key->ifname);

	generate_counter_name(&counter);

	ret = del_counter(&counter);

	if(ret != RESOURCED_ERROR_NONE) {
		_E("Can't delete counter %s",
		   counter.name);
		goto out;
	}

	nfacct_value->state = NFACCT_STATE_DEACTIVATED;

out:
	free(del_ctx);
	return ECORE_CALLBACK_CANCEL;
}

static gboolean deactivate_each_counter_by_iftype(gpointer key,
	gpointer value,
	gpointer data)
{
	struct nfacct_key *nfacct_key = (struct nfacct_key *)key;
	struct nfacct_value *nfacct_value = (struct nfacct_value *)value;
	struct iftype_context *ctx = (struct iftype_context *)data;
	struct del_counter_context *del_ctx = NULL;

	/**
	 * deactivate counters only for ctx->iftype interface,
	 * and only counters warning/restriction will be removed in
	 * another _reset_restriction_iter
	 */
	if (ctx->iftype != nfacct_key->iftype ||
	    nfacct_key->intend == NFACCT_WARN ||
	    nfacct_key->intend == NFACCT_BLOCK)
		return FALSE; /* continue iteration */

	del_ctx = (struct del_counter_context *)malloc(
		sizeof(struct del_counter_context));
	ret_value_msg_if(del_ctx == NULL, FALSE,
		"Can't allocate del_counter_context");
	del_ctx->nfacct_key = nfacct_key;
	del_ctx->nfacct_value = nfacct_value;
	del_ctx->carg = ctx->carg;
	nfacct_value->state = NFACCT_STATE_DEL_DELAYED;
	ecore_timer_add(0, del_counter_delayed, del_ctx);

	return FALSE;
}

static void handle_on_iface_down(const int ifindex)
{
	/* iface is gone, lets remove counter */
	resourced_iface_type iftype;
	struct shared_modules_data *m_data;
	m_data = get_shared_modules_data();
	ret_msg_if(m_data == NULL,
		"Can't get module data!");
	iftype = get_iftype(ifindex);

	turn_off_counters(iftype, m_data->carg);
}

iface_callback *create_counter_callback(void)
{
	iface_callback *ret_arg = (iface_callback *)
		malloc(sizeof(iface_callback));

	if (!ret_arg) {
		_E("Malloc of iface_callback failed\n");
		return NULL;
	}
	ret_arg->handle_iface_up = handle_on_iface_up;
	ret_arg->handle_iface_down = handle_on_iface_down;

	return ret_arg;
}

/* end iface reset section */

#endif /*DATAUSAGE_TYPE*/

resourced_ret_c join_net_cls(const char *app_id, const pid_t pid)
{
	resourced_ret_c ret;
	ret_value_msg_if(!app_id, RESOURCED_ERROR_INVALID_PARAMETER,
			"invalid app_id");
	ret = make_net_cls_cgroup_with_pid(pid, app_id);
	ret_value_if(ret != RESOURCED_ERROR_NONE, ret);
	ret = update_classids();
	ret_value_if(ret != RESOURCED_ERROR_NONE, ret);
#ifdef CONFIG_DATAUSAGE_NFACCT
	/* Create iptable rule */
	ret = create_iptables_rule(app_id, pid);
	ret_value_if(ret != RESOURCED_ERROR_NONE, ret);
#endif /* CONFIG_DATAUSAGE_NFACCT */
	return RESOURCED_ERROR_NONE;
}

static const struct module_ops datausage_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "datausage",
	.init = resourced_datausage_init,
	.exit = resourced_datausage_finalize,
};

MODULE_REGISTER(&datausage_modules_ops)
