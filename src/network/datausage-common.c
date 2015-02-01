/*
 * resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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

#include "appid-helper.h"
#include "config.h"
#include "const.h"
#include "counter-process.h"
#include "counter.h"
#include "cgroup.h"
#include "datausage-restriction.h"
#include "generic-netlink.h"
#include "net-cls-cgroup.h"
#include "nl-helper.h"
#include "notifier.h"
#include "notification.h" /* for sending datausage dbus notification */
#include "daemon-options.h"
#include "datausage-common.h"
#include "datausage-quota.h"
#include "datausage-vconf-callbacks.h"
#include "iface-cb.h"
#include "macro.h"
#include "module-data.h"
#include "module.h"
#include "nfacct-rule.h"
#include "protocol-info.h"
#include "resourced.h"
#include "restriction-handler.h"
#include "roaming.h"
#include "storage.h"
#include "trace.h"

#include <linux/rtnetlink.h>

#ifdef CONFIG_DATAUSAGE_NFACCT


struct make_rule_context {
	struct counter_arg *carg;
	struct nfacct_rule *counter;
};

struct nfacct_key {
	u_int32_t classid;
	resourced_iface_type iftype;
	nfacct_rule_direction iotype;
	char ifname[MAX_NAME_LENGTH];
};

enum nfacct_state {
	NFACCT_STATE_ACTIVE,	/* kernel counter is applied */
	NFACCT_STATE_DEACTIVATED, /* kernel counter was removed, but this counter
		is still active, and it will be required for network interface,
		when it will be activated */
};

struct nfacct_value {
	pid_t pid;
	enum nfacct_state state;
};

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

static void resourced_roaming_cb_init(void)
{
	regist_roaming_cb(get_roaming_restriction_cb());
}

static int app_launch_cb(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	int ret;
	ret_value_msg_if(p_data == NULL, RESOURCED_ERROR_FAIL,
		"Please provide valid argument!");
	ret = join_net_cls(p_data->appid, p_data->pid);
	if (ret != RESOURCED_ERROR_NONE)
		_D("Failed to start network counting.");
	return ret;
}

#ifdef CONFIG_DATAUSAGE_NFACCT

static int remove_each_counter(
	gpointer key,
	gpointer value,
	gpointer data)
{
	struct nfacct_rule *counter = (struct nfacct_rule *)data;
	resourced_iface_type iftype = *(resourced_iface_type *)value;
	struct nfacct_key nf_key;

	if (iftype == RESOURCED_IFACE_UNKNOWN)
		return FALSE;

	nf_key.classid = counter->classid;
	nf_key.iotype = counter->iotype;
	counter->iftype = nf_key.iftype = iftype;

	generate_counter_name(counter);
	counter->iptables_rule(counter);

	/*  remove from local tree  */
#ifdef DEBUG_ENABLED
	{
		gconstpointer t = g_tree_lookup(counter->carg->nf_cntrs, &nf_key);
		if (t)
			_I("Element exists, remove it!");
		else
			_D("Element doesn't exist!");
	}
#endif

	g_tree_remove(counter->carg->nf_cntrs, &nf_key);
#ifdef DEBUG_ENABLED
	{
		gconstpointer t = g_tree_lookup(counter->carg->nf_cntrs, &nf_key);
		if (t)
			_E("Element wasn't removed!");
	}
#endif

	return FALSE;
}

static void remove_nfacct_counters_for_all_iface(u_int32_t classid, struct counter_arg *carg)
{
	struct nfacct_rule counter = {
		.classid = classid,
		.iotype = NFACCT_COUNTER_IN,
		.iptables_rule = del_iptables_in,
		.carg = carg,
		/* .name until we don't have iftype,
		*	we couldn't get name */
	};

	/* TODO rework for_each_ifindex to avoid cast,
	 * right now cast is necessary due for_each_ifindex directy pass
	 * given function into g_tree_foreach */
	/* remove for ingress counter */
	for_each_ifindex((ifindex_iterator)remove_each_counter, NULL, &counter);
	/* remove for engress counter */
	counter.iotype = NFACCT_COUNTER_OUT;
	counter.iptables_rule = del_iptables_out;
	for_each_ifindex((ifindex_iterator)remove_each_counter, NULL, &counter);
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

static int app_terminate_cb(void *data)
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
	resourced_iface_type iftype = *(resourced_iface_type *)value;

	if (iftype <= RESOURCED_IFACE_UNKNOWN ||
		iftype >= RESOURCED_IFACE_LAST_ELEM)
		return FALSE;

	counter.iotype = NFACCT_COUNTER_IN;
	counter.iftype = iftype;
	counter.carg = carg;
	generate_counter_name(&counter);
	add_iptables_in(&counter);
	counter.iotype = NFACCT_COUNTER_OUT;
	generate_counter_name(&counter);
	add_iptables_out(&counter);
	return FALSE;
}

static void add_tizen_os_counters(struct counter_arg *carg) {

	for_each_ifindex((ifindex_iterator)add_one_tizen_os_counter, NULL, carg);
}

static void reload_all_nf_counters(struct counter_arg *carg)
{
	add_tizen_os_counters(carg);
	/* it can be done by following ways:
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

	/* fill classid list, due we couldn't iterate on tree and
	 * remove elements from it */
	g_tree_foreach(carg->nf_cntrs, populate_classid_tree, classid_tree);
	g_tree_foreach(classid_tree, remove_each_counter_by_classid, carg);

	g_tree_destroy(carg->nf_cntrs);
	g_tree_destroy(classid_tree);
}

/* notification section */
/*
 * TODO use following constant from kernel header
 * nfacct/include/linux/netfilter/nfnetlink.h
 * */
#ifndef NFNLGRP_ACCT_QUOTA
#define NFNLGRP_ACCT_QUOTA 8
#endif
#ifndef SOL_NETLINK
#define SOL_NETLINK	270
#endif

static inline char *get_public_appid(const uint32_t classid)
{
	char *appid;

	/* following value for ALL is suitable for using in statistics
	   what's why it's not in get_app_id_by_classid */
	if (classid == RESOURCED_ALL_APP_CLASSID)
		return RESOURCED_ALL_APP;

	appid = get_app_id_by_classid(classid, true);
	return !appid ? UNKNOWN_APP : appid;
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

static int fill_restriction(struct rtattr *attr_list[__NFACCT_MAX],
		void *user_data)
{
	struct counter_arg *carg = (struct counter_arg *)user_data;
	struct nfacct_rule counter = { .name = {0}, .ifname = {0}, 0, };
	char *cnt_name = (char *)RTA_DATA(
				attr_list[NFACCT_NAME]);
	char *app_id = 0;
	int ret = 0;
	resourced_restriction_info rst_info = {0};

	init_nfacct(0, 0, 0, carg, &counter);
	strcpy(counter.name, cnt_name);
	recreate_counter_by_name(cnt_name, &counter);

	app_id = get_public_appid(counter.classid);
	ret = get_restriction_info(app_id, counter.iftype, &rst_info);
        ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
                "Failed to get restriction info!");

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
			/* TODO need to think how to release it and what about
			 * not yet fired rule */
			ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"Can't create auxilary counter %s", out_counter.name);
		}

		if (rst_info.quota_id != NONE_QUOTA_ID)
			send_restriction_notification(app_id);
		update_restriction_db(app_id, counter.iftype, 0, 0,
				      RESOURCED_RESTRICTION_ACTIVATED,
		rst_info.quota_id, rst_info.roaming);

	} else if (counter.intend == NFACCT_WARN) {
		if (rst_info.quota_id != NONE_QUOTA_ID)
			send_restriction_warn_notification(app_id);
		/* remove both warnings */
		counter.iotype = NFACCT_COUNTER_IN | NFACCT_COUNTER_OUT;
		ret = del_counter(&counter);
		ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
			"Can't delete warning %s", counter.name);
	} else
		_E("Unkown restriction notification type");

	return 0;
}

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
static int app_terminate_cb(void *data)
{
	return 0;
}

iface_callback *create_counter_callback(void)
{
	return NULL;
}

#endif /* CONFIG_DATAUSAGE_NFACCT */

static int resourced_datausage_init(void *data)
{
	struct modules_arg *marg = (struct modules_arg *)data;
	struct shared_modules_data *m_data = get_shared_modules_data();
	int ret_code;

	load_daemon_opts(marg->opts);
	_D("Initialize network counter function\n");
	ret_value_msg_if(marg == NULL, RESOURCED_ERROR_INVALID_PARAMETER,
			 "Invalid modules argument\n");
	ret_value_msg_if(m_data == NULL, RESOURCED_ERROR_FAIL,
			 "Invalid shared modules data\n");
	/* register notifier cb */
	register_notifier(RESOURCED_NOTIFIER_APP_LAUNCH, app_launch_cb);
	register_notifier(RESOURCED_NOTIFIER_APP_RESUME, app_launch_cb);
	register_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, app_launch_cb);
	register_notifier(RESOURCED_NOTIFIER_APP_TERMINATE, app_terminate_cb);
	m_data->carg = init_counter_arg(marg->opts);
	ret_code = resourced_iface_init();
	ret_value_msg_if(ret_code < 0, ret_code, "resourced_iface_init failed");
	resourced_roaming_cb_init();
	ret_code = resourced_init_counter_func(m_data->carg);
	ret_value_msg_if(ret_code < 0, ret_code, "Error init counter func\n");
	resourced_add_vconf_datausage_cb(m_data->carg);
	init_hw_net_protocol_type();
	reactivate_restrictions();

#ifdef CONFIG_DATAUSAGE_NFACCT
	reload_all_nf_counters(m_data->carg);

	/* let's make a notification socket */
	init_notifier(m_data->carg);
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
	finalize_carg(m_data->carg);
	finalize_storage_stm();
	finalize_hw_net_protocol_type();
	unregister_notifier(RESOURCED_NOTIFIER_APP_LAUNCH, app_launch_cb);
	unregister_notifier(RESOURCED_NOTIFIER_APP_RESUME, app_launch_cb);
	unregister_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, app_launch_cb);
	unregister_notifier(RESOURCED_NOTIFIER_APP_TERMINATE, app_terminate_cb);
	resourced_iface_finalize();
	finalize_iftypes();

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
	return strcmp(key_a->ifname, key_b->ifname);
}

GTree *create_nfacct_tree(void)
{
	return g_tree_new_full(compare_nfcntr, NULL, NULL, free);
}

static struct nfacct_value *lookup_counter(struct nfacct_rule *counter)
{
	struct nfacct_key key = {
		.classid = counter->classid,
		.iftype = counter->iftype,
		.iotype = counter->iotype
	};
	STRING_SAVE_COPY(key.ifname, counter->ifname);

	return (struct nfacct_value *)g_tree_lookup(counter->carg->nf_cntrs,
		&key);
}

/* Called only in case of successful kernle operation */
void keep_counter(struct nfacct_rule *counter)
{
	struct nfacct_key *key = NULL;
	struct nfacct_value *value = NULL;

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
	STRING_SAVE_COPY(key->ifname, counter->ifname);

	value->pid =  counter->pid;
	value->state = NFACCT_STATE_ACTIVE;

	g_tree_insert(counter->carg->nf_cntrs, key, value);
}

static int create_each_iptable_rule(gpointer key, gpointer value, void *data)
{
	struct make_rule_context *ctx = (struct make_rule_context *)data;
	resourced_ret_c ret;
	resourced_iface_type iftype = *(resourced_iface_type *)value;
	struct nfacct_value *counter = NULL;

	if (iftype <= RESOURCED_IFACE_UNKNOWN ||
		iftype >= RESOURCED_IFACE_LAST_ELEM) {
		_D("Unsupported network interface type %d",
			iftype);
		return RESOURCED_ERROR_NONE;
	}

	ctx->counter->iftype = iftype;
	generate_counter_name(ctx->counter);
	counter = lookup_counter(ctx->counter);
	if (counter != NULL) {
		_D("Counter already exists!");
		return RESOURCED_ERROR_NONE;
	}
	ret = ctx->counter->iptables_rule(ctx->counter);
	ret_value_msg_if(ret != RESOURCED_ERROR_NONE, RESOURCED_ERROR_FAIL,
		"Can't add iptables ingress rule");

	keep_counter(ctx->counter);
	return RESOURCED_ERROR_NONE;
}

static void populate_incomplete_counter(void *data)
{
	struct make_rule_context *ctx = (struct make_rule_context *)data;
	struct nfacct_value *counter;
	generate_counter_name(ctx->counter);

	counter = lookup_counter(ctx->counter);
	if (counter != NULL) {
		_D("Counter already exists!");
		return;
	}
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

	for_each_ifindex((ifindex_iterator)create_each_iptable_rule,
		populate_incomplete_counter, &ctx);

	counter.iotype = NFACCT_COUNTER_OUT;
	counter.iptables_rule = add_iptables_out;
	for_each_ifindex((ifindex_iterator)create_each_iptable_rule,
		populate_incomplete_counter, &ctx);

	return RESOURCED_ERROR_NONE;
}

/* iface reset section */
struct iftype_context {
	resourced_iface_type iftype;
	struct counter_arg *carg;
};

static bool is_incomplete_counter(struct nfacct_key *nfacct_key, struct nfacct_value *nfacct_value)
{
	return nfacct_key->iftype == RESOURCED_IFACE_UNKNOWN &&
		nfacct_value->state == NFACCT_STATE_ACTIVE;
			/* special incomplete status unnecessary */
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

	/* ugly check, due in case of RMNET -> WLAN switch,
	 *		WLAN activated before then RMNET is deactivated */

	/*
	 * skip activating in case of
	 * 1. new interface is the same as was before
	 * 2. and counter is still active and new interface is Wifi
	 *	such problem was with WiFi only
	 * 3. and state is not deactivated, it's mean we wil skip in case of active
	 *   incomplete counter
	 * */
	if (!(ctx->iftype != nfacct_key->iftype &&
	    nfacct_value->state == NFACCT_STATE_ACTIVE &&
	    ctx->iftype == RESOURCED_IFACE_WIFI) &&
	    nfacct_value->state != NFACCT_STATE_DEACTIVATED &&
	    !is_incomplete_counter(nfacct_key, nfacct_value))
		/* it means ctx->iftype was activated, but we still have
		 *	active counter for another interface, assume
		 *	WLAN is preffered, so lets deactivate it */
		return FALSE; /* continue iteration */


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
	else
		keep_counter(&counter);

	return FALSE;
}

static void handle_on_iface_up(const int ifindex)
{
	/* NEW IFACE LET's add COUNTER if it DOESN"T exists */
	resourced_iface_type iftype;
	struct shared_modules_data *m_data;
	struct iftype_context ctx;
	m_data = get_shared_modules_data();
	ret_msg_if(m_data == NULL,
		"Can't get module data!");
	iftype = get_iftype(ifindex);

	ret_msg_if(iftype == RESOURCED_IFACE_UNKNOWN,
		"Can't get iftype for remove counter");

	ctx.iftype = iftype;
	ctx.carg = m_data->carg;
	g_tree_foreach(ctx.carg->nf_cntrs, activate_each_counter_by_iftype, &ctx);
	add_tizen_os_counters(m_data->carg);
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

	counter.classid = nfacct_key->classid;
	counter.iotype = nfacct_key->iotype;
	counter.iftype = nfacct_key->iftype;
	counter.carg = del_ctx->carg;
	STRING_SAVE_COPY(counter.ifname, nfacct_key->ifname);

	generate_counter_name(&counter);

	ret = del_counter(&counter);

	ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ECORE_CALLBACK_CANCEL,
		"Can't delete counter %s",
		counter.name);

	nfacct_value->state = NFACCT_STATE_DEACTIVATED;

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

	/* deactivate counters only for ctx->iftype interface */
	if (ctx->iftype != nfacct_key->iftype)
		return FALSE; /* continue iteration */

	del_ctx = (struct del_counter_context *)malloc(
		sizeof(struct del_counter_context));
	ret_value_msg_if(del_ctx == NULL, FALSE,
		"Can't allocate del_counter_context");
	del_ctx->nfacct_key = nfacct_key;
	del_ctx->nfacct_value = nfacct_value;
	del_ctx->carg = ctx->carg;
	ecore_timer_add(0, del_counter_delayed, del_ctx);

	return FALSE;
}

static void handle_on_iface_down(const int ifindex)
{
	/* iface is gone, lets remove counter */
	resourced_iface_type iftype;
	struct shared_modules_data *m_data;
	struct iftype_context ctx;
	m_data = get_shared_modules_data();
	ret_msg_if(m_data == NULL,
		"Can't get module data!");
	iftype = get_iftype(ifindex);

	ret_msg_if(iftype == RESOURCED_IFACE_UNKNOWN,
		"Can't get iftype for remove counter");

	ctx.iftype = iftype;
	ctx.carg = m_data->carg;
	g_tree_foreach(ctx.carg->nf_cntrs, deactivate_each_counter_by_iftype, &ctx);
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
	char pkgname[MAX_PATH_LENGTH];
	extract_pkgname(app_id, pkgname, sizeof(pkgname));
	ret = make_net_cls_cgroup_with_pid(pid, pkgname);
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
