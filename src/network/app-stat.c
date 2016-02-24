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
 *
 */


/*
 * @file app-stat.c
 *
 * @desc application statistics entity helper functions
 */

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "app-stat.h"
#include "counter.h"
#include "datausage-common.h"
#include "net-cls-cgroup.h"
#include "iface.h"
#include "macro.h"
#include "telephony.h"
#include "trace.h"
#ifdef CONFIG_DATAUSAGE_NFACCT
#include "nfacct-rule.h"
#else
#include "genl.h"
#endif

static void free_app(gpointer data)
{
	struct application_stat *app_stat = (struct application_stat *)data;
	if (!app_stat)
		return;

	if (app_stat->application_id)
		free(app_stat->application_id);

	free(app_stat);
}

static gint compare_classid(gconstpointer a, gconstpointer b,
	gpointer __attribute__((__unused__)) userdata)
{
	const struct classid_iftype_key *a_key = (struct classid_iftype_key*)a;
	const struct classid_iftype_key *b_key = (struct classid_iftype_key*)b;
	gint ret = a_key->classid - b_key->classid;

	if (ret)
		return ret;

	ret = a_key->iftype - b_key->iftype;
	if (ret)
		return ret;

	ret = (a_key->ifname && b_key->ifname) ?
		strcmp(a_key->ifname, b_key->ifname) : 0;

	if (ret)
		return ret;

	return (a_key->imsi && b_key->imsi) ?
		strcmp(a_key->imsi, b_key->imsi) : 0;
}

struct application_stat_tree *create_app_stat_tree(void)
{
	int ret;
	char buf[256];
	struct application_stat_tree *app_stat_tree;
	app_stat_tree =
		(struct application_stat_tree *) malloc
		(sizeof(struct application_stat_tree));
	if (!app_stat_tree) {
		_E("Malloc of create_app_stat_tree failed\n");
		return NULL;
	}

	app_stat_tree->tree =
		(GTree *)g_tree_new_full(compare_classid,
							 NULL, free,
							 free_app);
	app_stat_tree->last_touch_time = time(0);
	ret = pthread_rwlock_init(&app_stat_tree->guard, NULL);
	if (ret != 0) {
		strerror_r(ret, buf, sizeof(buf));
		_E("Could not initialize tree guard %s.", buf);
		free(app_stat_tree);
		app_stat_tree = NULL;
	}
	return app_stat_tree;
}

void free_app_stat_tree(struct application_stat_tree *app_stat_tree)
{
	/* do not check null pointer because it makes g_tree_destroy */
	ret_msg_if(app_stat_tree == NULL,
		"Please provide valid app_stat_tree!");
	g_tree_destroy((GTree *)app_stat_tree->tree);
}

void nulify_app_stat_tree(struct application_stat_tree **app_stat_tree)
{
	free_app_stat_tree(*app_stat_tree);
	free(*app_stat_tree);
	*app_stat_tree = NULL;
}

static gboolean set_app_id(gpointer key, gpointer value,
	void __attribute__((__unused__)) *data)
{
	/* Open closed principle would be better here */
	struct application_stat *stat = (struct application_stat *)value;
	u_int32_t classid = ((struct classid_iftype_key*)key)->classid;

	/* No need to request update classid table per each app entry */
	stat->application_id = get_app_id_by_classid(classid, false);
	return FALSE;
}

static inline void identify_application(
	struct application_stat_tree *app_stat_tree)
{
	g_tree_foreach(app_stat_tree->tree, (GTraverseFunc)set_app_id, NULL);
}

#ifdef CONFIG_DATAUSAGE_NFACCT

static void fill_nfacct_counter(struct nfacct_rule *counter, uint64_t bytes)
{
	struct classid_iftype_key *key;
	struct classid_iftype_key search_key = {0};
	struct counter_arg *carg = counter->carg;
	struct application_stat_tree *app_tree =
		(struct application_stat_tree *)carg->result;
	struct application_stat *app_stat = NULL;

	search_key.classid = counter->classid;
	search_key.iftype = counter->iftype;
	STRING_SAVE_COPY(search_key.ifname, counter->ifname);
	search_key.imsi = counter->iftype == RESOURCED_IFACE_DATACALL ?
		get_current_modem_imsi() : ""; /* we'll not free it */

	app_stat = (struct application_stat *)
		g_tree_lookup((GTree *)app_tree->tree, &search_key);

	if (!app_stat) {
		key = g_new(struct classid_iftype_key, 1);

		if (!key) {
			_D("g_new alloc error\n");
			return;
		}
		memcpy(key, &search_key, sizeof(struct classid_iftype_key));
		STRING_SAVE_COPY(key->ifname, search_key.ifname);

		app_stat = g_new(struct application_stat, 1);
		if (!app_stat) {
			_D("g_new alloc error\n");
			g_free((gpointer)key);
			return;
		}
		memset(app_stat, 0, sizeof(struct application_stat));
		g_tree_insert((GTree *)app_tree->tree, (gpointer)key, (gpointer)app_stat);
		_D("new app stat for classid %u\n", counter->classid);
	} else {
		_D("app stat for classid %d found in tree", search_key.classid);
		_D("app stats app id %s", app_stat->application_id);
		_D("counter intend %d", counter->intend);
	}

	if (counter->iotype == NFACCT_COUNTER_IN) {
		app_stat->delta_rcv += bytes; /* += because we could update
						 counters several times before
						 flush it */
		app_stat->rcv_count += bytes; /* for different update/flush interval
						 in quota processing,
						 quota nulifies it and flush operation
						 as well, so 2 counters */
	} else if (counter->iotype == NFACCT_COUNTER_OUT) {
		app_stat->delta_rcv += bytes;
		app_stat->rcv_count += bytes;
	}

	app_stat->is_roaming = get_current_roaming();
	if (!app_stat->application_id)
		app_stat->application_id = get_app_id_by_classid(counter->classid, false);
	app_stat->ground = get_app_ground(counter);
}

static void fill_nfacct_restriction(struct nfacct_rule *counter, uint64_t bytes)
{
	/* update db from here ? */
	_D("byte for restriction %" PRIu64 " ", bytes);
	update_counter_quota_value(counter, bytes);
}

void fill_nfacct_result(char *cnt_name, uint64_t bytes,
			struct counter_arg *carg)
{
	struct nfacct_rule counter = {
		.carg = carg,
		.name = {0},
		.ifname = {0},
		0, };

	_D("cnt_name %s", cnt_name);

	if (!recreate_counter_by_name(cnt_name, &counter)) {
		_E("Can't parse counter name %s", cnt_name);
		return;
	}

	_D("classid %u, iftype %u, iotype %d, intend %d, ifname %s, bytes %lu",
	   counter.classid, counter.iftype, counter.iotype, counter.intend, counter.ifname, bytes);

	if (counter.iotype == NFACCT_COUNTER_UNKNOWN) {
		_D("Counter type is not supported!");
		return;
	}
	if (counter.intend == NFACCT_COUNTER ||
	    counter.intend == NFACCT_TETH_COUNTER) {
		return fill_nfacct_counter(&counter, bytes);
	} else if (counter.intend == NFACCT_BLOCK)
		return fill_nfacct_restriction(&counter, bytes);
}
#else
API void fill_app_stat_result(int ifindex, int classid, uint64_t bytes, int iotype,
			  struct counter_arg *carg)
{
	struct classid_iftype_key *key;
	struct classid_iftype_key search_key = {0};
	char *ifname;

	struct application_stat_tree *app_tree =
		(struct application_stat_tree *)carg->result;
	struct application_stat *app_stat = NULL;

	search_key.classid = classid;
	search_key.iftype = get_iftype(ifindex);
	ifname = get_iftype_name(search_key.iftype);
	STRING_SAVE_COPY(search_key.ifname, ifname);
	search_key.imsi = search_key.iftype == RESOURCED_IFACE_DATACALL ?
		get_current_modem_imsi() : ""; /* we'll not free it */

	app_stat = (struct application_stat *)
		g_tree_lookup((GTree *)app_tree->tree, &search_key);

	if (!app_stat) {
		key = g_new(struct classid_iftype_key, 1);

		if (!key) {
			_D("g_new alloc error\n");
			return;
		}
		memcpy(key, &search_key, sizeof(struct classid_iftype_key));
		STRING_SAVE_COPY(key->ifname, search_key.ifname);

		app_stat = g_new(struct application_stat, 1);
		if (!app_stat) {
			_D("g_new alloc error\n");
			g_free((gpointer)key);
			return;
		}
		memset(app_stat, 0, sizeof(struct application_stat));
		g_tree_insert((GTree *)app_tree->tree, (gpointer)key, (gpointer)app_stat);
		_D("new app stat for classid %u\n", classid);
	}

	if (iotype == TRAF_STAT_C_GET_CONN_IN) {
		app_stat->delta_rcv += bytes; /* += because we could update
						 counters several times before
						 flush it */
		app_stat->rcv_count += bytes; /* for different update/flush interval
						 in quota processing,
						 quota nulifies it and flush operation
						 as well, so 2 counters */
	} else if (iotype == TRAF_STAT_C_GET_PID_OUT) {
		app_stat->delta_snd += bytes;
		app_stat->snd_count += bytes;
	}

	app_stat->is_roaming = get_current_roaming();
	if (!app_stat->application_id)
		app_stat->application_id = get_app_id_by_classid(classid, false);

}
#endif /* CONFIG_DATAUSAGE_NFACCT */
