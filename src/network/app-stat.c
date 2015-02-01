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

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "app-stat.h"
#include "net-cls-cgroup.h"
#include "iface.h"
#include "macro.h"
#include "roaming.h"
#include "trace.h"

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
	gint ret = 0;

	ret = a_key->classid - b_key->classid;
	if (!ret)
		return ret;

	ret = a_key->iftype - b_key->iftype;
	if (!ret)
		return ret;

	return strcmp(a_key->ifname, b_key->ifname);
}

static void free_stat(gpointer data)
{
	free(data);
}

struct application_stat_tree *create_app_stat_tree(void)
{
	int ret;
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
							 NULL, free_stat,
							 free_app);
	app_stat_tree->last_touch_time = time(0);
	ret = pthread_rwlock_init(&app_stat_tree->guard, NULL);
	if (ret != 0) {
		_E("Could not initialize tree guard %s.", strerror(ret));
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

traffic_stat_tree *create_traffic_stat_tree(void)
{
	return g_tree_new_full(compare_classid, NULL, NULL, free_stat);
}

void free_traffic_stat_tree(traffic_stat_tree *tree)
{
	g_tree_destroy((GTree *) tree);
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

static gboolean fill_incomming(gpointer key,
	gpointer value, gpointer data)
{
	struct application_stat_tree *app_tree =
		(struct application_stat_tree *)data;
	struct traffic_stat *in_event = (struct traffic_stat *)value;

	struct application_stat *app_stat = NULL;
	if (!is_allowed_ifindex(in_event->ifindex))
		return FALSE;

	app_stat = (struct application_stat *)
		g_tree_lookup((GTree *)app_tree->tree, key);
	if (app_stat)
		app_stat->rcv_count += in_event->bytes;
	else {
		app_stat = g_new(struct application_stat, 1);
		memset(app_stat, 0, sizeof(struct application_stat));
		app_stat->rcv_count = in_event->bytes;
		g_tree_insert((GTree *)app_tree->tree, key, app_stat);
	}
	app_stat->delta_rcv += in_event->bytes;

	/*only for debug purpose*/
	if (!app_stat->ifindex)
		app_stat->ifindex = in_event->ifindex;

	app_stat->is_roaming = get_roaming();
	return FALSE;
}

static gboolean fill_outgoing(gpointer key,
	gpointer value, gpointer data)
{
	struct application_stat_tree *app_tree =
		(struct application_stat_tree *)data;
	struct traffic_stat *out_event = (struct traffic_stat *)value;

	struct application_stat *app_stat = (struct application_stat *)
		g_tree_lookup((GTree *)app_tree->tree, key);
	if (app_stat)
		app_stat->snd_count += out_event->bytes;
	else {
		app_stat = g_new(struct application_stat, 1);
		memset(app_stat, 0, sizeof(struct application_stat));
		app_stat->snd_count = out_event->bytes;
		g_tree_insert((GTree *)app_tree->tree, key, app_stat);
	}
	app_stat->delta_snd += out_event->bytes;

	if (!app_stat->ifindex)
		app_stat->ifindex = out_event->ifindex;

	if (!app_stat->is_roaming)
		app_stat->is_roaming = get_roaming();
	return FALSE;
}


static void fill_result(traffic_stat_tree *tree_in,
		traffic_stat_tree *tree_out,
		struct application_stat_tree *result)
{

	g_tree_foreach(tree_in, (GTraverseFunc)fill_incomming, result);
	g_tree_foreach(tree_out, (GTraverseFunc)fill_outgoing, result);
}

resourced_ret_c prepare_application_stat(traffic_stat_tree *tree_in,
			     traffic_stat_tree *tree_out,
			     struct application_stat_tree *result,
			     volatile struct daemon_opts *opts)
{
	fill_result(tree_in, tree_out, result);
	identify_application(result);

	return RESOURCED_ERROR_NONE;
}
