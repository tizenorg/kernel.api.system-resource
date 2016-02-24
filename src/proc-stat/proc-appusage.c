/*
 * resourced
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file proc-appusage.c
 * @desc check history (application frequency and application execution time) based application usage
*/

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <Ecore.h>

#include "resourced.h"
#include "logging.h"
#include "trace.h"
#include "module.h"
#include "macro.h"
#include "proc-main.h"
#include "notifier.h"
#include "config-parser.h"

#ifdef HEART_SUPPORT
#include "logging-common.h"
#endif

#define UPDATE_INTERVAL	DAY_TO_SEC(1)
#define APPUSAGE_CONF_FILE      "/etc/resourced/proc.conf"
#define APPUSAGE_CONF_SECTION	"APPUSAGE"

static int favorite_count;
static GHashTable *appusage_favorite_htab;

#ifdef HEART_SUPPORT
static Ecore_Timer *appusage_update_timer;
#endif

static void free_key(gpointer data)
{
	if (data)
		free(data);
}

static gboolean find_hash(gpointer key, gpointer value, gpointer user_data)
{
	return (gboolean)strstr((char *)user_data, (char *)key);
}

static void print_favorite_list(gpointer key, gpointer value, gpointer user_data)
{
	_D("favorit app list : %s", (char*)key);
}

#ifdef HEART_SUPPORT
static Eina_Bool appusage_update_cb(void *data)
{
	GHashTable *apps_htab = (GHashTable *)data;
	int ret;

	if (!data)
		return ECORE_CALLBACK_CANCEL;

	ret = logging_cpu_get_appusage_list(apps_htab, favorite_count);
	if (!ret) {
		_I("most_recently_used_list updated");
		g_hash_table_foreach(apps_htab, print_favorite_list, NULL);
	}

	return ECORE_CALLBACK_RENEW;
}
#endif

static int load_appusage_config(struct parse_result *result, void *user_data)
{
	if(!result)
		return -EINVAL;

	if (strcmp(result->section, APPUSAGE_CONF_SECTION))
		return RESOURCED_ERROR_NO_DATA;

	if (!strcmp(result->name, "APPUSAGE")) {
		if (!strcmp(result->value, "OFF"))
			return RESOURCED_ERROR_UNINITIALIZED;

		appusage_favorite_htab = g_hash_table_new_full(g_str_hash,
				g_str_equal, free_key, NULL);

	} else if (!strcmp(result->name, "PREDEFINE")) {
		g_hash_table_insert(appusage_favorite_htab,
				g_strndup(result->value, strlen(result->value)), GINT_TO_POINTER(1));
	}

	return RESOURCED_ERROR_NONE;
}

static int proc_appusage_table_init(void)
{
	int ret;

	ret = config_parse(APPUSAGE_CONF_FILE, load_appusage_config, NULL);
	if(ret || !appusage_favorite_htab)
		return RESOURCED_ERROR_NO_DATA;

	favorite_count = g_hash_table_size(appusage_favorite_htab);

#ifdef HEART_SUPPORT
	ret = logging_cpu_get_appusage_list(appusage_favorite_htab,
			favorite_count);
	if (!ret)
		_I("most_recently_used_list updated");
#endif

	g_hash_table_foreach(appusage_favorite_htab, print_favorite_list, NULL);

	return RESOURCED_ERROR_NONE;
}

static int booting_done(void *data)
{
	static const struct module_ops *swap;
	int ret;

	/*
	 * When kernel enables swap feature,
	 * resourced can control favorite applications because it will
	 * apply early swap and late oom kill.
	 */
	swap = find_module("swap");
	if (!swap)
		return RESOURCED_ERROR_NO_DATA;

	ret = proc_appusage_table_init();
	if (ret)
		return RESOURCED_ERROR_NO_DATA;

#ifdef HEART_SUPPORT
	appusage_update_timer = ecore_timer_add(UPDATE_INTERVAL,
			appusage_update_cb, (void *)appusage_favorite_htab);
#endif

	return RESOURCED_ERROR_NONE;
}

bool proc_check_favorite_app(char *appid)
{
	gpointer app_ptr = NULL;

	if (!appusage_favorite_htab)
		return false;

	app_ptr = g_hash_table_find(appusage_favorite_htab,
			    find_hash, (gpointer)appid);
	if (app_ptr)
		return true;
	return false;
}

static int proc_appusage_init(void *data)
{
	register_notifier(RESOURCED_NOTIFIER_BOOTING_DONE, booting_done);
	return RESOURCED_ERROR_NONE;
}

static int proc_appusage_exit(void *data)
{
	if (appusage_favorite_htab)
		g_hash_table_destroy(appusage_favorite_htab);
	unregister_notifier(RESOURCED_NOTIFIER_BOOTING_DONE, booting_done);
	return RESOURCED_ERROR_NONE;
}

static const struct proc_module_ops proc_appusage_ops = {
	.name		= "PROC_APPUSAGE",
	.init		= proc_appusage_init,
	.exit		= proc_appusage_exit,
};
PROC_MODULE_REGISTER(&proc_appusage_ops)
