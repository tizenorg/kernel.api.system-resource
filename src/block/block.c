/*
 * resourced
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file cpu.c
 *
 * @desc cpu module
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include "notifier.h"
#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "resourced.h"
#include "trace.h"
#include "vconf.h"
#include "cgroup.h"
#include "config-parser.h"
#include "const.h"
#include "block.h"
#include "proc-common.h"
#include "appinfo-list.h"

#define BLOCK_CONF_FILE                  "/etc/resourced/block.conf"
#define BLOCK_CONF_SECTION		"MONITOR"

static GSList *block_monitor_list;

static void free_exclude_key(gpointer data)
{
	if (data)
		free(data);
}

static int load_block_config(struct parse_result *result, void *user_data)
{
	struct block_monitor_info *bmi;

	if (!result)
		return RESOURCED_ERROR_NO_DATA;

	if (!result->section || !result->name)
		return RESOURCED_ERROR_NO_DATA;

	if (!strstr(result->section, BLOCK_CONF_SECTION))
		return RESOURCED_ERROR_NO_DATA;

	if (MATCH(result->name, "path")) {
		bmi = calloc(1, sizeof(struct block_monitor_info));
		if (!bmi) {
			_E("Failed to create monitor info");
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}
		strncpy(bmi->path, result->value, MAX_PATH_LENGTH-1);
		block_monitor_list = g_slist_prepend(block_monitor_list, bmi);

	} else if (MATCH(result->name, "mode")) {
		bmi = (struct block_monitor_info *)g_slist_nth_data(block_monitor_list, 0);
		SET_CONF(bmi->mode, convert_fanotify_mode(result->value));

	} else if (MATCH(result->name, "include")) {
			bmi = (struct block_monitor_info *)g_slist_nth_data(block_monitor_list, 0);
			if (!bmi->block_include_proc)
				bmi->block_include_proc = g_hash_table_new_full(
						g_str_hash, g_str_equal, free_exclude_key, NULL);

	} else if (MATCH(result->name, "exclude")) {
		bmi = (struct block_monitor_info *)g_slist_nth_data(block_monitor_list, 0);
		if (!bmi->block_exclude_path)
			bmi->block_exclude_path = g_hash_table_new_full(
				    g_str_hash, g_str_equal, free_exclude_key, NULL);
		g_hash_table_insert(bmi->block_exclude_path, g_strndup(result->value, strlen(result->value)),
			    GINT_TO_POINTER(1));

	} else if (MATCH(result->name, "logging")) {
		bmi = (struct block_monitor_info *)g_slist_nth_data(block_monitor_list, 0);
		SET_CONF(bmi->logging, atoi(result->value));

	} else if (MATCH(result->name, "configend")) {
		int ret;

		bmi = (struct block_monitor_info *)g_slist_nth_data(block_monitor_list, 0);
		if (bmi->mode) {
			ret = register_fanotify(bmi);
			if (ret == RESOURCED_ERROR_NONE)
				return ret;
		}
		block_monitor_list = g_slist_remove(block_monitor_list, bmi);
		free(bmi);
	}
       return RESOURCED_ERROR_NONE;
}

static int block_prelaunch_state(void *data)
{
	GSList *iter;
	struct proc_status *ps = (struct proc_status *)data;
	struct proc_app_info *pai = ps->pai;

	if (!CHECK_BIT(pai->flags, PROC_DOWNLOADAPP))
		return RESOURCED_ERROR_NONE;

	gslist_for_each_item(iter, block_monitor_list) {
		struct block_monitor_info *bmi = (struct block_monitor_info *)iter->data;
		if (!bmi->block_include_proc)
			continue;

		g_hash_table_insert(bmi->block_include_proc, g_strndup(pai->ai->pkgname, strlen(pai->ai->pkgname)),
			    GINT_TO_POINTER(1));
		_E("insert data %s, table num : %d", pai->ai->pkgname, g_hash_table_size(bmi->block_include_proc));
	}
	return RESOURCED_ERROR_NONE;
}

static int block_booting_done(void *data)
{
	config_parse(BLOCK_CONF_FILE, load_block_config, NULL);
	return RESOURCED_ERROR_NONE;
}

static int resourced_block_init(void *data)
{
	register_notifier(RESOURCED_NOTIFIER_BOOTING_DONE, block_booting_done);
	register_notifier(RESOURCED_NOTIFIER_APP_PRELAUNCH, block_prelaunch_state);
	return RESOURCED_ERROR_NONE;
}

static int resourced_block_exit(void *data)
{
	GSList *iter, *next;
	struct block_monitor_info *bmi;

	gslist_for_each_safe(block_monitor_list, iter, next, bmi) {
		block_monitor_list = g_slist_remove(block_monitor_list, bmi);
		unregister_fanotify(bmi);
		if (bmi->block_exclude_path)
			g_hash_table_destroy(bmi->block_exclude_path);
		if (bmi->block_include_proc)
			g_hash_table_destroy(bmi->block_include_proc);
		free(bmi);
	}
	unregister_notifier(RESOURCED_NOTIFIER_BOOTING_DONE, block_booting_done);
	unregister_notifier(RESOURCED_NOTIFIER_APP_PRELAUNCH, block_prelaunch_state);
	return RESOURCED_ERROR_NONE;
}

static struct module_ops block_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "block",
	.init = resourced_block_init,
	.exit = resourced_block_exit,
};

MODULE_REGISTER(&block_modules_ops)
