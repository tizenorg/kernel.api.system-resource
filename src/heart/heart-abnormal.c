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
 */

/*
 * @file heart-abnormal.c
 *
 * @desc heart abnormal module
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#include "proc-common.h"
#include "notifier.h"
#include "resourced.h"
#include "edbus-handler.h"
#include "heart.h"
#include "logging.h"
#include "heart-common.h"
#include "trace.h"
#include "module.h"
#include "macro.h"

#define ABNORMAL_NAME                          "abnormal"
#define ABNORMAL_DATA_MAX                      1024

enum abnormal_type {
	FC = 0,
	ANR = 1,
	ABNORMAL_TYPE_MAX,
};

struct heart_abnormal_table {
	char appid[MAX_APPID_LENGTH];
	char pkgid[MAX_PKGNAME_LENGTH];
	time_t time;
	int count[ABNORMAL_TYPE_MAX];
};

static GHashTable *heart_abnormal_list;
static pthread_mutex_t heart_abnormal_mutex = PTHREAD_MUTEX_INITIALIZER;

static void heart_abnormal_process_crashed(void *data, DBusMessage *msg)
{
	int ret;
	char *process_name, *exepath, *appid, *pkgid;
	char info[ABNORMAL_DATA_MAX];

	ret = dbus_message_is_signal(msg, CRASH_INTERFACE_CRASH, PROCESS_CRASHED);
	if (!ret) {
		_E("dbus_message_is_signal error");
		return;
	}
	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &process_name,
			DBUS_TYPE_STRING, &exepath, DBUS_TYPE_STRING, &appid,
			DBUS_TYPE_STRING, &pkgid, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("Failed: dbus_message_get_args()");
		return;
	}
	snprintf(info, sizeof(info), "%s %s %d ", process_name, exepath, FC);
	_D("info : %s", info);
	ret = logging_write(ABNORMAL_NAME, appid, pkgid, time(NULL), info);
	if (ret != RESOURCED_ERROR_NONE)
		return;
}

static int heart_abnormal_anr(void *data)
{
	int ret;
	char info[ABNORMAL_DATA_MAX];
	struct proc_status *ps = (struct proc_status *)data;
	char *appid, *pkgid;

	ret = proc_get_id_info(ps, &appid, &pkgid);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to proc_get_id_info");
		return ret;
	}
	snprintf(info, sizeof(info), "%d ANR %d ", ps->pid, ANR);
	_D("info : %s", info);
	ret = logging_write(ABNORMAL_NAME, appid, pkgid, time(NULL), info);
	return ret;
}

static void heart_abnormal_free_value(gpointer value)
{
	struct heart_abnormal_table *table =
		(struct heart_abnormal_table *)value;

	if (!table)
		return;

	free(table);
}

void heart_abnormal_fill_array(struct logging_table_form *data, void *user_data)
{
	int ret, i;
	unsigned int type;
	struct heart_abnormal_table *table = NULL;
	GHashTable *abnormal_list = (GHashTable *)user_data;

	sscanf((char *)data->data, "%*s %*s %u ", &type);
	ret = pthread_mutex_lock(&heart_abnormal_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return;
	}
	table = g_hash_table_lookup(abnormal_list, data->pkgid);
	if (table)
		table->count[type]++;
	else {
		table = malloc(sizeof(struct heart_abnormal_table));
		if (!table) {
			_E("malloc failed");
			goto unlock_exit;
		}

		if (snprintf(table->appid, MAX_APPID_LENGTH, "%s", data->appid) < 0) {
			_E("snprintf failed");
			free(table);
			goto unlock_exit;
		}

		if (snprintf(table->pkgid, MAX_PKGNAME_LENGTH, "%s", data->pkgid) < 0) {
			_E("snprintf failed");
			free(table);
			goto unlock_exit;
		}
		table->time = data->time;
		for (i = 0; i < ABNORMAL_TYPE_MAX; i++)
			table->count[i] = 0;
		table->count[type] = 1;
		g_hash_table_insert(abnormal_list, (gpointer)table->pkgid, (gpointer)table);
	}

unlock_exit:
	ret = pthread_mutex_unlock(&heart_abnormal_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return;
	}
}

static DBusMessage *edbus_heart_get_abnormal_data(E_DBus_Object *obj, DBusMessage *msg)
{
	int type, period, ret, count, i;
	time_t starttime;
	char *pkgid;
	gpointer key, value;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter arr;
	GHashTableIter hiter;
	struct heart_abnormal_table *table = NULL;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &type,
			DBUS_TYPE_INT32, &period, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	if (type < 0 || ABNORMAL_TYPE_MAX  < type) {
		_E("Wrong message arguments! %d", type);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	starttime = time(NULL);
	switch (period) {
	case DATA_LATEST:
		starttime = 0;
		break;
	case DATA_3HOUR:
		starttime -= 10800;
		break;
	case DATA_6HOUR:
		starttime -= 21600;
		break;
	case DATA_12HOUR:
		starttime -= 43200;
		break;
	case DATA_1DAY:
		starttime -= 86400;
		break;
	case DATA_1WEEK:
		starttime -= 604800;
		break;
	default:
		_E("Wrong message arguments! %d", period);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	if (starttime < 0)
		starttime = 0;

	if (g_hash_table_size(heart_abnormal_list))
		g_hash_table_remove_all(heart_abnormal_list);

	logging_read_foreach(ABNORMAL_NAME, NULL, NULL, starttime, 0,
			heart_abnormal_fill_array, heart_abnormal_list);

	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init_append(reply, &iter);

	ret = pthread_mutex_lock(&heart_abnormal_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	g_hash_table_iter_init(&hiter, heart_abnormal_list);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(si)", &arr);

	while (g_hash_table_iter_next(&hiter, &key, &value)) {
		DBusMessageIter sub;
		table = (struct heart_abnormal_table *)value;
		if (!table)
			break;
		count = 0;
		pkgid = table->pkgid;

		if (type == ABNORMAL_TYPE_MAX) {
			for (i = 0; i < ABNORMAL_TYPE_MAX; i++)
				count += table->count[i];
		} else
			count += table->count[type];

		if (!count)
			continue;

		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &pkgid);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &count);
		dbus_message_iter_close_container(&arr, &sub);
	}
	dbus_message_iter_close_container(&iter, &arr);

	ret = pthread_mutex_unlock(&heart_abnormal_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	return reply;
}

static struct edbus_method edbus_methods[] = {
       { "GetAbnormalData",      "ii",   "a(si)",     edbus_heart_get_abnormal_data },
};

static int heart_abnormal_init(void *data)
{
	int ret;

	ret = logging_module_init(ABNORMAL_NAME, ONE_WEEK, HALF_HOUR, NULL, 0);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("logging module init failed");
		return RESOURCED_ERROR_FAIL;
	}

	ret = edbus_add_methods(RESOURCED_PATH_LOGGING, edbus_methods,
			ARRAY_SIZE(edbus_methods));
	if (ret != RESOURCED_ERROR_NONE) {
		_E("DBus method registration for %s is failed",
				RESOURCED_PATH_LOGGING);
	}
	ret = register_edbus_signal_handler(CRASH_PATH_CRASH,
			CRASH_INTERFACE_CRASH, PROCESS_CRASHED,
			heart_abnormal_process_crashed, NULL);
	if (ret < 0) {
		_E("Failed to add a capacity status signal handler");
	}
	heart_abnormal_list = g_hash_table_new_full(
			g_str_hash,
			g_str_equal,
			NULL,
			heart_abnormal_free_value);

	register_notifier(RESOURCED_NOTIFIER_APP_ANR, heart_abnormal_anr);
	_D("heart abnormal init finished");
	return RESOURCED_ERROR_NONE;
}

static int heart_abnormal_exit(void *data)
{
	if (heart_abnormal_list)
		g_hash_table_destroy(heart_abnormal_list);
	logging_module_exit();
	unregister_notifier(RESOURCED_NOTIFIER_APP_ANR, heart_abnormal_anr);
	_D("heart abnormal exit");
	return RESOURCED_ERROR_NONE;
}

static const struct heart_module_ops heart_abnormal_ops = {
	.name           = "ABNORMAL",
	.init           = heart_abnormal_init,
	.exit           = heart_abnormal_exit,
};
HEART_MODULE_REGISTER(&heart_abnormal_ops)
