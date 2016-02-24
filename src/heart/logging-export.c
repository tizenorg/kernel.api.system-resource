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

/*
 * @file logging-export.c
 *
 * @desc start export logging system
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <glib.h>
#include <Ecore.h>

#include "resourced.h"
#include "trace.h"
#include "module.h"
#include "macro.h"
#include "logging-common.h"
#include "edbus-handler.h"

static DBusMessage *logging_export_getmemory_latest(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	DBusMessageIter iter;
	DBusMessage *reply;
	char *appid;
	unsigned int pss = 0, uss = 0;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &appid, DBUS_TYPE_INVALID);

	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	ret = logging_memory_get_latest_data(appid, &pss, &uss);

	if (ret) {
		_E("logging_memory_get_latest_data failed %d", ret);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &pss);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &uss);

	return reply;
}

static DBusMessage *logging_export_getmemory_data(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret, period;
	DBusMessageIter iter;
	DBusMessage *reply;
	char *appid;
	struct logging_memory_data *md;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &appid, DBUS_TYPE_INT32, &period, DBUS_TYPE_INVALID);

	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	md = logging_memory_get_data(appid, period);

	if (!md) {
		_E("logging_memory_get_data failed %d", ret);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &md->max_pss);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &md->avg_pss);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &md->max_uss);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &md->avg_uss);

	free(md);

	return reply;
}

static DBusMessage *logging_export_getmemory(E_DBus_Object *obj, DBusMessage *msg)
{
	int i, ret, period;
	char *appid, *pkgid;
	GArray *temp_array;
	DBusMessageIter iter;
	DBusMessageIter arr;
	DBusMessage *reply;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &period, DBUS_TYPE_INVALID);

	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	temp_array = g_array_new(false, false, sizeof(struct logging_memory_data *));

	ret = logging_memory_get_table(temp_array, period);

	if (ret) {
		_E("logging_memory_get_table failed %d", ret);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(ssuuuu)", &arr);

	for (i = 0; i < temp_array->len; i++) {
		DBusMessageIter sub;
		struct logging_memory_data *md;

		md = g_array_index(temp_array, struct logging_memory_data *, i);

		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		appid = md->appid;
		pkgid = md->pkgid;
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &appid);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &pkgid);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &md->max_pss);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &md->avg_pss);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &md->max_uss);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &md->avg_uss);

		dbus_message_iter_close_container(&arr, &sub);
	}

	dbus_message_iter_close_container(&iter, &arr);

	g_array_free(temp_array, true);

	return reply;
}

static DBusMessage *logging_export_getmemorydb(E_DBus_Object *obj, DBusMessage *msg)
{
	int i, ret, period;
	char *appid, *pkgid;
	GArray *temp_array;
	DBusMessageIter iter;
	DBusMessageIter arr;
	DBusMessage *reply;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &period, DBUS_TYPE_INVALID);

	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	/* read from query */
	temp_array = g_array_new(false, false, sizeof(struct logging_memory_data *));
	_E("start get read query!!! %d", time(NULL));
	ret = logging_memory_get_query(temp_array, period);
	_E("end get read query!!! %d", time(NULL));

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(ssuuuu)", &arr);

	for (i = 0; i < temp_array->len; i++) {
		DBusMessageIter sub;
		struct logging_memory_data *md;

		md = g_array_index(temp_array, struct logging_memory_data *, i);

		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		appid = md->appid;
		pkgid = md->pkgid;
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &appid);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &pkgid);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &md->max_pss);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &md->avg_pss);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &md->max_uss);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &md->avg_uss);

		dbus_message_iter_close_container(&arr, &sub);
	}

	dbus_message_iter_close_container(&iter, &arr);

	g_array_free(temp_array, true);

	return reply;
}

static DBusMessage *logging_export_getmemoryforeach(E_DBus_Object *obj, DBusMessage *msg)
{
	int i, ret, period;
	char *appid, *pkgid;
	GArray *temp_array;
	DBusMessageIter iter;
	DBusMessageIter arr;
	DBusMessage *reply;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &period, DBUS_TYPE_INVALID);

	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	/* read from query */
	temp_array = g_array_new(false, false, sizeof(struct logging_memory_data *));
	_E("start get read foreach!!! %d", time(NULL));
	ret = logging_memory_get_foreach(temp_array, period);
	_E("end get read foreach!!! %d", time(NULL));

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(ssuuuu)", &arr);

	for (i = 0; i < temp_array->len; i++) {
		DBusMessageIter sub;
		struct logging_memory_data *md;

		md = g_array_index(temp_array, struct logging_memory_data *, i);

		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		appid = md->appid;
		pkgid = md->pkgid;
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &appid);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &pkgid);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &md->max_pss);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &md->avg_pss);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &md->max_uss);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &md->avg_uss);

		dbus_message_iter_close_container(&arr, &sub);
	}

	dbus_message_iter_close_container(&iter, &arr);

	g_array_free(temp_array, true);

	return reply;
}

static DBusMessage *logging_export_memory_save_to_file(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	DBusMessage *reply;
	DBusMessageIter iter;

	ret = logging_memory_save();

	if (ret) {
		_E("save to file failed");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);

	return reply;
}

static struct edbus_method edbus_methods[] = {
	{ "GetMemoryLatest",   "s",   "uu", logging_export_getmemory_latest },
	{ "GetMemoryData",   "si",   "uuuu", logging_export_getmemory_data },
	{ "GetMemoryDataList",   "i",   "a(ssuuuu)", logging_export_getmemory },
	{ "GetMemoryDB",   "i",   "a(ssuuuu)", logging_export_getmemorydb },
	{ "GetMemoryforeach",   "i",   "a(ssuuuu)", logging_export_getmemoryforeach },
	{ "SaveMemoryData",   NULL,   "i", logging_export_memory_save_to_file },
	/* Add methods here */
};


static int logging_export_init(void *data)
{
	int ret;

	ret = edbus_add_methods(RESOURCED_PATH_LOGGING, edbus_methods,
							ARRAY_SIZE(edbus_methods));

	if (ret != RESOURCED_ERROR_NONE) {
		_E("DBus method registration for %s is failed", RESOURCED_PATH_LOGGING);
		return RESOURCED_ERROR_FAIL;
	}

	_D("logging export init finished");
	return RESOURCED_ERROR_NONE;
}

static int logging_export_exit(void *data)
{
	_D("logging export finalize");

	return RESOURCED_ERROR_NONE;
}

static struct module_ops logging_export_ops = {
	.priority	= MODULE_PRIORITY_NORMAL,
	.name		= "logging_export",
	.init		= logging_export_init,
	.exit		= logging_export_exit,
};

MODULE_REGISTER(&logging_export_ops)
