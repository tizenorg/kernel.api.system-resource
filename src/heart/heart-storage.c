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
 * @file heart-storage.c
 *
 * @desc heart storage module
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <Ecore.h>
#include <stdbool.h>
#include <time.h>

#include "resourced.h"
#include "trace.h"
#include "module.h"
#include "macro.h"
#include "notifier.h"
#include "heart.h"
#include "logging.h"
#include "heart-common.h"
#include "edbus-handler.h"
#include "helper.h"

#include <sqlite3.h>

#define HEART_STORAGE_DB			"/opt/usr/dbspace/.resourced-logging-storage.db"
#define STORAGE_NAME		"storage"

static bool heart_storage_initailized = false;
static pthread_mutex_t heart_storage_verifying_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t heart_storage_verifying_thread = 0;
static GQueue *queue = NULL;

static DBusMessage *edbus_insert_log(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	char *pkgid = NULL;
	char *data = NULL;
	DBusMessage *reply;
	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pkgid, DBUS_TYPE_STRING, &data, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	_SD("Insert record (%s, %s)", pkgid, data);
	ret = logging_write(STORAGE_NAME, pkgid, pkgid, time(NULL), data);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Write request failed");
	}

	reply = dbus_message_new_method_return(msg);
	return reply;
}

void heart_storage_delete_cb(struct logging_table_form *table, void *user_data)
{
	int ret;

	if (!table) {
		_E("the table is empty!");
		return;
	}

	_SD("Delete callback for '%s'", table->data);
	if (access(table->data, F_OK) == 0)
		return;

	ret = logging_delete(STORAGE_NAME, table->data);
	if (ret != RESOURCED_ERROR_NONE)
		_SE("Delete request failed: %s", table->data);
}

void *heart_storage_verifying_thread_main(void *arg)
{
	int ret;
	char *pkgid;

	_D("Verifying thread is created!");
	do {
		ret = pthread_mutex_lock(&heart_storage_verifying_mutex);
		if (ret) {
			_E("logging storage verifying thread::pthread_mutex_lock() failed, %d", ret);
			break;
		}

		pkgid = g_queue_pop_head(queue);
		if (!pkgid)
			break;

		pthread_mutex_unlock(&heart_storage_verifying_mutex);

		_SD("Verify '%s'", pkgid);
		ret = logging_read_foreach(STORAGE_NAME, NULL, pkgid, 0, 0, heart_storage_delete_cb, NULL);
		if (ret != RESOURCED_ERROR_NONE)
			_E("Failed to read logs! : %d", ret);
		free(pkgid);
	} while (1);

	heart_storage_verifying_thread = 0;
	pthread_mutex_unlock(&heart_storage_verifying_mutex);
	pthread_exit((void *)0);
}

void heart_storage_verifying_thread_create(const char *data)
{
	char *pkgid = strndup(data, strlen(data)+1);
	if (!pkgid) {
		_E("Failed to allocate memory");
		return;
	}

	int ret = pthread_mutex_lock(&heart_storage_verifying_mutex);
	if (ret) {
		_E("logging storage verifying thread::pthread_mutex_lock() failed, %d", ret);
		free(pkgid);
		return;
	}

	/* Add pkgid to queue */
	g_queue_push_tail(queue, pkgid);

	if (heart_storage_verifying_thread == 0) {
		pthread_attr_t attr;
		ret = pthread_attr_init(&attr);
		if (ret < 0) {
			_E("Failed to initialize pthread attributes, %d", ret);
			pthread_mutex_unlock(&heart_storage_verifying_mutex);
			return;
		}

		ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (ret < 0) {
			_E("Failed to set detached state, %d", ret);
			pthread_mutex_unlock(&heart_storage_verifying_mutex);
			return;
		}

		ret = pthread_create(&heart_storage_verifying_thread, &attr, heart_storage_verifying_thread_main, NULL);
		if (ret < 0) {
			_E("pthread creation for heart_storage_verifying_thread_main failed, %d", ret);
			pthread_mutex_unlock(&heart_storage_verifying_mutex);
			return;
		}
	}

	pthread_mutex_unlock(&heart_storage_verifying_mutex);
}

static DBusMessage *edbus_verify_log(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	char *pkgid = NULL;
	DBusMessage *reply = NULL;
	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pkgid, DBUS_TYPE_INVALID);
	reply = dbus_message_new_method_return(msg);
	if (!ret || !pkgid) {
		_E("Wrong message arguments!");
		return reply;
	}
	/* flush module cache */
	logging_save_to_storage(true);

	heart_storage_verifying_thread_create(pkgid);
	return reply;
}

static const struct edbus_method edbus_methods[] = {
	{ "Insert", "ss", NULL, edbus_insert_log },
	{ "Verify", "s", NULL, edbus_verify_log }
};

static bool is_storage_logging(void)
{
	static const struct module_ops *block;

	block = find_module("block");
	if (block)
		heart_storage_initailized = true;
	return heart_storage_initailized;
}

static int heart_storage_write(void *data)
{
	int ret;
	struct logging_data *ld = (struct logging_data *)data;

	ret = logging_write(STORAGE_NAME, ld->appid, ld->pkgid, time(NULL), ld->data);
	return ret;
}

static int heart_storage_init(void *data)
{
	int ret;

	if (!is_storage_logging())
		return RESOURCED_ERROR_UNINITIALIZED;

	ret = pthread_mutex_init(&heart_storage_verifying_mutex, NULL);
	if (ret < 0) {
		_E("mutex_init failed %d", ret);
		return RESOURCED_ERROR_FAIL;
	}

	queue = g_queue_new();
	if (!queue) {
		_E("queue init failed");
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}
	g_queue_init(queue);

	ret = logging_module_init_with_db_path(STORAGE_NAME, FOUR_MONTH, FIVE_MINUTE, NULL, 0, HEART_STORAGE_DB);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("logging module init failed");
		return RESOURCED_ERROR_FAIL;
	}

	ret = edbus_add_methods(RESOURCED_PATH_LOGGING, edbus_methods, ARRAY_SIZE(edbus_methods));
	if (ret != RESOURCED_ERROR_NONE) {
		_E("DBus method registration for %s is failed", RESOURCED_PATH_LOGGING);
	}

	register_notifier(RESOURCED_NOTIFIER_LOGGING_WRITE, heart_storage_write);
	return RESOURCED_ERROR_NONE;
}

static int heart_storage_exit(void *data)
{
	if (!heart_storage_initailized)
		return RESOURCED_ERROR_NONE;

	_D("heart_storage exit");
	unregister_notifier(RESOURCED_NOTIFIER_LOGGING_WRITE, heart_storage_write);
	logging_module_exit();
	return RESOURCED_ERROR_NONE;
}

static const struct heart_module_ops heart_storage_ops = {
	.name		= "STORAGE",
	.init		= heart_storage_init,
	.exit		= heart_storage_exit,
};
HEART_MODULE_REGISTER(&heart_storage_ops)
