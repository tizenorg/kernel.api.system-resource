/*
 * resourced
 *
 * Copyright (c) 2012 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file logging.c
 *
 * @desc start logging system for resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <leveldb/c.h>
#include <Ecore.h>
#include <sqlite3.h>
#include <unistd.h>
#include <pthread.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <assert.h>

#include "trace.h"
#include "heart.h"
#include "logging.h"
#include "resourced.h"
#include "macro.h"
#include "module.h"
#include "config-parser.h"
#include "notifier.h"


#define LOGGING_BUF_MAX			1024
#define LOGGING_PTIORITY		20

#define DB_SIZE_THRESHOLD		(50<<20)
#define LOGGING_FILE_PATH		HEART_FILE_PATH
#define CREATE_QUERY			"CREATE TABLE IF NOT EXISTS %s (appid TEXT, pkgid TEXT, time INT, data TEXT, idx INT, PRIMARY KEY(time, idx));"
#define DELETE_QUERY_WITH_TIME	"DELETE from %s where time < %d;"
#define DELETE_QUERY_WITH_DATA	"DELETE from %s where data = ?;"
#define INSERT_QUERY			"INSERT INTO %s values (?, ?, ?, ?, ?);"
#define SELECT_QUERY			"SELECT * FROM %s WHERE time >= %d;"

#define SELECT_BEGIN_QUERY		"SELECT * FROM %s "
#define SELECT_WHERE_QUERY		"WHERE"
#define SELECT_AND_QUERY		" AND"
#define SELECT_APPID_QUERY		" appid = \'%s\'"
#define SELECT_PKGID_QUERY		" pkgid = \'%s\'"
#define SELECT_START_QUERY		" time > %d"
#define SELECT_END_QUERY		" time < %d"
#define SELECT_FINISH_QUERY		";"

#define FINALIZE_AND_RETURN_IF(cond, func, format, arg...) do \
	{ if (CONDITION(cond)) { \
		func(format, ##arg); \
		pthread_mutex_unlock(&(module->cache_mutex)); \
		sqlite3_finalize(insert_stmt); \
		sqlite3_finalize(delete_stmt); \
		return; \
	} } while (0)

enum { read_until_null = -1 };

struct logging_module {
	char *name;
	char *db_path;
	sqlite3 *db;
	enum logging_period max_period;
	pthread_mutex_t cache_mutex;
	logging_info_cb func;
	time_t latest_update_time;
	int saved_interval;
	int updated_interval;
	enum logging_interval save_interval;
	enum logging_interval update_interval;
	GQueue *cache;
	GSList *listener;
};

struct logging_search {
	char *appid;
	char *pkgid;
	time_t start;
	time_t end;
	logging_info_cb func;
};

struct logging_listerner {
	void (*func)(char *data);
};

static const struct module_ops logging_modules_ops;

static pthread_t logging_data_thread = 0;
static pthread_mutex_t logging_data_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t logging_data_cond = PTHREAD_COND_INITIALIZER;
static Ecore_Timer *logging_data_timer = NULL;

static pthread_t logging_update_thread = 0;
static pthread_mutex_t logging_update_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t logging_update_cond = PTHREAD_COND_INITIALIZER;
static Ecore_Timer *logging_update_timer = NULL;

static GArray *logging_modules;
static sqlite3 *logging_db;
static leveldb_t *logging_leveldb;
static leveldb_options_t *options;
static leveldb_readoptions_t *roptions;
static leveldb_writeoptions_t *woptions;

static struct logging_object *logging_instance = NULL;

time_t logging_get_time(int clk_id)
{
	struct timespec ts;

	if (clock_gettime(clk_id, &ts) == -1) {
		_E("clock_gettime failed");
		clock_gettime(CLOCK_MONOTONIC, &ts);
	}

	return ts.tv_sec;
}

long logging_get_time_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

static struct logging_module *logging_find_module(char *name)
{
	int i;

	if (!logging_modules)
		return NULL;

	for (i = 0; i < logging_modules->len; i++) {
		struct logging_module *module = g_array_index(logging_modules,
				struct logging_module *, i);
		if (!strcmp(name, module->name)) {
			return module;
		}
	}

	return NULL;
}

static int logging_db_busy(void * UNUSED user, int attempts)
{
	struct timespec req, rem;

	_E("DB locked by another process, attempts number %d", attempts);

	req.tv_sec = 0;
	req.tv_nsec = 500000000;
	nanosleep(&req, &rem);
	return 1;
}

int logging_module_init_with_db_path(char *name, enum logging_period max_period,
		enum logging_interval save_interval, logging_info_cb func, enum logging_interval update_interval, const char *db_path)
{
	int ret;
	sqlite3 *db = NULL;
	const char *path = NULL;
	sqlite3_stmt *stmt = NULL;
	char buf[LOGGING_BUF_MAX] = {0, };
	struct logging_module *module;

	if (!logging_instance) {
		logging_instance = (struct logging_object *)malloc(sizeof(struct logging_object));
		if (!logging_instance) {
			_E("Failed to malloc logging_instance");
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}
		logging_instance->ref = 0;
		logging_init(NULL);
	}

	logging_instance->ref++;

	/* check*/
	if (logging_find_module(name)) {
		_E("%s is already exist", name);
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	if (db_path) {
		/* DB create */
		if (sqlite3_open(db_path, &db) != SQLITE_OK) {
			_E("%s DB open failed (%s)", db_path, sqlite3_errmsg(db));
			return RESOURCED_ERROR_FAIL;
		}

		ret = sqlite3_exec(db, "PRAGMA locking_mode = NORMAL", 0, 0, 0);
		if (ret != SQLITE_OK) {
			_E("Can't set locking mode %s", sqlite3_errmsg(db));
			_E("Skip set busy handler.");
		} else {
			/* Set how many times we'll repeat our attempts for sqlite_step */
			if (sqlite3_busy_handler(db, logging_db_busy, NULL) != SQLITE_OK) {
				_E("Couldn't set busy handler!");
			}
		}

		path = db_path;
	} else {
		db = logging_db;
		path = LOGGING_DB_FILE_NAME;
	}

	/* create table using module name and field_forms */
	snprintf(buf, LOGGING_BUF_MAX, CREATE_QUERY, name);
	ret = sqlite3_prepare_v2(db, buf, read_until_null, &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("create %s table failed %s", name, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return RESOURCED_ERROR_DB_FAILED;
	}

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		_E("create %s table failed %s", name, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return RESOURCED_ERROR_DB_FAILED;
	}

	sqlite3_finalize(stmt);

	module = malloc(sizeof(struct logging_module));

	if (!module) {
		_E("malloc failed");
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	/* make logging_module_inform and set module_inform */
	module->db = db;
	module->func = func;
	module->latest_update_time = time(NULL);
	module->save_interval = save_interval;
	module->saved_interval = save_interval;
	module->update_interval = update_interval;
	module->updated_interval = update_interval;
	module->listener = NULL;

	if (asprintf(&(module->name), "%s", name) < 0) {
		_E("asprintf failed");
		free(module);
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	if (asprintf(&(module->db_path), "%s", path) < 0) {
		_E("asprintf failed");
		free(module);
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	module->max_period = max_period;

	if (pthread_mutex_init(&module->cache_mutex, NULL) < 0) {
		_E("%s module mutex_init failed %d", name, errno);
		free(module->name);
		free(module);
		return RESOURCED_ERROR_FAIL;
	}

	module->cache = g_queue_new();

	if (!module->cache) {
		_E("g_queue_new failed");
		free(module->name);
		free(module);
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	g_queue_init(module->cache);

	g_array_append_val(logging_modules, module);

	return RESOURCED_ERROR_NONE;
}

int logging_module_init(char *name, enum logging_period max_period,
		enum logging_interval save_interval, logging_info_cb func, enum logging_interval update_interval)
{
	return logging_module_init_with_db_path(name, max_period, save_interval, func, update_interval, NULL);
}

int logging_module_exit(void)
{
	assert(logging_instance);
	assert(logging_instance->ref > 0);

	logging_instance->ref--;

	if (logging_instance->ref == 0) {
		free(logging_instance);
		logging_instance = NULL;
		logging_exit(NULL);
	}
	return RESOURCED_ERROR_NONE;
}

int logging_register_listener(char *name, logging_listener_cb listener_cb)
{
	GSList *registerd;
	struct logging_listerner *listener;
	struct logging_module *module;

	if (!listener_cb) {
		_E("invalid listern func");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	module = logging_find_module(name);

	if (!module) {
		_E("There is no %s module", name);
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	registerd = g_slist_find(module->listener, listener_cb);

	if (registerd) {
		_E("already registerd listener %x", listener_cb);
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	listener = malloc(sizeof(struct logging_listerner));
	if (!listener) {
		_E("Fail to malloc for notifier!");
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	listener->func = listener_cb;

	module->listener = g_slist_append(module->listener, listener);

	return RESOURCED_ERROR_NONE;
}

int logging_unregister_listener(char *name, logging_listener_cb listener_cb)
{
	GSList *registerd;
	struct logging_module *module;

	if (!listener_cb) {
		_E("invalid listern func");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	module = logging_find_module(name);

	if (!module) {
		_E("There is no %s module", name);
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	registerd = g_slist_find(module->listener, listener_cb);

	if (!registerd) {
		_E("It is not registered listerner %x", listener_cb);
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	module->listener = g_slist_remove(module->listener, registerd->data);

	free(registerd->data);

	return RESOURCED_ERROR_NONE;
}

int logging_operate(char *name, char *appid, char *pkgid, time_t time, char *data, int operation)
{
	/* Save data to cache  */
	struct logging_module *module;
	struct logging_table_form *table;

	module = logging_find_module(name);

	if (!module) {
		_E("There is no %s module", name);
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	table = malloc(sizeof(struct logging_table_form));

	if (!table) {
		_E("malloc failed");
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	if (operation == INSERT) {
		if (snprintf(table->appid, MAX_APPID_LENGTH, "%s", appid) < 0) {
			_E("snprintf failed");
			free(table);
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}

		if (snprintf(table->pkgid, MAX_PKGNAME_LENGTH, "%s", pkgid) < 0) {
			_E("snprintf failed");
			free(table);
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}
	}

	table->time = time;

	if (asprintf(&(table->data), "%s", data) < 0) {
		_E("asprintf failed");
		free(table);
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	table->operation = operation;

	pthread_mutex_lock(&(module->cache_mutex));
	g_queue_push_tail(module->cache, (gpointer)table);
	pthread_mutex_unlock(&(module->cache_mutex));

	/* call listners */
	if (module->listener) {
		GSList *iter;
		struct logging_listerner *listener;
		char buf[LOGGING_BUF_MAX];

		gslist_for_each_item(iter, module->listener) {
			listener = (struct logging_listerner *)iter->data;
			snprintf(buf, LOGGING_BUF_MAX, "%s %s %d %s", appid, pkgid, (int)time, data);

			listener->func(buf);
		}
	}

	return RESOURCED_ERROR_NONE;
}

int logging_write(char *name, char *appid, char *pkgid, time_t time, char *data)
{
	return logging_operate(name, appid, pkgid, time, data, INSERT);
}

int logging_delete(char *name, char *data)
{
	time_t time = 0;
	return logging_operate(name, NULL, NULL, time, data, DELETE);
}

int logging_leveldb_put(char *key, unsigned int key_len, char *value, unsigned int value_len)
{
	char *err =  NULL;

	if (!key || !key_len || !value || !value_len)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	leveldb_put(logging_leveldb, woptions, key, key_len, value, value_len, &err);
	if (err != NULL) {
		_E("Failed to put to leveldb");
		return RESOURCED_ERROR_DB_FAILED;
	}
	free(err);
	err = NULL;
	_D("%s:%s", key, value);
	return RESOURCED_ERROR_NONE;
}

int logging_leveldb_putv(char *key, unsigned int key_len, const char *fmt, ...)
{
	char *err =  NULL;
	va_list ap;
	char value[LOGGING_BUF_MAX];
	unsigned int value_len;

	if (!key || !key_len || !fmt)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	va_start(ap, fmt);
	vsnprintf(value, LOGGING_BUF_MAX, fmt, ap);
	va_end(ap);

	value_len = strlen(value);
	if (!value_len) {
		_E("Failed to get length of string");
		return RESOURCED_ERROR_DB_FAILED;
	}
	leveldb_put(logging_leveldb, woptions, key, key_len, value, value_len, &err);
	if (err != NULL) {
		_E("Failed to put to leveldb");
		return RESOURCED_ERROR_DB_FAILED;
	}
	free(err);
	err = NULL;
	_D("%s:%s", key, value);
	return RESOURCED_ERROR_NONE;
}

int logging_leveldb_read(char *key, unsigned int key_len, char *value, unsigned int value_len)
{
	unsigned int read_len;
	char *err =  NULL;
	char *result = NULL;

	if (!key || !key_len || !value || !value_len)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	result = leveldb_get(logging_leveldb, roptions, key, key_len, &read_len, &err);
	if (err != NULL) {
		_E("Failed to get from leveldb");
		return RESOURCED_ERROR_DB_FAILED;
	}
	free(err);
	err = NULL;
	if (value_len < read_len)
		snprintf(value, value_len, "%s", result);
	else
		snprintf(value, read_len + 1, "%s", result);

	free(result);

	_D("%s:%s", key, value);
	return RESOURCED_ERROR_NONE;
}

int logging_leveldb_delete(char *key, unsigned int key_len)
{
	char *err =  NULL;

	if (!key || !key_len)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	leveldb_delete(logging_leveldb, woptions, key, key_len, &err);
	if (err != NULL) {
		_E("Failed to delete from leveldb");
		return RESOURCED_ERROR_DB_FAILED;
	}
	free(err);
	err = NULL;
	return RESOURCED_ERROR_NONE;
}

int logging_get_latest_in_cache(char *name, char *appid, char **data)
{
	int i, len;
	struct logging_module *module;
	struct logging_table_form *table;

	module = logging_find_module(name);

	if (!module) {
		_E("There is no %s module", name);
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	if (!appid) {
		_E("appid parameter should be valid");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	pthread_mutex_lock(&(module->cache_mutex));
	len = g_queue_get_length(module->cache);
	pthread_mutex_unlock(&(module->cache_mutex));

	if (!len) {
		_I("%s cache is empty", module->name);
		return RESOURCED_ERROR_NO_DATA;
	}

	*data = NULL;

	for (i = 0; i < len; i++) {
		pthread_mutex_lock(&(module->cache_mutex));
		table = g_queue_peek_nth(module->cache, i);

		if (table &&
			!strcmp(appid, table->appid))
			*data = table->data;
		pthread_mutex_unlock(&(module->cache_mutex));
	}

	if (!*data) {
		_E("NOT found in cache %s", appid);
		return RESOURCED_ERROR_NO_DATA;
	}

	return RESOURCED_ERROR_NONE;
}

static void logging_cache_search(struct logging_table_form *data, struct logging_search *search)
{
	/* search in cache */
	/* true condition, call function */
	if (search->appid) {
		if (strcmp(search->appid, data->appid))
			return;

		if (search->start && search->start < data->time)
			return;

		if (search->end && search->end > data->time)
			return;
	} else if (search->pkgid) {
		if (strcmp(search->pkgid, data->pkgid))
			return;

		if (search->start && search->start < data->time)
			return;

		if (search->end && search->end > data->time)
			return;
	} else if (search->start) {
		if (search->start < data->time)
			return;

		if (search->end && search->end > data->time)
			return;
	} else if (search->end) {
		if (search->end > data->time)
			return;
	}

	search->func(data);
}

int logging_read_foreach(char *name, char *appid, char *pkgid,
		time_t start_time, time_t end_time, logging_info_cb callback)
{
	/* Read from storage (cache & db) */
	int result;
	int len;
	sqlite3_stmt *stmt = NULL;
	struct logging_table_form table;
	struct logging_module *module;
	struct logging_search search;
	char buf[LOGGING_BUF_MAX] = {0, };

	module = logging_find_module(name);

	if (!module) {
		_E("There is no %s module", name);
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	search.appid = NULL;
	search.pkgid = NULL;
	search.start = 0;
	search.end = 0;
	search.func = callback;

	len = snprintf(buf, LOGGING_BUF_MAX, SELECT_BEGIN_QUERY, name);

	if (appid) {
		len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_WHERE_QUERY);

		search.appid = appid;
		len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_APPID_QUERY, appid);

		if (start_time) {
			search.start = start_time;
			len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_AND_QUERY);
			len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_START_QUERY, (int)start_time);
		}
		if (end_time) {
			search.end = end_time;
			len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_AND_QUERY);
			len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_END_QUERY, (int)end_time);
		}
	} else if (pkgid) {
		len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_WHERE_QUERY);

		search.pkgid = pkgid;
		len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_PKGID_QUERY, pkgid);

		if (start_time) {
			search.start = start_time;
			len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_AND_QUERY);
			len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_START_QUERY, (int)start_time);
		}
		if (end_time) {
			search.end = end_time;
			len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_AND_QUERY);
			len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_END_QUERY, (int)end_time);
		}
	} else if (start_time) {
		len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_WHERE_QUERY);

		search.start = start_time;
		len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_START_QUERY, (int)start_time);

		if (end_time) {
			search.end = end_time;
			len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_AND_QUERY);
			len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_END_QUERY, (int)end_time);
		}
	} else if (end_time) {
		len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_WHERE_QUERY);

		search.end = end_time;
		len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_END_QUERY, (int)end_time);
	}

	len += snprintf(buf+len, LOGGING_BUF_MAX - len, SELECT_FINISH_QUERY);

	/* search from db */
	if (sqlite3_prepare_v2(module->db, buf, read_until_null, &stmt, NULL) != SQLITE_OK) {
		_E("select failed");
		sqlite3_finalize(stmt);
		return RESOURCED_ERROR_DB_FAILED;
	}

	do {
		result = sqlite3_step(stmt);
		switch (result) {
		case SQLITE_ROW:
			snprintf(table.appid, MAX_APPID_LENGTH, "%s", (char *)sqlite3_column_text(stmt, 0));
			snprintf(table.pkgid, MAX_PKGNAME_LENGTH, "%s", (char *)sqlite3_column_text(stmt, 1));
			table.time = sqlite3_column_int(stmt, 2);
			if (module->latest_update_time < table.time)
				module->latest_update_time = table.time;
			table.data = (char *)sqlite3_column_text(stmt, 3);

			callback(&table);
			break;
		case SQLITE_DONE:
			break;
		case SQLITE_ERROR:
			_E("select %s table failed %s", name, sqlite3_errmsg(module->db));
			/* FALLTHROUGH */
		default:
			sqlite3_finalize(stmt);
			return RESOURCED_ERROR_DB_FAILED;
		}
	} while (result == SQLITE_ROW);

	sqlite3_finalize(stmt);

	/* search from cache */
	if (!g_queue_is_empty(module->cache)) {
		pthread_mutex_lock(&(module->cache_mutex));
		g_queue_foreach(module->cache, (GFunc)logging_cache_search, (gpointer)&search);
		pthread_mutex_unlock(&(module->cache_mutex));
	}

	return RESOURCED_ERROR_NONE;
}

static int logging_reset(char *name)
{
	/* Table cut using max period */
	time_t curr_time, del_time;
	sqlite3_stmt *stmt = NULL;
	struct logging_module *module;
	char buf[LOGGING_BUF_MAX] = {0, };

	module = logging_find_module(name);

	if (!module) {
		_E("There is no %s module", name);
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	time(&curr_time);

	switch (module->max_period) {
	case ONE_HOUR:
		del_time = curr_time - HOUR_TO_SEC(1);
		break;
	case THREE_HOUR:
		del_time = curr_time - HOUR_TO_SEC(3);
		break;
	case SIX_HOUR:
		del_time = curr_time - HOUR_TO_SEC(6);
		break;
	case TWELVE_HOUR:
		del_time = curr_time - HOUR_TO_SEC(12);
		break;
	case ONE_DAY:
		del_time = curr_time - HOUR_TO_SEC(24);
		break;
	case ONE_WEEK:
		del_time = curr_time - DAY_TO_SEC(7);
		break;
	case ONE_MONTH:
		del_time = curr_time - MONTH_TO_SEC(1);
		break;
	case FOUR_MONTH:
		del_time = curr_time - MONTH_TO_SEC(4);
		break;
	default:
		_E("%s invalid max period", module->name);
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	snprintf(buf, LOGGING_BUF_MAX, DELETE_QUERY_WITH_TIME, name, (int)del_time);

	if (sqlite3_prepare_v2(module->db, buf, read_until_null, &stmt, NULL) != SQLITE_OK) {
		_E("delete %s table failed %s", name, sqlite3_errmsg(module->db));
		sqlite3_finalize(stmt);
		return RESOURCED_ERROR_DB_FAILED;
	}

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		_E("delete %s table failed %s", name, sqlite3_errmsg(module->db));
		sqlite3_finalize(stmt);
		return RESOURCED_ERROR_DB_FAILED;
	}

	sqlite3_finalize(stmt);

	return RESOURCED_ERROR_NONE;
}

static int logging_check_storage_size(const char *db_path)
{
	int ret;
	struct stat db_stat = {0};

	if (!db_path)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	ret = stat(db_path, &db_stat);

	if (ret) {
		_E("Failed to get statistics for %s errno %d",
				db_path, errno);
		return RESOURCED_ERROR_DB_FAILED;
	}

	if (db_stat.st_size >= DB_SIZE_THRESHOLD)
		return RESOURCED_ERROR_FAIL;

	return RESOURCED_ERROR_NONE;
}

static void logging_update(void)
{
	int i, ret;
	sqlite3_stmt *stmt = NULL;
	struct logging_table_form table;
	struct logging_module *module;
	char buf[LOGGING_BUF_MAX] = {0, };

	for (i = 0; i < logging_modules->len; i++) {
		module = g_array_index(logging_modules,
				struct logging_module *, i);

		/* no update when module update func is not registered */
		if (module->func == NULL)
			continue;

		if (module->updated_interval > 0) {
			module->updated_interval -= ONE_MINUTE;
			continue;
		}

		module->updated_interval = module->update_interval;

		snprintf(buf, LOGGING_BUF_MAX, SELECT_QUERY, module->name,
							(int)module->latest_update_time);

		ret = sqlite3_prepare_v2(module->db, buf, read_until_null, &stmt, NULL);
		if (ret != SQLITE_OK) {
			_E("select failed");
			sqlite3_finalize(stmt);
			return;
		}

		do {
			ret = sqlite3_step(stmt);
			switch (ret) {
			case SQLITE_ROW:
				snprintf(table.appid, MAX_APPID_LENGTH, "%s", (char *)sqlite3_column_text(stmt, 0));
				snprintf(table.pkgid, MAX_PKGNAME_LENGTH, "%s", (char *)sqlite3_column_text(stmt, 1));
				table.time = sqlite3_column_int(stmt, 2);
				if (module->latest_update_time < table.time)
					module->latest_update_time = table.time;
				table.data = (char *)sqlite3_column_text(stmt, 3);
				module->func(&table);
				break;
			case SQLITE_DONE:
				break;
			case SQLITE_ERROR:
				_E("select %s table failed %s", module->name, 
									sqlite3_errmsg(module->db));
				/* FALLTHROUGH */
			default:
				sqlite3_finalize(stmt);
				return;
			}
		} while (ret == SQLITE_ROW);

		sqlite3_finalize(stmt);
	}

}

void logging_save_to_storage(int force)
{
	/* Save cache to storage */
	static int index = 0;
	int i, j, len, ret = 0;
	sqlite3_stmt *insert_stmt = NULL;
	sqlite3_stmt *delete_stmt = NULL;
	char buf[LOGGING_BUF_MAX] = {0, };
	struct logging_module *module;
	struct logging_table_form *table;

	for (i = 0; i < logging_modules->len; i++) {
		module = g_array_index(logging_modules, struct logging_module *, i);

		if (!force && module->saved_interval > 0) {
			module->saved_interval -= ONE_MINUTE;
			continue;
		}

		module->saved_interval = module->save_interval;

		/* find q and pop */
		pthread_mutex_lock(&(module->cache_mutex));
		len = g_queue_get_length(module->cache);
		pthread_mutex_unlock(&(module->cache_mutex));

		if (!len) {
			_I("%s cache is empty", module->name);
			continue;
		}

		sqlite3_exec(module->db, "BEGIN;", NULL, NULL, NULL);

		snprintf(buf, LOGGING_BUF_MAX, INSERT_QUERY, module->name);
		ret = sqlite3_prepare_v2(module->db, buf, read_until_null, &insert_stmt, NULL);
		FINALIZE_AND_RETURN_IF(ret != SQLITE_OK, _E, "insert %s table failed %s", module->name, sqlite3_errmsg(module->db));

		snprintf(buf, LOGGING_BUF_MAX, DELETE_QUERY_WITH_DATA, module->name);
		ret = sqlite3_prepare_v2(module->db, buf, read_until_null, &delete_stmt, NULL);
		FINALIZE_AND_RETURN_IF(ret != SQLITE_OK, _E, "insert %s table failed %s", module->name, sqlite3_errmsg(module->db));

		for (j = 0; j < len; j++) {
			pthread_mutex_lock(&(module->cache_mutex));
			table = g_queue_peek_head(module->cache);

			if (table && table->operation == DELETE) {
				sqlite3_reset(delete_stmt);

				ret = sqlite3_bind_text(delete_stmt, 1, table->data, -1, SQLITE_STATIC);
				FINALIZE_AND_RETURN_IF(ret != SQLITE_OK, _SE, "Can not bind data : %s for preparing statement", table->pkgid);

				ret = sqlite3_step(delete_stmt);
				FINALIZE_AND_RETURN_IF(ret != SQLITE_DONE, _E, "delete %s table failed %s", module->name, sqlite3_errmsg(module->db));

			} else {
				/* else if (table->operation == INSERT) */
				sqlite3_reset(insert_stmt);

				ret = sqlite3_bind_text(insert_stmt, 1, table->appid, -1, SQLITE_STATIC);
				FINALIZE_AND_RETURN_IF(ret != SQLITE_OK, _SE, "Can not bind appid : %s for preparing statement", table->appid);

				ret = sqlite3_bind_text(insert_stmt, 2, table->pkgid, -1, SQLITE_STATIC);
				FINALIZE_AND_RETURN_IF(ret != SQLITE_OK, _SE, "Can not bind pkgid : %s for preparing statement", table->pkgid);

				ret = sqlite3_bind_int(insert_stmt, 3, table->time);
				FINALIZE_AND_RETURN_IF(ret != SQLITE_OK, _SE, "Can not bind time : %d for preparing statement", table->time);

				ret = sqlite3_bind_text(insert_stmt, 4, table->data, -1, SQLITE_STATIC);
				FINALIZE_AND_RETURN_IF(ret != SQLITE_OK, _SE, "Can not bind data : %s for preparing statement", table->data);

				ret = sqlite3_bind_int(insert_stmt, 5, index++);
				FINALIZE_AND_RETURN_IF(ret != SQLITE_OK, _SE, "Can not bind index : %d for preparing statement", index);

				ret = sqlite3_step(insert_stmt);
				FINALIZE_AND_RETURN_IF(ret != SQLITE_DONE, _E, "insert %s table failed %s", module->name, sqlite3_errmsg(module->db));
			}

			table = g_queue_pop_head(module->cache);
			free(table);
			pthread_mutex_unlock(&(module->cache_mutex));
		}

		sqlite3_exec(module->db, "COMMIT;", NULL, NULL, NULL);
		sqlite3_finalize(insert_stmt);
		sqlite3_finalize(delete_stmt);
	}

	for (i = 0; i < logging_modules->len; i++) {
		module = g_array_index(logging_modules, struct logging_module *, i);

		/* Check storage limitation by maximum period and storage size (50MiB) */
		if (logging_check_storage_size(module->db_path) == RESOURCED_ERROR_FAIL) {
			logging_reset(module->name);
			sqlite3_exec(module->db, "VACUUM;", NULL, NULL, NULL);
		}
	}
}

static void *logging_data_thread_main(void *arg)
{
	int ret = 0;

	setpriority(PRIO_PROCESS, 0, LOGGING_PTIORITY);

	while (1) {
		/*
		 * When signalled by main thread,
		 * it starts logging_pthread().
		 */
		ret = pthread_mutex_lock(&logging_data_mutex);
		if (ret) {
			_E("logging data thread::pthread_mutex_lock() failed, %d", ret);
			break;
		}

		ret = pthread_cond_wait(&logging_data_cond, &logging_data_mutex);
		if (ret) {
			_E("logging data thread::pthread_cond_wait() failed, %d", ret);
			ret = pthread_mutex_unlock(&logging_data_mutex);
			if (ret)
				_E("logging data thread::pthread_mutex_lock() failed, %d", ret);
			break;
		}

		logging_save_to_storage(false);

		ret = pthread_mutex_unlock(&logging_data_mutex);
		if (ret) {
			_E("logging data thread::pthread_mutex_unlock() failed, %d", ret);
			break;
		}
	}

	/* Now our thread finishes - cleanup TID */
	logging_data_thread = 0;

	return NULL;
}

static Eina_Bool logging_send_signal_to_data(void *data)
{
	int ret;

	_D("logging timer callback function start");

	/* signal to logging data thread for start logging */
	ret = pthread_mutex_trylock(&logging_data_mutex);

	if (ret)
		_E("pthread_mutex_trylock fail : %d, errno : %d", ret, errno);
	else {
		pthread_cond_signal(&logging_data_cond);
		_I("send signal to logging data thread");
		pthread_mutex_unlock(&logging_data_mutex);
	}

	return ECORE_CALLBACK_RENEW;
}

static int logging_start(void *data)
{
	return RESOURCED_ERROR_NONE;
}

static void *logging_update_thread_main(void *arg)
{
	int ret = 0;

	setpriority(PRIO_PROCESS, 0, LOGGING_PTIORITY);

	while (1) {
		/*
		 * it starts fuction of registered module.
		 */
		ret = pthread_mutex_lock(&logging_update_mutex);
		if (ret) {
			_E("logging update thread::pthread_mutex_lock() failed, %d", ret);
			break;
		}

		ret = pthread_cond_wait(&logging_update_cond, &logging_update_mutex);
		if (ret) {
			_E("logging update thread::pthread_cond_wait() failed, %d", ret);
			ret = pthread_mutex_unlock(&logging_update_mutex);
			if (ret)
				_E("logging update thread::pthread_mutex_lock() failed, %d", ret);
			break;
		}

		logging_update();

		ret = pthread_mutex_unlock(&logging_update_mutex);
		if (ret) {
			_E("logging update thread::pthread_mutex_unlock() failed, %d", ret);
			break;
		}
	}

	/* Now our thread finishes - cleanup TID */
	logging_update_thread = 0;

	return NULL;
}

static Eina_Bool logging_send_signal_to_update(void *data)
{
	int ret;
	DIR *dir_info;

	dir_info = opendir(LOGGING_FILE_PATH);

	if (dir_info)
		closedir(dir_info);
	else {
		_E("There is no %s", LOGGING_FILE_PATH);
		ret = mkdir(LOGGING_FILE_PATH, S_IRWXU | S_IRWXG | S_IROTH);

		if (ret) {
			_E("mkdir failed %s", LOGGING_FILE_PATH);
			return ECORE_CALLBACK_RENEW;
		}
	}

	_D("logging timer callback function start");

	/* signal to logging update thread for start update */
	ret = pthread_mutex_trylock(&logging_update_mutex);

	if (ret)
		_E("pthread_mutex_trylock fail : %d, errno : %d", ret, errno);
	else {
		pthread_cond_signal(&logging_update_cond);
		_I("send signal to logging update thread");
		pthread_mutex_unlock(&logging_update_mutex);
	}

	return ECORE_CALLBACK_RENEW;
}

static int logging_thread_create(void)
{
	int ret = RESOURCED_ERROR_NONE;

	/* initialize logging_data_thread */
	if (logging_data_thread) {
		_I("logging data thread %u already created", (unsigned)logging_data_thread);
	} else {
		ret = pthread_create(&logging_data_thread, NULL,
							(void *)logging_data_thread_main, (void *)NULL);
		if (ret) {
			_E("pthread creation for logging_data_thread_main failed, %d\n", ret);
			logging_data_thread = 0;
		} else {
			_D("pthread creation for logging data success");
			pthread_detach(logging_data_thread);
		}
	}

	/* initialize logging_update_thread */
	if (logging_update_thread) {
		_I("logging update thread %u already created", (unsigned)logging_update_thread);
	} else {
		ret = pthread_create(&logging_update_thread, NULL,
							(void *)logging_update_thread_main, (void *)NULL);
		if (ret) {
			_E("pthread creation for logging_update_thread_main failed, %d\n", ret);
			logging_update_thread = 0;
		} else {
			_D("pthread creation for logging update success");
			pthread_detach(logging_update_thread);
		}
	}
	return ret;
}

static int logging_poweroff(void *data)
{
	/* flush module cache */
	logging_save_to_storage(true);
	return RESOURCED_ERROR_NONE;
}

int logging_init(void *data)
{
	int ret = RESOURCED_ERROR_NONE;
	char *err = NULL;

	_D("logging_init start");

	ret = logging_thread_create();
	if (ret) {
		_E("logging thread create failed");
		return RESOURCED_ERROR_FAIL;
	}

	/* module array create */
	logging_modules = g_array_new(false, false, sizeof(struct logging_module *));

	if (logging_modules == NULL) {
		_E("logging_modules_array create failed");
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	/* DB create */
	if (sqlite3_open(LOGGING_DB_FILE_NAME, &logging_db) != SQLITE_OK) {
		_E("%s DB open failed (%s)", LOGGING_DB_FILE_NAME, sqlite3_errmsg(logging_db));
		return RESOURCED_ERROR_FAIL;
	}

	ret = sqlite3_exec(logging_db, "PRAGMA locking_mode = NORMAL", 0, 0, 0);
	if (ret != SQLITE_OK) {
		_E("Can't set locking mode %s", sqlite3_errmsg(logging_db));
		_E("Skip set busy handler.");
		return RESOURCED_ERROR_DB_FAILED;
	}

	/* Set how many times we'll repeat our attempts for sqlite_step */
	if (sqlite3_busy_handler(logging_db, logging_db_busy, NULL) != SQLITE_OK) {
		_E("Couldn't set busy handler!");
	}

	options = leveldb_options_create();
	leveldb_options_set_create_if_missing(options, 1);
	logging_leveldb = leveldb_open(options, LOGGING_LEVEL_DB_FILE_NAME, &err);
	if (err != NULL) {
		_E("Failed to open leveldb");
		return RESOURCED_ERROR_DB_FAILED;
	}
	free(err);
	err = NULL;
	roptions = leveldb_readoptions_create();
	woptions = leveldb_writeoptions_create();
	leveldb_writeoptions_set_sync(woptions, 1);

	register_notifier(RESOURCED_NOTIFIER_LOGGING_START, logging_start);
	register_notifier(RESOURCED_NOTIFIER_POWER_OFF, logging_poweroff);

	if (logging_data_timer == NULL) {
		_D("logging data timer start");
		logging_data_timer =
			ecore_timer_add(ONE_MINUTE, logging_send_signal_to_data, (void *)NULL);
	}

	if (logging_update_timer == NULL) {
		_D("logging data timer start");
		logging_update_timer =
			ecore_timer_add(ONE_MINUTE, logging_send_signal_to_update, (void *)NULL);
	}

	return RESOURCED_ERROR_NONE;
}

int logging_exit(void *data)
{
	int i;
	struct logging_module *module;

	/* update timer delete */
	ecore_timer_del(logging_update_timer);
	logging_update_timer = NULL;

	unregister_notifier(RESOURCED_NOTIFIER_LOGGING_START, logging_start);
	unregister_notifier(RESOURCED_NOTIFIER_POWER_OFF, logging_poweroff);

	/* flush module cache */
	logging_save_to_storage(true);

	/* logging_modules array deinitialize */
	for (i = 0; i < logging_modules->len; i++) {
		module = g_array_index(logging_modules,
				struct logging_module *, i);
		free(module->name);
		free(module->db_path);
		g_queue_free(module->cache);

		/* DB close */
		sqlite3_close(module->db);
	}

	g_array_free(logging_modules, true);

	/* DB close */
	sqlite3_close(logging_db);
	leveldb_close(logging_leveldb);
	_D("logging_exit");

	return RESOURCED_ERROR_NONE;
}
