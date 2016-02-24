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
 * @file logging-memory.c
 *
 * @desc start memory logging system for resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <glib.h>
#include <Ecore.h>

#include "resourced.h"
#include "trace.h"
#include "module.h"
#include "macro.h"
#include "notifier.h"
#include "proc-common.h"
#include "heart.h"
#include "logging.h"
#include "logging-common.h"
#include "edbus-handler.h"
#include "helper.h"

#include <sqlite3.h>
#include <time.h>

#define MEM_NAME					"memory"
#define MEM_DATA_MAX					1024
#define MEM_ARRAY_MAX					24
#define MEM_FILE_SEPERATOR				'@'

#define LOGGING_MEMORY_INTERVAL				3600  /* 1 hour */
#define LOGGING_MEMORY_FILE				HEART_FILE_PATH"/.memory.dat"

struct logging_memory_info {
	unsigned int max_pss;
	unsigned int avg_pss;
	unsigned int max_uss;
	unsigned int avg_uss;
};

struct logging_memory_table {
	char appid[MAX_APPID_LENGTH];
	char pkgid[MAX_PKGNAME_LENGTH];
	unsigned int total_pss;
	unsigned int max_pss;
	unsigned int latest_pss;
	unsigned int total_uss;
	unsigned int max_uss;
	unsigned int latest_uss;
	unsigned int count;
	int renew;
	GArray *memory_info;
};

static GHashTable *logging_memory_app_list;
static pthread_mutex_t logging_memory_mutex = PTHREAD_MUTEX_INITIALIZER;
static time_t last_file_update_time;
static Ecore_Timer *logging_memory_update_timer = NULL;
static GArray *send;

struct logging_memory_table *logging_memory_find_info(GHashTable *hashtable, char *appid)
{
	int ret;
	struct logging_memory_table *table;

	ret = pthread_mutex_lock(&logging_memory_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return NULL;
	}

	table = g_hash_table_lookup(hashtable, (gconstpointer)appid);

	ret = pthread_mutex_unlock(&logging_memory_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return NULL;
	}

	return table;
}

static void logging_memory_free_value(gpointer value)
{
	struct logging_memory_table * table = (struct logging_memory_table *)value;

	if (!table)
		return;
	free(table);
}

static int logging_memory_read_length(char *buf, int count)
{
	int i, find = 0;
	int len = strlen(buf);

	for (i = 0; i < len; i++) {
		if (buf[i] == ' ')
			find++;

		if (find == count)
			return i+1;
	}

	return RESOURCED_ERROR_FAIL;
}

static int logging_memory_read_from_file(GHashTable *hashtable, char *filename)
{
	int i, len, ret, result;
	unsigned int total_pss, max_pss, avg_pss;
	unsigned int total_uss, max_uss, avg_uss;
	unsigned int count;
	FILE *fp;
	struct logging_memory_table *table;
	char appid[MAX_APPID_LENGTH] = {0, };
	char pkgid[MAX_PKGNAME_LENGTH] = {0, };
	char buf[MEM_DATA_MAX] = {0, };

	fp = fopen(filename, "r");

	if (!fp) {
		_E("%s fopen failed %d", filename, errno);
		return RESOURCED_ERROR_FAIL;
	}

	while (fgets(buf, MEM_DATA_MAX, fp)) {
		table = malloc(sizeof(struct logging_memory_table));

		if (!table) {
			_E("malloc failed");
			fclose(fp);
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}

		/* make return values */
		result = sscanf(buf, "%s %s %u %u %u %u %u ", appid, pkgid,
				&total_pss, &max_pss, &total_uss, &max_uss, &count);

		if (result < 0) {
			_E("sscanf failed");
			free(table);
			fclose(fp);
			return RESOURCED_ERROR_FAIL;
		}

		if (snprintf(table->appid, MAX_APPID_LENGTH, "%s", appid) < 0) {
			_E("snprintf failed");
			free(table);
			fclose(fp);
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}

		if (snprintf(table->pkgid, MAX_PKGNAME_LENGTH, "%s", pkgid) < 0) {
			_E("snprintf failed");
			free(table);
			fclose(fp);
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}

		len = logging_memory_read_length(buf, 7);

		if (len < 0) {
			_E("7 space read length failed %s", buf);
			free(table);
			fclose(fp);
			return RESOURCED_ERROR_FAIL;
		}

		table->total_pss = total_pss;
		table->max_pss = max_pss;
		table->latest_pss = 0;
		table->total_uss = total_uss;
		table->max_uss = max_uss;
		table->latest_uss = 0;
		table->count = count;
		table->memory_info =
			g_array_new(false, false, sizeof(struct logging_memory_info *));

		for (i = 0; i < MEM_ARRAY_MAX; i++) {
			struct logging_memory_info *mi;

			result = sscanf(buf + len, "%u %u %u %u ",
					&max_pss, &avg_pss, &max_uss, &avg_uss);

			if (result <= 0) {
				_E("file read fail %s", buf + len);
				g_array_free(table->memory_info, true);
				free(table);
				fclose(fp);
				return RESOURCED_ERROR_FAIL;
			}

			mi = malloc(sizeof(struct logging_memory_info));

			if (!mi) {
				_E("malloc failed");
				g_array_free(table->memory_info, true);
				free(table);
				fclose(fp);
				return RESOURCED_ERROR_OUT_OF_MEMORY;
			}

			mi->max_pss = max_pss;
			mi->avg_pss = avg_pss;
			mi->max_uss = max_uss;
			mi->avg_uss = avg_uss;

			len += logging_memory_read_length(buf + len, 4);

			g_array_append_val(table->memory_info, mi);
		}

		ret = pthread_mutex_lock(&logging_memory_mutex);
		if (ret) {
			_E("pthread_mutex_lock() failed, %d", ret);
			g_array_free(table->memory_info, true);
			free(table);
			fclose(fp);
			return RESOURCED_ERROR_FAIL;
		}

		g_hash_table_insert(hashtable, (gpointer)table->appid, (gpointer)table);

		ret = pthread_mutex_unlock(&logging_memory_mutex);
		if (ret) {
			_E("pthread_mutex_unlock() failed, %d", ret);
			fclose(fp);
			return RESOURCED_ERROR_FAIL;
		}
	}

	fclose(fp);

	return RESOURCED_ERROR_NONE;
}

static int logging_memory_save_to_file(GHashTable *hashtable, char *filename)
{
	int i, len, ret, array_len;
	gpointer value;
	gpointer key;
	GHashTableIter iter;
	struct logging_memory_table *table;
	FILE *fp;
	char buf[MEM_DATA_MAX] = {0, };

	fp = fopen(filename, "w");
	if (!fp) {
		_E("%s fopen failed %d", filename, errno);
		return RESOURCED_ERROR_FAIL;
	}

	ret = pthread_mutex_lock(&logging_memory_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	g_hash_table_iter_init(&iter, hashtable);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		table = (struct logging_memory_table *)value;

		len = snprintf(buf, MEM_DATA_MAX, "%s %s %u %u %u %u %u ",
				table->appid, table->pkgid,
				table->total_pss, table->max_pss,
				table->total_uss, table->max_uss,
				table->count);

		array_len = table->memory_info->len;

		for (i = 0; i < MEM_ARRAY_MAX; i++) {
			struct logging_memory_info *mi;

			if (array_len <= i)
				len += snprintf(buf + len, MEM_DATA_MAX - len, "0 0 0 0 ");
			else {
				mi = g_array_index(table->memory_info, struct logging_memory_info *, i);

				len += snprintf(buf + len, MEM_DATA_MAX - len, "%u %u %u %u ",
						mi->max_pss, mi->avg_pss,
						mi->max_uss, mi->avg_uss);
			}
		}

		len += snprintf(buf + len, MEM_DATA_MAX - len, "%c\n", MEM_FILE_SEPERATOR);

		fputs(buf, fp);
	}

	ret = pthread_mutex_unlock(&logging_memory_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	fclose(fp);

	return RESOURCED_ERROR_NONE;
}

void logging_memory_fill_array(struct logging_table_form *data)
{
	int i;
	unsigned int pss, uss;
	struct logging_memory_data *md = NULL;

	_E("data : %s %s %d %s", data->appid, data->pkgid, (int)data->time, data->data);

	for (i = 0; i < send->len; i++) {
		struct logging_memory_data *loop;
		loop = g_array_index(send, struct logging_memory_data *, i);

		if (!strcmp(loop->appid, data->appid)) {
			md = loop;
			break;
		}
	}

	if (sscanf(data->data, "%u %u", &pss, &uss) < 0) {
		_E("sscanf failed");
		return;
	}

	if (!md) {
		md = malloc(sizeof(struct logging_memory_data));

		if (!md) {
			_E("malloc failed");
			return;
		}

		if (snprintf(md->appid, MAX_APPID_LENGTH, "%s", data->appid) < 0) {
			_E("snprintf failed");
			free(md);
			return;
		}

		if (snprintf(md->pkgid, MAX_PKGNAME_LENGTH, "%s", data->pkgid) < 0) {
			_E("snprintf failed");
			free(md);
			return;
		}

		md->max_pss = pss;
		md->avg_pss = pss;
		md->max_uss = uss;
		md->avg_uss = uss;

		g_array_append_val(send, md);
	} else {
		if (md->max_pss < pss)
			md->max_pss = pss;

		md->avg_pss = (md->avg_pss + pss) / 2;

		if (md->max_uss < uss)
			md->max_uss = uss;

		md->avg_uss = (md->avg_uss + uss) / 2;
	}
}

int logging_memory_get_foreach(GArray *arrays, enum logging_data_period period)
{
	int ret;
	time_t curr_time = time(NULL);

	switch (period) {
	case LOGGING_LATEST:
		break;
	case LOGGING_3HOUR:
		curr_time -= 10800;
		break;
	case LOGGING_6HOUR:
		curr_time -= 21600;
		break;
	case LOGGING_12HOUR:
		curr_time -= 43200;
		break;
	case LOGGING_24HOUR:
		curr_time -= 86400;
		break;
	default:
		_E("Wrong message arguments! %d", period);
		return RESOURCED_ERROR_FAIL;
	}

	send = arrays;

	ret = logging_read_foreach(MEM_NAME, NULL, NULL, curr_time, 0, logging_memory_fill_array);

	if (ret) {
		_E("failed logging_read_foreach");
		return RESOURCED_ERROR_FAIL;
	}

	send = NULL;

	return RESOURCED_ERROR_NONE;
}

int logging_memory_get_query(GArray *arrays, enum logging_data_period period)
{
	int count, result;
	time_t curr_time = time(NULL);
	sqlite3 *logging_db;
	sqlite3_stmt *stmt = NULL;
	gpointer value;
	gpointer key;
	char *data;
	unsigned int pss, uss;
	GHashTableIter h_iter;
	struct logging_memory_data *md;
	struct logging_memory_table *table;
	char buf[MEM_DATA_MAX] = {0, };

	switch (period) {
	case LOGGING_LATEST:
		break;
	case LOGGING_3HOUR:
		curr_time -= 10800;
		break;
	case LOGGING_6HOUR:
		curr_time -= 21600;
		break;
	case LOGGING_12HOUR:
		curr_time -= 43200;
		break;
	case LOGGING_24HOUR:
		curr_time -= 86400;
		break;
	default:
		_E("Wrong message arguments! %d", period);
		return RESOURCED_ERROR_FAIL;
	}

	result = sqlite3_open(LOGGING_DB_FILE_NAME, &logging_db);
	if (result != SQLITE_OK) {
		_E("Can't open database %s: %s\n", MEM_NAME,
				sqlite3_errmsg(logging_db));
		sqlite3_close(logging_db);
		return RESOURCED_ERROR_FAIL;
	}

	g_hash_table_iter_init(&h_iter, logging_memory_app_list);

	while (g_hash_table_iter_next(&h_iter, &key, &value)) {
		table = (struct logging_memory_table *)value;

		md = malloc(sizeof(struct logging_memory_data));

		if (!md) {
			_E("malloc failed");
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}

		if (snprintf(md->appid, MAX_APPID_LENGTH, "%s", table->appid) < 0) {
			_E("snprintf failed");
			free(md);
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}

		if (snprintf(md->pkgid, MAX_PKGNAME_LENGTH,  "%s", table->pkgid) < 0) {
			_E("asprintf failed");
			free(md);
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}

		count = 0;
		md->max_pss = 0;
		md->avg_pss = 0;
		md->max_uss = 0;
		md->avg_uss = 0;

		snprintf(buf, MEM_DATA_MAX, "select * from memory where appid = \'%s\' AND time > %d",
				table->appid, (int)curr_time);

		/* search from db */
		if (sqlite3_prepare_v2(logging_db, buf, -1, &stmt, NULL) != SQLITE_OK) {
			_E("select failed");
			free(md);
			sqlite3_finalize(stmt);
			return RESOURCED_ERROR_DB_FAILED;
		}

		do {
			result = sqlite3_step(stmt);
			switch (result) {
			case SQLITE_ROW:
				data = (char *)sqlite3_column_text(stmt, 3);

				if (sscanf(data, "%u %u", &pss, &uss) < 0) {
					_E("sscanf failed");
					free(md);
					sqlite3_finalize(stmt);
					return RESOURCED_ERROR_DB_FAILED;
				}

				if (md->max_pss < pss)
					md->max_pss = pss;

				if (md->max_uss < uss)
					md->max_uss = uss;

				md->avg_pss += pss;
				md->avg_uss += uss;
				count++;
				break;
			case SQLITE_DONE:
				break;
			case SQLITE_ERROR:
				_E("select %s table failed %s",
						MEM_NAME, sqlite3_errmsg(logging_db));
				/* FALLTHROUGH */
			default:
				free(md);
				sqlite3_finalize(stmt);
				return RESOURCED_ERROR_DB_FAILED;
			}
		} while (result == SQLITE_ROW);
		if (count) {
			md->avg_pss /= count;
			md->avg_uss /= count;
		}

		g_array_append_val(arrays, md);
	}

	sqlite3_finalize(stmt);

	sqlite3_close(logging_db);

	return RESOURCED_ERROR_NONE;
}

struct logging_memory_data *logging_memory_get_data(char *appid, enum logging_data_period period)
{
	int index, i, ret, count, time;
	unsigned int max_pss = 0, avg_pss = 0, total_pss = 0;
	unsigned int max_uss = 0, avg_uss = 0, total_uss = 0;
	struct logging_memory_table *table;
	struct logging_memory_data *md;

	if (!appid) {
		_E("Wrong message arguments!");
		return NULL;
	}

	switch (period) {
	case LOGGING_LATEST:
		index = 0;
		break;
	case LOGGING_3HOUR:
		index = 3;
		break;
	case LOGGING_6HOUR:
		index = 6;
		break;
	case LOGGING_12HOUR:
		index = 12;
		break;
	case LOGGING_24HOUR:
		index = 24;
		break;
	default:
		_E("Wrong message arguments! %d", period);
		return NULL;
	}

	/* read from hash and make reply hash */
	/* loop in file read and make reply */
	ret = pthread_mutex_lock(&logging_memory_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return NULL;
	}

	table = g_hash_table_lookup(logging_memory_app_list, (gconstpointer)appid);
	if (!table) {
		goto unlock_exit;
	}
	md = malloc(sizeof(struct logging_memory_data));
	if (!md) {
		_E("malloc failed");
		goto unlock_exit;
	}

	if (snprintf(md->appid, MAX_APPID_LENGTH, "%s", table->appid) < 0) {
		_E("snprintf failed");
		free(md);
		goto unlock_exit;
	}

	if (snprintf(md->pkgid, MAX_PKGNAME_LENGTH, "%s", table->pkgid) < 0) {
		_E("snprintf failed");
		free(md);
		goto unlock_exit;
	}

	count = table->count;
	total_pss = table->total_pss;
	max_pss = table->max_pss;
	avg_pss = total_pss / count;
	total_uss = table->total_uss;
	max_uss = table->max_uss;
	avg_uss = total_uss / count;
	time = 1;

	if (period != LOGGING_LATEST) {
		i = table->memory_info->len;

		if (i < index)
			index = i;

		for (i = 0; i < index; i++) {
			struct logging_memory_info *mi;

			mi = g_array_index(table->memory_info, struct logging_memory_info *, i);

			if (mi->max_pss || mi->avg_pss ||
					mi->max_uss || mi->avg_uss)
				time++;

			if (max_pss < mi->max_pss)
				max_pss = mi->max_pss;

			avg_pss += mi->avg_pss;

			if (max_uss < mi->max_uss)
				max_uss = mi->max_uss;

			avg_uss += mi->avg_uss;
		}

		if (time) {
			avg_pss /= time;
			avg_uss /= time;
		}
	}

	md->max_pss = max_pss;
	md->avg_pss = avg_pss;
	md->max_uss = max_uss;
	md->avg_uss = avg_uss;

	ret = pthread_mutex_unlock(&logging_memory_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		free(md);
		return NULL;
	}
	return md;

unlock_exit:
	ret = pthread_mutex_unlock(&logging_memory_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return NULL;
	}
	return NULL;
}

int logging_memory_get_latest_data(char *appid, unsigned int *pss, unsigned int *uss)
{
	int ret;
	char *data;
	struct logging_memory_table *table;

	if (!appid) {
		_E("Wrong message arguments!");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	/* read from hash and make reply hash */
	/* loop in file read and make reply */
	ret = pthread_mutex_lock(&logging_memory_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}

	table = g_hash_table_lookup(logging_memory_app_list, (gconstpointer)appid);
	if (!table) {
		_E("NOT found in table %s", appid);

		ret = logging_get_latest_in_cache(MEM_NAME, appid, &data);

		if (ret) {
			_E("logging_get_latest_in_cache failed");

			ret = pthread_mutex_unlock(&logging_memory_mutex);
			if (ret) {
				_E("pthread_mutex_unlock() failed, %d", ret);
				return RESOURCED_ERROR_FAIL;
			}
			return RESOURCED_ERROR_FAIL;
		}

		if (sscanf(data, "%u %u", pss, uss) < 0) {
			_E("sscanf failed");
			ret = pthread_mutex_unlock(&logging_memory_mutex);
			if (ret) {
				_E("pthread_mutex_unlock() failed, %d", ret);
				return RESOURCED_ERROR_FAIL;
			}
			return RESOURCED_ERROR_FAIL;
		}

		ret = pthread_mutex_unlock(&logging_memory_mutex);
		if (ret) {
			_E("pthread_mutex_unlock() failed, %d", ret);
			return RESOURCED_ERROR_FAIL;
		}
		return RESOURCED_ERROR_NONE;
	}

	if (table->latest_pss || table->latest_uss) {
		*pss = table->latest_pss;
		*uss = table->latest_uss;
	} else {
		ret = logging_get_latest_in_cache(MEM_NAME, appid, &data);

		if (ret) {
			_E("logging_get_latest_in_cache failed");
			ret = pthread_mutex_unlock(&logging_memory_mutex);
			if (ret) {
				_E("pthread_mutex_unlock() failed, %d", ret);
				return RESOURCED_ERROR_FAIL;
			}
			return RESOURCED_ERROR_FAIL;
		}

		if (sscanf(data, "%u %u", pss, uss) < 0) {
			_E("sscanf failed");
			ret = pthread_mutex_unlock(&logging_memory_mutex);
			if (ret) {
				_E("pthread_mutex_unlock() failed, %d", ret);
				return RESOURCED_ERROR_FAIL;
			}
			return RESOURCED_ERROR_FAIL;
		}
	}

	ret = pthread_mutex_unlock(&logging_memory_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}

	return RESOURCED_ERROR_NONE;
}

int logging_memory_get_table(GArray *arrays, enum logging_data_period period)
{
	int index, i, ret, count, time;
	gpointer value;
	gpointer key;
	unsigned int max_pss = 0, avg_pss = 0, total_pss = 0;
	unsigned int max_uss = 0, avg_uss = 0, total_uss = 0;
	GHashTableIter h_iter;
	struct logging_memory_table *table;
	struct logging_memory_data *md;

	switch (period) {
	case LOGGING_LATEST:
		index = 0;
		break;
	case LOGGING_3HOUR:
		index = 3;
		break;
	case LOGGING_6HOUR:
		index = 6;
		break;
	case LOGGING_12HOUR:
		index = 12;
		break;
	case LOGGING_24HOUR:
		index = 24;
		break;
	default:
		_E("Wrong message arguments! %d", period);
		return RESOURCED_ERROR_FAIL;
	}

	/* read from hash and make reply hash */
	/* loop in file read and make reply */
	ret = pthread_mutex_lock(&logging_memory_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}

	g_hash_table_iter_init(&h_iter, logging_memory_app_list);

	while (g_hash_table_iter_next(&h_iter, &key, &value)) {
		table = (struct logging_memory_table *)value;

		md = malloc(sizeof(struct logging_memory_data));
		if (!md) {
			_E("malloc failed");
			goto unlock_out_of_memory_exit;
		}

		if (snprintf(md->appid, MAX_APPID_LENGTH, "%s", table->appid) < 0) {
			_E("snprintf failed");
			free(md);
			goto unlock_out_of_memory_exit;
		}

		if (snprintf(md->pkgid, MAX_PKGNAME_LENGTH, "%s", table->pkgid) < 0) {
			_E("snprintf failed");
			free(md);
			goto unlock_out_of_memory_exit;
		}

		count = table->count;
		total_pss = table->total_pss;
		max_pss = table->max_pss;
		avg_pss = total_pss / count;
		total_uss = table->total_uss;
		max_uss = table->max_uss;
		avg_uss = total_uss / count;
		time = 1;

		if (period != LOGGING_LATEST) {
			i = table->memory_info->len;

			if (i < index)
				index = i;

			for (i = 0; i < index; i++) {
				struct logging_memory_info *mi;

				mi = g_array_index(table->memory_info, struct logging_memory_info *, i);

				if (mi->max_pss || mi->avg_pss ||
						mi->max_uss || mi->avg_uss)
					time++;

				if (max_pss < mi->max_pss)
					max_pss = mi->max_pss;

				avg_pss += mi->avg_pss;

				if (max_uss < mi->max_uss)
					max_uss = mi->max_uss;

				avg_uss += mi->avg_uss;
			}

			if (time) {
				avg_pss /= time;
				avg_uss /= time;
			}
		}

		md->max_pss = max_pss;
		md->avg_pss = avg_pss;
		md->max_uss = max_uss;
		md->avg_uss = avg_uss;

		g_array_append_val(arrays, md);
	}

	ret = pthread_mutex_unlock(&logging_memory_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}

	return RESOURCED_ERROR_NONE;

unlock_out_of_memory_exit:
	ret = pthread_mutex_unlock(&logging_memory_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_OUT_OF_MEMORY;
}

int logging_memory_save(void)
{
	return logging_memory_save_to_file(logging_memory_app_list, LOGGING_MEMORY_FILE);
}

void logging_memory_update(struct logging_table_form *data)
{
	int ret;
	unsigned int pss, uss;
	time_t curr_time = logging_get_time(CLOCK_BOOTTIME);
	struct logging_memory_table *find;
	struct logging_memory_table *table;

	if (sscanf(data->data, "%u %u", &pss, &uss) < 0) {
		_E("sscanf failed");
		return;
	}

	find = logging_memory_find_info(logging_memory_app_list, data->appid);

	/* get last node and update it & re-insert to hash table  */
	/* update */
	if (find) {
		ret = pthread_mutex_lock(&logging_memory_mutex);
		if (ret) {
			_E("pthread_mutex_lock() failed, %d", ret);
			return;
		}

		if (find->renew) {
			find->count = 0;
			find->max_pss = 0;
			find->total_pss = 0;
			find->max_uss = 0;
			find->total_uss = 0;
			find->renew = 0;
		}

		find->total_pss += pss;

		if (find->max_pss < pss)
			find->max_pss = pss;

		find->latest_pss = pss;

		find->total_uss += uss;

		if (find->max_uss < uss)
			find->max_uss = uss;

		find->latest_uss = uss;

		find->count++;

		table = find;

		ret = pthread_mutex_unlock(&logging_memory_mutex);
		if (ret) {
			_E("pthread_mutex_unlock() failed, %d", ret);
			return;
		}
	} else {
		table = malloc(sizeof(struct logging_memory_table));

		if (!table) {
			_E("malloc failed");
			return;
		}

		if (snprintf(table->appid, MAX_APPID_LENGTH, "%s", data->appid) < 0) {
			free(table);
			_E("snprintf failed");
			return;
		}

		if (snprintf(table->pkgid, MAX_PKGNAME_LENGTH, "%s", data->pkgid) < 0) {
			free(table);
			_E("snprintf failed");
			return;
		}

		table->memory_info =
			g_array_new(false, false, sizeof(struct logging_memory_info *));

		table->total_pss = pss;

		table->max_pss = pss;

		table->latest_pss = pss;

		table->total_uss = uss;

		table->max_uss = uss;

		table->latest_uss = uss;

		table->count = 1;

		ret = pthread_mutex_lock(&logging_memory_mutex);
		if (ret) {
			free(table);
			_E("pthread_mutex_lock() failed, %d", ret);
			return;
		}

		g_hash_table_insert(logging_memory_app_list, (gpointer)table->appid, (gpointer)table);

		ret = pthread_mutex_unlock(&logging_memory_mutex);
		if (ret) {
			_E("pthread_mutex_unlock() failed, %d", ret);
			return;
		}
	}

	if (last_file_update_time + LOGGING_MEMORY_INTERVAL < curr_time) {
		/* all hash table update and make new array */
		gpointer value;
		gpointer key;
		GHashTableIter iter;
		struct logging_memory_table *search;
		struct logging_memory_info *new_memory_info;

		ret = pthread_mutex_lock(&logging_memory_mutex);
		if (ret) {
			_E("pthread_mutex_lock() failed, %d", ret);
			return;
		}

		g_hash_table_iter_init(&iter, logging_memory_app_list);

		while (g_hash_table_iter_next(&iter, &key, &value)) {
			search = (struct logging_memory_table *)value;

			new_memory_info = malloc(sizeof(struct logging_memory_info));

			if (!new_memory_info) {
				ret = pthread_mutex_unlock(&logging_memory_mutex);
				if (ret) {
					_E("pthread_mutex_lock() failed, %d", ret);
					return;
				}
				_E("malloc failed");
				return;
			}

			/* make new array node */
			new_memory_info->max_pss = search->max_pss;

			if (search->count)
				new_memory_info->avg_pss = search->total_pss / search->count;
			else
				new_memory_info->avg_pss = search->total_pss;

			new_memory_info->max_uss = search->max_uss;

			if (search->count)
				new_memory_info->avg_uss = search->total_uss / search->count;
			else
				new_memory_info->avg_uss = search->total_uss;

			search->renew = 1;

			/* hashtable sliding : remove last node and make new one */
			g_array_remove_index(search->memory_info, MEM_ARRAY_MAX-1);
			g_array_prepend_val(search->memory_info, new_memory_info);
		}

		ret = pthread_mutex_unlock(&logging_memory_mutex);
		if (ret) {
			_E("pthread_mutex_unlock() failed, %d", ret);
			return;
		}
		/* rewrite hashtable list file */
		ret = logging_memory_save_to_file(logging_memory_app_list, LOGGING_MEMORY_FILE);
		if (ret) {
			_E("save to file failed");
			return;
		}

		last_file_update_time = curr_time;
	}
}

static int logging_memory_write(char *appid, char *pkgid, struct proc_status *p_data)
{
	int ret;
	unsigned int pss = 0, uss = 0;
	char info[MEM_DATA_MAX];

	/* For write to data crud during period */
	/* write memory usage in proc_list */

	ret = smaps_helper_get_pss(p_data->pid, &pss, &uss);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("pid(%d) smaps_helper_get_pss failed %d", p_data->pid, ret);
		return ret;
	}

	snprintf(info, sizeof(info), "%u %u", pss, uss);

	ret = logging_write(MEM_NAME, appid, pkgid, time(NULL), info);

	if (ret)
		_E("logging_write failed %d", ret);

	return ret;
}

static int logging_memory_state_cb(void *data)
{
	int ret;
	char *appid, *pkgid;
	struct proc_status *ps = (struct proc_status *)data;

	ret = proc_get_id_info(ps, &appid, &pkgid);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to proc_get_id_info");
		return ret;
	}

	logging_memory_write(appid, pkgid, ps);

	return RESOURCED_ERROR_NONE;
}

static Eina_Bool logging_memory_notify(void *data)
{
	resourced_notify(RESOURCED_NOTIFIER_LOGGING_START, NULL);

	return ECORE_CALLBACK_RENEW;
}

int logging_memory_init(void *data)
{
	int ret;

	ret = logging_module_init(MEM_NAME, ONE_HOUR, TEN_MINUTE, logging_memory_update, TEN_MINUTE);

	if (ret != RESOURCED_ERROR_NONE) {
		_E("logging module init failed");
		return RESOURCED_ERROR_FAIL;
	}

	ret = smaps_helper_init();
	if (ret != RESOURCED_ERROR_NONE) {
		_E("smaps helper failed");
		return RESOURCED_ERROR_FAIL;
	}

	if (!logging_memory_app_list) {
		logging_memory_app_list = g_hash_table_new_full(
				g_str_hash,
				g_str_equal,
				NULL,
				logging_memory_free_value);

		/* make hash from file */
		ret = logging_memory_read_from_file(logging_memory_app_list, LOGGING_MEMORY_FILE);

		if (ret == RESOURCED_ERROR_OUT_OF_MEMORY) {
			_E("logging_memory_init failed");
			return ret;
		}
	}

	register_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, logging_memory_state_cb);
	register_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, logging_memory_state_cb);
	register_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, logging_memory_state_cb);

	last_file_update_time = logging_get_time(CLOCK_BOOTTIME);

	if (logging_memory_update_timer == NULL) {
		_D("logging memory update timer start");
		logging_memory_update_timer = ecore_timer_add(TEN_MINUTE, logging_memory_notify, (void *)NULL);
	}

	_D("logging memory init finished");
	return RESOURCED_ERROR_NONE;
}

int logging_memory_exit(void *data)
{
	int ret;

	/* update timer delete */
	ecore_timer_del(logging_memory_update_timer);
	logging_memory_update_timer = NULL;

	unregister_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, logging_memory_state_cb);
	unregister_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, logging_memory_state_cb);
	unregister_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, logging_memory_state_cb);

	if (logging_memory_app_list) {
		ret = logging_memory_save_to_file(logging_memory_app_list, LOGGING_MEMORY_FILE);

		if (ret)
			_E("save file failed %d", ret);

		if (logging_memory_app_list) {
			gpointer value;
			gpointer key;
			GHashTableIter iter;

			g_hash_table_iter_init(&iter, logging_memory_app_list);

			while (g_hash_table_iter_next(&iter, &key, &value)) {
				struct logging_memory_table *table = (struct logging_memory_table *)value;

				if (table->memory_info)
					g_array_free(table->memory_info, true);
			}

			g_hash_table_destroy(logging_memory_app_list);
		}
	}

	smaps_helper_free();

	logging_module_exit();

	_D("logging memory finalize");

	return RESOURCED_ERROR_NONE;
}
