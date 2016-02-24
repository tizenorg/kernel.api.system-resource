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
 * @file logging-cpu.c
 *
 * @desc start cpu logging system for resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <math.h>

#include "proc-common.h"
#include "notifier.h"
#include "resourced.h"
#include "edbus-handler.h"
#include "heart.h"
#include "logging.h"
#include "logging-common.h"
#include "trace.h"
#include "module.h"
#include "macro.h"

#define PROC_STAT_PATH				"/proc/%d/stat"
#define CPU_NAME				"cpu"
#define CPU_DATA_MAX				1024
#define CPU_ARRAY_MAX				24
#define LOGGING_CPU_INTERVAL			3600
#define LOGGING_CPU_DATA_FILE			HEART_FILE_PATH"/.cpu.dat"

enum {
	SERVICE = 0,
	FOREG = 1,
	BACKG = 2
};

struct logging_cpu_info {
	time_t utime;
	time_t stime;
	pid_t pid;
};

struct logging_cpu_table {
	char appid[MAX_APPID_LENGTH];
	char pkgid[MAX_PKGNAME_LENGTH];
	time_t total_utime;
	time_t total_stime;
	time_t utime;
	time_t stime;
	time_t last_utime;
	time_t last_stime;
	int fg_count;
	time_t fg_time;
	time_t used_time;
	pid_t last_pid;
	time_t last_renew_time;
	GArray *cpu_info;
};

static GHashTable *logging_cpu_app_list;
static pthread_mutex_t logging_cpu_mutex = PTHREAD_MUTEX_INITIALIZER;
static time_t last_file_commit_time;

static int logging_cpu_get_cpu_time(pid_t pid, time_t *utime,
		time_t *stime)
{
	char proc_path[sizeof(PROC_STAT_PATH) + MAX_DEC_SIZE(int)];
	FILE *fp;

	assert(utime != NULL);
	assert(stime != NULL);

	snprintf(proc_path, sizeof(proc_path), PROC_STAT_PATH, pid);
	fp = fopen(proc_path, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;

	if (fscanf(fp, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s") < 0) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	if (fscanf(fp, "%ld %ld", utime, stime) < 1) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	fclose(fp);

	return RESOURCED_ERROR_NONE;
}

static int logging_cpu_service_launch(void *data)
{
	int ret;
	time_t utime, stime;
	char info[CPU_DATA_MAX];
	char *appid, *pkgid;
	struct proc_status *ps = (struct proc_status *)data;

	ret = logging_cpu_get_cpu_time(ps->pid, &utime, &stime);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;
	snprintf(info, sizeof(info), "%ld %ld %d %d", utime, stime, ps->pid, SERVICE);

	ret = proc_get_id_info(ps, &appid, &pkgid);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to proc_get_id_info");
		return ret;
	}

	ret = logging_write(CPU_NAME, appid, pkgid, time(NULL), info);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	_D("logging_cpu_service_launch : pid = %d, appname = %s, pkgname = %s",
			ps->pid, appid, pkgid);
	resourced_notify(RESOURCED_NOTIFIER_LOGGING_START, NULL);
	return RESOURCED_ERROR_NONE;
}

static int logging_cpu_foreground_state(void *data)
{
	int ret;
	time_t utime, stime;
	char info[CPU_DATA_MAX];
	char *appid, *pkgid;
	struct proc_status *ps = (struct proc_status *)data;

	ret = logging_cpu_get_cpu_time(ps->pid, &utime, &stime);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;
	snprintf(info, sizeof(info), "%ld %ld %d %d", utime, stime, ps->pid, FOREG);

	ret = proc_get_id_info(ps, &appid, &pkgid);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to proc_get_id_info");
		return ret;
	}

	ret = logging_write(CPU_NAME, appid, pkgid, time(NULL), info);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	_D("logging_cpu_foreground_state : pid = %d, appname = %s, pkgname = %s",
			ps->pid, appid, pkgid);
	resourced_notify(RESOURCED_NOTIFIER_LOGGING_START, NULL);
	return RESOURCED_ERROR_NONE;
}

static int logging_cpu_background_state(void *data)
{
	int ret;
	time_t utime, stime;
	char info[CPU_DATA_MAX];
	char *appid, *pkgid;
	struct proc_status *ps = (struct proc_status *)data;

	ret = logging_cpu_get_cpu_time(ps->pid, &utime, &stime);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;
	snprintf(info, sizeof(info), "%ld %ld %d %d", utime, stime, ps->pid, BACKG);

	ret = proc_get_id_info(ps, &appid, &pkgid);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to proc_get_id_info");
		return ret;
	}

	ret = logging_write(CPU_NAME, appid, pkgid, time(NULL), info);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	_D("logging_cpu_background_state : pid = %d, appname = %s, pkgname = %s",
			ps->pid, appid, pkgid);
	resourced_notify(RESOURCED_NOTIFIER_LOGGING_START, NULL);
	return RESOURCED_ERROR_NONE;
}

static void logging_free_value(gpointer value)
{
	struct logging_cpu_table *table = (struct logging_cpu_table *)value;

	if (!table)
		return;
	free(table);
}

static int logging_cpu_read_length(char *buf, int count)
{
	int i, find = 0;
	int len = strlen(buf);

	for (i = 0; i < len; i++) {
		if (buf[i] == ' ')
			find++;
		if (find == count)
			return i + 1;
	}
	return RESOURCED_ERROR_FAIL;
}

static int logging_cpu_read_from_file(GHashTable *hashtable, char *filename)
{
	int i, len, ret, fg_count;
	time_t total_utime, total_stime, last_utime, last_stime;
	time_t fg_time, used_time;
	pid_t last_pid, pid;
	time_t utime, stime;
	FILE *fp;
	struct logging_cpu_table *table;
	char appid[MAX_APPID_LENGTH] = {0, };
	char pkgid[MAX_PKGNAME_LENGTH] = {0, };
	char buf[CPU_DATA_MAX] = {0, };

	fp = fopen(filename, "r");

	if (!fp) {
		_E("%s fopen failed %d", filename, errno);
		return RESOURCED_ERROR_FAIL;
	}

	while (fgets(buf, CPU_DATA_MAX, fp)) {
		table = malloc(sizeof(struct logging_cpu_table));

		if (!table) {
			_E("malloc failed");
			fclose(fp);
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}

		/* make return values */
		ret = sscanf(buf, "%s %s %ld %ld %ld %ld %ld %ld %d %d %ld %ld ", appid, pkgid,
				&total_utime, &total_stime,
				&utime, &stime, &last_utime,
				&last_stime, &last_pid,
				&fg_count, &fg_time, &used_time);

		if (ret <= 0) {
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
		len = logging_cpu_read_length(buf, 9);
		if (len <= 0) {
			_E("sscanf failed");
			free(table);
			fclose(fp);
			return RESOURCED_ERROR_FAIL;
		}
		table->total_utime = total_utime;
		table->total_stime = total_stime;
		table->utime = utime;
		table->stime = stime;
		table->last_utime = last_utime;
		table->last_stime = last_stime;
		table->last_pid = last_pid;
		table->fg_count = fg_count;
		table->fg_time = fg_time;
		table->used_time = used_time;
		table->cpu_info =
			g_array_new(FALSE, FALSE, sizeof(struct logging_cpu_info *));

		for (i = 0; i < CPU_ARRAY_MAX; i++) {
			struct logging_cpu_info *ci;

			ret = sscanf(buf + len, "%ld %ld %d ", &utime, &stime, &pid);
			if (ret <= 0) {
				_E("file read fail %s", buf + len);
				free(table);
				fclose(fp);
				return RESOURCED_ERROR_FAIL;
			}
			ci = malloc(sizeof(struct logging_cpu_info));
			if (!ci) {
				free(table);
				fclose(fp);
				return RESOURCED_ERROR_OUT_OF_MEMORY;
			}
			ci->utime = utime;
			ci->stime = stime;
			ci->pid = pid;
			len += logging_cpu_read_length(buf + len, 3);
			g_array_append_val(table->cpu_info, ci);
		}

		ret = pthread_mutex_lock(&logging_cpu_mutex);
		if (ret) {
			_E("pthread_mutex_lock() failed, %d", ret);
			g_array_free(table->cpu_info, TRUE);
			free(table);
			fclose(fp);
			return RESOURCED_ERROR_FAIL;
		}
		g_hash_table_insert(hashtable, (gpointer)table->appid, (gpointer)table);
		ret = pthread_mutex_unlock(&logging_cpu_mutex);
		if (ret) {
			_E("pthread_mutex_unlock() failed, %d", ret);
			fclose(fp);
			return RESOURCED_ERROR_FAIL;
		}
	}

	fclose(fp);

	return RESOURCED_ERROR_NONE;
}

static int logging_cpu_save_to_file(GHashTable *hashtable, char *filename)
{
	int i, len, ret, array_len;
	gpointer value;
	gpointer key;
	GHashTableIter iter;
	struct logging_cpu_table *table;
	FILE *fp;
	char buf[CPU_DATA_MAX] = {0, };

	fp = fopen(filename, "w");
	if (!fp) {
		_E("%s fopen failed %d", filename, errno);
		return RESOURCED_ERROR_FAIL;
	}

	if (!logging_cpu_app_list) {
		_E("empty app list");
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	if (!g_hash_table_size(logging_cpu_app_list)) {
		_E("hash table is mepty");
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	ret = pthread_mutex_lock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	g_hash_table_iter_init(&iter, hashtable);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		table = (struct logging_cpu_table *)value;
		array_len = table->cpu_info->len;
		len = snprintf(buf, CPU_DATA_MAX, "%s %s %ld %ld %ld %ld %ld %ld %d %d %ld %ld ",
				table->appid, table->pkgid,
				table->total_utime,
				table->total_stime,
				table->utime,
				table->stime,
				table->last_utime,
				table->last_stime,
				table->last_pid,
				table->fg_count,
				table->fg_time,
				table->used_time);

		for (i = 0; i < CPU_ARRAY_MAX; i++) {
			struct logging_cpu_info *ci;
			if (array_len <= i) {
				len += snprintf(buf + len, CPU_DATA_MAX - len, "0 0 0 ");
			} else {
				ci = g_array_index(table->cpu_info, struct logging_cpu_info *, i);
				if (!ci)
					break;
				len += snprintf(buf + len, CPU_DATA_MAX - len, "%ld %ld %d ",
						ci->utime,
						ci->stime,
						ci->pid);
			}
		}
		len += snprintf(buf + len, CPU_DATA_MAX - len, "\n");
		fputs(buf, fp);
	}
	ret = pthread_mutex_unlock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	fclose(fp);

	return RESOURCED_ERROR_NONE;
}

static int logging_cpu_hashtable_renew(GHashTable *hashtable, time_t now)
{
	int ret;
	gpointer value;
	gpointer key;
	GHashTableIter iter;
	struct logging_cpu_table *table;

	if (!logging_cpu_app_list) {
		_E("empty app list");
		return RESOURCED_ERROR_FAIL;
	}

	if (!g_hash_table_size(logging_cpu_app_list)) {
		_E("hash table is mepty");
		return RESOURCED_ERROR_FAIL;
	}
	ret = pthread_mutex_lock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	g_hash_table_iter_init(&iter, hashtable);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		table = (struct logging_cpu_table *)value;
		table->total_utime = 0;
		table->total_stime = 0;
		table->last_renew_time = now;
		table->fg_count = 0;
		table->fg_time = 0;
		table->used_time = 0;
	}
	ret = pthread_mutex_unlock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
}

void logging_cpu_update(struct logging_table_form *data)
{
	int ret;
	pid_t pid;
	int state;
	time_t utime, stime;
	time_t time_diff = 0, utime_diff = 0, stime_diff = 0;
	time_t curr_time = logging_get_time(CLOCK_BOOTTIME);
	struct logging_cpu_table *table;

	_D("%s %s %d %s", data->appid, data->pkgid, data->time, data->data);
	if (sscanf(data->data, "%ld %ld %d %d", &utime, &stime, &pid, &state) < 0) {
		_E("sscanf failed");
		return;
	}

	ret = pthread_mutex_lock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return;
	}
	table =
		g_hash_table_lookup(logging_cpu_app_list, data->appid);
	/* update */
	if (table) {
		if (table->last_pid == pid) {
			utime_diff = utime - table->last_utime;
			table->utime += utime_diff;
			table->total_utime += utime_diff;
			stime_diff = stime - table->last_stime;
			table->stime += stime_diff;
			table->total_stime += stime_diff;
		} else {
			table->utime += utime;
			table->total_utime += utime;
			table->stime += stime;
			table->total_stime += stime;
			table->last_pid = pid;
		}
		table->last_utime = utime;
		table->last_stime = stime;

		if (state == FOREG) {
			table->fg_time = data->time;
		} else if (state == BACKG && table->fg_time) {
			table->fg_count++;
			time_diff = data->time - table->fg_time;
			if (time_diff > 0)
				table->used_time += time_diff;
			if (table->used_time < 0)
				table->used_time = 0;
			table->fg_time = 0;
		}

	} else {
		table = malloc(sizeof(struct logging_cpu_table));

		if (!table) {
			_E("malloc failed");
			goto unlock_exit;
		}

		if (snprintf(table->appid, MAX_APPID_LENGTH,  "%s", data->appid) < 0) {
			free(table);
			_E("snprintf failed");
			goto unlock_exit;
		}

		if (snprintf(table->pkgid, MAX_PKGNAME_LENGTH, "%s", data->pkgid) < 0) {
			free(table);
			_E("snprintf failed");
			goto unlock_exit;
		}
		table->total_utime = utime;
		table->total_stime = stime;
		table->utime = utime;
		table->stime = stime;
		table->last_utime = utime;
		table->last_stime = stime;
		table->last_pid = pid;
		table->fg_count = 0;
		table->fg_time = 0;
		table->used_time = 0;
		table->cpu_info =
			g_array_new(FALSE, FALSE, sizeof(struct logging_cpu_info *));

		if (state == FOREG)
			table->fg_time = data->time;

		if (!table->cpu_info) {
			free(table);
			_E("g_array_new failed");
			goto unlock_exit;
		}
		g_hash_table_insert(logging_cpu_app_list, (gpointer)table->appid, (gpointer)table);
	}
	ret = pthread_mutex_unlock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return;
	}

	if (last_file_commit_time + LOGGING_CPU_INTERVAL < curr_time) {
		/* all hash table update and make new array */
		gpointer value;
		gpointer key;
		GHashTableIter iter;
		struct logging_cpu_table *search;
		struct logging_cpu_info *ci;

		ret = pthread_mutex_lock(&logging_cpu_mutex);
		if (ret) {
			_E("pthread_mutex_lock() failed, %d", ret);
			return;
		}

		g_hash_table_iter_init(&iter, logging_cpu_app_list);

		while (g_hash_table_iter_next(&iter, &key, &value)) {
			search = (struct logging_cpu_table *)value;

			ci = malloc(sizeof(struct logging_cpu_info));

			if (!ci) {
				_E("malloc failed");
				goto unlock_exit;
			}
			/* make new array node */
			ci->pid = search->last_pid;
			ci->utime = search->utime;
			ci->stime = search->stime;
			search->utime = 0;
			search->stime = 0;
			/* hashtable sliding : remove last node and make new one */
			g_array_remove_index(search->cpu_info, CPU_ARRAY_MAX - 1);
			g_array_prepend_val(search->cpu_info, ci);
		}
		ret = pthread_mutex_unlock(&logging_cpu_mutex);
		if (ret) {
			_E("pthread_mutex_unlock() failed, %d", ret);
			return;
		}
		/* rewrite hashtable list file */
		ret = logging_cpu_save_to_file(logging_cpu_app_list, LOGGING_CPU_DATA_FILE);
		if (ret) {
			_E("save to file failed");
			goto unlock_exit;
		}

		last_file_commit_time = curr_time;
	}

	return;

unlock_exit:
	ret = pthread_mutex_unlock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return;
	}
}

struct logging_cpu_data *logging_cpu_get_data(char *appid, enum logging_data_period period)
{
	int index, i, ret;
	struct logging_cpu_table *table;
	struct logging_cpu_data *data;

	if (!appid) {
		_E("Wrong arguments!");
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
	if (!logging_cpu_app_list) {
		_E("empty app list");
		return NULL;
	}

	if (!g_hash_table_size(logging_cpu_app_list)) {
		_E("hash table is mepty");
		return NULL;
	}

	ret = pthread_mutex_lock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return NULL;
	}
	table = g_hash_table_lookup(logging_cpu_app_list, (gconstpointer)appid);
	if (!table) {
		goto unlock_exit;
	}
	data = malloc(sizeof(struct logging_cpu_data));
	if (!data) {
		_E("malloc failed");
		goto unlock_exit;
	}
	if (snprintf(data->appid, MAX_APPID_LENGTH, "%s", table->appid) < 0) {
		_E("snprintf failed");
		free(data);
		goto unlock_exit;
	}
	if (snprintf(data->pkgid, MAX_PKGNAME_LENGTH, "%s", table->pkgid) < 0) {
		_E("snprintf failed");
		free(data);
		goto unlock_exit;
	}
	if (period == LOGGING_LATEST) {
		data->utime = table->total_utime;
		data->stime = table->total_stime;
	} else {
		data->utime = table->utime;
		data->stime = table->stime;
		i = table->cpu_info->len;
		if (i == 0) {
			free(data);
			goto unlock_exit;
		}
		if (i < index)
			index = i;
		for (i = 0; i < index; i++) {
			struct logging_cpu_info *cpu_info;
			cpu_info =
				g_array_index(table->cpu_info, struct logging_cpu_info *, i);
			if (!cpu_info)
				break;
			data->utime += cpu_info->utime;
			data->stime += cpu_info->stime;
		}
	}
	ret = pthread_mutex_unlock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		free(data);
		return NULL;
	}
	return data;
unlock_exit:
	ret = pthread_mutex_unlock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return NULL;
	}
	return NULL;
}

static int compare_usage(const struct logging_app_usage *lau_a,
	    const struct logging_app_usage *lau_b)
{
	if (lau_a->point != lau_b->point)
		return (lau_b->point - lau_a->point);

	return 0;
}

/*
 * Calculate application usage using frequency and time
 */
static double logging_cpu_get_point(int freq, int time)
{
	double weightForFrequence = 3;
	double point = 0;
	point = sqrt(time + (freq*weightForFrequence));
	return point;
}

int logging_cpu_get_table(GArray *arrays, enum logging_data_period period)
{
	int index, i, ret;
	gpointer value;
	gpointer key;
	GHashTableIter h_iter;
	struct logging_cpu_table *table;
	struct logging_cpu_data *cdata;

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

	if (!logging_cpu_app_list) {
		_E("empty app list");
		return RESOURCED_ERROR_FAIL;
	}

	if (!g_hash_table_size(logging_cpu_app_list)) {
		_E("hash table is mepty");
		return RESOURCED_ERROR_FAIL;
	}

	ret = pthread_mutex_lock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}

	g_hash_table_iter_init(&h_iter, logging_cpu_app_list);

	while (g_hash_table_iter_next(&h_iter, &key, &value)) {

		table = (struct logging_cpu_table *)value;
		cdata = malloc(sizeof(struct logging_cpu_data));
		if (!cdata) {
			_E("malloc failed");
			goto unlock_out_of_memory_exit;
		}
		if (snprintf(cdata->appid, MAX_APPID_LENGTH, "%s", table->appid) < 0) {
			_E("snprintf failed");
			free(cdata);
			goto unlock_out_of_memory_exit;
		}
		if (snprintf(cdata->pkgid, MAX_PKGNAME_LENGTH, "%s", table->pkgid) < 0) {
			_E("snprintf failed");
			free(cdata);
			goto unlock_out_of_memory_exit;
		}
		if (period == LOGGING_LATEST) {
			cdata->utime = table->total_utime;
			cdata->stime = table->total_stime;
		} else {
			cdata->utime = table->utime;
			cdata->stime = table->stime;
			i = table->cpu_info->len;
			if (i == 0) {
				free(cdata);
				break;
			}
			if (i < index)
				index = i;
			for (i = 0; i < index; i++) {
				struct logging_cpu_info *cpu_info;
				cpu_info =
					g_array_index(table->cpu_info, struct logging_cpu_info *, i);
				if (!cpu_info)
					break;
				cdata->utime += cpu_info->utime;
				cdata->stime += cpu_info->stime;
			}
		}
		g_array_append_val(arrays, cdata);
	}
	ret = pthread_mutex_unlock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
unlock_out_of_memory_exit:
	ret = pthread_mutex_unlock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_OUT_OF_MEMORY;
}

int logging_cpu_get_appusage_list(GHashTable *lists, int top)
{
	int index = top, i, ret;
	gpointer value;
	gpointer key;
	GHashTableIter h_iter;
	struct logging_cpu_table *table;
	struct logging_app_usage lau;
	GArray *app_lists = NULL;

	if (!logging_cpu_app_list) {
		_E("empty app list");
		return RESOURCED_ERROR_FAIL;
	}

	if (!g_hash_table_size(logging_cpu_app_list)) {
		_E("hash table is mepty");
		return RESOURCED_ERROR_FAIL;
	}

	app_lists = g_array_new(false, false, sizeof(struct logging_app_usage));
	ret = pthread_mutex_lock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}

	g_hash_table_iter_init(&h_iter, logging_cpu_app_list);

	while (g_hash_table_iter_next(&h_iter, &key, &value)) {

		table = (struct logging_cpu_table *)value;
		if (!table->fg_count)
			continue;

		lau.appid = table->appid;
		lau.pkgid = table->pkgid;
		lau.fg_count = table->fg_count;
		lau.used_time = table->used_time;
		lau.point = (int)logging_cpu_get_point(lau.fg_count, lau.used_time);
		/*
		 * make all application lists with weighted point value excepting service application
		 */
		g_array_append_val(app_lists, lau);
	}
	ret = pthread_mutex_unlock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		g_array_free(app_lists, true);
		return RESOURCED_ERROR_FAIL;
	}
	if (app_lists->len < top) {
		_I("too small data for making app usage lists");
		g_array_free(app_lists, true);
		return RESOURCED_ERROR_NO_DATA;
	}

	g_array_sort(app_lists, (GCompareFunc)compare_usage);

	if (!top)
		index = app_lists->len;

	/*
	 * replace application usage lists with sorted usage arrays
	 */
	g_hash_table_remove_all(lists);
	for (i = 0; i < index; i++) {
		struct logging_app_usage *usage = &g_array_index(app_lists, struct logging_app_usage, i);
		_D("appid : %s, point : %d", usage->appid, usage->point);
		g_hash_table_insert(lists, g_strndup(usage->appid, strlen(usage->appid)), GINT_TO_POINTER(1));
	}
	g_array_free(app_lists, true);
	return RESOURCED_ERROR_NONE;
}

static DBusMessage *edbus_logging_get_cpu_data(E_DBus_Object *obj, DBusMessage *msg)
{
	int period, index, i, ret;
	char *appid;
	struct logging_cpu_table *table;

	DBusMessage *reply;
	DBusMessageIter iter;
	time_t utime = 0, stime = 0;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &appid, DBUS_TYPE_INT32, &period, DBUS_TYPE_INVALID);

	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
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
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	if (!logging_cpu_app_list) {
		_E("empty app list");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	if (!g_hash_table_size(logging_cpu_app_list)) {
		_E("hash table is mepty");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init_append(reply, &iter);
	ret = pthread_mutex_lock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	table = g_hash_table_lookup(logging_cpu_app_list, (gconstpointer)appid);
	if (!table) {
		goto unlock_exit;
	}
	if (period == LOGGING_LATEST) {
		utime = table->total_utime;
		stime = table->total_stime;
	} else {
		utime = table->utime;
		stime = table->stime;
		i =  table->cpu_info->len;
		if (i < index)
			index = i;
		for (i = 0; i < index; i++) {
			struct logging_cpu_info *ci;
			ci = g_array_index(table->cpu_info, struct logging_cpu_info *, i);
			if (!ci)
				break;
			utime += ci->utime;
			stime += ci->stime;
		}
	}
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &utime);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &stime);
unlock_exit:
	ret = pthread_mutex_unlock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	return reply;
}

static DBusMessage *edbus_logging_get_cpu_data_list(E_DBus_Object *obj, DBusMessage *msg)
{
	int period, index, i, ret;
	gpointer value;
	gpointer key;
	GHashTableIter h_iter;
	struct logging_cpu_table *table;

	DBusMessage *reply;
	DBusMessageIter d_iter;
	DBusMessageIter arr;
	char *appid;
	time_t utime , stime, ftime, total;
	utime = stime = ftime = total = 0;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &period, DBUS_TYPE_INVALID);

	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
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
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	if (!logging_cpu_app_list) {
		_E("empty app list");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	if (!g_hash_table_size(logging_cpu_app_list)) {
		_E("hash table is mepty");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init_append(reply, &d_iter);
	dbus_message_iter_open_container(&d_iter, DBUS_TYPE_ARRAY, "(sii)", &arr);
	ret = pthread_mutex_lock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		dbus_message_iter_close_container(&d_iter, &arr);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	g_hash_table_iter_init(&h_iter, logging_cpu_app_list);

	while (g_hash_table_iter_next(&h_iter, &key, &value)) {
		DBusMessageIter sub;

		table = (struct logging_cpu_table *)value;
		if (!table)
			break;
		if (period == LOGGING_LATEST) {
			utime = table->total_utime;
			stime = table->total_stime;
		} else {
			utime = table->utime;
			stime = table->stime;
			i =  table->cpu_info->len;
			if (i < index)
				index = i;
			for (i = 0; i < index; i++) {
				struct logging_cpu_info *ci;
				ci = g_array_index(table->cpu_info, struct logging_cpu_info *, i);
				if (!ci)
					break;
				utime += ci->utime;
				stime += ci->stime;
			}
		}
		ftime = table->used_time;
		total = utime + stime;
		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		appid = table->appid;
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &appid);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &total);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &ftime);
		dbus_message_iter_close_container(&arr, &sub);
	}

	ret = pthread_mutex_unlock(&logging_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		dbus_message_iter_close_container(&d_iter, &arr);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	dbus_message_iter_close_container(&d_iter, &arr);

	return reply;
}

static DBusMessage *edbus_logging_reset_cpu_data(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	DBusMessage *reply;
	DBusMessageIter iter;

	if (!logging_cpu_app_list) {
		_E("empty app list");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	if (!g_hash_table_size(logging_cpu_app_list)) {
		_E("hash table is mepty");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	ret = logging_cpu_hashtable_renew(logging_cpu_app_list, logging_get_time(CLOCK_BOOTTIME));

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);

	return reply;
}

static DBusMessage *edbus_logging_save_to_file(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	DBusMessage *reply;
	DBusMessageIter iter;

	ret = logging_cpu_save_to_file(logging_cpu_app_list, LOGGING_CPU_DATA_FILE);
	if (ret) {
		_E("save to file failed");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);
	last_file_commit_time = logging_get_time(CLOCK_BOOTTIME);

	return reply;
}

static struct edbus_method edbus_methods[] = {
	{ "GetCpuData",      "si",   "ii",     edbus_logging_get_cpu_data },
	{ "GetCpuDataList",   "i",   "a(sii)", edbus_logging_get_cpu_data_list },
	{ "ResetCpuData",    NULL,   "i",      edbus_logging_reset_cpu_data },
	{ "SaveCpuData",     NULL,   "i",      edbus_logging_save_to_file },
};

int logging_cpu_init(void *data)
{
	int ret;

	ret = logging_module_init(CPU_NAME, ONE_DAY, FIVE_MINUTE, logging_cpu_update, TEN_MINUTE);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("logging module init failed");
		return RESOURCED_ERROR_FAIL;
	}
	if (!logging_cpu_app_list) {
		logging_cpu_app_list = g_hash_table_new_full(
				g_str_hash,
				g_str_equal,
				NULL,
				logging_free_value);

		/* make hash from file */
		ret = logging_cpu_read_from_file(logging_cpu_app_list, LOGGING_CPU_DATA_FILE);

		if (ret == RESOURCED_ERROR_OUT_OF_MEMORY) {
			_E("logging_cpu_init failed");
			return ret;
		}
	}

	ret = edbus_add_methods(RESOURCED_PATH_LOGGING, edbus_methods,
			ARRAY_SIZE(edbus_methods));
	if (ret != RESOURCED_ERROR_NONE) {
		_E("DBus method registration for %s is failed",
				RESOURCED_PATH_LOGGING);
	}

	register_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, logging_cpu_service_launch);
	register_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, logging_cpu_foreground_state);
	register_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, logging_cpu_background_state);

	last_file_commit_time = logging_get_time(CLOCK_BOOTTIME);

	_D("logging cpu init finished");
	return RESOURCED_ERROR_NONE;
}

int logging_cpu_exit(void *data)
{
	unregister_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, logging_cpu_service_launch);
	unregister_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, logging_cpu_foreground_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, logging_cpu_background_state);

	if (logging_cpu_app_list) {
		logging_cpu_save_to_file(logging_cpu_app_list, LOGGING_CPU_DATA_FILE);
		if (logging_cpu_app_list)
			g_hash_table_destroy(logging_cpu_app_list);
	}

	logging_module_exit();

	_D("logging cpu exit");
	return RESOURCED_ERROR_NONE;
}
