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
 * @file heart-cpu.c
 *
 * @desc heart cpu module
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

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
#include "heart-common.h"
#include "trace.h"
#include "module.h"
#include "macro.h"

#define PROC_PATH				"/proc/%d"
#define PROC_STAT_PATH				"/proc/%d/stat"
#define CPU_NAME				"cpu"
#define CPU_DATA_MAX				1024
#define CPU_ARRAY_MAX				24
#define HEART_CPU_SAVE_INTERVAL			3600
#define HEART_CPU_DATA_FILE			HEART_FILE_PATH"/.cpu.dat"

enum {
	SERVICE = 0,
	FOREG = 1,
	BACKG = 2
};

struct heart_cpu_info {
	unsigned long utime;
	unsigned long stime;
	int state;
	pid_t pid;
};

struct heart_cpu_table {
	char appid[MAX_APPID_LENGTH];
	char pkgid[MAX_PKGNAME_LENGTH];
	unsigned long total_utime;
	unsigned long total_stime;
	unsigned long utime;
	unsigned long stime;
	int fg_count;
	unsigned long fg_time;
	unsigned long bg_time;
	GSList *last_pid_info;
	pid_t last_pid;
	time_t last_renew_time;
	GArray *cpu_info;
};

static GHashTable *heart_cpu_app_list;
static pthread_mutex_t heart_cpu_mutex = PTHREAD_MUTEX_INITIALIZER;
static time_t last_file_commit_time;

static void heart_cpu_remove_last_pid_info_exited(struct heart_cpu_table *table)
{
	char proc_path[sizeof(PROC_PATH) + MAX_DEC_SIZE(int)];
	GSList *iter, *next;
	struct heart_cpu_info *ci = NULL;

	if (!table || !table->last_pid_info)
		return;

	gslist_for_each_safe(table->last_pid_info, iter, next, ci) {
		snprintf(proc_path, sizeof(proc_path), PROC_PATH, ci->pid);
		if (!access(proc_path, F_OK))
			continue;
		table->last_pid_info = g_slist_remove(table->last_pid_info, ci);
		free(ci);
	}
}

static struct heart_cpu_info *find_pid_info(struct heart_cpu_table *table, pid_t pid)
{
	GSList *iter = NULL;
	struct heart_cpu_info *ci = NULL;

	if (!table || !table->last_pid_info)
		return NULL;

	gslist_for_each_item(iter, table->last_pid_info) {
		ci = (struct heart_cpu_info *)iter->data;
		if (ci && ci->pid == pid)
			return ci;
	}
	return NULL;
}

static int heart_cpu_get_cpu_time(pid_t pid, unsigned long *utime,
		unsigned long *stime)
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

	if (fscanf(fp, "%lu %lu", utime, stime) < 1) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	fclose(fp);

	return RESOURCED_ERROR_NONE;
}

static int heart_cpu_service_launch(void *data)
{
	int ret;
	unsigned long utime, stime;
	char info[CPU_DATA_MAX];
	char *appid, *pkgid;
	struct proc_status *ps = (struct proc_status *)data;

	ret = heart_cpu_get_cpu_time(ps->pid, &utime, &stime);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;
	snprintf(info, sizeof(info), "%lu %lu %d %d", utime, stime, ps->pid, SERVICE);

	ret = proc_get_id_info(ps, &appid, &pkgid);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to proc_get_id_info");
		return ret;
	}

	ret = logging_write(CPU_NAME, appid, pkgid, time(NULL), info);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	_D("heart_cpu_service_launch : pid = %d, appname = %s, pkgname = %s",
			ps->pid, appid, pkgid);
	resourced_notify(RESOURCED_NOTIFIER_LOGGING_START, NULL);
	return RESOURCED_ERROR_NONE;
}

static int heart_cpu_foreground_state(void *data)
{
	int ret;
	unsigned long utime, stime;
	char info[CPU_DATA_MAX];
	char *appid, *pkgid;
	struct proc_status *ps = (struct proc_status *)data;

	ret = heart_cpu_get_cpu_time(ps->pid, &utime, &stime);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;
	snprintf(info, sizeof(info), "%lu %lu %d %d", utime, stime, ps->pid, FOREG);

	ret = proc_get_id_info(ps, &appid, &pkgid);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to proc_get_id_info");
		return ret;
	}

	ret = logging_write(CPU_NAME, appid, pkgid, time(NULL), info);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	_D("heart_cpu_foreground_state : pid = %d, appname = %s, pkgname = %s",
			ps->pid, appid, pkgid);
	resourced_notify(RESOURCED_NOTIFIER_LOGGING_START, NULL);
	return RESOURCED_ERROR_NONE;
}

static int heart_cpu_background_state(void *data)
{
	int ret;
	unsigned long utime, stime;
	char info[CPU_DATA_MAX];
	char *appid, *pkgid;
	struct proc_status *ps = (struct proc_status *)data;

	ret = heart_cpu_get_cpu_time(ps->pid, &utime, &stime);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;
	snprintf(info, sizeof(info), "%lu %lu %d %d", utime, stime, ps->pid, BACKG);

	ret = proc_get_id_info(ps, &appid, &pkgid);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to proc_get_id_info");
		return ret;
	}

	ret = logging_write(CPU_NAME, appid, pkgid, time(NULL), info);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	_D("heart_cpu_background_state : pid = %d, appname = %s, pkgname = %s",
			ps->pid, appid, pkgid);
	resourced_notify(RESOURCED_NOTIFIER_LOGGING_START, NULL);
	return RESOURCED_ERROR_NONE;
}

static int heart_cpu_update_state(void *data)
{
	int ret, state;
	unsigned long utime, stime;
	char info[CPU_DATA_MAX];
	char *appid, *pkgid;
	struct proc_status *ps = (struct proc_status *)data;

	ret = heart_cpu_get_cpu_time(ps->pid, &utime, &stime);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	if (ps->pai->lru_state == PROC_FOREGROUND)
		state = FOREG;
	else
		state = BACKG;

	snprintf(info, sizeof(info), "%lu %lu %d %d", utime, stime, ps->pid, state);

	ret = proc_get_id_info(ps, &appid, &pkgid);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to proc_get_id_info");
		return ret;
	}

	ret = logging_write(CPU_NAME, appid, pkgid, time(NULL), info);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	_D("heart_cpu_update_state : pid = %d, appname = %s, pkgname = %s, state = %d",
			ps->pid, appid, pkgid, state);
	resourced_notify(RESOURCED_NOTIFIER_LOGGING_START, NULL);
	return RESOURCED_ERROR_NONE;
}

static int heart_cpu_update_app_list(void *data)
{
	GSList *giter = NULL;
	struct proc_app_info *pai = NULL;

	gslist_for_each_item(giter, proc_app_list) {
		struct proc_status ps;
		pai = (struct proc_app_info *)giter->data;
		if (!pai->ai)
			continue;
		ps.pid = pai->main_pid;
		ps.appid = pai->appid;
		ps.pai = pai;
		heart_cpu_update_state(&ps);
	}
	return RESOURCED_ERROR_NONE;
}

static void heart_free_value(gpointer value)
{
	struct heart_cpu_table *table = (struct heart_cpu_table *)value;

	if (!table)
		return;

	if (table->last_pid_info)
		g_slist_free_full(table->last_pid_info, free);

	if (table->cpu_info)
		g_array_free(table->cpu_info, TRUE);

	free(table);
}

static int heart_cpu_read_length(char *buf, int count)
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

static int heart_cpu_read_from_file(GHashTable *hashtable, char *filename)
{
	int i, len, ret, fg_count, state;
	unsigned long total_utime, total_stime;
	unsigned long utime, stime;
	unsigned long fg_time, bg_time;
	pid_t pid;
	FILE *fp;
	struct heart_cpu_table *table;
	char appid[MAX_APPID_LENGTH] = {0, };
	char pkgid[MAX_PKGNAME_LENGTH] = {0, };
	char buf[CPU_DATA_MAX] = {0, };

	fp = fopen(filename, "r");

	if (!fp) {
		_E("%s fopen failed %d", filename, errno);
		return RESOURCED_ERROR_FAIL;
	}

	while (fgets(buf, CPU_DATA_MAX, fp)) {
		table = malloc(sizeof(struct heart_cpu_table));

		if (!table) {
			_E("malloc failed");
			fclose(fp);
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}

		/* make return values */
		ret = sscanf(buf, "%s %s %lu %lu %lu %lu %lu %lu %d ", appid, pkgid,
				&total_utime, &total_stime,
				&utime, &stime,
				&fg_time, &bg_time, &fg_count);

		if (ret <= 0) {
			_E("sscanf failed");
			free(table);
			fclose(fp);
			return RESOURCED_ERROR_FAIL;
		}

		if (snprintf(table->appid, MAX_APPID_LENGTH, "%s", appid) < 0) {
			_E("sprintf failed");
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
		len = heart_cpu_read_length(buf, 9);
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
		table->last_pid_info = NULL;
		table->last_pid = 0;
		table->fg_time = fg_time;
		table->bg_time = bg_time;
		table->fg_count = fg_count;
		table->cpu_info =
			g_array_new(FALSE, FALSE, sizeof(struct heart_cpu_info *));

		for (i = 0; i < CPU_ARRAY_MAX; i++) {
			struct heart_cpu_info *ci;

			ret = sscanf(buf + len, "%lu %lu %d %d ", &utime, &stime, &pid, &state);
			if (ret <= 0) {
				_E("file read fail %s", buf + len);
				free(table);
				fclose(fp);
				return RESOURCED_ERROR_FAIL;
			}
			ci = malloc(sizeof(struct heart_cpu_info));
			if (!ci) {
				free(table);
				fclose(fp);
				return RESOURCED_ERROR_OUT_OF_MEMORY;
			}
			ci->utime = utime;
			ci->stime = stime;
			ci->pid = pid;
			ci->state = state;
			len += heart_cpu_read_length(buf + len, 4);
			g_array_append_val(table->cpu_info, ci);
		}

		ret = pthread_mutex_lock(&heart_cpu_mutex);
		if (ret) {
			_E("pthread_mutex_lock() failed, %d", ret);
			g_array_free(table->cpu_info, TRUE);
			free(table);
			fclose(fp);
			return RESOURCED_ERROR_FAIL;
		}
		g_hash_table_insert(hashtable, (gpointer)table->appid, (gpointer)table);
		ret = pthread_mutex_unlock(&heart_cpu_mutex);
		if (ret) {
			_E("pthread_mutex_unlock() failed, %d", ret);
			fclose(fp);
			return RESOURCED_ERROR_FAIL;
		}
	}

	fclose(fp);

	return RESOURCED_ERROR_NONE;
}

static int heart_cpu_save_to_file(GHashTable *hashtable, char *filename)
{
	int i, len, ret, array_len;
	gpointer value;
	gpointer key;
	GHashTableIter iter;
	struct heart_cpu_table *table;
	FILE *fp;
	char buf[CPU_DATA_MAX] = {0, };

	fp = fopen(filename, "w");
	if (!fp) {
		_E("%s fopen failed %d", filename, errno);
		return RESOURCED_ERROR_FAIL;
	}

	if (!heart_cpu_app_list) {
		_E("empty app list");
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	if (!g_hash_table_size(heart_cpu_app_list)) {
		_E("hash table is empty");
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	ret = pthread_mutex_lock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	g_hash_table_iter_init(&iter, hashtable);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		table = (struct heart_cpu_table *)value;
		array_len = table->cpu_info->len;
		len = snprintf(buf, CPU_DATA_MAX, "%s %s %lu %lu %lu %lu %lu %lu %d ",
				table->appid, table->pkgid,
				table->total_utime,
				table->total_stime,
				table->utime,
				table->stime,
				table->fg_time,
				table->bg_time,
				table->fg_count);

		for (i = 0; i < CPU_ARRAY_MAX; i++) {
			struct heart_cpu_info *ci;
			if (array_len <= i) {
				len += snprintf(buf + len, CPU_DATA_MAX - len, "0 0 0 0 ");
			} else {
				ci = g_array_index(table->cpu_info, struct heart_cpu_info *, i);
				if (!ci)
					break;
				len += snprintf(buf + len, CPU_DATA_MAX - len, "%lu %lu %d %d ",
						ci->utime,
						ci->stime,
						ci->pid,
						ci->state);
			}
		}
		len += snprintf(buf + len, CPU_DATA_MAX - len, "\n");
		fputs(buf, fp);
	}
	ret = pthread_mutex_unlock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	fclose(fp);

	return RESOURCED_ERROR_NONE;
}

static int heart_cpu_hashtable_renew(GHashTable *hashtable, time_t now)
{
	int ret;
	gpointer value;
	gpointer key;
	GHashTableIter iter;
	struct heart_cpu_table *table;

	if (!heart_cpu_app_list) {
		_E("empty app list");
		return RESOURCED_ERROR_FAIL;
	}

	if (!g_hash_table_size(heart_cpu_app_list)) {
		_E("hash table is empty");
		return RESOURCED_ERROR_FAIL;
	}
	ret = pthread_mutex_lock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	g_hash_table_iter_init(&iter, hashtable);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		table = (struct heart_cpu_table *)value;
		table->total_utime = 0;
		table->total_stime = 0;
		table->last_renew_time = now;
		table->fg_count = 0;
		table->fg_time = 0;
		table->bg_time = 0;
	}
	ret = pthread_mutex_unlock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
}

void heart_cpu_update(struct logging_table_form *data, void *user_data)
{
	int ret;
	pid_t pid;
	int state;
	unsigned long utime, stime;
	unsigned long utime_diff = 0, stime_diff = 0;
	time_t curr_time = logging_get_time(CLOCK_BOOTTIME);
	struct heart_cpu_table *table;
	struct heart_cpu_info *ci = NULL;
        GHashTable *cpu_usage_list = NULL;

	if (user_data)
		cpu_usage_list = (GHashTable *)user_data;
	else
		cpu_usage_list = heart_cpu_app_list;

	_D("%s %s %d %s", data->appid, data->pkgid, data->time, data->data);
	if (sscanf(data->data, "%lu %lu %d %d", &utime, &stime, &pid, &state) < 0) {
		_E("sscanf failed");
		return;
	}

	ret = pthread_mutex_lock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return;
	}
	table =
		g_hash_table_lookup(cpu_usage_list, data->appid);
	/* update */
	if (table) {

		if (table->last_renew_time > data->time)
			goto unlock_exit;

		ci = find_pid_info(table, pid);
		if (table->last_pid_info && ci) {
			utime_diff = utime - ci->utime;
			table->utime += utime_diff;
			table->total_utime += utime_diff;
			stime_diff = stime - ci->stime;
			table->stime += stime_diff;
			table->total_stime += stime_diff;
			ci->utime = utime;
			ci->stime = stime;
			if (ci->state == BACKG) {
				table->bg_time += utime_diff + stime_diff;
				if (state == FOREG)
					table->fg_count++;
			} else
				table->fg_time += utime_diff + stime_diff;
			ci->state = state;
		} else {
			table->utime += utime;
			table->total_utime += utime;
			table->stime += stime;
			table->total_stime += stime;
			if (table->last_pid_info)
				heart_cpu_remove_last_pid_info_exited(table);
			ci = malloc(sizeof(struct heart_cpu_info));
			if (!ci) {
				_E("malloc failed");
				goto unlock_exit;
			}
			ci->pid = pid;
			ci->utime = utime;
			ci->stime = stime;
			ci->state = state;
			if (ci->state == FOREG)
				table->fg_count++;
			table->last_pid_info = g_slist_prepend(table->last_pid_info, ci);
			table->last_pid = pid;
		}
	} else {
		table = malloc(sizeof(struct heart_cpu_table));

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
		table->fg_count = 0;
		table->fg_time = 0;
		table->bg_time = 0;
		if (state == FOREG)
			table->fg_count = 1;

		table->cpu_info =
			g_array_new(FALSE, FALSE, sizeof(struct heart_cpu_info *));
		if (!table->cpu_info) {
			free(table);
			_E("g_array_new failed");
			goto unlock_exit;
		}

		ci = malloc(sizeof(struct heart_cpu_info));
		if (!ci) {
			_E("malloc failed");
			free(table);
			goto unlock_exit;
		}
		ci->pid = pid;
		ci->utime = utime;
		ci->stime = stime;
		ci->state = state;
		table->last_pid_info = NULL;
		table->last_pid_info = g_slist_prepend(table->last_pid_info, ci);
		table->last_pid = pid;

		g_hash_table_insert(cpu_usage_list, (gpointer)table->appid, (gpointer)table);
	}
	ret = pthread_mutex_unlock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return;
	}

	if (last_file_commit_time + HEART_CPU_SAVE_INTERVAL < curr_time) {
		/* all hash table update and make new array */
		gpointer value;
		gpointer key;
		GHashTableIter iter;
		struct heart_cpu_table *search;
		struct heart_cpu_info *ci;

		ret = pthread_mutex_lock(&heart_cpu_mutex);
		if (ret) {
			_E("pthread_mutex_lock() failed, %d", ret);
			return;
		}

		g_hash_table_iter_init(&iter, cpu_usage_list);

		while (g_hash_table_iter_next(&iter, &key, &value)) {
			search = (struct heart_cpu_table *)value;

			ci = malloc(sizeof(struct heart_cpu_info));

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
		ret = pthread_mutex_unlock(&heart_cpu_mutex);
		if (ret) {
			_E("pthread_mutex_unlock() failed, %d", ret);
			return;
		}
		/* rewrite hashtable list file */
		ret = heart_cpu_save_to_file(cpu_usage_list, HEART_CPU_DATA_FILE);
		if (ret) {
			_E("save to file failed");
			goto unlock_exit;
		}

		last_file_commit_time = curr_time;
	}

	return;

unlock_exit:
	ret = pthread_mutex_unlock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return;
	}
}

struct heart_cpu_data *heart_cpu_get_data(char *appid, enum heart_data_period period)
{
	int index, i, ret;
	struct heart_cpu_table *table;
	struct heart_cpu_data *data;

	if (!appid) {
		_E("Wrong arguments!");
		return NULL;
	}
	switch (period) {
	case DATA_LATEST:
		index = 0;
		break;
	case DATA_3HOUR:
		index = 3;
		break;
	case DATA_6HOUR:
		index = 6;
		break;
	case DATA_12HOUR:
		index = 12;
		break;
	case DATA_1DAY:
		index = 24;
		break;
	default:
		_E("Wrong message arguments! %d", period);
		return NULL;
	}
	if (!heart_cpu_app_list) {
		_E("empty app list");
		return NULL;
	}

	if (!g_hash_table_size(heart_cpu_app_list)) {
		_E("hash table is empty");
		return NULL;
	}

	ret = pthread_mutex_lock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return NULL;
	}
	table = g_hash_table_lookup(heart_cpu_app_list, (gconstpointer)appid);
	if (!table) {
		goto unlock_exit;
	}
	data = malloc(sizeof(struct heart_cpu_data));
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
	if (period == DATA_LATEST) {
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
			struct heart_cpu_info *cpu_info;
			cpu_info =
				g_array_index(table->cpu_info, struct heart_cpu_info *, i);
			if (!cpu_info)
				break;
			data->utime += cpu_info->utime;
			data->stime += cpu_info->stime;
		}
	}
	ret = pthread_mutex_unlock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		free(data);
		return NULL;
	}
	return data;
unlock_exit:
	ret = pthread_mutex_unlock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return NULL;
	}
	return NULL;
}

static int compare_usage(const struct heart_app_usage *lau_a,
	    const struct heart_app_usage *lau_b)
{
	if (lau_a->point != lau_b->point)
		return (lau_b->point - lau_a->point);

	return 0;
}

/*
 * Calculate application usage using frequency and time
 */
static double heart_cpu_get_point(int freq, int time)
{
	double weightForFrequence = 3;
	double point = 0;
	point = sqrt(time + (freq*weightForFrequence));
	return point;
}

int heart_cpu_get_table(GArray *arrays, enum heart_data_period period)
{
	int index, i, ret;
	gpointer value;
	gpointer key;
	GHashTableIter h_iter;
	struct heart_cpu_table *table;
	struct heart_cpu_data *cdata;

	switch (period) {
	case DATA_LATEST:
		index = 0;
		break;
	case DATA_3HOUR:
		index = 3;
		break;
	case DATA_6HOUR:
		index = 6;
		break;
	case DATA_12HOUR:
		index = 12;
		break;
	case DATA_1DAY:
		index = 24;
		break;
	default:
		_E("Wrong message arguments! %d", period);
		return RESOURCED_ERROR_FAIL;
	}

	if (!heart_cpu_app_list) {
		_E("empty app list");
		return RESOURCED_ERROR_FAIL;
	}

	if (!g_hash_table_size(heart_cpu_app_list)) {
		_E("hash table is empty");
		return RESOURCED_ERROR_FAIL;
	}

	ret = pthread_mutex_lock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}

	g_hash_table_iter_init(&h_iter, heart_cpu_app_list);

	while (g_hash_table_iter_next(&h_iter, &key, &value)) {

		table = (struct heart_cpu_table *)value;
		cdata = malloc(sizeof(struct heart_cpu_data));
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
		if (period == DATA_LATEST) {
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
				struct heart_cpu_info *cpu_info;
				cpu_info =
					g_array_index(table->cpu_info, struct heart_cpu_info *, i);
				if (!cpu_info)
					break;
				cdata->utime += cpu_info->utime;
				cdata->stime += cpu_info->stime;
			}
		}
		g_array_append_val(arrays, cdata);
	}
	ret = pthread_mutex_unlock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
unlock_out_of_memory_exit:
	ret = pthread_mutex_unlock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_OUT_OF_MEMORY;
}

int heart_cpu_get_appusage_list(GHashTable *lists, int top)
{
	int index = top, i, ret;
	gpointer value;
	gpointer key;
	GHashTableIter h_iter;
	struct heart_cpu_table *table;
	struct heart_app_usage lau;
	GArray *app_lists = NULL;

	if (!heart_cpu_app_list) {
		_E("empty app list");
		return RESOURCED_ERROR_FAIL;
	}

	if (!g_hash_table_size(heart_cpu_app_list)) {
		_E("hash table is empty");
		return RESOURCED_ERROR_FAIL;
	}

	app_lists = g_array_new(false, false, sizeof(struct heart_app_usage));
	ret = pthread_mutex_lock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}

	g_hash_table_iter_init(&h_iter, heart_cpu_app_list);

	while (g_hash_table_iter_next(&h_iter, &key, &value)) {

		table = (struct heart_cpu_table *)value;
		if (!table->fg_count)
			continue;

		lau.appid = table->appid;
		lau.pkgid = table->pkgid;
		lau.fg_count = table->fg_count;
		lau.used_time = table->fg_time;
		lau.point = (int)heart_cpu_get_point(lau.fg_count, lau.used_time);
		/*
		 * make all application lists with weighted point value excepting service application
		 */
		g_array_append_val(app_lists, lau);
	}
	ret = pthread_mutex_unlock(&heart_cpu_mutex);
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
		struct heart_app_usage *usage = &g_array_index(app_lists, struct heart_app_usage, i);
		_D("appid : %s, point : %d", usage->appid, usage->point);
		g_hash_table_insert(lists, g_strndup(usage->appid, strlen(usage->appid)), GINT_TO_POINTER(1));
	}
	g_array_free(app_lists, true);
	return RESOURCED_ERROR_NONE;
}

static DBusMessage *edbus_heart_get_cpu_data(E_DBus_Object *obj, DBusMessage *msg)
{
	int period, index, i, ret;
	char *appid;
	struct heart_cpu_table *table;

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
	case DATA_LATEST:
		index = 0;
		break;
	case DATA_3HOUR:
		index = 3;
		break;
	case DATA_6HOUR:
		index = 6;
		break;
	case DATA_12HOUR:
		index = 12;
		break;
	case DATA_1DAY:
		index = 24;
		break;
	default:
		_E("Wrong message arguments! %d", period);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	if (!heart_cpu_app_list) {
		_E("empty app list");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	if (!g_hash_table_size(heart_cpu_app_list)) {
		_E("hash table is empty");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init_append(reply, &iter);
	ret = pthread_mutex_lock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	table = g_hash_table_lookup(heart_cpu_app_list, (gconstpointer)appid);
	if (!table) {
		goto unlock_exit;
	}
	if (period == DATA_LATEST) {
		utime = table->total_utime;
		stime = table->total_stime;
	} else {
		utime = table->utime;
		stime = table->stime;
		i =  table->cpu_info->len;
		if (i < index)
			index = i;
		for (i = 0; i < index; i++) {
			struct heart_cpu_info *ci;
			ci = g_array_index(table->cpu_info, struct heart_cpu_info *, i);
			if (!ci)
				break;
			utime += ci->utime;
			stime += ci->stime;
		}
	}
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &utime);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &stime);
unlock_exit:
	ret = pthread_mutex_unlock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	return reply;
}

static DBusMessage *edbus_heart_get_cpu_data_list(E_DBus_Object *obj, DBusMessage *msg)
{
	int period, index, i, ret;
	gpointer value;
	gpointer key;
	GHashTableIter h_iter;
	struct heart_cpu_table *table;

	DBusMessage *reply;
	DBusMessageIter d_iter;
	DBusMessageIter arr;
	char *appid;
	unsigned long utime, stime, ftime, total;
	utime = stime = ftime = total = 0;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &period, DBUS_TYPE_INVALID);

	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	heart_cpu_update_app_list(NULL);

        logging_save_to_storage(true);
	/* update data list from db */
	logging_update(true);

	switch (period) {
	case DATA_LATEST:
		index = 0;
		break;
	case DATA_3HOUR:
		index = 3;
		break;
	case DATA_6HOUR:
		index = 6;
		break;
	case DATA_12HOUR:
		index = 12;
		break;
	case DATA_1DAY:
		index = 24;
		break;
	default:
		_E("Wrong message arguments! %d", period);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	if (!heart_cpu_app_list) {
		_E("empty app list");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	if (!g_hash_table_size(heart_cpu_app_list)) {
		_E("hash table is empty");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init_append(reply, &d_iter);
	dbus_message_iter_open_container(&d_iter, DBUS_TYPE_ARRAY, "(sii)", &arr);
	ret = pthread_mutex_lock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		dbus_message_iter_close_container(&d_iter, &arr);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	g_hash_table_iter_init(&h_iter, heart_cpu_app_list);

	while (g_hash_table_iter_next(&h_iter, &key, &value)) {
		DBusMessageIter sub;

		table = (struct heart_cpu_table *)value;
		if (!table)
			break;
		if (period == DATA_LATEST) {
			utime = table->total_utime;
			stime = table->total_stime;
		} else {
			utime = table->utime;
			stime = table->stime;
			i =  table->cpu_info->len;
			if (i < index)
				index = i;
			for (i = 0; i < index; i++) {
				struct heart_cpu_info *ci;
				ci = g_array_index(table->cpu_info, struct heart_cpu_info *, i);
				if (!ci)
					break;
				utime += ci->utime;
				stime += ci->stime;
			}
		}
		ftime = table->fg_time;
		total = utime + stime;
		if (total == 0)
			continue;
		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		appid = table->appid;
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &appid);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &total);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &ftime);
		dbus_message_iter_close_container(&arr, &sub);
	}

	ret = pthread_mutex_unlock(&heart_cpu_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		dbus_message_iter_close_container(&d_iter, &arr);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	dbus_message_iter_close_container(&d_iter, &arr);

	return reply;
}

static DBusMessage *edbus_heart_reset_cpu_data(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	DBusMessage *reply;
	DBusMessageIter iter;

	if (!heart_cpu_app_list) {
		_E("empty app list");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	if (!g_hash_table_size(heart_cpu_app_list)) {
		_E("hash table is empty");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	ret = heart_cpu_hashtable_renew(heart_cpu_app_list, time(NULL));

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);

	return reply;
}

static DBusMessage *edbus_heart_update_cpu_data(E_DBus_Object *obj, DBusMessage *msg)
{

	int ret = 0;
	DBusMessage *reply;
	DBusMessageIter iter;

	heart_cpu_update_app_list(NULL);
	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);
	return reply;
}

static DBusMessage *edbus_heart_save_to_file(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	DBusMessage *reply;
	DBusMessageIter iter;

	ret = heart_cpu_save_to_file(heart_cpu_app_list, HEART_CPU_DATA_FILE);
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
	{ "GetCpuData",      "si",   "ii",     edbus_heart_get_cpu_data },
	{ "GetCpuDataList",   "i",   "a(sii)", edbus_heart_get_cpu_data_list },
	{ "ResetCpuData",    NULL,   "i",      edbus_heart_reset_cpu_data },
	{ "UpdateCpuData",   NULL,   "i",      edbus_heart_update_cpu_data },
	{ "SaveCpuData",     NULL,   "i",      edbus_heart_save_to_file },
};

static int heart_cpu_reset(void *data)
{
	return heart_cpu_hashtable_renew(heart_cpu_app_list, time(NULL));
}

static int heart_cpu_init(void *data)
{
	int ret;

	ret = logging_module_init(CPU_NAME, ONE_DAY, TEN_MINUTE, heart_cpu_update, TEN_MINUTE);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("logging module init failed");
		return RESOURCED_ERROR_FAIL;
	}
	if (!heart_cpu_app_list) {
		heart_cpu_app_list = g_hash_table_new_full(
				g_str_hash,
				g_str_equal,
				NULL,
				heart_free_value);

		/* make hash from file */
		ret = heart_cpu_read_from_file(heart_cpu_app_list, HEART_CPU_DATA_FILE);

		if (ret == RESOURCED_ERROR_OUT_OF_MEMORY) {
			_E("heart_cpu_init failed");
			return ret;
		}
	}

	ret = edbus_add_methods(RESOURCED_PATH_LOGGING, edbus_methods,
			ARRAY_SIZE(edbus_methods));
	if (ret != RESOURCED_ERROR_NONE) {
		_E("DBus method registration for %s is failed",
				RESOURCED_PATH_LOGGING);
	}

	register_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, heart_cpu_service_launch);
	register_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, heart_cpu_foreground_state);
	register_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, heart_cpu_background_state);
	register_notifier(RESOURCED_NOTIFIER_DATA_UPDATE, heart_cpu_update_app_list);
	register_notifier(RESOURCED_NOTIFIER_DATA_RESET, heart_cpu_reset);

	last_file_commit_time = logging_get_time(CLOCK_BOOTTIME);

	_D("heart cpu init finished");
	return RESOURCED_ERROR_NONE;
}

static int heart_cpu_exit(void *data)
{
	unregister_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, heart_cpu_service_launch);
	unregister_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, heart_cpu_foreground_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, heart_cpu_background_state);
	unregister_notifier(RESOURCED_NOTIFIER_DATA_UPDATE, heart_cpu_update_app_list);
	unregister_notifier(RESOURCED_NOTIFIER_DATA_RESET, heart_cpu_reset);

	if (heart_cpu_app_list) {
		heart_cpu_save_to_file(heart_cpu_app_list, HEART_CPU_DATA_FILE);
		if (heart_cpu_app_list)
			g_hash_table_destroy(heart_cpu_app_list);
	}

	logging_module_exit();

	_D("heart cpu exit");
	return RESOURCED_ERROR_NONE;
}

static int heart_cpu_dump(FILE *fp, int mode, void *data)
{
	time_t starttime;
	char timestr[80];
	struct tm loc_tm;
	static GHashTable *cpu_usage_list;
	gpointer value;
	gpointer key;
	GHashTableIter h_iter;
	struct heart_cpu_table *table;

	starttime = time(NULL);

	starttime -= mode;
	localtime_r(&starttime, &loc_tm);
	/* print timestamp */
	strftime(timestr, sizeof(timestr),
			"%Y-%m-%d %H:%M:%S%z", &loc_tm);

	cpu_usage_list = g_hash_table_new_full(
			g_str_hash,
			g_str_equal,
			NULL,
			free);


	logging_read_foreach(CPU_NAME, NULL, NULL, starttime, 0,
			heart_cpu_update, cpu_usage_list);

	if (!g_hash_table_size(cpu_usage_list)) {
		_E("hash table is empty");
		return 0;
	}

	LOG_DUMP(fp, "[CPU USAGE LISTS] since %s\n", timestr);
	LOG_DUMP(fp, "appid pkgid total fg_count fg_time\n");
	g_hash_table_iter_init(&h_iter, cpu_usage_list);

	while (g_hash_table_iter_next(&h_iter, &key, &value)) {

		table = (struct heart_cpu_table *)value;
		if (!table)
			break;
		LOG_DUMP(fp, "%s %s %ld %d %ld\n", table->appid, table->pkgid,
				table->total_utime + table->total_stime,
				table->fg_count, table->fg_time);
	}
	fflush(fp);
	g_hash_table_destroy(cpu_usage_list);

	return RESOURCED_ERROR_NONE;
}

static const struct heart_module_ops heart_cpu_ops = {
	.name           = "CPU",
	.init           = heart_cpu_init,
	.dump		= heart_cpu_dump,
	.exit           = heart_cpu_exit,
};
HEART_MODULE_REGISTER(&heart_cpu_ops)
