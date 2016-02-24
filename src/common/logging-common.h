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
 *
 */

/**
 * @file logging-common.h
 * @desc logging common process
 **/

#ifndef __LOGGING_COMMON_H__
#define __LOGGING_COMMON_H__

#include <stdio.h>
#include <time.h>
#include "const.h"

/* period data types */
enum logging_data_period {
	LOGGING_LATEST,
	LOGGING_3HOUR,
	LOGGING_6HOUR,
	LOGGING_12HOUR,
	LOGGING_24HOUR,
};

struct logging_cpu_data {
	char appid[MAX_APPID_LENGTH];
	char pkgid[MAX_PKGNAME_LENGTH];
	unsigned int utime;
	unsigned int stime;
};

struct logging_app_usage {
	char *appid;
	char *pkgid;
	int fg_count;
	time_t used_time;
	int point;
};

struct logging_memory_data {
	char appid[MAX_APPID_LENGTH];
	char pkgid[MAX_PKGNAME_LENGTH];
	unsigned int max_pss;
	unsigned int avg_pss;
	unsigned int max_uss;
	unsigned int avg_uss;
};

struct logging_battery_capacity {
	time_t timestamp;
	int capacity;
	int diff_capacity;
	long used_time;
	long charging_time;
	int charger_status;
	int reset_mark;
};

int logging_battery_get_capacity_history_latest(GArray *arrays, int charge, int max_size);
int logging_battery_get_capacity_history(GArray *arrays, enum logging_data_period period);
int logging_cpu_get_table(GArray *arrays, enum logging_data_period period);
struct logging_cpu_data *logging_cpu_get_data(char *appid, enum logging_data_period period);
int logging_cpu_get_appusage_list(GHashTable *lists, int top);
int logging_memory_get_query(GArray *arrays, enum logging_data_period period);
int logging_memory_get_foreach(GArray *arrays, enum logging_data_period period);
int logging_memory_get_table(GArray *arrays, enum logging_data_period period);
int logging_memory_save(void);
struct logging_memory_data *logging_memory_get_data(char *appid, enum logging_data_period period);
int logging_memory_get_latest_data(char *appid, unsigned int *pss, unsigned int *uss);

#endif /* __LOGGING_COMMON_H__ */
