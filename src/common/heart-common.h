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
 * @file heart-common.h
 * @desc heart common interface
 **/

#ifndef __HEART_COMMON_H__
#define __HEART_COMMON_H__

#include <stdio.h>
#include <time.h>
#include "const.h"

/* period data types */
enum heart_data_period {
	DATA_LATEST,
	DATA_3HOUR,
	DATA_6HOUR,
	DATA_12HOUR,
	DATA_1DAY,
	DATA_1WEEK,
};

struct heart_cpu_data {
	char appid[MAX_APPID_LENGTH];
	char pkgid[MAX_PKGNAME_LENGTH];
	unsigned long utime;
	unsigned long stime;
};

struct heart_app_usage {
	char *appid;
	char *pkgid;
	int fg_count;
	time_t used_time;
	int point;
};

struct heart_memory_data {
	char appid[MAX_APPID_LENGTH];
	char pkgid[MAX_PKGNAME_LENGTH];
	unsigned int max_pss;
	unsigned int avg_pss;
	unsigned int max_uss;
	unsigned int avg_uss;
};

struct heart_battery_capacity {
	time_t timestamp;
	int capacity;
	int diff_capacity;
	long used_time;
	long charging_time;
	int charger_status;
	int reset_mark;
};
/* battery capacity history*/
int heart_battery_get_capacity_history_latest(GArray *arrays, int charge, int max_size);
int heart_battery_get_capacity_history(GArray *arrays, enum heart_data_period period);

/* cpu */
int heart_cpu_get_table(GArray *arrays, enum heart_data_period period);
struct heart_cpu_data *heart_cpu_get_data(char *appid, enum heart_data_period period);
int heart_cpu_get_appusage_list(GHashTable *lists, int top);

/* memory */
int heart_memory_get_query(GArray *arrays, enum heart_data_period period);
int heart_memory_get_foreach(GArray *arrays, enum heart_data_period period);
int heart_memory_get_table(GArray *arrays, enum heart_data_period period);
int heart_memory_save(void);
struct heart_memory_data *heart_memory_get_data(char *appid, enum heart_data_period period);
int heart_memory_get_latest_data(char *appid, unsigned int *pss, unsigned int *uss);

#endif /* __heart_COMMON_H__ */
