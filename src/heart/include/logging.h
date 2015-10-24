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
 * @file logging.h
 * @desc define structures and functions for logging.
 **/

#ifndef __LOGGING_H__
#define __LOGGING_H__

#include <stdio.h>
#include <time.h>
#include "const.h"

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME                          7
#endif

#define STRINGFY(x) #x
#define KEY_TO_STRING(x) STRINGFY(x)

#define LOGGING_DB_FILE_NAME			"/opt/usr/dbspace/.resourced-logging.db"
#define LOGGING_LEVEL_DB_FILE_NAME		"/opt/usr/dbspace/.resourced-logging-leveldb"
#define HOUR_TO_SEC(x)				(x*3600)
#define DAY_TO_SEC(x)				(x*HOUR_TO_SEC(24))
#define MONTH_TO_SEC(x)				(x*DAY_TO_SEC(30))

enum logging_interval {
	ONE_MINUTE = 60,
	FIVE_MINUTE = 300,
	TEN_MINUTE = 600,
	HALF_HOUR = 1800
};

enum logging_period {
	ONE_HOUR,
	THREE_HOUR,
	SIX_HOUR,
	TWELVE_HOUR,
	ONE_DAY,
	ONE_WEEK,
	ONE_MONTH,
	FOUR_MONTH
};

enum logging_operation {
	INSERT = 0,
	DELETE
};

struct logging_table_form {
	char appid[MAX_APPID_LENGTH];
	char pkgid[MAX_PKGNAME_LENGTH];
	time_t time;
	char *data;
	int operation;
};

struct logging_object {
	int ref;
};

struct logging_data {
	char *appid;
	char *pkgid;
	char *data;
};

typedef void(*logging_info_cb) (struct logging_table_form *data, void *user_data);
typedef void(*logging_listener_cb) (char *data);

int logging_init(void *data);
int logging_exit(void *data);
time_t logging_get_time(int clk_id);
long logging_get_time_ms(void);
int logging_module_init(char *name, enum logging_period max_period,
		enum logging_interval save_interval, logging_info_cb func, enum logging_interval update_interval);
int logging_module_init_with_db_path(char *name, enum logging_period max_period,
		enum logging_interval save_interval, logging_info_cb func, enum logging_interval update_interval,
		const char *db_path);
int logging_module_exit(void);
int logging_register_listener(char *name, logging_listener_cb listener);
int logging_unregister_listener(char *name, logging_listener_cb listener);
int logging_get_latest_in_cache(char *name, char *appid, char **data);
int logging_write(char *name, char *appid, char *pkgid, time_t time, char *data);
int logging_delete(char *name, char *data);
int logging_read_foreach(char *name, char *appid, char *pkgid,
		time_t start_time, time_t end_time, logging_info_cb callback, void *user_data);
void logging_update(int force);
void logging_save_to_storage(int force);
int logging_leveldb_put(char *key, unsigned int key_len, char *value, unsigned int value_len);
int logging_leveldb_putv(char *key, unsigned int key_len, const char *fmt, ... );
int logging_leveldb_read(char *key, unsigned int key_len, char *value, unsigned int value_len);
int logging_leveldb_delete(char *key, unsigned int key_len);

#endif /*__LOGGING_H__*/
