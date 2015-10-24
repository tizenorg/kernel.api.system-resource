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
 * @file heart-battery.c
 *
 * @desc heart battery module
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <glib.h>

#include "proc-common.h"
#include "notifier.h"
#include "resourced.h"
#include "edbus-handler.h"
#include "heart.h"
#include "logging.h"
#include "heart-common.h"
#include "config-parser.h"
#include "trace.h"
#include "module.h"
#include "macro.h"

#define TIZEN_SYSTEM_APPID			"org.tizen.system"
#define TIZEN_SYSTEM_BATTERY_APPID		"org.tizen.system.battery.capacity"
#define BATTERY_NAME				"battery"
#define BATTERY_DATA_MAX			1024
#define BATTERY_CAPACITY_MAX			512
#define BATTERY_LINE_MAX			128
#define BATTERY_CLEAN_MAX			100
#define BATTERY_HISTORY_DAY_MAX			7
#define BATTERY_HISTORY_RESET_MAX		5
#define BATTERY_HISTORY_RESET_CURRENT		(BATTERY_HISTORY_RESET_MAX - 1)
#define BATTERY_HISTORY_SECONDS_MAX		DAY_TO_SEC(BATTERY_HISTORY_DAY_MAX)
#define BATTERY_HISTORY_COUNT_MAX		1000
#define HEART_BATTERY_UPDATE_INTERVAL		HALF_HOUR
#define HEART_BATTERY_SAVE_INTERVAL		HALF_HOUR
#define HEART_BATTERY_CAPACITY_DATA_FILE	HEART_FILE_PATH"/.battery_capacity.dat"
#define HEART_BATTERY_CONF_SECTION              "BATTERY_POWER_MODE"
#define GET_CHARGER_STATUS			"ChargerStatus"
#define GET_BATTERY_CAPACITY			"GetPercent"
#define CALCULATE_DAY_BASE_TIME(x)		((x / DAY_TO_SEC(1)) * (DAY_TO_SEC(1)))
#define REMAIN_CAPACITY(x)			(100 - x)
#define BATTERY_PREDICTION_DATA_MIN		5
#define CUMUL_WEIGHT				(0.8)
#define TREND_WEIGHT				(1 - CUMUL_WEIGHT)
/*
 * BATTERY_PREDICTION_LATEST_COUNT must be >= BATTERY_PREDICTION_DATA_MIN
 */
#define BATTERY_PREDICTION_LATEST_COUNT		5
/*
 * BATTERY_PREDICTION_PERIOD possible values:
 * DATA_LATEST, DATA_3HOUR, DATA_6HOUR, DATA_12HOUR, DATA_1DAY
 */
#define BATTERY_PREDICTION_PERIOD		DATA_3HOUR

#define BATTERY_USED_TIME                       "BATTERY_USED_TIME"
#define BATTERY_STATUS                          "BATTERY_STATUS"
#define BATTERY_RESET_USAGE                     "BATTERY_RESET_USAGE"
#define BATTERY_WEEK_DAY_USAGE                  "BATTERY_WEEK_DAY_USAGE"
#define BATTERY_LEVEL_USAGE                     "BATTERY_LEVEL_USAGE"
#define BATTERY_PREDICTION                      "BATTERY_PREDICTION"

enum {
	TA     = 0,	/* prediction based on total data average */
	PCB    = 1,	/* prediction with physiological behaviors */
	WEEK   = 2,	/* prediction based on weekly data */
	COUNT  = 3,	/* prediction based on last BATTERY_PREDICTION_COUNT number of items */
	PERIOD = 4,	/* prediction based on data from last BATTERY_PREDICTION_PERIOD time */
	MAX_STRATEGY = 5,
};

enum {
	POWER_NORMAL_MODE  = 0,
	POWER_SAVING_MODE  = 1,
	ULTRA_SAVING_MODE  = 2,
	POWER_MODE_MAX     = 3,
};

enum charging_goal {
	DISCHARGING = 0,
	CHARGING = 1,
	MAX_CHARGER_STATE = 2,
};

enum {
	BATTERY_LEVEL_LOW = 0, /* 15 ~ 0 */
	BATTERY_LEVEL_MID = 1, /* 49 ~ 16 */
	BATTERY_LEVEL_HIGH = 2, /* 50 ~ 100 */
	BATTERY_LEVEL_MAX = 3,
};

enum {
	DEFAULT_MIN = 0,
	DEFAULT_AVG = 1,
	DEFAULT_MAX = 2,
	DEFAULT_VALUE_MAX = 3,
};

struct battery_used {
	time_t used_time_sec; /* seconds on battery */
	time_t last_update_time;
	int last_charger_status;
};

struct battery_usage {
	time_t start_time; /* timestamp when event started */
	long sec_per_cap[MAX_CHARGER_STATE]; /* seconds per capacity level change */
	long cap_counter[MAX_CHARGER_STATE]; /* number of capacity level changes */
};

struct battery_prediction {
	long sec_per_cap[MAX_STRATEGY]; /* seconds per capacity level change */
	long cap_counter[MAX_STRATEGY]; /* number of capacity level changes */
	long time_pred_min[MAX_STRATEGY]; /* time prediction in minutes */
};

struct battery_status {
	/* current battery status */
	int curr_charger_status;
	int curr_capacity;

	/* current runtime statistics */
	long curr_run_time_sec[MAX_CHARGER_STATE]; /* seconds since reset */
	long curr_cap_counter[MAX_CHARGER_STATE]; /* capacity level changes */

	/* wall clock time stamp when last event happened in milliseconds */
	long last_event_wall_time_ms;

	/*
	 * reset mark is set when battery is charged in over 90% and
	 * charger was disconnected from the device.
	 * We consider then the device as "charged"
	 *
	 * The possible values are 0 and 1 they're swapped to opposite on change.
	 */
	int reset_mark;
	time_t reset_mark_timestamp;

	/* usage time from last reset_mark change*/
	struct battery_usage batt_reset_usage[BATTERY_HISTORY_RESET_MAX];

	/* usage time by week day */
	struct battery_usage week_day_usage[BATTERY_HISTORY_DAY_MAX];

	/* usage time by user behavior & battery level */
	struct battery_usage batt_lvl_usage[BATTERY_LEVEL_MAX];

	/* calculated battery prediction */
	struct battery_prediction prediction[MAX_CHARGER_STATE];
};

static int default_sec_per_cap[MAX_CHARGER_STATE][DEFAULT_VALUE_MAX] = {
	{ 70, 430, 43200 }, /* DISCHARGING MIN: 70s, AVG: 430s, MAX: 12h */
	{ 30, 80, 3600 }    /* CHARGING MIN: 30s, AVG: 80s,  MAX: 1 hour */
};

static double default_mode_spc[POWER_MODE_MAX] = {
	430,	/* POWER_NORMAL_MODE */
	520,	/* POWER_SAVING_MODE */
	1010	/* ULTRA_SAVING_MODE */
};

static double default_mode_factor[POWER_MODE_MAX] = {
	1,	/* POWER_NORMAL_MODE */
	1.2,	/* POWER_SAVING_MODE */
	2.35	/* ULTRA_SAVING_MODE */
};

static struct battery_used batt_used;
static struct battery_status batt_stat;
static GSList *capacity_history_list = NULL;
static pthread_mutex_t heart_battery_mutex = PTHREAD_MUTEX_INITIALIZER;
static time_t last_file_commit_time;

inline void heart_battery_set_usage_reset_stime(int history, time_t start_time)
{
	batt_stat.batt_reset_usage[history].start_time = start_time;
}

inline time_t heart_battery_get_usage_reset_stime(int history)
{
	return batt_stat.batt_reset_usage[history].start_time;
}

inline void heart_battery_set_usage_reset(int history, int status, long sec_per_cap, long cap_counter)
{
	batt_stat.batt_reset_usage[history].sec_per_cap[status] = sec_per_cap;
	batt_stat.batt_reset_usage[history].cap_counter[status] = cap_counter;
}

inline long heart_battery_get_usage_reset_total_time(int history, int status)
{
	return batt_stat.batt_reset_usage[history].sec_per_cap[status] * batt_stat.batt_reset_usage[history].cap_counter[status];
}

inline long heart_battery_get_usage_reset_count(int history, int status)
{
	return batt_stat.batt_reset_usage[history].cap_counter[status];
}

inline void heart_battery_set_usage_level_stime(int level, time_t start_time)
{
	batt_stat.batt_lvl_usage[level].start_time = start_time;
}

inline time_t heart_battery_get_usage_level_stime(int level)
{
	return batt_stat.batt_lvl_usage[level].start_time;
}

inline void heart_battery_set_usage_level(int level, int status, long sec_per_cap, long cap_counter)
{
	batt_stat.batt_lvl_usage[level].sec_per_cap[status] = sec_per_cap;
	batt_stat.batt_lvl_usage[level].cap_counter[status] = cap_counter;
}

inline long heart_battery_get_usage_level_total_time(int level, int status)
{
	return batt_stat.batt_lvl_usage[level].sec_per_cap[status] * batt_stat.batt_lvl_usage[level].cap_counter[status];
}

inline long heart_battery_get_usage_level_spc(int level, int status)
{
	return batt_stat.batt_lvl_usage[level].sec_per_cap[status];
}

inline long heart_battery_get_usage_level_count(int level, int status)
{
	return batt_stat.batt_lvl_usage[level].cap_counter[status];
}

inline long heart_battery_get_usage_week_total_time(int day, int status)
{
	return batt_stat.week_day_usage[day].sec_per_cap[status] * batt_stat.week_day_usage[day].cap_counter[status];
}

inline long heart_battery_get_usage_week_count(int day, int status)
{
	return batt_stat.week_day_usage[day].cap_counter[status];
}

inline void heart_battery_set_usage_week_stime(int day, time_t start_time)
{
	batt_stat.week_day_usage[day].start_time = start_time;
}

inline time_t heart_battery_get_usage_week_stime(int day)
{
	return batt_stat.week_day_usage[day].start_time;
}

inline void heart_battery_set_usage_week(int day, int status, long sec_per_cap, long cap_counter)
{
	batt_stat.week_day_usage[day].sec_per_cap[status] = sec_per_cap;
	batt_stat.week_day_usage[day].cap_counter[status] = cap_counter;
}

inline void heart_battery_set_prediction(int strategy, int status, long sec_per_cap, long cap_counter, long pred_min)
{
	batt_stat.prediction[status].sec_per_cap[strategy] = sec_per_cap;
	batt_stat.prediction[status].cap_counter[strategy] = cap_counter;
	batt_stat.prediction[status].time_pred_min[strategy] = pred_min;
}

inline long heart_battery_get_prediction_time(int strategy, int status)
{
	return batt_stat.prediction[status].time_pred_min[strategy];
}

inline time_t heart_battery_get_file_commit_timestamp()
{
	return last_file_commit_time;
}

inline void heart_battery_set_file_commit_timestamp(time_t timestamp)
{
	last_file_commit_time = timestamp;
}

static int heart_battery_save_used_time(char *key, struct battery_used *used)
{
	if (!key || !used)
		return RESOURCED_ERROR_FAIL;

	logging_leveldb_putv(key, strlen(key), "%d %d ",
			used->used_time_sec, used->last_update_time);
	return RESOURCED_ERROR_NONE;
};

static int heart_battery_save_status(char *key, struct battery_status *status)
{
	if (!key || !status)
		return RESOURCED_ERROR_FAIL;

	logging_leveldb_putv(key, strlen(key), "%d %ld %ld %ld %ld %d %d ",
			status->curr_capacity,
			status->curr_run_time_sec[DISCHARGING],
			status->curr_cap_counter[DISCHARGING],
			status->curr_run_time_sec[CHARGING],
			status->curr_cap_counter[CHARGING],
			status->curr_charger_status,
			status->reset_mark);
	return RESOURCED_ERROR_NONE;
};

static int heart_battery_save_usage(char *key, struct battery_usage *usage, int total_size)
{
	int i, len, num;
	char buf[BATTERY_DATA_MAX] = {0, };

	if (!key || !usage)
		return RESOURCED_ERROR_FAIL;
	len = 0;
	num = total_size/sizeof(struct battery_usage);
	for (i = 0; i < num; i++) {
		len += snprintf(buf + len, BATTERY_DATA_MAX - len, "%ld %ld %ld %ld %ld ",
				usage[i].start_time,
				usage[i].sec_per_cap[DISCHARGING],
				usage[i].cap_counter[DISCHARGING],
				usage[i].sec_per_cap[CHARGING],
				usage[i].cap_counter[CHARGING]);
	}
	logging_leveldb_put(key, strlen(key), buf, len);
	return RESOURCED_ERROR_NONE;
};

static int heart_battery_save_prediction(char *key, struct battery_prediction *prediction)
{
	int i, len;
	char buf[BATTERY_DATA_MAX] = {0, };

	if (!key || !prediction)
		return RESOURCED_ERROR_FAIL;
	len = 0;
	for (i = 0; i < MAX_STRATEGY; i++) {
		len += snprintf(buf + len, BATTERY_DATA_MAX - len, "%ld %ld %ld %ld %ld %ld ",
				prediction[DISCHARGING].sec_per_cap[i],
				prediction[DISCHARGING].cap_counter[i],
				prediction[DISCHARGING].time_pred_min[i],
				prediction[CHARGING].sec_per_cap[i],
				prediction[CHARGING].cap_counter[i],
				prediction[CHARGING].time_pred_min[i]);
	}
	logging_leveldb_put(key, strlen(key), buf, len);
	return RESOURCED_ERROR_NONE;
};


static int heart_battery_load_used_time(char *key, struct battery_used *used)
{
	int ret;
	char *token;
	char buf[BATTERY_DATA_MAX] = {0, };
	char *saveptr;

	if (!key || !used)
		return RESOURCED_ERROR_FAIL;

	ret = logging_leveldb_read(key, strlen(key), buf, sizeof(buf));
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to read leveldb key: %s", key);
		return RESOURCED_ERROR_FAIL;
	}
	token = strtok_r(buf, " ", &saveptr);
	if (!token) {
		_E("Failed to token value");
		return RESOURCED_ERROR_FAIL;
	}
	used->used_time_sec = atoi(token);
	token = strtok_r(NULL, " ", &saveptr);
	if (!token) {
		_E("Failed to token value");
		return RESOURCED_ERROR_FAIL;
	}
	used->last_update_time = atoi(token);
	return RESOURCED_ERROR_NONE;
};

static int heart_battery_load_status(char *key, struct battery_status *status)
{
	int ret;
	char *token;
	char buf[BATTERY_DATA_MAX] = {0, };
	char *saveptr;

	if (!key || !status)
		return RESOURCED_ERROR_FAIL;

	ret = logging_leveldb_read(key, strlen(key), buf, sizeof(buf));
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to read leveldb key: %s", key);
		return RESOURCED_ERROR_FAIL;
	}
	token = strtok_r(buf, " ", &saveptr);
	if (!token) {
		_E("Failed to token value");
		return RESOURCED_ERROR_FAIL;
	}
	status->curr_capacity = atoi(token);
	token = strtok_r(NULL, " ", &saveptr);
	if (!token) {
		_E("Failed to token value");
		return RESOURCED_ERROR_FAIL;
	}
	status->curr_run_time_sec[DISCHARGING] = atol(token);
	token = strtok_r(NULL, " ", &saveptr);
	if (!token) {
		_E("Failed to token value");
		return RESOURCED_ERROR_FAIL;
	}
	status->curr_cap_counter[DISCHARGING] = atol(token);
	token = strtok_r(NULL, " ", &saveptr);
	if (!token) {
		_E("Failed to token value");
		return RESOURCED_ERROR_FAIL;
	}
	status->curr_run_time_sec[CHARGING] = atol(token);
	token = strtok_r(NULL, " ", &saveptr);
	if (!token) {
		_E("Failed to token value");
		return RESOURCED_ERROR_FAIL;
	}
	status->curr_cap_counter[CHARGING] = atol(token);
	token = strtok_r(NULL, " ", &saveptr);
	if (!token) {
		_E("Failed to token value");
		return RESOURCED_ERROR_FAIL;
	}
	status->curr_charger_status = atoi(token);
	token = strtok_r(NULL, " ", &saveptr);
	if (!token) {
		_E("Failed to token value");
		return RESOURCED_ERROR_FAIL;
	}
	status->reset_mark = atoi(token);
	return RESOURCED_ERROR_NONE;
};

static int heart_battery_load_usage(char *key, struct battery_usage *usage, int total_size)
{
	int i, num, ret;
	char *token;
	char buf[BATTERY_DATA_MAX] = {0, };
	char *saveptr;

	if (!key || !usage)
		return RESOURCED_ERROR_FAIL;

	ret = logging_leveldb_read(key, strlen(key), buf, sizeof(buf));
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to read leveldb key: %s", key);
		return RESOURCED_ERROR_FAIL;
	}
	i = 0;
	num = total_size/sizeof(struct battery_usage);

	token = strtok_r(buf, " ", &saveptr);
	if (!token) {
		_E("Failed to token value");
		return RESOURCED_ERROR_FAIL;
	}
	while (token && i++ < num) {
		usage[i].start_time = atol(token);
		token = strtok_r(NULL, " ", &saveptr);
		if (!token) {
			_E("Failed to token value");
			return RESOURCED_ERROR_FAIL;
		}
		usage[i].sec_per_cap[DISCHARGING] = atol(token);
		token = strtok_r(NULL, " ", &saveptr);
		if (!token) {
			_E("Failed to token value");
			return RESOURCED_ERROR_FAIL;
		}
		usage[i].cap_counter[DISCHARGING] = atol(token);
		token = strtok_r(NULL, " ", &saveptr);
		if (!token) {
			_E("Failed to token value");
			return RESOURCED_ERROR_FAIL;
		}
		usage[i].sec_per_cap[CHARGING] = atol(token);
		token = strtok_r(NULL, " ", &saveptr);
		if (!token) {
			_E("Failed to token value");
			return RESOURCED_ERROR_FAIL;
		}
		usage[i].cap_counter[CHARGING] = atol(token);
		token = strtok_r(NULL, " ", &saveptr);
	}
	return RESOURCED_ERROR_NONE;
};

static int heart_battery_load_prediction(char *key, struct battery_prediction *prediction)
{
	int ret, i;
	char *token;
	char buf[BATTERY_DATA_MAX] = {0, };
	char *saveptr;

	if (!key || !prediction)
		return RESOURCED_ERROR_FAIL;

	ret = logging_leveldb_read(key, strlen(key), buf, sizeof(buf));
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to read leveldb key: %s", key);
		return RESOURCED_ERROR_FAIL;
	}
	token = strtok_r(buf, " ", &saveptr);
	if (!token) {
		_E("Failed to token value");
		return RESOURCED_ERROR_FAIL;
	}
	for (i = 0; i < MAX_STRATEGY && token; i++) {
		prediction[DISCHARGING].sec_per_cap[i] = atol(token);
		token = strtok_r(NULL, " ", &saveptr);
		if (!token) {
			_E("Failed to token value");
			return RESOURCED_ERROR_FAIL;
		}
		prediction[DISCHARGING].cap_counter[i] = atol(token);
		token = strtok_r(NULL, " ", &saveptr);
		if (!token) {
			_E("Failed to token value");
			return RESOURCED_ERROR_FAIL;
		}
		prediction[DISCHARGING].time_pred_min[i] = atol(token);
		token = strtok_r(NULL, " ", &saveptr);
		if (!token) {
			_E("Failed to token value");
			return RESOURCED_ERROR_FAIL;
		}
		prediction[CHARGING].sec_per_cap[i] = atol(token);
		token = strtok_r(NULL, " ", &saveptr);
		if (!token) {
			_E("Failed to token value");
			return RESOURCED_ERROR_FAIL;
		}
		prediction[CHARGING].cap_counter[i] = atol(token);
		token = strtok_r(NULL, " ", &saveptr);
		if (!token) {
			_E("Failed to token value");
			return RESOURCED_ERROR_FAIL;
		}
		prediction[CHARGING].time_pred_min[i] = atol(token);
		token = strtok_r(NULL, " ", &saveptr);
	}
	return RESOURCED_ERROR_NONE;
};

static void heart_battery_update_used_time(time_t now, int status)
{
	if (batt_used.last_charger_status == DISCHARGING)
		batt_used.used_time_sec +=
			now - batt_used.last_update_time;
	batt_used.last_charger_status = status;
	batt_used.last_update_time = now;
	heart_battery_save_used_time(BATTERY_USED_TIME, &batt_used);
}

static int heart_battery_get_capacity_history_size(void)
{
	int size, ret;

	ret = pthread_mutex_lock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	size = g_slist_length(capacity_history_list);
	if (!size) {
		_I("capacity history is empty");
		ret = pthread_mutex_unlock(&heart_battery_mutex);
		if (ret) {
			_E("pthread_mutex_unlock() failed, %d", ret);
			return RESOURCED_ERROR_FAIL;
		}
		return RESOURCED_ERROR_NONE;
	}
	ret = pthread_mutex_unlock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	return size;
}

static void heart_battery_insert_capacity(GSList **history_list, int capacity,
		int diff_capacity, time_t timestamp, long used_time, long charging_time,
		int charger_status, int reset_mark, int clear)
{
	static int old_reset_mark = 0;
	GSList *iter, *next;
	int ret, count;
	struct heart_battery_capacity *lbc, *tlbc;

	lbc = malloc(sizeof(struct heart_battery_capacity));
	if (!lbc) {
		_E("malloc failed");
		return;
	}
	lbc->capacity = capacity;
	lbc->diff_capacity = diff_capacity;
	lbc->used_time = used_time;
	lbc->charging_time = charging_time;
	lbc->charger_status = charger_status;
	lbc->reset_mark = reset_mark;
	lbc->timestamp = timestamp;

	ret = pthread_mutex_lock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		free(lbc);
		return;
	}
	/* clean all history when reset event */
	if (clear && *history_list && lbc->reset_mark != old_reset_mark) {
		g_slist_free_full(*history_list, free);
		*history_list = NULL;
	}

	/* history reached maximum limitation number */
	if (*history_list && g_slist_length(*history_list) > BATTERY_CAPACITY_MAX) {
		count = 0;
		gslist_for_each_safe(*history_list, iter, next, tlbc) {
			*history_list = g_slist_remove(*history_list, (gpointer)tlbc);
			free(tlbc);
			if (BATTERY_CLEAN_MAX < count++)
				break;
		}
	}
	old_reset_mark = lbc->reset_mark;
	*history_list = g_slist_append(*history_list, (gpointer)lbc);
	ret = pthread_mutex_unlock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
	}
}

/* ======================== Serialization/Deserialization ==================== */

static int heart_battery_status_save_to_db(void)
{
	heart_battery_save_used_time(BATTERY_USED_TIME, &batt_used);
	heart_battery_save_status(BATTERY_STATUS, &batt_stat);

	heart_battery_save_usage(BATTERY_RESET_USAGE, batt_stat.batt_reset_usage, sizeof(batt_stat.batt_reset_usage));
	heart_battery_save_usage(BATTERY_WEEK_DAY_USAGE, batt_stat.week_day_usage, sizeof(batt_stat.week_day_usage));
	heart_battery_save_usage(BATTERY_LEVEL_USAGE, batt_stat.batt_lvl_usage, sizeof(batt_stat.batt_lvl_usage));

	heart_battery_save_prediction(BATTERY_PREDICTION, batt_stat.prediction);
	return RESOURCED_ERROR_NONE;
}

static int heart_battery_status_read_from_db(void)
{
	heart_battery_load_used_time(BATTERY_USED_TIME, &batt_used);
	heart_battery_load_status(BATTERY_STATUS, &batt_stat);

	heart_battery_load_usage(BATTERY_RESET_USAGE, batt_stat.batt_reset_usage, sizeof(batt_stat.batt_reset_usage));
	heart_battery_load_usage(BATTERY_WEEK_DAY_USAGE, batt_stat.week_day_usage, sizeof(batt_stat.week_day_usage));
	heart_battery_load_usage(BATTERY_LEVEL_USAGE, batt_stat.batt_lvl_usage, sizeof(batt_stat.batt_lvl_usage));

	heart_battery_load_prediction(BATTERY_PREDICTION, batt_stat.prediction);
	return RESOURCED_ERROR_NONE;
}

static int heart_battery_capacity_save_to_file(char *filename)
{
	int size, ret, count, len = 0;
	struct heart_battery_capacity *lbc;
	GSList *iter, *next;
	FILE *fp;
	char buf[BATTERY_DATA_MAX] = {0, };

	if (!capacity_history_list) {
		_E("capacity history is NULL!");
		return RESOURCED_ERROR_NONE;
	}
	ret = pthread_mutex_lock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	size = g_slist_length(capacity_history_list);
	if (!size) {
		_I("capacity history is empty");
		ret = pthread_mutex_unlock(&heart_battery_mutex);
		if (ret) {
			_E("pthread_mutex_unlock() failed, %d", ret);
			return RESOURCED_ERROR_FAIL;
		}
		return RESOURCED_ERROR_NONE;
	}
	fp = fopen(filename, "w");
	if (!fp) {
		_E("%s fopen failed %d", filename, errno);
		ret = pthread_mutex_unlock(&heart_battery_mutex);
		if (ret) {
			_E("pthread_mutex_unlock() failed, %d", ret);
			return RESOURCED_ERROR_FAIL;
		}
		return RESOURCED_ERROR_FAIL;
	}
	gslist_for_each_item(iter, capacity_history_list) {
		lbc = (struct heart_battery_capacity *)iter->data;
		if (!lbc)
			break;
		len += snprintf(buf + len, BATTERY_DATA_MAX - len, "%d %d %ld %ld %ld %d %d\n",
				lbc->capacity, lbc->diff_capacity, lbc->timestamp, lbc->used_time,
				lbc->charging_time, lbc->charger_status,
				lbc->reset_mark);
		if (BATTERY_DATA_MAX < len + BATTERY_LINE_MAX) {
			fputs(buf, fp);
			len = 0;
		}
	}
	fputs(buf, fp);
	fclose(fp);
	if (BATTERY_CAPACITY_MAX < size) {
		count = 0;
		gslist_for_each_safe(capacity_history_list, iter, next, lbc) {
			capacity_history_list = g_slist_remove(capacity_history_list, (gpointer)lbc);
			free(lbc);
			if (BATTERY_CLEAN_MAX < count++)
				break;
		}
	}
	ret = pthread_mutex_unlock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
}

static int heart_battery_capacity_read_from_file(char *filename)
{
	int len;
	int capacity, diff_capacity, charger_status, reset_mark;
	long used_time, charging_time;
	time_t timestamp;
	FILE *fp;
	char buf[BATTERY_DATA_MAX] = {0, };

	fp = fopen(filename, "r");
	if (!fp) {
		_E("%s fopen failed %d", filename, errno);
		return RESOURCED_ERROR_FAIL;
	}
	while (fgets(buf, BATTERY_DATA_MAX, fp)) {
		len = sscanf(buf, "%d %d %ld %ld %ld %d %d", &capacity, &diff_capacity,
				&timestamp, &used_time, &charging_time,
				&charger_status, &reset_mark);
		if (len < 0) {
			_E("sscanf failed");
			fclose(fp);
			return RESOURCED_ERROR_FAIL;
		}
		heart_battery_insert_capacity(&capacity_history_list, capacity, diff_capacity,
				timestamp, used_time, charging_time,
				charger_status, reset_mark, true);
	}
	fclose(fp);
	return RESOURCED_ERROR_NONE;
}

/* ==================== Serialization/Deserialization END ==================== */

static void heart_battery_save_to_file(bool force)
{
	int ret;
	time_t now = logging_get_time(CLOCK_BOOTTIME);

	heart_battery_update_used_time(now, batt_stat.curr_charger_status);

	if (!force &&
	    heart_battery_get_file_commit_timestamp() + HEART_BATTERY_SAVE_INTERVAL >= now)
		return;

	ret = heart_battery_status_save_to_db();
	if (ret) {
		_E("failed to save status db");
	}

	ret = heart_battery_capacity_save_to_file(HEART_BATTERY_CAPACITY_DATA_FILE);
	if (ret) {
		_E("failed to save capacity file");
	}
	heart_battery_set_file_commit_timestamp(now);
}

void heart_battery_update(struct logging_table_form *data, void *user_data)
{
	heart_battery_save_to_file(false);
}

static int heart_battery_get_level_usage_index(int capacity)
{
	return (capacity > 49) ? BATTERY_LEVEL_HIGH :
		(capacity < 16) ? BATTERY_LEVEL_LOW : BATTERY_LEVEL_MID;
}

static int heart_battery_get_week_day_usage_index(time_t timestamp)
{
	int i;

	for (i = 0; i < BATTERY_HISTORY_DAY_MAX; i++) {
		if (!heart_battery_get_usage_week_stime(i))
			return i;
		else if (abs(timestamp - heart_battery_get_usage_week_stime(i)) < DAY_TO_SEC(1))
			return i;
	}
	for (i = 0; i < BATTERY_HISTORY_DAY_MAX - 1; i++) {
		batt_stat.week_day_usage[i].start_time =
			batt_stat.week_day_usage[i + 1].start_time;
		batt_stat.week_day_usage[i].sec_per_cap[DISCHARGING] =
			batt_stat.week_day_usage[i + 1].sec_per_cap[DISCHARGING];
		batt_stat.week_day_usage[i].sec_per_cap[CHARGING] =
			batt_stat.week_day_usage[i + 1].sec_per_cap[CHARGING];
		batt_stat.week_day_usage[i].cap_counter[DISCHARGING] =
			batt_stat.week_day_usage[i + 1].cap_counter[DISCHARGING];
		batt_stat.week_day_usage[i].cap_counter[CHARGING] =
			batt_stat.week_day_usage[i + 1].cap_counter[CHARGING];
	}
	return BATTERY_HISTORY_DAY_MAX - 1;
}

static int heart_battery_get_batt_reset_usage_index(void)
{
	int i;

	for(i = 0; i < BATTERY_HISTORY_RESET_MAX; i++) {
		if (heart_battery_get_usage_reset_count(i, DISCHARGING) < BATTERY_HISTORY_COUNT_MAX
			&& heart_battery_get_usage_reset_count(i, CHARGING) < BATTERY_HISTORY_COUNT_MAX)
			return i;
	}
	for (i = 0; i < BATTERY_HISTORY_RESET_MAX - 1; i++) {
		batt_stat.batt_reset_usage[i].start_time =
			batt_stat.batt_reset_usage[i + 1].start_time;
		batt_stat.batt_reset_usage[i].sec_per_cap[DISCHARGING] =
			batt_stat.batt_reset_usage[i + 1].sec_per_cap[DISCHARGING];
		batt_stat.batt_reset_usage[i].sec_per_cap[CHARGING] =
			batt_stat.batt_reset_usage[i + 1].sec_per_cap[CHARGING];
		batt_stat.batt_reset_usage[i].cap_counter[DISCHARGING] =
			batt_stat.batt_reset_usage[i + 1].cap_counter[DISCHARGING];
		batt_stat.batt_reset_usage[i].cap_counter[CHARGING] =
			batt_stat.batt_reset_usage[i + 1].cap_counter[CHARGING];
	}
	return BATTERY_HISTORY_RESET_CURRENT;
}

static int heart_battery_reset(void *data)
{
	int idx;
	long total_time, total_count, sec_per_cap;

	idx = heart_battery_get_batt_reset_usage_index();

	/* DISCHARGING */
	total_time = 0; total_count = 0;
	total_time = heart_battery_get_usage_reset_total_time(idx, DISCHARGING) + batt_stat.curr_run_time_sec[DISCHARGING];
	total_count = heart_battery_get_usage_reset_count(idx, DISCHARGING) + batt_stat.curr_cap_counter[DISCHARGING];

	if (total_time && total_count) {
		sec_per_cap = total_time / total_count;
		if (sec_per_cap < default_sec_per_cap[DISCHARGING][DEFAULT_MIN])
			sec_per_cap = default_sec_per_cap[DISCHARGING][DEFAULT_MIN];
		else if (sec_per_cap > default_sec_per_cap[DISCHARGING][DEFAULT_MAX])
			sec_per_cap = default_sec_per_cap[DISCHARGING][DEFAULT_AVG];
		heart_battery_set_usage_reset(idx, DISCHARGING, sec_per_cap, total_count);
	}
	/* CHARGING */
	total_time = 0; total_count = 0;
	total_time = heart_battery_get_usage_reset_total_time(idx, CHARGING)
		+ batt_stat.curr_run_time_sec[CHARGING];
	total_count = heart_battery_get_usage_reset_count(idx, CHARGING) + batt_stat.curr_cap_counter[CHARGING];

	if (total_time && total_count) {
		sec_per_cap = total_time / total_count;
		if (sec_per_cap < default_sec_per_cap[CHARGING][DEFAULT_MIN])
			sec_per_cap = default_sec_per_cap[CHARGING][DEFAULT_MIN];
		else if (sec_per_cap > default_sec_per_cap[CHARGING][DEFAULT_MAX])
			sec_per_cap = default_sec_per_cap[CHARGING][DEFAULT_AVG];
		heart_battery_set_usage_reset(idx, CHARGING, sec_per_cap, total_count);
	}

	batt_stat.reset_mark = batt_stat.reset_mark ? 0 : 1; /* Swap reset_mark */
	batt_stat.reset_mark_timestamp = time(NULL);
	batt_stat.curr_run_time_sec[DISCHARGING] = 0;
	batt_stat.curr_run_time_sec[CHARGING] = 0;
	batt_stat.curr_cap_counter[DISCHARGING] = 0;
	batt_stat.curr_cap_counter[CHARGING] = 0;
	batt_used.used_time_sec = 0;
	batt_used.last_update_time = logging_get_time(CLOCK_BOOTTIME);

        return RESOURCED_ERROR_NONE;
}

static long heart_battery_compute_remaining_time_in_min(int capacity_count, long sec_per_cap)
{
	/*
	 * Calculates and returns remaining time in minutes based on number
	 * of capacity changes and time needed for one change.
	 */
	long time;

	time = (capacity_count * sec_per_cap); /* seconds */
	time = time + 30; /* add 30s margin */
	time = time / 60; /* change to minutes */
	return time;
}

static void heart_battery_calculate_prediction(enum charging_goal goal)
{
	int i, capacity, level;
	long total_time, total_count, sec_per_cap, pred_min;
	struct heart_battery_capacity *lbc = NULL;
	GArray *arrays = NULL;

	if (heart_battery_get_capacity_history_size() < BATTERY_PREDICTION_DATA_MIN) {
		_E("data is not enough to calculate prediction");
	}

	if (goal == CHARGING) {
		capacity = REMAIN_CAPACITY(batt_stat.curr_capacity);
	} else {
		capacity = batt_stat.curr_capacity;
	}


	/* PREDICTION METHOD: total average */
	total_time = 0;
	total_count = 0;
	for (i = 0; i < BATTERY_HISTORY_RESET_MAX; i++) {
		total_time += heart_battery_get_usage_reset_total_time(i, goal);
		total_count += heart_battery_get_usage_reset_count(i, goal);
	}
	total_time += batt_stat.curr_run_time_sec[goal];
	total_count += batt_stat.curr_cap_counter[goal];

	if (total_time && total_count >= BATTERY_PREDICTION_DATA_MIN) {
		sec_per_cap = total_time / total_count;
		if (sec_per_cap < default_sec_per_cap[goal][DEFAULT_MIN])
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_MIN];
		else if (sec_per_cap > default_sec_per_cap[goal][DEFAULT_MAX])
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_AVG];
		pred_min = heart_battery_compute_remaining_time_in_min(capacity, sec_per_cap);
		heart_battery_set_prediction(TA, goal,
				sec_per_cap, total_count,
				pred_min);
	} else {
		heart_battery_set_prediction(TA, goal, 0, 0, 0);
	}


	/* PREDICTION METHOD:
	 * Prediction of battery remaining usage time
	 * considering users' psychological usage patterns
	 * by batt_lvl_usage of battery charge
	 * */
	total_time = 0;
	total_count = 0;
	pred_min = 0;
	level = heart_battery_get_level_usage_index(capacity);
	if (level == BATTERY_LEVEL_LOW) {
		total_count = heart_battery_get_usage_level_count(BATTERY_LEVEL_LOW, goal);
		if (total_count >= BATTERY_PREDICTION_DATA_MIN) {
			sec_per_cap = heart_battery_get_usage_level_spc(BATTERY_LEVEL_LOW, goal);
		} else
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_AVG];
		pred_min = heart_battery_compute_remaining_time_in_min(capacity, sec_per_cap); 
	} else if (level == BATTERY_LEVEL_MID) {
		total_count = heart_battery_get_usage_level_count(BATTERY_LEVEL_LOW, goal);
		if (total_count >= BATTERY_PREDICTION_DATA_MIN) {
			sec_per_cap = heart_battery_get_usage_level_spc(BATTERY_LEVEL_LOW, goal);
		} else
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_AVG];
		pred_min = heart_battery_compute_remaining_time_in_min(15, sec_per_cap);
		total_count = heart_battery_get_usage_level_count(BATTERY_LEVEL_MID, goal);
		if (total_count >= BATTERY_PREDICTION_DATA_MIN) {
			sec_per_cap = heart_battery_get_usage_level_spc(BATTERY_LEVEL_MID, goal);
		} else
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_AVG];
		pred_min +=
			heart_battery_compute_remaining_time_in_min(capacity - 15, sec_per_cap);
	} else if (level == BATTERY_LEVEL_HIGH) {
		total_count = heart_battery_get_usage_level_count(BATTERY_LEVEL_LOW, goal);
		if (total_count >= BATTERY_PREDICTION_DATA_MIN) {
			sec_per_cap = heart_battery_get_usage_level_spc(BATTERY_LEVEL_LOW, goal);
		} else
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_AVG];
		pred_min = heart_battery_compute_remaining_time_in_min(15, sec_per_cap);

		total_count = heart_battery_get_usage_level_count(BATTERY_LEVEL_MID, goal);
		if (total_count >= BATTERY_PREDICTION_DATA_MIN) {
			sec_per_cap = heart_battery_get_usage_level_spc(BATTERY_LEVEL_MID, goal);
		} else
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_AVG];
		pred_min +=
			heart_battery_compute_remaining_time_in_min(35, sec_per_cap);

		total_count = heart_battery_get_usage_level_count(BATTERY_LEVEL_HIGH, goal);
		if (total_count >= BATTERY_PREDICTION_DATA_MIN) {
			sec_per_cap = heart_battery_get_usage_level_spc(BATTERY_LEVEL_HIGH, goal);
		} else
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_AVG];
		pred_min +=
			heart_battery_compute_remaining_time_in_min(capacity - 50, sec_per_cap);
	}
	heart_battery_set_prediction(PCB, goal, 0, 0, pred_min);


	/* PREDICTION METHOD: week average */
	total_time = 0;
	total_count = 0;
	for (i = 0; i < BATTERY_HISTORY_DAY_MAX; i++) {
		total_time += heart_battery_get_usage_week_total_time(i, goal);
		total_count += heart_battery_get_usage_week_count(i, goal);
	}
	if (total_time && total_count >= BATTERY_PREDICTION_DATA_MIN) {
		sec_per_cap = total_time / total_count;
		if (sec_per_cap < default_sec_per_cap[goal][DEFAULT_MIN])
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_MIN];
		else if (sec_per_cap > default_sec_per_cap[goal][DEFAULT_MAX])
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_AVG];
		pred_min =
			heart_battery_compute_remaining_time_in_min(capacity, sec_per_cap);
		heart_battery_set_prediction(WEEK, goal, sec_per_cap, total_count, pred_min);
	} else
		heart_battery_set_prediction(WEEK, goal, 0, 0, 0);


	/* PREDICTION METHOD:  last BATTERY_PREDICTION_COUNT data average */
	arrays = g_array_new(FALSE, FALSE, sizeof(struct heart_battery_capacity *));
	if (!arrays) {
		_E("Failed to alloc array");
		return;
	}
	if (heart_battery_get_capacity_history_latest(arrays, goal, BATTERY_PREDICTION_LATEST_COUNT) != RESOURCED_ERROR_NONE) {
		_E("Failed to get battery capacity history");
		return;
	}
	if (!arrays->len) {
		_E("No battery capacity history data");
	}
	total_time = 0;
	total_count = 0;
	for (i = 0; i < arrays->len; i++) {
		lbc = g_array_index(arrays, struct heart_battery_capacity *, i);
		if (!lbc)
			break;
		total_count += lbc->diff_capacity;
		if (goal == CHARGING)
			total_time += lbc->charging_time;
		else
			total_time += lbc->used_time;
	}
	if (total_time && total_count >= BATTERY_PREDICTION_DATA_MIN) {
		sec_per_cap = total_time / (total_count * 1000);
		if (sec_per_cap < default_sec_per_cap[goal][DEFAULT_MIN])
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_MIN];
		else if (sec_per_cap > default_sec_per_cap[goal][DEFAULT_MAX])
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_AVG];

		pred_min =
			heart_battery_compute_remaining_time_in_min(capacity, sec_per_cap);
		heart_battery_set_prediction(COUNT, goal, sec_per_cap, total_count, pred_min);
	} else
		heart_battery_set_prediction(COUNT, goal, 0, 0, 0);
	g_array_free(arrays, TRUE);
	arrays = NULL;


	/* PREDICTION METHOD: last BATTERY_PREDICTION_PERIOD hours average */
	arrays = g_array_new(FALSE, FALSE, sizeof(struct heart_battery_capacity *));
	if (!arrays) {
		_E("Failed to alloc array");
		return;
	}
	if (heart_battery_get_capacity_history(arrays, BATTERY_PREDICTION_PERIOD) != RESOURCED_ERROR_NONE) {
		_E("Failed to get battery capacity history");
		return;
	}
	if (!arrays->len) {
		_E("No battery capacity history data");
	}
	total_time = 0;
	total_count = 0;
	for (i = 0; i < arrays->len; i++) {
		lbc = g_array_index(arrays, struct heart_battery_capacity *, i);
		if (!lbc)
			break;
		if (goal == CHARGING) {
			if (lbc->charger_status != CHARGING)
				continue;
			total_time += lbc->charging_time;
			total_count += lbc->diff_capacity;
		} else {
			if (lbc->charger_status != DISCHARGING)
				continue;
			total_time += lbc->used_time;
			total_count += lbc->diff_capacity;
		}
	}
	g_array_free(arrays, TRUE);
	arrays = NULL;
	if (total_time && total_count >= BATTERY_PREDICTION_DATA_MIN) {
		sec_per_cap = total_time / (total_count * 1000);
		if (sec_per_cap < default_sec_per_cap[goal][DEFAULT_MIN])
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_MIN];
		else if (sec_per_cap > default_sec_per_cap[goal][DEFAULT_MAX])
			sec_per_cap = default_sec_per_cap[goal][DEFAULT_AVG];
		pred_min =
			heart_battery_compute_remaining_time_in_min(capacity, sec_per_cap);
		heart_battery_set_prediction(PERIOD, goal, sec_per_cap, total_count, pred_min);

	} else
		heart_battery_set_prediction(PERIOD, goal, 0, 0, 0);

	/* Log values of all predictions calculated */
	for (i = 0; i < MAX_STRATEGY; i++) {
		_I("%s %d %ld %ld %ld",
				(goal == DISCHARGING) ? "TimeToEmpty:" : "TimeToFull:",
				batt_stat.curr_capacity,
				batt_stat.prediction[goal].sec_per_cap[i],
				batt_stat.prediction[goal].cap_counter[i],
				batt_stat.prediction[goal].time_pred_min[i]);
	}
}

static int heart_battery_add_capacity(int capacity)
{
	char info[BATTERY_DATA_MAX];
	int ret, idx, status;
	long time_diff_capacity_lvl_ms[MAX_CHARGER_STATE];
	int diff_capacity_lvl;
	long time_diff_capacity_lvl_sec, total_time, total_count, sec_per_cap;
	time_t timestamp = time(NULL);
	long curr_wall_time_ms = logging_get_time_ms();

	status = batt_stat.curr_charger_status;
	/* calculate diff */
	time_diff_capacity_lvl_ms[status] = curr_wall_time_ms - batt_stat.last_event_wall_time_ms;

	if (time_diff_capacity_lvl_ms[status] < 0)
		return 0;

	time_diff_capacity_lvl_ms[!status] = 0;
	time_diff_capacity_lvl_sec = (time_diff_capacity_lvl_ms[status] + 500)/1000;

	if (!batt_stat.curr_capacity)
		diff_capacity_lvl = 1;
	else
		diff_capacity_lvl = abs(batt_stat.curr_capacity - capacity);

	_I("%d -> %d %ld %ld %ld", batt_stat.curr_capacity, capacity,
			timestamp, time_diff_capacity_lvl_sec, time_diff_capacity_lvl_ms[status]);

	/* update battery current status */
	batt_stat.last_event_wall_time_ms = curr_wall_time_ms;
	batt_stat.curr_capacity = capacity;

	/* Full Charging status */
	if (status == CHARGING && !REMAIN_CAPACITY(capacity) && !diff_capacity_lvl)
		return 0;

	/* update run usage */
	batt_stat.curr_run_time_sec[status] += time_diff_capacity_lvl_sec;
	batt_stat.curr_cap_counter[status] += diff_capacity_lvl;

	/* update batt_lvl_usage usage */
	total_time = 0;
	total_count = 0;

	if (status == CHARGING)
		idx = heart_battery_get_level_usage_index(REMAIN_CAPACITY(capacity));
	else
		idx = heart_battery_get_level_usage_index(capacity);

	total_time = heart_battery_get_usage_level_total_time(idx, status) + time_diff_capacity_lvl_sec;
	if (total_time)
		total_count = heart_battery_get_usage_level_count(idx, status) + diff_capacity_lvl;

	if (total_count) {
		sec_per_cap = total_time / total_count;
		if (sec_per_cap == 0)
			sec_per_cap = default_sec_per_cap[status][DEFAULT_AVG];
		else if (sec_per_cap < default_sec_per_cap[status][DEFAULT_MIN])
			sec_per_cap = default_sec_per_cap[status][DEFAULT_MIN];
		else if (sec_per_cap > default_sec_per_cap[status][DEFAULT_MAX])
			sec_per_cap = default_sec_per_cap[status][DEFAULT_AVG];
		/*
		 * If counts reached MAXIMUM number,
		 * counts is divided by 2 to reduce previous data's effect to equation
		 */
		if (total_count >= BATTERY_HISTORY_COUNT_MAX)
			total_count = total_count >> 1;

		heart_battery_set_usage_level(idx, status, sec_per_cap, total_count);
		heart_battery_set_usage_level_stime(idx, timestamp);
	}

	/* update day usage */
	total_time = 0;
	total_count = 0;

	idx = heart_battery_get_week_day_usage_index(timestamp);
	total_time = heart_battery_get_usage_week_total_time(idx, status) + time_diff_capacity_lvl_sec;
	if (total_time)
		total_count = heart_battery_get_usage_week_count(idx, status) + diff_capacity_lvl;

	if (total_count) {
		sec_per_cap = total_time / total_count;
		if (sec_per_cap == 0)
			sec_per_cap = default_sec_per_cap[status][DEFAULT_AVG];
		else if (sec_per_cap < default_sec_per_cap[status][DEFAULT_MIN])
			sec_per_cap = default_sec_per_cap[status][DEFAULT_MIN];
		else if (sec_per_cap > default_sec_per_cap[status][DEFAULT_MAX])
			sec_per_cap = default_sec_per_cap[status][DEFAULT_AVG];
		heart_battery_set_usage_week(idx, status, sec_per_cap, total_count);
		heart_battery_set_usage_week_stime(idx, CALCULATE_DAY_BASE_TIME(timestamp));
	}

	heart_battery_calculate_prediction(batt_stat.curr_charger_status);

	/* db backup */
	snprintf(info, sizeof(info), "%d %d %ld %ld %d %d ",
			capacity, diff_capacity_lvl,
			time_diff_capacity_lvl_ms[DISCHARGING], time_diff_capacity_lvl_ms[CHARGING],
			batt_stat.curr_charger_status, batt_stat.reset_mark);
	ret = logging_write(BATTERY_NAME, TIZEN_SYSTEM_BATTERY_APPID,
			TIZEN_SYSTEM_APPID, timestamp, info);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	/* insert capacity history list */
	heart_battery_insert_capacity(&capacity_history_list, capacity, diff_capacity_lvl,
			timestamp, time_diff_capacity_lvl_ms[DISCHARGING],
			time_diff_capacity_lvl_ms[CHARGING], batt_stat.curr_charger_status,
			batt_stat.reset_mark, true);

	_D("battery_heart_capacity_write %d diff_capacity %ld, used time %ld, charging time %ld, charger status %d, reset_mark %d",
			capacity, diff_capacity_lvl,
			time_diff_capacity_lvl_ms[DISCHARGING], time_diff_capacity_lvl_ms[CHARGING],
			batt_stat.curr_charger_status, batt_stat.reset_mark);

	resourced_notify(RESOURCED_NOTIFIER_LOGGING_START, NULL);
	return RESOURCED_ERROR_NONE;
}

/* ============================ DBUS -> DEVICED on demand ==================== */

static int heart_battery_get_capacity(void)
{
	int capacity, ret;
	DBusMessage *msg;

	msg = dbus_method_sync(DEVICED_BUS_NAME, DEVICED_PATH_BATTERY,
			DEVICED_INTERFACE_BATTERY,
			GET_BATTERY_CAPACITY,
			NULL, NULL);
	if (!msg) {
		_E("Failed to sync DBUS message.");
		return RESOURCED_ERROR_FAIL;
	}
	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &capacity, DBUS_TYPE_INVALID);
	dbus_message_unref(msg);
	if (!ret) {
		_E("Failed: dbus_message_get_args()");
		return RESOURCED_ERROR_FAIL;
	}
	return capacity;
}

static int heart_battery_get_charger_status(void)
{
	int status, ret;
	DBusMessage *msg;

	msg = dbus_method_sync(DEVICED_BUS_NAME, DEVICED_PATH_BATTERY,
			DEVICED_INTERFACE_BATTERY,
			GET_CHARGER_STATUS,
			NULL, NULL);
	if (!msg) {
		_E("Failed to sync DBUS message.");
		return RESOURCED_ERROR_FAIL;
	}
	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &status, DBUS_TYPE_INVALID);
	dbus_message_unref(msg);
	if (!ret) {
		_E("Failed: dbus_message_get_args()");
		return RESOURCED_ERROR_FAIL;
	}

	if (status > 0)
		return CHARGING;
	return DISCHARGING;
}

/* =========================  DBUS -> DEVICED  on demand END ================= */

/* ============================ DBUS -> DEVICED handler ====================== */
static void heart_battery_capacity_status(void *data, DBusMessage *msg)
{
	/*
	 * This handler is called when battery capacity value change in 1%
	 *
	 * The message have current percent value of capacity
	 *
	 * (This requires deviced with commit at least:
	 * "f1ae1d1f270e9 battery: add battery capacity dbus signal broadcast")
	 */

	int ret, capacity;

	ret = dbus_message_is_signal(msg, DEVICED_INTERFACE_BATTERY, GET_BATTERY_CAPACITY);
	if (!ret) {
		_E("dbus_message_is_signal error");
		return;
	}
	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &capacity, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("Failed: dbus_message_get_args()");
		return;
	}
	heart_battery_add_capacity(capacity);
	heart_battery_update_used_time(logging_get_time(CLOCK_BOOTTIME),
			batt_stat.curr_charger_status);
}

static void heart_battery_charger_status(void *data, DBusMessage *msg)
{
	/*
	 * This handler is called when USB cable with charging capabilities
	 * is connected or disconnected from the device.
	 *
	 * The message have current status of charger connection.
	 * STATUSES:
	 * 0 - charger was disconnected
	 * 1 - charger was connected
	 */
	int ret, capacity, charger_status, cap_history_size;

	ret = dbus_message_is_signal(msg, DEVICED_INTERFACE_BATTERY, GET_CHARGER_STATUS);
	if (!ret) {
		_E("dbus_message_is_signal error");
		return;
	}
	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &charger_status, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("Failed: dbus_message_get_args()");
		return;
	}
	capacity = heart_battery_get_capacity();
	if (capacity < 0)
		capacity = batt_stat.curr_capacity;

	/* Update the statistics with capacity when charger state was changed */
	heart_battery_add_capacity(capacity);

	cap_history_size = heart_battery_get_capacity_history_size();

	if (charger_status == DISCHARGING && capacity >= 90) {
		/*
		 * If battery is charged over 90 and charger was disconnected.
		 * So most probably the phone was "charged".
		 * Let's reset the statistics.
		 */
		resourced_notify(RESOURCED_NOTIFIER_DATA_RESET, NULL);
	} else if (charger_status == DISCHARGING && cap_history_size >= BATTERY_CAPACITY_MAX) {
		/*
		 * Charger is not connected and the battery history is over limit.
		 * Let's reset the statistics.
		 */
		resourced_notify(RESOURCED_NOTIFIER_DATA_RESET, NULL);
	}
	/* Update current charger connection status */
	batt_stat.curr_charger_status = charger_status;
	heart_battery_update_used_time(logging_get_time(CLOCK_BOOTTIME),
			batt_stat.curr_charger_status);
	heart_battery_calculate_prediction(batt_stat.curr_charger_status);
}

/* =========================  DBUS -> DEVICED handler END ==================== */

int heart_battery_get_capacity_history_latest(GArray *arrays, int charge, int max_size)
{
	int ret, size, count;
	struct heart_battery_capacity *lbc, *lbci;
	GSList *iter, *rlist;

	if (!capacity_history_list) {
		_E("empty capacity history list");
		return RESOURCED_ERROR_FAIL;
	}
	size = g_slist_length(capacity_history_list);
	if (!size) {
		_I("capacity history is empty");
		return RESOURCED_ERROR_NONE;
	}
	ret = pthread_mutex_lock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	count = 0;

	rlist = g_slist_copy(capacity_history_list);

	rlist = g_slist_reverse(rlist);

	gslist_for_each_item(iter, rlist) {
		lbc = (struct heart_battery_capacity *)iter->data;
		if (!lbc)
			break;
		if (charge < MAX_CHARGER_STATE && charge != lbc->charger_status)
			continue;
		count++;
		if (max_size < count)
			break;
		lbci = malloc(sizeof(struct heart_battery_capacity));
		if (!lbci) {
			_E("malloc failed");
			ret = pthread_mutex_unlock(&heart_battery_mutex);
			if (ret) {
				_E("pthread_mutex_unlock() failed, %d", ret);
				return RESOURCED_ERROR_FAIL;
			}
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}
		lbci->capacity = lbc->capacity;
		lbci->diff_capacity = lbc->diff_capacity;
		if (!lbc->diff_capacity)
			count--;
		lbci->used_time = lbc->used_time;
		lbci->charging_time = lbc->charging_time;
		lbci->charger_status = lbc->charger_status;
		g_array_prepend_val(arrays, lbci);
	}
	ret = pthread_mutex_unlock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
}

int heart_battery_get_capacity_history(GArray *arrays, enum heart_data_period period)
{
	int ret, index, size;
	struct heart_battery_capacity *lbc, *lbci;
	GSList *iter;
	time_t curr = time(NULL);

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

	if (!capacity_history_list) {
		_E("empty capacity history list");
		return RESOURCED_ERROR_FAIL;
	}
	size = g_slist_length(capacity_history_list);
	if (!size) {
		_I("capacity history is empty");
		return RESOURCED_ERROR_NONE;
	}
	ret = pthread_mutex_lock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	gslist_for_each_item(iter, capacity_history_list) {
		lbc = (struct heart_battery_capacity *)iter->data;
		if (!lbc)
			break;
		if (index && (lbc->timestamp < curr - (index * 3600)))
			continue;
		lbci = malloc(sizeof(struct heart_battery_capacity));
		if (!lbci) {
			_E("malloc failed");
			ret = pthread_mutex_unlock(&heart_battery_mutex);
			if (ret) {
				_E("pthread_mutex_unlock() failed, %d", ret);
				return RESOURCED_ERROR_FAIL;
			}
			return RESOURCED_ERROR_OUT_OF_MEMORY;
		}
		lbci->capacity = lbc->capacity;
		lbci->diff_capacity = lbc->diff_capacity;
		lbci->used_time = lbc->used_time;
		lbci->charging_time = lbc->charging_time;
		lbci->charger_status = lbc->charger_status;
		g_array_append_val(arrays, lbci);
	}
	ret = pthread_mutex_unlock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
}

/* ============================ DBUS interface ====================== */

static DBusMessage *edbus_get_battery_capacity_history_latest(E_DBus_Object *obj, DBusMessage *msg)
{
	int i, ret, size, charge, max_size;
	DBusMessage *reply;
	DBusMessageIter d_iter;
	DBusMessageIter arr;
	GArray *arrays = NULL;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &charge, DBUS_TYPE_INT32, &max_size, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	reply = dbus_message_new_method_return(msg);
	size = g_slist_length(capacity_history_list);
	if (!size) {
		_I("capacity history is empty");
		return reply;
	}
	dbus_message_iter_init_append(reply, &d_iter);
	arrays = g_array_new(FALSE, FALSE, sizeof(struct heart_battery_capacity *));
	if (!arrays) {
		_E("Failed to alloc array");
		return reply;
	}
	if (heart_battery_get_capacity_history_latest(arrays, charge, max_size) != RESOURCED_ERROR_NONE) {
		_E("Failed to get capacity history latest");
		goto exit;
	}
	if (!arrays->len) {
		_E("No battery capacity history data");
		goto exit;
	}
	dbus_message_iter_open_container(&d_iter, DBUS_TYPE_ARRAY, "(iii)", &arr);
	for (i = 0; i < arrays->len; i++) {
		DBusMessageIter sub;
		struct heart_battery_capacity *lbc;
		lbc = g_array_index(arrays, struct heart_battery_capacity *, i);
		if (!lbc)
			break;
		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &lbc->capacity);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &lbc->used_time);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &lbc->charging_time);
		dbus_message_iter_close_container(&arr, &sub);
	}
	dbus_message_iter_close_container(&d_iter, &arr);
exit:
	g_array_free(arrays, TRUE);
	return reply;
}

static DBusMessage *edbus_get_battery_capacity_history(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret, size, period, index;
	DBusMessage *reply;
	DBusMessageIter d_iter;
	DBusMessageIter arr;
	struct heart_battery_capacity *lbc;
	GSList *iter;
	time_t curr = time(NULL);

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &period, DBUS_TYPE_INVALID);
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
	reply = dbus_message_new_method_return(msg);
	size = g_slist_length(capacity_history_list);
	if (!size) {
		_I("capacity history is empty");
		return reply;
	}
	dbus_message_iter_init_append(reply, &d_iter);
	dbus_message_iter_open_container(&d_iter, DBUS_TYPE_ARRAY, "(iii)", &arr);
	ret = pthread_mutex_lock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		dbus_message_iter_close_container(&d_iter, &arr);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	gslist_for_each_item(iter, capacity_history_list) {
		DBusMessageIter sub;
		lbc = (struct heart_battery_capacity *)iter->data;
		if (!lbc)
			break;
		if (index && (lbc->timestamp < curr - (index * 3600)))
			continue;
		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &lbc->capacity);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &lbc->used_time);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &lbc->charging_time);
		dbus_message_iter_close_container(&arr, &sub);
	}
	ret = pthread_mutex_unlock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		dbus_message_iter_close_container(&d_iter, &arr);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	dbus_message_iter_close_container(&d_iter, &arr);
	return reply;
}

static DBusMessage *edbus_get_battery_used_time(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	DBusMessage *reply;
	DBusMessageIter iter;

	heart_battery_update_used_time(logging_get_time(CLOCK_BOOTTIME),
			batt_stat.curr_charger_status);
	ret = batt_used.used_time_sec;
	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);

	return reply;
}

static int get_battery_remaining_time(int mode, int status)
{
	int i, ret, count;
	long sum, time, cumul_average, trend_average;
	double result;

	ret = count = 0;
	sum = time = 0;
	cumul_average = trend_average = 0;
	/* get prediction time of cumulative value */
	for (i = 0; i <= WEEK; i++) {
		time = heart_battery_get_prediction_time(i, status);
		if (time) {
			sum += time;
			count++;
		}
	}
	if (count)
		cumul_average = sum / count;

	count = 0;
	sum = 0;
	/* get prediction time of trend value */
	for (i = COUNT; i < MAX_STRATEGY; i++) {
		time = heart_battery_get_prediction_time(i, status);
		if (time) {
			sum += time;
			count++;
		}
	}
	if (count)
		trend_average = sum / count;

	/* failed to get prediction to calculate that with default value */
	if (!cumul_average && !trend_average) {
		if (batt_stat.curr_capacity != 100 && batt_stat.curr_capacity != 0)
			ret = heart_battery_compute_remaining_time_in_min(batt_stat.curr_capacity,
					default_sec_per_cap[status][DEFAULT_AVG]);
	} else if (cumul_average && !trend_average) {
		/* failed to get prediction of trend average */
		ret = cumul_average;
	} else if (!cumul_average && trend_average) {
		/* failed to get prediction of cumulative average */
		ret = trend_average;
	} else
		ret = ((cumul_average * CUMUL_WEIGHT) + (trend_average * TREND_WEIGHT));

	if (status == CHARGING)
		return ret;

	switch (mode) {
	case ULTRA_SAVING_MODE:
		/* Fall through */
	case POWER_SAVING_MODE:
		result = (double)ret * default_mode_factor[mode];
		return (int)result;
	case POWER_NORMAL_MODE:
		/* Fall through */
	default:
		return ret;
	}
}

static DBusMessage *edbus_get_battery_remaining_time(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	int ret, mode;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &mode, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	ret = get_battery_remaining_time(mode, DISCHARGING);

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);
	_I("Remaining_time %d (mode: %d)", ret, mode);

	return reply;
}

static DBusMessage *edbus_get_battery_charging_time(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	int ret;

	ret = get_battery_remaining_time(POWER_NORMAL_MODE, CHARGING);

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);
	_I("Remaining_charging_time %d", ret);

	return reply;
}

static DBusMessage *edbus_battery_save_to_file(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	DBusMessage *reply;
	DBusMessageIter iter;

	ret = heart_battery_status_save_to_db();
	if (ret) {
		_E("save to db failed");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}
	ret = heart_battery_capacity_save_to_file(HEART_BATTERY_CAPACITY_DATA_FILE);
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
	{ "GetBatteryCapacityHistory", "i",   "a(iii)", edbus_get_battery_capacity_history },
	{ "GetBatteryCapacityHistoryLatest", "ii", "a(iii)", edbus_get_battery_capacity_history_latest },
	{ "GetBatteryUsedTime",   NULL,   "i", edbus_get_battery_used_time },
	{ "GetBatteryRemainingTime",   "i",   "i", edbus_get_battery_remaining_time },
	{ "GetBatteryChargingTime",   NULL,   "i", edbus_get_battery_charging_time },
	{ "SaveBatteryData",   NULL,   "i", edbus_battery_save_to_file },
};

/* =========================  DBUS interface END ==================== */
static void heart_battery_used_time_init(int status)
{
	batt_used.last_charger_status = status;
	batt_used.last_update_time = logging_get_time(CLOCK_BOOTTIME);
}

static void heart_battery_status_init(void)
{
	int i, ret, status, capacity;

	batt_stat.curr_capacity = 0;
	batt_stat.curr_run_time_sec[DISCHARGING] = 0;
	batt_stat.curr_run_time_sec[CHARGING] = 0;
	batt_stat.curr_cap_counter[DISCHARGING] = 0;
	batt_stat.curr_cap_counter[CHARGING] = 0;
	batt_stat.curr_charger_status = 0;
	batt_stat.reset_mark = 0;

	for (i = 0; i < BATTERY_HISTORY_RESET_MAX; i++) {
		heart_battery_set_usage_reset_stime(i, 0);
		heart_battery_set_usage_reset(i, DISCHARGING, 0, 0);
		heart_battery_set_usage_reset(i, CHARGING, 0, 0);
	}


	for (i = 0; i < BATTERY_LEVEL_MAX; i++) {
		heart_battery_set_usage_level_stime(i, 0);
		heart_battery_set_usage_level(i, DISCHARGING, default_sec_per_cap[DISCHARGING][DEFAULT_AVG], 0);
		heart_battery_set_usage_level(i, CHARGING, default_sec_per_cap[CHARGING][DEFAULT_AVG], 0);
	}

	for (i = 0; i < BATTERY_HISTORY_DAY_MAX; i++) {
		heart_battery_set_usage_week_stime(i, 0);
		heart_battery_set_usage_week(i, DISCHARGING, 0, 0);
		heart_battery_set_usage_week(i, CHARGING, 0, 0);
	}

	for (i = 0; i < MAX_STRATEGY; i++) {
		heart_battery_set_prediction(i, DISCHARGING, 0, 0, 0);
		heart_battery_set_prediction(i, CHARGING, 0, 0, 0);
	}

	ret = heart_battery_status_read_from_db();
	if (ret < 0) {
		_E("Failed to read battery status data");
	}

	ret = heart_battery_capacity_read_from_file(HEART_BATTERY_CAPACITY_DATA_FILE);
	if (ret < 0) {
		_E("Failed to read battery capacity data");
	}

	capacity = heart_battery_get_capacity();
	if (capacity > 0) {
		batt_stat.curr_capacity = capacity;
	}
	status = heart_battery_get_charger_status();
	if (status >= 0) {
		batt_stat.curr_charger_status = status;
	}
	heart_battery_used_time_init(batt_stat.curr_charger_status);
	heart_battery_calculate_prediction(batt_stat.curr_charger_status);
	batt_stat.last_event_wall_time_ms = logging_get_time_ms();
}

static int low_battery_handler(void *data)
{
	heart_battery_save_to_file(false);
	return RESOURCED_ERROR_NONE;
}

static int heart_battery_config(struct parse_result *result, void *user_data)
{
	int val;

	if (!result)
		return -EINVAL;

	if (strcmp(result->section, HEART_BATTERY_CONF_SECTION))
		return RESOURCED_ERROR_FAIL;

	if (!strcmp(result->name, "POWER_NORMAL_MODE")) {
		val = atoi(result->value);
		if (val > 0)
			default_mode_spc[POWER_NORMAL_MODE] = val;
		_D("POWER_NORMAL_MODE SPC: %d", val);
	} else if (!strcmp(result->name, "POWER_SAVING_MODE")) {
		val = atoi(result->value);
		if (val > 0)
			default_mode_spc[POWER_SAVING_MODE] = val;
		_D("POWER_SAVING_MODE SPC: %d", val);
	} else if (!strcmp(result->name, "ULTRA_SAVING_MODE")) {
		val = atoi(result->value);
		if (val > 0)
			default_mode_spc[ULTRA_SAVING_MODE] = val;
		_D("ULTRA_POWER_SAVING_MODE SPC: %d", val);
	}
	return RESOURCED_ERROR_NONE;
}

static void heart_battery_mode_factor_init(void)
{
	double val;

	val = default_mode_spc[POWER_SAVING_MODE]/default_mode_spc[POWER_NORMAL_MODE];

	if (1.0 < val)
		default_mode_factor[POWER_SAVING_MODE] = val;
	_I("POWER_SAVING_MODE factor: %f", val);

	val = default_mode_spc[ULTRA_SAVING_MODE]/default_mode_spc[POWER_NORMAL_MODE];

	if (1.0 < val)
		default_mode_factor[ULTRA_SAVING_MODE] = val;
	_I("ULTRA_POWER_SAVING_MODE factor: %f", val);
}

static int heart_battery_init(void *data)
{
	int ret;

	ret = logging_module_init(BATTERY_NAME, ONE_DAY, TEN_MINUTE,
			heart_battery_update, HEART_BATTERY_UPDATE_INTERVAL);
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
	ret = register_edbus_signal_handler(DEVICED_PATH_BATTERY,
			DEVICED_INTERFACE_BATTERY, GET_BATTERY_CAPACITY,
			heart_battery_capacity_status, NULL);
	if (ret < 0) {
		_E("Failed to add a capacity status signal handler");
	}

	ret = register_edbus_signal_handler(DEVICED_PATH_BATTERY,
			DEVICED_INTERFACE_BATTERY, GET_CHARGER_STATUS,
			heart_battery_charger_status, NULL);
	if (ret < 0) {
		_E("Failed to add a charger status signal handler");
	}

	config_parse(HEART_CONF_FILE_PATH, heart_battery_config, NULL);

	heart_battery_mode_factor_init();

	heart_battery_status_init();

	register_notifier(RESOURCED_NOTIFIER_LOW_BATTERY, low_battery_handler);
	register_notifier(RESOURCED_NOTIFIER_DATA_RESET, heart_battery_reset);

	heart_battery_set_file_commit_timestamp(logging_get_time(CLOCK_BOOTTIME));
	_D("heart battery init finished");
	return RESOURCED_ERROR_NONE;
}

void heart_capacity_history_update(struct logging_table_form *data, void *user_data)
{
	int status, reset, capacity, diff;
	unsigned long discharging = 0, charging = 0;
	GSList **history_list = NULL;

	if (user_data)
		history_list = (GSList **)user_data;
	else
		history_list = &capacity_history_list;

	_D("%s %s %d %s", data->appid, data->pkgid, data->time, data->data);
	if (sscanf(data->data, "%d %d %ld %ld %d %d ",
				&capacity, &diff,
				&discharging, &charging,
				&status, &reset) < 0) {
		_E("sscanf failed");
		return;
	}
	heart_battery_insert_capacity(history_list, capacity,
			diff, data->time, discharging, charging, status,
			reset, false);
}

static int heart_battery_dump(FILE *fp, int mode, void *data)
{
	struct heart_battery_capacity *lbc;
	GSList *iter;
	char buf[BATTERY_DATA_MAX] = {0, };
	int ret, size, len = 0;
	time_t starttime;
	char timestr[80];
	struct tm loc_tm;
	GSList *history_list = NULL;

	starttime = time(NULL);
	starttime -= mode;
	localtime_r(&starttime, &loc_tm);
	/* print timestamp */
	strftime(timestr, sizeof(timestr),
			"%Y-%m-%d %H:%M:%S%z", &loc_tm);

	logging_read_foreach(BATTERY_NAME, NULL, NULL, starttime, 0,
			heart_capacity_history_update, &history_list);

	if (!history_list) {
		_E("capacity history is NULL!");
		return RESOURCED_ERROR_NONE;
	}
	LOG_DUMP(fp, "[BATTERY CAPACITY HISTORY] since %s\n", timestr);
	LOG_DUMP(fp, "capacity diff timestamp used_time charging_time charger_status, reset_mark\n");
	ret = pthread_mutex_lock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	size = g_slist_length(history_list);
	if (!size) {
		_I("capacity history is empty");
		ret = pthread_mutex_unlock(&heart_battery_mutex);
		if (ret) {
			_E("pthread_mutex_unlock() failed, %d", ret);
			return RESOURCED_ERROR_FAIL;
		}
		return RESOURCED_ERROR_NONE;
	}
	gslist_for_each_item(iter, history_list) {
		lbc = (struct heart_battery_capacity *)iter->data;
		if (!lbc)
			break;
		len += snprintf(buf + len, BATTERY_DATA_MAX - len, "%d %d %ld %ld %ld %d %d\n",
				lbc->capacity, lbc->diff_capacity, lbc->timestamp, lbc->used_time,
				lbc->charging_time, lbc->charger_status,
				lbc->reset_mark);
		if (BATTERY_DATA_MAX < len + BATTERY_LINE_MAX) {
			LOG_DUMP(fp, "%s\n", buf);
			len = 0;
		}
	}
	LOG_DUMP(fp, "%s\n", buf);
	ret = pthread_mutex_unlock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}
	fflush(fp);
	if (history_list) {
		g_slist_free_full(history_list, free);
		history_list = NULL;
	}

	return RESOURCED_ERROR_NONE;
}

static int heart_battery_exit(void *data)
{
	int ret;
	GSList *iter, *next;
	struct heart_battery_capacity *lbc;

        heart_battery_save_to_file(true);
	ret = pthread_mutex_lock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
	}

	gslist_for_each_safe(capacity_history_list, iter, next, lbc) {
		capacity_history_list = g_slist_remove(capacity_history_list, lbc);
		free(lbc);
	}
	capacity_history_list = NULL;

	ret = pthread_mutex_unlock(&heart_battery_mutex);
	if (ret) {
		_E("pthread_mutex_unlock() failed, %d", ret);
	}

	unregister_notifier(RESOURCED_NOTIFIER_LOW_BATTERY, low_battery_handler);
	unregister_notifier(RESOURCED_NOTIFIER_DATA_RESET, heart_battery_reset);

	logging_module_exit();

	_D("heart battery exit");
	return RESOURCED_ERROR_NONE;
}

static const struct heart_module_ops heart_battery_ops = {
	.name           = "BATTERY",
	.init           = heart_battery_init,
	.dump           = heart_battery_dump,
	.exit           = heart_battery_exit,
};
HEART_MODULE_REGISTER(&heart_battery_ops)
