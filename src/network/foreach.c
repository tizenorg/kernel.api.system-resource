/*
 * resourced
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file foreach.c
 * @desc Implementation of the datausage foreach function.
 *
 */


#include <sqlite3.h>
#include <string.h>

#include "database.h"
#include "data_usage.h"
#include "datausage-foreach.h"
#include "macro.h"
#include "trace.h"

#define DATA_USAGE_FOR_PERIOD "select binpath, hw_net_protocol_type, "	\
	"is_roaming, sum(received) as received, "			\
	"sum(sent) as sent, imsi, ground from statistics "			\
	"where time_stamp between ? and ? " \
	"group by ground, binpath, is_roaming, imsi order by received desc"

#define DATA_USAGE_FOR_PERIOD_IFACE "select binpath, hw_net_protocol_type, " \
	"is_roaming, sum(received) as received, "			\
	"sum(sent) as sent, imsi, ground from statistics "			\
	"where time_stamp between ? and ? " \
	"and iftype=? group by ground, binpath, is_roaming, imsi order by received desc"

#define DATA_USAGE_CHUNKS "select binpath, hw_net_protocol_type, "	\
	"is_roaming, sum(received) as received, "			\
	"sum(sent) as sent, time_stamp - time_stamp % ? as time_stamp, imsi, "\
	"ground " \
	"from statistics where time_stamp between ? and ? " \
	"group by ground, binpath, time_stamp, imsi order by time_stamp"

#define DATA_USAGE_CHUNKS_IFACE "select binpath, hw_net_protocol_type, " \
	"is_roaming, sum(received) as received, "			\
	"sum(sent) as sent, imsi, ground, "			\
	"time_stamp - time_stamp % ? as time_stamp " \
	"from statistics where time_stamp between ? and ? and iftype=?" \
	"group by ground, binpath, time_stamp, imsi order by time_stamp"

#define DATA_USAGE_APP_DETAILS "select iftype, hw_net_protocol_type, "	\
	"is_roaming, sum(received) as received, sum(sent) as sent, "	\
	"ifname, imsi, ground from statistics where time_stamp between ? and ? " \
	"and binpath=? " \
	"group by binpath, iftype, ifname, imsi, hw_net_protocol_type, " \
	"is_roaming " \
	"order by time_stamp, binpath, iftype, ifname, imsi, " \
	"hw_net_protocol_type, is_roaming"

#define DATA_USAGE_APP_DETAILS_IFACE "select iftype, hw_net_protocol_type, " \
	"is_roaming, sum(received) as received, sum(sent) as sent, "	\
	"ifname, imsi, ground from statistics where time_stamp between ? and ? " \
	"and binpath=? and iftype=?" \
	"group by hw_net_protocol_type, is_roaming, iftype, ifname, imsi " \
	"order by time_stamp, hw_net_protocol_type, is_roaming, iftype, "\
	"ifname, imsi"

#define DATA_USAGE_CHUNKS_APP "select iftype, hw_net_protocol_type, "	\
	"is_roaming, sum(received) as received, sum(sent) as sent, "	\
	"ifname, imsi, ground, time_stamp - time_stamp % ? as time_stamp " \
	"from statistics " \
	"group by iftype, ifname, time_stamp, hw_net_protocol_type, is_roaming " \
	"order by time_stamp, iftype, ifname, hw_net_protocol_type, is_roaming"

#define DATA_USAGE_CHUNKS_APP_IFACE "select iftype, hw_net_protocol_type, " \
	"is_roaming, sum(received) as received, sum(sent) as sent, "	\
	"ifname, imsi, ground, time_stamp - time_stamp % ? as time_stamp " \
	"from statistics where time_stamp between ? and ? and binpath = ? " \
	"and iftype = ? " \
	"group by time_stamp, hw_net_protocol_type, is_roaming, " \
	"iftype, ifname, imsi " \
	"order by time_stamp, iftype, ifname, imsi, hw_net_protocol_type, " \
	"is_roaming"

#define DATA_USAGE_TOTAL "select iftype, hw_net_protocol_type, "	\
	"is_roaming, sum(received) as received, sum(sent) as sent, "	\
	"ifname, imsi, ground from statistics where time_stamp between ? and ? " \
	"group by iftype, ifname, imsi, hw_net_protocol_type, is_roaming " \
	"order by time_stamp, iftype, ifname, imsi, hw_net_protocol_type, " \
	"is_roaming"

#define DATA_USAGE_TOTAL_IFACE "select iftype, hw_net_protocol_type, "	\
	"is_roaming, sum(received) as received, sum(sent) as sent, "	\
	"ifname, imsi, ground from statistics where time_stamp between ? and ? " \
	"and iftype=? " \
	"group by hw_net_protocol_type, is_roaming, " \
	"iftype, ifname, imsi " \
	"order by time_stamp, iftype, ifname, imsi, hw_net_protocol_type, " \
	"is_roaming"

#define DATA_USAGE_CHUNKS_TOTAL "select iftype, hw_net_protocol_type, "	\
	"is_roaming, sum(received) as received, sum(sent) as sent, "	\
	"ifname, imsi, ground, time_stamp - time_stamp % ? as time_stamp " \
	"from statistics where time_stamp between ? and ? "		\
	"group by time_stamp, iftype, ifname, imsi, hw_net_protocol_type, " \
	"is_roaming " \
	"order by time_stamp, iftype, ifname, imsi, hw_net_protocol_type, " \
	"is_roaming"

#define DATA_USAGE_CHUNKS_TOTAL_IFACE "select iftype, hw_net_protocol_type, " \
	"is_roaming, sum(received) as received, sum(sent) as sent, "	\
	"ifname, imsi, ground, time_stamp - time_stamp % ? as time_stamp " \
	"from statistics where time_stamp between ? and ? "		\
	"and iftype = ? " \
	"group by time_stamp, hw_net_protocol_type, is_roaming, iftype, ifname, imsi " \
	"order by time_stamp, hw_net_protocol_type, is_roaming, iftype, " \
	"ifname, imsi"

static sqlite3_stmt *data_usage_for_period;
static sqlite3_stmt *data_usage_for_period_iface;
static sqlite3_stmt *data_usage_chunks;
static sqlite3_stmt *data_usage_chunks_iface;
static sqlite3_stmt *data_usage_app_details;
static sqlite3_stmt *data_usage_app_details_iface;
static sqlite3_stmt *data_usage_chunks_app;
static sqlite3_stmt *data_usage_chunks_app_iface;
static sqlite3_stmt *data_usage_total;
static sqlite3_stmt *data_usage_total_iface;
static sqlite3_stmt *data_usage_chunks_total;
static sqlite3_stmt *data_usage_chunks_total_iface;

#define PREPARE(stm, query) do {				\
	rc = sqlite3_prepare_v2(db, query, -1, &stm, NULL);	\
	if (rc != SQLITE_OK) {					\
		stm = NULL;					\
		finalize_datausage_foreach();				\
		_E("Failed to prepare %s\n", query);		\
		return rc;					\
	}							\
} while (0)

int init_datausage_foreach(sqlite3 *db)
{
	int rc;
	static int initialized;

	if (initialized)
		return SQLITE_OK;

	PREPARE(data_usage_for_period, DATA_USAGE_FOR_PERIOD);
	PREPARE(data_usage_for_period_iface, DATA_USAGE_FOR_PERIOD_IFACE);
	PREPARE(data_usage_chunks, DATA_USAGE_CHUNKS);
	PREPARE(data_usage_chunks_iface, DATA_USAGE_CHUNKS_IFACE);
	PREPARE(data_usage_app_details, DATA_USAGE_APP_DETAILS);
	PREPARE(data_usage_app_details_iface, DATA_USAGE_APP_DETAILS_IFACE);
	PREPARE(data_usage_chunks_app, DATA_USAGE_CHUNKS_APP);
	PREPARE(data_usage_chunks_app_iface, DATA_USAGE_CHUNKS_APP_IFACE);
	PREPARE(data_usage_total, DATA_USAGE_TOTAL);
	PREPARE(data_usage_total_iface, DATA_USAGE_TOTAL_IFACE);
	PREPARE(data_usage_chunks_total, DATA_USAGE_CHUNKS_TOTAL);
	PREPARE(data_usage_chunks_total_iface, DATA_USAGE_CHUNKS_TOTAL_IFACE);

	initialized = 1;
	return SQLITE_OK;
}

#define FINALIZE(stm) do {		\
	if (stm) {			\
		sqlite3_finalize(stm);	\
		stm = NULL;		\
	}				\
} while (0)

void finalize_datausage_foreach(void)
{
	FINALIZE(data_usage_for_period);
	FINALIZE(data_usage_for_period_iface);
	FINALIZE(data_usage_chunks);
	FINALIZE(data_usage_chunks_iface);
	FINALIZE(data_usage_app_details);
	FINALIZE(data_usage_app_details_iface);
	FINALIZE(data_usage_chunks_app);
	FINALIZE(data_usage_chunks_app_iface);
	FINALIZE(data_usage_total);
	FINALIZE(data_usage_total_iface);
	FINALIZE(data_usage_chunks_total);
	FINALIZE(data_usage_chunks_total_iface);
}

static int is_iftype_defined(const resourced_iface_type iftype)
{
	return iftype < RESOURCED_IFACE_LAST_ELEM &&
	       iftype > RESOURCED_IFACE_UNKNOWN &&
	       iftype != RESOURCED_IFACE_ALL;
}

API resourced_ret_c data_usage_foreach(const data_usage_selection_rule *rule,
				       data_usage_info_cb info_cb,
				       void *user_data)
{
	data_usage_info data;
	sqlite3_stmt *stm;
	resourced_ret_c result = RESOURCED_ERROR_NONE;
	int rc;
	int pos = 1;/* running through positions where to
		bind parameters in the query */
	resourced_tm_interval interval;

	libresourced_db_initialize_once();
	if (init_datausage_foreach(resourced_get_database())!= SQLITE_OK) {
		_D("Failed to initialize data usage statements: %s\n",
		   sqlite3_errmsg(resourced_get_database()));
		return RESOURCED_ERROR_DB_FAILED;
	}

	memset(&data, 0, sizeof(data));

	if (!rule || !info_cb)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	/* pick a statement depending on parameters */
	if (rule->granularity) {
		stm = is_iftype_defined(rule->iftype) ?
			data_usage_chunks_iface : data_usage_chunks;

		if (sqlite3_bind_int64(stm, pos++, rule->granularity) !=
		    SQLITE_OK) {
			result = RESOURCED_ERROR_DB_FAILED;
			goto out;
		}
		data.interval = &interval;
	} else {
		stm = is_iftype_defined(rule->iftype)
		    ? data_usage_for_period_iface : data_usage_for_period;
	}

	if (sqlite3_bind_int64(stm, pos++, rule->from) != SQLITE_OK) {
		result = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}
	if (sqlite3_bind_int64(stm, pos++, rule->to) != SQLITE_OK) {
		result = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (is_iftype_defined(rule->iftype)) {
		data.iftype = rule->iftype;
		if (sqlite3_bind_int
		    (stm, pos++, rule->iftype) != SQLITE_OK) {
			result = RESOURCED_ERROR_DB_FAILED;
			goto out;
		}
	}

	do {
		rc = sqlite3_step(stm);
		switch (rc) {
		case SQLITE_ROW:
			data.app_id = (char *)sqlite3_column_text(stm, 0);
			data.hw_net_protocol_type = sqlite3_column_int(stm, 1);
			data.roaming = sqlite3_column_int(stm, 2);
			data.ground = sqlite3_column_int(stm, 6);
			data.cnt.incoming_bytes = sqlite3_column_int64(stm, 3);
			data.cnt.outgoing_bytes = sqlite3_column_int64(stm, 4);
			data.imsi = (char *)sqlite3_column_text(stm, 5);
			if (rule->granularity) {
				interval.from = sqlite3_column_int64(stm, 7);
				interval.to = interval.from + rule->granularity;
			}

			if (info_cb(&data, user_data) == RESOURCED_CANCEL)
				rc = SQLITE_DONE;/* emulate end of data */
			break;
		case SQLITE_DONE:
			break;
		case SQLITE_ERROR:
		default:
			result = RESOURCED_ERROR_DB_FAILED;
			break;
		}
	} while (rc == SQLITE_ROW);
 out:
	sqlite3_reset(stm);
	return result;
}

/* the following array is strictly ordered
 * to find required statement the following code will be used:
 * (iface ? 1 : 0) | (total ? 2 : 0) | (chunks ? 4 : 0)
 */
static sqlite3_stmt **details_stms[] = {
	&data_usage_app_details,
	&data_usage_app_details_iface,
	&data_usage_total,
	&data_usage_total_iface,
	&data_usage_chunks_app,
	&data_usage_chunks_app_iface,
	&data_usage_chunks_total,
	&data_usage_chunks_total_iface
};

static sqlite3_stmt *select_statement(const char *app_id,
	const data_usage_selection_rule *rule)
{
	const int stm_index = is_iftype_defined(rule->iftype) |
	(app_id ? 0 : 2) | (rule->granularity ? 4 : 0);
	_D("stm index %d", stm_index);
	return *details_stms[stm_index];
}

API resourced_ret_c data_usage_details_foreach(const char *app_id,
				     data_usage_selection_rule *rule,
				     data_usage_info_cb info_cb, void *user_data)
{
	data_usage_info data;
	sqlite3_stmt *stm;
	resourced_ret_c result = RESOURCED_ERROR_NONE;
	int rc;
	int pos = 1;/* running through positions
		 where to bind parameters in the query */
	resourced_tm_interval interval;

	libresourced_db_initialize_once();
	if (init_datausage_foreach(resourced_get_database())!= SQLITE_OK) {
		_D("Failed to initialize data usage statements: %s\n",
		   sqlite3_errmsg(resourced_get_database()));
		return RESOURCED_ERROR_DB_FAILED;
	}
	memset(&data, 0, sizeof(data));

	if (!rule || !info_cb)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	/* pick a statement depending on parameters.
		See comment for details_stms */
	stm = select_statement(app_id, rule);

	if (rule->granularity) {
		if (sqlite3_bind_int64(stm, pos++, rule->granularity) !=
		    SQLITE_OK) {
			result = RESOURCED_ERROR_DB_FAILED;
			goto out;
		}
		data.interval = &interval;
	}

	if (sqlite3_bind_int64(stm, pos++, rule->from) != SQLITE_OK) {
		result = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}
	if (sqlite3_bind_int64(stm, pos++, rule->to) != SQLITE_OK) {
		result = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (app_id) {
		if (sqlite3_bind_text(stm, pos++, app_id, -1, SQLITE_TRANSIENT)
		    != SQLITE_OK) {
			result = RESOURCED_ERROR_DB_FAILED;
			goto out;
		}
		data.app_id = app_id;
	}

	if (is_iftype_defined(rule->iftype)) {
		if (sqlite3_bind_int
		    (stm, pos++, rule->iftype) != SQLITE_OK) {
			result = RESOURCED_ERROR_DB_FAILED;
			goto out;
		}
	}

	do {
		rc = sqlite3_step(stm);
		switch (rc) {
		case SQLITE_ROW:
			data.iftype = sqlite3_column_int(stm, 0);
			data.hw_net_protocol_type = sqlite3_column_int(stm, 1);
			data.roaming = sqlite3_column_int(stm, 2);
			data.cnt.incoming_bytes = sqlite3_column_int64(stm, 3);
			data.cnt.outgoing_bytes = sqlite3_column_int64(stm, 4);
			data.ifname = (char *)sqlite3_column_text(stm, 5);
			data.imsi = (char *)sqlite3_column_text(stm, 6);

			if (rule->granularity) {
				interval.from = sqlite3_column_int64(stm, 7);
				interval.to = interval.from + rule->granularity;
			}

			if (info_cb(&data, user_data) == RESOURCED_CANCEL)
				rc = SQLITE_DONE; /* emulate end of data */
			break;
		case SQLITE_DONE:
			break;
		case SQLITE_ERROR:
		default:
			result = RESOURCED_ERROR_DB_FAILED;
			break;
		}
	} while (rc == SQLITE_ROW);
 out:
	sqlite3_reset(stm);
	return result;
}
