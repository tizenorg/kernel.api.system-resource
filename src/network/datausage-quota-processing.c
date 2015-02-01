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
 *
 */

/*
 * @file datausage-quota-processing.c
 *
 * @desc Quota processing implementation.
 *	This implementation updates used quota table and determine
 *	moment of time for blocking.
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <inttypes.h>

#include "database.h"
#include "data_usage.h"
#include "macro.h"
#include "protocol-info.h"
#include "resourced.h"
#include "notification.h"
#include "storage.h"
#include "trace.h"
#include "roaming.h"
#include "datausage-restriction.h"
#include "datausage-vconf-common.h"

static GTree *quotas;
static sqlite3_stmt *select_stmt;
static sqlite3_stmt *insert_stmt;
static sqlite3_stmt *clear_effective_stmt;

static const char select_query[] = "SELECT qt.binpath, qt.sent_quota, qt.rcv_quota, "\
	"qt.snd_warning_threshold, qt.rcv_warning_threshold, "\
	"sent_used_quota, rcv_used_quota, qt.start_time AS quota_start_time, "\
	"qt.time_period AS quota_period, efq.start_time AS effective_start, "\
	"efq.finish_time AS effective_finish, qt.iftype AS iftype, " \
	"qt.roaming, "\
	"efq.state, "\
	"qt.ROWID "\
	"FROM quotas AS qt "\
	"LEFT OUTER JOIN effective_quotas AS efq ON (qt.binpath = efq.binpath "\
	"AND qt.iftype = efq.iftype AND qt.roaming = efq.roaming) "\
	"GROUP BY qt.binpath, qt.iftype, qt.sent_quota, qt.rcv_quota, " \
	"qt.roaming";

static const char insert_query[] = "REPLACE INTO effective_quotas " \
	"(binpath, sent_used_quota, rcv_used_quota, " \
	"start_time, finish_time, iftype, roaming, state) " \
	" VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

static const char clear_effective_quota_query[] = "DELETE FROM effective_quotas " \
	" WHERE binpath = ? AND iftype = ? AND roaming = ?";

enum resourced_quota_state {
	RESOURCED_QUOTA_UNKNOWN,	/**< undefined/initial state */
	RESOURCED_QUOTA_APPLIED,	/**< enabled/applied state */
	RESOURCED_QUOTA_REVERTED,	/**< disabled/reverted state */
};

struct quota {
	int quota_id;
	int64_t send_quota;
	int64_t rcv_quota;
	int64_t sent_used_quota;
	int64_t rcv_used_quota;
	int snd_warning_threshold;
	int rcv_warning_threshold;
	int start_time;
	int time_period;
	int real_start;
	int real_finish;
	enum resourced_quota_state state;
};

struct quota_key {
	const char *app_id;
	resourced_iface_type iftype;
	resourced_roaming_type roaming;
};

typedef enum {
	DROP_UNDEF = 0,
	DROP_NEED = 1,
	DROP_NO_NEED = 2
} drop_decision;

static void obtain_and_keep_quotas(sqlite3_stmt *query)
{
	int rc = 0;
	struct quota *value = 0;
	struct quota_key *key = 0;

	if (!query) {
		_D("Can not update quotas: empty query");
		return;
	}

	do {
		rc = sqlite3_step(query);

		if (rc == SQLITE_ERROR) {
			_E("Error updating quotas %s", sqlite3_errmsg(resourced_get_database()));
			return;
		} else if (rc == SQLITE_ROW) {
			value = g_new0(struct quota, 1);
			if (!value) {
				_E("Can't allocate value for quota");
				return;
			}

			key = g_new0(struct quota_key, 1);
			if (!key) {
				_E("Can't allocate key for quota");
				goto free_value;
			}

			key->app_id = strdup((char *)sqlite3_column_text(
				query, 0));
			key->iftype = sqlite3_column_int(
				query, 11);
			key->roaming = sqlite3_column_int(
				query, 12);

			value->send_quota = sqlite3_column_int64(
				query, 1);
			value->rcv_quota = sqlite3_column_int64(
				query, 2);
			value->snd_warning_threshold = sqlite3_column_int64(
				query, 3);
			value->rcv_warning_threshold = sqlite3_column_int64(
				query, 4);
			value->sent_used_quota = sqlite3_column_int64(
				query, 5);
			value->rcv_used_quota = sqlite3_column_int64(
				query, 6);
			value->start_time = sqlite3_column_int64(
				query, 7);
			value->time_period = sqlite3_column_int64(
				query, 8);
			value->real_start = sqlite3_column_int64(
				query, 9);
			value->real_finish = sqlite3_column_int64(
				query, 10);
			value->state = sqlite3_column_int64(
				query, 13);
			value->quota_id = sqlite3_column_int(
				query, 14);

			g_tree_insert(quotas, key, value);
		}
	} while (rc == SQLITE_ROW);

	return;
free_value:
	if (value)
		g_free(value);
}

static gint compare_quota_key(gconstpointer a, gconstpointer b,
	gpointer UNUSED user_data)
{
	const struct quota_key *key1 = a;
	const struct quota_key *key2 = b;
	/* the first part of the key is equal compare second */
	return strcmp(key1->app_id, key2->app_id) ||
		key1->iftype - key2->iftype ||
		key1->roaming - key2->roaming;
}

#define quota_key_destructor g_free
#define quota_destructor g_free

static void _clear_effective_quota(const char *app_id,
	const resourced_iface_type iftype,
	const resourced_roaming_type roaming)
{
	if (sqlite3_bind_text(clear_effective_stmt, 1, app_id, -1,
			  SQLITE_TRANSIENT) != SQLITE_OK) {
		_SE("Can not bind app_id:%s for preparing statement:%s",
			app_id, sqlite3_errmsg(resourced_get_database()));
		return;
	}

	if (sqlite3_bind_int(clear_effective_stmt, 2, iftype)
		!= SQLITE_OK) {
		_E("Can not bind iftype:%d for preparing statement:%s",
			iftype, sqlite3_errmsg(resourced_get_database()));
		return;
	}

	if (sqlite3_bind_int(clear_effective_stmt, 3, roaming)
		!= SQLITE_OK) {
		_E("Can not bind roaming:%d for preparing statement:%s",
			roaming, sqlite3_errmsg(resourced_get_database()));
		return;
	}

	if (sqlite3_step(clear_effective_stmt) != SQLITE_DONE)
		_E("Failed to clear effective quotas %s",
		sqlite3_errmsg(resourced_get_database()));
	sqlite3_reset(clear_effective_stmt);
}

static inline int _is_period_devisible(const int time_period,
		                     data_usage_quota_period_t quota_period)
{
	return time_period > quota_period &&
		time_period % RESOURCED_PERIOD_MONTH == 0;
}

/**
 * @desc Define period base on stored in data base time interval
 * @return time period
 */
static data_usage_quota_period_t _define_period(const int time_period, int *quantity)
{
	if (quantity == 0)
		return RESOURCED_PERIOD_UNDEF;

	if (_is_period_devisible(time_period, RESOURCED_PERIOD_MONTH)) {
		*quantity = time_period / RESOURCED_PERIOD_MONTH;
		return RESOURCED_PERIOD_MONTH;
	}

	if (_is_period_devisible(time_period, RESOURCED_PERIOD_MONTH)) {
		*quantity = time_period / RESOURCED_PERIOD_MONTH;
		return RESOURCED_PERIOD_MONTH;
	}

	if (_is_period_devisible(time_period, RESOURCED_PERIOD_WEEK)) {
		*quantity = time_period / RESOURCED_PERIOD_WEEK;
		return RESOURCED_PERIOD_WEEK;
	}

	if (_is_period_devisible(time_period, RESOURCED_PERIOD_DAY)) {
		*quantity = time_period / RESOURCED_PERIOD_DAY;
		return RESOURCED_PERIOD_DAY;
	}

	if (_is_period_devisible(time_period, RESOURCED_PERIOD_HOUR)) {
		*quantity = time_period / RESOURCED_PERIOD_HOUR;
		return RESOURCED_PERIOD_HOUR;
	}

	*quantity = time_period;
	return RESOURCED_PERIOD_UNDEF;
}


static time_t _get_finish_time(const time_t start_time, const int time_period)
{
	int quantity = 0;
	struct tm *new_start = gmtime((const time_t *)&start_time);

	switch (_define_period(time_period, &quantity)) {
	case RESOURCED_PERIOD_UNDEF:
		return start_time + time_period;
	case RESOURCED_PERIOD_HOUR:
		new_start->tm_hour += quantity;
	break;
	case RESOURCED_PERIOD_DAY:
		new_start->tm_mday += quantity;
	break;
	case RESOURCED_PERIOD_WEEK:
		new_start->tm_mday += quantity * 7;
	break;
	case RESOURCED_PERIOD_MONTH:
		new_start->tm_mon += quantity;
	break;
	}

	/* normilize */
	return mktime(new_start);
}

struct data_usage_context {
	int64_t sent_used_quota;
	int64_t rcv_used_quota;
	resourced_roaming_type roaming;
};

static resourced_cb_ret data_usage_details_cb(const data_usage_info *info,
					       void *user_data)
{
	struct data_usage_context *context =
		(struct data_usage_context *)user_data;

	if (!context ||
	    (context->roaming != RESOURCED_ROAMING_UNKNOWN &&
	     context->roaming != info->roaming))
		return RESOURCED_CONTINUE;

	context->sent_used_quota = info->foreground.cnt.incoming_bytes;
	context->rcv_used_quota = info->foreground.cnt.outgoing_bytes;
	return RESOURCED_CANCEL; /* only one entry allowed */
}

static void _record_quota(const struct quota_key *key,
		          const struct quota *app_quota)
{
	if (!key || !app_quota) {
		_E("Please, provide valid argument.");
		return;
	}

	if (!app_quota->sent_used_quota &&
	    !app_quota->rcv_used_quota) {
		_D("Nothing to store for effective quota.");
		return;
	}

	if (sqlite3_bind_text(insert_stmt, 1, key->app_id, -1,
			  SQLITE_STATIC) != SQLITE_OK) {
		_SE("Can not bind app_id:%s for preparing statement",
			key->app_id);
		return;
	}

	if (sqlite3_bind_int64(insert_stmt, 2, app_quota->sent_used_quota)
		!= SQLITE_OK) {
		_E("Can not bind sent_used_quota:%lld for preparing statement",
			app_quota->sent_used_quota);
		return;
	}

	if (sqlite3_bind_int64(insert_stmt, 3, app_quota->rcv_used_quota)
		!= SQLITE_OK) {
		_E("Can not bind rcv_used_quota:%lld for preparing statement",
			app_quota->rcv_used_quota);
		return;
	}

	if (sqlite3_bind_int64(insert_stmt, 4, app_quota->real_start)
		!= SQLITE_OK) {
		_E("Can not bind start_time:%d for preparing statement",
			app_quota->real_start);
		return;
	}

	if (sqlite3_bind_int64(insert_stmt, 5, app_quota->real_finish)
		!= SQLITE_OK) {
		_E("Can not bind finish_time:%d for preparing statement",
			app_quota->real_finish);
		return;
	}

	if (sqlite3_bind_int(insert_stmt, 6, key->iftype)
		!= SQLITE_OK) {
		_E("Can not bind iftype:%d for preparing statement",
			key->iftype);
		return;
	}

	if (sqlite3_bind_int(insert_stmt, 7, key->roaming)
		!= SQLITE_OK) {
		_E("Can not bind roaming:%d for preparing statement",
			key->roaming);
		return;
	}

	if (sqlite3_bind_int(insert_stmt, 8, app_quota->state)
		!= SQLITE_OK) {
		_E("Can not bind state:%d for preparing statement",
			app_quota->state);
		return;
	}

	if (sqlite3_step(insert_stmt) != SQLITE_DONE)
		_D("Failed to record quotas %s", sqlite3_errmsg(resourced_get_database()));
	sqlite3_reset(insert_stmt);
}

static void _set_effective_quota(const char *app_id,
	const resourced_iface_type iftype, const time_t start_time,
	const int time_period,
	const resourced_roaming_type roaming)
{
	data_usage_selection_rule rule = {0,};
	struct data_usage_context out_context = {0,};
	struct quota_key key_quota = {
		.app_id = app_id,
		.iftype = iftype,
		.roaming = roaming,
	};
	struct quota app_quota = {0,};
	const time_t cur_time = time(0);

	if (cur_time < start_time) {
		_D("No need to update effective quota!");
		return;
	}

	out_context.roaming = roaming;
	rule.from = start_time;
	rule.to = cur_time;
	rule.iftype = iftype;

	if (data_usage_details_foreach(app_id, &rule, data_usage_details_cb,
	                               &out_context) != RESOURCED_ERROR_NONE) {
		_E("Cant obtain sent_used_quota/rcv_used_quota");
		return;
	}

	_SD("Get counted traffic for appid:%s, per"
		"%s, incoming:%d, outgoing:%d", app_id, ctime(&start_time),
		out_context.rcv_used_quota, out_context.sent_used_quota);

	app_quota.sent_used_quota = out_context.sent_used_quota;
	app_quota.rcv_used_quota = out_context.rcv_used_quota;
	app_quota.real_start = start_time;
	app_quota.real_finish = _get_finish_time(start_time, time_period);
	app_quota.state = RESOURCED_QUOTA_APPLIED;
	_record_quota(&key_quota, &app_quota);
}

void update_quota_state(const char *app_id,
			const resourced_iface_type iftype,
			const time_t start_time,
			const int time_period,
			const resourced_roaming_type roaming)
{
	struct quota_key key;
	struct quota *tree_value;

	if (!app_id) {
		_SE("app_id must be not NULL");
		return;
	}

	key.app_id = app_id;
	key.iftype = iftype;
	key.roaming = roaming;
	tree_value = (struct quota *)g_tree_search(quotas,
	    (GCompareFunc)compare_quota_key, &key);

	if (tree_value && tree_value->state == RESOURCED_QUOTA_APPLIED) {
		_SD("Removing quota and restriction for %s,%d", app_id, iftype);
		/* Restrictions can't be separated */
		remove_restriction_local(app_id, iftype);
		g_tree_remove(quotas, (gconstpointer*)(&key));
		_clear_effective_quota(app_id, iftype, roaming);

		if (start_time && time_period)
			_set_effective_quota(app_id, iftype, start_time,
			time_period, roaming);
	} else
		_SD("There is no quota %s,%d in tree", app_id, iftype);
}

static resourced_ret_c _init_quotas(void)
{
	execute_once {
		quotas = g_tree_new_full(compare_quota_key, NULL,
			quota_key_destructor, quota_destructor);
	}

	if (!resourced_get_database())
		return RESOURCED_ERROR_DB_FAILED;

	if (select_stmt && insert_stmt)
		return RESOURCED_ERROR_NONE;

	if (sqlite3_prepare_v2(resourced_get_database(),
	                       select_query, -1, &select_stmt,
	                       NULL) != SQLITE_OK) {
		_E("Error preparing query: %s, \
		   %s\n", select_query, sqlite3_errmsg(resourced_get_database()));
		goto handle_error;
	}

	if (sqlite3_prepare_v2(resourced_get_database(),
	                       insert_query, -1, &insert_stmt,
	                       NULL) != SQLITE_OK) {
		_E("Error preparing query: %s, \
		   %s\n", insert_query, sqlite3_errmsg(resourced_get_database()));
		goto handle_error;
	}

	if (sqlite3_prepare_v2(resourced_get_database(),
		               clear_effective_quota_query,
	                       -1, &clear_effective_stmt,
	                       NULL) != SQLITE_OK) {
		_E("Error preparing query: %s, \
		   %s\n", clear_effective_quota_query,
			sqlite3_errmsg(resourced_get_database()));
		goto handle_error;
	}

	return RESOURCED_ERROR_NONE;
handle_error:
	/* Invoking sqlite3_finalize() on a NULL pointer is a harmless no-op */
	sqlite3_finalize(select_stmt);
	sqlite3_finalize(insert_stmt);
	sqlite3_finalize(clear_effective_stmt);
	return RESOURCED_ERROR_DB_FAILED;
}


/**
 * Update quotas tree, where app_id will the key
 */
static resourced_ret_c _update_quotas(void)
{
	const resourced_ret_c ret = _init_quotas();
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to init quotas");
		return ret;
	}

	obtain_and_keep_quotas(select_stmt);
	return RESOURCED_ERROR_NONE;
}

static const int64_t quota_gap_value[RESOURCED_IFACE_ALL] = {
	5000,	/* ~4.5MB UNKNOWN */
	5000,	/* ~3MB RESOURCED_IFACE_DATACALL */
	6000000,	/* ~6MB RESOURCED_IFACE_WIFI */
	5000000,	/* ~100MB RESOURCED_IFACE_WIRED */
	6000000,	/* ~6MB RESOURCED_IFACE_BLUETOOTH */
};

static const int64_t quota_datacall_gap_value[RESOURCED_PROTOCOL_MAX_ELEM] = {
	5000,  /* RESOURCED_PROTOCOL_NONE */
	5000,  /* RESOURCED_PROTOCOL_DATACALL_NOSVC */
	5000,  /* RESOURCED_PROTOCOL_DATACALL_EMERGENCY */
	5000,  /* RESOURCED_PROTOCOL_DATACALL_SEARCH */
	5000,  /* RESOURCED_PROTOCOL_DATACALL_2G */
	5000,  /* RESOURCED_PROTOCOL_DATACALL_2_5G #GPRS 40 kbit/s in practice */
	18750, /* RESOURCED_PROTOCOL_DATACALL_2_5G_EDGE 150 kbit/s in practice */
	400000, /* RESOURCED_PROTOCOL_DATACALL_3G, 7Mb/s on QC device */
	475000, /* RESOURCED_PROTOCOL_DATACALL_HSDPA */
	5000000,/* RESOURCED_PROTOCOL_DATACALL_LTE */
};

/*
 * @desc this function returns valud per second
 */
static int64_t _get_quota_gap(const resourced_iface_type iftype)
{

	const resourced_hw_net_protocol_type proto = get_hw_net_protocol_type(iftype);

	if (proto != RESOURCED_PROTOCOL_NONE)
		return quota_datacall_gap_value[proto];

	if (iftype > RESOURCED_IFACE_UNKNOWN &&
	    iftype < RESOURCED_IFACE_ALL)
		return quota_gap_value[iftype];

	return quota_gap_value[RESOURCED_IFACE_UNKNOWN];
}

int _is_under_restriction(const int64_t send_delta,
	const int64_t rcv_delta,
	const resourced_iface_type iftype,
	int update_period)
{
	/* multiply on 2, due  */
	const int64_t quota_gap = _get_quota_gap(iftype) * update_period;

	_D("send_delta %"PRId64" rcv_delta%"PRId64" quota_gap %"PRId64""
		 "update_period %d ",
		send_delta, rcv_delta, quota_gap, update_period);
	return send_delta <= quota_gap ||
		rcv_delta <= quota_gap;
}

inline void _check_warning_threshold(const int64_t send_delta, const int64_t rcv_delta,
	struct quota *app_quota, const char *appid)
{
	ret_msg_if(!app_quota, "Please provide valid pointer");

	if (send_delta <= app_quota->snd_warning_threshold ||
	    rcv_delta <= app_quota->rcv_warning_threshold) {
		app_quota->snd_warning_threshold = 0;
		app_quota->rcv_warning_threshold = 0;
		send_restriction_warn_notification(appid);
	}
}

inline static int _get_warning_limit(int64_t limit, int threshold)
{
	if (limit < threshold) {
		_E("Warning threshold is greater than limit!");
		return WARNING_THRESHOLD_DEFAULT; /* 0 means kernel will
						not procced it*/
	}
	return limit - threshold;
}

static int cast_restriction_limit(int64_t delta)
{
	if (delta < 0)
		return 0;
	if (delta > INT_MAX)
		return INT_MAX;
	return delta;
}

static gboolean check_and_apply_node(gpointer key,
				     gpointer value, gpointer user_data)
{
	struct quota *app_quota = value;
	struct quota_key *key_quota = key;
	int64_t send_delta, rcv_delta;
	struct daemon_opts *opts = (struct daemon_opts *)user_data;
	resourced_net_restrictions rst = { RESOURCED_STATE_UNKNOWN,
					   RESOURCED_IFACE_UNKNOWN };

	/* do not check already applied quota*/
	if (app_quota->state == RESOURCED_QUOTA_APPLIED)
		return FALSE;

	send_delta = app_quota->send_quota - app_quota->sent_used_quota;
	rcv_delta = app_quota->rcv_quota - app_quota->rcv_used_quota;

	if (app_quota->send_quota <= 0 || app_quota->rcv_quota <= 0)
		send_restriction_notification(key_quota->app_id);
	else
		_check_warning_threshold(send_delta, rcv_delta, app_quota,
			key_quota->app_id);

	if (_is_under_restriction(send_delta, rcv_delta, key_quota->iftype,
		opts->update_period) &&
	    (key_quota->roaming == RESOURCED_ROAMING_UNKNOWN ||
	     key_quota->roaming == get_roaming())) {
		if (!strcmp(key_quota->app_id, TETHERING_APP_NAME) &&
		    (send_delta > 0 || rcv_delta > 0))
			/* in the case of tethering we send
			   restriction only that must apply now */
			return FALSE;

		rst.send_limit = cast_restriction_limit(send_delta);
		rst.rcv_limit = cast_restriction_limit(rcv_delta);
		rst.snd_warning_limit = _get_warning_limit(
			rst.send_limit, app_quota->snd_warning_threshold);
		rst.rcv_warning_limit = _get_warning_limit(
			rst.rcv_limit, app_quota->rcv_warning_threshold);

		_SD("Applying quota for %s, iftype %d", key_quota->app_id,
		    key_quota->iftype);
		rst.iftype = key_quota->iftype;

		if (proc_keep_restriction(key_quota->app_id,
					      app_quota->quota_id, &rst,
					      RST_SET) == RESOURCED_ERROR_NONE) {
			app_quota->state = RESOURCED_QUOTA_APPLIED;
			_D("Restriction was applied successfully.");
		}
	}

	return FALSE; /* continue iteration */
}

static void check_and_apply_quota(volatile struct daemon_opts *opts)
{
	g_tree_foreach(quotas, check_and_apply_node, (void *)opts);
}

struct update_all_arg
{
	resourced_iface_type iftype;
	struct application_stat *app_stat;
};

static gboolean update_pseudo_app_entry(gpointer key,
	gpointer value, gpointer user_data)
{
	struct update_all_arg *arg = (struct
		update_all_arg *)user_data;
	const struct quota_key *qkey = (const struct
		quota_key *)key;

	/* handle case for network interfaces*/
	if ((!strcmp(qkey->app_id, RESOURCED_ALL_APP) &&
	     (qkey->iftype == RESOURCED_IFACE_UNKNOWN ||
	      qkey->iftype == RESOURCED_IFACE_ALL ||
	      qkey->iftype == arg->iftype) &&
	     (qkey->roaming == RESOURCED_ROAMING_UNKNOWN ||
	      qkey->roaming == arg->app_stat->is_roaming)) ||
	    !strcmp(qkey->app_id, TETHERING_APP_NAME)) {
		struct quota *total_quota = (struct quota *)value;
		/* update it */
		total_quota->sent_used_quota += arg->app_stat->delta_snd;
		total_quota->rcv_used_quota += arg->app_stat->delta_rcv;
		arg->app_stat->delta_snd = 0;
		arg->app_stat->delta_rcv = 0;
		_D("update total_quota tx:%"PRId64";rx:%"PRId64" iftype %d ifindex %d\n",
		   total_quota->sent_used_quota, total_quota->rcv_used_quota,
			arg->iftype, arg->app_stat->ifindex);

	}

	return FALSE;
}

static void update_all_app_quotas(struct update_all_arg *update_all_arg)
{
	/* Now RESOURCED_ALL_APP can contain many iftypes */
	g_tree_foreach(quotas, update_pseudo_app_entry, update_all_arg);
}

static void update_traffic_quota(const struct quota_key *quota_key,
				 uint32_t *snd_count,
				 uint32_t *rcv_count)
{
	struct quota *found_quota = g_tree_lookup(quotas, quota_key);

	if (!found_quota)
		return;
	if (time(0) < found_quota->start_time) {
		_D("No need to update effective quota!");
		return;
	}
	found_quota->sent_used_quota += *snd_count;
	found_quota->rcv_used_quota += *rcv_count;
	_D("update total_quota tx:%"PRId64";rx:%"PRId64"\n",
	   found_quota->sent_used_quota, found_quota->rcv_used_quota);

	_D("delta_rcv %d app_id %s\n", *rcv_count, quota_key->app_id);
	*snd_count = 0;
	*rcv_count = 0;
	return;
}

static gboolean update_each_quota(gpointer key, gpointer value,
	gpointer UNUSED userdata)
{
	const struct classid_iftype_key *app_key =
		(const struct classid_iftype_key *)key;
	struct application_stat *app_stat =
		(struct application_stat *)value;
	struct update_all_arg arg = {
		.iftype = app_key->iftype,
		.app_stat = app_stat
	};
	struct quota_key qkey;

	/* We should handle cases of RESOURCED_ALL_APP or TETHERING_APP_NAME
	   in separate way due it's not comming with statistics from kernel */
	update_all_app_quotas(&arg);

	if (!app_stat->application_id)
		return FALSE;

	qkey.app_id = app_stat->application_id;
	qkey.iftype = app_key->iftype;
	qkey.roaming = app_stat->is_roaming;
	update_traffic_quota(&qkey, &app_stat->delta_snd,
			     &app_stat->delta_rcv);
	return FALSE;
}

static void actualize_quota_table(struct application_stat_tree *apps)
{
	g_tree_foreach((GTree *)apps->tree, update_each_quota, NULL);
}

/**
 * @desc Assume app_quota is not null
 */
static void calculate_finish_time(struct quota *app_quota)
{
	if (!app_quota || app_quota->real_finish)
		return;

	if (!app_quota->real_start)
		app_quota->real_start = time(0);

	app_quota->real_finish = _get_finish_time(app_quota->real_start,
		app_quota->time_period);
}

/**
 * @desc Reset quota. This function sets new real_start based on fihish time.
 * Assume app_quota is set and  time(0) < app_quota->real_finish
 */
static void reset_quota(struct quota *app_quota)
{
	_D("reset_quota called");
	app_quota->real_start = app_quota->real_finish;
	app_quota->real_finish = 0;
	app_quota->sent_used_quota = app_quota->rcv_used_quota = 0;
	restriction_set_status(RESTRICTION_STATE_UNSET);
}

/**
 * @desc Remove restriction if needed
 */
static void drop_restriction(const struct quota_key *qkey, struct quota *app_quota)
{
	if (!app_quota || !qkey) {
		_E("Please provide valid arguments!");
		return;
	}

	/* We can revert only applied quotas */
	if (app_quota->state != RESOURCED_QUOTA_APPLIED)
		return;

	_SD("Removing restriction of quota for %s,%d", qkey->app_id,
	    qkey->iftype);
	if (remove_restriction_local(qkey->app_id, qkey->iftype)
	    == RESOURCED_ERROR_NONE)
		app_quota->state = RESOURCED_QUOTA_REVERTED;
}

/**
 * @desc This function actualize current quotas states. It calculate new
 *  finish time and remove restriction if exists.
 */
static gboolean flush_quota_node(gpointer key,
	gpointer value, gpointer UNUSED user_data)
{
	struct quota *app_quota = value;
	struct quota_key *key_quota = key;

	if (!app_quota || !key_quota->app_id)
		return FALSE; /* continue iteration even
		current data is empty */

	calculate_finish_time(app_quota);

	_record_quota(key_quota, app_quota);
	/* It's time to reset */
	if (time(0) >= app_quota->real_finish) {
		drop_restriction(key_quota, app_quota);
		reset_quota(app_quota);
	}
	return FALSE;
}

/**
 * Save to database effective quota
 */
void flush_quota_table(void)
{
	g_tree_foreach(quotas, flush_quota_node, NULL);
}

static void finalize_statement(sqlite3_stmt **stmt)
{
	if (*stmt) {
		sqlite3_finalize(*stmt);
		*stmt = NULL;
	}
}

resourced_ret_c process_quota(struct application_stat_tree *apps,
	volatile struct daemon_opts *opts)
{
	/* For first initialization */
	static int quota_updated;

	if (opts && opts->is_update_quota) {
		const int error = _update_quotas();
		if (error)
			return error;
		quota_updated = 1;
	}

	actualize_quota_table(apps);

	check_and_apply_quota(opts);

	/* finilize state */
	if (opts && opts->is_update_quota && quota_updated) {
		opts->is_update_quota = 0;
		quota_updated = 0;
	}
	return RESOURCED_ERROR_NONE;
}

/**
 * Release  statement
 */
void finalize_quotas(void)
{
	finalize_statement(&insert_stmt);
	finalize_statement(&select_stmt);
	finalize_statement(&clear_effective_stmt);
	g_tree_destroy(quotas);
}

