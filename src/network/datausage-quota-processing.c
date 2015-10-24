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

#include "counter.h"
#include "database.h"
#include "data_usage.h"
#include "macro.h"
#include "resourced.h"
#include "net-cls-cgroup.h"
#include "notification.h"
#include "storage.h"
#include "trace.h"
#include "telephony.h"
#include "datausage-common.h"
#include "datausage-restriction.h"
#include "datausage-vconf-common.h"
#include "datausage-quota-processing.h"

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
	"qt.ROWID, "\
	"qt.imsi, "\
	"qt.ground "\
	"FROM quotas AS qt "\
	"LEFT OUTER JOIN effective_quotas AS efq ON (qt.binpath = efq.binpath "\
	"AND qt.iftype = efq.iftype AND qt.roaming = efq.roaming "\
	"AND qt.imsi = efq.imsi) "\
	"GROUP BY qt.binpath, qt.iftype, qt.sent_quota, qt.rcv_quota, " \
	"qt.roaming, qt.imsi";

static const char insert_query[] = "REPLACE INTO effective_quotas " \
	"(binpath, sent_used_quota, rcv_used_quota, " \
	"start_time, finish_time, iftype, roaming, state, imsi) " \
	" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

static const char clear_effective_quota_query[] = "DELETE FROM effective_quotas " \
	" WHERE binpath = ? AND iftype = ? AND roaming = ? AND imsi = ?";

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
	const char *imsi_hash;
	resourced_state_t ground;
};

typedef enum {
	DROP_UNDEF = 0,
	DROP_NEED = 1,
	DROP_NO_NEED = 2
} drop_decision;

static inline bool check_imsi_hash(const char *hash_a, const char *hash_b);

static resourced_ret_c obtain_and_keep_quotas(sqlite3_stmt *query)
{
	int rc = 0;
	resourced_ret_c ret = RESOURCED_ERROR_NONE;
	struct quota *value = 0;
	struct quota_key *key = 0;

	ret_value_msg_if(!query, RESOURCED_ERROR_INVALID_PARAMETER,
		"Can not update quotas: empty query");

	do {
		rc = sqlite3_step(query);

		if (rc == SQLITE_ERROR) {
			_E("Error updating quotas %s", sqlite3_errmsg(resourced_get_database()));
			return RESOURCED_ERROR_DB_FAILED;
		} else if (rc == SQLITE_ROW) {
			value = g_new0(struct quota, 1);
			if (!value) {
				_E("Can't allocate value for quota");
				return RESOURCED_ERROR_OUT_OF_MEMORY;
			}

			key = g_new0(struct quota_key, 1);
			if (!key) {
				_E("Can't allocate key for quota");
				ret = RESOURCED_ERROR_OUT_OF_MEMORY;
				goto free_value;
			}

			key->app_id = strndup((char *)sqlite3_column_text(query, 0),
						strlen((char *)sqlite3_column_text(query, 0)));
			key->iftype = sqlite3_column_int(
				query, 11);
			key->roaming = sqlite3_column_int(
				query, 12);
			key->imsi_hash = strndup((char *)sqlite3_column_text(query, 15),
						strlen((char *)sqlite3_column_text(query, 15)));
			key->ground = sqlite3_column_int(query, 16);

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

			_D("populate quota tree:");
			_D("app_id: %s", key->app_id);
			_D("iftype: %d", key->iftype);
			_D("roaming: %d", key->roaming);
			_D("imsi_hash: %s", key->imsi_hash);
			_D("quota_id: %d", value->quota_id);
			_D("ground: %d", key->ground);
			g_tree_insert(quotas, key, value);
		}
	} while (rc == SQLITE_ROW);

	return RESOURCED_ERROR_NONE;
free_value:
	g_free(value);
	return ret;
}

static gint compare_quota_key(gconstpointer a, gconstpointer b,
	gpointer UNUSED user_data)
{
	const struct quota_key *key1 = a;
	const struct quota_key *key2 = b;
	int ret = 0;

	/* the main use case of setting it's different quotas
	 * per sim, and only afterward by appid */

	if (key1->imsi_hash && key2->imsi_hash)
		ret = strcmp(key1->imsi_hash, key2->imsi_hash);
	else if (!key1->imsi_hash || !key2->imsi_hash) /* in case of one empty another not */
		ret = key1->imsi_hash - key2->imsi_hash;

	if (ret) {
		_D("quotas different by imsi");
		return ret;
	}

	if (key1->app_id && key2->app_id)
		ret = strcmp(key1->app_id, key2->app_id);
	if (ret) {
		_D("quotas different by app_id");
		return ret;
	}

	ret = key1->iftype - key2->iftype;
	if (ret) {
		_D("quotas different by iftype");
		return ret;
	}
	ret = key1->ground - key2->ground;
	if (ret) {
		_D("quotas different by ground");
		return ret;
	}
	return key1->roaming - key2->roaming;
}

static void quota_key_destructor(void *key)
{
	struct quota_key *qkey = (struct quota_key *)key;
	if (qkey->app_id)
		free((char *)qkey->app_id);
	if (qkey->imsi_hash)
		free((char *)qkey->imsi_hash);
	g_free(key);
}
#define quota_destructor g_free

void clear_effective_quota(const char *app_id,
	const resourced_iface_type iftype,
	const resourced_roaming_type roaming,
	const char *imsi_hash)
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

	if (sqlite3_bind_text(clear_effective_stmt, 4, imsi_hash, -1, SQLITE_TRANSIENT)
		!= SQLITE_OK) {
		_E("Can not bind subscriber_id:%s for preparing statement:%s",
			imsi_hash, sqlite3_errmsg(resourced_get_database()));
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


static time_t get_finish_time(const time_t start_time, const int time_period)
{
	int quantity = 0;
	struct tm new_start;

	if (gmtime_r((const time_t *)&start_time, &new_start) == NULL)
		return (time_t)(-1);

	switch (_define_period(time_period, &quantity)) {
	case RESOURCED_PERIOD_UNDEF:
		return start_time + time_period;
	case RESOURCED_PERIOD_HOUR:
		new_start.tm_hour += quantity;
	break;
	case RESOURCED_PERIOD_DAY:
		new_start.tm_mday += quantity;
	break;
	case RESOURCED_PERIOD_WEEK:
		new_start.tm_mday += quantity * 7;
	break;
	case RESOURCED_PERIOD_MONTH:
		new_start.tm_mon += quantity;
	break;
	}

	/* normilize */
	return mktime(&new_start);
}

struct data_usage_context {
	int64_t sent_used_quota;
	int64_t rcv_used_quota;
	resourced_roaming_type roaming;
	const char *imsi;
	resourced_state_t ground;
};

static resourced_cb_ret data_usage_details_cb(const data_usage_info *info,
					       void *user_data)
{
	struct data_usage_context *context =
		(struct data_usage_context *)user_data;

	ret_value_msg_if(!context, RESOURCED_CONTINUE,
			"Invalid cb data!");

	if (context->roaming != info->roaming)
		return RESOURCED_CONTINUE;

	if (!CHECK_BIT(context->ground, info->ground))
		return RESOURCED_CONTINUE;

	/* if imsi is not specified, e.g. for WiFi
	 * need additional check*/
	if (info->imsi && context->imsi && strcmp(context->imsi, info->imsi))
		return RESOURCED_CONTINUE;

	context->sent_used_quota += info->cnt.outgoing_bytes;
	context->rcv_used_quota += info->cnt.incoming_bytes;
	/* calculate all traffic, several iteration could be
	 * needed when end user request quota for unknown roaming */
	return RESOURCED_CONTINUE;
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

	if (sqlite3_bind_text(insert_stmt, 9, key->imsi_hash, -1,
			  SQLITE_STATIC)
		!= SQLITE_OK) {
		_E("Can not bind subscriber_id:%s for preparing statement",
			key->imsi_hash);
		return;
	}

	if (sqlite3_step(insert_stmt) != SQLITE_DONE)
		_D("Failed to record quotas %s", sqlite3_errmsg(resourced_get_database()));
	sqlite3_reset(insert_stmt);
}

static time_t rule_start_time(time_t start_time,
					     time_t cur_time,
					     time_t time_interval)
{
	if (cur_time - start_time > time_interval)
		return cur_time - (cur_time - start_time) % time_interval;
	return start_time;
}

static void set_effective_quota(const char *app_id,
	const resourced_iface_type iftype, const time_t start_time,
	const int time_period,
	const resourced_roaming_type roaming,
	const char *imsi_hash,
	const resourced_state_t ground,
	struct quota *app_quota)
{
	data_usage_selection_rule rule = {0,};
	struct data_usage_context out_context = {0,};
	const time_t cur_time = time(0);
	char buf[30];

	app_id = !strcmp(app_id, RESOURCED_ALL_APP) ? 0: app_id;

	if (cur_time < start_time) {
		_D("No need to update effective quota!");
		return;
	}

	out_context.roaming = roaming;
	out_context.imsi = imsi_hash;
	out_context.ground = ground;
	/* user could specify start_time far ago in the past, and
	 * we will recalculate since that time, it's not good,
	 * especially if time_period is smaller then
	 * current_time - start_time */
	rule.from = rule_start_time(start_time, cur_time, time_period);
	rule.to = cur_time;
	rule.iftype = iftype;

	if (data_usage_details_foreach(app_id, &rule, data_usage_details_cb,
	                               &out_context) != RESOURCED_ERROR_NONE) {
		_E("Cant obtain sent_used_quota/rcv_used_quota");
		return;
	}

	if (ctime_r(&rule.from, buf))
		_SD("Get counted traffic for appid:%s, per %s "\
				"time interval %d, incoming:%" PRId64 ", outgoing:%" PRId64 "", app_id,
				buf, time_period, out_context.rcv_used_quota,
				out_context.sent_used_quota);

	app_quota->sent_used_quota = out_context.sent_used_quota;
	app_quota->rcv_used_quota = out_context.rcv_used_quota;
	app_quota->real_start = rule.from; /* otherwise we could get
					      real_finish in the past */
	app_quota->real_finish = get_finish_time(app_quota->real_start,
						 time_period);
}

static struct quota *find_quota_in_tree(const char *app_id,
		const resourced_iface_type iftype, const resourced_roaming_type roaming,
		const char *imsi, const resourced_state_t ground)
{
	struct quota_key key;
	key.app_id = app_id;
	key.iftype = iftype;
	key.roaming = roaming;
	key.imsi_hash = imsi;
	key.ground = ground;
	return (struct quota *)g_tree_lookup(quotas, &key);
}

bool check_quota_applied(const char *app_id, const resourced_iface_type iftype,
		const resourced_roaming_type roaming, const char *imsi,
		const resourced_state_t ground,	int *quota_id)
{
	struct quota *tree_value = find_quota_in_tree(app_id, iftype, roaming,
						      imsi, ground);

	if (!tree_value)
		return false;
	*quota_id = tree_value->quota_id;
	return tree_value->state == RESOURCED_QUOTA_APPLIED;
}

void update_quota_state(const char *app_id, const int quota_id,
			struct serialization_quota *ser_quota)
{
	struct quota *tree_value;
	struct quota_key *insert_key;

	if (!app_id) {
		_SE("app_id must be not NULL");
		return;
	}

	tree_value = find_quota_in_tree(app_id, ser_quota->iftype,
					ser_quota->roaming_type,
				        ser_quota->imsi_hash, ser_quota->quota_type);
	if (!check_event_in_current_modem(ser_quota->imsi_hash,
				ser_quota->iftype))
		check_and_clear_all_noti();

	if (tree_value && tree_value->state == RESOURCED_QUOTA_APPLIED) {
		_SD("Removing quota and restriction for %s,%d, %s", app_id,
				ser_quota->iftype, ser_quota->imsi_hash);
		/* Restrictions can't be separated */
		if (remove_restriction_local(app_id, ser_quota->iftype,
				tree_value->quota_id, ser_quota->imsi_hash,
				ser_quota->quota_type) == RESOURCED_ERROR_NONE)
			tree_value->state = RESOURCED_QUOTA_REVERTED;
		else
			_D("failed to revert quota %d", tree_value->quota_id);

		clear_effective_quota(app_id, ser_quota->iftype,
				ser_quota->roaming_type, ser_quota->imsi_hash);
	} else if (!tree_value) {
		insert_key = malloc(sizeof(struct quota_key));
		ret_msg_if (!insert_key, "not enough memory");
		memset(insert_key, 0, sizeof(struct quota_key));
		tree_value = (struct quota *)malloc(sizeof(struct quota));
		if (!tree_value) {
			_E("not enough memory");
			goto release_quota_key;
		}

		memset(tree_value, 0, sizeof(struct quota));
		/* app_id was allocated by dbus, and it will be freed
		 * when dbus request is gone */
		insert_key->app_id = strndup(app_id, strlen(app_id));
		if (!insert_key->app_id) {
			_E("not enough memory");
			goto release_quota_value;
		}

		insert_key->imsi_hash = strndup(ser_quota->imsi_hash, strlen(ser_quota->imsi_hash));
		if (!insert_key->imsi_hash) {
			_E("not enough memory");
			goto release_app_id;
		}
		insert_key->iftype = ser_quota->iftype;
		insert_key->roaming = ser_quota->roaming_type;
		_SD("There is no quota %s,%d in tree", app_id,
				ser_quota->iftype);
		insert_key->ground = ser_quota->quota_type;
		g_tree_insert(quotas, insert_key, tree_value);
	}

	/* we already stored quota, so _set_effective_quota, stores
	 * effective quota in db with new calculated value for exceeded
	 * trafifc */
	tree_value->send_quota = ser_quota->snd_quota;
	tree_value->rcv_quota = ser_quota->rcv_quota;
	/*
	 * in case of APPLIED/REVERTED quota used traffic need to clear
	 * it will be recalculated in set_effective_quota, due start
	 * time could be changed,
	 * also data_usage_details_foreach could fail, or user
	 * could not specify start_time and time_period
	 */
	tree_value->sent_used_quota = 0;
	tree_value->rcv_used_quota = 0;
	tree_value->snd_warning_threshold = ser_quota->snd_warning_threshold;
	tree_value->rcv_warning_threshold = ser_quota->rcv_warning_threshold;
	/* link with restriction */
	tree_value->quota_id = quota_id;
	set_effective_quota(app_id, ser_quota->iftype, ser_quota->start_time,
			    ser_quota->time_period, ser_quota->roaming_type,
			    ser_quota->imsi_hash, ser_quota->quota_type,
			    tree_value);

	return;

release_app_id:
	free((char *)insert_key->app_id);
release_quota_value:
	free(tree_value);
release_quota_key:
	free(insert_key);
}

void remove_quota_from_counting(const char *app_id, const resourced_iface_type iftype,
	const resourced_roaming_type roaming,
	const char *imsi_hash)
{
	struct quota_key key;
	ret_msg_if(!app_id,"app_id must be not NULL");

	key.app_id = app_id;
	key.iftype = iftype;
	key.roaming = roaming;
	key.imsi_hash = strndup(imsi_hash, strlen(imsi_hash));

	g_tree_remove(quotas, (gconstpointer*)(&key));
}


static resourced_ret_c _init_quotas(void)
{
	quotas = g_tree_new_full(compare_quota_key, NULL,
			quota_key_destructor, quota_destructor);

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
static resourced_ret_c load_quotas(void)
{
	const resourced_ret_c ret = _init_quotas();
	ret_value_msg_if (ret != RESOURCED_ERROR_NONE, ret, "Failed to init quotas");
	return obtain_and_keep_quotas(select_stmt);
}

static const int64_t quota_gap_value[RESOURCED_IFACE_ALL] = {
	400000,	/* ~4.5MB UNKNOWN */
	400000,	/* ~3MB RESOURCED_IFACE_DATACALL */
	6000000,	/* ~6MB RESOURCED_IFACE_WIFI */
	5000000,	/* ~100MB RESOURCED_IFACE_WIRED */
	6000000,	/* ~6MB RESOURCED_IFACE_BLUETOOTH */
};

static const int64_t quota_datacall_gap_value[RESOURCED_PROTOCOL_MAX_ELEM] = {
	400000,  /* RESOURCED_PROTOCOL_NONE */
	400000,  /* RESOURCED_PROTOCOL_DATACALL_NOSVC */
	400000,  /* RESOURCED_PROTOCOL_DATACALL_EMERGENCY */
	400000,  /* RESOURCED_PROTOCOL_DATACALL_SEARCH */
	400000,  /* RESOURCED_PROTOCOL_DATACALL_2G */
	400000,  /* RESOURCED_PROTOCOL_DATACALL_2_5G #GPRS 40 kbit/s in practice */
	400000, /* RESOURCED_PROTOCOL_DATACALL_2_5G_EDGE 150 kbit/s in practice */
	400000, /* RESOURCED_PROTOCOL_DATACALL_3G, 7Mb/s on QC device */
	475000, /* RESOURCED_PROTOCOL_DATACALL_HSDPA */
	5000000,/* RESOURCED_PROTOCOL_DATACALL_LTE */
};

/*
 * @desc this function returns valud per second
 */
static int64_t _get_quota_gap(const resourced_iface_type iftype)
{

	const resourced_hw_net_protocol_type proto = get_current_protocol(iftype);
	_D("proto: %d, iftype: %d", proto, iftype);

	if (proto != RESOURCED_PROTOCOL_NONE)
		return quota_datacall_gap_value[proto];

	if (iftype > RESOURCED_IFACE_UNKNOWN &&
	    iftype < RESOURCED_IFACE_ALL)
		return quota_gap_value[iftype];

	return quota_gap_value[RESOURCED_IFACE_UNKNOWN];
}

static int check_restriction_needed(const int64_t send_delta,
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

inline static int get_warning_limit(int64_t delta, int64_t limit, int threshold)
{
	if (delta < threshold)
		return 0; /* send warning immediately */

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

static bool skip_quota(struct quota_key *key_quota, struct quota *app_quota,
		const int64_t send_delta, const int64_t rcv_delta)
{
	char *imsi_hash;
	/* do not check already applied quota*/
	if (app_quota->state == RESOURCED_QUOTA_APPLIED) {
		_D("already applied");
		return true;
	}

	if (!strcmp(key_quota->app_id, TETHERING_APP_NAME) &&
	    (send_delta > 0 || rcv_delta > 0)) {
		_D("tethering");
		/* in the case of tethering we send
		   restriction only that must apply now */
		return true;
	}

	if (key_quota->iftype == RESOURCED_IFACE_DATACALL) {
		/* TODO it could get_current_modem_imsi_hash, and
		 * it could be faster */
		imsi_hash = get_imsi_hash(get_current_modem_imsi());
		/* in redwood imsi could be null due absent telephony
		 * response */
		if (!check_imsi_hash(key_quota->imsi_hash, imsi_hash)) {
			_D("imsi different");
			return true;
		}
	}
	/* TODO the same check for current iftype, without it
	 * WiFi quota and datacall quota couldn't coexit */
	return false;
}

static gboolean check_and_apply_node(gpointer key,
				     gpointer value, gpointer user_data)
{
	struct quota *app_quota = value;
	struct quota_key *key_quota = key;
	struct counter_arg *carg = (struct counter_arg *)user_data;
	resourced_net_restrictions rst = { RESOURCED_STATE_UNKNOWN,
					   RESOURCED_IFACE_UNKNOWN,};
	int64_t send_delta = app_quota->send_quota - app_quota->sent_used_quota;
	int64_t rcv_delta = app_quota->rcv_quota - app_quota->rcv_used_quota;
	struct net_counter_opts *opts;

	ret_value_msg_if(!carg, FALSE, "Please provide valid carg argument!");

	opts = carg->opts;

	if (skip_quota(key_quota, app_quota, send_delta, rcv_delta)) {
		_D("no need to apply quota");
		return FALSE;
	}

	_D("quota rcv: %" PRId64 ", send: %" PRId64 "", app_quota->rcv_quota,
	   app_quota->send_quota);
	_D("delta rcv: %" PRId64 ", send: %" PRId64 "", rcv_delta, send_delta);

	/* gap guard part, block immediately if send/rcv_delta is less or
	 * equal zero */
	if (check_restriction_needed(send_delta, rcv_delta, key_quota->iftype,
		opts->update_period) &&
	    (key_quota->roaming == RESOURCED_ROAMING_UNKNOWN ||
	     key_quota->roaming == get_current_roaming())) {
		data_usage_quota du_quota = {0}; /* use both for
						    warning/restriction noti */

		rst.rs_type = key_quota->ground;
		rst.send_limit = cast_restriction_limit(send_delta);
		rst.rcv_limit = cast_restriction_limit(rcv_delta);
		rst.snd_warning_limit = get_warning_limit(send_delta,
				rst.send_limit, app_quota->snd_warning_threshold);
		rst.rcv_warning_limit = get_warning_limit(rcv_delta,
				rst.rcv_limit, app_quota->rcv_warning_threshold);

		_SD("Applying gap quota for %s, iftype %d, ground", key_quota->app_id,
		    key_quota->iftype, key_quota->ground);
		rst.iftype = key_quota->iftype;
		rst.ifname = get_iftype_name(rst.iftype);
		rst.roaming = key_quota->roaming;
		rst.imsi = key_quota->imsi_hash;

		/*
		 * client request quota for background application or
		 * applications, lets create here background cgroup,
		 * we will put later processes in it
		 */
		if (key_quota->ground == RESOURCED_STATE_BACKGROUND)
			create_net_background_cgroup(carg);

		/* we already checked in check_restriction_needed
		 * is it current imsi or not,
		 * just do not skip kernel op */
		if (proc_keep_restriction(key_quota->app_id,
				          app_quota->quota_id, &rst,
					  RST_SET, false, RESOURCED_RESTRICTION_ACTIVATED) != RESOURCED_ERROR_NONE) {
			_E("Failed to keep restriction!");
			return FALSE;
		}

		du_quota.snd_quota = app_quota->send_quota;
		du_quota.rcv_quota = app_quota->rcv_quota;
		du_quota.quota_type = key_quota->ground;

		/*
		 * in case of !rst.send_limit and !rst.rcv_limit
		 * restriction will come from fill_restriction nfacct handler
		 * */
		if (/*!rst.send_limit || */ !rst.rcv_limit)
			send_restriction_notification(key_quota->app_id, &du_quota);
		else if (/*!rst.snd_warning_limit ||*/!rst.rcv_warning_limit)
			send_restriction_warn_notification(key_quota->app_id, &du_quota);

		app_quota->state = RESOURCED_QUOTA_APPLIED;
		_D("Restriction was applied successfully.");

	}

	return FALSE; /* continue iteration */
}

static void check_and_apply_quota(struct counter_arg *carg)
{
	g_tree_foreach(quotas, check_and_apply_node, (void *)carg);
}

struct update_all_arg
{
	resourced_iface_type iftype;
	char *imsi_hash;
	struct application_stat *app_stat;
};

static inline bool check_imsi_hash(const char *hash_a, const char *hash_b)
{
	if (hash_a && hash_b)
		return !strcmp(hash_a,  hash_b);
	return hash_a == hash_b; /* both null */
}

static bool check_ground_state(const struct quota_key *qkey,
		struct application_stat *app_stat)
{
	/*
	 * unspecified quota, means BACKGROUND and FOREGROUND
	 * traffic should be taken into account
	 * */
	if (qkey->ground == RESOURCED_STATE_UNKNOWN)
		return true;
	return CHECK_BIT(qkey->ground, app_stat->ground);
}

static gboolean update_pseudo_app_entry(gpointer key,
	gpointer value, gpointer user_data)
{
	struct update_all_arg *arg = (struct
		update_all_arg *)user_data;
	const struct quota_key *qkey = (const struct
		quota_key *)key;
	struct quota *total_quota = (struct quota *)value;

	if (time(0) < total_quota->start_time) {
		_D("No need to update effective quota!");
		return FALSE;
	}

	_D("app id %s", qkey->app_id);
	_D("app ground %d", qkey->ground);
	_D("app stat app_id %s", arg->app_stat->application_id);
	_D("app stat ground %d", arg->app_stat->ground);

	/* handle case for network interfaces*/
	if ((!strcmp(qkey->app_id, RESOURCED_ALL_APP) &&
	     (qkey->iftype == RESOURCED_IFACE_UNKNOWN ||
	      qkey->iftype == RESOURCED_IFACE_ALL ||
	      qkey->iftype == arg->iftype) &&
	     (check_imsi_hash(qkey->imsi_hash, arg->imsi_hash)) &&
	     (qkey->roaming == RESOURCED_ROAMING_UNKNOWN ||
	      qkey->roaming == arg->app_stat->is_roaming) &&
	      check_ground_state(qkey, arg->app_stat)) ||
	    !strcmp(qkey->app_id, TETHERING_APP_NAME))
	{
		/* update it */
		total_quota->sent_used_quota += arg->app_stat->delta_snd;
		total_quota->rcv_used_quota += arg->app_stat->delta_rcv;
		arg->app_stat->delta_snd = 0;
		arg->app_stat->delta_rcv = 0;
		_D("update total_quota tx:%"PRId64";rx:%"PRId64" iftype %d \n",
		   total_quota->sent_used_quota, total_quota->rcv_used_quota,
			arg->iftype);
		_D("app id %s", qkey->app_id);
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
	arg.imsi_hash = app_key->iftype == RESOURCED_IFACE_DATACALL ?
		get_imsi_hash(app_key->imsi) : "";

	/* We should handle cases of RESOURCED_ALL_APP or TETHERING_APP_NAME
	   in separate way due it's not comming with statistics from kernel */
	update_all_app_quotas(&arg);

	if (!app_stat->application_id)
		return FALSE;

	qkey.app_id = app_stat->application_id;
	qkey.iftype = app_key->iftype;
	qkey.roaming = app_stat->is_roaming;
	/* TODO ground is not handled for quota per application,
	 * due GUI is not set quota per application, yet,
	 * no such requirements */
	qkey.imsi_hash = app_key->iftype == RESOURCED_IFACE_DATACALL ? get_imsi_hash(app_key->imsi): "";
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

	app_quota->real_finish = get_finish_time(app_quota->real_start,
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
	if (remove_restriction_local(qkey->app_id, qkey->iftype,
				app_quota->quota_id, qkey->imsi_hash, qkey->ground)
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

resourced_ret_c process_quota(struct counter_arg *carg)
{
	ret_value_msg_if(!carg, RESOURCED_ERROR_INVALID_PARAMETER,
			"Please provide carg!");

	execute_once {
		const resourced_ret_c ret = load_quotas();
		ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"Failed to load quotas!");
	}

	actualize_quota_table(carg->result);

	check_and_apply_quota(carg);

	return RESOURCED_ERROR_NONE;
}

struct quota_search_context {
	int quota_id;
	struct quota *quota;
	struct quota_key *key;
};

static gboolean search_quota_cb(gpointer key, gpointer value, gpointer data)
{
	struct quota_search_context *ctx = (struct quota_search_context *)data;
	struct quota *quota = (struct quota *)value;
	/**
	 * quota id is uniqe, but not in key, because isn't used in
	 * checking quota
	 */
	if (ctx->quota_id == quota->quota_id) {
		ctx->quota = quota;
		ctx->key = key;
		return TRUE;
	}
	return FALSE;
}

static gboolean search_background_quota_cb(gpointer key, gpointer value, gpointer data)
{
	bool *background = (bool *)data;
	struct quota *quota = (struct quota *)value;
	struct quota_key *qkey = (struct quota_key *)key;
	/**
	 * quota id is uniqe, but not in key, because isn't used in
	 * checking quota
	 */
	if (quota->state == RESOURCED_QUOTA_APPLIED &&
	    qkey->ground == RESOURCED_STATE_BACKGROUND) {
		*background = true;
		return TRUE;
	}
	return FALSE;
}

resourced_ret_c get_quota_by_id(const int quota_id, data_usage_quota *du_quota)
{
	struct quota_search_context ctx = {.quota_id = quota_id};
	execute_once {
		if (!g_tree_nnodes(quotas))
			load_quotas();
	}
	g_tree_foreach(quotas, search_quota_cb, &ctx);
	if (ctx.key && ctx.quota) {
		du_quota->snd_quota = ctx.quota->send_quota;
		du_quota->rcv_quota = ctx.quota->rcv_quota;
		du_quota->imsi = ctx.key->imsi_hash;
		du_quota->quota_type = ctx.key->ground;
		return RESOURCED_ERROR_NONE;
	}
	return RESOURCED_ERROR_FAIL;
}

resourced_ret_c get_quota_by_appid(const char* app_id, const char *imsi_hash,
		const resourced_iface_type iftype, resourced_roaming_type roaming,
	        data_usage_quota *du_quota, int *quota_id, resourced_state_t ground)
{
	struct quota *qt;
	execute_once {
		if (!g_tree_nnodes(quotas))
			load_quotas();
	}

	qt = find_quota_in_tree(app_id, iftype, roaming, imsi_hash, ground);
	if (qt) {
		du_quota->snd_quota = qt->send_quota;
		du_quota->rcv_quota = qt->rcv_quota;
		*quota_id = qt->quota_id;
		return RESOURCED_ERROR_NONE;
	}
	return RESOURCED_ERROR_FAIL;
}

bool get_background_quota(void)
{
	bool background = false;
	g_tree_foreach(quotas, search_background_quota_cb, &background);
	return background;
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

