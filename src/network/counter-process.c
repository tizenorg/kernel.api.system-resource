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

/**
 * @file counter-process.c
 *
 * @desc Counter process entity
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "app-stat.h"
#include "cgroup.h"
#include "config.h"
#include "const.h"
#include "counter.h"
#include "database.h"
#include "datausage-common.h"
#include "datausage-quota.h"
#include "datausage-quota-processing.h"
#include "datausage-restriction.h"
#include "edbus-handler.h"
#include "generic-netlink.h"
#include "net-cls-cgroup.h"
#include "nfacct-rule.h"
#include "macro.h"
#include "module-data.h"
#include "notification.h"
#include "resourced.h"
#include "roaming.h"
#include "storage.h"
#include "trace.h"
#include "transmission.h"
#include "datausage-vconf-common.h"

#include <Ecore.h>
#include <endian.h>
#include <glib.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <stdbool.h>

static char *null_str = "(null)";

#define INSERT_QUERY "REPLACE INTO quotas " \
	"(binpath, sent_quota, rcv_quota, " \
	"snd_warning_threshold, rcv_warning_threshold, time_period, " \
	"start_time, iftype, roaming) " \
	"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);"
#define REMOVE_QUOTA "DELETE FROM quotas WHERE binpath=? AND iftype=? " \
	" AND roaming=?"

#define QUOTA_CEILING_VALUE 10737418220

/* Warning threshold part in percent*/
enum {
	WARNING_THRESHOLD_DEFAULT_PART = 5,
	WARNING_THRESHOLD_PART_10 = 10,
	WARNING_THRESHOLD_PART_15 = 15,
	WARNING_THRESHOLD_PART_20 = 20,
};

static sqlite3_stmt *datausage_quota_insert;
static sqlite3_stmt *datausage_quota_remove;

static bool check_net_blocked(sig_atomic_t state)
{
	static int net_blocked; /* counter for run only one time after blocking
		to store gap value */
	if (state & RESOURCED_NET_BLOCKED_STATE &&
		net_blocked)
		return true;

	/* set net_blocked flag */
	if (!net_blocked &&
			state & RESOURCED_NET_BLOCKED_STATE)
		++net_blocked;
	/* reset net_blocked flag */
	if (net_blocked &&
		!(state & RESOURCED_NET_BLOCKED_STATE))
		--net_blocked;
	_D("net_blocked %d, state %d", net_blocked, state);
	return false;
}

#ifdef CONFIG_DATAUSAGE_NFACCT
static Eina_Bool send_counter_request(struct counter_arg *carg)
{
	return nfacct_send_get(carg) == RESOURCED_ERROR_NONE ?
		ECORE_CALLBACK_RENEW : ECORE_CALLBACK_CANCEL;
}

/* TODO exclude wlll be broken */
static nfacct_rule_jump get_counter_jump(nfacct_rule_intend intend)
{
	if (intend == NFACCT_WARN)
		return NFACCT_JUMP_ACCEPT;
	else if (intend == NFACCT_BLOCK)
		return NFACCT_JUMP_REJECT;

	return NFACCT_JUMP_UNKNOWN;
}

static void populate_counters(char *cnt_name,
			struct counter_arg *carg)
{
	struct nfacct_rule counter = { .name = {0}, .ifname = {0}, 0, };
	nfacct_rule_jump jump = NFACCT_JUMP_UNKNOWN;

	if (!recreate_counter_by_name(cnt_name, &counter)) {
		_E("Can't parse counter name %s", cnt_name);
		return;
	}

	counter.carg = carg;
	strcpy(counter.name, cnt_name);
	jump = get_counter_jump(counter.intend);
	_D("counter: %s, classid %u, iftype %u, iotype %d, bytes %lu", cnt_name,
		counter.classid, counter.iftype,
		counter.iotype);

	produce_net_rule(&counter, 0, 0,
		NFACCT_ACTION_APPEND, jump, counter.iotype);

	keep_counter(&counter);
}

static void populate_traf_stat_list(char *cnt_name, uint64_t bytes,
			struct counter_arg *carg)
{
	struct traffic_stat *to_insert;
	struct classid_iftype_key *key;
	struct nfacct_rule counter = { .name = {0}, .ifname = {0}, 0, };
	traffic_stat_tree *tree = NULL;

	_D("cnt_name %s", cnt_name);

	if (!recreate_counter_by_name(cnt_name, &counter)) {
		_E("Can't parse counter name %s", cnt_name);
		return;
	}

	_D("classid %u, iftype %u, iotype %d, intend %d, ifname %s, bytes %lu",
	   counter.classid, counter.iftype, counter.iotype, counter.intend, counter.ifname, bytes);

	if (counter.iotype == NFACCT_COUNTER_UNKNOWN ||
		counter.intend != NFACCT_COUNTER) {
		_E("Counter type is not supported!");
		return;
	}

	tree = counter.iotype == NFACCT_COUNTER_IN ? carg->in_tree : carg->out_tree;
	to_insert = g_new(struct traffic_stat, 1);
	if (!to_insert) {
		_D("Can't allocate %d bytes for traffic_stat\n", sizeof(struct traffic_stat));
		return;
	}

	key = g_new(struct classid_iftype_key, 1);

	if (!key) {
		_D("Can't allocate %d bytes for classid_iftype_key\n", sizeof(struct classid_iftype_key));
		g_free((gpointer)to_insert);
		return;
	}

	to_insert->bytes = bytes;
	/*to_insert->ifindex = cur->ifindex;*/
	key->classid = counter.classid;
	key->iftype = counter.iftype;
	STRING_SAVE_COPY(key->ifname, counter.ifname);
	g_tree_insert((GTree *) tree, (gpointer)key, to_insert);
}

static int fill_counters(struct rtattr *attr_list[__NFACCT_MAX],
		void *user_data)
{
	struct counter_arg *carg = user_data;
	char *cnt_name = (char *)RTA_DATA(
				attr_list[NFACCT_NAME]);
	if (carg->initiate)
		populate_counters(cnt_name, carg);
	else {
		uint64_t *bytes_p = (uint64_t *)RTA_DATA(attr_list[NFACCT_BYTES]);
		int bytes = be64toh(*bytes_p);
		/* TODO: optimize at kernel level, kernel should not send counter
		 * in case of 0 bytes, it's necessary to introduce new NFACCT_*
		 * command */
		if (bytes)
			populate_traf_stat_list(cnt_name, bytes, carg);
	}

	return 0;
}

static int post_fill_counters(void *user_data)
{
	struct counter_arg *carg = user_data;

	if (carg->initiate)
		carg->initiate = 0;

	return 0;
}

#else
static Eina_Bool send_counter_request(struct counter_arg *carg)
{
	int ret = send_command(carg->sock, carg->pid, carg->family_id_stat,
			TRAF_STAT_C_GET_CONN_IN);
	ret_value_msg_if(ret < 0, ECORE_CALLBACK_RENEW,
			"Failed to send command to get incomming traffic");

	ret = send_command(carg->sock, carg->pid, carg->family_id_stat,
			TRAF_STAT_C_GET_PID_OUT);
	ret_value_msg_if(ret < 0, ECORE_CALLBACK_RENEW,
			"Failed to send command to get outgoing traffic");

	return ECORE_CALLBACK_RENEW;
}
#endif /* CONFIG_DATAUSAGE_NFACCT */

static Eina_Bool _counter_func_cb(void *user_data)
{
	struct counter_arg *carg = (struct counter_arg *)user_data;

	if (check_net_blocked(carg->opts->state)) {
		ecore_timer_freeze(carg->ecore_timer);
		return ECORE_CALLBACK_RENEW;
	}

	if (!(carg->opts->state & RESOURCED_FORCIBLY_QUIT_STATE)) {
		/* Here we just sent command,
		 * answer we receiving in another callback, send_command uses
		 * return value the same as sendto
		 */

		return send_counter_request(carg);
	}

	close(carg->sock);
	return ECORE_CALLBACK_CANCEL;
}

static dbus_bool_t deserialize_restriction(
	DBusMessage *msg, char **appid, resourced_net_restrictions *rest,
	enum traffic_restriction_type *rst_type)
{
	DBusError err;
	dbus_error_init(&err);

	int ret = dbus_message_get_args(
		msg, &err,
		DBUS_TYPE_STRING, appid,
		DBUS_TYPE_INT32, rst_type,
		DBUS_TYPE_INT32, &(rest->rs_type),
		DBUS_TYPE_INT32, &(rest->iftype),
		DBUS_TYPE_INT32, &(rest->send_limit),
		DBUS_TYPE_INT32, &(rest->rcv_limit),
		DBUS_TYPE_INT32, &(rest->snd_warning_limit),
		DBUS_TYPE_INT32, &(rest->rcv_warning_limit),
		DBUS_TYPE_INT32, &(rest->roaming),
		DBUS_TYPE_INVALID);

	if (ret == FALSE) {
		_E("Can't deserialize quota! [%s:%s]\n",
		err.name, err.message);
	}

	dbus_error_free(&err);

	return ret;
}

static DBusMessage *edbus_process_restriction(E_DBus_Object *obj,
					      DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	int ret;
	resourced_ret_c dbus_ret = RESOURCED_ERROR_NONE;
	char *appid = NULL;
	resourced_net_restrictions rest;
	enum traffic_restriction_type rst_type;

	ret = dbus_message_is_method_call(
	    msg, RESOURCED_INTERFACE_NETWORK,
	    RESOURCED_NETWORK_PROCESS_RESTRICTION);

	if (ret == FALSE)
		return dbus_message_new_error(msg, DBUS_ERROR_UNKNOWN_METHOD,
					      "Method is not supported");

	ret = deserialize_restriction(msg, &appid, &rest, &rst_type);

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	if (ret == FALSE) {
		dbus_ret = RESOURCED_ERROR_FAIL;
		goto out;
	}

	dbus_ret = proc_keep_restriction(appid, NONE_QUOTA_ID, &rest,
					     rst_type);
out:
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &dbus_ret);

	return reply;
}

static DBusMessage *edbus_update_counters(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessage *reply;
	struct shared_modules_data *m_data = get_shared_modules_data();

	if (dbus_message_is_method_call(msg, RESOURCED_INTERFACE_NETWORK,
					RESOURCED_NETWORK_UPDATE) == 0)
		return dbus_message_new_error(msg, DBUS_ERROR_UNKNOWN_METHOD,
					      "Method is not supported");

	if (m_data != NULL && m_data->carg != NULL) {
		if (!(m_data->carg->opts->state & RESOURCED_FORCIBLY_QUIT_STATE))
			m_data->carg->opts->state |=
				RESOURCED_FORCIBLY_FLUSH_STATE;

		/* postpone periodic update on one minute */
		reschedule_count_timer(m_data->carg, COUNTER_UPDATE_PERIOD);
		_counter_func_cb(m_data->carg);
	}

	reply = dbus_message_new_method_return(msg);
	return reply;
}

struct serialization_quota {
	int time_period;
	int64_t snd_quota;
	int64_t rcv_quota;
	int snd_warning_threshold;
	int rcv_warning_threshold;
	resourced_state_t quota_type;
	resourced_iface_type iftype;
	time_t start_time;
	resourced_roaming_type roaming_type;
};

static inline int _get_threshold_part(int time_period)
{
	if (time_period < RESOURCED_PERIOD_DAY)
		return WARNING_THRESHOLD_PART_20;

	if (time_period < RESOURCED_PERIOD_WEEK)
		return WARNING_THRESHOLD_PART_15;

	if (time_period < RESOURCED_PERIOD_MONTH)
		return WARNING_THRESHOLD_PART_10;

	return WARNING_THRESHOLD_DEFAULT_PART;
}

static inline int64_t get_quota_ceiling(const int64_t quota)
{
	return quota >= QUOTA_CEILING_VALUE ? QUOTA_CEILING_VALUE :
		quota;
}

static inline int _evaluate_warning_threshold(const int64_t quota,
	const int time_period, const int user_threshold)
{
	int threshold_part = WARNING_THRESHOLD_DEFAULT_PART;

	if (user_threshold != WARNING_THRESHOLD_DEFAULT)
		return user_threshold;

	threshold_part = _get_threshold_part(time_period);

	return (get_quota_ceiling(quota) / 100 ) * threshold_part;
}

static dbus_bool_t deserialize_quota(
	DBusMessage *msg, char **appid,
	struct serialization_quota *quota)
{
	DBusError err;
	dbus_error_init(&err);

	int ret = dbus_message_get_args(
		msg, &err,
		DBUS_TYPE_STRING, appid,
		DBUS_TYPE_INT32, &quota->time_period,
		DBUS_TYPE_UINT64, &quota->snd_quota,
		DBUS_TYPE_UINT64, &quota->rcv_quota,
		DBUS_TYPE_INT32, &quota->snd_warning_threshold,
		DBUS_TYPE_INT32, &quota->rcv_warning_threshold,
		DBUS_TYPE_INT32, &quota->quota_type,
		DBUS_TYPE_INT32, &quota->iftype,
		DBUS_TYPE_INT32, &quota->start_time,
		DBUS_TYPE_INT32, &quota->roaming_type,
		DBUS_TYPE_INVALID);
	if (ret == FALSE) {
		_E("Can't deserialize set quota message ![%s:%s]\n",
		err.name, err.message);
	}

	dbus_error_free(&err);

	quota->iftype =	(quota->iftype == RESOURCED_IFACE_UNKNOWN) ?
			RESOURCED_IFACE_ALL : quota->iftype;

	quota->snd_warning_threshold = _evaluate_warning_threshold(
		quota->snd_quota, quota->time_period,
		quota->snd_warning_threshold);
	quota->rcv_warning_threshold = _evaluate_warning_threshold(
		quota->rcv_quota, quota->time_period,
		quota->rcv_warning_threshold);

return ret;
}

static dbus_bool_t deserialize_remove_quota(
	DBusMessage *msg, char **appid,
	resourced_iface_type *iftype, resourced_roaming_type *roaming)
{
	DBusError err;
	dbus_error_init(&err);

	int ret = dbus_message_get_args(
		msg, &err,
		DBUS_TYPE_STRING, appid,
		DBUS_TYPE_INT32, iftype,
		DBUS_TYPE_INT32, roaming,
		DBUS_TYPE_INVALID);
	if (ret == FALSE) {
		_E("Can't deserialize remove quota message! [%s:%s]\n",
		err.name, err.message);
	}

	dbus_error_free(&err);

	return ret;
}

static DBusMessage *edbus_join_net_stat(E_DBus_Object *obj, DBusMessage *msg)
{
	char *app_id = NULL;
	int pid = 0;
	resourced_ret_c ret = RESOURCED_ERROR_NONE;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusError err;

	dbus_error_init(&err);

	if (dbus_message_is_method_call(msg, RESOURCED_INTERFACE_NETWORK,
				RESOURCED_NETWORK_JOIN_NET_STAT) == 0) {
		ret = RESOURCED_ERROR_INVALID_PARAMETER;
		goto join_net_out;
	}

	ret = dbus_message_get_args(
		msg, &err,
		DBUS_TYPE_STRING, &app_id,
		DBUS_TYPE_INT32, &pid,
		DBUS_TYPE_INVALID);
	if (ret == FALSE) {
		_E("Can't deserialize join netstat message! [%s:%s]\n",
		err.name, err.message);
		ret = RESOURCED_ERROR_INVALID_PARAMETER;
		goto join_net_out;
	}

	ret = join_net_cls(app_id, pid);

join_net_out:
	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);

	dbus_error_free(&err);
	return reply;
}

static int init_datausage_quota_remove(sqlite3 *db)
{
	int rc;

	if (datausage_quota_remove)
		return SQLITE_OK;

	 rc = sqlite3_prepare_v2(db, REMOVE_QUOTA, -1,
			&datausage_quota_remove, NULL);
	if (rc != SQLITE_OK) {
		_E("can not prepare datausage_quota_remove");
		datausage_quota_remove = NULL;
		sqlite3_finalize(datausage_quota_remove);
		return rc;
	}

	return rc;
}

static resourced_ret_c remove_quota(const char *app_id,
	resourced_iface_type iftype, resourced_roaming_type roaming)
{
	resourced_ret_c error_code = RESOURCED_ERROR_NONE;
	libresourced_db_initialize_once();

	if (init_datausage_quota_remove(resourced_get_database()) != SQLITE_OK) {
		_D("Failed to initialize data usage quota statements: %s\n",
		   sqlite3_errmsg(resourced_get_database()));
		return RESOURCED_ERROR_DB_FAILED;
	}

	if (sqlite3_bind_text(datausage_quota_remove, 1, app_id, -1, SQLITE_STATIC) !=
	    SQLITE_OK) {
		_SE("Can not bind app_id: %s for preparing statement",
		   app_id);
		error_code =  RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int(datausage_quota_remove, 2, iftype)
	    != SQLITE_OK) {
		_E("Can not bind iftype:%d for preparing statement",
			iftype);
		error_code =  RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int(datausage_quota_remove, 3, roaming)
	    != SQLITE_OK) {
		_E("Can not bind iftype:%d for preparing statement",
			roaming);
		error_code =  RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_step(datausage_quota_remove) != SQLITE_DONE) {
		_E("failed to remove record");
		error_code =  RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	restriction_set_status(RESTRICTION_STATE_UNSET);

	_SD("quota for app %s removed", app_id);

out:
	sqlite3_reset(datausage_quota_remove);
	return error_code;
}

static DBusMessage *edbus_remove_quota(E_DBus_Object *obj, DBusMessage *msg)
{
	char *app_id = NULL;
	resourced_iface_type iftype;
	resourced_ret_c ret = RESOURCED_ERROR_NONE;
	resourced_roaming_type roaming;
	DBusMessage *reply;
	DBusMessageIter iter;

	if (dbus_message_is_method_call(msg, RESOURCED_INTERFACE_NETWORK,
				RESOURCED_NETWORK_REMOVE_QUOTA) == 0) {
		ret = RESOURCED_ERROR_INVALID_PARAMETER;
		goto remove_out;
	}

	if (deserialize_remove_quota(msg, &app_id, &iftype, &roaming)
			     == FALSE) {
		ret = RESOURCED_ERROR_INVALID_PARAMETER;
		goto remove_out;
	}

	ret = remove_quota(app_id, iftype, roaming);
	update_quota_state(app_id, iftype, 0, 0, roaming);

remove_out:
	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);
	return reply;
}

static int init_datausage_quota_insert(sqlite3 *db)
{
	int rc;

	if (datausage_quota_insert)
		return SQLITE_OK;

	rc = sqlite3_prepare_v2(db, INSERT_QUERY,
				    -1, &datausage_quota_insert, NULL);

	if (rc != SQLITE_OK) {
		_E("can not prepare datausage_quota_insert");
		datausage_quota_insert = NULL;
		sqlite3_finalize(datausage_quota_insert);
	}

	return rc;
}

static resourced_ret_c store_quota(const char *app_id,
	const struct serialization_quota *quota)
{
	resourced_ret_c error_code = RESOURCED_ERROR_NONE;

	libresourced_db_initialize_once();

	if (init_datausage_quota_insert(resourced_get_database()) != SQLITE_OK) {
		_D("Failed to initialize data usage quota statements: %s\n",
		   sqlite3_errmsg(resourced_get_database()));
		return RESOURCED_ERROR_DB_FAILED;
	}

	if (sqlite3_bind_text(datausage_quota_insert, 1, app_id, -1,
		SQLITE_STATIC) != SQLITE_OK) {
		_SE("Can not bind app_id: %s for prepearing statement: %s",
			app_id, sqlite3_errmsg(resourced_get_database()));
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int64(datausage_quota_insert, 2,
		quota->snd_quota) != SQLITE_OK) {
		_E("Can not bind snd_quota: %lld for preparing statement",
			quota->snd_quota);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int64(datausage_quota_insert, 3,
		quota->rcv_quota) != SQLITE_OK) {
		_E("Can not bind rcv_quota: %lld for preparing statement",
			quota->rcv_quota);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int64(datausage_quota_insert, 4,
		quota->snd_warning_threshold) != SQLITE_OK) {
		_E("Can not bind snd_warning_threshold: %lld for preparing statement",
			quota->snd_warning_threshold);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int64(datausage_quota_insert, 5,
		quota->rcv_warning_threshold) != SQLITE_OK) {
		_E("Can not bind rcv_warning_threshold: %lld for preparing statement",
			quota->rcv_warning_threshold);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int64(datausage_quota_insert, 6,
		quota->time_period) != SQLITE_OK) {
		_E("Can not bind time_period: %d for preparing statement",
			quota->time_period);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int(datausage_quota_insert, 7,
		quota->start_time) != SQLITE_OK) {
		_E("Can not bind start_time: %d for preparing statement",
			quota->start_time);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int(datausage_quota_insert, 8,
		quota->iftype) != SQLITE_OK) {
		_E("Can not bind iftype: %d for preparing statement",
			quota->iftype);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int(datausage_quota_insert, 9,
		quota->roaming_type) != SQLITE_OK) {
		_E("Can not bind start_time: %d for preparing statement",
			quota->start_time);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_step(datausage_quota_insert) != SQLITE_DONE) {
		_E("Failed to record quota %s.",
			sqlite3_errmsg(resourced_get_database()));
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}
out:
	sqlite3_reset(datausage_quota_insert);
	return error_code;
}

static DBusMessage *edbus_create_quota(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter iter;

	char *app_id = NULL;
	struct serialization_quota quota;
	struct shared_modules_data *m_data = get_shared_modules_data();
	struct counter_arg *carg;
	resourced_ret_c ret = RESOURCED_ERROR_NONE;

	if (!m_data || !m_data->carg) {
		_E("Not enough local parameters: modules data %p, counter arg %p",
			m_data, m_data->carg);
		ret = RESOURCED_ERROR_INVALID_PARAMETER;
		goto update_out;
	}

	carg = m_data->carg;

	if (dbus_message_is_method_call(msg, RESOURCED_INTERFACE_NETWORK,
					RESOURCED_NETWORK_CREATE_QUOTA) == 0) {
		_E("Invalid DBUS argument");
		ret = RESOURCED_ERROR_INVALID_PARAMETER;
		goto update_out;
	}

	deserialize_quota(msg, &app_id, &quota);
	ret = store_quota(app_id, &quota);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Can't store quota!");
		goto update_out;
	}

	update_quota_state(app_id, quota.iftype, quota.start_time,
		quota.time_period, quota.roaming_type);

	ret_value_msg_if(!carg->opts,
		dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS,
				      "Counter args is not provided"),
			 "Please provide valid argument!");

	carg->opts->is_update_quota = 1;
	reschedule_count_timer(carg, 0);
	_SD("Datausage quota changed");

update_out:
	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);
	return reply;
}

struct get_stats_context {
	DBusMessage *reply;
	DBusMessage *msg;
	int info_count;
	GSList *infos;
	DBusMessageIter iter;
};

static resourced_cb_ret answer_get_stat(const data_usage_info *info,
					       void *user_data)
{
	struct get_stats_context *ctx = (struct get_stats_context *)user_data;
	data_usage_info *insert = (data_usage_info *)malloc(sizeof(data_usage_info));

	ret_value_msg_if(insert == NULL, RESOURCED_CANCEL, "Can't allocate memory!");
	memcpy(insert, info, sizeof(data_usage_info));
	if (info->app_id) {
		int app_id_len = strlen(info->app_id) + 1;
		insert->app_id = (char *)malloc(app_id_len);
		if (!insert->app_id) {
			free(insert);
			_E("Malloc of answer_get_stat failed\n");
			return RESOURCED_CANCEL;
		}

		strncpy((char *)insert->app_id, info->app_id, app_id_len);
	}
	ctx->infos = g_slist_append(ctx->infos, insert);
	return RESOURCED_CONTINUE;
}

static void prepare_response(struct get_stats_context *ctx)
{
	GSList *iter;
	data_usage_info *info;
	DBusMessageIter arr;

	ctx->reply = dbus_message_new_method_return(ctx->msg);
	dbus_message_iter_init_append(ctx->reply, &ctx->iter);
	dbus_message_iter_open_container(&ctx->iter, DBUS_TYPE_ARRAY, "(siiiiiii)", &arr);

	gslist_for_each_item(iter, ctx->infos) {
		info = (data_usage_info *)iter->data;

		DBusMessageIter sub;

		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		if (info->app_id == NULL)
			dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING,
				&null_str);
		else
			dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING,
				&info->app_id);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &info->iftype);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &info->interval->from);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &info->interval->to);
		/* incoming bytes */
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT64, &info->foreground.cnt.incoming_bytes);
		/* outgoing bytes */
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT64, &info->foreground.cnt.outgoing_bytes);

		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &info->roaming);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &info->hw_net_protocol_type);

		dbus_message_iter_close_container(&arr, &sub);
	}

	dbus_message_iter_close_container(&ctx->iter, &arr);
	g_slist_free_full(ctx->infos, free);
}

static void deserialize_rule(DBusMessage *msg, data_usage_selection_rule *rule, char **app_id)
{
	DBusError err;
	dbus_error_init(&err);

	int ret = dbus_message_get_args(
		msg, &err,
		DBUS_TYPE_STRING, app_id,
		DBUS_TYPE_INT32, &rule->from,
		DBUS_TYPE_INT32, &rule->to,
		DBUS_TYPE_INT32, &rule->iftype,
		DBUS_TYPE_INT32, &rule->granularity,
		DBUS_TYPE_INVALID);

	if (ret == FALSE) {
		_E("Can't deserialize quota! [%s:%s]\n",
			err.name, err.message);
	}

	if (app_id && !strcmp(*app_id, null_str))
		*app_id = NULL;
	dbus_error_free(&err);
}

static DBusMessage *edbus_get_stats(E_DBus_Object *obj, DBusMessage *msg)
{
	data_usage_selection_rule rule;
	char *app_id = NULL;
	resourced_ret_c ret;
	struct get_stats_context ctx;
	ctx.infos = NULL;

	if (dbus_message_is_method_call(msg, RESOURCED_INTERFACE_NETWORK,
					RESOURCED_NETWORK_GET_STATS) == 0) {
		ret = RESOURCED_ERROR_INVALID_PARAMETER;
		goto update_out;
	}

	_SD("Datausage get stats");
	ctx.msg = msg;
	deserialize_rule(msg, &rule, &app_id);
	if (app_id)
		ret = data_usage_details_foreach(app_id, &rule, answer_get_stat,
			&ctx);
	else
		ret = data_usage_foreach(&rule, answer_get_stat, &ctx);

	prepare_response(&ctx);
	return ctx.reply;

update_out:
	ctx.reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(ctx.reply, &ctx.iter);
	dbus_message_iter_append_basic(&ctx.iter, DBUS_TYPE_INT32, &ret);
	return ctx.reply;
}

struct nl_family_params {
	struct genl *ans;
	struct counter_arg *carg;
};

typedef struct {
	struct nl_family_params params;
	void (*process)(struct nl_family_params *params);
} nl_serialization_command;

static inline char *_get_public_appid(const uint32_t classid)
{
	char *appid;

	/* following value for ALL is suitable for using in statistics
	   what's why it's not in get_app_id_by_classid */
	if (classid == RESOURCED_ALL_APP_CLASSID)
		return RESOURCED_ALL_APP;

	appid = get_app_id_by_classid(classid, true);
	return !appid ? UNKNOWN_APP : appid;
}

static bool need_flush_immediatelly(sig_atomic_t state)
{
	return state & RESOURCED_FORCIBLY_FLUSH_STATE ||
		state & RESOURCED_FORCIBLY_QUIT_STATE;
}

static Eina_Bool _store_and_free_result_cb(void *user_data)
{
	struct counter_arg *arg = (struct counter_arg *)user_data;

	ret_value_msg_if(!arg, ECORE_CALLBACK_CANCEL, "Please provide valid argument!");

	if (store_result(arg->result, need_flush_immediatelly(arg->opts->state)
			 ? 0 : arg->opts->flush_period)) {
		/*We still plan to use result outside, just
		remove and free elements */
		g_tree_ref(arg->result->tree);
		free_app_stat_tree(arg->result);
		if (arg->opts->state & RESOURCED_FORCIBLY_FLUSH_STATE) {
			arg->opts->state &= ~RESOURCED_FORCIBLY_FLUSH_STATE;
			if (broadcast_edbus_signal(
				    RESOURCED_PATH_NETWORK,
				    RESOURCED_INTERFACE_NETWORK,
				    RESOURCED_NETWORK_UPDATE_FINISH,
				    DBUS_TYPE_INVALID, NULL))
				_E("Failed to send DBUS message\n");
		}
	}

	arg->store_result_timer = NULL;
	return ECORE_CALLBACK_CANCEL;
}

static void _store_and_free_result(struct counter_arg *arg)
{
	if (!arg->store_result_timer)
		arg->store_result_timer = ecore_timer_add(STORE_DELAY_INTERVAL,
					   _store_and_free_result_cb, arg);
}

static void _process_network_counter(struct nl_family_params *params)
{
	resourced_ret_c ret;
	struct netlink_serialization_params ser_params = {
		.carg = params->carg,
		.ans = params->ans,
#ifdef CONFIG_DATAUSAGE_NFACCT
		.eval_attr = fill_counters,
		.post_eval_attr = post_fill_counters,
#endif
	};

	netlink_serialization_command *netlink =
		netlink_create_command(&ser_params);

	if (!netlink) {
		_E("Can not create command");
		return;
	}

	netlink->deserialize_answer(&(netlink->params));

	/* process only filled in/out or tethering traffic */
	if ((!g_tree_nnodes(params->carg->in_tree) ||
	     !g_tree_nnodes(params->carg->out_tree)) &&
	    params->carg->opts->state & RESOURCED_FORCIBLY_QUIT_STATE)
		return;

	pthread_rwlock_wrlock(&params->carg->result->guard);
	ret = prepare_application_stat(params->carg->in_tree,
			params->carg->out_tree, params->carg->result,
		params->carg->opts);
	pthread_rwlock_unlock(&params->carg->result->guard);

	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to prepare application statistics!");
		return;
	}
	ret = process_quota(params->carg->result, params->carg->opts);
	if (ret != 0) {
		_E("Failed to process quota!");
		return;
	}

	_store_and_free_result(params->carg);

	g_tree_ref(params->carg->out_tree);
	free_traffic_stat_tree(params->carg->out_tree);
	g_tree_ref(params->carg->in_tree);
	free_traffic_stat_tree(params->carg->in_tree);
}

#ifdef CONFIG_DATAUSAGE_NFACCT
static resourced_ret_c choose_netlink_process(struct genl *ans, nl_serialization_command *command,
	struct counter_arg *carg)
{
	command->process = _process_network_counter;
	return RESOURCED_ERROR_NONE;
}
#else

static void _process_restriction(struct nl_family_params *cmd)
{
	struct traffic_restriction restriction = {0,};
	uint8_t notification_type = RESTRICTION_NOTI_C_UNSPEC;
	char *app_id = NULL;
	resourced_iface_type iftype;
	resourced_restriction_info rst_info = {0,};
	resourced_ret_c ret;

	_D("Restriction notification");

	if (process_netlink_restriction_msg(cmd->ans, &restriction,
	    &notification_type) !=
	    RESOURCED_ERROR_NONE) {
		_E("Failed to process netlink restriction.");
		return;
	}

	app_id = _get_public_appid(restriction.sk_classid);
	iftype = get_iftype(restriction.ifindex);

	ret = get_restriction_info(app_id, iftype, &rst_info);
	ret_msg_if(ret != RESOURCED_ERROR_NONE,
		"Failed to get restriction info!");

	if (notification_type == RESTRICTION_NOTI_C_ACTIVE) {
		if (rst_info.quota_id != NONE_QUOTA_ID)
			send_restriction_notification(app_id);
		update_restriction_db(app_id, iftype, 0, 0,
				      RESOURCED_RESTRICTION_ACTIVATED,
		rst_info.quota_id, rst_info.roaming);
	} else if (notification_type == RESTRICTION_NOTI_C_WARNING) {
		/* nested if due error message correctness */
		if (rst_info.quota_id != NONE_QUOTA_ID)
			send_restriction_warn_notification(app_id);
	} else
		_E("Unkown restriction notification type");
}

static resourced_ret_c choose_netlink_process(struct genl *ans,
	nl_serialization_command *command, struct counter_arg *carg)
{
	int family = netlink_get_family(ans);

	if (family == carg->family_id_restriction)
		command->process = _process_restriction;
	else if (family == carg->family_id_stat)
		command->process = _process_network_counter;
	else {
		_E("General netlink family %d unsupported!", family);
		return RESOURCED_ERROR_NO_DATA;
	}
	return RESOURCED_ERROR_NONE;
}
#endif /* CONFIG_DATAUSAGE_NFACCT */

static nl_serialization_command *choose_handler(struct genl *ans,
	struct counter_arg *carg)
{
	static nl_serialization_command command;
	resourced_ret_c ret;

	if (!ans || !carg) {
		_E("Please provide valid pointer!");
		return NULL;
	}

	if (!command.params.carg)
		command.params.carg = carg;
	command.params.ans = ans;

	ret = choose_netlink_process(ans, &command, carg);
	ret_value_msg_if(ret != RESOURCED_ERROR_NONE, NULL,
		"Could not choose proper netlink process function! \n");

	return &command;
}

static Eina_Bool _answer_func_cb(void *user_data, Ecore_Fd_Handler *fd_handler)
{
	struct counter_arg *carg = (struct counter_arg *)user_data;
	struct genl ans;
	nl_serialization_command *netlink_handler = NULL;
	int ret;

	ret = read_netlink(carg->sock, &ans, sizeof(struct genl));
	if (ret == 0)
		goto out;
	carg->ans_len = ret;
	netlink_handler = choose_handler(&ans, carg);

	if (!netlink_handler)
		goto out;

	netlink_handler->process(&(netlink_handler->params));

out:
	return ECORE_CALLBACK_RENEW;
}

static const struct edbus_method edbus_methods[] = {
	{ RESOURCED_NETWORK_UPDATE, NULL, NULL, edbus_update_counters },
	{ RESOURCED_NETWORK_PROCESS_RESTRICTION, NULL, NULL,
	  edbus_process_restriction },
	{ RESOURCED_NETWORK_CREATE_QUOTA, NULL, NULL, edbus_create_quota },
	{ RESOURCED_NETWORK_REMOVE_QUOTA, NULL, NULL, edbus_remove_quota },
	{ RESOURCED_NETWORK_JOIN_NET_STAT, NULL, NULL, edbus_join_net_stat },
	{ RESOURCED_NETWORK_GET_STATS, "siiii", "a(siiiiiii)", edbus_get_stats },
};

#ifdef CONFIG_DATAUSAGE_NFACCT
int init_sock(struct counter_arg *carg)
{
	carg->sock = create_netlink(NETLINK_NETFILTER, 0);
	return carg->sock != 0 ? RESOURCED_ERROR_NONE :
		RESOURCED_ERROR_FAIL;
}
#else
int init_sock(struct counter_arg *carg)
{
	int error = RESOURCED_ERROR_NONE;
	carg->sock = create_netlink(NETLINK_GENERIC, 0);

	ret_value_msg_if(carg->sock < 0, RESOURCED_ERROR_FAIL,
		"Failed to create and bind netlink socket.");

	carg->family_id_stat = get_family_id(carg->sock,
		carg->pid, "TRAF_STAT");
	if (carg->family_id_stat == 0) {
		_E("Failed to get family id for TRAF_STAT.");
		error = RESOURCED_ERROR_FAIL;
		goto release_sock;
	}

	carg->family_id_restriction = get_family_id(carg->sock,
		carg->pid, "REST_NOTI");

	if (carg->family_id_restriction ==  0) {
		_E("Failed to get family id for REST_NOTI.");
		error = RESOURCED_ERROR_FAIL;
		goto release_sock;
	}
	/*thereafter we'll be able to receive message from server */
	send_start(carg->sock, carg->pid, carg->family_id_stat);

	return RESOURCED_ERROR_NONE;
release_sock:
	close(carg->sock);
	return error;
}
#endif /* CONFIG_DATAUSAGE_NFACCT */


int resourced_init_counter_func(struct counter_arg *carg)
{
	int error = 0;

	if (!carg) {
		_E("Please provide valid argument for counting routine.");
		error = RESOURCED_ERROR_INVALID_PARAMETER;
		return error;
	}

	error = init_sock(carg);
	ret_value_msg_if(error != RESOURCED_ERROR_NONE, RESOURCED_ERROR_FAIL,
			 "Couldn't init socket!");

	carg->result = create_app_stat_tree();
	carg->in_tree = create_traffic_stat_tree();
	carg->out_tree = create_traffic_stat_tree();
#ifdef CONFIG_DATAUSAGE_NFACCT
	carg->nf_cntrs = create_nfacct_tree();
#endif /* CONFIG_DATAUSAGE_NFACCT */

	init_iftype();

	error = edbus_add_methods(RESOURCED_PATH_NETWORK, edbus_methods,
			  ARRAY_SIZE(edbus_methods));

	if (error != RESOURCED_ERROR_NONE)
		_E("DBus method registration for %s is failed",
			RESOURCED_PATH_NETWORK);

	_counter_func_cb(carg);

	carg->ecore_timer = ecore_timer_add(carg->opts->update_period,
					   _counter_func_cb, carg);

	ret_value_msg_if(carg->ecore_timer == 0, RESOURCED_ERROR_FAIL,
			 "carg_timer is null, can't work! update period: %d",
			 carg->opts->update_period);

	carg->ecore_fd_handler = ecore_main_fd_handler_add(
		carg->sock, ECORE_FD_READ, _answer_func_cb, carg, NULL, NULL);
	_D("ecore_carg_handler = %p", carg->ecore_fd_handler);

	return error;
}

static void finalize_quota_insert(void)
{
	if (datausage_quota_insert) {
		sqlite3_finalize(datausage_quota_insert);
		datausage_quota_insert = NULL;
	}
}

static void finalize_quota_remove(void)
{
	if (datausage_quota_remove) {
		sqlite3_finalize(datausage_quota_remove);
		datausage_quota_remove = NULL;
	}
}

void resourced_finalize_counter_func(struct counter_arg *carg)
{
	ret_msg_if(carg == NULL, "Invalid counter argument\n");
	free_traffic_stat_tree(carg->out_tree);
	free_traffic_stat_tree(carg->in_tree);
	nulify_app_stat_tree(&carg->result);
	ecore_main_fd_handler_del(carg->ecore_fd_handler);
	ecore_timer_del(carg->ecore_timer);
	finalize_quota_insert();
	finalize_quota_remove();
}
