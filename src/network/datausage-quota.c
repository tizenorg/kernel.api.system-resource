/*
 * resourced
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file datausage-quota.c
 *
 * @desc Quota logic implementation
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <inttypes.h>
#include <sqlite3.h>
#include <string.h>
#include <time.h>
#include <vconf.h>

#include "const.h"
#include "const.h"
#include "data_usage.h"
#include "database.h"
#include "datausage-quota.h"
#include "edbus-handler.h"
#include "macro.h"
#include "trace.h"

static resourced_ret_c send_quota_message(const char *interface,
	const char *format_str,	char *params[])
{
	DBusError err;
	DBusMessage *msg;
	resourced_ret_c ret_val;
	int ret, i = 0;

	do {
		msg = dbus_method_sync(BUS_NAME, RESOURCED_PATH_NETWORK,
				       RESOURCED_INTERFACE_NETWORK,
				       interface,
				       format_str, params);
		if (msg)
			break;
		_E("Re-try to sync DBUS message, err_count : %d", i);
	} while (i++ < RETRY_MAX);

	if (!msg) {
		_E("Failed to sync DBUS message.");
		return RESOURCED_ERROR_FAIL;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &ret_val,
				    DBUS_TYPE_INVALID);

	if (ret == FALSE) {
		_E("no message : [%s:%s]\n", err.name, err.message);
		ret_val = RESOURCED_ERROR_FAIL;
	}

	dbus_message_unref(msg);
	dbus_error_free(&err);

	return ret_val;
}

static resourced_ret_c send_create_quota_message(const char *app_id,
	const data_usage_quota *quota)
{
	char *params[10];
	char snd_quota[MAX_DEC_SIZE(int64_t)], rcv_quota[MAX_DEC_SIZE(int64_t)];

	snprintf(snd_quota, sizeof(snd_quota), "%" PRId64 "", quota->snd_quota);
	snprintf(rcv_quota, sizeof(rcv_quota), "%" PRId64 "", quota->rcv_quota);

	serialize_params(params, ARRAY_SIZE(params), app_id, quota->time_period,
		snd_quota, rcv_quota, quota->snd_warning_threshold,
		quota->rcv_warning_threshold, quota->quota_type, quota->iftype,
		*quota->start_time, quota->roaming_type);
	return send_quota_message(RESOURCED_NETWORK_CREATE_QUOTA, "sdttdddddd",
		params);
}

static resourced_ret_c send_remove_quota_message(const char *app_id,
	const resourced_iface_type iftype,
	const resourced_roaming_type roaming_type)
{
	char *params[3];

	serialize_params(params, ARRAY_SIZE(params), app_id, iftype,
		roaming_type);
	return send_quota_message(RESOURCED_NETWORK_REMOVE_QUOTA, "sdd",
		params);
}

API resourced_ret_c remove_datausage_quota(
	const struct datausage_quota_reset_rule *rule)
{
	if (!rule || !rule->app_id)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	if (rule->iftype <= RESOURCED_IFACE_UNKNOWN ||
	    rule->iftype >= RESOURCED_IFACE_LAST_ELEM)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	if (rule->roaming < RESOURCED_ROAMING_UNKNOWN ||
	    rule->roaming >= RESOURCED_ROAMING_LAST_ELEM)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	return send_remove_quota_message(rule->app_id, rule->iftype,
	         rule->roaming);
}

API resourced_ret_c remove_datausage_quota_by_iftype(
	const char *app_id, const resourced_iface_type iftype)
{
	struct datausage_quota_reset_rule rule = {
		.app_id = app_id,
		.iftype = iftype,
		.roaming = RESOURCED_ROAMING_UNKNOWN,
	};

	return remove_datausage_quota(&rule);
}

static int _is_valid_datausage_quota_params(const char *app_id,
					const data_usage_quota *quota)
{
	if (!app_id) {
		_SE("Empty appid! Please provide valid appid.");
		return 0;
	}

	if (!quota) {
		_E("Empty quota! Please provide valid quota.");
		return 0;
	}

	if (quota->iftype >= RESOURCED_IFACE_LAST_ELEM) {
		_E("Not valid value for iftype! See resourced_iface_type!");
		return 0;
	}

	return 1;
}

static time_t _get_datausage_start_time(const time_t *quota_start_time)
{
	return quota_start_time ? *quota_start_time : time(0);
}

API resourced_ret_c set_datausage_quota(const char *app_id,
					const data_usage_quota *quota)
{
	/* support old behaviour undefined iftype mean all iftype */
	time_t start_time = 0;
	data_usage_quota quota_to_send;

	if (!_is_valid_datausage_quota_params(app_id, quota))
		return RESOURCED_ERROR_INVALID_PARAMETER;

	quota_to_send = *quota;
	start_time = _get_datausage_start_time(quota->start_time);
	quota_to_send.start_time = &start_time;

	_SD("quota for app %s set", app_id);
	_SD("===============================");
	_SD("quota.start_time = %s", ctime(quota->start_time));
	_SD("quota.time_period = %d", quota->time_period);
	_SD("quota.snd_quota = %lld", quota->snd_quota);
	_SD("quota.rcv_quota = %lld", quota->rcv_quota);
	_SD("quota.quota_type = %d", quota->quota_type);
	_SD("quota.iftype = %d", quota->iftype);
	_SD("===============================");

	return send_create_quota_message(app_id, &quota_to_send);
}
