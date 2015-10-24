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
 * @file notification_mobile.c
 *
 * @desc Notification specific functions
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <resourced.h>

#include "edbus-handler.h"
#include "notification.h"
#include "trace.h"
#include "macro.h"
#include "telephony.h"
#include "datausage-vconf-common.h"

#define RESTRICTION_ACTIVE  "RestrictionActive"
#define RESTRICTION_WARNING "RestrictionWarning"
#define B_TO_MB    (1024 * 1024)

static int warning_noti_id = 0;
static int disable_noti_id = 0;

static int *get_noti_id(int type)
{
	if (type == WARNING_NOTI)
		return &warning_noti_id;
	else if (type == DISABLE_NOTI)
		return &disable_noti_id;
	else
		_E("No matched noti type: %d", type);
	return NULL;
}

static int call_datausage_noti(const char *method_name, char *sig, char *pa[])
{
	DBusError err;
	DBusMessage *msg;
	int ret, ret_val;
	int i = 0;

	do {
		msg = dbus_method_sync(SYSTEM_POPUP_BUS_NAME, SYSTEM_POPUP_PATH_DATAUSAGE, SYSTEM_POPUP_IFACE_DATAUSAGE, method_name, sig, pa);
		if (msg)
			break;
		_E("Re-try to sync DBUS message, err_count : %d", i);
	} while (i++ < RETRY_MAX);

	if (!msg) {
		_E("Failed to sync DBUS message.");
		return -EBADMSG;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &ret_val, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("no message : [%s:%s]\n", err.name, err.message);
		ret_val = -EBADMSG;
	}
	dbus_message_unref(msg);
	dbus_error_free(&err);

	return ret_val;
}

static int clear_datausage_noti(int *id, const char *method_name)
{
	char buf[MAX_DEC_SIZE(int)];
	char *pa[1];
	int ret;

	ret_value_msg_if (!id || !method_name, -EINVAL, "Invalid param");

	snprintf(buf, sizeof(buf), "%d", *id);

	pa[0] = buf;
	ret = call_datausage_noti(method_name, "i", pa);
	if(ret != 0) {
		_E("clear noti id : %d", *id);
		*id = 0;
		return ret;
	}

	return 0;
}

void check_and_clear_all_noti(void)
{
	int *warning_id;
	int *disable_id;

	/* remove warning noti. */
	warning_id = get_noti_id(WARNING_NOTI);
	if (warning_id)
		clear_datausage_noti(warning_id, WARNING_NOTI_OFF);

	/* remove disable noti. */
	disable_id = get_noti_id(DISABLE_NOTI);
	if (disable_id) {
		clear_datausage_noti(disable_id, DISABLE_NOTI_OFF);
		restriction_set_status(RESTRICTION_STATE_UNSET);
	} else
		_D("No disable noti. to remove");
}

static int show_restriction_noti(const char *method_name)
{
	ret_value_msg_if (!method_name, -EINVAL, "Invalid param");

	return call_datausage_noti(method_name, NULL, NULL);
}

static int show_restriction_popup(const char *value, data_usage_quota *du_quota)
{
	char buf[MAX_DEC_SIZE(int)];
	char str_val[32];
	char *pa[4];
	int ret, retval, quota_limit = -1;

	ret_value_msg_if(!value || !du_quota, -EINVAL, "Invalid param");

	if (restriction_check_limit_status(&retval) < 0)
		_E("Failed to check limit status");

	if (!retval) {
		_E("data usage limit is not set");
		return RESOURCED_ERROR_FAIL;
	}

	quota_limit = (int) du_quota->snd_quota / B_TO_MB;

	ret_value_msg_if(quota_limit <= 0, RESOURCED_ERROR_FAIL, "quota_limit is invalid: %d\n", quota_limit);

	snprintf(str_val, sizeof(str_val), "%s", value);
	snprintf(buf, sizeof(buf), "%d", quota_limit);

	pa[0] = POPUP_KEY;
	pa[1] = str_val;
	pa[2] = POPUP_KEY_LIMIT;
	pa[3] = buf;

	ret = dbus_method_async(SYSTEM_POPUP_BUS_NAME, SYSTEM_POPUP_PATH_DATAUSAGE, SYSTEM_POPUP_IFACE_DATAUSAGE, METHOD_CALL_POPUP, "ssss", pa);
	if (ret < 0)
		_E("no message : failed to setting %d", ret);
	return ret;
}

void send_restriction_notification(const char *appid, data_usage_quota *du_quota)
{
	if (broadcast_edbus_signal(RESOURCED_PATH_NETWORK,
	                           RESOURCED_INTERFACE_NETWORK,
	                           RESTRICTION_ACTIVE,
	                           DBUS_TYPE_STRING,
	                           (void *)(&appid)) != RESOURCED_ERROR_NONE) {
		_E("Failed to send DBUS message.");
	}

	restriction_set_status(RESTRICTION_STATE_SET);

	_I("Show a network disabled popup & noti.");

	if (warning_noti_id)
		clear_datausage_noti(&warning_noti_id, WARNING_NOTI_OFF);

	show_restriction_popup(POPUP_VALUE_DISABLED, du_quota);
	disable_noti_id = show_restriction_noti(DISABLE_NOTI_ON);
}

void send_restriction_warn_notification(const char *appid, data_usage_quota *du_quota)
{
	if (broadcast_edbus_signal(RESOURCED_PATH_NETWORK,
	                           RESOURCED_INTERFACE_NETWORK,
	                           RESTRICTION_WARNING,
	                           DBUS_TYPE_STRING,
	                           (void *)(&appid)) != RESOURCED_ERROR_NONE) {
		_E("Failed to send DBUS message.");
	}

	_I("Show a network warning notification");

	warning_noti_id = show_restriction_noti(WARNING_NOTI_ON);
}
