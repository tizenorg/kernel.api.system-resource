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
 * @file notification_wearable.c
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

#define RESTRICTION_ACTIVE     "RestrictionActive"
#define RESTRICTION_WARNING    "RestrictionWarning"

#define NOTI_KEY               "_SYSPOPUP_CONTENT_"
#define NOTI_KEY_LIMIT         "_DATAUSAGE_LIMIT_"
#define NOTI_VALUE_DISABLED    "datausage_disabled"
#define NOTI_VALUE_WARNING     "datausage_warning"
#define METHOD_CALL_POPUP      "DatausagePopupLaunch"

void check_and_clear_all_noti(void)
{

}

static int show_restriction_popup(const char *value, data_usage_quota *du_quota)
{
	char buf[MAX_DEC_SIZE(int)];
	char str_val[32];
	char *pa[4];
	int ret, retval, quota_limit = -1;

	if (restriction_check_limit_status(&retval) < 0)
		_E("Failed to check limit status");

	if (!retval) {
		_E("data usage limit is not set");
		return RESOURCED_ERROR_FAIL;
	}

	if (quota_limit <= 0) {
		_D("quota_limit is invalid\n");
		return RESOURCED_ERROR_FAIL;
	}

	snprintf(str_val, sizeof(str_val), "%s", value);
	snprintf(buf, sizeof(buf), "%d", quota_limit);

	pa[0] = NOTI_KEY;
	pa[1] = str_val;
	pa[2] = NOTI_KEY_LIMIT;
	pa[3] = buf;

	ret = dbus_method_async(SYSTEM_POPUP_BUS_NAME, SYSTEM_POPUP_PATH_WATCHDOG, SYSTEM_POPUP_IFACE_WATCHDOG, METHOD_CALL_POPUP, "ssss", pa);
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

	_I("Show a network disabled popup");
	show_restriction_popup(NOTI_VALUE_DISABLED, du_quota);
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

	_I("Show a network warning popup");
	show_restriction_popup(NOTI_VALUE_WARNING, du_quota);
}

