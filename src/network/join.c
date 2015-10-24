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

/**
 * @file join.c
 * @desc Implement Performance API. Joining performance control.
 *    Entity for creation cgroup
 */

#include <resourced.h>

#include "const.h"
#include "edbus-handler.h"
#include "macro.h"
#include "trace.h"

static resourced_ret_c send_join_message(const char *interface,
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

API resourced_ret_c join_app_performance(const char *app_id, const pid_t pid)
{
	char *params[2];

	if (!app_id)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	serialize_params(params, ARRAY_SIZE(params), app_id, pid);

	return send_join_message(RESOURCED_NETWORK_JOIN_NET_STAT, "sd", params);
}
