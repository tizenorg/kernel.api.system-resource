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
 * @file update.c
 *
 * @desc Implementation of API network statistics update
 *
 */


#include "resourced.h"

#include "const.h"
#include "edbus-handler.h"
#include "macro.h"
#include "trace.h"

static E_DBus_Signal_Handler *handler;
static E_DBus_Connection *edbus_conn;

static dbus_bool_t dbus_call_method(const char *dest, const char *path,
				     const char *interface, const char *method)
{
	DBusConnection *conn;
	DBusMessage *msg;
	dbus_bool_t ret;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn) {
		_E("dbus_bus_get failed\n");
		return FALSE;
	}

	msg = dbus_message_new_method_call(dest, path, interface, method);
	if (!msg) {
		_E("Create dbus message failed\n");
		return FALSE;
	}

	ret = dbus_connection_send(conn, msg, NULL);
	dbus_connection_flush(conn);

	dbus_message_unref(msg);
	dbus_connection_unref(conn);
	return ret;
}

API resourced_ret_c resourced_update_statistics(void)
{
	dbus_bool_t ret = dbus_call_method(BUS_NAME,
					    RESOURCED_PATH_NETWORK,
					    RESOURCED_INTERFACE_NETWORK,
					    RESOURCED_NETWORK_UPDATE);
	if (ret == FALSE) {
		_D("Error resourced update statistics\n");
		return RESOURCED_ERROR_FAIL;
	}

	return RESOURCED_ERROR_NONE;
}

struct update_context {
	void *user_data;
	network_update_cb cb;
};

static void network_update_dbus_handler(void *user_data, DBusMessage *msg)
{
	struct update_context *context;
	struct network_update_info info;

	ret_msg_if(user_data == NULL,
		"Not valid user data");
	context = user_data;
	ret_msg_if(context->cb == NULL,
		"Not valid user data");

	if (context->cb(&info, context->user_data) == NETWORK_CANCEL) {
		network_unregister_update_cb();
	}
}

API network_error_e network_register_update_cb(network_update_cb update_cb,
	void *user_data)
{
	static int edbus_init_val;
	static struct update_context context;

	ret_value_msg_if(update_cb == NULL, NETWORK_ERROR_INVALID_PARAMETER,
		"Please provide valid callback argument!");

	ret_value_msg_if(handler != NULL, NETWORK_ERROR_INVALID_PARAMETER,
		"Only one callback is supported!");

	context.user_data = user_data;
	context.cb = update_cb;

	edbus_init_val = e_dbus_init();
	ret_value_msg_if(edbus_init_val == 0,
		 NETWORK_ERROR_FAIL, "Fail to initialize dbus!");

	edbus_conn = e_dbus_bus_get(DBUS_BUS_SYSTEM);
	if (edbus_conn == NULL)
		goto dbus_release;

	handler = e_dbus_signal_handler_add(edbus_conn, NULL,
		RESOURCED_PATH_NETWORK,
		RESOURCED_INTERFACE_NETWORK,
		RESOURCED_NETWORK_UPDATE_FINISH,
		network_update_dbus_handler, &context);

	if (handler == NULL)
		goto dbus_close;

	return NETWORK_ERROR_NONE;
dbus_close:
	e_dbus_connection_close(edbus_conn);

dbus_release:
	e_dbus_shutdown();
	return NETWORK_ERROR_FAIL;
}

API void network_unregister_update_cb(void)
{
	e_dbus_signal_handler_del(edbus_conn, handler);
	e_dbus_connection_close(edbus_conn);
	e_dbus_shutdown();

	handler = NULL;
	edbus_conn = NULL;
}

