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
 * @file restriction.c
 * @desc Implementation of the network restriction
 */

#include <sqlite3.h>
#include <resourced.h>
#include <data_usage.h>
#include <rd-network.h>

#include "cgroup.h"		/*get_classid_by_pkg_name */
#include "const.h"
#include "database.h"
#include "datausage-restriction.h"
#include "edbus-handler.h"
#include "macro.h"
#include "netlink-restriction.h"
#include "restriction-helper.h"
#include "tethering-restriction.h"
#include "trace.h"

#define SELECT_RESTRICTIONS "SELECT binpath, rcv_limit, " \
	"send_limit, iftype, rst_state, quota_id, roaming FROM restrictions"

#define SELECT_RESTRICTION_STATE "SELECT rst_state FROM restrictions " \
	"WHERE binpath = ? AND iftype = ?"

static sqlite3_stmt *datausage_restriction_select;
static sqlite3_stmt *restriction_get_state_stmt;

static int init_datausage_restriction(sqlite3 *db)
{
	int rc;
	if (datausage_restriction_select)
		return SQLITE_OK;

	rc = sqlite3_prepare_v2(db, SELECT_RESTRICTIONS, -1 ,
				    &datausage_restriction_select, NULL);
	if (rc != SQLITE_OK) {
		_E("can not prepare datausage_restriction_select\n");
		datausage_restriction_select = NULL;
		return rc;
	}
	return rc;
}

static void serialize_restriction(const char *appid,
				  const enum traffic_restriction_type rst_type,
				  const resourced_net_restrictions *rst,
				  char *params[])
{
	params[0] = (char *)appid;
	params[1] = (char *)rst_type;
	params[2] = (char *)rst->rs_type;
	params[3] = (char *)rst->iftype;
	params[4] = (char *)rst->send_limit;
	params[5] = (char *)rst->rcv_limit;
	params[6] = (char *)rst->snd_warning_limit;
	params[7] = (char *)rst->rcv_warning_limit;
	params[8] = (char *)rst->roaming;
}

static resourced_ret_c process_restriction(
	const char *app_id, const resourced_net_restrictions *rst,
	const enum traffic_restriction_type rst_type)
{
	DBusError err;
	DBusMessage *msg;
	char *params[9];
	int i = 0, ret;
	resourced_ret_c ret_val;

	ret = check_restriction_arguments(app_id, rst, rst_type);
	ret_value_msg_if(ret != RESOURCED_ERROR_NONE,
			 RESOURCED_ERROR_INVALID_PARAMETER,
			 "Invalid restriction arguments\n");

	serialize_restriction(app_id, rst_type, rst, params);

	do {
		msg = dbus_method_sync(BUS_NAME, RESOURCED_PATH_NETWORK,
				       RESOURCED_INTERFACE_NETWORK,
				       RESOURCED_NETWORK_PROCESS_RESTRICTION,
				       "sdddddddd", params);
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

API resourced_ret_c restrictions_foreach(
	resourced_restriction_cb restriction_cb, void *user_data)
{
	resourced_restriction_info data;
	int rc;
	resourced_ret_c error_code = NETWORK_ERROR_NONE;

	libresourced_db_initialize_once();
	if (init_datausage_restriction(resourced_get_database()) != SQLITE_OK) {
		_D("Failed to initialize data usage restriction statement: %s\n",
		   sqlite3_errmsg(resourced_get_database()));
		return RESOURCED_ERROR_DB_FAILED;
	}

	do {
		rc = sqlite3_step(datausage_restriction_select);
		switch (rc) {
		case SQLITE_DONE:
			break;
		case SQLITE_ROW:
			data.app_id = (char *)sqlite3_column_text(
				datausage_restriction_select, 0);
			data.iftype = (resourced_iface_type)sqlite3_column_int(
				datausage_restriction_select, 3);
			data.rcv_limit = sqlite3_column_int(
				datausage_restriction_select, 1);
			data.send_limit = sqlite3_column_int(
				datausage_restriction_select, 2);
			data.rst_state =
				(resourced_restriction_state)sqlite3_column_int(
					datausage_restriction_select, 4);
			data.quota_id = sqlite3_column_int(
				datausage_restriction_select, 5);
			data.roaming = sqlite3_column_int(
				datausage_restriction_select, 6);

			if (restriction_cb(&data, user_data) == RESOURCED_CANCEL)
				rc = SQLITE_DONE;
			break;
		case SQLITE_ERROR:
		default:
			_E("Failed to enumerate restrictions: %s\n",
				sqlite3_errmsg(resourced_get_database()));

			error_code = RESOURCED_ERROR_DB_FAILED;
		}
	} while (rc == SQLITE_ROW);

	sqlite3_reset(datausage_restriction_select);
	return error_code;
}

API resourced_ret_c set_net_restriction(const char *app_id,
					const resourced_net_restrictions *rst)
{
	return process_restriction(app_id, rst, RST_SET);
}

API resourced_ret_c remove_restriction(const char *app_id)
{
	return remove_restriction_by_iftype(app_id, RESOURCED_IFACE_ALL);
}

API resourced_ret_c remove_restriction_by_iftype(
	const char *app_id, const resourced_iface_type iftype)
{
	resourced_net_restrictions rst = { 0 };

	rst.iftype = iftype;
	return process_restriction(app_id, &rst, RST_UNSET);
}

API resourced_ret_c exclude_restriction(const char *app_id)
{
	return exclude_restriction_by_iftype(app_id, RESOURCED_IFACE_ALL);
}

API resourced_ret_c exclude_restriction_by_iftype(
	const char *app_id, const resourced_iface_type iftype)
{
	resourced_net_restrictions rst = { 0 };

	rst.iftype = iftype;
	return process_restriction(app_id, &rst, RST_EXCLUDE);
}

API resourced_ret_c set_net_exclusion(const char *app_id,
			const resourced_net_restrictions *rst)
{
	return process_restriction(app_id, rst, RST_EXCLUDE);
}

void finalize_datausage_restriction(void)
{
	if (datausage_restriction_select) {
		sqlite3_finalize(datausage_restriction_select);
		datausage_restriction_select = NULL;
	}
}

static int init_get_rst_statement(sqlite3* db)
{
	int rc;

	rc = sqlite3_prepare_v2(db, SELECT_RESTRICTION_STATE, -1 ,
				    &restriction_get_state_stmt, NULL);
	if (rc != SQLITE_OK) {
		_E("can not prepare restriction_get_state: %d\n", rc);
		restriction_get_state_stmt = NULL;
		return NETWORK_ERROR_DB_FAILED;
	}
	return rc;
}

API resourced_ret_c get_restriction_state(const char *pkg_id,
	resourced_iface_type iftype, resourced_restriction_state *state)
{

	int error_code = RESOURCED_ERROR_NONE;
	sqlite3 *db;

	if (state == NULL) {
		_E("Please provide valid argument!");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	db = resourced_get_database();

	if (db == NULL) {
		_E("Can't get database.");
		return RESOURCED_ERROR_DB_FAILED;
	}

	execute_once {
		error_code = init_get_rst_statement(db);
		if (error_code != RESOURCED_ERROR_NONE)
			return error_code;
	}

	*state = RESOURCED_RESTRICTION_UNKNOWN;
	sqlite3_reset(restriction_get_state_stmt);
	DB_ACTION(sqlite3_bind_text(restriction_get_state_stmt, 1, pkg_id, -1,
		SQLITE_STATIC));
	DB_ACTION(sqlite3_bind_int(restriction_get_state_stmt, 2, iftype));

	error_code = sqlite3_step(restriction_get_state_stmt);
	switch (error_code) {
	case SQLITE_DONE:
		break;
	case SQLITE_ROW:
		*state = (network_restriction_state)sqlite3_column_int(
			restriction_get_state_stmt, 0);
		break;
	case SQLITE_ERROR:
	default:
		_E("Can't perform sql query: %s \n%s",
			SELECT_RESTRICTION_STATE, sqlite3_errmsg(db));
		error_code = RESOURCED_ERROR_DB_FAILED;
	}

handle_error:

	sqlite3_reset(restriction_get_state_stmt);
	return error_code;
}

