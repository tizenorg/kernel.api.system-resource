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
 * @file set-restriction.c
 * @desc Implementation of the set network restriction body
 */

#include <sqlite3.h>
#include <stdbool.h>
#include <resourced.h>

#include "const.h"
#include "database.h"
#include "macro.h"
#include "module-data.h"
#include "net-cls-cgroup.h"
#include "netlink-restriction.h"
#include "init.h"
#include "restriction-helper.h"
#include "datausage-restriction.h"
#include "roaming.h"
#include "storage.h"
#include "trace.h"
#include "tethering-restriction.h"

#define SET_NET_RESTRICTIONS "REPLACE INTO restrictions "     \
	"(binpath, rcv_limit, send_limit, iftype, rst_state, "\
	" quota_id, roaming) " \
	"VALUES (?, ?, ?, ?, ?, ?, ?)"

#define GET_NET_RESTRICTION "SELECT rcv_limit, send_limit, " \
	" rst_state, quota_id FROM restrictions " \
	"WHERE binpath = ? AND iftype = ?"

#define RESET_RESTRICTIONS "DELETE FROM restrictions "	\
	"WHERE binpath=? AND iftype=?"

static sqlite3_stmt *update_rst_stm;
static sqlite3_stmt *reset_rst_stm;

static resourced_ret_c init_reset_rst(void)
{
	resourced_ret_c error_code = RESOURCED_ERROR_NONE;
	if (reset_rst_stm)
		return error_code;

	DB_ACTION(sqlite3_prepare_v2
		  (resourced_get_database(), RESET_RESTRICTIONS, -1,
		&reset_rst_stm, NULL));

	return error_code;

handle_error:
	_E("Failed to initialize %s", RESET_RESTRICTIONS);
	return error_code;
}

static resourced_ret_c reset_restriction_db(const char *app_id,
					    const resourced_iface_type iftype)
{
	resourced_ret_c error_code = init_reset_rst();

	ret_value_if(error_code != RESOURCED_ERROR_NONE, error_code);

	DB_ACTION(sqlite3_bind_text(reset_rst_stm, 1, app_id, -1, SQLITE_TRANSIENT));
	DB_ACTION(sqlite3_bind_int(reset_rst_stm, 2, iftype));

	if (sqlite3_step(reset_rst_stm) != SQLITE_DONE)
		error_code = RESOURCED_ERROR_DB_FAILED;

handle_error:

	sqlite3_reset(reset_rst_stm);
	if (error_code == RESOURCED_ERROR_DB_FAILED)
		_E("Failed to remove restrictions by network interface %s\n",
		   sqlite3_errmsg(resourced_get_database()));

	return error_code;
}

static resourced_ret_c init_update_rest_stmt(void)
{
	resourced_ret_c error_code = RESOURCED_ERROR_NONE;
	if (update_rst_stm)
		return error_code;

	DB_ACTION(sqlite3_prepare_v2
	  (resourced_get_database(), SET_NET_RESTRICTIONS, -1,
		&update_rst_stm, NULL));
	return error_code;

handle_error:
	_E("Failed to initialize %s", SET_NET_RESTRICTIONS);
	return error_code;
}

resourced_ret_c update_restriction_db(
	const char *app_id, const resourced_iface_type iftype,
	const int rcv_limit, const int snd_limit,
	const resourced_restriction_state rst_state,
	const int quota_id,
	const resourced_roaming_type roaming)
{
	resourced_ret_c error_code = RESOURCED_ERROR_NONE;

	if (rst_state == RESOURCED_RESTRICTION_REMOVED)
		return reset_restriction_db(app_id, iftype);

	error_code = init_update_rest_stmt();
	ret_value_if(error_code != RESOURCED_ERROR_NONE, error_code);

	DB_ACTION(sqlite3_bind_text(update_rst_stm, 1, app_id, -1, SQLITE_TRANSIENT));
	DB_ACTION(sqlite3_bind_int64(update_rst_stm, 2, rcv_limit));
	DB_ACTION(sqlite3_bind_int64(update_rst_stm, 3, snd_limit));
	DB_ACTION(sqlite3_bind_int(update_rst_stm, 4, iftype));
	DB_ACTION(sqlite3_bind_int(update_rst_stm, 5, rst_state));
	DB_ACTION(sqlite3_bind_int(update_rst_stm, 6, quota_id));
	DB_ACTION(sqlite3_bind_int(update_rst_stm, 7, roaming));

	if (sqlite3_step(update_rst_stm) != SQLITE_DONE)
		error_code = RESOURCED_ERROR_DB_FAILED;

handle_error:

	sqlite3_reset(update_rst_stm);
	if (error_code == RESOURCED_ERROR_DB_FAILED)
		_E("Failed to set network restriction: %s\n",
			sqlite3_errmsg(resourced_get_database()));

	return error_code;
}

resourced_ret_c get_restriction_info(const char *app_id,
				 const resourced_iface_type iftype,
				resourced_restriction_info *rst)
{
	int rc;
	resourced_ret_c error_code = RESOURCED_ERROR_NONE;
	int quota_id = 0;
	sqlite3_stmt *stm = NULL;

	ret_value_msg_if(rst == NULL, RESOURCED_ERROR_INVALID_PARAMETER,
		"Please provide valid restriction argument!");

	ret_value_msg_if(app_id == NULL, RESOURCED_ERROR_INVALID_PARAMETER,
		"Please provide valid app_id argument!");

	_SD("%s, %d", app_id, iftype);

	DB_ACTION(sqlite3_prepare_v2
		  (resourced_get_database(), GET_NET_RESTRICTION, -1, &stm, NULL));

	DB_ACTION(sqlite3_bind_text(stm, 1, app_id, -1, SQLITE_TRANSIENT));
	DB_ACTION(sqlite3_bind_int(stm, 2, iftype));

	do {
		rc = sqlite3_step(stm);
		switch (rc) {
		case SQLITE_ROW:
			rst->rcv_limit = sqlite3_column_int(stm, 0);
			rst->send_limit = sqlite3_column_int64(stm, 1);
			rst->rst_state = sqlite3_column_int(stm, 2);
			rst->quota_id = sqlite3_column_int(stm, 3);

			break;
		case SQLITE_DONE:
			break;
		case SQLITE_ERROR:
		default:
			error_code = RESOURCED_ERROR_DB_FAILED;
			goto handle_error;
		}
	} while (rc == SQLITE_ROW);

	_D("%d", quota_id);

handle_error:

	if (stm)
		sqlite3_finalize(stm);

	if (error_code == RESOURCED_ERROR_DB_FAILED)
		_E("Failed to get network restriction's quota id: %s\n",
			sqlite3_errmsg(resourced_get_database()));

	return quota_id;
}

static bool check_roaming(const resourced_net_restrictions *rst)
{
	resourced_roaming_type roaming;
	ret_value_msg_if(rst == NULL, false,
		"Invalid net_restriction pointer, please provide valid argument");

	roaming = get_roaming();
	_D("roaming %d rst->roaming %d", roaming, rst->roaming);
	if (roaming == RESOURCED_ROAMING_UNKNOWN ||
		rst->roaming == RESOURCED_ROAMING_UNKNOWN) {
		return false;
	}
	return rst->roaming != roaming;
}

static void process_net_block_state(const enum
	traffic_restriction_type rst_type)
{
	struct shared_modules_data *m_data = get_shared_modules_data();

	if (m_data)
		set_daemon_net_block_state(rst_type, m_data->carg);
	else
		_E("shared modules data is empty");
}

resourced_ret_c process_kernel_restriction(
	const u_int32_t classid,
	const resourced_net_restrictions *rst,
	const enum traffic_restriction_type rst_type)
{
	int ret = RESOURCED_ERROR_NONE;

	ret_value_secure_msg_if(!classid, RESOURCED_ERROR_INVALID_PARAMETER,
			 "Can not determine classid for package %u.\n"
			 "Probably package was not joined to performance "
			 "monitoring\n", classid);

	if (rst_type == RST_EXCLUDE && check_roaming(rst)) {
		_D("Restriction not applied: rst->roaming %d", rst->roaming);
		return RESOURCED_ERROR_NONE;
	}

	/* TODO check, and think how to implement it
	 * in unified way, maybe also block FORWARD chain in
	 * send_net_restriction */
	if (classid == RESOURCED_ALL_APP_CLASSID ||
	    classid == RESOURCED_TETHERING_APP_CLASSID)
		ret = apply_tethering_restriction(rst_type);
	if (classid != RESOURCED_TETHERING_APP_CLASSID &&
	    ret == RESOURCED_ERROR_NONE)
		ret = send_net_restriction(rst_type, classid,
						  rst->iftype,
						  rst->send_limit,
						  rst->rcv_limit,
						  rst->snd_warning_limit,
						  rst->rcv_warning_limit);
	ret_value_msg_if(ret < 0, RESOURCED_ERROR_FAIL,
			 "Restriction, type %d falied, return code %d\n",
			 rst_type, ret);

	return RESOURCED_ERROR_NONE;
}

resourced_ret_c proc_keep_restriction(
	const char *app_id, const int quota_id,
	const resourced_net_restrictions *rst,
	const enum traffic_restriction_type rst_type)
{
	u_int32_t app_classid = 0;
	resourced_iface_type store_iftype;
	resourced_restriction_state rst_state;
	int ret = check_restriction_arguments(app_id, rst, rst_type);
	ret_value_msg_if(ret != RESOURCED_ERROR_NONE,
			 RESOURCED_ERROR_INVALID_PARAMETER,
			 "Invalid restriction arguments\n");

	app_classid = get_classid_by_app_id(app_id, rst_type != RST_UNSET);
	ret = process_kernel_restriction(app_classid, rst, rst_type);
	ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
		"Can't keep restriction.");

	store_iftype = get_store_iftype(app_classid, rst->iftype);
	rst_state = convert_to_restriction_state(rst_type);
	_SD("restriction: app_id %s, iftype %d, state %d, type %d\n", app_id,
	    store_iftype, rst_state, rst_type);

	if (!strcmp(app_id, RESOURCED_ALL_APP) &&
		rst->iftype == RESOURCED_IFACE_ALL)
		process_net_block_state(rst_type);

	return update_restriction_db(app_id, store_iftype,
					   rst->rcv_limit, rst->send_limit,
					   rst_state, quota_id, rst->roaming);
}

resourced_ret_c remove_restriction_local(const char *app_id,
					 const resourced_iface_type iftype)
{
	resourced_net_restrictions rst = { 0 };

	rst.iftype = iftype;
	return proc_keep_restriction(app_id, NONE_QUOTA_ID, &rst,
					 RST_UNSET);
}

resourced_ret_c exclude_restriction_local(const char *app_id,
					  const int quota_id,
					  const resourced_iface_type iftype)
{
	resourced_net_restrictions rst = { 0 };

	rst.iftype = iftype;
	return proc_keep_restriction(app_id, quota_id, &rst, RST_EXCLUDE);
}
