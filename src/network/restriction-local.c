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
#include "telephony.h"
#include "storage.h"
#include "trace.h"
#include "tethering-restriction.h"
#include "datausage-common.h"

#define SET_NET_RESTRICTIONS "REPLACE INTO restrictions "     \
	"(binpath, rcv_limit, send_limit, iftype, rst_state, "\
	" quota_id, roaming, ifname) " \
	"VALUES (?, ?, ?, ?, ?, ?, ?, ?)"

#define GET_NET_RESTRICTION "SELECT rcv_limit, send_limit, " \
	" rst_state, roaming, quota_id FROM restrictions " \
	"WHERE binpath = ? AND iftype = ? AND ifname = ?"
#define GET_NET_RESTRICTION_BY_QUOTA "SELECT rcv_limit, send_limit, " \
	" rst_state, roaming, ifname FROM restrictions " \
	"WHERE binpath = ? AND iftype = ? AND quota_id = ?"


#define RESET_RESTRICTIONS "DELETE FROM restrictions "	\
	"WHERE binpath=? AND iftype=? AND ifname = ? AND quota_id = ?"

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
					    const resourced_iface_type iftype,
					    const char *ifname,
					    const int quota_id)
{
	resourced_ret_c error_code = init_reset_rst();

	ret_value_if(error_code != RESOURCED_ERROR_NONE, error_code);

	_D("app_id %s",app_id);
	_D("iftype %d", iftype);
	_D("ifname %s", ifname);
	_D("quota_id %d", quota_id);

	DB_ACTION(sqlite3_bind_text(reset_rst_stm, 1, app_id, -1, SQLITE_TRANSIENT));
	DB_ACTION(sqlite3_bind_int(reset_rst_stm, 2, iftype));
	DB_ACTION(sqlite3_bind_text(reset_rst_stm, 3, ifname, -1, SQLITE_TRANSIENT));
	DB_ACTION(sqlite3_bind_int(reset_rst_stm, 4, quota_id));

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
	const resourced_roaming_type roaming,
	const char *ifname)
{
	resourced_ret_c error_code = init_update_rest_stmt();
	ret_value_if(error_code != RESOURCED_ERROR_NONE, error_code);

	DB_ACTION(sqlite3_bind_text(update_rst_stm, 1, app_id, -1, SQLITE_TRANSIENT));
	DB_ACTION(sqlite3_bind_int64(update_rst_stm, 2, rcv_limit));
	DB_ACTION(sqlite3_bind_int64(update_rst_stm, 3, snd_limit));
	DB_ACTION(sqlite3_bind_int(update_rst_stm, 4, iftype));
	DB_ACTION(sqlite3_bind_int(update_rst_stm, 5, rst_state));
	DB_ACTION(sqlite3_bind_int(update_rst_stm, 6, quota_id));
	DB_ACTION(sqlite3_bind_int(update_rst_stm, 7, roaming));
	DB_ACTION(sqlite3_bind_text(update_rst_stm, 8, ifname, -1, SQLITE_TRANSIENT));

	if (sqlite3_step(update_rst_stm) != SQLITE_DONE)
		error_code = RESOURCED_ERROR_DB_FAILED;

handle_error:

	sqlite3_reset(update_rst_stm);
	if (error_code == RESOURCED_ERROR_DB_FAILED)
		_E("Failed to set network restriction: %s\n",
			sqlite3_errmsg(resourced_get_database()));

	return error_code;
}

/**
 * Populate restriction info
 * @param app_id mandatory argument
 * @param iftype mandatory
 * @param rst - restriction to fill,
 *	if user specified ifname in it
 *	select will be by ifname
 *	vice versa, if quota_id was specified we are looking ifname
 *	in this case user should release ifname if it's no more needed.
 * */
resourced_ret_c get_restriction_info(const char *app_id,
				const resourced_iface_type iftype,
				resourced_restriction_info *rst)
{
	int rc;
	resourced_ret_c error_code = RESOURCED_ERROR_NONE;
	static sqlite3_stmt *stm_ifname;
	static sqlite3_stmt *stm_quota;
	sqlite3_stmt *stm = 0;

	ret_value_msg_if(rst == NULL, RESOURCED_ERROR_INVALID_PARAMETER,
		"Please provide valid restriction argument!");

	ret_value_msg_if(app_id == NULL, RESOURCED_ERROR_INVALID_PARAMETER,
		"Please provide valid app_id argument!");

	_SD("app_id: %s, iftype: %d, ifname: %s, quota_id: %d ",
			app_id, iftype, rst->ifname, rst->quota_id);

	if (rst->ifname && strlen(rst->ifname)) {
		if (stm_ifname == NULL) { /* lazy initialization of stm */
			DB_ACTION(sqlite3_prepare_v2(
			  resourced_get_database(), GET_NET_RESTRICTION, -1,
			  &stm_ifname, NULL));
		}
		stm = stm_ifname;
	} else if (rst->quota_id) {
		if (stm_quota == NULL) { /* lazy initialization of stm_quota */
			DB_ACTION(sqlite3_prepare_v2(
			  resourced_get_database(), GET_NET_RESTRICTION_BY_QUOTA,
			  -1, &stm_quota, NULL));
		}
		stm = stm_quota;
	} else
		return RESOURCED_ERROR_INVALID_PARAMETER;

	DB_ACTION(sqlite3_bind_text(stm, 1, app_id, -1, SQLITE_TRANSIENT));
	DB_ACTION(sqlite3_bind_int(stm, 2, iftype));
	if (rst->ifname && strlen(rst->ifname))
		DB_ACTION(sqlite3_bind_text(stm, 3, rst->ifname, -1, SQLITE_TRANSIENT));
	else if (rst->quota_id)
		DB_ACTION(sqlite3_bind_int(stm, 3, rst->quota_id));

	do {
		rc = sqlite3_step(stm);
		switch (rc) {
		case SQLITE_ROW:
			rst->rcv_limit = sqlite3_column_int(stm, 0);
			rst->send_limit = sqlite3_column_int64(stm, 1);
			rst->rst_state = sqlite3_column_int(stm, 2);
			rst->roaming = sqlite3_column_int(stm, 3);
			if (rst->ifname && strlen(rst->ifname))
				rst->quota_id = sqlite3_column_int(stm, 4);
			else if (rst->quota_id)
				rst->ifname = strdup((char *)sqlite3_column_text(
						stm, 4));

			break;
		case SQLITE_DONE:
			break;
		case SQLITE_ERROR:
		default:
			error_code = RESOURCED_ERROR_DB_FAILED;
			goto handle_error;
		}
	} while (rc == SQLITE_ROW);
	sqlite3_reset(stm);

	_D("quota_id: %d, if_name: %s", rst->quota_id, rst->ifname);

	return RESOURCED_ERROR_NONE;

handle_error:

	if (stm == stm_ifname) {
		sqlite3_finalize(stm_ifname);
		stm_ifname = 0;
	} else if (stm == stm_quota) {
		sqlite3_finalize(stm_quota);
		stm_quota = 0;
	}

	if (error_code == RESOURCED_ERROR_DB_FAILED)
		_E("Failed to fill network restriction's: %s\n",
			sqlite3_errmsg(resourced_get_database()));

	return error_code;
}

static bool check_roaming(const resourced_net_restrictions *rst)
{
	resourced_roaming_type roaming;
	ret_value_msg_if(rst == NULL, false,
		"Invalid net_restriction pointer, please provide valid argument");

	roaming = get_current_roaming();
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
	const enum traffic_restriction_type rst_type,
	const int quota_id)
{
	int ret = RESOURCED_ERROR_NONE;
	struct shared_modules_data *m_data;
	struct counter_arg *carg;

	m_data = get_shared_modules_data();
	ret_value_msg_if(m_data == NULL, RESOURCED_ERROR_FAIL,
		"Can't get module data!");

	carg = m_data->carg;
	ret_value_msg_if(carg == NULL, RESOURCED_ERROR_FAIL,
		"Cant' get counter arg!");
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
	if ((classid == RESOURCED_ALL_APP_CLASSID ||
	    classid == RESOURCED_TETHERING_APP_CLASSID) &&
	/* apply it now if we'll block now in case of send_limit
	 * rcv_limit 0, or when will block noti come */
	    ((rst_type == RST_UNSET || rst_type == RST_EXCLUDE) ||
	    (rst_type == RST_SET && (!rst->send_limit || !rst->rcv_limit))))
		ret = apply_tethering_restriction(rst_type);

	if (classid != RESOURCED_TETHERING_APP_CLASSID &&
	    ret == RESOURCED_ERROR_NONE)
		ret = send_net_restriction(rst_type, classid, quota_id,
						  rst->iftype,
						  rst->send_limit,
						  rst->rcv_limit,
						  rst->snd_warning_limit,
						  rst->rcv_warning_limit,
						  rst->ifname);
	ret_value_msg_if(ret < 0, RESOURCED_ERROR_FAIL,
			 "Restriction, type %d falied, return code %d\n",
			 rst_type, ret);
	if (classid == RESOURCED_BACKGROUND_APP_CLASSID) {
		if (rst_type == RST_UNSET) {
			foreground_apps(carg);
		} else {
			background_apps(carg);
		}
	}
	return RESOURCED_ERROR_NONE;
}

static bool check_background_app(const char *app_id, const resourced_state_t state)
{
	if (state == RESOURCED_STATE_BACKGROUND ||
	    !strcmp(app_id, RESOURCED_BACKGROUND_APP_NAME)) {
		return TRUE;
	}
	return FALSE;
}

resourced_ret_c proc_keep_restriction(
	const char *app_id, const int quota_id,
	const resourced_net_restrictions *rst,
	const enum traffic_restriction_type rst_type,
	bool skip_kernel_op)
{
	u_int32_t app_classid = 0;
	resourced_iface_type store_iftype;
	resourced_restriction_state rst_state;
	int ret = check_restriction_arguments(app_id, rst, rst_type);
	ret_value_msg_if(ret != RESOURCED_ERROR_NONE,
			 RESOURCED_ERROR_INVALID_PARAMETER,
			 "Invalid restriction arguments\n");

	if (check_background_app(app_id, rst->rs_type))
		app_classid = RESOURCED_BACKGROUND_APP_CLASSID;
	else
		app_classid = get_classid_by_app_id(app_id, rst_type != RST_UNSET);
	if (!skip_kernel_op) {
		ret = process_kernel_restriction(app_classid, rst, rst_type, quota_id);
		ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
			"Can't keep restriction.");
	}

	store_iftype = get_store_iftype(app_classid, rst->iftype);
	rst_state = convert_to_restriction_state(rst_type);
	_SD("restriction: app_id %s, classid %d, iftype %d, state %d, type %d, "\
	    "imsi %s, rs_type %d\n", app_id, app_classid,
	    store_iftype, rst_state, rst_type, rst->ifname, rst->rs_type);

	if (!strcmp(app_id, RESOURCED_ALL_APP) &&
		rst->iftype == RESOURCED_IFACE_ALL)
		process_net_block_state(rst_type);

	/* in case of SET/EXCLUDE just update state in db, otherwise remove fro
	 * db */
	if (rst_type == RST_UNSET)
		ret = reset_restriction_db(app_id, store_iftype, rst->ifname,
				quota_id);
	else
		ret = update_restriction_db(app_id, store_iftype,
					    rst->rcv_limit, rst->send_limit,
					    rst_state, quota_id, rst->roaming,
					    rst->ifname);

	return ret;
}

resourced_ret_c remove_restriction_local(const char *app_id,
					 const resourced_iface_type iftype,
					 const int quota_id,
					 const char *imsi_hash,
					 const resourced_state_t ground)
{
	resourced_net_restrictions rst = { .iftype = iftype };
	resourced_restriction_info rst_info = { .iftype = iftype, .quota_id = quota_id };

	bool skip_kernel_op = check_event_in_current_modem(imsi_hash, iftype);
	/* getting ifname by iftype form none persistent
	 * ifaces list is not so good idea,
	 * for example, user could delete applied quota,
	 * right after reboot, when ifnames is not yet initialized */
	resourced_ret_c ret = get_restriction_info(app_id, iftype, &rst_info);
	if (ret != RESOURCED_ERROR_NONE) {
		_D("Can't get restriction info: app_id %s, iftype %d, quota_id %d",
				app_id, iftype, quota_id);
		goto release_ifname;
	}
	rst.ifname = (char *)rst_info.ifname;
	rst.rs_type = ground;
	ret = proc_keep_restriction(app_id, quota_id, &rst,
					 RST_UNSET, skip_kernel_op);
	if (ret != RESOURCED_ERROR_NONE) {
		_D("Can't keep restriction");
	}

release_ifname:
	if(rst_info.ifname)
		free((char *)rst_info.ifname);
	return ret;
}

resourced_ret_c exclude_restriction_local(const char *app_id,
					  const int quota_id,
					  const resourced_iface_type iftype,
					  const char *imsi_hash)
{
	resourced_net_restrictions rst = { 0 };
	bool skip_kernel_op = check_event_in_current_modem(imsi_hash, iftype);

	rst.iftype = iftype;
	rst.ifname = get_iftype_name(rst.iftype);
	return proc_keep_restriction(app_id, quota_id, &rst, RST_EXCLUDE,
			skip_kernel_op);
}
