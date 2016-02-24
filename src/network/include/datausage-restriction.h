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
 * @file restriction.h
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#ifndef _RESOURCED_RESTRICTION_H_
#define _RESOURCED_RESTRICTION_H_

#include <sqlite3.h>
#include <stdbool.h>

#include "resourced.h"
#include "data_usage.h"
#include "transmission.h"

void finalize_datausage_restriction(void);

/**
 * @desc Update restriction database
 **/
resourced_ret_c update_restriction_db(
	const char *app_id, const resourced_iface_type iftype,
	const int rcv_limit, const int snd_limit,
	const resourced_restriction_state rst_state,
	const int quota_id,
	const resourced_roaming_type roaming,
	const char *ifname);

/**
 * @desc Get restriction info from database
 *	Now it filles only quota_id, send_limit,
 *	rcv_limit, rst_state
 *
 * @param app_id - binpath database field, currently pkgid
 * @param iftype - iftype database field
 **/
resourced_ret_c get_restriction_info(const char *app_id,
				const resourced_iface_type iftype,
				resourced_restriction_info *rst);

resourced_ret_c process_kernel_restriction(
	const u_int32_t classid,
	const resourced_net_restrictions *rst,
	const enum traffic_restriction_type rst_type,
	const int quota_id);

resourced_ret_c proc_keep_restriction(
	const char *app_id, int quota_id, const resourced_net_restrictions *rst,
	const enum traffic_restriction_type rst_type,
	bool skip_kernel_op);

resourced_ret_c remove_restriction_local(const char *app_id,
					 const resourced_iface_type iftype,
					 const int quota_id,
					 const char *imsi,
					 const resourced_state_t ground);

resourced_ret_c exclude_restriction_local(const char *app_id,
					  const int quota_id,
					  const resourced_iface_type iftype,
					  const char *imsi);

#endif /* _RESOURCED_RESTRICTION_H_ */
