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
 *  @file: datausage-quota-processing.h
 *
 *  @desc Entity for working with quotas
 *  @version 2.0
 *
 *  Created on: Aug 08, 2012
 */

#ifndef _TRESOURCED_DATAUSAGE_QUOTA_PROCESSING_H_
#define _TRESOURCED_DATAUSAGE_QUOTA_PROCESSING_H_

#include <sqlite3.h>
#include <stdbool.h>

#include "data_usage.h"

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
	char *imsi_hash;
};

/*
 * Store data in effective quota
 */
void flush_quota_table(void);

struct counter_arg;
/*
 * Quota processing. It's apply quota if needed.
 * And actualize current quotas state.
 */
resourced_ret_c process_quota(struct counter_arg *carg);

/*
 * Finish working with quotas
 */
void finalize_quotas(void);

/*
 * Delete quota and drop remove restriction
 */
void update_quota_state(const char *app_id, const int quota_id,
		struct serialization_quota *ser_quota);

void remove_quota_from_counting(const char *app_id, const resourced_iface_type iftype,
	const resourced_roaming_type roaming,
	const char *imsi);

void clear_effective_quota(const char *app_id,
	const resourced_iface_type iftype,
	const resourced_roaming_type roaming,
	const char *imsi_hash);

resourced_ret_c get_quota_by_id(const int quota_id, data_usage_quota *du_quota);
resourced_ret_c get_quota_by_appid(const char* app_id, const char *imsi_hash,
		const resourced_iface_type iftype, resourced_roaming_type roaming_type,
		data_usage_quota *du_quota, int *quota_id, resourced_state_t ground);
/**
 * @desc return true if we have applied background quota
 */
bool get_background_quota(void);


bool check_quota_applied(const char *app_id, const resourced_iface_type iftype,
		const resourced_roaming_type roaming, const char *imsi,
		const resourced_state_t ground,	int *quota_id);

#endif /* _TRESOURCED_DATAUSAGE_QUOTA_PROCESSING_H_ */
