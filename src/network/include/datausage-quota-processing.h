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

#include "app-stat.h"
#include "resourced.h"

/*
 * Store data in effective quota
 */
void flush_quota_table(void);

/*
 * Quota processing. It's apply quota if needed.
 * And actualize current quotas state.
 */
resourced_ret_c process_quota(struct application_stat_tree *apps,
	volatile struct daemon_opts *opts);

/*
 * Finish working with quotas
 */
void finalize_quotas(void);

/*
 * Delete quota and drop remove restriction
 */
void update_quota_state(const char *app_id, const resourced_iface_type iftype,
	const time_t start_time, const int time_period,
	const resourced_roaming_type roaming);

#endif /* _TRESOURCED_DATAUSAGE_QUOTA_PROCESSING_H_ */
