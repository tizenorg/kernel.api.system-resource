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
 *  @file: datausage-quota.h
 *
 *  @desc Performance management API
 *  @version 1.0
 *
 *  Created on: Jul 31, 2012
 */

#ifndef TRESOURCED_DATAUSAGE_QUOTA_H_
#define TRESOURCED_DATAUSAGE_QUOTA_H_

#include <sqlite3.h>

#define RESOURCED_NEW_LIMIT_PATH "db/private/resourced/new_limit"
#define RESOURCED_DELETE_LIMIT_PATH "db/private/resourced/delete_limit"

int init_datausage_quota(sqlite3 *db);

void finalize_datausage_quota(void);

#endif	/* TRESOURCED_DATAUSAGE_QUOTA_H_ */
