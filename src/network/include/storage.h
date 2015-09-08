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
 *  @file: storage.h
 *
 *  @desc Performance management daemon. Helper function
 *		for working with entity storage.
 *  @version 1.0
 *
 */


#ifndef _TRAFFIC_CONTROL_TRAFFIC_STAT_STORAGE_H_
#define _TRAFFIC_CONTROL_TRAFFIC_STAT_STORAGE_H_

#include <sqlite3.h>
#include <resourced.h>

#include "app-stat.h"
#include "iface.h"

/**
 * @desc Initialize database.
 *	At present it tweak "pragma synchronous = off"
 *	 and "pragma temp_store = memory"
 * @param filename - Full path to database
 */
resourced_ret_c init_database(const char *filename);

/**
 * @desc Store result list to database.
 * @param stats - List of resolved application information
 * @param flush_period - Time interval for storing data
 * @return 1 if flushed, 0 if not
 */
int store_result(struct application_stat_tree *stats, int flush_period);

/**
 * @desc Just close sqlite statements.
 */
void finalize_storage_stm(void);

/**
 * @desc Return arguments for network interface processing.
 *	Argument contains handler function for react on interface changes.
 *	Changes should be reflect in the database. Whats why it's here.
 *	We doesn't provide special entity for working with database.
 */
iface_callback *create_iface_storage_callback(void);

#endif /*_TRAFFIC_CONTROL_TRAFFIC_STAT_STORAGE_H_*/
