/*
 *  resourced
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
 *  @file: app-stat.h
 *
 *  @desc Application stat entity
 *  @version 1.0
 *
 */

#ifndef _RESOURCED_APPLICATION_STAT_H_
#define _RESOURCED_APPLICATION_STAT_H_

#include <netinet/in.h>
#include <glib.h>
#include <sys/types.h>

#include "const.h"
#include "data_usage.h"
#include "daemon-options.h"
#include "transmission.h"

#define RSML_UNKNOWN_CLASSID 1

/*
* General structure containing information for storing
* application_id - package name as unique application identifier
* snd_count - sent bytes
* rcv_count - received bytes
* pid - process identifier
* ifindex - network interface index, iftype holds in key @see resourced_iface_type
* is_roaming - is traffic consumed at roaming, @see resourced_roaming_type
*/
struct application_stat {
	char *application_id;
	uint32_t snd_count;
	uint32_t rcv_count;
	uint32_t delta_snd;
	uint32_t delta_rcv;

	pid_t pid;
	int ifindex;
	resourced_roaming_type is_roaming;
};

/*
* Structure for holding serialized data from kernel @see traffic_event
*/
struct traffic_stat {
	unsigned long bytes;
	int ifindex;
};

struct classid_iftype_key
{
	u_int32_t classid;
	int iftype;
	char ifname[MAX_NAME_LENGTH];
};

typedef GTree traffic_stat_tree;

struct application_stat_tree {
	GTree *tree;
	time_t last_touch_time;
	pthread_rwlock_t guard;
};

struct application_stat_tree *create_app_stat_tree(void);
void free_app_stat_tree(struct application_stat_tree *tree);
void nulify_app_stat_tree(struct application_stat_tree **tree);

traffic_stat_tree *create_traffic_stat_tree(void);
void free_traffic_stat_tree(traffic_stat_tree *list);

resourced_ret_c prepare_application_stat(traffic_stat_tree *tree_in,
		 traffic_stat_tree *tree_out,
		 struct application_stat_tree *result,
		 volatile struct daemon_opts *opts);


#endif /* _RESOURCED_APPLICATION_STAT_H_ */
