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
#include "config.h"
#include "data_usage.h"
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

#ifndef CONFIG_DATAUSAGE_NFACCT
	pid_t pid;
	int ifindex;
#endif
	resourced_roaming_type is_roaming;

	/* foreground/background state is here,
	 * not in classid_iftype_key, it means
	 * we'll not able to handle simultaneously
	 * counter per one application for background and
	 * foreground withing one counting cycle,
	 * so every time application goes to background/foreground
	 * we'll request its counter update */
	resourced_state_t ground;
};

struct classid_iftype_key
{
	u_int32_t classid;
	int iftype;
	/* pointer to telephony's imsi */
	char *imsi;
	char ifname[MAX_IFACE_LENGTH];
};

struct application_stat_tree {
	GTree *tree;
	time_t last_touch_time;
	pthread_rwlock_t guard;
};

struct application_stat_tree *create_app_stat_tree(void);
void free_app_stat_tree(struct application_stat_tree *tree);
void nulify_app_stat_tree(struct application_stat_tree **tree);

struct counter_arg;
#ifdef CONFIG_DATAUSAGE_NFACCT
void fill_nfacct_result(char *cnt_name, uint64_t bytes,
			  struct counter_arg *carg);
#else
/* It's not same function used at netacct and it's only used at ktgrabber. */
void fill_app_stat_result(int ifindex, int classid, uint64_t bytes, int iotype,
			  struct counter_arg *carg);
#endif



#endif /* _RESOURCED_APPLICATION_STAT_H_ */
