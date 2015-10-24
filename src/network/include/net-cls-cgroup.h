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
 *  @file: net-cls-cgroup.h
 *
 *  @desc Performance management daemon. Helper function
 *		for working with classid table.
 *  @version 1.0
 *
 */


#ifndef _RESOURCED_NET_CLS_CGROUP_H_
#define _RESOURCED_NET_CLS_CGROUP_H_

#include <sys/types.h>
#include <glib.h>
#include <stdbool.h>

#include "resourced.h"

#define PATH_TO_NET_CGROUP_DIR "/sys/fs/cgroup/net_cls"

typedef GArray int_array;

/**
 * @desc Get all pids from cgroup
 *     Should be invoked after update_classids
 * @return array, you should free it
 */
int_array *get_monitored_pids(void);

/**
 * @desc update class id - pid table. At present one pid per classid.
 */
int update_classids(void);

/**
 * @desc Get appid from classid task table. At present it is package name.
 */
char *get_app_id_by_pid(const pid_t pid);
char *get_app_id_by_classid(const u_int32_t classid, const bool update_state);

/**
 * @desc take classid from net_cls cgroup by appid
 *	This function converts appid to pkgname.
 * @param pkg_name - name of the cgroup
 * @param create - in case of true - create cgroup if it's not exists
 * @return classid
 */
u_int32_t get_classid_by_app_id(const char *app_id, int create);

/**
 * @desc create cgroup, generate classid and put classid into cgroup
 */
resourced_ret_c make_net_cls_cgroup(const char *pkg_name, u_int32_t classid);

resourced_ret_c place_pids_to_net_cgroup(const int pid, const char *pkg_name);

/**
 * @desc Make net_cls cgroup and put in it the given pid and
 * generated classid.
 * If cgroup alreay exists function just put pid in it.
 * @param pid - process, that will be added to cgroup pkg_name,
 * @param pkg_name - package name.
 */
resourced_ret_c make_net_cls_cgroup_with_pid(const int pid,
	const char *pkg_name);

struct counter_arg;
/**
 * @desc this function makes net_cls cgroup and put pids into it
 * */
void create_net_background_cgroup(struct counter_arg *carg);


#endif	/*_RESOURCED_NET_CLS_CGROUP_H_*/
