/*
 * resourced
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 */

/**
 * @file netstat-common.h
 *
 * @desc Datausage module control structures
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#ifndef __RESOURCED_NETSTAT_COMMON_H__
#define __RESOURCED_NETSTAT_COMMON_H__

#include <stdint.h>

#include <resourced.h>

#include "counter.h"
#include "nfacct-rule.h"
#include "iface.h"
#include "proc-common.h"

enum netstat_control_type {
	NET_CTRL_TYPE_UNKNOWN,
	JOIN_NET_CLS,
	NET_CTRL_TYPE_LAST_ELEM,
};

struct netstat_data_type
{
	enum netstat_control_type op_type;
	uint32_t *args;
};

/**
 * @brief It creates an appropriate cgroup,
 *   it generates classid for the network performance control.
 *   This function uses module's control callback interface to
 *   invoke join_app_performance
 * @param app_id[in] - application identifier, it's package name now
 * @param pid - pid to put in to cgroup, or self pid of 0
 * @return 0 if success or error code
 */
resourced_ret_c join_net_cls(const char *app_id, const pid_t pid);

iface_callback *create_counter_callback(void);

struct nfacct_rule;
void keep_counter(struct nfacct_rule *counter);
/* remove counter from tree and execute its rule */
void finalize_counter(struct nfacct_rule *counter);

void set_finalize_flag(struct nfacct_rule *counter);
void update_counter_quota_value(struct nfacct_rule *counter, uint64_t bytes);
void extract_restriction_list(struct counter_arg *arg, GSList **rst_list);
resourced_state_t get_app_ground(struct nfacct_rule *counter);

/**
 * @desc mark appropriate nfacct by app_id as background
 */
void mark_background(const char *app_id);

/**
 * @desc  move all pids of existing nfacct from background cgroup,
 * to appropriate apps cgroups
 */
void foreground_apps(struct counter_arg *carg);

/**
 * @desc move all pids of existing nfacct to background cgroup
 */
void background_apps(struct counter_arg *carg);

/**
 * @desc general function to load network's module options,
 * like update/flush period, wifi alloance
 * It loads options from VCONF, which should be rewritable or
 * from network.conf which are RO
 */
void load_network_opts(struct net_counter_opts *opts);

/**
 * @desc  move all pids of main pid to the
 * to appropriate apps cgroups
 */
void move_pids_tree_to_cgroup(struct proc_app_info *pai, const char *pkg_name);

#endif /* __RESOURCED_NETSTAT_COMMON_H__ */
