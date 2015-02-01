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
 * @file generic-netlink.h
 * @desc Helper function for making kernel request and process response
 **/

#ifndef _GRABBER_CONTROL_KERNEL_GENERIC_NETLINK_H_
#define _GRABBER_CONTROL_KERNEL_GENERIC_NETLINK_H_

#include "counter.h"
#include "genl.h"
#include "nl-helper.h"

#include <unistd.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>

enum net_activity_recv {
	RESOURCED_NET_ACTIVITY_OK,
	RESOURCED_NET_ACTIVITY_STOP,
	RESOURCED_NET_ACTIVITY_CONTINUE,
};

netlink_serialization_command *netlink_create_command(
	struct netlink_serialization_params *params);

uint32_t get_family_id(int sock, pid_t pid, char *family_name);

/**
 * @desc get id for multicasted generic netlink messages
 *	only one multicast group is supported per family id now.
 *	This function also gets family id, due it comes with the
 *	same answer as a multicast generic netlink message.
 */
uint32_t get_family_group_id(int sock, pid_t pid,
	                char *family_name, char *group_name,
			uint32_t *family_id);

/**
 * @desc Extracts family id from answer
 *	accepts opaque pointer
 **/
uint32_t netlink_get_family(struct genl *nl_ans);

/**
 * @desc This function sends to kernel command to start
 *	network activity reporting. This function creats
 *	and closes socket itself.
 **/
resourced_ret_c start_net_activity(void);

/**
 * @desc Stop network activity @see start_net_activity
 **/
resourced_ret_c stop_net_activity(void);

struct net_activity_info;

/**
 * @desc Receive and fill activity info from netlink socket.
 *	Received activity_info should contain the same family_id as
 *	net_activity_family_id
 */
enum net_activity_recv recv_net_activity(int sock, struct net_activity_info
	*activity_info, const uint32_t net_activity_family_id);

/**
 * @desc Extracts family id from answer
 *	accepts opaque pointer
 **/
uint32_t netlink_get_family(struct genl *nl_ans);

void send_start(int sock, const pid_t pid, const int family_id);

int send_command(int sock, const pid_t pid, const int family_id, uint8_t cmd);

int send_restriction(int sock, const pid_t pid, const int family_id,
		     const u_int32_t classid, const int ifindex,
		     const enum traffic_restriction_type restriction_type,
		     const int send_limit,
		     const int rcv_limit,
		     const int snd_warning_threshold,
		     const int rcv_warning_threshold);

resourced_ret_c process_netlink_restriction_msg(const struct genl *ans,
	struct traffic_restriction *restriction, uint8_t *command);

#endif /*_GRABBER_CONTROL_KERNEL_GENERIC_NETLINK_H_*/
