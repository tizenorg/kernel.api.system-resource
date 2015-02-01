/*
 * resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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

/*
 *  @file: net_activity.h
 *
 *  @desc Handler which get data from generic netlink (NET_ACTIVITY) family
 */

#include "const.h"
#include "net-cls-cgroup.h"
#include "generic-netlink.h"
#include "iface.h"
#include "macro.h"
#include "trace.h"

#include <data_usage.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#define NET_ACTIVITY_LISTEN_TIMEOUT 10

static pthread_t net_activity_worker;

struct net_activity_context {
	net_activity_cb cb;
	uint32_t group_family_id;
	uint32_t family_id;
	int sock;
};

static void set_socket_option(int sock)
{
	int ret;
	int opts = fcntl(sock, F_GETFL);

	ret_msg_if(opts < 0, "fcntl error");
	opts = (opts | O_NONBLOCK);

	ret = fcntl(sock, F_SETFL, opts);
	ret_msg_if(ret < 0, "fcntl error");
}

/**
 * Convert the netlink multicast group id into a bit map
 * (e.g. 4 => 16, 5 => 32)
 */
static uint32_t convert_mcast_group_id(uint32_t group_id)
{
        if (group_id > 31) {
                _E("Netlink: Use setsockopt for this group: %u\n", group_id);
                return 0;
        }
        return group_id ? (1 << (group_id - 1)) : 0;
}

static void *net_activity_func(void *user_data)
{
	int ret, max_fd;
	struct net_activity_context *context =
		(struct net_activity_context *)user_data;
	struct net_activity_info activity_info;
	struct timeval timeout = {0};

	fd_set rfd;
	max_fd = context->sock + 1;

	while (1) {
		timeout.tv_sec = NET_ACTIVITY_LISTEN_TIMEOUT;
		FD_ZERO(&rfd);
		FD_SET(context->sock, &rfd);

		ret = select(max_fd, &rfd, NULL, NULL, &timeout);

		if (ret < 0) {
			_E("Failed to select on generic netlink socket");
			goto stop_net_activity;
		}

		if (ret == 0) {
			_D("timeout");
			continue;
		}

		ret = recv_net_activity(context->sock, &activity_info,
			context->family_id);

		if (ret == RESOURCED_NET_ACTIVITY_STOP)
			goto stop_net_activity;
		else if (ret == RESOURCED_NET_ACTIVITY_CONTINUE)
			continue;

	        if (context->cb(&activity_info) == RESOURCED_CANCEL)
			goto stop_net_activity;
	}

stop_net_activity:
	stop_net_activity();
	close(context->sock);
	free(context);
	return NULL;

}

API resourced_ret_c register_net_activity_cb(net_activity_cb activity_cb)
{
	int ret;
	struct net_activity_context *context;
	pid_t pid;

	ret_value_msg_if(!activity_cb, RESOURCED_ERROR_INVALID_PARAMETER,
		"Please provide valid callback function!");

	context = (struct net_activity_context *)malloc(
		sizeof(struct net_activity_context));

	ret_value_if(!context, RESOURCED_ERROR_OUT_OF_MEMORY);

	context->cb = activity_cb;
	ret = update_classids();
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to update appid!");
		goto free_context;
	}

	context->sock = create_netlink(NETLINK_GENERIC, 0);

	if (context->sock < 0) {
		_E("Cant create socket");
		goto free_context;
	}

	set_socket_option(context->sock);
	pid = getpid();
	/* Initialize family id to communicate with NET_ACTIVITY chanel */
	context->group_family_id = get_family_group_id(context->sock,
		pid, "NET_ACTIVITY", "NET_ACT_MCAST", &context->family_id);

	start_net_activity();

	if (context->family_id == 0 || context->group_family_id == 0) {
		_E("Cant get family id");
		goto close_socket;
	}

	/* this one is no more needed */
	close(context->sock);

	/* New one subscribed to group_family_id */
	context->sock = create_netlink(NETLINK_GENERIC,
		convert_mcast_group_id(context->group_family_id));

	if (context->sock < 0) {
		_E("Failed to create multicast socket!");
		goto free_context;
	}

	/* start thread */
	pthread_create(&net_activity_worker, NULL, net_activity_func,
		(void *)context);

	return RESOURCED_ERROR_NONE;

close_socket:
	close(context->sock);

free_context:
	free(context);

	stop_net_activity();
	return RESOURCED_ERROR_FAIL;
}
