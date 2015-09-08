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
 *
 */

/**
 *  @file nl-helper.c
 *  @desc Common netlink helper function
 *
 *  Created on: Jun 25, 2012
 */

#include "nl-helper.h"
#include "trace.h"

#include <unistd.h>
#include <linux/rtnetlink.h>
#include <stdlib.h>
#include <string.h>

/**
 * create_netlink(): Create netlink socket and returns it.
 * Returns: Created socket on success and -1 on failure.
 */
int create_netlink(int protocol, uint32_t groups)
{
	/**
	* TODO it's one socket, in future make set of sockets
	* unique for protocol and groups
	*/
	int sock;
	sock = socket(PF_NETLINK, SOCK_RAW, protocol);
	if (sock < 0)
		return -EINVAL;

	struct sockaddr_nl src_addr = { 0, };

	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_groups = groups;

	if (bind(sock, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
		close(sock);
		return -1;
	}

	return sock;
}

void fill_attribute_list(struct rtattr **atb, const int max_len,
	struct rtattr *rt_na, int rt_len)
{
	int i = 0;
	while (RTA_OK(rt_na, rt_len)) {
		if (rt_na->rta_type <= max_len)
			atb[rt_na->rta_type] = rt_na;

		rt_na = RTA_NEXT(rt_na, rt_len);
		++i;
		if (i >= max_len)
			break;
	}
}

/* read netlink message from socket
 * return opaque pointer to genl structure */

#ifdef CONFIG_DATAUSAGE_NFACCT
int read_netlink(int sock, void *buf, size_t len)
{
	ssize_t ret;
	struct sockaddr_nl addr;
	struct iovec iov = {
		.iov_base	= buf,
		.iov_len	= len,
	};
	struct msghdr msg = {
		.msg_name	= &addr,
		.msg_namelen	= sizeof(struct sockaddr_nl),
		.msg_iov	= &iov,
		.msg_iovlen	= 1,
		.msg_control	= NULL,
		.msg_controllen	= 0,
		.msg_flags	= 0,
	};
	ret = recvmsg(sock, &msg, 0);
	if (ret == -1)
		return ret;

	if (msg.msg_flags & MSG_TRUNC) {
		errno = ENOSPC;
		return -1;
	}

	if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
		errno = EINVAL;
		return -1;
	}

	return ret;
}
#else
int read_netlink(int sock, void *buf, size_t len)
{
	int ans_len;
	struct genl *ans = buf;

	ans_len = recv(sock, ans, len, MSG_DONTWAIT);
	if (ans_len < 0)
		return 0;

	if (ans->n.nlmsg_type == NLMSG_ERROR)
		return 0;

	if (!NLMSG_OK((&ans->n), ans_len))
		return 0;

	return ans_len;
}
#endif
