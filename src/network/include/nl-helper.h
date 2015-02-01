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

/** @file nl-helper.h
 *
 *  @desc Common netlink helper function
 *
 *  Created on: Jun 25, 2012
 */

#ifndef RESOURCED_NL_HELPER_H_
#define RESOURCED_NL_HELPER_H_

#include "app-stat.h"
/*#include "nfacct-helper.h"*/

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>

#define NLA_BUF_MAX 65560	/*(65 * 1024) - used in tc_common,
	 we'll do the same */

/*TODO: move to common place and rewrite because it's from TC*/
#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/*TODO remove unused code */
typedef struct {
	struct nlmsghdr n;
	struct tcmsg t;
	char buf[NLA_BUF_MAX];
} rt_param;

void put_attr(rt_param *arg, int type, const void *data, int data_len);

/*
 * Generic macros for dealing with netlink sockets. Might be duplicated
 * elsewhere. It is recommended that commercial grade applications use
 * libnl or libnetlink and use the interfaces provided by the library
 */
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))

#define NETLINK_BUF_SIZE 16536

enum nfnl_acct_msg_types {
	NFNL_MSG_ACCT_NEW,
	NFNL_MSG_ACCT_GET,
	NFNL_MSG_ACCT_GET_CTRZERO,
	NFNL_MSG_ACCT_DEL,
	NFNL_MSG_ACCT_MAX
};

enum nfnl_acct_type {
	NFACCT_UNSPEC,
	NFACCT_NAME,
	NFACCT_PKTS,
	NFACCT_BYTES,
	NFACCT_USE,
	NFACCT_FLAGS,
	NFACCT_QUOTA,
	NFACCT_FILTER,
	__NFACCT_MAX
};

enum nfnl_attr_filter_type {
	NFACCT_FILTER_ATTR_UNSPEC,
	NFACCT_FILTER_ATTR_MASK,
	NFACCT_FILTER_ATTR_VALUE,
	__NFACCT_FILTER_ATTR_MAX
};

#define NFACCT_MAX (__NFACCT_MAX - 1)

struct genl {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[NETLINK_BUF_SIZE];
};

struct netlink_serialization_params {
	traffic_stat_tree *stat_tree;
	struct genl *ans;
	struct counter_arg *carg;
	int (*eval_attr)(struct rtattr *attr_list[__NFACCT_MAX],
		void *user_data);
	int (*post_eval_attr)(void *user_data);
};

typedef struct {
	void (*deserialize_answer)(struct netlink_serialization_params *params);
	void (*finalize)(struct netlink_serialization_params *params);
	struct netlink_serialization_params params;
} netlink_serialization_command;

int create_netlink(int protocol, uint32_t groups);
int read_netlink(int sock, void *buf, size_t len);

void fill_attribute_list(struct rtattr **atb, const int max_len,
	struct rtattr *rt_na, int rt_len);

#endif	/* RESOURCED_NL_HELPER_H_ */
