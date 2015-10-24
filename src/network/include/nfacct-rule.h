/*
 * resourced
 *
 * Copyright (c) 2012-2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file nfacct-rule.h
 *
 * @desc API for nfacct module
 *
 * Copyright (c) 2012-2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#ifndef _RESOURCED_NFACCT_RULE_H
#define _RESOURCED_NFACCT_RULE_H

#include "const.h"
#include "data_usage.h"

#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

typedef enum {
	NFACCT_COUNTER_UNKNOWN,
	NFACCT_COUNTER_IN = (1 << 1),
	NFACCT_COUNTER_OUT = (1 << 2),
	NFACCT_COUNTER_LAST_ELEM
} nfacct_rule_direction;

typedef enum {
	NFACCT_ACTION_UNKNOWN,
	NFACCT_ACTION_APPEND,
	NFACCT_ACTION_DELETE,
	NFACCT_ACTION_INSERT,
	NFACCT_ACTION_LAST_ELEM,
} nfacct_rule_action;

typedef enum {
	NFACCT_JUMP_UNKNOWN,
	NFACCT_JUMP_ACCEPT,
	NFACCT_JUMP_REJECT,
	NFACCT_JUMP_LAST_ELEM,
} nfacct_rule_jump;

typedef enum {
	NFACCT_COUNTER,
	NFACCT_WARN,
	NFACCT_BLOCK,
	NFACCT_TETH_COUNTER,
	NFACCT_RULE_LAST_ELEM,
} nfacct_rule_intend;

enum nfnl_acct_flags {
        NFACCT_F_QUOTA_PKTS     = (1 << 0),
        NFACCT_F_QUOTA_BYTES    = (1 << 1),
        NFACCT_F_OVERQUOTA      = (1 << 2), /* can't be set from userspace */
};

/* it's better to have
 * base nfacct_rule with following fields:
 *  name, ifname, pid, classid, iftype, intend, carg, iptables_rule
 *
 *  and inherited nfacct_rule_counter and nfacct_rule_restriction
 *  with additional field:
 *	quota, quota_id, roaming, rst_state
 *
 * But ANSI C doesn't support inheritance.
 */
struct nfacct_rule {
	char name[MAX_NAME_LENGTH];
	char ifname[MAX_IFACE_LENGTH];

	pid_t pid;
	u_int32_t classid;
	resourced_iface_type iftype;
	nfacct_rule_direction iotype;
	nfacct_rule_intend intend;
	struct counter_arg *carg;
	resourced_ret_c(*iptables_rule)(struct nfacct_rule *counter);
	u_int64_t quota;
	int quota_id;
	resourced_roaming_type roaming;
	resourced_restriction_state rst_state;
};

struct counter_arg;

void generate_counter_name(struct nfacct_rule *counter);
bool recreate_counter_by_name(char *cnt_name, struct nfacct_rule *counter);

resourced_ret_c nfacct_send_get_all(struct counter_arg *carg);
resourced_ret_c nfacct_send_get_counters(struct counter_arg *carg,
					 const char *name);
resourced_ret_c nfacct_send_get(struct nfacct_rule *rule);
resourced_ret_c nfacct_send_del(struct nfacct_rule *counter);
resourced_ret_c nfacct_send_initiate(struct counter_arg *carg);

resourced_ret_c exec_iptables_cmd(const char *cmd_buf, pid_t *pid);
resourced_ret_c produce_net_rule(struct nfacct_rule *rule,
			const int send_limit, const int rcv_limit,
			const nfacct_rule_action action,
			const nfacct_rule_jump jump,
			const nfacct_rule_direction iotype);

#endif /* _RESOURCED_NFACCT_RULE_H */

