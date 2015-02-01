/*
 * resourced
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file nfacct-restriction.c
 *
 * @desc Implementation for set up/down restrictions.
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "const.h"
#include "datausage-common.h"
#include "stdlib.h"
#include "macro.h"
#include "module-data.h"
#include "netlink-restriction.h"
#include "nfacct-rule.h"
#include "resourced.h"
#include "trace.h"

static resourced_ret_c apply_net_restriction(struct nfacct_rule *rule,
			const int send_limit, const int rcv_limit)
{
	nfacct_rule_jump jump = rule->intend == NFACCT_WARN ? NFACCT_JUMP_ACCEPT :
			NFACCT_JUMP_REJECT;

	return produce_net_rule(rule, send_limit, rcv_limit,
		NFACCT_ACTION_APPEND, jump,
		NFACCT_COUNTER_IN | NFACCT_COUNTER_OUT);
}

static resourced_ret_c revert_net_restriction(struct nfacct_rule *rule,
			 const int send_limit, const int rcv_limit)
{
	nfacct_rule_jump jump = rule->intend == NFACCT_WARN ? NFACCT_JUMP_ACCEPT :
			NFACCT_JUMP_REJECT;

	return produce_net_rule(rule, send_limit, rcv_limit,
		NFACCT_ACTION_DELETE, jump,
		NFACCT_COUNTER_IN | NFACCT_COUNTER_OUT);

}

static resourced_ret_c exclude_net_restriction(struct nfacct_rule *rule)
{
	/* Idea to remove old counter and insert new one at first position
	 * iptables has following architecture: it gets all entries from kernel
	 * modifies this list and returns it back, without iptables it could be
	 * done for one step, but with iptables cmd 2 steps is necessary */
	rule->intend = NFACCT_COUNTER;
	resourced_ret_c ret = produce_net_rule(rule, 0, 0,
		NFACCT_ACTION_DELETE, NFACCT_JUMP_UNKNOWN,
		NFACCT_COUNTER_IN | NFACCT_COUNTER_OUT);

	ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret, "Failed to delete");

	return produce_net_rule(rule, 0, 0,
		NFACCT_ACTION_INSERT, NFACCT_JUMP_ACCEPT,
		NFACCT_COUNTER_IN | NFACCT_COUNTER_OUT);
}

resourced_ret_c send_net_restriction(const enum traffic_restriction_type rst_type,
			 const u_int32_t classid,
			 const resourced_iface_type iftype,
			 const int send_limit, const int rcv_limit,
			 const int snd_warning_threshold,
			 const int rcv_warning_threshold)
{
	int ret;
	struct shared_modules_data *m_data = get_shared_modules_data();
	struct counter_arg *carg;
	struct nfacct_rule rule = {
		.name = {0},
		.ifname = {0},
		0,
	};

	ret_value_msg_if(m_data == NULL, RESOURCED_ERROR_FAIL, "Empty shared modules data");

	carg = m_data->carg;
	ret_value_msg_if(carg == NULL, RESOURCED_ERROR_FAIL, "Empty counter");


	rule.classid = classid;
	rule.iftype = iftype;
	rule.carg = carg;

	if (rst_type == RST_SET) {
		if (snd_warning_threshold ||
			rcv_warning_threshold) {
			rule.intend = NFACCT_WARN;
			ret = apply_net_restriction(&rule,
				snd_warning_threshold, rcv_warning_threshold);
			ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"Can't apply network restriction");
		}
		rule.intend = NFACCT_BLOCK;
		ret = apply_net_restriction(&rule, send_limit, rcv_limit);
		ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"Can't apply network restriction");
	} else if (rst_type == RST_UNSET) {
		rule.intend = NFACCT_WARN;
		ret = revert_net_restriction(&rule,
			snd_warning_threshold, rcv_warning_threshold);
		ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
			"Can't revert network restriction");
		rule.intend = NFACCT_BLOCK;
		return revert_net_restriction(&rule, send_limit,
			rcv_limit);
	} else if (rst_type == RST_EXCLUDE)
		return exclude_net_restriction(&rule);

	return RESOURCED_ERROR_NONE;
}
