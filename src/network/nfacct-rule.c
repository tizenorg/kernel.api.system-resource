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

/**
 * @file nfacct-rule.c
 *
 * @desc Datausage module
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "const.h"
#include "counter.h"
#include "iface.h"
#include "macro.h"
#include "module-data.h"
#include "nfacct-rule.h"
#include "nl-helper.h"
#include "resourced.h"
#include "trace.h"

#define IPTABLES "/usr/sbin/iptables"
#define IPTABLES_CHECK "-C"
#define APPEND "-A"
#define DELETE "-D"
#define INSERT "-I"

#define NFACCT_NAME_MOD " -m nfacct --nfacct-name %s"
#define REJECT_RULE " -j REJECT"
#define ACCEPT_RULE " -j ACCEPT"

/* TODO idea to use the same rule both for BLOCK (REJECT) and WARNING (ACCEPT) */
#define RULE_APP_OUT "%s -w %s OUTPUT -o %s -m cgroup --cgroup %u %s %s"
#define RULE_APP_IN "%s -w %s INPUT -i %s -m cgroup --cgroup %u %s %s"

#define RULE_IFACE_OUT "%s -w %s OUTPUT -o %s %s -m cgroup ! --cgroup 0 %s"
#define RULE_IFACE_IN "%s -w %s INPUT -i %s %s -m cgroup ! --cgroup 0 %s"

#define NFNL_SUBSYS_ACCT                7

enum nfnl_acct_flags {
        NFACCT_F_QUOTA_PKTS     = (1 << 0),
        NFACCT_F_QUOTA_BYTES    = (1 << 1),
        NFACCT_F_OVERQUOTA      = (1 << 2), /* can't be set from userspace */
};

static void prepare_netlink_msg(struct genl *req, int type, int flag)
{
	int seq = time(NULL);
	memset(req, 0, sizeof(struct genl));
	req->n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req->n.nlmsg_type = (NFNL_SUBSYS_ACCT << 8) | type;
	req->n.nlmsg_flags = NLM_F_REQUEST | flag;
	req->n.nlmsg_seq = seq;
}

static void add_value_attr(struct genl *req, const void *data, int len, int type)
{
	int payload;
	/* get tail */
	struct nlattr *na = (struct nlattr *)(
		 (char *)req + NLMSG_ALIGN(req->n.nlmsg_len));

	na->nla_type = type;
	payload = len + NLA_HDRLEN;
	na->nla_len = payload;
	memcpy(NLA_DATA(na), data, len);
	req->n.nlmsg_len += NLMSG_ALIGN(payload);
}

/*
 * following 2 function should be used in combination.
 * start_nest_attr returns nlattr structure, which should be completed by
 * end_nest_attr,
 * before these invocations any number of netlink arguments could be inserted
 * */
static struct nlattr *start_nest_attr(struct genl *req, uint16_t type)
{
	struct nlattr *start = (struct nlattr *)(
		 (char *)req + NLMSG_ALIGN(req->n.nlmsg_len));

        start->nla_type = NLA_F_NESTED | type;
        req->n.nlmsg_len += NLMSG_ALIGN(sizeof(struct nlattr));
        return start;
}

static void end_nest_attr(struct genl *req, struct nlattr *start)
{
	start->nla_len = (__u16)(
		 (char *)req + NLMSG_ALIGN(req->n.nlmsg_len) - (char *)start);
}

static void add_string_attr(struct genl *req, const char *str, int type)
{
	add_value_attr(req, str, strlen(str) + 1, type);
}

static void add_uint64_attr(struct genl *req, const uint64_t v, int type)
{
	add_value_attr(req, &v, sizeof(v), type);
}

/* macros or templare, due uint64 and uint32 is the same functions */
static void add_uint32_attr(struct genl *req, const uint32_t v, int type)
{
	add_value_attr(req, &v, sizeof(v), type);
}

static resourced_ret_c send_nfacct_request(int sock, struct genl *req)
{
	struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
	int ret = sendto(sock, (char *)(&req->n), req->n.nlmsg_len, 0,
		      (struct sockaddr *)&nladdr, sizeof(nladdr));
	ret_value_msg_if(ret < 0, RESOURCED_ERROR_FAIL,
			"Failed to send command to get outgoing traffic");

	return RESOURCED_ERROR_NONE;
}

static resourced_ret_c nfacct_send_new(struct nfacct_rule *counter)
{
	struct genl req;

	prepare_netlink_msg(&req, NFNL_MSG_ACCT_NEW, NLM_F_CREATE | NLM_F_ACK);
	add_string_attr(&req, counter->name, NFACCT_NAME);
	_D("counter name %s", counter->name);
	/* padding */
	add_uint64_attr(&req, 0, NFACCT_PKTS);
	add_uint64_attr(&req, 0, NFACCT_BYTES);
	if (counter->quota) {
		_D("quota bytes %"PRId64, counter->quota);
		add_uint32_attr(&req, htobe32(NFACCT_F_QUOTA_BYTES), NFACCT_FLAGS);
		add_uint64_attr(&req, htobe64(counter->quota), NFACCT_QUOTA);
	}

	return send_nfacct_request(counter->carg->sock, &req);
}

static resourced_ret_c nfacct_send_del(struct nfacct_rule *counter)
{
	struct genl req;

	prepare_netlink_msg(&req, NFNL_MSG_ACCT_DEL, NLM_F_ACK);
	add_string_attr(&req, counter->name, NFACCT_NAME);
	return send_nfacct_request(counter->carg->sock, &req);
}
#define NFACCT_F_QUOTAS (NFACCT_F_QUOTA_BYTES | NFACCT_F_QUOTA_PKTS)
resourced_ret_c nfacct_send_get(struct counter_arg *carg)
{
	struct genl req;
	struct nlattr *na;
	prepare_netlink_msg(&req, NFNL_MSG_ACCT_GET_CTRZERO,
		NLM_F_DUMP);
	/* due we don't get counter with quota any where else,
	* here we will request just counters by default */
	na = start_nest_attr(&req, NFACCT_FILTER);
	add_uint32_attr(&req, NFACCT_F_QUOTAS,
		NFACCT_FILTER_ATTR_MASK);
	add_uint32_attr(&req, 0, NFACCT_FILTER_ATTR_VALUE);
	end_nest_attr(&req, na);
	return send_nfacct_request(carg->sock, &req);
}

resourced_ret_c nfacct_send_initiate(struct counter_arg *carg)
{
	struct genl req;
	prepare_netlink_msg(&req, NFNL_MSG_ACCT_GET,
		NLM_F_DUMP);
	return send_nfacct_request(carg->sock, &req);
}

static nfacct_rule_direction convert_to_iotype(int type)
{
	return type < NFACCT_COUNTER_LAST_ELEM && type > NFACCT_COUNTER_UNKNOWN ?
		type : NFACCT_COUNTER_UNKNOWN;
}

static resourced_iface_type convert_to_iftype(int type)
{
	return type < RESOURCED_IFACE_LAST_ELEM && type > RESOURCED_IFACE_UNKNOWN ?
		type : RESOURCED_IFACE_UNKNOWN;
}

bool recreate_counter_by_name(char *cnt_name, struct nfacct_rule *cnt)
{
	char *iftype_part;
	char *classid_part;
	char *io_part;
	char *ifname_part;

	switch (cnt_name[0]) {
	case 'c':
		cnt->intend  = NFACCT_COUNTER;
		break;
	case 'w':
		cnt->intend  = NFACCT_WARN;
		break;
	case 'r':
		cnt->intend  = NFACCT_BLOCK;
		break;
	default:
		return false;
	}

	io_part = strtok(cnt_name, "_");
	if (io_part != NULL)
		cnt->iotype = convert_to_iotype(atoi(io_part + 1));
	else
		return false;

	iftype_part = strtok(NULL, "_");
	if (iftype_part != NULL)
		cnt->iftype = convert_to_iftype(atoi(iftype_part));
	else
		return false;

	classid_part = strtok(NULL, "_");
	if (classid_part != NULL)
		cnt->classid = atoi(classid_part);
	else {
		cnt->classid = RESOURCED_ALL_APP_CLASSID;
		return cnt->intend == NFACCT_BLOCK ? true : false;
	}

	ifname_part = strtok(NULL, "\0");
	if (ifname_part != NULL)
		STRING_SAVE_COPY(cnt->ifname, ifname_part);
	else
		return false;

	return true;
}

static void _process_answer(struct netlink_serialization_params *params)
{
	struct rtattr *na;
	struct rtattr *attr_list[__NFACCT_MAX] = {0};
	struct counter_arg *carg = params->carg;
	struct genl *ans = params->ans;;
	struct nlmsghdr *nlhdr = &ans->n;
	int len = GENLMSG_PAYLOAD(nlhdr);
	int ans_len = carg->ans_len;

	if (len == 0)
		return;

	/* parse reply message */
	na = (struct rtattr *)GENLMSG_DATA(ans);

	while (NLMSG_OK(nlhdr, ans_len )) {

		fill_attribute_list(attr_list, NFACCT_MAX,
			na, len);
		if (!attr_list[NFACCT_NAME] ||
			!attr_list[NFACCT_BYTES])
			goto next;
		params->eval_attr(attr_list, carg);

next:
		nlhdr = NLMSG_NEXT(nlhdr, ans_len);
		if (ans_len < 0)
			break;
		na = (struct rtattr *)GENLMSG_DATA(nlhdr);
	}

	if (params->post_eval_attr)
		params->post_eval_attr(carg);
}

netlink_serialization_command *netlink_create_command(
	struct netlink_serialization_params *params)
{
	static netlink_serialization_command command = {0,};
	command.deserialize_answer = _process_answer;
	command.params = *params;
	return &command;
}

static unsigned int get_args_number(const char *cmd_buf)
{
	char *str;
	unsigned int count = 0;

	for (str = (char *)cmd_buf; *str != '\0'; ++str) {
		if (*str == ' ')
			++count;
	}
	return count;
}

static void wait_for_rule_cmd(struct nfacct_rule *rule, pid_t pid)
{
	int status;
	pid_t ret_pid = waitpid(pid, &status, 0);
	if (ret_pid < 0)
		_D("can't wait for a pid %d %d %s", pid, status, strerror(errno));
}

static char* get_cmd_pos(const char *cmd_buf)
{
	char *cmd_pos = strstr(cmd_buf, APPEND);
	if (!cmd_pos)
		cmd_pos = strstr(cmd_buf, INSERT);

	return cmd_pos;
}

static bool is_rule_exists(const char *cmd_buf)
{
	size_t buf_len;
	char *exec_buf;
	char *cmd_pos = get_cmd_pos(cmd_buf);
	bool ret = false;
	if (!cmd_pos)
		return false;

	buf_len = strlen(cmd_buf) + 1;
	exec_buf = (char *)malloc(buf_len);
	if (!exec_buf)
		return false;

	strncpy(exec_buf, cmd_buf, buf_len);
	strncpy(exec_buf + (cmd_pos - cmd_buf), IPTABLES_CHECK,
		sizeof(IPTABLES_CHECK) - 1);
	_D("check rule %s", exec_buf);
	ret = system(exec_buf) == 0;
	free(exec_buf);
	return ret;
}

resourced_ret_c exec_iptables_cmd(const char *cmd_buf, pid_t *cmd_pid)
{
	pid_t pid = fork();

	if (pid == 0) {
		char *cmd;
		unsigned int i;
		const size_t args_number = get_args_number(cmd_buf);
		char *args[args_number + 2];
		int ret;

		_D("executing iptables cmd %s in forked process", cmd_buf);
		ret_value_msg_if(args_number == 0, RESOURCED_ERROR_FAIL, "no arguments");

		if (is_rule_exists(cmd_buf)) {
			_D("Rule %s already exists", cmd_buf);
			exit(0);
		}
		args[0] = "iptables";
		cmd = strtok((char *)cmd_buf, " ");
		for (i = 1; i <= args_number; ++i) {
			args[i] = strtok(NULL, " ");
		}
		args[i] = NULL;

		ret = execv(cmd, args);
		if (ret)
			_E("Can't execute %s: %s",
				cmd_buf, strerror(errno));
		exit(ret);
	}

	*cmd_pid = pid;
	return RESOURCED_ERROR_NONE;
}

static char *choose_iftype_name(struct nfacct_rule *rule)
{
	return strlen(rule->ifname) != 0 ? rule->ifname :
			get_iftype_name(rule->iftype);
}

static resourced_ret_c exec_iface_cmd(const char *pattern, const char *cmd,
		const char *nfacct, const char *jump,
		char *iftype_name, pid_t *pid)
{
	char block_buf[MAX_PATH_LENGTH];
	int ret;

	ret_value_msg_if(iftype_name == NULL, RESOURCED_ERROR_FAIL,
		"Invalid network interface name argument");

	ret = sprintf(block_buf, pattern, IPTABLES, cmd,
		iftype_name, nfacct, jump);
	ret_value_msg_if(ret > sizeof(block_buf), RESOURCED_ERROR_NONE,
		"Not enough buffer");
	return exec_iptables_cmd(block_buf, pid);
}

static resourced_ret_c exec_app_cmd(const char *pattern, const char *cmd,
		const char *nfacct, const char *jump,
		const u_int32_t classid, char *iftype_name,
		pid_t *pid)
{
	char block_buf[MAX_PATH_LENGTH];
	int ret;
	ret_value_msg_if(iftype_name == NULL, RESOURCED_ERROR_FAIL,
		"Invalid network interface name argument");
	ret = sprintf(block_buf, pattern, IPTABLES, cmd,
		iftype_name, classid, nfacct, jump);
	ret_value_msg_if(ret > sizeof(block_buf), RESOURCED_ERROR_NONE,
		"Not enough buffer");
	return exec_iptables_cmd(block_buf, pid);
}

static char *get_iptables_cmd(const nfacct_rule_action action)
{
	if (action == NFACCT_ACTION_APPEND)
		return APPEND;
	else if(action == NFACCT_ACTION_DELETE)
		return DELETE;
	else if (action == NFACCT_ACTION_INSERT)
		return INSERT;

	return "";
}

static char *get_iptables_jump(const nfacct_rule_jump jump)
{
	if (jump == NFACCT_JUMP_ACCEPT)
		return ACCEPT_RULE;
	else if (jump == NFACCT_JUMP_REJECT)
		return REJECT_RULE;

	return "";
}

static resourced_ret_c produce_app_rule(struct nfacct_rule *rule,
			const int send_limit, const int rcv_limit,
			const nfacct_rule_action action,
			const nfacct_rule_jump jump,
			const nfacct_rule_direction iotype)
{
	char *set_cmd = get_iptables_cmd(action);
	char *jump_cmd = get_iptables_jump(jump);
	char nfacct_buf[sizeof(NFACCT_NAME_MOD) +
		3*MAX_DEC_SIZE(int) + 4];
	resourced_ret_c ret = RESOURCED_ERROR_NONE;
	pid_t pid = 0;

	/* income part */
	if (iotype & NFACCT_COUNTER_IN) {
		rule->quota = rcv_limit;
		rule->iotype = NFACCT_COUNTER_IN;
		generate_counter_name(rule);

		/* to support quated counter we need nfacct,
		 *	don't use it in case of just block without a limit
		 *	iow, send_limit = 0 and rcv_limit 0 */
		if (action != NFACCT_ACTION_DELETE) {
			ret = nfacct_send_new(rule);
			ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"can't set nfacct counter");
		}

		/* we have a counter, let's key in a rule, drop in case of
		 *  send_limit/rcv_limit */
		ret = snprintf(nfacct_buf, sizeof(nfacct_buf), NFACCT_NAME_MOD,
			rule->name);
		ret = exec_app_cmd(RULE_APP_IN, set_cmd, nfacct_buf,
			jump_cmd, rule->classid, choose_iftype_name(rule), &pid);
		ret_value_msg_if(ret != RESOURCED_ERROR_NONE,
			RESOURCED_ERROR_FAIL, "Can't set conditional block for ingress"
				" traffic, for classid %u, cmd %s, j %s",
				rule->classid, set_cmd, jump_cmd);

		/* remove in any case */
		if (action != NFACCT_ACTION_APPEND) {
			/* TODO here and everywhere should be not just a del,
			 *	here should be get counted value and than
			 *	set new counter with that value, but it's minor issue,
			 *	due it's not clear when actual counters was stored,
			 *	and based on which value settings made such decition */
			wait_for_rule_cmd(rule, pid);
			ret = nfacct_send_del(rule);
			ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"can't set nfacct counter");
		}
	}

	if (iotype & NFACCT_COUNTER_OUT) {
		/* outcome part */
		rule->iotype = NFACCT_COUNTER_OUT;
		rule->quota = send_limit;
		generate_counter_name(rule);
		if (action != NFACCT_ACTION_DELETE) {
			ret = nfacct_send_new(rule);
			ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"can't set quota counter");
		}

		ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
			"can't set counter");

		ret = snprintf(nfacct_buf, sizeof(nfacct_buf), NFACCT_NAME_MOD,
			rule->name);
		ret = exec_app_cmd(RULE_APP_OUT, set_cmd, nfacct_buf,
			jump_cmd, rule->classid, choose_iftype_name(rule), &pid);
		ret_value_msg_if(ret != RESOURCED_ERROR_NONE,
			RESOURCED_ERROR_FAIL, "Can't set conditional block for engress"
				" traffic, for classid %u, cmd %s, j %s",
				rule->classid, set_cmd, jump_cmd);
		if (action != NFACCT_ACTION_APPEND) {
			wait_for_rule_cmd(rule, pid);
			ret = nfacct_send_del(rule);
			ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"can't del nfacct counter");
		}
	}
	return RESOURCED_ERROR_NONE;
}

static resourced_ret_c produce_iface_rule(struct nfacct_rule *rule,
			const int send_limit, const int rcv_limit,
			const nfacct_rule_action action,
			const nfacct_rule_jump jump,
			const nfacct_rule_direction iotype)
{
	char *set_cmd = get_iptables_cmd(action);
	char *jump_cmd = get_iptables_jump(jump);
	char nfacct_buf[sizeof(NFACCT_NAME_MOD) +
		3*MAX_DEC_SIZE(int) + 4];
	resourced_ret_c ret;
	pid_t pid = 0;

	if (iotype & NFACCT_COUNTER_IN) {
		/* income part */
		rule->quota = rcv_limit;
		rule->iotype = NFACCT_COUNTER_IN;
		generate_counter_name(rule);

		if (action != NFACCT_ACTION_DELETE) {
			ret = nfacct_send_new(rule);
			ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"can't set quota counter");
		}

		ret = snprintf(nfacct_buf, sizeof(nfacct_buf),
			NFACCT_NAME_MOD, rule->name);
		ret_value_msg_if(ret < 0, RESOURCED_ERROR_FAIL,
				"Not enought buffer");

		ret = exec_iface_cmd(RULE_IFACE_IN, set_cmd, nfacct_buf,
			jump_cmd, choose_iftype_name(rule), &pid);
		ret_value_msg_if(ret != RESOURCED_ERROR_NONE,
			RESOURCED_ERROR_NONE, "Can't set conditional block for ingress"
				" traffic, for iftype %d, cmd %s, j %s",
				rule->iftype, set_cmd, jump_cmd);

		if (action != NFACCT_ACTION_APPEND) {
			wait_for_rule_cmd(rule, pid);
			ret = nfacct_send_del(rule);
			ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"can't set quota counter");
		}
	}

	if (iotype & NFACCT_COUNTER_OUT) {
		/* outcome part */
		rule->iotype = NFACCT_COUNTER_OUT;
		rule->quota = send_limit;
		generate_counter_name(rule);

		if (action != NFACCT_ACTION_DELETE) {
			ret = nfacct_send_new(rule);
			ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"can't set quota counter");
		}

		ret = snprintf(nfacct_buf, sizeof(nfacct_buf),
				NFACCT_NAME_MOD, rule->name);
		ret_value_msg_if(ret < 0, RESOURCED_ERROR_FAIL,
				"Not enough buffer");

		ret = exec_iface_cmd(RULE_IFACE_OUT, set_cmd, nfacct_buf,
			jump_cmd, choose_iftype_name(rule), &pid);
		ret_value_msg_if(ret != RESOURCED_ERROR_NONE,
			RESOURCED_ERROR_FAIL, "Can't set conditional block for "
				" engress traffic, for iftype %d, cmd %s, j %s",
				rule->iftype, set_cmd, jump_cmd);

		if (action != NFACCT_ACTION_APPEND) {
			wait_for_rule_cmd(rule, pid);
			ret = nfacct_send_del(rule);
			ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
				"can't set quota counter");
		}
	}
	return RESOURCED_ERROR_NONE;
}

resourced_ret_c produce_net_rule(struct nfacct_rule *rule,
			const int send_limit, const int rcv_limit,
			const nfacct_rule_action action,
			const nfacct_rule_jump jump,
			const nfacct_rule_direction iotype)
{
	resourced_ret_c ret = RESOURCED_ERROR_NONE;

	if (action == NFACCT_ACTION_APPEND && rule->intend == NFACCT_WARN
		&& !send_limit && !rcv_limit)
		return RESOURCED_ERROR_NONE;

	if (rule->classid != RESOURCED_ALL_APP_CLASSID)
		ret = produce_app_rule(rule, send_limit,
			               rcv_limit, action, jump,
				       iotype);
	else
		ret = produce_iface_rule(rule, send_limit, rcv_limit,
					 action, jump, iotype);

	return ret;
}

void generate_counter_name(struct nfacct_rule *counter)
{
	char warn_symbol = 'c';
	char *iftype_name = get_iftype_name(counter->iftype);
	ret_msg_if(iftype_name == NULL, "Can't get interface name!");
	STRING_SAVE_COPY(counter->ifname, iftype_name);

	if (counter->intend  == NFACCT_WARN)
		warn_symbol = 'w';
	else if (counter->intend  == NFACCT_BLOCK)
		warn_symbol = 'r';
	if (counter->classid != RESOURCED_ALL_APP_CLASSID)
		snprintf(counter->name, MAX_NAME_LENGTH, "%c%d_%d_%d_%s",
			warn_symbol, counter->iotype, counter->iftype,
			counter->classid, counter->ifname);
	else
		snprintf(counter->name, MAX_NAME_LENGTH, "%c%d_%d_%s",
			warn_symbol, counter->iotype, counter->iftype,
			counter->ifname);

	}

