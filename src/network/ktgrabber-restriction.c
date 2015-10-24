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
 * @file net-restriction.c
 *
 * @desc Kernel communication routins for bloking network traffic based on
 *	netlink protocol.
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <errno.h>
#include <glib.h>
#include <sys/socket.h>		/*should be before linux/netlink */
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/netlink.h>	/*nlmsghdr */
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>

#include "resourced.h"
#include "generic-netlink.h"
#include "iface.h"
#include "macro.h"
#include "netlink-restriction.h"
#include "nl-helper.h"
#include "trace.h"

static const char kind_name[] = "htb";

struct rst_context {
	int sock;
	int family_id;
	pid_t pid;
};

struct nf_arg {
	u_int32_t classid;
	enum traffic_restriction_type restriction_type;
	resourced_iface_type iftype;
	int error;
	struct rst_context *context;
	int send_limit;
	int rcv_limit;
	int snd_warning_threshold;
	int rcv_warning_threshold;
};

static struct rst_context context;

#if 0

static int send_nl_msg(int sock, pid_t pid, const rt_param *arg)
{
	struct sockaddr_nl nladdr = { 0, };
	struct iovec iov = { 0, };
	struct msghdr msg = { 0, };
	int ret = 0;

	if (!arg)
		return -1;

	iov.iov_base = (void *)(&(arg->n));
	iov.iov_len = arg->n.nlmsg_len;

	msg.msg_name = &nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = pid;
	nladdr.nl_groups = 0;

	ret = sendmsg(sock, &msg, 0);
	if (ret < 0)
		return -errno;
	return ret;
}

static int fill_netlink_argument(u_int32_t classid, u_int32_t *seq,
				 int command, int flags, rt_param *argument)
{
	if (!argument)
		return -1;

	memset(argument, 0, sizeof(rt_param));

	argument->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	argument->n.nlmsg_flags = flags;
	argument->n.nlmsg_type = command;
	argument->n.nlmsg_seq = ++(*seq);
	argument->t.tcm_family = AF_UNSPEC;
	argument->t.tcm_handle = classid;
	argument->t.tcm_parent = TC_H_ROOT;
	argument->t.tcm_ifindex = 2;	/*TODO: use iface by sysctl
		termination, hardcoded eth0 */
	return 0;
}

static void add_htb_param(rt_param *arg)
{
	struct tc_htb_glob opt = { 0, };
	struct rtattr *tail = 0;

	opt.rate2quantum = 1;
	opt.version = 3;

	put_attr(arg, TCA_KIND, kind_name, sizeof(kind_name) + 1);
	tail = NLMSG_TAIL(&arg->n);
	put_attr(arg, TCA_OPTIONS, NULL, 0);
	put_attr(arg, TCA_HTB_INIT, &opt, NLMSG_ALIGN(sizeof(opt)));
	/*I don't know why but it present in TC */
	tail->rta_len = (void *)NLMSG_TAIL(&arg->n) - (void *)tail;
}

static u_int32_t strict_classid(u_int32_t classid)
{
	return classid & 0xFFFF0000;	/* number: in TC termins */
}

static int add_root_qdisc(int sock, u_int32_t *seq, pid_t pid)
{
	rt_param arg;
	fill_netlink_argument(0, seq, RTM_NEWQDISC,
			      NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE, &arg);
	return send_nl_msg(sock, pid, &arg);
}

/*Create root queue discipline and create base queue discipline*/
static int add_qdisc(int sock, u_int32_t *seq, pid_t pid, u_int32_t classid)
{
	rt_param arg;
	fill_netlink_argument(classid, seq, RTM_NEWQDISC,
			      NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE, &arg);
	add_htb_param(&arg);
	arg.t.tcm_handle = strict_classid(classid);
	return send_nl_msg(sock, pid, &arg);
}

/*At present we support only one type of class*/
static int add_class(int sock, u_int32_t *seq, pid_t pid, u_int32_t classid,
		     int rate_limit)
{
	rt_param arg;
	fill_netlink_argument(classid, seq, RTM_NEWTCLASS,
			      NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE, &arg);
	return send_nl_msg(sock, pid, &arg);
}

/*At present we support only one type of filter by cgroup*/
static int add_filter(int sock, u_int32_t *seq, pid_t pid, u_int32_t classid)
{
	rt_param arg;
	fill_netlink_argument(classid, seq, RTM_NEWTFILTER,
			      NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE, &arg);
	return send_nl_msg(sock, pid, &arg);
}
#endif

static resourced_ret_c send_nf_restriction(int ifindex, resourced_iface_type iftype,
	void *data)
{
	struct nf_arg *nfarg = data;

	if (!nfarg)
		return RESOURCED_ERROR_FAIL;

	/* use netfilter (ktgrabber) approach */
	if (nfarg->iftype == iftype) {
		_D("Sending restriction to kernel:"\
		" classid %d, ifindex %d, iftype %d, rest_type %d "\
		" rcv %d, snd %d",
		nfarg->classid, ifindex, iftype, nfarg->restriction_type,
		nfarg->rcv_limit, nfarg->send_limit);

		if (send_restriction(nfarg->context->sock, nfarg->context->pid,
			nfarg->context->family_id, nfarg->classid,
			ifindex, nfarg->restriction_type,
			nfarg->send_limit,
			nfarg->rcv_limit,
			nfarg->snd_warning_threshold,
			nfarg->rcv_warning_threshold) < 0) {
			_E("Failed to sent restriction to kernel");
			nfarg->error = errno;
		}
	}

	return RESOURCED_ERROR_NONE;
}

static gboolean send_each_restriction(gpointer key, gpointer value, gpointer data)
{
	return send_nf_restriction((int)key,
		*(resourced_iface_type *)(value), data) == RESOURCED_ERROR_NONE ?
		FALSE /* Glib continue iteration */ : TRUE;
}

static resourced_ret_c init_restriction_context(void)
{
	if (context.sock)
		return 0;

	context.sock = create_netlink(NETLINK_GENERIC, 0);

	if (context.sock < 0) {
		_D("Failed to create and bind netlink socket.");
		return RESOURCED_ERROR_FAIL;
	}

	context.family_id = get_family_id(context.sock,
		context.pid, "TRAF_STAT");

	if (context.family_id < 0) {
		_D("Failed to get family id.");
		return RESOURCED_ERROR_FAIL;
	}

	context.pid = getpid(); /* for user/kernel space communication */
	return RESOURCED_ERROR_NONE;
}

int send_net_restriction(const enum traffic_restriction_type rst_type,
			 const u_int32_t classid, const int UNUSED quota_id,
			 const resourced_iface_type iftype,
			 const int send_limit, const int rcv_limit,
			 const int snd_warning_threshold,
			 const int rcv_warning_threshold,
			 const char UNUSED *ifname)
{
	struct nf_arg nfarg;

	/* initialize context variables */
	if (init_restriction_context() < 0)
		return RESOURCED_ERROR_FAIL;

	/* emulate old behaviour, no iftype mean block all network interfaces */
	if (iftype == RESOURCED_IFACE_UNKNOWN ||
	    iftype == RESOURCED_IFACE_ALL) {
		_D("Sending restriction to kernel: classid %d, ifindex %d "
		   "iftype %d, restriction_type %d, rcv %d, snd %d\n",
		   classid, RESOURCED_ALL_IFINDEX, iftype, rst_type,
		   send_limit, rcv_limit);
		return send_restriction(context.sock, context.pid,
					context.family_id, classid,
					RESOURCED_ALL_IFINDEX, rst_type,
					send_limit, rcv_limit,
					snd_warning_threshold,
					rcv_warning_threshold);
	}

	nfarg.context = &context;
	nfarg.error = 0;
	nfarg.restriction_type = rst_type;
	nfarg.iftype = iftype;
	nfarg.classid = classid;
	nfarg.send_limit = send_limit;
	nfarg.rcv_limit = rcv_limit;
	nfarg.snd_warning_threshold = snd_warning_threshold;
	nfarg.rcv_warning_threshold = rcv_warning_threshold;

	/* apply a given type of restriction for each network
	   interface of the given network type */
	init_iftype();
	for_each_ifindex((ifindex_iterator)send_each_restriction, NULL, &nfarg);
	return nfarg.error;
}
