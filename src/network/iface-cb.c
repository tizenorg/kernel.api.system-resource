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
 * @file iface-cb.c
 *
 * @desc Network interface callbacks entity
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "macro.h"
#include "datausage-common.h"
#include "restriction-handler.h"
#include "settings.h"
#include "storage.h"
#include "trace.h"

#include <Ecore.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h> /*for netlink.h*/
#include <sys/types.h>
#include <unistd.h>

#define ADDR_EVENT_BUF_LEN 4096
static int iface_fd;

static iface_callbacks *ifcallbacks;
static Ecore_Fd_Handler *iface_ecore_fd_handler;

static iface_callbacks *create_iface_callback(void)
{
	iface_callbacks *callbacks = NULL;
	gpointer callback_data = create_restriction_callback();

	if (callback_data)
		callbacks = g_list_prepend(callbacks, callback_data);
	callback_data = create_iface_storage_callback();
	if (callback_data)
		callbacks = g_list_prepend(callbacks, callback_data);
	callback_data = create_counter_callback();
	if (callback_data)
		callbacks = g_list_prepend(callbacks, callback_data);

	return callbacks;
}

static void _iface_up_iter(gpointer data, gpointer user_data)
{
	iface_callback *arg = (iface_callback *)data;
	uint32_t ifindex = *(uint32_t *) (user_data);
	if (arg && arg->handle_iface_up)
		arg->handle_iface_up(ifindex);
}

static void _iface_down_iter(gpointer data, gpointer user_data)
{
	iface_callback *arg = (iface_callback *)data;
	uint32_t ifindex = *(uint32_t *)(user_data);
	if (arg && arg->handle_iface_down)
		arg->handle_iface_down(ifindex);
}

static void process_nlh(int len, const struct nlmsghdr *nlh,
				iface_callbacks *arg)
{
	if (!arg) {
		_D("Please provide valid argument!");
		return;
	}

	for (; (NLMSG_OK(nlh, len)) &&
		(nlh->nlmsg_type != NLMSG_DONE);
		nlh = NLMSG_NEXT(nlh, len)) {
		if (nlh->nlmsg_type != RTM_NEWADDR
			&& nlh->nlmsg_type != RTM_DELADDR)
			continue;

		struct ifaddrmsg *ifa =
			(struct ifaddrmsg *) NLMSG_DATA(nlh);
		struct rtattr *rth = IFA_RTA(ifa);
		int rtl = IFA_PAYLOAD(nlh);

		for (; rtl && RTA_OK(rth, rtl);
			rth = RTA_NEXT(rth, rtl)) {
			if (rth->rta_type != IFA_LOCAL)
				continue;

			if (nlh->nlmsg_type == RTM_NEWADDR) {
				init_iftype();
				return g_list_foreach(arg, _iface_up_iter,
					&(ifa->ifa_index));

			} else if (nlh->nlmsg_type == RTM_DELADDR) {
				g_list_foreach(arg, _iface_down_iter,
					&(ifa->ifa_index));
				/* network delete hooks require old information,
				 * for example for get_iftype by ifindex */
				init_iftype();
				return;
			}
		}
	}
}

static Eina_Bool iface_func_cb(void *user_data, Ecore_Fd_Handler *fd_handler)
{
	char buff[ADDR_EVENT_BUF_LEN];
	struct nlmsghdr *nlh;
	iface_callbacks *localiarg = (iface_callbacks *)user_data;
	int fd;
	int len;

	if (!ecore_main_fd_handler_active_get(fd_handler, ECORE_FD_READ)) {
		_E("ecore_main_fd_handler_active_get error , return\n");
		return ECORE_CALLBACK_RENEW;
	}

	fd = ecore_main_fd_handler_fd_get(fd_handler);
	if (fd < 0) {
		_E("ecore_main_fd_handler_fd_get error");
		return ECORE_CALLBACK_RENEW;
	}

	len = read(fd, buff, ADDR_EVENT_BUF_LEN);
	if (len < 0)  {
		_E("socket read error");
		return ECORE_CALLBACK_RENEW;
	}

	nlh = (struct nlmsghdr *)buff;
	process_nlh(len, nlh, localiarg);

	return ECORE_CALLBACK_RENEW;
}

static int iface_func_init()
{
	struct sockaddr_nl addr = {0};
	int sock, error = 0, on;

	sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock == -1) {
		_E("Error creating NETLINK_ROUTE socket");
		error = errno;
		goto handle_error;
	}

	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_IPV4_IFADDR;
/* Enable address reuse */
	on = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
		_E("Error setsockopt");
		error = errno;
		goto release_socket;
	}

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		_E("Error bind socket");
		error = errno;
		goto release_socket;
	}

	_D("Socket created successfully\n");

	return sock;

release_socket:
	close(sock);
handle_error:
	return -error;
}

static void apply_iface_options(void)
{
	resourced_options options = { 0 };

	load_options(&options);
	set_wifi_allowance(options.wifi);
	set_datacall_allowance(options.datacall);
}

int resourced_iface_init(void)
{
	ifcallbacks = create_iface_callback();
	_D("Initialize network interface callbacks\n");
	ret_value_msg_if(ifcallbacks == NULL, RESOURCED_ERROR_FAIL,
			 "Error create network interface callbacks");
	iface_fd = iface_func_init();
	ret_value_msg_if(iface_fd < 0, RESOURCED_ERROR_FAIL,
			 "Can not listen network interface changes %d",
			 iface_fd);
	iface_ecore_fd_handler = ecore_main_fd_handler_add(
		iface_fd, ECORE_FD_READ, iface_func_cb,
		(void *)ifcallbacks, NULL, NULL);
	ret_value_msg_if(iface_ecore_fd_handler == NULL, RESOURCED_ERROR_FAIL,
			 "Failed to add iface callbacks\n");
	apply_iface_options();
	return RESOURCED_ERROR_NONE;
}

void resourced_iface_finalize(void)
{
	_D("Finalize network interface callbacks\n");
	ecore_main_fd_handler_del(iface_ecore_fd_handler);
	shutdown(iface_fd, 2);
	close(iface_fd);
	finalize_iftypes();
	g_list_free_full(ifcallbacks, free);
}
