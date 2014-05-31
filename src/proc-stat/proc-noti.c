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
 * @file proc_noti.c
 * @desc It's main entry point for handling proc events
 * @see proc_cgroup_cmd_type
*/

#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include <Ecore.h>

#include "macro.h"
#include "proc-main.h"
#include "proc-noti.h"
#include "proc-process.h"
#include "resourced.h"
#include "trace.h"

/*
 * @desc function receives uint
 * negative value for error reporting
 */
static inline int recv_int(int fd)
{
	int val, r = -1;
	while (1) {
		r = read(fd, &val, sizeof(int));
		if (r >= 0)
			return val;

		if (errno == EINTR) {
			_E("Re-read for error(EINTR)");
			continue;
		} else {
			_E("Read fail for int");
			return -errno;
		}
	}
}

static inline char *recv_str(int fd)
{
	int len, r = -1;
	char *str;

	while (1) {
		r = read(fd, &len, sizeof(int));
		if (r < 0) {
			if (errno == EINTR) {
				_E("Re-read for error(EINTR)");
				continue;
			} else {
				_E("Read fail for str length");
				return NULL;
			}
		} else
			break;
	}

	if (len <= 0) {
		_D("str is null");
		return NULL;
	}

	if (len >= INT_MAX) {
		_E("size is over INT_MAX");
		return NULL;
	}

	str = (char *)malloc(len + 1);
	if (str == NULL) {
		_E("Not enough memory");
		return NULL;
	}

	while (1) {
		r = read(fd, str, len);
		if (r < 0) {
			if (errno == EINTR) {
				_E("Re-read for error(EINTR)");
				continue;
			} else {
				_E("Read fail for str");
				free(str);
				return NULL;
			}
		} else
			break;
	}
	str[len] = 0;

	return str;
}

/*
 * @desc This function read from fd to msg,
 * it supports multiple argument list given from client
 * of string type
 * @return 0 on success errno constants in error case
*/
static int read_message(int fd, struct resman_noti *msg)
{
	int i;

	msg->pid = recv_int(fd);
	ret_value_if(msg->pid < 0, errno);
	msg->type = recv_int(fd);
	ret_value_if(msg->type < 0, errno);
	msg->path = recv_str(fd);
	msg->argc = recv_int(fd);
	ret_value_if(msg->argc < 0, errno);

	for (i = 0; i < msg->argc; ++i)
		msg->argv[i] = recv_str(fd);

	return 0;
}

static bool _fatal_read_message_error(const int error_code)
{
	return error_code == EBADF || error_code == EISDIR;
}

static inline void internal_free(char *str)
{
	if (str)
		free(str);
}

static inline void free_message(struct resman_noti *msg)
{
	int i;

	internal_free(msg->path);

	for (i = 0; i < msg->argc; i++)
		internal_free(msg->argv[i]);
	free(msg);
}

static int process_message(struct resman_noti *msg)
{
	_D("process message caller pid %d\n", msg->pid);
	return resourced_proc_action(msg->type, msg->argc, msg->argv);
}

static void safe_write_int(int fd, int type, int *value)
{
	bool sync = SYNC_OPERATION(type);
	int ret;
	if (!sync) {
		_D("Response is not needed");
		return;
	}

	ret = write(fd, value, sizeof(int));
	if (ret < 0)
		ETRACE_ERRNO_MSG("Failed to response to client, %d", *value);
}

static Eina_Bool proc_noti_cb(void *data, Ecore_Fd_Handler *fd_handler)
{
	int fd;
	struct resman_noti *msg;
	int ret = -1;
	struct sockaddr_un client_address;
	int client_sockfd;
	int client_len;
	int error_code;

	if (!ecore_main_fd_handler_active_get(fd_handler, ECORE_FD_READ)) {
		_E("ecore_main_fd_handler_active_get error , return\n");
		return ECORE_CALLBACK_CANCEL;
	}

	fd = ecore_main_fd_handler_fd_get(fd_handler);

	msg = malloc(sizeof(struct resman_noti));
	if (msg == NULL) {
		_E("proc_noti_cb : Not enough memory");
		return ECORE_CALLBACK_RENEW;
	}

	client_len = sizeof(client_address);
	client_sockfd =
	    accept(fd, (struct sockaddr *)&client_address,
		   (socklen_t *)&client_len);
	if (client_sockfd == -1) {
		_E("socket accept error");
		free(msg);
		return ECORE_CALLBACK_RENEW;
	}

	error_code = read_message(client_sockfd, msg);

	if (error_code && _fatal_read_message_error(error_code)) {
		free_message(msg);
		close(client_sockfd);
		return ECORE_CALLBACK_CANCEL;
	} else if (error_code) { /* It's not fatal */
		_E("%s : recv error msg, %d", __func__, error_code);
		safe_write_int(client_sockfd, msg->type, &ret);
		goto proc_noti_renew;
	}

	if (msg->argc > NOTI_MAXARG) {
		_E("%s : error argument", __func__);
		safe_write_int(client_sockfd, msg->type, &ret);
		goto proc_noti_renew;
	}

	ret = process_message(msg);

	safe_write_int(client_sockfd, msg->type, &ret);

proc_noti_renew:

	close(client_sockfd);
	free_message(msg);

	return ECORE_CALLBACK_RENEW;
}

static int proc_noti_socket_init(void)
{
	int fd;
	struct sockaddr_un serveraddr;

	if (access(RESMAN_SOCKET_PATH, F_OK) == 0)
		unlink(RESMAN_SOCKET_PATH);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		_E("%s: socket create failed\n", __func__);
		return -1;
	}

	if ((fsetxattr(fd, "security.SMACK64IPOUT", "@", 2, 0)) < 0) {
		_E("%s: Socket SMACK labeling failed\n", __func__);
		if (errno != EOPNOTSUPP) {
			close(fd);
			return -1;
		}
	}

	if ((fsetxattr(fd, "security.SMACK64IPIN", "*", 2, 0)) < 0) {
		_E("%s: Socket SMACK labeling failed\n", __func__);
		if (errno != EOPNOTSUPP) {
			close(fd);
			return -1;
		}
	}

	bzero(&serveraddr, sizeof(struct sockaddr_un));
	serveraddr.sun_family = AF_UNIX;
	strncpy(serveraddr.sun_path, RESMAN_SOCKET_PATH,
		sizeof(serveraddr.sun_path));

	if (bind(fd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr)) <
	    0) {
		_E("%s: socket bind failed\n", __func__);
		close(fd);
		return -1;
	}

	if (chmod(RESMAN_SOCKET_PATH, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
		_E("failed to change the socket permission");

	if (listen(fd, 5) < 0) {
		_E("%s: socket listen failed\n", __func__);
		close(fd);
		return -1;
	}

	_D("socket create & listen ok\n");

	return fd;
}

int proc_noti_init()
{
	int fd;
	fd = proc_noti_socket_init();
	ecore_main_fd_handler_add(fd, ECORE_FD_READ, (Ecore_Fd_Cb)proc_noti_cb,
				  NULL, NULL, NULL);
	return fd;
}
