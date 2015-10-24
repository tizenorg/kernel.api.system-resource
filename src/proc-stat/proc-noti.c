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
#include <systemd/sd-daemon.h>

#include "macro.h"
#include "util.h"
#include "proc-main.h"
#include "proc-noti.h"
#include "proc-process.h"
#include "resourced.h"
#include "trace.h"

static int noti_fd;
/*
 * @desc function receives uint
 * negative value for error reporting
 */
static inline int recv_int(int fd)
{
	int val = 0, r = -1;
	while (1) {
		r = read(fd, &val, sizeof(int));
		if (r == sizeof(int))
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

	if (len <= 0)
		return NULL;

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
static int read_message(int fd, struct resourced_noti *msg)
{
	int i;

	ret_value_if(fd < 0, RESOURCED_ERROR_FAIL);
	msg->pid = recv_int(fd);
	ret_value_if(msg->pid <= 0, errno);
	msg->type = recv_int(fd);
	ret_value_if(msg->type <= 0, errno);
	msg->path = recv_str(fd);
	msg->argc = recv_int(fd);
	ret_value_if(msg->argc <= 0, errno);

	for (i = 0; i < msg->argc; ++i) {
		msg->argv[i] = recv_str(fd);
		ret_value_if(msg->argv[i] <= 0, errno);
	}

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

static inline void free_message(struct resourced_noti *msg)
{
	int i;

	internal_free(msg->path);

	for (i = 0; i < msg->argc; i++)
		internal_free(msg->argv[i]);
	free(msg);
}

static int process_message(struct resourced_noti *msg)
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

static int write_response(int *retval, int fd, char *buf, int len)
{
	int ret;
	ret = send(fd, retval, sizeof(int), 0);
	if (ret < 0)
		_E("Failed to send");
	ret = send(fd, buf, len, 0);
	if (ret < 0)
		_E("Failed to write");
	return ret;
}

static Eina_Bool proc_noti_cb(void *data, Ecore_Fd_Handler *fd_handler)
{
	int fd;
	struct resourced_noti *msg;
	int ret = -1;
	struct sockaddr_un client_address;
	int client_sockfd;
	int client_len;
	int error_code;
	_cleanup_free_ char *send_buffer = NULL;
	int send_len;
	pid_t pid;
	struct timeval tv = { 1, 0 };	/* 1 sec */

	if (!ecore_main_fd_handler_active_get(fd_handler, ECORE_FD_READ)) {
		_E("ecore_main_fd_handler_active_get error , return\n");
		return ECORE_CALLBACK_CANCEL;
	}

	fd = ecore_main_fd_handler_fd_get(fd_handler);

	msg = calloc(1, sizeof(struct resourced_noti));
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

	setsockopt(client_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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

	if (msg->type >= PROC_CGROUP_GET_CMDLINE) {
		pid = atoi(msg->argv[0]);
		send_len = atoi(msg->argv[1]);
		send_buffer = calloc(1, send_len);
		if (!send_buffer) {
			_E("not enough memory for calloc");
			ret = -ENOMEM;
			safe_write_int(client_sockfd, msg->type, &ret);
			goto proc_noti_renew;
		}
		ret = proc_get_state(msg->type, pid, send_buffer, send_len);
		write_response(&ret, client_sockfd, send_buffer, send_len);
	} else {
		ret = process_message(msg);
		safe_write_int(client_sockfd, msg->type, &ret);
	}

proc_noti_renew:

	close(client_sockfd);
	free_message(msg);

	return ECORE_CALLBACK_RENEW;
}

static int proc_noti_socket_init(void)
{
	int fd, n = 0;
	struct sockaddr_un serveraddr;

	n = sd_listen_fds(0);
	if (n > 1) {
		_E("Error: Too many file descriptors received: %d", n);
		return -1;
	} else if (n==1) {
		fd = SD_LISTEN_FDS_START + 0;
	} else {
		if (access(RESOURCED_SOCKET_PATH, F_OK) == 0)
			unlink(RESOURCED_SOCKET_PATH);

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
		strncpy(serveraddr.sun_path, RESOURCED_SOCKET_PATH,
			sizeof(serveraddr.sun_path)-1);
		serveraddr.sun_path[sizeof(serveraddr.sun_path)-1] = 0;

		if (bind(fd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr)) <
		    0) {
			_E("%s: socket bind failed\n", __func__);
			close(fd);
			return -1;
		}

		if (chmod(RESOURCED_SOCKET_PATH, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
			_E("failed to change the socket permission");

		if (listen(fd, 5) < 0) {
			_E("%s: socket listen failed\n", __func__);
			close(fd);
			return -1;
		}
	}
	_D("socket create & listen ok\n");

	return fd;
}

static int proc_noti_init(void *data)
{
	noti_fd = proc_noti_socket_init();
	ecore_main_fd_handler_add(noti_fd, ECORE_FD_READ, (Ecore_Fd_Cb)proc_noti_cb,
				  NULL, NULL, NULL);
	return RESOURCED_ERROR_NONE;
}

static int proc_noti_exit(void *data)
{
	close(noti_fd);
	return RESOURCED_ERROR_NONE;
}

static const struct proc_module_ops proc_noti_ops = {
	.name		= "PROC_NOTI",
	.init		= proc_noti_init,
	.exit		= proc_noti_exit,
};
PROC_MODULE_REGISTER(&proc_noti_ops)
