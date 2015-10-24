/*
 * resourced
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file proc_info.c
 * @desc It's main thread to get system & process information
 *       to provide runtime api
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
#include <pthread.h>

#include <Ecore.h>

#include "macro.h"
#include "proc-main.h"
#include "proc-info.h"
#include "proc-process.h"
#include "resourced.h"
#include "module.h"
#include "trace.h"

#define MAX_PROC_PATH 24
#define MAX_BUFFER_LEN 4096
#define MAX_MESSAGE_NUM (MAX_BUFFER_LEN/sizeof(unsigned long))
#define MAX_CONNECTION 5
#define REPLY_TYPE(x) (x + 2)

enum {
	REQ_PROCESS_CPU = 1,
	REQ_PROCESS_MEMORY = 2,
	ACK_PROCESS_CPU = 3,
	ACK_PROCESS_MEMORY = 4,
};

static pthread_t proc_info_thread;

static inline int send_int(int fd, int val)
{
	return write(fd, &val, sizeof(int));
}

static int send_buf(int fd, unsigned char *buf, int buf_len)
{
	int ret;

	if (!buf_len || !buf)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	ret = write(fd, &buf_len, sizeof(int));
	if (ret < 0) {
		_E("Failed to write");
		return ret;
	}
	ret = write(fd, buf, buf_len);
	if (ret < 0) {
		_E("Failed to write");
		return ret;
	}
	return ret;
}

static int recv_int(int fd)
{
	int val, ret = -1;
	while (1) {
		ret = read(fd, &val, sizeof(int));
		if (ret >= 0)
			return val;

		if (errno == EINTR) {
			_E("Re-read for error(EINTR)");
			continue;
		}

		_E("Read fail for int");
		return -errno;
	}
}

static int resourced_proc_info_get_cpu_time(int pid, unsigned long *utime,
		unsigned long *stime)
{
	char proc_path[MAX_PROC_PATH];
	FILE *fp;

	assert(utime != NULL);
	assert(stime != NULL);

	snprintf(proc_path, sizeof(proc_path), "/proc/%d/stat", pid);
	fp = fopen(proc_path, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;

	if (fscanf(fp, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s") < 0) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	if (fscanf(fp, "%lu %lu", utime, stime) < 1) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	fclose(fp);

	return RESOURCED_ERROR_NONE;
}

static int resourced_proc_info_get_process_cpu(int msg_num, unsigned char *recv_buffer, int buf_len, unsigned char *send_buffer, int *send_len)
{
	int i, j, pid;
	int *recv_buff;
	unsigned long utime, stime;
	unsigned long *send_buff;

	recv_buff = (int *)recv_buffer;
	send_buff = (unsigned long *)send_buffer;

	if (!recv_buffer || !buf_len) {
		_E("Wrong arguments");
		return RESOURCED_ERROR_FAIL;
	}
	for (i = 0, j = 0; i < msg_num; i++) {
		memcpy(&pid, &recv_buff[i], sizeof(int));
		if (resourced_proc_info_get_cpu_time(pid, &utime, &stime) < 0) {
			_E("Failed to get cpu time");
			utime = 0;
			stime = 0;
		}
		memcpy(&send_buff[j], &utime, sizeof(unsigned long));
		memcpy(&send_buff[j +  1], &stime, sizeof(unsigned long));
		j += 2;
	}
	*send_len = j * sizeof(unsigned long);
	return RESOURCED_ERROR_NONE;
}


static void *resourced_proc_info_func(void *data)
{
	unsigned char recv_buffer[MAX_BUFFER_LEN + 1];
	unsigned char send_buffer[MAX_BUFFER_LEN + 1];
	struct sockaddr_un client_address;
	int ret, msg_type, msg_num, recv_len, send_len;
	int server_fd, client_fd, client_len;

	if (!data) {
		_E("data is NULL");
		return NULL;
	}

	server_fd = (int)data;

	client_len = sizeof(client_address);

	if (listen(server_fd, MAX_CONNECTION) < 0) {
		_E("Failed to listen socket");
		close(server_fd);
		return NULL;
	}

	while (1) {
		memset(recv_buffer, 0x00, MAX_BUFFER_LEN + 1);
		memset(send_buffer, 0x00, MAX_BUFFER_LEN + 1);
		client_fd =
			accept(server_fd, (struct sockaddr *)&client_address,
					(socklen_t *)&client_len);
		if (client_fd < 0) {
			_E("Failed to accept");
			continue;
		}
		msg_type = recv_int(client_fd);
		msg_num = recv_int(client_fd);
		if (msg_num <= 0) {
			close(client_fd);
			continue;
		}
		if (msg_num > MAX_MESSAGE_NUM) {
			msg_num = MAX_MESSAGE_NUM;
		}

		recv_len = recv_int(client_fd);
		if (recv_len <= 0) {
			close(client_fd);
			continue;
		}

		if (recv_len > MAX_BUFFER_LEN) {
			recv_len = MAX_BUFFER_LEN;
		}

		ret = 0;
		while (1) {
			ret = read(client_fd, recv_buffer, recv_len);
			if (ret < 0) {
				if (errno == EINTR) {
					_E("Re-read for error(EINTR)");
					continue;
				}
				_E("Failed to read");
			}
			break;
		}
		recv_buffer[recv_len] = '\0';
		send_len = 0;
		switch (msg_type) {
		case REQ_PROCESS_CPU:
			ret = resourced_proc_info_get_process_cpu(msg_num, recv_buffer,
					recv_len, send_buffer, &send_len);
			break;
		case REQ_PROCESS_MEMORY:
			break;
		default:
			_E("Wrong Msg type");
			close(client_fd);
			continue;
		}
		if (ret < 0) {
			_E("Failed to get process info");
			close(client_fd);
			continue;
		}
		if (send_len <= 0 || send_len > MAX_BUFFER_LEN) {
			_E("Failed to get process info");
			close(client_fd);
			continue;
		}
		ret = send_int(client_fd, REPLY_TYPE(msg_type));
		if (ret < 0) {
			_E("Failed to send int");
			close(client_fd);
			continue;
		}
		ret = send_int(client_fd, msg_num);
		if (ret < 0) {
			_E("Failed to send int");
			close(client_fd);
			continue;
		}
		ret = send_buf(client_fd, send_buffer, send_len);
		if (ret < 0) {
			_E("Failed to send buf");
			close(client_fd);
			continue;
		}
		close(client_fd);
	}

	return NULL;
}

static int proc_info_socket_init(void)
{
	int fd;
	struct sockaddr_un serveraddr;

	if (access(RESOURCED_PROC_INFO_SOCKET_PATH, F_OK) == 0)
		unlink(RESOURCED_PROC_INFO_SOCKET_PATH);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		_E("Failed to create socket");
		return -1;
	}

	if ((fsetxattr(fd, "security.SMACK64IPOUT", "@", 2, 0)) < 0) {
		_E("Failed to set Socket SMACK label");
		if (errno != EOPNOTSUPP) {
			close(fd);
			return -1;
		}
	}

	if ((fsetxattr(fd, "security.SMACK64IPIN", "*", 2, 0)) < 0) {
		_E("Failed to set Socket SMACK label");
		if (errno != EOPNOTSUPP) {
			close(fd);
			return -1;
		}
	}

	bzero(&serveraddr, sizeof(struct sockaddr_un));
	serveraddr.sun_family = AF_UNIX;
	strncpy(serveraddr.sun_path, RESOURCED_PROC_INFO_SOCKET_PATH,
			sizeof(serveraddr.sun_path));

	if (bind(fd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr)) < 0) {
		_E("Failed to bind socket");
		close(fd);
		return -1;
	}

	if (chmod(RESOURCED_PROC_INFO_SOCKET_PATH, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
		_E("Failed to change the socket permission");
	_D("socket create ok");
	return fd;
}

static int proc_info_init(void *data)
{
	int fd, ret;

	fd = proc_info_socket_init();
	if (fd < 0) {
		_E("Failed to init socket");
		return -1;
	}
	/* start thread */
	ret = pthread_create(&proc_info_thread, NULL, resourced_proc_info_func,
			(void *)fd);
	if (ret != 0) {
		_E("Failed to create thread");
		return RESOURCED_ERROR_FAIL;
	}

	return RESOURCED_ERROR_NONE;
}

static int proc_info_exit(void *data)
{
	_D("proc info exit!");
	return RESOURCED_ERROR_NONE;
}

static const struct proc_module_ops proc_info_ops = {
	.name           = "PROC_INFO",
	.init           = proc_info_init,
	.exit           = proc_info_exit,
};
PROC_MODULE_REGISTER(&proc_info_ops)
