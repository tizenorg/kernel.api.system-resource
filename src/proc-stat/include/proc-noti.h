/*
 *  resourced
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
 * @file proc-noti.h
 * @desc communication api with libresourced for grouping process
 **/

#ifndef __PROC_NOTI_H__
#define __PROC_NOTI_H__

#define RESMAN_SOCKET_PATH "/tmp/resman"
#define NOTI_MAXARG	16
#define NOTI_MAXARGLEN 512

struct resman_noti { /** cgroup notification type **/
	int pid;
	int type;
	char *path;
	int argc;
	char *argv[NOTI_MAXARG];
};

#define SYNC_OPERATION(type) type == PROC_CGROUP_GET_MEMSWEEP || \
	type == PROC_CGROUP_SET_RESUME_REQUEST || \
	type == PROC_CGROUP_SET_TERMINATE_REQUEST

int proc_noti_init(void);


#endif /*__PROC_HANDLER_H__*/
