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

/**
 * @file block.h
 * @desc Controlling block devices and file systems
 **/


#ifndef __BLOCK_H__
#define __BLOCK_H__

#include <unistd.h>
#include <glib.h>
#include <Ecore.h>

#include "resourced.h"
#include "const.h"

struct block_monitor_info {
	int mfd;
	int mode;
	int logging;
	int mount;
	char *logpath;
	int total_loglen;
	pid_t last_monitor_pid;
	pid_t last_skip_pid;
	char path[MAX_PATH_LENGTH];
	Ecore_Fd_Handler *fd_handler;
	GHashTable *block_include_proc;
	GHashTable *block_exclude_path;
};

int convert_fanotify_mode(const char *mode);
int register_fanotify(struct block_monitor_info *bmi);
void unregister_fanotify(struct block_monitor_info *bmi);

#endif /* __BLOCK_H__ */

