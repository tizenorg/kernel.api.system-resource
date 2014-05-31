/*
 * resourced
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
 * @file proc-main.h
 * @desc intialize and start pthread for lowmem handler
 **/

#ifndef __PROC_MAIN_H__
#define __PROC_MAIN_H__

#include <unistd.h>
#include "resourced.h"

#define PROC_BUF_MAX 64
#define PROC_NAME_MAX 512


int resourced_proc_init(const struct daemon_opts *opts);

/**
 * @desc This function handle PROC_ typs @see
 */
int resourced_proc_action(int type, int argnum, char **arg);

int resourced_proc_excluded(const char *app_name);

int resourced_proc_status_change(int type, pid_t pid, char* app_name);

#endif /*__PROC_MAIN_H__ */

