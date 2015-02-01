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
 * @file logging.h
 * @desc define structures and functions for logging.
 **/

#ifndef __LOGGING_H__
#define __LOGGING_H__

#define	SS_NAME_MAX 10

struct logging_infos {
	pid_t pid;
	int oom;
	void **stats;
	bool running;
};

struct logging_info_ops {
	int (*update)(void *, pid_t, int, time_t, unsigned);
	int (*write)(char *, struct logging_infos *, int);
	int (*init)(void **, pid_t, int, time_t);
};

int register_logging_subsystem(const char *name, struct logging_info_ops *ops);
int update_commit_interval(const char *name, time_t commit_interval);
int get_pss(pid_t pid, unsigned *pss, unsigned *uss);
#endif /*__LOGGING_H__*/
