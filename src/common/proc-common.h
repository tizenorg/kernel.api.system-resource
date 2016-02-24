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
 * @file proc-common.h
 * @desc proc common process
 **/

#ifndef __PROC_COMMON_H__
#define __PROC_COMMON_H__

#include <unistd.h>
#include <glib.h>
#include <string.h>

#include "resourced.h"
#include "const.h"
#include "memcontrol.h"

typedef GSList *pid_list;

enum application_type {
	PROC_TYPE_NONE,
	PROC_TYPE_READY,
	PROC_TYPE_GUI,
	PROC_TYPE_SERVICE,
	PROC_TYPE_GROUP,
	PROC_TYPE_WATCH,
	PROC_TYPE_WIDGET,
};

enum proc_state {
	PROC_STATE_DEFAULT,
	PROC_STATE_FOREGROUND,
	PROC_STATE_BACKGROUND,
	PROC_STATE_SUSPEND_READY,
	PROC_STATE_SUSPEND,
};

struct child_pid {
	pid_t pid;
};

struct proc_status {
	pid_t pid;
	char* appid;
	struct proc_app_info *pai;
};

enum proc_exclude_type {
	PROC_INCLUDE,
	PROC_EXCLUDE,
};

enum {
	LCD_STATE_ON,
	LCD_STATE_OFF,
};

enum proc_prelaunch_flags {
	PROC_NONE	= 0x00u,
	PROC_LARGEMEMORY	= 0x01u,	/* for mark large memory */
	PROC_SIGTERM	= 0x02u,	/* for make killer kill victim by SIGTERM */
	PROC_WEBAPP	= 0x04u,	/* for checking webapp */
	PROC_DOWNLOADAPP = 0x08u,	/* for monitoring disk usage about downloadable app */
	PROC_SERVICEAPP = 0x10u,	/* for distinguishing service app and ui app */
	PROC_BGALLOW = 0x100u,	/* for allowing background application */
	PROC_BGCTRL_PLATFORM = 0x200u,	/* for controlling background application by appfw */
	PROC_BGCTRL_APP = 0x400u,	/* for checking old version application */
};

enum proc_lru_state {
	PROC_FOREGROUND	= -1,
	PROC_ACTIVE = 0,
	PROC_BACKGROUND	= 1,
	PROC_LRU_MAX	= 15,
};

extern GSList *proc_app_list;

struct proc_exclude {
	pid_t pid;
	enum proc_exclude_type type;
};

struct proc_program_info {
	char *pkgname;
	GSList *app_list;
	GSList *svc_list;
};

struct proc_app_info {
	char *appid;
	struct resourced_appinfo *ai;
	enum application_type type;
	pid_t main_pid;
	pid_list childs;
	struct proc_program_info *program;
	int proc_exclude;
	int runtime_exclude;
	int memcg_idx;
	struct memcg_info *memcg_info;
	int flags;
	int lru_state;
	enum proc_state state;
};

int get_proc_freezer_late_control(void);
void set_proc_freezer_late_control(int value);
int proc_get_freezer_status(void);

struct proc_app_info *find_app_info(const pid_t pid);
struct proc_app_info *find_app_info_by_appid(const char *appid);

struct child_pid *new_pid_info(const pid_t pid);
int proc_get_id_info(struct proc_status *ps, char **app_name, char **pkg_name);

void proc_set_process_info_memcg(struct proc_app_info *ppi,
	int memcg_idx, struct memcg_info *memcg_info);

int proc_get_appflag(const pid_t pid);

static inline int equal_name_info(const char *id_a, const char *id_b)
{
	return !strcmp(id_a, id_b);
}

int proc_get_svc_state(struct proc_program_info *ppi);

bool proc_check_lru_suspend(int val, int lru);

enum proc_state proc_check_suspend_state(struct proc_app_info *pai);

#endif /* __PROC_COMMON_H__ */
