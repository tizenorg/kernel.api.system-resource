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
#include <glib.h>
#include <string.h>

#include "proc-common.h"
#include "resourced.h"
#include "const.h"
#include "proc_stat.h"

struct proc_module_ops {
	char *name;
	int (*init) (void *data);
	int (*exit) (void *data);
};

#define PROC_MODULE_REGISTER(module) \
static void __attribute__ ((constructor)) module_init(void) \
{ \
	proc_module_add(module); \
} \
static void __attribute__ ((destructor)) module_exit(void) \
{ \
	proc_module_remove(module); \
}

void proc_module_add(const struct proc_module_ops *mod);
void proc_module_remove(const struct proc_module_ops *mod);

/**
 * @desc This function handle PROC_ typs @see
 */
int resourced_proc_action(int type, int argnum, char **arg);

int resourced_proc_excluded(const char *app_name);

int resourced_proc_status_change(int status, pid_t pid, char* app_name,  char* pkg_name, int apptype);

void resourced_proc_dump(int type, const char *path);

resourced_ret_c proc_set_runtime_exclude_list(const int pid, int type);

struct proc_app_info *proc_create_app_list(const char *appid, const char *pkgid);

int proc_remove_app_list(const pid_t pid);

char *proc_get_appid_from_pid(const pid_t pid);

void proc_set_group(pid_t onwerpid, pid_t childpid, char *pkgname);

static inline gint compare_pid(gconstpointer a, gconstpointer b)
{
	const struct child_pid *pida = (struct child_pid *)a;
	const struct child_pid *pidb = (struct child_pid *)b;
	return pida->pid == pidb->pid ? 0 :
		pida->pid > pidb->pid ? 1 : -1;
}

int proc_get_state(int type, pid_t pid, char *buf, int len);

#endif /*__PROC_MAIN_H__ */
