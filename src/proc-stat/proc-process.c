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

#include <ctype.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <Ecore.h>

#include "resourced.h"
#include "trace.h"
#include "proc-main.h"

#include "proc-process.h"
#include "lowmem-common.h"
#include "macro.h"
#include "cpu-common.h"
#include "proc-noti.h"
#include "proc-winstate.h"

#define PROC_OOM_SCORE_ADJ_PATH "/proc/%d/oom_score_adj"
#define PROC_SWEEP_TIMER	3
static GHashTable *proc_sweep_list;
static Ecore_Timer *proc_sweep_timer = NULL;

static int proc_backgrd_manage(int currentpid)
{
	int pid = -1, pgid, ret;
	DIR *dp;
	struct dirent *dentry;
	char appname[PROC_NAME_MAX];
	static int checkprevpid = 0;
	unsigned long lowmem_args[2] = {0,};

	ret = proc_get_cmdline(currentpid, appname);
	if (ret == RESOURCED_ERROR_NONE) {
		ret = resourced_proc_excluded(appname);
		if (ret || checkprevpid == currentpid) {
			_D("BACKGRD MANAGE : don't manage background application by %d", currentpid);
			return RESOURCED_ERROR_NONE;
		}
	}

	dp = opendir("/proc");
	if (!dp) {
		_E("BACKGRD MANAGE : fail to open /proc");
		return RESOURCED_ERROR_FAIL;
	}
	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		pid = atoi(dentry->d_name);
		pgid = getpgid(pid);
		if (!pgid)
			continue;

		if (currentpid != pid && currentpid == pgid) {
			_D("found owner pid = %d, pgid = %d", pid, pgid);
			lowmem_args[0] = (unsigned long)pid;
			lowmem_args[1] = (unsigned long)OOMADJ_BACKGRD_UNLOCKED;
			lowmem_control(LOWMEM_MOVE_CGROUP, lowmem_args);
			continue;
		}
	}
	checkprevpid = currentpid;
	closedir(dp);
	return RESOURCED_ERROR_NONE;
}

static void proc_foregrd_manage(int pid)
{
	unsigned long lowmem_args[2] = {0, };
	lowmem_args[0] = (unsigned long)pid;
	lowmem_control(LOWMEM_MANAGE_FOREGROUND, lowmem_args);
}

void proc_kill_victiom(gpointer key, gpointer value, gpointer user_data)
{
	int pid = *(gint*)key;
	int cur_oom = -1;
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	FILE *fp;

	snprintf(buf, sizeof(buf), PROC_OOM_SCORE_ADJ_PATH, pid);
	fp = fopen(buf, "r+");
	if (fp == NULL) {
		_D("sweep proc_kill_victiom : background process %d already terminated", pid);
		return;
	}
	if (fgets(buf, sizeof(buf), fp) == NULL) {
		fclose(fp);
		return;
	}
	cur_oom = atoi(buf);
	if (cur_oom >= OOMADJ_BACKGRD_UNLOCKED) {
		kill(pid, SIGKILL);
		_D("sweep memory : background process %d killed by sigkill", pid);
	}
	fclose(fp);
}

static Eina_Bool proc_check_sweep_cb(void *data)
{
	GHashTable *List = (GHashTable *)data;
	g_hash_table_foreach(List, proc_kill_victiom, NULL);
	g_hash_table_destroy(List);
	proc_sweep_list = NULL;
	return ECORE_CALLBACK_CANCEL;
}

int proc_sweep_memory(int callpid)
{
	int pid = -1, count=0, ret;
	DIR *dp;
	struct dirent *dentry;
	FILE *fp;
	gint *piddata;
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	char appname[PROC_NAME_MAX];

	int cur_oom = -1;
	dp = opendir("/proc");
	if (!dp) {
		_E("BACKGRD MANAGE : fail to open /proc");
		return RESOURCED_ERROR_FAIL;
	}
	if (proc_sweep_timer)
		ecore_timer_del(proc_sweep_timer);
	if (proc_sweep_list)
		g_hash_table_destroy(proc_sweep_list);
	proc_sweep_list = g_hash_table_new(g_int_hash, g_int_equal);

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		pid = atoi(dentry->d_name);
		if (pid == callpid)
			continue;

		snprintf(buf, sizeof(buf), PROC_OOM_SCORE_ADJ_PATH, pid);
		fp = fopen(buf, "r+");
		if (fp == NULL)
			continue;
		if (fgets(buf, sizeof(buf), fp) == NULL) {
			fclose(fp);
			continue;
		}
		cur_oom = atoi(buf);
		if (cur_oom >= OOMADJ_BACKGRD_UNLOCKED) {
			ret = proc_get_cmdline(pid, appname);
			if (ret != 0) {
				fclose(fp);
				continue;
			}
			piddata = g_new(gint, 1);
			*piddata = pid;
			g_hash_table_insert(proc_sweep_list, piddata, NULL);
			kill(pid, SIGTERM);
			_D("sweep memory : background process %d(%s) killed",
					pid, appname);
			count++;
		}
		fclose(fp);
	}
	if (count > 0) {
		proc_sweep_timer =
			    ecore_timer_add(PROC_SWEEP_TIMER, proc_check_sweep_cb, (void *)proc_sweep_list);
	}
	closedir(dp);
	return count;
}


int proc_get_cmdline(pid_t pid, char *cmdline)
{
	char buf[PROC_BUF_MAX];
	char cmdline_buf[PROC_NAME_MAX];
	char *filename;
	FILE *fp;

	sprintf(buf, "/proc/%d/cmdline", pid);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;

	if (fgets(cmdline_buf, PROC_NAME_MAX-1, fp) == NULL) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	fclose(fp);

	filename = strrchr(cmdline_buf, '/');
	if (filename == NULL)
		filename = cmdline_buf;
	else
		filename = filename + 1;

	strncpy(cmdline, filename, PROC_NAME_MAX-1);

	return RESOURCED_ERROR_NONE;
}


int proc_get_oom_score_adj(int pid, int *oom_score_adj)
{
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	FILE *fp = NULL;

	if (pid < 0)
		return RESOURCED_ERROR_FAIL;

	snprintf(buf, sizeof(buf), PROC_OOM_SCORE_ADJ_PATH, pid);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;
	if (fgets(buf, sizeof(buf), fp) == NULL) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	(*oom_score_adj) = atoi(buf);
	fclose(fp);
	return RESOURCED_ERROR_NONE;
}

int proc_set_oom_score_adj(int pid, int oom_score_adj)
{
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	FILE *fp;
	unsigned long lowmem_args[2] = {0, };

	snprintf(buf, sizeof(buf), PROC_OOM_SCORE_ADJ_PATH, pid);
	fp = fopen(buf, "r+");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;
	if (fgets(buf, sizeof(buf), fp) == NULL) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	fprintf(fp, "%d", oom_score_adj);
	fclose(fp);

	if (oom_score_adj >= OOMADJ_SU) {
		lowmem_args[0] = (unsigned long)pid;
		lowmem_args[1] = (unsigned long)oom_score_adj;
		lowmem_control(LOWMEM_MOVE_CGROUP, lowmem_args);
	}
	return 0;
}

int proc_set_foregrd(int pid, int oom_score_adj)
{
	int ret = 0;

	switch (oom_score_adj) {
	case OOMADJ_FOREGRD_LOCKED:
	case OOMADJ_FOREGRD_UNLOCKED:
	case OOMADJ_SU:
		ret = 0;
		break;
	case OOMADJ_BACKGRD_LOCKED:
		proc_foregrd_manage(pid);
		ret = proc_set_oom_score_adj(pid, OOMADJ_FOREGRD_LOCKED);
		break;
	case OOMADJ_BACKGRD_UNLOCKED:
		cpu_control(CPU_SET_FOREGROUND, pid);
		proc_foregrd_manage(pid);
		ret = proc_set_oom_score_adj(pid, OOMADJ_FOREGRD_UNLOCKED);
		break;
	case OOMADJ_INIT:
		ret = proc_set_oom_score_adj(pid, OOMADJ_FOREGRD_UNLOCKED);
		break;
	default:
		if (oom_score_adj > OOMADJ_BACKGRD_UNLOCKED) {
			ret = proc_set_oom_score_adj(pid, OOMADJ_FOREGRD_UNLOCKED);
		} else {
			ret = -1;
		}
		break;

	}
	return ret;
}

int proc_set_backgrd(int pid, int oom_score_adj)
{
	int ret = 0;

	switch (oom_score_adj) {
	case OOMADJ_BACKGRD_LOCKED:
	case OOMADJ_BACKGRD_UNLOCKED:
	case OOMADJ_SU:
		_D("don't change oom value pid = (%d) oom_score_adj (%d)!", pid, oom_score_adj);
		ret = -1;
		break;
	case OOMADJ_FOREGRD_LOCKED:
		ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_LOCKED);
		break;
	case OOMADJ_FOREGRD_UNLOCKED:
		proc_backgrd_manage(pid);
		cpu_control(CPU_SET_BACKGROUND, pid);
		ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_UNLOCKED);
		break;
	case OOMADJ_INIT:
		ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_UNLOCKED);
		break;
	default:
		if (oom_score_adj > OOMADJ_BACKGRD_UNLOCKED) {
			ret = 0;
		} else {
			ret = -1;
		}
		break;
	}
	return ret;
}

int proc_set_active(int pid, int oom_score_adj)
{
	int ret = 0;

	switch (oom_score_adj) {
	case OOMADJ_FOREGRD_LOCKED:
	case OOMADJ_BACKGRD_LOCKED:
	case OOMADJ_SU:
		/* don't change oom value pid */
		ret = -1;
		break;
	case OOMADJ_FOREGRD_UNLOCKED:
		ret = proc_set_oom_score_adj(pid, OOMADJ_FOREGRD_LOCKED);
		break;
	case OOMADJ_BACKGRD_UNLOCKED:
		ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_LOCKED);
		break;
	case OOMADJ_INIT:
		ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_LOCKED);
		break;
	default:
		if (oom_score_adj > OOMADJ_BACKGRD_UNLOCKED) {
			ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_LOCKED);
		} else {
			ret = -1;
		}
		break;
	}
	return ret;
}

int proc_set_inactive(int pid, int oom_score_adj)
{
	int ret = 0;

	switch (oom_score_adj) {
	case OOMADJ_FOREGRD_UNLOCKED:
	case OOMADJ_BACKGRD_UNLOCKED:
	case OOMADJ_SU:
		/* don't change oom value pid */
		ret = -1;
		break;
	case OOMADJ_FOREGRD_LOCKED:
		ret = proc_set_oom_score_adj(pid, OOMADJ_FOREGRD_UNLOCKED);
		break;
	case OOMADJ_BACKGRD_LOCKED:
		ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_UNLOCKED);
		break;
	case OOMADJ_INIT:
		ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_UNLOCKED);
		break;
	default:
		if (oom_score_adj > OOMADJ_BACKGRD_UNLOCKED) {
			ret = 0;
		} else {
			ret = -1;
		}
		break;

	}
	return ret;
}

pid_t find_pid_from_cmdline(char *cmdline)
{
	pid_t pid = -1, foundpid = -1;
	int ret = 0;
	DIR *dp;
	struct dirent *dentry;
	char appname[PROC_NAME_MAX];

	dp = opendir("/proc");
	if (!dp) {
		_E("BACKGRD MANAGE : fail to open /proc");
		return RESOURCED_ERROR_FAIL;
	}
	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		pid = atoi(dentry->d_name);
		if (!pid)
			continue;
		ret = proc_get_cmdline(pid, appname);
		if (ret == RESOURCED_ERROR_NONE) {
			if (strstr(cmdline, appname)) {
				foundpid = pid;
				break;
			}
		}
	}
	closedir(dp);
	return foundpid;
}
