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
#include "cgroup.h"
#include "proc-process.h"
#include "lowmem-common.h"
#include "logging-common.h"
#include "macro.h"
#include "swap-common.h"
#include "proc-noti.h"
#include "notifier.h"

#define PROC_OOM_SCORE_ADJ_PATH "/proc/%d/oom_score_adj"
#define PROC_SWEEP_TIMER	3
static GHashTable *proc_sweep_list;
static Ecore_Timer *proc_sweep_timer = NULL;

enum proc_background_type {
	PROC_BACKGROUND_INACTIVE,
	PROC_BACKGROUND_ACTIVE,
};

static int proc_backgrd_manage(int currentpid, int active)
{
	int pid = -1, pgid, ret;
	struct proc_status proc_data;;
	DIR *dp;
	struct dirent *dentry;
	FILE *fp;
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	char appname[PROC_NAME_MAX];
	int count = 0;
	int candidatepid[16] = {0,};
	int cur_oom = -1, prev_oom=OOMADJ_BACKGRD_UNLOCKED, select_pid=0;
	static int checkprevpid = 0;
	unsigned long swap_args[2] = {0,};
	unsigned long logging_args[3] = {0,};

	ret = proc_get_cmdline(currentpid, appname);
	if (ret == RESOURCED_ERROR_NONE) {
		ret = resourced_proc_excluded(appname);
		if (!active && !ret) {
			proc_data.pid = currentpid;
			proc_data.appid = appname;
			resourced_notify(RESOURCED_NOTIFIER_APP_BACKGRD, &proc_data);
		}
		if (ret) {
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

		snprintf(buf, sizeof(buf), PROC_OOM_SCORE_ADJ_PATH, pid);
		fp = fopen(buf, "r+");
		if (fp == NULL)
			continue;
		if (fgets(buf, sizeof(buf), fp) == NULL) {
			fclose(fp);
			continue;
		}
		cur_oom = atoi(buf);

		logging_args[0] = (unsigned long)pid;
		logging_args[1] = (unsigned long)pgid;
		logging_args[2] = (unsigned long)cur_oom;
		logging_control(LOGGING_INSERT_PROC_LIST, logging_args);

		if (currentpid != pid && currentpid == pgid) {
			proc_set_group(currentpid, pid);
			fclose(fp);
			continue;
		}

		if (active || checkprevpid == currentpid) {
			fclose(fp);
			continue;
		}

		if (select_pid != pid && select_pid == pgid && count < 16)
		{
			_D("found candidate child pid = %d, pgid = %d", pid, pgid);
			candidatepid[count++] = pid;
			fclose(fp);
			continue;
		}

		swap_args[0] = (unsigned long)pid;
		if (cur_oom > OOMADJ_BACKGRD_UNLOCKED && cur_oom > prev_oom
				&& !swap_status(SWAP_CHECK_PID, swap_args)) {
			count = 0;
			candidatepid[count++] = pid;
			select_pid = pid;
			prev_oom = cur_oom;
		}

		if (cur_oom >= OOMADJ_APP_MAX) {
			fclose(fp);
			continue;
		} else if (cur_oom >= OOMADJ_BACKGRD_UNLOCKED) {
			_D("BACKGRD : process %d set score %d (before %d)",
					pid, cur_oom+OOMADJ_APP_INCREASE, cur_oom);
			fprintf(fp, "%d", cur_oom+OOMADJ_APP_INCREASE);
		}
		fclose(fp);
	}

	if (select_pid) {
		_D("found candidate pid = %d, count = %d", candidatepid, count);
		swap_args[0] = (unsigned long)candidatepid;
		swap_args[1] = (unsigned long)count;
		resourced_notify(RESOURCED_NOTIFIER_SWAP_SET_CANDIDATE_PID, swap_args);
	}
	checkprevpid = currentpid;
	closedir(dp);

	logging_control(LOGGING_UPDATE_PROC_INFO, NULL);

	return RESOURCED_ERROR_NONE;
}

static int proc_foregrd_manage(int pid, int oom_score_adj)
{
	int ret = 0;
	GSList *iter;
	struct proc_process_info_t *process_info =
		find_process_info(NULL, pid, NULL);

	if (!process_info) {
		ret = proc_set_oom_score_adj(pid, oom_score_adj);
		return ret;
	}

	gslist_for_each_item(iter, process_info->pids) {
		struct pid_info_t *pid_info = (struct pid_info_t *)(iter->data);
		ret = proc_set_oom_score_adj(pid_info->pid, oom_score_adj);
	}
	return ret;
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
		_D("sweep proc_kill_victim : background process %d already terminated", pid);
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

int proc_sweep_memory(enum proc_sweep_type type, pid_t callpid)
{
	pid_t pid = -1;
	int count=0, ret;
	DIR *dp;
	struct dirent *dentry;
	FILE *fp;
	gint *piddata;
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	char appname[PROC_NAME_MAX];

	int cur_oom = -1;
	int select_sweep_limit;
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

	if (type == PROC_SWEEP_EXCLUDE_ACTIVE)
		select_sweep_limit = OOMADJ_BACKGRD_UNLOCKED;
	else
		select_sweep_limit = OOMADJ_BACKGRD_LOCKED;

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
		if (cur_oom >= select_sweep_limit) {
			ret = proc_get_cmdline(pid, appname);
			if (ret != 0) {
				fclose(fp);
				continue;
			}
			proc_remove_process_list(pid);
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

	if (fp == NULL) {
		_E("fopen %s failed", buf);
		return RESOURCED_ERROR_FAIL;
	}
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

int proc_set_foregrd(pid_t pid, int oom_score_adj)
{
	int ret = 0;

	switch (oom_score_adj) {
	case OOMADJ_FOREGRD_LOCKED:
	case OOMADJ_FOREGRD_UNLOCKED:
	case OOMADJ_SU:
		ret = 0;
		break;
	case OOMADJ_BACKGRD_LOCKED:
		ret = proc_foregrd_manage(pid, OOMADJ_FOREGRD_LOCKED);
		break;
	case OOMADJ_BACKGRD_UNLOCKED:
	case OOMADJ_INIT:
		ret = proc_foregrd_manage(pid, OOMADJ_FOREGRD_UNLOCKED);
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
		ret = -1;
		break;
	case OOMADJ_FOREGRD_LOCKED:
		proc_backgrd_manage(pid, PROC_BACKGROUND_ACTIVE);
		ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_LOCKED);
		break;
	case OOMADJ_FOREGRD_UNLOCKED:
		proc_backgrd_manage(pid, PROC_BACKGROUND_INACTIVE);
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
	case OOMADJ_INIT:
		/* don't change oom value pid */
		ret = -1;
		break;
	case OOMADJ_FOREGRD_UNLOCKED:
		ret = proc_set_oom_score_adj(pid, OOMADJ_FOREGRD_LOCKED);
		break;
	case OOMADJ_BACKGRD_UNLOCKED:
		ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_LOCKED);
		break;
	case OOMADJ_SERVICE_DEFAULT:
	case OOMADJ_SERVICE_BACKGRD:
		ret = proc_set_oom_score_adj(pid, OOMADJ_SERVICE_FOREGRD);
		break;
	default:
		if (oom_score_adj > OOMADJ_BACKGRD_UNLOCKED)
			ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_LOCKED);
		else
			ret = -1;
		break;
	}
	return ret;
}

int proc_set_inactive(int pid, int oom_score_adj)
{
	int ret = 0;
	struct proc_process_info_t * processinfo;
	switch (oom_score_adj) {
	case OOMADJ_FOREGRD_UNLOCKED:
	case OOMADJ_BACKGRD_UNLOCKED:
	case OOMADJ_SU:
	case OOMADJ_INIT:
		/* don't change oom value pid */
		ret = -1;
		break;
	case OOMADJ_FOREGRD_LOCKED:
		ret = proc_set_oom_score_adj(pid, OOMADJ_FOREGRD_UNLOCKED);
		break;
	case OOMADJ_BACKGRD_LOCKED:
		processinfo = find_process_info(NULL, pid, NULL);
		if (processinfo)
			ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_UNLOCKED);
		break;
	case OOMADJ_SERVICE_FOREGRD:
		ret = proc_set_oom_score_adj(pid, OOMADJ_SERVICE_DEFAULT);
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

void proc_set_group(pid_t onwerpid, pid_t childpid)
{
	int oom_score_adj = 0;
	struct proc_process_info_t *process_info =
		find_process_info(NULL, onwerpid, NULL);

	if (proc_get_oom_score_adj(onwerpid, &oom_score_adj) < 0) {
		_D("owner pid(%d) was already terminated", onwerpid);
		return;
	}
	if (process_info) {
		proc_add_pid_list(process_info, childpid, RESOURCED_APP_TYPE_GROUP);
		proc_set_oom_score_adj(childpid, oom_score_adj);
	}
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
			if (!strcmp(cmdline, appname)) {
				foundpid = pid;
				break;
			}
		}
	}
	closedir(dp);
	return foundpid;
}
