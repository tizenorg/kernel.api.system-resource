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

#include "resourced.h"
#include "trace.h"
#include "proc-main.h"
#include "lowmem-process.h"
#include "lowmem-handler.h"
#include "macro.h"
#include "proc-noti.h"
#include "proc-winstate.h"

#define PROC_NAME_MAX 512
#define PROC_BUF_MAX  64
#define PROC_OOM_SCORE_ADJ_PATH "/proc/%d/oom_score_adj"

static int lowmem_backgrd_manage(int currentpid)
{
	int pid = -1, pgid, ret;
	DIR *dp;
	struct dirent *dentry;
	FILE *fp;
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	char appname[PROC_NAME_MAX];
	int count = 0;

	int cur_oom = -1, prev_oom=OOMADJ_BACKGRD_UNLOCKED, select_pid=0;
	static int checkprevpid = 0;

	ret = lowmem_get_proc_cmdline(currentpid, appname);
	if (ret == RESOURCED_ERROR_NONE) {
		if (checkprevpid == currentpid) {
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
			lowmem_move_memcgroup(pid, OOMADJ_BACKGRD_UNLOCKED);
			continue;
		}

		if (select_pid != pid && select_pid == pgid && count < 16)
		{
			_D("found candidate child pid = %d, pgid = %d", pid, pgid);
		
			continue;
		}
		snprintf(buf, sizeof(buf), PROC_OOM_SCORE_ADJ_PATH, pid);
		fp = fopen(buf, "r+");
		if (fp == NULL)
			continue;
		if (fgets(buf, sizeof(buf), fp) == NULL) {
			fclose(fp);
			continue;
		}
		cur_oom = atoi(buf);
		if (cur_oom > OOMADJ_BACKGRD_UNLOCKED && cur_oom > prev_oom) {
			count = 0;
			
			select_pid = pid;
			prev_oom = cur_oom;
		}

		if (cur_oom >= OOMADJ_APP_MAX) {
			fclose(fp);
			continue;
		} else if (cur_oom >= OOMADJ_BACKGRD_UNLOCKED) {
			_D("BACKGRD : process %d set oom_score_adj %d (before %d)",
					pid, cur_oom+OOMADJ_APP_INCREASE, cur_oom);
			fprintf(fp, "%d", cur_oom+OOMADJ_APP_INCREASE);
		}
		fclose(fp);
	}
	checkprevpid = currentpid;
	closedir(dp);
	return RESOURCED_ERROR_OK;
}

static void lowmem_foregrd_manage(int pid)
{
	lowmem_cgroup_foregrd_manage(pid);
}

int lowmem_sweep_memory(int callpid)
{
	int pid = -1, count=0, ret;
	DIR *dp;
	struct dirent *dentry;
	FILE *fp;
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	char appname[PROC_NAME_MAX];

	int cur_oom = -1;
	dp = opendir("/proc");
	if (!dp) {
		_E("BACKGRD MANAGE : fail to open /proc");
		return RESOURCED_ERROR_FAIL;
	}
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
			ret = lowmem_get_proc_cmdline(pid, appname);
			if (ret != 0) {
				fclose(fp);
				continue;
			}
			kill(pid, SIGKILL);
			_D("sweep memory : background process %d(%s) killed",
					pid, appname);
			count++;
		}
		fclose(fp);
	}
	closedir(dp);
	return count;
}


int lowmem_get_proc_cmdline(pid_t pid, char *cmdline)
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


int get_proc_oom_score_adj(int pid, int *oom_score_adj)
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
	return RESOURCED_ERROR_OK;
}

int set_proc_oom_score_adj(int pid, int oom_score_adj)
{
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	FILE *fp;

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

	lowmem_move_memcgroup(pid, oom_score_adj);
	return 0;
}

int lowmem_set_foregrd(int pid, int oom_score_adj)
{
	int ret = 0;

	switch (oom_score_adj) {
	case OOMADJ_FOREGRD_LOCKED:
	case OOMADJ_FOREGRD_UNLOCKED:
	case OOMADJ_SU:
		ret = 0;
		break;
	case OOMADJ_BACKGRD_LOCKED:
		lowmem_foregrd_manage(pid);
		ret = set_proc_oom_score_adj(pid, OOMADJ_FOREGRD_LOCKED);
		break;
	case OOMADJ_BACKGRD_UNLOCKED:
		lowmem_foregrd_manage(pid);
		ret = set_proc_oom_score_adj(pid, OOMADJ_FOREGRD_UNLOCKED);
		break;
	case OOMADJ_INIT:
		ret = set_proc_oom_score_adj(pid, OOMADJ_FOREGRD_UNLOCKED);
		break;
	default:
		if (oom_score_adj > OOMADJ_BACKGRD_UNLOCKED) {
			ret = set_proc_oom_score_adj(pid, OOMADJ_FOREGRD_UNLOCKED);
		} else {
			_E("Unknown oom_score_adj value (%d) !", oom_score_adj);
			ret = -1;
		}
		break;

	}
	return ret;
}

int lowmem_set_backgrd(int pid, int oom_score_adj)
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
		ret = set_proc_oom_score_adj(pid, OOMADJ_BACKGRD_LOCKED);
		break;
	case OOMADJ_FOREGRD_UNLOCKED:
		lowmem_backgrd_manage(pid);
		ret = set_proc_oom_score_adj(pid, OOMADJ_BACKGRD_UNLOCKED);
		break;
	case OOMADJ_INIT:
		ret = set_proc_oom_score_adj(pid, OOMADJ_BACKGRD_UNLOCKED);
		break;
	default:
		if (oom_score_adj > OOMADJ_BACKGRD_UNLOCKED) {
			ret = 0;
		} else {
			_E("Unknown oom_score_adj value (%d) !", oom_score_adj);
			ret = -1;
		}
		break;
	}
	return ret;
}

int lowmem_set_active(int pid, int oom_score_adj)
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
		ret = set_proc_oom_score_adj(pid, OOMADJ_FOREGRD_LOCKED);
		break;
	case OOMADJ_BACKGRD_UNLOCKED:
		ret = set_proc_oom_score_adj(pid, OOMADJ_BACKGRD_LOCKED);
		break;
	case OOMADJ_INIT:
		ret = set_proc_oom_score_adj(pid, OOMADJ_BACKGRD_LOCKED);
		break;
	default:
		if (oom_score_adj > OOMADJ_BACKGRD_UNLOCKED) {
			ret = set_proc_oom_score_adj(pid, OOMADJ_BACKGRD_LOCKED);
		} else {
			_E("Unknown oom_score_adj value (%d) !", oom_score_adj);
			ret = -1;
		}
		break;
	}
	return ret;
}

int lowmem_set_inactive(int pid, int oom_score_adj)
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
		ret = set_proc_oom_score_adj(pid, OOMADJ_FOREGRD_UNLOCKED);
		break;
	case OOMADJ_BACKGRD_LOCKED:
		ret = set_proc_oom_score_adj(pid, OOMADJ_BACKGRD_UNLOCKED);
		break;
	case OOMADJ_INIT:
		ret = set_proc_oom_score_adj(pid, OOMADJ_BACKGRD_UNLOCKED);
		break;
	default:
		if (oom_score_adj > OOMADJ_BACKGRD_UNLOCKED) {
			ret = 0;
		} else {
			_E("Unknown oom_score_adj value (%d) !", oom_score_adj);
			ret = -1;
		}
		break;

	}
	return ret;
}
