/*
 * resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 */

/*
 * @file logging-cpu.c
 *
 * @desc start cpu logging system for resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <linux/limits.h>

#include <ctype.h>
#include <stddef.h>

#include <dirent.h>
#include <sys/utsname.h>
#include <systemd/sd-journal.h>

#include "resourced.h"
#include "trace.h"
#include "module.h"
#include "macro.h"
#include "proc-process.h"
#include "logging.h"

#define	PROC_STAT_PATH "/proc/%d/stat"
#define	CPU_NAME "cpu"
#define	CPU_COMMIT_INTERVAL		30*60	/* 20 min */

#define	CPU_MAX_INTERVAL		20*60	/* 5 min */
#define	CPU_INIT_INTERVAL		20*60	/* 3 min */
#define	CPU_FOREGRD_INTERVAL		3*60	/* 1 min */
#define	CPU_BACKGRD_INTERVAL		10*60	/* 2 min */
#define	CPU_BACKGRD_OLD_INTERVAL	15*60	/* 5 min */

struct logging_cpu_info {
	unsigned long utime;
	unsigned long stime;
	unsigned long last_utime;
	unsigned long last_stime;
	bool last_commited;
	time_t last_log_time;
	time_t log_interval;
	pid_t last_pid;
};

static int get_cpu_time(pid_t pid, unsigned long *utime,
	unsigned long *stime)
{
	char proc_path[sizeof(PROC_STAT_PATH) + MAX_DEC_SIZE(int)];
	FILE *fp;

	assert(utime != NULL);
	assert(stime != NULL);

	sprintf(proc_path, PROC_STAT_PATH, pid);
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

static void update_log_interval(struct logging_cpu_info *loginfo, int oom,
	int always)
{
	if (!always && (oom < OOMADJ_FOREGRD_LOCKED))
		return;

	switch (oom) {
	case OOMADJ_DISABLE:
	case OOMADJ_SERVICE_MIN:
	case OOMADJ_SU:
		loginfo->log_interval = CPU_MAX_INTERVAL;
		break;
	case OOMADJ_INIT:
		loginfo->log_interval = CPU_INIT_INTERVAL;
		break;
	case OOMADJ_FOREGRD_LOCKED:
	case OOMADJ_FOREGRD_UNLOCKED:
	case OOMADJ_BACKGRD_LOCKED:
	case OOMADJ_SERVICE_DEFAULT:
	case OOMADJ_SERVICE_FOREGRD:
		loginfo->log_interval = CPU_FOREGRD_INTERVAL;
		break;
	case OOMADJ_BACKGRD_UNLOCKED:
	case OOMADJ_SERVICE_BACKGRD:
		loginfo->log_interval = CPU_BACKGRD_INTERVAL;
		break;
	default:
		if (oom > OOMADJ_BACKGRD_UNLOCKED)
			loginfo->log_interval = CPU_BACKGRD_OLD_INTERVAL;
		break;
	}
}

static int init_cpu_info(void **pl, int pid, int oom, time_t now)
{
	struct logging_cpu_info *info;

	info = (struct logging_cpu_info *)
			malloc(sizeof(struct logging_cpu_info));
	if (!info) {
		_E("malloc for logging_cpu_info is failed");
		return RESOURCED_ERROR_FAIL;
	}
	info->last_pid = pid;
	info->utime = 0;
	info->stime = 0;
	info->last_utime = 0;
	info->last_stime = 0;
	info->last_log_time = now;
	info->last_commited = false;

	update_log_interval(info, oom, 1);
	*pl = (void *)info;
	return RESOURCED_ERROR_NONE;
}

/* pss_interval should be adjusted depending on app type */
static int update_cpu_info(void *pl, pid_t pid, int oom,
	time_t now, unsigned always)
{
	int ret = RESOURCED_ERROR_NONE;
	struct logging_cpu_info *loginfo = (struct logging_cpu_info *)pl;
	unsigned long utime = 0, stime = 0;
	unsigned long utime_diff = 0, stime_diff = 0;

	if (!always) {
		unsigned long update_interval = now - loginfo->last_log_time;
		if (update_interval < CPU_MAX_INTERVAL) {
			if (now < loginfo->last_log_time + loginfo->log_interval)
				return ret;
		} else {
			loginfo->last_log_time = now;
		}
	}

	ret = get_cpu_time(pid, &utime, &stime);

	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	if (loginfo->last_pid == pid) {
		if (loginfo->last_utime > utime)
			goto out;

		utime_diff = utime - loginfo->last_utime;
		loginfo->last_utime = utime;
		loginfo->utime += utime_diff;
		if (loginfo->stime > stime)
			goto out;
		stime_diff = stime - loginfo->last_stime;
		loginfo->last_stime = stime;
		loginfo->stime += stime_diff;

	} else {
		loginfo->last_pid = pid;
		loginfo->utime += utime;
		loginfo->stime += stime;
		loginfo->last_utime = utime;
		loginfo->last_stime = stime;
	}

out:
	loginfo->last_log_time = now;
	loginfo->last_commited = false;
	update_log_interval(loginfo, oom, 0);
	return ret;
}

static int write_cpu_info(char *name, struct logging_infos *infos,
	int ss_index)
{
	struct logging_cpu_info *ci = infos->stats[ss_index];

	if (!infos->running && ci->last_commited)
		return RESOURCED_ERROR_NONE;

	sd_journal_send("NAME=cpu",
		"TIME=%ld", ci->last_log_time,
		"PNAME=%s", name,
		"UTIME=%ld", ci->utime,
		"STIME=%ld", ci->stime,
		NULL);

	ci->last_commited = true;

	return RESOURCED_ERROR_NONE;
}

static struct logging_info_ops cpu_info_ops = {
	.update	= update_cpu_info,
	.write	= write_cpu_info,
	.init	= init_cpu_info,
};

static int logging_cpu_init(void *data)
{
	int ret;

	ret = register_logging_subsystem(CPU_NAME, &cpu_info_ops);
	if(ret != RESOURCED_ERROR_NONE) {
		_E("register logging subsystem failed");
		return RESOURCED_ERROR_FAIL;
	}
	ret = update_commit_interval(CPU_NAME, CPU_COMMIT_INTERVAL);
	if(ret != RESOURCED_ERROR_NONE) {
		_E("update commit interval logging subsystem failed");
		return RESOURCED_ERROR_FAIL;
	}

	_D("logging cpu init finished");
	return RESOURCED_ERROR_NONE;
}

static int logging_cpu_exit(void *data)
{
	_D("logging cpu exit");
	return RESOURCED_ERROR_NONE;
}

static struct module_ops logging_cpu_ops = {
	.priority	= MODULE_PRIORITY_NORMAL,
	.name		= "logging_cpu",
	.init		= logging_cpu_init,
	.exit		= logging_cpu_exit,
};

MODULE_REGISTER(&logging_cpu_ops)
