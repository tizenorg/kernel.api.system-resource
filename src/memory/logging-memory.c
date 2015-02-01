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
 * @file logging-memory.c
 *
 * @desc start memory logging system for resourced
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
#include "file-helper.h"
#include "module.h"
#include "macro.h"
#include "proc-process.h"
#include "logging.h"

#define	MEM_NAME "memory"
#define	MEM_COMMIT_INTERVAL		30*60	/* 30 min */

#define	MEM_MAX_INTERVAL		10*60	/* 10 min */
#define	MEM_INIT_INTERVAL		8*60	/* 8 min */
#define MEM_FOREGRD_INTERVAL		5*60	/* 5 min */
#define MEM_BACKGRD_INTERVAL		10*60	/* 10 min */
#define MEM_BACKGRD_OLD_INTERVAL	15*60	/* 15 min */

struct logging_memory_info {
	unsigned avg_pss;
	unsigned max_pss;
	unsigned avg_uss;
	unsigned max_uss;
	unsigned sampling_count;
	bool last_commited;
	time_t last_log_time;
	time_t log_interval;
	pid_t current_pid;
};

struct mapinfo {
	unsigned size;
	unsigned rss;
	unsigned pss;
	unsigned shared_clean;
	unsigned shared_dirty;
	unsigned private_clean;
	unsigned private_dirty;
};

static int ignore_smaps_field;
static struct mapinfo *mi;
static struct mapinfo *maps;

static void check_kernel_version(void)
{
	struct utsname buf;
	int ret;

	ret = uname(&buf);

	if (ret)
		return;

	if (buf.release[0] == '3') {
		char *pch;
		char str[3];
		int sub_version;
		pch = strstr(buf.release, ".");
		strncpy(str, pch+1, 2);
		sub_version = atoi(str);

		if (sub_version >= 10)
			ignore_smaps_field = 8; /* Referenced, Anonymous, AnonHugePages,
						   Swap, KernelPageSize, MMUPageSize,
						   Locked, VmFlags */

		else
			ignore_smaps_field = 7; /* Referenced, Anonymous, AnonHugePages,
						   Swap, KernelPageSize, MMUPageSize,
						   Locked */
	} else {
		ignore_smaps_field = 4; /* Referenced, Swap, KernelPageSize,
					   MMUPageSize */
	}
}


/* 6f000000-6f01e000 rwxp 00000000 00:0c 16389419   /android/lib/libcomposer.so
 * 012345678901234567890123456789012345678901234567890123456789
 * 0         1         2         3         4         5
 */

static int read_mapinfo(char** smaps, int rest_line)
{
	char* line;
	int len;

	if ((line = cgets(smaps)) == 0)
		return RESOURCED_ERROR_FAIL;

	len    = strlen(line);
	if (len < 1) {
		_E("line is less than 1");
		return RESOURCED_ERROR_FAIL;
	}

	if ((line = cgets(smaps)) == 0)
		goto oops;
	if (sscanf(line, "Size: %d kB", &mi->size) != 1)
		goto oops;
	if ((line = cgets(smaps)) == 0)
		goto oops;
	if (sscanf(line, "Rss: %d kB", &mi->rss) != 1)
		goto oops;
	if ((line = cgets(smaps)) == 0)
		goto oops;
	if (sscanf(line, "Pss: %d kB", &mi->pss) == 1)
		if ((line = cgets(smaps)) == 0)
			goto oops;
	if (sscanf(line, "Shared_Clean: %d kB", &mi->shared_clean) != 1)
		goto oops;
	if ((line = cgets(smaps)) == 0)
		goto oops;
	if (sscanf(line, "Shared_Dirty: %d kB", &mi->shared_dirty) != 1)
		goto oops;
	if ((line = cgets(smaps)) == 0)
		goto oops;
	if (sscanf(line, "Private_Clean: %d kB", &mi->private_clean) != 1)
		goto oops;
	if ((line = cgets(smaps)) == 0)
		goto oops;
	if (sscanf(line, "Private_Dirty: %d kB", &mi->private_dirty) != 1)
		goto oops;

	while (rest_line-- && cgets(smaps))
		;

	return RESOURCED_ERROR_NONE;
 oops:
	_E("mi get error\n");
	return RESOURCED_ERROR_FAIL;
}

static void init_maps()
{
	maps->size = 0;
	maps->rss = 0;
	maps->pss = 0;
	maps->shared_clean = 0;
	maps->shared_dirty = 0;
	maps->private_clean = 0;
	maps->private_dirty = 0;
}

static int load_maps(int pid)
{
	char* smaps, *start;
	char tmp[128];

	sprintf(tmp, "/proc/%d/smaps", pid);
	smaps = cread(tmp);
	if (smaps == NULL)
		return RESOURCED_ERROR_FAIL;

	start = smaps;
	init_maps();

	while (read_mapinfo(&smaps, ignore_smaps_field)
			== RESOURCED_ERROR_NONE) {
		maps->size += mi->size;
		maps->rss += mi->rss;
		maps->pss += mi->pss;
		maps->shared_clean += mi->shared_clean;
		maps->shared_dirty += mi->shared_dirty;
		maps->private_clean += mi->private_clean;
		maps->private_dirty += mi->private_dirty;
	}

	if(start)
		free(start);
	return RESOURCED_ERROR_NONE;
}

int get_pss(pid_t pid, unsigned *pss, unsigned *uss)
{
	int ret;
	ret = load_maps(pid);
	if (ret != RESOURCED_ERROR_NONE) {
		*pss = 0;
		*uss = 0;
	} else {
		*pss = maps->pss;
		*uss = maps->private_clean + maps->private_dirty;
	}

	return ret;
}

static void update_log_interval(struct logging_memory_info *loginfo, int oom,
	int always)
{
	if (!always && (oom < OOMADJ_FOREGRD_LOCKED))
		return;

	switch (oom) {
	case OOMADJ_DISABLE:
	case OOMADJ_SERVICE_MIN:
	case OOMADJ_SU:
		loginfo->log_interval = MEM_MAX_INTERVAL;
		break;
	case OOMADJ_INIT:
		loginfo->log_interval = MEM_INIT_INTERVAL;
		break;
	case OOMADJ_FOREGRD_LOCKED:
	case OOMADJ_FOREGRD_UNLOCKED:
	case OOMADJ_BACKGRD_LOCKED:
		loginfo->log_interval = MEM_FOREGRD_INTERVAL;
		break;
	case OOMADJ_BACKGRD_UNLOCKED:
		loginfo->log_interval = MEM_BACKGRD_INTERVAL;
		break;
	default:
		if (oom > OOMADJ_BACKGRD_UNLOCKED)
			loginfo->log_interval = MEM_BACKGRD_OLD_INTERVAL;
		break;
	}
}

static int init_memory_info(void **pl, pid_t pid, int oom, time_t now)
{
	struct logging_memory_info *info;

	info = (struct logging_memory_info *)
			malloc(sizeof(struct logging_memory_info));
	if (!info) {
		_E("malloc for logging_memory_info is failed");
		return RESOURCED_ERROR_FAIL;
	}
	info->current_pid = 0;
	info->avg_pss = 0;
	info->max_pss = 0;
	info->avg_uss = 0;
	info->max_uss = 0;
	info->last_log_time = now;
	info->sampling_count = 0;
	info->last_commited = false;

	update_log_interval(info, oom, 1);
	*pl = (void *)info;
	return RESOURCED_ERROR_NONE;
}

/* pss_interval should be adjusted depending on app type */
static int update_memory_info(void *pl, pid_t pid, int oom,
	time_t now, unsigned always)
{
	int ret = RESOURCED_ERROR_NONE;
	struct logging_memory_info *loginfo = (struct logging_memory_info *)pl;
	unsigned pss = 0, uss = 0;

	if (!always)
		if (now < loginfo->last_log_time + loginfo->log_interval)
			return ret;

	ret = get_pss(pid, &pss, &uss);

	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	loginfo->avg_pss = (loginfo->avg_pss * loginfo->sampling_count +
			pss)/(loginfo->sampling_count + 1);
	loginfo->avg_uss = (loginfo->avg_uss * loginfo->sampling_count +
			uss)/(loginfo->sampling_count + 1);
	if (pss > loginfo->max_pss)
		loginfo->max_pss = pss;
	if (uss > loginfo->max_uss)
		loginfo->max_uss = uss;

	loginfo->sampling_count++;
	loginfo->last_log_time = now;
	loginfo->last_commited = false;
	update_log_interval(loginfo, oom, 0);

	return ret;
}

static int write_memory_info(char *name, struct logging_infos *infos,
	int ss_index)
{
	struct logging_memory_info *mi = infos->stats[ss_index];

	if (!infos->running && mi->last_commited)
		return RESOURCED_ERROR_NONE;

	sd_journal_send("NAME=memory",
		"TIME=%ld", mi->last_log_time,
		"PNAME=%s", name,
		"AVG_PSS=%lu", mi->avg_pss,
		"MAX_PSS=%lu", mi->max_pss,
		"AVG_USS=%lu", mi->avg_uss,
		"MAX_USS=%lu", mi->max_uss,
		NULL);

	mi->last_commited = true;

	return RESOURCED_ERROR_NONE;
}

static struct logging_info_ops memory_info_ops = {
	.update	= update_memory_info,
	.write	= write_memory_info,
	.init	= init_memory_info,
};

static int allocate_memory(void)
{
	maps = (struct mapinfo *)malloc(sizeof(struct mapinfo));

	if (!maps) {
		_E("fail to allocate mapinfo\n");
		return RESOURCED_ERROR_FAIL;
	}

	mi = malloc(sizeof(struct mapinfo));
	if (mi == NULL) {
		_E("malloc failed for mapinfo");
		free(maps);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
}

static void free_memory(void)
{
	free(maps);
	free(mi);
}

static int logging_memory_init(void *data)
{
	int ret;
	check_kernel_version();

	ret = allocate_memory();

	if (ret != RESOURCED_ERROR_NONE) {
		_E("allocate structures failed");
		return RESOURCED_ERROR_FAIL;
	}

	ret = register_logging_subsystem(MEM_NAME, &memory_info_ops);
	if(ret != RESOURCED_ERROR_NONE) {
		_E("register logging subsystem failed");
		free_memory();
		return RESOURCED_ERROR_FAIL;
	}
	ret = update_commit_interval(MEM_NAME, MEM_COMMIT_INTERVAL);
	if(ret != RESOURCED_ERROR_NONE) {
		_E("update commit interval logging subsystem failed");
		free_memory();
		return RESOURCED_ERROR_FAIL;
	}

	_D("logging memory init finished");
	return RESOURCED_ERROR_NONE;
}

static int logging_memory_exit(void *data)
{
	_D("logging memory finalize");
	free_memory();
	return RESOURCED_ERROR_NONE;
}

static struct module_ops logging_memory_ops = {
	.priority	= MODULE_PRIORITY_NORMAL,
	.name		= "logging_memory",
	.init		= logging_memory_init,
	.exit		= logging_memory_exit,
};

MODULE_REGISTER(&logging_memory_ops)
