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
 * @file procfs.c
 *
 * @desc communicate with procfs in resourced
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <sys/stat.h>
#include <fcntl.h>

#include "resourced.h"
#include "trace.h"
#include "macro.h"
#include "util.h"
#include "procfs.h"
#include "proc-common.h"
#include "lowmem-common.h"

#define PAGE_SIZE_KB 4

int proc_get_cmdline(pid_t pid, char *cmdline)
{
	char buf[PROC_BUF_MAX];
	char cmdline_buf[PROC_NAME_MAX];
	char *filename;
	FILE *fp;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
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

pid_t find_pid_from_cmdline(char *cmdline)
{
	pid_t pid = -1, foundpid = -1;
	int ret = 0;
	DIR *dp;
	struct dirent dentry;
	struct dirent *result;
	char appname[PROC_NAME_MAX];

	dp = opendir("/proc");
	if (!dp) {
		_E("BACKGRD MANAGE : fail to open /proc");
		return RESOURCED_ERROR_FAIL;
	}
	while (!readdir_r(dp, &dentry, &result) && result != NULL) {
		if (!isdigit(dentry.d_name[0]))
			continue;

		pid = atoi(dentry.d_name);
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

int proc_get_label(pid_t pid, char *label)
{
	char buf[PROC_BUF_MAX];
	FILE *fp;

	snprintf(buf, sizeof(buf), "/proc/%d/attr/current", pid);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;

	if (fgets(label, PROC_NAME_MAX-1, fp) == NULL) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	fclose(fp);
	return RESOURCED_ERROR_NONE;
}

int proc_get_mem_usage(pid_t pid, unsigned int *vmsize, unsigned int *vmrss)
{
	char buf[PROC_BUF_MAX];
	char statm_buf[PROC_NAME_MAX];
	unsigned int size, rss;
	FILE *fp;


	snprintf(buf, sizeof(buf), "/proc/%d/statm", pid);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;

	if (fgets(statm_buf, PROC_NAME_MAX-1, fp) == NULL) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	fclose(fp);

	if (sscanf(statm_buf, "%u %u", &size, &rss) < 2)
		return RESOURCED_ERROR_FAIL;

	if (vmsize != NULL)
		*vmsize = size*PAGE_SIZE_KB;
	if (vmrss != NULL)
		*vmrss = rss*PAGE_SIZE_KB;

	return RESOURCED_ERROR_NONE;
}

unsigned int proc_get_mem_available(void)
{
	char buf[PATH_MAX];
	FILE *fp;
	char *idx;
	unsigned int free = 0, cached = 0;
	unsigned int available = 0;
	int check_free = 1;

	fp = fopen("/proc/meminfo", "r");

	if (!fp) {
		_E("%s open failed, %d", buf, fp);
		return available;
	}

	/*
	 * It is important to preserve the order of
	 * reading for performance purposes.
	 */
	while (fgets(buf, PATH_MAX, fp) != NULL) {
		if (check_free) {
			idx = strstr(buf, "MemFree:");
			if (idx) {
				idx += strlen("MemFree:");
				while (*idx < '0' || *idx > '9')
					idx++;
				free = atoi(idx);
				check_free = 0;
				continue;
			}
		}

		/*
		 * MemAvailable is introduced in Linux 3.14 kernel.
		 * If there is MemAvailable, use it instead of calculating
		 * available memory using MemFree and Cached.
		 */
		idx = strstr(buf, "MemAvailable:");
		if (idx) {
			idx += strlen("MemAvailable:");
			while (*idx < '0' || *idx > '9')
				idx++;
			available = atoi(idx);
			break;
		}

		idx = strstr(buf, "Cached:");
		if (idx) {
			idx += strlen("Cached:");
			while (*idx < '0' || *idx > '9')
				idx++;
			cached = atoi(idx);
			break;
		}
	}

	if (available == 0)
		available = free + cached;

	available >>= 10;
	fclose(fp);

	return available;
}

unsigned int proc_get_cpu_number(void)
{
	char buf[PATH_MAX];
	FILE *fp;
	int cpu = 0;

	fp = fopen("/proc/cpuinfo", "r");

	if (!fp) {
		_E("/proc/cpuinfo open failed");
		return RESOURCED_ERROR_FAIL;
	}

	while (fgets(buf, PATH_MAX, fp) != NULL) {
		if (!strncmp(buf, "processor", 9))
			cpu++;
	}

	fclose(fp);
	return cpu;
}

int proc_get_exepath(pid_t pid, char *buf, int len)
{
	char path[PROC_BUF_MAX];
	int ret = 0;

	sprintf(path, "/proc/%d/exe", pid);
	ret = readlink(path, buf, len-1);
	if (ret > 0)
		buf[ret] = '\0';
	else
		buf[0] = '\0';
	return RESOURCED_ERROR_NONE;
}

static int proc_get_data(char *path, char *buf, int len)
{
	int ret;
	_cleanup_close_ int fd = -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return RESOURCED_ERROR_FAIL;

	ret = read(fd, buf, len-1);
	if (ret < 0) {
		buf[0] = '\0';
		return RESOURCED_ERROR_FAIL;
	}
	buf[ret] = '\0';
	return RESOURCED_ERROR_NONE;
}

int proc_get_raw_cmdline(pid_t pid, char *buf, int len)
{
	char path[PROC_BUF_MAX];

	sprintf(path, "/proc/%d/cmdline", pid);
	return proc_get_data(path, buf, len);
}

int proc_get_stat(pid_t pid, char *buf, int len)
{
	char path[PROC_BUF_MAX];

	sprintf(path, "/proc/%d/stat", pid);
	return proc_get_data(path, buf, len);
}

int proc_get_status(pid_t pid, char *buf, int len)
{
	char path[PROC_BUF_MAX];

	sprintf(path, "/proc/%d/status", pid);
	return proc_get_data(path, buf, len);
}
