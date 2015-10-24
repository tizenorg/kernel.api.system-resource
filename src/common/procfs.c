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
#include "module.h"

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
	FILE *fp;
	struct lowmem_data_type lowmem_data;
	static const struct module_ops *lowmem;
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};

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

	lowmem = find_module("lowmem");
	if (lowmem && (oom_score_adj >= OOMADJ_SU)) {
		lowmem_data.control_type = LOWMEM_MOVE_CGROUP;
		lowmem_data.args[0] = (int)pid;
		lowmem_data.args[1] = (int)oom_score_adj;
		lowmem->control(&lowmem_data);
	}

	return RESOURCED_ERROR_NONE;
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
	unsigned int mem_available, mem_free, cached;
	int r;
	char buf[256];

	/*
	 * Let's try to read MemAvailable, it's in kernel from 3.14,
	 * but it's often backported. So we don't need to calculate the values
	 * by hand.
	 */
	r = proc_get_meminfo("MemAvailable", &mem_available);
	if (r < 0) {
		_E("Failed to get MemAvailable: %s", strerror_r(-r, buf, sizeof(buf)));
		return 0;
	}

	if (mem_available)
		return KBYTE_TO_MBYTE(mem_available);

	/*
	 * If it's not available read and calculate the size just like
	 * the kernel does.
	 */
	r = proc_get_meminfo("MemFree", &mem_free);
	if (r < 0) {
		_E("Failed to get MemFree: %s", strerror_r(-r, buf, sizeof(buf)));
		return 0;
	}

	r = proc_get_meminfo("Cached", &cached);
	if (r < 0) {
		_E("Failed to get Cached: %s", strerror_r(-r, buf, sizeof(buf)));
		return 0;
	}

	return KBYTE_TO_MBYTE(mem_free) + KBYTE_TO_MBYTE(cached);

}

int proc_get_meminfo(const char *info, unsigned int *size)
{
	_cleanup_fclose_ FILE *fp = NULL;

	assert(size);
	assert(info);

	fp = fopen("/proc/meminfo", "r");
	if (!fp)
		return -errno;

	while (true) {
		_cleanup_free_ char *line = NULL, *key = NULL;
		unsigned int v = 0;

		line = (char *)malloc(LINE_MAX);
		if (!line)
			return -ENOMEM;

		if (!fgets(line, LINE_MAX, fp)) {
			if (feof(fp))
				return -ENODATA;

			return ferror(fp);
		}

		if (sscanf(line, "%m[^:]: %u", &key, &v) < 2)
			continue;

		if (!strncmp(key, info, strlen(key))) {
			*size = v;
			break;
		}
	}

	return 0;
}

int proc_get_cpu_time(pid_t pid, unsigned long *utime,
		unsigned long *stime)
{
	char proc_path[sizeof(PROC_STAT_PATH) + MAX_DEC_SIZE(int)];
	_cleanup_fclose_ FILE *fp = NULL;

	assert(utime != NULL);
	assert(stime != NULL);

	snprintf(proc_path, sizeof(proc_path), PROC_STAT_PATH, pid);
	fp = fopen(proc_path, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;

	if (fscanf(fp, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s") < 0) {
		return RESOURCED_ERROR_FAIL;
	}

	if (fscanf(fp, "%lu %lu", utime, stime) < 1) {
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
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

	snprintf(path, sizeof(path), "/proc/%d/exe", pid);
	ret = readlink(path, buf, len-1);
	if (ret > 0)
		buf[ret] = '\0';
	else
		buf[0] = '\0';
	return RESOURCED_ERROR_NONE;
}

static int proc_get_data(char *path, char *buf, int len)
{
	_cleanup_close_ int fd = -1;
	int ret;

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
	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
	return proc_get_data(path, buf, len);
}

int proc_get_stat(pid_t pid, char *buf, int len)
{
	char path[PROC_BUF_MAX];
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	return proc_get_data(path, buf, len);
}

int proc_get_status(pid_t pid, char *buf, int len)
{
	char path[PROC_BUF_MAX];
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	return proc_get_data(path, buf, len);
}
