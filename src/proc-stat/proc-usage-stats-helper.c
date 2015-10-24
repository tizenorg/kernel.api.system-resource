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

/*
 * @file proc-usage-stats-helper.c
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <sys/types.h>
#include <unistd.h>

#include "proc-usage-stats-helper.h"
#include "macro.h"
#include "trace.h"

#define BtoKiB(bytes)   (bytes >> 10)
#define kBtoKiB(kbytes) (int)(((long long)kbytes * 1024)/1000)

#define TASK_NAME_BASE "runtime_info_%s_usage"

static int proc_get_virtual_mem_size(int pid, int *vsize)
{
	FILE *proc_stat;
	char buf[1024];
	unsigned long vsz;

	proc_stat = NULL;

	if (!vsize)
		goto error;

	snprintf(buf, sizeof(buf), "/proc/%d/stat", pid);
	proc_stat = fopen(buf, "r");
	if (!proc_stat)
		goto error;

	while (fgets(buf, sizeof(buf), proc_stat) != NULL) {
		if (sscanf(buf, "%*d %*s %*c %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %lu",
					&vsz) != 1)
			goto error;
	}
	fclose(proc_stat);

	*vsize =  BtoKiB(vsz);
	return RESOURCED_ERROR_NONE;

error:
	if (proc_stat)
		fclose(proc_stat);
	_E("error reading /proc/%d/stat file", pid);
	return RESOURCED_ERROR_FAIL;
}

static int proc_get_smaps_info(int pid, struct process_memory_info_s *mem_info)
{
	FILE *smaps;
	char buf[1024];
	int value;

	smaps = NULL;

	if (!mem_info)
		goto error;

	snprintf(buf, sizeof(buf), "/proc/%d/smaps", pid);
	smaps = fopen(buf, "r");
	if (!smaps)
		goto error;

	while (fgets(buf, sizeof(buf), smaps) != NULL) {
		if (sscanf(buf, "Rss: %d kB", &value) == 1)
			mem_info->rss += kBtoKiB(value);
		else if (sscanf(buf, "Pss: %d kB", &value) == 1)
			mem_info->pss += kBtoKiB(value);
		else if (sscanf(buf, "Shared_Clean: %d kB", &value) == 1)
			mem_info->shared_clean += kBtoKiB(value);
		else if (sscanf(buf, "Shared_Dirty: %d kB", &value) == 1)
			mem_info->shared_dirty += kBtoKiB(value);
		else if (sscanf(buf, "Private_Clean: %d kB", &value) == 1)
			mem_info->private_clean += kBtoKiB(value);
		else if (sscanf(buf, "Private_Dirty: %d kB", &value) == 1)
			mem_info->private_dirty += kBtoKiB(value);
	}
	fclose(smaps);

	return RESOURCED_ERROR_NONE;

error:
	if (smaps)
		fclose(smaps);
	_E("error reading /proc/%d/smaps file", pid);
	return RESOURCED_ERROR_FAIL;
}

/* Helper functions to get the needed memory usage info. */
void proc_get_memory_usage(int pid, struct process_memory_info_s *mem_info)
{
	if (!mem_info)
		return;

	if (pid < 0)
		goto error;

	memset(mem_info, 0, sizeof(struct process_memory_info_s));
	if (proc_get_virtual_mem_size(pid, &mem_info->vsz) != RESOURCED_ERROR_NONE)
		goto error;

	if (proc_get_smaps_info(pid, mem_info) != RESOURCED_ERROR_NONE)
		goto error;

	return;

error:
	mem_info->vsz = INVALID_PROCESS_INFO_FIELD_VALUE;
	mem_info->rss = INVALID_PROCESS_INFO_FIELD_VALUE;
	mem_info->pss = INVALID_PROCESS_INFO_FIELD_VALUE;
	mem_info->shared_clean = INVALID_PROCESS_INFO_FIELD_VALUE;
	mem_info->shared_dirty = INVALID_PROCESS_INFO_FIELD_VALUE;
	mem_info->private_clean = INVALID_PROCESS_INFO_FIELD_VALUE;
	mem_info->private_dirty = INVALID_PROCESS_INFO_FIELD_VALUE;
}

/* Helper functions to get the needed cpu usage info. */
void proc_get_cpu_usage(int pid, struct process_cpu_usage_s *cpu_usage)
{
	unsigned long utime, stime;
	FILE *proc_stat;
	char buf[1024];

	proc_stat = NULL;

	if (!cpu_usage)
		return;

	if (pid < 0)
		goto error;

	snprintf(buf, sizeof(buf), "/proc/%d/stat", pid);
	proc_stat = fopen(buf, "r");
	if (!proc_stat)
		goto error;
	while (fgets(buf, sizeof(buf), proc_stat) != NULL) {
		if (sscanf(buf, "%*d %*s %*c %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %lu %lu",
				&utime, &stime) != 2) {
			goto error;
		}
	}
	fclose(proc_stat);

	cpu_usage->utime = (int)utime;
	cpu_usage->stime = (int)stime;
	return;

error:
	if (proc_stat)
		fclose(proc_stat);
	_E("error reading /proc/%d/stat file", pid);
	cpu_usage->utime = INVALID_PROCESS_INFO_FIELD_VALUE;
	cpu_usage->stime = INVALID_PROCESS_INFO_FIELD_VALUE;
}

/* Helper function to read from usage_info struct and populate
 * result according to the task type */
int proc_read_from_usage_struct(void *usage_info_list, int index,
		int *result, runtime_info_task_type type)
{
	if (!usage_info_list || !result || (index < 0)) {
		_E("invalid input");
		return RESOURCED_ERROR_FAIL;
	}

	if (type == RUNTIME_INFO_TASK_MEMORY) {
		struct process_memory_info_s *mem_info;

		mem_info = (struct process_memory_info_s *)usage_info_list;
		result[0] = mem_info[index].vsz;
		result[1] = mem_info[index].rss;
		result[2] = mem_info[index].pss;
		result[3] = mem_info[index].shared_clean;
		result[4] = mem_info[index].shared_dirty;
		result[5] = mem_info[index].private_clean;
		result[6] = mem_info[index].private_dirty;
	} else {
		struct process_cpu_usage_s *cpu_usage;

		cpu_usage = (struct process_cpu_usage_s *)usage_info_list;
		result[0] = cpu_usage[index].utime;
		result[1] = cpu_usage[index].stime;
	}

	return RESOURCED_ERROR_NONE;
}

/* Create task name according to the current time and
 * set it to the input param task_name */
void proc_get_task_name(char *task_name, int size,
		runtime_info_task_type task_type)
{
	struct tm cur_tm;
	time_t now;
	char buf[TASK_NAME_SIZE];

	snprintf(buf, sizeof(buf), TASK_NAME_BASE,
			((task_type == RUNTIME_INFO_TASK_MEMORY) ? "memory" : "cpu"));

	if (!task_name || size <= 0)
		return;

	now = time(NULL);
	if (localtime_r(&now, &cur_tm) == NULL) {
		_E("Failed to get localtime");
		snprintf(task_name, size, "%s_%llu",
				buf, (long long)now);
		return;
	}

	snprintf(task_name, size, "%s_%.4d%.2d%.2d_%.2d%.2d%.2d",
			buf, (1900 + cur_tm.tm_year),
			1 + cur_tm.tm_mon, cur_tm.tm_mday, cur_tm.tm_hour,
			cur_tm.tm_min, cur_tm.tm_sec);
}

/* Helper function to free the runtime info task instance */
void proc_free_runtime_info_task(struct runtime_info_task *rt_task)
{
	if (!rt_task)
		return;

	if (rt_task->usage_info_list)
		free(rt_task->usage_info_list);

	if (rt_task->pipe_fds[0] >= 0)
		close(rt_task->pipe_fds[0]);
	if (rt_task->pipe_fds[1] >= 0)
		close(rt_task->pipe_fds[1]);

	dbus_message_unref(rt_task->task_msg);

	free(rt_task);
}
