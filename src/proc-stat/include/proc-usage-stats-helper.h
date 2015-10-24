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
 * @file  proc-usage-stats-helper.h
 * @desc  process usage stats helper methods
 **/

#ifndef __RESOURCED_PROC_USAGE_STATS_HELPER_H__
#define __RESOURCED_PROC_USAGE_STATS_HELPER_H__

#include <unistd.h>
#include <fcntl.h>
#include <resourced.h>
#include <E_DBus.h>
#include <pthread.h>
#include <time.h>

#define INVALID_PROCESS_INFO_FIELD_VALUE -1

#define TASK_NAME_SIZE 256

/* Process memory usage info struct (original design in runtime-info API) */
struct process_memory_info_s {
	int vsz;            /**< Virtual memory size (KiB) */
	int rss;            /**< Resident set size (KiB) */
	int pss;            /**< Proportional set size (KiB) */
	int shared_clean;   /**< Not modified and mapped by other processes (KiB) */
	int shared_dirty;   /**< Modified and mapped by other processes (KiB) */
	int private_clean;  /**< Not modified and available only to that process (KiB) */
	int private_dirty;  /**< Modified and available only to that process (KiB) */
};

struct process_cpu_usage_s {
	int utime;    /**< Amount of time that this process has spent in user mode */
	int stime;    /**< Amount of time that this process has spent in kernel mode */
};


typedef enum {
	RUNTIME_INFO_TASK_MEMORY,	/**< Represents memory usage requests */
	RUNTIME_INFO_TASK_CPU		/**< Represents cpu usage requests */
} runtime_info_task_type;

/* Runtime info task struct. Represents each request received by the runtime-info library */
struct runtime_info_task {
	runtime_info_task_type task_type; /**< Task type */
	int task_size;			/**< Size of the process id array */
	int pipe_fds[2];		/**< fds of the read and write end of the pipe */
	char task_name[TASK_NAME_SIZE];	/**< The name assigned to task */
	int *pid_list;			/**< Pointer to the process id array in the dbus message */
	void *usage_info_list;		/**< Pointer to the memory containing the usage info results */
	DBusMessage *task_msg;		/**< Pointer to the dbus message sent by runtime-info. */
};

void proc_get_memory_usage(int pid, struct process_memory_info_s *mem_info);
void proc_get_cpu_usage(int pid, struct process_cpu_usage_s *cpu_usage);
int proc_read_from_usage_struct(void *usage_info_list, int index, int *result, runtime_info_task_type task_type);
void proc_get_task_name(char *task_name, int size, runtime_info_task_type task_type);
void proc_free_runtime_info_task(struct runtime_info_task *rt_task);

/* TODO
 * ** Return different failure values in reply dbus message according to reason
 * ** Add some kind of identifier for the process making the method call,
 *	and use this id in the task file name
 * ** Change to thread pool if needed
 */
#endif /* __RESOURCED_PROC_USAGE_STATS_HELPER_H__ */

