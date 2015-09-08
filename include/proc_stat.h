/*
 * resourced
 *
 * Library for getting process statistics
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd.
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

#ifndef __LIB_PROC_STAT__
#define __LIB_PROC_STAT__

#ifndef __cplusplus
#include <stdbool.h>
#endif /* !__cplusplus */

#include <glib.h>
#include <resourced.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
typedef struct proc_stat_process_info	/** process statistics */
{
	pid_t pid;	/**< the process ID */
	char name[NAME_MAX]; /**< the name of process */

	bool valid; /** < whether this information is valid (can be used)*/
	bool active; /**< whether this process is active */
	bool fresh; /**< whether this process is newly created */
	unsigned long utime_diff; /**< user mode time this process spent during this measurement interval */
	unsigned long stime_diff;  /**< kernel mode time this process spent during this measurement interval */
	unsigned long utime_prev;  /**< previous user mode time this process spent during the last measurement interval */
	unsigned long stime_prev; /**< previous kernel mode time this process spent during the last measurement interval */

	unsigned int rss; /**<resident set size of this process by Kb */

} proc_stat_process_info;


typedef struct proc_stat_system_time	/** The time information system spent, measured in units of USER_HZ **/
{
	unsigned long long total_time;		/**< the total time system spent */
	unsigned long long user_time;		/**< the time system spent in user mode */
	unsigned long long nice_time;		/**< the time system spent in user mode with low priority(nice) */
	unsigned long long system_time;		/**< the time system spent in system mode */
	unsigned long long idle_time;		/**< the time system spent in idle task */
	unsigned long long iowait_time;		/**< the time system spent waiting for IO */
	unsigned long long irq_time;		/**< the time system spent servicing interrupts */
	unsigned long long softirq_time;	/**< the time system spent servicing softirqs */
} proc_stat_system_time;


/**
* The following APIs are not thread safe !!!
*
*/

/**
 * @brief Initialize internal resources which are used for managing process statistics
 *
 * @return nothing
 *
 * This function initializes internal resources which are used for managing process statistics so should be called firstly
 */
void proc_stat_init(void);

/**
 * @brief Release internal resources which are used for managing process statistics
 *
 * @return nothing
 *
 * This function releases internal resources which are used for managing process statistics
  */

void proc_stat_finalize(void);


/**
 * @brief Get process statistics between two consecutive its calls
 *
 * @param valid_proc_infos GArray instance to be filled with valid proc_stat_process_info
 * @param terminated_proc_infos GArray instance to be filled with proc_stat_process_info instances which were terminated between two consecutive its calls
		  ,pass NULL if this information is not necessary
 * @param total_valid_proc_time the sum of time spent by all valid proc_stat_process_info instance, pass NULL if if this information is not necessary
 * @return  true on success.
 *
 * This function gets process statistics between two consecutive its calls
 */

bool proc_stat_get_process_info(GArray *valid_proc_infos, GArray *terminated_proc_infos,
					   unsigned long *total_valid_proc_time);

/**
 * @brief Get the difference of system time between two consecutive its calls
 *
 * @param st_diff the difference of system time
 * @return  true on success, false when it is called first because it can't get the time difference.
 *
 * This function gets the difference of system time between two consecutive its calls
 */
bool proc_stat_get_system_time_diff(proc_stat_system_time *st_diff);


/**
 * @brief get total memory size by MB unit from /proc/meminfo
 *
 * @param total_mem to get the value of MemTotal
 * @return true on success, false when it doesn't get values from /proc/meminfo
 *
 * This function gets total memory size by MB unit from /proc/meminfo
 * total is from "MemTotal"
 */

bool proc_stat_get_total_mem_size(unsigned int *total_mem);

/**
 * @brief get free memory size by MB unit from /proc/meminfo
 *
 * @param free_mem to get free size of memory
 * @return true on success, false when it doesn't get values from /proc/meminfo
 *
 * This function gets free memory size by MB unit from /proc/meminfo
 * free_mem is calculated by "MemFree" + "Buffers" + "Cached" + "SwapCache" - "Shmem"
 */

bool proc_stat_get_free_mem_size(unsigned int *free_mem);

/**
 * @brief get CPU time by pid
 *
 * @param pid which process to get CPU time
 * @param utime user mode time this process spent
 * @param stime kernel mode time this process spent
 * @return true on success, false when it doesn't get values from /proc/<pid>/stat
 *
 * This function gets CPU usage of a process by clock ticks unit from /proc/<pid>/stat
 */

bool proc_stat_get_cpu_time_by_pid(pid_t pid, unsigned long *utime, unsigned long *stime);

/**
 * @brief get memory usage by pid
 *
 * @param pid which process to get memory usage
 * @param rss a process's memory usage
 * @return true on success, false when it doesn't get values from /proc/<pid>/statm
 *
 * This function gets memory usage of a process by KB unit from rss of /proc/<pid>/statm
 */

bool proc_stat_get_mem_usage_by_pid(pid_t pid, unsigned int *rss);



/**
 * @brief Get process name
 *
 * @param pid which process to get name
 * @name  name a process's name
 *	  the size of name should be equal or larger than NAME_MAX
 * @return  true on success, false on failure.
 *
 * This function gets process name
 *
 */
bool proc_stat_get_name_by_pid(pid_t pid, char *name);



/**
 * @brief Get pids under /proc file system
 *
 * @param pids which is filled with pids under /proc file system
 *	  The memory to accommodate pids will be allocated in this fuction
 *	  so the caller has reponsibility to free this memory
 * @param cnt which is the count of pids
 * @return  true on success, false on failure.
 *
 * This function fills pids(param) with pids under /proc file system.
 *
 */
bool proc_stat_get_pids(pid_t **pids, int *cnt);


/**
 * @brief return whether currently GPU is on or off
 *
 * @return  true on GPU being on, false on GPU being off
 *
 * This function returns whether currently GPU is on or off
 *
 */
bool proc_stat_is_gpu_on(void);


/**
 * @brief return GPU clock by MHz unit
 *
 * @return return GPU clock on success , -1 on false
 *
 * This function returns GPU clock
 *
 */

unsigned int proc_stat_get_gpu_clock(void);


enum proc_cgroup_cmd_type { /** cgroup command type **/
	PROC_CGROUP_SET_FOREGRD,
	PROC_CGROUP_SET_ACTIVE,
	PROC_CGROUP_SET_BACKGRD,
	PROC_CGROUP_SET_INACTIVE,
	PROC_CGROUP_SET_LAUNCH_REQUEST,
	PROC_CGROUP_SET_RESUME_REQUEST,
	PROC_CGROUP_SET_TERMINATE_REQUEST,
	PROC_CGROUP_SET_SERVICE_REQUEST,
	PROC_CGROUP_SET_NOTI_REQUEST,
	PROC_CGROUP_SET_PROC_EXCLUDE_REQUEST,
	PROC_CGROUP_GET_MEMSWEEP,
};


/**
 * @desc Set processes to foreground.
 */
resourced_ret_c proc_cgroup_foregrd(void);

/**
 * @desc Set processes to background.
 */
resourced_ret_c proc_cgroup_backgrd(void);

/**
 * @desc Set process to active
 */
resourced_ret_c proc_cgroup_active(pid_t pid);

/**
 * @desc Set process to inactive
 */
resourced_ret_c proc_cgroup_inactive(pid_t pid);

/**
 * @desc Change process status about cgroup with type
 */
resourced_ret_c proc_group_change_status(int type, pid_t pid, char* app_id);

/**
 * @desc Send process launch request
 */
resourced_ret_c proc_cgroup_launch(int type, pid_t pid, char* app_id, char* pkg_id);


/**
 * @brief sweep memory about background processes
 *
 * @return return num of swept processes
 *
 * This function returns GPU clock
 *
 */
resourced_ret_c proc_cgroup_sweep_memory(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LIB_PROC_STAT__ */
