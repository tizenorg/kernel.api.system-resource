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

#ifndef __PROCFS_H__
#define __PROCFS_H__

#include <resourced.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>

#define OOMADJ_DISABLE			(-1000)
#define OOMADJ_SERVICE_MIN		(-900)
#define OOMADJ_SU			(0)
#define OOMADJ_INIT			(100)
#define OOMADJ_FOREGRD_LOCKED		(150)
#define OOMADJ_FOREGRD_UNLOCKED		(200)
#define OOMADJ_BACKGRD_PERCEPTIBLE	(230)
#define OOMADJ_BACKGRD_LOCKED		(250)
#define OOMADJ_FAVORITE			(270)
#define OOMADJ_BACKGRD_UNLOCKED		(300)
#define OOMADJ_APP_LIMIT		OOMADJ_INIT
#define OOMADJ_APP_MAX			(990)
#define OOMADJ_APP_INCREASE		(30)
#define OOMADJ_SERVICE_GAP		(10)
#define OOMADJ_SERVICE_DEFAULT		(OOMADJ_BACKGRD_LOCKED - OOMADJ_SERVICE_GAP)
#define OOMADJ_SERVICE_FOREGRD		(OOMADJ_FOREGRD_UNLOCKED - OOMADJ_SERVICE_GAP)
#define OOMADJ_SERVICE_BACKGRD		(OOMADJ_BACKGRD_UNLOCKED - OOMADJ_SERVICE_GAP)


#define PROC_OOM_SCORE_ADJ_PATH "/proc/%d/oom_score_adj"
#define PROC_STAT_PATH "/proc/%d/stat"

/**
 * @desc get command line from /proc/{pid}/cmdline
 * @return negative value if error
 */
int proc_get_cmdline(pid_t pid, char *cmdline);

/**
 * @desc find pid with /proc/{pid}/cmdline
 * it returns first entry when many pids have same cmdline
 * @return negative value if error
 */
pid_t find_pid_from_cmdline(char *cmdline);

/**
 * @desc get oom score adj value from /proc/{pid}/oom_score_adj
 * @return negative value if error or pid doesn't exist
 */
int proc_get_oom_score_adj(int pid, int *oom_score_adj);

/**
 * @desc set oom score adj value to /proc/{pid}/oom_score_adj
 * @return negative value if error or pid doesn't exist
 */
int proc_set_oom_score_adj(int pid, int oom_score_adj);

/**
 * @desc get smack subject label from /proc/{pid}/attr/current
 * this label can indicate package name about child processes
 * @return negative value if error or pid doesn't exist
 */
int proc_get_label(pid_t pid, char *label);

/**
 * @desc get VmSize and VmRSS from /proc/{pid}/statm file.
 * @return negative value if error or pid doesn't exist
 */
int proc_get_mem_usage(pid_t pid, unsigned int *vmsize, unsigned int *vmrss);

/**
 * @desc get MemAvaliable from /proc/meminfo or calcuate it by MemFree+Cached
 * @return 0 if the values can't be read or the avaliable memory value
 */
unsigned int proc_get_mem_available(void);

/**
 * @desc get number of CPUs from /proc/cpuinfo
 * @return 0 if the number can't be found or number of CPUs
 */
unsigned int proc_get_cpu_number(void);

/**
 * @desc get command line from /proc/{pid}/cmdline without any truncation
 * @return negative value if error
 */
int proc_get_raw_cmdline(pid_t pid, char *buf, int len);

/**
 * @desc get symblolic link about /proc/{pid}/exe
 * @return negative value if error
 */
int proc_get_exepath(pid_t pid, char *buf, int len);

/**
 * @desc get stat from /proc/{pid}/stat
 * @return negative value if error
 */
int proc_get_stat(pid_t pid, char *buf, int len);

/**
 * @desc get status from /proc/{pid}/status
 * @return negative value if error
 */
int proc_get_status(pid_t pid, char *buf, int len);

#endif /*__PROCFS_H__*/
