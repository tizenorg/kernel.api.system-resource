/*
 *  resourced
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file lowmem_process.h
 * @desc grouping process and setting oom adj value
 **/

#ifndef __LOWMEM_PROCESS_H__
#define __LOWMEM_PROCESS_H__

#include <proc_stat.h>

#define OOMADJ_SU                   (0)
#define OOMADJ_INIT                 (100)
#define OOMADJ_FOREGRD_LOCKED       (150)
#define OOMADJ_FOREGRD_UNLOCKED     (200)
#define OOMADJ_BACKGRD_LOCKED       (250)
#define OOMADJ_BACKGRD_UNLOCKED     (300)
#define OOMADJ_APP_LIMIT            OOMADJ_INIT
#define OOMADJ_APP_MAX              (990)
#define OOMADJ_APP_INCREASE         (30)

int lowmem_get_proc_cmdline(pid_t pid, char *cmdline);
int lowmem_sweep_memory(int callpid);

int get_proc_oom_score_adj(int pid, int *oom_score_adj);
int set_proc_oom_score_adj(int pid, int oom_score_adj);

int lowmem_set_foregrd(int pid, int oom_score_adj);
int lowmem_set_backgrd(int pid, int oom_score_adj);

int lowmem_set_active(int pid, int oom_score_adj);
int lowmem_set_inactive(int pid, int oom_score_adj);

int lowmem_get_candidate_pid(void);

#endif /*__LOWMEM_PROCESS_H__*/
