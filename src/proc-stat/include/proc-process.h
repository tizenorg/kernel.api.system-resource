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
 * @file proc_process.h
 * @desc grouping process and setting oom adj value
 **/

#ifndef __PROC_PROCESS_H__
#define __PROC_PROCESS_H__

enum proc_sweep_type {
	PROC_SWEEP_EXCLUDE_ACTIVE,
	PROC_SWEEP_INCLUDE_ACTIVE,
};

int proc_sweep_memory(enum proc_sweep_type type, pid_t callpid);

int proc_set_foregrd(int pid, int oom_score_adj);
int proc_set_backgrd(int pid, int oom_score_adj);

int proc_set_active(int pid, int oom_score_adj);
int proc_set_inactive(int pid, int oom_score_adj);

int proc_set_service_oomscore(const pid_t pid, const int oom_score);


#endif /*__PROC_PROCESS_H__*/
