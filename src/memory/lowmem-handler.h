/*
 * resourced
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
 * @file lowmem_handler.h
 * @desc handler function for setting memcgroup memory controller and
 *	receiving event fd.
 **/

#ifndef __LOWMEM_HANDLER_H__
#define __LOWMEM_HANDLER_H__

void lowmem_cgroup_foregrd_manage(int currentpid);
void lowmem_move_memcgroup(int pid, int oom_score_adj);
int lowmem_init(void);
void lowmem_dbus_init(void);
void lowmem_oom_killer_cb(int memcg_idx, int force); /* vmpressure-* version */

void set_threshold(int level, int thres);
void set_leave_threshold(int thres);

#define NUM_FOREGROUND			3
enum {
	MEMCG_MEMORY,
	MEMCG_FOREGROUND,
	MEMCG_BACKGROUND = MEMCG_FOREGROUND + NUM_FOREGROUND,
	MEMCG_MAX_GROUPS,
};

#endif /*__LOWMEM_HANDLER_H__*/
