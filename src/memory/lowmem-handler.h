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

#include <memory-common.h>

void lowmem_dbus_init(void);
int lowmem_memory_oom_killer(int flags);
int lowmem_proactive_oom_killer(int flags, char *appid);
void lowmem_change_memory_state(int state, int force);
void lowmem_memcg_set_threshold(int idx, int level, int value);
void lowmem_memcg_set_leave_threshold(int idx, int value);
unsigned long lowmem_get_ktotalram(void);
void lowmem_trigger_swap(pid_t pid, int memcg_idx);

/*
 * Return memcg pointer to selected cgroup.
 */
int lowmem_get_memcg(enum memcg_type type, struct memcg **memcg_ptr);

enum oom_killer_cb_flags {
	OOM_NONE 		= 0x00000000,	/* for main oom killer thread */
	OOM_FORCE		= 0x00000001,	/* for forced kill */
	OOM_TIMER_CHECK		= 0x00000002,	/* for timer oom killer cb */
	OOM_NOMEMORY_CHECK	= 0x00000004,	/* check victims' memory */
};

#endif /*__LOWMEM_HANDLER_H__*/
