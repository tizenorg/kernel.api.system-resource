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

void lowmem_dbus_init(void);
int lowmem_oom_killer_cb(int memcg_idx, int flags);
void lowmem_dynamic_process_killer(int type);
unsigned int get_available(void);
void change_memory_state(int state, int force);

void set_threshold(int level, int thres);
void set_leave_threshold(int thres);

#define NUM_FOREGROUND			3
enum {
	MEMCG_MEMORY,
	MEMCG_FOREGROUND,
	MEMCG_BACKGROUND = MEMCG_FOREGROUND + NUM_FOREGROUND,
	MEMCG_MAX_GROUPS,
};

enum {
	MEMNOTIFY_NORMAL,
	MEMNOTIFY_SWAP,
	MEMNOTIFY_LOW,
	MEMNOTIFY_MEDIUM,
	MEMNOTIFY_MAX_LEVELS,
};

enum oom_killer_cb_flags {
	OOM_NONE 		= 0x00000000,	/* for main oom killer thread */
	OOM_FORCE		= 0x00000001,	/* for forced kill */
	OOM_TIMER_CHECK		= 0x00000002,	/* for timer oom killer cb */
	OOM_NOMEMORY_CHECK	= 0x00000004,	/* check victims' memory */
};

enum {
	DYNAMIC_KILL_LARGEHEAP,
	DYNAMIC_KILL_LUNCH,
	DYNAMIC_KILL_MAX,
};

#endif /*__LOWMEM_HANDLER_H__*/
