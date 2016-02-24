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
int lowmem_memory_oom_killer(int flags);
unsigned int get_available(void);
void lowmem_change_memory_state(int state, int force);
void lowmem_memcg_set_threshold(int idx, int level, int value);
void lowmem_memcg_set_leave_threshold(int idx, int value);
unsigned long lowmem_get_ktotalram(void);

#ifdef VMPRESURE_LOWMEM
int lowmem_proactive_oom_killer(int flags, char *appid);
#else
void lowmem_dynamic_process_killer(int type);

enum {
	DYNAMIC_KILL_LARGEHEAP,
	DYNAMIC_KILL_LUNCH,
	DYNAMIC_KILL_MAX,
};
#endif /* VMPRESURE_LOWMEM */

enum {
	MEMCG_MEMORY,
	MEMCG_FOREGROUND,
	MEMCG_SERVICE,
	MEMCG_FAVORITE,
	MEMCG_BACKGROUND,
	MEMCG_SWAP,
	MEMCG_MAX,
};

enum {
	LOWMEM_NORMAL,
	LOWMEM_SWAP,
	LOWMEM_LOW,
	LOWMEM_MEDIUM,
	LOWMEM_MAX_LEVEL,
};

enum oom_killer_cb_flags {
	OOM_NONE 		= 0x00000000,	/* for main oom killer thread */
	OOM_FORCE		= 0x00000001,	/* for forced kill */
	OOM_TIMER_CHECK		= 0x00000002,	/* for timer oom killer cb */
	OOM_NOMEMORY_CHECK	= 0x00000004,	/* check victims' memory */
};

#endif /*__LOWMEM_HANDLER_H__*/
