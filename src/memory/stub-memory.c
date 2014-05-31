/*
 * resourced
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file stub-memory.c
 * @desc Implement memory API stubs
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "lowmem-process.h"
#include "macro.h"
#include "proc-main.h"
#include "resourced.h"

#include <string.h>

int get_proc_oom_score_adj(UNUSED int pid, UNUSED int *oom_score_adj)
{
	return RESOURCED_ERROR_NONE;
}

int set_proc_oom_score_adj(UNUSED int pid, UNUSED int oom_score_adj)
{
	return RESOURCED_ERROR_NONE;
}

int lowmem_set_active(UNUSED int pid, UNUSED int oom_score_adj)
{
	return RESOURCED_ERROR_NONE;
}

int lowmem_set_inactive(UNUSED int pid, UNUSED int oom_score_adj)
{
	return RESOURCED_ERROR_NONE;
}

int lowmem_set_foregrd(UNUSED int pid, UNUSED int oom_score_adj)
{
	return RESOURCED_ERROR_NONE;
}

int lowmem_set_backgrd(UNUSED int pid, UNUSED int oom_score_adj)
{
	return RESOURCED_ERROR_NONE;
}

int lowmem_sweep_memory(UNUSED int callpid)
{
	return RESOURCED_ERROR_NONE;
}

int lowmem_get_proc_cmdline(UNUSED pid_t pid, char *cmdline)
{
	strncpy(cmdline, "", PROC_NAME_MAX-1);
	return RESOURCED_ERROR_NONE;
}
