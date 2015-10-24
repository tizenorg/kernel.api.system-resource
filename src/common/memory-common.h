/*
 * resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file memory-common.h
 * @desc header file for handling memory cgroups
 **/

#ifndef __MEMORY_COMMONL_H__
#define __MEMORY_COMMONL_H__

#include <glib.h>
#include "const.h"

/*
 * [memory cgroup information]
 * MEMCG_MEMORY : root cgroup for system daemons
 * MEMCG_PLATFORM : platform cgroup for swapping desired platform daemons
 * MEMCG_FOREGROUND : foreground cgroup (oom : 150 ~ 200)
 * MEMCG_PREVIOUS : previous cgroup including service and perciptible (oom : 230 ~ 300)
 * MEMCG_FAVORITE : recently used application (oom : 270)
 * MEMCG_BACKGROUND : background cgroup (oom : 330 ~ )
 * MEMCG_SWAP : swap cgroup (select victims from background applications)
 */
enum memcg_type {
	MEMCG_MEMORY,
	MEMCG_PLATFORM,
	MEMCG_FOREGROUND,
	MEMCG_PREVIOUS,
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

/* number of memory cgroups */
#define MEMCG_DEFAULT_NUM_SUBCGROUP		0
#define MEMCG_DEFAULT_EVENT_LEVEL		"medium"
#define MEMCG_DEFAULT_USE_HIERARCHY		0

#define MEMCG_LOW_RATIO			0.8
#define MEMCG_MEDIUM_RATIO		0.96
#define MEMCG_FOREGROUND_LEAVE_RATIO	0.25

struct memcg_info {
	/* name of memory cgroup */
	char name[MAX_PATH_LENGTH];
	/* id for sub cgroup. 0 if no hierarchy, 0 ~ MAX if use hierarchy */
	int id;
	/* limit ratio, if don't want to set limit, use NO_LIMIT*/
	float limit_ratio;
	unsigned int limit;
	/* leave memory usage */
	unsigned int oomleave;
	/* thresholds, normal, swap, low, medium, and leave */
	unsigned int threshold[LOWMEM_MAX_LEVEL];
	unsigned int threshold_leave;
	/* vmpressure event string. If don't want to register event, use null */
	char event_level[MAX_NAME_LENGTH];
	int evfd;
};

struct memcg {
	/* number of sub cgroups */
	int num_subcgroup;
	/* parent cgroup */
	struct memcg_info *info;
	/* set when using multiple sub cgroups */
	int use_hierarchy;
	/* list of child cgroups when using multi groups */
	GSList *cgroups;
};

void memcg_info_set_limit(struct memcg_info *memcg_info, float ratio,
	unsigned int totalram);
void memcg_info_init(struct memcg_info *memcg_info, const char *name);
void memcg_init(struct memcg *memcg);
void memcg_show(struct memcg *memcg);
int memcg_add_cgroups(struct memcg *memcg, int num);

/**
 * @desc get anon memory usage of cgroup mi based on memory.stat
 * @return 0 if the value was correctly read
 */
int memcg_get_anon_usage(struct memcg_info *mi, unsigned int *anon_usage);

/**
 * @desc get memory.get usage_in_bytes from cgroup mi (this is value without swap)
 * @return 0 if the value was correctly read
 */
int memcg_get_usage(struct memcg_info *mi, unsigned int *usage_in_bytes);

/**
 * @desc get PIDs of processes in mi cgroup, an allocated array must be provided
 * @return 0 if pids were read and array filled
 */
int memcg_get_pids(struct memcg_info *mi, GArray *pids);

#endif /*__MEMORY_COMMONL_H__*/
