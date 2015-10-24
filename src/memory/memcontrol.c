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
 */

/*
 * @file memcontrol.c
 *
 * @desc structure and operation for memory cgroups
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <string.h>
#include <stdio.h>

#include "resourced.h"
#include "trace.h"
#include "macro.h"
#include "memory-common.h"
#include "cgroup.h"

#include <stdlib.h>

#define BUF_MAX				1024

void memcg_info_set_limit(struct memcg_info *mi, float ratio,
	unsigned int totalram)
{
	if (!mi)
		return;

	mi->limit = (float)totalram * ratio;
	mi->limit_ratio = ratio;
	mi->threshold[LOWMEM_LOW] = (unsigned int)(mi->limit * MEMCG_LOW_RATIO);
	mi->threshold[LOWMEM_MEDIUM] = (unsigned int)(mi->limit * MEMCG_MEDIUM_RATIO);
	mi->threshold_leave = (float)mi->limit * MEMCG_FOREGROUND_LEAVE_RATIO;
	mi->oomleave = mi->limit - mi->threshold_leave;
}

static struct memcg_info *memcg_info_alloc_subcgroup(struct memcg *memcg)
{
	struct memcg_info *pmi, *mi;
	int i;
	if (!memcg)
		return NULL;
	mi = (struct memcg_info *)malloc(sizeof(struct memcg_info));
	if (!mi)
		return NULL;
	mi->id = memcg->num_subcgroup;
	pmi = memcg->info;
	snprintf(mi->name, MAX_PATH_LENGTH, "%s%d/",
		pmi->name, memcg->num_subcgroup++);
	mi->limit_ratio = pmi->limit_ratio;
	mi->limit = pmi->limit;
	mi->oomleave = pmi->oomleave;
	for (i = 0; i < LOWMEM_MAX_LEVEL; i++)
		mi->threshold[i] = pmi->threshold[i];
	mi->threshold_leave = pmi->threshold_leave;
	strncpy(mi->event_level, pmi->event_level,
		sizeof(mi->event_level)-1);
	mi->event_level[sizeof(mi->event_level)-1] = 0;
	mi->evfd = pmi->evfd;
	return mi;
}

static int memcg_add_cgroup(struct memcg *memcg)
{
	struct memcg_info *mi = NULL;
	if (!memcg)
		return RESOURCED_ERROR_FAIL;
	mi = memcg_info_alloc_subcgroup(memcg);
	if (!mi)
		return RESOURCED_ERROR_FAIL;
	memcg->cgroups = g_slist_prepend(memcg->cgroups, mi);
	return RESOURCED_ERROR_NONE;
}

int memcg_add_cgroups(struct memcg *memcg, int num)
{
	int i, ret = RESOURCED_ERROR_NONE;
	for (i = 0; i < num; i++) {
		ret = memcg_add_cgroup(memcg);
		if (ret == RESOURCED_ERROR_FAIL)
			return ret;
	}
	return ret;
}

static void memcg_info_show(struct memcg_info *mi)
{
	int i;
	_D("======================================");
	_D("memcg_info->name = %s", mi->name);
	_D("memcg_info->limit_ratio = %.f", mi->limit_ratio);
	_D("memcg_info->limit = %u", mi->limit);
	_D("memcg_info->oomleave = %u", mi->oomleave);
	for (i = 0; i < LOWMEM_MAX_LEVEL; i++)
		_D("memcg_info->threshold = %u", mi->threshold[i]);
	_D("memcg_info->threshold_leave = %u", mi->threshold_leave);
	_D("memcg_info->event_level = %s", mi->event_level);
	_D("memcg_info->evfd = %d", mi->evfd);
}

void memcg_show(struct memcg *memcg)
{
	GSList *iter = NULL;
	memcg_info_show(memcg->info);
	gslist_for_each_item(iter, memcg->cgroups) {
		struct memcg_info *mi =
			(struct memcg_info *)(iter->data);
		memcg_info_show(mi);
	}
}

void memcg_info_init(struct memcg_info *mi, const char *name)
{
	int i;
	mi->id = 0;
	mi->limit_ratio = 0;
	mi->limit = 0;
	mi->oomleave = 0;
	for (i = 0; i < LOWMEM_MAX_LEVEL; i++)
		mi->threshold[i] = 0;
	mi->threshold_leave = 0;
	mi->evfd = -1;
	strncpy(mi->event_level, MEMCG_DEFAULT_EVENT_LEVEL,
			sizeof(mi->event_level)-1);
	mi->event_level[sizeof(mi->event_level)-1] = 0;
	strncpy(mi->name, name, sizeof(mi->name)-1);
	mi->name[sizeof(mi->name)-1] = 0;
}

void memcg_init(struct memcg *memcg)
{
	memcg->num_subcgroup = MEMCG_DEFAULT_NUM_SUBCGROUP;
	memcg->use_hierarchy = MEMCG_DEFAULT_USE_HIERARCHY;
	memcg->info = NULL;
	memcg->cgroups = NULL;
}

int memcg_get_anon_usage(struct memcg_info *mi, unsigned int *anon_usage)
{
	FILE *f;
	char buf[BUF_MAX] = {0,};
	char line[BUF_MAX] = {0, };
	char name[BUF_MAX] = {0, };
	unsigned int tmp, active_anon = 0, inactive_anon = 0;

	snprintf(buf, sizeof(buf), "%smemory.stat", mi->name);
	_I("get mem usage anon from %s", buf);

	f = fopen(buf, "r");
	if (!f) {
		_E("%s open failed, %d", buf, f);
		return RESOURCED_ERROR_FAIL;
	}
	while (fgets(line, BUF_MAX, f) != NULL) {
		if (sscanf(line, "%s %d", name, &tmp)) {
			if (!strcmp(name, "inactive_anon")) {
				inactive_anon = tmp;
			} else if (!strcmp(name, "active_anon")) {
				active_anon = tmp;
				break;
			}
		}
	}

	fclose(f);
	*anon_usage = active_anon + inactive_anon;

	return RESOURCED_ERROR_NONE;
}

int memcg_get_usage(struct memcg_info *mi, unsigned int *usage_bytes)
{
	return cgroup_read_node(mi->name, "memory.usage_in_bytes", usage_bytes);
}

/*
 * Usage example:
 *	int i;
 *	pid_t pid;
 *	GArray *pids_array = g_array_new(false, false, sizeof(pid_t));
 *
 *	memcg_get_pids(mi, pids_array);
 *
 *	for (i=0; i < pids_array->len; i++)
 *		_D("pid_t: %d", g_array_index(pids_array, pid_t, i));
 *	g_array_free(pids_array, TRUE);
 *
 */
int memcg_get_pids(struct memcg_info *mi, GArray *pids)
{
	FILE *f;
	pid_t tpid;
	char buf[MAX_PATH_LENGTH] = {0, };

	if (pids == NULL)
		return RESOURCED_ERROR_FAIL;

	snprintf(buf, sizeof(buf), "%scgroup.procs", mi->name);

	f = fopen(buf, "r");
	if (!f) {
		_E("%s open failed, %d", buf, f);
		return RESOURCED_ERROR_FAIL;
	}

	while (fgets(buf, 32, f) != NULL) {
		tpid = atoi(buf);
		g_array_append_val(pids, tpid);
	}
	fclose(f);

	return RESOURCED_ERROR_NONE;
}
