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
 * @file smap-helper.c
 *
 * @desc proc/<pid>/smaps file helper functions
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <linux/limits.h>

#include <ctype.h>
#include <stddef.h>

#include <dirent.h>
#include <sys/utsname.h>
#include <stdbool.h>

#include <bundle.h>
#include <eventsystem.h>

#include "trace.h"
#include "file-helper.h"

#include "helper.h"

static struct mapinfo *mi;
static struct mapinfo *maps;
static int smaps_initialized;

bool starts_with(const char *pref, const char *str, const size_t size)
{
	return strncmp(pref, str, size) == 0;
}

static int read_mapinfo(char **smaps)
{
	char *line;
	unsigned tmp;
	unsigned read_lines = 0;
	int ignore = 0;
	static unsigned ignored_lines;

	mi->size = 0;
	mi->rss = 0;
	mi->pss = 0;
	mi->shared_clean = 0;
	mi->shared_dirty = 0;
	mi->private_clean = 0;
	mi->private_dirty = 0;
	mi->swap = 0;

	while ((line = cgets(smaps)) != NULL) {
		tmp = 0;

		/*
		 * Fast ignore lines, when we know how much
		 * we can ignore to the end.
		 */
		if (ignore > 0 && ignored_lines > 0) {
			ignore--;
			continue;
		}

		if (starts_with("Size: ", line, 6)) {
			if (sscanf(line, "Size: %d kB", &tmp) != 1)
				return RESOURCED_ERROR_FAIL;

			mi->size += tmp;
			continue;
		} else if (starts_with("Rss: ", line, 5)) {
			if (sscanf(line, "Rss: %d kB", &tmp) != 1)
				return RESOURCED_ERROR_FAIL;

			mi->rss += tmp;
			continue;
		} else if (starts_with("Pss: ", line, 5)) {
			if (sscanf(line, "Pss: %d kB", &tmp) != 1)
				return RESOURCED_ERROR_FAIL;

			mi->pss += tmp;
			continue;
		} else if (starts_with("Shared_Clean: ", line, 14)) {
			if (sscanf(line, "Shared_Clean: %d kB", &tmp) != 1)
				return RESOURCED_ERROR_FAIL;

			mi->shared_clean += tmp;
			continue;
		} else if (starts_with("Shared_Dirty: ", line, 14)) {
			if (sscanf(line, "Shared_Dirty: %d kB", &tmp) != 1)
				return RESOURCED_ERROR_FAIL;

			mi->shared_dirty += tmp;
			continue;
		} else if (starts_with("Private_Clean: ", line, 15)) {
			if (sscanf(line, "Private_Clean: %d kB", &tmp) != 1)
				return RESOURCED_ERROR_FAIL;

			mi->private_clean += tmp;
			continue;
		} else if (starts_with("Private_Dirty: ", line, 15)) {
			if (sscanf(line, "Private_Dirty: %d kB", &tmp) != 1)
				return RESOURCED_ERROR_FAIL;

			mi->private_dirty += tmp;
			continue;
		} else if (starts_with("Swap: ", line, 6)) {
			if (sscanf(line, "Swap: %d kB", &tmp) != 1)
				return RESOURCED_ERROR_FAIL;

			mi->swap += tmp;
			/*
			 * We just read last interesting for us field.
			 * Now we can ignore the rest of current block.
			 */
			ignore = ignored_lines;
			continue;
		} else {
		/*
		 * This calculates how many lines from the last field read
		 * we can safety ignore.
		 * The 'header line' is also counted, later we remove it
		 * because it is the first one and we don't want to overlap
		 * later when reading.
		 *
		 * The last line in smaps single block starts with 'VmFlags: '
		 * when occurred we know the amount of fields that we can ignore
		 * in smaps block.
		 * We count that only once per resourced running. (depends on
		 * kernel version)
		 *
		 * This won't work if we want to omit some fields in the middle
		 * of smaps block.
		 */

			read_lines++; /* not handled before, so count */

			if (ignored_lines == 0) /* make it only once */
				if (starts_with("VmFlags: ", line, 9))
					ignored_lines = read_lines-1;

			continue; /* ignore that line anyways */
		}
	}

	return RESOURCED_ERROR_NONE;
}


static void init_maps(void)
{
	maps->size = 0;
	maps->rss = 0;
	maps->pss = 0;
	maps->shared_clean = 0;
	maps->shared_dirty = 0;
	maps->private_clean = 0;
	maps->private_dirty = 0;
}

static int load_maps(int pid)
{
	char *smaps, *start;
	char tmp[128];

	snprintf(tmp, sizeof(tmp), "/proc/%d/smaps", pid);
	smaps = cread(tmp);
	if (smaps == NULL)
		return RESOURCED_ERROR_FAIL;

	start = smaps;
	init_maps();

	read_mapinfo(&smaps);

	maps->size = mi->size;
	maps->rss = mi->rss;
	maps->pss = mi->pss;
	maps->shared_clean = mi->shared_clean;
	maps->shared_dirty = mi->shared_dirty;
	maps->private_clean = mi->private_clean;
	maps->private_dirty = mi->private_dirty;
	maps->swap = mi->swap;

	_D("load_maps: %d %d %d %d %d", maps->size, maps->pss,
			maps->rss, maps->shared_dirty, maps->private_dirty);

	if (start)
		free(start);

	return RESOURCED_ERROR_NONE;
}


static int allocate_memory(void)
{
	if (smaps_initialized > 0) {
		_D("smaps helper already initialized");
		return RESOURCED_ERROR_NONE;
	}

	maps = (struct mapinfo *)malloc(sizeof(struct mapinfo));

	if (!maps) {
		_E("fail to allocate mapinfo\n");
		return RESOURCED_ERROR_FAIL;
	}

	mi = malloc(sizeof(struct mapinfo));
	if (mi == NULL) {
		_E("malloc failed for mapinfo");
		free(maps);
		return RESOURCED_ERROR_FAIL;
	}

	smaps_initialized++;

	return RESOURCED_ERROR_NONE;
}

int smaps_helper_get_meminfo(pid_t pid, struct mapinfo **meminfo)
{
	int ret;

	ret = load_maps(pid);
	if (ret != RESOURCED_ERROR_NONE)
		init_maps();
	else
		*meminfo = maps;
	return ret;
}

int smaps_helper_get_vmsize(pid_t pid, unsigned *vmsize, unsigned *vmrss)
{
	int ret;

	ret = load_maps(pid);
	if (ret != RESOURCED_ERROR_NONE) {
		*vmsize = 0;
		*vmrss = 0;
	} else {
		*vmsize = maps->size;
		*vmrss = maps->rss;
	}

	return ret;
}

int smaps_helper_get_shared(pid_t pid, unsigned *shared_clean,
							unsigned *shared_dirty)
{
	int ret;

	ret = load_maps(pid);
	if (ret != RESOURCED_ERROR_NONE) {
		*shared_clean = 0;
		*shared_dirty = 0;
	} else {
		*shared_clean = maps->shared_clean;
		*shared_dirty = maps->private_dirty;
	}

	return ret;
}

int smaps_helper_get_pss(pid_t pid, unsigned *pss, unsigned *uss)
{
	int ret;

	ret = load_maps(pid);
	if (ret != RESOURCED_ERROR_NONE) {
		*pss = 0;
		*uss = 0;
	} else {
		*pss = maps->pss;
		*uss = maps->private_clean + maps->private_dirty + maps->swap;
	}

	return ret;
}

int smaps_helper_init(void)
{
	int ret;

	ret = allocate_memory();

	if (ret != RESOURCED_ERROR_NONE) {
		_E("allocate structures failed");
		return RESOURCED_ERROR_FAIL;
	}

	smaps_initialized--;
	return RESOURCED_ERROR_NONE;
}

void smaps_helper_free(void)
{
	free(maps);
	free(mi);
}

void memory_level_send_system_event(int lv)
{
	bundle *b;
	const char *str;

	switch (lv) {
	case MEMORY_LEVEL_NORMAL:
		str = EVT_VAL_MEMORY_NORMAL;
		break;
	case MEMORY_LEVEL_LOW:
		str = EVT_VAL_MEMORY_SOFT_WARNING;
		break;
	case MEMORY_LEVEL_CRITICAL:
		str = EVT_VAL_MEMORY_HARD_WARNING;
		break;
	default:
		_E("Invalid state");
		return;
	}

	b = bundle_create();
	if (!b) {
		_E("Failed to create bundle");
		return;
	}

	bundle_add_str(b, EVT_KEY_LOW_MEMORY, str);
	eventsystem_send_system_event(SYS_EVENT_LOW_MEMORY, b);
	bundle_free(b);
}
