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
 * @file smaps-helper.h
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#ifndef SRC_MEMORY_SMAPS_HELPER_H_
#define SRC_MEMORY_SMAPS_HELPER_H_

struct mapinfo {
	unsigned size;
	unsigned rss;
	unsigned pss;
	unsigned shared_clean;
	unsigned shared_dirty;
	unsigned private_clean;
	unsigned private_dirty;
	unsigned swap;
};

int smaps_helper_get_meminfo(pid_t pid, struct mapinfo **meminfo);
int smaps_helper_get_pss(pid_t pid, unsigned *pss, unsigned *uss);
int smaps_helper_get_shared(pid_t pid, unsigned *shared_clean, unsigned *shared_dirty);
int smaps_helper_get_vmsize(pid_t pid, unsigned *vmsize, unsigned *vmrss);
int smaps_helper_init(void);
void smaps_helper_free(void);

enum memory_level {
	MEMORY_LEVEL_NORMAL,
	MEMORY_LEVEL_LOW,
	MEMORY_LEVEL_CRITICAL,
};

void memory_level_send_system_event(int lv);

#endif /* SRC_MEMORY_SMAPS_HELPER_H_ */
