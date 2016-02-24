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

#ifndef _CGROUP_LIBRARY_FREEZER_CGROUP_H_
#define _CGROUP_LIBRARY_FREEZER_CGROUP_H_

#include "cgroup.h"

int cgroup_set_sysfs_state(const enum freezer_state state);
resourced_ret_c freezer_cgroup_init(void);

/**
 * @desc Put pid to foreground cgroup,
 * it's in thawed state
 * @param pid - pid to place to cgroup
 * @return negative value if error
 */
resourced_ret_c thaw_process(const pid_t pid);

/**
 * @desc Put pid to background cgroup,
 * it's in frozen state
 * @param pid - pid to place to cgroup
 * @return negative value if error
 */
resourced_ret_c freez_process(const pid_t pid);

resourced_ret_c prepare_suspend_process(const pid_t pid);

resourced_ret_c prepare_late_resume_process(const pid_t pid);

resourced_ret_c freezer_suspend_cgroup_init(void);

#endif /* _CGROUP_LIBRARY_FREEZER_CGROUP_H_ */
