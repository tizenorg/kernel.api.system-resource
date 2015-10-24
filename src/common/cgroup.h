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

#include <resourced.h>
#include <sys/types.h>

/*
 * Cgroup creation interface
 */

#ifndef _CGROUP_LIBRARY_CGROUP_H_
#define _CGROUP_LIBRARY_CGROUP_H_

#define DEFAULT_CGROUP       "/sys/fs/cgroup"
#define PROC_TASK_CHILDREN   "/proc/%d/task/%d/children"

/**
 * @desc Get one unsigned int value from cgroup
 * @param cgroup_name - cgroup path
 * @param file_name - cgroup content to write
 * @param value - out parameter, value to fill
 * @return negative value if error
*/
int cgroup_read_node(const char *cgroup_name,
		const char *file_name, unsigned int *value);

/**
 * @desc Put value to cgroup,
 * @param cgroup_name - cgroup path
 * @param file_name - cgroup content to write
 * @param value - data to write
 * @return negative value if error
 */
int cgroup_write_node(const char *cgroup_name,  const char *file_name, unsigned int value);

/**
 * @desc Put value to cgroup,
 * @param cgroup_name - cgroup path
 * @param file_name - cgroup content to write
 * @param string -string to write
 * @return negative value if error
 */
int cgroup_write_node_str(const char *cgroup_name,
		const char *file_name, const char *string);

/**
 * @desc make cgroup,
 * @param parentdir - parent cgroup path
 * @param cgroup_name - cgroup subdirectory to write
 * @param already - true if subdir already exists, NULL pointer is possible
 * as formal argument, in this case it will not be filled
 * @return negative value if error
 */
int make_cgroup_subdir(const char* parentdir, const char* cgroup_name, bool *already);

/**
 * @desc mount cgroup,
 * @param source -cgroup name
 * @param mount_point - cgroup path
 * @param opts - mount options
 * @return negative value if error
 */
int mount_cgroup_subsystem(char* source, char* mount_point, char* opts);

/**
 * @desc write pid into cgroup_subsystem/cgroup_name file,
 * @param cgroup_subsystem path to /sys/fs/cgroup/subsystem
 * @param cgroup_name - name in /sys/fs/cgroup/subsystem/
 * @return negative value if error
 */
resourced_ret_c place_pid_to_cgroup(const char *cgroup_subsystem,
	const char *cgroup_name, const int pid);

resourced_ret_c place_pid_to_cgroup_by_fullpath(const char *cgroup_full_path,
	const int pid);

/**
 * @desc doing the same as @see place_pid_to_cgroup,
 * but also put into cgroup first level child processes
 */
resourced_ret_c place_pidtree_to_cgroup(const char *cgroup_subsystem,
	const char *cgroup_name, const int pid);

/**
 * @desc this function sets release agent path into cgroup subsystem
 * and enables this mechanism
 * @param cgroup_sussys - cgroup subsystem name, it's relative path to cgroup,
 * relativelly default cgroup path (DEFAULT_CGROUP)
 * @param release_agent full path to release agent executable
 * @return negative value if error
 */
int set_release_agent(const char *cgroup_subsys, const char *release_agent);

#endif /*_CGROUP_LIBRARY_CGROUP_H_*/
