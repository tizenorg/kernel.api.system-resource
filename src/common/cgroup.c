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

/*
 * Cgroup creation implementation
 */

#include "cgroup.h"
#include "const.h"
#include "macro.h"
#include "util.h"
#include "resourced.h"
#include "trace.h"
#include "file-helper.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>		/*mkdirat */
#include <glib.h>
#include <limits.h>
#include <sys/stat.h>		/*mkdirat */
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>		/*time function */
#include <unistd.h>
#include <sys/mount.h>

#define RELEASE_AGENT	"/release_agent"
#define NOTIFY_ON_RELEASE  "/notify_on_release"

static bool is_cgroup_exists(const char *cgroup_full_path)
{
	struct stat stat_buf;
	return stat(cgroup_full_path, &stat_buf) == 0;
}

static int create_cgroup(const char *cgroup_full_path)
{
	if (mkdir (cgroup_full_path,
		S_IRUSR | S_IWUSR | S_IRGRP) < 0)
		return -errno;

	return 0;
}

/*
 * @desc place pid to cgroup.procs file
 * @return 0 in case of success, errno value in case of failure
 */
resourced_ret_c place_pid_to_cgroup_by_fullpath(const char *cgroup_full_path,
	const int pid)
{
	char buf[256];
	int ret = cgroup_write_node(cgroup_full_path, CGROUP_FILE_NAME,
		(u_int32_t)pid);

	ret_value_msg_if(ret < 0, RESOURCED_ERROR_FAIL,
		"Failed place all pid to cgroup %s, error %s",
			cgroup_full_path, strerror_r(errno, buf, sizeof(buf)));
	return RESOURCED_ERROR_NONE;
}

resourced_ret_c place_pid_to_cgroup(const char *cgroup_subsystem,
	const char *cgroup_name, const int pid)
{
	char buf[MAX_PATH_LENGTH];
	snprintf(buf, sizeof(buf), "%s/%s", cgroup_subsystem, cgroup_name);
	return place_pid_to_cgroup_by_fullpath(buf, pid);
}

resourced_ret_c place_pidtree_to_cgroup(const char *cgroup_subsystem,
	const char *cgroup_name, const int pid)
{
	char buf[MAX_PATH_LENGTH];

	/*/proc/%d/task/%d/children */
	char child_buf[21 + MAX_DEC_SIZE(int) + MAX_DEC_SIZE(int)];
	char pidbuf[MAX_DEC_SIZE(int)];
	resourced_ret_c ret;

	FILE *f;

	snprintf(buf, sizeof(buf), "%s/%s", cgroup_subsystem, cgroup_name);
	/* place parent */
	ret = place_pid_to_cgroup_by_fullpath(buf, pid);
	ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
	  "Failed to put parent process %d into %s cgroup", pid, cgroup_name);

	snprintf(child_buf, sizeof(child_buf), PROC_TASK_CHILDREN,
		 pid, pid);
	f = fopen(child_buf, "r");
	ret_value_msg_if(!f, RESOURCED_ERROR_FAIL, "Failed to get child pids!");
	while (fgets(pidbuf, sizeof(pidbuf), f) != NULL) {
		int child_pid = atoi(pidbuf);
		if (child_pid < 0) {
			_E("Invalid child pid!");
			fclose(f);
			return RESOURCED_ERROR_FAIL;
		}
		resourced_ret_c ret = place_pid_to_cgroup_by_fullpath(buf, child_pid);
		if (ret != RESOURCED_ERROR_NONE) {
			_E("Failed to put parent process %d into %s cgroup", pid, cgroup_name);
			fclose(f);
			return ret;
		}
	}
	fclose(f);
	return RESOURCED_ERROR_NONE;
}

int cgroup_write_node(const char *cgroup_name,
		const char *file_name, unsigned int value)
{
	char buf[MAX_PATH_LENGTH];
	snprintf(buf, sizeof(buf), "%s%s", cgroup_name, file_name);
	_SD("cgroup_buf %s, value %d\n", buf, value);
	return fwrite_int(buf, value);
}

int cgroup_write_node_str(const char *cgroup_name,
			const char *file_name, const char *string)
{
	char buf[MAX_PATH_LENGTH];
	snprintf(buf, sizeof(buf), "%s%s", cgroup_name, file_name);
	_SD("cgroup_buf %s, string %s\n", buf, string);
	return fwrite_str(buf, string);
}

int cgroup_read_node(const char *cgroup_name,
		const char *file_name, unsigned int *value)
{
	char buf[MAX_PATH_LENGTH];
	int ret;
	snprintf(buf, sizeof(buf), "%s%s", cgroup_name, file_name);
	ret = fread_uint(buf, value);
	_SD("cgroup_buf %s, value %d\n", buf, *value);
	return ret;
}

int make_cgroup_subdir(const char* parentdir, const char* cgroup_name, bool *already)
{
	char buf[MAX_PATH_LENGTH];
	bool cgroup_exists;
	int ret = 0;

	if (parentdir)
		ret = snprintf(buf, sizeof(buf), "%s/%s", parentdir, cgroup_name);
	else
		ret = snprintf(buf, sizeof(buf), "%s", cgroup_name);

	ret_value_msg_if(ret > sizeof(buf), RESOURCED_ERROR_FAIL,
		"Not enought buffer size for %s%s", parentdir, cgroup_name);

	cgroup_exists = is_cgroup_exists(buf);
	if (!cgroup_exists) {
		ret = create_cgroup(buf);
		ret_value_msg_if(ret < 0, RESOURCED_ERROR_FAIL,
			"cpu cgroup create fail : err %d, name %s", errno,
				cgroup_name);
	}

	if (already)
		*already = cgroup_exists;

	return RESOURCED_ERROR_NONE;
}

int mount_cgroup_subsystem(char* source, char* mount_point, char* opts)
{
	return mount(source, mount_point, "cgroup",
		    MS_NODEV | MS_NOSUID | MS_NOEXEC, opts);
}

int set_release_agent(const char *cgroup_subsys, const char *release_agent)
{
	_cleanup_free_ char *buf = NULL;
	int r;

	r = asprintf(&buf, "%s/%s", DEFAULT_CGROUP, cgroup_subsys);
	if (r < 0)
		return -ENOMEM;

	r = cgroup_write_node_str(buf, RELEASE_AGENT, release_agent);
	if (r < 0)
		return r;

	return cgroup_write_node_str(buf, NOTIFY_ON_RELEASE, "1");
}
