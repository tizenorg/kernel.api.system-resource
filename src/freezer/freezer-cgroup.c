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
 * Cgroup creation implementation related to freezer
 */

#include "cgroup.h"
#include "const.h"
#include "file-helper.h"
#include "macro.h"
#include "trace.h"
#include "freezer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PATH_TO_FREEZER_CGROUP_DIR "/sys/fs/cgroup/freezer"
#define FROZEN_STATE	"FROZEN"
#define THAWED_STATE	"THAWED"
#define FREEZER_STATE	"/freezer.state"
#define THAWD_CGROUP	"thawed"
#define FROZEN_CGROUP	"frozen"
#define SUSPEND_CGROUP	"suspend"
#define LATERESUME_CGROUP	"lateresume"

static void fill_freezer_cgroup_path(const char *cgroup_name,
	const int cgroup_name_len,
	char *cgroup_path, const int cgroup_path_len)
{
	int len = sizeof(PATH_TO_FREEZER_CGROUP_DIR)+cgroup_name_len+1;

	if (len > cgroup_path_len) {
		_E("invalid parameter");
		return;
	}

	snprintf(cgroup_path, len, "%s/%s", PATH_TO_FREEZER_CGROUP_DIR,
		    cgroup_name);
	cgroup_path[len] = '\0';
}

static int child_condition(const int getpid, const int pid)
{
	return getpid == pid ||
		getpgid(getpid) != pid;
}

static void place_pid_to_thawed_cgroup(const int pid,
	int(*pid_condition)(const int, const int))
{
	char file_name_buf[MAX_SIZE3(
		PATH_TO_FREEZER_CGROUP_DIR, FROZEN_CGROUP,
		CGROUP_FILE_NAME)+1];
	char pidbuf[MAX_DEC_SIZE(int)];
	FILE *f;

	snprintf(file_name_buf, sizeof(file_name_buf), "%s/%s%s",
		PATH_TO_FREEZER_CGROUP_DIR, FROZEN_CGROUP, CGROUP_FILE_NAME);

	f = fopen(file_name_buf, "r");

	if (!f) {
		ETRACE_ERRNO_MSG("Cant open file %s", file_name_buf);
		return;
	}

	fill_freezer_cgroup_path(THAWD_CGROUP,
		sizeof(THAWD_CGROUP), file_name_buf,
		sizeof(file_name_buf));

	while (fgets(pidbuf, sizeof(pidbuf), f) != NULL) {
		int current_pid = atoi(pidbuf);

		if (pid_condition && pid_condition(current_pid, pid))
			continue;
		_SD("fgets : %s, current_pid %d", pidbuf, current_pid);
		/* could be replaced by */
		/* place_pid_to_cgroup(PATH_TO_FREEZER_CGROUP_DIR,	thawed_cgroup_name, pid)*/
		if (place_pid_to_cgroup_by_fullpath(file_name_buf, current_pid) !=
		    RESOURCED_ERROR_NONE)
			goto place_out;
	}

place_out:
	fclose(f);
}

static void place_child_pid_to_thawed_cgroup(const int pid)
{
	place_pid_to_thawed_cgroup(pid, child_condition);
}

static void place_all_pid_to_thawed_cgroup(void)
{
	place_pid_to_thawed_cgroup(0, NULL);
}

int cgroup_set_sysfs_state(const enum freezer_state state)
{
	char file_name_buf[MAX_PATH_LENGTH];
	int ret = 0;

	switch(state) {
	case CGROUP_FREEZER_DISABLED:
	case CGROUP_FREEZER_INITIALIZED:
		place_all_pid_to_thawed_cgroup();
		break;
	case CGROUP_FREEZER_ENABLED:
	case CGROUP_FREEZER_PAUSED:
		fill_freezer_cgroup_path(FROZEN_CGROUP,
			sizeof(FROZEN_CGROUP), file_name_buf,
			sizeof(file_name_buf));

		if (state == CGROUP_FREEZER_ENABLED)
			ret = cgroup_write_node_str(file_name_buf,
				    FREEZER_STATE, FROZEN_STATE);
		else if (state == CGROUP_FREEZER_PAUSED)
			ret = cgroup_write_node_str(file_name_buf,
				    FREEZER_STATE, THAWED_STATE);

		fill_freezer_cgroup_path(SUSPEND_CGROUP,
			sizeof(SUSPEND_CGROUP), file_name_buf,
			sizeof(file_name_buf));
		 cgroup_write_node_str(file_name_buf,
				    FREEZER_STATE, THAWED_STATE);
		break;
	case CGROUP_FREEZER_SUSPEND:
		fill_freezer_cgroup_path(SUSPEND_CGROUP,
			sizeof(SUSPEND_CGROUP), file_name_buf,
			sizeof(file_name_buf));
		 cgroup_write_node_str(file_name_buf,
				    FREEZER_STATE, FROZEN_STATE);
		 fill_freezer_cgroup_path(LATERESUME_CGROUP,
			sizeof(LATERESUME_CGROUP), file_name_buf,
			sizeof(file_name_buf));
		 cgroup_write_node_str(file_name_buf,
				    FREEZER_STATE, FROZEN_STATE);
		break;
	case CGROUP_FREEZER_RESUME:
		fill_freezer_cgroup_path(SUSPEND_CGROUP,
			sizeof(SUSPEND_CGROUP), file_name_buf,
			sizeof(file_name_buf));
		 cgroup_write_node_str(file_name_buf,
				    FREEZER_STATE, THAWED_STATE);
		break;
	case CGROUP_FREEZER_LATERESUME:
		fill_freezer_cgroup_path(LATERESUME_CGROUP,
			sizeof(LATERESUME_CGROUP), file_name_buf,
			sizeof(file_name_buf));
		 cgroup_write_node_str(file_name_buf,
				    FREEZER_STATE, THAWED_STATE);
		break;
	}
	return ret;
}


resourced_ret_c thaw_process(const pid_t pid)
{
	int ret;

	place_child_pid_to_thawed_cgroup(pid);
	ret = place_pid_to_cgroup(PATH_TO_FREEZER_CGROUP_DIR,
		THAWD_CGROUP, pid);

	if (!ret)
		freezer_broadcasting(SET_FOREGRD, pid);
	return ret;
}

resourced_ret_c freez_process(const pid_t pid)
{
	int ret;

	ret = place_pid_to_cgroup(PATH_TO_FREEZER_CGROUP_DIR,
		FROZEN_CGROUP, pid);
	if (!ret)
		freezer_broadcasting(SET_BACKGRD, pid);
	return ret;
}

resourced_ret_c prepare_suspend_process(const pid_t pid)
{
	return place_pid_to_cgroup(PATH_TO_FREEZER_CGROUP_DIR,
		SUSPEND_CGROUP, pid);
}

resourced_ret_c prepare_late_resume_process(const pid_t pid)
{
	return place_pid_to_cgroup(PATH_TO_FREEZER_CGROUP_DIR,
		LATERESUME_CGROUP, pid);
}

resourced_ret_c freezer_cgroup_init(void)
{
	int ret;

	ret = make_cgroup_subdir(PATH_TO_FREEZER_CGROUP_DIR,
		    THAWD_CGROUP, NULL);
	ret_value_msg_if(ret < 0, ret, "failed to make cgroup %s\n",
		    THAWD_CGROUP);
	ret = make_cgroup_subdir(PATH_TO_FREEZER_CGROUP_DIR,
		    FROZEN_CGROUP, NULL);
	ret_value_msg_if(ret < 0, ret, "failed to make cgroup %s\n",
		    FROZEN_CGROUP);
	return cgroup_set_sysfs_state(CGROUP_FREEZER_ENABLED);
}

resourced_ret_c freezer_suspend_cgroup_init(void)
{
	int ret;

	ret = make_cgroup_subdir(PATH_TO_FREEZER_CGROUP_DIR,
			    SUSPEND_CGROUP, NULL);
	ret_value_msg_if(ret < 0, ret, "failed to make cgroup %s\n",
			    SUSPEND_CGROUP);
	ret = make_cgroup_subdir(PATH_TO_FREEZER_CGROUP_DIR,
			    LATERESUME_CGROUP, NULL);
	ret_value_msg_if(ret < 0, ret, "failed to make cgroup %s\n",
			    SUSPEND_CGROUP);
	return RESOURCED_ERROR_NONE;
}
