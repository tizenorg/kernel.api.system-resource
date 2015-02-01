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
 * @file classid-helper.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "appid-helper.h"
#include "net-cls-cgroup.h"
#include "cgroup.h"
#include "const.h"
#include "data_usage.h"
#include "errors.h"
#include "file-helper.h"
#include "macro.h"
#include "trace.h"

#include <dirent.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>

#define CUR_CLASSID_PATH "/tmp/cur_classid"
#define CLASSID_FILE_NAME "/net_cls.classid"
#define PATH_TO_NET_CGROUP_DIR "/sys/fs/cgroup/net_cls"

struct task_classid {
	GArray *pids;
	int pid_count;
	u_int32_t classid;
	char cgroup_name[MAX_NAME_LENGTH];	/*in combination it's package name */
};

typedef GArray task_classid_array;
static task_classid_array *tasks_classids;

static int read_uint(FILE *handler, u_int32_t *out)
{
	return fscanf(handler, "%u", out);
}

static int read_int(FILE *handler, int *out)
{
	return fscanf(handler, "%d", out);
}

static u_int32_t produce_classid(void)
{
	u_int32_t classid = RESOURCED_RESERVED_CLASSID_MAX;
	int ret = fread_int(CUR_CLASSID_PATH, &classid);
	if (ret < 0)
		ETRACE_RET_ERRCODE_MSG(ret, "Can not read current classid");
	ret = fwrite_uint(CUR_CLASSID_PATH, ++classid);
	if (ret < 0)
		ETRACE_RET_ERRCODE_MSG(ret, "Can not write classid");

	return classid;
}

static int place_classid_to_cgroup(const char *cgroup, const char *subdir,
				   u_int32_t *classid)
{
	char buf[MAX_PATH_LENGTH];
	u_int32_t generated_classid = produce_classid();
	if (classid)
		*classid = generated_classid;

	snprintf(buf, sizeof(buf), "%s/%s", cgroup, subdir);
	return cgroup_write_node(buf, CLASSID_FILE_NAME, generated_classid);
}

static u_int32_t get_classid_from_cgroup(const char *cgroup, const char *subdir)
{
	char buf[MAX_PATH_LENGTH];
	u_int32_t classid = RESOURCED_UNKNOWN_CLASSID;
	snprintf(buf, sizeof(buf), "%s/%s", cgroup, subdir);

	int ret = cgroup_read_node(buf, CLASSID_FILE_NAME, &classid);
	if (ret < 0)
		ETRACE_RET_ERRCODE_MSG(ret, "Cant read classid from cgroup %s",
			buf);
	return classid;
}

static void
populate_classids_with_pids(const char *dir_name_buf, size_t dir_name_buf_len,
		  const char *cgroup_name_buf,
		  task_classid_array **tasks_classids_list)
{
	char file_name_buf[MAX_PATH_LENGTH];
	FILE *handler = 0;
	struct task_classid tc;
	memset(&tc, 0, sizeof(struct task_classid));
	tc.pids = g_array_new(FALSE, FALSE, sizeof(pid_t));
	pid_t pid_for_read = 0;

	/* first part of path */
	snprintf(file_name_buf, sizeof(file_name_buf), "%s%s", dir_name_buf,
		CLASSID_FILE_NAME);
	handler = fopen(file_name_buf, "r");

	if (!handler) {
		_E("can't open %s file\n", file_name_buf);
		return;
	}

	if (sizeof(tc.cgroup_name) < strlen(cgroup_name_buf))
		_SE("not enought buffer for %s", cgroup_name_buf);
	else
		strcpy(tc.cgroup_name, cgroup_name_buf);

	if (read_uint(handler, &tc.classid) < 0)
		_E("can't read classid from file %s\n", file_name_buf);

	fclose(handler);

	strncpy(file_name_buf + dir_name_buf_len, TASK_FILE_NAME,
		dir_name_buf_len + sizeof(TASK_FILE_NAME));

	handler = fopen(file_name_buf, "r");

	if (!handler) {
		_E("can't open %s file\n", file_name_buf);
		return;
	}

	while (read_int(handler, &pid_for_read) >= 0) {
		tc.pids = g_array_append_val(tc.pids, pid_for_read);
		++tc.pid_count;
	}
	*tasks_classids_list = g_array_append_val(*tasks_classids_list, tc);

	fclose(handler);
}

u_int32_t get_classid_by_app_id(const char *app_id, int create)
{
	char pkgname[MAX_PATH_LENGTH];
	extract_pkgname(app_id, pkgname, sizeof(pkgname));
	return get_classid_by_pkg_name(pkgname, create);
}

API u_int32_t get_classid_by_pkg_name(const char *pkg_name, int create)
{
	int ret = 0;
	int exists;
	u_int32_t classid = RESOURCED_UNKNOWN_CLASSID;

	if (!strcmp(pkg_name, RESOURCED_ALL_APP))
		return RESOURCED_ALL_APP_CLASSID;

	if (!strcmp(pkg_name, TETHERING_APP_NAME))
		return RESOURCED_TETHERING_APP_CLASSID;

	/* just read */
	if (!create)
		classid = get_classid_from_cgroup(PATH_TO_NET_CGROUP_DIR,
			pkg_name);

	if (classid != RESOURCED_UNKNOWN_CLASSID)
		return classid;

	ret = make_cgroup_subdir(PATH_TO_NET_CGROUP_DIR, (char *)pkg_name,
		&exists);
	if (ret)
		goto handle_error;

	if (exists)
		classid = get_classid_from_cgroup(PATH_TO_NET_CGROUP_DIR,
			pkg_name);
	else
		ret = place_classid_to_cgroup(PATH_TO_NET_CGROUP_DIR,
			(char *)pkg_name, &classid);
	if (ret)
		goto handle_error;

	return classid;

 handle_error:

	ETRACE_RET_ERRCODE(ret);
	return RESOURCED_UNKNOWN_CLASSID;
}


int update_classids(void)
{
	DIR *dir;
	struct dirent *entry;

	char file_name_buf[256];
	size_t path_to_cgroup_dir_len =
	    sizeof(PATH_TO_NET_CGROUP_DIR), file_name_len;

	sprintf(file_name_buf, "%s/", PATH_TO_NET_CGROUP_DIR);

	if (tasks_classids) {
		array_foreach(tc, struct task_classid, tasks_classids) {
			g_array_free(tc->pids, TRUE);
		}
		g_array_free(tasks_classids, TRUE);
	}

	tasks_classids = g_array_new(FALSE, FALSE, sizeof(struct task_classid));

	dir = opendir(file_name_buf);

	if (!dir)
		return ERROR_UPDATE_CLASSIDS_LIST;

	while ((entry = readdir(dir)) != 0) {
		if (entry->d_type != DT_DIR || entry->d_name[0] == '.')
			continue;

		file_name_len = strlen(entry->d_name);
		if (file_name_len + path_to_cgroup_dir_len >
		    sizeof(file_name_buf)) {
			_E("not enought buffer size\n");
			continue;
		}

		strncpy(file_name_buf + path_to_cgroup_dir_len, entry->d_name,
			file_name_len + 1);

		populate_classids_with_pids(file_name_buf,
				  path_to_cgroup_dir_len + file_name_len,
				  entry->d_name, &tasks_classids);
	}
	closedir(dir);
	_D("class id table updated");
	return 0;
}

int_array *get_monitored_pids(void)
{
	int_array *result = g_array_new(FALSE, FALSE, sizeof(pid_t));

	if (!result) {
		_D("Out of memory\n");
		return 0;
	}

	array_foreach(tc, struct task_classid, tasks_classids) {
		int i = 0;

		for (; i < tc->pid_count; ++i) {
			result = g_array_append_val(result,
				g_array_index(tc->pids, int, i));
		}
	}
	return result;
}

static char *get_app_id_by_classid_local(const u_int32_t classid)
{
	if (classid == RESOURCED_TETHERING_APP_CLASSID)
		return strdup(TETHERING_APP_NAME);
	array_foreach(tc, struct task_classid, tasks_classids)
		if (classid == tc->classid)
			return strdup(tc->cgroup_name);
	return 0;
}

char *get_app_id_by_classid(const u_int32_t classid, const bool update_state)
{
	int ret;
	char *appid = get_app_id_by_classid_local(classid);

	if (appid)
		return appid;

	_D("can't resolve app id");
	if (!update_state)
		return 0;

	ret = update_classids();
	ret_value_msg_if(ret, 0, "Can't get appid for %d", classid);

	return get_app_id_by_classid_local(classid);
}

API resourced_ret_c make_net_cls_cgroup_with_pid(const int pid, const char *pkg_name)
{
	int ret = 0;
	int exists = 0;

	if (pkg_name == NULL) {
		_E("package name must be not empty");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	_SD("pkg: %s; pid: %d\n", pkg_name, pid);

	ret = make_cgroup_subdir(PATH_TO_NET_CGROUP_DIR, (char *)pkg_name, &exists);
	ret_value_if(ret < 0, RESOURCED_ERROR_FAIL);

	if (!exists) {
		ret = place_classid_to_cgroup(PATH_TO_NET_CGROUP_DIR, pkg_name,
			NULL);
		ret_value_if(ret < 0, RESOURCED_ERROR_FAIL);
	}

	return place_pid_to_cgroup(PATH_TO_NET_CGROUP_DIR, pkg_name, pid);
}

