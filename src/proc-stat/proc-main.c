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
 * @file proc-main.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <Ecore.h>
#include <Ecore_File.h>

#include "proc-process.h"
#include "proc-main.h"

#include "proc-noti.h"
#include "trace.h"
#include "proc-winstate.h"
#include "proc-handler.h"
#include "proc-monitor.h"
#include "module.h"

static GHashTable *proc_exclude_list;
static Ecore_File_Monitor *exclude_list_monitor;
static const unsigned int exclude_list_limit = 1024;
static int proc_notifd;

static void proc_free_exclude_key(gpointer data)
{
	if (data)
		free(data);
}

static gboolean find_excluded(gpointer key, gpointer value, gpointer user_data)
{
	return (gboolean)strstr((char*)user_data, (char*)key);
}

int resourced_proc_excluded(const char *app_name)
{
	gpointer ret = 0;
	if (proc_exclude_list)
		ret = g_hash_table_find(proc_exclude_list, find_excluded, (gpointer)app_name);
	else
		return RESOURCED_ERROR_NONE;
	return ret ? RESOURCED_ERROR_NONMONITOR : RESOURCED_ERROR_NONE;
}

#if 0
static void _prepare_appid(char *appid, const int length)
{
	if (!appid || length - 1 <= 0)
		return;
	appid[length - 1] = '\0'; /*remove ending new line*/
}
#endif

#if 0
static void fill_exclude_list_by_path(const char *exclude_file_name,
	GHashTable *list)
{
	char *exclude_app_id = 0;
	int ret;
	unsigned int excluded_count = 0;
	size_t buf_size = 0;
	FILE *exclude_file = NULL;

	if (!list) {
		_D("Please initialize exclude list!");
		return;
	}

	exclude_file = fopen(exclude_file_name, "r");

	if (!exclude_file) {
		_E("Can't open %s.", exclude_file_name);
		return;
	}

	while (excluded_count++ < exclude_list_limit) {
		ret = getline(&exclude_app_id, &buf_size, exclude_file);
		if (ret <= 0)
			break;
		_prepare_appid(exclude_app_id, ret);
		_SD("append %s to proc exclude list", exclude_app_id);

		g_hash_table_insert(list, g_strdup(exclude_app_id),
			GINT_TO_POINTER(1));
	}

	if (excluded_count >= exclude_list_limit)
		_E("Exclude list is exceed the limit of %u application",
		exclude_list_limit);

	if (exclude_app_id)
		free(exclude_app_id);

	fclose(exclude_file);
}
#endif

static void _fill_exclude_list(GHashTable *list)
{
#if 0
	fill_exclude_list_by_path( , list);
#endif
}

static void _exclude_list_change_cb(void *data, Ecore_File_Monitor *em,
	Ecore_File_Event event, const char *path)
{
	_SD("file %s changed, path: %s, event: %d ", EXCLUDE_LIST_OPT_FULL_PATH,
	path, event);

	g_hash_table_remove_all(proc_exclude_list);
	/* reread all */
	_fill_exclude_list(proc_exclude_list);
}

static void _init_exclude_list_noti(void)
{
	if (ecore_file_init() == 0) {
                _E("ecore_file_init() failed");
		return;
        }
	exclude_list_monitor = ecore_file_monitor_add(EXCLUDE_LIST_OPT_FULL_PATH,
		_exclude_list_change_cb,
		NULL);
	if (exclude_list_monitor == NULL)
		_E("Dynamic exclude list is not supported. Can not add "
			"notification callback");
}

static void proc_exclude_init(void)
{
	proc_exclude_list = g_hash_table_new_full(
		g_str_hash,
		g_str_equal,
		proc_free_exclude_key,
		NULL);

	if (proc_exclude_list == NULL) {
		_E("Can't initialize exclude_list!");
		return;
	}

	_init_exclude_list_noti();
	_fill_exclude_list(proc_exclude_list);
}

int resourced_proc_init(const struct daemon_opts *opts)
{
	int ret;

	proc_notifd = proc_noti_init( );

	proc_win_status_init();

	ret = proc_monitor_init();
	if (ret)
		_E("proc_monitor_init failed : %d", ret);

	proc_exclude_init();
	return ret;
}

int resourced_proc_exit(const struct daemon_opts *opts)
{
	if (proc_notifd)
		close(proc_notifd);
	g_hash_table_destroy(proc_exclude_list);
	ecore_file_monitor_del(exclude_list_monitor);
	return RESOURCED_ERROR_NONE;
}

int resourced_proc_status_change(int type, pid_t pid, char* app_name)
{
	int ret = 0, oom_score_adj = 0;
	char pidbuf[32];

	if (pid && (proc_get_oom_score_adj(pid, &oom_score_adj) < 0)) {
		return RESOURCED_ERROR_FAIL;
	}

	switch (type) {
	case PROC_CGROUP_SET_FOREGRD:
		_SD("set foreground : %d", pid);
		snprintf(pidbuf, sizeof(pidbuf), "%d", pid);
		dbus_proc_handler(PREDEF_FOREGRD, pidbuf);
		ret = proc_set_foregrd(pid, oom_score_adj);
		if (ret != 0)
			_E("Failed to handle proc foreground action!");
		if ( oom_score_adj < OOMADJ_BACKGRD_UNLOCKED)
			break;

		break;
	case PROC_CGROUP_SET_LAUNCH_REQUEST:
		proc_set_oom_score_adj(pid, OOMADJ_INIT);
		if (!app_name) {
			_E("need application name!pid = %d", pid);
			return RESOURCED_ERROR_NO_DATA;
		}
		_SD("launch request %s, %d", app_name, pid);

		break;
	case PROC_CGROUP_SET_SERVICE_REQUEST:
		proc_set_oom_score_adj(pid, OOMADJ_INIT);
		if (!app_name) {
			_E("need application name!pid = %d", pid);
			return RESOURCED_ERROR_NO_DATA;
		}
		_SD("service launch request %s, %d", app_name, pid);

		break;
	case PROC_CGROUP_SET_RESUME_REQUEST:
		_SD("resume request %d", pid);
		/* init oom_score_value */
		if (oom_score_adj >= OOMADJ_BACKGRD_UNLOCKED)
			proc_set_oom_score_adj(pid, OOMADJ_INIT);

		if (!app_name) {
			_E("need application name!pid = %d", pid);
			return RESOURCED_ERROR_NO_DATA;
		}

		break;
	case PROC_CGROUP_SET_TERMINATE_REQUEST:
		break;
	case PROC_CGROUP_SET_ACTIVE:
		ret = proc_set_active(pid, oom_score_adj);
		break;
	case PROC_CGROUP_SET_BACKGRD:
		snprintf(pidbuf, sizeof(pidbuf), "%d", pid);
		dbus_proc_handler(PREDEF_BACKGRD, pidbuf);
		ret = proc_set_backgrd(pid, oom_score_adj);
		if (ret != 0)
			break;

		break;
	case PROC_CGROUP_SET_INACTIVE:
		ret = proc_set_inactive(pid, oom_score_adj);
		break;
	case PROC_CGROUP_GET_MEMSWEEP:
		ret = proc_sweep_memory(pid);
		break;
	case PROC_CGROUP_SET_NOTI_REQUEST:
		break;
	case PROC_CGROUP_SET_PROC_EXCLUDE_REQUEST:
		break;
	default:
		ret = RESOURCED_ERROR_INVALID_PARAMETER;
	}
	return ret;
}

int resourced_proc_action(int type, int argnum, char **arg)
{
	int pid;
	char *pidbuf = NULL, *cgroup_name = NULL;
	if (argnum < 1) {
		_E("Unsupported number of arguments!");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	pidbuf = arg[0];
	if ((pid = atoi(pidbuf)) < 0) {
		_E("Invalid pid argument!");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	/* Getting appid */
	if (argnum > 1) {
		/* It's possible to get appid from arg */
		cgroup_name = arg[1];
	}
	_SD("appid %s, pid %d, type %d \n", cgroup_name, pid, type);
	return resourced_proc_status_change(type, pid, cgroup_name);
}

