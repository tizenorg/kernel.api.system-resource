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
#include <pthread.h>

#include "notifier.h"
#include "proc-process.h"
#include "proc-main.h"
#include "cgroup.h"
#include "proc-noti.h"
#include "trace.h"
#include "proc-handler.h"
#include "proc-monitor.h"
#include "module.h"
#include "freezer.h"
#include "macro.h"
#include "appid-helper.h"
#include "lowmem-handler.h"
#include "procfs.h"
#include "appinfo-list.h"

static GHashTable *proc_exclude_list;
static Ecore_File_Monitor *exclude_list_monitor;
static const unsigned int exclude_list_limit = 1024;
int proc_freeze_late_control;
static const struct module_ops *freezer;
static GSList *proc_module;  /* proc sub-module list */

#define BASE_UGPATH_PREFIX "/usr/ug/bin"
#define LOG_PREFIX "resourced.log"
#define TIZEN_SYSTEM_APPID "org.tizen.system"

GSList *proc_app_list;
GSList *proc_program_list;

struct child_pid *new_pid_info(const pid_t pid)
{
	struct child_pid *result = (struct child_pid *)malloc(
			sizeof(struct child_pid));
	if (!result) {
		_E("Malloc of new_pid_info failed\n");
		return NULL;
	}

	result->pid = pid;
	return result;
}

static struct child_pid *find_child_info(pid_list pids, const pid_t pid)
{
	struct child_pid pid_to_find = {
		.pid = pid,
	};
	GSList *found = NULL;

	ret_value_msg_if(!pids, NULL, "Please provide valid pointer.");

	found = g_slist_find_custom((GSList *)pids,
		&pid_to_find, compare_pid);

	if (found)
		return (struct child_pid *)(found->data);
	return NULL;
}

static bool is_ui_app(enum application_type type)
{
	if (type == PROC_TYPE_GUI || type == PROC_TYPE_WIDGET ||
	    type == PROC_TYPE_WATCH)
		return true;
	return false;
}

void proc_add_child_pid(struct proc_app_info *pai, pid_t pid)
{
	struct child_pid pid_to_find = {
		.pid = pid,
	};
	GSList *found = NULL;

	if (pai->childs)
		found = g_slist_find_custom((GSList *)pai->childs,
			&pid_to_find, compare_pid);

	if (found)
		return;

	pai->childs = g_slist_prepend(pai->childs, new_pid_info(pid));
}

void proc_set_process_info_memcg(struct proc_app_info *pai,
	int memcg_idx, struct memcg_info *memcg_info)
{
	if (!pai)
		return;
	pai->memcg_idx = memcg_idx;
	pai->memcg_info = memcg_info;
}

/*
 * There can be many processes with same appid at same time.
 * This function returns the most recently used app of all app list.
 */
struct proc_app_info *find_app_info_by_appid(const char *appid)
{
	GSList *iter = NULL;
	struct proc_app_info *pai;

	if (!appid)
		return NULL;

	gslist_for_each_item(iter, proc_app_list) {
		pai = (struct proc_app_info *)iter->data;
		if (equal_name_info(pai->appid, appid))
			return pai;
	}
	return NULL;
}

struct proc_app_info *find_app_info(const pid_t pid)
{
	GSList *iter = NULL;
	struct proc_app_info *pai= NULL;

	gslist_for_each_item(iter, proc_app_list) {
		pai = (struct proc_app_info *)iter->data;
		if ((pai->main_pid == pid) ||
		    (pai->childs && find_child_info(pai->childs, pid)))
			return pai;
	}
	return NULL;
}

struct proc_program_info *find_program_info(const char *pkgname)
{
	GSList *iter = NULL;
	struct proc_program_info *ppi;

	if (!pkgname)
		return NULL;

	gslist_for_each_item(iter, proc_program_list) {
		ppi = (struct proc_program_info *)iter->data;
		if (equal_name_info(ppi->pkgname, pkgname))
			return ppi;
	}
	return NULL;
}

resourced_ret_c proc_set_runtime_exclude_list(const int pid, int type)
{
	struct proc_app_info *pai = NULL;
	struct proc_status proc_data = {0};

	pai = find_app_info(pid);
	if (!pai)
		return RESOURCED_ERROR_NO_DATA;

	if (pai->runtime_exclude) {
		if (type == PROC_EXCLUDE)
			pai->runtime_exclude++;
		else
				pai->runtime_exclude--;
	} else {
		pai->runtime_exclude = type;
	}
	_D("pid %d set proc exclude list, type = %d, exclude = %d",
		    pid, type, pai->runtime_exclude);

	proc_data.pid = pid;
	proc_data.pai = pai;
	if (type == PROC_EXCLUDE)
		resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &proc_data);
	return RESOURCED_ERROR_NONE;
}

/*
  * find main oom score value from latest launched UI application
  * And set oom score of service app
  */
static void proc_set_default_svc_oomscore
	    (struct proc_program_info *ppi, struct proc_app_info *svc)
{
	struct proc_app_info *pai =
		    (struct proc_app_info *)g_slist_nth_data(ppi->app_list, 0);
	int oom_score_adj = 0, ret ;
	if (pai) {
		ret = proc_get_oom_score_adj(pai->main_pid, &oom_score_adj);
		if (ret)
			oom_score_adj = 0;
	}
	proc_set_service_oomscore(svc->main_pid, oom_score_adj);
}

struct proc_program_info *proc_add_program_list(const int type,
	    struct proc_app_info *pai, const char *pkgname)
{
	struct proc_program_info *ppi;
	if (!pai || !pkgname)
		return NULL;

	ppi = find_program_info(pkgname);
	if (!ppi) {
		_E("not found ppi : %s", pkgname);
		ppi = calloc(sizeof(struct proc_program_info), 1);
		if (!ppi)
			return NULL;

		if (pai->ai)
			ppi->pkgname = pai->ai->pkgname;
		else {
			ppi->pkgname = strndup(pkgname, strlen(pkgname)+1);
			if (!ppi->pkgname) {
				_E("not enough memory");
				free(ppi);
				return NULL;
			}
		}
		proc_program_list = g_slist_prepend(proc_program_list, ppi);
	}
	if (is_ui_app(type))
		ppi->app_list = g_slist_prepend(ppi->app_list, pai);
	else {
		ppi->svc_list = g_slist_prepend(ppi->svc_list, pai);
		proc_set_default_svc_oomscore(ppi, pai);
	}
	return ppi;
}

struct proc_app_info *proc_add_app_list(const int type, const pid_t pid,
	    const char *appid, const char *pkgname)
{
	struct proc_app_info *pai;

	if (!appid)
		return NULL;

	/*
	 * check lastet item firstly because app list has already created in prelaunch
	 */
	pai = (struct proc_app_info *)g_slist_nth_data(proc_app_list, 0);
	if (!pai || pai->type != PROC_TYPE_READY) {
		_E("not found previous pai : %s", appid);
		pai = proc_create_app_list(appid, pkgname);
		if (!pai) {
			_E("failed to create app list");
			return NULL;
		}
	}

	pai->type = type;
	pai->main_pid = pid;
	pai->program = proc_add_program_list(type, pai, pkgname);
	pai->state = PROC_STATE_FOREGROUND;
	return pai;
}

static void _remove_child_pids(struct proc_app_info *pai, pid_t pid)
{
	GSList *iter, *next;
	struct child_pid *child;

	if (!pai->childs)
		return;

	/*
	 * if pid has a valid value, remove only one child with same pid
	 * otherwise pid is zero, remove all child pids
	 */
	gslist_for_each_safe(pai->childs, iter, next, child) {
		if (pid && pid != child->pid)
			continue;
		pai->childs = g_slist_remove(pai->childs, child);
		free(child);
		if (pid)
			return;
	}
}

int proc_remove_app_list(const pid_t pid)
{
	GSList *iter;
	struct proc_app_info *pai = NULL;
	struct proc_program_info *ppi;
	struct child_pid *found = NULL;

	gslist_for_each_item(iter, proc_app_list) {
		pai = (struct proc_app_info *)iter->data;
		if (!pai->main_pid)
			continue;

		if (pai->main_pid == pid) {
			_remove_child_pids(pai, 0);
			ppi = pai->program;
			if (ppi) {
				if (is_ui_app(pai->type))
					ppi->app_list = g_slist_remove(ppi->app_list, pai);
				else if (pai->type == PROC_TYPE_SERVICE)
					ppi->svc_list = g_slist_remove(ppi->svc_list, pai);
				if (!ppi->app_list && !ppi->svc_list) {
					proc_program_list = g_slist_remove(proc_program_list, ppi);
					resourced_appinfo_put(pai->ai);
					free(ppi);
				}
			}
			proc_app_list = g_slist_remove(proc_app_list, pai);
			free(pai);
			break;
		} else if (pai->childs) {
			found = find_child_info(pai->childs, pid);
			if (!found)
				continue;
			_remove_child_pids(pai, pid);
			break;
		} else
			continue;
	}
	return 0;
}

struct proc_app_info *proc_create_app_list(const char *appid, const char *pkgid)
{
	struct proc_app_info *pai;
	if (!appid)
		return NULL;

	pai = calloc(sizeof(struct proc_app_info), 1);
	if (!pai)
		return NULL;

	pai->ai = resourced_appinfo_get(pai->ai, appid, pkgid);
	if (pai->ai)
		pai->appid = pai->ai->appid;
	else {
		pai->appid = strndup(appid, strlen(appid)+1);
		if (!pai->appid) {
			free(pai);
			_E("not enough memory");
			return NULL;
		}
	}

	pai->proc_exclude = resourced_proc_excluded(appid);
	proc_app_list = g_slist_prepend(proc_app_list, pai);
	return pai;
}

int proc_delete_all_lists(void)
{
	GSList *iter, *next;
	struct proc_app_info *pai = NULL;
	struct proc_program_info *ppi = NULL;

	gslist_for_each_safe(proc_app_list, iter, next, pai) {
		_remove_child_pids(pai, 0);
		ppi = pai->program;
		if (ppi) {
			if (is_ui_app(pai->type))
				ppi->app_list = g_slist_remove(ppi->app_list, pai);
			else if (pai->type == PROC_TYPE_SERVICE)
				ppi->svc_list = g_slist_remove(ppi->svc_list, pai);
		}
		proc_app_list = g_slist_remove(proc_app_list, pai);
		resourced_appinfo_put(pai->ai);
		free(pai);
	}

	gslist_for_each_safe(proc_program_list, iter, next, ppi) {
		proc_program_list = g_slist_remove(proc_program_list, ppi);
		free(ppi);
	}
	return 0;
}

int proc_get_svc_state(struct proc_program_info *ppi)
{
	GSList *iter = NULL;
	int state = PROC_STATE_DEFAULT;

	if (!ppi->app_list)
		return PROC_STATE_DEFAULT;

	gslist_for_each_item(iter, ppi->app_list) {
		struct proc_app_info *pai = (struct proc_app_info *)(iter->data);

		if (pai->lru_state == PROC_FOREGROUND)
			return PROC_STATE_FOREGROUND;

		if (pai->lru_state >= PROC_BACKGROUND)
			state = PROC_STATE_BACKGROUND;
	}
	return state;
}

static void proc_dump_process_list(FILE *fp)
{
	GSList *iter, *iter_app, *iter_pid;
	struct proc_program_info *ppi = NULL;
	struct proc_app_info *pai = NULL;
	int index = 0, oom_score_adj;

	LOG_DUMP(fp, "[PROGRAM LISTS]\n");
	gslist_for_each_item(iter, proc_program_list) {
		ppi = (struct proc_program_info *)iter->data;
		LOG_DUMP(fp, "index : %d, pkgname : %s, state : %d\n",
		    index, ppi->pkgname, proc_get_svc_state(ppi));
		gslist_for_each_item(iter_app, ppi->app_list) {
			pai = (struct proc_app_info *)iter_app->data;
			if (proc_get_oom_score_adj(pai->main_pid,
				    &oom_score_adj) < 0)
				continue;
			if (!is_ui_app(pai->type))
				continue;

			LOG_DUMP(fp, "\t UI APP, pid : %d, appid : %s, oom_score : %d, "
				    "lru : %d, proc_exclude : %d, runtime_exclude : %d, "
				    "flags : %X\n",
				    pai->main_pid, pai->appid, oom_score_adj,
				    pai->lru_state, pai->proc_exclude,
				    pai->runtime_exclude, pai->flags);

			if (pai->childs) {
				struct child_pid *child;
				gslist_for_each_item(iter_pid, pai->childs) {
					child = (struct child_pid *)iter_pid->data;
					LOG_DUMP(fp, "\t child pid : %d", child->pid);
				}
				LOG_DUMP(fp, "\n");
			}
		}
		gslist_for_each_item(iter_app, ppi->svc_list) {
			pai = (struct proc_app_info *)iter_app->data;
			if (proc_get_oom_score_adj(pai->main_pid,
				    &oom_score_adj) < 0)
				continue;
			LOG_DUMP(fp, "\t SVC APP, pid : %d, appid : %s, oom_score : %d, "
				    "proc_exclude : %d, runtime_exclude : %d, flags : %X\n",
				    pai->main_pid, pai->appid, oom_score_adj,
				    pai->proc_exclude, pai->runtime_exclude,
				    pai->flags);
		}
		index++;
	}
}

static void proc_free_exclude_key(gpointer data)
{
	if (data)
		free(data);
}

static gboolean find_excluded(gpointer key, gpointer value, gpointer user_data)
{
	return (gboolean)strstr((char *)user_data, (char *)key);
}

int proc_get_id_info(struct proc_status *ps, char **app_name, char **pkg_name)
{
	if (!ps)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	if (!ps->pai || !ps->pai->ai) {
		*app_name = TIZEN_SYSTEM_APPID;
		*pkg_name = TIZEN_SYSTEM_APPID;
	} else {
		*app_name = ps->pai->ai->appid;
		*pkg_name = ps->pai->ai->pkgname;
	}
	return RESOURCED_ERROR_NONE;
}

char *proc_get_appid_from_pid(const pid_t pid)
{
	struct proc_app_info *pai = find_app_info(pid);
	if (!pai)
		return NULL;
	return pai->appid;
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

static void _prepare_appid(char *appid, const int length)
{
	if (!appid || length - 1 <= 0)
		return;
	appid[length - 1] = '\0'; /*remove ending new line*/
}

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

		g_hash_table_insert(list, g_strndup(exclude_app_id, strlen(exclude_app_id)),
			GINT_TO_POINTER(1));
	}

	if (excluded_count >= exclude_list_limit)
		_E("Exclude list is exceed the limit of %u application",
		exclude_list_limit);

	if (exclude_app_id)
		free(exclude_app_id);

	fclose(exclude_file);
}

static void _fill_exclude_list(GHashTable *list)
{
	fill_exclude_list_by_path(EXCLUDE_LIST_FULL_PATH, list);
	fill_exclude_list_by_path(EXCLUDE_LIST_OPT_FULL_PATH, list);
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
		_E("Dynamic exclude list not supported. Cannot add notification callback");
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

void proc_module_add(const struct proc_module_ops *ops)
{
	proc_module = g_slist_append(proc_module, (gpointer)ops);
}

void proc_module_remove(const struct proc_module_ops *ops)
{
	proc_module = g_slist_remove(proc_module, (gpointer)ops);
}

static void proc_module_init(void *data)
{
	GSList *iter;
	const struct proc_module_ops *module;
	int ret = RESOURCED_ERROR_NONE;

	gslist_for_each_item(iter, proc_module) {
		module = (struct proc_module_ops *)iter->data;
		_D("Initialize [%s] module\n", module->name);
		if (module->init)
			ret = module->init(data);
		if (ret != RESOURCED_ERROR_NONE)
			_E("Fail to initialize [%s] module\n", module->name);
	}
}

static void proc_module_exit(void *data)
{
	GSList *iter;
	const struct proc_module_ops *module;
	int ret = RESOURCED_ERROR_NONE;

	gslist_for_each_item(iter, proc_module) {
		module = (struct proc_module_ops *)iter->data;
		_D("Deinitialize [%s] module\n", module->name);
		if (module->exit)
			ret = module->exit(data);
		if (ret != RESOURCED_ERROR_NONE)
			_E("Fail to deinitialize [%s] module\n", module->name);
	}
}

static int resourced_proc_init(void* data)
{
	proc_exclude_init();
	proc_module_init(data);
	return RESOURCED_ERROR_NONE;
}

static int resourced_proc_exit(void* data)
{
	proc_delete_all_lists();
	g_hash_table_destroy(proc_exclude_list);
	ecore_file_monitor_del(exclude_list_monitor);
	proc_module_exit(data);
	return RESOURCED_ERROR_NONE;
}

int proc_get_freezer_status()
{
	int ret = CGROUP_FREEZER_DISABLED;
	struct freezer_status_data f_data;
	if (!freezer) {
		freezer = find_module("freezer");
		if (!freezer)
			return ret;
	}

	f_data.type = GET_STATUS;
	if (freezer->status)
		ret = freezer->status(&f_data);
	return ret;
}

int get_proc_freezer_late_control(void)
{
	return proc_freeze_late_control;
}

void set_proc_freezer_late_control(int value)
{
	proc_freeze_late_control = value;
}

int proc_get_appflag(const pid_t pid)
{
	struct proc_app_info *pai =
		find_app_info(pid);

	if (pai) {
		_D("get apptype = %d", pai->flags);
		return pai->flags;
	} else
		_D("there is no process info for pid = %d", pid);
	return PROC_NONE;
}

void proc_set_group(pid_t onwerpid, pid_t childpid, char *pkgname)
{
	int oom_score_adj = 0;
	struct proc_program_info *ppi;
	struct proc_app_info *pai, *owner;
	struct proc_status proc_data = {0};

	if (onwerpid <= 0 || childpid <=0)
		return;

	owner = find_app_info(onwerpid);
	pai = find_app_info(childpid);
	if (!owner)
		return;

	if (pkgname && pai) {
		/*
		 * when some application with appid migrated to owner program
		 * check previous ppi and remove if it's exist
		 */
		ppi = find_program_info(pkgname);
		if (ppi)
			ppi->app_list = g_slist_remove(ppi->app_list, pai);

		ppi = owner->program;
		if (ppi) {
			ppi->app_list = g_slist_prepend(ppi->app_list, pai);
			pai->program = ppi;
		}
	} else {
		/*
		 * when some process like webprocess needs to group in owner app
		 * add to child lists in the proc app info
		 */
		if (proc_get_oom_score_adj(onwerpid, &oom_score_adj) < 0) {
			_D("owner pid(%d) was already terminated", onwerpid);
			return;
		}
		proc_add_child_pid(owner, childpid);
		if (oom_score_adj <= OOMADJ_BACKGRD_LOCKED) {
			proc_data.pid = childpid;
			resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &proc_data);
		}
		proc_set_oom_score_adj(childpid, oom_score_adj);
	}
}

bool proc_check_lru_suspend(int val, int lru)
{
	if (proc_get_freezer_status() == CGROUP_FREEZER_DISABLED)
		return false;

	if ((PROC_BACKGROUND + val) == lru)
		return true;
	return false;
}

enum proc_state proc_check_suspend_state(struct proc_app_info *pai)
{
	if (!pai)
		return PROC_STATE_DEFAULT;

	if (pai->type == PROC_TYPE_GUI) {
		/*
		 * check LRU state about UI application
		 * whether it is active state or not
		 */
		if (pai->lru_state < PROC_BACKGROUND)
			return PROC_STATE_DEFAULT;

		/*
		 * if platform has a suspend policy and application has UI,
		 * waits suspend callback or changing LRU.
		 * Otherwise, application goes to suspend state without waiting.
		 */
		if (!(CHECK_BIT(pai->flags, PROC_BGCTRL_PLATFORM)) ||
		    (pai->state == PROC_STATE_SUSPEND_READY))
			return PROC_STATE_SUSPEND;

		pai->state = PROC_STATE_SUSPEND_READY;
		return PROC_STATE_SUSPEND_READY;

	}
	if (pai->type == PROC_TYPE_SERVICE) {
		/*
		 * standalone service goes to suspend state immediately.
		 * if service is connected with UI application,
		 * checks UI state from program list.
		 * if UI has already went to suspend mode,
		 * service goes to suspend state.
		 * Otherwise, service waits until UI app is suspended.
		 */
		struct proc_program_info *ppi = pai->program;
		struct proc_app_info *ui;

		if (!ppi->app_list)
			return PROC_STATE_SUSPEND;

		ui = (struct proc_app_info *)g_slist_nth_data(ppi->app_list, 0);
		if (ui->state == PROC_STATE_SUSPEND)
			return PROC_STATE_SUSPEND;
		pai->state = PROC_STATE_SUSPEND_READY;
		return PROC_STATE_SUSPEND_READY;
	}
	return PROC_STATE_DEFAULT;
}


int resourced_proc_status_change(int status, pid_t pid, char *app_name, char *pkg_name, int apptype)
{
	int ret = 0, oom_score_adj = 0, notitype;
	char pidbuf[MAX_DEC_SIZE(int)];
	struct proc_status proc_data = {0};
	struct proc_program_info *ppi;

	if (!pid) {
		_E("invalid pid : %d of %s", pid, app_name ? app_name : "noprocess");
		return RESOURCED_ERROR_FAIL;
	}

	if (status != PROC_CGROUP_SET_TERMINATED) {
		ret = proc_get_oom_score_adj(pid, &oom_score_adj);
		if (ret < 0) {
			_E("Empty pid or process not exists. %d", pid);
			return RESOURCED_ERROR_FAIL;
		}
	}

	if (!pid) {
		_E("invalid pid : %d of %s", pid, app_name ? app_name : "noprocess");
		return RESOURCED_ERROR_FAIL;
	}

	proc_data.pid = pid;
	proc_data.appid = app_name;
	proc_data.pai = NULL;
	switch (status) {
	case PROC_CGROUP_SET_FOREGRD:
		_SD("set foreground : %d", pid);
		proc_data.pai = find_app_info(pid);
		if (apptype == PROC_TYPE_WIDGET || apptype == PROC_TYPE_WATCH) {
			if (!proc_data.pai)
				proc_add_app_list(apptype, pid, app_name, pkg_name);
			proc_set_oom_score_adj(pid, OOMADJ_FOREGRD_UNLOCKED);
			resourced_notify(RESOURCED_NOTIFIER_WIDGET_FOREGRD, &proc_data);
			break;
		} else {
			snprintf(pidbuf, sizeof(pidbuf), "%d", pid);
			dbus_proc_handler(PREDEF_FOREGRD, pidbuf);
			ret = proc_set_foregrd(pid, oom_score_adj);
			if (ret != 0)
				return RESOURCED_ERROR_NO_DATA;
			notitype = RESOURCED_NOTIFIER_APP_FOREGRD;
		}
		if (proc_data.pai) {
			proc_data.appid = proc_data.pai->appid;
			resourced_notify(notitype, &proc_data);
		}

		if (proc_get_freezer_status() == CGROUP_FREEZER_DISABLED)
			break;

		if (apptype == PROC_TYPE_GUI)
			resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &proc_data);
		break;
	case PROC_CGROUP_SET_LAUNCH_REQUEST:
		proc_set_oom_score_adj(pid, OOMADJ_INIT);
		if (!app_name) {
			_E("need application name!pid = %d", pid);
			return RESOURCED_ERROR_NO_DATA;
		}
		_SD("launch request %s, %d", app_name, pid);
		if (pkg_name)
			_SD("launch request %s with pkgname", pkg_name);
		ret = resourced_proc_excluded(app_name);
		if (!ret)
			proc_data.pai = proc_add_app_list(apptype,
				    pid, app_name, pkg_name);
		if (!proc_data.pai)
			break;
		if (CHECK_BIT(proc_data.pai->flags, PROC_BGALLOW))
			proc_set_runtime_exclude_list(pid, PROC_EXCLUDE);
		resourced_notify(RESOURCED_NOTIFIER_APP_LAUNCH, &proc_data);
		_E("available memory = %u", proc_get_mem_available());
		if (proc_get_freezer_status() == CGROUP_FREEZER_DISABLED)
			break;
		ppi = proc_data.pai->program;
		if (ppi->svc_list)
			resourced_notify(RESOURCED_NOTIFIER_SERVICE_WAKEUP, &proc_data);
		break;
	case PROC_CGROUP_SET_SERVICE_REQUEST:
		if (!app_name) {
			_E("need application name!pid = %d", pid);
			return RESOURCED_ERROR_NO_DATA;
		}
		_SD("service launch request %s, %d", app_name, pid);
		if (pkg_name)
			_SD("launch request %s with pkgname", pkg_name);
		proc_data.pai = proc_add_app_list(PROC_TYPE_SERVICE,
				    pid, app_name, pkg_name);
		if (!proc_data.pai)
			break;
		if (resourced_proc_excluded(app_name) == RESOURCED_ERROR_NONE)
			resourced_notify(RESOURCED_NOTIFIER_SERVICE_LAUNCH, &proc_data);
		if (!(CHECK_BIT(proc_data.pai->flags, PROC_BGCTRL_APP)) ||
		    CHECK_BIT(proc_data.pai->flags, PROC_BGALLOW))
			proc_set_runtime_exclude_list(pid, PROC_EXCLUDE);
		break;
	case PROC_CGROUP_SET_RESUME_REQUEST:
		_SD("resume request %d", pid);
		/* init oom_score_value */
		if (!app_name) {
			_E("need application name!pid = %d", pid);
			return RESOURCED_ERROR_NO_DATA;
		}

		proc_data.pai = find_app_info(pid);
		if (!proc_data.pai && ! resourced_proc_excluded(app_name))
			proc_data.pai = proc_add_app_list(PROC_TYPE_GUI,
				    pid, app_name, pkg_name);

		if (!proc_data.pai)
			return RESOURCED_ERROR_NO_DATA;

		if (apptype == PROC_TYPE_GUI && oom_score_adj >= OOMADJ_FAVORITE) {
			resourced_notify(RESOURCED_NOTIFIER_APP_RESUME, &proc_data);
			proc_set_oom_score_adj(pid, OOMADJ_INIT);
		}
		if (proc_get_freezer_status() == CGROUP_FREEZER_DISABLED)
			break;
		if (apptype == PROC_TYPE_GUI)
			resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &proc_data);
		else if (apptype == PROC_TYPE_SERVICE)
			resourced_notify(RESOURCED_NOTIFIER_SERVICE_WAKEUP, &proc_data);
		break;
	case PROC_CGROUP_SET_TERMINATE_REQUEST:
		proc_data.pai = find_app_info(pid);
		proc_data.pid = pid;
		resourced_notify(RESOURCED_NOTIFIER_APP_TERMINATE_START, &proc_data);
		resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &proc_data);
		break;
	case PROC_CGROUP_SET_ACTIVE:
		ret = proc_set_active(pid, oom_score_adj);
		if (ret != RESOURCED_ERROR_OK)
			break;
		resourced_notify(RESOURCED_NOTIFIER_APP_ACTIVE, &proc_data);
		break;
	case PROC_CGROUP_SET_BACKGRD:
		if (apptype == PROC_TYPE_WIDGET  || apptype == PROC_TYPE_WATCH) {
			proc_data.pai = find_app_info(pid);
			if (!proc_data.pai)
				proc_add_app_list(apptype, pid, app_name, pkg_name);
			proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_PERCEPTIBLE);
			if (apptype == PROC_TYPE_WATCH)
				break;
			resourced_notify(RESOURCED_NOTIFIER_WIDGET_BACKGRD, &proc_data);
		} else {
			snprintf(pidbuf, sizeof(pidbuf), "%d", pid);
			dbus_proc_handler(PREDEF_BACKGRD, pidbuf);
			ret = proc_set_backgrd(pid, oom_score_adj);
			if (ret != 0)
				break;
			if ((proc_get_freezer_status() == CGROUP_FREEZER_DISABLED)
			    || get_proc_freezer_late_control())
				break;

			proc_data.pai = find_app_info(pid);
			proc_data.pid = pid;
			resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &proc_data);
		}
		break;
	case PROC_CGROUP_SET_INACTIVE:
		ret = proc_set_inactive(pid, oom_score_adj);
		if (ret != RESOURCED_ERROR_OK)
			break;
		resourced_notify(RESOURCED_NOTIFIER_APP_INACTIVE, &proc_data);
		break;
	case PROC_CGROUP_GET_MEMSWEEP:
		ret = proc_sweep_memory(PROC_SWEEP_EXCLUDE_ACTIVE, pid);
		break;
	case PROC_CGROUP_SET_NOTI_REQUEST:
		if (proc_get_freezer_status() == CGROUP_FREEZER_DISABLED)
			break;
		if (app_name) {
			proc_data.pai = find_app_info_by_appid(app_name);
			if (!proc_data.pai)
				break;
			proc_data.pid = proc_data.pai->main_pid;
			resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &proc_data);
		}
		break;
	case PROC_CGROUP_SET_PROC_EXCLUDE_REQUEST:
		proc_set_runtime_exclude_list(pid, PROC_EXCLUDE);
		break;
	case PROC_CGROUP_SET_TERMINATED:
		proc_data.pai = find_app_info(pid);
		if (proc_data.pai)
			proc_data.appid = proc_data.pai->appid;
		resourced_notify(RESOURCED_NOTIFIER_APP_TERMINATED, &proc_data);
		proc_remove_app_list(pid);
		break;
	case PROC_CGROUP_SET_SYSTEM_SERVICE:
		if (oom_score_adj < OOMADJ_BACKGRD_PERCEPTIBLE)
			proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_PERCEPTIBLE);
		resourced_notify(RESOURCED_NOTIFIER_SYSTEM_SERVICE, &proc_data);
		break;
	default:
		ret = RESOURCED_ERROR_INVALID_PARAMETER;
	}
	return ret;
}

int resourced_proc_action(int status, int argnum, char **arg)
{
	pid_t pid;
	char *pidbuf = NULL, *cgroup_name = NULL, *pkg_name = NULL;
	if (argnum < 1) {
		_E("Unsupported number of arguments!");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	pidbuf = arg[0];
	pid = (pid_t)atoi(pidbuf);
	if (pid < 0) {
		_E("Invalid pid argument!");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	/* Getting appid */
	if (argnum > 1)
		/* It's possible to get appid from arg */
		cgroup_name = arg[1];
	if (argnum == 3)
		pkg_name = arg[2];
	_SD("appid %s, pid %d, status %d\n", cgroup_name, pid, status);
	return resourced_proc_status_change(status, pid, cgroup_name, pkg_name, PROC_TYPE_GUI);
}

int proc_get_state(int type, pid_t pid, char *buf, int len)
{
	int ret = 0;

	switch (type) {
	case PROC_CGROUP_GET_CMDLINE:
		ret = proc_get_raw_cmdline(pid, buf, len);
		break;
	case PROC_CGROUP_GET_EXE:
		ret = proc_get_exepath(pid, buf, len);
		break;
	case PROC_CGROUP_GET_STAT:
		ret = proc_get_stat(pid, buf, len);
		break;
	case PROC_CGROUP_GET_STATUS:
		ret = proc_get_status(pid, buf, len);
		break;
	case PROC_CGROUP_GET_OOMSCORE:
		ret = proc_get_oom_score_adj(pid, (int *)buf);
		break;
	default:
		_E("unsupported command %d, pid(%d)", type, pid);
		ret = RESOURCED_ERROR_FAIL;
		break;
	}
	return ret;
}

void resourced_proc_dump(int mode, const char *dirpath)
{
	char buf[MAX_PATH_LENGTH];
	FILE *f = NULL;
	if (dirpath) {
		snprintf(buf, sizeof(buf), "%s/%s", dirpath, LOG_PREFIX);
		f = fopen(buf, "w+");
	}
	proc_dump_process_list(f);
	modules_dump((void *)f, mode);
	if (f)
		fclose(f);
}

static const struct module_ops proc_modules_ops = {
	.priority	= MODULE_PRIORITY_HIGH,
	.name		= "PROC",
	.init		= resourced_proc_init,
	.exit		= resourced_proc_exit,
};

MODULE_REGISTER(&proc_modules_ops)
