/*
 * resourced
 *
 * Copyright (c) 2012 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file logging.c
 *
 * @desc start logging system for resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <glib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <Ecore.h>

#include "trace.h"
#include "logging-common.h"
#include "resourced.h"
#include "macro.h"
#include "module.h"
#include "proc-process.h"
#include "proc-main.h"
#include "proc_stat.h"
#include "logging.h"
#include "edbus-handler.h"

#define	BUF_MAX 		1024
#define	WRITE_INFO_MAX 		10
#define	MAX_PROC_LIST 		200

#define	WEBPROCESS_NAME		"WebProcess"
#define	MAX_PROC_ITEM		200
#define	INC_PROC_ITEM		10
#define	COMMIT_INTERVAL		10*60	/* 10 min */
#define LOGGING_PTIORITY	-20

#define SIGNAL_LOGGING_INIT	"LoggingInit"
#define SIGNAL_LOGGING_GET	"LoggingGet"
#define SIGNAL_LOGGING_UPDATED	"LoggingUpdated"
#define PROC_OOM_SCORE_ADJ_PATH	"/proc/%d/oom_score_adj"

struct logging_sub_sys {
	const char *name;
	time_t commit_interval;
	time_t last_commit;
	struct logging_info_ops *ops;
};

static const struct module_ops logging_modules_ops;
static const struct module_ops *logging_ops;

static int num_log_infos;
static bool need_to_update;
static GHashTable *logging_proc_list;
static GArray *logging_ss_list;
static pthread_t	logging_thread	= 0;
static pthread_mutex_t	logging_mutex	= PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t	proc_list_mutex	= PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	logging_cond	= PTHREAD_COND_INITIALIZER;

static int init_logging_infos(struct logging_infos *info, const char *key,
	pid_t pid, int oom, time_t now)
{
	int i;
	int ret;

	if (!info) {
		_D("info is null");
		return RESOURCED_ERROR_FAIL;
	}

	info->oom = oom;
	info->pid = pid;
	info->running = true;

	for (i = 0; i < logging_ss_list->len; i++) {
		struct logging_sub_sys *ss = &g_array_index(logging_ss_list,
						struct logging_sub_sys, i);
		ret = ss->ops->init(&(info->stats[i]), pid, oom, now);
		if (ret != RESOURCED_ERROR_NONE) {
			_E("init logging at %lu", now);
			/* not return error, just continue updating */
		}
	}

	return RESOURCED_ERROR_NONE;
}

static void update_logging_infos(struct logging_infos *info,
	time_t now, unsigned first)
{
	int i;
	int ret;
	for (i = 0; i < logging_ss_list->len; i++) {
		struct logging_sub_sys *ss = &g_array_index(logging_ss_list,
						struct logging_sub_sys, i);
		ret = ss->ops->update(info->stats[i], info->pid, info->oom, now, first);
		if (ret != RESOURCED_ERROR_NONE) {
			/*
			 * when update failed, this is because there is no
			 * running process. So, just update processes running
			 * state.
			 */
			info->running = false;
		}
	}

	return;
}

static void insert_hash_table(char *key, pid_t pid, int oom)
{
	struct logging_infos *info;
	void **stats;
	char *name;
	time_t now;

	now = time(NULL);

	name = malloc(strlen(key) + 1);

	if (!name) {
		_D("memory allocation for name failed");
		return;
	}
	strcpy(name, key);
	info = (struct logging_infos *)malloc(sizeof(struct logging_infos));

	if (!info) {
		_D("memory allocation for logging_infos failed");
		free(name);
		return;
	}

	stats = (void **)malloc(sizeof(void *) * num_log_infos);

	if (!stats) {
		_D("memory allocation for log infos fails");
		free(name);
		free(info);
		return;
	}

	info->stats = stats;
	init_logging_infos(info, name, pid, oom, now);

	g_hash_table_insert(logging_proc_list, (gpointer) name, (gpointer) info);
	update_logging_infos(info, now, true);
	return;
}

static int write_journal(struct logging_sub_sys *pss, int ss_index)
{
	gpointer value;
	gpointer key;
	int ret = RESOURCED_ERROR_NONE;
	char *name;
	GHashTableIter iter;
	struct logging_infos *infos;
	g_hash_table_iter_init(&iter, logging_proc_list);

	while (1) {
		ret = pthread_mutex_lock(&proc_list_mutex);
		if (ret) {
			_E("proc_list_mutex::pthread_mutex_lock() failed, %d", ret);
			return ret;
		}

		if (!g_hash_table_iter_next(&iter, &key, &value)) {
			ret = pthread_mutex_unlock(&proc_list_mutex);
			if (ret) {
				_E("proc_list_mutex::pthread_mutex_unlock() failed, %d", ret);
				return ret;
			}
			break;
		}

		name = (char *)key;
		infos = (struct logging_infos *)value;
		pss->ops->write(name, infos, ss_index);
		ret = pthread_mutex_unlock(&proc_list_mutex);
		if (ret) {
			_E("proc_list_mutex::pthread_mutex_unlock() failed, %d", ret);
			return ret;
		}
	}

	return RESOURCED_ERROR_NONE;
}

static int write_logging_subsys_info(struct logging_sub_sys *pss, int sindex,
	time_t now, bool force)
{

	if (!force && now < pss->last_commit + pss->commit_interval)
		return RESOURCED_ERROR_NONE;

	_D("start write %s subsys, now %lu, last:%lu, interval:%lu",
		pss->name, now, pss->last_commit, pss->commit_interval);

	write_journal(pss, sindex);

	pss->last_commit = now;
	return RESOURCED_ERROR_NONE;

}

static int write_logging_infos(bool force)
{
	int i;
	int ret;
	time_t now;

	now = time(NULL);

	for (i = 0; i < logging_ss_list->len; i++) {
		struct logging_sub_sys *ss = &g_array_index(logging_ss_list,
						struct logging_sub_sys, i);
		ret = write_logging_subsys_info(ss, i, now, force);
		if (ret != RESOURCED_ERROR_NONE) {
			_E("write logging at %lu", now);
			/* not return error, just continue updating */
		}
	}

	return RESOURCED_ERROR_NONE;
}

int register_logging_subsystem(const char*name, struct logging_info_ops *ops)
{
	struct logging_sub_sys ss;
	char *ss_name;
	time_t now;

	ss_name = malloc(strlen(name)+1);

	if (!ss_name) {
		_E("memory allocation for name is failed");
		return RESOURCED_ERROR_FAIL;
	}

	now = time(NULL);

	strcpy(ss_name, name);
	ss.name = ss_name;
	ss.commit_interval = COMMIT_INTERVAL;
	ss.last_commit = now;
	ss.ops = ops;

	g_array_append_val(logging_ss_list, ss);
	num_log_infos++;

	return RESOURCED_ERROR_NONE;
}

int update_commit_interval(const char *name, time_t commit_interval)
{
	int i;
	for (i = 0; i < logging_ss_list->len; i++) {
		struct logging_sub_sys *ss = &g_array_index(logging_ss_list,
						struct logging_sub_sys, i);
		if (!strcmp(ss->name, name)) {
			ss->commit_interval = commit_interval;
			_D("%s logging subsystem commit interval updated to %lu",
			ss->name, ss->commit_interval);
			return RESOURCED_ERROR_NONE;
		}
	}

	_D("%s subsystem update fail, not exist", name);
	return RESOURCED_ERROR_FAIL;
}

static inline int is_webprocess(char *name)
{
	return !strcmp(name, WEBPROCESS_NAME);
}

static int rename_webprocess(pid_t pgid, char *name)
{
	char webui_name[PROC_NAME_MAX];
	int ret;

	if ((ret = proc_get_cmdline(pgid, webui_name)) != RESOURCED_ERROR_NONE)
		return RESOURCED_ERROR_FAIL;

	strcat(name, ".");
	strcat(name, webui_name);

	return RESOURCED_ERROR_NONE;
}

static int get_cmdline(pid_t pid, char *cmdline)
{
	char buf[PROC_BUF_MAX];
	FILE *fp;

	sprintf(buf, "/proc/%d/cmdline", pid);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;

	if (fgets(cmdline, PROC_NAME_MAX-1, fp) == NULL) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	fclose(fp);

	return RESOURCED_ERROR_NONE;
}

static void insert_proc_list(pid_t pid, pid_t pgid, int oom)
{
	int ret = RESOURCED_ERROR_NONE;
	char name[PROC_NAME_MAX];
	struct logging_infos *info;

	ret = get_cmdline(pid, name);
	/*
	 * if cmdline does not exist, remove item from queue
	 * and continue logging remaining items
	 */
	if (ret != RESOURCED_ERROR_NONE) {
		return;
	}

	if (is_webprocess(name)) {
		ret = rename_webprocess(pgid, name);
		if (ret != RESOURCED_ERROR_NONE)
			return;

	}

	ret = pthread_mutex_lock(&proc_list_mutex);
	if (ret) {
		_E("proc_list_mutex::pthread_mutex_lock() failed, %d", ret);
		return;
	}

	info = (struct logging_infos *)
		g_hash_table_lookup(logging_proc_list, name);

	/* To Do: handle multiple daemons with the same name */
	if (!info) {
		insert_hash_table(name, pid, oom);
	} else {
		info->running = true;
		info->pid = pid;
		info->oom = oom;
	}

	ret = pthread_mutex_unlock(&proc_list_mutex);
	if (ret) {
		_E("proc_list_mutex::pthread_mutex_unlock() failed, %d", ret);
		return;
	}
	return;
}

static bool is_running_process(GArray *garray, pid_t pid)
{
	int i;
	pid_t tpid;

	for (i = 0 ; i < garray->len; i++) {
		tpid = g_array_index(garray, pid_t, i);
		if (tpid == pid)
			return true;
	}
	return false;
}

static void update_proc_state(void)
{
	DIR *dirp;
	struct dirent *entry;
	GArray *running_procs = NULL;
	GHashTableIter iter;
	int ret;
	gpointer key, value;

	running_procs = g_array_new(false, false, sizeof(pid_t));

	if (!running_procs) {
		_E("fail to create garray for pids");
		return;
	}

	dirp = opendir("/proc");

	if (dirp == NULL) {
		_E("/proc open is failed, and cannot updated running procs");
		return;
	}

	while ((entry = readdir(dirp)) != NULL) {
		pid_t pid;

		if (!isdigit(entry->d_name[0]))
			continue;
		pid = atoi(entry->d_name);
		g_array_append_val(running_procs, pid);
	}

	closedir(dirp);

	g_hash_table_iter_init(&iter, logging_proc_list);

	ret = pthread_mutex_lock(&proc_list_mutex);
	if (ret) {
		_E("proc_list_mutex::pthread_mutex_lock() failed, %d", ret);
		g_array_free(running_procs, true);
		return;
	}

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct logging_infos *info = (struct logging_infos *)value;
		info->running = is_running_process(running_procs, info->pid);
	}

	g_array_free(running_procs, true);

	ret = pthread_mutex_unlock(&proc_list_mutex);
	if (ret) {
		_E("proc_list_mutex::pthread_mutex_unlock() failed, %d", ret);
		return;
	}

	need_to_update = false;
	return;
}

static void update_proc_list(void)
{
	GHashTableIter iter;
	gpointer key, value;
	time_t now;
	struct logging_infos *infos;
	int ret;

	if (need_to_update)
		update_proc_state();

	now = time(NULL);

	g_hash_table_iter_init(&iter, logging_proc_list);

	while (1) {
		ret = pthread_mutex_lock(&proc_list_mutex);
		if (ret) {
			_E("proc_list_mutex::pthread_mutex_lock() failed, %d", ret);
			return;
		}

		if (!g_hash_table_iter_next(&iter, &key, &value)) {
			ret = pthread_mutex_unlock(&proc_list_mutex);
			if (ret) {
				_E("proc_list_mutex::pthread_mutex_unlock() failed, %d", ret);
				return;
			}
			_D("finish proc list update");
			break;
		}
		infos = (struct logging_infos *)value;

		if (infos->running)
			update_logging_infos(infos, now, false);
		ret = pthread_mutex_unlock(&proc_list_mutex);
		if (ret) {
			_E("proc_list_mutex::pthread_mutex_unlock() failed, %d", ret);
			return;
		}
	}

	return;
}

static void logging_update_state(void)
{
	need_to_update = true;
}

static int check_running(gpointer key, gpointer value, gpointer user_data)
{
	struct logging_infos *infos = (struct logging_infos *)value;

	return !(infos->running);
}

static void reclaim_proc_list(void)
{
	int ret;

	ret = pthread_mutex_lock(&proc_list_mutex);
	if (ret) {
		_E("proc_list_mutex::pthread_mutex_lock() failed, %d", ret);
		return;
	}

	g_hash_table_foreach_remove(logging_proc_list, check_running, NULL);
	ret = pthread_mutex_unlock(&proc_list_mutex);
	if (ret) {
		_E("proc_list_mutex::pthread_mutex_unlock() failed, %d", ret);
		return;
	}
}

static void logging(void)
{
	update_proc_list();

	if (g_hash_table_size(logging_proc_list) > MAX_PROC_LIST) {
		write_logging_infos(true);
		reclaim_proc_list();
	} else
		write_logging_infos(false);
}

static void *logging_pthread(void *arg)
{
	int ret = 0;

	setpriority(PRIO_PROCESS, 0, LOGGING_PTIORITY);

	while (1) {
		/*
		 * When signalled by main thread,
		 * it starts logging_pthread().
		 */
		ret = pthread_mutex_lock(&logging_mutex);
		if ( ret ) {
			_E("logging thread::pthread_mutex_lock() failed, %d", ret);
			break;
		}

		ret = pthread_cond_wait(&logging_cond, &logging_mutex);
		if ( ret ) {
			_E("logging thread::pthread_cond_wait() failed, %d", ret);
			ret = pthread_mutex_unlock(&logging_mutex);
			if ( ret )
				_E("logging thread::pthread_mutex_lock() failed, %d", ret);
			break;
		}

		logging();

		ret = pthread_mutex_unlock(&logging_mutex);
		if ( ret ) {
			_E("logging thread::pthread_mutex_unlock() failed, %d", ret);
			break;
		}
	}

	/* Now our thread finishes - cleanup TID */
	logging_thread = 0;

	return NULL;
}


static int logging_thread_create(void)
{
	int ret = RESOURCED_ERROR_NONE;

	if (logging_thread) {
		_I("logging thread %u already created", (unsigned)logging_thread);
	} else {
		/* initialize logging_thread */
		ret = pthread_create(&logging_thread, NULL, (void *)logging_pthread, (void *)NULL);
		if (ret) {
			_E("pthread creation for logging_pthread failed, %d\n", ret);
			logging_thread = 0;
		} else {
			_D("pthread creation for logging success");
			pthread_detach(logging_thread);
		}
	}

	return ret;
}

static void free_key(gpointer key)
{
	if (!key)
		free(key);
}

static void free_value(gpointer value)
{
	int i;
	struct logging_infos * info = (struct logging_infos *)value;

	if (!info)
		return;

	for (i = 0; i < num_log_infos; i++) {
		if (info->stats[i])
			free(info->stats[i]);
	}

	if (info->stats)
		free(info->stats);

	free(info);
}

static void initialize_logging_proc_list(void)
{
	DIR *dirp;
	struct dirent *entry;
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	int cur_oom = -1;
	FILE *fp = NULL;

	dirp = opendir("/proc");

	if (dirp == NULL) {
		_E("/proc open is failed, and cannot updated running procs");
		return;
	}

	while ((entry = readdir(dirp)) != NULL) {
		pid_t pid, pgid;

		if (!isdigit(entry->d_name[0]))
			continue;
		pid = atoi(entry->d_name);
		pgid = getpgid(pid);
		if (!pgid)
			continue;
		snprintf(buf, sizeof(buf), PROC_OOM_SCORE_ADJ_PATH, pid);
		fp = fopen(buf, "r+");
		if (fp == NULL)
			continue;
		if (fgets(buf, sizeof(buf), fp) == NULL) {
			fclose(fp);
			continue;
		}
		cur_oom = atoi(buf);
		fclose(fp);
		insert_proc_list(pid, pgid, cur_oom);
	}

	closedir(dirp);
	write_logging_infos(true);
	return;
}

static void logging_update_start(void)
{
	int ret;
	/* signal to logging_pthread to start */
	ret = pthread_mutex_lock(&logging_mutex);
	if (ret) {
		_E("logging_update_start::pthread_mutex_lock() failed, %d", ret);
		return;
	}

	ret = pthread_cond_signal(&logging_cond);
	if (ret) {
		_E("logging_update_start::pthread_cond_wait() failed, %d", ret);
		ret = pthread_mutex_unlock(&logging_mutex);
		if ( ret )
			_E("logging_update_start::pthread_mutex_unlock() failed, %d", ret);
		return;
	}

	_D("send signal logging_pthread");
	ret = pthread_mutex_unlock(&logging_mutex);
	if (ret) {
		_E("logging_update_start::pthread_mutex_unlock() failed, %d", ret);
		return;
	}
}

static void broadcast_logging_data_updated_signal(void)
{
	int r;

	r = broadcast_edbus_signal_str(RESOURCED_PATH_LOGGING, RESOURCED_INTERFACE_LOGGING,
			SIGNAL_LOGGING_UPDATED, NULL, NULL);
	_I("broadcast logging_data updated signal!");

	if (r < 0)
		_E("Failed: broadcast logging_data_updated signal");
}

static void logging_init_booting_done_edbus_signal_handler(void *data, DBusMessage *msg)
{
	int ret;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_LOGGING,
		SIGNAL_LOGGING_INIT);
	if (ret == 0) {
		_D("there is booting done signal");
		return;
	}
	initialize_logging_proc_list();
	_D("logging_init_booting_done_edbus_signal_handler");
}

static void logging_get_edbus_signal_handler(void *data, DBusMessage *msg)
{
	int ret;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_LOGGING,
		SIGNAL_LOGGING_GET);
	if (ret == 0) {
		_D("there is logging get signal");
		return;
	}
	write_logging_infos(true);
	_D("logging_get_edbus_signal_handler");
	broadcast_logging_data_updated_signal();
}

static int logging_init(void)
{
	int ret = RESOURCED_ERROR_NONE;

	_D("logging_init start");

	logging_proc_list = g_hash_table_new_full(
		g_str_hash,
		g_str_equal,
		free_key,
		free_value);

	if (!logging_proc_list) {
		_E("fail g_hash_table_new_full() for logging_proc_list");
		return RESOURCED_ERROR_FAIL;
	}

	logging_ss_list = g_array_new(false, false,
		sizeof(struct logging_sub_sys));

	if (logging_ss_list == NULL)
		return RESOURCED_ERROR_FAIL;

	ret = logging_thread_create();
	if (ret) {
		_E("logging thread create failed");
		return RESOURCED_ERROR_FAIL;
	}

	register_edbus_signal_handler(RESOURCED_PATH_LOGGING,
		RESOURCED_INTERFACE_LOGGING, SIGNAL_LOGGING_INIT,
		    (void *)logging_init_booting_done_edbus_signal_handler);

	register_edbus_signal_handler(RESOURCED_PATH_LOGGING,
		RESOURCED_INTERFACE_LOGGING, SIGNAL_LOGGING_GET,
		    (void *)logging_get_edbus_signal_handler);

	return RESOURCED_ERROR_NONE;
}

static int resourced_logging_control(void *data)
{
	int ret = RESOURCED_ERROR_NONE;
	struct logging_data_type *l_data;

	if (!num_log_infos)
		return ret;

	l_data = (struct logging_data_type *)data;

	switch(l_data->control_type) {
	case LOGGING_INSERT_PROC_LIST:
		if (l_data->args)
			insert_proc_list((pid_t)l_data->args[0],
				(pid_t)l_data->args[1], (int)l_data->args[2]);
		break;
	case LOGGING_UPDATE_PROC_INFO:
		logging_update_start();
		break;
	case LOGGING_UPDATE_STATE:
		logging_update_state();
		break;
	}
	return ret;
}

static int resourced_logging_init(void *data)
{
	logging_ops = &logging_modules_ops;

	return logging_init();
}

static int resourced_logging_exit(void *data)
{
	if (logging_ss_list)
		g_array_free(logging_ss_list, TRUE);
	if (logging_proc_list)
		g_hash_table_destroy(logging_proc_list);
	return RESOURCED_ERROR_NONE;
}

int logging_control(enum logging_control_type type, unsigned long *args)
{
	struct logging_data_type l_data;

	if (logging_ops) {
		l_data.control_type = type;
		l_data.args = args;
		return logging_ops->control(&l_data);
	}

	return RESOURCED_ERROR_NONE;
}

static const struct module_ops logging_modules_ops = {
	.priority	= MODULE_PRIORITY_HIGH,
	.name		= "logging",
	.init		= resourced_logging_init,
	.exit		= resourced_logging_exit,
	.control	= resourced_logging_control,
};

MODULE_REGISTER(&logging_modules_ops)
