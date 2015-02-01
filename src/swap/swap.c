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
 *
*/

/*
 * @file swap.c
 * @desc swap process
 */

#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "edbus-handler.h"
#include "swap-common.h"
#include "notifier.h"
#include "proc-process.h"

#include <resourced.h>
#include <trace.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/resource.h>

#define MAX_SWAP_VICTIMS		16

#define MEMCG_PATH			"/sys/fs/cgroup/memory"
#define SWAPCG_PATH			MEMCG_PATH"/swap"
#define SWAPCG_PROCS			SWAPCG_PATH"/cgroup.procs"
#define SWAPCG_USAGE			SWAPCG_PATH"/memory.usage_in_bytes"
#define SWAPCG_RECLAIM			SWAPCG_PATH"/memory.force_reclaim"

#define SWAP_ON_EXEC_PATH		"/sbin/swapon"
#define SWAP_OFF_EXEC_PATH		"/sbin/swapoff"

#define SIGNAL_NAME_SWAP_TYPE		"SwapType"
#define SIGNAL_NAME_SWAP_START_PID	"SwapStartPid"

#define SWAPFILE_NAME			"/dev/zram0"

#define SWAP_PATH_MAX			100

#define MBtoB(x)			(x<<20)
#define MBtoPage(x)			(x<<8)

#define BtoMB(x)			((x) >> 20)
#define BtoPAGE(x)			((x) >> 12)

#define SWAP_TIMER_INTERVAL		0.5
#define SWAP_PRIORITY			20

#define SWAP_COUNT_MAX                 5

struct swap_data_type {
	enum swap_status_type	 status_type;
	unsigned long *args;
};

static int swapon;
static pthread_mutex_t swap_mutex;
static pthread_cond_t swap_cond;
static Ecore_Timer *swap_timer = NULL;

static const struct module_ops swap_modules_ops;
static const struct module_ops *swap_ops;

pid_t swap_victims[MAX_SWAP_VICTIMS];

static int swap_set_candidate_pid(void *data)
{
	unsigned long *args = data;
	int i;
	int *pid_array = (int*)args[0];
	int count = (int)args[1];

	memset(swap_victims, 0, sizeof(int)*MAX_SWAP_VICTIMS);

	for (i = 0; i < count; i++)
		swap_victims[i] = pid_array[i];

	return RESOURCED_ERROR_NONE;
}

static pid_t swap_get_candidate_pid(void)
{
	int i;
	pid_t pid = 0;

	for (i = 0; i < MAX_SWAP_VICTIMS; i++)
		if(swap_victims[i]) {
			pid = swap_victims[i];
			swap_victims[i] = 0;
			break;
		}
	return pid;
}

static int swap_get_swap_type(void)
{
	struct shared_modules_data *modules_data = get_shared_modules_data();

	ret_value_msg_if(modules_data == NULL, RESOURCED_ERROR_FAIL,
			 "Invalid shared modules data\n");
	return modules_data->swap_data.swaptype;
}

static void swap_set_swap_type(int type)
{
	struct shared_modules_data *modules_data = get_shared_modules_data();

	ret_msg_if(modules_data == NULL,
			 "Invalid shared modules data\n");
	modules_data->swap_data.swaptype = type;
}

static int swap_check_swap_pid(int pid)
{
	char buf[SWAP_PATH_MAX] = {0,};
	int swappid;
	int ret = 0;
	FILE *f;

	f = fopen(SWAPCG_PROCS, "r");
	if (!f) {
		_E("%s open failed", SWAPCG_PROCS);
		return RESOURCED_ERROR_FAIL;
	}

	while (fgets(buf, SWAP_PATH_MAX, f) != NULL) {
		swappid = atoi(buf);
		if (swappid == pid) {
			ret = swappid;
			break;
		}
	}
	fclose(f);
	return ret;
}

static int swap_check_swap_cgroup(void)
{
	char buf[SWAP_PATH_MAX] = {0,};
	int ret = SWAP_FALSE;
	FILE *f;

	f = fopen(SWAPCG_PROCS, "r");
	if (!f) {
		_E("%s open failed", SWAPCG_PROCS);
		return RESOURCED_ERROR_FAIL;
	}
	while (fgets(buf, SWAP_PATH_MAX, f) != NULL) {
		ret = SWAP_TRUE;
		break;
	}
	fclose(f);
	return ret;
}

static int swap_thread_do(FILE *procs, FILE *usage_in_bytes, FILE *force_reclaim)
{
	char buf[SWAP_PATH_MAX] = {0,};
	char appname[SWAP_PATH_MAX];
	pid_t pid = 0;
	int size;
	int swap_cg_cnt=0;
	unsigned long usage, nr_to_reclaim;

	/* check swap cgroup count */
	while (fgets(buf, SWAP_PATH_MAX, procs) != NULL) {
		pid_t tpid = 0;
		int toom = 0;
		int ret;

		if (!pid) {
			tpid = atoi(buf);

			if (proc_get_oom_score_adj(tpid, &toom) < 0) {
			       _D("pid(%d) was already terminated", tpid);
			       continue;
			}

			if (toom < OOMADJ_BACKGRD_UNLOCKED)
			       continue;

			ret = proc_get_cmdline(tpid, appname);
			if (ret == RESOURCED_ERROR_FAIL)
			       continue;

			pid = tpid;
		}
		swap_cg_cnt++;
	}

	/* swap cgroup count is MAX, kill 1 process */
	if (swap_cg_cnt >= SWAP_COUNT_MAX) {
		kill(pid, SIGKILL);
		_E("we killed %d (%s)", pid, appname);
	}

	/* cacluate reclaim size by usage and swap cgroup count */
	if (fgets(buf, 32, usage_in_bytes) == NULL)
		return RESOURCED_ERROR_FAIL;

	usage = (unsigned long)atol(buf);

	nr_to_reclaim = BtoPAGE(usage) >> ((swap_cg_cnt >> 1) + 1);

	/* set reclaim size */
	size = sprintf(buf, "%lu", nr_to_reclaim);
	if (fwrite(buf, 1, size, force_reclaim) != size)
		_E("fwrite %s\n", buf);

	return RESOURCED_ERROR_NONE;
}

static void *swap_thread_main(void * data)
{
	FILE *procs = NULL;
	FILE *usage_in_bytes = NULL;
	FILE *force_reclaim = NULL;

	setpriority(PRIO_PROCESS, 0, SWAP_PRIORITY);

	if (procs == NULL) {
		procs = fopen(SWAPCG_PROCS, "r");
		if (procs == NULL) {
			_E("%s open failed", SWAPCG_PROCS);
			return NULL;
		}
	}

	if (usage_in_bytes == NULL) {
		usage_in_bytes = fopen(SWAPCG_USAGE, "r");
		if (usage_in_bytes == NULL) {
			_E("%s open failed", SWAPCG_USAGE);
			fclose(procs);
			return NULL;
		}
	}

	if (force_reclaim == NULL) {
		force_reclaim = fopen(SWAPCG_RECLAIM, "w");
		if (force_reclaim == NULL) {
			_E("%s open failed", SWAPCG_RECLAIM);
			fclose(procs);
			fclose(usage_in_bytes);
			return NULL;
		}
	}

	while (1) {
		pthread_mutex_lock(&swap_mutex);
		pthread_cond_wait(&swap_cond, &swap_mutex);

		/*
		 * when signalled by main thread, it starts
		 * swap_thread_do().
		 */
		_I("swap thread conditional signal received");

		fseek(procs, 0, SEEK_SET);
		fseek(usage_in_bytes, 0, SEEK_SET);
		fseek(force_reclaim, 0, SEEK_SET);

		_D("swap_thread_do start");
		swap_thread_do(procs, usage_in_bytes, force_reclaim);
		_D("swap_thread_do end");
		pthread_mutex_unlock(&swap_mutex);
	}

	if (procs)
		fclose(procs);
	if (usage_in_bytes)
		fclose(usage_in_bytes);
	if (force_reclaim)
		fclose(force_reclaim);

	return NULL;
}

static Eina_Bool swap_send_signal(void *data)
{
	int ret;

	_D("swap timer callback function start");

	/* signal to swap_start to start swap */
	ret = pthread_mutex_trylock(&swap_mutex);

	if (ret)
		_E("pthread_mutex_trylock fail : %d, errno : %d", ret, errno);
	else {
		pthread_cond_signal(&swap_cond);
		_I("send signal to swap thread");
		pthread_mutex_unlock(&swap_mutex);
	}

	_D("swap timer delete");

	ecore_timer_del(swap_timer);
	swap_timer = NULL;

	return ECORE_CALLBACK_CANCEL;
}

static int swap_start(void *data)
{
	if (swap_timer == NULL) {
		_D("swap timer start");
		swap_timer =
			ecore_timer_add(SWAP_TIMER_INTERVAL, swap_send_signal, (void *)NULL);
	}

	return RESOURCED_ERROR_NONE;
}

static int swap_thread_create(void)
{
	int ret = RESOURCED_ERROR_NONE;
	pthread_t pth;

	pthread_mutex_init(&swap_mutex, NULL);
	pthread_cond_init(&swap_cond, NULL);

	ret = pthread_create(&pth, NULL, &swap_thread_main, (void*)NULL);
	if (ret) {
		_E("pthread creation for swap_thread failed\n");
		return ret;
	} else {
		pthread_detach(pth);
	}

	return ret;
}

static int get_swap_status(void)
{
	return swapon;
}

static pid_t swap_on(void)
{
	pid_t pid = fork();

	if (pid == 0) {
		execl(SWAP_ON_EXEC_PATH, SWAP_ON_EXEC_PATH, "-d", SWAPFILE_NAME, (char *)NULL);
		exit(0);
	}
	swapon = 1;
	return pid;
}

static pid_t swap_off(void)
{
	pid_t pid = fork();

	if (pid == 0) {
		execl(SWAP_OFF_EXEC_PATH, SWAP_OFF_EXEC_PATH, SWAPFILE_NAME, (char *)NULL);
		exit(0);
	}
	swapon = 0;
	return pid;
}

static int restart_swap(void *data)
{
	int status;
	pid_t pid;
	pid_t ret;

	if (!swapon) {
		swap_on();
		return RESOURCED_ERROR_NONE;
	}

	pid = fork();
	if (pid == -1) {
		_E("fork() error");
		return RESOURCED_ERROR_FAIL;
	} else if (pid == 0) {
		pid = swap_off();
		ret = waitpid(pid, &status, 0);
		if (ret == -1) {
			_E("Error waiting for swap_off child process (PID: %d, status: %d)", (int)pid, status);
		}
		swap_on();
		exit(0);
	}
	swapon = 1;

	return RESOURCED_ERROR_NONE;
}

static int swap_move_swap_cgroup(void *data)
{
	int *args = data;
	int size;
	FILE *f;
	char buf[SWAP_PATH_MAX] = {0,};

	f = fopen(SWAPCG_PROCS, "w");
	if (!f) {
		_E("Fail to %s file open", SWAPCG_PROCS);
		return RESOURCED_ERROR_FAIL;
	}
	size = sprintf(buf, "%d", *args);
	if (fwrite(buf, size, 1, f) != 1)
		_E("fwrite cgroup tasks to swap cgroup failed : %d\n", *args);
	fclose(f);

	return RESOURCED_ERROR_NONE;
}

static void swap_start_pid_edbus_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	pid_t pid;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_SWAP, SIGNAL_NAME_SWAP_START_PID);
	if (ret == 0) {
		_D("there is no swap type signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &pid, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	_I("swap cgroup entered : pid : %d", (int)pid);
	swap_move_swap_cgroup(&pid);

	if (get_swap_status() == SWAP_OFF)
			restart_swap(NULL);
	swap_start(NULL);
}

static void swap_type_edbus_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int type;

	if (dbus_message_is_signal(msg, RESOURCED_INTERFACE_SWAP, SIGNAL_NAME_SWAP_TYPE) == 0) {
		_D("there is no swap type signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	switch (type) {
	case 0:
		if (swap_get_swap_type() != SWAP_OFF) {
			if (swapon)
				swap_off();
			swap_set_swap_type(type);
		}
		break;
	case 1:
		if (swap_get_swap_type() != SWAP_ON) {
			restart_swap(NULL);
			swap_set_swap_type(type);
		}
		break;
	default:
		_D("It is not valid swap type : %d", type);
		break;
	}
}

static DBusMessage *edbus_getswaptype(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	int state;

	state = swap_get_swap_type();

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &state);

	return reply;
}

static struct edbus_method edbus_methods[] = {
	{ "GetSwapType",   NULL,   "i", edbus_getswaptype },
	/* Add methods here */
};

static void swap_dbus_init(void)
{
	resourced_ret_c ret;

	register_edbus_signal_handler(RESOURCED_PATH_SWAP, RESOURCED_INTERFACE_SWAP,
			SIGNAL_NAME_SWAP_TYPE,
		    (void *)swap_type_edbus_signal_handler);
	register_edbus_signal_handler(RESOURCED_PATH_SWAP, RESOURCED_INTERFACE_SWAP,
			SIGNAL_NAME_SWAP_START_PID,
		    (void *)swap_start_pid_edbus_signal_handler);

	ret = edbus_add_methods(RESOURCED_PATH_SWAP, edbus_methods,
			  ARRAY_SIZE(edbus_methods));

	ret_msg_if(ret != RESOURCED_ERROR_NONE,
		"DBus method registration for %s is failed",
			RESOURCED_PATH_SWAP);
}

static int swap_init(void)
{
	int ret;

	ret = swap_thread_create();
	if (ret) {
		_E("swap thread create failed");
		return ret;
	}

	_I("swap_init : %d", swap_get_swap_type());

	swap_dbus_init();

	return ret;
}

static int swap_check_node(void)
{
	FILE *procs = NULL;
	FILE *usage_in_bytes = NULL;
	FILE *force_reclaim = NULL;

	procs = fopen(SWAPCG_PROCS, "r");
	if (procs == NULL) {
		_E("%s open failed", SWAPCG_PROCS);
		return RESOURCED_ERROR_NO_DATA;
	}

	fclose(procs);

	usage_in_bytes = fopen(SWAPCG_USAGE, "r");
	if (usage_in_bytes == NULL) {
		_E("%s open failed", SWAPCG_USAGE);
		return RESOURCED_ERROR_NO_DATA;
	}

	fclose(usage_in_bytes);

	force_reclaim = fopen(SWAPCG_RECLAIM, "w");
	if (force_reclaim == NULL) {
		_E("%s open failed", SWAPCG_RECLAIM);
		return RESOURCED_ERROR_NO_DATA;
	}

	fclose(force_reclaim);

	return RESOURCED_ERROR_NONE;
}

static int resourced_swap_check_runtime_support(void *data)
{
	return swap_check_node();
}

static int resourced_swap_status(void *data)
{
	int ret = RESOURCED_ERROR_NONE;
	struct swap_data_type *s_data;

	s_data = (struct swap_data_type *)data;
	switch(s_data->status_type) {
	case SWAP_GET_TYPE:
		ret = swap_get_swap_type();
		break;
	case SWAP_GET_CANDIDATE_PID:
		ret = swap_get_candidate_pid();
		break;
	case SWAP_GET_STATUS:
		ret = get_swap_status();
		break;
	case SWAP_CHECK_PID:
		if (s_data->args)
			ret = swap_check_swap_pid((int)s_data->args[0]);
		else
			ret = RESOURCED_ERROR_FAIL;
		break;
	case SWAP_CHECK_CGROUP:
		ret = swap_check_swap_cgroup();
		break;
	}
	return ret;
}

static int resourced_swap_init(void *data)
{
	struct modules_arg *marg = (struct modules_arg *)data;
	struct daemon_opts *dopt = marg->opts;

	swap_ops = &swap_modules_ops;

	if (dopt->enable_swap)
		swap_set_swap_type(dopt->enable_swap);

	register_notifier(RESOURCED_NOTIFIER_SWAP_SET_CANDIDATE_PID, swap_set_candidate_pid);
	register_notifier(RESOURCED_NOTIFIER_SWAP_START, swap_start);
	register_notifier(RESOURCED_NOTIFIER_SWAP_RESTART, restart_swap);
	register_notifier(RESOURCED_NOTIFIER_SWAP_MOVE_CGROUP, swap_move_swap_cgroup);

	return swap_init();
}

static int resourced_swap_finalize(void *data)
{
	unregister_notifier(RESOURCED_NOTIFIER_SWAP_SET_CANDIDATE_PID, swap_set_candidate_pid);
	unregister_notifier(RESOURCED_NOTIFIER_SWAP_START, swap_start);
	unregister_notifier(RESOURCED_NOTIFIER_SWAP_RESTART, restart_swap);
	unregister_notifier(RESOURCED_NOTIFIER_SWAP_MOVE_CGROUP, swap_move_swap_cgroup);

	return RESOURCED_ERROR_NONE;
}

int swap_status(enum swap_status_type type, unsigned long *args)
{
	struct swap_data_type s_data;

	if (!swap_ops)
		return RESOURCED_ERROR_NONE;

	s_data.status_type = type;
	s_data.args = args;
	return swap_ops->status(&s_data);
}

static const struct module_ops swap_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "swap",
	.init = resourced_swap_init,
	.exit = resourced_swap_finalize,
	.check_runtime_support = resourced_swap_check_runtime_support,
	.status = resourced_swap_status,
};

MODULE_REGISTER(&swap_modules_ops)
