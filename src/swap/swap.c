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

#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "edbus-handler.h"
#include "swap-common.h"
#include "config-parser.h"
#include "lowmem-handler.h"
#include "notifier.h"
#include "procfs.h"
#include "cgroup.h"
#include "const.h"

#define MAX_SWAP_VICTIMS		16

#define MEMCG_PATH			"/sys/fs/cgroup/memory"
#define MEMCG_RECLAIM			MEMCG_PATH"/memory.force_reclaim"

#define BACKCG_PATH			MEMCG_PATH"/background"
#define BACKCG_PROCS			BACKCG_PATH"/cgroup.procs"
#define SWAPCG_PATH			MEMCG_PATH"/swap"
#define SWAPCG_PROCS			SWAPCG_PATH"/cgroup.procs"
#define SWAPCG_USAGE			SWAPCG_PATH"/memory.usage_in_bytes"
#define MOVE_CHARGE			"/memory.move_charge_at_immigrate"
#define SWAPCG_LIMIT			SWAPCG_PATH"/memory.limit_in_bytes"

#define SWAP_ON_EXEC_PATH		"/sbin/swapon"
#define SWAP_OFF_EXEC_PATH		"/sbin/swapoff"
#define SWAP_MKSWAP_EXEC_PATH		"/sbin/mkswap"
#define SWAP_MODPROBE_EXEC_PATH		"/sbin/modprobe"
#define SWAP_CONF_FILE			"/etc/resourced/swap.conf"
#define SWAP_CONTROL_SECTION		"CONTROL"
#define SWAP_CONF_STREAMS		"MAX_COMP_STREAMS"
#define SWAP_CONF_ALGORITHM		"COMP_ALGORITHM"

#define SIGNAL_NAME_SWAP_TYPE		"SwapType"
#define SIGNAL_NAME_SWAP_START_PID	"SwapStartPid"

#define SWAP_BACKEND			"zram"
#define SWAP_NUM_DEVICE			"1"
#define SWAPFILE_NAME			"/dev/zram0"
#define SWAP_SYSFILE_NAME		"/sys/block/zram0/"
#define SWAP_DISK_SIZE			SWAP_SYSFILE_NAME"disksize"
#define SWAP_MAX_COMP_STREAMS		SWAP_SYSFILE_NAME"max_comp_streams"
#define SWAP_COMP_ALGORITHM		SWAP_SYSFILE_NAME"comp_algorithm"
#define SWAP_HARD_LIMIT			"SWAP_HARD_LIMIT"
#define SWAP_HARD_LIMIT_DEFAULT		0.5

#define SWAP_PATH_MAX			100
#define SWAP_BUF_MAX			512

#define MBtoB(x)			(x<<20)
#define MBtoPage(x)			(x<<8)
#define BtoMB(x)			((x) >> 20)
#define BtoPAGE(x)			((x) >> 12)

#define SWAP_TIMER_INTERVAL		0.5
#define SWAP_PRIORITY			20
#define SWAP_SORT_MAX			10
#define MAX_PIDS			3
#define SWAP_RATE			20

struct task_info {
	pid_t pids[MAX_PIDS];
	pid_t pgid;
	int oom_score_adj;
	int size;
	int num_pid;
};

struct swap_zram_control {
	int max_comp_streams;
	char comp_algorithm[5];
};

static struct swap_zram_control swap_control = {
	.max_comp_streams = -1,
	.comp_algorithm = "lzo",
};

static float hard_limit_fraction = SWAP_HARD_LIMIT_DEFAULT;
static pthread_mutex_t swap_mutex;
static pthread_cond_t swap_cond;
static Ecore_Timer *swap_timer = NULL;

static const struct module_ops swap_modules_ops;
static const struct module_ops *swap_ops;

int swap_check_swap_pid(pid_t pid)
{
	char buf[SWAP_PATH_MAX] = {0,};
	int ret = 0;
	pid_t swappid;
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

static int swap_get_state(void)
{
	struct shared_modules_data *modules_data = get_shared_modules_data();

	ret_value_msg_if(modules_data == NULL, RESOURCED_ERROR_FAIL,
			 "Invalid shared modules data\n");
	return modules_data->swap_data.swap_state;
}

static void swap_set_state(int state)
{
	struct shared_modules_data *modules_data = get_shared_modules_data();

	ret_msg_if(modules_data == NULL,
			 "Invalid shared modules data\n");

	if (state <= SWAP_ARG_START || state >= SWAP_ARG_END)
		return;

	modules_data->swap_data.swap_state = state;
}

static unsigned long swap_calculate_hard_limit(unsigned long swap_cg_usage)
{
	return (unsigned long)(swap_cg_usage * hard_limit_fraction);
}

static int swap_get_disksize(void)
{
	FILE *fp;
	int disksize = 0;
	char buf[MAX_DEC_SIZE(int) + 1];

	fp = fopen(SWAP_DISK_SIZE, "r");

	if (!fp) {
		_E("cannot open %s", SWAP_DISK_SIZE);
		return RESOURCED_ERROR_FAIL;
	}

	if (fgets(buf, MAX_DEC_SIZE(int), fp) != NULL)
		disksize = atoi(buf);

	fclose(fp);

	if (disksize > 0)
		return disksize;

	return RESOURCED_ERROR_FAIL;
}

static int load_swap_config(struct parse_result *result, void *user_data)
{
	int limit_value;
	int value;

	if (!result) {
		_E("Invalid parameter: result is NULL");
		return -EINVAL;
	}

	if (!strncmp(result->section, SWAP_CONTROL_SECTION, strlen(SWAP_CONTROL_SECTION))) {
		if (!strncmp(result->name, SWAP_HARD_LIMIT, strlen(SWAP_HARD_LIMIT))) {
			limit_value = (int)strtoul(result->value, NULL, 0);
			if (limit_value < 0 || limit_value > 100) {
				_E("Invalid %s value in %s file, setting %f as default percent value",
						SWAP_HARD_LIMIT, SWAP_CONF_FILE,
						SWAP_HARD_LIMIT_DEFAULT);
				return RESOURCED_ERROR_NONE;
			}

			hard_limit_fraction = (float)limit_value/100;
			_D("hard limit fraction for swap module is %f", hard_limit_fraction);
		} else if (!strncmp(result->name, SWAP_CONF_STREAMS, strlen(SWAP_CONF_STREAMS))) {
			value = atoi(result->value);
			if (value > 0) {
				swap_control.max_comp_streams = value;
				_D("max_comp_streams of swap_control is %d",
						swap_control.max_comp_streams);
			}
		} else if (!strncmp(result->name, SWAP_CONF_ALGORITHM, strlen(SWAP_CONF_ALGORITHM))) {
			if (!strncmp(result->value, "lzo", strlen("lzo")) ||
					!strncmp(result->value, "lz4", strlen("lz4"))) {
				strncpy(swap_control.comp_algorithm, result->value,
						strlen(result->value) + 1);
				_D("comp_algorithm of swap_control is %s",
						result->value);
			}
		}

		if (swap_control.max_comp_streams < 0) {
			int cpu = proc_get_cpu_number();

			if (cpu > 0)
				swap_control.max_comp_streams = cpu;
			else
				swap_control.max_comp_streams = 1;
		}
	}
	return RESOURCED_ERROR_NONE;
}

static int swap_write_value(const char *path, int value)
{
	char buf[SWAP_PATH_MAX] = {0,};
	FILE *f;
	int size;

	f = fopen(path, "w");
	if (!f) {
		_E("Fail to %s file open", path);
		return RESOURCED_ERROR_FAIL;
	}
	size = snprintf(buf, sizeof(buf), "%d", value);
	if (fwrite(buf, size, 1, f) != 1)
		_E("fwrite to node failed : value = %d\n", value);
	fclose(f);

	_D("value = %d is written to node %s", value, path);

	return RESOURCED_ERROR_NONE;
}

static int swap_write_string(const char *path, const char *str)
{
	char buf[SWAP_PATH_MAX] = {0,};
	FILE *f;
	int size;

	f = fopen(path, "w");
	if (!f) {
		_E("Fail to %s file open", path);
		return RESOURCED_ERROR_FAIL;
	}
	size = snprintf(buf, sizeof(buf), "%s", str);
	if (fwrite(buf, size, 1, f) != 1)
		_E("fwrite to node failed : value = %s\n", str);
	fclose(f);

	_D("string = %s is written to node %s", str, path);
	return RESOURCED_ERROR_NONE;
}

static int swap_move_to_swap_cgroup(pid_t pid)
{
	return swap_write_value(SWAPCG_PROCS, pid);
}

/*
 * move the first process to swap cgroup.
 * if it has processes with the same pgid,
 * move them to swap group together.
 */
static void swap_victims(GArray *victim_candidates)
{
	struct task_info tsk;
	int i;

	tsk = g_array_index(victim_candidates, struct task_info, 0);
	for (i = 0; i < tsk.num_pid; i++)
		swap_move_to_swap_cgroup(tsk.pids[i]);
}

static int swap_sort_oom(const struct task_info *ta, const struct task_info *tb)
{
	/* sort by oom score adj */
	assert(ta != NULL);
	assert(tb != NULL);

	return ((int)(tb->oom_score_adj) - (int)(ta->oom_score_adj));
}

static int swap_sort_usage(const struct task_info *ta, const struct task_info *tb)
{
	/*
	* sort by task size
	*/
	assert(ta != NULL);
	assert(tb != NULL);

	return ((int)(tb->size) - (int)(ta->size));
}

static inline int swap_candidates(int oom)
{
	/* only consider background inactive process */
	if (oom > OOMADJ_BACKGRD_UNLOCKED)
		return RESOURCED_ERROR_NONE;

	return RESOURCED_ERROR_FAIL;
}

static int swap_candidates_select(GArray *candidates)
{
	int max_idx;

	/*
	 * consider 25% of background apps as swap candidates.
	 * this starts swap only when there is more than 4 background apps.
	 * With larger ram like 1GB or 2GB, there will be more backgrounds.
	 * In this case, we swap a process with largest memory usage among
	 * 25% of background oldest.
	 */
	max_idx = candidates->len >> 2;

	if (max_idx == 0)
		return RESOURCED_ERROR_FAIL;

	if (max_idx > SWAP_SORT_MAX)
		max_idx = SWAP_SORT_MAX;

	g_array_remove_range(candidates, max_idx, candidates->len - max_idx);

	return RESOURCED_ERROR_NONE;
}

static int swap_check_cgroup_victims(void)
{
	FILE *f = NULL;
	int i, ret;
	char buf[SWAP_PATH_MAX] = {0, };
	GArray *victim_candidates = NULL;

	victim_candidates = g_array_new(false, false, sizeof(struct task_info));

	/* if g_array_new fails, return the current number of victims */
	if (victim_candidates == NULL) {
		_E("victim_candidates failed");
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	if (f == NULL) {
		f = fopen(BACKCG_PROCS, "r");
		if (f == NULL) {
			_E("%s open failed", BACKCG_PROCS);
			return RESOURCED_ERROR_FAIL;
		}
	}

	while (fgets(buf, 32, f) != NULL) {
		struct task_info new_victim;
		pid_t tpid = 0;
		int toom = 0;
		unsigned int tsize = 0;

		tpid = atoi(buf);

		if (proc_get_oom_score_adj(tpid, &toom) < 0) {
			_D("pid(%d) was already terminated", tpid);
			continue;
		}

		if (swap_candidates(toom) < 0)
			continue;

		if (proc_get_mem_usage(tpid, NULL, &tsize) < 0) {
			_D("pid(%d) size is not available\n", tpid);
			continue;
		}

		for (i = 0; i < victim_candidates->len; i++) {
			struct task_info *tsk = &g_array_index(victim_candidates,
							struct task_info, i);
			if (getpgid(tpid) == tsk->pgid) {
				/*
				 * Since we swap based on memory usage,
				 * use sum of memory usage.
				 */
				tsk->size += tsize;
				if (tsk->num_pid < MAX_PIDS)
					tsk->pids[tsk->num_pid++] = tpid;

				break;
			}
		}

		if (i == victim_candidates->len) {
			new_victim.num_pid = 0;
			new_victim.pids[new_victim.num_pid++] = tpid;
			new_victim.pgid = getpgid(tpid);
			new_victim.oom_score_adj = toom;
			new_victim.size = tsize;
			g_array_append_val(victim_candidates, new_victim);
		}
	}

	fclose(f);

	if (victim_candidates->len == 0) {
		_E("victim_candidates->len = %d", victim_candidates->len);
		g_array_free(victim_candidates, true);
		return RESOURCED_ERROR_NO_DATA;
	}

	/* sort by oom score adj */
	g_array_sort(victim_candidates, (GCompareFunc)swap_sort_oom);

	ret = swap_candidates_select(victim_candidates);
	if (ret < 0) {
		_E("no candidates for swap");
		g_array_free(victim_candidates, true);
		return RESOURCED_ERROR_FAIL;
	}

	/* sort by mem usage */
	g_array_sort(victim_candidates, (GCompareFunc)swap_sort_usage);

	swap_victims(victim_candidates);

	g_array_free(victim_candidates, true);


	return RESOURCED_ERROR_NONE;
}

static int swap_thread_do(FILE *procs, FILE *usage_in_bytes, FILE *limit_in_bytes)
{
	char buf[SWAP_PATH_MAX] = {0,};
	int size;
	int ret;
	unsigned long usage;
	unsigned long swap_cg_limit;

	ret = swap_check_cgroup_victims();

	if (ret < 0)
		_D("cannot swap candidates but swap the existing processes");

	/* cacluate reclaim size by usage and swap cgroup count */
	if (fgets(buf, 32, usage_in_bytes) == NULL)
		return RESOURCED_ERROR_FAIL;

	usage = (unsigned long)atol(buf);

	swap_cg_limit = swap_calculate_hard_limit(usage);
	_D("swap cgroup usage is %lu, hard limit set to %lu (hard limit fraction %f)",
			usage, swap_cg_limit, hard_limit_fraction);

	/* set reclaim size */
	size = snprintf(buf, sizeof(buf), "%lu", swap_cg_limit);
	if (fwrite(buf, 1, size, limit_in_bytes) != size)
		_E("fwrite %s\n", buf);

	return RESOURCED_ERROR_NONE;
}

static int swap_size(void)
{
	int size;
	unsigned long ktotalram = lowmem_get_ktotalram();

	if (ktotalram >= 900000)
		size = 134217728;
	else if (ktotalram < 200000)
		size = 8388608;
	else
		size = ktotalram * SWAP_RATE / 100 * 1024;

	_D("swapfile size = %d", size);
	return size;
}

static int swap_mkswap(void)
{
	pid_t pid = fork();

	if (pid < 0) {
		_E("fork for mkswap failed");
		return pid;
	} else if (pid == 0) {
		_D("mkswap starts");
		execl(SWAP_MKSWAP_EXEC_PATH, SWAP_MKSWAP_EXEC_PATH,
			SWAPFILE_NAME, (char *)NULL);
		exit(0);
	} else {
		wait(0);
		_D("mkswap ends");
	}

	return pid;
}

static pid_t swap_on(void)
{
	pid_t pid = fork();

	if (pid == 0) {
		execl(SWAP_ON_EXEC_PATH, SWAP_ON_EXEC_PATH, "-d", SWAPFILE_NAME, (char *)NULL);
		exit(0);
	}
	swap_set_state(SWAP_ON);
	return pid;
}

static pid_t swap_off(void)
{
	pid_t pid = fork();

	if (pid == 0) {
		execl(SWAP_OFF_EXEC_PATH, SWAP_OFF_EXEC_PATH, SWAPFILE_NAME, (char *)NULL);
		exit(0);
	}
	swap_set_state(SWAP_OFF);
	return pid;
}


static int swap_activate(void)
{
	int ret, size;

	ret = swap_write_value(SWAP_MAX_COMP_STREAMS, swap_control.max_comp_streams);
	if (ret < 0) {
		_E("fail to write max_comp_streams");
		return ret;
	}

	ret = swap_write_string(SWAP_COMP_ALGORITHM, swap_control.comp_algorithm);
	if (ret < 0) {
		_E("fail to write comp_algrithm");
		return ret;
	}

	size = swap_size();
	ret = swap_write_value(SWAP_DISK_SIZE, size);
	if (ret < 0) {
		_E("fail to write disk_size");
		return ret;
	}

	ret = swap_mkswap();
	if (ret < 0) {
		_E("swap mkswap failed, fork error = %d", ret);
		return ret;
	}

	return RESOURCED_ERROR_NONE;
}

static void *swap_thread_main(void * data)
{
	int ret;
	FILE *procs;
	FILE *usage_in_bytes;
	FILE *limit_in_bytes;

	setpriority(PRIO_PROCESS, 0, SWAP_PRIORITY);

	procs = fopen(SWAPCG_PROCS, "r");
	if (procs == NULL) {
		_E("%s open failed", SWAPCG_PROCS);
		return NULL;
	}

	usage_in_bytes = fopen(SWAPCG_USAGE, "r");
	if (usage_in_bytes == NULL) {
		_E("%s open failed", SWAPCG_USAGE);
		fclose(procs);
		return NULL;
	}

	limit_in_bytes = fopen(SWAPCG_LIMIT, "w");
	if (limit_in_bytes == NULL) {
		_E("%s open failed", SWAPCG_LIMIT);
		fclose(procs);
		fclose(usage_in_bytes);
		return NULL;
	}

	while (1) {
		pthread_mutex_lock(&swap_mutex);
		pthread_cond_wait(&swap_cond, &swap_mutex);

		if (swap_get_state() != SWAP_ON) {
			int disksize = swap_get_disksize();
			if (disksize < 0) {
				ret = swap_activate();
				if (ret < 0) {
					_E("swap cannot be activated");
					fclose(procs);
					fclose(usage_in_bytes);
					fclose(limit_in_bytes);
					pthread_mutex_unlock(&swap_mutex);
					return NULL;
				}
			}
			swap_on();
		}

		/*
		 * when signalled by main thread, it starts
		 * swap_thread_do().
		 */
		_I("swap thread conditional signal received");

		fseek(procs, 0, SEEK_SET);
		fseek(usage_in_bytes, 0, SEEK_SET);
		fseek(limit_in_bytes, 0, SEEK_SET);

		_D("swap_thread_do start");
		swap_thread_do(procs, usage_in_bytes, limit_in_bytes);
		_D("swap_thread_do end");
		pthread_mutex_unlock(&swap_mutex);
	}

	if (procs)
		fclose(procs);
	if (usage_in_bytes)
		fclose(usage_in_bytes);
	if (limit_in_bytes)
		fclose(limit_in_bytes);

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
	int ret = 0;
	pthread_t pth;

	pthread_mutex_init(&swap_mutex, NULL);
	pthread_cond_init(&swap_cond, NULL);

	ret = pthread_create(&pth, NULL, &swap_thread_main, (void *)NULL);
	if (ret) {
		_E("pthread creation for swap_thread failed\n");
		return ret;
	} else {
		pthread_detach(pth);
	}

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
	swap_move_to_swap_cgroup(pid);

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
		if (swap_get_state() != SWAP_OFF) {
			swap_off();
			swap_set_state(type);
		}
		break;
	case 1:
		if (swap_get_state() != SWAP_ON) {
			swap_on();
			swap_set_state(type);
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

	state = swap_get_state();

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
		    (void *)swap_type_edbus_signal_handler, NULL);
	register_edbus_signal_handler(RESOURCED_PATH_SWAP, RESOURCED_INTERFACE_SWAP,
			SIGNAL_NAME_SWAP_START_PID,
		    (void *)swap_start_pid_edbus_signal_handler, NULL);

	ret = edbus_add_methods(RESOURCED_PATH_SWAP, edbus_methods,
			  ARRAY_SIZE(edbus_methods));

	ret_msg_if(ret != RESOURCED_ERROR_NONE,
		"DBus method registration for %s is failed",
			RESOURCED_PATH_SWAP);
}

static int swap_init(void)
{
	int ret;

	config_parse(SWAP_CONF_FILE, load_swap_config, NULL);

	ret = swap_thread_create();
	if (ret) {
		_E("swap thread create failed");
		return ret;
	}

	swap_dbus_init();

	return ret;
}

static int swap_check_node(void)
{
	FILE *fp;

	fp = fopen(SWAPFILE_NAME, "w");
	if (fp == NULL) {
		_E("%s open failed", SWAPFILE_NAME);
		return RESOURCED_ERROR_NO_DATA;
	}
	fclose(fp);

	return RESOURCED_ERROR_NONE;
}

static int resourced_swap_check_runtime_support(void *data)
{
	return swap_check_node();
}

/* This function is callback function for the notifier RESOURCED_NOTIFIER_SWAP_UNSET_LIMIT.
 * This notifier is notified from normal_act function of vmpressure module whenever the
 * memory state changes to normal.
 * This function resets the hard limit of the swap subcgroup to -1 (unlimited) */
static int swap_cgroup_reset_limit(void *data)
{
	int size;
	int limit;
	char buf[SWAP_PATH_MAX];
	FILE *fp;

	fp = fopen(SWAPCG_LIMIT, "w");
	if (!fp) {
		_E("%s open failed", SWAPCG_LIMIT);
		return RESOURCED_ERROR_FAIL;
	}

	limit = -1;
	size = snprintf(buf, sizeof(buf), "%d", limit);
	if (fwrite(buf, size, 1, fp) != 1) {
		_E("fwrite to %s failed", SWAPCG_LIMIT);
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	fclose(fp);
	_D("changed hard limit of swap cgroup to -1");
	return RESOURCED_ERROR_NONE;
}

static int resourced_swap_init(void *data)
{
	swap_ops = &swap_modules_ops;

	make_cgroup_subdir(MEMCG_PATH, "swap", NULL);
	cgroup_write_node(SWAPCG_PATH, MOVE_CHARGE, 3);

	/*
	 * Swap will be activated when certain SwapTreshold will be exceed
	 */
	swap_set_state(SWAP_OFF);
	register_notifier(RESOURCED_NOTIFIER_SWAP_START, swap_start);
	register_notifier(RESOURCED_NOTIFIER_SWAP_UNSET_LIMIT, swap_cgroup_reset_limit);

	return swap_init();
}

static int resourced_swap_finalize(void *data)
{
	unregister_notifier(RESOURCED_NOTIFIER_SWAP_START, swap_start);
	unregister_notifier(RESOURCED_NOTIFIER_SWAP_UNSET_LIMIT, swap_cgroup_reset_limit);
	return RESOURCED_ERROR_NONE;
}

static const struct module_ops swap_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "swap",
	.init = resourced_swap_init,
	.exit = resourced_swap_finalize,
	.check_runtime_support = resourced_swap_check_runtime_support,
};

MODULE_REGISTER(&swap_modules_ops)
