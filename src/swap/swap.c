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
#include <memory-common.h>

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
#include "file-helper.h"
#include "proc-common.h"

#define MAX_SWAP_VICTIMS		16

#define MEMCG_PATH			"/sys/fs/cgroup/memory"

#define SWAPCG_PATH			MEMCG_PATH"/swap"
#define SWAPCG_LIMIT			SWAPCG_PATH"/memory.limit_in_bytes"
#define MOVE_CHARGE			"/memory.move_charge_at_immigrate"

#define SWAP_ON_EXEC_PATH		"/sbin/swapon"
#define SWAP_OFF_EXEC_PATH		"/sbin/swapoff"
#define SWAP_MKSWAP_EXEC_PATH		"/sbin/mkswap"

#define SWAP_CONF_FILE			"/etc/resourced/swap.conf"
#define SWAP_CONTROL_SECTION		"CONTROL"
#define SWAP_CONF_STREAMS		"MAX_COMP_STREAMS"
#define SWAP_CONF_ALGORITHM		"COMP_ALGORITHM"
#define SWAP_CONF_RATIO			"RATIO"

#define SWAP_BACKEND			"zram"
#define SWAP_ZRAM_NUM_DEVICE		"1"
#define SWAP_ZRAM_DEVICE		"/dev/zram0"
#define SWAP_ZRAM_SYSFILE		"/sys/block/zram0/"
#define SWAP_ZRAM_DISK_SIZE		SWAP_ZRAM_SYSFILE"disksize"
#define SWAP_ZRAM_MAX_COMP_STREAMS	SWAP_ZRAM_SYSFILE"max_comp_streams"
#define SWAP_ZRAM_COMP_ALGORITHM	SWAP_ZRAM_SYSFILE"comp_algorithm"
#define SWAP_HARD_LIMIT			"SWAP_HARD_LIMIT"
#define SWAP_HARD_LIMIT_DEFAULT		0.5


#define MBtoB(x)			(x<<20)
#define MBtoPage(x)			(x<<8)
#define BtoMB(x)			((x) >> 20)
#define BtoPAGE(x)			((x) >> 12)

#define SWAP_TIMER_INTERVAL		0.5
#define SWAP_PRIORITY			20
#define SWAP_SORT_MAX			10
#define SWAP_NUM_TRY			2
#define MAX_PIDS			3
#define SWAP_RATIO			0.5

struct swap_info {
	struct proc_app_info *pai;
	int oom_score_adj;
	int size;
};

struct swap_zram_control {
	int max_comp_streams;
	char comp_algorithm[5];
	float ratio;
};

static struct swap_zram_control swap_control = {
	.max_comp_streams = -1,
	.comp_algorithm = "lzo",
	.ratio = SWAP_RATIO,
};

static float hard_limit_fraction = SWAP_HARD_LIMIT_DEFAULT;
static pthread_mutex_t swap_mutex;
static pthread_cond_t swap_cond;
static Ecore_Timer *swap_timer = NULL;
static struct memcg_info *swap_cg_info;

static const struct module_ops swap_modules_ops;
static const struct module_ops *swap_ops;

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

	if ((state <= SWAP_ARG_START) || (state >= SWAP_ARG_END))
		return;

	modules_data->swap_data.swap_state = state;
}

static unsigned long swap_calculate_hard_limit(unsigned long swap_cg_usage)
{
	return (unsigned long)(swap_cg_usage * hard_limit_fraction);
}

static int swap_get_disksize(void)
{
	int ret, disksize = 0;

	ret = fread_int(SWAP_ZRAM_DISK_SIZE, &disksize);
	if (ret == RESOURCED_ERROR_NONE)
		return disksize;

	return ret;
}

static int swap_move_to_cgroup_by_pid(enum memcg_type type, pid_t pid)
{
	int ret;
	struct memcg *memcg_swap = NULL;
	struct memcg_info *mi;
	struct proc_app_info *pai = find_app_info(pid);
	GSList *iter_child = NULL;

	ret = lowmem_get_memcg(type, &memcg_swap);
	if (ret != RESOURCED_ERROR_NONE)
		return RESOURCED_ERROR_FAIL;

	mi = memcg_swap->info;
	if (!pai)
		return place_pid_to_cgroup_by_fullpath(mi->name, pid);

	ret = place_pid_to_cgroup_by_fullpath(mi->name, pai->main_pid);
	gslist_for_each_item(iter_child, pai->childs) {
		struct child_pid *child;

		child = (struct child_pid *)(iter_child->data);
		ret= place_pid_to_cgroup_by_fullpath(mi->name, child->pid);
	}
	pai->memory.memcg_idx = MEMCG_SWAP;
	pai->memory.memcg_info = mi;
	return ret;
}

static int swap_move_to_cgroup(struct memcg_info *info, GArray *candidates)
{
	int index;
	struct swap_info tsk;
	struct proc_app_info *pai = NULL;
	GSList *iter_child = NULL;

	if (!candidates)
		return RESOURCED_ERROR_NO_DATA;

	for (index = 0; index < candidates->len; index++) {
		tsk = g_array_index(candidates, struct swap_info, index);
		pai = tsk.pai;
		place_pid_to_cgroup_by_fullpath(info->name, pai->main_pid);
		gslist_for_each_item(iter_child, pai->childs) {
			struct child_pid *child;

			child = (struct child_pid *)(iter_child->data);
			place_pid_to_cgroup_by_fullpath(info->name, child->pid);
		}
		pai->memory.memcg_idx = MEMCG_SWAP;
		pai->memory.memcg_info = info;
	}
	return RESOURCED_ERROR_NONE;
}

static int swap_sort_by_oom(const struct swap_info *ta,
    const struct swap_info *tb)
{
	/* sort by oom score adj */
	assert(ta != NULL);
	assert(tb != NULL);

	return ((int)(tb->oom_score_adj) - (int)(ta->oom_score_adj));
}

static int swap_sort_by_vmrss(const struct swap_info *ta,
    const struct swap_info *tb)
{
	/* sort by task memory usage */
	assert(ta != NULL);
	assert(tb != NULL);

	return ((int)(tb->size) - (int)(ta->size));
}

static int swap_prepare_victims(GArray *candidates)
{
	int oom_score_adj = 0;
	GSList *iter = NULL;
	struct proc_app_info *pai = NULL;
	struct swap_info victim;

	/*
	 * serch victims from proc_app_list
	 * It was better than searching backround cgroup
	 * because proc_app_list had already known current state and child processes
	 */
	gslist_for_each_item(iter, proc_app_list) {
		pai = (struct proc_app_info *)iter->data;
		if (pai->memory.memcg_idx != MEMCG_BACKGROUND)
			continue;
		if (proc_get_oom_score_adj(pai->main_pid, &oom_score_adj) < 0)
			continue;
		if (pai->lru_state <= PROC_BACKGROUND)
			continue;

		memset(&victim, 0, sizeof(struct swap_info));
		victim.oom_score_adj = oom_score_adj;
		victim.pai = pai;
		g_array_append_val(candidates, victim);
	}
	return candidates->len;
}

static int swap_reduce_victims(GArray *candidates, int max)
{
	int index;
	struct swap_info tsk;
	struct proc_app_info *pai = NULL;
	unsigned int vmrss = 0;

	if (!candidates)
		return RESOURCED_ERROR_NO_DATA;

	for (index = 0; index < candidates->len; index++) {
		tsk = g_array_index(candidates, struct swap_info, index);
		pai = tsk.pai;

		/* Measuring VmRSS is OK as it's anonymous + swapcache */
		if (proc_get_mem_usage(pai->main_pid, NULL, &vmrss) < 0)
			continue;

		tsk.size += vmrss;

		if (pai->childs) {
			GSList *iter_child = NULL;

			gslist_for_each_item(iter_child, pai->childs) {
				struct child_pid *child;

				child = (struct child_pid *)(iter_child->data);
				if (proc_get_mem_usage(child->pid, NULL, &vmrss) < 0)
					continue;
				tsk.size += vmrss;
			}
		}
	}
	/* sort by oom_score_adj value, older are better candidates */
	g_array_sort(candidates, (GCompareFunc)swap_sort_by_oom);

	/* sort by memory usage, swapping bigger will free more memory */
	g_array_sort(candidates, (GCompareFunc)swap_sort_by_vmrss);

	/* limit the number of potential candidates, after sort by oom */
	g_array_remove_range(candidates, max,
			candidates->len - max);
	return RESOURCED_ERROR_NONE;
}

static int swap_thread_do(void)
{
	int ret;
	unsigned int usage, swap_cg_limit;
	
	ret = memcg_get_usage(swap_cg_info, &usage);
	if (ret != RESOURCED_ERROR_NONE)
		usage = 0;
	swap_cg_limit = swap_calculate_hard_limit(usage);
	_D("swap cgroup usage is %lu, hard limit set to %lu (hard limit fraction %f)",
			usage, swap_cg_limit, hard_limit_fraction);
	ret = cgroup_write_node(swap_cg_info->name, SWAPCG_LIMIT,
		swap_cg_limit);

	return ret;
}

static int swap_prepare_cgroup(struct swap_status *ss)
{
	int max_victims, selected;
	int ret = RESOURCED_ERROR_NONE;
	GArray *candidates = NULL, *pids_array = NULL;
	struct memcg *memcg_swap = NULL;

	_D("swap prepare : %s", ss->info->name);
	/*
	 * Other cgroup like platform and favorite checks procs and swaps directly
	 */
	pids_array = g_array_new(false, false, sizeof(pid_t));
	if (!pids_array) {
		_E("failed to allocate memory");
		ret = RESOURCED_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Get procs to check for swap candidates */
	memcg_get_pids(ss->info, pids_array);
	if (pids_array->len == 0) {
		ret = RESOURCED_ERROR_NO_DATA;
		goto out;
	}
	if (ss->type == MEMCG_BACKGROUND) {
		/*
		 * background cgroup finds victims and moves them to swap group
		 */
		ret = lowmem_get_memcg(MEMCG_SWAP, &memcg_swap);
		if (ret != RESOURCED_ERROR_NONE)
			return RESOURCED_ERROR_FAIL;

		candidates = g_array_new(false, false, sizeof(struct swap_info));
		if (!candidates) {
			_E("failed to allocate memory");
			ret = RESOURCED_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		/*
		 * Let's consider 50% of background apps to be swappable. Using ZRAM
		 * swap makes the operation on swap cheaper. Only anonymous memory
		 * is swaped so the results are limited by size of allocations.
		 */
		max_victims = pids_array->len >> 1;
		/* It makes no sense if we will have no candidates */
		if (max_victims == 0) {
			ret = RESOURCED_ERROR_NO_DATA;
			goto out;
		}
		if (max_victims > SWAP_SORT_MAX)
			max_victims = SWAP_SORT_MAX;

		selected = swap_prepare_victims(candidates);
		if (selected == 0)  {
			ret = RESOURCED_ERROR_NO_DATA;
			goto out;
		} else if (selected > max_victims)
			swap_reduce_victims(candidates, max_victims);

		/*
		 * change swap info from background cgroup to swap group
		 * for using same structure to move and swap it
		 */
		ss->info = memcg_swap->info;
	}
	swap_move_to_cgroup(ss->info, candidates);
out:
	if (candidates)
		g_array_free(candidates, TRUE);
	if (pids_array)
		g_array_free(pids_array, TRUE);
	return ret;
}

static int swap_size(void)
{
	int size; /* size in bytes */
	unsigned long ktotalram = lowmem_get_ktotalram(); /* size in kilobytes */

	if (ktotalram >= 900000) /* >= 878 MB */
		size = 268435456; /* 256 MB */
	else if (ktotalram < 200000) /* < 195 MB */
		size = 16777216; /* 16 MB */
	else
		size = ktotalram * swap_control.ratio * 1024;

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
			SWAP_ZRAM_DEVICE, (char *)NULL);
		exit(0);
	} else {
		wait(0);
		_D("mkswap ends");
	}

	return pid;
}

static int swap_zram_activate(void)
{
	int ret, size;

	ret = fwrite_int(SWAP_ZRAM_MAX_COMP_STREAMS, swap_control.max_comp_streams);
	if (ret < 0) {
		_E("fail to write max_comp_streams");
		return ret;
	}

	ret = fwrite_str(SWAP_ZRAM_COMP_ALGORITHM, swap_control.comp_algorithm);
	if (ret < 0) {
		_E("fail to write comp_algrithm");
		return ret;
	}

	size = swap_size();
	ret = fwrite_int(SWAP_ZRAM_DISK_SIZE, size);
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

static pid_t swap_change_state(int type)
{
	int status;
	pid_t ret_pid;
	pid_t pid = fork();
	char buf[256];

	if (pid < 0) {
		_E("failed to fork");
		return RESOURCED_ERROR_FAIL;
	} else if (pid == 0) {
		if (type == SWAP_ON)
			execl(SWAP_ON_EXEC_PATH, SWAP_ON_EXEC_PATH, "-d",
			    SWAP_ZRAM_DEVICE, (char *)NULL);
		else if (type == SWAP_OFF)
			execl(SWAP_OFF_EXEC_PATH, SWAP_OFF_EXEC_PATH,
			    SWAP_ZRAM_DEVICE, (char *)NULL);
		exit(0);
	} else {
		ret_pid = waitpid(pid, &status, 0);
		if (ret_pid < 0) {
			_E("can't wait for a pid %d %d %s", pid, status, strerror_r(errno, buf, sizeof(buf)));
			return ret_pid;
		}
	}
	swap_set_state(type);
	return pid;
}

static void *swap_thread_main(void * data)
{
	int ret;

	setpriority(PRIO_PROCESS, 0, SWAP_PRIORITY);

	while (1) {
		pthread_mutex_lock(&swap_mutex);
		pthread_cond_wait(&swap_cond, &swap_mutex);

		if (swap_get_state() != SWAP_ON) {
			int disksize = swap_get_disksize();
			if (disksize <= 0) {
				ret = swap_zram_activate();
				if (ret < 0) {
					_E("swap cannot be activated");
					pthread_mutex_unlock(&swap_mutex);
					return NULL;
				}
			}
			swap_change_state(SWAP_ON);
		}
		/* When signaled by swap_mutex start swap_thread_do() */
		swap_thread_do();
		pthread_mutex_unlock(&swap_mutex);
	}

	return NULL;
}

static Eina_Bool swap_send_signal(void *data)
{
	int ret;
	struct swap_status *ss = (struct swap_status *)data;

	/* signal to swap_start to start swap */
	ret = pthread_mutex_trylock(&swap_mutex);
	if (ret)
		_E("pthread_mutex_trylock fail : %d, errno : %d", ret, errno);
	else {
		ret = swap_prepare_cgroup(ss);
		if (ret) {
			pthread_mutex_unlock(&swap_mutex);
			goto out;
		}
		swap_cg_info = ss->info;
		pthread_cond_signal(&swap_cond);
		_I("send signal to swap thread");
		pthread_mutex_unlock(&swap_mutex);
	}
out:
	ecore_timer_del(swap_timer);
	swap_timer = NULL;
	free(ss);

	return ECORE_CALLBACK_CANCEL;
}

static int swap_start(void *data)
{
	struct swap_status *ss = malloc(sizeof(struct swap_status));
	if (!ss)
		return RESOURCED_ERROR_OUT_OF_MEMORY;

	memcpy(ss, data, sizeof(struct swap_status));
	if (swap_timer == NULL) {
		_D("swap timer start");
		swap_timer =
			ecore_timer_add(SWAP_TIMER_INTERVAL, swap_send_signal, (void *)ss);
	} else {
		_D("not finished previous swap");
		free(ss);
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
	swap_move_to_cgroup_by_pid(MEMCG_SWAP, pid);
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

	if (swap_get_state() != type)
		swap_change_state(type);
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

static const struct edbus_signal edbus_signals[] = {
	/* RESOURCED DBUS */
	{RESOURCED_PATH_SWAP, RESOURCED_INTERFACE_SWAP,
	    SIGNAL_NAME_SWAP_TYPE, swap_type_edbus_signal_handler, NULL},
	{RESOURCED_PATH_SWAP, RESOURCED_INTERFACE_SWAP,
	    SIGNAL_NAME_SWAP_START_PID, swap_start_pid_edbus_signal_handler, NULL},
};

static void swap_dbus_init(void)
{
	resourced_ret_c ret;

	edbus_add_signals(edbus_signals, ARRAY_SIZE(edbus_signals));

	ret = edbus_add_methods(RESOURCED_PATH_SWAP, edbus_methods,
			  ARRAY_SIZE(edbus_methods));

	ret_msg_if(ret != RESOURCED_ERROR_NONE,
		"DBus method registration for %s is failed",
			RESOURCED_PATH_SWAP);
}

static int load_swap_config(struct parse_result *result, void *user_data)
{
	int limit_value;

	if (!result)
		return -EINVAL;

	if (strcmp(result->section, SWAP_CONTROL_SECTION))
		return RESOURCED_ERROR_NO_DATA;

	if (!strcmp(result->name, SWAP_CONF_STREAMS)) {
		int value = atoi(result->value);
		if (value > 0) {
			swap_control.max_comp_streams = value;
			_D("max_comp_streams of swap_control is %d",
				swap_control.max_comp_streams);
		}
	} else if (!strcmp(result->name, SWAP_CONF_ALGORITHM)) {
		if (!strcmp(result->value, "lzo") ||
		    !strcmp(result->value, "lz4")) {
			strncpy(swap_control.comp_algorithm, result->value,
				strlen(result->value) + 1);
			_D("comp_algorithm of swap_control is %s",
				result->value);
		}
	} else if (!strcmp(result->name, SWAP_CONF_RATIO)) {
		float ratio = atof(result->value);
		swap_control.ratio = ratio;
		_D("swap disk size ratio is %.2f", swap_control.ratio);
	} else if (!strncmp(result->name, SWAP_HARD_LIMIT, strlen(SWAP_HARD_LIMIT))) {
		limit_value = (int)strtoul(result->value, NULL, 0);
		if (limit_value < 0 || limit_value > 100) {
			_E("Invalid %s value in %s file, setting %f as default percent value",
					SWAP_HARD_LIMIT, SWAP_CONF_FILE,
					SWAP_HARD_LIMIT_DEFAULT);
			return RESOURCED_ERROR_NONE;
		}
		hard_limit_fraction = (float)limit_value/100;
		_D("hard limit fraction for swap module is %f", hard_limit_fraction);
	}

	if (swap_control.max_comp_streams < 0) {
		int cpu = proc_get_cpu_number();
		if (cpu > 0) {
			if (cpu > 4)
				/*
				 * On big.LITLLE we can have 8 cores visible
				 * but there can be used 4. Let's limit it to 4
				 * if there is no specified value in .conf file.
				 */
				cpu = 4;
			swap_control.max_comp_streams = cpu;
		} else
			swap_control.max_comp_streams = 1;
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

	fp = fopen(SWAP_ZRAM_DEVICE, "w");
	if (fp == NULL) {
		_E("%s open failed", SWAP_ZRAM_DEVICE);
		return RESOURCED_ERROR_NO_DATA;
	}
	fclose(fp);

	return RESOURCED_ERROR_NONE;
}

static int resourced_swap_check_runtime_support(void *data)
{
	return swap_check_node();
}

/*
 * Quote from: kernel Documentation/cgroups/memory.txt
 *
 * Each bit in move_charge_at_immigrate has its own meaning about what type of
 * charges should be moved. But in any case, it must be noted that an account of
 * a page or a swap can be moved only when it is charged to the task's current
 * (old) memory cgroup.
 *
 *  bit | what type of charges would be moved ?
 * -----+------------------------------------------------------------------------
 *   0  | A charge of an anonymous page (or swap of it) used by the target task.
 *      | You must enable Swap Extension (see 2.4) to enable move of swap charges.
 * -----+------------------------------------------------------------------------
 *   1  | A charge of file pages (normal file, tmpfs file (e.g. ipc shared memory)
 *      | and swaps of tmpfs file) mmapped by the target task. Unlike the case of
 *      | anonymous pages, file pages (and swaps) in the range mmapped by the task
 *      | will be moved even if the task hasn't done page fault, i.e. they might
 *      | not be the task's "RSS", but other task's "RSS" that maps the same file.
 *      | And mapcount of the page is ignored (the page can be moved even if
 *      | page_mapcount(page) > 1). You must enable Swap Extension (see 2.4) to
 *      | enable move of swap charges.
 * quote end.
 *
 * In our case it's better to set only the bit number 0 to charge only
 * anon pages. Therefore file pages etc. will be managed directly by
 * kernel reclaim mechanisms.
 * That will help focus us only on swapping the memory that we actually
 * can swap - anonymous pages.
 * This will prevent from flushing file pages from memory - causing
 * slowdown when re-launching applications.
 */
static void resourced_swap_change_conf(int type)
{
	struct memcg *memcg_swap = NULL;
	int ret;

	ret = lowmem_get_memcg(type, &memcg_swap);
	if (ret != RESOURCED_ERROR_NONE)
		return;

	cgroup_write_node(memcg_swap->info->name, MOVE_CHARGE, 1);
}

/* This function is callback function for the notifier RESOURCED_NOTIFIER_SWAP_UNSET_LIMIT.
 * This notifier is notified from normal_act function of vmpressure module whenever the
 * memory state changes to normal.
 * This function resets the hard limit of the swap subcgroup to -1 (unlimited) */
static int swap_cgroup_reset_limit(void *data)
{
	int size;
	int limit;
	char buf[100];
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
	resourced_swap_change_conf(MEMCG_SWAP);
	resourced_swap_change_conf(MEMCG_FAVORITE);
	resourced_swap_change_conf(MEMCG_PLATFORM);

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
