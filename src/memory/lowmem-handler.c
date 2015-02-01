/*
 * resourced
 *
 * Copyright (c) 2012 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file lowmem_handler.c
 *
 * @desc lowmem handler using memcgroup
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <limits.h>
#include <vconf.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/eventfd.h>
#include <Ecore.h>

#include "trace.h"
#include "cgroup.h"
#include "proc-main.h"
#include "lowmem-handler.h"
#include "proc-process.h"
#include "swap-common.h"
#include "lowmem-common.h"
#include "resourced.h"
#include "macro.h"
#include "module.h"
#include "notifier.h"

enum {
	MEMGC_OOM_NORMAL,
	MEMGC_OOM_SOFTSWAP,
	MEMGC_OOM_WARNING,
	MEMGC_OOM_HIGH,
	MEMGC_OOM_CRITICAL,
};

enum {
	MEMGC_GROUP_FOREGROUND,
	MEMGC_GROUP_BACKGROUND,
};

enum {
	MEM_SWAP_OFF,
	MEM_SWAP_ENABLE,
	MEM_SWAP_DECREASE,
	MEM_SWAP_INCREASE,
};

#define MEM_SOFTSWAP_ENABLE 1
#define MEMCG_GROUP_MAX		2

#define MEMINFO_PATH	"/proc/meminfo"
#define MEMCG_PATH		"/sys/fs/cgroup/memory"
#define VICTIM_TASK		"/sys/class/lowmemnotify/victims"
#define SET_LEAVE_THRESHOLD	"/sys/class/lowmemnotify/leave_threshold"
#define SET_CGROUP_LEAVE_THRESHOLD "/sys/class/lowmemnotify/cgroup_leave_threshold"
#define SET_THRESHOLD_LV1 "/sys/class/lowmemnotify/threshold_level1"
#define SET_THRESHOLD_LV2 "/sys/class/lowmemnotify/threshold_level2"
#define SET_THRESHOLD_RECLAIM "/sys/class/lowmemnotify/threshold_reclaim"

#define MEMPS_LOG_FILE	"/var/log/memps"

#define DELETE_SM		"sh -c "PREFIX"/bin/delete.sm"
#define MEMPS_EXEC_PATH		"usr/bin/memps"


#define _SYS_RES_CLEANUP	"RES_CLEANUP"

#define BtoMB(x)		((x) / 1024 / 1024)
#define MBtoB(x)		(x<<20)

#define MEMCG_FOREGROUND_LIMIT_RATIO	0.6
#define MEMCG_BACKGROUND_LIMIT_RATIO	0.7

#define MEMCG_FOREGROUND_MIN_LIMIT	MBtoB(400)
#define MEMCG_BACKGROUND_MIN_LIMIT	UINT_MAX

/* threshold lv 1 : wakeup softswapd */
#define MEMCG_TRHES_SOFTSWAP_RATIO		0.75

/* threshold lv 2 : lowmem warning */
#define MEMCG_THRES_WARNING_RATIO		0.92

/* threshold lv 3 : victim kill */
#define MEMCG_THRES_OOM_RATIO			0.96

/* leave threshold */
#define MEMCG_OOMLEAVE_RATIO			0.88

#define MEMNOTIFY_NORMAL	0x0000
#define MEMNOTIFY_RECLAIM	0xecae
#define MEMNOTIFY_LOW		0xfaac
#define MEMNOTIFY_CRITICAL	0xdead

/* define threshold limit */
#define MAX_OOM_THRES				0x04600000	/* 70M */
#define MIN_OOM_THRES				0x03000000	/* 48M */
#define MAX_WARN_THRES				0x07800000	/* 120M */
#define MAX_LEAVE_THRES				0x0B400000	/* 180M */
#define MIN_OOM_WARN_GAP			0x01400000	/* 30M */

#define MEM_THRESHOLD_RECLAIM			300
#define MEM_THRESHOLD_LV1			180
#define MEM_THRESHOLD_LV2			160
#define MEM_LEAVE_THRESHOLD			200
#define LOWMEM_PATH_MAX				100

#define MAX_VICTIMS		30

static int lowmem_fd = -1;
static Ecore_Fd_Handler *lowmem_efd;
static int cur_mem_state = MEMNOTIFY_NORMAL;

static Ecore_Timer *oom_check_timer;
#define OOM_TIMER_INTERVAL	3
#define OOM_MULTIKILL_WAIT	(1000*1000)
#define OOM_CHECK_PROC_WAIT	(2000*1000)

unsigned int oom_delete_sm_time;

/* low memory action function */
static int memory_low_act(void *ad);
static int memory_oom_act(void *ad);
static int memory_normal_act(void *ad);
static int memory_reclaim_act(void *ad);


/* low memory action function for cgroup */
static int memory_cgroup_oom_act(int memcg_index);

static int lowmem_fd_start();
static int lowmem_fd_stop(int fd);

struct memcg_class {
	unsigned int event_fd;
	unsigned int min_limit;
	float	limit_ratio;
	unsigned int oomlevel;
	unsigned int oomalert;
	unsigned int oomleave;
	char *cgroup_name;
	unsigned int total_limit;
	unsigned int thres_lv1;
	unsigned int thres_lv2;
	unsigned int thres_lv3;
	unsigned int thres_leave;
};

struct lowmem_process_entry {
	unsigned cur_mem_state;
	unsigned new_mem_state;
	int (*action) (void *);
};

static struct lowmem_process_entry lpe[] = {
	{MEMNOTIFY_NORMAL,	MEMNOTIFY_RECLAIM,	memory_reclaim_act},
	{MEMNOTIFY_NORMAL,	MEMNOTIFY_LOW,		memory_low_act},
	{MEMNOTIFY_NORMAL,	MEMNOTIFY_CRITICAL,	memory_oom_act},
	{MEMNOTIFY_RECLAIM,	MEMNOTIFY_LOW,		memory_low_act},
	{MEMNOTIFY_RECLAIM,	MEMNOTIFY_CRITICAL,	memory_oom_act},
	{MEMNOTIFY_LOW,		MEMNOTIFY_CRITICAL,	memory_oom_act},
	{MEMNOTIFY_CRITICAL,	MEMNOTIFY_CRITICAL,	memory_oom_act},
	{MEMNOTIFY_LOW,		MEMNOTIFY_RECLAIM,	memory_reclaim_act},
	{MEMNOTIFY_LOW,		MEMNOTIFY_NORMAL,	memory_normal_act},
	{MEMNOTIFY_CRITICAL,	MEMNOTIFY_NORMAL,	memory_normal_act},
	{MEMNOTIFY_CRITICAL,	MEMNOTIFY_RECLAIM,	memory_reclaim_act},
	{MEMNOTIFY_RECLAIM,	MEMNOTIFY_NORMAL,	memory_normal_act},
};

static struct memcg_class memcg_class[MEMCG_GROUP_MAX] = {
	{0, MEMCG_FOREGROUND_MIN_LIMIT, MEMCG_FOREGROUND_LIMIT_RATIO, 0, 0, 0, "foreground",
		0, 0, 0, 0, 0},
	{0, MEMCG_BACKGROUND_MIN_LIMIT, MEMCG_BACKGROUND_LIMIT_RATIO, 0, 0, 0, "background",
		0, 0, 0, 0, 0},
};

static const struct module_ops memory_modules_ops;
static const struct module_ops *lowmem_ops;

unsigned int get_available(void)
{
	char buf[PATH_MAX];
	FILE *fp;
	char *idx;
	unsigned int free = 0, cached = 0;
	unsigned int available = 0;

	fp = fopen(MEMINFO_PATH, "r");
	if (!fp) {
		_E("%s open failed, %d", buf, fp);
		return available;
	}

	while (fgets(buf, PATH_MAX, fp) != NULL) {
		if ((idx = strstr(buf, "MemFree:"))) {
			idx += strlen("MemFree:");
			while (*idx < '0' || *idx > '9')
				idx++;
			free = atoi(idx);
		} else if ((idx = strstr(buf, "MemAvailable:"))) {
			idx += strlen("MemAvailable:");
			while (*idx < '0' || *idx > '9')
				idx++;
			available = atoi(idx);
			break;
		} else if((idx = strstr(buf, "Cached:"))) {
			idx += strlen("Cached:");
			while (*idx < '0' || *idx > '9')
				idx++;
			cached = atoi(idx);
			break;
		}
	}

	if (available == 0)
		available = free + cached;
	available >>= 10;
	fclose(fp);

	return available;
}

void lowmem_dynamic_process_killer(int type)
{
	/* This function is not supported */
}

void change_memory_state(int state, int force)
{
	int mem_state;

	if (force) {
		mem_state = state;
	} else {
		mem_state = cur_mem_state;
		_D("mem_state = %d", mem_state);
	}

	switch (mem_state) {
	case MEMNOTIFY_NORMAL:
		memory_normal_act(NULL);
		break;
	case MEMNOTIFY_RECLAIM:
		memory_reclaim_act(NULL);
		break;
	case MEMNOTIFY_LOW:
		memory_low_act(NULL);
		break;
	case MEMNOTIFY_CRITICAL:
		memory_oom_act(NULL);
		break;
	default:
		assert(0);
	}
}

static unsigned int _get_total_memory(void)
{
	char buf[PATH_MAX];
	FILE *fp;
	char *idx;
	unsigned int total = 0;

	fp = fopen(MEMINFO_PATH, "r");
	while (fgets(buf, PATH_MAX, fp) != NULL) {
		if ((idx = strstr(buf, "MemTotal:"))) {
			idx += strlen("MemTotal:");
			while (*idx < '0' || *idx > '9')
				idx++;
			total = atoi(idx);
			total *= 1024;
			break;
		}
	}
	fclose(fp);
	return total;
}

static void _calc_threshold(int type, int limit)
{
	unsigned int val, check;

	/* calculate theshold lv3 */
	val = (unsigned int)(memcg_class[type].total_limit*
			(float)MEMCG_THRES_OOM_RATIO);

	/* check MIN & MAX value about threshold lv3*/
	if (limit - val > MAX_OOM_THRES)
		val = (unsigned int)(limit - MAX_OOM_THRES);
	else if (limit - val < MIN_OOM_THRES)
		val = (unsigned int)(limit - MIN_OOM_THRES);

	/* set threshold lv3 */
	memcg_class[type].thres_lv3 = val;

	/* calculate threshold lv2 */
	val = (unsigned int)(memcg_class[type].total_limit*
			(float)MEMCG_THRES_WARNING_RATIO);

	check = memcg_class[type].thres_lv3;

	/* check MIN & MAX value about threshold lv2*/
	if (check - val < MIN_OOM_WARN_GAP)
		val = (unsigned int)(check - MIN_OOM_WARN_GAP);
	else if (limit - val > MAX_WARN_THRES)
		val = (unsigned int)(limit - MAX_WARN_THRES);

	/* set threshold lv2 */
	memcg_class[type].thres_lv2 = val;

	/* calculate threshold lv1 */
	val = (unsigned int)(memcg_class[type].total_limit*
			(float)MEMCG_TRHES_SOFTSWAP_RATIO);

	/* check MIN value about threshold lv1*/
	check = memcg_class[type].thres_lv2;

	if (check - val < MIN_OOM_WARN_GAP)
		val = (unsigned int)(check - MIN_OOM_WARN_GAP);

	memcg_class[type].thres_lv1 = val;

	/* set leave threshold */
	val = (unsigned int)(memcg_class[type].total_limit*
			(float)MEMCG_OOMLEAVE_RATIO);

	check = memcg_class[type].thres_lv1;

	/* check MIN & MAX value about leave threshold */
	if (check - val < MIN_OOM_WARN_GAP)
		val = (unsigned int)(check - MIN_OOM_WARN_GAP);
	else if (limit - val > MAX_LEAVE_THRES)
		val = (unsigned int)(limit - MAX_WARN_THRES);

	memcg_class[type].oomleave = val;
}

static unsigned int get_mem_usage(int idx)
{
	FILE *f;
	char buf[LOWMEM_PATH_MAX] = {0,};
	unsigned int usage;

	sprintf(buf, "%s/%s/memory.usage_in_bytes",
			MEMCG_PATH, memcg_class[idx].cgroup_name);

	f = fopen(buf, "r");
	if (!f) {
		_E("%s open failed, %d", buf, f);
		return RESOURCED_ERROR_FAIL;
	}
	if (fgets(buf, 32, f) == NULL) {
		_E("fgets failed\n");
		fclose(f);
		return RESOURCED_ERROR_FAIL;
	}
	usage = atoi(buf);
	fclose(f);

	return usage;
}

static int get_current_oom(int idx)
{
	FILE *f;
	char buf[LOWMEM_PATH_MAX] = {0,};
	char *oom;
	unsigned int level;

	sprintf(buf, "%s/%s/memory.oom_usr_control",
			MEMCG_PATH, memcg_class[idx].cgroup_name);

	f = fopen(buf, "r");
	if (!f) {
		_E("%s open failed, %d", buf, f);
		return RESOURCED_ERROR_FAIL;
	}
	if (fgets(buf, 32, f) == NULL) {
		_E("fgets failed\n");
		fclose(f);
		return RESOURCED_ERROR_FAIL;
	}
	oom = strstr(buf, "oom_usr_control");
	oom += strlen("oom_usr_control");
	while (*oom < '0' || *oom > '9')
		oom++;
	level = atoi(oom);
	fclose(f);
	_D("get_current_oom : %d", level);
	return level;
}

static int remove_shm(void)
{
	int maxid, shmid, id;
	struct shmid_ds shmseg;
	struct shm_info shm_info;

	maxid = shmctl(0, SHM_INFO, (struct shmid_ds *)(void *)&shm_info);
	if (maxid < 0) {
		_E("shared mem error\n");
		return RESOURCED_ERROR_FAIL;
	}

	for (id = 0; id <= maxid; id++) {
		shmid = shmctl(id, SHM_STAT, &shmseg);
		if (shmid < 0)
			continue;
		if (shmseg.shm_nattch == 0) {
			_D("shared memory killer ==> %d killed\n",
				  shmid);
			shmctl(shmid, IPC_RMID, NULL);
		}
	}
	return 0;
}

static void print_mem_state(void)
{
	unsigned int usage, i;

	for (i = 0; i < MEMCG_GROUP_MAX; i++) {
		usage = get_mem_usage(i);
		_I("[MEM STATE] memcg : %s, usage %d oom level : %d",
				memcg_class[i].cgroup_name, usage,
				memcg_class[i].oomlevel);
	}
}

static void make_memps_log(char *file, pid_t pid, char *victim_name)
{
	time_t now;
	struct tm *cur_tm;
	char new_log[512];
	static pid_t old_pid;

	if (old_pid == pid)
		return;
	old_pid = pid;

	now = time(NULL);
	cur_tm = (struct tm *)malloc(sizeof(struct tm));
	if (cur_tm == NULL) {
		_E("Fail to memory allocation");
		return;
	}

	if (localtime_r(&now, cur_tm) == NULL) {
		_E("Fail to get localtime");
		free(cur_tm);
		return;
	}

	snprintf(new_log, sizeof(new_log),
		 "%s_%s_%d_%.4d%.2d%.2d_%.2d%.2d%.2d.log", file, victim_name,
		 pid, (1900 + cur_tm->tm_year), 1 + cur_tm->tm_mon,
		 cur_tm->tm_mday, cur_tm->tm_hour, cur_tm->tm_min,
		 cur_tm->tm_sec);

	free(cur_tm);
	if (fork() == 0) {
		execl(MEMPS_EXEC_PATH, MEMPS_EXEC_PATH, "-f", new_log, (char *)NULL);
		exit(0);
	}
}

static int lowmem_check_current_state(int memcg_index,
		int total_size, int oom_usage)
{
	unsigned int usage, oomleave, check = 0;

	oomleave = memcg_class[memcg_index].oomleave;
	usage = get_mem_usage(memcg_index);
	if (usage < oomleave) {
		_D("%s : usage : %d, oomleave : %d",
				__func__, usage, oomleave);
		check++;
	}
	if (oom_usage - total_size < oomleave) {
		_D("%s : oom_usage : %d, total size : %d, oomleave : %d",
				__func__, oom_usage, total_size, oomleave);
		check++;
	}
	return check;
}

static int lowmem_get_victim_pid(int *pid_arry, unsigned int* pid_size)
{
	int count, num_pid = 0;
	FILE *f;
	char buf[LOWMEM_PATH_MAX] = {0, };

	f = fopen(VICTIM_TASK, "r");

	if (!f) {
		_E("Fail to file open");
		return RESOURCED_ERROR_FAIL;
	}

	/* firstly, read victim count */
	if (fgets(buf, 32, f) == NULL) {
		_E("victim list is empty");
		goto out;
	}

	count = atoi(buf);

	if (count > MAX_VICTIMS) {
		_E("Victim count is wrong value");
		goto out;
	}

	while (fgets(buf, 32, f) != NULL) {
		pid_arry[num_pid] = atoi(buf);
		if (fgets(buf, 32, f) != NULL)
			pid_size[num_pid] = atoi(buf);
		else {
			_E("Victim size is needed\n");
			goto out;
		}
		num_pid++;
	}

	if (count != num_pid)
		_I("Number of pids is wrong\n");

	fclose(f);
	return num_pid;
out:
	fclose(f);
	return RESOURCED_ERROR_FAIL;


}

static int lowmem_set_cgroup_leave_threshold(unsigned int value)
{
	FILE *f;
	f = fopen(SET_CGROUP_LEAVE_THRESHOLD, "w");

	if (!f) {
		_E("Fail to file open");
		return RESOURCED_ERROR_FAIL;
	}
	fprintf(f, "%d", value);
	fclose(f);
	return 0;
}

static int lowmem_set_threshold(void)
{
	FILE *f;
	unsigned int val, total;

	f = fopen(SET_THRESHOLD_RECLAIM, "w");

	if (!f) {
		_E("Fail to file open : current kernel can't support swap cgroup");
		return RESOURCED_ERROR_FAIL;
	}

	/* set threshold reclaim */
	total = _get_total_memory();

	/*
	 * check total memory because total memory is over 1GiB,
	 * we want to start reclaim under 300 MiB remained memory.
	 * But, we check condition 700MiB because reserved memory.
	 */
	if (total > MBtoB(700))
		val = MEM_THRESHOLD_RECLAIM;
	else
		val = MEM_THRESHOLD_RECLAIM >> 1;
	fprintf(f, "%d", val);
	fclose(f);

	/* set threshold level1 */
	f = fopen(SET_THRESHOLD_LV1, "w");

	if (!f) {
		_E("Fail to file open");
		return RESOURCED_ERROR_FAIL;
	}
	fprintf(f, "%d", MEM_THRESHOLD_LV1);
	fclose(f);

	/* set threshold level2 */
	f = fopen(SET_THRESHOLD_LV2, "w");

	if (!f) {
		_E("Fail to file open");
		return RESOURCED_ERROR_FAIL;
	}
	fprintf(f, "%d", MEM_THRESHOLD_LV2);
	fclose(f);

	/* set leave threshold */
	f = fopen(SET_LEAVE_THRESHOLD, "w");

	if (!f) {
		_E("Fail to file open");
		return RESOURCED_ERROR_FAIL;
	}
	fprintf(f, "%d", MEM_LEAVE_THRESHOLD);
	fclose(f);
	return 0;
}

void *_lowmem_oom_killer_cb(void *data)
{
	int pid, ret, oom_score_adj, count, i;
	char appname[PROC_NAME_MAX];
	char popupname[PROC_NAME_MAX];
	int pid_array[MAX_VICTIMS];
	unsigned int pid_size[MAX_VICTIMS];
	unsigned int total_size = 0, forgrd_pid = 0, forgrd_size = 0;

	/* get multiple victims from kernel */
	count = lowmem_get_victim_pid((int *)pid_array,
				(unsigned int *)pid_size);

	if (count < 0) {
		_E("get victim was failed");
		return NULL;
	}

	/* kill all selected process */
	for (i = 0; i < count; i++) {
		pid = pid_array[i];

		if (pid <= 0)
			continue;
		_D("oom total memory size : %d", total_size);
		ret = proc_get_cmdline(pid, appname);
		if (ret != 0) {
			_D("invalid pid(%d) was selected", pid);
			continue;
		}
		if (!strcmp("memps", appname)) {
			_E("memps(%d) was selected, skip it", pid);
			continue;
		}
		if (!strcmp("crash-worker", appname)) {
			_E("crash-worker(%d) was selected, skip it", pid);
			continue;
		}

		/* make memps log for killing application firstly */
		if (i == 0)
			make_memps_log(MEMPS_LOG_FILE, pid, appname);

		if (proc_get_oom_score_adj(pid, &oom_score_adj) < 0) {
			_D("pid(%d) was already terminated", pid);
			continue;
		}

		/* just continue if selected process moved to foreground */
		if (BtoMB(total_size) > MEM_LEAVE_THRESHOLD && oom_score_adj < OOMADJ_BACKGRD_UNLOCKED)
			continue;

		proc_remove_process_list(pid);
		kill(pid, SIGKILL);

		total_size += pid_size[i];
		_I("we killed, lowmem lv2 = %d (%s) oom = %d\n",
				pid, appname, oom_score_adj);

		/* wait OOM_MULTIKILL_WAIT for removing a latency about killing proesss */
		if (BtoMB(total_size) > MEM_LEAVE_THRESHOLD && i%5==0)
			usleep(OOM_MULTIKILL_WAIT);

		if (oom_score_adj > OOMADJ_FOREGRD_UNLOCKED)
			continue;

		if (forgrd_size < pid_size[i]) {
			forgrd_pid = pid;
			forgrd_size = pid_size[i];
			strncpy(popupname, appname, PROC_NAME_MAX-1);
		}
	}

	if (forgrd_pid)
		make_memps_log(MEMPS_LOG_FILE, forgrd_pid, popupname);

	return NULL;
}

int lowmem_oom_killer_cb(int memcg_idx, int flags)
{
	int memcg_index = memcg_idx;
	_lowmem_oom_killer_cb((void *)&memcg_index);
	return 0;
}

static void lowmem_cgroup_oom_killer(int memcg_index)
{
	int pid, ret, oom_score_adj, count, i;
	char appname[PATH_MAX];
	int pid_array[32];
	unsigned int pid_size[32];
	unsigned int total_size = 0, oom_usage = 0;

	oom_usage = get_mem_usage(memcg_index);
	/* get multiple victims from kernel */
	count = lowmem_get_victim_pid((int *)pid_array,
				(unsigned int *)pid_size);

	if (count < 0) {
		_E("get victim was failed");
		return;
	}

	for (i = 0; i < count; i++) {
		pid = pid_array[i];

		if (pid <= 0)
			continue;
		_D("oom total memory size : %d", total_size);
		ret = proc_get_cmdline(pid, appname);
		if (ret != 0) {
			_E("invalid pid(%d) was selected", pid);
			continue;
		}
		if (!strcmp("memps", appname)) {
			_E("memps(%d) was selected, skip it", pid);
			continue;
		}
		if (!strcmp("crash-worker", appname)) {
			_E("crash-worker(%d) was selected, skip it", pid);
			continue;
		}
		if (proc_get_oom_score_adj(pid, &oom_score_adj) < 0) {
			_D("pid(%d) was already terminated", pid);
			continue;
		}

		/* check current memory status */
		if (lowmem_check_current_state(memcg_index, total_size,
					oom_usage) > 0)
			return;

		/* make memps log for killing application firstly */
		if (i==0)
			make_memps_log(MEMPS_LOG_FILE, pid, appname);

		proc_remove_process_list(pid);
		kill(pid, SIGTERM);

		total_size += pid_size[i];
		_I("we killed, lowmem lv2 = %d (%s) oom = %d\n",
				pid, appname, oom_score_adj);

		if (oom_score_adj > OOMADJ_FOREGRD_UNLOCKED)
			continue;

		if (i != 0)
			make_memps_log(MEMPS_LOG_FILE, pid, appname);
	}
}

static char *convert_to_str(unsigned int mem_state)
{
	char *tmp = NULL;
	switch (mem_state) {
	case MEMNOTIFY_NORMAL:
	case MEMNOTIFY_RECLAIM:
		tmp = "mem normal";
		break;
	case MEMNOTIFY_LOW:
		tmp = "mem low";
		break;
	case MEMNOTIFY_CRITICAL:
		tmp = "mem critical";
		break;
	default:
		assert(0);
	}
	return tmp;
}

static void print_lowmem_state(unsigned int mem_state)
{
	_I("[LOW MEM STATE] %s ==> %s", convert_to_str(cur_mem_state),
		convert_to_str(mem_state));
}

static void lowmem_swap_memory(void)
{
	pid_t pid;
	int swap_type;

	if (cur_mem_state == MEMNOTIFY_NORMAL)
		return;

	swap_type = swap_status(SWAP_GET_TYPE, NULL);

	if (swap_type == SWAP_ON) {
		while (1)
		{
			pid = (pid_t)swap_status(SWAP_GET_CANDIDATE_PID, NULL);
			if (!pid)
				break;
			_I("swap cgroup entered : pid : %d", (int)pid);
			resourced_notify(RESOURCED_NOTIFIER_SWAP_MOVE_CGROUP, (void*)&pid);
		}
		if (swap_status(SWAP_GET_STATUS, NULL) == SWAP_OFF)
			resourced_notify(RESOURCED_NOTIFIER_SWAP_RESTART, NULL);
		resourced_notify(RESOURCED_NOTIFIER_SWAP_START, NULL);
	}
}

static int memory_reclaim_act(void *data)
{
	int ret, status;
	_I("[LOW MEM STATE] memory reclaim state");
	ret = vconf_get_int(VCONFKEY_SYSMAN_LOW_MEMORY, &status);
	if (ret != 0) {
		_E("vconf get failed(VCONFKEY_SYSMAN_LOW_MEMORY)\n");
		return RESOURCED_ERROR_FAIL;
	}
	if (status != VCONFKEY_SYSMAN_LOW_MEMORY_NORMAL)
		vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
				  VCONFKEY_SYSMAN_LOW_MEMORY_NORMAL);
	else
		lowmem_swap_memory();

	return 0;
}

static int memory_low_act(void *data)
{
	_I("[LOW MEM STATE] memory low state");
	print_mem_state();
	remove_shm();

	vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
		      VCONFKEY_SYSMAN_LOW_MEMORY_SOFT_WARNING);

	return 0;
}

static int memory_oom_act(void *ad)
{
	pthread_t pth;
	int ret;

	_I("[LOW MEM STATE] memory oom state");

	print_mem_state();

	ret = pthread_create(&pth, 0, _lowmem_oom_killer_cb, (void*)NULL);
	if (ret < 0) {
		_E("pthread creation failed!, call directly!");
		_lowmem_oom_killer_cb((void*)NULL);
	} else
		pthread_detach(pth);

	vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
		      VCONFKEY_SYSMAN_LOW_MEMORY_HARD_WARNING);
	return 1;
}

static int memory_cgroup_oom_act(int memcg_index)
{
	_I("[LOW MEM STATE] memory oom state");

	print_mem_state();

	lowmem_cgroup_oom_killer(memcg_index);

	vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
		      VCONFKEY_SYSMAN_LOW_MEMORY_HARD_WARNING);
	return 1;
}

static int memory_normal_act(void *data)
{
	_I("[LOW MEM STATE] memory normal state");
	vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
		      VCONFKEY_SYSMAN_LOW_MEMORY_NORMAL);
	return 0;
}

static int lowmem_process(unsigned int mem_state, void *ad)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(lpe); i++) {
		if ((cur_mem_state == lpe[i].cur_mem_state)
				&& (mem_state == lpe[i].new_mem_state)) {
			if (oom_check_timer != NULL) {
				ecore_timer_del(oom_check_timer);
				oom_check_timer = NULL;
			}
			cur_mem_state = mem_state;
			lpe[i].action(ad);
			if (mem_state == MEMNOTIFY_CRITICAL)
				oom_check_timer =
					ecore_timer_add(OOM_TIMER_INTERVAL, (const void *)lpe[i].action, ad);
			return 0;
		}
	}
	cur_mem_state = mem_state;
	return 0;
}

static unsigned int lowmem_eventfd_read(int fd)
{
	unsigned int ret;
	uint64_t dummy_state;
	ret = read(fd, &dummy_state, sizeof(dummy_state));
	return ret;
}

static Eina_Bool lowmem_cb(void *data, Ecore_Fd_Handler *fd_handler)
{
	int fd, i, currentoom;
	struct ss_main_data *ad = (struct ss_main_data *)data;

	if (!ecore_main_fd_handler_active_get(fd_handler, ECORE_FD_READ)) {
		_E("ecore_main_fd_handler_active_get error , return\n");
		return ECORE_CALLBACK_CANCEL;
	}

	fd = ecore_main_fd_handler_fd_get(fd_handler);
	if (fd < 0) {
		_E("ecore_main_fd_handler_fd_get error , return\n");
		return ECORE_CALLBACK_CANCEL;
	}
	lowmem_eventfd_read(fd);

	for (i = 0; i < MEMCG_GROUP_MAX; i++) {
		currentoom = get_current_oom(i);
		if (currentoom == MEMGC_OOM_NORMAL) {
			if (memcg_class[i].oomalert)
				memory_normal_act(ad);
		}
		if (currentoom > memcg_class[i].oomlevel) {
			switch (currentoom) {
			case MEMGC_OOM_WARNING:
				memory_low_act(ad);
				break;
			case MEMGC_OOM_HIGH:
				memcg_class[i].oomalert = 1;
				memory_cgroup_oom_act(i);
				break;
			case MEMGC_OOM_CRITICAL:
				memcg_class[i].oomalert = 1;
				break;
			default:
				break;
			}
		}
		memcg_class[i].oomlevel = currentoom;
	}

	return ECORE_CALLBACK_RENEW;
}

/*
From memory.txt kernel document -
To register a notifier, application need:
- create an eventfd using eventfd(2)
- open memory.oom_control file
- write string like "<event_fd> <fd of memory.oom_control>"
to cgroup.event_control
*/

static int setup_eventfd(void)
{
	unsigned int thres, i;
	int mcgfd, cgfd, evfd, res, sz, ret = -1;
	char buf[LOWMEM_PATH_MAX] = {0,};

	/* create an eventfd using eventfd(2)
	use same event fd for using ecore event loop */
	evfd = eventfd(0, 0);
	ret = fcntl(evfd, F_SETFL, O_NONBLOCK);
	if (ret < 0)
		return RESOURCED_ERROR_FAIL;

	for (i = 0; i < MEMCG_GROUP_MAX; i++) {
		/* open cgroup.event_control */
		sprintf(buf, "%s/%s/cgroup.event_control",
				MEMCG_PATH, memcg_class[i].cgroup_name);
		cgfd = open(buf, O_WRONLY);
		if (cgfd < 0) {
			_E("open event_control failed");
			return RESOURCED_ERROR_FAIL;
		}

		/* register event in usage_in_byte */
		sprintf(buf, "%s/%s/memory.usage_in_bytes",
				MEMCG_PATH, memcg_class[i].cgroup_name);
		mcgfd = open(buf, O_RDONLY);
		if (mcgfd < 0) {
			_E("open memory control failed");
			close(cgfd);
			return RESOURCED_ERROR_FAIL;
		}

		/* threshold lv 1 : wakeup softswapd */
		/* write event fd about threshold lv1 */
		thres = memcg_class[i].thres_lv1;
		sz = sprintf(buf, "%d %d %d", evfd, mcgfd, thres);
		sz += 1;
		res = write(cgfd, buf, sz);
		if (res != sz) {
			_E("write cgfd failed : %d", res);
			close(cgfd);
			close(mcgfd);
			return RESOURCED_ERROR_FAIL;
		}

		/* calculate threshold lv_2 */
		/* threshold lv 2 : lowmem warning */
		thres = memcg_class[i].thres_lv2;

		/* write event fd about threshold lv1 */
		sz = sprintf(buf, "%d %d %d", evfd, mcgfd, thres);
		sz += 1;
		res = write(cgfd, buf, sz);
		if (res != sz) {
			_E("write cgfd failed : %d", res);
			close(cgfd);
			close(mcgfd);
			return RESOURCED_ERROR_FAIL;
		}

		/* calculate threshold lv_3 */
		/* threshold lv 3 : victim kill */
		thres = memcg_class[i].thres_lv3;

		/* write event fd about threshold lv2 */
		sz = sprintf(buf, "%d %d %d", evfd, mcgfd, thres);
		sz += 1;
		res = write(cgfd, buf, sz);
		if (res != sz) {
			_E("write cgfd failed : %d", res);
			close(cgfd);
			close(mcgfd);
			return RESOURCED_ERROR_FAIL;
		}
		close(mcgfd);

		/* register event in oom_control */
		sprintf(buf, "%s/%s/memory.oom_control",
				MEMCG_PATH, memcg_class[i].cgroup_name);

		mcgfd = open(buf, O_RDONLY);
		if (mcgfd < 0) {
			_E("open memory control failed");
			close(cgfd);
			return RESOURCED_ERROR_FAIL;
		}

		/* write event fd about oom control with zero threshold*/
		thres = 0;
		sz = sprintf(buf, "%d %d %d", evfd, mcgfd, thres);
		sz += 1;
		res = write(cgfd, buf, sz);
		if (res != sz) {
			_E("write cgfd failed : %d", res);
			close(cgfd);
			close(mcgfd);
			return RESOURCED_ERROR_FAIL;
		}
		close(cgfd);
		close(mcgfd);
	}
	return evfd;
}

void set_threshold(int level, int thres)
{
	return;
}

void set_leave_threshold(int thres)
{
	return;
}

static int init_memcg(void)
{
	unsigned int total, i, limit, size;
	char buf[LOWMEM_PATH_MAX] = {0,};
	FILE *f;
	total = _get_total_memory();
	_D("Total : %d", total);

	for (i = 0; i < MEMCG_GROUP_MAX; i++) {
		/* write limit_in_bytes */
		sprintf(buf, "%s/%s/memory.limit_in_bytes",
				MEMCG_PATH, memcg_class[i].cgroup_name);
		_D("buf : %s", buf);
		f = fopen(buf, "w");
		if (!f) {
			_E("%s open failed", buf);
			return RESOURCED_ERROR_FAIL;
		}

		limit = (unsigned int)(memcg_class[i].limit_ratio*(float)total);

		if (limit > memcg_class[i].min_limit)
			limit = memcg_class[i].min_limit;

		size = sprintf(buf, "%u", limit);
		if (fwrite(buf, size, 1, f) != 1)
			_E("fwrite memory.limit_in_bytes : %d\n", limit);
		fclose(f);

		/* save memory limitation for calculating threshold */
		memcg_class[i].total_limit = limit;

		_calc_threshold(i, limit);

		/* set leave threshold value to kernel */
		lowmem_set_cgroup_leave_threshold(memcg_class[i].oomleave);

		/* enable cgroup move */
		sprintf(buf, "%s/%s/memory.move_charge_at_immigrate",
				MEMCG_PATH, memcg_class[i].cgroup_name);
		_D("buf : %s", buf);
		f = fopen(buf, "w");
		if (!f) {
			_E("%s open failed", buf);
			return RESOURCED_ERROR_FAIL;
		}
		size = sprintf(buf, "3");
		if (fwrite(buf, size, 1, f) != 1)
			_E("fwrite memory.move_charge_at_immigrate\n");
		fclose(f);

	}
	return 0;
}

static void lowmem_move_memcgroup(int pid, int oom_score_adj)
{
	char buf[LOWMEM_PATH_MAX] = {0,};
	FILE *f;
	int size, background = 0;
	unsigned long swap_args[1] = {0,};

	if (oom_score_adj > OOMADJ_BACKGRD_LOCKED) {
		sprintf(buf, "%s/background/cgroup.procs", MEMCG_PATH);
		background = 1;
	}
	else if (oom_score_adj >= OOMADJ_FOREGRD_LOCKED &&
					oom_score_adj < OOMADJ_BACKGRD_LOCKED)
		sprintf(buf, "%s/foreground/cgroup.procs", MEMCG_PATH);
	else
		return;

	swap_args[0] = (unsigned long)pid;
	if (!swap_status(SWAP_CHECK_PID, swap_args) || !background) {
		_I("buf : %s, pid : %d, oom : %d", buf, pid, oom_score_adj);
		f = fopen(buf, "w");
		if (!f) {
			_E("%s open failed", buf);
			return;
		}
		size = sprintf(buf, "%d", pid);
		if (fwrite(buf, size, 1, f) != 1)
			_E("fwrite cgroup tasks : %d\n", pid);
		fclose(f);
	}
	if (background)
		lowmem_swap_memory();
}

static void lowmem_cgroup_foregrd_manage(int currentpid)
{
	char buf[LOWMEM_PATH_MAX] = {0,};
	int pid, pgid;
	FILE *f;
	sprintf(buf, "%s/background/cgroup.procs", MEMCG_PATH);
	f = fopen(buf, "r");
	if (!f) {
		_E("%s open failed", buf);
		return;
	}
	while (fgets(buf, LOWMEM_PATH_MAX, f) != NULL) {
		pid = atoi(buf);
		if (currentpid == pid)
			continue;
		pgid = getpgid(pid);
		if (currentpid == pgid)
			lowmem_move_memcgroup(pid, OOMADJ_APP_LIMIT);
	}
	fclose(f);
}

static unsigned int lowmem_read(int fd)
{
	unsigned int mem_state;
	if (read(fd, &mem_state, sizeof(mem_state)) < 0) {
		_E("error lowmem state");
		return RESOURCED_ERROR_FAIL;
	}
	return mem_state;
}

static Eina_Bool lowmem_efd_cb(void *data, Ecore_Fd_Handler *fd_handler)
{
	int fd;
	struct ss_main_data *ad = (struct ss_main_data *)data;
	unsigned int mem_state;

	if (!ecore_main_fd_handler_active_get(fd_handler, ECORE_FD_READ)) {
		_E("ecore_main_fd_handler_active_get_error, return\n");
		return ECORE_CALLBACK_CANCEL;
	}

	fd = ecore_main_fd_handler_fd_get(fd_handler);
	if (fd < 0) {
		_E("ecore_main_fd_handler_fd_get error, return\n");
		return ECORE_CALLBACK_CANCEL;
	}

	mem_state = lowmem_read(fd);
	if (mem_state == -1) {
		lowmem_fd_stop(fd);
		_E("error lowmem_read, restart lowmem fd");
		lowmem_fd_start();
		return ECORE_CALLBACK_CANCEL;
	}

	print_lowmem_state(mem_state);
	lowmem_process(mem_state, ad);

	return ECORE_CALLBACK_RENEW;
}

static int lowmem_fd_start(void)
{
	lowmem_fd = open("/dev/lowmemnotify", O_RDONLY);
	if (lowmem_fd < 0) {
		_E("lowmem_fd_start fd open failed");
		return RESOURCED_ERROR_FAIL;
	} else
		_D("lowmem_fd_start open /dev/lowmemnotify sucess\n");

	oom_check_timer = NULL;
	lowmem_efd = ecore_main_fd_handler_add(lowmem_fd, ECORE_FD_READ,
					       (Ecore_Fd_Cb)lowmem_efd_cb, NULL,
					       NULL, NULL);
	if (!lowmem_efd) {
		_E("error ecore_main_fd_handler_add in lowmem_fd_start\n");
		return RESOURCED_ERROR_FAIL;
	}
	return 0;
}

int lowmem_init(void)
{
	int ret = RESOURCED_ERROR_NONE;

	/* set default memcg value */
	ret = init_memcg();
	if (ret < 0) {
		_E("memory cgroup init failed");
		return RESOURCED_ERROR_FAIL;
	}

	ret = lowmem_fd_start();
	if (ret < 0) {
		_E("lowmem_fd_start fail\n");
		return RESOURCED_ERROR_FAIL;
	}

	/* set threshold level 1, level 2, leave threshold */
	ret = lowmem_set_threshold();
	if (ret < 0) {
		_E("lowmem_set_threshold fail\n");
		return RESOURCED_ERROR_FAIL;
	}

	/* register threshold and event fd */
	lowmem_fd = setup_eventfd();
	if (lowmem_fd < 0) {
		_E("setup event fd is failed");
		return RESOURCED_ERROR_FAIL;
	}

	ecore_main_fd_handler_add(lowmem_fd, ECORE_FD_READ,
				  (Ecore_Fd_Cb)lowmem_cb, NULL, NULL, NULL);

	_I("lowmem_swaptype : %d", swap_status(SWAP_GET_TYPE, NULL));

	lowmem_dbus_init();

	return 0;
}

static int lowmem_fd_stop(int fd)
{
	if (lowmem_efd) {
		ecore_main_fd_handler_del(lowmem_efd);
		lowmem_efd = NULL;
	}
	if (fd >= 0) {
		close(fd);
		fd = -1;
	}
	return 0;
}

static int resourced_memory_control(void *data)
{
	int ret = RESOURCED_ERROR_NONE;
	struct lowmem_data_type *l_data;

	l_data = (struct lowmem_data_type *)data;
	switch(l_data->control_type) {
	case LOWMEM_MOVE_CGROUP:
		if (l_data->args)
			lowmem_move_memcgroup((pid_t)l_data->args[0], l_data->args[1]);
		break;
	case LOWMEM_MANAGE_FOREGROUND:
		if (l_data->args)
			lowmem_cgroup_foregrd_manage((pid_t)l_data->args[0]);
		break;

	}
	return ret;
}

static int resourced_memory_init(void *data)
{
	lowmem_ops = &memory_modules_ops;

	return lowmem_init();
}

static int resourced_memory_finalize(void *data)
{
	return RESOURCED_ERROR_NONE;
}

int lowmem_control(enum lowmem_control_type type, unsigned long *args)
{
	struct lowmem_data_type l_data;

	if (lowmem_ops) {
		l_data.control_type = type;
		l_data.args = args;
		return lowmem_ops->control(&l_data);
	}

	return RESOURCED_ERROR_NONE;
}

static const struct module_ops memory_modules_ops = {
	.priority	= MODULE_PRIORITY_NORMAL,
	.name		= "lowmem",
	.init		= resourced_memory_init,
	.exit		= resourced_memory_finalize,
	.control	= resourced_memory_control,
};

MODULE_REGISTER(&memory_modules_ops)
