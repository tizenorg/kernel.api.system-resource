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
 * @file vmpressure-lowmem-handler.c
 *
 * @desc lowmem handler using memcgroup
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <dirent.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/eventfd.h>
#include <sys/sysinfo.h>
#include <Ecore.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <ctype.h>

#include "trace.h"
#include "cgroup.h"
#include "lowmem-handler.h"
#include "proc-common.h"
#include "procfs.h"
#include "freezer.h"
#include "lowmem-common.h"
#include "resourced.h"
#include "macro.h"
#include "notifier.h"
#include "config-parser.h"
#include "module.h"
#include "swap-common.h"
#include "cgroup.h"
#include "memcontrol.h"
#include "logging-common.h"
#include "freezer-common.h"
#include "proc-main.h"
#include "helper.h"

#define LOWMEM_DEFAULT_CGROUP		"/sys/fs/cgroup/memory"
#define LOWMEM_NO_LIMIT			0
#define LOWMEM_THRES_INIT		0

/* Experimently, RSS is 3 times larger than the actual allocated memory. */
#define LOWMEM_RSS_RATIO		0.3

#define MEMPS_LOG_PATH			"/var/log/"
#define MEMPS_LOG_FILE			MEMPS_LOG_PATH"memps"
#define MEMPS_EXEC_PATH			"usr/bin/memps"
#define MEMCG_MOVE_CHARGE_PATH		"memory.move_charge_at_immigrate"
#define MEMCG_OOM_CONTROL_PATH		"memory.oom_control"
#define MEMCG_LIMIT_PATH		"memory.limit_in_bytes"
#define MEM_CONF_FILE                   "/etc/resourced/memory.conf"
#define MEM_CONF_SECTION                "VIP_PROCESS"
#define MEM_CONF_PREDEFINE              "PREDEFINE"

#define BtoMB(x)			((x) >> 20)
#define BtoKB(x)			((x) >> 10)
#define KBtoMB(x)			((x) >> 10)
#define BtoPAGE(x)			((x) >> 12)
#define MBtoKB(x)			((x) << 10)

#define BUF_MAX				1024
#define MAX_MEMORY_CGROUP_VICTIMS	10
#define MAX_CGROUP_VICTIMS		1
#define OOM_TIMER_INTERVAL		2
#define OOM_KILLER_PRIORITY		-20
#define MAX_FD_VICTIMS			10
#define MAX_MEMPS_LOGS			50
#define MAX_FGRD_KILL			3
#define NUM_RM_LOGS			5
#define THRESHOLD_MARGIN		10 /* MB */

#define MEM_SIZE_64			64  /* MB */
#define MEM_SIZE_256			256 /* MB */
#define MEM_SIZE_512			512 /* MB */
#define MEM_SIZE_768			768 /* MB */
#define MEM_SIZE_1024			1024 /* MB */
#define MEM_SIZE_2048			2048 /* MB */

/* thresholds for 64M RAM*/
#define DYNAMIC_PROCESS_64_THRES		10 /* MB */
#define DYNAMIC_PROCESS_64_LEAVE		30 /* MB */
#define MEMCG_MEMORY_64_THRES_SWAP		15 /* MB */
#define MEMCG_MEMORY_64_THRES_LOW		8  /* MB */
#define MEMCG_MEMORY_64_THRES_MEDIUM		5  /* MB */
#define MEMCG_MEMORY_64_THRES_LEAVE		8  /* MB */

/* thresholds for 256M RAM */
#define DYNAMIC_PROCESS_256_THRES		50 /* MB */
#define DYNAMIC_PROCESS_256_LEAVE		80 /* MB */
#define MEMCG_MEMORY_256_THRES_SWAP		40 /* MB */
#define MEMCG_MEMORY_256_THRES_LOW		20 /* MB */
#define MEMCG_MEMORY_256_THRES_MEDIUM		10 /* MB */
#define MEMCG_MEMORY_256_THRES_LEAVE		20 /* MB */

/* threshold for 512M RAM */
#define DYNAMIC_PROCESS_512_THRES		80 /* MB */
#define DYNAMIC_PROCESS_512_LEAVE		100 /* MB */
#define MEMCG_MEMORY_512_THRES_SWAP		100 /* MB */
#define MEMCG_MEMORY_512_THRES_LOW		50  /* MB */
#define MEMCG_MEMORY_512_THRES_MEDIUM		40  /* MB */
#define MEMCG_MEMORY_512_THRES_LEAVE		60  /* MB */

/* threshold for 768 RAM */
#define DYNAMIC_PROCESS_768_THRES		100 /* MB */
#define DYNAMIC_PROCESS_768_LEAVE		120 /* MB */
#define MEMCG_MEMORY_768_THRES_SWAP		150 /* MB */
#define MEMCG_MEMORY_768_THRES_LOW		100  /* MB */
#define MEMCG_MEMORY_768_THRES_MEDIUM		60  /* MB */
#define MEMCG_MEMORY_768_THRES_LEAVE		100  /* MB */

/* threshold for more than 1024M RAM */
#define DYNAMIC_PROCESS_1024_THRES		150 /* MB */
#define DYNAMIC_PROCESS_1024_LEAVE		300 /* MB */
#define MEMCG_MEMORY_1024_THRES_SWAP		300 /* MB */
#define MEMCG_MEMORY_1024_THRES_LOW		200 /* MB */
#define MEMCG_MEMORY_1024_THRES_MEDIUM		100 /* MB */
#define MEMCG_MEMORY_1024_THRES_LEAVE		150 /* MB */

/* threshold for more than 2048M RAM */
#define DYNAMIC_PROCESS_2048_THRES		200 /* MB */
#define DYNAMIC_PROCESS_2048_LEAVE		500 /* MB */
#define MEMCG_MEMORY_2048_THRES_SWAP		300 /* MB */
#define MEMCG_MEMORY_2048_THRES_LOW		200 /* MB */
#define MEMCG_MEMORY_2048_THRES_MEDIUM		160 /* MB */
#define MEMCG_MEMORY_2048_THRES_LEAVE		300 /* MB */

static int proactive_threshold;
static int proactive_leave;

struct task_info {
	pid_t pid;
	pid_t pgid;
	int oom_score_adj;
	int size;
};

struct lowmem_process_entry {
	int cur_mem_state;
	int new_mem_state;
	void (*action) (void);
};

/* low memory action function for cgroup */
static void memory_cgroup_medium_act(int type, struct memcg_info *mi);
/* low memory action function */
static void normal_act(void);
static void swap_act(void);
static void low_act(void);
static void medium_act(void);

static Eina_Bool medium_cb(void *data);

#define LOWMEM_ENTRY(c, n, act)		\
	{ LOWMEM_##c, LOWMEM_##n, act}

static struct lowmem_process_entry lpe[] = {
	LOWMEM_ENTRY(NORMAL,	SWAP,		swap_act),
	LOWMEM_ENTRY(NORMAL,	LOW,		low_act),
	LOWMEM_ENTRY(NORMAL,	MEDIUM,		medium_act),
	LOWMEM_ENTRY(SWAP,	NORMAL,		normal_act),
	LOWMEM_ENTRY(SWAP,	LOW,		low_act),
	LOWMEM_ENTRY(SWAP,	MEDIUM,		medium_act),
	LOWMEM_ENTRY(LOW,	SWAP,		swap_act),
	LOWMEM_ENTRY(LOW,	NORMAL,		normal_act),
	LOWMEM_ENTRY(LOW,	MEDIUM,		medium_act),
	LOWMEM_ENTRY(MEDIUM,	SWAP,		swap_act),
	LOWMEM_ENTRY(MEDIUM,	NORMAL,		normal_act),
	LOWMEM_ENTRY(MEDIUM,	LOW,		low_act),
};

static int cur_mem_state = LOWMEM_NORMAL;
static Ecore_Timer *oom_check_timer;
static int num_max_victims = MAX_MEMORY_CGROUP_VICTIMS;

static pthread_t	oom_thread;
static pthread_mutex_t	oom_mutex	= PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	oom_cond	= PTHREAD_COND_INITIALIZER;

static unsigned long totalram;
static unsigned long ktotalram;
static int fg_killed;

static const struct module_ops memory_modules_ops;
static const struct module_ops *lowmem_ops;
static char *memcg_name[MEMCG_MAX] = {
	NULL,
	"foreground",
	"service",
	"favorite",
	"background",
	"swap",
};

struct memcg **memcg;
struct memcg_info *memcg_memory;

static inline void get_total_memory(void)
{
	struct sysinfo si;
	if (totalram)
		return;

	if (!sysinfo(&si)) {
		totalram = si.totalram;
		ktotalram = BtoKB(totalram);
	}
}

int lowmem_get_proc_mem_rss(pid_t pid, unsigned int *rss)
{
	FILE *fp;
	char proc_path[PATH_MAX];

	snprintf(proc_path, sizeof(proc_path), "/proc/%d/statm", pid);
	fp = fopen(proc_path, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;

	if (fscanf(fp, "%*s %d", rss) < 1) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	fclose(fp);

	if (*rss == 0)
		return RESOURCED_ERROR_FAIL;

	/* convert page to Kb */
	*rss *= 4;
	_D("success get rss = %u for %d from proc", *rss, pid);
	return RESOURCED_ERROR_NONE;
}

#ifdef HEART_SUPPORT
static int lowmem_get_proc_mem_uss(pid_t pid, unsigned int *uss)
{
	struct proc_app_info *pai = NULL;
	unsigned int tpss = 0, tuss = 0;
	int ret;

	pai = find_app_info(pid);
	if (!pai)
		goto error;

	ret = logging_memory_get_latest_data(pai->appid, &tpss, &tuss);
	if (ret == RESOURCED_ERROR_FAIL)
		goto error;
	*uss = tuss;
	_D("success get uss = %u for %s from data crud", tuss, pai->appid);
	return RESOURCED_ERROR_NONE;

error:
	*uss = 0;
	return RESOURCED_ERROR_FAIL;
}
#endif

static int get_proc_mem_usage(pid_t pid, unsigned int *usage)
{
	int ret;

#ifdef HEART_SUPPORT
	ret = lowmem_get_proc_mem_uss(pid, usage);
	if (ret == RESOURCED_ERROR_NONE && *usage > 0)
		return ret;
#endif

	ret = proc_get_mem_usage(pid, NULL, usage);
	if (ret == RESOURCED_ERROR_NONE)
		return ret;

	return RESOURCED_ERROR_FAIL;
}

static int memps_file_select(const struct dirent *entry)
{
   return strstr(entry->d_name, "memps") ? 1 : 0;
}

int compare_func(const struct dirent **a, const struct dirent **b)
{
	const char *fn_a = (*a)->d_name;
	const char *fn_b = (*b)->d_name;
	char *str_at = strrchr(fn_a, '_') + 1;
	char *str_bt = strrchr(fn_b, '_') + 1;

	return strcmp(str_at, str_bt);
}

static void clear_logs(char *dir)
{
	struct dirent **namelist;
	int n, i, ret;
	char fname[BUF_MAX];

	n = scandir(dir, &namelist, memps_file_select, compare_func);
	_D("num of log files %d", n);
	if (n < MAX_MEMPS_LOGS) {
		while (n--)
			free(namelist[n]);
		free(namelist);
		return;
	}

	for (i = 0; i < n; i++) {
		if (i < NUM_RM_LOGS) {
			snprintf(fname, sizeof(fname), "%s%s", dir, namelist[i]->d_name);
			_D("remove log file %s", fname);
			ret = remove(fname);
			if (ret < 0)
				_E("%s file cannot removed", fname);
		}

		free(namelist[i]);
	}
	free(namelist);
}

static void make_memps_log(char *file, pid_t pid, char *victim_name)
{
	time_t now;
	struct tm cur_tm;
	char new_log[BUF_MAX];
	static pid_t old_pid;

	if (old_pid == pid)
		return;
	old_pid = pid;

	now = time(NULL);

	if (localtime_r(&now, &cur_tm) == NULL) {
		_E("Fail to get localtime");
		return;
	}

	snprintf(new_log, sizeof(new_log),
		 "%s_%s_%d_%.4d%.2d%.2d%.2d%.2d%.2d", file, victim_name,
		 pid, (1900 + cur_tm.tm_year), 1 + cur_tm.tm_mon,
		 cur_tm.tm_mday, cur_tm.tm_hour, cur_tm.tm_min,
		 cur_tm.tm_sec);

	if (fork() == 0) {
		execl(MEMPS_EXEC_PATH, MEMPS_EXEC_PATH, "-r", new_log, (char *)NULL);
		exit(0);
	}
}

static int lowmem_check_current_state(struct memcg_info *mi)
{
	unsigned int usage, oomleave;
	int ret;

	oomleave = mi->oomleave;
	ret = memcg_get_anon_usage(mi, &usage);

	if (ret) {
		_D("getting anonymous usage fails");
		return ret;
	}

	if (oomleave > usage) {
		_D("%s : usage : %u, leave threshold : %u",
				__func__, usage, oomleave);
		return RESOURCED_ERROR_NONE;
	} else {
		_D("%s : usage : %u, leave threshold: %u",
				__func__, usage, oomleave);
		return RESOURCED_ERROR_FAIL;
	}
}

static int lowmem_get_task_info_array_for_memcg(struct memcg_info *mi, GArray *t_info_array)
{
	int i, j;
	char appname[BUF_MAX] = {0,};

	GArray *pids_array = g_array_new(false, false, sizeof(pid_t));
	memcg_get_pids(mi, pids_array);

	if (pids_array->len == 0)
		/*
		 * if task read in this cgroup fails,
		 * return the current number of victims
		 */
		return t_info_array->len;

	for (i = 0; i < pids_array->len; i++) {
		pid_t tpid = 0;
		int toom = 0;
		unsigned int tsize = 0;

		tpid =  g_array_index(pids_array, pid_t, i);

		if (proc_get_oom_score_adj(tpid, &toom) < 0 ||
			toom <= OOMADJ_SERVICE_MIN) {
			_D("pid(%d) was already terminated or high priority oom = %d",
				tpid, toom);
			continue;
		}

		if (get_proc_mem_usage(tpid, &tsize) < 0) {
			_D("pid(%d) size is not available\n", tpid);
			continue;
		}

		if (proc_get_cmdline(tpid, appname) < 0)
			continue;

		for (j = 0; j < t_info_array->len; j++) {
			struct task_info *tsk = &g_array_index(t_info_array,
							struct task_info, j);
			if (getpgid(tpid) == tsk->pgid) {
				tsk->size += tsize;
				if (tsk->oom_score_adj <= 0 && toom > 0) {
					tsk->pid = tpid;
					tsk->oom_score_adj = toom;
				}
				break;
			}
		}

		if (j == t_info_array->len) {
			struct task_info tsk;
			tsk.pid = tpid;
			tsk.pgid = getpgid(tpid);
			tsk.oom_score_adj = toom;
			tsk.size = tsize;

			g_array_append_val(t_info_array, tsk);
		}
	}

	g_array_free(pids_array, TRUE);
	return t_info_array->len;
}

static void lowmem_kill_victim(struct task_info *tsk,
	int flags, int memps_log, unsigned int *total_size)
{
	pid_t pid;
	int ret;
	unsigned int total = 0;
	char appname[PATH_MAX];
	int sigterm;

	pid = tsk->pid;

	if (pid <= 0 || pid == getpid())
		return;

	ret = proc_get_cmdline(pid, appname);
	if (ret == RESOURCED_ERROR_FAIL)
		return;

	if (!strcmp("memps", appname) ||
	    !strcmp("crash-worker", appname)) {
		_E("%s(%d) was selected, skip it", appname, pid);
		return;
	}

	/* make memps log for killing application firstly */
	if (!memps_log)
		make_memps_log(MEMPS_LOG_FILE, pid, appname);

	total += *total_size + ((float)tsk->size * LOWMEM_RSS_RATIO);

	resourced_proc_status_change(PROC_CGROUP_SET_TERMINATE_REQUEST,
		    pid, NULL, NULL, PROC_TYPE_NONE);

	if (tsk->oom_score_adj < OOMADJ_BACKGRD_LOCKED) {
		sigterm = 1;
	} else if (tsk->oom_score_adj == OOMADJ_BACKGRD_LOCKED) {
		int app_flag = proc_get_appflag(pid);
		sigterm = app_flag & PROC_SIGTERM;
	} else
		sigterm = 0;

	if (sigterm)
		kill(pid, SIGTERM);
	else
		kill(pid, SIGKILL);

	_E("we killed, force(%d), %d (%s) score = %d, size = %u KB, victim total size = %u KB, sigterm = %d\n",
			flags & OOM_FORCE, pid, appname, tsk->oom_score_adj,
			tsk->size, total, sigterm);
	*total_size = total;

	if (tsk->oom_score_adj > OOMADJ_FOREGRD_UNLOCKED)
		return;

	if (memps_log)
		make_memps_log(MEMPS_LOG_FILE, pid, appname);
}

/* return RESOURCED_ERROR_NONE when kill should be continued */
static int lowmem_check_kill_continued(struct task_info *tsk, int flags)
{
	unsigned int available;

	if (tsk->oom_score_adj >= OOMADJ_BACKGRD_UNLOCKED)
		return RESOURCED_ERROR_NONE;

	if ((flags & OOM_FORCE) || !(flags & OOM_TIMER_CHECK)) {
		_D("%d is skipped during force kill, flag = %d",
			tsk->pid, flags);
		return RESOURCED_ERROR_FAIL;
	}
	available = proc_get_mem_available();
	if (available > memcg_memory->threshold[LOWMEM_MEDIUM] +
			THRESHOLD_MARGIN) {
		_D("available: %d MB, larger than threshold margin",
				available);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
}

static int compare_victims(const struct task_info *ta, const struct task_info *tb)
{
	/*
	 * Firstly, sort by oom_score_adj
	 * Secondly, sort by task size
	 */
	assert(ta != NULL);
	assert(tb != NULL);

	if (ta->oom_score_adj != tb->oom_score_adj)
		return tb->oom_score_adj - ta->oom_score_adj;

	return (int)(tb->size) - (int)(ta->size);
}

static int compare_victims_point(const struct task_info *ta, const struct task_info *tb)
{
        unsigned int pa, pb;
	assert(ta != NULL);
	assert(tb != NULL);

	/*
	 * followed by kernel badness point calculation using heuristic.
	 * oom_score_adj is normalized by its unit, which varies -1000 ~ 1000.
	 * Since we only consider tasks with oom_score_adj larger than 0
	 * as victim candidates, point always has positive value.
	 */
	pa = ta->oom_score_adj * (ktotalram / 1000) + ta->size;
	pb = tb->oom_score_adj * (ktotalram / 1000) + tb->size;

	return pb - pa;
}

static int lowmem_kill_cgroup_victims(int type, struct memcg_info *mi,
	int max_victims, unsigned should_be_freed, int flags,
	unsigned int *total_size, int *completed)
{
	int i, ret, victim = 0, count = 0;
	unsigned total_victim_size = 0;
	GArray *candidates = NULL;

	candidates = g_array_new(false, false, sizeof(struct task_info));

	/* if g_array_new fails, return the current number of victims */
	if (candidates == NULL)
		return victim;

	/*
	 * if there is no tasks in this cgroup,
	 * return the current number of victims
	 */
	count = lowmem_get_task_info_array_for_memcg(mi, candidates);
	if (count == 0) {
		g_array_free(candidates, true);
		return victim;
	}

	g_array_sort(candidates,
		(GCompareFunc)compare_victims);

	for (i = 0; i < candidates->len; i++) {
		struct task_info *tsk;
		if (i >= max_victims ||
		    (!(flags & OOM_NOMEMORY_CHECK) &&
		    total_victim_size >= MBtoKB(should_be_freed))) {
			_D("victim = %d, max_victims = %d, total_size = %u",
				i, max_victims, total_victim_size);
			break;
		}

		tsk = &g_array_index(candidates, struct task_info, i);

		ret = lowmem_check_kill_continued(tsk, flags);
		if (ret == RESOURCED_ERROR_FAIL) {
			*completed = 1;
			break;
		}

		lowmem_kill_victim(tsk, flags, i, &total_victim_size);
	}

	victim = i;
	g_array_free(candidates, true);
	*total_size = total_victim_size;

	return victim;
}

static inline int is_dynamic_process_killer(int flags)
{
	return (flags & OOM_FORCE) && !(flags & OOM_NOMEMORY_CHECK);
}

static int lowmem_kill_subcgroup_victims(int type, int max_victims, int flags,
	unsigned int *total_size, int *completed)
{
	GSList *iter = NULL;
	GArray *candidates = NULL;
	int i, ret, victim = 0;
	unsigned int total_victim_size = 0;
	struct task_info *tsk;

	candidates = g_array_new(false, false, sizeof(struct task_info));
	gslist_for_each_item(iter, memcg[type]->cgroups) {
		struct memcg_info *mi =
			(struct memcg_info *)(iter->data);
		int count = lowmem_get_task_info_array_for_memcg(mi, candidates);
		_D("get %d pids", count);
	}

	g_array_sort(candidates, (GCompareFunc)compare_victims);

	for (i = 0; i < candidates->len; i++) {
		if (i == max_victims)
			break;

		tsk = &g_array_index(candidates, struct task_info, i);

		ret = lowmem_check_kill_continued(tsk, flags);
		if (ret == RESOURCED_ERROR_FAIL)
			break;

		lowmem_kill_victim(tsk, flags, i, &total_victim_size);
	}

	victim = i;
	g_array_free(candidates, true);
	return victim;
}

static unsigned int is_memory_recovered(unsigned int *avail, unsigned int *thres)
{
	unsigned int available = proc_get_mem_available();
	unsigned int leave_threshold = memcg_memory->threshold_leave;
	unsigned int should_be_freed = 0;

	if (available < leave_threshold)
		should_be_freed = leave_threshold - available;
	/*
	 * free THRESHOLD_MARGIN more than real should be freed,
	 * because launching app is consuming up the memory.
	 */
	if (should_be_freed > 0)
		should_be_freed += THRESHOLD_MARGIN;

	*avail = available;
	*thres = leave_threshold;

	_I("should_be_freed = %u MB", should_be_freed);
	return should_be_freed;
}

static int lowmem_get_pids_proc(GArray *pids)
{
	DIR *dp;
	struct dirent dentry;
	struct dirent *result;
	int ret;
	char appname[PROC_NAME_MAX] = {0};

	dp = opendir("/proc");
	if (!dp) {
		_E("fail to open /proc");
		return RESOURCED_ERROR_FAIL;
	}
	while (!(ret = readdir_r(dp, &dentry, &result)) && result != NULL) {
		struct task_info tsk;
		pid_t pid = 0, pgid = 0;
		int oom = 0;
		unsigned int size = 0;

		if (!isdigit(dentry.d_name[0]))
			continue;

		pid = (pid_t)atoi(dentry.d_name);
		pgid = getpgid(pid);
		if (!pgid)
			continue;

		if (proc_get_oom_score_adj(pid, &oom) < 0) {
			_D("pid(%d) was already terminated", pid);
			continue;
		}

		if (get_proc_mem_usage(pid, &size) < 0) {
			_D("pid(%d) size is not available\n", pid);
			continue;
		}

		if (proc_get_cmdline(pid, appname) < 0)
			continue;

		tsk.pid = pid;
		tsk.pgid = pgid;
		tsk.oom_score_adj = oom;
		tsk.size = size;

		g_array_append_val(pids, tsk);
	}

	closedir(dp);
	if (ret)
		_E("fail to open subdirectory in /proc");

	if (pids->len)
		return pids->len;
	return RESOURCED_ERROR_FAIL;
}

static int lowmem_kill_memory_cgroup_victims(int flags)
{
	GArray *candidates = NULL;
	int i, count, victim = 0;
	unsigned int av, total_victim_size = 0;
	struct task_info *tsk;

	candidates = g_array_new(false, false, sizeof(struct task_info));

	/* if g_array_new fails, return the current number of victims */
	if (candidates == NULL)
		return victim;

	count = lowmem_get_pids_proc(candidates);

	if (count <= 0)
		return victim;

	g_array_sort(candidates, (GCompareFunc)compare_victims_point);

	_D("start to kill for memory cgroup");
	for (i = 0; i < candidates->len; i++) {
		tsk = &g_array_index(candidates, struct task_info, i);
		av = proc_get_mem_available();

		if (av > memcg_memory->threshold[LOWMEM_MEDIUM] ||
		    i >= num_max_victims) {
			_D("checking proc, available: %d MB, larger than threshold margin", av);
			g_array_free(candidates, true);
			victim = i;
			return victim;
		}
		lowmem_kill_victim(tsk, flags, i, &total_victim_size);
	}
	victim = i;
	g_array_free(candidates, true);
	return victim;
}

/* Find victims: (SWAP -> ) BACKGROUND */
static int lowmem_kill_all_cgroup_victims(int flags)
{
	int i, count = 0, completed = 0;
	unsigned int available = 0, should_be_freed = 0, leave_threshold = 0;
	struct memcg_info *mi;
	unsigned int threshold, total_size = 0;

	for (i = MEMCG_MAX - 1; i > 0; i--) {
		should_be_freed = is_memory_recovered(&available, &leave_threshold);

		if (should_be_freed == 0)
			return count;

		if (!memcg[i] || !memcg[i]->info)
			continue;

		mi = memcg[i]->info;
		threshold = mi->threshold[LOWMEM_MEDIUM];

		if ((i <= MEMCG_FOREGROUND) && (available > threshold)) {
			_D("in timer, not kill fg app, available %u > threshold %u",
				available, threshold);
			return count;
		}

		_D("%s start, should_be_freed = %u",
			mi->name, should_be_freed);

		if (memcg[i]->use_hierarchy)
			count = lowmem_kill_subcgroup_victims(i, num_max_victims,
					flags, &total_size, &completed);
		else
			count = lowmem_kill_cgroup_victims(i, mi,
					num_max_victims, should_be_freed,
					flags, &total_size, &completed);

		if (count == 0) {
			_D("%s: there is no victim", mi->name);
			continue;
		}

		if ((flags & OOM_TIMER_CHECK) && (i <= MEMCG_SERVICE)) {
			if (fg_killed >= MAX_FGRD_KILL) {
				_D("foreground is killed %d times and search from proc", fg_killed);
				completed = 0;
				break;
			}
			_D("foreground is killed %d times", fg_killed);
			fg_killed++;
		}

		_D("%s: kill %d victims, total_size = %u",
				mi->name, count, total_size);
		return count;
	}

	if (!completed)
		count = lowmem_kill_memory_cgroup_victims(flags);

	return count;
}

static int lowmem_kill_victims(int type, struct memcg_info *mi, int flags)
{
	int count = 0, completed = 0;
	unsigned int total_size = 0;

	if (type == MEMCG_MEMORY)
		count = lowmem_kill_all_cgroup_victims(flags);
	else
		count = lowmem_kill_cgroup_victims(type, mi,
				MAX_CGROUP_VICTIMS, mi->threshold_leave,
				flags, &total_size, &completed);

	return count;
}

static int lowmem_oom_killer_cb(int type, struct memcg_info *mi, int flags)
{
	int count = 0;

	/* get multiple victims from /sys/fs/cgroup/memory/.../tasks */
	count = lowmem_kill_victims(type, mi, flags);

	if (count == 0) {
		_D("victim count = %d", count);
		return count;
	}

	/* check current memory status */
	if (!(flags & OOM_FORCE) && type != MEMCG_MEMORY &&
			lowmem_check_current_state(mi) >= 0)
		return count;

	clear_logs(MEMPS_LOG_PATH);
	return count;
}

static int lowmem_force_oom_killer(int flags, unsigned int should_be_freed,
	int max_victims)
{
	int count = 0, completed = 0, i;
	unsigned int total_size, freed = 0;

	lowmem_change_memory_state(LOWMEM_LOW, 1);
	for (i = MEMCG_MAX - 1; i >= MEMCG_BACKGROUND; i--) {
		int num_max = max_victims - count;
		unsigned int remained = should_be_freed - freed;
		count += lowmem_kill_cgroup_victims(i, memcg[i]->info,
			num_max, remained, flags, &total_size, &completed);
		freed += KBtoMB(total_size);
		_D("force kill total %d victims, freed = %u", count, freed);
		if (should_be_freed > 0 && freed >= should_be_freed)
			break;
	}
	lowmem_change_memory_state(LOWMEM_NORMAL, 0);

	return count;
}

static void *lowmem_oom_killer_pthread(void *arg)
{
	int ret = RESOURCED_ERROR_NONE;

	setpriority(PRIO_PROCESS, 0, OOM_KILLER_PRIORITY);

	while (1) {
		/*
		 * When signalled by main thread,
		 * it starts lowmem_oom_killer_cb().
		 */
		ret = pthread_mutex_lock(&oom_mutex);
		if (ret) {
			_E("oom thread::pthread_mutex_lock() failed, %d", ret);
			break;
		}

		ret = pthread_cond_wait(&oom_cond, &oom_mutex);
		if (ret) {
			_E("oom thread::pthread_cond_wait() failed, %d", ret);
			pthread_mutex_unlock(&oom_mutex);
			break;
		}

		_I("oom thread conditional signal received and start");
		lowmem_oom_killer_cb(MEMCG_MEMORY, memcg_memory, OOM_NONE);
		_I("lowmem_oom_killer_cb finished");

		ret = pthread_mutex_unlock(&oom_mutex);
		if (ret) {
			_E("oom thread::pthread_mutex_unlock() failed, %d", ret);
			break;
		}
	}

	/* Now our thread finishes - cleanup TID */
	oom_thread = 0;

	return NULL;
}

static char *convert_to_str(int mem_state)
{
	char *tmp = NULL;
	switch (mem_state) {
	case LOWMEM_NORMAL:
		tmp = "mem normal";
		break;
	case LOWMEM_SWAP:
		tmp = "mem swap";
		break;
	case LOWMEM_LOW:
		tmp = "mem low";
		break;
	case LOWMEM_MEDIUM:
		tmp = "mem medium";
		break;
	default:
		assert(0);
	}
	return tmp;
}

static void change_lowmem_state(unsigned int mem_state)
{
	if (cur_mem_state == mem_state)
		return;

	_I("[LOW MEM STATE] %s ==> %s", convert_to_str(cur_mem_state),
		convert_to_str(mem_state));
	cur_mem_state = mem_state;
}

static void lowmem_swap_memory(void)
{
	if (cur_mem_state == LOWMEM_NORMAL)
		return;

	resourced_notify(RESOURCED_NOTIFIER_SWAP_START, NULL);
}


static void normal_act(void)
{
	int ret, status;

	ret = vconf_get_int(VCONFKEY_SYSMAN_LOW_MEMORY, &status);
	if (ret)
		_D("vconf_get_int fail %s", VCONFKEY_SYSMAN_LOW_MEMORY);
	if (status != VCONFKEY_SYSMAN_LOW_MEMORY_NORMAL) {
		vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
			      VCONFKEY_SYSMAN_LOW_MEMORY_NORMAL);
		memory_level_send_system_event(MEMORY_LEVEL_NORMAL);
	}

	change_lowmem_state(LOWMEM_NORMAL);
	resourced_notify(RESOURCED_NOTIFIER_SWAP_UNSET_LIMIT, NULL);
	if (proc_get_freezer_status() == CGROUP_FREEZER_PAUSED)
		resourced_notify(RESOURCED_NOTIFIER_FREEZER_CGROUP_STATE,
			 (void *)CGROUP_FREEZER_ENABLED);
}

static void swap_act(void)
{
	int ret, status;

	ret = vconf_get_int(VCONFKEY_SYSMAN_LOW_MEMORY, &status);
	if (ret)
		_E("vconf get failed %s", VCONFKEY_SYSMAN_LOW_MEMORY);

	if (status != VCONFKEY_SYSMAN_LOW_MEMORY_NORMAL) {
		vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
				VCONFKEY_SYSMAN_LOW_MEMORY_NORMAL);
		memory_level_send_system_event(MEMORY_LEVEL_NORMAL);
	}
	change_lowmem_state(LOWMEM_SWAP);
	if (proc_get_freezer_status() == CGROUP_FREEZER_PAUSED)
		resourced_notify(RESOURCED_NOTIFIER_FREEZER_CGROUP_STATE,
			 (void *)CGROUP_FREEZER_ENABLED);
}

static void low_act(void)
{
	int ret, status;

	ret = vconf_get_int(VCONFKEY_SYSMAN_LOW_MEMORY, &status);

	if (ret)
		_D("vconf_get_int fail %s", VCONFKEY_SYSMAN_LOW_MEMORY);

	if (proc_get_freezer_status() == CGROUP_FREEZER_ENABLED)
		resourced_notify(RESOURCED_NOTIFIER_FREEZER_CGROUP_STATE,
			 (void *)CGROUP_FREEZER_PAUSED);
	change_lowmem_state(LOWMEM_LOW);

	/* Since vconf for soft warning could be set during low memory check,
	 * we set it only when the current status is not soft warning.
	 */
	if (status != VCONFKEY_SYSMAN_LOW_MEMORY_SOFT_WARNING) {
		vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
			      VCONFKEY_SYSMAN_LOW_MEMORY_SOFT_WARNING);
		memory_level_send_system_event(MEMORY_LEVEL_LOW);
	}
}

static Eina_Bool medium_cb(void *data)
{
	unsigned int available, threshold;
	int count = 0;

	available = proc_get_mem_available();
	_D("available = %u, timer run until reaching leave threshold", available);

	if (available >= memcg_memory->threshold_leave && oom_check_timer != NULL) {
		ecore_timer_del(oom_check_timer);
		oom_check_timer = NULL;
		_D("oom_check_timer deleted after reaching leave threshold");
		normal_act();
		fg_killed = 0;
		return ECORE_CALLBACK_CANCEL;
	}

	_I("available = %u cannot reach leave threshold %u, timer again",
		available, memcg_memory->threshold_leave);
	count = lowmem_oom_killer_cb(MEMCG_MEMORY,
			memcg_memory, OOM_TIMER_CHECK);

	/*
	 * After running oom killer in timer, but there is no victim,
	 * stop timer.
	 */
	threshold = memcg_memory->threshold[LOWMEM_MEDIUM];
	if (!count && available >= threshold &&
	    oom_check_timer != NULL) {
		ecore_timer_del(oom_check_timer);
		oom_check_timer = NULL;
		_D("oom_check_timer deleted, available %u > threshold %u, count = %d",
			available, threshold, count);
		normal_act();
		fg_killed = 0;
		return ECORE_CALLBACK_CANCEL;
	}
	return ECORE_CALLBACK_RENEW;
}

static void medium_act(void)
{
	int ret = 0;

	change_lowmem_state(LOWMEM_MEDIUM);

	/* signal to lowmem_oom_killer_pthread to start killer */
	ret = pthread_mutex_trylock(&oom_mutex);
	if (ret) {
		_E("medium_act::pthread_mutex_trylock() failed, %d, errno: %d", ret, errno);
		return;
	}
	_I("oom mutex trylock success");
	pthread_cond_signal(&oom_cond);
	_I("send signal to oom killer thread");
	pthread_mutex_unlock(&oom_mutex);

	vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
			VCONFKEY_SYSMAN_LOW_MEMORY_HARD_WARNING);
	memory_level_send_system_event(MEMORY_LEVEL_CRITICAL);

	if (oom_check_timer == NULL) {
		_D("timer run until reaching leave threshold");
		oom_check_timer =
			ecore_timer_add(OOM_TIMER_INTERVAL, medium_cb, (void *)NULL);
	}

	return;
}

static int lowmem_process(int mem_state)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(lpe); i++) {
		if ((cur_mem_state == lpe[i].cur_mem_state)
				&& (mem_state == lpe[i].new_mem_state)) {
			_D("cur_mem_state = %d, new_mem_state = %d\n",
				cur_mem_state, mem_state);
			lpe[i].action();
			return RESOURCED_ERROR_NONE;
		}

	}

	return RESOURCED_ERROR_NONE;
}

static void lowmem_dump_cgroup_procs(struct memcg_info *mi)
{
	int i;
	unsigned int size;
	pid_t pid;
	GArray *pids_array = g_array_new(false, false, sizeof(pid_t));

	memcg_get_pids(mi, pids_array);

	for (i = 0; i < pids_array->len; i++) {
		pid = g_array_index(pids_array, pid_t, i);
		get_proc_mem_usage(pid, &size);
		_E("pid = %d, size = %u KB", pid, size);
	}
	g_array_free(pids_array, TRUE);
}

static void memory_cgroup_medium_act(int type, struct memcg_info *mi)
{
	_I("[LOW MEM STATE] memory cgroup %s oom state",
		mi->name);

	/* To Do: only start to kill fg victim when no pending fg victim */
	lowmem_dump_cgroup_procs(mi);
	lowmem_oom_killer_cb(type, mi, OOM_NONE);
}

static unsigned int lowmem_eventfd_read(int fd)
{
	unsigned int ret;
	uint64_t dummy_state;
	ret = read(fd, &dummy_state, sizeof(dummy_state));
	return ret;
}

static unsigned int check_mem_state(unsigned int available)
{
	int mem_state;
	for (mem_state = LOWMEM_MAX_LEVEL - 1; mem_state > LOWMEM_NORMAL; mem_state--) {
		if (available <= memcg_memory->threshold[mem_state])
			break;
	}

	return mem_state;
}

static void lowmem_memory_handler(void)
{
	static unsigned int prev_available;
	unsigned int available;
	int mem_state;

	available = proc_get_mem_available();

	if (prev_available == available)
		return;

	mem_state = check_mem_state(available);
	lowmem_process(mem_state);
	prev_available = available;
}

static void lowmem_cgroup_handler(int type, struct memcg_info *mi)
{
	unsigned int usage, threshold;
	int ret;

	ret = memcg_get_anon_usage(mi, &usage);

	if (ret) {
		_D("getting anonymous memory usage fails");
		return;
	}
	threshold = mi->threshold[LOWMEM_MEDIUM];
	if (usage >= threshold)
		memory_cgroup_medium_act(type, mi);
	else
		_I("anon page (%u) is under medium threshold (%u)",
			usage >> 20, threshold >> 20);
}

static Eina_Bool lowmem_cb(void *data, Ecore_Fd_Handler *fd_handler)
{
	int fd, i;
	struct memcg_info *mi;
	GSList *iter = NULL;

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

	for (i = 0; i < MEMCG_MAX; i++) {
		if (!memcg[i] || !memcg[i]->info)
			continue;
		mi = memcg[i]->info;
		if (fd == mi->evfd) {
			/* call low memory handler for this memcg */
			if (i == MEMCG_MEMORY)
				lowmem_memory_handler();
			else
				lowmem_cgroup_handler(i, mi);
			return ECORE_CALLBACK_RENEW;
		}
		/* ToDo: iterate child memcgs */
		gslist_for_each_item(iter, memcg[i]->cgroups) {
			mi = (struct memcg_info *)(iter->data);
			if (fd == mi->evfd) {
				lowmem_cgroup_handler(i, mi);
				_D("lowmem cgroup handler is called for %s",
					mi->name);
				return ECORE_CALLBACK_RENEW;
			}
		}
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

static void register_eventfd(struct memcg_info *mi)
{
	int cgfd, pressurefd, evfd, res, sz;
	char buf[BUF_MAX] = {0,};
	const char *name = mi->name;

	if (mi->threshold[LOWMEM_MEDIUM] == LOWMEM_THRES_INIT)
		return;

	/* open cgroup.event_control */
	snprintf(buf, sizeof(buf), "%scgroup.event_control", name);
	cgfd = open(buf, O_WRONLY);
	if (cgfd < 0) {
		_E("open event_control failed");
		return;
	}

	/* register event pressure_level */
	snprintf(buf, sizeof(buf), "%smemory.pressure_level", name);
	pressurefd = open(buf, O_RDONLY);
	if (pressurefd < 0) {
		_E("open pressure control failed");
		close(cgfd);
		return;
	}

	/* create an eventfd using eventfd(2)
	   use same event fd for using ecore event loop */
	evfd = eventfd(0, O_NONBLOCK);
	if (evfd < 0) {
		_E("eventfd() error");
		close(cgfd);
		close(pressurefd);
		return;
	}
	mi->evfd = evfd;

	/* pressure level*/
	/* write event fd low level */
	sz = snprintf(buf, sizeof(buf), "%d %d %s", evfd, pressurefd, mi->event_level);
	sz += 1;
	res = write(cgfd, buf, sz);
	if (res != sz) {
		_E("write cgfd failed : %d for %s", res, name);
		close(cgfd);
		close(pressurefd);
		close(evfd);
		mi->evfd = -1;
		return;
	}

	_I("register event fd success for %s cgroup", name);
	ecore_main_fd_handler_add(evfd, ECORE_FD_READ,
			(Ecore_Fd_Cb)lowmem_cb, NULL, NULL, NULL);

	close(cgfd);
	close(pressurefd);
	return;
}

static int setup_eventfd(void)
{
	unsigned int i;
	struct memcg_info *mi;
	GSList *iter = NULL;

	for (i = 0; i < MEMCG_MAX; i++) {
		if (!memcg[i]->use_hierarchy) {
			register_eventfd(memcg[i]->info);
		} else {
			GSList *list = memcg[i]->cgroups;
			gslist_for_each_item(iter, list) {
				mi = (struct memcg_info *)(iter->data);
				register_eventfd(mi);
			}
		}
	}
	return RESOURCED_ERROR_NONE;
}

static int load_mem_config(struct parse_result *result, void *user_data)
{
	pid_t pid = 0;
	if (!result)
		return -EINVAL;

	if (strcmp(result->section, MEM_CONF_SECTION))
		return RESOURCED_ERROR_NONE;

	if (!strcmp(result->name, MEM_CONF_PREDEFINE)) {
		pid = find_pid_from_cmdline(result->value);
		if (pid > 0)
			proc_set_oom_score_adj(pid, OOMADJ_SERVICE_MIN);
	}
	return RESOURCED_ERROR_NONE;
}

static int set_memory_config(const char *section_name, const struct parse_result *result)
{
	if (!result || !section_name)
		return -EINVAL;

	if (strcmp(result->section, section_name))
		return RESOURCED_ERROR_NONE;

	if (!strcmp(result->name, "ThresholdSwap")) {
		int value = atoi(result->value);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_SWAP, value);
	} else if (!strcmp(result->name, "ThresholdLow")) {
		int value = atoi(result->value);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_LOW, value);
	} else if (!strcmp(result->name, "ThresholdMedium")) {
		int value = atoi(result->value);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_MEDIUM, value);
	} else if (!strcmp(result->name, "ThresholdLeave")) {
		int value = atoi(result->value);
		lowmem_memcg_set_leave_threshold(MEMCG_MEMORY, value);
	} else if (!strcmp(result->name, "ForegroundRatio")) {
		float ratio = atof(result->value);
		memcg_info_set_limit(memcg[MEMCG_FOREGROUND]->info, ratio, totalram);
	} else if (!strcmp(result->name, "ForegroundUseHierarchy")) {
		int use_hierarchy = atoi(result->value);
		memcg[MEMCG_FOREGROUND]->use_hierarchy = use_hierarchy;
	} else if (!strcmp(result->name, "ForegroundNumCgroups")) {
		int num_cgroups = atoi(result->value);
		memcg_add_cgroups(memcg[MEMCG_FOREGROUND],
			num_cgroups);
		memcg_show(memcg[MEMCG_FOREGROUND]);
	} else if (!strcmp(result->name, "NumMaxVictims")) {
		int value = atoi(result->value);
		num_max_victims = value;
		_D("set number of max victims as %d", num_max_victims);
	} else if (!strcmp(result->name, "DynamicThreshold")) {
		int value = atoi(result->value);
		proactive_threshold = value;
		_D("set dynamic process threshold as %d", proactive_threshold);
	} else if (!strcmp(result->name, "DynamicLeave")) {
		int value = atoi(result->value);
		proactive_leave = value;
		_D("set dynamic process leave threshold as %d", proactive_leave);
	}
	return RESOURCED_ERROR_NONE;
}

static int memory_load_64_config(struct parse_result *result, void *user_data)
{
       return set_memory_config("Memory64", result);
}

static int memory_load_256_config(struct parse_result *result, void *user_data)
{
       return set_memory_config("Memory256", result);
}

static int memory_load_512_config(struct parse_result *result, void *user_data)
{
       return set_memory_config("Memory512", result);
}

static int memory_load_768_config(struct parse_result *result, void *user_data)
{
       return set_memory_config("Memory768", result);
}

static int memory_load_1024_config(struct parse_result *result, void *user_data)
{
       return set_memory_config("Memory1024", result);
}

static int memory_load_2048_config(struct parse_result *result, void *user_data)
{
       return set_memory_config("Memory2048", result);
}

/* setup memcg parameters depending on total ram size. */
static void setup_memcg_params(void)
{
	int i;
	unsigned long total_ramsize = BtoMB(totalram);
	_D("Total : %lu MB", total_ramsize);
	if (total_ramsize <= MEM_SIZE_64) {
		/* set thresholds for ram size 64M */
		proactive_threshold = DYNAMIC_PROCESS_64_THRES;
		proactive_leave = DYNAMIC_PROCESS_64_LEAVE;
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_SWAP, MEMCG_MEMORY_64_THRES_SWAP);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_LOW, MEMCG_MEMORY_64_THRES_LOW);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_MEDIUM, MEMCG_MEMORY_64_THRES_MEDIUM);
		lowmem_memcg_set_leave_threshold(MEMCG_MEMORY, MEMCG_MEMORY_64_THRES_LEAVE);
		config_parse(MEM_CONF_FILE, memory_load_64_config, NULL);
	} else if (total_ramsize <= MEM_SIZE_256) {
		/* set thresholds for ram size 256M */
		proactive_threshold = DYNAMIC_PROCESS_256_THRES;
		proactive_leave = DYNAMIC_PROCESS_256_LEAVE;
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_SWAP, MEMCG_MEMORY_256_THRES_SWAP);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_LOW, MEMCG_MEMORY_256_THRES_LOW);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_MEDIUM, MEMCG_MEMORY_256_THRES_MEDIUM);
		lowmem_memcg_set_leave_threshold(MEMCG_MEMORY, MEMCG_MEMORY_256_THRES_LEAVE);
		config_parse(MEM_CONF_FILE, memory_load_256_config, NULL);
	} else if (total_ramsize <= MEM_SIZE_512) {
		/* set thresholds for ram size 512M */
		proactive_threshold = DYNAMIC_PROCESS_512_THRES;
		proactive_leave = DYNAMIC_PROCESS_512_LEAVE;
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_SWAP, MEMCG_MEMORY_512_THRES_SWAP);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_LOW, MEMCG_MEMORY_512_THRES_LOW);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_MEDIUM, MEMCG_MEMORY_512_THRES_MEDIUM);
		lowmem_memcg_set_leave_threshold(MEMCG_MEMORY, MEMCG_MEMORY_512_THRES_LEAVE);
		config_parse(MEM_CONF_FILE, memory_load_512_config, NULL);
	}  else if (total_ramsize <= MEM_SIZE_768) {
		/* set thresholds for ram size 512M */
		proactive_threshold = DYNAMIC_PROCESS_768_THRES;
		proactive_leave = DYNAMIC_PROCESS_768_LEAVE;
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_SWAP, MEMCG_MEMORY_768_THRES_SWAP);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_LOW, MEMCG_MEMORY_768_THRES_LOW);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_MEDIUM, MEMCG_MEMORY_768_THRES_MEDIUM);
		lowmem_memcg_set_leave_threshold(MEMCG_MEMORY, MEMCG_MEMORY_768_THRES_LEAVE);
		config_parse(MEM_CONF_FILE, memory_load_768_config, NULL);
	} else if (total_ramsize <= MEM_SIZE_1024) {
		/* set thresholds for ram size more than 1G */
		proactive_threshold = DYNAMIC_PROCESS_1024_THRES;
		proactive_leave = DYNAMIC_PROCESS_1024_LEAVE;
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_SWAP, MEMCG_MEMORY_1024_THRES_SWAP);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_LOW, MEMCG_MEMORY_1024_THRES_LOW);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_MEDIUM, MEMCG_MEMORY_1024_THRES_MEDIUM);
		lowmem_memcg_set_leave_threshold(MEMCG_MEMORY, MEMCG_MEMORY_1024_THRES_LEAVE);
		config_parse(MEM_CONF_FILE, memory_load_1024_config, NULL);
	} else {
		proactive_threshold = DYNAMIC_PROCESS_2048_THRES;
		proactive_leave = DYNAMIC_PROCESS_2048_LEAVE;
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_SWAP, MEMCG_MEMORY_2048_THRES_SWAP);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_LOW, MEMCG_MEMORY_2048_THRES_LOW);
		lowmem_memcg_set_threshold(MEMCG_MEMORY, LOWMEM_MEDIUM, MEMCG_MEMORY_2048_THRES_MEDIUM);
		lowmem_memcg_set_leave_threshold(MEMCG_MEMORY, MEMCG_MEMORY_2048_THRES_LEAVE);
		config_parse(MEM_CONF_FILE, memory_load_2048_config, NULL);
	}

	for (i = LOWMEM_SWAP; i < LOWMEM_MAX_LEVEL; i++)
		_I("set threshold for %d to %u", i, memcg_memory->threshold[i]);

	_I("set thres_leave to %u", memcg_memory->threshold_leave);
	_I("set dynamic process threshold to %u", proactive_threshold);
	_I("set dynamic process leave to %u", proactive_leave);
}

static int init_memcg_params(void)
{
	int idx = 0;
	char buf[MAX_PATH_LENGTH];
	memcg = (struct memcg **)malloc(sizeof(struct memcg *) *
		MEMCG_MAX);
	if (!memcg)
		return RESOURCED_ERROR_FAIL;

	for (idx = 0; idx < MEMCG_MAX; idx++) {
		struct memcg_info *mi = NULL;
		memcg[idx] = (struct memcg *)malloc(sizeof(struct memcg));
		if (!memcg[idx]) {
			int i;
			for (i = 0; i < idx - 1; i++)
				free(memcg[i]);
			free(memcg);
			return RESOURCED_ERROR_FAIL;
		}
		memcg_init(memcg[idx]);
		if (memcg_name[idx])
			snprintf(buf, MAX_PATH_LENGTH, "%s/%s/", LOWMEM_DEFAULT_CGROUP,
					memcg_name[idx]);
		else
			snprintf(buf, MAX_PATH_LENGTH, "%s/", LOWMEM_DEFAULT_CGROUP);
		mi = (struct memcg_info *)malloc(sizeof(struct memcg_info));
		if (!mi) {
			int i;
			for (i = 0; i < idx; i++)
				free(memcg[i]);
			free(memcg);
			return RESOURCED_ERROR_FAIL;
		}
		memcg_info_init(mi, buf);
		memcg[idx]->info = mi;
		_I("init memory cgroup for %s", buf);
		if (idx == MEMCG_MEMORY)
			memcg_memory = memcg[idx]->info;
	}
	return RESOURCED_ERROR_NONE;
}

static int write_params_memcg_info(struct memcg_info *mi,
	int write_limit)
{
	unsigned int limit = mi->limit;
	const char *name = mi->name;
	int ret = RESOURCED_ERROR_NONE;
	_I("write memcg param for %s", name);
	/* enable cgroup move */
	ret = cgroup_write_node(name,
			MEMCG_MOVE_CHARGE_PATH, 3);
	if (ret)
		return ret;

	/*
	 * for memcg with LOWMEM_NO_LIMIT or write_limit is not set,
	 * do not set limit for cgroup limit.
	 */
	if (mi->limit_ratio == LOWMEM_NO_LIMIT ||
		!write_limit)
		return ret;

	/* disable memcg OOM-killer */
	ret = cgroup_write_node(name,
			MEMCG_OOM_CONTROL_PATH, 1);
	if (ret)
		return ret;

	/* write limit_in_bytes */
	ret = cgroup_write_node(name,
			MEMCG_LIMIT_PATH, limit);
	_I("set %s's limit to %u", name, limit);
	return ret;
}

static int write_memcg_params(void)
{
	unsigned int i;
	_D("Total : %lu", totalram);
	int ret = RESOURCED_ERROR_NONE;
	GSList *iter = NULL;

	for (i = 0; i < MEMCG_MAX; i++) {
		struct memcg_info *mi = memcg[i]->info;
		int write_limit = !memcg[i]->use_hierarchy;
		GSList *list = memcg[i]->cgroups;
		write_params_memcg_info(mi, write_limit);
		/* write limit to the node for sub cgroups */
		write_limit = 1;
		/* write node for sub cgroups */
		gslist_for_each_item(iter, list) {
			struct memcg_info *mi =
				(struct memcg_info *)(iter->data);
			write_params_memcg_info(mi, write_limit);
		}
	}

	return ret;
}

static void lowmem_check(void)
{
	unsigned int available;

	available = proc_get_mem_available();
	_D("available = %u", available);

	if (cur_mem_state != LOWMEM_SWAP &&
		(available <= memcg_memory->threshold[LOWMEM_SWAP] &&
			available > memcg_memory->threshold[LOWMEM_LOW])) {
		swap_act();

	}
}

static struct memcg_info *find_foreground_cgroup(struct proc_app_info *pai)
{
	unsigned int usage;
	unsigned int min_usage = UINT_MAX;
	struct memcg_info *min_mi = NULL, *mi;
	GSList *iter = NULL;

	/*
	 * if this process group is already in one of the foreground cgroup,
	 * put all of the process in this group into the same cgroup.
	 */
	if (pai &&
		pai->memcg_idx == MEMCG_FOREGROUND) {
		_D("%s is already in foreground", pai->appid);
		return pai->memcg_info;
	}

	/*
	 * if any of the process in this group is not in foreground,
	 * find foreground cgroup with minimum usage
	 */
	if (memcg[MEMCG_FOREGROUND]->use_hierarchy) {
		gslist_for_each_item(iter,
			memcg[MEMCG_FOREGROUND]->cgroups) {
			mi = (struct memcg_info *)(iter->data);

			memcg_get_usage(mi, &usage);
			/* select foreground memcg with no task first */
			if (usage == 0) {
				_D("%s' usage is 0, selected", mi->name);
					return mi;
			}

			/* select forground memcg with minimum usage */
			if (usage > 0 && min_usage > usage) {
				min_usage = usage;
				min_mi = mi;
			}
		}
		_D("%s is selected at min usage = %u",
			min_mi->name, min_usage);

	} else {
		return memcg[MEMCG_FOREGROUND]->info;
	}

	return min_mi;
}

static void lowmem_move_memcgroup(int pid, int oom_score_adj)
{
	struct proc_app_info *pai = find_app_info(pid);
	struct memcg_info *mi;
	int background = 0;
	int memcg_idx;

	if (oom_score_adj >= OOMADJ_SERVICE_BACKGRD) {
		memcg_idx = MEMCG_BACKGROUND;
		mi = memcg[memcg_idx]->info;
		background = 1;
	} else if (oom_score_adj == OOMADJ_FAVORITE) {
		memcg_idx = MEMCG_FAVORITE;
		mi = memcg[memcg_idx]->info;
	} else if (oom_score_adj >= OOMADJ_BACKGRD_PERCEPTIBLE) {
		memcg_idx = MEMCG_SERVICE;
		mi = memcg[memcg_idx]->info;
	} else if (oom_score_adj >= OOMADJ_FOREGRD_LOCKED) {
		memcg_idx = MEMCG_FOREGROUND;
		mi = find_foreground_cgroup(pai);
	} else {
		return;
	}

	if (!swap_check_swap_pid(pid) || !background) {
		_D("name : %s, pid : %d, score : %d",
			mi->name, pid, oom_score_adj);
		cgroup_write_node(mi->name, CGROUP_FILE_NAME, pid);
	}

	proc_set_process_info_memcg(pai, memcg_idx, mi);

	if (background) {
		lowmem_check();
		lowmem_swap_memory();
	}
}

static int oom_thread_create(void)
{
	int ret = RESOURCED_ERROR_NONE;

	if (oom_thread) {
		_I("oom thread %u already created", (unsigned)oom_thread);
	} else {
		/* initialize oom killer thread */
		ret = pthread_create(&oom_thread, NULL, (void *)lowmem_oom_killer_pthread, (void *)NULL);
		if (ret) {
			_E("pthread creation for lowmem_oom_killer_pthread failed, %d\n", ret);
			oom_thread = 0;
		} else {
			pthread_detach(oom_thread);
		}
	}

	return ret;
}

static int create_memcgs(void)
{
	int i = 0;
	int ret = RESOURCED_ERROR_NONE;
	GSList *iter = NULL;
	struct memcg_info *mi;
	char *name;

	/* skip for memory cgroup */
	for (i = 0; i < MEMCG_MAX; i++) {
		if (!memcg_name[i])
			continue;
		mi = memcg[i]->info;
		name = mi->name;
		ret = make_cgroup_subdir(NULL, name, NULL);
		if (!memcg[i]->use_hierarchy)
			continue;
		_D("create memory cgroup for %s, ret = %d", name, ret);
		/* create sub cgroups */
		gslist_for_each_item(iter, memcg[i]->cgroups) {
			mi = (struct memcg_info *)
					iter->data;
			name = mi->name;
			ret = make_cgroup_subdir(NULL, name, NULL);
			_D("make cgroup subdir for %s, ret = %d", name, ret);
		}
	}

	return ret;
}

static int resourced_memory_control(void *data)
{
	int ret = RESOURCED_ERROR_NONE;
	struct lowmem_data_type *l_data;

	l_data = (struct lowmem_data_type *)data;
	switch (l_data->control_type) {
	case LOWMEM_MOVE_CGROUP:
		if (l_data->args) {
			_D("resourced_memory_control: %d %d", (pid_t)l_data->args[0], l_data->args[1]);
			lowmem_move_memcgroup((pid_t)l_data->args[0], l_data->args[1]);
		}
		break;
	default:
		break;
	}
	return ret;
}

/* To Do: should we need lowmem_fd_start, lowmem_fd_stop ?? */
int lowmem_init(void)
{
	int ret = RESOURCED_ERROR_NONE;

	get_total_memory();

	init_memcg_params();
	setup_memcg_params();
	config_parse(MEM_CONF_FILE, load_mem_config, NULL);

	create_memcgs();
	write_memcg_params();

	ret = oom_thread_create();
	if (ret) {
		_E("oom thread create failed\n");
		return ret;
	}

	/* register threshold and event fd */
	ret = setup_eventfd();
	if (ret) {
		_E("eventfd setup failed");
		return ret;
	}

	lowmem_dbus_init();

	return ret;
}

static int lowmem_exit(void)
{
	int i;
	for (i = 0; i < MEMCG_MAX; i++) {
		g_slist_free_full(memcg[i]->cgroups, free);
		free(memcg[i]->info);
		free(memcg[i]);
	}
	return RESOURCED_ERROR_NONE;
}

static int resourced_memory_init(void *data)
{
	lowmem_ops = &memory_modules_ops;
	return lowmem_init();
}

static int resourced_memory_finalize(void *data)
{
	return lowmem_exit();
}

int lowmem_memory_oom_killer(int flags)
{
	if (flags & OOM_FORCE)
		return lowmem_force_oom_killer(flags, 0, MAX_FD_VICTIMS);
	return lowmem_oom_killer_cb(MEMCG_MEMORY, memcg_memory, flags);
}

int lowmem_proactive_oom_killer(int flags, char *appid)
{
	int count = 0;
	unsigned int should_be_freed;
	unsigned int before;

#ifdef HEART_SUPPORT
	struct logging_memory_data *md;
#endif

	before = proc_get_mem_available();

	/* If low memory state, just return and kill in oom killer */
	if (before < memcg_memory->threshold[LOWMEM_MEDIUM])
		return RESOURCED_ERROR_FAIL;

#ifdef HEART_SUPPORT
	md = logging_memory_get_data(appid, LOGGING_6HOUR);

	if (md) {
		unsigned int uss;

		uss = KBtoMB(md->avg_uss);

		free(md);

		/*
		 * if launching app is predicted to consume all memory,
		 * free memory up to leave threshold after launching the app.
		 */
		if (before <= uss) {
			should_be_freed = memcg_memory->threshold_leave + uss;
			lowmem_force_oom_killer(OOM_FORCE, should_be_freed, num_max_victims);
			return RESOURCED_ERROR_NONE;
		}

		unsigned int after = before - uss;
		_D("available after launch = %u, available = %u, uss = %u",
			after, before, uss);

		/*
		 * after launching app, ensure that available memory is
		 * above threshold_leave
		 */
		 if (after >= memcg_memory->threshold[LOWMEM_MEDIUM])
			return RESOURCED_ERROR_FAIL;

		 should_be_freed = memcg_memory->threshold_leave +
			 THRESHOLD_MARGIN - after;
		 _D("run history based proactive killer, should_be_freed = %u",
			should_be_freed);
		lowmem_force_oom_killer(OOM_FORCE, should_be_freed, num_max_victims);

		return RESOURCED_ERROR_NONE;
	}
#endif

	/*
	 * When there is no history data for the launching app but it is
	 * indicated as PROC_LARGEMEMORY, run oom killer based on dynamic
	 * threshold.
	 */
	if (!(flags & PROC_LARGEMEMORY))
		return RESOURCED_ERROR_FAIL;
	/*
	 * run proactive oom killer only when available is larger than
	 * dynamic process threshold
	 */
	if (!proactive_threshold || before >= proactive_threshold)
		return RESOURCED_ERROR_FAIL;

	/*
	 * free THRESHOLD_MARGIN more than real should be freed,
	 * because launching app is consuming up the memory.
	 */
	should_be_freed = proactive_leave - before + THRESHOLD_MARGIN;
	_D("run threshold based proactive killer, should_be_freed = %u",
			should_be_freed);

	count = lowmem_force_oom_killer(OOM_FORCE, should_be_freed, num_max_victims);
	_D("kill %d victim total", count);

	return RESOURCED_ERROR_NONE;
}

void lowmem_change_memory_state(int state, int force)
{
	int mem_state;

	if (force) {
		mem_state = state;
	} else {
		unsigned int available = proc_get_mem_available();
		mem_state = check_mem_state(available);
		_D("available = %u, mem_state = %d", available, mem_state);
	}

	switch (mem_state) {
	case LOWMEM_NORMAL:
		normal_act();
		break;
	case LOWMEM_SWAP:
		swap_act();
		break;
	case LOWMEM_LOW:
		low_act();
		break;
	case LOWMEM_MEDIUM:
		medium_act();
		break;
	default:
		assert(0);
	}
}

void lowmem_memcg_set_threshold(int type, int level, int value)
{
	memcg[type]->info->threshold[level] = value;
}

void lowmem_memcg_set_leave_threshold(int type, int value)
{
	memcg[type]->info->threshold_leave = value;
}

unsigned long lowmem_get_ktotalram(void)
{
	return ktotalram;
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
