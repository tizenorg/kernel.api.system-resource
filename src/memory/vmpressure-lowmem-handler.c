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
#include <stdbool.h>
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
#include <sys/sysinfo.h>
#include <Ecore.h>

#include "trace.h"
#include "proc-main.h"
#include "lowmem-handler.h"
#include "proc-process.h"
#include "lowmem-common.h"
#include "resourced.h"
#include "macro.h"
#include "config-parser.h"
#include "module.h"

#define MEMINFO_PATH			"/proc/meminfo"
#define MEMCG_PATH			"/sys/fs/cgroup"
#define MEMPS_LOG_FILE			"/var/log/memps"
#define MEMPS_EXEC_PATH			"usr/bin/memps"
#define MEMCG_MOVE_CHARGE_PATH		"memory.move_charge_at_immigrate"
#define MEMCG_OOM_CONTROL_PATH		"memory.oom_control"
#define MEMCG_LIMIT_PATH		"memory.limit_in_bytes"
#define MEM_CONF_FILE                   "/etc/resourced/memory.conf"
#define MEM_CONF_SECTION                "VIP_PROCESS"
#define MEM_CONF_PREDEFINE              "PREDEFINE"

#define BtoMB(x)			((x) >> 20)
#define BtoKB(x)			((x) >> 10)
#define BtoPAGE(x)			((x) >> 12)

#define NO_LIMIT			-1
/* for memory cgroup, set no limit */
#define MEMCG_MEMORY_LIMIT_RATIO	NO_LIMIT
#define MEMCG_FOREGROUND_LIMIT_RATIO	1
/* for background cgroup, set no limit */
#define MEMCG_BACKGROUND_LIMIT_RATIO	NO_LIMIT
#define MEMCG_FOREGROUND_MIN_LIMIT	UINT_MAX
#define MEMCG_BACKGROUND_MIN_LIMIT	UINT_MAX
#define MEMCG_LOW_RATIO			0.8
#define MEMCG_MEDIUM_RATIO		0.96
#define MEMCG_FOREGROUND_THRES_LEAVE	100 /* MB */
#define MEMCG_FOREGROUND_LEAVE_RATIO	0.25

#define BUF_MAX				1024
#define LOWMEM_PATH_MAX			100
#define MAX_MEMORY_CGROUP_VICTIMS 	10
#define MAX_CGROUP_VICTIMS 		1
#define OOM_TIMER_INTERVAL		2
#define MAX_TIMER_CHECK 		10
#define OOM_MULTIKILL_WAIT		(1000*1000)
#define OOM_SCORE_POINT_WEIGHT		1500
#define MAX_FD_VICTIMS			10

#define MEM_SIZE_64			64  /* MB */
#define MEM_SIZE_256			256 /* MB */
#define MEM_SIZE_512			512 /* MB */
#define MEM_SIZE_1024			1024 /* MB */
#define MEM_SIZE_2048			2048 /* MB */

/* thresholds for 64M RAM*/
#define MEMCG_MEMORY_64_THRES_LOW		8 /* MB */
#define MEMCG_MEMORY_64_THRES_MEDIUM		5 /* MB */
#define MEMCG_MEMORY_64_THRES_LEAVE		8 /* MB */

/* thresholds for 256M RAM */
#define MEMCG_MEMORY_256_THRES_LOW		20 /* MB */
#define MEMCG_MEMORY_256_THRES_MEDIUM		10 /* MB */
#define MEMCG_MEMORY_256_THRES_LEAVE		20 /* MB */

/* threshold for 512M RAM */
#define MEMCG_MEMORY_512_THRES_LOW		50 /* MB */
#define MEMCG_MEMORY_512_THRES_MEDIUM		40 /* MB */
#define MEMCG_MEMORY_512_THRES_LEAVE		60 /* MB */

/* threshold for more than 1024M RAM */
#define MEMCG_MEMORY_1024_THRES_LOW		200 /* MB */
#define MEMCG_MEMORY_1024_THRES_MEDIUM		100 /* MB */
#define MEMCG_MEMORY_1024_THRES_LEAVE		150 /* MB */

/* threshold for more than 2048M RAM */
#define MEMCG_MEMORY_2048_THRES_LOW		200 /* MB */
#define MEMCG_MEMORY_2048_THRES_MEDIUM		160 /* MB */
#define MEMCG_MEMORY_2048_THRES_LEAVE		300 /* MB */

enum {
	MEMNOTIFY_NORMAL,
	MEMNOTIFY_LOW,
	MEMNOTIFY_MEDIUM,
	MEMNOTIFY_MAX_LEVELS,
};

static int thresholds[MEMNOTIFY_MAX_LEVELS];

struct task_info {
	pid_t pid;
	pid_t pgid;
	int oom_score_adj;
	int size;
};

struct memcg_class {
	unsigned int min_limit;  /* minimum limit */
	/* limit ratio, if don't want to set limit, use NO_LIMIT*/
	float limit_ratio;
	unsigned int oomleave; 	/* leave memory usage */
	char *cgroup_name;	/* cgroup name */
	unsigned int thres_low; /* low level threshold */
	unsigned int thres_medium; /* medium level threshold */
	unsigned int thres_leave;  /* leave threshold */
	/* vmpressure event string. If don't want to register event, use null */
	char *event_string;
	/* compare function for selecting victims in each cgroup */
	int (*compare_fn) (const struct task_info *, const struct task_info *);
};

struct lowmem_process_entry {
	int cur_mem_state;
	int new_mem_state;
	void (*action) (void);
};

struct mem_info {
	unsigned real_free;
	unsigned reclaimable;
};

/* low memory action function for cgroup */
static void memory_cgroup_medium_act(int memcg_idx);
static int compare_mem_victims(const struct task_info *ta, const struct task_info *tb);
static int compare_bg_victims(const struct task_info *ta, const struct task_info *tb);
static int compare_fg_victims(const struct task_info *ta, const struct task_info *tb);
/* low memory action function */
static void normal_act(void);
static void low_act(void);
static void medium_act(void);

static Eina_Bool medium_cb(void *data);

#define LOWMEM_ENTRY(c, n, act)		\
	{ MEMNOTIFY_##c, MEMNOTIFY_##n, act}

static struct lowmem_process_entry lpe[] = {
	LOWMEM_ENTRY(NORMAL,	LOW,		low_act),
	LOWMEM_ENTRY(NORMAL,	MEDIUM,		medium_act),
	LOWMEM_ENTRY(LOW, 	NORMAL, 	normal_act),
	LOWMEM_ENTRY(LOW, 	MEDIUM, 	medium_act),
	LOWMEM_ENTRY(MEDIUM,	NORMAL, 	normal_act),
	LOWMEM_ENTRY(MEDIUM,	LOW, 		low_act),
};

static struct memcg_class memcg_class[MEMCG_MAX_GROUPS] = {
	{NO_LIMIT,			MEMCG_MEMORY_LIMIT_RATIO,
	0,				"memory",
	0,				0,
	0,				"medium", /* register medium event*/
	compare_mem_victims},
	{MEMCG_FOREGROUND_MIN_LIMIT,	MEMCG_FOREGROUND_LIMIT_RATIO,
	0,				"memory/foreground1",
	0,				0,
	MEMCG_FOREGROUND_THRES_LEAVE,	"medium",
	compare_fg_victims},
	{MEMCG_FOREGROUND_MIN_LIMIT,	MEMCG_FOREGROUND_LIMIT_RATIO,
	0,				"memory/foreground2",
	0,				0,
	MEMCG_FOREGROUND_THRES_LEAVE,	"medium",
	compare_fg_victims},
	{MEMCG_FOREGROUND_MIN_LIMIT,	MEMCG_FOREGROUND_LIMIT_RATIO,
	0,				"memory/foreground3",
	0,				0,
	MEMCG_FOREGROUND_THRES_LEAVE,	"medium",
	compare_fg_victims},
	{MEMCG_BACKGROUND_MIN_LIMIT,	MEMCG_BACKGROUND_LIMIT_RATIO,
	0,				"memory/background",
	0,				0,
	0,				NULL, /* register no event*/
	compare_bg_victims},
};

static int evfd[MEMCG_MAX_GROUPS] = {-1, };
static int cur_mem_state = MEMNOTIFY_NORMAL;
static Ecore_Timer *oom_check_timer = NULL;
static pid_t killed_fg_victim;

static pthread_t	oom_thread	= 0;
static pthread_mutex_t	oom_mutex	= PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	oom_cond	= PTHREAD_COND_INITIALIZER;

static unsigned long totalram;
static unsigned long ktotalram;
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

static void get_mem_info(struct mem_info *mi)
{
	char buf[PATH_MAX];
	FILE *fp;
	char *idx;
	unsigned int tfree = 0, tactive_file = 0, tinactive_file = 0;

	fp = fopen(MEMINFO_PATH, "r");

	if (!fp) {
		_E("%s open failed, %d", buf, fp);
		return;
	}

	while (fgets(buf, PATH_MAX, fp) != NULL) {
		if ((idx = strstr(buf, "MemFree:"))) {
			idx += strlen("MemFree:");
			while (*idx < '0' || *idx > '9')
				idx++;
			tfree = atoi(idx);
			tfree >>= 10;
		} else if((idx = strstr(buf, "Active(file):"))) {
			idx += strlen("Active(file):");
			while (*idx < '0' || *idx > '9')
				idx++;
			tactive_file = atoi(idx);
			tactive_file >>= 10;
		} else if((idx = strstr(buf, "Inactive(file):"))) {
			idx += strlen("Inactive(file):");
			while (*idx < '0' || *idx > '9')
				idx++;
			tinactive_file = atoi(idx);
			tinactive_file >>= 10;
			break;
		}
	}

	mi->real_free = tfree;
	mi->reclaimable = tactive_file + tinactive_file;
	fclose(fp);
}

static bool get_mem_usage_by_pid(pid_t pid, unsigned int *rss)
{
	FILE *fp;
	char proc_path[PATH_MAX];

	sprintf(proc_path, "/proc/%d/statm", pid);
	fp = fopen(proc_path, "r");
	if (fp == NULL)
		return false;

	if (fscanf(fp, "%*s %d", rss) < 1) {
		fclose(fp);
		return false;
	}

	fclose(fp);

	/* convert page to Kb */
	*rss *= 4;
	return true;
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

static int get_mem_usage_anon(int idx, unsigned int *result)
{
	FILE *f;
	char buf[LOWMEM_PATH_MAX] = {0,};
	char line[BUF_MAX] = {0, };
	char name[30] = {0, };
	unsigned int tmp, active_anon = 0, inactive_anon = 0;

	sprintf(buf, "%s/%s/memory.stat",
			MEMCG_PATH, memcg_class[idx].cgroup_name);

	f = fopen(buf, "r");
	if (!f) {
		_E("%s open failed, %d", buf, f);
		return RESOURCED_ERROR_FAIL;
	}
	while (fgets(line, BUF_MAX, f) != NULL) {
		if (sscanf(line, "%s %d", name, &tmp)) {
			if (!strcmp(name, "inactive_anon")) {
				inactive_anon = tmp;
			} else if (!strcmp(name, "active_anon")) {
				active_anon = tmp;
				break;
			}
		}
	}
	fclose(f);
	*result = active_anon + inactive_anon;

	return RESOURCED_ERROR_NONE;
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

static int lowmem_check_current_state(int memcg_index)
{
	unsigned int usage, oomleave;
	int ret;

	oomleave = memcg_class[memcg_index].oomleave;
	ret = get_mem_usage_anon(memcg_index, &usage);

	if (ret) {
		_D("getting anonymous usage fails");
		return ret;
	}

	if (oomleave > usage) {
		_D("%s : usage : %u, oomleave : %u",
				__func__, usage, oomleave);
		return RESOURCED_ERROR_NONE;
	} else {
		_D("%s : usage : %u, oomleave : %u",
				__func__, usage, oomleave);
		return RESOURCED_ERROR_FAIL;
	}
}

static int compare_mem_victims(const struct task_info *ta, const struct task_info *tb)
{
	int pa, pb;
	assert(ta != NULL);
	assert(tb != NULL);

	/*
	 * Weight task size ratio to totalram by OOM_SCORE_POINT_WEIGHT so that
	 * tasks with score -1000 or -900 could be selected as victims if they consumes
	 * memory more than 70% of totalram.
	 */
	pa = (int)(ta->size * OOM_SCORE_POINT_WEIGHT) / ktotalram + ta->oom_score_adj;
	pb = (int)(tb->size * OOM_SCORE_POINT_WEIGHT) / ktotalram + tb->oom_score_adj;

	return (pb - pa);
}

static int compare_bg_victims(const struct task_info *ta, const struct task_info *tb)
{
	/*
	* Firstly, sort by oom_score_adj
	* Secondly, sort by task size
	*/
	assert(ta != NULL);
	assert(tb != NULL);

	if (ta->oom_score_adj != tb->oom_score_adj)
		return (tb->oom_score_adj - ta->oom_score_adj);

	return ((int)(tb->size) - (int)(ta->size));
}

static int compare_fg_victims(const struct task_info *ta, const struct task_info *tb)
{
	/*
	* only sort by task size
	*/
	assert(ta != NULL);
	assert(tb != NULL);

	return ((int)(tb->size) - (int)(ta->size));
}

static int lowmem_get_cgroup_victims(int idx, int nsel, int max_victims, struct task_info *selected,
					unsigned *total_size, unsigned
					should_be_freed, int force)
{
	FILE *f = NULL;
	char buf[LOWMEM_PATH_MAX] = {0, };
	int i = 0;
	int sel = nsel;
	unsigned total_victim_size = *total_size;
	char appname[PATH_MAX] = {0, };

	GArray *victim_candidates = NULL;

	victim_candidates = g_array_new(false, false, sizeof(struct task_info));

	/* if g_array_new fails, return the current number of victims */
	if (victim_candidates == NULL)
		return sel;

	if (idx == MEMCG_MEMORY) {
		sprintf(buf, "%s/%s/system.slice/cgroup.procs",
				MEMCG_PATH, memcg_class[idx].cgroup_name);
		f = fopen(buf, "r");
	}

	if (!f) {
		sprintf(buf, "%s/%s/cgroup.procs",
			MEMCG_PATH, memcg_class[idx].cgroup_name);

		f = fopen(buf, "r");
		if (!f) {
			_E("%s open failed, %d", buf, f);
			/*
			 * if task read in this cgroup fails,
			 * return the current number of victims
			 */
			return sel;
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

		if (!get_mem_usage_by_pid(tpid, &tsize)) {
			_D("pid(%d) size is not available\n", tpid);
			continue;
		}

		if(proc_get_cmdline(tpid, appname) == RESOURCED_ERROR_FAIL)
			continue;

		for (i = 0; i < victim_candidates->len; i++) {
			struct task_info tsk = g_array_index(victim_candidates,
							struct task_info, i);
			if (getpgid(tpid) == tsk.pgid) {
				tsk.size += tsize;
				if (tsk.oom_score_adj < 0 && toom > 0) {
					tsk.pid = tpid;
					tsk.oom_score_adj = toom;
					g_array_remove_index(victim_candidates, i);
					g_array_append_val(victim_candidates, tsk);
				}
				break;
			}
		}

		if (i == victim_candidates->len) {
			new_victim.pid = tpid;
			new_victim.pgid = getpgid(tpid);
			new_victim.oom_score_adj = toom;
			new_victim.size = tsize;

			g_array_append_val(victim_candidates, new_victim);
		}
	}

	/*
	 * if there is no tasks in this cgroup,
	 * return the current number of victims
	 */
	if (victim_candidates->len == 0) {
		g_array_free(victim_candidates, true);
		fclose(f);
		return sel;
	}

	g_array_sort(victim_candidates,
			(GCompareFunc)memcg_class[idx].compare_fn);

	for (i = 0; i < victim_candidates->len; i++) {
		struct task_info tsk;
		if (sel >= max_victims ||
			(!force && total_victim_size >= should_be_freed)) {
			break;
		}
		tsk = g_array_index(victim_candidates, struct task_info, i);

		selected[sel].pid = tsk.pid;
		selected[sel].pgid = tsk.pgid;
		selected[sel].oom_score_adj = tsk.oom_score_adj;
		selected[sel].size = tsk.size;
		total_victim_size += tsk.size >> 10;
		sel++;

	}

	g_array_free(victim_candidates, true);

	fclose(f);
	*total_size = total_victim_size;
	return sel;

}

/* Find victims: BACKGROUND */
static int lowmem_get_memory_cgroup_victims(struct task_info *selected, int force)
{
	int i, count = 0;
	unsigned available, should_be_freed = 0, total_size = 0;
	struct mem_info mi;

	if (force ) {
		count = lowmem_get_cgroup_victims(MEMCG_BACKGROUND, count,
				MAX_FD_VICTIMS, selected,
				&total_size, 0, force);
		return count;
	}

	get_mem_info(&mi);
	available = mi.real_free + mi.reclaimable;
	if (available < memcg_class[MEMCG_MEMORY].thres_leave)
		should_be_freed = memcg_class[MEMCG_MEMORY].thres_leave - available;

	_I("should_be_freed = %u MB", should_be_freed);

	if (should_be_freed) {
		for (i = MEMCG_MAX_GROUPS - 1; i >= 0; i--) {
			count = lowmem_get_cgroup_victims(i, count,
						MAX_MEMORY_CGROUP_VICTIMS, selected,
						&total_size, should_be_freed,
						force);
			if (count >= MAX_MEMORY_CGROUP_VICTIMS || total_size >= should_be_freed)
				break;
		}
	}

	return count;
}

static int lowmem_get_victims(int idx, struct task_info *selected, int force)
{
	int count = 0;
	unsigned total_size = 0;

	if (idx == MEMCG_MEMORY)
		count = lowmem_get_memory_cgroup_victims(selected, force);
	else
		count = lowmem_get_cgroup_victims(idx, count,
					MAX_CGROUP_VICTIMS, selected,
					&total_size,
					memcg_class[idx].thres_leave, force);

	return count;
}

/* To Do: decide the number of victims based on size */
void lowmem_oom_killer_cb(int memcg_idx, int force)
{
	const pid_t self = getpid();
	int pid, ret, oom_score_adj, i;
	char appname[PATH_MAX];
	unsigned total_size = 0, size;
	struct task_info selected[MAX_MEMORY_CGROUP_VICTIMS] = {{0, 0, OOMADJ_SU, 0}, };
	int count = 0;

	/* get multiple victims from /sys/fs/cgroup/memory/.../tasks */
	count = lowmem_get_victims(memcg_idx, selected, force);

	if (count == 0) {
		_D("get %s cgroup victim is failed",
		memcg_class[memcg_idx].cgroup_name);
		return;
	}

	for (i = 0; i < count; i++) {
		/* check current memory status */
		if (memcg_idx != MEMCG_MEMORY && lowmem_check_current_state(memcg_idx) >= 0)
			return;

		pid = selected[i].pid;
		oom_score_adj = selected[i].oom_score_adj;
		size = selected[i].size;

		if (pid <= 0 || self == pid)
			continue;
		ret = proc_get_cmdline(pid, appname);
		if (ret == RESOURCED_ERROR_FAIL)
			continue;

		if (!strcmp("memps", appname)) {
			_E("memps(%d) was selected, skip it", pid);
			continue;
		}
		if (!strcmp("crash-worker", appname)) {
			_E("crash-worker(%d) was selected, skip it", pid);
			continue;
		}

		/* make memps log for killing application firstly */
		if (i==0)
			make_memps_log(MEMPS_LOG_FILE, pid, appname);

		total_size += size;

		if (force)
			kill(pid, SIGTERM);
		else
			kill(pid, SIGKILL);

		_E("we killed, lowmem lv2 = %d (%s) oom = %d, size = %u KB, victim total size = %u KB\n",
				pid, appname, oom_score_adj, size, total_size);

		if (memcg_idx >= MEMCG_FOREGROUND &&
			memcg_idx < MEMCG_BACKGROUND)
			killed_fg_victim = selected[0].pid;

		if (oom_score_adj > OOMADJ_FOREGRD_UNLOCKED)
			continue;

		if (i != 0)
			make_memps_log(MEMPS_LOG_FILE, pid, appname);
	}
}

static void *lowmem_oom_killer_pthread(void *arg)
{
	int ret = 0;

	while (1) {
		/*
		 * When signalled by main thread,
		 * it starts lowmem_oom_killer_cb().
		 */
		ret = pthread_mutex_lock(&oom_mutex);
		if ( ret ) {
			_E("oom thread::pthread_mutex_lock() failed, %d", ret);
			break;
		}

		ret = pthread_cond_wait(&oom_cond, &oom_mutex);
		if ( ret ) {
			_E("oom thread::pthread_cond_wait() failed, %d", ret);
			pthread_mutex_unlock(&oom_mutex);
			break;
		}

		_I("oom thread conditional signal received");
		lowmem_oom_killer_cb(MEMCG_MEMORY, 0);

		ret = pthread_mutex_unlock(&oom_mutex);
		if ( ret ) {
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
	case MEMNOTIFY_NORMAL:
		tmp = "mem normal";
		break;
	case MEMNOTIFY_LOW:
		tmp = "mem low";
		break;
	case MEMNOTIFY_MEDIUM:
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

static void normal_act(void)
{
	int ret, status;

	ret = vconf_get_int(VCONFKEY_SYSMAN_LOW_MEMORY, &status);
	if (ret)
		_D("vconf_get_int fail %s", VCONFKEY_SYSMAN_LOW_MEMORY);
	if (status != VCONFKEY_SYSMAN_LOW_MEMORY_NORMAL)
		vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
			      VCONFKEY_SYSMAN_LOW_MEMORY_NORMAL);

	change_lowmem_state(MEMNOTIFY_NORMAL);
}

static void low_act(void)
{
	int ret, status;

	ret = vconf_get_int(VCONFKEY_SYSMAN_LOW_MEMORY, &status);

	if (ret)
		_D("vconf_get_int fail %s", VCONFKEY_SYSMAN_LOW_MEMORY);

	change_lowmem_state(MEMNOTIFY_LOW);
	remove_shm();

	/* Since vconf for soft warning could be set during low memory check,
	 * we set it only when the current status is not soft warning.
	 */
	if (status != VCONFKEY_SYSMAN_LOW_MEMORY_SOFT_WARNING)
		vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
			      VCONFKEY_SYSMAN_LOW_MEMORY_SOFT_WARNING);
}

static Eina_Bool medium_cb(void *data)
{
	struct mem_info mi;
	unsigned available;

	get_mem_info(&mi);
	available = mi.real_free + mi.reclaimable;
	_D("available = %u, timer run until reaching leave threshold", available);

	if (available >= memcg_class[MEMCG_MEMORY].thres_leave && oom_check_timer != NULL) {
		ecore_timer_del(oom_check_timer);
		oom_check_timer = NULL;
		_D("oom_check_timer deleted after reaching leave threshold");
		normal_act();
		return ECORE_CALLBACK_CANCEL;
	}

	_I("cannot reach leave threshold, timer again");
	lowmem_oom_killer_cb(MEMCG_MEMORY, 0);

	return ECORE_CALLBACK_RENEW;
}

static void medium_act(void)
{
	int ret = 0;

	change_lowmem_state(MEMNOTIFY_MEDIUM);

	/* signal to lowmem_oom_killer_pthread to start killer */
	ret = pthread_mutex_lock(&oom_mutex);
	if ( ret ) {
		_E("medium_act::pthread_mutex_lock() failed, %d", ret);
		return;
	}

	ret = pthread_cond_signal(&oom_cond);
	if ( ret ) {
		_E("medium_act::pthread_cond_wait() failed, %d", ret);
		pthread_mutex_unlock(&oom_mutex);
		return;
	}

	_I("send signal lowmem oom killer");
	ret = pthread_mutex_unlock(&oom_mutex);
	if ( ret ) {
		_E("medium_act::pthread_mutex_unlock() failed, %d", ret);
		return;
	}

	vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
			VCONFKEY_SYSMAN_LOW_MEMORY_HARD_WARNING);

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

static bool is_fg_victim_killed(int memcg_idx)
{
	if (killed_fg_victim) {
		char buf[LOWMEM_PATH_MAX] = {0, };
		FILE *f;
		sprintf(buf, "%s/memory/foreground%d/cgroup.procs", MEMCG_PATH,
			memcg_idx);
		f = fopen(buf, "r");
		if (!f) {
			_E("%s open failed, %d", buf, f);
			/* if file open fails, start to kill */
			return true;
		}

		while (fgets(buf, 32, f) != NULL) {
			pid_t pid = atoi(buf);

			/*
			 * not yet removed from foreground cgroup,
			 * so, not start to kill again
			 */
			if (killed_fg_victim == pid) {
				fclose(f);
				return false;
			}
		}

		/*
		 * in this case, memory is low even though the previous
		 * fg victim was already killed. so, start to kill.
		 */
		fclose(f);
		killed_fg_victim = 0;
		return true;
	}

	return true;
}

static void show_foreground_procs(int memcg_idx) {
	char buf[LOWMEM_PATH_MAX] = {0, };
	FILE *f;
	sprintf(buf, "%s/memory/foreground%d/cgroup.procs", MEMCG_PATH,
		memcg_idx);
	f = fopen(buf, "r");
	if (!f) {
		_E("%s open failed, %d", buf, f);
		/* if file open fails, start to kill */
		return;
	}

	while (fgets(buf, 32, f) != NULL) {
		pid_t pid = atoi(buf);
		unsigned int size;
		get_mem_usage_by_pid(pid, &size);
		_E("pid = %d, size = %u KB", pid, size);
	}

	fclose(f);
}

static void memory_cgroup_medium_act(int memcg_idx)
{
	_I("[LOW MEM STATE] memory cgroup %s oom state",
	memcg_class[memcg_idx].cgroup_name);

	/* only start to kill fg victim when no pending fg victim */
	if ((memcg_idx >= MEMCG_FOREGROUND && memcg_idx < MEMCG_BACKGROUND)
	    && is_fg_victim_killed(memcg_idx)) {
		show_foreground_procs(memcg_idx);
		lowmem_oom_killer_cb(memcg_idx, 0);
	}
}

static unsigned int lowmem_eventfd_read(int fd)
{
	unsigned int ret;
	uint64_t dummy_state;
	ret = read(fd, &dummy_state, sizeof(dummy_state));
	return ret;
}

static unsigned int check_mem_state(unsigned available)
{
	int mem_state;
	for (mem_state = MEMNOTIFY_MAX_LEVELS -1; mem_state > MEMNOTIFY_NORMAL; mem_state--) {
		if (available <= thresholds[mem_state])
			break;
	}

	return mem_state;
}

static void lowmem_handler(void)
{
	struct mem_info mi;
	unsigned available;
	int mem_state;

	get_mem_info(&mi);
	available = mi.real_free + mi.reclaimable;

	mem_state = check_mem_state(available);
	_D("available = %u, mem_state = %d", available, mem_state);

	lowmem_process(mem_state);
}

static void lowmem_cgroup_handler(int memcg_idx)
{
	unsigned int usage;
	int ret;

	ret = get_mem_usage_anon(memcg_idx, &usage);

	if (ret) {
		_D("getting anonymous memory usage fails");
		return;
	}

	if (usage >= memcg_class[memcg_idx].thres_medium)
		memory_cgroup_medium_act(memcg_idx);
	else
		_I("anon page (%u) is under medium threshold (%u)",
			usage >> 20, memcg_class[memcg_idx].thres_medium >> 20);
}

static Eina_Bool lowmem_cb(void *data, Ecore_Fd_Handler *fd_handler)
{
	int fd, i;

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

	for (i = 0; i < MEMCG_MAX_GROUPS; i++) {
		if (fd == evfd[i]) {
			if (i == MEMCG_MEMORY) {
				lowmem_handler();
			} else {
				lowmem_cgroup_handler(i);
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

static int setup_eventfd(void)
{
	unsigned int i;
	int cgfd, pressurefd, res, sz;
	char buf[LOWMEM_PATH_MAX] = {0,};


	for (i = 0; i < MEMCG_MAX_GROUPS; i++) {
		if (memcg_class[i].event_string == NULL)
			continue;
		/* open cgroup.event_control */
		sprintf(buf, "%s/%s/cgroup.event_control",
				MEMCG_PATH, memcg_class[i].cgroup_name);
		cgfd = open(buf, O_WRONLY);
		if (cgfd < 0) {
			_E("open event_control failed");
			return RESOURCED_ERROR_FAIL;
		}

		/* register event pressure_level */
		sprintf(buf, "%s/%s/memory.pressure_level",
				MEMCG_PATH, memcg_class[i].cgroup_name);
		pressurefd = open(buf, O_RDONLY);
		if (pressurefd < 0) {
			_E("open pressure control failed");
			close(cgfd);
			return RESOURCED_ERROR_FAIL;
		}

		/* create an eventfd using eventfd(2)
		   use same event fd for using ecore event loop */
		evfd[i] = eventfd(0, O_NONBLOCK);
		if (evfd[i] < 0) {
			_E("eventfd() error");
			close(cgfd);
			close(pressurefd);
			return RESOURCED_ERROR_FAIL;
		}

		/* pressure level*/
		/* write event fd low level */
		sz = sprintf(buf, "%d %d %s", evfd[i], pressurefd,
				memcg_class[i].event_string);
		sz += 1;
		res = write(cgfd, buf, sz);
		if (res != sz) {
			_E("write cgfd failed : %d for %s",
				res, memcg_class[i].cgroup_name);
			close(cgfd);
			close(pressurefd);
			close(evfd[i]);
			evfd[i] = -1;
			return RESOURCED_ERROR_FAIL;
		}

		_I("register event fd success for %s cgroup",
			memcg_class[i].cgroup_name);
		ecore_main_fd_handler_add(evfd[i], ECORE_FD_READ,
				(Ecore_Fd_Cb)lowmem_cb, NULL, NULL, NULL);

		close(cgfd);
		close(pressurefd);
	}
	return 0;
}

static int write_cgroup_node(const char *memcg_name,
		const char *file_name, unsigned int value)
{
	FILE *f = NULL;
	char buf[LOWMEM_PATH_MAX] = {0, };
	int size;

	sprintf(buf, "%s/%s/%s", MEMCG_PATH, memcg_name, file_name);
	f = fopen(buf, "w");
	if (!f) {
		_E("%s open failed", buf);
		return RESOURCED_ERROR_FAIL;
	}

	size = sprintf(buf, "%u", value);
	if (fwrite(buf, size, 1, f) != 1) {
		_E("fail fwrite %s\n", file_name);
		fclose(f);
		return RESOURCED_ERROR_FAIL;
	}

	fclose(f);
	return RESOURCED_ERROR_NONE;
}

void set_threshold(int level, int thres)
{
	thresholds[level] = thres;
	return;
}

void set_leave_threshold(int thres)
{
	memcg_class[MEMCG_MEMORY].thres_leave = thres;
	return;
}

void set_foreground_ratio(float ratio)
{
	int i;
	for (i = MEMCG_FOREGROUND; i < MEMCG_BACKGROUND; i++)
		memcg_class[i].limit_ratio = ratio;
	return;
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

static int set_thresholds(const char * section_name, const struct parse_result *result)
{
       if (!result || !section_name)
               return -EINVAL;

       if (strcmp(result->section, section_name))
               return RESOURCED_ERROR_NONE;

       if (!strcmp(result->name, "ThresholdLow")) {
	       int value = atoi(result->value);
	       set_threshold(MEMNOTIFY_LOW, value);
       } else if (!strcmp(result->name, "ThresholdMedium")) {
	       int value = atoi(result->value);
	       set_threshold(MEMNOTIFY_MEDIUM, value);
       } else if (!strcmp(result->name, "ThresholdLeave")) {
	       int value = atoi(result->value);
	       set_leave_threshold(value);
       } else if (!strcmp(result->name, "ForegroundRatio")) {
	       float value = atof(result->value);
	       set_foreground_ratio(value);
       }
       return RESOURCED_ERROR_NONE;
}

static int memory_load_64_config(struct parse_result *result, void *user_data)
{
       return set_thresholds("Memory64", result);
}

static int memory_load_256_config(struct parse_result *result, void *user_data)
{
       return set_thresholds("Memory256", result);
}

static int memory_load_512_config(struct parse_result *result, void *user_data)
{
       return set_thresholds("Memory512", result);
}

static int memory_load_1024_config(struct parse_result *result, void *user_data)
{
       return set_thresholds("Memory1024", result);
}

static int memory_load_2048_config(struct parse_result *result, void *user_data)
{
       return set_thresholds("Memory2048", result);
}

/* init thresholds depending on total ram size. */
static void init_thresholds(void)
{
	int i;
	unsigned long total_ramsize = BtoMB(totalram);
	_D("Total : %lu MB", total_ramsize);

	if (total_ramsize <= MEM_SIZE_64) {
		/* set thresholds for ram size 64M */
		set_threshold(MEMNOTIFY_LOW, MEMCG_MEMORY_64_THRES_LOW);
		set_threshold(MEMNOTIFY_MEDIUM, MEMCG_MEMORY_64_THRES_MEDIUM);
		set_leave_threshold(MEMCG_MEMORY_64_THRES_LEAVE);
		config_parse(MEM_CONF_FILE, memory_load_64_config, NULL);
	} else if (total_ramsize <= MEM_SIZE_256) {
		/* set thresholds for ram size 256M */
		set_threshold(MEMNOTIFY_LOW, MEMCG_MEMORY_256_THRES_LOW);
		set_threshold(MEMNOTIFY_MEDIUM, MEMCG_MEMORY_256_THRES_MEDIUM);
		set_leave_threshold(MEMCG_MEMORY_256_THRES_LEAVE);
		config_parse(MEM_CONF_FILE, memory_load_256_config, NULL);
	} else if (total_ramsize <= MEM_SIZE_512) {
		/* set thresholds for ram size 512M */
		set_threshold(MEMNOTIFY_LOW, MEMCG_MEMORY_512_THRES_LOW);
		set_threshold(MEMNOTIFY_MEDIUM, MEMCG_MEMORY_512_THRES_MEDIUM);
		set_leave_threshold(MEMCG_MEMORY_512_THRES_LEAVE);
		config_parse(MEM_CONF_FILE, memory_load_512_config, NULL);
	} else if (total_ramsize <= MEM_SIZE_1024) {
		/* set thresholds for ram size more than 1G */
		set_threshold(MEMNOTIFY_LOW, MEMCG_MEMORY_1024_THRES_LOW);
		set_threshold(MEMNOTIFY_MEDIUM, MEMCG_MEMORY_1024_THRES_MEDIUM);
		set_leave_threshold(MEMCG_MEMORY_1024_THRES_LEAVE);
		config_parse(MEM_CONF_FILE, memory_load_1024_config, NULL);
	} else {
		/* set thresholds for ram size more than 2G */
		set_threshold(MEMNOTIFY_LOW, MEMCG_MEMORY_2048_THRES_LOW);
		set_threshold(MEMNOTIFY_MEDIUM, MEMCG_MEMORY_2048_THRES_MEDIUM);
		set_leave_threshold(MEMCG_MEMORY_2048_THRES_LEAVE);
		config_parse(MEM_CONF_FILE, memory_load_2048_config, NULL);
	}

	for (i = MEMNOTIFY_NORMAL; i < MEMNOTIFY_MAX_LEVELS; i++)
		_I("set threshold for %d to %u", i, thresholds[i]);

	_I("set thres_leave to %u", memcg_class[MEMCG_MEMORY].thres_leave);
}

static int create_foreground_memcg(void)
{
	int i;
	char buf[LOWMEM_PATH_MAX] = {0, };
	for (i = MEMCG_FOREGROUND; i < MEMCG_MAX_GROUPS; i++) {
		sprintf(buf, "%s/%s", MEMCG_PATH, memcg_class[i].cgroup_name);
		if (mkdir(buf, 0755) && errno != EEXIST) {
			_E("mkdir %s failed, errno %d", buf, errno);
			return RESOURCED_ERROR_FAIL;
		}
		_I("%s is successfuly created", buf);
	}
	return RESOURCED_ERROR_NONE;
}

static int init_memcg(void)
{
	unsigned int i, limit;
	_D("Total : %lu", totalram);
	int ret = RESOURCED_ERROR_NONE;

	for (i = 0; i < MEMCG_MAX_GROUPS; i++) {
		/* enable cgroup move */
		ret = write_cgroup_node(memcg_class[i].cgroup_name,
					MEMCG_MOVE_CHARGE_PATH, 3);
		if (ret)
			return ret;

		 /* for memcg with NO_LIMIT, do not set limit for cgroup limit */
		if (memcg_class[i].limit_ratio == NO_LIMIT)
			continue;

		/* disable memcg OOM-killer */
		ret = write_cgroup_node(memcg_class[i].cgroup_name,
					MEMCG_OOM_CONTROL_PATH, 1);
		if (ret)
			return ret;

		/* write limit_in_bytes */
		limit = (unsigned int)(memcg_class[i].limit_ratio*(float)totalram);
		if (limit > memcg_class[i].min_limit)
			limit = memcg_class[i].min_limit;
		ret = write_cgroup_node(memcg_class[i].cgroup_name,
					MEMCG_LIMIT_PATH, limit);
		if (ret)
			return ret;
		else
			_I("set %s's limit to %u", memcg_class[i].cgroup_name, limit);

		if (BtoMB(totalram) < MEM_SIZE_512 &&
			(i >= MEMCG_FOREGROUND && i < MEMCG_BACKGROUND)) {
			memcg_class[i].thres_leave = limit * MEMCG_FOREGROUND_LEAVE_RATIO;
			_I("set foreground%d leave %u for limit %u",
				i, memcg_class[i].thres_leave, limit);
		}

		/* set threshold and oomleave for each memcg */
		memcg_class[i].thres_low =
			(unsigned int)(limit * MEMCG_LOW_RATIO);
		memcg_class[i].thres_medium =
			(unsigned int)(limit * MEMCG_MEDIUM_RATIO);
		memcg_class[i].oomleave =
			limit - (memcg_class[i].thres_leave << 20);
	}

	return ret;
}


static int find_foreground_cgroup(void) {
	int fg, min_fg = -1;
	unsigned int min_usage = UINT_MAX;

	for (fg = MEMCG_FOREGROUND; fg < MEMCG_BACKGROUND; fg++) {
		unsigned int usage;
		usage = get_mem_usage(fg);

		/* select foreground memcg with no task first*/
		if (usage == 0)
			return fg;

		/* select forground memcg with minimum usage */
		if (usage > 0 && min_usage > usage) {
			min_usage = usage;
			min_fg = fg;
		}
	}

	if (min_fg < 0)
		return RESOURCED_ERROR_FAIL;

	return min_fg;
}

void lowmem_move_memcgroup(int pid, int oom_score_adj)
{
	char buf[LOWMEM_PATH_MAX] = {0,};
	FILE *f;
	int size;

	if (oom_score_adj >= OOMADJ_BACKGRD_LOCKED) {
		sprintf(buf, "%s/memory/background/cgroup.procs", MEMCG_PATH);
	} else if (oom_score_adj >= OOMADJ_FOREGRD_LOCKED &&
					oom_score_adj < OOMADJ_BACKGRD_LOCKED) {
		int ret;
		ret = find_foreground_cgroup();
		if (ret == RESOURCED_ERROR_FAIL) {
			_E("cannot find foreground cgroup");
			return;
		}
		sprintf(buf, "%s/memory/foreground%d/cgroup.procs", MEMCG_PATH, ret);
	} else
		return;


		_D("buf : %s, pid : %d, oom : %d", buf, pid, oom_score_adj);
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

void lowmem_cgroup_foregrd_manage(int currentpid)
{
	char buf[LOWMEM_PATH_MAX] = {0,};
	int pid, pgid;
	FILE *f;
	sprintf(buf, "%s/memory/background/cgroup.procs", MEMCG_PATH);
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

static int oom_thread_create(void)
{
	int ret = RESOURCED_ERROR_NONE;

	if ( oom_thread ) {
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

/* To Do: should we need lowmem_fd_start, lowmem_fd_stop ?? */
int lowmem_init(void)
{
	int ret = RESOURCED_ERROR_NONE;

	ret = create_foreground_memcg();

	if (ret) {
		_E("create foreground memcgs failed");
		return ret;
	}
	get_total_memory();
	init_thresholds();
	config_parse(MEM_CONF_FILE, load_mem_config, NULL);

	ret = oom_thread_create();
	if (ret) {
		_E("oom thread create failed\n");
		return ret;
	}

	/* set default memcg value */
	ret = init_memcg();
	if (ret) {
		_E("memory cgroup init failed");
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
	return lowmem_init();
}

static int resourced_memory_finalize(void *data)
{
	return RESOURCED_ERROR_NONE;
}

static struct module_ops memory_modules_ops = {
	.priority	= MODULE_PRIORITY_NORMAL,
	.name		= "lowmem",
	.init		= resourced_memory_init,
	.exit		= resourced_memory_finalize,
	.control	= resourced_memory_control,
};

MODULE_REGISTER(&memory_modules_ops)
