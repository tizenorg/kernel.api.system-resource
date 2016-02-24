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
#include <stdlib.h>
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
#include "swap-common.h"
#include "proc-process.h"
#include "lowmem-common.h"
#include "resourced.h"
#include "macro.h"
#include "module.h"
#include "notifier.h"
#include "procfs.h"
#include "helper.h"

#define DEV_MEMNOTIFY		"/dev/memnotify"
#define VICTIM_TASK			"/sys/class/memnotify/victims"
#define SET_THRESHOLD_LV1	"/sys/class/memnotify/threshold_lv1"
#define SET_THRESHOLD_LV2	"/sys/class/memnotify/threshold_lv2"

#define MEMPS_LOG_FILE		"/var/log/memps"
#define MEMPS_EXEC_PATH		"usr/bin/memps"

#define BtoMB(x)		((x)>>20)
#define KBtoMB(x)		((x)>>10)
#define MBtoB(x)		((x)<<20)
#define MBtoKB(x)		((x)<<10)

#define MEMNOTIFY_NORMAL	0x0000
#define MEMNOTIFY_LOW		0xfaac
#define MEMNOTIFY_CRITICAL	0xdead

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

/* low memory action function */
static int memory_low_act(void *ad);
static int memory_oom_act(void *ad);
static int memory_normal_act(void *ad);

static int lowmem_fd_start();
static int lowmem_fd_stop(int fd);

struct lowmem_process_entry {
	unsigned cur_mem_state;
	unsigned new_mem_state;
	int (*action) (void *);
};

static struct lowmem_process_entry lpe[] = {
	{MEMNOTIFY_NORMAL,		MEMNOTIFY_LOW,		memory_low_act},
	{MEMNOTIFY_NORMAL,		MEMNOTIFY_CRITICAL,	memory_oom_act},
	{MEMNOTIFY_LOW,			MEMNOTIFY_CRITICAL,	memory_oom_act},
	{MEMNOTIFY_LOW,			MEMNOTIFY_NORMAL,	memory_normal_act},
	{MEMNOTIFY_CRITICAL,	MEMNOTIFY_CRITICAL,	memory_oom_act},
	{MEMNOTIFY_CRITICAL,	MEMNOTIFY_NORMAL,	memory_normal_act},
};

static const struct module_ops memory_modules_ops;
static const struct module_ops *lowmem_ops;

void lowmem_dynamic_process_killer(int type)
{
	/* This function is not supported */
}

static int convert_memory_state_type(int state)
{
	switch (state) {
	case LOWMEM_NORMAL:
		return MEMNOTIFY_NORMAL;
	case LOWMEM_LOW:
		return MEMNOTIFY_LOW;
	case LOWMEM_MEDIUM:
		return MEMNOTIFY_CRITICAL;
	default:
		_E("Invalid state (%d)", state);
		return -EINVAL;
	}
}

void lowmem_change_memory_state(int state, int force)
{
	int mem_state;

	state = convert_memory_state_type(state);
	if (state < 0)
		return;

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
	case MEMNOTIFY_LOW:
		memory_low_act(NULL);
		break;
	case MEMNOTIFY_CRITICAL:
		memory_oom_act(NULL);
		break;
	default:
		_E("Invalid mem state (%d)", mem_state);
		return;
	}
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
	_I("[MEM STATE] usage (%d)", get_mem_usage());
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

static int lowmem_set_threshold(void)
{
	FILE *f;

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

		proc_remove_app_list(pid);
		kill(pid, SIGKILL);

		total_size += pid_size[i];
		_I("we killed, lowmem lv2 = %d (%s) oom = %d\n",
				pid, appname, oom_score_adj);

		/* wait OOM_MULTIKILL_WAIT for removing a latency about killing proesss */
		if (BtoMB(total_size) > MEM_LEAVE_THRESHOLD && i%5==0) {
			struct timespec req, rem;

			req.tv_sec = 1;
			req.tv_nsec = 0;
			nanosleep(&req, &rem);
		}

		if (oom_score_adj > OOMADJ_FOREGRD_UNLOCKED)
			continue;

		if (forgrd_size < pid_size[i]) {
			forgrd_pid = pid;
			forgrd_size = pid_size[i];
			strncpy(popupname, appname, sizeof(popupname)-1);
			popupname[sizeof(popupname)-1] = 0;
		}
	}

	if (forgrd_pid)
		make_memps_log(MEMPS_LOG_FILE, forgrd_pid, popupname);

	return NULL;
}

static char *convert_to_str(unsigned int mem_state)
{
	char *tmp = NULL;
	switch (mem_state) {
	case MEMNOTIFY_NORMAL:
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

static int memory_low_act(void *data)
{
	_I("[LOW MEM STATE] memory low state");
	print_mem_state();
	remove_shm();

	vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
		      VCONFKEY_SYSMAN_LOW_MEMORY_SOFT_WARNING);
	memory_level_send_system_event(MEMORY_LEVEL_LOW);

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
	memory_level_send_system_event(MEMORY_LEVEL_CRITICAL);
	return 1;
}

static int memory_normal_act(void *data)
{
	_I("[LOW MEM STATE] memory normal state");
	vconf_set_int(VCONFKEY_SYSMAN_LOW_MEMORY,
		      VCONFKEY_SYSMAN_LOW_MEMORY_NORMAL);
	memory_level_send_system_event(MEMORY_LEVEL_NORMAL);
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

static unsigned int lowmem_read(int fd)
{
	unsigned int mem_state;
	if (read(fd, &mem_state, sizeof(mem_state)) < 0) {
		_E("error lowmem state");
		return RESOURCED_ERROR_FAIL;
	}
	return mem_state;
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

int lowmem_memory_oom_killer(int flags)
{
	return memory_oom_act(NULL);
}

void lowmem_memcg_set_threshold(int idx, int level, int value)
{
	/* This function is for vmpressure */
}

void lowmem_memcg_set_leave_threshold(int idx, int value)
{
	/* This function is for vmpressure */
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
	lowmem_fd = open(DEV_MEMNOTIFY, O_RDONLY);
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
	return RESOURCED_ERROR_NONE;
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
