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

#include <ctype.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <Ecore.h>

#include "resourced.h"
#include "trace.h"
#include "proc-main.h"
#include "cgroup.h"
#include "proc-process.h"
#include "procfs.h"
#include "lowmem-common.h"
#include "freezer-common.h"
#include "macro.h"
#include "freezer.h"
#include "proc-noti.h"
#include "notifier.h"
#include "proc-appusage.h"

#define PROC_SWEEP_TIMER	3
static GHashTable *proc_sweep_list;
static Ecore_Timer *proc_sweep_timer;

enum proc_background_type {
	PROC_BACKGROUND_INACTIVE,
	PROC_BACKGROUND_ACTIVE,
};

int proc_set_service_oomscore(const pid_t pid, const int oom_score)
{
	int service_oom;
	if (oom_score > 0)
		service_oom = oom_score - OOMADJ_SERVICE_GAP;
	else
		service_oom = OOMADJ_SERVICE_DEFAULT;
	return proc_set_oom_score_adj(pid, service_oom);
}

static void proc_set_oom_score_childs(GSList *childs, int oom_score_adj)
{
	GSList *iter;

	if (!childs)
		return;

	gslist_for_each_item(iter, childs) {
		struct child_pid *child = (struct child_pid *)(iter->data);
		proc_set_oom_score_adj(child->pid, oom_score_adj);
	}
}

static void proc_set_oom_score_services(GSList *svcs, int oom_score_adj)
{
	GSList *iter;

	if (!svcs)
		return;

	gslist_for_each_item(iter, svcs) {
		struct proc_app_info *svc = (struct proc_app_info *)(iter->data);
		proc_set_service_oomscore(svc->main_pid, oom_score_adj);
	}
}

static int proc_backgrd_manage(int currentpid, int active, int oom_score_adj)
{
	int pid = -1, flag = RESOURCED_NOTIFIER_APP_BACKGRD;
	struct proc_status proc_data;
	FILE *fp;
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	int cur_oom = -1;
	static int checkprevpid;
	int freeze_val = get_proc_freezer_late_control();
	GSList *iter;
	struct proc_program_info *ppi;
	struct proc_app_info *pai = find_app_info(currentpid);

	if (!pai || pai->proc_exclude) {
		_D("BACKGRD MANAGE : don't manage background application by %d", currentpid);
		return RESOURCED_ERROR_NONFREEZABLE;
	}

	proc_data.pid = currentpid;
	proc_data.appid = pai->appid;
	proc_data.pai = pai;
	if (active)
		flag = RESOURCED_NOTIFIER_APP_BACKGRD_ACTIVE;
	resourced_notify(flag, &proc_data);

	if (active)
		return RESOURCED_ERROR_NONE;

	if (checkprevpid != currentpid) {
		gslist_for_each_item(iter, proc_app_list) {
			struct proc_app_info *spi = (struct proc_app_info *)iter->data;
			int new_oom;
			int lru_offset = freeze_val;

			if (!spi->main_pid || spi->type != PROC_TYPE_GUI)
				continue;

			pid = spi->main_pid;
			snprintf(buf, sizeof(buf), PROC_OOM_SCORE_ADJ_PATH, pid);
			fp = fopen(buf, "r+");
			if (fp == NULL) {
				spi->main_pid = 0;
				continue;
			}
			if (fgets(buf, sizeof(buf), fp) == NULL) {
				fclose(fp);
				spi->main_pid = 0;
				continue;
			}
			cur_oom = atoi(buf);

			/*
			 * clear lru offset if platform controls background application
			 */
			if (spi->flags & PROC_BGCTRL_PLATFORM)
				lru_offset = 0;

			if (proc_check_lru_suspend(lru_offset, spi->lru_state) &&
			    (proc_check_suspend_state(spi) == PROC_STATE_SUSPEND)) {
				memset(&proc_data, 0, sizeof(struct proc_status));
				proc_data.pai = spi;
				proc_data.pid = pid;
				resourced_notify(
					    RESOURCED_NOTIFIER_APP_SUSPEND_READY,
					    &proc_data);
			}

			if (spi->lru_state >= PROC_BACKGROUND) {
				spi->lru_state++;
				if (spi->lru_state > PROC_LRU_MAX )
					spi->lru_state = PROC_LRU_MAX;
				_D("BACKGRD : process %d increase lru %d", pid, spi->lru_state);
			}

			if (cur_oom >= OOMADJ_APP_MAX) {
				fclose(fp);
				continue;
			} else if (cur_oom >= OOMADJ_BACKGRD_UNLOCKED) {
				new_oom = cur_oom+OOMADJ_APP_INCREASE;
				_D("BACKGRD : process %d set score %d (before %d)",
						pid, new_oom, cur_oom);
				fprintf(fp, "%d", new_oom);
				proc_set_oom_score_childs(spi->childs, new_oom);
			}
			fclose(fp);
		}
	}

	pai->lru_state = PROC_BACKGROUND;
	if (proc_check_favorite_app(pai->appid)) {
		_D("detect favorite application : %s", pai->appid);
		oom_score_adj = OOMADJ_FAVORITE;
	}

	proc_set_oom_score_adj(pai->main_pid, oom_score_adj);

	/* change oom score about child pids */
	proc_set_oom_score_childs(pai->childs, oom_score_adj);

	/* change oom score about grouped service processes */
	ppi = pai->program;
	if (ppi && proc_get_svc_state(ppi) == PROC_STATE_BACKGROUND)
		proc_set_oom_score_services(ppi->svc_list, oom_score_adj);

	checkprevpid = currentpid;
	return RESOURCED_ERROR_NONE;
}

static int proc_foregrd_manage(int pid, int oom_score_adj)
{
	int ret = 0;
	struct proc_program_info *ppi;
	struct proc_app_info *pai;

	pai = find_app_info(pid);
	if (!pai) {
		proc_set_oom_score_adj(pid, oom_score_adj);
		return RESOURCED_ERROR_NO_DATA;
	}

	proc_set_oom_score_adj(pai->main_pid, oom_score_adj);

	/* change oom score about child pids */
	proc_set_oom_score_childs(pai->childs, oom_score_adj);

	pai->lru_state = PROC_FOREGROUND;

	/* change oom score about grouped service processes */
	ppi = pai->program;
	if (ppi)
		proc_set_oom_score_services(ppi->svc_list, oom_score_adj);

	return ret;
}

void proc_kill_victiom(gpointer key, gpointer value, gpointer user_data)
{
	int pid = *(gint *)key;
	int cur_oom = -1;
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	FILE *fp;

	snprintf(buf, sizeof(buf), PROC_OOM_SCORE_ADJ_PATH, pid);
	fp = fopen(buf, "r+");
	if (fp == NULL) {
		_D("sweep proc_kill_victim : background process %d already terminated", pid);
		return;
	}
	if (fgets(buf, sizeof(buf), fp) == NULL) {
		fclose(fp);
		return;
	}
	cur_oom = atoi(buf);
	if (cur_oom >= OOMADJ_FAVORITE) {
		kill(pid, SIGKILL);
		_D("sweep memory : background process %d killed by sigkill", pid);
	}
	fclose(fp);
}

static Eina_Bool proc_check_sweep_cb(void *data)
{
	GHashTable *List = (GHashTable *)data;
	g_hash_table_foreach(List, proc_kill_victiom, NULL);
	g_hash_table_destroy(List);
	proc_sweep_list = NULL;
	return ECORE_CALLBACK_CANCEL;
}

int proc_sweep_memory(enum proc_sweep_type type, pid_t callpid)
{
	pid_t pid = -1;
	int count = 0, ret;
	FILE *fp;
	gint *piddata;
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	char appname[PROC_NAME_MAX];

	int cur_oom = -1;
	int select_sweep_limit;
	GSList *iter;
	struct proc_app_info *pai;

	if (proc_sweep_timer)
		ecore_timer_del(proc_sweep_timer);
	if (proc_sweep_list)
		g_hash_table_destroy(proc_sweep_list);
	proc_sweep_list = g_hash_table_new(g_int_hash, g_int_equal);

	if (type == PROC_SWEEP_EXCLUDE_ACTIVE)
		select_sweep_limit = OOMADJ_FAVORITE;
	else
		select_sweep_limit = OOMADJ_BACKGRD_LOCKED;

	gslist_for_each_item(iter, proc_app_list) {
		pai = (struct proc_app_info *)iter->data;
		if (!pai->main_pid || pai->type != PROC_TYPE_GUI)
			continue;

		pid = pai->main_pid;

		snprintf(buf, sizeof(buf), PROC_OOM_SCORE_ADJ_PATH, pid);
		fp = fopen(buf, "r+");
		if (fp == NULL)
			continue;
		if (fgets(buf, sizeof(buf), fp) == NULL) {
			fclose(fp);
			continue;
		}
		cur_oom = atoi(buf);
		if (cur_oom >= select_sweep_limit) {
			ret = proc_get_cmdline(pid, appname);
			if (ret != 0) {
				fclose(fp);
				continue;
			}
			resourced_proc_status_change(PROC_CGROUP_SET_TERMINATE_REQUEST,
				    pid, NULL, NULL, PROC_TYPE_NONE);
			piddata = g_new(gint, 1);
			*piddata = pid;
			g_hash_table_insert(proc_sweep_list, piddata, NULL);
			kill(pid, SIGTERM);
			_D("sweep memory : background process %d(%s) killed",
					pid, appname);
			count++;
		}
		fclose(fp);
	}
	if (count > 0) {
		proc_sweep_timer =
			    ecore_timer_add(PROC_SWEEP_TIMER, proc_check_sweep_cb, (void *)proc_sweep_list);
	}
	return count;
}

int proc_set_foregrd(pid_t pid, int oom_score_adj)
{
	int ret = 0;

	switch (oom_score_adj) {
	case OOMADJ_FOREGRD_LOCKED:
	case OOMADJ_FOREGRD_UNLOCKED:
	case OOMADJ_SU:
		ret = 0;
		break;
	case OOMADJ_BACKGRD_LOCKED:
		ret = proc_foregrd_manage(pid, OOMADJ_FOREGRD_LOCKED);
		break;
	case OOMADJ_BACKGRD_UNLOCKED:
	case OOMADJ_INIT:
	case OOMADJ_FAVORITE:
		ret = proc_foregrd_manage(pid, OOMADJ_FOREGRD_UNLOCKED);
		break;
	default:
		if (oom_score_adj > OOMADJ_BACKGRD_UNLOCKED) {
			ret = proc_foregrd_manage(pid, OOMADJ_FOREGRD_UNLOCKED);
		} else {
			ret = -1;
		}
		break;

	}
	return ret;
}

int proc_set_backgrd(int pid, int oom_score_adj)
{
	int ret = 0;

	switch (oom_score_adj) {
	case OOMADJ_BACKGRD_LOCKED:
	case OOMADJ_BACKGRD_UNLOCKED:
	case OOMADJ_SU:
		ret = -1;
		break;
	case OOMADJ_FOREGRD_LOCKED:
		ret = proc_backgrd_manage(pid, PROC_BACKGROUND_ACTIVE, OOMADJ_BACKGRD_LOCKED);
		break;
	case OOMADJ_FOREGRD_UNLOCKED:
		ret = proc_backgrd_manage(pid, PROC_BACKGROUND_INACTIVE, OOMADJ_BACKGRD_UNLOCKED);
		break;
	case OOMADJ_INIT:
		ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_UNLOCKED);
		break;
	default:
		if (oom_score_adj > OOMADJ_BACKGRD_UNLOCKED) {
			ret = 0;
		} else {
			ret = -1;
		}
		break;
	}
	return ret;
}

int proc_set_active(int pid, int oom_score_adj)
{
	int ret = 0;
	struct proc_app_info *pai;

	switch (oom_score_adj) {
	case OOMADJ_FOREGRD_LOCKED:
	case OOMADJ_BACKGRD_LOCKED:
	case OOMADJ_SU:
		/* don't change oom value pid */
		ret = -1;
		break;
	case OOMADJ_INIT:
	case OOMADJ_FOREGRD_UNLOCKED:
		ret = proc_set_oom_score_adj(pid, OOMADJ_FOREGRD_LOCKED);
		break;
	case OOMADJ_BACKGRD_UNLOCKED:
		pai = find_app_info(pid);
		if (pai)
			pai->lru_state = PROC_ACTIVE;
		ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_LOCKED);
		break;
	case OOMADJ_SERVICE_DEFAULT:
	case OOMADJ_SERVICE_BACKGRD:
		ret = proc_set_oom_score_adj(pid, OOMADJ_SERVICE_FOREGRD);
		break;
	default:
		if (oom_score_adj > OOMADJ_BACKGRD_UNLOCKED) {
			pai = find_app_info(pid);
			if (pai)
				pai->lru_state = PROC_ACTIVE;
			ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_LOCKED);
		} else
			ret = -1;
		break;
	}
	return ret;
}

int proc_set_inactive(int pid, int oom_score_adj)
{
	int ret = 0;
	struct proc_app_info *pai;
	switch (oom_score_adj) {
	case OOMADJ_FOREGRD_UNLOCKED:
	case OOMADJ_BACKGRD_UNLOCKED:
	case OOMADJ_SU:
	case OOMADJ_INIT:
		/* don't change oom value pid */
		ret = -1;
		break;
	case OOMADJ_FOREGRD_LOCKED:
		ret = proc_set_oom_score_adj(pid, OOMADJ_FOREGRD_UNLOCKED);
		break;
	case OOMADJ_BACKGRD_LOCKED:
		pai = find_app_info(pid);
		if (pai) {
			pai->lru_state = PROC_BACKGROUND;
			ret = proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_UNLOCKED);
		}
		break;
	case OOMADJ_SERVICE_FOREGRD:
		ret = proc_set_oom_score_adj(pid, OOMADJ_SERVICE_DEFAULT);
		break;
	default:
		if (oom_score_adj > OOMADJ_BACKGRD_UNLOCKED) {
			ret = 0;
		} else {
			ret = -1;
		}
		break;

	}
	return ret;
}
