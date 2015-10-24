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
 */

/*
 *  @file: counter.h
 *
 *  @desc Entity for working with datausage counter.
 *        In plans place to counter.c main counting procedure from main.c
 */


#ifndef _RESOURCED_DATAUSAGE_COUNTER_H
#define _RESOURCED_DATAUSAGE_COUNTER_H

#include "app-stat.h"
#include "config.h"

#include <Ecore.h>

#define RESOURCED_BACKGROUND_APP_NAME "BACKGROUND"

struct counter_arg {
	int sock;
	int ans_len;
#ifndef CONFIG_DATAUSAGE_NFACCT
	pid_t pid;
	int family_id_stat;
	int family_id_restriction;
#else
	GTree *nf_cntrs;
	int initiate;
	int noti_fd;
	Ecore_Fd_Handler *noti_fd_handler;
#endif
	int serialized_counters; /* number of counters which was serialized in
				    current request */
	struct net_counter_opts *opts;
	struct application_stat_tree *result;
	time_t last_run_time;
	/* main timer for getting kernel counters */
	Ecore_Timer *ecore_timer;
	/* handler for kernel's fd for getting counters from ktgrabber/nfacct */
	Ecore_Fd_Handler *ecore_fd_handler;
	/* timer for separate obtaining values from kernel and store result into db */
	Ecore_Timer *store_result_timer;
	/* timer for reset old statistics */
	Ecore_Timer *erase_timer;
};

struct net_counter_opts {
	sig_atomic_t update_period;
	sig_atomic_t flush_period;
	sig_atomic_t state;
};

/**
 * @desc Reschedule existing traffic counter function
 *  Rescheduling logic is following, we will postpone
 *  execution on delay seconds.
 */
void reschedule_count_timer(const struct counter_arg *carg, const double delay);

struct counter_arg *init_counter_arg(struct net_counter_opts *opts);

void finalize_carg(struct counter_arg *carg);

#ifdef CONFIG_DATAUSAGE_NFACCT
GTree *create_nfacct_tree(void);
#endif /* CONFIG_DATAUSAGE_NFACCT */

#endif /* _RESOURCED_NETWORK_COUNTING_H_ */


