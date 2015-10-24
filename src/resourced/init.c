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

/**
 * @file init.c
 * @desc Resourced initialization
 *
 **/

#include "const.h"
#include "counter.h"
#include "edbus-handler.h"
#include "cgroup.h"
#include "init.h"
#include "macro.h"
#include "module-data.h"
#include "proc-main.h"
#include "proc-monitor.h"
#include "swap-common.h"
#include "trace.h"
#include "version.h"

#include <Ecore.h>
#include <getopt.h>
#include <signal.h>

static void print_root_usage()
{
	puts("You must be root to start it.");
}

static int assert_root(void)
{
	if (getuid() != 0) {
		print_root_usage();
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
}

static void sig_term_handler(int sig)
{
	_E("sigterm or sigint received");
	resourced_quit_mainloop();
}

static void add_signal_handler(void)
{
	signal(SIGTERM, sig_term_handler);
	signal(SIGINT, sig_term_handler);
}

static Eina_Bool quit_main_loop(void *user_data)
{
	ecore_main_loop_quit();
	return ECORE_CALLBACK_CANCEL;
}

int resourced_init(struct daemon_arg *darg)
{
	int ret_code;

	ret_value_msg_if(darg == NULL, RESOURCED_ERROR_INVALID_PARAMETER,
			 "Invalid daemon argument\n");
	ret_code = assert_root();
	ret_value_if(ret_code < 0, RESOURCED_ERROR_FAIL);
	ecore_init();
	add_signal_handler();
	edbus_init();
	/* we couldn't create timer in signal callback, due ecore_timer_add
	 * alocates memory */
	darg->ecore_quit = ecore_timer_add(TIME_TO_SAFE_DATA, quit_main_loop, NULL);
	ecore_timer_freeze(darg->ecore_quit);

	return RESOURCED_ERROR_NONE;
}

int resourced_deinit(void)
{
	ecore_shutdown();
	edbus_exit();
	return RESOURCED_ERROR_NONE;
}

void resourced_quit_mainloop(void)
{
	static bool resourced_quit;

	if (resourced_quit)
		return;
	resourced_quit = true;

	struct shared_modules_data *shared_data = get_shared_modules_data();

	if (shared_data && shared_data->carg && shared_data->carg->ecore_timer) {
		SET_BIT(shared_data->carg->opts->state, RESOURCED_FORCIBLY_QUIT_STATE);
		/* save data on exit, it's impossible to do in fini
		 * module function, due it executes right after ecore stopped */
#ifdef NETWORK_MODULE
		reschedule_count_timer(shared_data->carg, 0);
#endif
	}
	ecore_timer_thaw(shared_data->darg->ecore_quit);
}

void set_daemon_net_block_state(const enum traffic_restriction_type rst_type,
	const struct counter_arg *carg)
{
	ret_msg_if(carg == NULL,
		"Please provide valid counter arg!");

	if (rst_type == RST_SET)
		carg->opts->state |= RESOURCED_NET_BLOCKED_STATE; /* set bit */
	else {
		carg->opts->state &=(~RESOURCED_NET_BLOCKED_STATE); /* nulify bit */
		ecore_timer_thaw(carg->ecore_timer);
	}
}
