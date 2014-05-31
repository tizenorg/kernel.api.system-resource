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

/**
 * @file init.c
 * @desc Resourced initialization
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 **/

#include "const.h"
#include "edbus-handler.h"

#include "init.h"
#include "macro.h"
#include "module-data.h"
#include "proc-main.h"
#include "proc-monitor.h"
#include "trace.h"
#include "version.h"
#include "resourced.h"

#include <Ecore.h>
#include <getopt.h>
#include <signal.h>

static struct daemon_opts opts = {1};

static void print_root_usage()
{
	puts("You must be root to start it.");
}

static void print_usage()
{
	puts("resmand [Options]");
	puts("       Application options:");
	printf("-s [--start-daemon] - start as daemon, %d by default\n",
	       opts.start_daemon);
	puts("-v [--version] - program version");
	puts("-h [--help] - application help");
}

static void print_version()
{
	printf("Version number: %d.%d.%d\n",
		MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);
}

static int parse_cmd(int argc, char **argv)
{
	const char *optstring = ":hv:s:w";
	const struct option options[] = {
		{"help", no_argument, 0, 'h'},
		{"version", no_argument, 0, 'v'},
		{"start-daemon", required_argument, 0, 's'},
		{"enable-watchodg", no_argument, 0, 'w'},
		{0, 0, 0, 0}
	};
	int longindex, retval;

	while ((retval =
		getopt_long(argc, argv, optstring, options, &longindex)) != -1)
		switch (retval) {
		case 'h':
		case '?':
			print_usage();
			return RESOURCED_ERROR_FAIL;
		case 'v':
			print_version();
			return RESOURCED_ERROR_FAIL;
		case 's':
			opts.start_daemon = atoi(optarg);
			break;
		case 'w':
			proc_set_watchdog_state(PROC_WATCHDOG_ENABLE);
			break;
		default:
			printf("Unknown option %c\n", (char)retval);
			print_usage();
			return RESOURCED_ERROR_FAIL;
		}
	return RESOURCED_ERROR_NONE;
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
	ecore_main_loop_quit();
}

static void add_signal_handler(void)
{
	signal(SIGTERM, sig_term_handler);
	signal(SIGINT, sig_term_handler);
}

int resourced_init(struct daemon_arg *darg)
{
	int ret_code;

	ret_value_msg_if(darg == NULL, RESOURCED_ERROR_INVALID_PARAMETER,
			 "Invalid daemon argument\n");
	ret_code = assert_root();
	ret_value_if(ret_code < 0, RESOURCED_ERROR_FAIL);
	ecore_init();
	darg->opts = &opts;
	ret_code = parse_cmd(darg->argc, darg->argv);
	ret_value_msg_if(ret_code < 0, RESOURCED_ERROR_FAIL,
			 "Error parse cmd arguments\n");
	add_signal_handler();
	edbus_init();
	return RESOURCED_ERROR_NONE;
}

int resourced_deinit(struct daemon_arg *darg)
{
	ecore_shutdown();
	edbus_exit();
	ret_value_msg_if(darg == NULL, RESOURCED_ERROR_INVALID_PARAMETER,
			 "Invalid daemon argument\n");
	return RESOURCED_ERROR_NONE;
}
