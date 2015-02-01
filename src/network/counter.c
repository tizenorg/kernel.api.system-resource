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
 */

/*
 *  @file: counter.c
 *  @desc Entity for working with datausage counter.
 *
 */

#include "app-stat.h"
#include "counter.h"
#include "macro.h"
#include "trace.h"

#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>

struct counter_arg *init_counter_arg(struct daemon_opts *opts)
{
	struct counter_arg *result =
		(struct counter_arg *)calloc(1, sizeof(struct counter_arg));

	ret_value_msg_if(result == NULL, NULL, "Not enough memory\n");
#ifndef CONFIG_DATAUSAGE_NFACCT
	result->pid = getpid();
#endif
	result->opts = opts;
	return result;
}

void finalize_carg(struct counter_arg *carg)
{
	free(carg);
}

void reschedule_count_timer(const struct counter_arg *carg, const double delay)
{
	ret_msg_if(!carg || !carg->ecore_timer,
			 "Invalid counter argument or carg_timer is null\n");
	ecore_timer_delay(carg->ecore_timer,
			  delay - ecore_timer_pending_get(carg->ecore_timer));
}
