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
 * @file init.h
 * @desc Resourced initialization
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 **/

#ifndef _RESOURCED_INIT_H
#define _RESOURCED_INIT_H

#include <Ecore.h>

#include "resourced.h"

#include "transmission.h"

struct daemon_arg {
	int argc;
	char **argv;
	Ecore_Timer *ecore_quit;
};

int resourced_init(struct daemon_arg *darg);

int resourced_deinit(void);

void resourced_quit_mainloop(void);

struct counter_arg;

void set_daemon_net_block_state(const enum traffic_restriction_type rst_type,
	const struct counter_arg* carg);

#endif /* _RESOURCED_INIT_H */
