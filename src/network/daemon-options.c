/*
 * resourced
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 *  @file: daemon-options.c
 *
 *  @desc Entity for working with daemon options
 *
 */

#include "daemon-options.h"
#include "macro.h"
#include "resourced.h"
#include "settings.h"
#include "trace.h"

void load_daemon_opts(struct daemon_opts *daemon_options)
{
	resourced_options options = { 0 };

	ret_msg_if(daemon_options == NULL,
			 "Invalid daemon options argument\n");
	load_options(&options);
	daemon_options->datacall_logging = options.datacall_logging;
	daemon_options->update_period = options.datausage_timer;
}
