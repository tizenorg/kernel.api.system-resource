/*
 * resourced
 *
 * Copyright (c) 2013 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 *  @file: daemon-options.h
 *
 *  @desc Entity for working with daemon options
 *
 */

#ifndef _RESOURCED_DATAUSAGE_DAEMON_OPTIONS_H
#define _RESOURCED_DATAUSAGE_DAEMON_OPTIONS_H


#include <sys/types.h>
#include <signal.h>

struct daemon_opts {
	sig_atomic_t is_update_quota;
	sig_atomic_t datacall_logging;  /**< type of rsml_datacall_logging_option */
	sig_atomic_t start_daemon;
	sig_atomic_t update_period;
	sig_atomic_t flush_period;
	sig_atomic_t state;
	sig_atomic_t enable_swap;
};

/* TODO remove */
void load_daemon_opts(struct daemon_opts *daemon_options);

#endif /* _RESOURCED_DATAUSAGE_DAEMON_OPTIONS_H */
