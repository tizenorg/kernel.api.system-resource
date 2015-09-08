/*
 * resourced
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file timer-slack.h
 * @desc timer slack common process
 **/

#ifndef __TIMER_SLACK_COMMON_H__
#define __TIMER_SLACK_COMMON_H__

#include <sys/types.h>
#define TIMER_CGROUP_PATH		"/sys/fs/cgroup/timer_slack"
#define TIMER_MODULE_NAME		"timer"

enum timer_cgroup_type {
	TIMER_CGROUP_DEFAULT,
	TIMER_CGROUP_EXCLUDE,
	TIMER_CGROUP_SERVICE,
	TIMER_CGROUP_BACKGRD,
};

#endif /* __TIMER_SLACK_COMMON_H__ */
