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
 * @file cpu-common.h
 * @desc cpu common process
 **/

#ifndef __CPU_COMMON_H__
#define __CPU_COMMON_H__

#include <sys/types.h>

enum cpu_control_type {
	CPU_SET_LAUNCH,
	CPU_SET_FOREGROUND,
	CPU_SET_BACKGROUND
};

struct cpu_data_type {
	enum cpu_control_type control_type;
	pid_t pid;
};

int cpu_control(enum cpu_control_type type, pid_t pid);

#endif /* __CPU_COMMON_H__ */
