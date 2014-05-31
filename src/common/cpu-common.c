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
 * @file cpu-common.c
 * @desc Implement lowmem API for external module
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "module.h"
#include "resourced.h"
#include "cpu-common.h"

static const struct module_ops *cpu;
static int cpu_module;

void cpu_find_module()
{
	if (!cpu_module) {
		cpu = find_module("cpu");
		cpu_module = 1;
	}
}

int cpu_control(enum cpu_control_type type, pid_t pid)
{
	struct cpu_data_type l_data;
	int ret = RESOURCED_ERROR_NONE;

	if (!cpu) {
		cpu_find_module();
		if (!cpu)
			return ret;
	}

	l_data.control_type = type;
	l_data.pid = pid;

	if (cpu->control)
		ret = cpu->control(&l_data);
	return ret;
}

