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
 */

/**
 * @file cpu.c
 *
 * @desc cpu module
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include "notifier.h"
#include "proc-main.h"
#include "proc-process.h"
#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "resourced.h"
#include "trace.h"
#include "vconf.h"
#include "cgroup.h"
#include "config-parser.h"
#include "const.h"

#define CPU_DEFAULT_CGROUP "/sys/fs/cgroup/cpu"
#define CPU_CONTROL_GROUP "/sys/fs/cgroup/cpu/background"
#define CPU_CONTROL_SERVICE_GROUP "/sys/fs/cgroup/cpu/service"
#define CPU_CONF_FILE                  "/etc/resourced/cpu.conf"
#define CPU_CONF_SECTION	"CONTROL"
#define CPU_CONF_PREDEFINE	"PREDEFINE"
#define CPU_SHARE	"/cpu.shares"

static int cpu_move_cgroup(pid_t pid, char *path)
{
	return cgroup_write_node(path, CGROUP_FILE_NAME, pid);
}

static int load_cpu_config(struct parse_result *result, void *user_data)
{
	pid_t pid = 0, value;
	if (!result)
		return -EINVAL;

	if (strcmp(result->section, CPU_CONF_SECTION))
		return RESOURCED_ERROR_NO_DATA;
	if (!strcmp(result->name, CPU_CONF_PREDEFINE)) {
		pid = find_pid_from_cmdline(result->value);
		if (pid > 0)
			cpu_move_cgroup(pid, CPU_CONTROL_GROUP);
	} else if (!strcmp(result->name, "BACKGROUND_CPU_SHARE")) {
		value = atoi(result->value);
		if (value)
			cgroup_write_node(CPU_CONTROL_GROUP, CPU_SHARE, value);
       } else if (!strcmp(result->name, "SERVICE_CPU_SHARE")) {
		value = atoi(result->value);
		if (value)
			cgroup_write_node(CPU_CONTROL_SERVICE_GROUP, CPU_SHARE, value);
       }
       return RESOURCED_ERROR_NONE;
}

static int cpu_service_launch(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	_D("cpu_service_launch : pid = %d, appname = %s", p_data->pid, p_data->appid);
	cpu_move_cgroup(p_data->pid, CPU_CONTROL_SERVICE_GROUP);
	return RESOURCED_ERROR_NONE;
}

static int cpu_foreground_state(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	_D("cpu_foreground_state : pid = %d, appname = %s", p_data->pid, p_data->appid);
	cpu_move_cgroup(p_data->pid, CPU_DEFAULT_CGROUP);
	return RESOURCED_ERROR_NONE;
}

static int cpu_background_state(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	_D("cpu_background_state : pid = %d, appname = %s", p_data->pid, p_data->appid);
	cpu_move_cgroup(p_data->pid, CPU_CONTROL_SERVICE_GROUP);
	return RESOURCED_ERROR_NONE;
}

static int resourced_cpu_init(void *data)
{
	int ret_code;

	_D("resourced_cpu_init");
	ret_code = make_cgroup_subdir(CPU_DEFAULT_CGROUP, "background", NULL);
	ret_value_msg_if(ret_code < 0, ret_code, "cpu init failed\n");
	ret_code = make_cgroup_subdir(CPU_DEFAULT_CGROUP, "service", NULL);
	ret_value_msg_if(ret_code < 0, ret_code, "create service cgroup failed\n");
	config_parse(CPU_CONF_FILE, load_cpu_config, NULL);

	register_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, cpu_service_launch);
	register_notifier(RESOURCED_NOTIFIER_APP_RESUME, cpu_foreground_state);
	register_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, cpu_foreground_state);
	register_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, cpu_background_state);
	return RESOURCED_ERROR_NONE;
}

static int resourced_cpu_finalize(void *data)
{
	unregister_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, cpu_service_launch);
	unregister_notifier(RESOURCED_NOTIFIER_APP_RESUME, cpu_foreground_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, cpu_foreground_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, cpu_background_state);
	return RESOURCED_ERROR_NONE;
}

static struct module_ops cpu_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "cpu",
	.init = resourced_cpu_init,
	.exit = resourced_cpu_finalize,
};

MODULE_REGISTER(&cpu_modules_ops)
