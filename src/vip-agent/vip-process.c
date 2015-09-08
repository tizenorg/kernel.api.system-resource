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

#include <ctype.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <Ecore.h>

#include "const.h"
#include "resourced.h"
#include "trace.h"
#include "proc-main.h"
#include "cgroup.h"
#include "proc-process.h"
#include "macro.h"
#include "config-parser.h"
#include "file-helper.h"
#include "module.h"
#include "module-data.h"
#include "vip-process.h"

#define VIP_CONF_FILE	  	"/etc/resourced/vip-process.conf"
#define VIP_CONF_SECTION	"VIP_PROCESS"
#define VIP_CONF_NAME	  	"VIP_PROC_NAME"
#define AGENT_PATH	  	"/usr/bin/vip-release-agent"
#define VIP_RELEASE_AGENT	"/release_agent"
#define VIP_NOTIFY_ON_RELEASE	"/notify_on_release"


static int load_vip_config(struct parse_result *result, void *user_data)
{
	pid_t pid = 0;
	char cgroup_name[MAX_NAME_LENGTH];
	if (!result)
		return -EINVAL;

	if (strcmp(result->section, VIP_CONF_SECTION))
		return RESOURCED_ERROR_NONE;

	if (!strcmp(result->name, VIP_CONF_NAME)) {
		/* 1. find pid */
		/* 2. decrease oom score adj for excepting it in oom candidate list */
		/* 3. make cgroup */
		pid =  find_pid_from_cmdline(result->value);
		if (pid) {
			make_cgroup_subdir(VIP_CGROUP, result->value, NULL);
			snprintf(cgroup_name, sizeof(cgroup_name), "%s/%s",
				    VIP_CGROUP, result->value);
			cgroup_write_node(cgroup_name, TASK_FILE_NAME, pid);
		}
	}
	return RESOURCED_ERROR_NONE;
}

static int resourced_vip_process_init(void *data)
{
	int checkfd;
	checkfd = open(CHECK_RELEASE_PROGRESS, O_RDONLY, 0666);
	if (checkfd >= 0)
	{
		if (unlink(CHECK_RELEASE_PROGRESS) < 0)
			_E("fail to remove %s file\n", CHECK_RELEASE_PROGRESS);
		close(checkfd);
	}
	make_cgroup_subdir(DEFAULT_CGROUP, "vip", NULL);
	mount_cgroup_subsystem("vip_cgroup", VIP_CGROUP, "none,name=vip_cgroup");
	cgroup_write_node_str(VIP_CGROUP, VIP_RELEASE_AGENT, AGENT_PATH);
	cgroup_write_node(VIP_CGROUP, VIP_NOTIFY_ON_RELEASE , 1);
	config_parse(VIP_CONF_FILE, load_vip_config, NULL);
	return RESOURCED_ERROR_NONE;
}

static int resourced_vip_process_finalize(void *data)
{
	return RESOURCED_ERROR_NONE;
}

static struct module_ops vip_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "vip-process",
	.init = resourced_vip_process_init,
	.exit = resourced_vip_process_finalize,
};

MODULE_REGISTER(&vip_modules_ops)
