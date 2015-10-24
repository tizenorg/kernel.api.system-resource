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
#include "cgroup.h"
#include "procfs.h"
#include "macro.h"
#include "util.h"
#include "config-parser.h"
#include "file-helper.h"
#include "storage-helper.h"
#include "systemd-util.h"
#include "notifier.h"
#include "module.h"
#include "module-data.h"
#include "vip-process.h"

#define VIP_CONF_FILE	  	"/etc/resourced/vip-process.conf"

static char **arg_vip_proc_names = NULL;
static char **arg_vip_systemd_services = NULL;

static int vip_parse_config_file(void)
{
	const ConfigTableItem items[] = {
		{ "VIP_PROCESS",	"VIP_PROC_NAME",
		  config_parse_strv,	0,	&arg_vip_proc_names	  },
		{ "VIP_PROCESS",	"VIP_SYSTEMD_SERVICE",
		  config_parse_strv,	0,	&arg_vip_systemd_services },
		{ NULL,			NULL,
		  NULL,			0,	NULL			  }
	};

	return config_parse_new(VIP_CONF_FILE, (void*) items);
}

static int vip_create_sub_cgroup(const char *name, pid_t pid)
{
	_cleanup_free_ char *cgroup_name = NULL;
	bool already;
	int r;
	char buf[256];

	assert(name);
	assert(pid);

	r = make_cgroup_subdir(VIP_CGROUP, name, &already);
	if (r < 0) {
		_E("failed to create vip sub dir");
		return r;
	}

	if (already) {
		_D("PID(%d) is already registered as VIP sub cgroup(%s)",
		   pid, name);
		return 0;
	}

	r = asprintf(&cgroup_name, "%s/%s", VIP_CGROUP, name);
	if (r < 0) {
		_E("failed to allocate memory");
		return -ENOMEM;
	}

	r = cgroup_write_node(cgroup_name, TASK_FILE_NAME, pid);
	if (r < 0) {
		_E("failed to write pid '%d' to '%s': %s",
		   pid, cgroup_name, strerror_r(-r, buf, sizeof(buf)));
		return r;
	}

	_D("PID(%d) is registered as VIP sub cgroup(%s)", pid, name);

	return 0;
}

static void vip_create_proc_name_groups(void)
{
	char **pname = NULL;
	int r;

	if (!arg_vip_proc_names)
		return;

	FOREACH_STRV(pname, arg_vip_proc_names) {
		pid_t pid = 0;

		pid = find_pid_from_cmdline(*pname);
		if (pid > 0) {
			r = vip_create_sub_cgroup(*pname, pid);
			if (r < 0)
				_E("failed to create "
				   "sub cgroup of '%s', ignoring", *pname);
		} else
			_D("failed to find pid of name: %s", *pname);
	}
}

static void vip_create_systemd_service_groups(void)
{
	char **pname = NULL;

	if (!arg_vip_systemd_services)
		return;

	FOREACH_STRV(pname, arg_vip_systemd_services) {
		_cleanup_free_ char *err_msg = NULL;
		unsigned int u = 0;
		int r;

		r = systemd_get_service_property_as_uint32(*pname,
							  "ExecMainPID",
							  &u,
							  &err_msg);
		if (r < 0 || !u) {
			_E("failed to get ExecMainPid of "
			   "'%s' systemd service: %s", *pname, err_msg);
			continue;
		}

		if (u > 0) {
			r = vip_create_sub_cgroup(*pname, (pid_t)u);
			if (r < 0)
				_E("failed to create "
				   "sub cgroup of '%s', ignoring", *pname);
		}
	}
}

static int vip_booting_done(void *data)
{
	vip_create_proc_name_groups();
	vip_create_systemd_service_groups();

	return 0;
}

static int resourced_vip_process_init(void *data)
{
	_cleanup_close_ int checkfd = -1;
	int r;
	char buf[256];

	r = access(CHECK_RELEASE_PROGRESS, F_OK);
	if (r == 0) {
		r = unlink(CHECK_RELEASE_PROGRESS);
		if (r < 0)
			_E("failed to remove %s: %m", CHECK_RELEASE_PROGRESS);
	}

	r = vip_parse_config_file();
	if (r < 0) {
		_E("failed to parse vip config file: %s", strerror_r(-r, buf, sizeof(buf)));
		return RESOURCED_ERROR_FAIL;
	}

	if (!arg_vip_proc_names)
		return RESOURCED_ERROR_NONE;

	if (!is_mounted(VIP_CGROUP)) {
		r = make_cgroup_subdir(DEFAULT_CGROUP, "vip", NULL);
		if (r < 0) {
			_E("failed to make vip cgroup");
			return RESOURCED_ERROR_FAIL;
		}

		r = mount_cgroup_subsystem("vip_cgroup", VIP_CGROUP,
					   "none,name=vip_cgroup");
		if (r < 0) {
			_E("failed to mount vip cgroup: %m");
			return RESOURCED_ERROR_FAIL;
		}

		r = set_release_agent("vip", "/usr/bin/vip-release-agent");
		if (r < 0) {
			_E("failed to set vip release agent: %s", strerror_r(-r, buf, sizeof(buf)));
			return RESOURCED_ERROR_FAIL;
		}
	}

	vip_create_proc_name_groups();
	vip_create_systemd_service_groups();

	r = register_notifier(RESOURCED_NOTIFIER_BOOTING_DONE,
			      vip_booting_done);
	if (r < 0) {
		_E("failed to register notifier BootingDone");
		return RESOURCED_ERROR_FAIL;
	}

	return RESOURCED_ERROR_NONE;
}

static int resourced_vip_process_finalize(void *data)
{
	strv_free_full(arg_vip_proc_names);
	strv_free_full(arg_vip_systemd_services);

	unregister_notifier(RESOURCED_NOTIFIER_BOOTING_DONE, vip_booting_done);

	return RESOURCED_ERROR_NONE;
}

static struct module_ops vip_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "vip-process",
	.init = resourced_vip_process_init,
	.exit = resourced_vip_process_finalize,
};

MODULE_REGISTER(&vip_modules_ops)
