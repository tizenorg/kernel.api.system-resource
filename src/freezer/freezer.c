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
 * @file freezer.c
 *
 * @desc Freezer module
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "freezer.h"
#include "freezer-process.h"
#include "freezer-cgroup.h"
#include "freezer-vconf-callbacks.h"
#include "freezer-common.h"
#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "notifier.h"
#include "resourced.h"
#include "trace.h"
#include "vconf.h"
#include "config-parser.h"
#include "procfs.h"

#define FREEZER_CONF_FILE           "/etc/resourced/freezer.conf"
#define FREEZER_CONF_SECTION		"SETTING"
#define FREEZER_CONF_ENABLE			"freezer"
#define FREEZER_CONF_BACKGROUND		"freezebackground"
#define FREEZER_CONF_SERVICE		"freezeservice"
#define FREEZER_CONF_PREDEFINE		"PREDEFINE"
#define FREEZER_CONF_LATEPREDEFINE	"LATE_PREDEFINE"
#define FREEZER_CONF_LEGACY		"freezelegacyapp"

static int freezer_intialized;
static int freezer_mode;

static int resourced_freezer_status(void *data)
{
	struct freezer_status_data *f_data;
	int ret = RESOURCED_ERROR_NONE;
	if (!freezer_intialized)
		return RESOURCED_ERROR_NONE;
	f_data = (struct freezer_status_data *)data;
	switch(f_data->type) {
	case GET_STATUS:
		ret = freezer_get_operation_state();
		break;
	default:
		_E("Unsupported command: %d; status", f_data->type,
			f_data->status);
	}
	return ret;
}

static int freezer_change_state_cb(void *data)
{
	int ret;
	int state = (int)data;
	ret = cgroup_set_sysfs_state(state);
	ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
		"Can't change cgroup state!");
	freezer_set_operation_state(state);
	return RESOURCED_ERROR_NONE;
}

static int freezer_service_launch(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;

	return prepare_suspend_process(ps->pid);
}

static int freezer_wakeup(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;

	if (!freezer_intialized ||
		(freezer_get_operation_state() == CGROUP_FREEZER_DISABLED))
		return RESOURCED_ERROR_NONE;

	return freezer_process_foregrd(ps->pid, ps->pai);
}

static int freezer_service_wakeup(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;

	if (!freezer_intialized ||
		(freezer_get_operation_state() == CGROUP_FREEZER_DISABLED))
		return RESOURCED_ERROR_NONE;

	return freezer_process_svc_foregrd(ps->pid, ps->pai);
}

static int freezer_suspend_ready(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;
	struct proc_app_info *pai = ps->pai;

	if (!freezer_intialized ||
		(freezer_get_operation_state() == CGROUP_FREEZER_DISABLED))
		return RESOURCED_ERROR_NONE;

	return freezer_process_backgrd(ps->pid, pai);
}

static int load_freezer_config(struct parse_result *result, void *user_data)
{
	int len, val;
	pid_t pid;

	if (!result)
		return -EINVAL;

	len = strlen(result->section);
	if (!strncmp(result->section, FREEZER_CONF_SECTION, len)) {
		len = strlen(result->name);
		if (!strncmp(result->name, FREEZER_CONF_ENABLE, len)) {
			if (!strncmp(result->value, "default", strlen(result->value))) {
				_I("enable freezer by default");
				freezer_set_operation_state(CGROUP_FREEZER_ENABLED);
				freezer_mode = FREEZER_ENABLE_BACKGRD;
			} else if (!strncmp(result->value, "suspend", strlen(result->value))) {
				_I("enable freezer with suspend mode");
				freezer_set_operation_state(CGROUP_FREEZER_ENABLED);
				freezer_suspend_cgroup_init();
				freezer_mode = FREEZER_ENABLE_SUSPEND;
			} else if (!strncmp(result->value, "psmode", strlen(result->value))) {
				_I("enable freezer when only power saving mode");
				freezer_mode = FREEZER_PSMODE;
			}
		} else if (!strncmp(result->name, FREEZER_CONF_BACKGROUND, len)) {
			val = atoi(result->value);
			set_proc_freezer_late_control(val);
		} else if (!strncmp(result->name, FREEZER_CONF_SERVICE, len)) {
			if (!strncmp(result->value, "enable", strlen(result->value))) {
				_I("enable freezer service");
				set_freezer_service(FREEZER_AFFECT_SERVICE);
			}
		} else if (!strncmp(result->name, FREEZER_CONF_LEGACY, len)) {
			if (!strncmp(result->value, "freeze", strlen(result->value))) {
				_I("freeze background application about legacy application under tizen 2.4");
				set_freezer_legacy_application(CGROUP_FREEZER_ENABLED);
			}
		}
	} else if (!strncmp(result->section, FREEZER_CONF_PREDEFINE, len)) {
		if (freezer_mode != FREEZER_ENABLE_SUSPEND)
			return RESOURCED_ERROR_NO_DATA;
		len = strlen(result->name);
		if (!strncmp(result->name, FREEZER_CONF_PREDEFINE, len)) {
			pid = find_pid_from_cmdline(result->value);
			if (pid > 0)
				prepare_suspend_process(pid);
		} else if (!strncmp(result->name, FREEZER_CONF_LATEPREDEFINE, len)) {
			pid = find_pid_from_cmdline(result->value);
			if (pid > 0)
				prepare_late_resume_process(pid);
		}
	}
	return RESOURCED_ERROR_NONE;
}

int get_freezer_mode(void)
{
	return freezer_mode;
}

int freezer_broadcasting(enum freezer_control_type type, pid_t pid)
{
	char *pa[2];
	char typebuf[MAX_DEC_SIZE(int)], pidbuf[MAX_DEC_SIZE(int)];
	int ret;

	snprintf(typebuf, sizeof(typebuf), "%d", type);
	snprintf(pidbuf, sizeof(pidbuf), "%d", pid);
	pa[0] = typebuf;
	pa[1] = pidbuf;

	ret = broadcast_edbus_signal_str(RESOURCED_PATH_FREEZER,
		    RESOURCED_INTERFACE_FREEZER, SIGNAL_FREEZER_STATE, "ii", pa);
	if (ret < 0)
		_E("Fail to broadcast dbus signal with type(%d), pid(%d)", type, pid);
	return ret;
}

static int resourced_freezer_init(void *data)
{
	int ret_code;
	int state = 0;

	freezer_intialized = 1;

	register_notifier(RESOURCED_NOTIFIER_FREEZER_CGROUP_STATE,
		freezer_change_state_cb);

	ret_code = freezer_init();
	ret_value_msg_if(ret_code < 0, ret_code, "freezer_init failed\n");
	ret_code = freezer_cgroup_init();
	ret_value_msg_if(ret_code < 0, ret_code, "freezer_cgroup_init failed\n");
	config_parse(FREEZER_CONF_FILE, load_freezer_config, NULL);
	freezer_dbus_init(freezer_mode);

	if (freezer_mode == FREEZER_ENABLE_SUSPEND)
		register_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH,
			    freezer_service_launch);

	resourced_add_vconf_freezer_cb();
	if (vconf_get_int(VCONFKEY_SETAPPL_PSMODE, &state) == 0) {
		if (state >= SETTING_PSMODE_EMERGENCY) {
			_D("set freezer on cause vconf value : %d", state);
			freezer_set_operation_state(CGROUP_FREEZER_ENABLED);
			set_proc_freezer_late_control( FREEZER_LATE_CONTROL_DEFAULT);
		}
	}
	register_notifier(RESOURCED_NOTIFIER_APP_WAKEUP,
		freezer_wakeup);
	register_notifier(RESOURCED_NOTIFIER_SERVICE_WAKEUP,
		freezer_service_wakeup);
	register_notifier(RESOURCED_NOTIFIER_APP_SUSPEND_READY,
		freezer_suspend_ready);
	return RESOURCED_ERROR_NONE;
}

static int resourced_freezer_finalize(void *data)
{
	resourced_remove_vconf_freezer_cb();
	freezer_finalize();
	unregister_notifier(RESOURCED_NOTIFIER_FREEZER_CGROUP_STATE,
		freezer_change_state_cb);
	unregister_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH,
		freezer_service_launch);
	unregister_notifier(RESOURCED_NOTIFIER_APP_WAKEUP,
		freezer_wakeup);
	unregister_notifier(RESOURCED_NOTIFIER_SERVICE_WAKEUP,
		freezer_service_wakeup);
	unregister_notifier(RESOURCED_NOTIFIER_APP_SUSPEND_READY,
		freezer_suspend_ready);
	return RESOURCED_ERROR_NONE;
}

static const struct module_ops freezer_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "freezer",
	.init = resourced_freezer_init,
	.exit = resourced_freezer_finalize,
	.status = resourced_freezer_status,
};

MODULE_REGISTER(&freezer_modules_ops)
