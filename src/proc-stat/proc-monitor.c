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

/*
 * @file proc-monitor.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <sys/types.h>
#include <unistd.h>
#include <Ecore.h>
#include <E_DBus.h>

#include "proc-main.h"
#include "proc-monitor.h"
#include "resourced.h"
#include "macro.h"
#include "trace.h"
#include "edbus-handler.h"
#include "proc-process.h"

#define WATCHDOG_LAUNCHING_PARAM "WatchdogPopupLaunch"
#define WATCHDOG_KEY1			"_SYSPOPUP_CONTENT_"
#define WATCHDOG_KEY2			"_APP_NAME_"
#define WATCHDOG_VALUE_1			"watchdog"

#define SIGNAL_PROC_WATCHDOG_RESULT	"WatchdogResult"
#define SIGNAL_PROC_ACTIVE   		"Active"
#define SIGNAL_PROC_EXCLUDE	  	"ProcExclude"
#define SIGNAL_PROC_STATUS	  	"ProcStatus"

static int proc_watchdog_state;
static int proc_dbus_proc_state;

/*
 * Callback function executed by edbus 'Signal' method call. Extracts
 * process pid and signal type from message body and uses it to send a specific
 * signal to the process.
 */
static DBusMessage *edbus_signal_trigger(E_DBus_Object *obj, DBusMessage *msg);

static struct proc_watchdog_info {
	pid_t pid;
	int signum;
} proc_watchdog = { -1, -1 };

/*
 * Adds function callbacks to edbus interface.
 */
static resourced_ret_c proc_dbus_init(void);

static const struct edbus_method edbus_methods[] = {
	{ "Signal", "ii", NULL, edbus_signal_trigger },
	/* Add methods here */
};

enum proc_status_type { /** cgroup command type **/
	PROC_STATUS_LAUNCH,
	PROC_STATUS_RESUME,
	PROC_STATUS_TERMINATE,
	PROC_STATUS_FOREGRD,
	PROC_STATUS_BACKGRD,
};

void proc_set_watchdog_state(int state)
{
	proc_watchdog_state = state;
}

static int proc_get_watchdog_state(void)
{
	return proc_watchdog_state;
}

static void proc_dbus_active_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret, type;
	char *str;
	pid_t pid;

	_D("call dbus_proc_active_signal_handler");
	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_PROCESS, SIGNAL_PROC_ACTIVE);
	if (ret == 0) {
		_D("there is no active signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &str, DBUS_TYPE_INT32, &pid, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	if (!strcmp(str, "active"))
		type = PROC_CGROUP_SET_ACTIVE;
	else if (!strcmp(str, "inactive"))
		type = PROC_CGROUP_SET_INACTIVE;
	else
		return;
	resourced_proc_status_change(type, pid, NULL);
}

int proc_get_dbus_proc_state(void)
{
	return proc_dbus_proc_state;
}

static void proc_set_dbus_proc_state(int state)
{
	proc_dbus_proc_state = state;
}

static void proc_dbus_proc_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret, type, convert = 0;
	pid_t pid;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_PROCESS, SIGNAL_PROC_STATUS);
	if (ret == 0) {
		_D("there is no active signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &type, DBUS_TYPE_INT32, &pid, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	if (!proc_dbus_proc_state)
		proc_set_dbus_proc_state(PROC_DBUS_ENABLE);

	switch (type) {
	case PROC_STATUS_LAUNCH:
		convert = PROC_CGROUP_SET_LAUNCH_REQUEST;
		break;
	case PROC_STATUS_RESUME:
		convert = PROC_CGROUP_SET_RESUME_REQUEST;
		break;
	case PROC_STATUS_TERMINATE:
		convert = PROC_CGROUP_SET_TERMINATE_REQUEST;
		break;
	case PROC_STATUS_FOREGRD:
		convert = PROC_CGROUP_SET_FOREGRD;
		break;
	case PROC_STATUS_BACKGRD:
		convert = PROC_CGROUP_SET_BACKGRD;
		break;
	default:
		return;
	}
	_D("call dbus_proc_active_signal_handler : pid = %d, type = %d", pid, convert);
	resourced_proc_status_change(convert, pid, NULL);
}

static void proc_dbus_exclude_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	char *str;
	pid_t pid;

	_D("call dbus_proc_active_signal_handler");
	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_PROCESS, SIGNAL_PROC_EXCLUDE);
	if (ret == 0) {
		_D("there is no active signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &str, DBUS_TYPE_INT32, &pid, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	return;
}

static void proc_dbus_watchdog_result(void *data, DBusMessage *msg)
{
	DBusError err;
	int type;

	if (dbus_message_is_signal(msg, RESOURCED_INTERFACE_PROCESS, SIGNAL_PROC_WATCHDOG_RESULT) == 0) {
		_D("there is no watchdog result signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	if (type == 1) {
		if (proc_watchdog.signum == SIGTERM || proc_watchdog.signum == SIGKILL)
			kill(proc_watchdog.pid, SIGABRT);
		else
			_E("ERROR: Unsupported signal type!");
	}
	proc_watchdog.pid = -1;
	proc_watchdog.signum = -1;
}

static int proc_dbus_show_popup(const char *value)
{
	DBusError err;
	DBusMessage *msg;
	char str_val[32];
	char *pa[4];
	int i, ret, ret_val;

	snprintf(str_val, sizeof(str_val), "%s", value);

	pa[0] = WATCHDOG_KEY1;
	pa[1] = WATCHDOG_VALUE_1;
	pa[2] = WATCHDOG_KEY2;
	pa[3] = str_val;
	i = 0;

	do {
		msg = dbus_method_sync(SYSTEM_POPUP_BUS_NAME, SYSTEM_POPUP_PATH_WATCHDOG, SYSTEM_POPUP_IFACE_WATCHDOG, WATCHDOG_LAUNCHING_PARAM, "ssss", pa);
		if (msg)
			break;
		_E("Re-try to sync DBUS message, err_count : %d", i);
	} while (i++ < RETRY_MAX);

	if (!msg) {
		_E("Failed to sync DBUS message.");
		return -EBADMSG;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &ret_val, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("no message : [%s:%s]\n", err.name, err.message);
		ret_val = -EBADMSG;
	}

	dbus_message_unref(msg);
	dbus_error_free(&err);

	return ret_val;
}

static DBusMessage *edbus_signal_trigger(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessage *reply;
	dbus_bool_t ret;
	int pid, command, ret_val;
	char appname[PROC_NAME_MAX];

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &pid, DBUS_TYPE_INT32,
		&command, DBUS_TYPE_INVALID);

	if (ret == TRUE) {
		ret_val = proc_get_cmdline(pid, appname);
		if (ret_val != RESOURCED_ERROR_NONE)
			_E("ERROR : invalid pid(%d)", pid);
		else {
			_E("Receive watchdog signal to pid: %d(%s)\n", pid, appname);
			if (proc_get_watchdog_state() == PROC_WATCHDOG_ENABLE  &&  proc_watchdog.pid == -1) {
				ret_val = resourced_proc_excluded(appname);
				if (ret_val == RESOURCED_ERROR_NONE) {
					ret_val = proc_dbus_show_popup(appname);
					if (ret_val < 0)
						_E("ERROR : request_to_launch_by_dbus()failed : %d", ret_val);
					else {
						proc_watchdog.pid = pid;
						proc_watchdog.signum = command;
					}
				}
			}
		}	
	} else
		_E("ERROR: Wrong message arguments!");

	reply = dbus_message_new_method_return(msg);
	return reply;
}

static resourced_ret_c proc_dbus_init(void)
{
	int ret;
	register_edbus_signal_handler(RESOURCED_PATH_PROCESS, RESOURCED_INTERFACE_PROCESS,
			SIGNAL_PROC_WATCHDOG_RESULT,
		    proc_dbus_watchdog_result);

	ret = register_edbus_signal_handler(RESOURCED_PATH_PROCESS, RESOURCED_INTERFACE_PROCESS,
			SIGNAL_PROC_ACTIVE,
		    proc_dbus_active_signal_handler);

	ret = register_edbus_signal_handler(RESOURCED_PATH_PROCESS, RESOURCED_INTERFACE_PROCESS,
			SIGNAL_PROC_EXCLUDE,
		    proc_dbus_exclude_signal_handler);

	ret = register_edbus_signal_handler(RESOURCED_PATH_PROCESS, RESOURCED_INTERFACE_PROCESS,
			SIGNAL_PROC_STATUS,
		    proc_dbus_proc_signal_handler);

	_D("register_edbus_signal_handler: %d\n", ret);

	return edbus_add_methods(RESOURCED_PATH_PROCESS, edbus_methods,
			  ARRAY_SIZE(edbus_methods));
}

resourced_ret_c proc_monitor_init(void)
{
	return proc_dbus_init();
}
