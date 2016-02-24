/*
 * resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file freezer-process.c
 * @desc Freezing background process module
 **/


#include "macro.h"
#include "freezer-cgroup.h"
#include "const.h"
#include "edbus-handler.h"
#include "procfs.h"
#include "freezer.h"
#include "freezer-common.h"
#include "freezer-process.h"
#include "proc-common.h"

#include <resourced.h>
#include <stdlib.h> /* for atoi*/
#include <trace.h>

static enum resourced_freezer_service freezer_service;

static enum freezer_state freezer_enabled;
static enum freezer_state freezer_suspend_state;
static enum freezer_state freezer_legacy_application;

static bool freezer_service_enabled(void)
{
	return freezer_service == FREEZER_AFFECT_SERVICE;
}

static bool freezer_legacy_application_allowed(void)
{
	return freezer_legacy_application == CGROUP_FREEZER_DISABLED;
}

static void freezer_lcdon_complete(void *data, DBusMessage *msg)
{
	DBusError err;
	dbus_error_init(&err);

	if (dbus_message_is_signal(msg, DEVICED_INTERFACE_DISPLAY,
		    SIGNAL_DEVICED_LCDONCOMPLETE) == 0) {
		_D("there is no lcd on signal");
		return;
	}
	dbus_error_free(&err);
	if (freezer_suspend_state == CGROUP_FREEZER_SUSPEND)
		cgroup_set_sysfs_state(CGROUP_FREEZER_LATERESUME);
	freezer_suspend_state = CGROUP_FREEZER_RESUME;
}

static DBusMessage *edbus_set_suspend(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	dbus_bool_t ret;
	char *command;
	int len;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &command,
		DBUS_TYPE_INVALID);
	if (!ret) {
			_E("Wrong message arguments!");
			reply = dbus_message_new_method_return(msg);
			return reply;
	}
	/*
	 * allowed strings: suspend, resume
	 */
	len = strlen(command);
	if (len == 6 && !strncmp(command, "re", 2))
		cgroup_set_sysfs_state(CGROUP_FREEZER_RESUME);
	else if (len == 7 && !strncmp(command, "su", 2)) {
		freezer_suspend_state = CGROUP_FREEZER_SUSPEND;
		cgroup_set_sysfs_state(freezer_suspend_state);
	}

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);
	return reply;
}

static DBusMessage *edbus_getfreezer_state(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	int state = freezer_get_operation_state();

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &state);

	return reply;
}

static DBusMessage *edbus_getfreezer_service(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	int state = freezer_service_enabled();

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &state);

	return reply;
}

static struct edbus_method edbus_methods[] = {
	{ "GetFreezerState",   NULL,   "i", edbus_getfreezer_state },
	{ "GetFreezerService",   NULL,   "i", edbus_getfreezer_service },
	/* Add methods here */
};

static struct edbus_method edbus_suspend_methods[] = {
	{ "SetSuspend", "s", "i", edbus_set_suspend },
	/* Add methods here */
};

void freezer_dbus_init(int mode)
{
	resourced_ret_c ret;

	register_edbus_signal_handler(RESOURCED_PATH_FREEZER, RESOURCED_INTERFACE_FREEZER,
			SIGNAL_NAME_FREEZER_STATUS,
		    (void *)freezer_signal_handler, NULL);
	register_edbus_signal_handler(RESOURCED_PATH_FREEZER, RESOURCED_INTERFACE_FREEZER,
			SIGNAL_NAME_FREEZER_SERVICE,
		    (void *)freezer_service_signal_handler, NULL);

	ret = edbus_add_methods(RESOURCED_PATH_FREEZER, edbus_methods,
		ARRAY_SIZE(edbus_methods));

	ret_msg_if(ret != RESOURCED_ERROR_NONE,
		"DBus method registration for %s is failed",
			RESOURCED_PATH_FREEZER);

	if (mode == FREEZER_ENABLE_SUSPEND) {
		register_edbus_signal_handler(DEVICED_PATH_DISPLAY, DEVICED_INTERFACE_DISPLAY,
			SIGNAL_DEVICED_LCDONCOMPLETE, (void *)freezer_lcdon_complete, NULL);

		ret = edbus_add_methods(RESOURCED_PATH_FREEZER, edbus_suspend_methods,
			    ARRAY_SIZE(edbus_suspend_methods));
		ret_msg_if(ret != RESOURCED_ERROR_NONE,
			    "DBus method registration for %s is failed",
			    RESOURCED_PATH_FREEZER);
	}
}

int freezer_init(void)
{
	resourced_ret_c ret;

	ret = cgroup_set_sysfs_state(CGROUP_FREEZER_INITIALIZED);
	_I("freezer_init : ret(%d)", ret);
	return ret;
}

void freezer_finalize(void)
{
	cgroup_set_sysfs_state(CGROUP_FREEZER_DISABLED);
}

void set_freezer_service(const enum resourced_freezer_service freezing_service)
{
	freezer_service = freezing_service;
}

void set_freezer_legacy_application(const enum freezer_state state)
{
	freezer_legacy_application = state;
}

static resourced_ret_c freezer_foreach_svc_pid(struct proc_program_info *ppi,
	freezer_action_func action,
	int type)
{
	GSList *iter = NULL;

	if (!ppi->svc_list)
		return RESOURCED_ERROR_NONE;

	if (type == SET_BACKGRD &&
	    proc_get_svc_state(ppi) == PROC_STATE_FOREGROUND)
		return RESOURCED_ERROR_NONE;

	gslist_for_each_item(iter, ppi->svc_list) {
		struct proc_app_info *pai = (struct proc_app_info *)(iter->data);

		if (pai->proc_exclude || pai->runtime_exclude)
			continue;

		if (type == SET_FOREGRD && pai->state == PROC_STATE_FOREGROUND)
			return RESOURCED_ERROR_NONE;

		if (type == SET_BACKGRD && pai->state != PROC_STATE_SUSPEND_READY)
			return RESOURCED_ERROR_NONE;

		if (type == SET_BACKGRD || get_freezer_mode() != FREEZER_ENABLE_SUSPEND) {
			if (action(pai->main_pid, type) == RESOURCED_CANCEL) {
				_E("Failed to process action for pid %d", pai->main_pid);
				continue;
			}
			if (type == SET_FOREGRD)
				pai->state = PROC_STATE_FOREGROUND;
			else
				pai->state = PROC_STATE_SUSPEND;
		} else
			prepare_suspend_process(pai->main_pid);
	}
	return RESOURCED_ERROR_NONE;
}

static resourced_ret_c freezer_foreach_pid(struct proc_app_info *pai,
	freezer_action_func action,
	int type)
{
	GSList *iter = NULL;

	if (!pai)
		return RESOURCED_ERROR_FAIL;

	if (type == SET_FOREGRD && pai->state == PROC_STATE_FOREGROUND)
		return RESOURCED_ERROR_NONE;

	if (action(pai->main_pid, type) == RESOURCED_CANCEL) {
		_E("Failed to process action for pid %d", pai->main_pid);
		return RESOURCED_ERROR_FAIL;
	}
	if (pai->childs) {
		gslist_for_each_item(iter, pai->childs) {
			struct child_pid *child = (struct child_pid *)(iter->data);
			if (action(child->pid, type) == RESOURCED_CANCEL) {
				_E("Failed to process action for pid %d", child->pid);
				return RESOURCED_ERROR_FAIL;
			}
		}
	}

	if (type == SET_FOREGRD)
		pai->state = PROC_STATE_FOREGROUND;
	else
		pai->state = PROC_STATE_SUSPEND;

	if (pai->type == PROC_TYPE_SERVICE)
		return RESOURCED_ERROR_NONE;

	if (freezer_service_enabled() ||
	    CHECK_BIT(pai->flags, PROC_BGCTRL_PLATFORM))
		freezer_foreach_svc_pid(pai->program, action, type);

	return RESOURCED_ERROR_NONE;
}

static int is_freezer_validity(pid_t pid)
{
	FILE *fp;
	pid_t lock_pid;
	fp = fopen("/proc/locks", "r");
	if (!fp) {
		_E("fopen faild (/proc/locks)");
		return RESOURCED_ERROR_NO_DATA;
	}

	while (fscanf(fp, "%*s %*s  %*s  %*s %d %*s %*s %*s", &lock_pid) != EOF) {
		if (pid == lock_pid) {
			_D("%d process has flocks", pid);
			fclose(fp);
			return RESOURCED_ERROR_NONFREEZABLE;
		}
	}
	fclose(fp);
	return RESOURCED_ERROR_NONE;
}

void freezer_set_operation_state(const enum freezer_state on)
{
	freezer_enabled = on;
}

enum freezer_state freezer_get_operation_state(void)
{
	return freezer_enabled;
}

void freezer_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int type;

	if (dbus_message_is_signal(msg, RESOURCED_INTERFACE_FREEZER, SIGNAL_NAME_FREEZER_STATUS) == 0) {
		_D("there is no freezer signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	switch (type) {
	case CGROUP_FREEZER_DISABLED:
		freezer_disable_all();
		_D("freezer on, %d, %d", freezer_get_operation_state(),
		   get_proc_freezer_late_control());
		break;
	case CGROUP_FREEZER_ENABLED:
		freezer_set_operation_state(CGROUP_FREEZER_ENABLED);
		set_proc_freezer_late_control( FREEZER_LATE_CONTROL_DEFAULT);
		_D("freezer on, %d, %d", freezer_get_operation_state(),
		   get_proc_freezer_late_control());
		break;
	default:
		_D("It is not valid freezer : %d", type);
		break;
	}
}

void freezer_service_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int type;

	if (dbus_message_is_signal(msg, RESOURCED_INTERFACE_FREEZER, SIGNAL_NAME_FREEZER_SERVICE) == 0) {
		_D("there is no freezer signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	switch (type) {
	case FREEZER_DONT_AFFECT_SERVICE:
		freezer_disable_all();
		_D("freezer on, %d, %d", freezer_get_operation_state(),
		   get_proc_freezer_late_control());
		break;
	case FREEZER_AFFECT_SERVICE:
		freezer_set_operation_state(CGROUP_FREEZER_ENABLED);
		set_proc_freezer_late_control( FREEZER_LATE_CONTROL_DEFAULT);
		_D("freezer on, %d, %d", freezer_get_operation_state(),
		   get_proc_freezer_late_control());
		set_freezer_service(FREEZER_AFFECT_SERVICE);
		break;
	default:
		_D("It is not valid freezer : %d", type);
		break;
	}
}

static resourced_ret_c freezer_process_pid_set(struct proc_app_info *pai, const int pid,
	freezer_action_func action, int type)
{
	if (!pai) {
		_E("Cant find process info for %d", pid);
		_D("freezer_process_pid_set %d", pid);
		/* imulate old behaviour */
		return action(pid, type) == RESOURCED_CANCEL ? RESOURCED_ERROR_FAIL :
			RESOURCED_ERROR_NONE;
	}

	if (pai->proc_exclude || pai->runtime_exclude)
		return RESOURCED_ERROR_NONFREEZABLE;

	_D("freezer_process_pid_set %d", pid);
	return freezer_foreach_pid(pai, action, type);
}

static resourced_cb_ret thaw_process_cb(pid_t pid, int UNUSED type)
{
	thaw_process(pid);
	return RESOURCED_CONTINUE;
}

static resourced_cb_ret freez_process_cb(pid_t pid, int UNUSED type)
{
	if (is_freezer_validity(pid) != RESOURCED_ERROR_NONFREEZABLE)
		freez_process(pid);
	return RESOURCED_CONTINUE;
}

resourced_ret_c freezer_process_backgrd(const pid_t pid,
	    struct proc_app_info *pai)
{
	/*
	 * Legacy applications under tizen 2.4 didn't have any categories
	 * about background policy.
	 * In this case, this application could be frozen
	 * when only it had UI and allowed configuration was enabled
	 */
	if ((!CHECK_BIT(pai->flags, PROC_BGCTRL_APP)) &&
	    (freezer_legacy_application_allowed() || pai->type != PROC_TYPE_GUI))
			return RESOURCED_ERROR_NONE;

	return freezer_process_pid_set(
		pai, pid, freez_process_cb, SET_BACKGRD);
}

resourced_ret_c freezer_process_foregrd(const pid_t pid,
	    struct proc_app_info *pai)
{
	return freezer_process_pid_set(
		pai, pid, thaw_process_cb, SET_FOREGRD);
}

resourced_ret_c freezer_process_svc_foregrd(const pid_t pid,
	    struct proc_app_info *pai)
{
	struct proc_program_info *ppi = pai->program;

	return freezer_foreach_svc_pid(
		ppi, thaw_process_cb, SET_FOREGRD);
}

void freezer_disable_all(void)
{
	freezer_set_operation_state(CGROUP_FREEZER_DISABLED);
	cgroup_set_sysfs_state(CGROUP_FREEZER_DISABLED);
	set_proc_freezer_late_control(FREEZER_LATE_CONTROL_DISABLED);
}

void freezer_runtime_enable(void)
{
	GSList *iter;
	pid_t pid;
	int oom_score_adj;
	int freeze_val = get_proc_freezer_late_control();
	struct proc_app_info *pai = NULL;

	gslist_for_each_item(iter, proc_app_list) {
		pai = (struct proc_app_info *)iter->data;
		pid = pai->main_pid;
		if ((pai->type == PROC_TYPE_SERVICE) || !pid ||
			    (proc_get_oom_score_adj(pid, &oom_score_adj) < 0))
			continue;
		if (proc_check_lru_suspend(freeze_val, pai->lru_state))
			freezer_process_backgrd(pid, pai);
	}
}
