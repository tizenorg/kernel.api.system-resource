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
 * @file freezer-process.h
 * @desc Freezing apropriate process
 **/


#ifndef __FREEZER_PROCESS_H__
#define __FREEZER_PROCESS_H__

#include <glib.h>
#include "cgroup.h"
#include "edbus-handler.h"
#include "proc-common.h"

#define SIGNAL_NAME_FREEZER_STATUS	"FreezerStatus"
#define SIGNAL_NAME_FREEZER_SERVICE	"FreezerService"

enum FREEZER_CONTROL_TYPE {
	FREEZER_LATE_CONTROL_DISABLED,
	FREEZER_LATE_CONTROL_FIRST_BACKGROUND,
	FREEZER_LATE_CONTROL_SECOND_BACKGROUND,
	FREEZER_LATE_CONTROL_THIRD_BACKGROUND,
};

#define FREEZER_LATE_CONTROL_DEFAULT FREEZER_LATE_CONTROL_FIRST_BACKGROUND

enum resourced_freezer_service {
	FREEZER_DONT_AFFECT_SERVICE,	/**< means do not freez 3rd party
					     services */
	FREEZER_AFFECT_SERVICE,		/**< freez 3rd party services */
};

enum freezer_type {
	FREEZER_INCLUDE,
	FREEZER_EXCLUDE,
};

typedef resourced_cb_ret(*freezer_action_func) (pid_t pid, int type);

/**
 * @desc This function is responsible for changing cgroup states, it sets THAWED
 *	Function is stable to appid argument absence, due we have a clients
 *	both with appid or without appid.
 * @param pid - pid to place to cgroup in case of cgroup absence
 */
int freezer_process_foregrd(const pid_t pid, struct proc_app_info *pai);

/**
 * @desc The behavior of this function is the same as @see freezer_process_foregrd
 * It changes cgroup state to FROZEN.
 */
int freezer_process_backgrd(const pid_t pid, struct proc_app_info *pai);

/**
 * @desc This function is responsible for moving process ids to thawed group.
 *	Function is only used to thaw service application without thawing UI application.
 * @param pid - pid to place to cgroup in case of cgroup absence
 * @param pai - application information list
 */
int freezer_process_svc_foregrd(const pid_t pid,
	    struct proc_app_info *pai);


/**
 * @desc This function creates freezer cgroup in case of it absence and in case
 * of appid presented in argument
 * @param pid - pid to add in freezer exclude-list
 * @param appid - unique application id to check from exclude_list
 * @return RESOURCED_ERROR_NONE - in case of successfull appending
 *         RESOURCED_ERROR_NONFREEZABLE - in case of appid in exclude list
 *         RESOURCED_ERROR_FAIL - in case of appid,pid already exist
 */
resourced_ret_c freezer_add_process_list(const int pid, const char *appid);

/**
 * @desc This function removes pid in exclude_list.
 * @param pid - pid to remove in freezer exclude-list
 */
int freezer_remove_process_list(const int pid);


/**
 * @desc This function sets freezer availability from argument.
 * @param on - 1 : on / 0 : off value
 */
void freezer_set_operation_state(const enum freezer_state on);

/**
 * @desc This function reads freezer availability. default value is disable.
 * @return freezer_state - client everywhere already used freezer_state
 */
enum freezer_state freezer_get_operation_state(void);

void freezer_signal_handler(void *data, DBusMessage *msg);
void freezer_service_signal_handler(void *data, DBusMessage *msg);

/**
 * @desc Initialize appid exclude list and file change notification handler
 */
int freezer_init(void);

/**
 * @desc Deinitialize exclude lists, close handlers
 */
void freezer_finalize(void);

/**
 * @desc Set operation and sysfs state to DISABLED
 * in case of sysfs state we also moving all frozen pids to
 * thawed cgroup
 */
void freezer_disable_all(void);

/**
 * @desc Freeze all background availabe processes at runtime
 */
void freezer_runtime_enable(void);


/**
 * @desc Set state for supporting 3rd party services
 */
void set_freezer_service(const enum resourced_freezer_service);

/**
 * @desc Set policy for controlling legacy application
 * in version of under Tizen 2.4.
 */
void set_freezer_legacy_application(const enum freezer_state state);

void fill_exclude_list_by_path(const char *exclude_file_name, GHashTable *list);

resourced_ret_c freezer_set_exclude_list(const int pid, int type);

void freezer_dbus_init(int mode);

#endif /* __FREEZER_PROCESS_H__ */
