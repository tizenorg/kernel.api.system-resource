/*
 * resourced
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file freezer.h
 * @desc Freezer library definitions
 **/


#ifndef __FREEZER_H__
#define __FREEZER_H__

#include <glib.h>

/* Freezer dbus signal names */
#define SIGNAL_FREEZER_STATE            "FreezerState"
#define SIGNAL_FREEZER_SERVICE          "FreezerService"
#define SIGNAL_FREEZER_STATUS           "FreezerStatus"

/* Freezer dbus method names */
#define METHOD_GET_FREEZER_STATE        "GetFreezerState"
#define METHOD_GET_FREEZER_SERVICE      "GetFreezerService"
#define METHOD_SET_FREEZER_SUSPEND      "SetSuspend"

/* Freezer cgroup state */
enum freezer_state {
	CGROUP_FREEZER_DISABLED,
	CGROUP_FREEZER_ENABLED,
	CGROUP_FREEZER_INITIALIZED,
	CGROUP_FREEZER_PAUSED,
	CGROUP_FREEZER_VITAL_SLEEP,
	CGROUP_FREEZER_VITAL_WAKEUP,
	CGROUP_FREEZER_VITAL_DISPLAY_WAKEUP,
	CGROUP_FREEZER_VITAL_EXIT,
};

/* Freezer cgroup state request type */
enum freezer_status_type {
	GET_STATUS,
	SET_STATUS,
};

/* Freezer cgroup state request payload */
struct freezer_status_data {
	int type;
	int status;
};

/* Freezer module init data (to be passed from resourced) */
struct freezer_init_data {
	GSList **resourced_app_list;
};

/* Freezer cgroup late control setting retrieval */
int resourced_freezer_proc_late_control(void);

#endif /* __FREEZER_H__ */

