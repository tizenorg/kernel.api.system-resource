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


#ifndef __NOTIFIER_H__
#define __NOTIFIER_H__

enum notifier_type {
	/*
	 * application status
	 */
	RESOURCED_NOTIFIER_APP_LAUNCH,
	RESOURCED_NOTIFIER_APP_RESUME,
	RESOURCED_NOTIFIER_APP_FOREGRD,
	RESOURCED_NOTIFIER_APP_BACKGRD,
	RESOURCED_NOTIFIER_APP_BACKGRD_ACTIVE,
	RESOURCED_NOTIFIER_APP_ACTIVE,
	RESOURCED_NOTIFIER_APP_INACTIVE,
	RESOURCED_NOTIFIER_APP_PRELAUNCH,
	RESOURCED_NOTIFIER_APP_ANR,
	/*
	 * start terminating application
	 */
	RESOURCED_NOTIFIER_APP_TERMINATE_START,
	/*
	 * finished application termination
	 */
	RESOURCED_NOTIFIER_APP_TERMINATED,

	/*
	 * suspend background application
	 */
	RESOURCED_NOTIFIER_APP_WAKEUP,
	RESOURCED_NOTIFIER_APP_SUSPEND_READY,
	RESOURCED_NOTIFIER_APP_SUSPEND,

	/*
	 * service status
	 */
	RESOURCED_NOTIFIER_SERVICE_LAUNCH,
	RESOURCED_NOTIFIER_SERVICE_WAKEUP,

	/*
	 * widget status
	 */
	RESOURCED_NOTIFIER_WIDGET_FOREGRD,
	RESOURCED_NOTIFIER_WIDGET_BACKGRD,

	/*
	 * control resourced module
	 */
	RESOURCED_NOTIFIER_FREEZER_CGROUP_STATE,
	RESOURCED_NOTIFIER_SWAP_START,
	RESOURCED_NOTIFIER_SWAP_UNSET_LIMIT,
	RESOURCED_NOTIFIER_LOGGING_START,
	RESOURCED_NOTIFIER_LOGGING_WRITE,
	RESOURCED_NOTIFIER_DATA_UPDATE,
	RESOURCED_NOTIFIER_DATA_RESET,
	RESOURCED_NOTIFIER_SYSTEM_SERVICE,
	RESOURCED_NOTIFIER_CONTROL_EXCLUDE,

	/*
	 * receive external event
	 */
	RESOURCED_NOTIFIER_BOOTING_DONE,
	RESOURCED_NOTIFIER_POWER_OFF,
	RESOURCED_NOTIFIER_LOW_BATTERY,
	RESOURCED_NOTIFIER_LCD_ON,
	RESOURCED_NOTIFIER_LCD_OFF,

	RESOURCED_NOTIFIER_MAX,
};

/*
 * This is for internal callback method.
 */
int register_notifier(enum notifier_type status, int (*func)(void *data));
int unregister_notifier(enum notifier_type status, int (*func)(void *data));
void resourced_notify(enum notifier_type status, void *value);

#endif /* __NOTIFIER_H__ */
