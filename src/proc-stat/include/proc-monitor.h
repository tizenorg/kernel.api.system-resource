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
 * @file proc-monitor.h
 * @desc  proc monitor
 **/

#ifndef __RESOURCED_PROC_MONITOR_H__
#define __RESOURCED_PROC_MONITOR_H__

#include <resourced.h>

/*
  * Initialize proc monitor module by registering it in edbus.
  */

enum proc_watchdog_type {
	PROC_WATCHDOG_DISABLE,
	PROC_WATCHDOG_ENABLE,
};

enum proc_dbus_use_type { /** cgroup command type **/
	PROC_DBUS_DISABLE,
	PROC_DBUS_ENABLE,
};

void proc_set_watchdog_state(int state);

#endif /* __RESOURCED_PROC_MONITOR_H__ */

