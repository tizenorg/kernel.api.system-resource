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

#ifndef __RESOURCED_DBUS_H__
#define __RESOURCED_DBUS_H__

#include <stdbool.h>
#include <dbus/dbus.h>
#include <E_DBus.h>

E_DBus_Connection *resourced_dbus_monitor_new(DBusBusType type, DBusHandleMessageFunction filter_func, const char * const *filters);

bool resourced_dbus_pid_has_busname(pid_t pid);
unsigned int resourced_dbus_pid_get_busnames(pid_t pid, char ***busnames);
pid_t resourced_dbus_get_pid_of_busname(const char *busname);

#endif /* __RESOURCED_DBUS_H__ */
