/*
 * resourced
 *
 * Copyright (c) 2012 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
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

/*
 * @file lowmem_dbus.c
 *
 * @desc lowmem dbus for oom triger
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <Ecore.h>

#include "trace.h"
#include "lowmem-handler.h"
#include "edbus-handler.h"
#include "resourced.h"
#include "macro.h"

#define SIGNAL_NAME_OOM_SET_THRESHOLD			"SetThreshold"
#define SIGNAL_NAME_OOM_SET_LEAVE_THRESHOLD		"SetLeaveThreshold"
#define SIGNAL_NAME_OOM_TRIGGER			"Trigger"

static void lowmem_dbus_oom_set_threshold(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	int level, thres;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_OOM, SIGNAL_NAME_OOM_SET_THRESHOLD);

	if (ret == 0) {
		_D("there is no oom set threshold signal");
		return;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &level, DBUS_TYPE_INT32, &thres, DBUS_TYPE_INVALID);

	if (ret == 0) {
		_D("there is no message");
		return;
	}

	set_threshold(level, thres);
}

static void lowmem_dbus_oom_set_leave_threshold(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	int thres;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_OOM, SIGNAL_NAME_OOM_SET_LEAVE_THRESHOLD);

	if (ret == 0) {
		_D("there is no oom set leave threshold signal");
		return;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &thres, DBUS_TYPE_INVALID);

	if (ret == 0) {
		_D("there is no message");
		return;
	}

	set_leave_threshold(thres);
}

static void lowmem_dbus_oom_trigger(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	int launching = 0;
	int flags = OOM_FORCE;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_OOM, SIGNAL_NAME_OOM_TRIGGER);
	if (ret == 0) {
		_D("there is no oom trigger signal");
		return;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &launching, DBUS_TYPE_INVALID);

	if (launching)
		flags |= OOM_NOMEMORY_CHECK;

	change_memory_state(MEMNOTIFY_LOW, 1);
	lowmem_oom_killer_cb(MEMCG_MEMORY, flags);
	_D("flags = %d", flags);
	change_memory_state(MEMNOTIFY_NORMAL, 0);
}

void lowmem_dbus_init(void)
{
	register_edbus_signal_handler(RESOURCED_PATH_OOM, RESOURCED_INTERFACE_OOM,
			SIGNAL_NAME_OOM_SET_THRESHOLD,
		    lowmem_dbus_oom_set_threshold);
	register_edbus_signal_handler(RESOURCED_PATH_OOM, RESOURCED_INTERFACE_OOM,
			SIGNAL_NAME_OOM_SET_LEAVE_THRESHOLD,
		    lowmem_dbus_oom_set_leave_threshold);
	register_edbus_signal_handler(RESOURCED_PATH_OOM, RESOURCED_INTERFACE_OOM,
			SIGNAL_NAME_OOM_TRIGGER,
		    lowmem_dbus_oom_trigger);

}
