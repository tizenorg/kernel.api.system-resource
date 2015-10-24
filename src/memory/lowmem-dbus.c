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
#include "memory-common.h"
#include "procfs.h"

static void lowmem_dbus_oom_set_threshold(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	int level, thres;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_OOM,
	    SIGNAL_OOM_SET_THRESHOLD);

	if (ret == 0) {
		_D("there is no oom set threshold signal");
		return;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &level,
	    DBUS_TYPE_INT32, &thres, DBUS_TYPE_INVALID);

	if (ret == 0) {
		_D("there is no message");
		return;
	}

	lowmem_memcg_set_threshold(MEMCG_MEMORY, level, thres);
}

static void lowmem_dbus_oom_set_leave_threshold(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	int thres;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_OOM,
	    SIGNAL_OOM_SET_LEAVE_THRESHOLD);

	if (ret == 0) {
		_D("there is no oom set leave threshold signal");
		return;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &thres,
	    DBUS_TYPE_INVALID);

	if (ret == 0) {
		_D("there is no message");
		return;
	}

	lowmem_memcg_set_leave_threshold(MEMCG_MEMORY, thres);
}

static void lowmem_dbus_oom_trigger(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_OOM,
	    SIGNAL_OOM_TRIGGER);
	if (ret == 0) {
		_D("there is no oom trigger signal");
		return;
	}

	dbus_error_init(&err);

	lowmem_change_memory_state(LOWMEM_LOW, 1);
	lowmem_memory_oom_killer(OOM_FORCE | OOM_NOMEMORY_CHECK);
	lowmem_change_memory_state(LOWMEM_NORMAL, 0);
}

static void lowmem_dbus_set_perceptible(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	pid_t pid;

	dbus_error_init(&err);
	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_OOM,
	    SIGNAL_OOM_SET_PERCEPTIBLE);
	if (ret == 0) {
		_D("there is no set perceptible signal");
		return;
	}

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &pid,
		    DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}
	dbus_error_free(&err);
	proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_PERCEPTIBLE);
}

static void lowmem_dbus_set_platform(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	pid_t pid;

	dbus_error_init(&err);
	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_OOM,
	    SIGNAL_OOM_SET_PLATFORM);
	if (ret == 0) {
		_D("there is no set platform swap signal");
		return;
	}

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &pid,
		    DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}
	dbus_error_free(&err);
	lowmem_trigger_swap(pid, MEMCG_PLATFORM);
}

static const struct edbus_signal edbus_signals[] = {
	/* RESOURCED DBUS */
	{RESOURCED_PATH_OOM, RESOURCED_INTERFACE_OOM,
	    SIGNAL_OOM_SET_THRESHOLD, lowmem_dbus_oom_set_threshold, NULL},
	{RESOURCED_PATH_OOM, RESOURCED_INTERFACE_OOM,
	    SIGNAL_OOM_SET_LEAVE_THRESHOLD,
	    lowmem_dbus_oom_set_leave_threshold, NULL},
	{RESOURCED_PATH_OOM, RESOURCED_INTERFACE_OOM,
	    SIGNAL_OOM_TRIGGER, lowmem_dbus_oom_trigger, NULL},
	{RESOURCED_PATH_OOM, RESOURCED_INTERFACE_OOM,
	    SIGNAL_OOM_SET_PERCEPTIBLE, lowmem_dbus_set_perceptible, NULL},
	{RESOURCED_PATH_OOM, RESOURCED_INTERFACE_OOM,
	    SIGNAL_OOM_SET_PLATFORM, lowmem_dbus_set_platform, NULL},
};

void lowmem_dbus_init(void)
{
	edbus_add_signals(edbus_signals, ARRAY_SIZE(edbus_signals));
}
