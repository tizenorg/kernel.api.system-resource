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
 */

/*
 *  @file: freezer-vconf-callbacks.c
 *
 *  @desc Add freezer callback functions to vconf
 *
 */

#include "freezer-vconf-callbacks.h"
#include "freezer-process.h"
#include "freezer-common.h"
#include "macro.h"
#include "trace.h"

#include <vconf.h>

static void freezer_control_cb(keynode_t *key, UNUSED void *data)
{
	int state = 0;

	if (vconf_get_int(VCONFKEY_SETAPPL_PSMODE, &state))
		return;

	_SD("VCONFKEY_SETAPPL_PSMODE is changed value : %d", state);

	if (state >= SETTING_PSMODE_EMERGENCY) {
		if (freezer_get_operation_state() == CGROUP_FREEZER_DISABLED) {
			freezer_set_operation_state(CGROUP_FREEZER_ENABLED);
			set_proc_freezer_late_control(FREEZER_LATE_CONTROL_DEFAULT);
			freezer_runtime_enable();
		}
	} else {
		if (freezer_get_operation_state() != CGROUP_FREEZER_DISABLED)
			freezer_disable_all();
	}
}

void resourced_add_vconf_freezer_cb(void)
{
	_D("Add vconf freezer callbacks\n");
	vconf_notify_key_changed(VCONFKEY_SETAPPL_PSMODE,
				 freezer_control_cb, NULL);
}

void resourced_remove_vconf_freezer_cb(void)
{
	_D("Remove vconf freezer callbacks\n");
	vconf_ignore_key_changed(VCONFKEY_SETAPPL_PSMODE, freezer_control_cb);
}
