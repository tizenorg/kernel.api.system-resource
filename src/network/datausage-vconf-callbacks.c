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
 */

/*
 *  @file: datausage-vconf-callbacks.c
 *
 *  @desc Add datausage callback functions to vconf
 *
 */

#include "const.h"
#include "counter.h"
#include "daemon-options.h"
#include "datausage-vconf-callbacks.h"
#include "datausage-quota-processing.h"
#include "datausage-quota.h"
#include "iface.h"
#include "macro.h"
#include "resourced.h"
#include "settings.h"
#include "trace.h"

#include <stdlib.h>
#include <vconf.h>

static void wifi_change_cb(keynode_t *key, void *data)
{
	int val = vconf_keynode_get_bool(key);
	_SD("key = %s, value = %d(int)\n",
	    vconf_keynode_get_name(key), val);
	set_wifi_allowance(val ?
			   RESOURCED_OPTION_ENABLE : RESOURCED_OPTION_DISABLE);
}

static void datacall_change_cb(keynode_t *key, void *data)
{
	int val = vconf_keynode_get_bool(key);

	_SD("key = %s, value = %d(int)\n",
	    vconf_keynode_get_name(key), val);
	set_datacall_allowance(val ? RESOURCED_OPTION_ENABLE :
			       RESOURCED_OPTION_DISABLE);
}

static void datacall_logging_change_cb(keynode_t *key, void *data)
{
	struct daemon_opts *options = (struct daemon_opts *)data;
	int val = vconf_keynode_get_bool(key);

	if (!options) {
		_E("Please provide valid argument!");
		return;
	}
	_SD("key = %s, value = %d(int)\n",
	    vconf_keynode_get_name(key), val);
	options->datacall_logging = val ? RESOURCED_OPTION_ENABLE :
		RESOURCED_OPTION_DISABLE;
}

static void datausage_timer_change_cb(keynode_t *key, void *data)
{
	struct daemon_opts *options = (struct daemon_opts *)data;
	int val = vconf_keynode_get_int(key);

	if (!options) {
		_E("Please provide valid argument!");
		return;
	}
	_SD("key = %s, value = %d(int)\n",
	    vconf_keynode_get_name(key), val);

	options->update_period = val;
}

void resourced_add_vconf_datausage_cb(struct counter_arg *carg)
{
	_D("Add vconf datausage callbacks\n");
	ret_msg_if(!carg || !carg->opts,
			 "Please provide valid argument!");
	vconf_notify_key_changed(RESOURCED_WIFI_STATISTICS_PATH, wifi_change_cb,
				 NULL);
	vconf_notify_key_changed(RESOURCED_DATACALL_PATH, datacall_change_cb,
				 NULL);
	vconf_notify_key_changed(RESOURCED_DATAUSAGE_TIMER_PATH,
				 datausage_timer_change_cb, (void *)carg->opts);
	vconf_notify_key_changed(RESOURCED_DATACALL_LOGGING_PATH,
				 datacall_logging_change_cb,
				 (void *)carg->opts);
}

void resourced_remove_vconf_datausage_cb(void)
{
	_D("Remove vconf datausage callbacks\n");
	vconf_ignore_key_changed(RESOURCED_WIFI_STATISTICS_PATH,
				 wifi_change_cb);
	vconf_ignore_key_changed(RESOURCED_DATACALL_PATH, datacall_change_cb);
	vconf_ignore_key_changed(RESOURCED_DATAUSAGE_TIMER_PATH,
				 datausage_timer_change_cb);
	vconf_ignore_key_changed(RESOURCED_DATACALL_LOGGING_PATH,
				 datacall_logging_change_cb);
}
