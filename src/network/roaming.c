/*
 *  resourced
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

/*
 *
 * @file roaming.c
 *
 * @desc Roaming persistent object. Due roaming changes not so often we can keep it in
 *  our memory and handle roaming changes.
 *  In this file we keep roaming state in global variable and change it in callback.
 */

#include <glib.h>
#include <telephony_network.h>

#include "roaming.h"
#include "trace.h"
#include "macro.h"

static resourced_roaming_type roaming_state;

/* for avoiding dependency in this file */

static GSList *roaming_callbacks;

static void invoke_roaming_callbacks(void)
{
	GSList *func_iter = NULL;
	gslist_for_each_item(func_iter, roaming_callbacks) {
		if (func_iter && func_iter->data)
			((roaming_cb)func_iter->data)();
	}
}

void regist_roaming_cb(roaming_cb cb)
{
	roaming_callbacks = g_slist_prepend(roaming_callbacks, cb);
}

static void on_roaming_change(bool new_roaming,
	void UNUSED *user_data)
{
	_D("Roaming is changed %d", (int)new_roaming);
	roaming_state = new_roaming ? RESOURCED_ROAMING_ENABLE : RESOURCED_ROAMING_DISABLE;
	invoke_roaming_callbacks();
}

/**
 * @brief Get initial value for roaming and sets callback for handling roaming change
 */
static void init_roaming_state(void)
{
	bool roaming = false;

	if (network_info_set_roaming_state_changed_cb(on_roaming_change,
		NULL) != NETWORK_INFO_ERROR_NONE)
		_E("Can not register callback for handle roaming changes.");

	if (network_info_is_roaming(&roaming) != NETWORK_INFO_ERROR_NONE)
		_E("Failed to get initial roaming state!");

	roaming_state = roaming ?
		RESOURCED_ROAMING_ENABLE : RESOURCED_ROAMING_DISABLE;
}

resourced_roaming_type get_roaming(void)
{
	execute_once {
		init_roaming_state();
	}
	return roaming_state;
}

