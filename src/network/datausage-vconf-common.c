/*
 * resourced
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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

#include <resourced.h>
#include <vconf.h>

#include "trace.h"
#include "data_usage.h"
#include "datausage-vconf-common.h"

#ifndef VCONFKEY_SETAPPL_SET_DATA_USAGE_LIMIT_BOOL
#define VCONFKEY_SETAPPL_SET_DATA_USAGE_LIMIT_BOOL "db/setting/set_data_usage_limit"
#endif

#ifndef VCONFKEY_SETAPPL_DATA_LIMIT_INT
#define VCONFKEY_SETAPPL_DATA_LIMIT_INT "db/setting/data_limit"
#endif

#ifndef VCONFKEY_SETAPPL_DATA_RESTRICTION_INT
#define VCONFKEY_SETAPPL_DATA_RESTRICTION_INT "db/setting/data_restriction"
#endif

resourced_ret_c restriction_check_limit_status(int *retval)
{
	if (vconf_get_bool(VCONFKEY_SETAPPL_SET_DATA_USAGE_LIMIT_BOOL, retval)) {
		_E("vconf_get_bool FAIL\n");
		return RESOURCED_ERROR_FAIL;
	};

	return RESOURCED_ERROR_NONE;
}

void restriction_set_status(int value)
{
	int limit = RESTRICTION_STATE_INIT;

	if (vconf_get_int(VCONFKEY_SETAPPL_DATA_RESTRICTION_INT, &limit)) {
		_E("vconf_get_int FAIL\n");
		return;
	}

	if (limit == value) {
		_E("No need to change a restriction status: %d", limit);
		return;
	}

	vconf_set_int(VCONFKEY_SETAPPL_DATA_RESTRICTION_INT, value);
	return;
}
