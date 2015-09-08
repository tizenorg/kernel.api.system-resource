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

/*
 *
 * @file settings.c
 *
 * @desc Entity for load vconf options
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <vconf/vconf.h>

#include "macro.h"
#include "settings.h"
#include "trace.h"

API int load_options(resourced_options *options)
{
	int val = 0;

	if (!options) {
		_E("Please provide valid argument!");
		return -1;
	}
	if (vconf_get_bool(RESOURCED_WIFI_STATISTICS_PATH, &val) == 0)
		options->wifi = val ?
			RESOURCED_OPTION_ENABLE : RESOURCED_OPTION_DISABLE;
	else {
		_D("Can not get WiFi statistics settings");
		return -1;
	}

	if (vconf_get_bool(RESOURCED_DATACALL_PATH, &val) == 0)
		options->datacall = val ?
			RESOURCED_OPTION_ENABLE : RESOURCED_OPTION_DISABLE;
	else {
		_D("Can not get DataCall settings");
		return -1;
	}

	if (vconf_get_int(RESOURCED_DATAUSAGE_TIMER_PATH, &val) == 0)
		options->datausage_timer = val;
	else {
		_D("Can not get DataUsage timer settings");
		return -1;
	}

	if (vconf_get_bool(RESOURCED_DATACALL_LOGGING_PATH, &val) == 0)
		options->datacall_logging = val ?
	RESOURCED_OPTION_ENABLE : RESOURCED_OPTION_DISABLE;
	else {
		_D("Can not get DataCall logging settings");
		return -1;
	}
	return 0;
}
