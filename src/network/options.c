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
 * @file options.c
 *
 * @desc Implementation of API for option tweaking:
 *	wifi - collect information for wifi
 *	datacall - collect information for packet data
 *	datausage_time - kernel update period
 *
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vconf/vconf.h>

#include "macro.h"
#include "settings.h"
#include "trace.h"
#include "resourced.h"
#include "const.h"

static int save_options(const resourced_options *options)
{
	if (!options) {
		_E("Please provid valid argument!");
		return -1;
	}

	if (vconf_set_bool(RESOURCED_WIFI_STATISTICS_PATH,
		options->wifi ==  RESOURCED_OPTION_ENABLE ? 1 : 0) != 0) {
		_D("Can not get WiFi statistics settings");
		return -1;
	}

	if (vconf_set_bool(RESOURCED_DATACALL_PATH,
		options->datacall == RESOURCED_OPTION_ENABLE ? 1 : 0) != 0) {
		_D("Can not get DataCall settings");
		return -1;
	}

	if (vconf_set_int(RESOURCED_DATAUSAGE_TIMER_PATH,
		options->datausage_timer) != 0) {
		_D("Can not get DataUsage timer settings");
		return -1;
	}

	if (vconf_set_bool(RESOURCED_DATACALL_LOGGING_PATH,
		options->datacall_logging == RESOURCED_OPTION_ENABLE ? 1 : 0) != 0) {
		_D("Can not get DataCall logging settings");
		return -1;
	}
	return 0;
}

API resourced_ret_c set_resourced_options(const resourced_options *options)
{
	return save_options(options) ? RESOURCED_ERROR_FAIL : RESOURCED_ERROR_NONE;
}

API resourced_ret_c get_resourced_options(resourced_options *options)
{
	return load_options(options) ? RESOURCED_ERROR_FAIL : RESOURCED_ERROR_NONE;
}
