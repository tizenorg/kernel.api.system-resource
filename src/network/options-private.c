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

/*
 *  @file: daemon-options.c
 *
 *  @desc Entity for working with daemon options
 *
 */

#include "config-parser.h"
#include "config.h"
#include "counter.h"
#include "const.h"
#include "iface.h"
#include "macro.h"
#include "resourced.h"
#include "settings.h"
#include "trace.h"

#include <stdlib.h>

#define GENERAL_SECTION "General"
#define NET_CONF_FILE "/etc/resourced/network.conf"
#define NET_UPDATE_PERIOD_NAME "update_period"
#define NET_FLUSH_PERIOD_NAME "flush_period"

static int fill_general_opt(struct parse_result *result,
		void *user_data)
{
	struct net_counter_opts *opts = (struct net_counter_opts *)user_data;
	if (strcmp(result->section, GENERAL_SECTION))
		return RESOURCED_ERROR_NONE;

	if (strcmp(result->name, NET_UPDATE_PERIOD_NAME) == 0) {
		opts->update_period = atoi(result->value);
		if (opts->update_period == 0) {
			_D("not valid value %s for %s key", result->value,
			   NET_UPDATE_PERIOD_NAME);
			/* use default value */
			opts->update_period = COUNTER_UPDATE_PERIOD;
		} else
			_D("update period is %d", opts->update_period);
	}

	if (strcmp(result->name, NET_FLUSH_PERIOD_NAME) == 0) {
		opts->flush_period = atoi(result->value);
		if (opts->flush_period == 0) {
			_D("not valid value %s for %s key", result->value,
			   NET_FLUSH_PERIOD_NAME);
			/* use default value */
			opts->flush_period = COUNTER_FLUSH_PERIOD;
		} else
			_D("flush period is %d", opts->flush_period);
	}
	return RESOURCED_ERROR_NONE;
}

static int parse_net_conf(struct parse_result *result,
		void *user_data)
{
	fill_general_opt(result, user_data);
	return fill_ifaces_relation(result, user_data);
}

void load_network_opts(struct net_counter_opts *opts)
{
	int ret = 0;
	/* public structure used only for serialization */
	resourced_net_options options = { 0 };

	ret_msg_if(opts == NULL,
			 "Invalid daemon options argument\n");

	load_vconf_net_options(&options);

	set_wifi_allowance(options.wifi);
	set_datacall_allowance(options.datacall);
	/* TODO replace it to set_datacall_logging
	 * get_datacall_loging in datausage_foreach function */
	/*opts->datacall_logging = options.datacall_logging;*/

	ret = config_parse(NET_CONF_FILE,
			   parse_net_conf, opts);
	if (ret != 0)
		_D("Can't parse config file %s",
		   NET_CONF_FILE);

}
