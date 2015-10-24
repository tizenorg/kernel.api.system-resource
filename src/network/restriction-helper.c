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

/**
 * @file restriction-helper.c
 * @desc Helper restriction functions
 */

#include "const.h"
#include "data_usage.h"
#include "macro.h"
#include "trace.h"
#include "transmission.h"

resourced_iface_type get_store_iftype(const u_int32_t app_classid,
				      const resourced_iface_type iftype)
{
	/* in general tethering is based on datacall interface */
	return (app_classid == RESOURCED_TETHERING_APP_CLASSID) ?
		RESOURCED_IFACE_DATACALL : iftype;
}

resourced_restriction_state convert_to_restriction_state(
	const enum traffic_restriction_type rst_type)
{
	switch (rst_type) {
	case RST_SET:
		return RESOURCED_RESTRICTION_ACTIVATED;
	case RST_UNSET:
		return RESOURCED_RESTRICTION_REMOVED;
	case RST_EXCLUDE:
		return RESOURCED_RESTRICTION_EXCLUDED;
	default:
		return RESOURCED_RESTRICTION_UNKNOWN;
	}
}

enum traffic_restriction_type convert_to_restriction_type(
	const resourced_restriction_state rst_state)
{
	switch (rst_state) {
	case RESOURCED_RESTRICTION_ACTIVATED:
		return RST_SET;
	case RESOURCED_RESTRICTION_REMOVED:
		return RST_UNSET;
	case RESOURCED_RESTRICTION_EXCLUDED:
		return RST_EXCLUDE;
	default:
		return RST_UNDEFINDED;
	}
}

int check_restriction_arguments(const char *appid,
				const resourced_net_restrictions *rst,
				const enum traffic_restriction_type rst_type)
{
	ret_value_secure_msg_if(!appid, RESOURCED_ERROR_INVALID_PARAMETER,
				"appid is required argument\n");
	ret_value_msg_if(
		rst_type <= RST_UNDEFINDED || rst_type >= RST_MAX_VALUE,
		RESOURCED_ERROR_INVALID_PARAMETER,
		"Invalid restriction_type %d\n", rst_type);
	ret_value_msg_if(!rst, RESOURCED_ERROR_INVALID_PARAMETER,
			 "Restriction should be set\n");
	ret_value_msg_if(rst->iftype <= RESOURCED_IFACE_UNKNOWN ||
			 rst->iftype >= RESOURCED_IFACE_LAST_ELEM,
			 RESOURCED_ERROR_INVALID_PARAMETER,
			 "Invalid restriction network interface type %d\n",
			 rst->iftype);
	if (rst_type == RST_SET) {
		ret_value_msg_if(rst->send_limit < 0,
				 RESOURCED_ERROR_INVALID_PARAMETER,
				 "Invalid send_limit %d\n", rst->send_limit);
		ret_value_msg_if(rst->rcv_limit < 0,
				 RESOURCED_ERROR_INVALID_PARAMETER,
				 "Invalid rcv_limit %d\n", rst->rcv_limit);
		ret_value_msg_if(rst->snd_warning_limit < 0,
				 RESOURCED_ERROR_INVALID_PARAMETER,
				 "Invalid snd_warning_limit %d\n",
				 rst->snd_warning_limit);
		ret_value_msg_if(rst->rcv_warning_limit < 0,
				 RESOURCED_ERROR_INVALID_PARAMETER,
				 "Invalid rcv_warning_limit %d\n",
				 rst->rcv_warning_limit);
	}

	/* check roaming */
	ret_value_msg_if(rst->roaming >= RESOURCED_ROAMING_LAST_ELEM,
		RESOURCED_ERROR_INVALID_PARAMETER,
		"roaming is not valid %d", rst->roaming);
	/* check imsi */
	ret_value_msg_if(rst->imsi == NULL,
		RESOURCED_ERROR_INVALID_PARAMETER,
		"imsi is not valid");
	return RESOURCED_ERROR_NONE;
}
