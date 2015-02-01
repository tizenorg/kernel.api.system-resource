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
 * @file restriction-helper.h
 * @desc Helper restriction functions
 */

#ifndef _RESOURCED_RESTRICTION_HELPER_H_
#define _RESOURCED_RESTRICTION_HELPER_H_

#include "resourced.h"
#include "transmission.h"

resourced_iface_type get_store_iftype(const u_int32_t app_classid,
				      const resourced_iface_type iftype);

resourced_restriction_state convert_to_restriction_state(
	const enum traffic_restriction_type rst_type);

enum traffic_restriction_type convert_to_restriction_type(
	const resourced_restriction_state rst_state);

int check_restriction_arguments(const char *appid,
				const resourced_net_restrictions *rst,
				const enum traffic_restriction_type rst_type);

#endif /* _RESOURCED_RESTRICTION_HELPER_H_ */
