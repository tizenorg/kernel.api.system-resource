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
 *  @file tethering-restriction.h
 *  @desc Performance management API. Tethering restriction.
 *  @version 1.0
 *
 *  Created on: May 14, 2013
 */

#ifndef RESOURCED_TETHERING_RESTRICTION_H_
#define RESOURCED_TETHERING_RESTRICTION_H_

#include "transmission.h"

#define PATH_TO_PROC_IP_FORWARD "/proc/sys/net/ipv4/ip_forward"

/*
 * @desc Apply tethering restriction for tethering pseudo app
 */
resourced_ret_c apply_tethering_restriction(
	const enum traffic_restriction_type type);

#endif /* RESOURCED_TETHERING_RESTRICTION_H_ */
