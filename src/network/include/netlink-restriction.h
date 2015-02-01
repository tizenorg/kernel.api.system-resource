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
 *  @file net-restriction.h
 *  @desc Performance management API. Network restriction.
 *  @version 1.0
 *
 *  Created on: Jun 18, 2012
 */

#ifndef RESOURCED_NET_RESTRICTION_H_
#define RESOURCED_NET_RESTRICTION_H_

#include <sys/types.h>

#include "data_usage.h"
#include "transmission.h"

/**
 * @brief Send network restriction for specific classid
 * rst_type - type of restriction on the basis of which the restriction
 * can be applied, removed or excluded.
 * classid - id, that generated for each application in the cgroup
 * iftype - network interface type to proccess restriction
 * send_limit - amount number of engress bytes allowed for restriction
 * rcv_limit - amount number of ingress bytes allowed for restriction
 * snd_warning_limit - threshold for warning notification on engress bytes
 * rcv_warning_limit - threshold for warning notification on ingress bytes
 */
int send_net_restriction(const enum traffic_restriction_type rst_type,
			 const u_int32_t classid,
			 const resourced_iface_type iftype,
			 const int send_limit, const int rcv_limit,
			 const int snd_warning_threshold,
			 const int rcv_warning_threshold);

#endif /* RESOURCED_NET_RESTRICTION_H_ */
