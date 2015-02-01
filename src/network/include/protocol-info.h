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
 * @file protocol-info.h
 *
 * @desc Network protocol entity: now it's only for
 * datacall network interface type
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#ifndef RESOURCED_PROTOCOL_INFO_NET_IFACE_H_
#define RESOURCED_PROTOCOL_INFO_NET_IFACE_H_

#include "data_usage.h"

void init_hw_net_protocol_type(void);

void finalize_hw_net_protocol_type(void);

resourced_hw_net_protocol_type get_hw_net_protocol_type(
	const resourced_iface_type iftype);

#endif /* RESOURCED_PROTOCOL_INFO_NET_IFACE_H_ */
