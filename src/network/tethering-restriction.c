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
 * @file tethering-restriction.c
 *
 * @desc Implementation of tethering restriction for tethering pseudo app
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "resourced.h"
#include "tethering-restriction.h"
#include "file-helper.h"

resourced_ret_c apply_tethering_restriction(
	const enum traffic_restriction_type type)
{
	_D("apply tethering rule %d", type);
	switch (type) {
	case RST_SET:
		return fwrite_str(PATH_TO_PROC_IP_FORWARD, "0");
	case RST_UNSET:
		return fwrite_str(PATH_TO_PROC_IP_FORWARD, "1");
	case RST_EXCLUDE:
		return fwrite_str(PATH_TO_PROC_IP_FORWARD, "1");
	default:
		return RESOURCED_ERROR_INVALID_PARAMETER;

	}
	return RESOURCED_ERROR_NONE;
}
