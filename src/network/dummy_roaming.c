/*
 *  resourced
 *
 * Copyright (c) 2013 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file roaming.c
 *
 * @desc It's dummy implementation for none telephony case.
 */

#include "macro.h"
#include "roaming.h"
#include "trace.h"

/* for avoiding dependency in this file */

void regist_roaming_cb(roaming_cb UNUSED cb)
{
	_D("ROAMING ISN'T SUPPORTED, CHECK TELEPHONY MODULE");
}

resourced_roaming_type get_roaming(void)
{
	_D("ROAMING ISN'T SUPPORTED, CHECK TELEPHONY MODULE");
	return RESOURCED_ROAMING_UNKNOWN;
}

