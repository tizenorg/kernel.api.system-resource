/*
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
 * @file testgrabbing.c
 * @desc Functionality for testing ktgrabber communications
 *	and related procedures
 */

#include "trace.h"

#include <data_usage.h>
#include <mcheck.h>
#include <Ecore.h>

resourced_cb_ret net_activity_func(struct net_activity_info *info)
{
	printf("%20s\t|%8d\t|%8d\t|%8d\t|\n", info->appid, info->iftype,
	       info->type, info->bytes);
	return RESOURCED_CONTINUE;
}

int main(int argc, char **argv)
{
	resourced_ret_c ret;
#ifdef DEBUG_ENABLED
	mtrace();
	mcheck(0);
#endif
	printf("%20s\t|%8s\t|%8s\t|%8s\t|\n", "appid", "iftype",
	       "type", "bytes");

	ret = register_net_activity_cb(net_activity_func);
	ecore_main_loop_begin();
	return 0;
}
