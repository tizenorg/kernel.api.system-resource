/*
 * resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file module-data.c
 * @desc Module data features
 **/

#include "macro.h"
#include "module-data.h"
#include "trace.h"

static struct shared_modules_data modules_data;

struct shared_modules_data *get_shared_modules_data(void)
{
	return &modules_data;
}

void init_modules_arg(struct modules_arg *marg, struct daemon_arg *darg)
{
	ret_msg_if(marg == NULL || darg == NULL,
			 "Init modules argument failed\n");
	marg->opts = darg->opts;
}
