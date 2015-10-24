/*
 * resourced
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file module-data.h
 * @desc Module data features
 **/

#ifndef __MODULE_DATA_HANDLE_H__
#define __MODULE_DATA_HANDLE_H__

#include "counter.h"
#include "init.h"

struct swap_module_data {
	int swap_state;			/* swap SWAP_ON/SWAP_OFF */
};

struct shared_modules_data {
	struct counter_arg *carg;
	struct daemon_arg *darg;
	struct swap_module_data swap_data;
};

struct shared_modules_data *get_shared_modules_data(void);

void init_modules_arg(struct daemon_arg *darg);

#endif /* __MODULE_DATA_HANDLE_H__ */
