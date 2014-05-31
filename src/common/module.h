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
 * @file module.h
 * @desc Module helper functions
 **/

#ifndef __MODULE_HANDLE_H__
#define __MODULE_HANDLE_H__

enum module_priority {
	MODULE_PRIORITY_NORMAL,
	MODULE_PRIORITY_HIGH,
};

struct module_ops {
	enum module_priority priority;
	const char *name;
	int (*init) (void *data);
	int (*exit) (void *data);
	int (*control) (void *data);
	int (*status) (void *data);
};

void add_module(struct module_ops *module);
void remove_module(struct module_ops *module);

void modules_init(void *data);
void modules_exit(void *data);

const struct module_ops *find_module(const char *name);

#endif /* __MODULE_HANDLE_H__ */
