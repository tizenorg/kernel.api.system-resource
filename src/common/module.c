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
 * @file module.c
 * @desc Module helper functions
 **/

#include "macro.h"
#include "module.h"
#include "resourced.h"
#include "trace.h"

#include <glib.h>

static GSList *modules_list;

void add_module(const struct module_ops *module)
{
	ret_msg_if(!module, "Invalid module handler\n");
	if (module->priority == MODULE_PRIORITY_HIGH)
		modules_list = g_slist_prepend(modules_list, (gpointer)module);
	else
		modules_list = g_slist_append(modules_list, (gpointer)module);
}

void remove_module(const struct module_ops *module)
{
	modules_list = g_slist_remove(modules_list, (gpointer)module);
}

const struct module_ops *find_module(const char *name)
{
	GSList *iter;
	const struct module_ops *module;

	gslist_for_each_item(iter, modules_list) {
		module = (struct module_ops *)iter->data;
		if (!strcmp(module->name, name))
			return module;
	}
	return NULL;
}

void modules_check_runtime_support(void *data)
{
	GSList *iter;
	const struct module_ops *module;
	int ret_code = RESOURCED_ERROR_NONE;

	gslist_for_each_item(iter, modules_list) {
		module = (const struct module_ops *)iter->data;
		_D("check runtime support [%s] module\n", module->name);

		if (!module->check_runtime_support)
			continue;

		ret_code = module->check_runtime_support((void *)module);
		if (ret_code != RESOURCED_ERROR_NONE) {
			_E("%s module check failed", module->name);
			remove_module(module);
			continue;
		}
	}
}

void modules_init(void *data)
{
	GSList *iter;
	const struct module_ops *module;
	int ret_code = RESOURCED_ERROR_NONE;

	gslist_for_each_item(iter, modules_list) {
		module = (struct module_ops *)iter->data;
		_D("Initialize [%s] module\n", module->name);
		if (module->init)
			ret_code = module->init(data);
		if (ret_code < 0)
			_E("Fail to initialize [%s] module\n", module->name);
	}
}

void modules_exit(void *data)
{
	GSList *iter;
	/* Deinitialize in reverse order */
	GSList *reverse_list = g_slist_reverse(modules_list);
	const struct module_ops *module;
	int ret_code = RESOURCED_ERROR_NONE;

	gslist_for_each_item(iter, reverse_list) {
		module = (struct module_ops *)iter->data;
		_D("Deinitialize [%s] module\n", module->name);
		if (module->exit)
			ret_code = module->exit(data);
		if (ret_code < 0)
			_E("Fail to deinitialize [%s] module\n", module->name);
	}
}
