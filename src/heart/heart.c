/*
 * resourced
 *
 * Copyright (c) 2012 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 */

/*
 * @file heart.c
 *
 * @desc start heart for resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#include "trace.h"
#include "module.h"
#include "macro.h"
#include "heart.h"
#include "logging.h"
#include "resourced.h"
#include "config-parser.h"

static GSList *heart_module;  /* module list */

void heart_module_add(const struct heart_module_ops *ops)
{
	heart_module = g_slist_append(heart_module, (gpointer)ops);
}

void heart_module_remove(const struct heart_module_ops *ops)
{
	heart_module = g_slist_remove(heart_module, (gpointer)ops);
}

static const struct heart_module_ops *heart_module_find(const char *name)
{
	GSList *iter;
	struct heart_module_ops *module;

	gslist_for_each_item(iter, heart_module) {
		module = (struct heart_module_ops *)iter->data;
		if (!strcmp(module->name, name))
			return module;
	}
	return NULL;
}

static void heart_module_init(void *data)
{
	GSList *iter;
	const struct heart_module_ops *module;
	int ret = RESOURCED_ERROR_NONE;

	gslist_for_each_item(iter, heart_module) {
		module = (struct heart_module_ops *)iter->data;
		_D("Initialize [%s] module\n", module->name);
		if (module->init)
			ret = module->init(data);
		if (ret != RESOURCED_ERROR_NONE)
			_E("Fail to initialize [%s] module\n", module->name);
	}
}

static void heart_module_exit(void *data)
{
	GSList *iter;
	const struct heart_module_ops *module;
	int ret = RESOURCED_ERROR_NONE;

	gslist_for_each_item(iter, heart_module) {
		module = (struct heart_module_ops *)iter->data;
		_D("Deinitialize [%s] module\n", module->name);
		if (module->exit)
			ret = module->exit(data);
		if (ret != RESOURCED_ERROR_NONE)
			_E("Fail to deinitialize [%s] module\n", module->name);
	}
}

static int heart_load_config(struct parse_result *result, void *user_data)
{
	const struct heart_module_ops *ops;
	int *count = (int *)user_data;

	if (!result)
		return -EINVAL;

	if (strcmp(result->section, HEART_CONF_SECTION))
		return RESOURCED_ERROR_FAIL;

	ops = heart_module_find(result->name);
	if (!ops)
		return RESOURCED_ERROR_FAIL;

	if (!strcmp(result->value, "ON"))
		*count = *count + 1;
	else
		heart_module_remove(ops);

	return RESOURCED_ERROR_NONE;
}

static int resourced_heart_init(void *data)
{
	int module_num = 0;

	config_parse(HEART_CONF_FILE_PATH, heart_load_config, &module_num);

	if (!module_num) {
		_E("all heart modules have been disabled");
		return RESOURCED_ERROR_NONE;
	}

	heart_module_init(data);

	return RESOURCED_ERROR_NONE;
}

static int resourced_heart_exit(void *data)
{
	heart_module_exit(data);

	return RESOURCED_ERROR_NONE;
}

static const struct module_ops heart_modules_ops = {
	.priority	= MODULE_PRIORITY_HIGH,
	.name		= "HEART",
	.init		= resourced_heart_init,
	.exit		= resourced_heart_exit,
};

MODULE_REGISTER(&heart_modules_ops)
