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

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#include "notifier.h"
#include "trace.h"
#include "module.h"
#include "macro.h"
#include "heart.h"
#include "logging.h"
#include "resourced.h"
#include "config-parser.h"
#include "edbus-handler.h"

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

static DBusMessage *edbus_update_data_list(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	DBusMessage *reply = NULL;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INVALID);
	reply = dbus_message_new_method_return(msg);
	if (!ret) {
		_E("Wrong message arguments!");
		return reply;
	}

	resourced_notify(RESOURCED_NOTIFIER_DATA_UPDATE, NULL);

	logging_save_to_storage(true);
	/* update data list from db */
	logging_update(true);

	return reply;
}

static DBusMessage *edbus_flush_cache(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	DBusMessage *reply = NULL;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INVALID);
	reply = dbus_message_new_method_return(msg);
	if (!ret) {
		_E("Wrong message arguments!");
		return reply;
	}
	/* flush module cache */
	logging_save_to_storage(true);

	return reply;
}

static const struct edbus_method edbus_methods[] = {
	{ "UpdateDataList", NULL, NULL, edbus_update_data_list },
	{ "Flush", NULL, NULL, edbus_flush_cache }
};

static int resourced_heart_init(void *data)
{
	int ret, module_num = 0;

	config_parse(HEART_CONF_FILE_PATH, heart_load_config, &module_num);

	if (!module_num) {
		_E("all heart modules have been disabled");
		return RESOURCED_ERROR_NONE;
	}

	ret = edbus_add_methods(RESOURCED_PATH_LOGGING, edbus_methods, ARRAY_SIZE(edbus_methods));
	if (ret != RESOURCED_ERROR_NONE) {
		_E("DBus method registration for %s is failed", RESOURCED_PATH_LOGGING);
	}

	heart_module_init(data);

	return RESOURCED_ERROR_NONE;
}

static int resourced_heart_dump(FILE *fp, int mode, void *data)
{
	GSList *iter;
	const struct heart_module_ops *module;
	int ret = RESOURCED_ERROR_NONE;

	logging_save_to_storage(true);

	gslist_for_each_item(iter, heart_module) {
		module = (struct heart_module_ops *)iter->data;
		_D("Dump [%s] module\n", module->name);
		if (module->dump)
			ret = module->dump(fp, mode, data);
		if (ret != RESOURCED_ERROR_NONE)
			_E("Fail to dump [%s] module\n", module->name);
	}
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
	.dump		= resourced_heart_dump,
	.exit		= resourced_heart_exit,
};

MODULE_REGISTER(&heart_modules_ops)
