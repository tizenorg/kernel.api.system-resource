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
 */

/**
 * @file freezer.c
 *
 * @desc Freezer module
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <dlfcn.h>

#include "macro.h"
#include "util.h"
#include "module.h"
#include "module-data.h"
#include "notifier.h"
#include "edbus-handler.h"
#include "resourced.h"
#include "trace.h"
#include "vconf.h"
#include "config-parser.h"
#include "procfs.h"
#include "proc-common.h"

#include "freezer.h"

#define FREEZER_MODULE_PATH "/usr/lib/libsystem-freezer.so"

static int freezer_init_check;

/******************************************** Freezer symbols *************************************************/
/* Freezer cgroup late control setting retrieval */
int (*resourced_freezer_get_proc_late_control)(void) = NULL;

/* Freezer suspend status retrieval */
static bool (*resourced_freezer_is_suspended)(void) = NULL;

/* Freezer cgroup operation state */
static enum freezer_state (*resourced_freezer_get_operation_state)(void) = NULL;

/* Freezer module initialization and finalization functions */
static int (*resourced_freezer_initialize)(void *data) = NULL;
static int (*resourced_freezer_deinitialize)(void) = NULL;

/* Freezer module dbus method calls and signal handlers */
static DBusMessage *(*resourced_freezer_dbus_method_handler)(E_DBus_Object *obj, DBusMessage *msg) = NULL;
static void (*resourced_freezer_dbus_signal_handler)(void *data, DBusMessage *msg) = NULL;

/* Resourced notifier handlers */
static int (*resourced_freezer_change_state_cb)(void *data) = NULL;
static int (*resourced_freezer_service_launch)(void *data) = NULL;
static int (*resourced_freezer_wakeup)(void *data) = NULL;
static int (*resourced_freezer_service_wakeup)(void *data) = NULL;
static int (*resourced_freezer_app_suspend)(void *data) = NULL;

/* dlopen handle for libfreezer */
static void *dlopen_handle;
/****************************************** Freezer symbols end ***********************************************/

/* freezer_proc_get_late_control function defined for freezer module on case */
int resourced_freezer_proc_late_control(void)
{
	if (resourced_freezer_get_proc_late_control)
		return resourced_freezer_get_proc_late_control();

	_E("freezer_get_proc_late_control is not loaded!");
	return 0;
}

/****************************************** Internal symbols **************************************************/
static DBusMessage *resourced_freezer_dbus_method_handler_generic(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	int ret;

	if (resourced_freezer_dbus_method_handler)
		return resourced_freezer_dbus_method_handler(obj, msg);

	ret = 0;

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);
	return reply;
}

static struct edbus_method edbus_methods[] = {
	{ METHOD_GET_FREEZER_STATE,     NULL,   "i", resourced_freezer_dbus_method_handler_generic },
	{ METHOD_GET_FREEZER_SERVICE,   NULL,   "i", resourced_freezer_dbus_method_handler_generic },
	/* Add methods here */
};

static struct edbus_method edbus_suspend_methods[] = {
	{ METHOD_SET_FREEZER_SUSPEND,   "s", "i", resourced_freezer_dbus_method_handler_generic },
	/* Add methods here */
};

static void freezer_dbus_init(bool is_suspend)
{
	resourced_ret_c ret;

	register_edbus_signal_handler(RESOURCED_PATH_FREEZER,
				      RESOURCED_INTERFACE_FREEZER,
				      SIGNAL_FREEZER_STATUS,
				      (void *)resourced_freezer_dbus_signal_handler,
				      NULL);
	register_edbus_signal_handler(RESOURCED_PATH_FREEZER,
				      RESOURCED_INTERFACE_FREEZER,
				      SIGNAL_FREEZER_SERVICE,
				      (void *)resourced_freezer_dbus_signal_handler,
				      NULL);

	ret = edbus_add_methods(RESOURCED_PATH_FREEZER,
				edbus_methods,
				ARRAY_SIZE(edbus_methods));

	ret_msg_if(ret != RESOURCED_ERROR_NONE,
		   "DBus method registration for %s is failed",
		   RESOURCED_PATH_FREEZER);

	if (!is_suspend)
		return;

	register_edbus_signal_handler(DEVICED_PATH_DISPLAY,
				      DEVICED_INTERFACE_DISPLAY,
				      SIGNAL_DEVICED_LCDONCOMPLETE,
				      (void *)resourced_freezer_dbus_signal_handler,
				      NULL);

	ret = edbus_add_methods(RESOURCED_PATH_FREEZER,
				edbus_suspend_methods,
				ARRAY_SIZE(edbus_suspend_methods));
	ret_msg_if(ret != RESOURCED_ERROR_NONE,
		   "DBus method registration for %s is failed",
		   RESOURCED_PATH_FREEZER);
}

static bool freezer_is_present(void)
{
	struct stat buf;

	/* Check if libfreezer.so is present or not */
	if (stat(FREEZER_MODULE_PATH, &buf)) {
		_E("Freezer library is not present @ %s", FREEZER_MODULE_PATH);
		return false;
	}

	return true;
}

static void freezer_unload_symbols(void)
{
#define FREEZER_UNLOAD_SYMBOL(sym) \
	sym = NULL;

	FREEZER_UNLOAD_SYMBOL(resourced_freezer_get_proc_late_control);
	FREEZER_UNLOAD_SYMBOL(resourced_freezer_is_suspended);
	FREEZER_UNLOAD_SYMBOL(resourced_freezer_get_operation_state);
	FREEZER_UNLOAD_SYMBOL(resourced_freezer_initialize);
	FREEZER_UNLOAD_SYMBOL(resourced_freezer_deinitialize);
	FREEZER_UNLOAD_SYMBOL(resourced_freezer_dbus_method_handler);
	FREEZER_UNLOAD_SYMBOL(resourced_freezer_dbus_signal_handler);
	FREEZER_UNLOAD_SYMBOL(resourced_freezer_change_state_cb);
	FREEZER_UNLOAD_SYMBOL(resourced_freezer_service_launch);
	FREEZER_UNLOAD_SYMBOL(resourced_freezer_wakeup);
	FREEZER_UNLOAD_SYMBOL(resourced_freezer_service_wakeup);
	FREEZER_UNLOAD_SYMBOL(resourced_freezer_app_suspend);

#undef FREEZER_UNLOAD_SYMBOL

	if (dlopen_handle) {
		dlclose(dlopen_handle);
		dlopen_handle = NULL;
	}
}

static int freezer_load_symbols(void)
{
	dlopen_handle = dlopen(FREEZER_MODULE_PATH, RTLD_NOW);
	if (!dlopen_handle) {
		_E("freezer dlopen failed!");
		return RESOURCED_ERROR_FAIL;
	}

#define FREEZER_LOAD_SYMBOL(sym, name) \
	sym = dlsym(dlopen_handle, name); \
	if (!sym) { \
		_E("failed to dlsym %s", name); \
		goto error; \
	} \

	FREEZER_LOAD_SYMBOL(resourced_freezer_get_proc_late_control, "freezer_get_proc_late_control");
	FREEZER_LOAD_SYMBOL(resourced_freezer_is_suspended, "freezer_is_suspended");
	FREEZER_LOAD_SYMBOL(resourced_freezer_get_operation_state, "freezer_get_operation_state");
	FREEZER_LOAD_SYMBOL(resourced_freezer_initialize, "freezer_initialize");
	FREEZER_LOAD_SYMBOL(resourced_freezer_deinitialize, "freezer_finalize");
	FREEZER_LOAD_SYMBOL(resourced_freezer_dbus_method_handler, "freezer_dbus_method_handler");
	FREEZER_LOAD_SYMBOL(resourced_freezer_dbus_signal_handler, "freezer_dbus_signal_handler");
	FREEZER_LOAD_SYMBOL(resourced_freezer_change_state_cb, "freezer_change_state_cb");
	FREEZER_LOAD_SYMBOL(resourced_freezer_service_launch, "freezer_service_launch");
	FREEZER_LOAD_SYMBOL(resourced_freezer_wakeup, "freezer_wakeup");
	FREEZER_LOAD_SYMBOL(resourced_freezer_service_wakeup, "freezer_service_wakeup");
	FREEZER_LOAD_SYMBOL(resourced_freezer_app_suspend, "freezer_app_suspend");

#undef FREEZER_LOAD_SYMBOL

	return RESOURCED_ERROR_NONE;
error:
	freezer_unload_symbols();
	return RESOURCED_ERROR_FAIL;
}

static int resourced_freezer_init(void *data)
{
	int ret_code;
	bool is_suspend;
	bool is_present;
	struct freezer_init_data init_data = { .resourced_app_list = &proc_app_list };

	is_present = freezer_is_present();
	if (!is_present) {
		_E("Freezer library not present. Not enabling freezer");
		return RESOURCED_ERROR_FAIL;
	}
	ret_code = freezer_load_symbols();
	if (ret_code != RESOURCED_ERROR_NONE) {
		_E("Not able to load symbols. Will use default definitions");
		return RESOURCED_ERROR_FAIL;
	}

	ret_code = resourced_freezer_initialize(&init_data);
	ret_value_msg_if(ret_code < 0, ret_code, "failed to initialize freezer module\n");

	is_suspend = resourced_freezer_is_suspended();
	freezer_dbus_init(is_suspend);

	if (is_suspend)
		register_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH,
			    resourced_freezer_service_launch);
	register_notifier(RESOURCED_NOTIFIER_FREEZER_CGROUP_STATE,
		resourced_freezer_change_state_cb);
	register_notifier(RESOURCED_NOTIFIER_APP_WAKEUP,
		resourced_freezer_wakeup);
	register_notifier(RESOURCED_NOTIFIER_SERVICE_WAKEUP,
		resourced_freezer_service_wakeup);
	register_notifier(RESOURCED_NOTIFIER_APP_SUSPEND,
		resourced_freezer_app_suspend);

	freezer_init_check = 1;

	return RESOURCED_ERROR_NONE;
}

static int resourced_freezer_finalize(void *data)
{
	if (freezer_init_check == 0)
		return RESOURCED_ERROR_NONE;

	freezer_init_check = 0;

	resourced_freezer_deinitialize();

	unregister_notifier(RESOURCED_NOTIFIER_FREEZER_CGROUP_STATE,
		resourced_freezer_change_state_cb);
	unregister_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH,
		resourced_freezer_service_launch);
	unregister_notifier(RESOURCED_NOTIFIER_APP_WAKEUP,
		resourced_freezer_wakeup);
	unregister_notifier(RESOURCED_NOTIFIER_SERVICE_WAKEUP,
		resourced_freezer_service_wakeup);
	unregister_notifier(RESOURCED_NOTIFIER_APP_SUSPEND,
		resourced_freezer_app_suspend);

	freezer_unload_symbols();

	return RESOURCED_ERROR_NONE;
}

static int resourced_freezer_status(void *data)
{
	struct freezer_status_data *f_data;
	int ret = RESOURCED_ERROR_NONE;

	if (!freezer_init_check)
		return RESOURCED_ERROR_NONE;

	f_data = (struct freezer_status_data *)data;
	switch (f_data->type) {
	case GET_STATUS:
		ret = resourced_freezer_get_operation_state();
		break;
	default:
		_E("Unsupported command: %d; status", f_data->type);
	}

	return ret;
}

static const struct module_ops freezer_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "freezer",
	.init = resourced_freezer_init,
	.exit = resourced_freezer_finalize,
	.status = resourced_freezer_status,
};

MODULE_REGISTER(&freezer_modules_ops)
