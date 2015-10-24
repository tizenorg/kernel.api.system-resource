/*
 * resourced
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
 *  @file: systemd-util.c
 *  @desc: systemd helper utility function
 */

#include <errno.h>
#include <assert.h>
#include <string.h>
#include <dbus/dbus.h>

#include "macro.h"
#include "util.h"
#include "trace.h"
#include "edbus-handler.h"

static int systemd_get_unit_obj_path(const char *unit_name,
				     char **obj_path,
				     char **err_msg)
{
	DBusMessage *msg = NULL;
	DBusError err;
	char *path = NULL;
	char *pa[1];
	char buf[256];
	int r = 0;
	char *str_err;

	assert(unit_name);
	assert(obj_path);
	assert(err_msg && !*err_msg);

	pa[0] = (char *)unit_name;

	msg = dbus_method_sync("org.freedesktop.systemd1",
			       "/org/freedesktop/systemd1",
			       "org.freedesktop.systemd1.Manager", "GetUnit",
			       "s", pa);

	if (!msg) {
		_E("failed to method call(GetUnit) to systemd");
		*err_msg = strndup("method call(GetUnit) failed", 30);
		if (!*err_msg) {
			_E("failed to duplicate dbus error message");
			r = -ENOMEM;
			goto finish;
		}

		r = RESOURCED_ERROR_FAIL;
		goto finish;
	}

	dbus_error_init(&err);

	if (!dbus_message_get_args(msg, &err,
				   DBUS_TYPE_OBJECT_PATH, &path,
				   DBUS_TYPE_INVALID)) {
		_E("failed to get object path: %s", err.message);
		*err_msg = strndup(err.message, strlen(err.message));
		if (!*err_msg) {
			_E("failed to duplicate dbus error message");
			r = -ENOMEM;
			goto finish;
		}

		r = RESOURCED_ERROR_FAIL;
		goto finish;
	}

	*obj_path = strndup(path, strlen(path));
	if (!*obj_path) {
		_E("failed to duplicate object path: %s", strerror_r(ENOMEM, buf, sizeof(buf)));
		*err_msg = strndup(str_err, strlen(str_err));
		if (!*err_msg)
			_E("failed to duplicate dbus error message");

		r = -ENOMEM;
	}

finish:
	dbus_message_unref(msg);
	dbus_error_free(&err);

	return r;
}

int systemd_get_service_property_as_uint32(const char *unit_name,
					   const char *property,
					   unsigned int *result,
					   char **err_msg)
{
	_cleanup_free_ char *obj_path = NULL;
	DBusMessageIter iter, sub;
	DBusMessage *reply = NULL;
	/* DBusError err; */
	char *pa[2];
	char buf[256];
	char *str_err;
	int r;

	assert(unit_name);
	assert(property);
	assert(result);
	assert(err_msg && !*err_msg);

	r = systemd_get_unit_obj_path(unit_name, &obj_path, err_msg);
	if (r < 0) {
		_E("failed to get object path of %s: %s", unit_name, *err_msg);
		goto finish;
	}

	pa[0] = "org.freedesktop.systemd1.Service";
	pa[1] = (char *)property;

	reply = dbus_method_sync("org.freedesktop.systemd1",
				 obj_path,
				 "org.freedesktop.DBus.Properties", "Get",
				 "ss", pa);
	if (!reply) {
		_E("failed to get property method call to systemd");
		*err_msg = strndup("get property method call failed", 30);
		if (!*err_msg) {
			_E("failed to duplicate dbus error message");
			r = -ENOMEM;
			goto finish;
		}

		r = RESOURCED_ERROR_FAIL;
		goto finish;
	}

	if (!dbus_message_iter_init(reply, &iter)) {
		_E("failed to init iterator");
		*err_msg = strndup("failed to init iterator", 30);
		if (!*err_msg) {
			_E("failed to duplicate dbus error message");
			r = -ENOMEM;
			goto finish;
		}

		r = RESOURCED_ERROR_FAIL;
		goto finish;
	}

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
		_E("arg is not type of variant");
		str_err = strerror_r(EINVAL, buf, sizeof(buf));
		*err_msg = strndup(str_err, strlen(str_err));
		if (!*err_msg) {
			_E("failed to duplicate dbus error message");
			r = -ENOMEM;
			goto finish;
		}

		r = RESOURCED_ERROR_FAIL;
		goto finish;
	}


	dbus_message_iter_recurse(&iter, &sub);

	if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_UINT32) {
		_E("arg is not type of int32");
		str_err = strerror_r(EINVAL, buf, sizeof(buf));
		*err_msg = strndup(str_err, strlen(str_err));
		if (!*err_msg) {
			_E("failed to duplicate dbus error message");
			r = -ENOMEM;
			goto finish;
		}

		r = RESOURCED_ERROR_FAIL;
		goto finish;
	}

	dbus_message_iter_get_basic(&sub, result);

finish:
	if (reply)
		dbus_message_unref(reply);
	/* dbus_error_free(&err); */

	return r;
}
