/*
 * resourced
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
 * @file edbus-handler.c
 *
 * @desc dbus handler using edbus interface
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "trace.h"
#include "edbus-handler.h"
#include "macro.h"
#include "resourced.h"

#define EDBUS_INIT_RETRY_COUNT 5

struct edbus_list{
	char *signal_name;
	E_DBus_Signal_Handler *handler;
};

static struct edbus_object edbus_objects[] = {
	{ RESOURCED_PATH_OOM, RESOURCED_INTERFACE_OOM, NULL, NULL },
	{ RESOURCED_PATH_PROCESS, RESOURCED_INTERFACE_PROCESS, NULL, NULL },
	/* Add new object & interface here*/
};

static Eina_List *edbus_handler_list;
static int edbus_init_val;
static E_DBus_Connection *edbus_conn;
static DBusPendingCall *edbus_request_name;

static int append_variant(DBusMessageIter *iter,
		const char *sig, char *param[])
{
	char *ch;
	int i;
	int int_type;
	uint64_t int64_type;
	DBusMessageIter arr;
	struct dbus_byte *byte;

	if (!sig || !param)
		return 0;

	for (ch = (char*)sig, i = 0; *ch != '\0'; ++i, ++ch) {
		switch (*ch) {
		case 'i':
			int_type = atoi(param[i]);
			dbus_message_iter_append_basic(iter,
				DBUS_TYPE_INT32, &int_type);
			break;
		case 'u':
			int_type = strtoul(param[i], NULL, 10);
			dbus_message_iter_append_basic(iter,
				DBUS_TYPE_UINT32, &int_type);
			break;
		case 't':
			int64_type = atoll(param[i]);
			dbus_message_iter_append_basic(iter,
				DBUS_TYPE_UINT64, &int64_type);
			break;
		case 's':
			dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &param[i]);
			break;
		case 'a':
			++i, ++ch;
			switch (*ch) {
			case 'y':
				dbus_message_iter_open_container(iter,
					DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE_AS_STRING, &arr);
				byte = (struct dbus_byte*)param[i];
				dbus_message_iter_append_fixed_array(&arr,
					DBUS_TYPE_BYTE, &(byte->data), byte->size);
				dbus_message_iter_close_container(iter, &arr);
				break;
			default:
				break;
			}
			break;
		case 'd':
			dbus_message_iter_append_basic(iter,
				DBUS_TYPE_INT32, &param[i]);
			break;

		default:
			return -EINVAL;
		}
	}

	return 0;
}

DBusMessage *dbus_method_sync(const char *dest, const char *path,
		const char *interface, const char *method,
		const char *sig, char *param[])
{
	DBusConnection *conn;
	DBusMessage *msg;
	DBusMessageIter iter;
	DBusMessage *reply;
	DBusError err;
	int r;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn) {
		_E("dbus_bus_get error");
		return NULL;
	}

	msg = dbus_message_new_method_call(dest, path, interface, method);
	if (!msg) {
		_E("dbus_message_new_method_call(%s:%s-%s)", path, interface, method);
		return NULL;
	}

	dbus_message_iter_init_append(msg, &iter);
	r = append_variant(&iter, sig, param);
	if (r < 0) {
		_E("append_variant error(%d)", r);
		dbus_message_unref(msg);
		return NULL;
	}

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg,
			DBUS_REPLY_TIMEOUT, &err);
	if (!reply) {
		_E("dbus_connection_send error(No reply)");
	}

	if (dbus_error_is_set(&err)) {
		_E("dbus_connection_send error(%s:%s)", err.name, err.message);
		dbus_error_free(&err);
		reply = NULL;
	}

	dbus_message_unref(msg);
	return reply;
}


int register_edbus_interface(struct edbus_object *object)
{
	int ret = RESOURCED_ERROR_FAIL;

	if (!object) {
		_E("object is invalid value!");
		return ret;
	}

	object->obj = e_dbus_object_add(edbus_conn, object->path, NULL);
	if (!object->obj) {
		_E("fail to add edbus obj");
		return ret;
	}

	object->iface = e_dbus_interface_new(object->interface);
	if (!object->iface) {
		_E("fail to add edbus interface");
		return ret;
	}

	e_dbus_object_interface_attach(object->obj, object->iface);

	return 0;
}

E_DBus_Interface *get_edbus_interface(const char *path)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(edbus_objects); i++)
		if (!strcmp(path, edbus_objects[i].path))
			return edbus_objects[i].iface;

	return NULL;
}

pid_t get_edbus_sender_pid(DBusMessage *msg)
{
	const char *sender;
	DBusMessage *send_msg;
	DBusPendingCall *pending;
	DBusMessageIter iter;
	int ret;
	pid_t pid;

	if (!msg) {
		_E("invalid argument!");
		return RESOURCED_ERROR_FAIL;
	}

	sender = dbus_message_get_sender(msg);
	if (!sender) {
		_E("invalid sender!");
		return RESOURCED_ERROR_FAIL;
	}

	send_msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
				    DBUS_PATH_DBUS,
				    DBUS_INTERFACE_DBUS,
				    "GetConnectionUnixProcessID");
	if (!send_msg) {
		_E("invalid send msg!");
		return RESOURCED_ERROR_FAIL;
	}

	ret = dbus_message_append_args(send_msg, DBUS_TYPE_STRING,
				    &sender, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("fail to append args!");
		dbus_message_unref(send_msg);
		return RESOURCED_ERROR_FAIL;
	}

	pending = e_dbus_message_send(edbus_conn, send_msg, NULL, -1, NULL);
	if (!pending) {
		_E("pending is null!");
		dbus_message_unref(send_msg);
		return RESOURCED_ERROR_FAIL;
	}

	dbus_message_unref(send_msg);

	/* block until reply is received */
	dbus_pending_call_block(pending);

	msg = dbus_pending_call_steal_reply(pending);
	dbus_pending_call_unref(pending);
	if (!msg) {
		_E("reply msg is null!");
		return RESOURCED_ERROR_FAIL;
	}

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &pid);
	dbus_message_unref(msg);

	return pid;
}

static void unregister_edbus_signal_handle(void)
{
	Eina_List *search;
	Eina_List *serach_next;
	struct edbus_list *entry;

	EINA_LIST_FOREACH_SAFE(edbus_handler_list, search, serach_next, entry) {
		if (entry != NULL) {
			e_dbus_signal_handler_del(edbus_conn, entry->handler);
			edbus_handler_list = eina_list_remove(edbus_handler_list, entry);
			free(entry->signal_name);
			free(entry);
		}
	}
}

int register_edbus_signal_handler(const char *path, const char *interface,
		const char *name, E_DBus_Signal_Cb cb)
{
	Eina_List *search;
	struct edbus_list *entry;
	E_DBus_Signal_Handler *handler;

	EINA_LIST_FOREACH(edbus_handler_list, search, entry) {
		if (entry != NULL && strncmp(entry->signal_name, name, strlen(name)) == 0)
			return RESOURCED_ERROR_FAIL;
	}

	handler = e_dbus_signal_handler_add(edbus_conn, NULL, path,
				interface, name, cb, NULL);

	if (!handler) {
		_E("fail to add edbus handler");
		return RESOURCED_ERROR_FAIL;
	}

	entry = malloc(sizeof(struct edbus_list));

	if (!entry) {
		_E("Malloc failed");
		return RESOURCED_ERROR_FAIL;
	}

	entry->signal_name = strndup(name, strlen(name));

	if (!entry->signal_name) {
		_E("Malloc failed");
		free(entry);
		return -1;
	}

	entry->handler = handler;
	edbus_handler_list = eina_list_prepend(edbus_handler_list, entry);
	if (!edbus_handler_list) {
		_E("eina_list_prepend failed");
		free(entry->signal_name);
		free(entry);
		return RESOURCED_ERROR_FAIL;
	}
	return 0;
}

int broadcast_edbus_signal_str(const char *path, const char *interface,
		const char *name, const char *sig, char *param[])
{
	DBusMessage *msg;
	DBusMessageIter iter;
	int r;

	msg = dbus_message_new_signal(path, interface, name);
	if (!msg) {
		_E("fail to allocate new %s.%s signal", interface, name);
		return -EPERM;
	}

	dbus_message_iter_init_append(msg, &iter);
	r = append_variant(&iter, sig, param);
	if (r < 0) {
		_E("append_variant error(%d)", r);
		return -EPERM;
	}

	e_dbus_message_send(edbus_conn, msg, NULL, -1, NULL);

	dbus_message_unref(msg);
	return 0;
}

int broadcast_edbus_signal(const char *path, const char *interface,
		const char *name, int type, void *value)
{
	DBusMessage *signal = dbus_message_new_signal(path, interface, name);

	if (!signal) {
		_E("fail to allocate new %s.%s signal", interface, name);
		return RESOURCED_ERROR_FAIL;
	}

	dbus_message_append_args(signal, type, value, DBUS_TYPE_INVALID);

	e_dbus_message_send(edbus_conn, signal, NULL, -1, NULL);

	dbus_message_unref(signal);
	return RESOURCED_ERROR_OK;
}

resourced_ret_c edbus_add_methods(const char *path,
		       const struct edbus_method *const edbus_methods,
		       const size_t size)
{
	E_DBus_Interface *iface;
	int i;
	int ret;

	iface = get_edbus_interface(path);

	if (!iface) {
		_E("Fail to get edbus interface! Path = %s\n", path);
		return RESOURCED_ERROR_FAIL;
	}

	for (i = 0; i < size; i++) {
		ret = e_dbus_interface_method_add(iface,
				    edbus_methods[i].member,
				    edbus_methods[i].signature,
				    edbus_methods[i].reply_signature,
				    edbus_methods[i].func);
		if (!ret) {
			_E("Fail to add method %s!\n",
				edbus_methods[i].member);
			return RESOURCED_ERROR_FAIL;
		}
	}

	return RESOURCED_ERROR_NONE;
}

void edbus_init(void)
{
	int retry = RESOURCED_ERROR_OK;
	int i;
retry_init:
	edbus_init_val = e_dbus_init();
	if (edbus_init_val)
		goto retry_bus_get;
	if (retry == EDBUS_INIT_RETRY_COUNT) {
		_E("fail to init edbus");
		return;
	}
	retry++;
	goto retry_init;

retry_bus_get:
	retry = 0;
	edbus_conn = e_dbus_bus_get(DBUS_BUS_SYSTEM);
	if (edbus_conn)
		goto retry_bus_request;
	if (retry == EDBUS_INIT_RETRY_COUNT) {
		_E("fail to get edbus");
		return;
	}
	retry++;
	goto retry_bus_get;

retry_bus_request:
	retry = 0;
	edbus_request_name = e_dbus_request_name(edbus_conn, BUS_NAME, 0, NULL, NULL);
	if (edbus_request_name)
		goto register_objects;
	if (retry == EDBUS_INIT_RETRY_COUNT) {
		_E("fail to request edbus name");
		return;
	}
	retry++;
	goto retry_bus_request;

register_objects:
	for (i = 0; i < ARRAY_SIZE(edbus_objects); i++) {
		int ret;

		ret = register_edbus_interface(&edbus_objects[i]);
		if (ret < 0) {
			_E("fail to add obj & interface for %s",
				    edbus_objects[i].interface);
			return;
		}

		_I("add new obj for %s", edbus_objects[i].interface);
	}

	_I("start edbus service");
}

void edbus_exit(void)
{
	unregister_edbus_signal_handle();
	e_dbus_connection_close(edbus_conn);
	e_dbus_shutdown();
}
