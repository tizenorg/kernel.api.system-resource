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
 *
*/

#include <assert.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <E_DBus.h>

#include "edbus-handler.h"
#include "macro.h"
#include "util.h"
#include "module.h"
#include "resourced.h"
#include "trace.h"
#include "resourced-dbus.h"

/* key  : DBus system BusName */
/* value: PID of Busname */
/* BusName hash is 1:1 table */
static GHashTable *dbus_system_busname_hash = NULL;

/* key  : PID */
/* value: Another GHashTable of BusNames */
/* BusName hash is 1:N table */
static GHashTable *dbus_system_pid_hash = NULL;

E_DBus_Signal_Handler *dbus_name_owner_changed_handler = NULL;


static void ghash_free(void *hash)
{
	if (g_hash_table_size((GHashTable *)hash))
		g_hash_table_remove_all((GHashTable *)hash);

	g_hash_table_unref((GHashTable *)hash);
}

bool resourced_dbus_pid_has_busname(pid_t pid)
{
	return g_hash_table_contains(dbus_system_pid_hash, GUINT_TO_POINTER(pid));
}

unsigned int resourced_dbus_pid_get_busnames(pid_t pid, char ***busnames)
{
	void *pid_p = GUINT_TO_POINTER(pid);
	GHashTable *busname_hash = NULL;
	char **names = NULL;
	unsigned int len = 0;

	assert(busnames);

	busname_hash = g_hash_table_lookup(dbus_system_pid_hash, pid_p);
	if (!busname_hash)
		return 0;

#if (GLIB_MAJOR_VERSION <= 2 && GLIB_MINOR_VERSION < 40)
	{
		GHashTableIter iter;
		char *busname;
		int i;

		names = (char **)malloc(sizeof(char *) * (size_t)(g_hash_table_size(busname_hash) + 1));
		if (!names)
			return 0;

		g_hash_table_iter_init (&iter, busname_hash);
		for (i = 0; g_hash_table_iter_next(&iter, (void **)&busname, NULL); i++)
			names[i] = strndup(busname, strlen(busname)+1);

		names[i] = NULL;
	}
#else
	names = (char **)g_hash_table_get_keys_as_array(busname_hash, &len);
#endif
	*busnames = names;

	return len;
}

pid_t resourced_dbus_get_pid_of_busname(const char *busname)
{
	return GPOINTER_TO_UINT(g_hash_table_lookup(dbus_system_busname_hash, busname));
}

static void resourced_dbus_system_bus_append_connection_info(void *key, void *value, void *data)
{
	DBusMessageIter *iter = data, sub;
	char *busname = key;
	pid_t pid = GPOINTER_TO_UINT(value);

	if (!dbus_message_iter_open_container(iter, DBUS_TYPE_DICT_ENTRY, NULL, &sub)) {
		_E("Failed to open dictionary");
		return;
	}

	if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &busname)) {
		_E("Failed to append string: %s", busname);
		dbus_message_iter_abandon_container(iter, &sub);
		return;
	}

	if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &pid)) {
		_E("Failed to append uint32: %u", pid);
		dbus_message_iter_abandon_container(iter, &sub);
		return;
	}

	if (!dbus_message_iter_close_container(iter, &sub)) {
		_E("Failed to close array");
		return;
	}
}

static DBusMessage *resourced_dbus_handle_get_system_bus_name_info(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter, sub;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		_E("Failed to create method reply");
		return NULL;
	}

	dbus_message_iter_init_append(reply, &iter);
	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{su}", &sub)) {
		_E("Failed to open string array");
		return NULL;
	}

	g_hash_table_foreach(dbus_system_busname_hash,
			     resourced_dbus_system_bus_append_connection_info,
			     &sub);

	if (!dbus_message_iter_close_container(&iter, &sub)) {
		_E("Failed to close array");
		return NULL;
	}

	return reply;
}

static void resourced_dbus_system_bus_append_busname_info(void *key, void *value, void *data)
{
	if (!dbus_message_iter_append_basic((DBusMessageIter *)data, DBUS_TYPE_STRING, &key))
		_E("Failed to append string: %s", (char *)key);
}

static DBusMessage *resourced_dbus_handle_get_system_bus_pid_info(E_DBus_Object *obj, DBusMessage *msg)
{
	GHashTable *busname_hash = NULL;
	DBusMessageIter iter, sub;
	DBusMessage *reply = NULL;
	DBusError error = DBUS_ERROR_INIT;
	pid_t pid;

	if (!dbus_message_get_args(msg, &error, DBUS_TYPE_UINT32, &pid, DBUS_TYPE_INVALID)) {
		_E("Failed to get arguments from message: %s", error.message);
		return NULL;
	}

	if (!g_hash_table_contains(dbus_system_pid_hash, GUINT_TO_POINTER(pid))) {
		reply = dbus_message_new_error(msg,
					       DBUS_ERROR_INVALID_ARGS,
					       "Given PID has no system bus");
		return reply;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		_E("Failed to create method reply");
		return NULL;
	}

	busname_hash = g_hash_table_lookup(dbus_system_pid_hash, GUINT_TO_POINTER(pid));
	if (!busname_hash) {
		_E("Failed to find value of key(PID: %u)", pid);
		return NULL;
	}

	dbus_message_iter_init_append(reply, &iter);
	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub)) {
		_E("Failed to open string array");
		dbus_message_unref (reply);
		return NULL;
	}

	g_hash_table_foreach(busname_hash,
			     resourced_dbus_system_bus_append_busname_info,
			     &sub);

	if (!dbus_message_iter_close_container(&iter, &sub)) {
		_E("Failed to close array");
		return NULL;
	}

	return reply;
}

static void resourced_dbus_system_bus_append_pid_info(void *key, void *value, void *data)
{
	DBusMessageIter *iter = data, sub, ssub;
	pid_t pid = GPOINTER_TO_UINT(key);
	GHashTable *busname_hash = value;

	if (!dbus_message_iter_open_container(iter, DBUS_TYPE_DICT_ENTRY, NULL, &sub)) {
		_E("Failed to open dictionary");
		return;
	}

	if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &pid)) {
		_E("Failed to append uint32: %u", pid);
		return;
	}

	if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_ARRAY, "s", &ssub)) {
		_E("Failed to open string array");
		return;
	}

	g_hash_table_foreach(busname_hash,
			     resourced_dbus_system_bus_append_busname_info,
			     &ssub);

	if (!dbus_message_iter_close_container(&sub, &ssub)) {
		_E("Failed to close array");
		return;
	}

	if (!dbus_message_iter_close_container(iter, &sub)) {
		_E("Failed to close array");
		return;
	}
}

static DBusMessage *resourced_dbus_handle_get_system_bus_pid_info_all(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter, sub;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		_E("Failed to create method reply");
		return NULL;
	}

	dbus_message_iter_init_append(reply, &iter);
	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{uas}", &sub)) {
		_E("Failed to open string array");
		dbus_message_unref (reply);
		return NULL;
	}

	g_hash_table_foreach(dbus_system_pid_hash,
			     resourced_dbus_system_bus_append_pid_info,
			     &sub);

	if (!dbus_message_iter_close_container(&iter, &sub)) {
		_E("Failed to close array");
		return NULL;
	}

	return reply;
}

static struct edbus_method resourced_dbus_methods[] = {
	{ "GetSystemBusPIDInfo",	"u",	"as",
	  resourced_dbus_handle_get_system_bus_pid_info		},
	{ "GetSystemBusPIDInfoAll",	NULL,	"a{uas}",
	  resourced_dbus_handle_get_system_bus_pid_info_all	},
	{ "GetSystemBusNameInfo",	NULL,	"a{su}",
	  resourced_dbus_handle_get_system_bus_name_info	},
	{ NULL,				NULL,	NULL,
	  NULL							},
};

static void resourced_dbus_system_hash_insert_busname(char *busname, pid_t pid)
{
	GHashTable *busname_hash = NULL;
	void *pid_p = GUINT_TO_POINTER(pid);

	g_hash_table_replace(dbus_system_busname_hash, busname, pid_p);

	busname_hash = (GHashTable *)g_hash_table_lookup(dbus_system_pid_hash, pid_p);
	if (!busname_hash) {
		/* !! CAUTION !! */
		/* We are using same busname pointer at two of hash
		 * table. So the free operation should be done at
		 * once. */
		busname_hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
		if (!busname_hash) {
			_E("Failed to create BusName hash table");
			return;
		}
		g_hash_table_replace(dbus_system_pid_hash, pid_p, busname_hash);
	}

	g_hash_table_replace(busname_hash, busname, NULL);
}

static void resourced_dbus_system_hash_drop_busname(char *busname)
{
	GHashTable *busname_hash = NULL;
	void *pid_p;

	/* BusName hash */
	if (!g_hash_table_contains(dbus_system_busname_hash, busname)) {
		_E("Does not exist in busname hash: %s", busname);
		return;
	}

	/* Lookup PID of BusName */
	pid_p = g_hash_table_lookup(dbus_system_busname_hash, busname);

	/* Drop PID hash */
	if (!g_hash_table_contains(dbus_system_pid_hash, pid_p)) {
		_E("Does not exist in PID hash: %s", busname);
		return;
	}

	busname_hash = (GHashTable *)g_hash_table_lookup(dbus_system_pid_hash, pid_p);
	if (!busname_hash) {
		_E("Failed to find value of PID: %u", GPOINTER_TO_UINT(pid_p));
		g_hash_table_remove(dbus_system_pid_hash, pid_p);
		return;
	}

	g_hash_table_remove(busname_hash, busname);

	if (!g_hash_table_size(busname_hash)) {
		g_hash_table_unref(busname_hash);
		if (!g_hash_table_remove(dbus_system_pid_hash, pid_p))
			_E("Failed to drop from PID hash table: %s", busname);
	}

	/* Drop BusName hash */
	if (!g_hash_table_remove(dbus_system_busname_hash, busname))
		_E("Failed to drop from busname hash table: %s", busname);
}

static void resourced_dbus_get_connection_unix_process_id_callback(void *data, DBusMessage *msg, DBusError *error)
{
	DBusError err = DBUS_ERROR_INIT;
	char *busname = data;
	pid_t pid;

	if (dbus_error_is_set(error)) {
		free(busname);
		return;
	}

	if (!dbus_message_get_args(msg, &err, DBUS_TYPE_UINT32, &pid, DBUS_TYPE_INVALID)) {
		free(busname);
		_E("Failed to get arguments from message: %s", err.message);
		return;
	}

	resourced_dbus_system_hash_insert_busname(busname, pid);
}

static void resourced_dbus_get_connection_unix_process_id(char *busname)
{
	E_DBus_Connection *conn = NULL;
	DBusMessage *msg = NULL;
	DBusPendingCall *pending = NULL;

	conn = get_resourced_edbus_connection();

	msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
					   DBUS_PATH_DBUS,
					   DBUS_INTERFACE_DBUS,
					   "GetConnectionUnixProcessID");
	if (!msg) {
		_E("Failed to get new message");
		return;
	}

	if (!dbus_message_append_args(msg, DBUS_TYPE_STRING, &busname, DBUS_TYPE_INVALID)) {
		_E("Failed to append args");
		dbus_message_unref(msg);
		return;
	}

	pending = e_dbus_message_send(conn,
				      msg,
				      resourced_dbus_get_connection_unix_process_id_callback,
				      -1,
				      strndup(busname, strlen(busname)+1));
	if (!pending) {
		_E("Failed to send message");
		dbus_message_unref(msg);
		return;
	}

	dbus_message_unref(msg);

	return;
}

static void resourced_dbus_get_list_names_callback(void *data, DBusMessage *msg, DBusError *error)
{
	DBusMessageIter iter, sub;
	char *busname = NULL;

	if (dbus_error_is_set(error)) {
		_E("Failed to get DBus list names: %s", error->message);
		return;
	}

	if (!dbus_message_iter_init(msg, &iter)) {
		_D("message has no arguments");
		return;
	}

	dbus_message_iter_recurse(&iter, &sub);
	do {
		dbus_message_iter_get_basic(&sub, &busname);
		resourced_dbus_get_connection_unix_process_id(busname);
	} while(dbus_message_iter_next(&sub));
}

static bool resourced_dbus_get_list_names(void)
{
	DBusMessage *msg = NULL;
	DBusPendingCall *pending = NULL;

	msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
					   DBUS_PATH_DBUS,
					   DBUS_INTERFACE_DBUS,
					   "ListNames");
	if (!msg) {
		_E("Failed to get new message");
		return FALSE;
	}

	pending = e_dbus_message_send(get_resourced_edbus_connection(),
				      msg,
				      resourced_dbus_get_list_names_callback,
				      -1,
				      NULL);
	if (!pending) {
		_E("Failed to send message");
		dbus_message_unref(msg);
		return FALSE;
	}

	dbus_message_unref(msg);

	return TRUE;
}

static bool resourced_dbus_become_monitor(DBusConnection *connection,
					  const char * const *filters)
{
	DBusError error = DBUS_ERROR_INIT;
	DBusMessage *msg;
	DBusMessage *reply;
	int i;
	unsigned int zero = 0;
	DBusMessageIter iter, sub;

	msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
					   DBUS_PATH_DBUS,
					   DBUS_INTERFACE_MONITORING,
					   "BecomeMonitor");
	if (!msg) {
		_E("Failed to become a monitor");
		return FALSE;
	}

	dbus_message_iter_init_append(msg, &iter);

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub)) {
		_E("Failed to open string array");
		return FALSE;
	}

	for (i = 0; filters[i] != NULL; i++) {
		if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &filters[i])) {
			_E("Failed to add filter to array");
			return FALSE;
		}
	}

	if (!dbus_message_iter_close_container(&iter, &sub)) {
		_E("Failed to close array");
		return FALSE;
	}

	if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &zero)) {
		_E("Failed to append finish argument zero");
		return FALSE;
	}

	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &error);
	if (!reply) {
		_E("Failed to enable new-style monitoring: "
		   "%s: \"%s\". Falling back to eavesdropping.",
		   error.name, error.message);
		dbus_error_free(&error);
		return FALSE;
	}

	dbus_message_unref(msg);
	dbus_message_unref(reply);

	return (reply != NULL);
}

E_DBus_Connection *resourced_dbus_monitor_new(DBusBusType type,
					      DBusHandleMessageFunction filter_func,
					      const char * const *filters)
{
	E_DBus_Connection *edbus_conn = NULL;
	DBusConnection *conn = NULL;
	DBusError error = DBUS_ERROR_INIT;

	conn = dbus_bus_get_private(type, &error);
	if (!conn) {
		_E("Failed to open connecion: %s", error.message);
		goto on_error;
	}

	if (!dbus_connection_add_filter(conn,
					filter_func,
					NULL,
					NULL)) {
		_E("Failed to add filter function on connection");
		goto on_error;
	}

	if (!resourced_dbus_become_monitor(conn, filters)) {
		_E("Failed to become a monitor connection");
		goto on_error;
	}

	edbus_conn = e_dbus_connection_setup(conn);
	if (!edbus_conn) {
		_E("Failed to setup edbus connection");
		goto on_error;
	}

	return edbus_conn;

on_error:
	if (dbus_error_is_set(&error))
	    dbus_error_free(&error);

	if (conn) {
		dbus_connection_close(conn);
		dbus_connection_unref(conn);
	}

	return NULL;
}

static void resourced_dbus_name_owner_changed_callback(void *data, DBusMessage *msg)
{
	char *busname = NULL, *from = NULL, *to = NULL;
	DBusError error = DBUS_ERROR_INIT;

	if (!dbus_message_get_args(msg, &error,
				   DBUS_TYPE_STRING, &busname,
				   DBUS_TYPE_STRING, &from,
				   DBUS_TYPE_STRING, &to,
				   DBUS_TYPE_INVALID)) {
		_E("Failed to get arguments from message: %s", error.message);
		return;
	}

        /* If the name owner process is activated then: */
        /* arg_0: busname */
        /* arg_1: "" */
        /* arg_2: ":x.xxx" */

        /* If the name owner process is deactivated then: */
        /* arg_0: busname */
        /* arg_1: ":x.xxx" */
        /* arg_2: "" */

	if (is_empty(busname)) {
		_E("NameOwnerChanged: arg_0 is empty");
		return;
	}

	if (is_empty(from) && is_empty(to)) {
		_E("NameOwnerChanged: both arg_1 and arg_2 are empty");
		return;
	}

	if (is_empty(from) && !is_empty(to)) {
		/* New BusName */

		resourced_dbus_get_connection_unix_process_id(busname);
		return;
	} else if (!is_empty(from) && is_empty(to)) {
		/* Drop BusName */

		resourced_dbus_system_hash_drop_busname(busname);
		return;
	}

	_E("Should NOT reached here!!");
}

static int resourced_dbus_init(void *data)
{
	resourced_ret_c ret;

	dbus_system_busname_hash = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
	if (!dbus_system_busname_hash)
		_E("Failed to create dbus connection list hash table");

	dbus_system_pid_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, ghash_free);
	if (!dbus_system_pid_hash)
		_E("Failed to create dbus connection list hash table");

	resourced_dbus_get_list_names();

	dbus_name_owner_changed_handler = e_dbus_signal_handler_add(get_resourced_edbus_connection(),
								    DBUS_SERVICE_DBUS,
								    DBUS_PATH_DBUS,
								    DBUS_INTERFACE_DBUS,
								    "NameOwnerChanged",
								    resourced_dbus_name_owner_changed_callback,
								    NULL);

	ret = edbus_add_methods(RESOURCED_PATH_DBUS,
				resourced_dbus_methods,
				ARRAY_SIZE(resourced_dbus_methods));

	ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ret,
			 "DBus method registration for %s is failed", RESOURCED_PATH_DBUS);

	return RESOURCED_ERROR_NONE;
}

static int resourced_dbus_finalize(void *data)
{
	ghash_free(dbus_system_busname_hash);
	ghash_free(dbus_system_pid_hash);

	return RESOURCED_ERROR_NONE;
}

static const struct module_ops resourced_dbus_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "resourced-dbus",
	.init = resourced_dbus_init,
	.exit = resourced_dbus_finalize,
};

MODULE_REGISTER(&resourced_dbus_modules_ops)
