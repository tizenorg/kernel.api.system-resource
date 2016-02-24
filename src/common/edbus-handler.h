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
 * @file edbus-handler.h
 * @desc  dbus handler using edbus interface
 **/

#ifndef __EDBUS_HANDLE_H__
#define __EDBUS_HANDLE_H__

#include <E_DBus.h>
#include <resourced.h>

struct edbus_method {
	const char *member;
	const char *signature;
	const char *reply_signature;
	E_DBus_Method_Cb func;
};

struct edbus_object {
	const char *path;
	const char *interface;
	E_DBus_Object *obj;
	E_DBus_Interface *iface;
};

struct edbus_signal {
	const char *path;
	const char *interface;
	const char *name;
	E_DBus_Signal_Cb func;
	void *user_data;
};

#define DBUS_REPLY_TIMEOUT  (120 * 1000)

#define BUS_NAME		"org.tizen.resourced"
#define OBJECT_PATH		"/Org/Tizen/ResourceD"
#define INTERFACE_NAME		BUS_NAME

/*
 * The EDbus method to update the resourced counters
 * Signal is generated after the database update
 * and store new values of the counters
 */
#define RESOURCED_NETWORK_UPDATE		"Update"
#define RESOURCED_NETWORK_UPDATE_FINISH	"UpdateFinish"
#define RESOURCED_NETWORK_PROCESS_RESTRICTION	"ProcessRestriction"
#define RESOURCED_NETWORK_CREATE_QUOTA		"CreateQuota"
#define RESOURCED_NETWORK_REMOVE_QUOTA		"RemoveQuota"
#define RESOURCED_NETWORK_JOIN_NET_STAT		"JoinNetStat"
#define RESOURCED_NETWORK_GET_STATS		"GetStats"

/*
 * Core service
 *   get/set swap status
 *   operations about swap
 */
#define RESOURCED_PATH_SWAP		OBJECT_PATH"/Swap"
#define RESOURCED_INTERFACE_SWAP	INTERFACE_NAME".swap"

#define RESOURCED_PATH_FREEZER		OBJECT_PATH"/Freezer"
#define RESOURCED_INTERFACE_FREEZER	INTERFACE_NAME".freezer"

#define RESOURCED_PATH_OOM		OBJECT_PATH"/Oom"
#define RESOURCED_INTERFACE_OOM		INTERFACE_NAME".oom"

#define RESOURCED_PATH_NETWORK		OBJECT_PATH"/Network"
#define RESOURCED_INTERFACE_NETWORK	INTERFACE_NAME".network"

#define RESOURCED_PATH_PROCESS		OBJECT_PATH"/Process"
#define RESOURCED_INTERFACE_PROCESS	INTERFACE_NAME".process"

#define RESOURCED_PATH_DBUS			OBJECT_PATH"/DBus"
#define RESOURCED_INTERFACE_DBUS	INTERFACE_NAME".dbus"

#define SIGNAL_PROC_WATCHDOG_RESULT	"WatchdogResult"
#define SIGNAL_PROC_ACTIVE		"Active"
#define SIGNAL_PROC_EXCLUDE		"ProcExclude"
#define SIGNAL_PROC_PRELAUNCH	"ProcPrelaunch"
#define SIGNAL_PROC_SWEEP		"ProcSweep"
#define SIGNAL_PROC_WATCHDOG	"ProcWatchdog"
#define SIGNAL_PROC_SYSTEMSERVICE	"SystemService"

#define SIGNAL_FREEZER_STATE		"FreezerState"

/*
 * Logging
 */
#define RESOURCED_PATH_LOGGING		OBJECT_PATH"/Logging"
#define RESOURCED_INTERFACE_LOGGING	INTERFACE_NAME".logging"

/*
 * System popup
 */
#define SYSTEM_POPUP_BUS_NAME "org.tizen.system.popup"
#define SYSTEM_POPUP_PATH_NAME "/Org/Tizen/System/Popup"
#define SYSTEM_POPUP_IFACE_NAME SYSTEM_POPUP_BUS_NAME

#define SYSTEM_POPUP_PATH_WATCHDOG SYSTEM_POPUP_PATH_NAME"/System"
#define SYSTEM_POPUP_IFACE_WATCHDOG SYSTEM_POPUP_BUS_NAME".System"

#define SYSTEM_POPUP_PATH_DATAUSAGE SYSTEM_POPUP_PATH_NAME"/DataUsage"
#define SYSTEM_POPUP_IFACE_DATAUSAGE SYSTEM_POPUP_BUS_NAME".DataUsage"

/*
 * Deviced
 */
#define DEVICED_BUS_NAME		"org.tizen.system.deviced"
#define DEVICED_OBJECT_PATH		"/Org/Tizen/System/DeviceD"
#define DEVICED_PATH_PROCESS		DEVICED_OBJECT_PATH"/Process"
#define DEVICED_INTERFACE_PROCESS	DEVICED_BUS_NAME".Process"

#define DEVICED_PATH_DISPLAY		DEVICED_OBJECT_PATH"/Display"
#define DEVICED_INTERFACE_DISPLAY	DEVICED_BUS_NAME".display"

#define DEVICED_PATH_BATTERY		DEVICED_OBJECT_PATH"/Battery"
#define DEVICED_INTERFACE_BATTERY	DEVICED_BUS_NAME".Battery"

#define DEVICED_PATH_CORE			DEVICED_OBJECT_PATH"/Core"
#define DEVICED_INTERFACE_CORE		DEVICED_BUS_NAME".core"

#define DEVICED_PATH_POWEROFF		DEVICED_OBJECT_PATH"/PowerOff"
#define DEVICED_INTERFACE_POWEROFF	DEVICED_BUS_NAME".PowerOff"

#define SIGNAL_DEVICED_LCDON			"LCDOn"
#define SIGNAL_DEVICED_LCDOFF			"LCDOff"
#define SIGNAL_DEVICED_LCDONCOMPLETE	"LCDOnCompleted"
#define SIGNAL_DEVICED_BOOTINGDONE		"BootingDone"
#define SIGNAL_DEVICED_POWEROFF_STATE		"ChangeState"
#define SIGNAL_DEVICED_LOW_BATTERY		"BatteryStatusLow"

/*
 * dump service
 */
#define DUMP_SERVICE_BUS_NAME               "org.tizen.system.dumpservice"
#define DUMP_SERVICE_OBJECT_PATH            "/Org/Tizen/System/DumpService"
#define DUMP_SERVICE_INTERFACE_NAME         DUMP_SERVICE_BUS_NAME

#define SIGNAL_DUMP			"Dump"
#define SIGNAL_DUMP_START	"Start"
#define SIGNAL_DUMP_FINISH	"Finish"

/*
 * AMD
 */
#define AUL_APPSTATUS_BUS_NAME			"org.tizen.aul.AppStatus"
#define AUL_APPSTATUS_OBJECT_PATH		"/Org/Tizen/Aul/AppStatus"
#define AUL_APPSTATUS_INTERFACE_NAME	AUL_APPSTATUS_BUS_NAME

#define AUL_SUSPEND_BUS_NAME	"org.tizen.appfw.SuspendHint"
#define AUL_SUSPEND_OBJECT_PATH "/Org/Tizen/Appfw/SuspendHint"
#define AUL_SUSPEND_INTERFACE_NAME AUL_SUSPEND_BUS_NAME

#define SIGNAL_AMD_LAUNCH		"AppLaunch"
#define SIGNAL_AMD_RESUME		"AppResume"
#define SIGNAL_AMD_TERMINATE	"AppTerminate"
#define SIGNAL_AMD_STATE		"AppStatusChange"
#define SIGNAL_AMD_GROUP		"AppGroup"
#define SIGNAL_AMD_TERMINATED	"AppTerminated"
#define SIGNAL_AMD_SUSPNED		"SuspendHint"

struct dbus_byte {
	char *data;
	int size;
};

#define RETRY_MAX 5

/*
 * @desc helper function for filling params array
 * That params array is used in dbus_method_sync/dbus_method_async
 * */
void serialize_params(char *params[], size_t n, ...);


DBusMessage *dbus_method_sync(const char *dest, const char *path,
		const char *interface, const char *method,
		const char *sig, char *param[]);

int dbus_method_async(const char *dest, const char *path,
		const char *interface, const char *method,
		const char *sig, char *param[]);

int register_edbus_signal_handler(const char *path, const char *interface,
		const char *name, E_DBus_Signal_Cb cb, void *user_data);
E_DBus_Interface *get_edbus_interface(const char *path);
pid_t get_edbus_sender_pid(DBusMessage *msg);
int broadcast_edbus_signal_str(const char *path, const char *interface,
		const char *name, const char *sig, char *param[]);
int broadcast_edbus_signal(const char *path, const char *interface,
			   const char *name, int type, void *value);
resourced_ret_c edbus_add_methods(const char *path,
		       const struct edbus_method *const edbus_methods,
		       const size_t size);
resourced_ret_c edbus_add_signals(
		       const struct edbus_signal *const edbus_signals,
		       const size_t size);
resourced_ret_c edbus_message_send(DBusMessage *msg);
int register_edbus_interface(struct edbus_object *object);
int check_dbus_active(void);

void edbus_init(void);
void edbus_exit(void);

E_DBus_Connection *get_resourced_edbus_connection(void);

#endif /* __EDBUS_HANDLE_H__ */
