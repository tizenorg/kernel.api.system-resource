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

/**
 * @file sluggish.c
 * @desc Sluggishness processing functions
 *
 **/

#include <glib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include "edbus-handler.h"
#include "trace.h"
#include "module.h"
#include "macro.h"
#include "time-helper.h"
#include "proc-cpu.h"
#include "storage-helper.h"
#include "file-helper.h"
#include "util.h"

#define SLUGGISH_PATH	"/opt/usr/share/sluggish"	/* Path to dump system snapshot */
#define PATH_DLOG	"/opt/var/log/dlog_main"	/* Platform log file */
#define PATH_DLOG1	"/opt/var/log/dlog_main.1"	/* Platform log file */
#define MAX_TIMESTAMP_LEN	30
#define MAX_FILENAME_LEN	256
#define MAX_BUF_LEN	1024
#define POPUP_KEY_CONTENT	"_SYSPOPUP_CONTENT_"
#define SLUGGISH_POPUP	"sluggish_popup"
#define SLUGGISH_TYPE	"_DETECTION_TYPE_"
#define MEMINFO_FILE_PATH	"/proc/meminfo"	/* meminfo file path */
#define VMSTAT_FILE_PATH	"/proc/vmstat"	/* vmstat file path */
#define SLUGGISH_DUP_NOTI_TIMELIMIT	5	/* duplicate sluggish notification timelimit */
#define KILOBYTE	1024
#define POPUP_DELAY_TIME	15	/* Unit: seconds */
#define CPU_THRESHOLD	80	/* Delay popup if CPU usage percentage crossed this limit */
#define GET_BATTERY_CAPACITY	"GetPercent"

static int sluggish_count;	/* sluggish notification count*/

enum sluggish_event {
	GRAPHICS = 1,	/* Graphics vertical */
	MULTIMEDIA	/* Multimedia vertical */
};

typedef void (*sluggish_stat_func)(char *ts);

struct sluggish_stat {
	char *type;
	sluggish_stat_func func;
};

static void sluggish_launch_popup(int type)
{
	char *param[4];
	int ret;

	/* Launch sluggish system popup */
	param[0] = POPUP_KEY_CONTENT;
	param[1] = SLUGGISH_POPUP;
	param[2] = SLUGGISH_TYPE;
	if (type == GRAPHICS)
		param[3] = "Graphics sluggishenss";
	else if (type == MULTIMEDIA)
		param[3] = "Multimedia sluggishens";
	else {
		_E("Invalid sluggish type :%d", type);
		return;
	}
	ret = dbus_method_async("org.tizen.system.popup",
	    "/Org/Tizen/System/Popup/System",
	    "org.tizen.system.popup.System",
	    "SluggishPopupLaunch", "ssss", param);
	if (ret < 0)
		_E("Failed to launch SluggishPopup");
	else
		_I("SluggishPopupLaunch Success");
}

static gboolean sluggish_popup_cb(gpointer user_data)
{
	sluggish_launch_popup((int )user_data);
	return FALSE;
}

static void sluggish_get_vmstat(char *timestamp)
{
	char file_name[MAX_FILENAME_LEN];
	int ret;

	snprintf(file_name, sizeof(file_name), "%s/%s/vmstat", SLUGGISH_PATH, timestamp);
	/* dump /proc/vmstat to SLUGGISH_PATH */
	ret = copy_file(file_name, VMSTAT_FILE_PATH);
	if (ret < 0)
		_E("Copy: %s to %s FAILED", VMSTAT_FILE_PATH, file_name);
	else
		_I("Copy: %s to %s SUCCESS", VMSTAT_FILE_PATH, file_name);
}

static void sluggish_get_memps(char *timestamp)
{
	char file_name[MAX_FILENAME_LEN];
	int ret;
	char *argv[3];

	snprintf(file_name, sizeof(file_name), "%s/%s/memps", SLUGGISH_PATH, timestamp);
	argv[0] = "memps";
	argv[1] = "-a";
	argv[2] = NULL;

	/* dump memps output to SLUGGISH_PATH */
	ret = exec_cmd(argv, file_name);
	if (ret < 0)
		_E("Cmd: memps -a Failed");
	else
		_I("Cmd: memps -a  Success");
}

static void sluggish_get_meminfo(char *timestamp)
{
	char file_name[MAX_FILENAME_LEN];
	int ret;

	snprintf(file_name, sizeof(file_name), "%s/%s/meminfo", SLUGGISH_PATH, timestamp);
	/* dump /proc/meminfo to SLUGGISH_PATH */
	ret = copy_file(file_name, MEMINFO_FILE_PATH);
	if (ret < 0)
		_E("Copy: %s to %s FAILED", MEMINFO_FILE_PATH, file_name);
	else
		_I("Copy: %s to %s SUCCESS", MEMINFO_FILE_PATH, file_name);
}

static void sluggish_get_psinfo(char *timestamp)
{
	char file_name[MAX_FILENAME_LEN];
	int ret;
	char *argv[4];

	snprintf(file_name, sizeof(file_name), "%s/%s/ps-eo", SLUGGISH_PATH, timestamp);
	argv[0] = "ps";
	argv[1] = "-eo";
	argv[2] = "pid,uname,ppid,pri,ni,vsize,rss,pcpu,pmem,size,time,s,policy,cmd";
	argv[3] = NULL;

	/* dump ps -eo output to SLUGGISH_PATH */
	ret = exec_cmd(argv, file_name);
	if (ret < 0)
		_E("Cmd: ps -eo Failed");
	else
		_I("Cmd: ps -eo Success");
}

static const struct sluggish_stat sluggish_memstat[] = {
	{ "vmstat", sluggish_get_vmstat },
	{ "memps", sluggish_get_memps },
	{ "meminfo", sluggish_get_meminfo },
};

static void sluggish_get_mem_status(char *timestamp)
{
	/* Get memory status using vmstat, meminfo, memps and dump to SLUGGISH_PATH */
	int i;

	for (i = 0; i < ARRAY_SIZE(sluggish_memstat); i++) {
		sluggish_memstat[i].func(timestamp);
	}
}

static void sluggish_get_dlog(char *timestamp)
{
	char file_name[MAX_FILENAME_LEN];
	char file_name1[MAX_FILENAME_LEN];
	int ret;

	/* Dump platform log files to SLUGGISH_PATH */
	if (!access(PATH_DLOG, F_OK)) {
		snprintf(file_name, sizeof(file_name), "%s/%s/dlog_main", SLUGGISH_PATH, timestamp);
		ret = copy_file(file_name, PATH_DLOG);
		if (ret < 0)
			_E("Copy: %s to %s FAILED", PATH_DLOG, file_name);
		else
			_I("Copy: %s to %s SUCCESS", PATH_DLOG, file_name);
	}
	if (!access(PATH_DLOG1, F_OK)) {
		snprintf(file_name1, sizeof(file_name1), "%s/%s/dlog_main.1", SLUGGISH_PATH, timestamp);
		ret = copy_file(file_name1, PATH_DLOG1);
		if (ret < 0)
			_E("Copy: %s to %s FAILED", PATH_DLOG1, file_name1);
		else
			_I("Copy: %s to %s SUCCESS", PATH_DLOG1, file_name1);
	}
}

static int sluggish_get_battery_status(void)
{
	int capacity, ret;
	DBusMessage *msg;

	/* Get battery status from deviced */
	msg = dbus_method_sync(DEVICED_BUS_NAME, DEVICED_PATH_BATTERY,
			DEVICED_INTERFACE_BATTERY,
			GET_BATTERY_CAPACITY,
			NULL, NULL);
	if (!msg) {
		_E("Failed to sync DBUS message.");
		return RESOURCED_ERROR_FAIL;
	}

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &capacity, DBUS_TYPE_INVALID);
	dbus_message_unref(msg);
	if (!ret) {
		_E("Failed: dbus_message_get_args()");
		return RESOURCED_ERROR_FAIL;
	}
	return capacity;
}

static void sluggish_get_summary(char *timestamp, int slug_vertical, int pid, double cpu_usage)
{
	char file_name[MAX_FILENAME_LEN];
	char buf[MAX_BUF_LEN] = "";
	char batbuf[MAX_BUF_LEN] = "";
	char proc[MAX_FILENAME_LEN];
	struct statvfs s;
	double int_tot = 0;
	double int_free = 0;
	double ext_tot = 0;
	double ext_free = 0;
	FILE *fptr = NULL;
	FILE *fp = NULL;
	int batteryp;
	size_t size;

	/*
	* Dump
	* 1. Storage status
	* 2. Battery status
	* 3. Sluggishness type
	* 4. Sluggish PID/Process
	* 5. CPU Usage
	*/

	/* Get internal memory status */
	memset(&s, 0x00, sizeof(struct statvfs));
	if (storage_get_size(INTERNAL, &s) < 0 ) {
		_E("Fail to get internal memory size");
	} else {
		int_tot = ((double)s.f_frsize * s.f_blocks) / KILOBYTE;
		int_free = ((double)s.f_bsize * s.f_bavail) / KILOBYTE;
		_I("Internal Memory Status:Total : %lfKB, Avail : %lfKB", int_tot, int_free);
	}

	/* Get external memory status */
	memset(&s, 0x00, sizeof(struct statvfs));
	if (storage_get_size(EXTERNAL, &s) < 0 ) {
		_E("Fail to get external memory size");
	} else {
		ext_tot = ((double)s.f_frsize * s.f_blocks) / KILOBYTE;
		ext_free = ((double)s.f_bsize * s.f_bavail) / KILOBYTE;
		_I("External Memory Status:Total : %lfKB, Avail : %lfKB", ext_tot, ext_free);
	}
	snprintf(file_name, sizeof(file_name), "%s/%s/summary", SLUGGISH_PATH, timestamp);
	if (ext_tot > 0) {
		snprintf(buf, sizeof(buf), "Internal Memory Status:\nTotal : %lfKB, Avail : %lfKB\nExternal Memory Status:\nTotal : %lfKB, Avail : %lfKB\n",
		    int_tot, int_free, ext_tot, ext_free);
	} else
		snprintf(buf, sizeof(buf), "Internal Memory Status:\nTotal : %lfKB, Avail : %lfKB\n", int_tot, int_free);


	/* Get Battery status */
	batteryp = sluggish_get_battery_status();
	if (batteryp >= 0)
		snprintf(batbuf, sizeof(batbuf), "Battery percentage:%d%%\n", batteryp);

	/* Open file in SLUGGISH_PATH to dump summary */
	fptr = fopen(file_name, "w+");
	if (fptr == NULL) {
		_E("Failed to open file %s", file_name);
		return;
	}

	/* 1. Write storage status */
	fputs(buf, fptr);

	/* 2. Write battery status */
	if (batteryp >= 0)
		fputs(batbuf, fptr);

	/* 3. Write sluggishness type */
	if (slug_vertical == GRAPHICS)
		fputs("Sluggishness type: GRAPHICS\n", fptr);
	else if (slug_vertical == MULTIMEDIA)
		fputs("Sluggishness type: MULTIMEDIA\n", fptr);

	/* 4. Write sluggish PID and process name */
	fprintf(fptr,"Sluggish PID:%d\n", pid);

	/* Get process name */
	snprintf(proc, sizeof(proc), "/proc/%d/cmdline", pid);
	fp = fopen(proc, "rb");
	if (fp) {
		memset(buf, 0x00, sizeof(buf));
		size = fread(buf, 1, MAX_BUF_LEN, fp);
		if (size > 0) {
			fputs("Sluggish Process: ", fptr);
			fputs(buf, fptr);
			fputs("\n", fptr);
		}
		fclose(fp);
	}

	/* 5. Write CPU usage */
	fprintf(fptr,"CPU used:%3.2lf%%, idle:%3.2lf%%\n", cpu_usage, (100 - cpu_usage));
	fclose(fptr);
}

static void sluggish_get_sys_status(char *timestamp, int slug_vertical, int pid)
{
	char dir_name[MAX_FILENAME_LEN];
	double cu;
	struct cpu_stat cs1;
	struct cpu_stat cs2;

	/* Get first cpu stat reading */
	memset(&cs1, 0x00, sizeof(struct cpu_stat));
	memset(&cs2, 0x00, sizeof(struct cpu_stat));

	proc_cpu_stat(&cs1);

	/* Get current timestamp */
	time_stamp(timestamp);

	/*
	* Create dir to store the system snapshot
	* All the data captured on sluggish detection notification will be
	* stored in this directory for uploading later
	*/
	/* Note : Data is captured only on receiving "SluggishDetected" signal */
	snprintf(dir_name, sizeof(dir_name), "%s/%s", SLUGGISH_PATH, timestamp);
	if (mkdir(dir_name, S_IRUSR | S_IWUSR | S_IRGRP) < 0) {
		if (errno != EEXIST) {
			_E("Failed to create dir %s", dir_name);
			return;
		}
	}
	_I("Created %s successfully", dir_name);

	/* Get process Status */
	sluggish_get_psinfo(timestamp);

	/* Get Memory Status */
	sluggish_get_mem_status(timestamp);

	/* Get dlog */
	sluggish_get_dlog(timestamp);

	/* Get second cpu stat reading */
	proc_cpu_stat(&cs2);

	/* Get CPU usage % */
	cu = proc_cpu_usage(&cs1, &cs2);

	/* Get storage, battaery, cpu status */
	sluggish_get_summary(timestamp, slug_vertical, pid, cu);

	/* If current CPU utilization is > threshold (CPU_THRESHOLD) delay popup display */
	if ((unsigned int)cu > CPU_THRESHOLD) {
		_I("CPU used(%d%%) > %d%% - Delaying popup display ", (unsigned int)cu, CPU_THRESHOLD);
		g_timeout_add_seconds(POPUP_DELAY_TIME, sluggish_popup_cb, (void *)slug_vertical);
		return;
	}
	sluggish_launch_popup(slug_vertical);
}

static void sluggish_graphics(pid_t pid)
{
	char timestamp[MAX_TIMESTAMP_LEN];
	struct timeval timeval;
	struct timeval interval;
	static pid_t sluggish_graphics_last_pid;	/* PID of last graphics sluggishness */
	static struct timeval sluggish_graphics_last_ts;	/* Timestamp of last graphics sluggishness */

	/* Process graphics sluggishness */
	_I("Graphics sluggishness for PID (%d), Count:%d", pid, ++sluggish_count);
	if (gettimeofday(&timeval, NULL)) {
		_E("gettimeofday() failed");
		return;
	}
	if (pid == sluggish_graphics_last_pid) {
		time_diff(&interval, &sluggish_graphics_last_ts, &timeval);
		_D("Current ts-sec:%ld usec:%ld", timeval.tv_sec, timeval.tv_usec);
		_D("Last ts-sec:%ld usec:%ld", sluggish_graphics_last_ts.tv_sec, sluggish_graphics_last_ts.tv_usec);
		_D("Diff-%ld sec, %ld usec\n", interval.tv_sec, interval.tv_usec);
		/*
		*If Duplicate(Same PID, Same sluggish type)
		* "SluggisgDetected" notification is received
		* within SLUGGISH_DUP_NOTI_TIMELIMIT ignore it
		*/
		if (interval.tv_sec <= SLUGGISH_DUP_NOTI_TIMELIMIT) {
			_I("Ignoring update for same PID:%d within timelimit(%ds)", pid, SLUGGISH_DUP_NOTI_TIMELIMIT);
			return;
		}
	}
	sluggish_graphics_last_pid = pid;
	sluggish_graphics_last_ts.tv_sec = timeval.tv_sec;
	sluggish_graphics_last_ts.tv_usec = timeval.tv_usec;

	/* Get system snapshot and dump to SLUGGISH_PATH */
	sluggish_get_sys_status(timestamp, GRAPHICS, pid);
}

static void sluggish_multimedia(pid_t pid)
{
	char timestamp[MAX_TIMESTAMP_LEN];
	struct timeval timeval;
	struct timeval interval;
	static pid_t sluggish_media_last_pid;	/* PID of last multimedia sluggishness */
	static struct timeval sluggish_media_last_ts;	/* Timestamp of last graphics sluggishness */

	/* Process multimedia sluggishness */
	_I("Multimedia sluggishness for PID (%d), Count:%d", pid, ++sluggish_count);
	if (gettimeofday(&timeval, NULL)) {
		_E("gettimeofday() failed");
		return;
	}
	if (pid == sluggish_media_last_pid) {
		time_diff(&interval, &sluggish_media_last_ts, &timeval);
		_D("Current ts-sec:%ld usec:%ld", timeval.tv_sec, timeval.tv_usec);
		_D("Last ts-sec:%ld usec:%ld", sluggish_media_last_ts.tv_sec, sluggish_media_last_ts.tv_usec);
		_D("Diff-%ld sec, %ld usec\n", interval.tv_sec, interval.tv_usec);
		/*
		* If Duplicate(Same PID, Same sluggish type)
		* "SluggisgDetected" notification is received
		* within SLUGGISH_DUP_NOTI_TIMELIMIT ignore it
		*/
		if (interval.tv_sec <= SLUGGISH_DUP_NOTI_TIMELIMIT) {
			_I("Ignoring update for same PID:%d within timelimit(%ds)", pid, SLUGGISH_DUP_NOTI_TIMELIMIT);
			return;
		}
	}
	sluggish_media_last_pid = pid;
	sluggish_media_last_ts.tv_sec = timeval.tv_sec;
	sluggish_media_last_ts.tv_usec = timeval.tv_usec;

	/* Get system snapshot and dump to SLUGGISH_PATH */
	sluggish_get_sys_status(timestamp, MULTIMEDIA, pid);
}

static void sluggish_process(enum sluggish_event event, pid_t pid)
{
	switch (event) {
	case GRAPHICS:
		sluggish_graphics(pid);
		break;
	case MULTIMEDIA:
		sluggish_multimedia(pid);
		break;
	default:
		break;
	};
}

static DBusMessage *edbus_sluggish_detected(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessage *reply;
	dbus_bool_t ret;
	DBusError err;
	pid_t pid = 0;
	int slug_vertical = 0;

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &slug_vertical,
	    DBUS_TYPE_INT32, &pid, DBUS_TYPE_INVALID);
	if (ret == FALSE) {
		_E("Can't deserialize sluggish detection message ![%s:%s]\n",
		err.name, err.message);
		goto error;
	}

	dbus_error_free(&err);
	if (slug_vertical != GRAPHICS && slug_vertical != MULTIMEDIA) {
		_E("Invalid sluggish vertical:%d", slug_vertical);
		goto error;
	}

	/* Received "SluggishDetected" message, so get system details and dump to SLUGGISH_PATH */
	sluggish_process(slug_vertical, pid);
error:
	reply = dbus_message_new_method_return(msg);
	return reply;
}

static const struct edbus_method edbus_methods[] = {
	{ "SluggishDetected", NULL, "ii", edbus_sluggish_detected },
	/* Add methods here */
};

static int sluggish_init(void *data)
{
	resourced_ret_c ret;
	/* Create SLUGGISH_PATH folder to dump system snapshot*/
	if (mkdir(SLUGGISH_PATH, S_IRUSR | S_IWUSR | S_IRGRP) < 0) {
		if (errno != EEXIST) {
			_E("Failed to create dir %s", SLUGGISH_PATH);
			return RESOURCED_ERROR_FAIL;
		}
	}
	_I("Created %s successfully", SLUGGISH_PATH);
	ret = edbus_add_methods(RESOURCED_PATH_SLUGGISH, edbus_methods,
		ARRAY_SIZE(edbus_methods));

	if (ret != RESOURCED_ERROR_NONE) {
		_E("DBus method registration for %s is failed", RESOURCED_PATH_SLUGGISH);
		return ret;
	}

	return RESOURCED_ERROR_NONE;
}

static const struct module_ops sluggish_ops = {
	.priority	= MODULE_PRIORITY_NORMAL,
	.name		= "sluggish",
	.init		= sluggish_init,
};

MODULE_REGISTER(&sluggish_ops)
