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

/*
 * @file proc-usage-stats.c
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * ** Handles the dbus method calls made by the runtime-info APIs
 * ** The supported calls are for collection of memory and cpu usage of input processes
 * ** The fields collected can be found in the process_memory_info_s and
 *	process_cpu_usage_s structs in the proc-usage-stats-helper.h file
 * ** The working is as follows:
 *	* The dbus method is called from runtime-info API
 *	* For each request, a runtime_info_task instance is created
 *	* This instance contains info related to that request
 *	* A pipe is created for each request and an ecore handler is added for the read end
 *	* A thread is swapned for the request and this thread collects the needed info
 *	* After collection of the usage info, the thread writes the success status to the
 *		write end of the pipe
 *	* This activates the handler, which appends the collected usage info to the reply
 *		dbus message and sends it to the process making the method call
 *	* The reply message is as follows:
 *		* If everything succeeded, it is an array of memory or cpu usage info structs
 *		* If some of the PIDs are invalid, then the entries for those PIDs will be
 *			INVALID_PROCESS_FIELD_VALUE
 *		* If anything went wrong in the above steps, then the reply is an integer
 *			which contains the error value
 *	* In case there was any error writing to the pipe from the swapned thread,
 *		then there is no reply and the method call fails after the timeout
 */

#include <sys/types.h>
#include <unistd.h>
#include <Ecore.h>
#include <errno.h>

#include "proc-main.h"
#include "proc-usage-stats-helper.h"
#include "resourced.h"
#include "macro.h"
#include "trace.h"
#include "edbus-handler.h"

#define BtoKiB(bytes)   (bytes >> 10)
#define kBtoKiB(kbytes) (int)(((long long)kbytes * 1024)/1000)

#define PROCESS_MEMORY_USAGE_METHOD "ProcMemoryUsage"
#define PROCESS_CPU_USAGE_METHOD "ProcCpuUsage"

/**
 * @brief       DBus method to return the memory usage information of input processes
 * @since_tizen 2.4
 *
 * @param[in] obj       The E_DBus_Object
 * @param[in] msg       The dbus message sent by the runtime info API.
 *			This should be an array of process IDs.
 *
 * @retval              The response dbus message contains an array of structs
 *			(structure similar to process_memory_info_s). The structs contain the
 *			memory usage info fields for the processes (in the same order).
 *			For invalid process IDs, the fields of the process_memory_info_s struct
 *			will be set to INVALID_PROCESS_INFO_FIELD_VALUE.
 *			If the input dbus message does not contain array of integers or if there
 *			are errors in computation, collection and sending of usage info, then the
 *			response dbus message contains only an integer whose value will the error value.
 */
static DBusMessage *edbus_proc_memory_usage(E_DBus_Object *obj, DBusMessage *msg);

/**
 * @brief       DBus method to return the cpu usage information of input processes
 * @since_tizen 2.4
 *
 * @param[in] obj       The E_DBus_Object
 * @param[in] msg       The dbus message sent by the runtime info API.
 *			This should be an array of process IDs.
 *
 * @retval              The response dbus message contains an array of structs
 *			(structure similar to process_cpu_usage_s). The structs contain the
 *			cpu usage info fields for the processes (in the same order).
 *			For invalid process IDs, the fields of the process_cpu_usage_s struct
 *			will be set to INVALID_PROCESS_INFO_FIELD_VALUE.
 *			If the input dbus message does not contain array of integers or if there
 *			are errors in computation, collection and sending of usage info, then the
 *			response dbus message contains only an integer whose value will the error value.
 */
static DBusMessage *edbus_proc_cpu_usage(E_DBus_Object *obj, DBusMessage *msg);

/* edbus_methods to register with edbus */
static const struct edbus_method edbus_methods[] = {
	{ PROCESS_MEMORY_USAGE_METHOD, "ai", NULL, edbus_proc_memory_usage },
	{ PROCESS_CPU_USAGE_METHOD, "ai", NULL, edbus_proc_cpu_usage },
};

/* Ecore file handler for the read end of the pipe.
 * Receives the error status from the runtime info task thread and collects
 * the usage info calculated and sends it in a dbus message or send an error dbus message back
 * with the error status added to the message
 */
static Eina_Bool proc_runtime_info_task_cb(void *data, Ecore_Fd_Handler *fd_handler)
{
	int i, j, ret, rsize, struct_size;
	int fd;
	int result[7];
	DBusMessage *reply;
	DBusMessageIter iter, iter_arr, iter_struct;
	struct runtime_info_task *rt_task;

	/* In case of errors in ecore file hander, the returned dbus message
	 * contains only a failure value */
	rt_task = (struct runtime_info_task *)data;
	if (!rt_task) {
		_E("invalid input data");
		goto error;
	}

	if (!ecore_main_fd_handler_active_get(fd_handler, ECORE_FD_READ)) {
		_E("task %s: ecore_main_fd_handler_active_get_error", rt_task->task_name);
		goto error;
	}

	fd = ecore_main_fd_handler_fd_get(fd_handler);
	if (fd < 0) {
		_E("task %s: ecore_main_fd_handler_fd_get error", rt_task->task_name);
		goto error;
	}

	rsize = read(fd, &ret, sizeof(int));
	if (rsize != sizeof(int)) {
		_E("task %s: error reading value from read end of pipe", rt_task->task_name);
		goto error;
	}
	_D("task %s: received %d on the read end", rt_task->task_name, ret);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("task %s: error in collection of information", rt_task->task_name);
		goto error;
	}

	/* Create a reply message with the needed structure */
	reply = dbus_message_new_method_return(rt_task->task_msg);
	if (!reply) {
		_E("task %s: out of memory to allocate for reply dbus message. not attempting again!!!", rt_task->task_name);
		return ECORE_CALLBACK_CANCEL;
	}
	dbus_message_iter_init_append(reply, &iter);
	if (rt_task->task_type == RUNTIME_INFO_TASK_MEMORY) {
		struct_size = 7;
		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(iiiiiii)", &iter_arr);
	} else {
		struct_size = 2;
		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(ii)", &iter_arr);
	}
	/* Populate the reply message with the usage info */
	for (i = 0; i < rt_task->task_size; ++i) {
		dbus_message_iter_open_container(&iter_arr, DBUS_TYPE_STRUCT, NULL, &iter_struct);

		/* Write the fields of the usage info struct to an int array
		 * (this is so that the code of dbus message append could be more elegant) */
		ret = proc_read_from_usage_struct(rt_task->usage_info_list, i, result, rt_task->task_type);
		if (ret != RESOURCED_ERROR_NONE) {
			_E("task %s: error in reading from usage info struct", rt_task->task_name);
			goto error;
		}

		for (j = 0; j < struct_size; ++j)
			dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_INT32, &result[j]);

		dbus_message_iter_close_container(&iter_arr, &iter_struct);
	}
	dbus_message_iter_close_container(&iter, &iter_arr);
	goto send_message;

error:
	/* In case of error, return only a failure value in the reply dbus message */
	if (!rt_task)
		return ECORE_CALLBACK_CANCEL;

	_D("task %s: error occured in collection of usage info, sending error message", rt_task->task_name);
	reply = dbus_message_new_method_return(rt_task->task_msg);
	ret = -EREMOTEIO;
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);

send_message:
	/* Send the reply message back to the caller. Best effort feature. */
	_D("task %s: sending reply dbus message", rt_task->task_name);
	ret = edbus_message_send(reply);
	if (ret != RESOURCED_ERROR_NONE)
		_E("task %s: sending message failed. not attempting again!!!", rt_task->task_name);

	proc_free_runtime_info_task(rt_task);
	dbus_message_unref(reply);
	return ECORE_CALLBACK_CANCEL;
}

static int proc_runtime_info_task(struct runtime_info_task *rt_task)
{
	int i, ret;
	int wsize;

	/* Populate the usage_info_list with the needed info. There can be no failures here. */
	if (rt_task->task_type == RUNTIME_INFO_TASK_MEMORY) {
		struct process_memory_info_s *mem_info;

		mem_info = (struct process_memory_info_s *)rt_task->usage_info_list;
		for (i = 0; i < rt_task->task_size; ++i)
			proc_get_memory_usage(rt_task->pid_list[i], &mem_info[i]);
	} else {
		struct process_cpu_usage_s *cpu_usage;

		cpu_usage = (struct process_cpu_usage_s *)rt_task->usage_info_list;
		for (i = 0; i < rt_task->task_size; ++i)
			proc_get_cpu_usage(rt_task->pid_list[i], &cpu_usage[i]);
	}

	/* Write to the write end of the pipe depending on the success of
	 * the info collection (currently this is always success) */
	ret = RESOURCED_ERROR_NONE;
	wsize = write(rt_task->pipe_fds[1], &ret, sizeof(int));
	if (wsize != sizeof(int)) {
		_E("task %s: error in writing to write end of pipe", rt_task->task_name);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
}

/* Task thread start routine. Gathers needed info and writes it to
 * the memory in the runtime_info_task instance.
 */
static void *proc_runtime_info_task_thread(void *arg)
{
	int ret;
	struct runtime_info_task *rt_task = (struct runtime_info_task *)arg;

	if (!rt_task) {
		_E("invalid arguments!");
		return NULL;
	}

	ret = proc_runtime_info_task(rt_task);
	_D("task %s: finished processing, task status %d", rt_task->task_name, ret);

	if (ret != RESOURCED_ERROR_NONE) {
		/* TODO: write code to close fds and release the runtime_task_info memory */
		_E("task %s: request was not completed! no reply to be sent to runtime-info!!!", rt_task->task_name);
	}

	return NULL;
}

static DBusMessage *proc_runtime_info_request_handler(DBusMessage *msg, runtime_info_task_type type)
{
	int ret;
	pthread_t task_thread;
	struct runtime_info_task *rt_task;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusError err;
	dbus_bool_t bret;
	Ecore_Fd_Handler *task_efd;

	rt_task = NULL;

	dbus_message_iter_init(msg, &iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
			dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_INT32) {
		_E("wrong message arguments. expected array of integers");
		ret = -EIO;
		goto error;
	}

	/* Create runtime_info_task for current task */
	rt_task = (struct runtime_info_task *)calloc(1, (sizeof(struct runtime_info_task)));
	if (!rt_task) {
		_E("out of memory: not able to create runtime_info_task");
		ret = -ENOMEM;
		goto error;
	}

	rt_task->usage_info_list = NULL;
	rt_task->pipe_fds[0] = -1;
	rt_task->pipe_fds[1] = -1;

	/* Populate fields of the runtime_info_task */
	proc_get_task_name(rt_task->task_name, sizeof(rt_task->task_name),
			type);
	rt_task->task_type = type;
	dbus_message_ref(msg);
	rt_task->task_msg = msg;

	_D("Received %s usage request, task name is %s",
			(rt_task->task_type == RUNTIME_INFO_TASK_MEMORY) ? "memory" : "cpu",
			rt_task->task_name);

	dbus_error_init(&err);
	bret = dbus_message_get_args(rt_task->task_msg, &err, DBUS_TYPE_ARRAY, DBUS_TYPE_INT32,
			&rt_task->pid_list, &rt_task->task_size, DBUS_TYPE_INVALID);
	if (!bret) {
		_E("task %s: not able to extract list of process IDs from the dbus message", rt_task->task_name);
		ret = -EIO;
		goto error;
	}

	if (rt_task->task_type == RUNTIME_INFO_TASK_MEMORY)
		rt_task->usage_info_list = (void *)malloc(sizeof(struct process_memory_info_s) * rt_task->task_size);
	else
		rt_task->usage_info_list = (void *)malloc(sizeof(struct process_cpu_usage_s) * rt_task->task_size);
	if (!rt_task->usage_info_list) {
		_E("task %s: out of memory: not able to create usage_info_list of rt_task", rt_task->task_name);
		ret = -ENOMEM;
		goto error;
	}

	/* Create pipe between main loop and (to-be-created) task thread and add ecore file handler for the read end */
	ret = pipe(rt_task->pipe_fds);
	if (ret) {
		_E("task %s: error creating pipe.", rt_task->task_name);
		ret = -EIO;
		goto error;
	}
	task_efd = ecore_main_fd_handler_add(rt_task->pipe_fds[0], ECORE_FD_READ,
			(Ecore_Fd_Cb)proc_runtime_info_task_cb, (void *)rt_task, NULL, NULL);
	if (!task_efd) {
		_E("task %s: error creating ecore file handler", rt_task->task_name);
		ret = -EREMOTEIO;
		goto error;
	}

	/* Create task thread to complete requested task */
	ret = pthread_create(&task_thread, NULL, (void *)proc_runtime_info_task_thread, (void *)rt_task);
	if (ret) {
		_E("task %s: error creating task thread", rt_task->task_name);
		ret = -EREMOTEIO;
		goto error;
	} else
		pthread_detach(task_thread);
	_D("task %s: created thread for task", rt_task->task_name);
	dbus_error_free(&err);
	return NULL;

error:
	/* In case of error, return only a failure value in the reply dbus message */
	if (rt_task)
		_D("task %s: error occured, sending error reply message", rt_task->task_name);
	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);

	dbus_error_free(&err);
	proc_free_runtime_info_task(rt_task);
	return reply;
}

static DBusMessage *edbus_proc_memory_usage(E_DBus_Object *obj, DBusMessage *msg)
{
	return proc_runtime_info_request_handler(msg, RUNTIME_INFO_TASK_MEMORY);
}

static DBusMessage *edbus_proc_cpu_usage(E_DBus_Object *obj, DBusMessage *msg)
{
	return proc_runtime_info_request_handler(msg, RUNTIME_INFO_TASK_CPU);
}

static int proc_usage_stats_init(void *data)
{
	int ret;

	ret = edbus_add_methods(RESOURCED_PATH_PROCESS, edbus_methods, ARRAY_SIZE(edbus_methods));
	return ret;
}

static int proc_usage_stats_exit(void *data)
{
	return RESOURCED_ERROR_NONE;
}

static const struct proc_module_ops proc_usage_stats_ops = {
	.name	= "PROC_USAGE_STATS",
	.init	= proc_usage_stats_init,
	.exit	= proc_usage_stats_exit,
};
PROC_MODULE_REGISTER(&proc_usage_stats_ops);
