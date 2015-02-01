/*
 * resourced
 *
 * Library for getting process statistics
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>

#include "macro.h"
#include "proc_stat.h"
#include "trace.h"
#include "proc-noti.h"
#include "const.h"

#define PROC_STAT_PATH "/proc/%d/stat"
#define PROC_STATM_PATH "/proc/%d/statm"
#define PROC_CMDLINE_PATH "/proc/%d/cmdline"

#ifndef TEST_IN_X86
#include <assert.h>
#else
#define assert(x) \
do { \
	if (!(x)) { \
		printf("assertion %s %d\n", __FILE__ , __LINE__); \
		exit(-1); \
	} \
} while (0)
#endif

API bool proc_stat_get_cpu_time_by_pid(pid_t pid, unsigned long *utime,
				       unsigned long *stime)
{
	char proc_path[sizeof(PROC_STAT_PATH) + MAX_DEC_SIZE(int)];
	FILE *fp;

	assert(utime != NULL);
	assert(stime != NULL);

	sprintf(proc_path, PROC_STAT_PATH, pid);
	fp = fopen(proc_path, "r");
	if (fp == NULL)
		return false;

	if (fscanf(fp, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s") < 0) {
		fclose(fp);
		return false;
	}

	if (fscanf(fp, "%lu %lu", utime, stime) < 1) {
		fclose(fp);
		return false;
	}

	fclose(fp);

	return true;
}


API bool proc_stat_get_mem_usage_by_pid(pid_t pid, unsigned int *rss)
{
	FILE *fp;
	char proc_path[sizeof(PROC_STATM_PATH) + MAX_DEC_SIZE(int)] = {0};

	sprintf(proc_path, PROC_STATM_PATH, pid);
	fp = fopen(proc_path, "r");
	if (fp == NULL)
		return false;

	if (fscanf(fp, "%*s %d", rss) < 1) {
		fclose(fp);
		return false;
	}

	fclose(fp);

	/* convert page to Kb */
	*rss *= 4;
	return true;
}


static int get_mem_size(char *buffer, const char *const items[], const int items_len[], const int items_cnt, unsigned int mem_size[])
{
	char *p = buffer;
	int num_found = 0;

	while (*p && num_found < items_cnt) {
		int i = 0;
		while (i < items_cnt) {
			if (strncmp(p, items[i], items_len[i] - 1) == 0) {
				/* the format of line is like this "MemTotal:		  745696 kB" */
				/* when it finds a item, skip the name of item */
				p += items_len[i];

				/* skip white space */
				while (*p == ' ')
					++p;

				char *num = p;

				/* go to the immediate next of numerical value */
				while (*p >= '0' && *p <= '9')
					++p;

				/* at this time, [num,p) is the value of item */

				/* insert null to p to parse [num,p] by atoi() */
				if (*p != 0) {
					*p = 0;
					++p;

					/* when it is the end of buffer, to avoid out of buffer */
					if (*p == 0)
						--p;
				}
				mem_size[i] = atoi(num);
				num_found++;
				break;
			}
			++i;
		}
		++p;
	}

	return num_found;
}


API bool proc_stat_get_total_mem_size(unsigned int *total_mem)
{
	int fd = 0;
	int len = 0;
	char *buffer = NULL;
	const int buffer_size = 4096;
	static const char *const items[] = { "MemTotal:" };
	static const int items_len[] = {sizeof("MemTotal:") };
	unsigned int mem_size[1];
	int num_found;

	assert(total_mem != NULL);

	fd = open("/proc/meminfo", O_RDONLY);
	if (fd < 0)
		return false;

	buffer = malloc(buffer_size);
	assert(buffer != NULL);

	len = read(fd, buffer, buffer_size - 1);
	close(fd);

	if (len < 0) {
		free(buffer);
		return false;
	}

	buffer[len] = 0;

	/* to get the best search performance, the order of items should refelect the order of /proc/meminfo */
	num_found = get_mem_size(buffer, items, items_len, 1 , mem_size);

	free(buffer);

	if (num_found < 1)
		return false;

	/* total_mem = "MemTotal" */
	*total_mem = mem_size[0] / 1024;

	return true;
}


API bool proc_stat_get_free_mem_size(unsigned int *free_mem)
{
	int fd = 0;
	char *buffer = NULL;
	const int buffer_size = 4096;
	int len = 0;
	static const char *const items[] = { "MemFree:", "Buffers:", "Cached:", "SwapCached:", "Shmem:" };
	static const int items_len[] = { sizeof("MemFree:"), sizeof("Buffers:"), sizeof("Cached:"),
							  sizeof("SwapCached:"), sizeof("Shmem:") };
	static const int items_cnt = ARRAY_SIZE(items);
	unsigned int mem_size[items_cnt];
	int num_found;

	assert(free_mem != NULL);

	fd = open("/proc/meminfo", O_RDONLY);

	if (fd < 0)
		return false;

	buffer = malloc(buffer_size);
	assert(buffer != NULL);

	len = read(fd, buffer, buffer_size - 1);
	close(fd);
	buffer[len] = 0;


	/* to get the best search performance, the order of items should refelect the order of /proc/meminfo */
	num_found = get_mem_size(buffer, items, items_len, items_cnt, mem_size);

	free(buffer);

	if (num_found < items_cnt)
		return false;

	/* free_mem = "MemFree" + "Buffers" + "Cached" + "SwapCache" - "Shmem" */
	*free_mem = (mem_size[0] + mem_size[1] + mem_size[2] + mem_size[3] - mem_size[4]) / 1024;

	return true;
}

static bool get_proc_cmdline(pid_t pid, char *cmdline)
{
	assert(cmdline != NULL);

	char buf[PATH_MAX];
	char cmdline_path[sizeof(PROC_CMDLINE_PATH) + MAX_DEC_SIZE(int)] = {0};
	char *filename;
	FILE *fp;

	sprintf(cmdline_path, PROC_CMDLINE_PATH, pid);
	fp = fopen(cmdline_path, "r");
	if (fp == NULL)
		return false;

	if (fscanf(fp, "%s", buf) < 1) {
		fclose(fp);
		return false;
	}
	fclose(fp);


	filename = strrchr(buf, '/');
	if (filename == NULL)
		filename = buf;
	else
		filename = filename + 1;

	strncpy(cmdline, filename, NAME_MAX-1);

	return true;
}

static bool get_proc_filename(pid_t pid, char *process_name)
{
	FILE *fp;
	char buf[sizeof(PROC_STAT_PATH) + MAX_DEC_SIZE(int)];
	char filename[PATH_MAX];

	assert(process_name != NULL);

	sprintf(buf, PROC_STAT_PATH, pid);
	fp = fopen(buf, "r");

	if (fp == NULL)
		return false;

	if (fscanf(fp, "%*s (%[^)]", filename) < 1) {
		fclose(fp);
		return false;
	}

	strncpy(process_name, filename, NAME_MAX-1);
	fclose(fp);

	return true;
}

API bool proc_stat_get_name_by_pid(pid_t pid, char *name)
{

	assert(name != NULL);

	if (get_proc_cmdline(pid, name))
		return true;
	else if (get_proc_filename(pid, name))
		return true;

	return false;
}


static void diff_system_time(proc_stat_system_time *st_diff, proc_stat_system_time *st_a, proc_stat_system_time *st_b)
{
	assert(st_diff != NULL);
	assert(st_a != NULL);
	assert(st_b != NULL);

	st_diff->total_time = st_a->total_time - st_b->total_time;
	st_diff->user_time = st_a->user_time - st_b->user_time;
	st_diff->nice_time = st_a->nice_time - st_b->nice_time;
	st_diff->system_time = st_a->system_time - st_b->system_time;
	st_diff->idle_time = st_a->idle_time - st_b->idle_time;
	st_diff->iowait_time = st_a->iowait_time - st_b->iowait_time;
	st_diff->irq_time = st_a->irq_time - st_b->irq_time;
	st_diff->softirq_time = st_a->softirq_time - st_b->softirq_time;
}

static bool get_system_time(proc_stat_system_time *st)
{
	FILE *fp;

	assert(st != NULL);

	fp = fopen("/proc/stat", "r");
	if (fp == NULL)
		return false;

	if (fscanf(fp, "%*s %lld %lld %lld %lld %lld %lld %lld",
		&st->user_time, &st->nice_time, &st->system_time, &st->idle_time,
		&st->iowait_time, &st->irq_time, &st->softirq_time) < 1) {
		fclose(fp);
		return false;
	}

	fclose(fp);

	st->total_time = st->user_time + st->nice_time + st->system_time + st->idle_time
				+ st->iowait_time + st->irq_time + st->softirq_time;

	return true;
}



API bool proc_stat_get_system_time_diff(proc_stat_system_time *st_diff)
{
	static proc_stat_system_time prev_st;
	proc_stat_system_time cur_st;

	assert(st_diff != NULL);

	get_system_time(&cur_st);

	if (prev_st.total_time == 0) {
		memset(st_diff, 0, sizeof(proc_stat_system_time));
		prev_st = cur_st;
		return false;
	}

	diff_system_time(st_diff, &cur_st, &prev_st);
	prev_st = cur_st;

	return (bool) (st_diff->total_time);
}


static int comapre_pid(const pid_t *pid_a, const pid_t *pid_b)
{
	assert(pid_a != NULL);
	assert(pid_b != NULL);

	/* the process which has smaller number of pid is ordered ahead */
	return (*pid_a - *pid_b);
}

/**
 * @brief Get pids under /proc file system
 *
 * @param pids the pointer of GArray to store pids
 * @return  true on success, false on failure.
 *
 * This function fills Garray instance with pids under /proc file system.
 */

static bool get_pids(GArray *pids)
{
	DIR *dirp;
	struct dirent *entry;

	assert(pids != NULL);

	dirp = opendir("/proc");

	if (dirp == NULL)
		return false;

	while ((entry = readdir(dirp)) != NULL) {
		const char *p = entry->d_name;
		char *end;
		pid_t pid;

		while (*p) {
			if (*p < '0' || *p > '9')
				break;
			p++;
		}

		if (*p != 0)
			continue;

		pid = strtol(entry->d_name, &end, 10);

		g_array_append_val(pids, pid);
	}

	closedir(dirp);
	g_array_sort(pids, (GCompareFunc)comapre_pid);

	return true;
}

API bool proc_stat_get_pids(pid_t **pids, int *cnt)
{
	unsigned int i;
	GArray *garray = NULL;

	assert(pids != NULL);
	assert(cnt != NULL);

	garray = g_array_new(false, false, sizeof(pid_t));
	g_return_val_if_fail(garray, false);

	if (get_pids(garray) == false) {
		/* g_array_free is resistant to input NULL */
		g_array_free(garray, true);
		return false;
	}

	*pids = malloc(sizeof(pid_t) * garray->len);
	assert(*pids != NULL);

	*cnt = garray->len;

	for (i = 0 ; i < garray->len; ++i)
		(*pids)[i] = g_array_index(garray, pid_t, i);

	g_array_free(garray, true);

	return true;
}


/**
 * @brief Fill proc_infos with proc_stat_process_info instances which have process statistics , specially time difference each process spent in user mode and system mode between two consecutive its calls
 *
 * @param pids GArray instance which have current pids under /proc file system
 * @param proc_infos the pointer of GArray instance to be filled with proc_stat_process_info instances which are matched with each pid in pids.
 * @param terminated_proc_infos the pointer of GArray instance to be filled with proc_stat_process_info instances which were terminated between two consecutive its calls
		  ,pass NULL if if this information is not necessary
 * @return nothing
 *
 * This function fills proc_infos with proc_stat_process_info instances which have process statistics , specially time difference each process spent in user mode and system mode between two consecutive its calls
 *
 */

static void update_proc_infos(GArray *pids, GArray *proc_infos,
						GArray *terminated_proc_infos)
{
	/* when this function is called first, we don't have basis
	*  for time interval, so it is not valid.
	*/
	static bool first = true;

	unsigned int pids_cnt = 0;
	unsigned int cur_pi_idx = 0;
	proc_stat_process_info *pi = NULL;

	unsigned int i;

	assert(pids != NULL);
	assert(proc_infos != NULL);

	pids_cnt = pids->len;

	/* with current pids, update proc_infos */
	for (i = 0 ; i < pids_cnt; ++i) {
		unsigned long utime, stime;

		if (cur_pi_idx < proc_infos->len)
			pi = &g_array_index(proc_infos, proc_stat_process_info, cur_pi_idx);
		else
		/* current pid is out of proc_infos, so it is new pid. */
			pi = NULL;

		assert(i < pids->len);
		pid_t pid = g_array_index(pids, pid_t, i);

		if ((pi != NULL) && (pi->pid == pid)) {
			/* current pid is matched with proc_infos[curPsIdex],
			*  so update proc_infos[curPsIdex]
			*/
			++cur_pi_idx;

			pi->fresh = false; /* it is not new process */
			/* by now, we don't know whether it is valid or not,
			*  so mark it as invalid by default.
			*/
			pi->valid = false;

			if (!(proc_stat_get_cpu_time_by_pid(pid, &utime, &stime) && proc_stat_get_mem_usage_by_pid(pid, &(pi->rss))))
				continue;

			if ((pi->utime_prev == utime) && (pi->stime_prev == stime)) {
				/* There is no diff in execution time, mark it as inactive. */
				pi->utime_diff = 0;
				pi->stime_diff = 0;
				pi->active = false;
				continue;
			} else {
				pi->active = true; /* mark it as active */
			}
			/* update time related fields */
			pi->utime_diff = (utime - pi->utime_prev);
			pi->stime_diff = (stime - pi->stime_prev);
			pi->utime_prev = utime;
			pi->stime_prev = stime;

			pi->valid = true; /* mark it as valid */
		} else if ((pi == NULL) || (pi->pid > pid)) {
			/* in case of new process */
			proc_stat_process_info new_pi;

			new_pi.pid = pid;

			if (!(proc_stat_get_name_by_pid(pid, new_pi.name) && proc_stat_get_cpu_time_by_pid(pid, &utime, &stime) && proc_stat_get_mem_usage_by_pid(pid, &new_pi.rss)))
				continue; /* in case of not getting information of current pid, skip it */

			new_pi.fresh = true; /* mark it as new (process) */
			new_pi.utime_prev = utime;
			new_pi.stime_prev = stime;
			new_pi.utime_diff = utime;
			new_pi.stime_diff = stime;

			if (first == false)
				/* This process is created after the first call of update_proc_infos, so we know execution time of it.
				*  Mark it as valid.
				*/
				new_pi.valid = true;
			else
				new_pi.valid = false;

			/* add it to proc_infos */
			g_array_insert_val(proc_infos, cur_pi_idx , new_pi);
			++cur_pi_idx;
		} else {
			if (terminated_proc_infos != NULL) {
				proc_stat_process_info terminated_pi;
				terminated_pi = *pi;
				g_array_append_val(terminated_proc_infos, terminated_pi);
			}

			/* in case of the process terminated, remove it from proc_infos */
			assert(cur_pi_idx < proc_infos->len);
			g_array_remove_index(proc_infos, cur_pi_idx);
			/* current pid should be compared again, so decrease loop count */
			--i;
		}

	}

	/* in case of the process terminated, remove it from proc_infos */
	while (cur_pi_idx < proc_infos->len) {
		if (terminated_proc_infos != NULL) {
			proc_stat_process_info terminated_pi;

			assert(cur_pi_idx < proc_infos->len);
			terminated_pi = g_array_index(proc_infos, proc_stat_process_info, cur_pi_idx);
			g_array_append_val(terminated_proc_infos, terminated_pi);
		}

		assert(cur_pi_idx < proc_infos->len);
		g_array_remove_index(proc_infos, cur_pi_idx);
	}

	first = false;
}



static int compare_proc_info(const proc_stat_process_info *proc_info_a, const proc_stat_process_info *proc_info_b)
{
	/*
	* Firstly, long execution time process is ordered  ahead
	* Secondly, newly created process is ordered ahead
	*/
	unsigned long exec_time_a, exec_time_b;

	assert(proc_info_a != NULL);
	assert(proc_info_b != NULL);

	exec_time_a = proc_info_a->utime_diff + proc_info_a->stime_diff;
	exec_time_b = proc_info_b->utime_diff + proc_info_b->stime_diff;

	if (exec_time_a != exec_time_b)
		return (exec_time_b - exec_time_a);

	if (proc_info_a->fresh != proc_info_b->fresh)
		return ((int)(proc_info_b->fresh) - (int)(proc_info_a->fresh));

	return 0;

}


/**
 * @brief Extract valid proc_stat_process_info instances from proc_infos and fill valid_proc_infos with these instances
 *
 * @param proc_infos from which source to extract valid proc_stat_process_info instances
 * @param valid_proc_infos GArray instance to be filled with valid proc_stat_process_info instances
 * @param total_valid_proc_time to get the sum of the time spent by all valid proc_stat_process_info instance, pass NULL if if this information is not necessary
 * @return  nothing
 *
 * This function extracts valid proc_stat_process_info instances from proc_infos and fills valid_proc_infos with these instances
 */
static void pick_valid_proc_infos(GArray *proc_infos, GArray *valid_proc_infos, unsigned long *total_valid_proc_time)
{
	unsigned int i;
	proc_stat_process_info pi;

	assert(valid_proc_infos != NULL);

	if (total_valid_proc_time != NULL)
		*total_valid_proc_time = 0;

	for (i = 0; i < proc_infos->len ; ++i) {
		assert(i < proc_infos->len);
		pi = g_array_index(proc_infos, proc_stat_process_info, i);

		if (pi.valid) {
			g_array_append_val(valid_proc_infos, pi);

			if (total_valid_proc_time != NULL)
				*total_valid_proc_time += (pi.utime_diff+pi.stime_diff);
		}
	}

	g_array_sort(valid_proc_infos, (GCompareFunc)compare_proc_info);
}


static GArray *g_pids = NULL;
static GArray *proc_infos = NULL;

API void proc_stat_init(void)
{
	g_pids = g_array_new(false, false, sizeof(pid_t));
	proc_infos = g_array_new(false, false, sizeof(proc_stat_process_info));
}

API bool proc_stat_get_process_info(GArray *valid_proc_infos,
				    GArray *terminated_proc_infos,
				    unsigned long *total_valid_proc_time)
{
	assert(valid_proc_infos != NULL);

	g_array_set_size(g_pids, 0);

	if (!get_pids(g_pids))
		return false;

	update_proc_infos(g_pids, proc_infos, terminated_proc_infos);
	pick_valid_proc_infos(proc_infos, valid_proc_infos, total_valid_proc_time);

	return true;

}

API void proc_stat_finalize(void)
{
	if (g_pids) {
		g_array_free(g_pids, true);
		g_pids = NULL;
	}

	if (proc_infos) {
		g_array_free(proc_infos, true);
		proc_infos = NULL;
	}
}


API unsigned int proc_stat_get_gpu_clock(void)
{
	FILE *fp;
	unsigned int clock;

	fp = fopen("/sys/module/mali/parameters/mali_gpu_clk", "r");
	if (fp == NULL)
		return -1;

	if (fscanf(fp, "%d", &clock) < 1) {
		fclose(fp);
		return -1;
	}

	fclose(fp);

	return clock;
}

bool proc_stat_is_gpu_on(void)
{
	if (proc_stat_get_gpu_clock() <= 0)
		return false;

	return true;
}



static inline int send_int(int fd, int val)
{
	return write(fd, &val, sizeof(int));
}

static inline int send_str(int fd, char *str)
{
	int len;
	int ret;
	if (str == NULL) {
		len = 0;
		ret = write(fd, &len, sizeof(int));
	} else {
		len = strlen(str);
		if (len > NOTI_MAXARGLEN)
			len = NOTI_MAXARGLEN;
		ret = write(fd, &len, sizeof(int));
		if (ret < 0) {
			_E("%s: write failed\n", __FUNCTION__);
			return ret;
		}
		ret = write(fd, str, len);
	}
	return ret;
}

static int send_socket(struct resourced_noti *msg, bool sync)
{
	int client_len;
	int client_sockfd;
	int result = 0;
	struct sockaddr_un clientaddr;
	int i;
	int ret;

	client_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (client_sockfd == -1) {
		_E("%s: socket create failed\n", __FUNCTION__);
		return -1;
	}

	bzero(&clientaddr, sizeof(clientaddr));
	clientaddr.sun_family = AF_UNIX;
	strncpy(clientaddr.sun_path, RESOURCED_SOCKET_PATH, sizeof(clientaddr.sun_path) - 1);
	client_len = sizeof(clientaddr);

	if (connect(client_sockfd, (struct sockaddr *)&clientaddr, client_len) <
	    0) {
		_E("%s: connect failed\n", __FUNCTION__);
		close(client_sockfd);
		return RESOURCED_ERROR_FAIL;
	}

	send_int(client_sockfd, msg->pid);
	send_int(client_sockfd, msg->type);
	send_str(client_sockfd, msg->path);
	send_int(client_sockfd, msg->argc);
	for (i = 0; i < msg->argc; i++)
		send_str(client_sockfd, msg->argv[i]);

	if (sync) {
		ret = read(client_sockfd, &result, sizeof(int));
		if (ret < 0) {
			_E("%s: read failed\n", __FUNCTION__);
			close(client_sockfd);
			return RESOURCED_ERROR_FAIL;
		}
	}

	close(client_sockfd);
	return result;
}

static resourced_ret_c proc_cgroup_send_status(const int type, int num, ...)
{
	struct resourced_noti *msg;
	resourced_ret_c ret = RESOURCED_ERROR_NONE;
	va_list argptr;

	int i;
	char *args = NULL;
	bool sync = SYNC_OPERATION(type);

	msg = malloc(sizeof(struct resourced_noti));

	if (msg == NULL)
		return RESOURCED_ERROR_OUT_OF_MEMORY;

	msg->pid = getpid();
	msg->type = type;
	msg->path = NULL;

	msg->argc = num;
	va_start(argptr, num);
	/* it's just for debug purpose to test error reporting */
	for (i = 0; i < num; i++) {
		args = va_arg(argptr, char *);
		msg->argv[i] = args;
	}
	va_end(argptr);

	ret = send_socket(msg, sync);
	if (ret < 0)
		ret = RESOURCED_ERROR_FAIL;

	free(msg);

	return ret;
}

API resourced_ret_c proc_cgroup_foregrd(void)
{
	char buf[MAX_DEC_SIZE(int)];
	snprintf(buf, sizeof(buf), "%d", getpid());
	return proc_cgroup_send_status(PROC_CGROUP_SET_FOREGRD, 1, buf);
}

API resourced_ret_c proc_cgroup_backgrd(void)
{
	char buf[MAX_DEC_SIZE(int)];
	snprintf(buf, sizeof(buf), "%d", getpid());
	return proc_cgroup_send_status(PROC_CGROUP_SET_BACKGRD, 1, buf);
}

API resourced_ret_c proc_cgroup_active(pid_t pid)
{
	char buf[MAX_DEC_SIZE(int)];
	snprintf(buf, sizeof(buf), "%d", pid);
	return proc_cgroup_send_status(PROC_CGROUP_SET_ACTIVE, 1, buf);
}

API resourced_ret_c proc_cgroup_inactive(pid_t pid)
{
	char buf[MAX_DEC_SIZE(int)];
	snprintf(buf, sizeof(buf), "%d", pid);
	return proc_cgroup_send_status(PROC_CGROUP_SET_INACTIVE, 1, buf);
}

API resourced_ret_c proc_group_change_status(int type, pid_t pid, char* app_id)
{
	char pid_buf[MAX_DEC_SIZE(int)];
	char appid_buf[NOTI_MAXARGLEN];
	snprintf(pid_buf, sizeof(pid_buf), "%d", pid);
	snprintf(appid_buf, sizeof(appid_buf)-1, "%s", app_id);
	return proc_cgroup_send_status(type, 2, pid_buf, appid_buf);
}

API resourced_ret_c proc_cgroup_sweep_memory(void)
{
	char buf[MAX_DEC_SIZE(int)];
	snprintf(buf, sizeof(buf), "%d", getpid());
	return proc_cgroup_send_status(PROC_CGROUP_GET_MEMSWEEP, 1, buf);
}

API resourced_ret_c proc_cgroup_launch(int type, pid_t pid, char* app_id, char* pkg_id)
{
	char pid_buf[MAX_DEC_SIZE(int)];
	char appid_buf[NOTI_MAXARGLEN];
	char pkgid_buf[NOTI_MAXARGLEN];
	snprintf(pid_buf, sizeof(pid_buf), "%d", pid);
	snprintf(appid_buf, sizeof(appid_buf)-1, "%s", app_id);
	snprintf(pkgid_buf, sizeof(pkgid_buf)-1, "%s", pkg_id);
	return proc_cgroup_send_status(type, 3, pid_buf, appid_buf, pkgid_buf);
}

