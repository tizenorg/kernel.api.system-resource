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

/**
 * @file block-monitor.c
 *
 * @desc monitor file system using fanotify
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <dirent.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/fanotify.h>
#include <sys/mount.h>
#include <mntent.h>
#include <Ecore.h>

#include "notifier.h"
#include "procfs.h"
#include "proc-common.h"
#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "resourced.h"
#include "trace.h"
#include "config-parser.h"
#include "const.h"
#include "file-helper.h"
#include "block.h"
#include "logging.h"

#define FAN_MODE_ACCESS		"ACCESS"
#define FAN_MODE_READ		"READ"
#define FAN_MODE_WRITE		"WRITE"
#define FAN_MODE_DISALBE	"DISALBE"
#define MAX_LOGGING_LIMIT	0x20000

enum block_mount_type {
	BLOCK_MOUNT_ORIGINAL,
	BLOCK_MOUNT_BIND,
};

enum block_logging_type {
	BLOCK_LOGGING_NONE = 0x0,
	BLOCK_LOGGING_DLOG = 0x1,
	BLOCK_LOGGING_FILE = 0x2,
	BLOCK_LOGGING_DB = 0x4,
};

static gboolean find_hash(gpointer key, gpointer value, gpointer user_data)
{
	return (gboolean)strstr((char *)user_data, (char *)key);
}

int convert_fanotify_mode(const char *mode)
{
	int famode = FAN_EVENT_ON_CHILD;
	if (!strncmp(mode, FAN_MODE_ACCESS, sizeof(FAN_MODE_ACCESS)))
		famode |= FAN_OPEN;
	else if (!strncmp(mode, FAN_MODE_READ, sizeof(FAN_MODE_READ)))
		famode |= FAN_CLOSE_NOWRITE;
	else if (!strncmp(mode, FAN_MODE_WRITE, sizeof(FAN_MODE_WRITE)))
		famode |= FAN_CLOSE_WRITE;
	else if (!strncmp(mode, FAN_MODE_DISALBE, sizeof(FAN_MODE_DISALBE)))
		famode = 0;
	return famode;
}

static bool check_mount_dest(const char *path)
{
	bool ret = false;
	struct mntent *mnt;
	const char *table = "/etc/mtab";
	FILE *fp;
	int len = strlen(path);

	fp = setmntent(table, "r");
	if (!fp)
		return ret;

	do {
		mnt = getmntent(fp);
		if (mnt && !strncmp(mnt->mnt_dir, path, len)) {
			ret = true;
			break;
		}
	} while (mnt != NULL);
	endmntent(fp);
	return ret;
}

static void block_logging(struct block_monitor_info *bmi, pid_t pid,
						    char *label, char *filename)
{
	int type = bmi->logging;

	if (type & BLOCK_LOGGING_DLOG)
		_E("pid %d(%s) accessed %s", pid, label, filename);

	if (type & BLOCK_LOGGING_FILE) {
		FILE *f;

		if (bmi->logpath == NULL) {
			bmi->logpath = malloc(MAX_PATH_LENGTH);
			if (!bmi->logpath) {
				_E("not enough memory");
				return;
			}
			snprintf(bmi->logpath, MAX_PATH_LENGTH-1, "/var/log/%s.log", strrchr(bmi->path, '/'));
		}

		f = fopen(bmi->logpath, "a+");
		if (!f)
			return;
		bmi->total_loglen += fprintf(f, "pid %d(%s) accessed %s\n", pid, label, filename);
		fclose(f);
		if (bmi->total_loglen > MAX_LOGGING_LIMIT) {
			if (unlink(bmi->logpath) < 0)
				_E("fail to remove %s file\n", bmi->logpath);
			else
				_I("clear previous log files");
		}
	}

	if (type & BLOCK_LOGGING_DB) {
		struct logging_data ld;

		/*
		 * label in the xattr meant owner package name.
		 * block logging needed only package name.
		 * For removing overhead, block reqeusted to write label instead of appid or pkgid.
		 */
		ld.appid = ld.pkgid = label;
		ld.data = filename;
		resourced_notify(RESOURCED_NOTIFIER_LOGGING_WRITE, &ld);
	}
}

static Eina_Bool block_monitor_cb(void *user_data, Ecore_Fd_Handler *fd_handler)
{
	int fd, n, ret;
	struct fanotify_event_metadata *m;
	union {
		struct fanotify_event_metadata metadata;
		char buffer[4096];
	} data;
	pid_t currentpid = getpid();
	struct block_monitor_info *bmi = (struct block_monitor_info *)user_data;
	gpointer hash = 0;

	if (!ecore_main_fd_handler_active_get(fd_handler, ECORE_FD_READ)) {
		_E("ecore_main_fd_handler_active_get error , return\n");
		return ECORE_CALLBACK_CANCEL;
	}

	fd = ecore_main_fd_handler_fd_get(fd_handler);
	if (fd < 0) {
		_E("ecore_main_fd_handler_fd_get error, return\n");
		return ECORE_CALLBACK_CANCEL;
	}

	n = read(fd, &data, sizeof(data));
	if (n < 0) {
		_E("Failed to read fanotify event\n");
		if (errno == EINTR || errno == EAGAIN || errno == EACCES)
			return ECORE_CALLBACK_RENEW;
		else
			return ECORE_CALLBACK_CANCEL;
	}

	for (m = &data.metadata; FAN_EVENT_OK(m, n); m = FAN_EVENT_NEXT(m, n)) {
		char fn[sizeof("/proc/self/fd/") + MAX_DEC_SIZE(int)];
		char buf[MAX_PATH_LENGTH] = {0,};
		char label[PROC_NAME_MAX];

		if (m->fd < 0)
			goto next;
		if (m->pid == currentpid)
			goto next;
		snprintf(fn, sizeof(fn), "/proc/self/fd/%d", m->fd);
		ret = readlink(fn, buf, sizeof(buf)-1);
		if (ret < 0)
			goto next;

		if (bmi->last_skip_pid == m->pid)
			goto next;

		if (bmi->last_monitor_pid == m->pid)
			goto logging;

		hash= g_hash_table_find(bmi->block_exclude_path,
			    find_hash, (gpointer)buf);
		if (hash) {
			bmi->last_skip_pid = m->pid;
			goto next;
		}

		ret = proc_get_label(m->pid, label);
		if (ret < 0)
			goto next;

		if (bmi->block_include_proc) {
			hash = g_hash_table_find(bmi->block_include_proc,
				    find_hash, (gpointer)label);
			if (!hash) {
				bmi->last_skip_pid = m->pid;
				goto next;
			}
		}

	logging:
		bmi->last_monitor_pid = m->pid;
		block_logging(bmi, m->pid, label, buf);

	next:
		close(m->fd);
	}
	return ECORE_CALLBACK_RENEW;
}

static void block_logging_init(struct block_monitor_info *bmi)
{
	if (bmi->logging & BLOCK_LOGGING_DB) {
		static const struct module_ops *heart;
		heart = find_module("HEART");
		if (!heart)
			bmi->logging &= (~BLOCK_LOGGING_DB);
	}
}

int register_fanotify(struct block_monitor_info *bmi)
{
	int ret;

	if (!bmi || !strlen(bmi->path))
		return RESOURCED_ERROR_NO_DATA;

	_D("monitor register : path %s, mode %d", bmi->path, bmi->mode);

	bmi->mfd = fanotify_init(FAN_CLOEXEC|FAN_NONBLOCK | FAN_CLASS_CONTENT,
			    O_RDONLY | O_LARGEFILE | O_CLOEXEC | O_NOATIME);
	if (bmi->mfd< 0)  {
		_E("Failed to create fanotify fd");
		goto error;
        }
	if (!check_mount_dest(bmi->path)) {
		ret = mount(bmi->path, bmi->path, 0, MS_BIND, 0);
		if (ret) {
			_E("Failed to mount monitor dir");
			goto error;
		}
		bmi->mount = BLOCK_MOUNT_BIND;
	}
	if (fanotify_mark(bmi->mfd, FAN_MARK_ADD | FAN_MARK_MOUNT,
			    bmi->mode, AT_FDCWD, bmi->path) < 0) {
		_E("Failed to mark fsnotify for %s", bmi->path);
                goto error;
        }
	bmi->fd_handler = ecore_main_fd_handler_add(
		bmi->mfd, ECORE_FD_READ, block_monitor_cb, bmi, NULL, NULL);
	block_logging_init(bmi);
	return RESOURCED_ERROR_NONE;
error:
	if (bmi->mfd) {
		close(bmi->mfd);
		bmi->mfd = 0;
	}
	if (bmi->logpath) {
		free(bmi->logpath);
		bmi->logpath = NULL;
	}
	return RESOURCED_ERROR_FAIL;
}

void unregister_fanotify(struct block_monitor_info *bmi)
{
	int ret;

	if (bmi) {
		if (bmi->logpath)
			free(bmi->logpath);
		if (bmi->mount == BLOCK_MOUNT_BIND) {
			ret = umount(bmi->path);
			if (ret)
				_E("Failed to umount partition : %s", bmi->path);
			bmi->mount = BLOCK_MOUNT_ORIGINAL;
		}
		close(bmi->mfd);
		ecore_main_fd_handler_del(bmi->fd_handler);
	}
}
