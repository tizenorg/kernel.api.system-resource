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
 *  @file: storage-helper.c
 *  @desc: Helper functions to get storage details
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "storage-helper.h"
#include "trace.h"
#include <mntent.h>

#define PATH_MAX	256
#define INTERNAL_MEMORY_PATH	 "/opt/usr"
#define EXTERNAL_MEMORY_PATH	 "/opt/storage/sdcard"

bool is_mounted(const char* path)
{
	int ret = false;
	struct mntent* mnt;
	const char* table = "/etc/mtab";
	FILE* fp;

	fp = setmntent(table, "r");
	if (!fp)
		return ret;
	while ((mnt = getmntent(fp))) {
		if (!strcmp(mnt->mnt_dir, path)) {
			ret = true;
			break;
		}
	}
	endmntent(fp);
	return ret;
}

resourced_ret_c storage_get_size(int type, struct statvfs *buf)
{
	int ret;
	char path[PATH_MAX] = "";
	char errbuf[PATH_MAX];

	if (type == INTERNAL)
		snprintf(path, sizeof(path),"%s", INTERNAL_MEMORY_PATH);
	else if (type == EXTERNAL)
		snprintf(path, sizeof(path), "%s", EXTERNAL_MEMORY_PATH);
	else {
		_E("Unsupported storage type:%d", type);
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	_I("Path:%s", path);
	if (type == EXTERNAL) {
		if (!is_mounted(EXTERNAL_MEMORY_PATH)) {
			memset(buf, 0, sizeof(struct statvfs));
			return RESOURCED_ERROR_NONE;
		}
	}

	ret = statvfs(path, buf);
	if (ret) {
		_E("statvfs() failed. Path:%s err:%s", path, strerror_r(errno, errbuf, sizeof(errbuf)));
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
}
