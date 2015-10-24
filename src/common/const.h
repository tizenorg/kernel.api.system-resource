/*
 *  resourced
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 *  @file: const.h
 *
 */

#ifndef _RESOURCED_CONST_H
#define _RESOURCED_CONST_H

#define TASK_FILE_NAME "/tasks"
#define CGROUP_FILE_NAME "/cgroup.procs"
#define UNKNOWN_APP "(unknown)"

#define MAX_PATH_LENGTH 512
#define MAX_NAME_LENGTH 256
#define MAX_IFACE_LENGTH 32
#define MAX_APPID_LENGTH 128
#define MAX_PKGNAME_LENGTH 128

#define PROC_BUF_MAX 64
#define PROC_NAME_MAX 1024

#define COMMA_DELIMETER ","

#define COUNTER_UPDATE_PERIOD 60
#define COUNTER_FLUSH_PERIOD 60

#define NONE_QUOTA_ID 0

#define TIME_TO_SAFE_DATA 1 /* one second */

/*
 * @desc reserved classid enums
 * internal structure, we don't provide it externally
*/
enum resourced_reserved_classid {
	RESOURCED_UNKNOWN_CLASSID,
	RESOURCED_ALL_APP_CLASSID,		/**< kernel expects 1 for
						handling restriction for all
						applications  */
	RESOURCED_TETHERING_APP_CLASSID,	/**< it uses in user space logic
						for counting tethering traffic */
	RESOURCED_FOREGROUND_APP_CLASSID,	/* it will used for special cgroup,
						   blocked cgroup */
	RESOURCED_BACKGROUND_APP_CLASSID,
	RESOURCED_RESERVED_CLASSID_MAX,
};

enum resourced_counter_state {
	RESOURCED_DEFAULT_STATE = 0,
	RESOURCED_FORCIBLY_FLUSH_STATE = 1 << 1,
	RESOURCED_FORCIBLY_QUIT_STATE = 1 << 2,
	RESOURCED_NET_BLOCKED_STATE = 1 << 3,
	RESOURCED_CHECK_QUOTA = 1 << 4,
	RESOURCED_UPDATE_REQUESTED = 1 << 5,
};

#endif /* _RESOURCED_CONST_H */
