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
 * @file storage-helper.h
 * @desc Helper functions to get storage details
 */

#ifndef _RESOURCED_STORAGE_HELPER_H_
#define _RESOURCED_STORAGE_HELPER_H_

#include "resourced.h"
#include <stdbool.h>
#include <sys/statvfs.h>

enum storage_type {
	INTERNAL = 1,
	EXTERNAL
};

bool is_mounted(const char* path);

/**
 * @desc gets storage details
 * @param type-INTERNAL/EXTERNAL, buf-storage details
 * @return negative value if error
 */
resourced_ret_c storage_get_size(int type, struct statvfs *buf);

#endif  /*_RESOURCED_STORAGE_HELPER_H_*/
