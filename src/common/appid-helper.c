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

#include <stdlib.h>
#include <string.h>

#define BASE_NAME_PREFIX "com.samsung."
#define DOT_DELIMETER '.'

static int is_base_name(const char *appid)
{
	return strstr(appid, BASE_NAME_PREFIX) != NULL;
}

void extract_pkgname(const char *appid, char *pkgname,
	const int pkgname_size)
{
	char *delim_pos; /* delimeter position */
	size_t pkgname_res_size;

	if (is_base_name(appid)) {
		strncpy(pkgname, appid, pkgname_size);
		return;
	}

	/* no a base name case try to dedicate pkg name */
	delim_pos = strchr(appid, DOT_DELIMETER);
	if (delim_pos) {
		pkgname_res_size = abs(delim_pos - appid);
		pkgname_res_size = pkgname_res_size > pkgname_size ?
			pkgname_size : pkgname_res_size;
	} else
		pkgname_res_size = pkgname_size -1;

	strncpy(pkgname, appid, pkgname_res_size);
	pkgname[pkgname_res_size] = '\0';
}
