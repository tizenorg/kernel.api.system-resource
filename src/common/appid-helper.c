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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define DOT_DELIMETER '.'

/*
 * no need to extract in case of com.facebook, com.opera.
 * org.tizen
 * but in case of samsung.Engk10bghd we will do it,
 * It's better here to pass appid as is to setting,
 * but in this case setting should group it, because
 * several appid is possible in one package.
 * */
static bool is_base_name(const char *appid)
{
	char *dot = index(appid, DOT_DELIMETER);
	if (!dot)
		return false;

	return index(dot, DOT_DELIMETER) != NULL;
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
