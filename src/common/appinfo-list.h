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
 * @file appinfo-list.h
 * @desc define helper functions to get/put appid info.
 **/

#ifndef __APPID_LIST_H__
#define __APPID_LIST_H__

#include <glib.h>

struct resourced_appinfo {
	char appid[MAX_APPID_LENGTH];
	char pkgname[MAX_PKGNAME_LENGTH];
	gint ref;
};

struct resourced_appinfo *resourced_appinfo_get(struct resourced_appinfo *ai,
	const char *appid, const char *pkgname);
void resourced_appinfo_put(struct resourced_appinfo *ai);
#endif /*__APPID_LIST_H__*/
