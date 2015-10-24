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
 * @file appinfo-list.c
 * @desc define helper functions to get/put appid info.
 **/

#include <resourced.h>
#include <trace.h>
#include <stdlib.h>
#include <assert.h>

#include "macro.h"
#include "const.h"
#include "appinfo-list.h"

static GRWLock resourced_appinfo_lock;
static GHashTable *resourced_appinfo_list;

static struct resourced_appinfo *resourced_appinfo_create(const char *appid,
	const char *pkgname)
{
	struct resourced_appinfo *ai;
	int appid_len, pkgname_len;

	assert(appid != NULL);
	assert(pkgname != NULL);

	if (!appid || !pkgname){
		_E("appid or pkgname was null, values: %s, %s", appid, pkgname);
		return NULL;
	}

	appid_len = strlen(appid);
	pkgname_len = strlen(pkgname);

	if (appid_len >= MAX_APPID_LENGTH - 1 ||
	    pkgname_len >= MAX_PKGNAME_LENGTH - 1) {
		_E("appid length = %d, pkgname length = %d",
			appid_len, pkgname_len);
		return NULL;
	}

	ai = malloc(sizeof(struct resourced_appinfo));
	if (!ai) {
		_E("malloc failed for resourced_appinfo");
		return NULL;
	}

	/* appid and pkgname are terminated with null */
	strncpy(ai->appid, appid, appid_len);
	ai->appid[appid_len] = '\0';
	strncpy(ai->pkgname, pkgname, pkgname_len);
	ai->pkgname[pkgname_len] = '\0';
	ai->ref = 0;

	g_rw_lock_writer_lock(&resourced_appinfo_lock);

	g_hash_table_insert(resourced_appinfo_list, (gpointer)ai->appid,
		(gpointer)ai);

	g_rw_lock_writer_unlock(&resourced_appinfo_lock);

	return ai;
}

static void resourced_appinfo_remove(struct resourced_appinfo *ai)
{
	if (!ai)
		return;

	g_rw_lock_writer_lock(&resourced_appinfo_lock);

	/* ai is freed by free notifier */
	g_hash_table_remove(resourced_appinfo_list, (gpointer)ai->appid);

	g_rw_lock_writer_unlock(&resourced_appinfo_lock);
}

struct resourced_appinfo *resourced_appinfo_get(struct resourced_appinfo *ai,
	const char *appid, const char *pkgname)
{
	if (!appid)
		return NULL;

	g_rw_lock_reader_lock(&resourced_appinfo_lock);

	ai = g_hash_table_lookup(resourced_appinfo_list, (gconstpointer)appid);

	g_rw_lock_reader_unlock(&resourced_appinfo_lock);

	if (!ai) {
		ai = resourced_appinfo_create(appid, pkgname);
		if (!ai)
			return NULL;
	}

	g_atomic_int_inc(&ai->ref);
	_D("appid %s, pkgname = %s, ref = %d", appid, pkgname,
		g_atomic_int_get(&ai->ref));

	return ai;
}

void resourced_appinfo_put(struct resourced_appinfo *ai)
{
	gboolean ret;

	if (!ai)
		return;

	ret = g_atomic_int_dec_and_test(&ai->ref);

	_D("appid %s, pkgname = %s, ref = %d", ai->appid, ai->pkgname,
		g_atomic_int_get(&ai->ref));

	if (ret)
		resourced_appinfo_remove(ai);

}

static void resourced_appinfo_free_value(gpointer value)
{
	struct resourced_appinfo *ai = (struct resourced_appinfo *)value;

	if (!ai)
		return;

	free(ai);
}

static int __attribute__ ((constructor)) resourced_appinfo_list_init(void)
{
	resourced_appinfo_list = g_hash_table_new_full(
			g_str_hash,
			g_str_equal,
			NULL,
			resourced_appinfo_free_value);
	if (!resourced_appinfo_list) {
		_E("fail create resourced_appinfo_list");
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	_D("resourced_appinfo_list created");
	return RESOURCED_ERROR_NONE;
}

static int __attribute__ ((destructor)) resourced_appinfo_list_exit(void)
{
	assert(resourced_appinfo_list);

	g_hash_table_destroy(resourced_appinfo_list);
	return RESOURCED_ERROR_NONE;
}
