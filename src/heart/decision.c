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
 * @file decision.c
 *
 * @desc decision for resourced
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <Ecore.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <glib.h>
#include <sys/resource.h>

#include "resourced.h"
#include "trace.h"
#include "module.h"
#include "macro.h"
#include "notifier.h"
#include "proc-common.h"
#include "heart.h"
#include "logging.h"
#include "heart-common.h"
#include "edbus-handler.h"
#include "helper.h"
#include "decision.h"
#include "filemap.h"

#define DECISION_FILE_PATH	HEART_FILE_PATH"/.decision.dat"
#define DECISION_FILE_SIZE	(512 * 1024)
/* To Do: make configurable */
#define DECISION_WRITE_INTERVAL	60 * 30		/* 30 minute */
#define DECISION_PRIORITY	20

enum {
	DECISION_THREAD_UPDATE,
	DECISION_THREAD_WRITE,
	DECISION_THREAD_MAX,
};

static pthread_mutex_t decision_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static GHashTable *decision_app_list;

static pthread_mutex_t decision_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static GQueue *decision_queue;
static struct filemap *fm;

static const struct decision_module *decision_modules[DECISION_MAX];
static int num_decisions;

struct decision_thread {
	pthread_t thread;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};
static struct decision_thread decisions[DECISION_THREAD_MAX];

static Ecore_Timer *decision_write_timer = NULL;

static const struct decision_module *decision_module_find(int type)
{
	if (type < 0 || type >= DECISION_MAX)
		return NULL;

	return decision_modules[type];
}

static void* decision_info_find(struct decision_table *dt, int type)
{
	if (!dt || type < 0 || type >= DECISION_MAX)
		return NULL;

	return dt->infos[type];
}

static int decision_table_init(struct decision_table *dt, const char *appid,
	const char *pkgname)
{
	int i;

	if (!dt) {
		_E("parameter dt is null");
		return RESOURCED_ERROR_FAIL;
	}

	dt->ai = resourced_appinfo_get(dt->ai, appid, pkgname);

	assert(dt->ai);

	dt->updated = 0;

	for (i = 0; i < DECISION_MAX; i++) {
		const struct decision_module *dm;
		void *info;

		dm = decision_module_find(i);
		if (!dm) {
			_E("cannot find decision module");
			return RESOURCED_ERROR_FAIL;
		}

		info = dm->create();

		if (!info) {
			_E("cannot create info for type %d", i);
			return RESOURCED_ERROR_FAIL;
		}

		dt->infos[i] = info;
	}

	return RESOURCED_ERROR_NONE;
}

static struct decision_table *decision_table_new(const char *appid,
	const char *pkgname)
{
	struct decision_table *dt;
	int ret;

	dt = calloc(1, sizeof(struct decision_table));
	if (!dt) {
		_E("fail to allocate decision_table");
		return NULL;
	}

	ret = decision_table_init(dt, appid, pkgname);
	if (ret < 0) {
		_E("fail to init decision table for appid = %s", appid);
		free(dt);
		return NULL;
	}

	g_hash_table_insert(decision_app_list, (gpointer)dt->ai->appid,
		(gpointer)dt);

	return dt;
}

static void decision_table_free(gpointer value)
{
	struct decision_table *dt = (struct decision_table *)value;
	int i;

	if (!dt)
		return;

	for (i = 0; i < DECISION_MAX; i++) {
		const struct decision_module *dm;
		void * info;

		dm = decision_module_find(i);
		info = decision_info_find(dt, i);

		if (dm && info)
			dm->free(info);
	}
	resourced_appinfo_put(dt->ai);
	free(dt);
}

static struct decision_table *decision_table_find(const char *appid,
	const char *pkgname)
{
	struct decision_table *dt;

	if (!decision_app_list) {
		_E("decision app list was not created");
		return NULL;
	}

	dt = g_hash_table_lookup(decision_app_list, (gconstpointer)appid);
	if (!dt) {
		dt = decision_table_new(appid, pkgname);
		if (!dt) {
			_E("cannot create decision table for %s", appid);
			return NULL;
		}
	}

	return dt;
}

struct decision_item *decision_item_new(int type, const char *appid, const char *pkgname)
{
	struct decision_item *di;

	di = malloc(sizeof(struct decision_item));
	if (!di) {
		_E("fail to allocate decision_item");
		return NULL;
	}

	memset(di, 0, sizeof(struct decision_item));
	di->type = type;
	di->ai = resourced_appinfo_get(di->ai, appid, pkgname);

	if (!di->ai) {
		_E("fail to get appinfo for appid = %s, pkgname = %s",
			appid, pkgname);
		free(di);
		return NULL;
	}

	return di;
}

static void decision_item_free(struct decision_item *di)
{
	if (!di)
		return;

	resourced_appinfo_put(di->ai);
	free(di);
}


static int decision_item_update(struct decision_item *di)
{
	const struct decision_module *dm;
	struct decision_table *dt;
	void *info;

	if (!di || !di->ai) {
		_E("invalid parameter decision item or null appinfo");
		return RESOURCED_ERROR_FAIL;
	}

	pthread_mutex_lock(&decision_list_mutex);
	dt = decision_table_find(di->ai->appid, di->ai->pkgname);
	if (!dt) {
		_E("there is no decision table for %s", di->ai->appid);
		pthread_mutex_unlock(&decision_list_mutex);
		return RESOURCED_ERROR_FAIL;
	}
	pthread_mutex_unlock(&decision_list_mutex);

	info = decision_info_find(dt, di->type);
	if (!info) {
		_E("there is no info for type = %d", di->type);
		return RESOURCED_ERROR_FAIL;
	}

	/* call sub module's update function */
	dm = decision_module_find(di->type);
	if (!dm) {
		_E("invalid module index = %d", di->type);
		return RESOURCED_ERROR_FAIL;
	}

	dm->update(di, info);

	dt->updated = 1;
	_D("update item for module %d for appid %s", dm->type, dt->ai->appid);

	decision_item_free(di);

	return RESOURCED_ERROR_NONE;
}

int decision_queue_item_insert(struct decision_item *di)
{
	if (!di)
		return RESOURCED_ERROR_FAIL;

	pthread_mutex_lock(&decision_queue_mutex);
	g_queue_push_tail(decision_queue, (gpointer)di);
	pthread_mutex_unlock(&decision_queue_mutex);
	return RESOURCED_ERROR_NONE;
}

static int decision_update(void)
{
	struct decision_item *di;
	int ret;

	pthread_mutex_lock(&decision_queue_mutex);
	while (!g_queue_is_empty(decision_queue)) {
		di = g_queue_pop_head(decision_queue);

		ret = decision_item_update(di);

		if (ret < 0) {
			_E("fail to update item");
			pthread_mutex_unlock(&decision_queue_mutex);
			return RESOURCED_ERROR_FAIL;
		}
	}
	pthread_mutex_unlock(&decision_queue_mutex);
	_D("finish update deicion item");
	return RESOURCED_ERROR_NONE;
}

static void decision_entry_read(const struct filemap_info *fi)
{
	if (!fi)
		return;

	_D("read: name = %s, value = %s", fi->key, fi->value);
}

static int decision_table_write(struct decision_table *dt)
{
	int i, size = 0;
	/* buffer includes '\n' and null */
	char buf[DECISION_BUF_MAX] = {0, };
	char result_buf[DECISION_BUF_MAX] = {0, };
	int ret = RESOURCED_ERROR_NONE;

	if (!dt) {
		_E("decision table is null or appinfo is null");
		return RESOURCED_ERROR_FAIL;
	}
	assert(dt->ai);

	if (!dt->updated)
		return ret;

	for (i = 0; i < DECISION_MAX; i++) {
		const struct decision_module *dm = decision_module_find(i);
		void *info = decision_info_find(dt, i);

		if (!dm || !info) {
			_E("invalid decision module or decision info");
			continue;
		}

		dm->write(info, result_buf, DECISION_BUF_MAX);

		size += snprintf(buf + size, DECISION_BUF_MAX - size, "\t%s",
				result_buf);

		if (size >= DECISION_BUF_MAX) {
			_E("write buffer size exceeded size = %d", size);
			break;
		}
	}

	ret = filemap_write(fm, dt->ai->appid, buf, &(dt->offset));
	if (ret < 0)
		_E("cannot write buf %s for %s", buf, dt->ai->appid);

	_I("decision write buf: %s", buf);
	dt->updated = 0;

	return ret;
}

static int decision_write(void)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	struct decision_table *dt;
	int ret;

	g_hash_table_iter_init(&iter, decision_app_list);

	pthread_mutex_lock(&decision_list_mutex);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		dt = (struct decision_table *)value;

		ret = decision_table_write(dt);
		if (ret < 0)
			_E("decision table write failed for %s", key);
	}

	pthread_mutex_unlock(&decision_list_mutex);

	filemap_foreach_read(fm, filemap_root_node(fm), decision_entry_read);

	return ret;
}

static int decision_app_terminated_cb(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;
	struct decision_table *dt;
	int ret;

	if (!ps || !ps->pai || !ps->pai->program)
		return RESOURCED_ERROR_FAIL;

	pthread_mutex_lock(&decision_list_mutex);

	dt = decision_table_find(ps->appid, ps->pai->program->pkgname);

	if (!dt) {
		pthread_mutex_unlock(&decision_list_mutex);
		return RESOURCED_ERROR_FAIL;
	}

	ret = decision_table_write(dt);
	if (ret < 0)
		_D("decision table write failed for %s", ps->appid);

	g_hash_table_remove(decision_app_list, (gconstpointer)ps->appid);

	pthread_mutex_unlock(&decision_list_mutex);
	_I("%s table is removed from decision table", ps->appid);

	return RESOURCED_ERROR_NONE;
}

static void *decision_update_thread(void *arg)
{
	int ret;

	setpriority(PRIO_PROCESS, 0, DECISION_PRIORITY);

	while (1) {
		/*
		 * it starts fuction of writing decision result.
		 */
		ret = pthread_mutex_lock(&decisions[DECISION_THREAD_UPDATE].mutex);
		if (ret) {
			_E("decision write thread::pthread_mutex_lock() failed, %d", ret);
			break;
		}

		ret = pthread_cond_wait(&decisions[DECISION_THREAD_UPDATE].cond,
			&decisions[DECISION_THREAD_UPDATE].mutex);
		if (ret) {
			_E("decision update thread::pthread_cond_wait() failed, %d", ret);
			ret = pthread_mutex_unlock(&decisions[DECISION_THREAD_UPDATE].mutex);
			if (ret)
				_E("decision update thread::pthread_mutex_lock() failed, %d", ret);
			break;
		}

		decision_update();

		ret = pthread_mutex_unlock(&decisions[DECISION_THREAD_UPDATE].mutex);
		if (ret) {
			_E("decision update thread::pthread_mutex_unlock() failed, %d", ret);
			break;
		}
	}

	/* now our thread finishes - cleanup tid */
	decisions[DECISION_THREAD_UPDATE].thread = (int)NULL;

	return NULL;
}

static void *decision_write_thread_main(void *arg)
{
	int ret;

	setpriority(PRIO_PROCESS, 0, DECISION_PRIORITY);

	while (1) {
		/*
		 * it starts fuction of writing decision result.
		 */
		ret = pthread_mutex_lock(&decisions[DECISION_THREAD_WRITE].mutex);
		if (ret) {
			_E("decision write thread::pthread_mutex_lock() failed, %d", ret);
			break;
		}

		ret = pthread_cond_wait(&decisions[DECISION_THREAD_WRITE].cond,
			&decisions[DECISION_THREAD_WRITE].mutex);
		if (ret) {
			_E("decision write thread::pthread_cond_wait() failed, %d", ret);
			ret = pthread_mutex_unlock(&decisions[DECISION_THREAD_WRITE].mutex);
			if (ret)
				_E("decision write thread::pthread_mutex_lock() failed, %d", ret);
			break;
		}

		decision_write();

		ret = pthread_mutex_unlock(&decisions[DECISION_THREAD_WRITE].mutex);
		if (ret) {
			_E("decision write thread::pthread_mutex_unlock() failed, %d", ret);
			break;
		}
	}

	/* now our thread finishes - cleanup tid */
	decisions[DECISION_THREAD_WRITE].thread = (int)NULL;

	return NULL;
}

static int decision_thread_create(void)
{
	int ret = RESOURCED_ERROR_NONE;

	pthread_mutex_init(&decisions[DECISION_THREAD_UPDATE].mutex, NULL);
	pthread_cond_init(&decisions[DECISION_THREAD_UPDATE].cond, NULL);

	/* initialize decision_update_thread */
	 if (!decisions[DECISION_THREAD_UPDATE].thread) {
		ret = pthread_create(&decisions[DECISION_THREAD_UPDATE].thread, NULL,
			(void *)decision_update_thread, (void *)NULL);
		if (ret) {
			_E("pthread creation for decision_update_thread_main failed, %d\n", ret);
			decisions[DECISION_THREAD_UPDATE].thread = (int)NULL;
			return RESOURCED_ERROR_FAIL;
		}
		_D("pthread creation for decision update success");
		pthread_detach(decisions[DECISION_THREAD_UPDATE].thread);
	}
	 _I("decision update thread %u is running",
		 decisions[DECISION_THREAD_UPDATE].thread);


	pthread_mutex_init(&decisions[DECISION_THREAD_WRITE].mutex, NULL);
	pthread_cond_init(&decisions[DECISION_THREAD_WRITE].cond, NULL);

	/* initialize decision_write_thread */
	if (!decisions[DECISION_THREAD_WRITE].thread) {
		ret = pthread_create(&decisions[DECISION_THREAD_WRITE].thread, NULL,
			(void *)decision_write_thread_main, (void *)NULL);
		if (ret) {
			_E("pthread creation for decision_write_thread failed, %d\n", ret);
			decisions[DECISION_THREAD_WRITE].thread = (int)NULL;
			return RESOURCED_ERROR_FAIL;
		}
		_D("pthread creation for decision write success");
		pthread_detach(decisions[DECISION_THREAD_WRITE].thread);
	}
	 _I("decision update thread %u is running",
		 decisions[DECISION_THREAD_WRITE].thread);

	return RESOURCED_ERROR_NONE;
}

int decision_update_start(void)
{
	int ret;

	_D("decision update callback function start");

	/* signal to decision update thread */
	ret = pthread_mutex_trylock(&decisions[DECISION_THREAD_UPDATE].mutex);
	if (ret) {
		_E("pthread_mutex_trylock fail : %d, errno : %d", ret, errno);
		return RESOURCED_ERROR_FAIL;
	}

	pthread_cond_signal(&decisions[DECISION_THREAD_UPDATE].cond);
	_I("send signal to decision update thread");
	pthread_mutex_unlock(&decisions[DECISION_THREAD_UPDATE].mutex);

	return RESOURCED_ERROR_NONE;
}

static Eina_Bool decision_send_signal_to_write(void *data)
{
	int ret;

	_D("decision write callback function start");

	/* signal to decision write thread */
	ret = pthread_mutex_trylock(&decisions[DECISION_THREAD_WRITE].mutex);
	if (ret) {
		_E("pthread_mutex_trylock fail : %d, errno : %d", ret, errno);
		return ECORE_CALLBACK_RENEW;
	}

	pthread_cond_signal(&decisions[DECISION_THREAD_WRITE].cond);
	_I("send signal to decision write thread");
	pthread_mutex_unlock(&decisions[DECISION_THREAD_WRITE].mutex);

	return ECORE_CALLBACK_RENEW;
}

static int decision_init(void)
{
	int ret = RESOURCED_ERROR_NONE;

	decision_app_list = g_hash_table_new_full(
			g_str_hash,
			g_str_equal,
			NULL,
			decision_table_free);
	if (!decision_app_list) {
		_E("fail to allocate decision app list");
		return RESOURCED_ERROR_FAIL;
	}

	decision_queue = g_queue_new();

	if (!decision_queue) {
		g_hash_table_destroy(decision_app_list);
		decision_app_list = NULL;
		return RESOURCED_ERROR_FAIL;
	}

	g_queue_init(decision_queue);

	ret = filemap_new(&fm, DECISION_FILE_PATH, DECISION_FILE_SIZE, 1);

	if (ret < 0) {
		_E("fail filemap_init");
		g_hash_table_destroy(decision_app_list);
		decision_app_list = NULL;
		g_queue_free(decision_queue);
		decision_queue = NULL;
		return RESOURCED_ERROR_FAIL;
	}

	register_notifier(RESOURCED_NOTIFIER_APP_TERMINATED,
		decision_app_terminated_cb);

	if (decision_write_timer == NULL) {
		_E("decision write timer start");
		decision_write_timer = ecore_timer_add(DECISION_WRITE_INTERVAL,
			decision_send_signal_to_write, (void *)NULL);
	}

	ret = decision_thread_create();

	return ret;
}


static int decision_exit(void)
{
	if (decision_app_list) {
		g_hash_table_destroy(decision_app_list);
		decision_app_list = NULL;
	}

	if (decision_queue) {
		g_queue_free(decision_queue);
		decision_queue = NULL;
	}

	ecore_timer_del(decision_write_timer);
	decision_write_timer = NULL;

	unregister_notifier(RESOURCED_NOTIFIER_APP_TERMINATED,
		decision_app_terminated_cb);

	filemap_destroy(fm);

	return RESOURCED_ERROR_NONE;
}

int decision_module_register(const struct decision_module *dm)
{
	if (!dm) {
		_E("parameter decision module is NULL");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	if (num_decisions == 0)
		decision_init();

	if (decision_module_find(dm->type)) {
		_E("%d is already exist", dm->type);
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	decision_modules[dm->type] = dm;

	return RESOURCED_ERROR_NONE;
}

int decision_module_unregister(const struct decision_module *dm)
{
	if (!dm) {
		_E("parameter decision module is NULL");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	decision_modules[dm->type] = NULL;

	num_decisions--;
	if (num_decisions == 0)
		decision_exit();

	return RESOURCED_ERROR_NONE;
}
