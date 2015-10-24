/*
 * test
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __TEST_H__
#define __TEST_H__
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <E_DBus.h>

#ifdef ENABLE_TEST_DLOG
#define LOG_TAG "TEST"
#include <dlog.h>
#define _D(fmt, arg...) \
	        do { LOGD(fmt, ##arg); } while(0)
#define _I(fmt, arg...) \
	        do { LOGI(fmt, ##arg); } while(0)
#define _W(fmt, arg...) \
	        do { LOGW(fmt, ##arg); } while(0)
#define _E(fmt, arg...) \
	        do { LOGE(fmt, ##arg); } while(0)
#define _SD(fmt, arg...) \
	        do { SECURE_LOGD(fmt, ##arg); } while(0)
#define _SI(fmt, arg...) \
	        do { SECURE_LOGI(fmt, ##arg); } while(0)
#define _SW(fmt, arg...) \
	        do { SECURE_LOGW(fmt, ##arg); } while(0)
#define _SE(fmt, arg...) \
	        do { SECURE_LOGE(fmt, ##arg); } while(0)
#else
#define _D(...)  do { } while (0)
#define _I(...)  do { } while (0)
#define _W(...)  do { } while (0)
#define _E(...)  do { } while (0)
#define _SD(...)   do { } while (0)
#define _SI(...)   do { } while (0)
#define _SW(...)   do { } while (0)
#define _SE(...)   do { } while (0)
#endif


#define gslist_for_each_item(item, list)                       \
        for(item = list; item != NULL; item = g_slist_next(item))

#define TEST_WAIT_TIME_INTERVAL	2

enum test_priority {
	TEST_PRIORITY_NORMAL = 0,
	TEST_PRIORITY_HIGH,
};

struct test_ops {
	enum test_priority priority;
	char *name;
	void (*init) (void *data);
	void (*exit) (void *data);
	int (*start) (void);
	int (*stop) (void);
	int (*status) (void);
	int (*unit) (int argc, char **argv);
};

enum test_ops_status {
	TEST_OPS_STATUS_UNINIT,
	TEST_OPS_STATUS_START,
	TEST_OPS_STATUS_STOP,
	TEST_OPS_STATUS_MAX,
};

void test_init(void *data);
void test_exit(void *data);

static inline int test_start(const struct test_ops *c)
{
	if (c && c->start)
		return c->start();

	return -EINVAL;
}

static inline int test_stop(const struct test_ops *c)
{
	if (c && c->stop)
		return c->stop();

	return -EINVAL;
}

static inline int test_get_status(const struct test_ops *c)
{
	if (c && c->status)
		return c->status();

	return -EINVAL;
}

#define TEST_OPS_REGISTER(c)	\
static void __CONSTRUCTOR__ module_init(void)	\
{	\
	test_add(c);	\
}	\
static void __DESTRUCTOR__ module_exit(void)	\
{	\
	test_remove(c);	\
}

void test_add(const struct test_ops *c);
void test_remove(const struct test_ops *c);
const struct test_ops *test_find(const char *name);
#endif
