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
#include <glib.h>

#include "test.h"

static GSList *test_header;

void test_add(const struct test_ops *module)
{
	if (module->priority == TEST_PRIORITY_HIGH)
		test_header = g_slist_prepend(test_header, (gpointer)module);
	else
		test_header = g_slist_append(test_header, (gpointer)module);
}

void test_remove(const struct test_ops *module)
{
	test_header = g_slist_remove(test_header, (gpointer)module);
}

const struct test_ops *test_find(const char *name)
{
	GSList *iter;
	const struct test_ops *module;

	gslist_for_each_item(iter, test_header) {
		module = (struct test_ops *)iter->data;
		if (!strcmp(module->name, name))
			return module;
	}
	return NULL;
}

void test_init(void *data)
{
	GSList *iter;
	const struct test_ops *module;

	gslist_for_each_item(iter, test_header) {
		module = (struct test_ops *)iter->data;
		_D("Initialize [%s] module\n", module->name);
		if (module->init)
			module->init(data);
	}
}

void test_exit(void *data)
{
	GSList *iter;
	const struct test_ops *module;

	gslist_for_each_item(iter, test_header) {
		module = (struct test_ops *)iter->data;
		_D("Deinitialize [%s] module\n", module->name);
		if (module->exit)
			module->exit(data);
	}
}
