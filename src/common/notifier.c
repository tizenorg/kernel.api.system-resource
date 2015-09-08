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

#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "notifier.h"

#include <resourced.h>
#include <trace.h>
#include <stdlib.h>
#include <glib.h>

struct resourced_notifier {
	enum notifier_type status;
	int (*func)(void *data);
};

static GSList *resourced_notifier_list;

#define FIND_NOTIFIER(a, b, d, e, f) \
	gslist_for_each(a, b, d) \
		if (e == d->e && f == (d->f))

int register_notifier(enum notifier_type status, int (*func)(void *data))
{
	GSList *n;
	struct resourced_notifier *notifier;

	_I("%d, %x", status, func);

	if (!func) {
		_E("invalid func address!");
		return -EINVAL;
	}

	FIND_NOTIFIER(resourced_notifier_list, n, notifier, status, func) {
		_E("function is already registered! [%d, %x]",
		    status, func);
		return -EINVAL;
	}

	notifier = malloc(sizeof(struct resourced_notifier));
	if (!notifier) {
		_E("Fail to malloc for notifier!");
		return -ENOMEM;
	}

	notifier->status = status;
	notifier->func = func;

	resourced_notifier_list = g_slist_append(resourced_notifier_list, notifier);

	return 0;
}

int unregister_notifier(enum notifier_type status, int (*func)(void *data))
{
	GSList *n;
	struct resourced_notifier *notifier;

	if (!func) {
		_E("invalid func address!");
		return -EINVAL;
	}

	FIND_NOTIFIER(resourced_notifier_list, n, notifier, status, func) {
		_I("[%d, %x]", status, func);
		resourced_notifier_list = g_slist_remove(resourced_notifier_list, notifier);
		free(notifier);
	}

	return 0;
}

void resourced_notify(enum notifier_type status, void *data)
{
	GSList *iter;
	struct resourced_notifier *notifier;

	gslist_for_each_item(iter, resourced_notifier_list) {
		notifier = (struct resourced_notifier *)iter->data;
		if (status == notifier->status) {
			if (notifier->func)
				notifier->func(data);
		}
	}
}

static int notifier_exit(void *data)
{
	GSList *iter;
	/* Deinitialize in reverse order */
	GSList *reverse_list = g_slist_reverse(resourced_notifier_list);
	struct resourced_notifier *notifier;

	gslist_for_each_item(iter, reverse_list) {
		notifier = (struct resourced_notifier *)iter->data;
		resourced_notifier_list = g_slist_remove(resourced_notifier_list, iter);
		free(notifier);
	}
	return RESOURCED_ERROR_NONE;
}

static struct module_ops notifier_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name     = "notifier",
	.exit     = notifier_exit,
};

MODULE_REGISTER(&notifier_ops)

