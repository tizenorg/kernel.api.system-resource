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
 * @file decision.h
 * @desc define structures and functions for decision.
 **/

#ifndef __DECISION_H__
#define __DECISION_H__

#define DECISION_BUF_MAX	1024
#define DECISION_MAX_ARGS	5

#include "appinfo-list.h"

enum {
	DECISION_MEMORY,
	DECISION_MAX,
};

struct decision_table {
	struct resourced_appinfo *ai;
	void *infos[DECISION_MAX];
	unsigned updated;
	unsigned offset;
};

struct decision_item {
	int type;
	struct resourced_appinfo *ai;
	unsigned args[DECISION_MAX_ARGS];
};

typedef void *(*info_create_fn)(void);
typedef void (*info_free_fn)(void *);
typedef void (*info_update_fn)(struct decision_item *, void *);
typedef void (*info_write_fn)(void *, char *buf, int len);

struct decision_module {
	int type;
	info_create_fn create;
	info_free_fn free;
	info_update_fn update;
	info_write_fn write;
};

int decision_module_register(const struct decision_module *dm);
int decision_module_unregister(const struct decision_module *dm);
int decision_update_start(void);
int decision_queue_item_insert(struct decision_item *di);
struct decision_item *decision_item_new(int type, const char *appid, const char *pkgname);
#endif /*__DECISION_H__*/
