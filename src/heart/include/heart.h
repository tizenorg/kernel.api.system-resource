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
 * @file heart.h
 * @desc define structures and functions for logging.
 **/

#ifndef __HEART_H__
#define __HEART_H__

#include <stdio.h>
#include <time.h>

#define HEART_CONF_FILE_PATH			"/etc/resourced/heart.conf"
#define HEART_FILE_PATH				"/opt/usr/data/heart"
#define HEART_CONF_SECTION			"HEART"

struct heart_module_ops {
	char *name;
	int (*init) (void *data);
	int (*dump) (FILE *fp, int mode, void *data);
	int (*exit) (void *data);
};

#define HEART_MODULE_REGISTER(module) \
static void __attribute__ ((constructor)) module_init(void) \
{ \
	heart_module_add(module); \
} \
static void __attribute__ ((destructor)) module_exit(void) \
{ \
	heart_module_remove(module); \
}

void heart_module_add(const struct heart_module_ops *mod);
void heart_module_remove(const struct heart_module_ops *mod);

#endif /*__HEART_H__*/
