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
 * @file memory.c
 *
 * @desc start memory logging system for resourced
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#include "notifier.h"
#include "resourced.h"
#include "edbus-handler.h"
#include "trace.h"
#include "module.h"
#include "macro.h"
#include "heart.h"
#include "logging.h"
#include "logging-common.h"
#include "logging-memory.h"
#include "decision-memory.h"

static int heart_memory_init(void *data)
{
	_D("heart memory init finished");
	logging_memory_init(data);
	decision_memory_init(data);
	return RESOURCED_ERROR_NONE;
}

static int heart_memory_exit(void *data)
{
	_D("heart memory exit");
	logging_memory_exit(data);
	decision_memory_init(data);
	return RESOURCED_ERROR_NONE;
}

static const struct heart_module_ops heart_memory_ops = {
	.name		= "MEMORY",
	.init		= heart_memory_init,
	.exit		= heart_memory_exit,
};
HEART_MODULE_REGISTER(&heart_memory_ops)
