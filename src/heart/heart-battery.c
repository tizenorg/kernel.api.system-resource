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
 * @file battery.c
 *
 * @desc start battery logging system for resourced
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
#include "logging-battery.h"

static int heart_battery_init(void *data)
{
	_D("heart battery init finished");
	logging_battery_init(data);
	return RESOURCED_ERROR_NONE;
}

static int heart_battery_exit(void *data)
{
	_D("heart battery exit");
	logging_battery_exit(data);
	return RESOURCED_ERROR_NONE;
}

static const struct heart_module_ops heart_battery_ops = {
	.name		= "BATTERY",
	.init		= heart_battery_init,
	.exit		= heart_battery_exit,
};
HEART_MODULE_REGISTER(&heart_battery_ops)
