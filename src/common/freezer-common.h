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
 * @file freezer-common.h
 * @desc freezer common process
 **/

#ifndef __FREEZER_COMMON_H__
#define __FREEZER_COMMON_H__

#include <unistd.h>
#include <glib.h>
#include <string.h>

#include "resourced.h"
#include "const.h"
#include "proc-common.h"

#define OOMADJ_FREEZE_INIT          (OOMADJ_BACKGRD_UNLOCKED)

int get_proc_freezer_late_control(void);
void set_proc_freezer_late_control(int value);
int proc_get_freezer_status(void);

#endif /* __FREEZER_COMMON_H__ */
