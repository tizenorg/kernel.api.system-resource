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
 * @file logging-memory.h
 * @desc define structures and functions for logging.
 **/

#ifndef __LOGGING_MEMORY_H__
#define __LOGGING_MEMORY_H__

#include <stdio.h>

int logging_memory_init(void *data);
int logging_memory_exit(void *data);
#endif /*__LOGGING_MEMORY_H__*/
