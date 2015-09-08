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

/*
 *  @file: specific-trace.h
 *
 *  @desc Function for print trees for application statistics and for
 *  traffic statistics.
 *  @version 1.0
 *
 */


#ifndef __PERF_CONTROL_SPECIFIC_TRACE_H__
#define __PERF_CONTROL_SPECIFIC_TRACE_H__

#include "app-stat.h"

#include "macro.h"
#include "transmission.h"

gboolean print_appstat(gpointer key, gpointer value, void *data);

#endif /*__PERF_CONTROL_SPECIFIC_TRACE_H__*/
