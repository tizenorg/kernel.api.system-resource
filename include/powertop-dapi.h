/*
 * Library for getting power usage statistics
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd.
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

#ifndef __POWERTOP_DAPI_H__
#define __POWERTOP_DAPI_H__

#ifndef UNUSED
#define UNUSED __attribute__((unused))
#endif /* UNUSED */

#ifndef DEPRECATED
#define DEPRECATED __attribute__((deprecated))
#endif

#ifndef __cplusplus
#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


void powertop_set_check_interval(unsigned int interval) DEPRECATED;
bool powertop_start_check(const char *output_path) DEPRECATED;
void powertop_stop_check(void) DEPRECATED;
void powertop_async_stop_check(void (*callback)(void *), void *arg) DEPRECATED;

#ifdef __cplusplus
}
#endif

#endif /* __POWERTOP_DAPI_H__ */
