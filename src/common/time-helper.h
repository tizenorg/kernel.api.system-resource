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


/*
 * @file time-helper.h
 * @desc Helper functions for to get timestamp and time difference
 */

#ifndef _RESOURCED_TIME_HELPER_H_
#define _RESOURCED_TIME_HELPER_H_

#include "resourced.h"

/**
 * @desc gets current timestamp in "%y%m%d%H%M%S%ms" format
 * @param ts - timestamp string
 * @return None
 */
void time_stamp(char *ts);

/**
 * @desc gets time difference between two timeval
 * @param diff-differece, start-starting timeval, end-ending timeval
 * @return None
 */
void time_diff(struct timeval *diff, struct timeval *start, struct timeval *end);

#endif  /*_RESOURCED_TIME_HELPER_H_*/
