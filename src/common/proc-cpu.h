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
 * @file proc-cpu.h
 * @desc Helper functions to get cpu stat and usage
 */

#ifndef _RESOURCED_PROC_CPU_H_
#define _RESOURCED_PROC_CPU_H_

#include "resourced.h"

#define PROC_STAT_MAX_FLDS 10

struct cpu_stat {
	unsigned long long int cs[PROC_STAT_MAX_FLDS+1];
};

/**
 * @desc reads cpu stat from /proc/stat
 * @param cs - cpu stat read from /proc/stat
 * @return negative value if error
 */
resourced_ret_c proc_cpu_stat(struct cpu_stat *cs);

/**
 * @desc computes cpu usage
 * @param cs1- first cpu stat, cs2- second cpu stat
 * @return cpu usage percentage
 */
double proc_cpu_usage(struct cpu_stat *cs1, struct cpu_stat *cs2);

#endif  /*_RESOURCED_PROC_CPU_H_*/
