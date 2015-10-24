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
 * @file decision-memory.h
 * @desc define structures and functions for decision memory.
 **/

#ifndef __DECISION_MEMORY_H__
#define __DECISION_MEMORY_H__

struct regression_info {
	unsigned int sum_x;
	unsigned int sum_y;
	unsigned int sum_xs;
	unsigned int sum_xy;
	unsigned int sample_count;
	unsigned int hit;
	float coeff_a;
	float coeff_b;
};

struct decision_memory_info {
	unsigned int pred_uss;
	int warning_leak;

	struct regression_info *ri;
};

int decision_memory_init(void *data);
int decision_memory_exit(void *data);
#endif /*__DECISION_MEMORY_H__*/
