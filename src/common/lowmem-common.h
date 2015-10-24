/*
 * resourced
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file lowmem-common.h
 * @desc lowmem common process
 **/

#ifndef __LOWMEM_COMMON_H__
#define __LOWMEM_COMMON_H__

enum lowmem_control_type {
	LOWMEM_MOVE_CGROUP,
	LOWMEM_MANAGE_FOREGROUND,
};

struct lowmem_data_type {
	enum lowmem_control_type control_type;
	int args[2];
};

#endif /* __LOWMEM_COMMON_H__ */
