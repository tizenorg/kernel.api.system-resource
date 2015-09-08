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
 * @file logging-common.h
 * @desc logging common process
 **/

#ifndef __LOGGING_COMMON_H__
#define __LOGGING_COMMON_H__

enum logging_control_type {
	LOGGING_INSERT_PROC_LIST,
	LOGGING_UPDATE_PROC_INFO,
	LOGGING_UPDATE_STATE
};

struct logging_data_type {
	enum logging_control_type control_type;
	unsigned long *args;
};

#ifdef LOGGING_SUPPORT
int logging_control(enum logging_control_type type, unsigned long *args);
#else
static inline int logging_control(enum logging_control_type type, unsigned long *args)
{
	return RESOURCED_ERROR_NONE;
}
#endif /* LOGGING_SUPPORT */

#endif /* __LOGGING_COMMON_H__ */
