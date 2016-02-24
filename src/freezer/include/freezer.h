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
 * @file freezer-process.h
 * @desc Freezing apropriate process
 **/


#ifndef __FREEZER_H__
#define __FREEZER_H__

#include "resourced.h"

enum freezer_enable_type {
	FREEZER_DISABLE,
	FREEZER_PSMODE,
	FREEZER_ENABLE_BACKGRD,
	FREEZER_ENABLE_SUSPEND,
};

enum freezer_control_type {
	SET_FOREGRD,
	SET_BACKGRD,
};

enum freezer_status_type {
	GET_STATUS,
	SET_STATUS,
};

struct freezer_cotrol_data {
	int type;
	int pid;
	char* appid;
};

struct freezer_status_data {
	int type;
	int status;
};

int get_freezer_mode(void);
int freezer_broadcasting(enum freezer_control_type type,
	    pid_t pid);

#endif /* __FREEZER_H__ */

