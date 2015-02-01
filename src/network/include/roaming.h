/*
 * resourced
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd. All rights reserved.
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
 *
 * @file roaming.h
 *
 * @desc Roaming persistent object. Due roaming changes not so often we can keep it in
 *  our memory and handle roaming changes.
 */

#ifndef _RSML_LIBS_ROAMING_H
#define _RSML_LIBS_ROAMING_H

#include "data_usage.h"

/**
 * @brief Just get roaming state.
 */
resourced_roaming_type get_roaming(void);

typedef void(*roaming_cb)(void);

void regist_roaming_cb(roaming_cb cb);

#endif /* _RSML_LIBS_ROAMING_H*/
