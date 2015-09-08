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
 *
 * @file restriction-handler.h
 *
 * @desc Callback for working reset restrictions
 */

#ifndef _RESOURCED_RESTRICTION_HANDLER_H_
#define _RESOURCED_RESTRICTION_HANDLER_H_

#include "iface.h"
#include "roaming.h"

/**
 * @brief This function allocates structure
 * with network up/down handlers.
 * It's necessary to free memory after usage.
 */
iface_callback *create_restriction_callback(void);

/**
 * @brief This function returns pointer to roaming
 * callback. No need to free memory.
 */
roaming_cb get_roaming_restriction_cb(void);

void reactivate_restrictions(void);

typedef GList list_restrictions_info;

#endif /* _RESOURCED_RESTRICTION_HANDLER_H_ */
