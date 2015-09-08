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

/** @file datausage-foreach.h
 *
 *  @desc Data usage foreach initialization/deinitialization functions.
 *
 *  Created on: Jul 17, 2012
 */

#ifndef _RESOURCED_SRC_DATAUSAGE_H_
#define _RESOURCED_SRC_DATAUSAGE_H_

int init_datausage_foreach(sqlite3 *db);
void finalize_datausage_foreach(void);

#endif /* _RESOURCED_SRC_DATAUSAGE_H_ */

