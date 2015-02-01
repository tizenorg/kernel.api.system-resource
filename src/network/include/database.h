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
 *  @file: database.h
 *
 *  @desc Performance management API. Database helper
 *  @version 1.0
 *
 *  Created on: Jun 29, 2012
 */

#include <sqlite3.h>

#ifndef TRESOURCED_DATABASE_H_
#define TRESOURCED_DATABASE_H_

sqlite3 *resourced_get_database(void);

/**
 * @desc Initialize DB and DB statement
 * only once time
 */
void libresourced_db_initialize_once(void);

#endif /* TRESOURCED_DATABASE_H_ */
