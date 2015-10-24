/*
 * resourced
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file db-guard.h
 *
 * @desc This guard procedures are responsible for period db erasing
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#ifndef _RESOURCED_DB_GUARD_H_
#define _RESOURCED_DB_GUARD_H_

void change_db_entries_num_num(int num);

struct counter_arg;
resourced_ret_c resourced_init_db_guard(struct counter_arg *carg);

#endif /* _RESOURCED_DB_GUARD_H_ */

