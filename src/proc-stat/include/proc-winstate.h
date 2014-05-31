/*
 *  resourced
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
 * @file proc_noti.h
 * @desc communication api with libresourced for grouping process
 **/

#ifndef __PROC_WINSTATE_H__
#define __PROC_WINSTATE_H__

int proc_win_status_init(void);
int proc_add_visibiliry(int pid);

#endif /*__PROC_WINSTATE_H__*/

