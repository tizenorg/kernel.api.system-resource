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
 * @file iface.h
 *
 * @desc Utility for working with network interfaces
 */

#ifndef TRESOURCED_LIBS_NET_IFACE_H_
#define TRESOURCED_LIBS_NET_IFACE_H_

#include <glib.h>
#include <stdbool.h>

#include "data_usage.h"

/**
 * @desc Storage now create an instance of this structure
 */
typedef struct {
	void(*handle_iface_up)(int ifindex);
	void(*handle_iface_down)(int ifindex);
} iface_callback;

int init_iftype(void);
void finalize_iftypes(void);

int is_allowed_ifindex(int ifindex);

resourced_iface_type get_iftype(int ifindex);
char *get_iftype_name(resourced_iface_type iftype);
bool is_address_exists(const char *name);

resourced_iface_type convert_iftype(const char *buffer);

void set_wifi_allowance(const resourced_option_state wifi_option);
void set_datacall_allowance(const resourced_option_state datacall_option);

typedef int(*ifindex_iterator)(int ifindex,
	resourced_iface_type iftype, void *data);

void for_each_ifindex(ifindex_iterator iter, void(*empty_func)(void *),
	void *data);

typedef GList iface_callbacks;

#endif /*TRESOURCED_LIBS_NET_IFACE_H_*/
