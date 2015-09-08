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
 * @file specific-trace.c
 *
 * @desc functions for tracing complex entities
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "specific-trace.h"
#include "macro.h"
#include "trace.h"

gboolean print_appstat(gpointer key, gpointer value,
	void __attribute__((__unused__)) *data)
{
	struct application_stat *appstat = (struct application_stat *)value;
	struct classid_iftype_key *composite_key =
		(struct classid_iftype_key *)key;

	if (!appstat || !composite_key) {
		_E("Please provide valid argument for printing app stat\n");
		return TRUE; /*stop printing*/
	}

       _SD("appid %s, pid %d, rcv %u, snd %u, classid %u, iftype %d, ifname %s," \
               " is_roaming %d",
		appstat->application_id, appstat->pid, appstat->rcv_count,
		appstat->snd_count, (u_int32_t)composite_key->classid,
		composite_key->iftype, composite_key->ifname,
		appstat->is_roaming);

	return FALSE;
}
