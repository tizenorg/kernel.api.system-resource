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
 * @file protocol-info.c
 *
 * @desc Network protocol entity: now it's only for
 * datacall network interface type
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <vconf/vconf.h>

#include "macro.h"
#include "protocol-info.h"
#include "resourced.h"
#include "trace.h"

static resourced_hw_net_protocol_type datacall_prot_t =	RESOURCED_PROTOCOL_NONE;

static resourced_hw_net_protocol_type _convert_to_resourced_protocol(
	const int prot_type)
{
	switch (prot_type) {
	case VCONFKEY_TELEPHONY_SVCTYPE_NOSVC:
		return RESOURCED_PROTOCOL_DATACALL_NOSVC;
	case VCONFKEY_TELEPHONY_SVCTYPE_EMERGENCY:
		return RESOURCED_PROTOCOL_DATACALL_EMERGENCY;
	case VCONFKEY_TELEPHONY_SVCTYPE_SEARCH:
		return RESOURCED_PROTOCOL_DATACALL_SEARCH;
	case VCONFKEY_TELEPHONY_SVCTYPE_2G:
		return RESOURCED_PROTOCOL_DATACALL_2G;
	case VCONFKEY_TELEPHONY_SVCTYPE_2_5G:
		return RESOURCED_PROTOCOL_DATACALL_2_5G;
	case VCONFKEY_TELEPHONY_SVCTYPE_2_5G_EDGE:
		return RESOURCED_PROTOCOL_DATACALL_2_5G_EDGE;
	case VCONFKEY_TELEPHONY_SVCTYPE_3G:
		return RESOURCED_PROTOCOL_DATACALL_3G;
	case VCONFKEY_TELEPHONY_SVCTYPE_HSDPA:
		return RESOURCED_PROTOCOL_DATACALL_HSDPA;
	case VCONFKEY_TELEPHONY_SVCTYPE_LTE:
		return RESOURCED_PROTOCOL_DATACALL_LTE;
	case VCONFKEY_TELEPHONY_SVCTYPE_NONE:
	default:
		return RESOURCED_PROTOCOL_NONE;
	}
}

static resourced_ret_c _get_protocol_type(
	resourced_hw_net_protocol_type *prot_type)
{
	int ret, status;

	ret = vconf_get_int(VCONFKEY_TELEPHONY_SVCTYPE, &status);
	ret_value_msg_if(ret != 0, RESOURCED_ERROR_FAIL,
			 "vconf get failed(VCONFKEY_TELEPHONY_SVCTYPE)\n");
	*prot_type = _convert_to_resourced_protocol(status);
	return RESOURCED_ERROR_NONE;
}

static void _datacall_protocol_type_change_cb(keynode_t *key, void *data)
{
	int val = vconf_keynode_get_int(key);

	_D("key = %s, value = %d(int)\n", vconf_keynode_get_name(key), val);
	datacall_prot_t = _convert_to_resourced_protocol(val);
}

void init_hw_net_protocol_type(void)
{
	vconf_notify_key_changed(VCONFKEY_TELEPHONY_SVCTYPE,
				 _datacall_protocol_type_change_cb, NULL);
	if (_get_protocol_type(&datacall_prot_t) != RESOURCED_ERROR_NONE)
		_E("_get_protocol_type failed\n");
}

void finalize_hw_net_protocol_type(void)
{
	vconf_ignore_key_changed(VCONFKEY_TELEPHONY_SVCTYPE,
				 _datacall_protocol_type_change_cb);
	datacall_prot_t = RESOURCED_PROTOCOL_NONE;
}

resourced_hw_net_protocol_type get_hw_net_protocol_type(
	const resourced_iface_type iftype)
{
	if (iftype == RESOURCED_IFACE_DATACALL)
		return datacall_prot_t;

	return RESOURCED_PROTOCOL_NONE;
}
