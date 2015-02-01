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
 * @file network.c
 *
 * @desc Entity for storing applications statistics
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <stdio.h>

#include "data_usage.h"
#include "datausage-restriction.h"
#include "macro.h"
#include "net-cls-cgroup.h"
#include "rd-network.h"
#include "resourced.h"

API network_error_e network_set_option(const network_option_s *options)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_get_option(network_option_s *options)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_make_cgroup_with_pid(const int pid,
	const char *pkg_name)
{
	return NETWORK_ERROR_NONE;
}

API u_int32_t network_get_classid_by_pkg_name(const char *pkg_name, int create)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_set_restriction(const char *app_id,
			    const network_restriction_s *restriction)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_restriction_foreach(network_restriction_cb restriction_cb,
				void *user_data)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_remove_restriction(const char *app_id)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_remove_restriction_by_iftype(const char *app_id,
					     const network_iface_e iftype)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_exclude_restriction(const char *app_id)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_exclude_restriction_by_iftype(
	const char *app_id, const network_iface_e iftype)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_register_activity_cb(network_activity_cb activity_cb)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_join_app_performance(const char *app_id, const pid_t pid)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_update_statistics(void)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_foreach(const network_selection_rule_s *rule,
			     network_info_cb info_cb, void *user_data)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_details_foreach(const char *app_id,
					   network_selection_rule_s *rule,
					   network_info_cb info_cb,
					   void *user_data)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_reset(const network_reset_rule_s *rule)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_remove_quota(
	const network_quota_reset_rule_s *rule)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_remove_quota_by_iftype(
	const char *app_id, const network_iface_e iftype)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_set_quota(const char *app_id,
			      const network_quota_s *quota)
{
	return NETWORK_ERROR_NONE;
}

API network_error_e network_get_restriction_state(const char *pkg_id,
	network_iface_e iftype, network_restriction_state *state)
{
	*state = NETWORK_RESTRICTION_UNDEFINDED;
	return NETWORK_ERROR_NONE;
}
