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
 * @file ktgrabber-parse.c
 *
 * @desc User space code for ktgrabber logic
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "generic-netlink.h"
#include "genl.h"
#include "trace.h"


/**
 * @desc accepts opaque pointer
 * extracts command id
 */
static inline int netlink_get_command(struct genl *nl_ans)
{
	return nl_ans->g.cmd;
}

static void fill_traf_stat_list(char *buffer, __u16 count,
			struct netlink_serialization_params *params)
{
	struct traffic_event *cur = (struct traffic_event *)buffer;

	while (count) {
		fill_app_stat_result(cur->ifindex, cur->sk_classid,
			cur->bytes, params->direction, params->carg);
		--count;
		++cur;
	}
}

static void _process_answer(struct netlink_serialization_params *params)
{
	struct genl *nl_ans = params->ans;
	ssize_t remains;
	char *buffer;
	struct nlattr *first_na, *second_na;
	int first_len;
	int count = 0;

	remains = GENLMSG_PAYLOAD(&nl_ans->n);
	if (remains <= 0)
		return;

	/* parse reply message */
	first_na = (struct nlattr *)GENLMSG_DATA(nl_ans);

	/* inline nla_next() */
	first_len = NLA_ALIGN(first_na->nla_len);

	second_na = (struct nlattr *) ((char *) first_na + first_len);
	remains -= first_len;

	/* but we need data_attr->nla_len */
	buffer = (char *) malloc((size_t)remains);
	if (buffer == NULL)
		return;

	if (first_na->nla_type == TRAF_STAT_COUNT) {
		count = *(__u16 *) NLA_DATA(first_na);
		memcpy(buffer, (char *) NLA_DATA(second_na),
		       second_na->nla_len);
	} else {
		_D("Expected attribute %d got %d", TRAF_STAT_COUNT, first_na->nla_type);
	}

	if (count > 0)
		fill_traf_stat_list(buffer, count, params);
	free(buffer);

}

netlink_serialization_command *netlink_create_command(
	struct netlink_serialization_params *params)
{
	static netlink_serialization_command command = {
		.deserialize_answer = _process_answer,
		0,};

	command.params = *params;
	command.params.direction = netlink_get_command(params->ans);

	return &command;
}


