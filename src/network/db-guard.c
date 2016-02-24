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
 * @file db-guard.c
 *
 * @desc This guard procedures are responsible for period db erasing
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include <data_usage.h>
#include <vconf/vconf.h>
#include <Ecore.h>

#include "config.h"
#include "counter.h"
#include "macro.h"
#include "trace.h"

#define VCONF_KEY_DB_ENTRIES_COUNT "db/private/resourced/network_db_entries"
#define ENTRY_SIZE 128

/* one hour */
#define ERASE_TIMER_INTERVAL 3600
/* 40 days */
#define ERASE_INTERVAL 3600 * 24 * 40
/* 50 Mb */
#define DB_SIZE_THRESHOLD 1048576 * 50

static int db_entries;

resourced_ret_c reset_data_usage_first_n_entries(int num);

void change_db_entries_num_num(int num)
{
	db_entries += num;
	if (vconf_set_int(VCONF_KEY_DB_ENTRIES_COUNT, db_entries))
		_E("Failed to set new db entries number");
}

static void check_erase_db_oversize(void)
{
	struct stat db_stat = {0};
	int del_entry = 0;

	ret_msg_if(stat(DATABASE_FULL_PATH, &db_stat),
		   "Failed to get statistics for %s errno %d",
		   DATABASE_FULL_PATH, errno);
	if (db_stat.st_size < DB_SIZE_THRESHOLD) {
		_D("Db truncation isn't required!");
		return;
	}
	/* get approximate number of entries for removing */
	del_entry = (db_stat.st_size - DB_SIZE_THRESHOLD) / ENTRY_SIZE;
	ret_msg_if(reset_data_usage_first_n_entries(del_entry),
			"Failed to remove first %d entries", del_entry);
	change_db_entries_num_num(-del_entry);
}

static void erase_old_entries(void)
{
	data_usage_reset_rule rule = {
		.iftype = RESOURCED_IFACE_LAST_ELEM,
	};
	resourced_tm_interval interval;
	time_t until = time(0);
	until -= ERASE_INTERVAL;

	interval.from = 0;
	interval.to = until;
	rule.interval = &interval;
	_D("Reset datausage statistics till %s", asctime(localtime(&until)));
	ret_msg_if(reset_data_usage(&rule),
		"Failed to reset statistics");
}

static Eina_Bool erase_func_cb(void *user_data)
{
	check_erase_db_oversize();
	erase_old_entries();
	return ECORE_CALLBACK_RENEW;
}

resourced_ret_c resourced_init_db_guard(struct counter_arg *carg)
{
	carg->erase_timer = ecore_timer_add(ERASE_TIMER_INTERVAL,
					   erase_func_cb, carg);
	ret_value_msg_if(carg->erase_timer == NULL, RESOURCED_ERROR_FAIL,
			 "Failed to create timer");
	ret_value_msg_if(vconf_get_int(VCONF_KEY_DB_ENTRIES_COUNT, &db_entries),
			 RESOURCED_ERROR_FAIL, "Failed to get vconf %s value!",
			 VCONF_KEY_DB_ENTRIES_COUNT);
	return RESOURCED_ERROR_NONE;
}

