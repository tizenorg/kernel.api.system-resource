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
 * @file reset.c
 *
 * @desc Network statistics reset implementation. This function's clearing
 * datausage database.
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <sqlite3.h>
#include <string.h>

#include "database.h"
#include "data_usage.h"
#include "datausage-reset.h"
#include "macro.h"
#include "trace.h"

#define RESET_ALL "delete from statistics where time_stamp between ? and ?"
#define RESET_APP "delete from statistics where binpath=? and " \
	"time_stamp between ? and ? "
#define RESET_IFACE "delete from statistics where iftype=? and " \
	"time_stamp between ? and ?"
#define RESET_APP_IFACE "delete from statistics where binpath=? and " \
	"iftype=? and time_stamp between ? and ?"

/* the following array is strictly ordered
 * to find required statement the following code will be used:
 * (app ? 1 : 0) | (iftype ? 2 : 0)
 */
static sqlite3_stmt *reset_stms[4];

#define PREPARE(stm, query) do {				\
	rc = sqlite3_prepare_v2(db, query, -1, &stm, NULL);	\
	if (rc != SQLITE_OK) {					\
		stm = NULL;					\
		finalize_datausage_reset();			\
		_E("Failed to prepare statement for\"%s\"query" \
			, query);				\
		return rc;					\
	}							\
} while (0)

static int init_datausage_reset(sqlite3 *db)
{
	int rc;
	static int initialized;

	if (initialized)
		return SQLITE_OK;

	PREPARE(reset_stms[0], RESET_ALL);
	PREPARE(reset_stms[1], RESET_APP);
	PREPARE(reset_stms[2], RESET_IFACE);
	PREPARE(reset_stms[3], RESET_APP_IFACE);

	initialized = 1;
	return rc;
}

#define FINALIZE(stm) do {		\
	if (stm) {			\
		sqlite3_finalize(stm);	\
		stm = NULL;		\
	}				\
} while (0)


void finalize_datausage_reset(void)
{
	int i;
	for (i = 0; i < sizeof(reset_stms) / sizeof(*reset_stms); i++)
		FINALIZE(reset_stms[i]);
}

API resourced_ret_c reset_data_usage(const data_usage_reset_rule *rule)
{
	sqlite3_stmt *stm;
	resourced_ret_c result = RESOURCED_ERROR_NONE;
	int pos = 1;/* running through positions where to
		bind parameters in the query */

	if (!rule || !rule->interval)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	libresourced_db_initialize_once();

	if (init_datausage_reset(resourced_get_database()) != SQLITE_OK) {
		_D("Failed to initialize data usage reset statements: %s\n",
		   sqlite3_errmsg(resourced_get_database()));
		return RESOURCED_ERROR_DB_FAILED;
	}
	/* pick a statement depending on parameters.
		See comment for reset_stms */
	stm = reset_stms[(rule->app_id ? 1 : 0) |
		(rule->iftype != RESOURCED_IFACE_LAST_ELEM ? 2 : 0)];

	if (rule->app_id && sqlite3_bind_text(stm, pos++, rule->app_id, -1,
			SQLITE_TRANSIENT) != SQLITE_OK) {
		result = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (rule->iftype != RESOURCED_IFACE_LAST_ELEM &&
		sqlite3_bind_int(stm, pos++, rule->iftype) != SQLITE_OK) {
		result = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int64(stm, pos++, rule->interval->from) != SQLITE_OK) {
		result = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}
	if (sqlite3_bind_int64(stm, pos++, rule->interval->to) != SQLITE_OK) {
		result = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_step(stm) != SQLITE_DONE) {
		_D("Failed to drop collected statistics.");
		result = RESOURCED_ERROR_DB_FAILED;
	}

out:
	sqlite3_reset(stm);
	return result;
}

