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

/**
 * @file main.c
 * @desc Implement resource API. Initialization routines.
 *
 */

#include <dbus/dbus.h>
#include <sqlite3.h>
#include <unistd.h>

#include "const.h"
#include "cgroup.h"
#include "datausage-foreach.h"
#include "datausage-quota.h"
#include "datausage-reset.h"
#include "datausage-restriction.h"
#include "macro.h"
#include "trace.h"

static void __attribute__ ((constructor)) librsml_initialize(void);
static void __attribute__ ((destructor)) librsml_deinitialize(void);

static sqlite3 *database;


static void librsml_initialize(void)
{
	_D("librsml_initialize");

	if (dbus_threads_init_default() != TRUE)
		_E("Failed to initialize dbus threads support");
}

#define SQLITE_BUSY_TIMEOUT 500000

static int resourced_db_busy(void UNUSED *user, int attempts)
{
	_E("DB locked by another process, attempts number %d", attempts);

	usleep(SQLITE_BUSY_TIMEOUT); /* wait for a half second*/
	return 1;
}

API void libresourced_db_initialize_once(void)
{
	int res = 0;
	if (database != NULL)
		return;

	_D("libresourced_db_initialize_once");

	res = sqlite3_open(DATABASE_FULL_PATH, &database);
	if (res != SQLITE_OK) {
		_D("Can't open database %s: %s\n", DATABASE_FULL_PATH,
		   sqlite3_errmsg(database));
		sqlite3_close(database);
		return;
	}

	/* Set how many times we'll repeat our attempts for sqlite_step */
	if (sqlite3_busy_handler(database, resourced_db_busy, NULL) != SQLITE_OK) {
		_E("Couldn't set busy handler!");
	}
}

static void librsml_deinitialize(void)
{
	finalize_datausage_reset();
	finalize_datausage_foreach();
	finalize_datausage_restriction();
	sqlite3_close(database);
}

API sqlite3 *resourced_get_database(void)
{
	libresourced_db_initialize_once();
	return database;
}
