/*
 * resourced
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
 */

/*
 *  @file: time-helper.c
 *  @desc: Helper functions for getting current timestanp and time difference
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include "time-helper.h"
#include "trace.h"
#include "macro.h"
#include <mntent.h>

#define TIMESTAMP_LEN	16
#define MILLISEC	1000

void time_stamp(char *timestamp)
{
	char ts[TIMESTAMP_LEN];
	struct timeval curTime;
	int milli;
	struct tm local;

	gettimeofday(&curTime, NULL);
	milli = curTime.tv_usec / MILLISEC;
	if (!localtime_r(&curTime.tv_sec, &local))
		return;
	/* Current timestamp */
	strftime(ts,TIMESTAMP_LEN,"%y%m%d%H%M%S",&local);
	/* Append milliseconds */
	snprintf(timestamp, sizeof(ts) + 8, "%s%d", ts, milli);
}

void time_diff(struct timeval *diff,
	    struct timeval *start,
	    struct timeval *end)
{
	if (diff == NULL)
		return;

	diff->tv_sec = end->tv_sec - start->tv_sec ;
	diff->tv_usec = end->tv_usec - start->tv_usec;

	while (diff->tv_usec < 0) {
		diff->tv_usec += 1000000;
		diff->tv_sec -= 1;
	}
}
