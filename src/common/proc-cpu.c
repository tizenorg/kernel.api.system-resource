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
 *  @file: proc-cpu.c
 *  @desc: Helper functions for getting cpu stat and usage
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include "proc-cpu.h"
#include "trace.h"
#include "util.h"

#define BUF_MAX	1024

resourced_ret_c proc_cpu_stat(struct cpu_stat *cs)
{
	FILE *fp;
	int retval;
	char buffer[BUF_MAX];

	fp = fopen("/proc/stat", "r");
	if (fp == NULL) {
		_E("fopen -/proc/stat- faied");
		return RESOURCED_ERROR_FAIL;
	}

	retval = fseek(fp, 0, SEEK_SET);
	if (retval < 0) {
		_E("fseek() failed");
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}

	if (!fgets(buffer, BUF_MAX, fp)) {
		_E ("fgets() failed");
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	retval = sscanf(buffer, "cpu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu",
	    &cs->cs[0], /* user */
	    &cs->cs[1], /* nice */
	    &cs->cs[2], /* system */
	    &cs->cs[3], /* idle */
	    &cs->cs[4], /* iowait */
	    &cs->cs[5], /* irq */
	    &cs->cs[6], /* softirq */
	    &cs->cs[7], /* steal */
	    &cs->cs[8], /* guest */
	    &cs->cs[9]); /* guest_nice */
	if (retval < 4) { /* Atleast 4 fields is to be read */
		_E("Error reading /proc/stat cpu field");
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	fclose(fp);
	return RESOURCED_ERROR_NONE;
}

double proc_cpu_usage(struct cpu_stat *cs1, struct cpu_stat *cs2)
{
	int i;
	unsigned long long int total_tick_old, total_tick, diff_total_tick, diff_idle;
	double cpu_usage, idlep;

	/* first reading */
	for (i = 0, total_tick_old = 0; i < PROC_STAT_MAX_FLDS; i++)
		total_tick_old += cs1->cs[i];

	/* second reading */
	for (i = 0, total_tick = 0; i < PROC_STAT_MAX_FLDS; i++)
		total_tick += cs2->cs[i];

	/* Calculate CPU idle and used percentage */
	diff_total_tick = NUM_DIFF(total_tick, total_tick_old);
	diff_idle = NUM_DIFF(cs2->cs[3], cs1->cs[3]);
	idlep = (diff_idle / (double)diff_total_tick) * 100;
	cpu_usage = 100 - idlep;
	return cpu_usage;
}
