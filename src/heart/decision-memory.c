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
 * @file decision-memory.c
 *
 * @desc start memory decision system for resourced
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <glib.h>

#include "resourced.h"
#include "const.h"
#include "trace.h"
#include "module.h"
#include "macro.h"
#include "notifier.h"
#include "heart.h"
#include "logging.h"
#include "heart-common.h"
#include "decision.h"
#include "decision-memory.h"

#define	DECISION_MEMORY_THRES_HIT	20
#define DECISION_MEMORY_THRES_LEAK	200

enum decision_memory_args {
	DECISION_MEMORY_PSS,
	DECISION_MEMORY_USS,
};

static int decision_is_leak_warning(struct regression_info *ri)
{
	if (ri->hit > DECISION_MEMORY_THRES_HIT &&
	    ri->coeff_a > DECISION_MEMORY_THRES_LEAK)
		return RESOURCED_ERROR_NONE;

	return RESOURCED_ERROR_FAIL;
}

static void decision_regression_info_update(struct decision_memory_info *dmi, unsigned int uss)
{
	struct regression_info *ri;
	unsigned N, x, y, error;
	long d, an, bn;

	if (!dmi || !dmi->ri) {
		_E("decision memory info or regression info is null");
		return;
	}

	ri = dmi->ri;

	if (!ri) {
		_D("regression info is null");
		return;
	}

	if (dmi->pred_uss) {
		int hit = 0;
		error = (float)dmi->pred_uss * 0.1;
		if (dmi->pred_uss - error <= uss &&
		    dmi->pred_uss + error >= uss) {
			ri->hit++;
			hit = 1;
		}
		_D("uss = %u, pred_uss = %u, hit = %u, error = %u, hit = %d\n",
			uss, dmi->pred_uss, ri->hit, error, hit);
		if (hit) {
			if (decision_is_leak_warning(ri) >= 0) {
				dmi->warning_leak = 1;
				_D("hit = %d, coeff_a = %.2f, douted leak",
					ri->hit, ri->coeff_a);
			}
		} else {
			ri->hit = 0;
			dmi->warning_leak = 0;
		}
	}

	/* On first sample, sample_count and x value starts from 1 */
	x = ++ri->sample_count;
	y = uss;
	N = x;
	ri->sum_x += x;
	ri->sum_y += y;
	ri->sum_xs += x * x;
	ri->sum_xy += x * y;
	d = ((long)N * ri->sum_xs) - ((long)ri->sum_x * ri->sum_x);

	if (!d) {
		_D("denominator for coefficient a and b is zero");
		return;
	}

	an = ((long)N * ri->sum_xy) - ((long)ri->sum_x * ri->sum_y);
	bn = ((long)ri->sum_y * ri->sum_xs) - ((long)ri->sum_x * ri->sum_xy);
	ri->coeff_a = (float)an / d;
	ri->coeff_b = (float)bn / d;

	/*
	 * pred_uss is the prediction of next expected uss.
	 * and it can be calculated using next x value, (x + 1).
	 * When regression eq. is y = a * x + b,
	 * predicted y can be calculated using a * (x + 1) + b.
	 */
	dmi->pred_uss = (ri->coeff_a * (x + 1)) + ri->coeff_b;
	_D("x = %u, y = %u, a = %.2f, b = %.2f, pred_uss = %u, an = %ld, bn = %ld, d = %ld",
		x, y, ri->coeff_a, ri->coeff_b, dmi->pred_uss, an, bn, d);

}

static struct regression_info *new_regression_info(void)
{
	struct regression_info *ri;

	ri = malloc(sizeof(struct regression_info));
	if (!ri) {
		_D("fail to allocate regression_info");
		return NULL;
	}

	memset(ri, 0, sizeof(struct regression_info));

	return ri;
}

static void *decision_memory_info_create(void)
{
	struct decision_memory_info *dmi;

	dmi = malloc(sizeof(struct decision_memory_info));
	if (!dmi) {
		_D("fail to allocate decision_memory_info");
		return NULL;
	}

	dmi->pred_uss = 0;
	dmi->warning_leak = 0;

	dmi->ri = new_regression_info();
	if (!dmi->ri) {
		_E("fail to allocate regression info");
		free(dmi);
		return NULL;
	}

	return (void *)dmi;
}

static void decision_memory_info_free(void *data)
{
	struct decision_memory_info *dmi;

	if (!data)
		return;
	dmi = (struct decision_memory_info *)data;
	if (dmi->ri)
		free(dmi->ri);
	free(dmi);
}

static void decision_memory_info_update(struct decision_item *di, void *info)
{
	struct decision_memory_info *dmi = (struct decision_memory_info *)info;

	_D("decision update regression info for %s", di->ai->appid);
	decision_regression_info_update(dmi, di->args[DECISION_MEMORY_USS]);
}

static void decision_memory_info_write(void *data, char *buf, int len)
{
	struct decision_memory_info *dmi;

	if (!data) {
		snprintf(buf, len, "invalid");
		return;
	}
	dmi = (struct decision_memory_info *)data;
	snprintf(buf, len, "%s", dmi->warning_leak ? "Y" : "N");
}

static void decision_memory_updated_cb(char *data)
{
	char appid[MAX_APPID_LENGTH];
	char pkgname[MAX_PKGNAME_LENGTH];
	struct decision_item *di;
	unsigned pss, uss;
	int time, len;

	if (!data)
		return;

	len = sscanf(data, "%s %s %d %u %u", appid, pkgname, &time, &pss, &uss);
	if (len < 0) {
		_E("sscanf failed");
		return;
	}
	_D("%s: %s %s %d %u %u", data, appid, pkgname, time, pss, uss);

	di = decision_item_new(DECISION_MEMORY, appid, pkgname);

	if (!di)
		return;

	di->args[DECISION_MEMORY_PSS] = pss;
	di->args[DECISION_MEMORY_USS] = uss;

	decision_queue_item_insert(di);
	decision_update_start();
}

static const struct decision_module decision_memory = {
	.type	= DECISION_MEMORY,
	.create	= decision_memory_info_create,
	.free	= decision_memory_info_free,
	.update	= decision_memory_info_update,
	.write	= decision_memory_info_write,
};

int decision_memory_init(void *data)
{
	_D("decision memory init finished");

	logging_register_listener("memory", decision_memory_updated_cb);
	decision_module_register(&decision_memory);

	return RESOURCED_ERROR_NONE;
}

int decision_memory_exit(void *data)
{
	_D("decision memory finalize");

	decision_module_unregister(&decision_memory);
	logging_unregister_listener(DECISION_MEMORY,
		decision_memory_updated_cb);

	return RESOURCED_ERROR_NONE;
}
