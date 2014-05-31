/*
 * Library for getting power usage statistics
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd.
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

#ifndef __POWERTOP_WRAPPER_H__
#define __POWERTOP_WRAPPER_H__

#include <string.h>

#include <map>

#define POWERTOP	"powertop"
#define LOGFILE		"./powertop-wrapper.log"
#define REPORTHEADER	"/usr/share/powertop-wrapper/header.html"

#ifndef UNUSED
#define UNUSED __attribute__((unused))
#endif /* UNUSED */

/* ************************************************************************ */

typedef enum {
	S_UNKNOWN,
	S_SYSTEM_INFORMATION,
	S_SOFTWARE_POWER_CONSUMERS,
	S_DEVICE_POWER_REPORT,
	S_PROCESS_DEVICE_ACTIVITY,
	S_POWER_CONSUMPTION_SUMMARY,
	S_SOFTWARE_SETTINGS_TUNING,
	S_UNTUNABLE_SOFTWARE_ISSUES,
	S_OPTIMAL_TUNED_SOFTWARE_SETTINGS,
	S_PROCESSOR_IDLE_STATE_REPORT,
	S_PROCESSOR_FREQUENCY_REPORT,
	S_MALI_GPU_POWER_CONSUMERS
} sections;

/* ************************************************************************ */

typedef struct {
	/* gpu, harddisk and disk are unneeded now */
	double usage, wakeups, gpu, harddisk, disk, gfx;
	char *category, *description;
} sw_power_consumer;

/* ************************************************************************ */

typedef struct {
	double usage;
	char *device;
	bool network;
} hw_power_consumer;

/* ************************************************************************ */

typedef struct {
	double usage;
	pid_t pid;
	char *name, *description;
} mali_power_consumer;

/* ************************************************************************ */

class power_consumer_cmp
{
public:
	bool
	operator()(const char *a, const char *b) const
	{
		return (strcmp(a, b) < 0);
	}
};

/* ************************************************************************ */

typedef std::map<const char *, sw_power_consumer, power_consumer_cmp>
							sw_power_consumer_map;
typedef std::map<const char *, hw_power_consumer, power_consumer_cmp>
							hw_power_consumer_map;
typedef std::map<pid_t, mali_power_consumer> mali_power_consumer_map;

/* ************************************************************************ */

typedef struct {
	sw_power_consumer_map swpc;
	hw_power_consumer_map hwpc;
	mali_power_consumer_map malipc;
	int iterations;
	const char *report_file;
} work_ctx;

#endif /* __POWERTOP_WRAPPER_H__ */
