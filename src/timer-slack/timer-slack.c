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
 * @file timer-slack.c
 * @desc control timer about timer-slack cgroup
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 */

#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "edbus-handler.h"
#include "resourced.h"
#include "trace.h"
#include "vconf.h"
#include "cgroup.h"
#include "config-parser.h"
#include "const.h"
#include "timer-slack.h"
#include "notifier.h"
#include "proc-main.h"
#include "proc-process.h"

#include <resourced.h>
#include <trace.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#define TIMER_EXCLUDE_CGROUP 	"exclude"
#define TIMER_SERVICE_CGROUP 	"service"
#define TIMER_BACKGRD_CGROUP 	"background"
#define TIMER_STATUS_LCDOFF 	"LCDOFF"
#define TIMER_SLACK_ROOT		NULL
#define TIMER_STATUS_POWERSAVING 	"POWERSAVING"

#define TIMER_CONF_FILE	  	"/etc/resourced/timer-slack.conf"
#define EXCLUDE_CONF_SECTION    	"EXCLUDE_TIMER_SLACK"
#define EXCLUDE_CONF_NAME    	"EXCLUDE_PROC_NAME"

#define TIMER_SLACK_MODE	"/timer_slack.timer_mode"
#define TIMER_SLACK_VALUE	"/timer_slack.min_slack_ns"

struct timer_slack_class {
	char *name;
	int timer_mode;
	int slack_value;
};

enum {
	TIMER_SLACK_DEFAULT,
	TIMER_SLACK_SERVICE,
	TIMER_SLACK_BACKGROUND,
	TIMER_SLACK_LCDOFF,
	TIMER_SLACK_POWERSAVIG,
	TIMER_SLACK_MAX,
};

static struct timer_slack_class timer_slack[TIMER_SLACK_MAX] = {
	{"DEFAULT", 0, 0},
	{TIMER_SERVICE_CGROUP, 0, 0},
	{TIMER_BACKGRD_CGROUP, 0, 0},
	{TIMER_STATUS_LCDOFF, 0, 0},
	{TIMER_STATUS_POWERSAVING, 0, 0},
};

static int current_root_timer_state = TIMER_SLACK_DEFAULT;

static const struct module_ops timer_modules_ops;
static const struct module_ops *timer_ops;

static int timer_slack_write(char *sub_cgroup, char *node, int val)
{
	char path_buf[MAX_PATH_LENGTH];
	int ret;
	if (sub_cgroup) {
		strncpy(path_buf, TIMER_CGROUP_PATH, sizeof(TIMER_CGROUP_PATH));
		strcat(path_buf, "/");
		strcat(path_buf, sub_cgroup);
		ret = cgroup_write_node(path_buf, node, val);
	} else
		ret = cgroup_write_node(TIMER_CGROUP_PATH, node, val);
	return ret;
}

static int launch_service(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	int ret;
	ret = timer_slack_write(TIMER_SERVICE_CGROUP, CGROUP_FILE_NAME, p_data->pid);
	_I("move to service timer slack cgroup : pid (%d), ret (%d)", p_data->pid, ret);
	return ret;
}

static int wakeup_timer_state(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	int ret;
	ret = timer_slack_write(TIMER_EXCLUDE_CGROUP, CGROUP_FILE_NAME, p_data->pid);
	return ret;
}

static int background_timer_state(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	int ret;
	ret = timer_slack_write(TIMER_BACKGRD_CGROUP, CGROUP_FILE_NAME, p_data->pid);
	return ret;
}

static int active_timer_state(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	int ret;
	ret = timer_slack_write(TIMER_EXCLUDE_CGROUP, CGROUP_FILE_NAME, p_data->pid);
	return ret;
}

static int inactive_timer_state(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	int ret;
	ret = timer_slack_write(TIMER_SLACK_ROOT, CGROUP_FILE_NAME, p_data->pid);
	return ret;
}

static int timer_lcd_off(void *data)
{
	if (current_root_timer_state == TIMER_SLACK_DEFAULT) {
		timer_slack_write(TIMER_SLACK_ROOT, TIMER_SLACK_MODE,
			    timer_slack[TIMER_SLACK_LCDOFF].timer_mode);
		timer_slack_write(TIMER_SLACK_ROOT, TIMER_SLACK_VALUE,
			    timer_slack[TIMER_SLACK_LCDOFF].slack_value);
	}
	current_root_timer_state = TIMER_SLACK_LCDOFF;
	return RESOURCED_ERROR_NONE;
}

static int timer_lcd_on(void *data)
{
	if (current_root_timer_state == TIMER_SLACK_LCDOFF) {
		timer_slack_write(TIMER_SLACK_ROOT, TIMER_SLACK_MODE,
			    timer_slack[TIMER_SLACK_DEFAULT].timer_mode);
		timer_slack_write(TIMER_SLACK_ROOT, TIMER_SLACK_VALUE,
			    timer_slack[TIMER_SLACK_DEFAULT].slack_value);
		current_root_timer_state = TIMER_SLACK_DEFAULT;
	}
	return RESOURCED_ERROR_NONE;
}

static void set_default_cgroup_value(void)
{
	int i;
	char *cgroup;
	for (i = 0; i < TIMER_SLACK_MAX; i++) {
		if (i == TIMER_SLACK_DEFAULT)
			cgroup = TIMER_SLACK_ROOT;
		else if (i == TIMER_SLACK_SERVICE)
			cgroup = TIMER_SERVICE_CGROUP;
		else if (i == TIMER_SLACK_BACKGROUND)
			cgroup = TIMER_BACKGRD_CGROUP;
		else
			continue;
		timer_slack_write(cgroup, TIMER_SLACK_MODE, timer_slack[i].timer_mode);
		timer_slack_write(cgroup, TIMER_SLACK_VALUE, timer_slack[i].slack_value);
	}
}

static int load_timer_config(struct parse_result *result, void *user_data)
{
	int i;
	pid_t pid = 0;

	if (!result)
		return -EINVAL;

	if (!strcmp(result->section, EXCLUDE_CONF_SECTION)) {
		if (strcmp(result->name, EXCLUDE_CONF_NAME))
			return RESOURCED_ERROR_NO_DATA;
		pid = find_pid_from_cmdline(result->value);
		if (pid > 0)
			timer_slack_write(TIMER_EXCLUDE_CGROUP, CGROUP_FILE_NAME, pid);
	} else {
		for (i = 0; i < TIMER_SLACK_MAX; i++) {
			if (strcmp(result->section, timer_slack[i].name))
				continue;
			if (!strcmp(result->name, "timer_mode"))
				timer_slack[i].timer_mode = atoi(result->value);
			if (!strcmp(result->name, "min_slack_ns"))
				timer_slack[i].slack_value = atoi(result->value);
		}
	}
       return RESOURCED_ERROR_NONE;
}

static void timer_slack_cgroup_init(void)
{
	make_cgroup_subdir(TIMER_CGROUP_PATH, TIMER_EXCLUDE_CGROUP, NULL);
	make_cgroup_subdir(TIMER_CGROUP_PATH, TIMER_SERVICE_CGROUP, NULL);
	make_cgroup_subdir(TIMER_CGROUP_PATH, TIMER_BACKGRD_CGROUP, NULL);

	config_parse(TIMER_CONF_FILE, load_timer_config, NULL);
	set_default_cgroup_value();
}

static int resourced_timer_slack_check_runtime_support(void *data)
{
	DIR *dir = 0;

	dir = opendir(TIMER_CGROUP_PATH);

	if (dir) {
		closedir(dir);
		return RESOURCED_ERROR_NONE;
	}
	return RESOURCED_ERROR_NO_DATA;
}

static int resourced_timer_slack_init(void *data)
{
	timer_ops = &timer_modules_ops;	

	timer_slack_cgroup_init();

	register_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, launch_service);
	register_notifier(RESOURCED_NOTIFIER_APP_RESUME, wakeup_timer_state);
	register_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, wakeup_timer_state);
	register_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, background_timer_state);
	register_notifier(RESOURCED_NOTIFIER_APP_ACTIVE, active_timer_state);
	register_notifier(RESOURCED_NOTIFIER_APP_INACTIVE, inactive_timer_state);
	register_notifier(RESOURCED_NOTIFIER_LCD_ON, timer_lcd_on);
	register_notifier(RESOURCED_NOTIFIER_LCD_OFF, timer_lcd_off);
	return RESOURCED_ERROR_NONE;
}

static int resourced_timer_slack_finalize(void *data)
{
	unregister_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, launch_service);
	unregister_notifier(RESOURCED_NOTIFIER_APP_RESUME, wakeup_timer_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, wakeup_timer_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, background_timer_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_ACTIVE, active_timer_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_INACTIVE, inactive_timer_state);
	unregister_notifier(RESOURCED_NOTIFIER_LCD_ON, timer_lcd_on);
	unregister_notifier(RESOURCED_NOTIFIER_LCD_OFF, timer_lcd_off);
	return RESOURCED_ERROR_NONE;
}

static const struct module_ops timer_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = TIMER_MODULE_NAME,
	.init = resourced_timer_slack_init,
	.exit = resourced_timer_slack_finalize,
	.check_runtime_support = resourced_timer_slack_check_runtime_support,
};
MODULE_REGISTER(&timer_modules_ops)
