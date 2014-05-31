/*
 * Library for getting power usage statistics
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd.
 *
 * Contact: Igor Zhbanov <i.zhbanov@samsung.com>
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

#define _BSD_SOURCE

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <locale.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <map>
#include <string>

#include <powertop-dapi.h>
#include <powertop-wrapper.h>


#define LINE_SIZE 4096

static FILE *log = stderr;
static volatile bool stopping = false, running = false;
static int check_interval = 3;
static pthread_t thr;
static void (*t_callback)(void *) = NULL;
static void *t_arg = NULL;

/* ************************************************************************ */

static void
logprintf(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));

static void
logprintf(const char *fmt, ...)
{
        va_list ap;
	char timebuf[128];
	time_t t;
	struct tm *tmp;

	if (!log)
		return;

	t = time(NULL);
	tmp = localtime(&t);

        va_start(ap, fmt);
	strftime(timebuf, sizeof(timebuf), "[%Y-%m-%d %H:%M:%S] ", tmp);
	fputs(timebuf, log);
	vfprintf(log, fmt, ap);
	fputc('\n', log);
	fflush(log);
	va_end(ap);
}

/* ************************************************************************ */

static int
loginit(const char *logname)
{
	if (!strcmp(logname, "STDERR")) {
		log = stderr;
		return 0;
	}

	log = fopen(logname, "a");
	if (!log) {
		perror("Can't open the log file");
		return -1;
	}

	return 0;
}

/* ************************************************************************ */

static void
logclose(void)
{
	if (log && log != stderr)
		fclose(log);
}

/* ************************************************************************ */

static bool
get_double(char **str, double *d)
{
	char *comma;

	if (!(comma = strchr(*str, ',')))
		return false;

	*comma = '\0';
	*d = atof(*str);
	*str = comma + 1;
	return true;
}

/* ************************************************************************ */

static bool
get_pid_t(char **str, pid_t *p)
{
	char *comma;

	if (!(comma = strchr(*str, ',')))
		return false;

	*comma = '\0';
	*p = (pid_t)atol(*str);
	*str = comma + 1;
	return true;
}

/* ************************************************************************ */

static bool
get_percent(char **str, double *d)
{
	char *comma;

	if (!(comma = strchr(*str, ',')))
		return false;

	*comma = '\0';
	if (!strchr(*str, '%')) {
		*comma = ',';
		return false;
	}

	*d = atof(*str);
	*str = comma + 1;
	return true;
}

/* ************************************************************************ */

static bool
get_packets(char **str, double *usage)
{
	char *comma;

	if (!(comma = strchr(*str, ',')))
		return false;

	*comma = '\0';
	if (sscanf(*str, "%lf pkts/s", usage) != 1) {
		*comma = ',';
		return false;
	}

	*str = comma + 1;
	return true;
}

/* ************************************************************************ */

static bool
get_usage(char **str, double *usage)
{
	char *comma, suffix[10];

	if (!(comma = strchr(*str, ',')))
		return false;

	*comma = '\0';
	if (sscanf(*str, "%lf %9s", usage, suffix) != 2) {
		*comma = ',';
		return false;
	}

	if (!strcmp(suffix, "ms/s"))
		*usage /= 1000.;
	else if (!strcmp(suffix, "us/s"))
		*usage /= 1000000.;
	else {
		*comma = ',';
		return false;
	}

	*str = comma + 1;
	return true;
}

/* ************************************************************************ */

static bool
get_disks(char **str, double *harddisk, double *disk)
{
	char *comma;

	if (!(comma = strchr(*str, ',')))
		return false;

	*comma = '\0';
	*harddisk = 0;
	*disk = 0;
	sscanf(*str, "%lf (%lf)", harddisk, disk);
	*str = comma + 1;
	return true;
}

/* ************************************************************************ */

static bool
get_string(char **str, char **s)
{
	char *comma;

	if (!(comma = strchr(*str, ',')))
		return false;

	*comma = '\0';
	*s = *str;
	while (**s == ' ')
		(*s)++;

	*str = comma + 1;
	return true;
}

/* ************************************************************************ */

static bool
get_qstring(char **str, char **s)
{
	char *comma;

	comma = strchr(*str, ',');
	if (comma) {
		*comma = '\0';
		if (comma[-1] == '"')
			comma[-1] = '\0';
	}

	*s = *str;
	while (**s == ' ')
		(*s)++;

	if (**s == '"')
		(*s)++;

	*str = comma + 1;
	return true;
}

/* ************************************************************************ */

/* Will modify the line */
static void
update_software_power_consumers(char *line, work_ctx *ctx)
{
	double usage, wakeups, gpu, harddisk, disk, gfx;
	char *category, *description, *newdescr, buf[LINE_SIZE], *str;

	strcpy(buf, line);
	str = buf;

	if (!get_usage(&str, &usage))
		return; /* Skip invalid or header line */

	if (!get_double(&str, &wakeups))
		return;

	if (!get_double(&str, &gpu))
		return;

	if (!get_disks(&str, &harddisk, &disk))
		return;

	if (!get_double(&str, &gfx))
		return;

	if (!get_string(&str, &category))
		return;

	if (!get_string(&str, &description))
		return;

	newdescr = strdup(description);
	sw_power_consumer &consumer = ctx->swpc[newdescr];
	consumer.usage	  += usage;
	consumer.wakeups  += wakeups;
	consumer.gpu	  += gpu;
	consumer.harddisk += harddisk;
	consumer.disk	  += disk;
	consumer.gfx	  += gfx;
	if (!consumer.category)
		consumer.category = strdup(category);

	if (!consumer.description)
		consumer.description = newdescr;
	else
		free(newdescr);
}

/* ************************************************************************ */

/* Will modify the line */
static void
update_device_power_report(const char *line, work_ctx *ctx)
{
	double usage;
	char *device, *newdevice, buf[LINE_SIZE], *str;
	bool network = false;

	strcpy(buf, line);
	str = buf;

	if (!get_percent(&str, &usage)) {
		if (!get_packets(&str, &usage))
			return; /* Skip invalid or header line */
		else
			network = true;
	}

	if (!get_qstring(&str, &device))
		return;

	newdevice = strdup(device);
	hw_power_consumer &consumer = ctx->hwpc[newdevice];
	consumer.network = network;
	consumer.usage += usage;
	if (!consumer.device)
		consumer.device = newdevice;
	else
		free(newdevice);
}

/* ************************************************************************ */

static void
update_mali_gpu_power_consumers(const char *line, work_ctx *ctx)
{
	double usage;
	pid_t pid;
	char *name, *description, buf[LINE_SIZE], *str;

	strcpy(buf, line);
	str = buf;

	if (!get_double(&str, &usage))
		return; /* Skip invalid or header line */

	if (!get_pid_t(&str, &pid))
		return;
	if (!pid)
		return; /* Skip header */

	if (!get_qstring(&str, &name))
		return;

	if (!get_qstring(&str, &description))
		return;

	mali_power_consumer &consumer = ctx->malipc[pid];
	consumer.pid = pid;
	consumer.usage += usage;

	if (!consumer.name)
		consumer.name = strdup(name);

	if (!consumer.description)
		consumer.description = strdup(description);
}

/* ************************************************************************ */

static void
process_report(const char *report, work_ctx *ctx)
{
	char line[LINE_SIZE];
	const char *rep = report, *eol;
	bool in_section = false;
	sections section = S_UNKNOWN;

	if (!report)
		return;

	rep = strchr(rep, '\n') + 1; /* Skip the first line. */
	while ((eol = strchr(rep, '\n')) != NULL) {
		ssize_t len;

		len = eol + 1 - rep;
		if (len > LINE_SIZE - 1)
			len = LINE_SIZE - 1;

		strncpy(line, rep, len);
		line[len] = '\0';
		rep += len;

		if (in_section) {
			if (line[0] == '*')
				in_section = false;
			else if (line[0] == '\n')
				continue;
			else if (section == S_SOFTWARE_POWER_CONSUMERS)
				update_software_power_consumers(line, ctx);
			else if (section == S_DEVICE_POWER_REPORT)
				update_device_power_report(line, ctx);
			else if (section == S_MALI_GPU_POWER_CONSUMERS)
				update_mali_gpu_power_consumers(line, ctx);
		}

		if (!in_section) {
			if (line[0] != '*')
				continue; /* Wrong line */
			else if (!strcmp(line, "**Overview of Software "
					  "Power Consumers**, \n"))
				section = S_SOFTWARE_POWER_CONSUMERS;
			else if (!strcmp(line, "**Device Power "
						 "Report**,\n"))
				section = S_DEVICE_POWER_REPORT;
			else if (!strcmp(line, "** Overview of MALI GPU "
						 "power consumers **\n"))
				section = S_MALI_GPU_POWER_CONSUMERS;
			else
				section = S_UNKNOWN;

			in_section = true;
		}

	}

	free((void *)report);
}

/* ************************************************************************ */

static int
collect_reports(const char *cmdline, work_ctx *ctx)
{
	char line[LINE_SIZE], *report = NULL;
	FILE *f;

	f = popen(cmdline, "r");
	if (!f) {
		logprintf("Can't open pipe to powertop: %s",
			  strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		size_t len;

		len = strlen(line);
		if (!strcmp(line, "***PowerTOP Report***, \n")) {
			/* Try to process incomplete report */
			process_report(report, ctx);
			report = (char *)malloc(len + 1);
			if (!report) {
				logprintf("No memory!");
				pclose(f);
				return -1;
			}

			strcpy(report, line);
		} else if (!strcmp(line, "***End of report***\n")) {
			process_report(report, ctx);
			report = NULL;
		} else if (report) {
			char *oldreport;

			oldreport = report;
			report = (char *)realloc(report,
						 strlen(report) + len + 1);
			if (!report) {
				logprintf("No memory!");
				free(oldreport);
				pclose(f);
				return -1;
			}

			strcat(report, line);
		} /* else skip unknown line */
	}

	pclose(f);
	process_report(report, ctx); /* Try to process incomplete report */
	return 0;
}

/* ************************************************************************ */

static void
clear_context(work_ctx *ctx)
{
	sw_power_consumer_map::iterator sit;
	hw_power_consumer_map::iterator hit;
	mali_power_consumer_map::iterator mit;

	for (sit = ctx->swpc.begin(); sit != ctx->swpc.end(); sit++) {
		sw_power_consumer &swpc = sit->second;
		if (swpc.description)
			free(swpc.description);

		if (swpc.category)
			free(swpc.category);
	}

	ctx->swpc.clear();

	for (hit = ctx->hwpc.begin(); hit != ctx->hwpc.end(); hit++) {
		hw_power_consumer &hwpc = hit->second;
		if (hwpc.device)
			free(hwpc.device);
	}

	ctx->hwpc.clear();

	for (mit = ctx->malipc.begin(); mit != ctx->malipc.end(); mit++) {
		mali_power_consumer &malipc = mit->second;
		if (malipc.name)
			free(malipc.name);

		if (malipc.description)
			free(malipc.description);
	}

	ctx->malipc.clear();
	ctx->iterations = 0;
}

/* ************************************************************************ */

static char fbuf[65536];

static void
report_write_header(FILE *out)
{
	FILE *in;
	size_t len;

	in = fopen(REPORTHEADER, "r");
	if (!in) {
		logprintf("Can't open header file '%s'.", REPORTHEADER);
		return;
	}

	while ((len = fread(fbuf, 1, sizeof(fbuf), in)) > 0)
		fwrite(fbuf, 1, len, out);

	fclose(in);
}

/* ************************************************************************ */

static void
report_write_footer(FILE *f)
{
	fprintf(f,
		"</body>\n"
		"</html>\n");
}

/* ************************************************************************ */

static void
report_write_swpc(work_ctx *ctx, FILE *f) /* Software Power Consumers */
{
	int n = ctx->iterations, i;
	sw_power_consumer_map::iterator it;

	fprintf(f,
		"<div id=\"software\"><h2>Overview of Software Power"
			" Consumers</h2>\n"
		"<table width=\"100%%\">"
		"<tr><th width=\"10%%\">Usage</th>"
			"<th width=\"10%%\">Wakeups/s</th>"
			"<th width=\"10%%\">GFX Wakeups/s</th>"
			"<th width=\"10%%\" class=\"process\">Category</th>"
			"<th class=\"process\">Description</th></tr>\n");
	for (i = 0, it = ctx->swpc.begin(); it != ctx->swpc.end(); it++, i++) {
		sw_power_consumer &swpc = it->second;

		fprintf(f,
			"<tr class=\"process_%s\">"
				"<td class=\"process_power\">%g</td>"
				"<td class=\"process_power\">%g</td>"
				"<td class=\"process_power\">%g</td>"
				"<td>%s</td><td>%s</td></tr>\n",
			(i & 1 ? "even" : "odd"),
			swpc.usage / n, swpc.wakeups / n, swpc.gfx / n,
			swpc.category, swpc.description);
	}

	fprintf(f,
		"</table>\n"
		"</div>\n");
}

/* ************************************************************************ */

static void
report_write_hwpc(work_ctx *ctx, FILE *f) /* Device Power Consumers */
{
	int n = ctx->iterations, i;
	hw_power_consumer_map::iterator it;

	fprintf(f,
		"<h2>Device Power Report</h2>\n"
		"<table width=\"100%%\">\n"
		"<tr><th width=\"10%%\">Usage</th>"
			"<th class=\"device\">Device name</th></tr>\n");
	for (i = 0, it = ctx->hwpc.begin(); it != ctx->hwpc.end();
	     it++, i++) {
		hw_power_consumer &hwpc = it->second;


		fprintf(f,
			"<tr class=\"device_%s\">"
				"<td class=\"device_util\">%g%s</td>"
				"<td>%s</td></tr>\n",
			(i & 1 ? "even" : "odd"), hwpc.usage / n,
			(hwpc.network ? " pkts/s" : "%"), hwpc.device);
	}

	fprintf(f, "</table>\n");
}

/* ************************************************************************ */

static void
report_write_malipc(work_ctx *ctx, FILE *f) /* MALI GPU Power Consumers */
{
	int n = ctx->iterations, i;
	mali_power_consumer_map::iterator it;

	fprintf(f,
		"<h2>Overview of MALI GPU power consumers</h2>\n"
		"<p><table width='100%%'>\n"
		"<tr><th width='10%%' class='process'>Power est. "
			"(PseudoWatts&middot;s)</th>"
			"<th class='process'>PID</th>"
			"<th class='process'>Name</th>"
			"<th class='process'>Description</th></tr>\n");
	for (i = 0, it = ctx->malipc.begin(); it != ctx->malipc.end();
	     it++, i++) {
		mali_power_consumer &malipc = it->second;

		fprintf(f,
			"<tr class='process_%s'>"
			"<td class='process_power'>%g PWs</td><td>%ld</td>"
			"<td>%s</td><td>%s</td></tr>\n",
			(i & 1 ? "even" : "odd"), malipc.usage / n,
			(long)malipc.pid, malipc.name, malipc.description);
	}

	fprintf(f, "</table>\n");
}

/* ************************************************************************ */

static void
write_report(work_ctx *ctx)
{
	FILE *f;

	f = fopen(ctx->report_file, "w+");
	if (!f) {
		logprintf("Can't open report file '%s'.",
			  ctx->report_file);
		return;
	}

	report_write_header(f);
	report_write_swpc(ctx, f);
	fprintf(f, "<div id=\"device\">\n");
	report_write_hwpc(ctx, f);
	report_write_malipc(ctx, f);
	fprintf(f,"</div>\n");
	report_write_footer(f);
	fclose(f);
}

/* ************************************************************************ */

static void *
thread_main(void *d)
{
	work_ctx ctx;
	char *oldlocale, cmdline[8192];

/*	logprintf("Thread started.");*/
	sprintf(cmdline,
		"LC_NUMERIC=en %s -D -i 1 --time=%d --csv 2>/dev/null",
		POWERTOP, check_interval);

	oldlocale = setlocale(LC_NUMERIC, NULL);
	oldlocale = strdup(oldlocale);
	setlocale(LC_NUMERIC, "C"); /* For dots in %f in printf() */

	ctx.report_file = (char *)d;
	unlink(ctx.report_file);
	ctx.iterations = 0;
	while (running) {
		if (collect_reports(cmdline, &ctx) == -1) {
/*			logprintf("Powertop error");*/
			running = false;
			break;
		}

		ctx.iterations++;
	}

	if (ctx.iterations) /* Generate total report */
		write_report(&ctx);

	clear_context(&ctx);

	setlocale(LC_NUMERIC, oldlocale);
	free(oldlocale);

	if (t_callback)
		t_callback(t_arg);

/*	logprintf("Thread finished.");*/
	return NULL;
}

/* ************************************************************************ */

void
powertop_set_check_interval(unsigned int interval)
{
	check_interval = interval;
}

/* ************************************************************************ */

bool
powertop_start_check(const char *output_path)
{
	pthread_attr_t thr_attr;

	if (loginit(LOGFILE) == -1)
		return false;

	if (running) {
		logprintf("The thread is already started.");
		logclose();
		return false;
	}

/*	logprintf("start_power_consumption_check()");*/

	t_callback = NULL;
	running = true;
	pthread_attr_init(&thr_attr);
	pthread_create(&thr, &thr_attr, &thread_main, (void *)output_path);
	pthread_attr_destroy(&thr_attr);
	return true;
}

/* ************************************************************************ */

void
powertop_stop_check(void)
{
/*	logprintf("stop_power_consumption_check()");*/
	if (!running)
		logprintf("The thread is not started of unexpectedly died.");

	running = false;
	pthread_join(thr, NULL);
	logclose();
}

/* ************************************************************************ */

void
powertop_async_stop_check(void (*callback)(void *), void *arg)
{
/*	logprintf("async_stop_power_consumption_check()");*/
	if (!running)
		logprintf("The thread is not started of unexpectedly died.");

	t_arg = arg;
	t_callback = callback;
	running = false;
	pthread_detach(thr);
	logclose();
}
