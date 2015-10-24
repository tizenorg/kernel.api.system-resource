/*
   Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License
*/

#include <sys/mman.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "util.h"
#include "config-parser.h"

#define MEM_STRESS_CONF "/etc/mem-stress.conf"

static bool quite = false;
static size_t arg_size = 0;

static int parse_config_file(void)
{
	const ConfigTableItem items[] = {
		{ "MemStress",	"Size",	config_parse_bytes,	0,	&arg_size	},
		{ NULL,		NULL,	NULL,			0,	NULL		}
	};

	return config_parse_new(MEM_STRESS_CONF, (void*) items);
}

static void mem_stress_signal_handler(int signo)
{
	if (signo == SIGTERM)
		quite = true;
}

static int mem_stress_signal_init(void)
{
	if (signal(SIGTERM, &mem_stress_signal_handler) == SIG_ERR) {
		fprintf(stdout, "Failed to catch SIGTERM signal: %m");
		return -errno;
	}

	return 0;
}

static int mem_stress_allocate_memory(void **addr, size_t len)
{
	void *p = NULL;
	int r;

	do {
		fprintf(stdout, "Try to allocate memory %u", len);
		p = new0(void, len);
	} while(!p);

	r = mlock(p, len);
	if (r < 0) {
		free(p);
		return r;
	}

	*addr = p;

	return 0;
}

static int mem_stress_free_memory(void *addr, size_t len)
{
	int r;

	r = munlock(addr, len);
	if (r < 0)
		return r;

	free(addr);

	return 0;
}

static int mem_stress_run_loop(void)
{
	void *mem = NULL;
	int r;
	char buf[256];

	fprintf(stdout, "Memory stress size is: %u", arg_size);

	if (!arg_size)
		return 0;

	r = mem_stress_allocate_memory(&mem, arg_size);
	if (r < 0) {
		fprintf(stderr, "Failed to allocate memory: %s", strerror_r(-r, buf, sizeof(buf)));
		return r;
	}

	while(!quite)
		sleep(10);

	r = mem_stress_free_memory(mem, arg_size);
	if (r < 0) {
		fprintf(stderr, "Failed to free memory: %s", strerror_r(-r, buf, sizeof(buf)));
		return r;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int r;

	r = access(MEM_STRESS_CONF, F_OK);
	if (r < 0) {
		fprintf(stderr, "Failed to access '%s': %m", MEM_STRESS_CONF);
		return EXIT_FAILURE;
	}

	r = mem_stress_signal_init();
	if (r < 0)
		return EXIT_FAILURE;

	r = parse_config_file();
	if (r < 0)
		return EXIT_FAILURE;

	r = mem_stress_run_loop();
	if (r < 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
