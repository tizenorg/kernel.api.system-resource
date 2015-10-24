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
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "file-helper.h"

#define STR_TEST_FILE	"/tmp/test-file-helper-str"
#define INT_TEST_FILE	"/tmp/test-file-helper-int"
#define UINT_TEST_FILE	"/tmp/test-file-helper-uint"

#define TEST_STR "hello"
#define TEST_INT -2563
#define TEST_UINT 3253

static void test_fwrite_str(void)
{
	int r;
	char buf[256];

	r = fwrite_str(STR_TEST_FILE, "test");
	if (r < 0)
		fprintf(stderr, "Error: failed to test fwrite_str: %s\n", strerror_r(-r, buf, sizeof(buf)));
}

static void test_fwrite_fread_int(void)
{
	int i = 0;
	int r;
	char buf[256];

	r = fwrite_int(INT_TEST_FILE, TEST_INT);
	if (r < 0)
		fprintf(stderr, "Error: failed to test fwrite_int: %s\n", strerror_r(-r, buf, sizeof(buf)));

	r = fread_int(INT_TEST_FILE, &i);
	if (r < 0)
		fprintf(stderr, "Error: failed to test fread_int: %s\n", strerror_r(-r, buf, sizeof(buf)));

	if (i != TEST_INT)
		fprintf(stderr, "Error: read int(%d) mismatch with (%d)\n", i, TEST_INT);
}

static void test_fwrite_fread_uint(void)
{
	uint32_t u = 0;
	int r;
	char buf[256];

	r = fwrite_uint(UINT_TEST_FILE, TEST_UINT);
	if (r < 0)
		fprintf(stderr, "Error: failed to test fwrite_uint: %s\n", strerror_r(-r, buf, sizeof(buf)));

	r = fread_uint(UINT_TEST_FILE, &u);
	if (r < 0)
		fprintf(stderr, "Error: failed to test fwrite_uint: %s\n", strerror_r(-r, buf, sizeof(buf)));

	if (u != TEST_UINT)
		fprintf(stderr, "Error: read uint(%u) mismatch with (%u)\n", u, TEST_UINT);
}

int main(int argc, char *argv[])
{
	test_fwrite_str();
	test_fwrite_fread_int();
	test_fwrite_fread_uint();

	return 0;
}
