/*
 * test
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "test.h"

static void test_main(int argc, char **argv)
{
	_I("test all");
	test_init((void *)NULL);
	test_exit((void *)NULL);
}

static void unit_test(int argc, char **argv)
{
	const struct test_ops *ops;

	ops = test_find(argv[1]);
	if (!ops) {
		_E("there is no test ops : %s", argv[1]);
		return;
	}
	ops->unit(argc, argv);
}

int main(int argc, char **argv)
{
	if (argc >= 2)
		unit_test(argc, argv);
	else
		test_main(argc, argv);
	return 0;
}

