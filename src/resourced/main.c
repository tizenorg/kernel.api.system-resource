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
 * @file main.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "init.h"
#include "macro.h"
#include "module-data.h"
#include "module.h"
#include "proc-main.h"
#include "proc-monitor.h"
#include "trace.h"
#include "version.h"

#include <Ecore.h>
#include <mcheck.h>
#include <systemd/sd-daemon.h>

int main(int argc, char **argv)
{
	int ret_code = 0;
	struct daemon_arg darg = { argc, argv, NULL };
	struct modules_arg marg;

#ifdef DEBUG_ENABLED
	mtrace();
	mcheck(0);
#endif
	ret_code = resourced_init(&darg);
	ret_value_msg_if(ret_code < 0, ret_code,
			 "Resourced initialization failed\n");
	init_modules_arg(&marg, &darg);
	modules_check_runtime_support(&marg);
	modules_init(&marg);
	ret_code = resourced_proc_init(darg.opts);
	if (ret_code < 0)
		_E("Proc init failed");
	sd_notify(0, "READY=1");

	ecore_main_loop_begin();
	modules_exit(&marg);
	resourced_deinit(&darg);
	return ret_code;
}
