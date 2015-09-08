/*
 * resourced
 *
 * Lib for getting process statistics
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd.
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


#include <stdio.h>
#include <unistd.h>
#include <proc_stat.h>



int main(void)
{
	GArray *valid_proc_infos = NULL;
	GArray *terminated_proc_infos = NULL;
	proc_stat_system_time st_diff;

	terminated_proc_infos = g_array_new(false, false, sizeof(proc_stat_process_info));
	valid_proc_infos = g_array_new(false, false, sizeof(proc_stat_process_info));


	proc_stat_init();

	while (true) {

		proc_stat_get_process_info(valid_proc_infos, terminated_proc_infos, NULL);
		proc_stat_get_system_time_diff(&st_diff);

		if (st_diff.total_time != 0) {

			double total_time = st_diff.total_time;

			printf("Total CPU Info : %3.2lf%%us %3.2lf%%sy %3.2lf%%ni %3.2lf%%id %3.2lf%%iowait %3.2lf%%irq %3.2lf%%softirq\n",
				(double)st_diff.user_time / total_time * 100,
				(double)st_diff.system_time / total_time * 100,
				(double)st_diff.nice_time / total_time * 100,
				(double)st_diff.idle_time / total_time * 100,
				(double)st_diff.iowait_time / total_time * 100,
				(double)st_diff.irq_time / total_time * 100,
				(double)st_diff.softirq_time / total_time * 100);

			unsigned int total, free;
			if (proc_stat_get_total_mem_size(&total) && proc_stat_get_free_mem_size(&free))
				printf("Total Memory Info : Total:%dMB Free:%dMB Used:%dMB\n", total, free, total - free);

			unsigned int i = 0;
			for (i = 0; i < valid_proc_infos->len; ++i) {
				proc_stat_process_info *ps = &g_array_index(valid_proc_infos, proc_stat_process_info, i);

				if ((ps->active) || (ps->fresh)) {
					if (ps->fresh)
						printf("N ");
					else
						printf("  ");

					printf("[pid:%d\t name:%40s utime:%3.2lf%% stime:%3.2lf%% rss:%dKb\n",
						ps->pid, ps->name,
						(double)(ps->utime_diff)/(double)st_diff.total_time*100,
						(double)(ps->stime_diff)/(double)st_diff.total_time*100,
						ps->rss);
				}
			}

			for (i = 0; i < terminated_proc_infos->len; ++i) {

				proc_stat_process_info *ps = &g_array_index(terminated_proc_infos, proc_stat_process_info, i);

				printf("T ");
				printf("[pid:%d\t name:%40s\n",
						ps->pid, ps->name);
			}

		}

		usleep(1000000);
		g_array_set_size(valid_proc_infos, 0);
		g_array_set_size(terminated_proc_infos, 0);

		printf("-------------------------------------------------------------------------------\n");

	}

	if (valid_proc_infos) {
		g_array_free(valid_proc_infos, true);
		valid_proc_infos = NULL;
	}


	if (terminated_proc_infos) {
		g_array_free(terminated_proc_infos, true);
		terminated_proc_infos = NULL;
	}

	proc_stat_finalize();

	return 0;
}
