#include <config.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#include "net-cls-cgroup.h"

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000L
#endif

int64_t timespecDiff(struct timespec *time_a, struct timespec *time_b)
{
	return (((int64_t)time_a->tv_sec * NSEC_PER_SEC) + time_a->tv_nsec) -
		(((int64_t)time_b->tv_sec * NSEC_PER_SEC) + time_b->tv_nsec);
}

#define START_MEASURE {\
	struct timespec start, end; \
	clock_gettime(CLOCK_MONOTONIC, &start);

#define END_MEASURE \
	clock_gettime(CLOCK_MONOTONIC, &end); \
	int64_t timeElapsed = timespecDiff(&end, &start);\
	printf("time diff %"PRId64"\n", timeElapsed); \
	}

#define TEST_NUM 100

int main(void)
{
	int i = 0;
	char cgroup_name[128];

	printf("start measure");
	for (; i < TEST_NUM; ++i) {
		snprintf(cgroup_name, sizeof(cgroup_name), "com.samsung.browser%d", i);
		START_MEASURE
		make_net_cls_cgroup_with_pid(i, cgroup_name);
		END_MEASURE
	}

	return 0;
}
