#include "net-cls-cgroup.h"
#include "macro.h"

int main(int argc, char **argv)
{
	int_array *pids = get_monitored_pids();
	array_foreach(key, int, pids) {
		printf("%d\n", *key);
	}
	return 0;
}
