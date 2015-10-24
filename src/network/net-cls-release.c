#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "const.h"
#include "net-cls-cgroup.h" /* for const */

int main(int argc, char *argv[])
{
	char buf[MAX_PATH_LENGTH];
	if (argc < 2) {
		return 1;
	}

	/* kernel already adds symbol '/' before cgroup name */
	snprintf(buf, sizeof(buf), "%s/%s", PATH_TO_NET_CGROUP_DIR, argv[1]);
	return rmdir(buf);
}
