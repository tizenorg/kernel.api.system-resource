#include <inode2pid.h>

int main(int argc, char **argv)
{
	int index;
	for (index = 0; index < 15; ++index)
		update_inode_pid_map();
	return 0;
}
