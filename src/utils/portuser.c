
#include "inode2pid.h"
#include "macro.h"
#include "port2inode.h"
#include "trace.h"

static void forearch_get_pid(int inode)
{
	int pid;
	_D("Related inode is: %d", inode);
	pid = get_pid_from_inode(inode);
	_D("Got pid : %d", pid);
}

int main(int argc, char **argv)
{
	const int port = 1580;
	GArray *inodes;
	int index;
	for (index = 0; index != 15000; ++index)
		update_port_inode_map();

	inodes = get_inode_from_port(port, GRABBER_PROTO_TCP);
	update_inode_pid_map();
	for (index = 0; inodes && index != inodes->len; ++index)
		forearch_get_pid(g_array_index(inodes, int, index));
	return 0;
}
