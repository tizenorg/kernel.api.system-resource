#include <netinet/in.h>
#include <string.h>

#include "udp-common.h"

void prepare_address(int family, int port, struct sockaddr_in *addr)
{
	memset((char *) addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family = family;
	addr->sin_port = htons(port);
}
