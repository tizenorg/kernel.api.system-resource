#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "udp-common.h"

int main(void)
{
	struct sockaddr_in local_address, remote_address;
	int i;
	socklen_t slen = sizeof(struct sockaddr_in);
	char buf[BUF_SIZE];
	int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (s == -1) {
		perror("socket");
		exit(1);
	}

	prepare_address(AF_INET, PORT, &local_address);
	local_address.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(s, (struct sockaddr *)(&local_address),
		sizeof(struct sockaddr_in)) == -1) {
		perror("bind");
		exit(1);
	}

	for (i = 0; i < PACKET_NUMBER; i++) {
		if (recvfrom(s, buf, BUF_SIZE, 0,
			(struct sockaddr *)&remote_address, &slen) == -1) {
			perror("recvfrom()");
			exit(1);
		}
		printf("Received packet from %s:%d\nData: %s\n\n",
			inet_ntoa(remote_address.sin_addr), ntohs(remote_address.sin_port), buf);
	}

	close(s);
	return 0;
}
