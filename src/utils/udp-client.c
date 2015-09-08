#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "udp-common.h"

int main(void)
{
	struct sockaddr_in remote_address;

	int i, slen = sizeof(struct sockaddr_in);
	char buf[BUF_SIZE];

	int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == -1) {
		perror("socket");
		exit(1);
	}

	prepare_address(AF_INET, PORT, &remote_address);

	if (inet_aton(SRV_IP, &remote_address.sin_addr) == 0) {
		fprintf(stderr, "inet_aton() failed\n");
		exit(1);
	}
	for (i = 0; i < PACKET_NUMBER; i++) {
		printf("Sending packet %d\n", i);
		snprintf(buf, sizeof(buf), "This is packet %d\n", i);
		if (sendto(s, buf, BUF_SIZE, 0, (struct sockaddr *)&remote_address, slen) == -1) {
			perror("sendto()");
			exit(1);
		}
		sleep(WAIT_INTERVAL);
	}

	close(s);
	return 0;
}
