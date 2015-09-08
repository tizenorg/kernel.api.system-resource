#ifndef _PERF_CONTROL_UTILS_UDP_COMMON_H
#define _PERF_CONTROL_UTILS_UDP_COMMON_H

#include <sys/socket.h>
#include <sys/types.h>

#define BUF_SIZE 512
#define PACKET_NUMBER 1000
#define PORT 2012
#define WAIT_INTERVAL 20
#define SRV_IP "192.168.129.3"

void prepare_address(int family, int port, struct sockaddr_in *addr);

#endif /*_PERF_CONTROL_UTILS_UDP_COMMON_H*/

