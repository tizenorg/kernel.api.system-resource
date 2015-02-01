/*
 * @file transmission.h
 * @brief Kernel - user space transmition structures
 *
 */

#ifndef _TRAFFIC_CONTROL_TRAFFIC_STAT_TRANSMITION_H_
#define _TRAFFIC_CONTROL_TRAFFIC_STAT_TRANSMITION_H_
#ifdef _KERNEL_
#include <linux/socket.h>
#include <linux/types.h>
#else
#include <netinet/in.h>
#include <sys/types.h>
#endif

/* Used both in kernel module and in control daemon */

/*
 * @brief Entity for outgoing and incomming packet counter information.
 * Used for serialization.
 */
struct traffic_event {
	u_int32_t sk_classid;
	unsigned long bytes;
	int ifindex;
};

enum traffic_restriction_type {
	RST_UNDEFINDED,
	RST_SET,
	RST_UNSET,
	RST_EXCLUDE,
	RST_MAX_VALUE
};

/*
 * @brief Traffic restriction structure for serialization
 * type - traffic_restriction_type
 */
struct traffic_restriction {
	u_int32_t sk_classid;
	int type;
	int ifindex;
	int send_limit;
	int rcv_limit;
	int snd_warning_threshold;
	int rcv_warning_threshold;
};

#define RESOURCED_ALL_IFINDEX 1

#endif				/*TRAFFIC_CONTROL_TRAFFIC_STAT_TRANSMITION */
