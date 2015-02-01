/*
 *  genl.h
 *
 *  Samsung Traffic Counter Module
 *
 *  Copyright (C) 2012 Samsung Electronics
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *   @brief Trace macro definitions.
 *
 */

#ifndef _KERNEL_MODULE_TRAFFIC_STAT_GEN_NETLINK_H_
#define _KERNEL_MODULE_TRAFFIC_STAT_GEN_NETLINK_H_

/* attributes*/
enum {
	TRAF_STAT_A_UNSPEC,
	TRAF_STAT_A_MSG,
	TRAF_STAT_DATA_IN,
	TRAF_STAT_DATA_OUT,
	TRAF_STAT_COUNT,
	TRAF_STAT_DATA_RESTRICTION,
	__TRAF_STAT_A_MAX,
};

/*
 * commands: enumeration of all commands (functions),
 * used by userspace application to identify command to be executed
 */
enum {
	TRAF_STAT_C_UNSPEC,
	TRAF_STAT_C_START,
	TRAF_STAT_C_GET_PID_OUT,
	TRAF_STAT_C_GET_CONN_IN,
	TRAF_STAT_C_STOP,
	TRAF_STAT_C_SET_RESTRICTIONS,
	__TRAF_STAT_C_MAX,
};

enum {
	RESTRICTION_NOTI_A_UNSPEC,
	RESTRICTION_A_CLASSID,
	RESTRICTION_A_IFINDEX,
	__RESTRICTION_NOTI_A_MAX,
};

enum {
	RESTRICTION_NOTI_C_UNSPEC,
	RESTRICTION_NOTI_C_ACTIVE,
	RESTRICTION_NOTI_C_WARNING,
	__RESTRICTION_NOTI_C_MAX,
};

enum {
        NET_ACTIVITY_A_UNSPEC,
        NET_ACTIVITY_A_DATA_IN,
        NET_ACTIVITY_A_DATA_OUT,
        __NET_ACTIVITY_A_MAX,
};

enum {
        NET_ACTIVITY_C_UNSPEC,
        NET_ACTIVITY_C_START,
        NET_ACTIVITY_C_STOP,
        __NET_ACTIVITY_C_MAX,
};

#endif	/*_KERNEL_MODULE_TRAFFIC_STAT_GEN_NETLINK_H_ */
