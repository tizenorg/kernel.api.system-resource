/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __RD_NETWORK_H__
#define __RD_NETWORK_H__

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumeration for return type
 */
typedef enum {
	NETWORK_ERROR_NONMONITOR = -9,		/** < Process don't show watchdog popup */
	NETWORK_ERROR_NOTIMPL = -7,		 /**< Not implemented yet error */
	NETWORK_ERROR_UNINITIALIZED = -6,	 /**< Cgroup doen't mounted or daemon not started */
	NETWORK_ERROR_NO_DATA = -5,		 /**< Success, but no data */
	NETWORK_ERROR_INVALID_PARAMETER = -4,/**< Invalid parameter */
	NETWORK_ERROR_OUT_OF_MEMORY = -3,	 /**< Out of memory */
	NETWORK_ERROR_DB_FAILED = -2,	 /**< Database error */
	NETWORK_ERROR_FAIL = -1,		 /**< General error */
	NETWORK_ERROR_NONE = 0		 /**< General success */
} network_error_e;


/**
 * @brief Enumeration for return type of the callback
 */
typedef enum {
	NETWORK_CANCEL = 0,			/**< cancel */
	NETWORK_CONTINUE = 1,		/**< continue */
} network_cb_ret_e;

/**
 * @brief Enumeration for the monitored process state
 */
typedef enum {
	NETWORK_STATE_UNKNOWN = 0,
	NETWORK_STATE_FOREGROUND = 1 << 1,		/** < foreground state */
	NETWORK_STATE_BACKGROUND = 1 << 2,		/** < background state */
	NETWORK_STATE_LAST_ELEM = 1 << 3
} network_state_e;

/**
 * @brief Enumeration for network restriction state
 */
typedef enum {
	NETWORK_RESTRICTION_UNDEFINDED,
	NETWORK_RESTRICTION_ACTIVATED,  /** < restriction activated - means it
					        was sent to kernel */
	NETWORK_RESTRICTION_EXCLUDED,   /** < restriction has been excluded -
					        means it was sent to kernel as
						excluded */
	NETWORK_RESTRICTION_REMOVED,	 /** < restriction has been removed */

	NETWORK_RESTRICTION_MAX_VALUE
} network_restriction_state;

/**
 * @brief Enumeration for network interface types
 */
typedef enum {
	NETWORK_IFACE_UNKNOWN,	/**< undefined iface */
	NETWORK_IFACE_DATACALL,	/**< mobile data */
	NETWORK_IFACE_WIFI,		/**< wifi data */
	NETWORK_IFACE_WIRED,	/**< wired interface */
	NETWORK_IFACE_BLUETOOTH,	/**< bluetooth interface */
	NETWORK_IFACE_ALL,	/**< enumerate all network interface types */
	NETWORK_IFACE_LAST_ELEM
} network_iface_e;

/**
 * @brief Structure for time interval
 * @details It's time interval. Zero interval since 0 til 0 means entires interval.
 */
typedef struct {
	time_t from;
	time_t to;
} network_tm_interval_s;

/**
 * @brief Enumeration for network connection period type
 * @details Last received/sent mean counting data from the first connection of each interface
 */
typedef enum {
	NETWORK_CON_PERIOD_UNKNOWN,			/**< Undefined period */
	NETWORK_CON_PERIOD_LAST_RECEIVED_DATA,	/**< Last received data */
	NETWORK_CON_PERIOD_LAST_SENT_DATA,		/**< Last sent data */
	NETWORK_CON_PERIOD_TOTAL_RECEIVED_DATA,	/**< Total received data */
	NETWORK_CON_PERIOD_TOTAL_SENT_DATA,		/**< Total sent data */
	NETWORK_CON_PERIOD_LAST_ELEM
} network_connection_period_e;

/**
 * @brief Enumeration for network roaming type
 */
typedef enum {
	NETWORK_ROAMING_UNKNOWN,		/**< can't define roaming - roaming unknown */
	NETWORK_ROAMING_ENABLE,		/**< in roaming */
	NETWORK_ROAMING_DISABLE,		/**< not in roaming */
	NETWORK_ROAMING_LAST_ELEM,
} network_roaming_e;

/**
 * @brief Enumeration for hardware network protocol types
 */
typedef enum {
	NETWORK_PROTOCOL_NONE,			/**< Network unknown */
	NETWORK_PROTOCOL_DATACALL_NOSVC,		/**< Network no service */
	NETWORK_PROTOCOL_DATACALL_EMERGENCY,		/**< Network emergency */
	NETWORK_PROTOCOL_DATACALL_SEARCH,		/**< Network search 1900 */
	NETWORK_PROTOCOL_DATACALL_2G,			/**< Network 2G */
	NETWORK_PROTOCOL_DATACALL_2_5G,		/**< Network 2.5G */
	NETWORK_PROTOCOL_DATACALL_2_5G_EDGE,		/**< Network EDGE */
	NETWORK_PROTOCOL_DATACALL_3G,			/**< Network UMTS */
	NETWORK_PROTOCOL_DATACALL_HSDPA,		/**< Network HSDPA */
	NETWORK_PROTOCOL_DATACALL_LTE,		/**< Network LTE */
	NETWORK_PROTOCOL_MAX_ELEM
} network_hw_net_protocol_e;

/**
 * @brief Enumeration for the boolean option
 * @details Description of the boolean option for enabling/disabling
 *	network interfaces and enabling/disabling some behaviar
 */
typedef enum {
	NETWORK_OPTION_UNDEF,
	NETWORK_OPTION_ENABLE,
	NETWORK_OPTION_DISABLE
} network_option_e;

/**
 * @brief Structure for network option
 * @details Set of the options.
 * version - contains structure version
 * wifi - enable/disable wifi, NETWORK_OPTION_UNDEF to leave option as is
 * datacall - enable/disable datacall, NETWORK_OPTION_UNDEF to leave option as is
 * network_timer - set period of the updating data from the kernel,
 *	0 to leave option as is
 * datacall_logging - enable/disable datacall_logging,
 *	NETWORK_OPTION_UNDEF to leave option as is
 */
typedef struct {
	unsigned char version;
	network_option_e wifi;
	network_option_e datacall;
	time_t network_timer;
	network_option_e datacall_logging;
} network_option_s;

/**
 * @brief Set options, daemon will handle option setting.
 * @param[in] options The network state option
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_option_s
 * @see #network_get_option
 */
network_error_e network_set_option(const network_option_s *options);

/**
 * @brief Get performance control options.
 * @param[out] options The network state option
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_option_s
 * @see #network_set_option
 */
network_error_e network_get_option(network_option_s *options);

/**
 * @brief Make cgroup and put in it the given pid and generated classid
 * @details If cgroup already exists function just put pid in it.
 * @param[in] pid Process, that will be added to cgroup pkg name
 * @param[in] pkg_name Package name
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_get_classid_by_pkg_name
 */
network_error_e network_make_cgroup_with_pid(const int pid,
	const char *pkg_name);

/**
 * @brief Get classid from cgroup with name pkg_name
 * @param[in] pkg_name Name of the cgroup
 * @param[in] create In case of true - create cgroup if it's not exists
 * @return a positive value is classid, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_make_cgroup_with_pid
 */
u_int32_t network_get_classid_by_pkg_name(const char *pkg_name, int create);

/**
 * @brief Structure for network restriction information
 * @details
 * rs_type: foreground or background process
 * iftype - interface type to apply restriction
 * send_limit - amount number of engress bytes allowed for restriction
 * rcv_limit - amount number of ingress bytes allowed for restriction
 *		old behaviour for send_limit & rcv_limit was 0
 * snd_warning_limit - threshold for warning notification on engress bytes
 * rcv_warning_limit - threshold for warning notification on ingress bytes
 *		value - WARNING_THRESHOLD_UNDEF means no threshold
 *		this limit is different from quota warning threshold,
 *		threshold means remaining, limit means occupaied
 */
typedef struct {
	network_state_e rs_type;
	network_iface_e iftype;
	int send_limit;
	int rcv_limit;
	int snd_warning_limit;
	int rcv_warning_limit;
} network_restriction_s;

/**
 * @brief Enumeration for restriction counter
 */
typedef struct {
	long incoming_bytes;
	long outgoing_bytes;
} network_counter_s;

/**
 * @brief Enumeration for holding data usage information
 */
typedef struct {
	network_counter_s cnt;
	network_restriction_s rst;
} network_common_info;

/**
 * @brief Set restriction information
 * @details Set and apply restriction for application.
 * It will create new restriction or modify existing.
 * @param[in] app_id Application identifier, it's package name now
 * @param[in] restriction Restriction to apply for application in foreground mode
 * At least one of the restriction should be setted.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_restriction_s
 * @see #network_remove_restriction
 * @see #network_remove_restriction_by_iftype
 */
network_error_e network_set_restriction(const char *app_id,
			    const network_restriction_s *restriction);

/**
 * @brief Structure for information on restrictions.
 * @details
 * app_id - application identification - copy it if you in
 * callback function, don't store raw pointer on it
 * iftype - type of network interface
 */
typedef struct {
	const char *app_id;
	network_iface_e iftype;
	network_restriction_state rst_state;
	int rcv_limit;
	int send_limit;
} network_restriction_info_s;

/**
 * @brief callback for processing information of restrictions
 */
typedef network_cb_ret_e(*network_restriction_cb)(
	const network_restriction_info_s *info, void *user_data);

/**
 * @brief Restrictions enumerate function
 * @param[in] restriction_db The callback is called for each application that restrcited now
 * @param[in] user_data User data will be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_restriction_cb
 */
network_error_e network_restriction_foreach(network_restriction_cb restriction_cb,
				void *user_data);

/**
 * @brief Remove existing restriction for application
 * @details Remove existing restriction for application
 *   It will delete restriction rule in kernel
 * @param[in] app_id Application identifier, it's package name
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_set_restriction
 * @see #network_remove_restriction_by_iftype
 */
network_error_e network_remove_restriction(const char *app_id);

/**
 * @brief Remove existing restriction for application from interface type
 * @details Remove existing restriction for application
 *   It will delete restriction rule in kernel
 * @param[in] app_id Application identifier, it's package name
 * @param[in] iftype Interface type
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_iface_e
 * @see #network_set_restriction
 * @see #network_remove_restriction_by_iftype
 */
network_error_e network_remove_restriction_by_iftype(const char *app_id,
					     const network_iface_e iftype);

/**
 * @brief Exclude restriction for application
 * @details Exclude restriction for application
 *   It will exclude restriction rule in kernel
 * @param[in] app_id Application identifier, it's package name
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_OK Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_set_restriction
 * @see #network_exclude_restriction_by_iftype
 */
network_error_e network_exclude_restriction(const char *app_id);

/**
 * @brief Exclude restriction for application from interface type
 * @details Exclude restriction for application
 *   It will exclude restriction rule in kernel
 * @param[in] app_id Application identifier, it's package name
 * @param[in] iftype Interface type
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_OK Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_iface_e
 * @see #network_set_restriction
 * @see #network_exclude_restriction_by_iftype
 */
network_error_e network_exclude_restriction_by_iftype(
	const char *app_id, const network_iface_e iftype);

/**
 * @brief Structure for network activity information
 */
typedef struct {
	int type;		/*<< ingress/egress */
	char *appid;
	int iftype;
	int bytes;
} network_activity_info_s;

/**
 * @brief callback for network activity information of packet
 */
typedef network_cb_ret_e(*network_activity_cb)(network_activity_info_s *info);

/**
 * @brief Register activity callback
 * @details This function registering callback which invokes per every packet.
 * Function creates new reading thread and returns.
 * @param[in] activity_cb Invoked per every packet with NET_ACTIVITY channel
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_activity_cb
 */
network_error_e network_register_activity_cb(network_activity_cb activity_cb);

/**
 * @brief After invoking this function, application will be in the monitored scope
 * @details It creates an appropriate cgroup,
 * it generates classid for the network performance control.
 * It creates a unit file for the systemd.
 * @param[in] app_id Application identifier, it's package name now
 * @param[in] pid Pid to put in to cgroup, or self pid of 0
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 */
network_error_e network_join_app_performance(const char *app_id, const pid_t pid);

/**
 * @brief Update the resourced counters and stores it in the database.
 * @details Updates going asynchronyusly, it mean client can't be sure was
 * counters updated or not after this function finished.
 * To handle finish of the update process client need to
 * regist callback function
 * @see network_register_update_cb.
 * Next counters updating will procced according to resourced
 * update period, unless another network_update_statisitcs is
 * not invoked.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 */
network_error_e network_update_statistics(void);

/*
 * @brief Counters update information
 * @details This structure is needed to prevent client API from modification
 * in case of any information about update will be required.
 */
struct network_update_info {
	/*dummy content*/
};

/**
 * @brief Callback for update counters
 */
typedef network_cb_ret_e(*network_update_cb)(
	const struct network_update_info *info,
	void *user_data);

/**
 * @brief Register callback for update counters.
 * @details Callback function will be called if
 * network_update_statistics is requested.
 * To stop callbacks invocation return NETWORK_CANCEL from
 * callback function or call @see network_unregister_update_cb.
 *
 * @param[in] user_data pointer to any data given to callback function.
 *	Memory area should not be released until callback is unregistered.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @code

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rd-network.h>

network_cb_ret_e network_update(const struct network_update_info *info,
	void *user_data)
{
	char buf[50];
	char *str_data = user_data;
	printf("Callback updated. Stop yes/no?: ");
	scanf("%s", buf);
	if (strcmp(buf, "yes") == 0)
		return NETWORK_CANCEL;

	printf("user data is %s\n", user_data);

	return NETWORK_CONTINUE;
}

int main(void)
{
	network_error_e ret;

	ecore_init();

	char *user_data = (char *)malloc(1024);

	strcpy(user_data, "hello");

	ret = network_register_update_cb(network_update, (void *)user_data);

	network_update_statistics();

	ecore_main_loop_begin();

	free(user_data);
	ecore_shutdown();
}

 * @endcode
 */
network_error_e network_register_update_cb(network_update_cb update_cb,
	void *user_data);

/**
 * @brief Unregister update callback.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 */
void network_unregister_update_cb(void);

/**
 * @brief Structure for selection rule applied
 */
typedef struct {
	unsigned char version;
	time_t from;
	time_t to;
	network_iface_e iftype;
	int granularity;
} network_selection_rule_s;

/**
 * @brief Bundle structure for bringing all together application identification and properties
 * @details
 * app_id - application identification - copy it if you in
 *   callback function, don't store raw pointer on it
 * iface - interface name, NULL means all interfaces,
 *   don't store raw pointer on it in the callback function, copy it by value
 * interval - time interval for given result, NULL means entire interval
 * foreground - foreground restrictions and counters
 * background - background restrictions and counters
 */
typedef struct {
	const char *app_id;
	network_iface_e iftype;
	network_tm_interval_s *interval;
	network_common_info foreground;
	network_common_info background;
	network_roaming_e roaming;
	network_hw_net_protocol_e hw_net_protocol_type;
} network_info_s;

/**
 * @brief Callback for enumerate counters and restrictions
 */
typedef network_cb_ret_e(*network_info_cb) (const network_info_s *info,
					       void *user_data);

/**
 * @brief Data usage enumerate function
 * @details The callback is called for each application that used network
 * in between timestamps specified.
 * If interface name is not specified, each application will only appear
 * once with the total traffic used over all interfaces.
 * @param[in] rule Selection rule
 * @param[in] info_cb The callback is called for each application
 * that used network in between timestamps specified
 * @param[in] user_data User data will be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_selection_rule_s
 * @see #network_info_cb
 * @see #network_details_foreach
 */
network_error_e network_foreach(const network_selection_rule_s *rule,
			     network_info_cb info_cb, void *user_data);

/**
 * @brief Data usage details enumerate function
 * @detail
 * If interface name is specified in rule, the callback will be called
 * exactly 1 time with the total traffic counts for that interface
 * by specified application in the specified time interval.
 * If interface name is not specified, the callback will be called once
 * for each interface used by application during the specified interval.
 * It could be 0 if the application did not use any network interfaces
 * during that period.
 * @param[in] app_id Application id
 * @param[in] rule Selection rule
 * @param[in] info_cb The callback is called for each application
 * that used network in between timestamps specified
 * @param[in] user_data User data will be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_selection_rule_s
 * @see #network_info_cb
 * @s22 #network_foreach
 */
network_error_e network_details_foreach(const char *app_id,
					   network_selection_rule_s *rule,
					   network_info_cb info_cb,
					   void *user_data);

/**
 * @brief Structure for reset rule
 * @details It's statistics erasing description.
 * app_id - Erase statistics per appropriate app_id.
 * app_id can be NULL in this case erasing all datas
 * iftype - Erase statistics per appropriate network interface type
 * #network_iface_e, if iftype is NETWORK_IFACE_LAST_ELEM - erase all
 * NETWORK_IFACE_UNKNOW - means undetermined interface on moment of storing data.
 * interval - It's time interval, @see network_tm_interval_s.
 * It should be set. Zero interval since 0 till 0 means entire interval.
 * connection_state - It's mask on time interval.
 * Possible variation LAST and TOTAL for send and received data.
 */
typedef struct {
	unsigned char version;
	char *app_id;
	network_iface_e iftype;
	network_tm_interval_s *interval;
	network_connection_period_e connection_state;
} network_reset_rule_s;

/**
 * @brief Reset data usage information
 * @param[in] rule Reset rule. It's statistics erasing description
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_reset_rule_s
 */
network_error_e network_reset(const network_reset_rule_s *rule);

/**
 * @brief Reset filter for quota
 * @details
 * app_id is mandatory field
 * iftype interface type, NETWORK_IFACE_UNKNOWN
 * interface is not valid parameter, use NETWORK_IFACE_ALL instead
 * roaming_type roaming type
 * If user will not specify last 2 fields (UNKNOWN by default),
 *   neither quota with defined interface nor
 *   quota with defined roaming state will be removed.
 */
typedef struct {
	const char *app_id;
	network_iface_e iftype;
	network_roaming_e roaming;
} network_quota_reset_rule_s;

/**
 * @brief Remove datausage quota by quota rule
 * @param[in] rule reset filter for quota
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_quota_reset_rule_s
 * @see #network_set_quota
 * @see #network_remove_quota_by_iftype
 */
network_error_e network_remove_quota(
	const network_quota_reset_rule_s *rule);

/**
 * @brief Remove datausage quota by quota rule
 * @param[in] app_id Application id
 * @param[in] iftype Interface type
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_quota_reset_rule_s
 * @see #network_set_quota
 * @see #network_remove_quota
 */
network_error_e network_remove_quota_by_iftype(
	const char *app_id, const network_iface_e iftype);

/**
 * @brief Datausage quota
 * @details
 * time_period - time interval for quota, use predefined quota
 * #network_quota_s_period_t
 * snd_quota - quota for outcoming data
 * rcv_quota - quota for incoming data
 * warning_send_threshold - threshold for warning notification on engress bytes
 * warning_rcv_threshold - threshold for warning notification on ingress bytes
 * value - WARNING_THRESHOLD_UNDEF means no threshold
 *       - WARNING_THRESHOLD_DEFAULT means system-resource will be
 *         responsible for evaluation threshold value
 * The threshold value is amount of bytes remaining till blocking
 * quota_type - at present it can be foreground quota or background
 * iftype - network interface type
 * start_time - quota processing activation time, if NULL current time is used
 */
typedef struct {
	int time_period;
	int64_t snd_quota;
	int64_t rcv_quota;
	int snd_warning_threshold;
	int rcv_warning_threshold;
	network_state_e quota_type;
	network_iface_e iftype;
	time_t *start_time;
	network_roaming_e roaming_type;
} network_quota_s;

/**
 * @brief Set datausage quota
 * @details This function will set time interval based quota for data usage
 * Restriction will be applied in case of exceeding of the quota
 * during time interval
 * @param app_id[in] Application identifier, it's package name
 * @param quotas[in] Time interval based restriction for data usage
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #NETWORK_ERROR_NONE Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NETWORK_ERROR_NO_DATA Success, but no data
 * @retval #NETWORK_ERROR_UNINITIALIZED Cgroup doesn't mounted or daemon is not started
 * @retval #NETWORK_ERROR_NOTIMPL No implemented yet error
 * @retval #NETWORK_ERROR_NONMONITOR Process don't show watchdog popup
 *
 * @see #network_set_quota
 * @see #network_remove_quota
 * @see #network_remove_quota_by_iftype
 */
network_error_e network_set_quota(const char *app_id,
			      const network_quota_s *quota);


/**
 *
 * This function get restriction state.
 * State can be following:
 *	NETWORK_RESTRICTION_UNDEFINDED - means restriction wasn't set
 *	NETWORK_RESTRICTION_ACTIVATED  - means  restriction activated
 *	NETWORK_RESTRICTION_EXCLUDED   - restriction has been excluded
 *
 * @code
 * #include <rd-network.h>
 *
 * int is_whole_network_restricted()
 * {
 *	network_restriction_state state;
 *	network_error_r ret_code = network_get_restriction_state(
 *		RESOURCED_ALL_APP, NETWORK_IFACE_ALL, &state);
 *	if (ret_code != NETWORK_ERROR_NONE &&
 *		state == NETWORK_RESTRICTION_ACTIVATED)
 *		return 1;
 *	return 0;
 * }
 *
 * @endcode
 *
 * @retval #NETWORK_ERROR_OK Successful
 * @retval #NETWORK_ERROR_FAIL General error
 * @retval #NETWORK_ERROR_DB_FAILED Database error
 * @retval #NETWORK_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see #network_iface_e
 * @see #network_restriction_state
 * @see #network_set_restriction
 * @see #network_exclude_restriction_by_iftype
 *
 */
network_error_e network_get_restriction_state(const char *pkg_id,
	network_iface_e iftype, network_restriction_state *state);


#ifdef __cplusplus
}
#endif

#endif  // __RD_NETWORK_H__
