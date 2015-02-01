/*
 * resourced
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 *
 */

/*
 *  @file: data_udage.h
 *
 *  @desc Data usage API
 *  @version 1.0
 *
 *  Created on: 28 June, 2012
 */

#ifndef _RESOURCED_DATA_USAGE_H_
#define _RESOURCED_DATA_USAGE_H_

#include <resourced.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Hardware network protocol types
 */
typedef enum {
	RESOURCED_PROTOCOL_NONE,			/**< Network unknown */
	RESOURCED_PROTOCOL_DATACALL_NOSVC,		/**< Network no service */
	RESOURCED_PROTOCOL_DATACALL_EMERGENCY,		/**< Network emergency */
	RESOURCED_PROTOCOL_DATACALL_SEARCH,		/**< Network search 1900 */
	RESOURCED_PROTOCOL_DATACALL_2G,			/**< Network 2G */
	RESOURCED_PROTOCOL_DATACALL_2_5G,		/**< Network 2.5G */
	RESOURCED_PROTOCOL_DATACALL_2_5G_EDGE,		/**< Network EDGE */
	RESOURCED_PROTOCOL_DATACALL_3G,			/**< Network UMTS */
	RESOURCED_PROTOCOL_DATACALL_HSDPA,		/**< Network HSDPA */
	RESOURCED_PROTOCOL_DATACALL_LTE,		/**< Network LTE */
	RESOURCED_PROTOCOL_MAX_ELEM
} resourced_hw_net_protocol_type;

/**
 * @brief State of the monitored process
 */
typedef enum {
	RESOURCED_STATE_UNKNOWN = 0,
	RESOURCED_STATE_FOREGROUND = 1 << 1,		/** < foreground state */
	RESOURCED_STATE_BACKGROUND = 1 << 2,		/** < background state */
	RESOURCED_STATE_LAST_ELEM = 1 << 3
} resourced_state_t;

/**
 * @brief Network restriction states
 */
typedef enum {
	RESOURCED_RESTRICTION_UNKNOWN,
	RESOURCED_RESTRICTION_ACTIVATED, /** < restriction has been activated */
	RESOURCED_RESTRICTION_REMOVED,	 /** < restriction has been removed */
	RESOURCED_RESTRICTION_EXCLUDED,	 /** < restriction has been excluded */
	RESOURCED_RESTRICTION_LAST_ELEM
} resourced_restriction_state;

/**
 * @brief Network interface types
 */
typedef enum {
	RESOURCED_IFACE_UNKNOWN,	/**< undefined iface */
	RESOURCED_IFACE_DATACALL,	/**< mobile data */
	RESOURCED_IFACE_WIFI,		/**< wifi data */
	RESOURCED_IFACE_WIRED,	/**< wired interface */
	RESOURCED_IFACE_BLUETOOTH,	/**< bluetooth interface */
	RESOURCED_IFACE_ALL,	/**< enumerate all network interface types */
	RESOURCED_IFACE_LAST_ELEM
} resourced_iface_type;

/**
 * @brief Network roaming type
 */
typedef enum {
	RESOURCED_ROAMING_UNKNOWN,		/**< can't define roaming - roaming unknown */
	RESOURCED_ROAMING_ENABLE,		/**< in roaming */
	RESOURCED_ROAMING_DISABLE,		/**< not in roaming */
	RESOURCED_ROAMING_LAST_ELEM,
} resourced_roaming_type;

/*
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
 * roaming - roaming support now only for exclusions for restriction it doesn't
 * make sense (roaming will be saved as UNKNOWN and restriction will be applied
 * in any case).
 *
 */
typedef struct {
	resourced_state_t rs_type;
	resourced_iface_type iftype;
	int send_limit;
	int rcv_limit;
	int snd_warning_limit;
	int rcv_warning_limit;
	resourced_roaming_type roaming;
} resourced_net_restrictions;

/**
 * @brief the same as for restriction
 */
typedef struct {
	long incoming_bytes;
	long outgoing_bytes;
} resourced_counters;


/**
 * @brief Commulative structure for holding data usage information
 */
typedef struct {
	resourced_counters cnt;
	resourced_net_restrictions rst;
} resourced_common_info;

typedef struct {
	time_t from;
	time_t to;
} resourced_tm_interval;

typedef enum {
	RESOURCED_CON_PERIOD_UNKNOWN,			/**< Undefined period */
	RESOURCED_CON_PERIOD_LAST_RECEIVED_DATA,	/**< Last received data */
	RESOURCED_CON_PERIOD_LAST_SENT_DATA,		/**< Last sent data */
	RESOURCED_CON_PERIOD_TOTAL_RECEIVED_DATA,	/**< Total received data */
	RESOURCED_CON_PERIOD_TOTAL_SENT_DATA,		/**< Total sent data */
	RESOURCED_CON_PERIOD_LAST_ELEM
} resourced_connection_period_type;

/**
 * @brief Period used in quota
 */
typedef enum {
	RESOURCED_PERIOD_UNDEF = 0,
	RESOURCED_PERIOD_HOUR = 3600,
	RESOURCED_PERIOD_DAY = 86400,
	RESOURCED_PERIOD_WEEK = 604800,
	RESOURCED_PERIOD_MONTH = 2419200
} data_usage_quota_period_t;

/**
 * @brief Restriction notification warning threshold value
 * definitions
 */
enum {
	WARNING_THRESHOLD_DEFAULT,		/**< for quota it means
		system-resource will evaluate proper value, for restriction it
		means no warning */
	WARNING_THRESHOLD_NONE,			/**< means no threshold at all */
};

/**
 * @brief Datausage quota
 * time_period - time interval for quota, use predefined quota
 *  @see data_usage_quota_period_t
 * snd_quota - quota for outcoming data
 * rcv_quota - quota for incoming data
 * warning_send_threshold - threshold for warning notification on engress bytes
 * warning_rcv_threshold - threshold for warning notification on ingress bytes
 *		value - WARNING_THRESHOLD_UNDEF means no threshold
 *		      - WARNING_THRESHOLD_DEFAULT means system-resource will be
 *              responsible for evaluation threshold value
 *		The threshold value is amount of bytes remaining till blocking
 *
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
	resourced_state_t quota_type;
	resourced_iface_type iftype;
	time_t *start_time;
	resourced_roaming_type roaming_type;
} data_usage_quota;

/**
 * @brief Reset filter for quota
 * app_id is mandatory field
 * iftype interface type, RESOURCED_IFACE_UNKNOWN
 *     interface is not valid parameter, use
 *     RESOURCED_IFACE_ALL instead
 * roaming_type roaming type
 * If user will not specify last 2 fields (UNKNOWN by default),
 *   neither quota with defined interface nor
 *   quota with defined roaming state will be removed.
 */
struct datausage_quota_reset_rule {
	const char *app_id;
	resourced_iface_type iftype;
	resourced_roaming_type roaming;
};

/**
 * @brief Selection rule applied for data usage enumeration
 */
typedef struct {
	unsigned char version;
	time_t from;
	time_t to;
	resourced_iface_type iftype;
	int granularity;
} data_usage_selection_rule;

/**
 * @brief Bundle structure for bringing all together application identification
 *     and properties.
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
	const char *ifname;
	resourced_iface_type iftype;
	resourced_tm_interval *interval;
	resourced_common_info foreground;
	resourced_common_info background;
	resourced_roaming_type roaming;
	resourced_hw_net_protocol_type hw_net_protocol_type;
} data_usage_info;

/**
 * @brief callback for enumerate counters and restrictions
 */
typedef resourced_cb_ret(*data_usage_info_cb) (const data_usage_info *info,
					       void *user_data);


/**
 * @desc Description of the boolean option for enabling/disabling
 *	network interfaces and enabling/disabling some behaviar
 */
typedef enum {
	RESOURCED_OPTION_UNDEF,
	RESOURCED_OPTION_ENABLE,
	RESOURCED_OPTION_DISABLE
} resourced_option_state;

/**
 * @desc Set of the options.
 * version - contains structure version
 * wifi - enable/disable wifi, RESOURCED_OPTION_UNDEF to leave option as is
 * datacall - enable/disable datacall, RESOURCED_OPTION_UNDEF to leave option as is
 * datausage_timer - set period of the updating data from the kernel,
 *	0 to leave option as is
 * datacall_logging - enable/disable datacall_logging,
 *	RESOURCED_OPTION_UNDEF to leave option as is
 */
typedef struct {
	unsigned char version;
	resourced_option_state wifi;
	resourced_option_state datacall;
	time_t datausage_timer;
	resourced_option_state datacall_logging;
} resourced_options;

/**
 * @brief Structure for information on restrictions.
 * app_id - application identification - copy it if you in
 *   callback function, don't store raw pointer on it
 * iftype - type of network interface
 */
typedef struct {
	const char *app_id;
	resourced_iface_type iftype;
	resourced_restriction_state rst_state;
	int rcv_limit;
	int send_limit;
	int quota_id;
	resourced_roaming_type roaming;
} resourced_restriction_info;

/**
 * @brief callback for processing information of restrictions
 */
typedef resourced_cb_ret(*resourced_restriction_cb)(
	const resourced_restriction_info *info, void *user_data);

/**
 * @desc Reset rule. It's statistics erasing description.
 * app_id - Erase statistics per appropriate app_id.
 *	app_id can be NULL in this case erasing all datas
 * iftype - Erase statistics per appropriate network interface type
 *	@see resourced_iface_type, if iftype is RESOURCED_IFACE_LAST_ELEM - erase all
 *	RESOURCED_IFACE_UNKNOW - means undetermined interface
 *	on moment of storing data.
 * interval - It's time interval, @see resourced_tm_interval. It should be set.
 *      Zero interval since 0 till 0 means entire interval.
 * connection_state - It's mask on time interval.
 *	Possible variation LAST and TOTAL for send and received data.
 */
typedef struct {
	unsigned char version;
	char *app_id;
	resourced_iface_type iftype;
	resourced_tm_interval *interval;
	resourced_connection_period_type connection_state;
} data_usage_reset_rule;

resourced_ret_c reset_data_usage(const data_usage_reset_rule *rule);

struct net_activity_info {
	int type;		/*<< ingress/egress */
	char *appid;
	int iftype;
	int bytes;
};

typedef resourced_cb_ret(*net_activity_cb)(struct net_activity_info *info);



/**
 * @desc Set and apply restriction for application.
 *      It will create new restriction or modify existing.
 * @param app_id[in] - application identifier, it's package name now
 * @param restriction[in] - restriction to apply for application
 *	in foreground mode
 * At least one of the restriction should be setted.
 * @return 0 on success, otherwise error code
 */
resourced_ret_c set_net_restriction(const char *app_id,
			    const resourced_net_restrictions *restriction);

/**
 * @desc Remove existing restriction for application
 *   It will delete restriction rule in kernel
 * @param app_id[in] - application identifier, it's package name
 */
resourced_ret_c remove_restriction(const char *app_id);

resourced_ret_c remove_restriction_by_iftype(const char *app_id,
					     const resourced_iface_type iftype);

/**
 * @desc Exclude restriction for application
 *   It will exclude restriction rule in kernel
 * @param app_id[in] - application identifier, it's package name
 * This function is deprecated, use set_net_exclusion
 */
resourced_ret_c exclude_restriction(const char *app_id);

/**
 * This function is deprecated, use set_net_exclusion
 */
resourced_ret_c exclude_restriction_by_iftype(
	const char *app_id, const resourced_iface_type iftype);


/**
 * @brief Exclude application from network restriction.
 * Excluded application will be granted to
 * internet access, in case of whole network restriction.
 * iftype and roaming in resourced_net_restriction is supported right now
 */
resourced_ret_c set_net_exclusion(const char *app_id,
			const resourced_net_restrictions *rst);

/**
 * @desc Remove datausage quota by quota rule
 */
resourced_ret_c remove_datausage_quota(
	const struct datausage_quota_reset_rule *rule);

/**
 * @deprecated
 */
resourced_ret_c remove_datausage_quota_by_iftype(
	const char *app_id, const resourced_iface_type iftype);

/**
 * @desc Set options, daemon will handle option setting.
 */
resourced_ret_c set_resourced_options(const resourced_options *options);

/**
 * @desc Obtain performance control options.
 */
resourced_ret_c get_resourced_options(resourced_options *options);

/**
 * @desc This function will set time interval based quota for data usage
 *    Restriction will be applied in case of exceeding of the quota
 *    during time interval
 * @param app_id[in] - application identifier, it's package name
 * @param quotas[in] - time interval based restriction for data usage
 */
resourced_ret_c set_datausage_quota(const char *app_id,
			      const data_usage_quota *quota);

/**
 * The callback is called for each application that used network
 * in between timestamps specified.
 *
 * If interface name is not specified, each application will only appear
 * once with the total traffic used over all interfaces.
 *
 * @brief Data usage enumerate function
 */
resourced_ret_c data_usage_foreach(const data_usage_selection_rule *rule,
			     data_usage_info_cb info_cb, void *user_data);

/**
 * The callback is called for each application that restricted now
 *
 * @brief Restrictions enumerate function
 */
resourced_ret_c restrictions_foreach(resourced_restriction_cb restriction_cb,
				void *user_data);

/**
 * If interface name is specified in rule, the callback will be called
 * exactly 1 time with the total traffic counts for that interface
 * by specified application in the specified time interval.
 *
 * If interface name is not specified, the callback will be called once
 * for each interface used by application during the specified interval.
 * It could be 0 if the application did not use any network interfaces
 * during that period.
 *
 * @brief Data usage details enumerate function
 */
resourced_ret_c data_usage_details_foreach(const char *app_id,
					   data_usage_selection_rule *rule,
					   data_usage_info_cb info_cb,
					   void *user_data);

/**
 * @desc This function registering callback which invokes per every packet.
 *	Function creates new reading thread and returns.
 */
resourced_ret_c register_net_activity_cb(net_activity_cb activity_cb);

/**
 * @desc This function updates the resourced counters and stores in the database
 */
resourced_ret_c resourced_update_statistics(void);

resourced_ret_c get_restriction_state(const char *pkg_id,
	resourced_iface_type iftype, resourced_restriction_state *state);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _RESOURCED_DATA_USAGE_H_ */
