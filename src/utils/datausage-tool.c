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

/**
 * @file datausage-tool.c
 * @desc Implement Performance API. Command line utility.
 *
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "data_usage.h"
#include "resourced.h"
#include "rd-network.h"
#include "const.h"
#include "iface.h"
#include "config.h"
#include "trace.h"
#include "version.h"

enum run_rsml_cmd {
	UNDEFINED,
	RESOURCED_APPLY,
	RESOURCED_GET,
	RESOURCED_DATA_USAGE,
	RESOURCED_DATA_USAGE_DETAILS,
	RESOURCED_EXCLUDE,
	RESOURCED_REVERT,
	RESOURCED_GET_RESTRICTIONS,
	RESOURCED_SET_OPTIONS,
	RESOURCED_GET_OPTIONS,
	RESOURCED_SET_QUOTA,
	RESOURCED_REMOVE_QUOTA,
	RESOURCED_RESTRICTION_STATE,
};

struct arg_param {
	data_usage_selection_rule du_rule;
	int64_t rcv_limit;
	int64_t send_limit;
	resourced_roaming_type roaming_type;
	char *app_id;
};

static resourced_ret_c convert_roaming(const char *str,
	resourced_roaming_type *roaming)
{
	if (!str)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	if (!strcmp(optarg, "enabled")) {
		*roaming = RESOURCED_ROAMING_ENABLE;
		return RESOURCED_ERROR_NONE;
	}

	if (!strcmp(optarg, "disabled")) {
		*roaming = RESOURCED_ROAMING_DISABLE;
		return RESOURCED_ERROR_NONE;
	}

	if (!strcmp(optarg, "unknown")) {
		*roaming = RESOURCED_ROAMING_UNKNOWN;
		return RESOURCED_ERROR_NONE;
	}
	return RESOURCED_ERROR_INVALID_PARAMETER;
}

static void print_version()
{
	printf("Version number: %d.%d-%d\n", MAJOR_VERSION, MINOR_VERSION,
		PATCH_VERSION);
}

static void print_usage()
{
	puts("run_rsml [Options]");
	puts("       Application options:");
	puts(" possible ordering values: ");
	puts("\t\tappid - order by application id (package name) "
	     "in ascending");
	puts("\t\tappiddesc - order by application id (package name) "
	     "in descending");
	puts("\t\tiface - ascending ordering by network interface name");
	puts("\t\tifacedesc - descending ordering by network interface name");
	puts("-a [--apply-rst] <package name> - apply restriction");
	puts("-e [--exclude-rst] <package name> - exclude restriction");
	puts("-R [--restrictions] <incoming>,<outgoing> "
	     "- restrictions to apply");
	puts("-r [--revert-rst] <package name> - revert restriction");
	puts("-l [--list-app-rst] - list of restricted applications");
	puts("-g [--get] - get counters and restriction for application");
	puts("-v [--version] - program version");
	puts("-h [--help] - application help");
	puts("-u [--data-usage] - data usage");
	puts("-f [--from] <timestamp> - starting timestamp "
	     "for data usage requests");
	puts("-t [--to] <timestamp> - ending timestamp "
	     "for data usage requests");
	puts("-i [--interface] <iface> - interface name");
	puts("-d [--data-usage-details] [<appid>] - data usage details "
	     "total/for application");
	puts("-G [--granularity] <seconds> - split data usage results "
	     "into chunks of <seconds>");
	puts("-O [--options] <set|get> set or get options");
	puts(" In case of set options:");
	puts(" -W [--wifi] <1|0> enable or disable wifi");
	puts(" -D [--datacall] <1|0> enable or disable datacall");
	puts(" -T [--datausagetimer] <1|0> enable or disable datausage timer");
	puts(" -L [--datacalllogging] <1|0> enable or disable datacall logging");
	puts(" -M [--roaming] <enalbled|disabled|unknown> enable or disable "
		" roaming, unknown by default");
	puts(" -q [--quota] <appid> ");
	puts(" -Q [--remove-quota] <appid> ");
	puts(" -s [--rst-state] <pkgid> ");
}

static enum run_rsml_cmd parse_cmd(int argc, char **argv,
				  struct arg_param *param)
{
	const char *optstring = "hvla:e:g:uf:t:i:d::G:R:r:O:q:Q:M:s:";

	const struct option options[] = {
		{"help", no_argument, 0, 'h'},
		{"list-app-rst", no_argument, 0, 'l'},
		{"version", no_argument, 0, 'v'},
		{"apply-rst", required_argument, 0, 'a'},
		{"exclude-rst", required_argument, 0, 'e'},
		{"revert-rst", required_argument, 0, 'r'},
		{"get", required_argument, 0, 'g'},
		{"data-usage", no_argument, 0, 'u'},
		{"from", required_argument, 0, 'f'},
		{"to", required_argument, 0, 't'},
		{"interface", required_argument, 0, 'i'},
		{"data-usage-details", optional_argument, 0, 'd'},
		{"granularity", required_argument, 0, 'G'},
		{"restrictions", required_argument, 0, 'R'},
		{"options", required_argument, 0, 'O'},
		{"quota", required_argument, 0, 'q'},
		{"remove-quota", required_argument, 0, 'Q'},
		{"roaming", required_argument, 0, 'M'},
		{"rst-state", required_argument, 0, 's'},
		{0, 0, 0, 0}
	};

	int longindex, retval;
	enum run_rsml_cmd cmd = UNDEFINED;
	resourced_iface_type iftype;

	while ((retval =
		getopt_long(argc, argv, optstring, options,
			    &longindex)) != -1) {
		switch (retval) {
		case 'h':
		case '?':
			print_usage();
			exit(EXIT_SUCCESS);
		case 'v':
			print_version();
			exit(EXIT_SUCCESS);
		case 'a':
			if (!optarg) {
				printf("apply-rst option requeres an argument.");
				exit(EXIT_FAILURE);
			}
			cmd = RESOURCED_APPLY;
			param->app_id = strdup(optarg);
			break;
		case 'e':
			if (!optarg) {
				printf("exclude-rst option requeres an argument.");
				exit(EXIT_FAILURE);
			}
			cmd = RESOURCED_EXCLUDE;
			param->app_id = strdup(optarg);
			break;
		case 'g':
			cmd = RESOURCED_GET;
			break;
		case 'u':
			cmd = RESOURCED_DATA_USAGE;
			break;
		case 'f':
			if (!optarg) {
				printf("from option requeres an argument.");
				exit(EXIT_FAILURE);
			}
			if (sscanf(optarg, "%ld", &param->du_rule.from) != 1) {
				printf("Failed to parse 'from' timestamp: %s\n",
				       optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 't':
			if (!optarg) {
				printf("to option requeres an argument.");
				exit(EXIT_FAILURE);
			}
			if (sscanf(optarg, "%ld", &param->du_rule.to) != 1) {
				printf("Failed to parse 'to' timestamp: %s\n",
				       optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'i':
			if (!optarg) {
				printf("interface option requeres an argument.");
				exit(EXIT_FAILURE);
			}
			iftype = convert_iftype(optarg);
			if (iftype == RESOURCED_IFACE_UNKNOWN) {
				printf("Unknown network interface!\n");
				exit(EXIT_FAILURE);
			}

			/* TODO change internal param structure */
			param->du_rule.iftype =	iftype;
			break;
		case 'M':
			if (!optarg) {
				printf("roaming option requeres an argument.");
				exit(EXIT_FAILURE);
			}
			resourced_ret_c ret_code = convert_roaming(optarg,
				&param->roaming_type);

			if (ret_code != RESOURCED_ERROR_NONE) {
				printf("Wrong argument of roaming: %s, roaming "
					"can only be enabled or disabled\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'd':
			cmd = RESOURCED_DATA_USAGE_DETAILS;
			if (optarg)
				param->app_id = strdup(optarg);
			break;
		case 'G':
			if (!optarg) {
				printf("granularity option requeres an argument.");
				exit(EXIT_FAILURE);
			}
			if (sscanf(optarg, "%d", &param->du_rule.granularity) !=
			    1) {
				printf("Failed to parse granularity: %s\n",
				       optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'r':
			if (!optarg) {
				printf("revert-rst option requeres an argument.");
				exit(EXIT_FAILURE);
			}
			cmd = RESOURCED_REVERT;
			param->app_id = strdup(optarg);
			break;
		case 'l':
			cmd = RESOURCED_GET_RESTRICTIONS;
			break;
		case 'R':
			if (!optarg) {
				printf("restrictions option requeres an argument.");
				exit(EXIT_FAILURE);
			}
			if (sscanf
			    (optarg, "%jd,%jd",
			     &param->rcv_limit,
			     &param->send_limit) != 2) {
				printf("Failed to parse restrictions\n"
				       "expected 2 integer numbers separated with commas without spaces\n"
				       "got \"%s\"\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'O':
			if (!optarg) {
				printf("options option requeres an argument.");
				exit(EXIT_FAILURE);
			}
			if (optarg && strcmp(optarg, "set") == 0)
				cmd = RESOURCED_SET_OPTIONS;
			else if (optarg && strcmp(optarg, "get") == 0)
				cmd = RESOURCED_GET_OPTIONS;
			break;
		case 'q':
			if (!optarg) {
				printf("Quota option requeres an argument.");
				exit(EXIT_FAILURE);
			}
			cmd = RESOURCED_SET_QUOTA;
			param->app_id = strdup(optarg);

			break;
		case 'Q':
			if (!optarg) {
				printf("Remove quota option requeres an argument.");
				exit(EXIT_FAILURE);
			}
			cmd = RESOURCED_REMOVE_QUOTA;
			param->app_id = strdup(optarg);
			break;
		case 's':
			if (!optarg) {
				printf("Restriction state requeres an argument.");
				exit(EXIT_FAILURE);
			}
			cmd = RESOURCED_RESTRICTION_STATE;
			param->app_id = strdup(optarg);
			break;
		default:
			printf("Unknown option %c\n", (char)retval);
			print_usage();
			exit(EXIT_FAILURE);
		}
	}
	return cmd;
}

/* common callback for data usage and data usage details
 * user_data is NULL for data usage
 * user_data is a non-NULL
 * (but not necessarily meaningful) for data usage details
 */
resourced_cb_ret data_usage_callback(const data_usage_info *info, void *user_data)
{
	/*TODO rewrite this hack*/
	if (user_data)
		printf("iftype %d\n", info->iftype);
	else
		printf("%s\n", info->app_id ? info->app_id : UNKNOWN_APP);

	if (info->interval) {
		printf("%s\t", ctime(&info->interval->from));
		printf("%s\t", ctime(&info->interval->to));
	} else
		printf("<entire interval>\t");

	printf("%ld/%ld\t%ld/%ld/%u/%u/%s\n", info->foreground.cnt.incoming_bytes,
	       info->background.cnt.incoming_bytes,
	       info->foreground.cnt.outgoing_bytes,
	       info->background.cnt.outgoing_bytes,
	       info->roaming, info->hw_net_protocol_type,
	       info->ifname);
	return RESOURCED_CONTINUE;
}

static inline int is_valid_range32(const int64_t value)
{
	return value >= 0 && value <= 2147483647; /* 2Gb */
}

/* callback for restriction details
 */
resourced_cb_ret restriction_callback(const resourced_restriction_info *info,
				      void *user_data)
{
	printf("appid: %s, iftype: %d, rst_state %d, rcv_limit %d, "
	       "send_limit %d, roaming %d\n",
		info->app_id ? info->app_id : UNKNOWN_APP,
	       info->iftype, info->rst_state,
	       info->rcv_limit, info->send_limit, info->roaming);
	return RESOURCED_CONTINUE;
}

const char *state_representation[] = {
	"UNDEFINDED",
	"ACTIVATED",
	"EXCLUDED",
};

const char *convert_restriction_state(network_restriction_state state) {
	if (state <= NETWORK_RESTRICTION_UNDEFINDED
		&& state >= NETWORK_RESTRICTION_MAX_VALUE) {
		fprintf(stderr, "state not in range %d", state);
		return NULL;
	}

	return state_representation[state];
}

void print_restriction_state(resourced_restriction_state state)
{
	const char *state_str = convert_restriction_state(state);
	if (state_str)
		printf("\nRestriction state: %s\n", state_str);
}

int main(int argc, char **argv)
{
	int ret_code = 0;
	struct arg_param param;
	enum run_rsml_cmd cmd = UNDEFINED;
	if (argc == 1) {
		print_usage();
		exit(EXIT_FAILURE);
	}

	memset(&param, 0, sizeof(struct arg_param));
	cmd = parse_cmd(argc, argv, &param);
	switch (cmd) {
	case RESOURCED_APPLY:
	{
		int err = 0;
		resourced_net_restrictions net_rst = {0,};

		if (!param.du_rule.iftype) {
			fprintf(stderr, "Apply restriction command requires -i\n");
			err = RESOURCED_ERROR_INVALID_PARAMETER;
		}

		if (!is_valid_range32(param.send_limit)) {
			fprintf(stderr, "Send limit should be in range 0 - 2Gb");
			err = RESOURCED_ERROR_INVALID_PARAMETER;
		}
		if (!is_valid_range32(param.rcv_limit)) {
			fprintf(stderr, "Rcv limit should be in range 0 - 2Gb");
			err = RESOURCED_ERROR_INVALID_PARAMETER;
		}

		if (err)
			return err;

		net_rst.send_limit = param.send_limit;
		net_rst.rcv_limit = param.rcv_limit;
		net_rst.iftype = param.du_rule.iftype;

		ret_code = set_net_restriction(param.app_id,
						       &net_rst);
		if (ret_code != RESOURCED_ERROR_NONE) {
			fprintf(stderr, "Failed to set restriction\n");
			return ret_code;
		}

		break;

	}
	case RESOURCED_EXCLUDE:
	{
		resourced_net_restrictions rst = {0,};
		rst.iftype = param.du_rule.iftype;
		rst.roaming = param.roaming_type;

		ret_code = set_net_exclusion(param.app_id,
			&rst);
		if (ret_code != RESOURCED_ERROR_NONE)
			return ret_code;
		break;
	}
	case RESOURCED_DATA_USAGE:
		if (param.du_rule.from && param.du_rule.to) {
			data_usage_foreach(&param.du_rule, data_usage_callback,
					   NULL);
		} else {
			fprintf(stderr, "Data usage commands require both "
			       "--from and --to\n");
		}
		break;
	case RESOURCED_DATA_USAGE_DETAILS:
		if (param.du_rule.from && param.du_rule.to) {
			/* see description for data_usage_callback above */
			data_usage_details_foreach(param.app_id, &param.du_rule,
						   data_usage_callback,
						   (void *)1);
		} else {
			fprintf(stderr, "Data usage commands require both "
			       "--from and --to\n");
		}
		break;
	case RESOURCED_REVERT:
		if (param.du_rule.iftype)
			ret_code = remove_restriction_by_iftype(
				param.app_id, param.du_rule.iftype);
		else
			fprintf(stderr, "Revert restriction commands require -i\n");
		if (ret_code != RESOURCED_ERROR_NONE)
			return ret_code;
		break;
	case RESOURCED_GET_RESTRICTIONS:
		printf("Applications are restricted now:\n");
		ret_code = restrictions_foreach(restriction_callback, NULL);
		break;
	case RESOURCED_SET_OPTIONS:
	{
		resourced_options options = {0};
		ret_code = set_resourced_options(&options);
		break;
	}
	case RESOURCED_GET_OPTIONS:
	{
		resourced_options options = {0};
		ret_code = get_resourced_options(&options);
		break;
	}
	case RESOURCED_SET_QUOTA:
	{
		data_usage_quota quota = { 0 };
		if (!param.du_rule.from || !param.du_rule.to) {
			fprintf(stderr, "Quota command requires all of this options: "
			       "--from, --to and --roaming\n");
			break;
		}

		/* TODO in case of refactoring, use internal command line structure instead of public structure for holding param */
		time_t quota_start_time = time(NULL);
		quota.start_time = &quota_start_time;
		quota.snd_quota = param.send_limit;
		quota.rcv_quota = param.rcv_limit;
		quota.iftype = param.du_rule.iftype;
		quota.time_period = param.du_rule.to - param.du_rule.from;
		quota.roaming_type =  param.roaming_type;
		if (set_datausage_quota(param.app_id, &quota) !=
		     RESOURCED_ERROR_NONE) {
				fprintf(stderr, "Failed to apply quota!\n");
		}
		break;
	}
	case RESOURCED_REMOVE_QUOTA:
	{
		struct datausage_quota_reset_rule rule = {0};

		rule.app_id = param.app_id;
		rule.iftype = param.du_rule.iftype;
		rule.roaming = param.roaming_type;

		if (remove_datausage_quota(&rule) != RESOURCED_ERROR_NONE) {
			fprintf(stderr, "Failed to remove quota!\n");
		}
		break;
	}
	case RESOURCED_RESTRICTION_STATE:
	{
		resourced_restriction_state state;
		if (!param.du_rule.iftype) {
			fprintf(stderr, "Exclude restriction commands require -i\n");
			ret_code = RESOURCED_ERROR_INVALID_PARAMETER;
			break;
		}

		ret_code = get_restriction_state(param.app_id,
			param.du_rule.iftype, &state);

		print_restriction_state(state);
		break;
	}
	default:
		ret_code = RESOURCED_ERROR_INVALID_PARAMETER;
		break;
	}

	return ret_code;
}
