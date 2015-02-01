/*
 * resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 *
 * @file iface.c
 *
 * @desc Utility for working with network interfaces
 */


#include <errno.h>
#include <glib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <linux/un.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "config-parser.h"
#include "const.h"
#include "iface.h"
#include "macro.h"
#include "trace.h"

#define NET_INTERFACE_NAMES_FILE "/etc/resourced/network.conf"
#define IFACES_TYPE_SECTION "IFACES_TYPE"

static int iface_stat[RESOURCED_IFACE_LAST_ELEM - 1];
static GTree *iftypes; /* holds int key and value of type resourced_iface_type */
static GTree *ifnames; /* for keeping ifype - interface name association */

static pthread_rwlock_t iftypes_guard = PTHREAD_RWLOCK_INITIALIZER;
static pthread_rwlock_t ifnames_guard = PTHREAD_RWLOCK_INITIALIZER;


static const char *UEVENT_FMT = "/sys/class/net/%s/uevent";
static const char *DEVTYPE_KEY = "DEVTYPE";
static const char *WIRED_VALUE = "gadget";
static const char *WIFI_VALUE = "wlan";
static const char *BLUETOOTH_VALUE = "bluetooth";
static const char *DATACALL_VALUE = "datacall";
static const char *ALL_NET_IFACE_VALUE = "all";
static const char *UEVENT_DELIM = "=\n";

static GSList *ifnames_relations;

struct iface_relation {
	resourced_iface_type iftype;
	char ifname[MAX_NAME_LENGTH];
};

static gint compare_int(gconstpointer a, gconstpointer b,
	gpointer UNUSED userdata)
{
	if (a == b)
		return 0;
	else if (a > b)
		return 1;
	return -1;
}

static GTree *create_iface_tree(void)
{
	return g_tree_new_full(compare_int,
		NULL, NULL, free);
}

static void put_iftype_to_tree(GTree *iftypes_tree, int ifindex, int iftype)
{
	gpointer new_value;

	ret_msg_if(!iftypes_tree, "Please provide valid argument!");
	new_value = (gpointer)malloc(sizeof(int));
	if (!new_value) {
		_E("Malloc of put_iftype_to_tree failed\n");
		return;
	}
	*(int *)new_value = iftype;
	g_tree_replace(iftypes_tree, (gpointer)ifindex, new_value);
}

static void put_ifname_to_tree(GTree *ifnames_tree, char *ifname, int iftype)
{
	int name_len = strlen(ifname) + 1;
	gpointer new_value = (gpointer)malloc(name_len);
	if (!new_value) {
		_E("Malloc of put_ifname_to_tree failed\n");
		return;
	}
	strncpy(new_value, ifname, name_len);

	if (!ifnames_tree) {
		free(new_value);
		_E("Please provide valid argument!");
		return;
	}
	g_tree_replace(ifnames_tree, (gpointer)iftype, new_value);
}

static resourced_iface_type get_iftype_from_tree(GTree *iftypes_tree, int ifindex)
{
	resourced_iface_type ret = RESOURCED_IFACE_UNKNOWN;
	gpointer table_value;

	ret_value_msg_if(!iftypes_tree, ret, "Please provide valid argument!");

	pthread_rwlock_rdlock(&iftypes_guard);
	table_value = g_tree_lookup(iftypes_tree, (gpointer)ifindex);
	pthread_rwlock_unlock(&iftypes_guard);
	if (table_value != NULL)
		ret = *(int *)table_value;

	return ret;
}

static void free_iftypes_tree(GTree *iftypes_tree)
{
	g_tree_destroy(iftypes_tree);
}

static void iface_stat_allowance(void)
{
	size_t i;
	for (i = 0; i < ARRAY_SIZE(iface_stat); ++i)
		iface_stat[i] = 1;
}

static resourced_iface_type get_predefined_iftype(const char *ifname)
{
	struct iface_relation *relation;
	GSList *iter;
	gslist_for_each_item(iter, ifnames_relations) {
		relation = (struct iface_relation *)iter->data;
			if (strstr(ifname, relation->ifname))
				return relation->iftype;
	}
	_D("Even in predefined interface name list, interface types wasn't "
	   " find for %s", ifname);
	return RESOURCED_IFACE_UNKNOWN;
}

static resourced_iface_type read_iftype(const char *iface)
{
	char buffer[UNIX_PATH_MAX];
	char *key_buffer;
	char *value_buffer;
	FILE *uevent;
	resourced_iface_type ret = RESOURCED_IFACE_UNKNOWN;

	snprintf(buffer, UNIX_PATH_MAX, UEVENT_FMT, iface);
	uevent = fopen(buffer, "r");

	if (!uevent)
		return ret;

	while (!feof(uevent)) {
		if (fgets(buffer, UNIX_PATH_MAX, uevent) == NULL)
			break;
		key_buffer = strtok(buffer, UEVENT_DELIM);
		value_buffer = strtok(NULL, UEVENT_DELIM);
		if (strcmp(key_buffer, DEVTYPE_KEY) != 0)
			continue;
		ret = convert_iftype(value_buffer);
		break;
	}

	fclose(uevent);

	/* work around, in case of missing DEVTYPE field */
	if (ret == RESOURCED_IFACE_UNKNOWN)
		ret = get_predefined_iftype(iface);

	return ret;
}

static void reset_tree(GTree *new, GTree **old,
	pthread_rwlock_t *guard)
{
	GTree *release = *old;

	pthread_rwlock_wrlock(guard);
	*old = new;
	pthread_rwlock_unlock(guard);
	if (release)
		free_iftypes_tree(release);
}

bool is_address_exists(const char *name)
{
#ifdef SIOCDIFADDR
	struct ifreq ifr;
	static int fd;
	if (!fd)
		fd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(struct ifreq));
	strcpy(ifr.ifr_name, name);
	return ioctl(fd, SIOCGIFADDR, &ifr) == 0;
#endif /* SIOCDIFADDR */
	return true;
}

static int fill_ifaces_relation(struct parse_result *result,
				void UNUSED *user_data)
{
	struct iface_relation *relation;
	if (strcmp(result->section, IFACES_TYPE_SECTION))
		return RESOURCED_ERROR_NONE;

	relation = (struct iface_relation *)malloc(sizeof(struct iface_relation));

	ret_value_msg_if(relation == NULL, RESOURCED_ERROR_NONE,
		"Failed to allocated memory!");

	relation->iftype = convert_iftype(result->name);
	STRING_SAVE_COPY(relation->ifname, result->value);

	ifnames_relations = g_slist_prepend(ifnames_relations, relation);
	return RESOURCED_ERROR_NONE;
}

int init_iftype(void)
{
	int i, ret;
	resourced_iface_type iftype;
	struct if_nameindex *ids = if_nameindex();
	GTree *iftypes_next = create_iface_tree();
	GTree *ifnames_next = create_iface_tree();

	if (ids == NULL) {
		_E("Failed to initialize iftype table! errno: %d, %s",
			errno, strerror(errno));
		return RESOURCED_ERROR_FAIL;
	}

	if (!ifnames_relations) {
		ret = config_parse(NET_INTERFACE_NAMES_FILE,
				   fill_ifaces_relation, NULL);
		if (ret != 0)
			_D("Can't parse config file %s",
			   NET_INTERFACE_NAMES_FILE);
	}

	iface_stat_allowance();

	for (i = 0; ids[i].if_index != 0; ++i) {
		if (!is_address_exists(ids[i].if_name))
			continue;
		iftype = read_iftype(ids[i].if_name);
		put_iftype_to_tree(iftypes_next, ids[i].if_index, iftype);
		/*  we know here iftype/ids[i].if_name, lets populate
		 *	ifnames_tree */
		put_ifname_to_tree(ifnames_next, ids[i].if_name, iftype);
		_D("ifname %s, ifype %d", ids[i].if_name, iftype);
	}

	/* Do not forget to free the memory */
	if_freenameindex(ids);

	reset_tree(iftypes_next, &iftypes, &iftypes_guard);
	reset_tree(ifnames_next, &ifnames, &ifnames_guard);
	return RESOURCED_ERROR_NONE;
}

void finalize_iftypes(void)
{
	reset_tree(NULL, &iftypes, &iftypes_guard);
	reset_tree(NULL, &ifnames, &ifnames_guard);
	g_slist_free_full(ifnames_relations, free);
}

resourced_iface_type convert_iftype(const char *buffer)
{
	if (!buffer) {
		_E("Malloc of answer_get_stat failed\n");
		return RESOURCED_IFACE_UNKNOWN;
	}

	if (strcmp(buffer, DATACALL_VALUE) == 0)
		return RESOURCED_IFACE_DATACALL;

	if (strcmp(buffer, WIFI_VALUE) == 0)
		return RESOURCED_IFACE_WIFI;

	if (strcmp(buffer, BLUETOOTH_VALUE) == 0)
		return RESOURCED_IFACE_BLUETOOTH;

	if (strcmp(buffer, WIRED_VALUE) == 0)
		return RESOURCED_IFACE_WIRED;
	if (strcmp(buffer, ALL_NET_IFACE_VALUE) == 0)
		return RESOURCED_IFACE_ALL;
	return RESOURCED_IFACE_UNKNOWN;
}

int is_allowed_ifindex(int ifindex)
{
	return iface_stat[get_iftype(ifindex)];
}

resourced_iface_type get_iftype(int ifindex)
{
	return get_iftype_from_tree(iftypes, ifindex);
}

static gboolean print_ifname(gpointer key, gpointer value, gpointer data)
{
	_D("ifname %s", (char *)value);
	return FALSE;
}

static char *get_ifname_from_tree(GTree *ifnames_tree, int iftype)
{
	char *ret = NULL;

	ret_value_msg_if(!ifnames_tree, NULL, "Please provide valid argument!");

	pthread_rwlock_rdlock(&ifnames_guard);
	ret = (char *)g_tree_lookup(ifnames_tree, (gpointer)iftype);
	pthread_rwlock_unlock(&ifnames_guard);
	if (ret == NULL)
		g_tree_foreach(ifnames_tree, print_ifname, NULL);

	return ret;
}

char *get_iftype_name(resourced_iface_type iftype)
{
	return get_ifname_from_tree(ifnames, iftype);
}

static gboolean search_loopback(gpointer key,
                  gpointer value,
                  gpointer data)
{
	int *res = (int *)data;
	if (!value)
		return FALSE;
	*res = *(int *)value == RESOURCED_IFACE_UNKNOWN ? TRUE : FALSE;
	return *res;
}

static bool is_only_loopback(GTree *iftypes_tree)
{
	int nodes = g_tree_nnodes(iftypes_tree);
	int res = 0;

	if (nodes > 1)
		return false;

	g_tree_foreach(iftypes_tree, search_loopback, &res);
	return res;
}

void for_each_ifindex(ifindex_iterator iter, void(*empty_func)(void *),
	void *data)
{
	pthread_rwlock_rdlock(&iftypes_guard);
	if (!is_only_loopback(iftypes))
		g_tree_foreach(iftypes, (GTraverseFunc)iter, data);
	else if (empty_func)
		empty_func(data);

	pthread_rwlock_unlock(&iftypes_guard);
}

void set_wifi_allowance(const resourced_option_state wifi_option)
{
	iface_stat[RESOURCED_IFACE_WIFI] = wifi_option == RESOURCED_OPTION_ENABLE ? 1 : 0;
}

void set_datacall_allowance(const resourced_option_state datacall_option)
{
	iface_stat[RESOURCED_IFACE_DATACALL] = datacall_option == RESOURCED_OPTION_ENABLE ? 1 : 0;
}
