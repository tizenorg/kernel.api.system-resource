/*
 * resourced
 *
 * Copyright (c) 2014 - 2015 Samsung Electronics Co., Ltd. All rights reserved.
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

#include "const.h"
#include "iface.h"
#include "macro.h"
#include "trace.h"

#define IFACES_TYPE_SECTION "IFACES_TYPE"

static int iface_stat[RESOURCED_IFACE_LAST_ELEM - 1];
static GTree *iftypes; /* holds int key and value of type resourced_iface_type */

static GSList *ifnames; /* for keeping ifype - interface name association */

static pthread_rwlock_t iftypes_guard = PTHREAD_RWLOCK_INITIALIZER;

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

struct iface_status {
	bool active;
	char ifname[MAX_NAME_LENGTH];
	resourced_iface_type iftype;
};

static allowance_cb allow_cb;

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

static void keep_ifname(GSList **ifnames_list, char *ifname, int iftype)
{
	GSList *iter;
	bool found = false;
	struct iface_status *value;
	ret_msg_if (!ifnames_list || !ifname, "Please provide valid argument!");

	gslist_for_each_item(iter, *ifnames_list) {
		struct iface_status *cur = (struct iface_status *)iter->data;
		if (cur->iftype == iftype && !strcmp(cur->ifname, ifname)) {
			cur->active = true;
			found = true;
		}
	}

	if (found)
		return;

	_D("Add new entry into ifnames");
	value = (struct iface_status *)malloc(
			sizeof(struct iface_status));

	ret_msg_if (!value, "Can't allocate memory for iface_status\n");
	value->active = true; /* we're putting it => it's active now */
	value->iftype = iftype;
	STRING_SAVE_COPY(value->ifname, ifname);
	*ifnames_list = g_slist_prepend(*ifnames_list, value);
}

static void reset_active_ifnames(GSList *ifnames_list)
{
	GSList *iter;
	gslist_for_each_item(iter, ifnames_list) {
		struct iface_status *value = (struct iface_status *)iter->data;
		value->active = false;
	}
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
	char *saveptr;
	FILE *uevent;
	resourced_iface_type ret = RESOURCED_IFACE_UNKNOWN;

	snprintf(buffer, UNIX_PATH_MAX, UEVENT_FMT, iface);
	uevent = fopen(buffer, "r");

	if (!uevent)
		return ret;

	while (!feof(uevent)) {
		if (fgets(buffer, UNIX_PATH_MAX, uevent) == NULL)
			break;
		key_buffer = strtok_r(buffer, UEVENT_DELIM, &saveptr);
		value_buffer = strtok_r(NULL, UEVENT_DELIM, &saveptr);
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
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name)-1);
	return ioctl(fd, SIOCGIFADDR, &ifr) == 0;
#endif /* SIOCDIFADDR */
	return true;
}

int fill_ifaces_relation(struct parse_result *result,
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
	int i;
	resourced_iface_type iftype;
	struct if_nameindex *ids = if_nameindex();
	GTree *iftypes_next = create_iface_tree();

	if (ids == NULL) {
		strerror_r(errno, buf, sizeof(buf));
		_E("Failed to initialize iftype table! errno: %d, %s",
			errno, buf);
		return RESOURCED_ERROR_FAIL;
	}

	if (!ifnames_relations) {
		_D("interface name relations are empty");
	}

	reset_active_ifnames(ifnames);
	iface_stat_allowance();

	for (i = 0; ids[i].if_index != 0; ++i) {
		if (!is_address_exists(ids[i].if_name))
			continue;
		iftype = read_iftype(ids[i].if_name);
		/* don't put unknown network interface into list */
		if (iftype == RESOURCED_IFACE_UNKNOWN) {
			_D("unknown ifname %s, ifype %d", ids[i].if_name, iftype);
			continue;
		}
		put_iftype_to_tree(iftypes_next, ids[i].if_index, iftype);
		/*  we know here iftype/ids[i].if_name, lets populate
		 *	ifnames_tree */
		keep_ifname(&ifnames, ids[i].if_name, iftype);
		_D("ifname %s, ifype %d", ids[i].if_name, iftype);
	}

	/* Do not forget to free the memory */
	if_freenameindex(ids);

	reset_tree(iftypes_next, &iftypes, &iftypes_guard);
	return RESOURCED_ERROR_NONE;
}

void finalize_iftypes(void)
{
	reset_tree(NULL, &iftypes, &iftypes_guard);
	g_slist_free_full(ifnames, free);
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

int is_counting_allowed(resourced_iface_type iftype)
{
	return iface_stat[iftype];
}

API resourced_iface_type get_iftype(int ifindex)
{
	return get_iftype_from_tree(iftypes, ifindex);
}

static char *lookup_ifname(GSList *ifnames_list, int iftype)
{
	GSList *iter;

	ret_value_msg_if(!ifnames_list, NULL, "Please provide valid argument!");

	gslist_for_each_item(iter, ifnames_list) {
		struct iface_status *value = (struct iface_status *)iter->data;
		if (value->iftype == iftype)
			return value->ifname;
	}

	return NULL;
}

char *get_iftype_name(resourced_iface_type iftype)
{
	return lookup_ifname(ifnames, iftype);
}

resourced_iface_type get_iftype_by_name(char *name)
{
	GSList *iter;
	ret_value_msg_if(name == NULL, RESOURCED_IFACE_UNKNOWN,
		"Invalid argument");

	gslist_for_each_item(iter, ifnames) {
		struct iface_status *value = (struct iface_status *)iter->data;
		if (!strcmp(value->ifname, name))
			return value->iftype;
	}

	return RESOURCED_IFACE_UNKNOWN;
}

/* now used only in ./src/network/ktgrabber-restriction.c:285 */
void for_each_ifindex(ifindex_iterator iter, void(*empty_func)(void *),
	void *data)
{
	pthread_rwlock_rdlock(&iftypes_guard);
	g_tree_foreach(iftypes, (GTraverseFunc)iter, data);

	if (empty_func)
		empty_func(data);

	pthread_rwlock_unlock(&iftypes_guard);
}

void for_each_ifnames(ifnames_iterator iter_cb, void(*empty_func)(void *),
	void *data)
{
	GSList *iter;
	gslist_for_each_item(iter, ifnames) {
		struct iface_status *value = (struct iface_status *)iter->data;
		/* as before invoke cb only for active interfaces */
		if (!value->active)
			continue;

		if (!is_counting_allowed(value->iftype) && empty_func) {
			empty_func(data);
			continue;
		}

		if (iter_cb(value->iftype, value->ifname, data) == TRUE)
			break;
	}

	if (!g_slist_length(ifnames) && empty_func)
		empty_func(data);

}

void set_wifi_allowance(const resourced_option_state wifi_option)
{
	int old_allowance = iface_stat[RESOURCED_IFACE_WIFI];
	iface_stat[RESOURCED_IFACE_WIFI] = wifi_option == RESOURCED_OPTION_ENABLE ? 1 : 0;

	if (old_allowance != iface_stat[RESOURCED_IFACE_WIFI] && allow_cb)
		allow_cb(RESOURCED_IFACE_WIFI, iface_stat[RESOURCED_IFACE_WIFI]);
}

void set_datacall_allowance(const resourced_option_state datacall_option)
{
	int old_allowance = iface_stat[RESOURCED_IFACE_DATACALL];

	iface_stat[RESOURCED_IFACE_DATACALL] = datacall_option == RESOURCED_OPTION_ENABLE ? 1 : 0;
	if (old_allowance != iface_stat[RESOURCED_IFACE_DATACALL] && allow_cb)
		allow_cb(RESOURCED_IFACE_DATACALL, iface_stat[RESOURCED_IFACE_DATACALL]);
}

void set_change_allow_cb(allowance_cb cb)
{
	allow_cb = cb;
}
