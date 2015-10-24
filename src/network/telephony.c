/*
 *  resourced
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file telephony.c
 *
 * @desc Roaming persistent object. Due roaming changes not so often we can keep it in
 *  our memory and handle roaming changes.
 *  In this file we keep roaming state in global variable.
 */

#include <glib.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <vconf/vconf.h>
#include <vconf/vconf-internal-telephony-keys.h>
#include <TelSim.h>

#include "config.h"
#include "const.h"
#include "edbus-handler.h"
#include "iface.h"
#include "macro.h"
#include "telephony.h"
#include "trace.h"

/**
 * @brief Definition for the telephony service name.
 */
#define DBUS_TELEPHONY_SERVICE		"org.tizen.telephony"

#define DBUS_TELEPHONY_SERVICE_MANAGER	DBUS_TELEPHONY_SERVICE".Manager"
#define DBUS_TELEPHONY_SERVICE_NETWORK	DBUS_TELEPHONY_SERVICE".Network"
#define DBUS_TELEPHONY_SIM_INTERFACE	DBUS_TELEPHONY_SERVICE".Sim"


/**
 * @brief Definition for the telephony object path.
 */
#define DBUS_TELEPHONY_DEFAULT_PATH		"/org/tizen/telephony"

#define DBUS_TELEPHONY_GET_MODEMS		"GetModems"
#define DBUS_TELEPHONY_PROPERTIES_CHANGED	"PropertiesChanged"
#define DBUS_TELEPHONY_ROAMING_STATUS		"roaming_status"
#define DBUS_TELEPHONY_SERVICE_TYPE		"service_type"
#define DBUS_TELEPHONY_GET			"Get"
#define DBUS_TELEPHONY_GET_IMSI			"GetIMSI"
#define DBUS_FREEDESKTOP_PROPERTIES		"org.freedesktop.DBus.Properties"
#define DBUS_TELEPHONY_STATUS			"Status"

/**
 * @brief vconf value for checking active modem
 *  copied from vconfkey-internal
 */
#define DEFAULT_DATA_SERVICE_SIM1 0
#define DEFAULT_DATA_SERVICE_SIM2 1
#define SIM_SLOT_SINGLE 1
#define IMSI_LENGTH 16

struct modem_state {
	char *name;
	bool roaming;
	char *path;
	char *imsi;  /* International mobile subscriber identity, to identify SIM card */
	/* such model will be if we'll have ability to make 2 connection by 2 sim
	 * card simultaneously, but for Kiran the "Dual SIM Dual Standby"
	 * model was chosen, where it's impossible, so keep only pointer to
	 * current modem, if model will be changed to "Dual SIM Dual Active",
	 * change get_current_imsi() and
	 * add into it iteration, also patch
	 * "[PATCH 2/8] network: add modem section into config" which was
	 * abondoned in current patch set, could be usefull as well (but not
	 * confg value in it, due everything could change). */
	/* char *ifname; */
	/* bool active;	*/
	char *imsi_hash;
	resourced_hw_net_protocol_type protocol;
};

static struct modem_state *current_modem;
static GSList *modems; /* list of available modems with roaming state */

#ifdef DEBUG_ENABLED
#define _D_DBUS _D
#else
#define _D_DBUS(s, args...) ({ do { } while (0); })
#endif /*DEBUG_ENABLED*/

static bool check_current_modem(const char *modem_name, int sim_number)
{
	int digit_pos = 0;
	ret_value_msg_if(!modem_name, false, "Invalid argument!");

	ret_value_msg_if(sim_number >= 10, false, "Unsupported sim number %d", sim_number);
	digit_pos = strlen(modem_name);
	ret_value_msg_if(!digit_pos, false, "Invalid argument!");
	return modem_name[digit_pos - 1] == '0' + sim_number;
}

static void default_data_service_change_cb(keynode_t *key, void *data)
{
	int current_sim = vconf_keynode_get_int(key);
	GSList *iter;

	_D("default data service has changed: key = %s, value = %d(int)\n",
			vconf_keynode_get_name(key), current_sim);

	gslist_for_each_item(iter, modems) {
		struct modem_state *modem = (struct modem_state *)iter->data;
		if (!modem->name)
			continue;
		if (check_current_modem(modem->name, current_sim)) {
			current_modem = modem;
			break;
		}
	}
}

static int get_current_sim(void)
{
	int sim_slot_count = 0;
	int current_sim = 0;
	ret_value_msg_if(vconf_get_int(
			 VCONFKEY_TELEPHONY_SIM_SLOT_COUNT, &sim_slot_count) != 0, -1,
			 "failed to get sim slot count");

	if(sim_slot_count == SIM_SLOT_SINGLE) {
	       _D("It's single sim model");
	       return current_sim;
	}

	ret_value_msg_if(vconf_get_int(
			 VCONF_TELEPHONY_DEFAULT_DATA_SERVICE, &current_sim) != 0, -1,
			 "failed to get default data service = %d\n", current_sim);
	return current_sim;
}

static void init_available_modems(void)
{
	DBusError err;
	DBusMessage *msg;
	DBusMessageIter iter, iter_array;
	int i = 0;
	int current_sim;

	do {
		msg = dbus_method_sync(DBUS_TELEPHONY_SERVICE,
				       DBUS_TELEPHONY_DEFAULT_PATH,
				       DBUS_TELEPHONY_SERVICE_MANAGER,
				       DBUS_TELEPHONY_GET_MODEMS,
				       NULL, NULL);
		if (msg)
			break;
		_E("Re-try to sync DBUS message, err_count : %d", i);
	} while (i++ < RETRY_MAX);

	if (!msg) {
		_E("Failed to sync DBUS message.");
		return;
	}

	dbus_error_init(&err);

	dbus_message_iter_init (msg, &iter);
	dbus_message_iter_recurse (&iter, &iter_array);
	current_sim = get_current_sim();

	while (dbus_message_iter_get_arg_type (&iter_array) != DBUS_TYPE_INVALID) {
		const char *name;
		struct modem_state *state = (struct modem_state *)malloc(
					      sizeof(struct modem_state));
		memset(state, 0, sizeof(struct modem_state));
		dbus_message_iter_get_basic (&iter_array, &name);
		_D("modem name %s", name);
		dbus_message_iter_next (&iter_array);
		state->name = strndup(name, strlen(name));
		state->roaming = false;
		modems = g_slist_prepend(modems, state);
		if (check_current_modem(state->name, current_sim))
			current_modem = state;
	}

	vconf_notify_key_changed(VCONF_TELEPHONY_DEFAULT_DATA_SERVICE,
				 default_data_service_change_cb, NULL);

	dbus_message_unref(msg);
	dbus_error_free(&err);
}

static void hash_imsi(struct modem_state *modem)
{
	int i;
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	unsigned char md[SHA256_DIGEST_LENGTH];
	SHA256_Update(&ctx, modem->imsi, strlen(modem->imsi));
	SHA256_Final(md, &ctx);
	if (!modem->imsi_hash) {
		modem->imsi_hash = (char *)malloc(SHA256_DIGEST_LENGTH * 2 + 1);
		ret_msg_if(!modem->imsi_hash, "Can't allocate buffer for imsi_hash!");
	}
	_SD("make hash for imsi %s", modem->imsi);
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		snprintf(modem->imsi_hash + (i * 2), 2, "%02x", md[i]);
}

static void fill_modem_imsi(struct modem_state *modem)
{
	DBusError err;
	DBusMessage *msg;
	DBusMessageIter iter;
	char tel_path[MAX_PATH_LENGTH];
	char *plmn = NULL;
	int plmn_len;
	char *msin = NULL;
	int msin_len;
	int i = 0;

	snprintf(tel_path, sizeof(tel_path), "%s/%s", DBUS_TELEPHONY_DEFAULT_PATH, modem->name);
	do {
		msg = dbus_method_sync(DBUS_TELEPHONY_SERVICE,
				       tel_path,
				       DBUS_TELEPHONY_SIM_INTERFACE,
				       DBUS_TELEPHONY_GET_IMSI,
				       NULL, NULL);
		if (msg)
			break;
		_E("Re-try to sync DBUS message, err_count : %d", i);
	} while (i++ < RETRY_MAX);

	if (!msg) {
		_E("Failed to sync DBUS message.");
		return;
	}

	dbus_error_init(&err);

	dbus_message_iter_init (msg, &iter);
	_D_DBUS("dbus message type %d", dbus_message_iter_get_arg_type(&iter));
	ret_msg_if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING,
		"Return for %s isn't variant type as expected",
		DBUS_FREEDESKTOP_PROPERTIES);
	dbus_message_iter_get_basic (&iter, &plmn);
	_D_DBUS("plmn value %d", plmn);
	plmn_len = strlen(plmn);
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic (&iter, &msin);
	_D_DBUS("msin value %d", msin);
	msin_len = strlen(msin);
	if (!modem->imsi) { /* it's reinit case */
		modem->imsi = malloc(plmn_len + msin_len + 1);
		ret_msg_if(!modem->imsi, "Can't allocate string for imsi");
	}
	if (msin_len + plmn_len >= IMSI_LENGTH) {
		_D("Incorrect length of mobile subscriber identifier + net id");
		return;
	}
	snprintf(modem->imsi, IMSI_LENGTH, "%s%s", plmn, msin);
	hash_imsi(modem);
}

static void init_modem_imsi(void)
{
	GSList *iter;
	gslist_for_each_item(iter, modems) {
		struct modem_state *modem = (struct modem_state *)iter->data;
		fill_modem_imsi(modem);
	}
}

static void fill_modem_state(struct modem_state *modem)
{
	DBusError err;
	DBusMessage *msg;
	DBusMessageIter iter, var;
	char tel_path[MAX_PATH_LENGTH];
	int i = 0;
	char *params[2] = {DBUS_TELEPHONY_SERVICE_NETWORK, DBUS_TELEPHONY_ROAMING_STATUS};


	snprintf(tel_path, sizeof(tel_path), "%s/%s", DBUS_TELEPHONY_DEFAULT_PATH, modem->name);
	do {
		msg = dbus_method_sync(DBUS_TELEPHONY_SERVICE,
				       tel_path,
				       DBUS_FREEDESKTOP_PROPERTIES,
				       DBUS_TELEPHONY_GET,
				       "ss", params);
		if (msg)
			break;
		_E("Re-try to sync DBUS message, err_count : %d", i);
	} while (i++ < RETRY_MAX);

	if (!msg) {
		_E("Failed to sync DBUS message.");
		return;
	}

	dbus_error_init(&err);

	dbus_message_iter_init (msg, &iter);
	_D_DBUS("dbus message type %d", dbus_message_iter_get_arg_type(&iter));
	ret_msg_if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT,
		"Return for %s isn't variant type as expected", DBUS_FREEDESKTOP_PROPERTIES);
	dbus_message_iter_recurse(&iter, &var);
	_D_DBUS("dbus message variant type %d", dbus_message_iter_get_arg_type(&var));
	ret_msg_if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_BOOLEAN,
		"Return for %s isn't boolean type as expected", DBUS_FREEDESKTOP_PROPERTIES);

	dbus_message_iter_get_basic (&var, &modem->roaming);
	_D("modem roaming value %d", modem->roaming);
}

static void fill_protocol(struct modem_state *modem)
{
	DBusError err;
	DBusMessage *msg;
	DBusMessageIter iter, var;
	char tel_path[MAX_PATH_LENGTH];
	int i = 0;
	char *params[2] = {DBUS_TELEPHONY_SERVICE_NETWORK, DBUS_TELEPHONY_SERVICE_TYPE};


	snprintf(tel_path, sizeof(tel_path), "%s/%s", DBUS_TELEPHONY_DEFAULT_PATH, modem->name);
	do {
		msg = dbus_method_sync(DBUS_TELEPHONY_SERVICE,
				       tel_path,
				       DBUS_FREEDESKTOP_PROPERTIES,
				       DBUS_TELEPHONY_GET,
				       "ss", params);
		if (msg)
			break;
		_E("Re-try to sync DBUS message, err_count : %d", i);
	} while (i++ < RETRY_MAX);

	if (!msg) {
		_E("Failed to sync DBUS message.");
		return;
	}

	dbus_error_init(&err);

	dbus_message_iter_init (msg, &iter);
	_D_DBUS("dbus message type %d", dbus_message_iter_get_arg_type(&iter));
	ret_msg_if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT,
		"Return for %s isn't variant type as expected", DBUS_FREEDESKTOP_PROPERTIES);
	dbus_message_iter_recurse(&iter, &var);
	_D_DBUS("dbus message variant type %d", dbus_message_iter_get_arg_type(&var));
	ret_msg_if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_INT32,
		"Return for %s isn't int type as expected", DBUS_FREEDESKTOP_PROPERTIES);

	dbus_message_iter_get_basic (&var, &modem->protocol);
	_D("modem roaming value %d", modem->protocol);
}

/**
 * @brief Get initial value for roaming and sets callback for handling roaming change
 */
static void init_roaming_states(void)
{
	GSList *iter;
	gslist_for_each_item(iter, modems) {
		struct modem_state *modem = (struct modem_state *)iter->data;
		fill_modem_state(modem);
	}
}

static void init_protocols(void)
{
	GSList *iter;
	gslist_for_each_item(iter, modems) {
		struct modem_state *modem = (struct modem_state *)iter->data;
		fill_protocol(modem);
	}
}


/**
 * Response format:
 * signal sender=:1.273 -> dest=(null destination) serial=546
 * path=/org/tizen/telephony/sprdmodem0;
 * interface=org.freedesktop.DBus.Properties;
 * member=PropertiesChanged
 *    string "org.tizen.telephony.Network"
 *       array [
 *       ...
 *         dict entry(
 *           string "roaming_status"
 *           variant             boolean false
 *         )
 *         ...
 *         dict entry(
 *           string "service_type"
 *           variant             int32 3
 *         )
 *             ]
 *      array [
 *            ]
 **/
static void edbus_telephony_changed(void *data, DBusMessage *msg)
{
	struct modem_state *modem = (struct modem_state *)data;
	char *property;
	/* parse msg */
	DBusMessageIter iter, dict, prop, bool_iter;

	_D_DBUS("it's signal by %s path", dbus_message_get_path(msg));
	dbus_message_iter_init (msg, &iter);
	dbus_message_iter_next(&iter);
	/* call dbus_message_iter_next(&iter) */
	_D_DBUS("dbus message type %d", dbus_message_iter_get_arg_type(&iter));

	while (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_ARRAY) {
		dbus_message_iter_recurse(&iter, &dict);
		_D_DBUS("dbus message variant type %d", dbus_message_iter_get_arg_type(&dict));
		ret_msg_if (dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_DICT_ENTRY,
			"Return for %s isn't variant type as expected",
			 modem->path);

		dbus_message_iter_recurse(&dict, &prop);
		_D_DBUS("dbus message roaming type %d", dbus_message_iter_get_arg_type(&prop));
		ret_msg_if (dbus_message_iter_get_arg_type(&prop) != DBUS_TYPE_STRING,
			"Return for %s isn't boolean type as expected",
			 modem->path);

		dbus_message_iter_get_basic (&prop, &property);

		if (strcmp(property, DBUS_TELEPHONY_ROAMING_STATUS) == 0) {
			dbus_message_iter_next(&prop); /* it's variant here, expand it */
			dbus_message_iter_recurse(&prop, &bool_iter);
			ret_msg_if (dbus_message_iter_get_arg_type(&bool_iter) != DBUS_TYPE_BOOLEAN,
			"Return for %s isn't variant type as expected", DBUS_FREEDESKTOP_PROPERTIES);

			dbus_message_iter_get_basic (&bool_iter, &modem->roaming);
			_D("Roaming state for modem %s has changed", modem->name);
			_D("roaming state now is %d", modem->roaming);
		} else if (strcmp(property, DBUS_TELEPHONY_SERVICE_TYPE) == 0) {
			dbus_message_iter_next(&prop); /* it's variant here, expand it */
			dbus_message_iter_recurse(&prop, &bool_iter);
			ret_msg_if (dbus_message_iter_get_arg_type(&bool_iter) != DBUS_TYPE_INT32,
			"Return for %s isn't variant type as expected", DBUS_FREEDESKTOP_PROPERTIES);

			dbus_message_iter_get_basic (&bool_iter, &modem->protocol);
			_D("Protocol for modem %s has changed", modem->name);
			_D("protocol now is %d", modem->protocol);
		} else {
			_D("Unnecessary property %s", property);
			return;
		}
		dbus_message_iter_next(&iter);
	}
}

static void regist_telephony_callbacks(void)
{
	resourced_ret_c ret;
	GSList *iter;
	gslist_for_each_item(iter, modems) {
		struct modem_state *modem = (struct modem_state *)iter->data;
		size_t path_size = sizeof(DBUS_TELEPHONY_DEFAULT_PATH) + strlen(modem->name) + 2;

		modem->path = (char *)malloc(path_size);
		snprintf(modem->path, path_size, "%s/%s", DBUS_TELEPHONY_DEFAULT_PATH, modem->name);
		ret = register_edbus_signal_handler(modem->path,
			DBUS_FREEDESKTOP_PROPERTIES,
			DBUS_TELEPHONY_PROPERTIES_CHANGED,
			edbus_telephony_changed, modem);
		if (ret != RESOURCED_ERROR_NONE) {
			_E("Could not register edbus path %s", modem->path);
			modem->path = NULL;
			continue;
		}
	}
}

static void edbus_sim_status_changed(void *data, DBusMessage *msg)
{
	struct modem_state *modem = (struct modem_state *)data;
	int sim_status = 0;
	int arg_type  = 0;
	/* parse msg */
	DBusMessageIter iter;

	_D("it's signal by %s path", dbus_message_get_path(msg));
	dbus_message_iter_init (msg, &iter);
	arg_type = dbus_message_iter_get_arg_type(&iter);
	dbus_message_iter_get_basic(&iter, &sim_status);

	_D("sim status type %d, %d", sim_status, arg_type);
	if (sim_status == TAPI_SIM_STATUS_SIM_INIT_COMPLETED) {
		/* we could request IMSI */
		fill_modem_imsi(modem);
	}
}


static void regist_sim_status_callbacks(void)
{
	resourced_ret_c ret;
	GSList *iter;
	gslist_for_each_item(iter, modems) {
		struct modem_state *modem = (struct modem_state *)iter->data;
		size_t path_size = sizeof(DBUS_TELEPHONY_DEFAULT_PATH) + strlen(modem->name) + 2;

		modem->path = (char *)malloc(path_size);
		snprintf(modem->path, path_size, "%s/%s", DBUS_TELEPHONY_DEFAULT_PATH, modem->name);
		ret = register_edbus_signal_handler(modem->path,
			DBUS_TELEPHONY_SIM_INTERFACE,
			DBUS_TELEPHONY_STATUS,
			edbus_sim_status_changed, modem);
		if (ret != RESOURCED_ERROR_NONE) {
			_E("Could not register edbus path %s", modem->path);
			modem->path = NULL;
			continue;
		}
	}
}

static void init_telephony(void)
{
	if (!modems) {
		init_available_modems();
		init_roaming_states();
		init_modem_imsi();
		init_protocols();
		regist_telephony_callbacks();
		regist_sim_status_callbacks();
	}
}

resourced_roaming_type get_current_roaming(void)
{
	init_telephony(); /* one time lazy initialization */
	ret_value_msg_if(!current_modem, RESOURCED_ROAMING_UNKNOWN,
		"There is no current modem!");

	return current_modem->roaming ? RESOURCED_ROAMING_ENABLE:
		RESOURCED_ROAMING_DISABLE;
}

char *get_imsi_hash(char *imsi)
{
	GSList *iter;

	if (!imsi) {
		_E("imsi is NULL");
		return NULL;
	}

	gslist_for_each_item(iter, modems) {
		struct modem_state *modem = (struct modem_state *)iter->data;
		if (modem->imsi == NULL)
			continue;
		if(!strcmp(imsi, modem->imsi))
			return modem->imsi_hash;
	}
	return NULL;
}

char *get_current_modem_imsi(void)
{
	init_telephony(); /* one time lazy initialization */
	ret_value_msg_if(current_modem == NULL, NULL, "Current modem isn't " \
			"selected");

	return current_modem->imsi;
}

bool check_event_in_current_modem(const char *imsi_hash,
		const resourced_iface_type iftype)
{
	char *current_imsi_hash;
	if (iftype != RESOURCED_IFACE_DATACALL)
		return false;

	current_imsi_hash = get_imsi_hash(get_current_modem_imsi());
	/* if we don't have current_imsi_hash
	 * do everything as before */
	return (current_imsi_hash && imsi_hash) ?
			strcmp(imsi_hash, current_imsi_hash) : false;
}

static void modem_free(gpointer data)
{
	struct modem_state *modem = (struct modem_state *)data;
	if (modem->imsi)
		free(modem->imsi);
	if (modem->name)
		free(modem->name);
	if (modem->path)
		free(modem->path);
}

resourced_hw_net_protocol_type get_current_protocol(resourced_iface_type iftype)
{
	if (iftype != RESOURCED_IFACE_DATACALL)
		return RESOURCED_PROTOCOL_NONE;

	init_telephony();
	ret_value_msg_if(current_modem == NULL, RESOURCED_PROTOCOL_NONE,
			 "Current modem isn't selected");

	return current_modem->protocol;
}

void finilize_telephony(void)
{
	g_slist_free_full(modems, modem_free);
	vconf_ignore_key_changed(VCONF_TELEPHONY_DEFAULT_DATA_SERVICE,
				 default_data_service_change_cb);

}

