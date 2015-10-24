/*
 * resourced
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
 * @file telephony.h
 *
 * @desc Roaming persistent object. Due roaming changes not so often we can keep it in
 *  our memory and handle roaming changes.
 */

#ifndef __RESOURCED_TELEPHONY_H
#define __RESOURCED_TELEPHONY_H

#include <stdbool.h>
#include "data_usage.h"

#define VCONF_TELEPHONY_DEFAULT_DATA_SERVICE "db/telephony/dualsim/default_data_service"

resourced_roaming_type get_current_roaming(void);
resourced_hw_net_protocol_type get_current_protocol(resourced_iface_type iftype);

/**
 * @brief Get international mobile subscriber identity from saved list for current modem
 */
char *get_current_modem_imsi(void);
char *get_imsi_hash(char *imsi);
bool check_event_in_current_modem(const char *imsi_hash,
		const resourced_iface_type iftype);

void finilize_telephony(void);

#endif /* __RESOURCED_TELEPHONY_H */
