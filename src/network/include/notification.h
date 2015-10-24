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
 */


/*
 * @file notification.h
 *
 * @desc Notification specific functions
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#ifndef _RESOURCED_DATAUSAGE_NOTIFICATION_H
#define _RESOURCED_DATAUSAGE_NOTIFICATION_H

#include "data_usage.h"

/* NOTI. */
#define WARNING_NOTI_ON     "WarningNotiOn"
#define WARNING_NOTI_OFF    "WarningNotiOff"
#define DISABLE_NOTI_ON     "DisabledNotiOn"
#define DISABLE_NOTI_OFF    "DisabledNotiOff"


/* POPUP */
#define POPUP_KEY               "_SYSPOPUP_CONTENT_"
#define POPUP_KEY_LIMIT         "_DATAUSAGE_LIMIT_"
#define POPUP_VALUE_DISABLED    "datausage_disabled"
#define POPUP_VALUE_WARNING     "datausage_warning"
#define METHOD_CALL_POPUP       "DatausagePopupLaunch"

enum noti_type {
	WARNING_NOTI,
	DISABLE_NOTI,
};

void check_and_clear_all_noti(void);
void send_restriction_notification(const char *appid, data_usage_quota *du_quota);
void send_restriction_warn_notification(const char *appid, data_usage_quota *du_quota);

#endif /* _RESOURCED_DATAUSAGE_NOTIFICATION_H */
