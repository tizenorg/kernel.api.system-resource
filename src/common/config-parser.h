/*
 * resourced
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __CONFIG_PARSER_H__
#define __CONFIG_PARSER_H__

struct parse_result {
	char *section;
	char *name;
	char *value;
};

/**
 * @brief Parse config file and call callback\n
 * @param[in] file_name conf file.
 * @param[in] cb cb is called when conf file is parsed line by line.
 * @param[in] user_data user data is passed to cb.
 * @return 0 on success, negative if failed
 */
int config_parse(const char *file_name, int cb(struct parse_result *result,
    void *user_data), void *user_data);

#endif

