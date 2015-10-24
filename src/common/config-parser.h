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

#include <stdio.h>
#include <stdbool.h>

#define MATCH(a, b)	(!strncmp(a, b, strlen(a)))
#define SET_CONF(a, b)	(a = (b > 0.0 ? b : a))

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

/* Prototype for a parser for a specific configuration setting */
typedef int (*ConfigParserCallback)(
		const char *filename,
		unsigned line,
		const char *section,
		const char *lvalue,
		int ltype,
		const char *rvalue,
		void *data);

typedef int (*ConfigParseFunc)(const char *path, void *data);

/* Wraps information for parsing a specific configuration variable, to
 * be stored in a simple array */
typedef struct ConfigTableItem {
	const char *section;		/* Section */
	const char *lvalue;		/* Name of the variable */
	ConfigParserCallback cb;	/* Function that is called to
					 * parse the variable's
					 * value */
	int ltype;			/* Distinguish different
					 * variables passed to the
					 * same callback */
	void *data;			/* Where to store the
					 * variable's data */
} ConfigTableItem;

int config_parse_new(const char *filename, void *table);
int config_parse_dir(const char *dir, ConfigParseFunc fp, void *data);

int config_parse_bool(const char *filename, unsigned line, const char *section, const char *lvalue, int ltype, const char *rvalue, void *data);
int config_parse_int(const char *filename, unsigned line, const char *section, const char *lvalue, int ltype, const char *rvalue, void *data);
int config_parse_string(const char *filename, unsigned line, const char *section, const char *lvalue, int ltype, const char *rvalue, void *data);
int config_parse_bytes(const char *filename, unsigned line, const char *section, const char *lvalue, int ltype, const char *rvalue, void *data);
int config_parse_strv(const char *filename, unsigned line, const char *section, const char *lvalue, int ltype, const char *rvalue, void *data);
#endif

