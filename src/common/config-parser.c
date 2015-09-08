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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "trace.h"
#include "config-parser.h"

#define MAX_LINE	128
#define MAX_SECTION	64
#define WHITESPACE	" \t"
#define NEWLINE		"\n\r"
#define COMMENT		'#'

static inline char *trim_str(char *s)
{
	char *t;
	/* left trim */
	s += strspn(s, WHITESPACE);

	/* right trim */
	for (t = strchr(s, 0); t > s; t--)
		if (!strchr(WHITESPACE, t[-1]))
			break;
	*t = 0;
	return s;
}

int config_parse(const char *file_name, int cb(struct parse_result *result,
    void *user_data), void *user_data)
{
	FILE *f = NULL;
	struct parse_result result;
	/* use stack for parsing */
	char line[MAX_LINE];
	char section[MAX_SECTION];
	char *start, *end, *name, *value;
	int lineno = 0, ret = 0;

	if (!file_name || !cb) {
		ret = -EINVAL;
		goto error;
	}

	/* open conf file */
	f = fopen(file_name, "r");
	if (!f) {
		_E("Failed to open file %s", file_name);
		ret = -EIO;
		goto error;
	}

	/* parsing line by line */
	while (fgets(line, MAX_LINE, f) != NULL) {
		lineno++;

		start = line;
		start[strcspn(start, NEWLINE)] = '\0';
		start = trim_str(start);

		if (*start == COMMENT) {
			continue;
		} else if (*start == '[') {
			/* parse section */
			end = strchr(start, ']');
			if (!end || *end != ']') {
				ret = -EBADMSG;
				goto error;
			}

			*end = '\0';
			strncpy(section, start + 1, sizeof(section));
			section[MAX_SECTION-1] = '\0';
		} else if (*start) {
			/* parse name & value */
			end = strchr(start, '=');
			if (!end || *end != '=') {
				ret = -EBADMSG;
				goto error;
			}
			*end = '\0';
			name = trim_str(start);
			value = trim_str(end + 1);
			end = strchr(value, COMMENT);
			if (end && *end == COMMENT) {
				*end = '\0';
				value = trim_str(value);
			}

			result.section = section;
			result.name = name;
			result.value = value;
			/* callback with parse result */
			ret = cb(&result, user_data);
			if (ret < 0) {
				ret = -EBADMSG;
				goto error;
			}
		}
	}
	_D("Success to load %s", file_name);
	fclose(f);
	return 0;

error:
	if (f)
		fclose(f);
	_E("Failed to read %s:%d!", file_name, lineno);
	return ret;
}

