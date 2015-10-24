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
#include <assert.h>
#include <limits.h>

#include "util.h"
#include "trace.h"
#include "config-parser.h"

#define MAX_SECTION	64

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
	char line[LINE_MAX];
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
	while (fgets(line, LINE_MAX, f) != NULL) {
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
			strncpy(section, start + 1, sizeof(section)-1);
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

static int config_table_lookup(void *table,
			       const char *section,
			       const char *lvalue,
			       ConfigParserCallback *func,
			       int *ltype,
			       void **data)
{
	ConfigTableItem *t;

	assert(table);
	assert(lvalue);
	assert(func);
	assert(ltype);
	assert(data);

	for (t = table; t->lvalue; t++) {

		if (!streq(lvalue, t->lvalue))
			continue;

		if (!streq_ptr(section, t->section))
			continue;

		*func = t->cb;
		*ltype = t->ltype;
		*data = t->data;
		return 1;
	}

	return 0;
}

/* Run the user supplied parser for an assignment */
static int config_parse_table(const char *filename,
			      unsigned line,
			      void *table,
			      const char *section,
			      const char *lvalue,
			      const char *rvalue)
{
	ConfigParserCallback cb = NULL;
	int ltype = 0;
	void *data = NULL;
	int r;

	assert(filename);
	assert(section);
	assert(lvalue);
	assert(rvalue);

	r = config_table_lookup(table,
				section,
				lvalue,
				&cb,
				&ltype,
				&data);
	if (r <= 0)
		return r;

	if (cb)
		return cb(filename,
			  line,
			  section,
			  lvalue,
			  ltype,
			  rvalue,
			  data);

	return 0;
}

int config_parse_new(const char *filename, void *table)
{
	_cleanup_fclose_ FILE *f = NULL;
	char *sections[MAX_SECTION] = { 0 };
	char *section = NULL, *n, *e, l[LINE_MAX];
	size_t len;
	int i, r, num_section = 0;
	bool already;
	unsigned line = 0;

	assert(filename);

	f = fopen(filename, "r");
	if (!f) {
		_E("Failed to open file %s", filename);
		return -errno;
	}

	while (!feof(f)) {
		_cleanup_free_ char *lvalue = NULL, *rvalue = NULL;
		char *rs = NULL;

		if (fgets(l, LINE_MAX, f) == NULL) {
			if (feof(f))
				break;

			_E("Failed to parse configuration file '%s': %m", filename);
			r = -errno;
			goto finish;
		}

		line++;
		truncate_nl(l);

		if (strchr(COMMENTS NEWLINE, *l))
			continue;

		if (*l == '[') {
			len = strlen(l);
			if (l[len-1] != ']') {
				_E("Error: Invalid section header: %s", l);
				r = -EBADMSG;
				goto finish;
			}

			n = strndup(l+1, len-2);
			if (!n) {
				r = -ENOMEM;
				goto finish;
			}

			already = false;
			for (i = 0; i < num_section; i++) {
				if (streq(n, sections[i])) {
					section = sections[i];
					already = true;
					free(n);
					break;
				}
			}

			if (already)
				continue;

			section = n;
			sections[num_section] = n;
			num_section++;
			if (num_section > MAX_SECTION) {
				_E("Error: max number of section reached: %d", num_section);
				r = -EOVERFLOW;
				goto finish;
			}

			continue;
		}

		if (!section)
			continue;

		e = strchr(l, '=');
		if (e == NULL) {
			_D("Warning: config: no '=' character in line '%s'.", l);
			continue;
		}

		lvalue = strndup(l, e-l);
		strstrip(lvalue);

		rs = strstrip(e+1);
		rvalue = strndup(rs, strlen(rs));
		strstrip(rvalue);

		r = config_parse_table(filename,
				       line,
				       table,
				       section,
				       lvalue,
				       rvalue);
		if (r < 0)
			goto finish;
	}

	r = 0;

finish:
	for (i=0; i<num_section; i++)
		if (sections[i])
			free(sections[i]);

	return r;
}

int config_parse_dir(const char *dir, ConfigParseFunc fp, void *data)
{
	_cleanup_closedir_ DIR *d = NULL;
	struct dirent de;
	struct dirent *result;

	d = opendir(dir);
	if (!d) {
		_E("Failed to open dir: %s", dir);
		return errno;
	}

	FOREACH_DIRENT(de, d, result, return -errno) {
		_cleanup_free_ char *path = NULL;
		int r;

		if (de.d_type != DT_REG)
			continue;

		r = asprintf(&path, "%s/%s", dir, de.d_name);
		if (r < 0)
			return -ENOMEM;

		r = fp(path, data);
		/* Do not just break loop until parse all file of
		 * dir. Just only put log */
		if (r < 0)
			_D("Failed to parse config: %s", de.d_name);
	}

	return 0;
}

int config_parse_bool(const char *filename,
		      unsigned line,
		      const char *section,
		      const char *lvalue,
		      int ltype,
		      const char *rvalue,
		      void *data)
{
	int k;
	bool *b = data;

	assert(filename);
	assert(lvalue);
	assert(rvalue);
	assert(data);

	k = parse_boolean(rvalue);
	if (k < 0) {
		_E("Failed to parse boolean value, ignoring: %s", rvalue);
		return 0;
	}

	*b = !!k;

	return 0;
}


int config_parse_int(const char *filename,
		     unsigned line,
		     const char *section,
		     const char *lvalue,
		     int ltype,
		     const char *rvalue,
		     void *data)
{
	int *i = data;

	assert(filename);
	assert(lvalue);
	assert(rvalue);
	assert(data);

	*i = atoi(rvalue);

	return 0;
}

int config_parse_string(const char *filename,
			unsigned line,
			const char *section,
			const char *lvalue,
			int ltype,
			const char *rvalue,
			void *data)
{
	char **s = data, *n;

	assert(filename);
	assert(lvalue);
	assert(rvalue);
	assert(data);

	if (is_empty(rvalue))
		n = NULL;
	else {
		n = strndup(rvalue, strlen(rvalue));
		if (!n)
			return -ENOMEM;
	}

	free(*s);
	*s = n;

	return 0;
}

int config_parse_bytes(const char *filename,
		       unsigned line,
		       const char *section,
		       const char *lvalue,
		       int ltype,
		       const char *rvalue,
		       void *data)
{
	size_t *s = data;
	int r;

	assert(filename);
	assert(lvalue);
	assert(rvalue);
	assert(data);

	if (is_empty(rvalue))
		*s = 0;
	else {
		r = parse_bytes(rvalue, s);
		if (r < 0)
			return r;
	}

	return 0;
}

int config_parse_strv(const char *filename,
		      unsigned line,
		      const char *section,
		      const char *lvalue,
		      int ltype,
		      const char *rvalue,
		      void *data)
{
	char ***strv = data;
	char **o = NULL, **v = NULL, **vv = NULL;
	int r;

	assert(filename);
	assert(lvalue);
	assert(rvalue);
	assert(data);

	if (is_empty(rvalue))
		return 0;

	r = str_to_strv(rvalue, &v, WHITESPACE);
	if (r < 0)
		return r;

	o = *strv;

	r = strv_attach(o, v, &vv, true);
	if (r < 0)
		return r;

	*strv = vv;

	return 0;
}
