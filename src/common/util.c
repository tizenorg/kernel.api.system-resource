/*
 * resourced
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
 *  @file: util.c
 *  @desc: Generic Helper functions
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

#include "util.h"
#include "trace.h"
#include "resourced.h"

int exec_cmd(char *argv[], char *filename)
{
	int status = 0;
	int fd = -1;

	if (fork() == 0) {
		fd= open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
		if (fd < 0) {
			_E("Failed to create/open file %s", filename);
			return RESOURCED_ERROR_FAIL;
		}
		dup2(fd, 1);
		status = execvp(argv[0], argv);
		close(fd);
	}
	return status;
}

bool streq_ptr(const char *a, const char *b)
{

	/* Like streq(), but tries to make sense of NULL pointers */

	if (a && b)
		return streq(a, b);

	if (!a && !b)
		return true;

	return false;
}

int parse_boolean(const char *v)
{
	assert(v);

	if (streq(v, "1") || v[0] == 'y' || v[0] == 'Y' || v[0] == 't' || v[0] == 'T' ||
	    strcaseeq(v, "on") || strcaseeq(v, "enable") || strcaseeq(v, "enabled"))
		return 1;
	else if (streq(v, "0") || v[0] == 'n' || v[0] == 'N' || v[0] == 'f' || v[0] == 'F' ||
		 strcaseeq(v, "off") || strcaseeq(v, "disable") || strcaseeq(v, "disabled"))
		return 0;

	return -EINVAL;
}

int parse_bytes(const char *b, size_t *s)
{
	_cleanup_free_ char *num = NULL;
	size_t len;

	assert(b);

	len = strlen(b);

	if (!len)
		return 0;

	num = strndup(b, len - 1);
	if (!num)
		return -ENOMEM;

	switch (b[len - 1]) {
	case 'B':
		*s = atoi(num);
		break;
	case 'K':
		*s = atoi(num) << 10;
		break;
	case 'M':
		*s = atoi(num) << 20;
		break;
	case 'G':
		*s = atoi(num) << 30;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/* Split a string into words. */
char *split(const char *c, size_t *l, const char *separator, char **state) {
        char *current;

        current = *state ? *state : (char*) c;

        if (!*current || *c == 0)
                return NULL;

        current += strspn(current, separator);
        *l = strcspn(current, separator);
        *state = current+*l;

        return (char*) current;
}

char *truncate_nl(char *s)
{
	assert(s);

	s[strcspn(s, NEWLINE)] = 0;

	return s;
}

char *strstrip(char *s)
{
	char *e;

	/* Drops trailing whitespace. Modifies the string in
	 * place. Returns pointer to first non-space character */

	s += strspn(s, WHITESPACE);

	for (e = strchr(s, 0); e > s; e --)
		if (!strchr(WHITESPACE, e[-1]))
			break;

	*e = 0;

	return s;
}

int str_to_strv(const char *str, char ***strv, const char *seperator)
{
        char *w, *state, *p;
	char **v = NULL, **new = NULL;
        size_t l;
	size_t i = 0;

	FOREACH_WORD_SEPARATOR(w, l, str, seperator, state) {
		p = strndup(w, l);
		if (!p) {
			if (v)
				free(v);
			return -ENOMEM;
		}

		new = (char **)realloc(v, sizeof(char *) * (i + 2));
		if (!new) {
			free(p);
			p = NULL;
			return -ENOMEM;
		}

		v = new;

		v[i] = p;
		v[i+1] = NULL;
		i++;
	}

	*strv = v;

	return 0;
}

size_t sizeof_strv(const char **strv)
{
	size_t u = 0;

	assert(strv);

	while(strv[u++])
		;

	return u - 1;
}

int strv_attach(char **first, char **second, char ***strv, bool free_second)
{
	char **new = NULL;
	size_t n1 = 0, n2 = 0;

	assert(strv);

	if (first)
		n1 = sizeof_strv((const char **)first);

	if (second) {
		n2 = sizeof_strv((const char **)second);

		new = (char **)realloc(first, sizeof(char *) * (n1 + n2 + 1));
		if (!new)
			return -ENOMEM;

		first = new;

		memcpy(first + n1, second, sizeof(char *) * (n2 + 1));

		if (free_second)
			free(second);
	}

	*strv = first;

	return 0;
}

void strv_free_full(char **strv)
{
	char **s;

	if (!strv)
		return;

	FOREACH_STRV(s, strv) {
		if (s && *s) {
			free(*s);
			*s = NULL;
		}
	}

	free(strv);
	strv = NULL;
}
