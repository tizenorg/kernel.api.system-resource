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
 *
*/

/*
 * @file util.h
 * @desc Generic Helper functions
 */

#ifndef _RESOURCED_UTIL_H_
#define _RESOURCED_UTIL_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <dirent.h>

#define COMMENT		'#'
#define COMMENTS	"#;"
#define NEWLINE		"\n\r"
#define WHITESPACE	" \t\n\r"

#define _pure_ __attribute__ ((pure))
#define _cleanup_(x) __attribute__((cleanup(x)))

static inline void freep(void *p)
{
	free(*(void**) p);
}

static inline void closep(int *fd)
{
	if (*fd >= 0)
		close(*fd);
}

static inline void fclosep(FILE **f)
{
	if (*f)
		fclose(*f);
}

static inline void closedirp(DIR **d)
{
	if (*d)
		closedir(*d);
}

#define _cleanup_free_ _cleanup_(freep)
#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_fclose_ _cleanup_(fclosep)
#define _cleanup_closedir_ _cleanup_(closedirp)

#define NUM_DIFF(x, y) ((x > y) ? (x - y) : (y -x))

#define BYTE_TO_KBYTE(b) (b >> 10)
#define BYTE_TO_MBYTE(b) (b >> 20)
#define BYTE_TO_GBYTE(b) (b >> 30)

#define KBYTE_TO_BYTE(k) (k << 10)
#define KBYTE_TO_MBYTE(k) (k >> 10)
#define KBYTE_TO_GBYTE(k) (k >> 20)

#define GBYTE_TO_BYTE(g) (g << 30)
#define GBYTE_TO_KBYTE(g) (g << 20)
#define GBYTE_TO_MBYTE(g) (g << 10)

#define streq(a,b) (strcmp((a),(b)) == 0)
#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)
#define strcaseeq(a,b) (strcasecmp((a),(b)) == 0)
#define strncaseeq(a, b, n) (strncasecmp((a), (b), (n)) == 0)

#define new(t, n) ((t*) malloc(sizeof(t) * (n)))
#define new0(t, n) ((t*) calloc((n), sizeof(t)))
#define malloc0(n) (calloc((n), 1))

static inline bool is_empty(const char *p)
{
	return !p || !p[0];
}

#define FOREACH_WORD_SEPARATOR(word, length, s, separator, state)       \
        for ((state) = NULL, (word) = split((s), &(length), (separator), &(state)); \
	     (word);							\
	     (word) = split((s), &(length), (separator), &(state)))

#define FOREACH_WORD(word, length, s, state)                            \
        FOREACH_WORD_SEPARATOR(word, length, s, WHITESPACE, state)

#define FOREACH_DIRENT(de, d, result, on_error)						\
	for (errno  = readdir_r(d, &de, &result);; errno = readdir_r(d, &de, &result))	\
		if (errno || !result) {							\
			if (errno)							\
				on_error;						\
			break;								\
		} else if (streq(de.d_name, ".") ||					\
			   streq(de.d_name, ".."))					\
			continue;							\
		else

#define FOREACH_STRV(s, l)                      \
        for ((s) = (l); (s) && *(s); (s)++)

/**
 * @desc executes given command and dumps output to a file
 * @param argv - command to be executed with parameters
 filename - output file
 * @return None
 */
int exec_cmd(char *argv[], char *filename);

bool streq_ptr(const char *a, const char *b) _pure_;
int parse_boolean(const char *v) _pure_;
int parse_bytes(const char *b, size_t *s) _pure_;
char *split(const char *c, size_t *l, const char *separator, char **state);
char *truncate_nl(char *s);
char *strstrip(char *s);
int str_to_strv(const char *str, char ***strv, const char *seperator);
size_t sizeof_strv(const char **strv);
int strv_attach(char **first, char **second, char ***strv, bool free_second);
void strv_free_full(char **strv);
#endif /*_RESOURCED_UTIL_H_*/
