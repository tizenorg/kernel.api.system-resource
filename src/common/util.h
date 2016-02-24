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

#define _cleanup_(x) __attribute__((cleanup(x)))

static inline void freep(void *p)
{
	free(*(void **) p);
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

static inline bool is_empty(const char *p)
{
        return !p || !p[0];
}

#endif
