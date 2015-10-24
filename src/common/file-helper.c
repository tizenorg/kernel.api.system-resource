/*
 * resourced
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file file-helper.c
 * @desc Helper functions for working with files
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "file-helper.h"
#include "trace.h"
#include "macro.h"
#include "util.h"

#define BUF_MAX		(BUFSIZ)
#define BUF_INC_SIZE	(512 << 10)

int fwrite_str(const char *path, const char *str)
{
	_cleanup_fclose_ FILE *f = NULL;
	int ret;

	assert(path);
	assert(str);

	f = fopen(path, "w");
	ret_value_errno_msg_if(!f, -errno,
			       "Fail to open file %s", path);

	ret = fputs(str, f);
	ret_value_errno_msg_if(ret == EOF, errno ? -errno : -EIO,
			       "Fail to write file");

	return RESOURCED_ERROR_NONE;
}

int fwrite_int(const char *path, const int number)
{
	_cleanup_free_ char *digit_buf = NULL;
	int ret;

	ret = asprintf(&digit_buf, "%d", number);
	ret_value_errno_msg_if(ret < 0, -ENOMEM,
			       "sprintf failed\n");

	return fwrite_str(path, digit_buf);
}

int fwrite_uint(const char *path, const u_int32_t number)
{
	_cleanup_free_ char *digit_buf = NULL;
	int ret;

	ret = asprintf(&digit_buf, "%d", number);
	ret_value_errno_msg_if(ret < 0, -ENOMEM,
			       "sprintf failed\n");

	return fwrite_str(path, digit_buf);
}

int fread_int(const char *path, int32_t *number)
{
	_cleanup_fclose_ FILE *f = NULL;
	int ret;

	f = fopen(path, "r");
	ret_value_errno_msg_if(!f, -errno,
			       "Fail to open  %s file.", path);

	ret = fscanf(f, "%d", number);
	ret_value_errno_msg_if(ret == EOF, -errno,
			       "Fail to read file\n");

	return RESOURCED_ERROR_NONE;
}

int fread_uint(const char *path, u_int32_t *number)
{
	_cleanup_fclose_ FILE *f = NULL;
	int ret;

	f = fopen(path, "r");
	ret_value_errno_msg_if(!f, -errno,
			       "Fail to open %s file.", path);

	ret = fscanf(f, "%u", number);
	ret_value_errno_msg_if(ret == EOF, -errno,
			       "Fail to read file\n");

	return RESOURCED_ERROR_NONE;
}

int fwrite_array(const char *path, const void *array,
		 const size_t size_of_elem,
		 const size_t numb_of_elem)
{
	_cleanup_fclose_ FILE *f = NULL;
	int ret;

	assert(path);
	assert(array);

	f = fopen(path, "w");
	ret_value_errno_msg_if(!f, -errno,
			       "Failed open %s file", path);

	ret = fwrite(array, size_of_elem, numb_of_elem, f);
	ret_value_errno_msg_if(ret != numb_of_elem, -errno,
			       "Failed write array into %s file", path);

	return RESOURCED_ERROR_NONE;
}

/* reads file contents into memory */
char* cread(const char* path)
{
	char*	text = NULL;
	size_t	size = 0;

	ssize_t	ret;
	char*	ptr = text;
	size_t	cap = size;
	_cleanup_close_ int fd = -1;

	assert(path);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		_E("Failed to open %s: %m", path);
		return NULL;
	}

	do {
		/* ensure we have enough space */
		if (cap == 0) {
			ptr = (char*)realloc(text, size + BUF_INC_SIZE);
			if (ptr == NULL) {
				ret = -1;
				break;
			}

			text  = ptr;
			ptr   = text + size;
			cap   = BUF_INC_SIZE;
			size += BUF_INC_SIZE;
		}
		ret = read(fd, ptr, cap);
		if (ret == 0) {
			*ptr = 0;
		} else if (ret > 0) {
			cap -= ret;
			ptr += ret;
		} else
			free(text);
	} while (ret > 0);

	return (ret < 0 ? NULL : text);
}

/* like fgets/gets but adjusting contents pointer */
char* cgets(char** contents)
{
	if (contents && *contents && **contents) {
		char* bos = *contents;		/* begin of string */
		char* eos = strchr(bos, '\n');	/* end of string   */

		if (eos) {
			*contents = eos + 1;
			*eos      = 0;
		} else {
			*contents = NULL;
		}

		return bos;
	}

	return NULL;
}

int copy_file(char *dest, char *src)
{
	_cleanup_fclose_ FILE *fps = NULL;
	_cleanup_fclose_ FILE *fpd = NULL;
	char buf[BUF_MAX];
	size_t size;

	fps = fopen(src, "rb");
	if (fps == NULL) {
		_E("Failed to open src file '%s': %m", src);
		return -errno;
	}

	fpd = fopen(dest, "wb");
	if (fpd == NULL) {
		_E("Failed to open dest file '%s': %m", dest);
		return -errno;
	}

	while ((size = fread(buf, 1, BUF_MAX, fps))) {
		fwrite(buf, 1, size, fpd);
	}

	return RESOURCED_ERROR_NONE;
}
