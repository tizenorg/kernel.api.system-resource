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

#define BUF_MAX         (BUFSIZ)
#define BUF_INC_SIZE    (512 * 1024)
#define KB(bytes)       ((bytes)/1024)

resourced_ret_c fwrite_str(const char *path, const char *str)
{
	FILE *f;
	int ret;

	ret_value_msg_if(!path, RESOURCED_ERROR_INVALID_PARAMETER,
			 "please provide valid name file!\n");
	ret_value_msg_if(!str, RESOURCED_ERROR_INVALID_PARAMETER,
			 "please provide valid string!\n");

	f = fopen(path, "w");
	ret_value_errno_msg_if(!f, RESOURCED_ERROR_FAIL, "Fail to file open");

	ret = fputs(str, f);
	fclose(f);
	ret_value_errno_msg_if(ret == EOF, RESOURCED_ERROR_FAIL,
			       "Fail to write file\n");

	return RESOURCED_ERROR_NONE;
}

resourced_ret_c fwrite_int(const char *path, const int number)
{
	char digit_buf[MAX_DEC_SIZE(int)];
	int ret;

	ret = sprintf(digit_buf, "%d", number);
	ret_value_errno_msg_if(ret < 0, RESOURCED_ERROR_FAIL,
			       "sprintf failed\n");

	return fwrite_str(path, digit_buf);
}

resourced_ret_c fwrite_uint(const char *path, const u_int32_t number)
{
	char digit_buf[MAX_DEC_SIZE(u_int32_t)];
	int ret;

	ret = sprintf(digit_buf, "%u", number);
	ret_value_errno_msg_if(ret < 0, RESOURCED_ERROR_FAIL,
			       "sprintf failed\n");

	return fwrite_str(path, digit_buf);
}

resourced_ret_c fread_int(const char *path, u_int32_t *number)
{
	FILE *f;
	int ret;

	f = fopen(path, "r");

	ret_value_errno_msg_if(!f, RESOURCED_ERROR_FAIL, "Fail to open file");

	ret = fscanf(f, "%u", number);
	fclose(f);
	ret_value_errno_msg_if(ret == EOF, RESOURCED_ERROR_FAIL,
			       "Fail to read file\n");

	return RESOURCED_ERROR_NONE;
}

resourced_ret_c fwrite_array(const char *path, const void *array,
			     const size_t size_of_elem,
			     const size_t numb_of_elem)
{
	FILE *f;
	int ret;

	ret_value_msg_if(!array, RESOURCED_ERROR_INVALID_PARAMETER,
			 "please provide valid array of elements!\n");

	f = fopen(path, "w");

	ret_value_errno_msg_if(!f, RESOURCED_ERROR_FAIL,
			       "Failed open %s file\n", path);

	ret = fwrite(array, size_of_elem, numb_of_elem, f);
	fclose(f);
	ret_value_errno_msg_if(ret != numb_of_elem, RESOURCED_ERROR_FAIL,
			       "Failed write array into %s file\n");

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
	int	fd  = open(path, O_RDONLY);

	if (fd < 0) {
		_E("%s open error", path);
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
		}
	} while (ret > 0);
	close(fd);

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
