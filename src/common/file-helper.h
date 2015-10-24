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
 * @file file-helper.h
 * @desc Helper functions for working with files
 */

#ifndef _RESOURCED_FILE_HELPER_H_
#define _RESOURCED_FILE_HELPER_H_

#include "resourced.h"

/**
 * @desc write string to the file
 * @param path - path to the file, str - string is written to the file
 * @return negative value if error
 */
int fwrite_str(const char *path, const char *str);

int fwrite_int(const char *path, const int number);

int fwrite_uint(const char *path, const u_int32_t number);

int fread_int(const char *path, int32_t *number);

int fread_uint(const char *path, u_int32_t *number);

int fwrite_array(const char *path, const void *array,
		 const size_t size_of_elem,
		 const size_t numb_of_elem);

char *cread(const char *path);
char *cgets(char **contents);

/**
 * @desc copy file from src to dest
 * @param dest- destination file path, src- source file path
 * @return negative value if error
 */
int copy_file(char *dest, char *src);

#endif  /*_RESOURCED_FILE_HELPER_H_*/
