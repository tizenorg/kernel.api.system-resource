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

/**
 * @file filemap-helper.h
 * @desc filemap structure and functions
 **/

#ifndef __FILEMAP_HELPER_H_
#define __FILEMAP_HELPER_H__

#define FILEMAP_DEFAULT_SIZE
#define FILEMAP_MAX_KEY_LEN	1024
#define FILEMAP_MAX_VALUE_LEN	1024

struct filemap {
	unsigned byte_used;
	unsigned filemap_size;
	unsigned filemap_data_size;
	unsigned root;	//start of the root in the map
};

struct filemap_info {
	unsigned keylen;
	char value[FILEMAP_MAX_VALUE_LEN];
	char key[FILEMAP_MAX_KEY_LEN];
};

struct filemap_node {
	unsigned keylen;
	unsigned info;
	unsigned left;
	unsigned right;
	unsigned children;
	char key[FILEMAP_MAX_KEY_LEN];
};

int filemap_new(struct filemap **fm, const char *fname, int size, int check_exist);
void filemap_destroy(struct filemap *fm);
int filemap_write(struct filemap *fm, const char *key, const char *value,
	unsigned *offset);
int filemap_foreach_read(struct filemap *fm, struct filemap_node *fn,
	void (*callbackfn)(const struct filemap_info *fi));
struct filemap_node *filemap_root_node(struct filemap *fm);

#endif /*__FILEMAP_HELPER_H__*/
