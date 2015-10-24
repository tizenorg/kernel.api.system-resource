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
 * @file filemap-helper.c
 *
 * @desc filemap for storing (key, value) based on tree
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

#include "const.h"
#include "heart.h"
#include "resourced.h"
#include "trace.h"
#include "macro.h"
#include "filemap.h"

static int filemap_exist(const char *fname)
{
	FILE *fp;

	fp = fopen(fname, "r");

	if (!fp)
		return RESOURCED_ERROR_FAIL;

	fclose(fp);
	return RESOURCED_ERROR_NONE;
}

int filemap_new(struct filemap **fm, const char *fname,
			int size, int check_exist)
{
	int exist = -1;
	int fd;

	assert(fm);

	/*
	 * when filemap already exists and caller wants to
	 * keep contents previously stored in the filemap by
	 * calling with check_exist set, check if there is
	 * filemap with path before it tries to open it.
	 */
	if (check_exist)
		exist = filemap_exist(fname);

	fd = open(fname, O_RDWR | O_CREAT, 0400);

	if (fd < 0) {
		_E("%s open error %d", fname, errno);
		return RESOURCED_ERROR_FAIL;
	}

	if (ftruncate(fd, size) < 0) {
		_E("%s ftruncate failed", fname);
		close(fd);
		return RESOURCED_ERROR_FAIL;
	}

	*fm = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
			fd, 0);

	if (*fm == MAP_FAILED) {
		_E("%s mmap failed", fname);
		close(fd);
		return RESOURCED_ERROR_FAIL;
	}

	(*fm)->filemap_size = size;
	(*fm)->filemap_data_size = size - sizeof(struct filemap);
	/* root start right after filemap */
	(*fm)->root = sizeof(struct filemap);

	/*
	 * allocate node for root and set byte_used after root.
	 * when filemap exists already and check_exit is set,
	 * we use byte_used value stored in existing filemap.
	 */
	if (exist < 0) {
		_D("filemap does not exist");
		(*fm)->byte_used = sizeof(struct filemap_node);
	}

	close(fd);

	return RESOURCED_ERROR_NONE;
}

void filemap_destroy(struct filemap *fm)
{
	assert(fm);
	munmap(fm, fm->filemap_size);
}

static void *filemap_obj_alloc(struct filemap *fm, size_t size, unsigned *off)
{

	if (fm->byte_used + size > fm->filemap_data_size) {
		_E("filemap_data_size is exceeded");
		return NULL;
	}

	*off = fm->byte_used;
	fm->byte_used += size;

	return fm + fm->root + *off;
}

static struct filemap_node *filemap_node_init(void *start, const char *key,
					unsigned keylen)
{
	struct filemap_node *fn = start;

	assert(keylen < FILEMAP_MAX_KEY_LEN - 1);
	assert(start);

	fn->keylen = keylen;
	strncpy(fn->key, key, keylen + 1);

	return fn;
}

static struct filemap_info *filemap_info_init(void *start, const char *key,
					unsigned keylen, const char *value,
					unsigned valuelen)
{
	struct filemap_info *fi = start;

	assert(start);
	assert(keylen < FILEMAP_MAX_KEY_LEN - 1);
	assert(valuelen < FILEMAP_MAX_VALUE_LEN - 1);

	fi->keylen = keylen;
	strncpy(fi->key, key, keylen + 1);
	strncpy(fi->value, value, valuelen + 1);

	return fi;
}

static struct filemap_node *filemap_node_new(struct filemap *fm, const char *key,
					unsigned keylen, unsigned *off)
{
	struct filemap_node *fn;
	unsigned offset;
	void *p;

	p = filemap_obj_alloc(fm, sizeof(struct filemap_node), &offset);

	if (!p) {
		_E("fail to allocate filemap_node");
		return NULL;
	}

	fn = filemap_node_init(p, key, keylen);
	*off = offset;

	return fn;
}

static struct filemap_info *filemap_info_new(struct filemap *fm, const char *key,
					unsigned keylen, const char *value,
					unsigned valuelen, unsigned *off)
{
	struct filemap_info *fi;
	unsigned offset;
	void *p;

	p = filemap_obj_alloc(fm, sizeof(struct filemap_info), &offset);

	if (!p) {
		_E("fail to allocate filemap_info");
		return NULL;
	}

	fi = filemap_info_init(p, key, keylen, value, valuelen);
	*off = offset;

	return fi;
}

static void *filemap_to_obj(struct filemap *fm, unsigned off)
{
	if (!fm || off > fm->filemap_data_size)
		return NULL;

	return fm + fm->root + off;
}

static struct filemap_node *filemap_to_node(struct filemap *fm, unsigned *p_off)
{
	unsigned off = g_atomic_int_get(p_off);

	return (struct filemap_node *)filemap_to_obj(fm, off);
}

static struct filemap_info *filemap_to_info(struct filemap *fm, unsigned *p_off)
{
	unsigned off = g_atomic_int_get(p_off);

	return (struct filemap_info *)filemap_to_obj(fm, off);
}

struct filemap_node *filemap_root_node(struct filemap *fm)
{
	return (struct filemap_node *)filemap_to_obj(fm, 0);
}

static int filemap_key_cmp(const char *na, const unsigned na_len,
			const char *nb, const unsigned nb_len)
{

	if (na_len < nb_len)
		return -1;
	else if (na_len > nb_len)
		return 1;
	else
		return strncmp(na, nb, na_len);
}

static struct filemap_node *filemap_node_find(struct filemap *fm, struct filemap_node *fn,
					const char *key, unsigned keylen)
{
	struct filemap_node *current = fn;
	int ret;

	while (true) {
		if (!current)
			return NULL;

		ret = filemap_key_cmp(key, keylen, current->key,
			current->keylen);
		if (ret == 0)
			return current;

		if (ret < 0) {
			unsigned left = g_atomic_int_get(&current->left);

			if (left != 0) {
				current = filemap_to_node(fm, &current->left);
			} else {
				unsigned new_offset;

				struct filemap_node *fn = filemap_node_new(fm, key,
					keylen, &new_offset);

				_D("insert left %s", key);
				if (fn)
					g_atomic_int_set(&current->left,
						new_offset);
				return fn;
			}
		} else {
			unsigned right = g_atomic_int_get(&current->right);

			if (right != 0) {
				current = filemap_to_node(fm, &current->right);
			} else {
				unsigned new_offset;
				struct filemap_node *fn = filemap_node_new(fm, key,
					keylen, &new_offset);

				_D("insert right %s", key);
				if (fn)
					g_atomic_int_set(&current->right,
						new_offset);
				return fn;
			}
		}
	}
}

static struct filemap_info *filemap_entry_find(struct filemap *fm, struct filemap_node *fn,
					const char *key, unsigned keylen,
					const char *value, unsigned valuelen,
					unsigned *offset)
{
	struct filemap_node *current;
	struct filemap_info *fi;
	const char *remaining = key;

	if (!fn)
		return NULL;

	current = fn;

	while (true) {
		unsigned str_size;
		struct filemap_node *root;
		int completed = 0;
		unsigned children;
		char *sep;

		_D("remaining %s", remaining);

		sep = strchr(remaining, '.');

		if (!sep) {
			completed = 1;
			str_size = strlen(remaining);
		} else {
			str_size = sep - remaining;
		}

		if (!str_size)
			return NULL;

		children = g_atomic_int_get(&current->children);

		if (children) {
			root = filemap_to_node(fm, &current->children);
		} else {
			unsigned new_offset;
			root = filemap_node_new(fm, remaining, str_size, &new_offset);
			_D("insert node child remaining = %s",remaining);
			if (root)
				g_atomic_int_set(&current->children, new_offset);
		}

		if (!root)
			return NULL;

		current = filemap_node_find(fm, root, remaining, str_size);
		if (!current) {
			_D("cannot find bt");
			return NULL;
		}
		_D("current = %s", current->key);

		if (completed)
			break;

		remaining = sep + 1;
	}

	*offset = g_atomic_int_get(&current->info);
	if (*offset) {
		return filemap_to_info(fm, &current->info);
	}

	fi = filemap_info_new(fm, key, keylen, value, valuelen, offset);

	if (fi)
		g_atomic_int_set(&current->info, *offset);

	return fi;
}

static void filemap_entry_update(struct filemap_info *fi,
		const char *value, unsigned len)
{
	if (len >= FILEMAP_MAX_VALUE_LEN)
		len = FILEMAP_MAX_VALUE_LEN;

	assert(fi);
	memcpy(fi->value, value, len);
}

int filemap_write(struct filemap *fm, const char *key, const char *value,
		unsigned *offset)
{
	struct filemap_node *root = filemap_root_node(fm);
	struct filemap_info *fi = NULL;
	unsigned keylen = strlen(key);
	unsigned valuelen = strlen(value);

	if (*offset) {
		fi = filemap_to_info(fm, offset);
		if (fi && !strcmp(fi->key, key))
			_D("fi for key %s is found using offset", fi->key);
		else
			fi = NULL;
	}

	if (!fi)
		fi = filemap_entry_find(fm, root, key, keylen,
			value, valuelen, offset);

	if (!fi) {
		_E("cannot find and add entry for %s", key);
		return RESOURCED_ERROR_FAIL;
	}

	filemap_entry_update(fi, value, valuelen);

	return RESOURCED_ERROR_NONE;
}

int filemap_foreach_read(struct filemap *fm, struct filemap_node *fn,
	void (*callbackfn)(const struct filemap_info *fi))
{
	unsigned offset;
	int ret;

	if (!fn)
		return RESOURCED_ERROR_FAIL;

	offset = g_atomic_int_get(&fn->left);
	if (offset != 0) {
		ret = filemap_foreach_read(fm, filemap_to_node(fm, &fn->left), callbackfn);
		if (ret < 0)
			return RESOURCED_ERROR_FAIL;
	}

	offset = g_atomic_int_get(&fn->info);
	if (offset != 0) {
		struct filemap_info *fi = filemap_to_info(fm, &fn->info);
		if (!fi)
			return RESOURCED_ERROR_FAIL;
		callbackfn(fi);
	}

	offset = g_atomic_int_get(&fn->children);
	if (offset != 0) {
		ret = filemap_foreach_read(fm, filemap_to_node(fm, &fn->children),
			callbackfn);
		if (ret < 0)
			return RESOURCED_ERROR_FAIL;
	}

	offset = g_atomic_int_get(&fn->right);
	if (offset != 0) {
		ret = filemap_foreach_read(fm, filemap_to_node(fm, &fn->right), callbackfn);
		if (ret < 0)
			return RESOURCED_ERROR_FAIL;
	}

	return RESOURCED_ERROR_NONE;
}
