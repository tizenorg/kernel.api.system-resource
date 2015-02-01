/*
   Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License
*/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <linux/limits.h>

#include <ctype.h>
#include <stddef.h>

#include <dirent.h>
#include <sys/utsname.h>

#define STR_SGX_PATH	"/dev/pvrsrvkm"
#define STR_3D_PATH1	"/dev/mali"
#define STR_3D_PATH2	"/dev/kgsl-3d0"
#define STR_DRM_PATH1	"/drm mm object (deleted)"
#define STR_DRM_PATH2	"/dev/dri/card0"

#define BUF_MAX         (BUFSIZ)            /* most optimal for libc::stdio */
#define BUF_INC_SIZE    (512 * 1024)        /* maximal SMAPS I saw 2 MB     */
#define KB(bytes)       ((bytes)/1024)

typedef struct geminfo geminfo;
typedef struct mapinfo mapinfo;
typedef struct trib_mapinfo trib_mapinfo;

enum {
	OUTPUT_UART,
	OUTPUT_FILE,
	NUM_OUTPUT_TYPE
};

struct mapinfo {
	mapinfo *next;
	unsigned start;
	unsigned end;
	unsigned size;
	unsigned rss;
	unsigned pss;
	unsigned shared_clean;
	unsigned shared_dirty;
	unsigned private_clean;
	unsigned private_dirty;
	char perm[4];
	char name[1];
};

/* classify normal, graphic and other devices memory */
struct trib_mapinfo {
	unsigned shared_clean;
	unsigned shared_dirty;
	unsigned private_clean;
	unsigned private_dirty;
	unsigned shared_clean_pss;
	unsigned shared_dirty_pss;
	unsigned rss;
	unsigned pss;
	unsigned size;
	unsigned graphic_3d;
	unsigned gem_rss;
	unsigned gem_pss;
	unsigned peak_rss;
	unsigned other_devices;
	unsigned gem_mmap;
};

struct geminfo {
	geminfo *next;
	unsigned int tgid;
	unsigned rss_size;
	unsigned pss_size;
	unsigned hcount;
};

static int ignore_smaps_field;
static int sum;
static int verbos;

/* reads file contents into memory */
static char* cread(const char* path)
{
	/* once allocated area for reads */
	static char*	text = NULL;
	static size_t	size = 0;

	ssize_t	ret;
	char*	ptr = text;
	size_t	cap = size;
	int	fd  = open(path, O_RDONLY);

	if (fd < 0) {
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
} /* cread */

/* like fgets/gets but adjusting contents pointer */
static inline char* cgets(char** contents)
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
} /* cgets */


static unsigned get_peak_rss(unsigned int pid)
{
	static const char field[] = "VmHWM:";
	char tmp[128];
	char* line;
	char* value;

	sprintf(tmp, "/proc/%d/status", pid);
	line = cread(tmp);
	if (line == NULL) {
		fprintf(stderr,	"cannot open %s\n", tmp);
		return 0;
	}

	value = strstr(line, field);
	if (value) {
		value += sizeof(field);
		return strtoul(value, NULL, 10);
	}

	return 0;
}
#define NUM_GEM_FIELD 6

static geminfo *read_geminfo(FILE *fp)
{
	geminfo *tgeminfo;
	char line[BUF_MAX];
	unsigned int pid, tgid, handle, refcount, hcount;
	unsigned gem_size;

	if (fgets(line, BUF_MAX, fp) != NULL) {
		if (sscanf(line, "%d %d %d %d %d 0x%x",
			&pid, &tgid, &handle, &refcount,
			&hcount, &gem_size) != NUM_GEM_FIELD)
			return NULL;

		tgeminfo = malloc(sizeof(geminfo));
		if (tgeminfo == NULL)
			return NULL;
		tgeminfo->tgid = tgid;
		tgeminfo->hcount = hcount;
		tgeminfo->rss_size = KB(gem_size);
		tgeminfo->pss_size = KB(gem_size/tgeminfo->hcount);
	} else
		return NULL;

	return tgeminfo;
}


static geminfo *load_geminfo(void)
{
	geminfo *ginfo;
	geminfo *gilist = NULL;
	FILE *drm_fp;
	char line[BUF_MAX];

	drm_fp = fopen("/sys/kernel/debug/dri/0/gem_info", "r");

	if (drm_fp == NULL) {
		fprintf(stderr,
		"cannot open /sys/kernel/debug/dri/0/gem_info\n");
		return NULL;
	}

	if (fgets(line, BUF_MAX, drm_fp) == NULL) {
		fclose(drm_fp);
		return NULL;
	} else {
		/* we should count a number of whitespace separated fields */
		int 	 in_field = (line[0] && !isblank(line[0]));
		unsigned int size = (unsigned)in_field;
		const char*  ptr  = &line[1];

		/* sscanf() was used in original code, so number of fields */
		/* in string is expected to be at least NUM_GEM_FIELD      */
		while (*ptr && size < NUM_GEM_FIELD) {
			if (isblank(*ptr++)) {
				if (in_field) {
					/* end of field */
					in_field = 0;
				}
			} else {
				if (!in_field) {
					/* next field started */
					in_field = 1;
					size++;
				}
			}
		} /* while */

		if (size != NUM_GEM_FIELD) {
			fclose(drm_fp);
			return NULL;
		}
	}

	while ((ginfo = read_geminfo(drm_fp)) != NULL) {
		if (gilist && ginfo->tgid == gilist->tgid) {
			gilist->pss_size += ginfo->pss_size;
			gilist->rss_size += ginfo->rss_size;
			free(ginfo);
			continue;
		}
		ginfo->next = gilist;
		gilist = ginfo;
	}

	fclose(drm_fp);

	return gilist;
}


/* 6f000000-6f01e000 rwxp 00000000 00:0c 16389419   /android/lib/libcomposer.so
 * 012345678901234567890123456789012345678901234567890123456789
 * 0         1         2         3         4         5
 */

mapinfo *read_mapinfo(char** smaps, int rest_line)
{
	char* line;
	mapinfo *mi;
	int len;
	int tmp;

	if ((line = cgets(smaps)) == 0)
		return 0;

	len    = strlen(line);
	if (len < 1)
		return 0;

	mi = malloc(sizeof(mapinfo) + len + 16);
	if (mi == 0)
		return 0;

	mi->start = strtoul(line, 0, 16);
	mi->end = strtoul(line + 9, 0, 16);

	mi->perm[0] = line[18];	/* read */
	mi->perm[1] = line[19];	/* write */
	mi->perm[2] = line[20];	/* execute */
	mi->perm[3] = line[21];	/* may share or private */

	if (len < 50)
		strcpy(mi->name, "[anon]");
	else
		strcpy(mi->name, line + 49);

	if ((line = cgets(smaps)) == 0)
		goto oops;
	if (sscanf(line, "Size: %d kB", &mi->size) != 1)
		goto oops;
	if ((line = cgets(smaps)) == 0)
		goto oops;
	if (sscanf(line, "Rss: %d kB", &mi->rss) != 1)
		goto oops;
	if ((line = cgets(smaps)) == 0)
		goto oops;
	if (sscanf(line, "Pss: %d kB", &mi->pss) == 1)
		if ((line = cgets(smaps)) == 0)
			goto oops;
	if (sscanf(line, "Shared_Clean: %d kB", &mi->shared_clean) != 1)
		goto oops;
	if ((line = cgets(smaps)) == 0)
		goto oops;
	if (sscanf(line, "Shared_Dirty: %d kB", &mi->shared_dirty) != 1)
		goto oops;
	if ((line = cgets(smaps)) == 0)
		goto oops;
	if (sscanf(line, "Private_Clean: %d kB", &mi->private_clean) != 1)
		goto oops;
	if ((line = cgets(smaps)) == 0)
		goto oops;
	if (sscanf(line, "Private_Dirty: %d kB", &mi->private_dirty) != 1)
		goto oops;

	while (rest_line-- && (line = cgets(smaps))) {
		if (sscanf(line, "PSwap: %d kB", &tmp) == 1)
			rest_line++;
	}

	return mi;
 oops:
	printf("mi get error\n");
	free(mi);
	return 0;
}

static unsigned total_gem_memory(void)
{
	FILE *gem_fp;
	unsigned total_gem_mem = 0;
	unsigned name, size, handles, refcount;
	char line[BUF_MAX];

	gem_fp = fopen("/proc/dri/0/gem_names", "r");
	if(gem_fp == NULL) {
		fprintf(stderr,
		"cannot open /proc/dir/0/gem_names\n");
		return 0;
	}

	if (fgets(line, BUF_MAX, gem_fp) == NULL) {
		fclose(gem_fp);
		return 0;
	}

	while (fgets(line, BUF_MAX, gem_fp) != NULL)
		if (sscanf(line, "%d %d %d %d\n",
		    &name, &size, &handles, &refcount) == 4)
			total_gem_mem += size;
	fclose(gem_fp);

	return total_gem_mem;
}

static void get_mem_info(FILE *output_fp)
{
	char buf[PATH_MAX];
	FILE *fp;
	char *idx;
	unsigned int free = 0, cached = 0;
	unsigned int total_mem = 0, available = 0, used;
	unsigned int swap_total = 0, swap_free = 0, swap_used;
	unsigned int used_ratio;

	if (output_fp == NULL)
		return;

	fp = fopen("/proc/meminfo", "r");

	if (!fp) {
		fprintf(stderr, "%s open failed, %p", buf, fp);
		return;
	}

	while (fgets(buf, PATH_MAX, fp) != NULL) {
		if ((idx = strstr(buf, "MemTotal:"))) {
			idx += strlen("Memtotal:");
			while (*idx < '0' || *idx > '9')
				idx++;
			total_mem = atoi(idx);
		} else if ((idx = strstr(buf, "MemFree:"))) {
			idx += strlen("MemFree:");
			while (*idx < '0' || *idx > '9')
				idx++;
			free = atoi(idx);
		} else if ((idx = strstr(buf, "MemAvailable:"))) {
			idx += strlen("MemAvailable:");
			while (*idx < '0' || *idx > '9')
				idx++;
			available = atoi(idx);
		} else if((idx = strstr(buf, "Cached:")) && !strstr(buf, "Swap")) {
			idx += strlen("Cached:");
			while (*idx < '0' || *idx > '9')
				idx++;
			cached = atoi(idx);
		} else if((idx = strstr(buf, "SwapTotal:"))) {
			idx += strlen("SwapTotal:");
			while (*idx < '0' || *idx > '9')
				idx++;
			swap_total = atoi(idx);
		} else if((idx = strstr(buf, "SwapFree:"))) {
			idx += strlen("SwapFree");
			while (*idx < '0' || *idx > '9')
				idx++;
			swap_free = atoi(idx);
			break;
		}
	}

	if (available == 0)
		available = free + cached;
	used = total_mem - available;
	used_ratio = used * 100 / total_mem;
	swap_used = swap_total - swap_free;

	fprintf(output_fp,
		"====================================================================\n");


	fprintf(output_fp, "Total RAM size: \t%15d MB( %6d kB)\n",
			total_mem >> 10, total_mem);

	fprintf(output_fp, "Used (Mem+Reclaimable): %15d MB( %6d kB)\n",
			(total_mem - free) >> 10, total_mem - free);

	fprintf(output_fp, "Used (Mem+Swap): \t%15d MB( %6d kB)\n",
			used >> 10, used);

	fprintf(output_fp, "Used (Mem):  \t\t%15d MB( %6d kB)\n",
			used >> 10, used);

	fprintf(output_fp, "Used (Swap): \t\t%15d MB( %6d kB)\n",
			swap_used >> 10, swap_used);

	fprintf(output_fp, "Used Ratio: \t\t%15d  %%\n", used_ratio);

	fprintf(output_fp, "Mem Free:\t\t%15d MB( %6d kB)\n",
			free >> 10, free);

	fprintf(output_fp, "Available (Free+Reclaimable):%10d MB( %6d kB)\n",
			available >> 10,
			available);
	fclose(fp);
}

static int get_tmpfs_info(FILE *output_fp)
{
	FILE *fp;
	char line[BUF_MAX];
	char tmpfs_mp[NAME_MAX];	/* tmpfs mount point */
	struct statfs tmpfs_info;

	if (output_fp == NULL)
		return -1;

	fp = fopen("/etc/mtab", "r");
	if (fp == NULL)
		return -1;

	fprintf(output_fp,
		"====================================================================\n");
	fprintf(output_fp, "TMPFS INFO\n");

	while (fgets(line, BUF_MAX, fp) != NULL) {
		if (sscanf(line, "tmpfs %s tmpfs", tmpfs_mp) == 1) {
			statfs(tmpfs_mp, &tmpfs_info);
			fprintf(output_fp,
				"tmpfs %16s  Total %8ld KB, Used %8ld, Avail %8ld\n",
				tmpfs_mp,
				/* 1 block is 4 KB */
				tmpfs_info.f_blocks * 4,
				(tmpfs_info.f_blocks - tmpfs_info.f_bfree) * 4,
				tmpfs_info.f_bfree * 4);
		}
	}
	fclose(fp);
	return 0;
}

mapinfo *load_maps(int pid)
{
	char* smaps;
	char tmp[128];
	mapinfo *milist = 0;
	mapinfo *mi;

	sprintf(tmp, "/proc/%d/smaps", pid);
	smaps = cread(tmp);
	if (smaps == NULL)
		return 0;

	while ((mi = read_mapinfo(&smaps, ignore_smaps_field)) != 0) {
		if (milist) {
			if ((!strcmp(mi->name, milist->name)
			     && (mi->name[0] != '['))) {
				milist->size += mi->size;
				milist->rss += mi->rss;
				milist->pss += mi->pss;
				milist->shared_clean += mi->shared_clean;
				milist->shared_dirty += mi->shared_dirty;
				milist->private_clean += mi->private_clean;
				milist->private_dirty += mi->private_dirty;

				milist->perm[0] = mi->perm[0];
				milist->perm[1] = mi->perm[1];
				milist->perm[2] = mi->perm[2];
				milist->perm[3] = mi->perm[3];
				milist->end = mi->end;
				strncpy(milist->perm, mi->perm, 4);
				free(mi);
				continue;
			}
		}
		mi->next = milist;
		milist = mi;
	}

	return milist;
}

static geminfo *find_geminfo(unsigned int tgid, geminfo *gilist)
{
	geminfo *gi;
	for (gi = gilist; gi; ) {
		if (gi->tgid == tgid)
			return gi;

		gi = gi->next;
	}
	return NULL;
}

static void init_trib_mapinfo(trib_mapinfo *tmi)
{
	if (!tmi)
		return;
	tmi->shared_clean = 0;
	tmi->shared_dirty = 0;
	tmi->private_clean = 0;
	tmi->private_dirty = 0;
	tmi->shared_clean_pss = 0;
	tmi->shared_dirty_pss = 0;
	tmi->rss = 0;
	tmi->pss = 0;
	tmi->size = 0;
	tmi->graphic_3d = 0;
	tmi->gem_rss = 0;
	tmi->gem_pss = 0;
	tmi->peak_rss = 0;
	tmi->other_devices = 0;
	tmi->gem_mmap = 0;
}

static int
get_trib_mapinfo(unsigned int tgid, mapinfo *milist,
		 geminfo *gilist, trib_mapinfo *result)

{
	mapinfo *mi;
	mapinfo *temp = NULL;
	geminfo *gi;

	if (!result)
		return -EINVAL;

	init_trib_mapinfo(result);
	for (mi = milist; mi;) {
		if (strstr(mi->name, STR_SGX_PATH)) {
			result->graphic_3d += mi->pss;
		} else if (strstr(mi->name, STR_3D_PATH1) ||
			strstr(mi->name, STR_3D_PATH2)) {
			result->graphic_3d += mi->size;
		} else if (mi->rss != 0 && mi->pss == 0
			   && mi->shared_clean == 0
			   && mi->shared_dirty == 0
			   && mi->private_clean == 0
			   && mi->private_dirty == 0) {
			result->other_devices += mi->size;
		} else if (!strncmp(mi->name, STR_DRM_PATH1,
				sizeof(STR_DRM_PATH1)) ||
				!strncmp(mi->name, STR_DRM_PATH2,
				sizeof(STR_DRM_PATH2))) {
			result->gem_mmap += mi->rss;
		} else {
			result->shared_clean += mi->shared_clean;
			result->shared_dirty += mi->shared_dirty;
			result->private_clean += mi->private_clean;
			result->private_dirty += mi->private_dirty;
			result->rss += mi->rss;
			result->pss += mi->pss;
			result->size += mi->size;

			if(mi->shared_clean != 0)
				result->shared_clean_pss += mi->pss;
			else if (mi->shared_dirty != 0)
				result->shared_dirty_pss += mi->pss;
		}

		temp = mi;
		mi = mi->next;
		free(temp);
		temp = NULL;
	}

	result->peak_rss = get_peak_rss(tgid);
	if (result->peak_rss < result->rss)
		result->peak_rss = result->rss;
	if (result->gem_mmap > 0)
		result->peak_rss -= result->gem_mmap;

	gi = find_geminfo(tgid, gilist);
	if (gi != NULL) {
		result->gem_rss = gi->rss_size;
		result->gem_pss = gi->pss_size;
	}

	return 0;
}

static int get_cmdline(unsigned int pid, char *cmdline)
{
	FILE *fp;
	char buf[NAME_MAX] = {0, };
	int ret = -1;

	sprintf(buf, "/proc/%d/cmdline", pid);
	fp = fopen(buf, "r");
	if (fp == 0) {
		fprintf(stderr, "cannot file open %s\n", buf);
		return ret;
	}
	if ((ret = fscanf(fp, "%s", cmdline)) < 1) {
		fclose(fp);
		return ret;
	}
	fclose(fp);

	return ret;
}

static int get_oomscoreadj(unsigned int pid)
{
	FILE *fp;
	char tmp[256];
	int oomadj_val;

	sprintf(tmp, "/proc/%d/oom_score_adj", pid);
	fp = fopen(tmp, "r");

	if (fp == NULL) {
		oomadj_val = -50;
		return oomadj_val;
	}
	if (fgets(tmp, sizeof(tmp), fp) == NULL) {
		oomadj_val = -100;
		fclose(fp);
		return oomadj_val;
	}

	oomadj_val = atoi(tmp);

	fclose(fp);
	return oomadj_val;
}

static void get_rss(pid_t pid, unsigned int *result)
{
	FILE *fp;
	char proc_path[PATH_MAX];
	int rss = 0;

	*result = 0;

	sprintf(proc_path, "/proc/%d/statm", pid);
	fp = fopen(proc_path, "r");
	if (fp == NULL)
		return;

	if (fscanf(fp, "%*s %d", &rss) < 1) {
		fclose(fp);
		return;
	}

	fclose(fp);

	/* convert page to Kb */
	*result = rss * 4;
	return;
}

static void show_rss(int output_type, char *output_path)
{
	DIR *pDir = NULL;
	struct dirent *curdir;
	pid_t pid;
	char cmdline[PATH_MAX];
	FILE *output_file = NULL;
	int oom_score_adj;
	unsigned int rss;

	pDir = opendir("/proc");
	if (pDir == NULL) {
		fprintf(stderr, "cannot read directory /proc.\n");
		return;
	}

	if (output_type == OUTPUT_FILE && output_path) {
		output_file = fopen(output_path, "w+");
		if (!output_file) {
			fprintf(stderr, "cannot open output file(%s)\n",
				output_path);
			closedir(pDir);
			exit(1);
		}
	} else
		output_file = stdout;


	fprintf(output_file,
			"     PID    RSS    OOM_SCORE    COMMAND\n");

	while ((curdir = readdir(pDir)) != NULL) {
		pid = atoi(curdir->d_name);
		if (pid < 1 || pid > 32768 || pid == getpid())
			continue;

		if (get_cmdline(pid, cmdline) < 0)
			continue;
		get_rss(pid, &rss);
		oom_score_adj = get_oomscoreadj(pid);

		fprintf(output_file,
				"%8d %8u %8d          %s\n",
				pid,
				rss,
				oom_score_adj,
				cmdline);


	} /* end of while */

	get_tmpfs_info(output_file);
	get_mem_info(output_file);

	fclose(output_file);
	closedir(pDir);

	return;
}

static int show_map_all_new(int output_type, char *output_path)
{
	DIR *pDir = NULL;
	struct dirent *curdir;
	unsigned int pid;
	mapinfo *milist;
	geminfo *glist;
	unsigned total_pss = 0;
	unsigned total_private = 0;
	unsigned total_private_code = 0;
	unsigned total_private_data = 0;
	unsigned total_shared_code = 0;
	unsigned total_shared_data = 0;
	unsigned total_shared_code_pss = 0;
	unsigned total_shared_data_pss = 0;
	unsigned total_rss = 0;
	unsigned total_graphic_3d = 0;
	unsigned total_gem_rss = 0;
	unsigned total_gem_pss = 0;
	unsigned total_peak_rss = 0;
	unsigned total_allocated_gem = 0;
	trib_mapinfo tmi;
	char cmdline[PATH_MAX];
	FILE *output_file = NULL;
	int oom_score_adj;

	pDir = opendir("/proc");
	if (pDir == NULL) {
		fprintf(stderr, "cannot read directory /proc.\n");
		return 0;
	}

	if (output_type == OUTPUT_FILE && output_path) {
		output_file = fopen(output_path, "w+");
		if (!output_file) {
			fprintf(stderr, "cannot open output file(%s)\n",
				output_path);
			closedir(pDir);
			exit(1);
		}
	} else
		output_file = stdout;

	glist = load_geminfo();

	if (!sum) {
		if (verbos)
			fprintf(output_file,
					"     PID  S(CODE)  S(DATA)  P(CODE)  P(DATA)"
					"     PEAK      PSS       3D"
					"     GEM(PSS)  GEM(RSS)"
					" OOM_SCORE_ADJ    COMMAND\n");
		else
			fprintf(output_file,
					"     PID     CODE     DATA     PEAK     PSS"
					"     3D      GEM(PSS)      COMMAND\n");
	}

	while ((curdir = readdir(pDir)) != NULL) {
		pid = atoi(curdir->d_name);
		if (pid < 1 || pid > 32768 || pid == getpid())
			continue;

		if (get_cmdline(pid, cmdline) < 0)
			continue;

		milist = load_maps(pid);
		if (milist == 0)
			continue;

		/* get classified map info */
		get_trib_mapinfo(pid, milist, glist, &tmi);
		oom_score_adj = get_oomscoreadj(pid);

		if (!sum) {
			if (verbos)
				fprintf(output_file,
					"%8d %8d %8d %8d %8d %8d %8d %8d %8d %8d"
					" %8d \t\t%s\n",
					pid,
					tmi.shared_clean, tmi.shared_dirty,
					tmi.private_clean, tmi.private_dirty,
					tmi.peak_rss, tmi.pss, tmi.graphic_3d,
					tmi.gem_pss, tmi.gem_rss, oom_score_adj, cmdline);
			else
				fprintf(output_file,
					"%8d %8d %8d %8d %8d %8d %8d      %s\n",
					pid,
					tmi.shared_clean +
					tmi.private_clean,
					tmi.shared_dirty + tmi.private_dirty,
					tmi.peak_rss,
					tmi.pss,
					tmi.graphic_3d,
					tmi.gem_pss, cmdline);

			if (tmi.other_devices != 0)
				fprintf(output_file,
					"%s(%d) %d KB may mapped by device(s).\n",
					cmdline, pid, tmi.other_devices);
		}

		total_private += (tmi.private_clean + tmi.private_dirty);
		total_pss += tmi.pss;
		total_rss += tmi.rss;
		total_graphic_3d += tmi.graphic_3d;
		total_gem_rss += tmi.gem_rss;
		total_gem_pss += tmi.gem_pss;
		total_private_code += tmi.private_clean;
		total_private_data += tmi.private_dirty;
		total_shared_code += tmi.shared_clean;
		total_shared_data += tmi.shared_dirty;
		total_peak_rss += tmi.peak_rss;

		total_shared_code_pss += tmi.shared_clean_pss;
		total_shared_data_pss += tmi.shared_dirty_pss;
	} /* end of while */

	total_allocated_gem = KB(total_gem_memory());
	fprintf(output_file,
			"==============================================="
			"===============================================\n");
	if (verbos) {
		fprintf(output_file,
				"TOTAL:      S(CODE) S(DATA) P(CODE)  P(DATA)"
				"    PEAK     PSS       3D    "
				"GEM(PSS) GEM(RSS) GEM(ALLOC) TOTAL(KB)\n");
		fprintf(output_file,
			"         %8d %8d %8d %8d %8d %8d %8d"
			" %8d %8d %8d %8d\n",
			total_shared_code, total_shared_data,
			total_private_code, total_private_data,
			total_peak_rss,	total_pss, total_graphic_3d,
			total_gem_pss, total_gem_rss,
			total_allocated_gem,
			total_pss + total_graphic_3d +
			total_allocated_gem);
	} else {
		fprintf(output_file,
			"TOTAL:        CODE     DATA    PEAK     PSS     "
			"3D    GEM(PSS) GEM(ALLOC)     TOTAL(KB)\n");
		fprintf(output_file, "         %8d %8d %8d %8d %8d %8d %7d %8d\n",
			total_shared_code + total_private_code,
			total_shared_data + total_private_data,
			total_peak_rss, total_pss,
			total_graphic_3d, total_gem_pss,
			total_allocated_gem,
			total_pss + total_graphic_3d +
			total_allocated_gem);

	}

	if (verbos)
		fprintf(output_file,
			"* S(CODE): shared clean memory, it includes"
			" duplicated memory\n"
			"* S(DATA): shared dirty memory, it includes"
			" duplicated memory\n"
			"* P(CODE): private clean memory\n"
			"* P(DATA): private dirty memory\n"
			"* PEAK: peak memory usage of S(CODE) + S(DATA)"
			" + P(CODE) + P(DATA)\n"
			"* PSS: Proportional Set Size\n"
			"* 3D: memory allocated by GPU driver\n"
			"* GEM(PSS): GEM memory devided by # of sharers\n"
			"* GEM(RSS): GEM memory including duplicated memory\n"
			"* GEM(ALLOC): sum of unique gem memory in the system\n"
			"* TOTAL: PSS + 3D + GEM(ALLOC) \n");
	else
		fprintf(output_file,
			"* CODE: shared and private clean memory\n"
			"* DATA: shared and private dirty memory\n"
			"* PEAK: peak memory usage of CODE + DATA\n"
			"* PSS: Proportional Set Size\n"
			"* 3D: memory allocated by GPU driver\n"
			"* GEM(PSS): GEM memory deviced by # of sharers\n"
			"* GEM(ALLOC): sum of unique GEM memory in the system\n"
			"* TOTAL: PSS + 3D + GEM(ALLOC)\n");

	get_tmpfs_info(output_file);
	get_mem_info(output_file);

	fclose(output_file);
	free(glist);
	closedir(pDir);
	return 1;
}

static int show_map_new(int pid)
{
	mapinfo *milist;
	mapinfo *mi;
	unsigned shared_dirty = 0;
	unsigned shared_clean = 0;
	unsigned private_dirty = 0;
	unsigned private_clean = 0;
	unsigned pss = 0;
	unsigned start = 0;
	unsigned end = 0;
	unsigned private_clean_total = 0;
	unsigned private_dirty_total = 0;
	unsigned shared_clean_total = 0;
	unsigned shared_dirty_total = 0;
	int duplication = 0;

	milist = load_maps(pid);

	if (milist == 0) {
		fprintf(stderr, "cannot get /proc/smaps for pid %d\n", pid);
		return 1;
	}

	if (!sum) {
		printf(" S(CODE)  S(DATA)  P(CODE)  P(DATA)  ADDR(start-end)"
			"OBJECT NAME\n");
		printf("-------- -------- -------- -------- -----------------"
			"------------------------------\n");
	} else {
		printf(" S(CODE)  S(DATA)  P(CODE)  P(DATA)  PSS\n");
		printf("-------- -------- -------------------"
			"------------------\n");
	}
	for (mi = milist; mi; mi = mi->next) {
		shared_clean += mi->shared_clean;
		shared_dirty += mi->shared_dirty;
		private_clean += mi->private_clean;
		private_dirty += mi->private_dirty;
		pss += mi->pss;

		shared_clean_total += mi->shared_clean;
		shared_dirty_total += mi->shared_dirty;
		private_clean_total += mi->private_clean;
		private_dirty_total += mi->private_dirty;

		if (!duplication)
			start = mi->start;

		if ((mi->next && !strcmp(mi->next->name, mi->name)) &&
		    (mi->next->start == mi->end)) {
			duplication = 1;
			continue;
		}
		end = mi->end;
		duplication = 0;

		if (!sum) {
			printf("%8d %8d %8d %8d %08x-%08x %s\n",
			       shared_clean, shared_dirty, private_clean, private_dirty,
			       start, end, mi->name);
		}
		shared_clean = 0;
		shared_dirty = 0;
		private_clean = 0;
		private_dirty = 0;
	}
	if (sum) {
		printf("%8d %8d %8d %8d %18d\n",
		       shared_clean_total,
		       shared_dirty_total,
		       private_clean_total,
		       private_dirty_total,
		       pss);
	}

	return 1;
}

void check_kernel_version(void)
{
	struct utsname buf;
	int ret;

	ret = uname(&buf);

	if (!ret) {
		if (buf.release[0] == '3') {
			char *pch;
			char str[3];
			int sub_version;
			pch = strstr(buf.release, ".");
			strncpy(str, pch+1, 2);
			sub_version = atoi(str);

			if (sub_version >= 10)
				ignore_smaps_field = 8; /* Referenced, Anonymous, AnonHugePages,
						   Swap, KernelPageSize, MMUPageSize,
						   Locked, VmFlags */

			else
				ignore_smaps_field = 7; /* Referenced, Anonymous, AnonHugePages,
						   Swap, KernelPageSize, MMUPageSize,
						   Locked */
		} else {
			ignore_smaps_field = 4; /* Referenced, Swap, KernelPageSize,
						   MMUPageSize */
		}
	}
}

int main(int argc, char *argv[])
{
	int usage = 1;
	sum = 0;

	if (argc > 1) {
		check_kernel_version();

		if (!strcmp(argv[1], "-r")) {
			if (argc >= 3)
				show_rss(OUTPUT_FILE, argv[2]);
			else
				show_rss(OUTPUT_UART, NULL);
			usage = 0;
		} else if (!strcmp(argv[1], "-s")) {
			sum = 1;
			if (argc == 3 && atoi(argv[2]) > 0) {
				show_map_new(atoi(argv[2]));
				usage = 0;
			}
		} else if (!strcmp(argv[1], "-a")) {
			verbos = 0;
			show_map_all_new(OUTPUT_UART, NULL);
			usage = 0;
		} else if (!strcmp(argv[1], "-v")) {
			verbos = 1;
			show_map_all_new(OUTPUT_UART, NULL);
			usage = 0;
		} else if (!strcmp(argv[1], "-f")) {
			if (argc >= 3) {
				verbos = 1;
				show_map_all_new(OUTPUT_FILE, argv[2]);
				usage = 0;
			}
		} else if (argc == 2 && atoi(argv[1]) > 0) {
			show_map_new(atoi(argv[1]));
			usage = 0;
		}
	}
	if (usage) {
		fprintf(stderr,
			"memps [-a] | [-v] | [-s] <pid> | [-f] <output file full path>\n"
			"	 -s = sum (show only sum of each)\n"
			"	 -f = all (show all processes via output file)\n"
			"        -a = all (show all processes)\n"
			"        -v = verbos (show all processes in detail)\n");
	}

	return 0;
}
