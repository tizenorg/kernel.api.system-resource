#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mount.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include "trace.h"
#include "vip-process.h"

#define TIZEN_DEBUG_MODE_FILE   "/opt/etc/.debugmode"
#define DUMP_PATH "/usr/bin/all_log_dump.sh"
#define REBOOT_PATH "/usr/sbin/reboot"
#define WAIT_TIMEOUT 10
#define MAX_TIMES 30

static int check_debugenable(void)
{
	if (access(TIZEN_DEBUG_MODE_FILE, F_OK) == 0)
		return 1;
	else
		return 0;
}

static int run_exec(char **argv)
{
	int status = 0, times = 0, wpid;
	pid_t pid = 0;
	char buf[256];

	if (argv == NULL)
		return -3;

	pid = fork();

	if (pid == -1)
		return -1;

	if (pid == 0) {
		setpgid(0, 0);
		if (execv(argv[0], argv) == -1) {
			_E("Error execv: %s.\n", strerror_r(errno, buf, sizeof(buf)));
			_exit(-1);
		}
		_exit(1);
	}
	do {
		wpid = waitpid(pid, &status, WNOHANG);
		if (wpid == 0) {
			if (times < MAX_TIMES) {
				sleep(WAIT_TIMEOUT);
				times ++;
			} else {
				_D("timeout!!, kill child process(%s)\n",
				    argv[0]);
				kill(pid, SIGKILL);
			}
		}
	} while (wpid == 0 && times <= MAX_TIMES);
	return 0;
}

int main(int argc, char *argv[])
{
	int checkfd;
	char *dumpargv[3] = {DUMP_PATH, "urgent", NULL};
	char *rebootargv[4] = {REBOOT_PATH, "silent", NULL, NULL};
	DIR *dir = 0;

	dir = opendir(VIP_CGROUP);
	if (!dir) {
		_E("doesn't support cgroup release agent");
		return 0;
	}
	closedir(dir);

	_E("call release agent : [%d:%s]\n", argc, argv[1]);

	/* check previous process */
	if (access(CHECK_RELEASE_PROGRESS, F_OK) == 0)
		return 0;

	/* make tmp file */
	checkfd = creat(CHECK_RELEASE_PROGRESS, 0640);
	if (checkfd < 0) {
		_E("fail to make %s file\n", CHECK_RELEASE_PROGRESS);
		checkfd = 0;
	}

	/* unmount cgroup for preventing launching another release-agent */
	_E("systemd service stop");
	umount2("/sys/fs/cgroup", MNT_FORCE |MNT_DETACH);

	/* check debug level */
	if (check_debugenable())
		run_exec(dumpargv);

	/* clear tmp file */
	if (checkfd) {
		if (unlink(CHECK_RELEASE_PROGRESS) < 0)
			_E("fail to remove %s file\n", CHECK_RELEASE_PROGRESS);
		close(checkfd);
	}

	sync();

	run_exec(rebootargv);
	return 0;
}

