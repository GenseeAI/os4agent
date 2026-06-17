#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/sched.h>
#include <linux/types.h>

#include "../uapi_criu_capbypass.h"

#define DEVPATH "/dev/criu_capbypass"
#define UID_MAP "0 1000 1\n"
#define GID_MAP "0 1000 1\n"

#define log(fmt, ...) do { fprintf(stderr, "[" fmt "]\n", ##__VA_ARGS__); fflush(stderr); } while (0)

static int write_file(const char *p, const char *b, size_t n)
{
	int fd = open(p, O_WRONLY);

	if (fd < 0)
		return -1;
	if (write(fd, b, n) != (ssize_t)n) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int write_child_maps(pid_t pid)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
	if (write_file(path, "deny", 4))
		return -1;
	snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
	if (write_file(path, UID_MAP, sizeof(UID_MAP) - 1))
		return -1;
	snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
	if (write_file(path, GID_MAP, sizeof(GID_MAP) - 1))
		return -1;
	return 0;
}

static int child_main(int sync_fd)
{
	struct clone_args ca = {0};
	pid_t tids[2] = { 1, 201 };
	char c, buf;
	int ret;

	if (unshare(CLONE_NEWUSER) < 0) {
		perror("child unshare");
		return 1;
	}
	if (write(sync_fd, "1", 1) != 1)
		return 1;
	if (read(sync_fd, &buf, 1) != 1)
		return 1;
	if (setuid(0) < 0 || setgid(0) < 0)
		return 1;

	log("child in nested user_ns; uts_ns still owned by HOST");

	if (write(sync_fd, "g", 1) != 1)
		return 1;
	if (read(sync_fd, &c, 1) != 1)
		return 1;

	ret = sethostname("bypass-test", 11);
	if (ret == 0) {
		log("FAIL: sethostname succeeded -- bypass leaked outside CLONE/SETNS/UNSHARE/MOUNT");
		return 2;
	}
	if (errno != EPERM) {
		log("FAIL: sethostname failed with %s, expected EPERM", strerror(errno));
		return 3;
	}
	log("OK: sethostname stayed EPERM even with default grant");

	ca.flags        = CLONE_NEWPID;
	ca.exit_signal  = SIGCHLD;
	ca.set_tid      = (__u64)(unsigned long)tids;
	ca.set_tid_size = 2;
	ret = syscall(SYS_clone3, &ca, sizeof(ca));
	if (ret < 0) {
		log("FAIL: clone3 under grant returned %s -- CLONE class should be permitted",
			strerror(errno));
		return 4;
	}
	if (ret == 0)
		_exit(0);
	waitpid(ret, NULL, 0);
	log("OK: clone3 (CLONE class) succeeded under same grant");

	return 0;
}

int main(void)
{
	pid_t child;
	int status;
	int sync_pair[2];
	int dev_fd;
	struct clone_args ca = {0};
	struct criu_capbypass_args cba;
	char c;

	setvbuf(stderr, NULL, _IOLBF, 0);
	if (geteuid() != 0) {
		fprintf(stderr, "Run as root.\n");
		return 1;
	}

	dev_fd = open(DEVPATH, O_WRONLY);
	if (dev_fd < 0) {
		fprintf(stderr, "open %s: %s\n", DEVPATH, strerror(errno));
		return 1;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sync_pair) < 0) {
		perror("socketpair");
		return 1;
	}


	ca.flags       = CLONE_NEWPID;
	ca.exit_signal = SIGCHLD;
	child = syscall(SYS_clone3, &ca, sizeof(ca));
	if (child < 0) {
		perror("clone3");
		return 1;
	}
	if (child == 0) {
		close(sync_pair[0]);
		close(dev_fd);
		_exit(child_main(sync_pair[1]));
	}
	close(sync_pair[1]);

	if (read(sync_pair[0], &c, 1) != 1)
		return 1;
	if (write_child_maps(child))
		return 1;
	if (write(sync_pair[0], "m", 1) != 1)
		return 1;

	if (read(sync_pair[0], &c, 1) != 1)
		return 1;
	memset(&cba, 0, sizeof(cba));
	cba.target_id    = child;
	cba.flags        = CRIU_CB_TARGET_VPID;
	cba.cap_mask     = 0;
	cba.syscall_mask = 0;
	if (ioctl(dev_fd, CRIU_CB_GRANT, &cba) < 0) {
		perror("ioctl GRANT");
		return 1;
	}
	if (write(sync_pair[0], "1", 1) != 1)
		return 1;

	if (waitpid(child, &status, 0) != child) {
		perror("waitpid");
		return 1;
	}
	close(dev_fd);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "child failed: status=0x%x\n", status);
		return 1;
	}
	log("test_non_clone_denied: OK");
	return 0;
}
