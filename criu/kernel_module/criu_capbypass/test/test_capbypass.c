#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

static int write_file(const char *path, const char *buf, size_t len)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return -1;
	}
	if (write(fd, buf, len) != (ssize_t)len) {
		fprintf(stderr, "write %s: %s\n", path, strerror(errno));
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

static int try_clone_newpid_set_tid(pid_t inner_tid, pid_t outer_tid)
{
	struct clone_args ca = {0};
	pid_t tids[2] = { inner_tid, outer_tid };
	pid_t ret;

	ca.flags        = CLONE_NEWPID;
	ca.exit_signal  = SIGCHLD;
	ca.set_tid      = (__u64)(unsigned long)tids;
	ca.set_tid_size = 2;

	ret = syscall(SYS_clone3, &ca, sizeof(ca));
	if (ret < 0)
		return -errno;
	if (ret == 0)
		_exit(0);
	waitpid(ret, NULL, 0);
	return 0;
}

static int child_main(int sync_fd)
{
	char c;
	int rc;

	if (getpid() != 1) {
		fprintf(stderr, "child: expected pid 1, got %d\n", (int)getpid());
		return 1;
	}


	if (unshare(CLONE_NEWUSER) < 0) {
		perror("child unshare(CLONE_NEWUSER)");
		return 1;
	}

	if (write(sync_fd, "1", 1) != 1) {
		perror("child write ready");
		return 1;
	}
	if (read(sync_fd, &c, 1) != 1) {
		perror("child read maps");
		return 1;
	}

	if (setuid(0) < 0) {
		perror("child setuid(0)");
		return 1;
	}
	if (setgid(0) < 0) {
		perror("child setgid(0)");
		return 1;
	}

	log("child pid=%d uid=%d: in U_child, P_child.owner=HOST", (int)getpid(), (int)getuid());

	rc = try_clone_newpid_set_tid(1, 100);
	log("BEFORE grant: clone3(CLONE_NEWPID, set_tid=[1,100]) -> %d %s",
		rc, rc == 0 ? "(success)" : strerror(-rc));
	if (rc != -EPERM)
		fprintf(stderr, "UNEXPECTED: expected -EPERM before grant, got %d\n", rc);

	if (write(sync_fd, "g", 1) != 1) {
		perror("child write grant-req");
		return 1;
	}
	if (read(sync_fd, &c, 1) != 1) {
		perror("child read grant-ack");
		return 1;
	}

	rc = try_clone_newpid_set_tid(1, 101);
	log("WITH grant:   clone3(CLONE_NEWPID, set_tid=[1,101]) -> %d %s",
		rc, rc == 0 ? "(success)" : strerror(-rc));
	if (rc != 0) {
		fprintf(stderr, "FAIL: expected success under bypass, got %d (%s)\n",
			rc, strerror(-rc));
		return 2;
	}

	if (write(sync_fd, "r", 1) != 1) {
		perror("child write revoke-req");
		return 1;
	}
	if (read(sync_fd, &c, 1) != 1) {
		perror("child read revoke-ack");
		return 1;
	}

	rc = try_clone_newpid_set_tid(1, 102);
	log("AFTER revoke: clone3(CLONE_NEWPID, set_tid=[1,102]) -> %d %s",
		rc, rc == 0 ? "(success)" : strerror(-rc));
	if (rc != -EPERM) {
		fprintf(stderr, "FAIL: expected -EPERM after revoke, got %d (%s)\n",
			rc, rc == 0 ? "success" : strerror(-rc));
		return 3;
	}

	log("TEST PASSED: bypass correctly toggled cap_capable outcome");
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

	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IOLBF, 0);

	if (geteuid() != 0) {
		fprintf(stderr, "Must run as root.\n");
		return 1;
	}

	dev_fd = open(DEVPATH, O_WRONLY);
	if (dev_fd < 0) {
		fprintf(stderr, "open %s: %s (is the module loaded?)\n",
			DEVPATH, strerror(errno));
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
		perror("clone3 child");
		return 1;
	}
	if (child == 0) {
		close(sync_pair[0]);
		close(dev_fd);
		_exit(child_main(sync_pair[1]));
	}
	close(sync_pair[1]);

	if (read(sync_pair[0], &c, 1) != 1) {
		perror("parent read ready");
		return 1;
	}

	if (write_child_maps(child)) {
		fprintf(stderr, "failed to write maps for %d\n", (int)child);
		return 1;
	}
	if (write(sync_pair[0], "m", 1) != 1) {
		perror("parent write maps-ready");
		return 1;
	}

	if (read(sync_pair[0], &c, 1) != 1) {
		perror("parent read grant-req");
		return 1;
	}
	memset(&cba, 0, sizeof(cba));
	cba.target_id    = child;
	cba.flags        = CRIU_CB_TARGET_VPID;
	cba.cap_mask     = 0;
	cba.syscall_mask = 0;
	if (ioctl(dev_fd, CRIU_CB_GRANT, &cba) < 0) {
		perror("ioctl GRANT");
		return 1;
	}
	log("parent: granted bypass for pid %d", (int)child);
	if (write(sync_pair[0], "1", 1) != 1) {
		perror("parent write grant-ack");
		return 1;
	}

	if (read(sync_pair[0], &c, 1) != 1) {
		perror("parent read revoke-req");
		return 1;
	}
	memset(&cba, 0, sizeof(cba));
	cba.target_id = child;
	cba.flags     = CRIU_CB_TARGET_VPID;
	if (ioctl(dev_fd, CRIU_CB_REVOKE, &cba) < 0) {
		perror("ioctl REVOKE");
		return 1;
	}
	log("parent: revoked bypass for pid %d", (int)child);
	if (write(sync_pair[0], "1", 1) != 1) {
		perror("parent write revoke-ack");
		return 1;
	}

	if (waitpid(child, &status, 0) != child) {
		perror("waitpid");
		return 1;
	}
	close(dev_fd);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "child failed: status=0x%x (exited=%d, code=%d)\n",
			status, WIFEXITED(status), WEXITSTATUS(status));
		return 1;
	}

	log("test_capbypass: OK");
	return 0;
}
