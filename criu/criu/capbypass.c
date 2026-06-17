#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "criu-log.h"
#include "capbypass.h"
#include "servicefd.h"
#include "../kernel_module/criu_capbypass/uapi_criu_capbypass.h"

#define CAPBYPASS_DEV "/dev/criu_capbypass"

#define CAPBYPASS_FD_ENV  "CRIU_CAPBYPASS_FD"

#undef LOG_PREFIX
#define LOG_PREFIX "capbypass: "

static bool capbypass_ready = false;

bool capbypass_available(void)
{
	return capbypass_ready;
}

static int validate_inherited_fd(int fd)
{
	struct stat fst, dst;

	if (fstat(fd, &fst) < 0) {
		pr_perror("fstat inherited capbypass fd %d", fd);
		return -1;
	}
	if (!S_ISCHR(fst.st_mode)) {
		pr_err("inherited fd %d is not a char device (mode 0%o)\n",
		       fd, fst.st_mode & S_IFMT);
		return -1;
	}
	if (stat(CAPBYPASS_DEV, &dst) < 0) {

		pr_info("inherited fd %d: %s not visible to fstat-compare; "
			"trusting char-device check\n", fd, CAPBYPASS_DEV);
		return 0;
	}
	if (fst.st_rdev != dst.st_rdev) {
		pr_err("inherited fd %d points to char device %u:%u, "
		       "expected %s = %u:%u\n",
		       fd, major(fst.st_rdev), minor(fst.st_rdev),
		       CAPBYPASS_DEV, major(dst.st_rdev), minor(dst.st_rdev));
		return -1;
	}
	return 0;
}

int capbypass_open(void)
{
	const char *env_fd_s = getenv(CAPBYPASS_FD_ENV);
	int fd;

	if (env_fd_s && *env_fd_s) {
		char *endp = NULL;
		long env_fd = strtol(env_fd_s, &endp, 10);

		if (!endp || *endp || env_fd < 0 || env_fd > INT_MAX) {
			pr_err("%s=\"%s\" is not a valid fd; ignoring\n",
			       CAPBYPASS_FD_ENV, env_fd_s);
			env_fd = -1;
		}
		if (env_fd >= 0) {
			if (validate_inherited_fd((int)env_fd) < 0) {
				pr_err("%s=%ld failed validation; bypass disabled\n",
				       CAPBYPASS_FD_ENV, env_fd);
				capbypass_ready = false;
				return 0;
			}
			if (install_service_fd(CAPBYPASS_FD_OFF, (int)env_fd) < 0) {
				pr_err("install_service_fd(CAPBYPASS_FD_OFF) failed for inherited fd\n");
				return -1;
			}
			capbypass_ready = true;

			unsetenv(CAPBYPASS_FD_ENV);
			pr_info("using inherited %s fd %ld as service fd %d\n",
				CAPBYPASS_DEV, env_fd,
				get_service_fd(CAPBYPASS_FD_OFF));
			return 0;
		}
	}

	fd = open(CAPBYPASS_DEV, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		pr_info("%s not available (%s); cap_capable bypass disabled\n",
			CAPBYPASS_DEV, strerror(errno));
		capbypass_ready = false;
		return 0;
	}

	if (install_service_fd(CAPBYPASS_FD_OFF, fd) < 0) {
		pr_err("install_service_fd(CAPBYPASS_FD_OFF) failed\n");
		close(fd);
		return -1;
	}

	capbypass_ready = true;
	pr_info("opened %s as service fd %d\n", CAPBYPASS_DEV,
		get_service_fd(CAPBYPASS_FD_OFF));
	return 0;
}

void capbypass_close(void)
{
	if (!capbypass_ready)
		return;
	close_service_fd(CAPBYPASS_FD_OFF);
	capbypass_ready = false;
	pr_info("closed %s (all grants auto-revoked)\n", CAPBYPASS_DEV);
}

static int do_ioctl(unsigned int cmd, pid_t target)
{
	struct criu_capbypass_args args = {0};
	int fd;

	if (!capbypass_ready)
		return 0;

	fd = get_service_fd(CAPBYPASS_FD_OFF);
	if (fd < 0)
		return 0;

	args.target_id    = target;
	args.flags        = CRIU_CB_TARGET_VPID;
	args.cap_mask     = 0;
	args.syscall_mask = 0;

	if (ioctl(fd, cmd, &args) < 0) {
		pr_perror("ioctl on %s pid=%d", CAPBYPASS_DEV, target);
		return -1;
	}
	return 0;
}

int capbypass_grant(pid_t host_pid)
{
	int ret = do_ioctl(CRIU_CB_GRANT, host_pid);
	if (ret == 0 && capbypass_ready)
		pr_debug("granted bypass for pid=%d\n", host_pid);
	return ret;
}

int capbypass_grant_self(void)
{
	return capbypass_grant(getpid());
}

int capbypass_revoke(pid_t host_pid)
{
	int ret = do_ioctl(CRIU_CB_REVOKE, host_pid);
	if (ret == 0 && capbypass_ready)
		pr_debug("revoked bypass for pid=%d\n", host_pid);
	return ret;
}
