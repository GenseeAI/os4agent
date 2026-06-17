#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "criu-log.h"
#include "pkey_state.h"
#include "servicefd.h"
#include "../kernel_module/pkey_state/uapi_pkey_state.h"

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

#define PKEY_STATE_DEV    "/dev/pkey_state"
#define PKEY_STATE_FD_ENV "CRIU_PKEY_STATE_FD"

#undef LOG_PREFIX
#define LOG_PREFIX "pkey_state: "

static int pidfd_open_for(pid_t host_pid)
{
	int pidfd;

	pidfd = syscall(__NR_pidfd_open, host_pid, 0);
	if (pidfd < 0) {
		pr_perror("pidfd_open(%d)", host_pid);
		return -1;
	}
	return pidfd;
}

static bool pkey_state_ready = false;

bool pkey_state_available(void)
{
	return pkey_state_ready;
}

static int validate_inherited_fd(int fd)
{
	struct stat fst, dst;

	if (fstat(fd, &fst) < 0) {
		pr_perror("fstat inherited pkey_state fd %d", fd);
		return -1;
	}
	if (!S_ISCHR(fst.st_mode)) {
		pr_err("inherited fd %d is not a char device (mode 0%o)\n",
		       fd, fst.st_mode & S_IFMT);
		return -1;
	}
	if (stat(PKEY_STATE_DEV, &dst) < 0) {

		pr_info("inherited fd %d: %s not visible to fstat-compare; "
			"trusting char-device check\n", fd, PKEY_STATE_DEV);
		return 0;
	}
	if (fst.st_rdev != dst.st_rdev) {
		pr_err("inherited fd %d points to char device %u:%u, "
		       "expected %s = %u:%u\n",
		       fd, major(fst.st_rdev), minor(fst.st_rdev),
		       PKEY_STATE_DEV, major(dst.st_rdev), minor(dst.st_rdev));
		return -1;
	}
	return 0;
}

int pkey_state_init(void)
{
	const char *env_fd_s = getenv(PKEY_STATE_FD_ENV);
	struct stat st;
	int fd;

	if (pkey_state_ready) {
		pr_debug("already initialized (sfd=%d)\n",
			 get_service_fd(PKEY_STATE_FD_OFF));
		return 0;
	}

	if (env_fd_s && *env_fd_s) {
		char *endp = NULL;
		long env_fd = strtol(env_fd_s, &endp, 10);

		if (!endp || *endp || env_fd < 0 || env_fd > INT_MAX) {
			pr_err("%s=\"%s\" is not a valid fd; ignoring\n",
			       PKEY_STATE_FD_ENV, env_fd_s);
			env_fd = -1;
		}
		if (env_fd >= 0) {
			if (validate_inherited_fd((int)env_fd) < 0) {
				pr_err("%s=%ld failed validation; pkey roundtrip disabled\n",
				       PKEY_STATE_FD_ENV, env_fd);
				return 0;
			}
			if (install_service_fd(PKEY_STATE_FD_OFF, (int)env_fd) < 0) {
				pr_err("install_service_fd(PKEY_STATE_FD_OFF) failed for inherited fd\n");
				return -1;
			}
			pkey_state_ready = true;

			unsetenv(PKEY_STATE_FD_ENV);
			pr_info("using inherited %s fd %ld as service fd %d\n",
				PKEY_STATE_DEV, env_fd,
				get_service_fd(PKEY_STATE_FD_OFF));
			return 0;
		}
	}

	if (stat(PKEY_STATE_DEV, &st) < 0) {
		if (errno == ENOENT) {
			pr_info("%s not present — pkey allocation map will "
				"NOT be roundtripped (chromium-style "
				"pkey_alloc users may SIGILL post-restore; "
				"see Documentation/CRIU_PKEY_STATE_DESIGN.md)\n",
				PKEY_STATE_DEV);
			return 0;
		}
		pr_perror("stat %s", PKEY_STATE_DEV);
		return 0;
	}

	if (!S_ISCHR(st.st_mode)) {
		pr_warn("%s exists but is not a char device (mode 0%o); "
			"skipping\n", PKEY_STATE_DEV, st.st_mode & S_IFMT);
		return 0;
	}

	fd = open(PKEY_STATE_DEV, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("open %s (continuing without pkey state roundtrip)",
			  PKEY_STATE_DEV);
		return 0;
	}

	if (install_service_fd(PKEY_STATE_FD_OFF, fd) < 0) {
		pr_err("install_service_fd(PKEY_STATE_FD_OFF) failed\n");
		close(fd);
		return -1;
	}
	pkey_state_ready = true;
	pr_info("ready (sfd=%d): per-mm pkey allocation map will be "
		"dumped+restored\n", get_service_fd(PKEY_STATE_FD_OFF));
	return 0;
}

void pkey_state_close(void)
{
	close_service_fd(PKEY_STATE_FD_OFF);
	pkey_state_ready = false;
}

int pkey_state_get(pid_t host_pid, uint32_t *allocation_map,
		   int32_t *execute_only_pkey)
{
	struct pkey_state_args args = {
		.flags = PKEY_STATE_FLAG_PIDFD,
	};
	int pidfd, ret;

	if (!pkey_state_ready)
		return -ENOTSUP;

	pidfd = pidfd_open_for(host_pid);
	if (pidfd < 0)
		return -1;
	args.target_id = pidfd;

	ret = ioctl(get_service_fd(PKEY_STATE_FD_OFF), PKEY_STATE_GET, &args);
	close(pidfd);

	if (ret < 0) {
		pr_perror("PKEY_STATE_GET pid=%d", host_pid);
		return -1;
	}

	*allocation_map    = args.pkey_allocation_map;
	*execute_only_pkey = args.execute_only_pkey;
	pr_debug("GET pid=%d map=0x%x exec_only=%d\n",
		 host_pid, *allocation_map, *execute_only_pkey);
	return 0;
}

int pkey_state_set(pid_t host_pid, uint32_t allocation_map,
		   int32_t execute_only_pkey)
{
	struct pkey_state_args args = {
		.flags               = PKEY_STATE_FLAG_PIDFD,
		.pkey_allocation_map = allocation_map,
		.execute_only_pkey   = execute_only_pkey,
	};
	int pidfd, ret;

	if (!pkey_state_ready)
		return -ENOTSUP;

	pidfd = pidfd_open_for(host_pid);
	if (pidfd < 0)
		return -1;
	args.target_id = pidfd;

	ret = ioctl(get_service_fd(PKEY_STATE_FD_OFF), PKEY_STATE_SET, &args);
	close(pidfd);

	if (ret < 0) {
		pr_perror("PKEY_STATE_SET pid=%d map=0x%x exec_only=%d",
			  host_pid, allocation_map, execute_only_pkey);
		return -1;
	}

	pr_debug("SET pid=%d map=0x%x exec_only=%d\n",
		 host_pid, allocation_map, execute_only_pkey);
	return 0;
}
