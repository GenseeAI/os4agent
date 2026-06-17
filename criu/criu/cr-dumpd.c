#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#include "common/scm.h"

#define LOG_PREFIX "dumpd: "
#include "log.h"
#include "cr-tfork.h"
#include "cr_options.h"
#include "kernel_module/reparent_task/reparent_uapi.h"

#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

static int dumpd_handle_one(int control_sock, int reparent_dev_fd,
			    int self_pidfd, int *in_flight, int *eof_seen)
{
	struct pollfd pfd = {.fd = control_sock, .events = POLLIN};
	int helper_pidfd = -1;
	struct reparent_task_arg rep;
	int rc;

	rc = poll(&pfd, 1, *in_flight ? 100 : -1);
	if (rc < 0) {
		if (errno == EINTR)
			return 0;
		pr_perror("dumpd: poll failed");
		return -1;
	}

	if (rc > 0 && (pfd.revents & POLLIN)) {
		rc = recv_fd(control_sock);
		if (rc < 0) {

			if (rc == -ENOMSG || rc == 0 ||
			    (pfd.revents & (POLLHUP | POLLERR)))
				*eof_seen = 1;
			else
				pr_perror("dumpd: recv_fd failed (rc=%d)", rc);
		} else {
			char ack;
			helper_pidfd = rc;
			rep.target_pidfd = helper_pidfd;
			rep.new_parent_pidfd = self_pidfd;
			if (ioctl(reparent_dev_fd, REPARENT_TASK_CMD, &rep) < 0) {
				pr_perror("dumpd: REPARENT_TASK_CMD failed");
				ack = 0;
				close(helper_pidfd);
			} else {
				(*in_flight)++;
				close(helper_pidfd);
				ack = 1;
			}
			if (write(control_sock, &ack, 1) != 1)
				pr_perror("dumpd: write ack failed");
		}
	} else if (pfd.revents & (POLLHUP | POLLERR)) {
		*eof_seen = 1;
	}

	while (*in_flight > 0) {
		int status;
		pid_t pid = waitpid(-1, &status, WNOHANG);
		if (pid > 0) {
			(*in_flight)--;
			pr_debug("dumpd: reaped child pid=%d status=0x%x\n",
				 pid, status);
		} else if (pid == 0) {
			break;
		} else {
			if (errno == ECHILD)
				*in_flight = 0;
			else
				pr_perror("dumpd: waitpid failed");
			break;
		}
	}
	return 0;
}

static void dumpd_fdatasync_images(int img_dir_fd)
{
	DIR *d;
	int dfd;
	struct dirent *de;

	if (img_dir_fd < 0)
		return;

	dfd = fcntl(img_dir_fd, F_DUPFD_CLOEXEC, 0);
	if (dfd < 0) {
		pr_pwarn("dumpd: dup(img_dir_fd) for fdatasync failed");
		return;
	}
	d = fdopendir(dfd);
	if (!d) {
		pr_pwarn("dumpd: fdopendir failed");
		close(dfd);
		return;
	}

	while ((de = readdir(d))) {
		int fd;
		if (strncmp(de->d_name, "pages-", 6) != 0 &&
		    strncmp(de->d_name, "pagemap-", 8) != 0)
			continue;

		fd = openat(img_dir_fd, de->d_name, O_RDONLY);
		if (fd < 0) {
			pr_pwarn("dumpd: openat(%s) for fdatasync failed",
				 de->d_name);
			continue;
		}
		if (fdatasync(fd) < 0)
			pr_pwarn("dumpd: fdatasync(%s) failed", de->d_name);
		close(fd);
	}
	closedir(d);
}


static void dumpd_publish_done(int img_dir_fd, int inflight_fd)
{
	int dst;

	if (img_dir_fd < 0)
		return;

	dumpd_fdatasync_images(img_dir_fd);

	dst = openat(img_dir_fd, ".dump.done.tmp",
		     O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (dst < 0) {
		pr_perror("dumpd: openat(.dump.done.tmp) failed");
	} else {
		if (write(dst, "ok\n", 3) != 3)
			pr_perror("dumpd: write(.dump.done.tmp) failed");
		close(dst);
		if (renameat(img_dir_fd, ".dump.done.tmp",
			     img_dir_fd, ".dump.done") < 0)
			pr_perror("dumpd: renameat(.dump.done) failed");
	}

	if (unlinkat(img_dir_fd, ".dump.inflight", 0) < 0)
		pr_perror("dumpd: unlinkat(.dump.inflight) failed");

	(void)inflight_fd;
}


static int dumpd_reparent_to(int reparent_dev_fd, int self_pidfd,
			     pid_t target_pid)
{
	struct stat self_st, target_st;
	char path[64];
	struct reparent_task_arg rep;
	int target_pidfd;

	if (stat("/proc/self/ns/pid", &self_st) < 0) {
		pr_perror("dumpd: stat(/proc/self/ns/pid) failed");
		return -1;
	}
	snprintf(path, sizeof(path), "/proc/%d/ns/pid", target_pid);
	if (stat(path, &target_st) < 0) {
		pr_perror("dumpd: stat(%s) failed (target pid %d gone?)",
			  path, target_pid);
		return -1;
	}
	if (self_st.st_ino != target_st.st_ino ||
	    self_st.st_dev != target_st.st_dev) {
		pr_err("dumpd: --tfork-dumpd-parent=%d lives in a different "
		       "pidns (self ino=%lu vs target ino=%lu); refusing to "
		       "reparent (kernel module's cross-pidns reparent can "
		       "crash on waitpid). Pass a host-pidns PID.\n",
		       target_pid, (unsigned long)self_st.st_ino,
		       (unsigned long)target_st.st_ino);
		return -1;
	}

	target_pidfd = syscall(__NR_pidfd_open, target_pid, 0);
	if (target_pidfd < 0) {
		pr_perror("dumpd: pidfd_open(%d) for new parent failed",
			  target_pid);
		return -1;
	}

	rep.target_pidfd = self_pidfd;
	rep.new_parent_pidfd = target_pidfd;
	if (ioctl(reparent_dev_fd, REPARENT_TASK_CMD, &rep) < 0) {
		pr_perror("dumpd: REPARENT_TASK_CMD(self -> pid %d) failed",
			  target_pid);
		close(target_pidfd);
		return -1;
	}
	close(target_pidfd);

	if (prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0) < 0)
		pr_pwarn("dumpd: PR_SET_PDEATHSIG(SIGTERM) failed");

	pr_info("dumpd: reparented to pid %d, PDEATHSIG=SIGTERM\n",
		target_pid);
	return 0;
}

static volatile sig_atomic_t dumpd_sigterm_received = 0;

static void dumpd_sigterm_handler(int signo)
{
	(void)signo;
	dumpd_sigterm_received = 1;
}

int run_dumpd_loop(int control_sock, int inflight_fd, int img_dir_fd)
{
	struct sigaction sa;
	int reparent_dev_fd;
	int self_pidfd;
	int in_flight = 0;
	int eof_seen = 0;

	if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0)
		pr_perror("dumpd: PR_SET_CHILD_SUBREAPER failed");

	sa.sa_handler = dumpd_sigterm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGTERM, &sa, NULL) < 0)
		pr_perror("dumpd: sigaction(SIGTERM) failed");

	reparent_dev_fd = open(REPARENT_DEV, O_WRONLY);
	if (reparent_dev_fd < 0) {
		pr_perror("dumpd: can't open %s (is reparent_task module "
			  "loaded?)", REPARENT_DEV);
		return -1;
	}

	self_pidfd = syscall(__NR_pidfd_open, getpid(), 0);
	if (self_pidfd < 0) {
		pr_perror("dumpd: pidfd_open(self) failed");
		close(reparent_dev_fd);
		return -1;
	}

	if (opts.tfork.dumpd_parent_pid > 0) {
		if (dumpd_reparent_to(reparent_dev_fd, self_pidfd,
				      opts.tfork.dumpd_parent_pid) < 0) {
			pr_err("dumpd: reparent to pid %d failed; bailing "
			       "(strict mode — fix orchestration and retry)\n",
			       opts.tfork.dumpd_parent_pid);
			close(reparent_dev_fd);
			close(self_pidfd);
			close(control_sock);
			if (inflight_fd >= 0)
				close(inflight_fd);
			if (img_dir_fd >= 0)
				close(img_dir_fd);
			return -1;
		}
	}

	pr_info("dumpd: ready (pid=%d)\n", getpid());

	while (!(eof_seen && in_flight == 0)) {
		if (dumpd_sigterm_received)
			break;
		if (dumpd_handle_one(control_sock, reparent_dev_fd,
				     self_pidfd, &in_flight, &eof_seen) < 0)
			break;
	}

	if (dumpd_sigterm_received) {
		pr_info("dumpd: SIGTERM caught (parent died via "
			"PR_SET_PDEATHSIG); leaving .dump.inflight in place "
			"and exiting (eof=%d in_flight=%d)\n",
			eof_seen, in_flight);
	} else {
		pr_info("dumpd: drained (eof=%d in_flight=%d), publishing "
			".dump.done\n", eof_seen, in_flight);
		dumpd_publish_done(img_dir_fd, inflight_fd);
	}

	close(reparent_dev_fd);
	close(self_pidfd);
	close(control_sock);
	if (inflight_fd >= 0)
		close(inflight_fd);
	if (img_dir_fd >= 0)
		close(img_dir_fd);
	return 0;
}
