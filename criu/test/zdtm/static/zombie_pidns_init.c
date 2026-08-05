#include <sched.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check that an outer pid namespace can reap a restored zombie init";
const char *test_author = "GenseeAI";

#define ZOMBIE_EXIT_CODE 42

int main(int argc, char **argv)
{
	siginfo_t info;
	pid_t zombie;
	int status;

	test_init(argc, argv);

	/* The next child becomes init (PID 1) of a nested PID namespace. */
	if (unshare(CLONE_NEWPID) < 0) {
		pr_perror("Unable to create nested pid namespace");
		return 1;
	}

	zombie = fork();
	if (zombie < 0) {
		pr_perror("fork failed");
		return 1;
	}

	if (zombie == 0) {
		if (getpid() != 1)
			_exit(1);
		_exit(ZOMBIE_EXIT_CODE);
	}

	/* Observe the exit without reaping it, so CRIU must restore the zombie. */
	if (waitid(P_PID, zombie, &info, WNOWAIT | WEXITED) < 0) {
		pr_perror("Unable to observe zombie pid %d", zombie);
		return 1;
	}
	if (info.si_pid != zombie || info.si_code != CLD_EXITED ||
	    info.si_status != ZOMBIE_EXIT_CODE) {
		fail("Unexpected pre-dump zombie status: pid=%d code=%d status=%d",
		     info.si_pid, info.si_code, info.si_status);
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (waitpid(zombie, &status, 0) != zombie) {
		pr_perror("Unable to reap restored zombie pid %d", zombie);
		return 1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != ZOMBIE_EXIT_CODE) {
		fail("Restored zombie has wrong status: %#x", status);
		return 1;
	}

	pass();
	return 0;
}
