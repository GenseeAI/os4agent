#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define READY_PATH "/tmp/tfork-ncopy-nested-pidns-ready"

static void set_name(const char *name)
{
	if (prctl(PR_SET_NAME, name, 0, 0, 0)) {
		perror("prctl(PR_SET_NAME)");
		exit(1);
	}
}

static void park(void)
{
	for (;;)
		pause();
}

static void *thread_main(void *arg)
{
	(void)arg;
	set_name("tfork-thread");
	park();
	return NULL;
}

static void spawn_siblings(int count)
{
	int i;

	for (i = 0; i < count; i++) {
		pid_t pid = fork();

		if (pid < 0) {
			perror("fork sibling");
			exit(1);
		}
		if (pid == 0) {
			execlp("sleep", "tfork-sibling", "3600", NULL);
			perror("exec sleep sibling");
			_exit(1);
		}
	}
}

static void nested_pidns_helper(int thread_count)
{
	pid_t nested_init;
	int status;

	set_name("tfork-helper");
	if (unshare(CLONE_NEWPID)) {
		perror("unshare(CLONE_NEWPID)");
		exit(1);
	}

	nested_init = fork();
	if (nested_init < 0) {
		perror("fork nested init");
		exit(1);
	}
	if (nested_init == 0) {
		pthread_t *threads;
		int fd, i;

		set_name("tfork-ns-init");
		threads = calloc(thread_count, sizeof(*threads));
		if (!threads) {
			perror("calloc threads");
			_exit(1);
		}
		for (i = 0; i < thread_count; i++) {
			int ret = pthread_create(&threads[i], NULL, thread_main, NULL);

			if (ret) {
				errno = ret;
				perror("pthread_create");
				_exit(1);
			}
		}

		fd = open(READY_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			perror("open ready file");
			_exit(1);
		}
		dprintf(fd, "pid=%d threads=%d\n", getpid(), thread_count + 1);
		close(fd);
		park();
		_exit(0);
	}

	if (waitpid(nested_init, &status, 0) != nested_init)
		perror("waitpid nested init");
	exit(1);
}

int main(int argc, char **argv)
{
	int siblings, threads;
	pid_t helper;

	if (argc != 3) {
		fprintf(stderr, "usage: %s SIBLINGS THREADS\n", argv[0]);
		return 2;
	}
	siblings = atoi(argv[1]);
	threads = atoi(argv[2]);
	if (siblings < 1 || threads < 1)
		return 2;

	set_name("tfork-test-root");
	spawn_siblings(siblings);
	helper = fork();
	if (helper < 0) {
		perror("fork helper");
		return 1;
	}
	if (helper == 0)
		nested_pidns_helper(threads);

	while (access(READY_PATH, F_OK))
		usleep(10000);
	execlp("tail", "tail", "-f", "/dev/null", NULL);
	perror("exec tail root");
	return 1;
}
