#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "../reparent_uapi.h"

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

#define STACK_SIZE (64 * 1024)
char a_stack[STACK_SIZE];
char c_stack[STACK_SIZE];
pid_t c_pid_hostview;
int c_pidfd;
int c_ready[2];
int sync_main_to_a[2];

uint64_t get_my_ns_id(void)
{
    char path[PATH_MAX];
    struct stat sb;

    snprintf(path, sizeof(path), "/proc/self/ns/pid");
    if (stat(path, &sb) == -1) {
        perror("stat");
        return 0;
    }
    return (uint64_t)sb.st_ino;
}

static int c_process(void *unused)
{
    char c = '1';
    printf("C: Started. My active PID ns is %lu. My PID (in NS): %d\n", get_my_ns_id(), getpid());
    write(c_ready[1], &c, 1);


    printf("C: Sleeping for 20 seconds to allow A to attempt reparenting...\n");
    sleep(120);
    return 0;
}

static int a_process(void *unused)
{
    char c;
    int reparent_fd;
    int original_a_pidfd;
    int status;
    pid_t b_pid, res;
    pid_t original_a_pid = getpid();

    read(sync_main_to_a[0], &c, 1);
    printf("A: Started. My active PID ns is %lu. My PID (in NS): %d\n", get_my_ns_id(), getpid());

    printf("A: saving original pid_for_children namespace...\n");
    original_a_pidfd = syscall(SYS_pidfd_open, getpid(), 0);
    if (original_a_pidfd < 0) {
        perror("A: open original pid_for_children ns");
        exit(1);
    }

    printf("A: Attempting to setns into C's PID NS using FORCE_SET_PIDNS_CMD ioctl...\n");
    reparent_fd = open("/dev/reparent", O_RDWR);
    if (reparent_fd < 0) {
        perror("A: open /dev/reparent module failed");
        exit(1);
    }

    if (ioctl(reparent_fd, FORCE_SET_PIDNS_CMD, &c_pidfd) < 0) {
        perror("A: !!! FORCE_SET_PIDNS_CMD ioctl FAILED !!!");
        exit(1);
    }

    printf("A: Spawning B ...\n");
    sleep(10);
    b_pid = fork();
    if (b_pid < 0) {
        perror("A: fork B failed");
        exit(1);
    }

    if (getpid() != original_a_pid) {
        printf("B: Started. My active PID ns is %lu. My PID (in NS): %d\n", get_my_ns_id(), getpid());
        printf("B: Sleeping for 5 seconds before exiting...\n");
        sleep(10);
        exit(0);

    }

    printf("\nA: Restoring original PID namespace using FORCE_SET_PIDNS_CMD ioctl...\n");
    if (ioctl(reparent_fd, FORCE_SET_PIDNS_CMD, &original_a_pidfd) < 0) {
        perror("A: FORCE_SET_PIDNS_CMD restore failed");
    }
    close(original_a_pidfd);
    close(reparent_fd);
    sleep(30);
    exit(0);
}

int main() {
    char dummy;
    pid_t a_pid_hostview;

    printf("M: PID is %d\n", getpid());

    if (pipe(c_ready) < 0 || pipe(sync_main_to_a) < 0) {
        perror("M: pipe");
        return -1;
    }

    c_pid_hostview = clone(c_process, c_stack + sizeof(c_stack), CLONE_NEWPID | SIGCHLD, NULL);
    if (c_pid_hostview < 0) {
        perror("M: clone C");
        return -1;
    }

    read(c_ready[0], &dummy, 1);

    c_pidfd = syscall(SYS_pidfd_open, c_pid_hostview, 0);
    if (c_pidfd < 0) {
        perror("M: pidfd_open C");
        return -1;
    }

    a_pid_hostview = clone(a_process, a_stack + sizeof(a_stack), CLONE_NEWPID | SIGCHLD, NULL);
    if (a_pid_hostview < 0) {
        perror("M: clone A");
        return -1;
    }

    write(sync_main_to_a[1], "1", 1);
    printf("M: a pid: %d, c pid: %d\n", a_pid_hostview, c_pid_hostview);
    sleep(60);
    return 0;
}
