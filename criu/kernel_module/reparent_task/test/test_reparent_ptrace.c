#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <string.h>

#include "../reparent_uapi.h"

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif

static pid_t get_tracer_pid(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    pid_t tracer_pid = 0;

    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:\t", 11) == 0) {
            tracer_pid = atoi(line + 11);
            break;
        }
    }
    fclose(f);
    return tracer_pid;
}

static int test_ptrace_attach(int trace_fork, int reparent_fd)
{
    int n, c_status, tracer_status, b_status = -1;
    int ret = -1;
    pid_t tracer_pid, a_pid, b_pid, c_pid;
    pid_t main_pgid = getpgid(0);
    pid_t main_sid = getsid(0);
    int pipe_c_ready[2];
    int pipe_sync_b[2];
    int pipe_b_to_c[2];
    int pipe_b_to_a[2];
    int c_pidfd;

    if (pipe(pipe_c_ready) < 0 || pipe(pipe_sync_b) < 0 || pipe(pipe_b_to_c) < 0 || pipe(pipe_b_to_a) < 0) {
        perror("pipe");
        return -1;
    }

    c_pid = fork();
    if (c_pid == 0) {
        char ready[3] = "C1";
        char b_msg[3] = {0};
        pid_t child_pid;

        close(pipe_c_ready[0]);
        close(pipe_sync_b[0]);
        close(pipe_sync_b[1]);
        close(pipe_b_to_c[1]);
        close(pipe_b_to_a[0]);
        close(pipe_b_to_a[1]);

        printf("C: pid - %d, pgid - %d, sid - %d\n", getpid(), getpgid(0), getsid(0));

        write(pipe_c_ready[1], ready, 3);
        n = read(pipe_b_to_c[0], b_msg, 3);
        if (n < 3 || b_msg[0] != 'B' || b_msg[1] != '1') {
            printf("C: Failed to read valid 'B1' message from B\n");
            exit(1);
        }
        printf("C: Received message from B: \'%s\'\n", b_msg);
        close(pipe_b_to_c[0]);

        child_pid = wait(&c_status);
        if (child_pid > 0) {
            ret = WIFEXITED(c_status) && WEXITSTATUS(c_status) == 0 ? 0 : 1;
            printf("C: Reaped child %d with status %d\n", child_pid, WEXITSTATUS(c_status));
        } else {
            perror("C: wait");
            ret = 1;
        }
        exit(ret);
    }

    close(pipe_c_ready[1]);
    char dummy[3] = {0};
    n = read(pipe_c_ready[0], dummy, 3);
    if (n < 3 || dummy[0] != 'C' || dummy[1] != '1') {
        printf("Main: Failed to read valid 'C1' message from C\n");
        return -1;
    }

    c_pidfd = syscall(SYS_pidfd_open, c_pid, 0);
    if (c_pidfd < 0) {
        perror("pidfd_open");
        return -1;
    }

    tracer_pid = fork();
    if (tracer_pid == 0) {
        a_pid = fork();
        if (a_pid == 0) {
            close(pipe_sync_b[0]);
            close(pipe_b_to_c[0]);

            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
                perror("ptrace traceme");
                exit(1);
            }
            raise(SIGSTOP);

            printf("A: pid - %d, pgid - %d, sid - %d\n", getpid(), getpgid(0), getsid(0));
            b_pid = fork();
            if (b_pid == 0) {
                int ret_ioctl;
                int err = 1;
                pid_t new_ppid, new_pgid, new_sid;
                pid_t expected_pgid, expected_sid;
                pid_t initial_tracer_pid, final_tracer_pid;
                char msg_to_c[3] = "B1";
                char msg_to_a[3] = "B2";
                int success;

                initial_tracer_pid = get_tracer_pid();

                ret_ioctl = ioctl(reparent_fd, REPARENT_ME_CMD, &c_pidfd);
                if (ret_ioctl < 0) {
                    perror("ioctl reparent");
                    write(pipe_sync_b[1], &err, sizeof(err));
                    exit(1);
                }

                new_ppid = getppid();
                new_pgid = getpgid(0);
                new_sid = getsid(0);
                final_tracer_pid = get_tracer_pid();
                expected_pgid = main_pgid;
                expected_sid = main_sid;

                printf("B: my new parent is %d (should be %d)\n", new_ppid, c_pid);
                printf("B: my new pgid is %d (should be %d)\n", new_pgid, expected_pgid);
                printf("B: my new sid is %d (should be %d)\n", new_sid, expected_sid);
                printf("B: my initial TracerPid is %d, final TracerPid is %d\n", initial_tracer_pid, final_tracer_pid);

                write(pipe_b_to_c[1], msg_to_c, 3);
                close(pipe_b_to_c[1]);

                write(pipe_b_to_a[1], msg_to_a, 3);
                close(pipe_b_to_a[1]);

                if (new_ppid == c_pid && new_pgid == expected_pgid &&
                    new_sid == expected_sid && initial_tracer_pid == final_tracer_pid)
                    success = 0;
                else
                    success = 2;

                if (trace_fork && final_tracer_pid == 0)
                    success = 2;
                write(pipe_sync_b[1], &success, sizeof(success));
                printf("B: exiting with status %d\n", success);
                exit(success);
            } else if (b_pid > 0) {
                char msg[3] = {0};
                int n_read;

                close(pipe_b_to_c[1]);

                n_read = read(pipe_b_to_a[0], msg, 3);
                if (n_read < 3 || msg[0] != 'B' || msg[1] != '2') {
                    printf("A: Failed to read valid 'B2' message from B\n");
                    exit(1);
                }
                printf("A: Received message from B: \'%s\'\n", msg);
                close(pipe_b_to_a[0]);
                exit(0);
            } else {
                perror("fork B");
                exit(1);
            }
        } else if (a_pid > 0) {

            int status;
            pid_t p;
            int active_tracees = 1;

            close(pipe_sync_b[0]);
            close(pipe_sync_b[1]);
            close(pipe_b_to_c[0]);
            close(pipe_b_to_c[1]);
            close(pipe_b_to_a[0]);
            close(pipe_b_to_a[1]);

            p = waitpid(a_pid, &status, __WALL);
            if (p == a_pid && WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
                if (trace_fork) {
                    ptrace(PTRACE_SETOPTIONS, a_pid, 0, PTRACE_O_TRACEFORK);
                }
                ptrace(PTRACE_CONT, a_pid, NULL, NULL);
            } else {
                printf("Tracer: failed to attach or wait for Process A\n");
                exit(1);
            }

            while (active_tracees > 0) {
                p = waitpid(-1, &status, __WALL);
                if (p < 0) {
                    if (errno == ECHILD) break;
                    continue;
                }

                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    active_tracees--;
                    if (p == a_pid) {
                        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                            printf("Tracer: A exited with failure\n");
                            exit(1);
                        }
                    }
                } else if (WIFSTOPPED(status)) {
                    int sig = WSTOPSIG(status);
                    int event = status >> 16;

                    if (event == PTRACE_EVENT_FORK) {
                        active_tracees++;
                        ptrace(PTRACE_CONT, p, 0, 0);
                    } else {
                        ptrace(PTRACE_CONT, p, 0, (sig == SIGSTOP || sig == SIGTRAP) ? 0 : sig);
                    }
                }
            }
            exit(0);
        } else {
            perror("fork A");
            exit(1);
        }
    }

    close(pipe_sync_b[1]);
    close(pipe_b_to_c[0]);
    close(pipe_b_to_c[1]);
    close(pipe_b_to_a[0]);
    close(pipe_b_to_a[1]);

    n = read(pipe_sync_b[0], &b_status, sizeof(b_status));
    waitpid(tracer_pid, &tracer_status, 0);
    waitpid(c_pid, &c_status, 0);
    close(c_pidfd);

    if (n == sizeof(b_status) && b_status == 0 &&
        WIFEXITED(c_status) && WEXITSTATUS(c_status) == 0 &&
        WIFEXITED(tracer_status) && WEXITSTATUS(tracer_status) == 0) {
        ret = 0;
    } else {
        ret = -1;
    }
    return ret;
}

int test_ptrace_seize(int reparent_fd)
{
    int a_status, c_status, ret = -1;
    pid_t a_pid, b_pid, c_pid;
    int pipe_c_ready[2];
    int pipe_b_pid_to_c[2];
    int pipe_c_attached_to_b[2];
    int pipe_b_to_a[2];
    int c_pidfd;

    printf("M: main process pid: %d\n", getpid());

    if (pipe(pipe_c_ready) < 0 || pipe(pipe_b_pid_to_c) < 0 || pipe(pipe_c_attached_to_b) < 0 || pipe(pipe_b_to_a) < 0) {
        perror("pipe");
        return -1;
    }

    c_pid = fork();
    if (c_pid == 0) {
        pid_t target_b_pid;
        int status;

        close(pipe_c_ready[0]);
        close(pipe_b_pid_to_c[1]);
        close(pipe_c_attached_to_b[0]);
        close(pipe_b_to_a[0]);
        close(pipe_b_to_a[1]);

        printf("C: pid - %d, pgid - %d, sid - %d\n", getpid(), getpgid(0), getsid(0));

        write(pipe_c_ready[1], "C1", 3);
        close(pipe_c_ready[1]);

        if (read(pipe_b_pid_to_c[0], &target_b_pid, sizeof(target_b_pid)) != sizeof(target_b_pid)) {
            printf("C: failed to read B's pid\n");
            exit(1);
        }
        close(pipe_b_pid_to_c[0]);

        printf("C: Received B's pid: %d. Attempting PTRACE_SEIZE...\n", target_b_pid);
        if (ptrace(PTRACE_SEIZE, target_b_pid, NULL, 0) < 0) {
            perror("C: ptrace seize");
            exit(1);
        }

        printf("C: Successfully seized B! (C is Tracer)\n");
        write(pipe_c_attached_to_b[1], "GO", 3);
        close(pipe_c_attached_to_b[1]);

        if (waitpid(target_b_pid, &status, __WALL) == target_b_pid) {
            if (WIFEXITED(status)) {
                printf("C: Reaped B with exit status %d natively through Ptrace\n", WEXITSTATUS(status));
                exit(WEXITSTATUS(status));
            } else {
                printf("C: B did not exit normally!\n");
                exit(1);
            }
        } else {
            perror("C: waitpid for B");
            exit(1);
        }
    }
    close(pipe_c_ready[1]);

    char dummy[3] = {0};
    if (read(pipe_c_ready[0], dummy, 3) < 3 || dummy[0] != 'C' || dummy[1] != '1') {
        printf("Main: Failed to read valid 'C1' message from C\n");
        return -1;
    }
    close(pipe_c_ready[0]);

    c_pidfd = syscall(SYS_pidfd_open, c_pid, 0);
    if (c_pidfd < 0) {
        perror("pidfd_open");
        return -1;
    }

    a_pid = fork();
    if (a_pid == 0) {
        close(pipe_b_pid_to_c[0]);
        close(pipe_c_attached_to_b[1]);

        b_pid = fork();
        if (b_pid == 0) {
            pid_t initial_ppid, new_ppid;
            pid_t initial_tracer, final_tracer;
            char go_msg[3] = {0};
            int ret_ioctl;
            int success = 0;

            initial_ppid = getppid();

            if (read(pipe_c_attached_to_b[0], go_msg, 3) < 3 || strncmp(go_msg, "GO", 2) != 0) {
                printf("B: Failed to wait for C to attach\n");
                exit(1);
            }
            close(pipe_c_attached_to_b[0]);

            initial_tracer = get_tracer_pid();
            printf("B: Before ioctl - PPID: %d, TracerPid: %d (expected C=%d)\n", initial_ppid, initial_tracer, c_pid);
            if (initial_tracer != c_pid) {
                printf("B: Error! Tracer is NOT C!\n");
                success = 2;
            }

            ret_ioctl = ioctl(reparent_fd, REPARENT_ME_CMD, &c_pidfd);
            if (ret_ioctl < 0) {
                perror("B: ioctl reparent");
                exit(1);
            }

            new_ppid = getppid();
            final_tracer = get_tracer_pid();

            printf("B: After ioctl - PPID: %d (expected C=%d), TracerPid: %d (expected C=%d)\n",
                    new_ppid, c_pid, final_tracer, c_pid);

            if (new_ppid != c_pid || final_tracer != c_pid) {
                printf("B: Reparent verification failed dynamically!\n");
                success = 2;
            }

            write(pipe_b_to_a[1], "B2", 3);
            close(pipe_b_to_a[1]);

            printf("B: Exiting with success code %d\n", success);
            exit(success);

        } else if (b_pid > 0) {
            char msg[3] = {0};
            write(pipe_b_pid_to_c[1], &b_pid, sizeof(b_pid));
            close(pipe_b_pid_to_c[1]);
            close(pipe_c_attached_to_b[0]);
            close(pipe_b_to_a[1]);

            printf("A: with pid %d forked B with PID %d and sent it to C\n", getpid(), b_pid);

            if (read(pipe_b_to_a[0], msg, 3) < 3 || strncmp(msg, "B2", 2) != 0) {
                printf("A: Failed to read valid 'B2' message from B\n");
                exit(1);
            }
            close(pipe_b_to_a[0]);
            exit(0);
        } else {
            perror("fork B");
            exit(1);
        }
    }

    close(pipe_b_pid_to_c[0]);
    close(pipe_b_pid_to_c[1]);
    close(pipe_c_attached_to_b[0]);
    close(pipe_c_attached_to_b[1]);
    close(pipe_b_to_a[0]);
    close(pipe_b_to_a[1]);

    waitpid(a_pid, &a_status, 0);
    waitpid(c_pid, &c_status, 0);
    close(c_pidfd);

    if (WIFEXITED(c_status) && WEXITSTATUS(c_status) == 0 &&
        WIFEXITED(a_status) && WEXITSTATUS(a_status) == 0) {
        ret = 0;
    } else {
        printf("Result: Test Seize + Process C traced Failed. C status: %d, A status: %d\n",
                WIFEXITED(c_status) ? WEXITSTATUS(c_status) : -1,
                WIFEXITED(a_status) ? WEXITSTATUS(a_status) : -1);
        ret = -1;
    }

    return ret;
}

int test_ptrace_parent_traced(int reparent_fd)
{
    int tracer_a_status, tracer_c_status, ret = -1;
    pid_t tracer_a_pid, tracer_c_pid;
    pid_t a_pid, b_pid, c_pid;

    int pipe_c_pid[2];
    int pipe_b_pid[2];
    int pipe_c_ready[2];
    int pipe_a_ready[2];
    int pipe_sync_b[2];
    int pipe_b_to_c[2];

    printf("M: main process pid: %d\n", getpid());

    if (pipe(pipe_c_pid) < 0 || pipe(pipe_b_pid) < 0 || pipe(pipe_c_ready) < 0 || pipe(pipe_a_ready) < 0 || pipe(pipe_sync_b) < 0 || pipe(pipe_b_to_c) < 0) {
        perror("pipe");
        return -1;
    }

    tracer_c_pid = fork();
    if (tracer_c_pid == 0) {
        c_pid = fork();
        if (c_pid == 0) {
            pid_t target_b_pid;
            int status;

            close(pipe_c_pid[0]);
            close(pipe_b_pid[1]);
            close(pipe_c_ready[0]);
            close(pipe_a_ready[0]);
            close(pipe_a_ready[1]);
            close(pipe_sync_b[0]);
            close(pipe_sync_b[1]);
            close(pipe_b_to_c[1]);

            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
                perror("C: ptrace traceme");
                exit(1);
            }
            raise(SIGSTOP);

            pid_t my_pid = getpid();
            write(pipe_c_pid[1], &my_pid, sizeof(my_pid));
            close(pipe_c_pid[1]);

            if (read(pipe_b_pid[0], &target_b_pid, sizeof(target_b_pid)) != sizeof(target_b_pid)) {
                printf("C: failed to read B's pid\n");
                exit(1);
            }
            close(pipe_b_pid[0]);

            write(pipe_c_ready[1], "C1", 3);
            close(pipe_c_ready[1]);

            char b_msg[3] = {0};
            if (read(pipe_b_to_c[0], b_msg, 3) < 3 || strncmp(b_msg, "B1", 2) != 0) {
                printf("C: failed to get b_to_c sync msg\n");
                exit(1);
            }
            close(pipe_b_to_c[0]);

            if (waitpid(target_b_pid, &status, 0) == target_b_pid) {
                if (WIFEXITED(status)) {
                    int exit_val = WEXITSTATUS(status);
                    printf("C: Reaped B natively! (Exit status %d)\n", exit_val);
                    exit(exit_val);
                } else {
                    printf("C: B didn't exit normally!\n");
                    exit(1);
                }
            } else {
                perror("C: waitpid B");
                exit(1);
            }
        } else if (c_pid > 0) {
            int status;
            pid_t p;
            close(pipe_c_pid[0]); close(pipe_c_pid[1]);
            close(pipe_b_pid[0]); close(pipe_b_pid[1]);
            close(pipe_c_ready[0]); close(pipe_c_ready[1]);
            close(pipe_a_ready[0]); close(pipe_a_ready[1]);
            close(pipe_sync_b[0]); close(pipe_sync_b[1]);
            close(pipe_b_to_c[0]); close(pipe_b_to_c[1]);

            p = waitpid(c_pid, &status, __WALL);
            if (p == c_pid && WIFSTOPPED(status)) {
                ptrace(PTRACE_CONT, c_pid, 0, 0);
            }

            while (1) {
                p = waitpid(-1, &status, __WALL);
                if (p < 0) {
                    if (errno == ECHILD) break;
                    continue;
                }
                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    if (p == c_pid) {
                        exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
                    }
                } else if (WIFSTOPPED(status)) {
                    int sig = WSTOPSIG(status);
                    ptrace(PTRACE_CONT, p, 0, (sig == SIGSTOP || sig == SIGTRAP) ? 0 : sig);
                }
            }
            exit(0);
        } else {
            perror("fork C"); exit(1);
        }
    }

    close(pipe_c_pid[1]);
    if (read(pipe_c_pid[0], &c_pid, sizeof(c_pid)) != sizeof(c_pid)) {
        printf("Main: failed to get C pid\n");
        return -1;
    }
    close(pipe_c_pid[0]);

    int c_pidfd = syscall(SYS_pidfd_open, c_pid, 0);
    if (c_pidfd < 0) {
        perror("pidfd_open");
        return -1;
    }

    tracer_a_pid = fork();
    if (tracer_a_pid == 0) {
        a_pid = fork();
        if (a_pid == 0) {
            close(pipe_c_ready[0]); close(pipe_c_ready[1]);
            close(pipe_b_pid[0]);
            close(pipe_sync_b[0]);
            close(pipe_b_to_c[0]);

            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
                perror("A: ptrace traceme");
                exit(1);
            }
            raise(SIGSTOP);

            b_pid = fork();
            if (b_pid == 0) {
                int ret_ioctl;
                int success = 0;
                pid_t initial_tracer, final_tracer;
                char dummy[3] = {0};

                pid_t my_pid = getpid();
                write(pipe_b_pid[1], &my_pid, sizeof(my_pid));
                close(pipe_b_pid[1]);

                if (read(pipe_a_ready[0], dummy, 3) < 3 || strncmp(dummy, "GO", 2) != 0) {
                    printf("B: Failed to get GO from M\n");
                    exit(1);
                }
                close(pipe_a_ready[0]);

                initial_tracer = get_tracer_pid();
                ret_ioctl = ioctl(reparent_fd, REPARENT_ME_CMD, &c_pidfd);
                if (ret_ioctl < 0) {
                    perror("B: ioctl reparent");
                    exit(1);
                }
                final_tracer = get_tracer_pid();

                printf("B: Reparent successful! Initial Tracer: %d, Final Tracer: %d\n", initial_tracer, final_tracer);
                if (initial_tracer == 0 || initial_tracer != final_tracer) {
                    printf("B: Tracer consistency validation failed natively!\n");
                    success = 2;
                }

                write(pipe_b_to_c[1], "B1", 3);
                close(pipe_b_to_c[1]);

                write(pipe_sync_b[1], &success, sizeof(success));
                close(pipe_sync_b[1]);
                exit(success);

            } else if (b_pid > 0) {
                close(pipe_b_pid[1]);
                close(pipe_a_ready[0]); close(pipe_a_ready[1]);
                close(pipe_sync_b[1]);
                close(pipe_b_to_c[1]);
                exit(0);
            } else {
                perror("fork B");
                exit(1);
            }
        } else if (a_pid > 0) {
            int status;
            pid_t p;
            int active_tracees = 1;

            close(pipe_c_ready[0]); close(pipe_c_ready[1]);
            close(pipe_b_pid[0]); close(pipe_b_pid[1]);
            close(pipe_a_ready[0]); close(pipe_a_ready[1]);
            close(pipe_sync_b[0]); close(pipe_sync_b[1]);
            close(pipe_b_to_c[0]); close(pipe_b_to_c[1]);

            p = waitpid(a_pid, &status, __WALL);
            if (p == a_pid && WIFSTOPPED(status)) {
                ptrace(PTRACE_SETOPTIONS, a_pid, 0, PTRACE_O_TRACEFORK);
                ptrace(PTRACE_CONT, a_pid, 0, 0);
            }

            while (active_tracees > 0) {
                p = waitpid(-1, &status, __WALL);
                if (p < 0) {
                    if (errno == ECHILD) break;
                    continue;
                }

                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    active_tracees--;
                    if (p != a_pid)
                        printf("Tracer A: Reaped B via WIFEXITED. B natively passes to C now.\n");
                } else if (WIFSTOPPED(status)) {
                    int sig = WSTOPSIG(status);
                    int event = status >> 16;
                    if (event == PTRACE_EVENT_FORK) {
                        active_tracees++;
                        ptrace(PTRACE_CONT, p, 0, 0);
                    } else {
                        ptrace(PTRACE_CONT, p, 0, (sig == SIGSTOP || sig == SIGTRAP) ? 0 : sig);
                    }
                }
            }
            exit(0);
        } else {
            perror("fork A"); exit(1);
        }
    }

    close(pipe_b_pid[0]);
    close(pipe_b_pid[1]);
    close(pipe_b_to_c[0]);
    close(pipe_b_to_c[1]);

    char dummy[3] = {0};
    if (read(pipe_c_ready[0], dummy, 3) < 3 || strncmp(dummy, "C1", 2) != 0) {
        printf("Main: C not ready\n");
        return -1;
    }
    close(pipe_c_ready[0]);

    write(pipe_a_ready[1], "GO", 3);
    close(pipe_a_ready[1]);
    close(pipe_a_ready[0]);

    int b_status_ret = -1;
    read(pipe_sync_b[0], &b_status_ret, sizeof(b_status_ret));
    close(pipe_sync_b[0]);

    waitpid(tracer_a_pid, &tracer_a_status, 0);
    waitpid(tracer_c_pid, &tracer_c_status, 0);
    close(c_pidfd);

    if (b_status_ret == 0 &&
        WIFEXITED(tracer_c_status) && WEXITSTATUS(tracer_c_status) == 0 &&
        WIFEXITED(tracer_a_status) && WEXITSTATUS(tracer_a_status) == 0) {
        ret = 0;
    } else {
        printf("M: Test Traced_C + Traced_B Failed. Tracer C: %d, Tracer A: %d, B stat: %d\n",
                WIFEXITED(tracer_c_status) ? WEXITSTATUS(tracer_c_status) : -1,
                WIFEXITED(tracer_a_status) ? WEXITSTATUS(tracer_a_status) : -1,
                b_status_ret);
        ret = -1;
    }

    return ret;
}

int main(void) {
    int passed = 0;
    int reparent_fd = open("/dev/reparent", O_RDWR);
    if (reparent_fd < 0) {
        perror("open /dev/reparent");
        exit(2);
    }

    setbuf(stdout, NULL);
    printf("M: main process pid: %d\n", getpid());

    printf("\n--- Test Case 1: B does NOT inherit ptrace ---\n");
    if (test_ptrace_attach(0, reparent_fd) == 0) {
        printf("Result: PASSED\n");
        passed++;
    } else {
        printf("Result: FAILED\n");
    }

    printf("\n--- Test Case 2: B DOES inherit ptrace ---\n");
    if (test_ptrace_attach(1, reparent_fd) == 0) {
        printf("Result: PASSED\n");
        passed++;
    } else {
        printf("Result: FAILED\n");
    }

    printf("\n--- Test Case 3: uses PTRACE_SEIZE ---\n");
    if (test_ptrace_seize(reparent_fd) == 0) {
        printf("Result: PASSED\n");
        passed++;
    } else {
        printf("Result: FAILED\n");
    }

    printf("\n--- Test Case 4: both parents are traced ---\n");
    if (test_ptrace_parent_traced(reparent_fd) == 0) {
        printf("Result: PASSED\n");
        passed++;
    } else {
        printf("Result: FAILED\n");
    }

    printf("\n===================================\n");
    printf("ALL TESTS SUMMARY: %d / 4 CASES PASSED.\n", passed);
    printf("===================================\n");

    close(reparent_fd);
    return passed == 4 ? 0 : 1;
}
