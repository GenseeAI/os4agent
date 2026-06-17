#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>

#include "../reparent_uapi.h"

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

enum proc_state {
    STATE_NORMAL = 0,
    STATE_PGL,
    STATE_SL
};

static const char *state_to_str(enum proc_state st)
{
    switch (st) {
        case STATE_NORMAL:  return "Normal";
        case STATE_PGL:     return "Process Group Leader";
        case STATE_SL:      return "Session Leader";
        default:            return "Unknown";
    }
}

int run_test_case(enum proc_state a_state, enum proc_state c_state, int reparent_fd)
{
    int n, a_status, b_status, c_status, ret = -1;
    pid_t a_pid, b_pid, c_pid;
    pid_t main_pgid = getpgid(0);
    pid_t main_sid = getsid(0);
    int pipe_c_ready[2];
    int pipe_sync_b[2];
    int pipe_b_to_c[2];
    int pipe_b_to_a[2];
    char dummy[3] = {0};
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

        if (c_state == STATE_PGL) {
            setpgid(0, 0);
        } else if (c_state == STATE_SL) {
            setsid();
        }

        printf("C: pid - %d, pgid - %d, sid - %d\n", getpid(), getpgid(0), getsid(0));

        close(pipe_c_ready[0]);
        close(pipe_sync_b[0]);
        close(pipe_sync_b[1]);
        close(pipe_b_to_c[1]);

        write(pipe_c_ready[1], ready, 3);
        n = read(pipe_b_to_c[0], b_msg, 3);
        if (n < 3 || b_msg[0] != 'B' || b_msg[1] != '1') {
            printf("C: Failed to read valid 'B1' message from B\n");
            exit(1);
        }
        close(pipe_b_to_c[0]);

        child_pid = wait(&c_status);
        if (child_pid > 0) {
            ret = WIFEXITED(c_status) && WEXITSTATUS(c_status) == 0 ? 0 : 1;
        } else {
            perror("C: wait");
            ret = 1;
        }
        exit(ret);
    }

    close(pipe_c_ready[1]);
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

    a_pid = fork();
    if (a_pid == 0) {
        close(pipe_sync_b[0]);
        close(pipe_b_to_c[0]);

        if (a_state == STATE_PGL) {
            setpgid(0, 0);
        } else if (a_state == STATE_SL) {
            setsid();
        }

        printf("A: pid - %d, pgid - %d, sid - %d\n", getpid(), getpgid(0), getsid(0));

        b_pid = fork();
        if (b_pid == 0) {
            int ret_ioctl;
            int err = 1;
            pid_t new_ppid, new_pgid, new_sid;
            pid_t expected_pgid, expected_sid;
            char msg_to_c[3] = "B1";
            char msg_to_a[3] = "B2";
            int success;

            ret_ioctl = ioctl(reparent_fd, REPARENT_ME_CMD, &c_pidfd);
            if (ret_ioctl < 0) {
                perror("ioctl reparent");
                write(pipe_sync_b[1], &err, sizeof(err));
                exit(1);
            }

            new_ppid = getppid();
            new_pgid = getpgid(0);
            new_sid = getsid(0);

            expected_pgid = (c_state == STATE_NORMAL) ? main_pgid : c_pid;
            expected_sid = (c_state == STATE_SL) ? c_pid : main_sid;

            printf("B: my new parent is %d (should be C=%d)\n", new_ppid, c_pid);
            printf("B: my new pgid is %d (should be %d)\n", new_pgid, expected_pgid);
            printf("B: my new sid is %d (should be %d)\n", new_sid, expected_sid);

            write(pipe_b_to_c[1], msg_to_c, 3);
            close(pipe_b_to_c[1]);

            write(pipe_b_to_a[1], msg_to_a, 3);
            close(pipe_b_to_a[1]);

            success = (new_ppid == c_pid && new_pgid == expected_pgid && new_sid == expected_sid) ? 0 : 2;
            write(pipe_sync_b[1], &success, sizeof(success));
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
            close(pipe_b_to_a[0]);
            exit(0);
        } else {
            perror("fork B");
            exit(1);
        }
    }

    close(pipe_sync_b[1]);
    close(pipe_b_to_c[0]);
    close(pipe_b_to_c[1]);
    close(pipe_b_to_a[0]);
    close(pipe_b_to_a[1]);

    b_status = -1;
    n = read(pipe_sync_b[0], &b_status, sizeof(b_status));
    waitpid(a_pid, &a_status, 0);
    waitpid(c_pid, &c_status, 0);
    close(c_pidfd);

    if (n == sizeof(b_status) && b_status == 0 &&
        WIFEXITED(c_status) && WEXITSTATUS(c_status) == 0 &&
        WIFEXITED(a_status) && WEXITSTATUS(a_status) == 0) {
        ret = 0;
    } else {
        ret = -1;
    }
    return ret;
}

int main(void)
{
    int reparent_fd;
    int total_cases = 0;
    int passed_cases = 0;
    int a_state, c_state;
    int ret;

    setbuf(stdout, NULL);
    printf("M: main process pid: %d\n", getpid());

    reparent_fd = open("/dev/reparent", O_RDWR);
    if (reparent_fd < 0) {
        perror("open /dev/reparent (is the module loaded?)");
        exit(2);
    }

    for (a_state = STATE_NORMAL; a_state <= STATE_SL; a_state++) {
        for (c_state = STATE_NORMAL; c_state <= STATE_SL; c_state++) {
            total_cases++;
            printf("\n--- Test Case %d ---\n", total_cases);
            printf("A configuration: %s\n", state_to_str(a_state));
            printf("C configuration: %s\n", state_to_str(c_state));

            ret = run_test_case(a_state, c_state, reparent_fd);
            if (ret == 0) {
                printf("Result: PASSED\n");
                passed_cases++;
            } else {
                printf("Result: FAILED\n");
            }
        }
    }

    printf("\n===================================\n");
    printf("Test Summary: %d/%d cases passed.\n", passed_cases, total_cases);
    printf("===================================\n");

    close(reparent_fd);
    return (passed_cases == total_cases) ? 0 : 1;
}
