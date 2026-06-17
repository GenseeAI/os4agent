CFLAGS := -O2 -Wall -Wextra -pthread

TESTS := test_capbypass test_non_clone_denied test_narrow_syscall_mask test_fd_close_revoke

default: $(TESTS)

%: %.c ../uapi_criu_capbypass.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TESTS)
