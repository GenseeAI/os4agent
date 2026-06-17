CFLAGS ?= -O2 -Wall -Wextra
TEST := test_pkey_state

all: $(TEST)

$(TEST): $(TEST).c ../uapi_pkey_state.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TEST)

.PHONY: all clean
