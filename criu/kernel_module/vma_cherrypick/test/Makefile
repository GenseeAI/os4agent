CC = gcc
CFLAGS = -Wall -Wextra -O2 -fno-stack-protector -no-pie

SRCS = $(wildcard *.c)
BINS = $(SRCS:.c=)

all: $(BINS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BINS)
