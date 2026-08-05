#!/usr/bin/env python3

import ctypes
import os
import threading
import time


CLONE_NEWPID = 0x20000000
PR_SET_NAME = 15
READY_PATH = "/tmp/tfork-ncopy-nested-pidns-ready"

libc = ctypes.CDLL(None, use_errno=True)


def set_name(name):
	if libc.prctl(PR_SET_NAME, name.encode(), 0, 0, 0) != 0:
		errno = ctypes.get_errno()
		raise OSError(errno, os.strerror(errno))


def park():
	while True:
		time.sleep(3600)


def spawn_siblings(count):
	for _ in range(count):
		pid = os.fork()
		if pid == 0:
			os.execl("/bin/sleep", "tfork-sibling", "3600")
			os._exit(0)


def nested_pidns_helper(thread_count):
	set_name("tfork-helper")
	if libc.unshare(CLONE_NEWPID) != 0:
		errno = ctypes.get_errno()
		raise OSError(errno, os.strerror(errno))

	nested_init = os.fork()
	if nested_init == 0:
		set_name("tfork-ns-init")
		threads = []
		for index in range(thread_count):
			thread = threading.Thread(target=park, name=f"tfork-thr-{index}")
			thread.start()
			threads.append(thread)
		with open(READY_PATH, "w", encoding="utf-8") as ready:
			ready.write(f"pid={os.getpid()} threads={threading.active_count()}\n")
		park()
		os._exit(0)

	os.waitpid(nested_init, 0)


def main():
	siblings = int(os.environ.get("TFORK_TEST_SIBLINGS", "40"))
	threads = int(os.environ.get("TFORK_TEST_THREADS", "8"))

	set_name("tfork-test-root")
	spawn_siblings(siblings)
	helper = os.fork()
	if helper == 0:
		nested_pidns_helper(threads)
		os._exit(0)

	while not os.path.exists(READY_PATH):
		time.sleep(0.01)
	park()


if __name__ == "__main__":
	main()
