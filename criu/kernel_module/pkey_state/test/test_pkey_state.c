#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "../uapi_pkey_state.h"

#ifndef SYS_pkey_alloc
#define SYS_pkey_alloc 330
#endif
#ifndef SYS_pkey_free
#define SYS_pkey_free 331
#endif
#ifndef SYS_pkey_mprotect
#define SYS_pkey_mprotect 329
#endif

static int dev_fd;

#define BAIL(fmt, ...) do { \
    fprintf(stderr, "FAIL " fmt "\n", ##__VA_ARGS__); \
    exit(1); \
} while (0)

static void get_state(struct pkey_state_args *a)
{
	memset(a, 0, sizeof(*a));
	a->target_id = getpid();
	a->flags = PKEY_STATE_FLAG_VPID;
	if (ioctl(dev_fd, PKEY_STATE_GET, a) < 0)
		BAIL("ioctl GET: %s", strerror(errno));
}

static void set_state(unsigned int map, int exec_only)
{
	struct pkey_state_args a = {
		.target_id = getpid(),
		.flags = PKEY_STATE_FLAG_VPID,
		.pkey_allocation_map = map,
		.execute_only_pkey = exec_only,
	};
	if (ioctl(dev_fd, PKEY_STATE_SET, &a) < 0)
		BAIL("ioctl SET: %s", strerror(errno));
}

int main(void)
{
	struct pkey_state_args a;
	void *page;
	size_t pgsz = sysconf(_SC_PAGESIZE);
	int pkey, r;
	unsigned int saved_map;
	int saved_exec;

	dev_fd = open("/dev/pkey_state", O_RDWR);
	if (dev_fd < 0)
		BAIL("open /dev/pkey_state: %s (is the module loaded?)",
		     strerror(errno));

	get_state(&a);
	printf("[1] initial GET: map=0x%x exec_only=%d\n",
	       a.pkey_allocation_map, a.execute_only_pkey);
	if (!(a.pkey_allocation_map & 0x1))
		BAIL("[1] default pkey 0 bit not set");
	saved_map = a.pkey_allocation_map;
	saved_exec = a.execute_only_pkey;

	pkey = syscall(SYS_pkey_alloc, 0, 0);
	if (pkey < 0)
		BAIL("[2] pkey_alloc: %s", strerror(errno));
	printf("[2] pkey_alloc returned %d\n", pkey);

	get_state(&a);
	printf("[2] post-alloc GET: map=0x%x\n", a.pkey_allocation_map);
	if (!(a.pkey_allocation_map & (1U << pkey)))
		BAIL("[2] map didn't gain bit %d after pkey_alloc", pkey);

	page = mmap(NULL, pgsz, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED)
		BAIL("[3] mmap: %s", strerror(errno));
	r = syscall(SYS_pkey_mprotect, page, pgsz, PROT_READ | PROT_WRITE,
		    (long)pkey);
	if (r < 0)
		BAIL("[3] pre-SET pkey_mprotect: %s", strerror(errno));
	printf("[3] pre-SET pkey_mprotect with pkey=%d: ok\n", pkey);

	set_state(saved_map, saved_exec);
	get_state(&a);
	printf("[4] after SET-back: map=0x%x\n", a.pkey_allocation_map);
	if (a.pkey_allocation_map & (1U << pkey))
		BAIL("[4] map still has bit %d after SET-back to 0x%x",
		     pkey, saved_map);

	r = syscall(SYS_pkey_mprotect, page, pgsz, PROT_READ | PROT_WRITE,
		    (long)pkey);
	if (r >= 0)
		BAIL("[4] pkey_mprotect with pkey=%d unexpectedly succeeded "
		     "after we wiped its allocation", pkey);
	if (errno != EINVAL)
		BAIL("[4] expected EINVAL, got %s", strerror(errno));
	printf("[4] post-SET-back pkey_mprotect: EINVAL as expected\n");

	set_state(saved_map | (1U << pkey), saved_exec);
	r = syscall(SYS_pkey_mprotect, page, pgsz, PROT_READ | PROT_WRITE,
		    (long)pkey);
	if (r < 0)
		BAIL("[5] post-restore-style SET pkey_mprotect: %s",
		     strerror(errno));
	printf("[5] SET map back with bit %d → pkey_mprotect ok again\n",
	       pkey);

	puts("PASS");
	return 0;
}
