#define _GNU_SOURCE
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <signal.h>

#include "../uapi_vma_cherrypick.h"

#define TEST_ADDR	0x600000000000UL
#define TEST_SIZE	(4096 * 4)
#define SECRET_MAGIC	0xFEEDC0DEUL
#define COW_MAGIC	0xC0FFEEUL

static uint64_t get_pfn(pid_t pid, unsigned long vaddr)
{
	char path[64];
	int fd;
	uint64_t entry = 0;
	off_t offset = (vaddr / 4096) * sizeof(uint64_t);

	snprintf(path, sizeof(path), "/proc/%d/pagemap", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	if (pread(fd, &entry, sizeof(entry), offset) != sizeof(entry)) {
		close(fd);
		return 0;
	}
	close(fd);

	if (!(entry & (1ULL << 63)))
		return 0;
	return entry & ((1ULL << 55) - 1);
}

static int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(SYS_pidfd_open, pid, flags);
}

static void print_usage(const char *prog)
{
	printf("Usage:\n");
	printf("  1. Target:          %s target\n", prog);
	printf("  2. PID mode:        %s test-vpid <target_pid>\n", prog);
	printf("  3. PIDFD:           %s test-pidfd <target_pid>\n", prog);
	printf("  4. DONTFORK target: %s target-dontfork\n", prog);
	printf("  5. DONTFORK vpid:   %s test-dontfork-vpid <target_pid>\n", prog);
	printf("  6. DONTFORK pidfd:  %s test-dontfork-pidfd <target_pid>\n", prog);
}

static int run_target_common(int dontfork)
{
	uint64_t *ptr;
	int i;

	ptr = mmap((void *)TEST_ADDR, TEST_SIZE,
		   PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap failed");
		return 1;
	}

	for (i = 0; i < (int)(TEST_SIZE / 4096); i++)
		ptr[i * 512] = SECRET_MAGIC + i;

	if (dontfork) {
		if (madvise(ptr, TEST_SIZE, MADV_DONTFORK)) {
			perror("madvise MADV_DONTFORK failed");
			return 1;
		}
		printf("[TARGET] Applied MADV_DONTFORK\n");
	}

	printf("[TARGET] PID: %d\n", getpid());
	printf("[TARGET] Mapped %d pages at %p%s\n",
	       (int)(TEST_SIZE / 4096), ptr,
	       dontfork ? " (DONTFORK)" : "");
	for (i = 0; i < (int)(TEST_SIZE / 4096); i++)
		printf("[TARGET] Page %d: 0x%lx\n", i, ptr[i * 512]);
	printf("[TARGET] Sleeping...\n");

	while (1)
		pause();

	return 0;
}

static int run_target(void)
{
	return run_target_common(0);
}

static int run_target_dontfork(void)
{
	return run_target_common(1);
}

static int run_test(pid_t target_pid, int use_pidfd)
{
	int fd, target_handle = -1, mem_fd;
	struct vma_cherrypick_args args;
	uint64_t *ptr, val, expected, target_val;
	uint64_t our_pfn, target_pfn;
	int i, pass = 1;
	char path[64];

	munmap((void *)TEST_ADDR, TEST_SIZE);

	fd = open("/dev/vma_cherrypick", O_WRONLY);
	if (fd < 0) {
		perror("Failed to open /dev/vma_cherrypick");
		return 1;
	}

	memset(&args, 0, sizeof(args));
	args.src_addr = TEST_ADDR;
	args.dst_addr = TEST_ADDR;

	if (use_pidfd) {
		target_handle = pidfd_open(target_pid, 0);
		if (target_handle < 0) {
			perror("pidfd_open failed");
			close(fd);
			return 1;
		}
		args.target_id = target_handle;
		args.flags = VMA_CHERRYPICK_FLAG_PIDFD;
		printf("[TEST] Using PIDFD %d for target PID %d\n",
		       target_handle, target_pid);
	} else {
		args.target_id = target_pid;
		args.flags = VMA_CHERRYPICK_FLAG_VPID;
		printf("[TEST] Using VPID %d\n", target_pid);
	}

	printf("[TEST] Calling VMA_CHERRYPICK for %lx-%lx\n",
	       (unsigned long)args.src_addr,
	       (unsigned long)(args.src_addr + TEST_SIZE));

	if (ioctl(fd, VMA_CHERRYPICK, &args) < 0) {
		perror("VMA_CHERRYPICK ioctl failed");
		close(fd);
		if (target_handle >= 0)
			close(target_handle);
		return 1;
	}

	printf("[TEST] ioctl succeeded!\n");

	ptr = (uint64_t *)TEST_ADDR;
	printf("\n=== Test 1: Read CoW'd pages ===\n");
	for (i = 0; i < (int)(TEST_SIZE / 4096); i++) {
		val = ptr[i * 512];
		expected = SECRET_MAGIC + i;

		if (val == expected)
			printf("[TEST] Page %d: 0x%lx — PASS\n", i, val);
		else {
			printf("[TEST] Page %d: 0x%lx — FAIL (expected 0x%lx)\n",
			       i, val, expected);
			pass = 0;
		}
	}

	printf("\n=== Test 2: Write CoW isolation ===\n");
	ptr[0] = COW_MAGIC;
	printf("[TEST] Wrote 0x%lx to page 0\n", COW_MAGIC);

	if (ptr[0] == COW_MAGIC)
		printf("[TEST] Read back 0x%lx — PASS\n", ptr[0]);
	else {
		printf("[TEST] Read back 0x%lx — FAIL\n", ptr[0]);
		pass = 0;
	}

	if (ptr[512] == SECRET_MAGIC + 1)
		printf("[TEST] Page 1 still 0x%lx — PASS\n", ptr[512]);
	else {
		printf("[TEST] Page 1 is 0x%lx — FAIL (expected 0x%lx)\n",
		       ptr[512], SECRET_MAGIC + 1);
		pass = 0;
	}

	printf("\n=== Test 3: Target isolation ===\n");
	snprintf(path, sizeof(path), "/proc/%d/mem", target_pid);
	mem_fd = open(path, O_RDONLY);
	if (mem_fd >= 0) {
		if (pread(mem_fd, &target_val, sizeof(target_val),
			  TEST_ADDR) == sizeof(target_val)) {
			if (target_val == SECRET_MAGIC)
				printf("[TEST] Target page 0 still 0x%lx — PASS\n",
				       target_val);
			else {
				printf("[TEST] Target page 0 is 0x%lx — FAIL (expected 0x%lx)\n",
				       target_val, SECRET_MAGIC);
				pass = 0;
			}
		} else {
			perror("[TEST] pread target mem");
		}
		close(mem_fd);
	} else {
		perror("[TEST] Can't open target /proc/pid/mem");
	}

	printf("\n=== Test 4: Physical page isolation (pagemap) ===\n");
	our_pfn = get_pfn(getpid(), TEST_ADDR);
	target_pfn = get_pfn(target_pid, TEST_ADDR);
	if (our_pfn && target_pfn) {
		if (our_pfn != target_pfn)
			printf("[TEST] Page 0: PFN 0x%lx vs 0x%lx (different) — PASS\n",
			       (unsigned long)our_pfn, (unsigned long)target_pfn);
		else {
			printf("[TEST] Page 0: PFN 0x%lx vs 0x%lx (same!) — FAIL\n",
			       (unsigned long)our_pfn, (unsigned long)target_pfn);
			pass = 0;
		}
	} else {
		printf("[TEST] Could not read PFN (our=0x%lx target=0x%lx) — SKIP\n",
		       (unsigned long)our_pfn, (unsigned long)target_pfn);
	}

	our_pfn = get_pfn(getpid(), TEST_ADDR + 4096);
	target_pfn = get_pfn(target_pid, TEST_ADDR + 4096);
	if (our_pfn && target_pfn) {
		if (our_pfn == target_pfn)
			printf("[TEST] Page 1: PFN 0x%lx vs 0x%lx (same) — PASS\n",
			       (unsigned long)our_pfn, (unsigned long)target_pfn);
		else {
			printf("[TEST] Page 1: PFN 0x%lx vs 0x%lx (different!) — FAIL\n",
			       (unsigned long)our_pfn, (unsigned long)target_pfn);
			pass = 0;
		}
	} else {
		printf("[TEST] Could not read PFN (our=0x%lx target=0x%lx) — SKIP\n",
		       (unsigned long)our_pfn, (unsigned long)target_pfn);
	}

	printf("\n=== Result: %s ===\n", pass ? "ALL PASSED" : "SOME FAILED");

	close(fd);
	if (target_handle >= 0)
		close(target_handle);

	return pass ? 0 : 1;
}

static int run_test_force_copy(pid_t target_pid, int use_pidfd)
{
	int fd, target_handle = -1, mem_fd;
	struct vma_cherrypick_args args;
	uint64_t *ptr, val, expected, target_val;
	uint64_t our_pfn, target_pfn;
	int i, pg, pass = 1;
	char path[64];

	munmap((void *)TEST_ADDR, TEST_SIZE);
	fd = open("/dev/vma_cherrypick", O_WRONLY);
	if (fd < 0) {
		perror("Failed to open /dev/vma_cherrypick");
		return 1;
	}

	memset(&args, 0, sizeof(args));
	args.src_addr = TEST_ADDR;
	args.dst_addr = TEST_ADDR;

	if (use_pidfd) {
		target_handle = pidfd_open(target_pid, 0);
		if (target_handle < 0) {
			perror("pidfd_open failed");
			close(fd);
			return 1;
		}
		args.target_id = target_handle;
		args.flags = VMA_CHERRYPICK_FLAG_PIDFD;
	} else {
		args.target_id = target_pid;
		args.flags = VMA_CHERRYPICK_FLAG_VPID;
	}

	printf("\n=== Test 0: DONTFORK rejection without FORCE_COPY ===\n");
	if (ioctl(fd, VMA_CHERRYPICK, &args) == 0) {
		printf("[TEST] ioctl should have failed but succeeded — FAIL\n");
		pass = 0;
	} else if (errno == EINVAL) {
		printf("[TEST] Correctly rejected with EINVAL — PASS\n");
	} else {
		printf("[TEST] Unexpected errno %d — FAIL\n", errno);
		pass = 0;
	}

	args.flags |= VMA_CHERRYPICK_FLAG_FORCE_COPY;
	printf("\n=== Test 1: FORCE_COPY on DONTFORK VMA ===\n");
	printf("[TEST] Using %s %d with FORCE_COPY\n",
	       use_pidfd ? "PIDFD" : "VPID",
	       use_pidfd ? target_handle : target_pid);

	if (ioctl(fd, VMA_CHERRYPICK, &args) < 0) {
		perror("VMA_CHERRYPICK FORCE_COPY ioctl failed");
		close(fd);
		if (target_handle >= 0)
			close(target_handle);
		return 1;
	}

	printf("[TEST] ioctl succeeded!\n");
	ptr = (uint64_t *)TEST_ADDR;
	printf("\n=== Test 2: Read FORCE_COPY'd pages ===\n");
	for (i = 0; i < (int)(TEST_SIZE / 4096); i++) {
		val = ptr[i * 512];
		expected = SECRET_MAGIC + i;

		if (val == expected)
			printf("[TEST] Page %d: 0x%lx — PASS\n", i, val);
		else {
			printf("[TEST] Page %d: 0x%lx — FAIL (expected 0x%lx)\n",
			       i, val, expected);
			pass = 0;
		}
	}

	printf("\n=== Test 3: Write isolation ===\n");
	ptr[0] = COW_MAGIC;
	printf("[TEST] Wrote 0x%lx to page 0\n", COW_MAGIC);

	if (ptr[0] == COW_MAGIC)
		printf("[TEST] Read back 0x%lx — PASS\n", ptr[0]);
	else {
		printf("[TEST] Read back 0x%lx — FAIL\n", ptr[0]);
		pass = 0;
	}

	printf("\n=== Test 4: Target isolation ===\n");
	snprintf(path, sizeof(path), "/proc/%d/mem", target_pid);
	mem_fd = open(path, O_RDONLY);
	if (mem_fd >= 0) {
		if (pread(mem_fd, &target_val, sizeof(target_val),
			  TEST_ADDR) == sizeof(target_val)) {
			if (target_val == SECRET_MAGIC)
				printf("[TEST] Target page 0 still 0x%lx — PASS\n",
				       target_val);
			else {
				printf("[TEST] Target page 0 is 0x%lx — FAIL (expected 0x%lx)\n",
				       target_val, SECRET_MAGIC);
				pass = 0;
			}
		} else {
			perror("[TEST] pread target mem");
		}
		close(mem_fd);
	} else {
		perror("[TEST] Can't open target /proc/pid/mem");
	}

	printf("\n=== Test 5: Physical page isolation (pagemap) ===\n");
	for (pg = 0; pg < (int)(TEST_SIZE / 4096); pg++) {
		our_pfn = get_pfn(getpid(), TEST_ADDR + pg * 4096);
		target_pfn = get_pfn(target_pid, TEST_ADDR + pg * 4096);
		if (our_pfn && target_pfn) {
			if (our_pfn != target_pfn)
				printf("[TEST] Page %d: PFN 0x%lx vs 0x%lx (different) — PASS\n",
				       pg, (unsigned long)our_pfn,
				       (unsigned long)target_pfn);
			else {
				printf("[TEST] Page %d: PFN 0x%lx vs 0x%lx (same!) — FAIL\n",
				       pg, (unsigned long)our_pfn,
				       (unsigned long)target_pfn);
				pass = 0;
			}
		} else {
			printf("[TEST] Page %d: Could not read PFN — SKIP\n", pg);
		}
	}
	printf("\n=== Result: %s ===\n", pass ? "ALL PASSED" : "SOME FAILED");

	close(fd);
	if (target_handle >= 0)
		close(target_handle);

	return pass ? 0 : 1;
}

int main(int argc, char *argv[])
{
	pid_t target_pid;

	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "target") == 0)
		return run_target();
	if (strcmp(argv[1], "target-dontfork") == 0)
		return run_target_dontfork();

	if (argc < 3) {
		print_usage(argv[0]);
		return 1;
	}

	target_pid = atoi(argv[2]);

	if (strcmp(argv[1], "test-vpid") == 0)
		return run_test(target_pid, 0);
	if (strcmp(argv[1], "test-pidfd") == 0)
		return run_test(target_pid, 1);
	if (strcmp(argv[1], "test-dontfork-vpid") == 0)
		return run_test_force_copy(target_pid, 0);
	if (strcmp(argv[1], "test-dontfork-pidfd") == 0)
		return run_test_force_copy(target_pid, 1);

	print_usage(argv[0]);
	return 1;
}
