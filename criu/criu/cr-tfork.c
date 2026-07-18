#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/file.h>

#include <limits.h>
#include <sys/sysmacros.h>

#include "crtools.h"
#include "cr_options.h"
#include "cr-tfork.h"
#include "files.h"
#include "pstree.h"
#include "imgset.h"
#include "namespaces.h"
#include <sys/socket.h>
#include "net.h"
#include "stats.h"
#include "lsm.h"
#include "seccomp.h"
#include "plugin.h"
#include "cgroup-props.h"
#include "file-lock.h"
#include "mount.h"
#include "external.h"
#include "action-scripts.h"
#include "seize.h"
#include "dump.h"
#include "sysfs_parse.h"
#include "files-reg.h"
#include "servicefd.h"
#include "util.h"
#include "image.h"
#include "bfd.h"
#include "log.h"
#include "xmalloc.h"

#define VMA_CHERRYPICK_FD_ENV "CRIU_VMA_CHERRYPICK_FD"

static int tfork_dup_inherited_vma_cherrypick(int env_fd)
{
	struct stat fst, dst;
	int dup_fd;

	if (fstat(env_fd, &fst) < 0) {
		pr_perror("tfork: fstat inherited %s=%d",
			  VMA_CHERRYPICK_FD_ENV, env_fd);
		return -1;
	}
	if (!S_ISCHR(fst.st_mode)) {
		pr_err("tfork: inherited fd %d is not a char device "
		       "(mode 0%o)\n",
		       env_fd, fst.st_mode & S_IFMT);
		return -1;
	}
	if (stat("/dev/vma_cherrypick", &dst) == 0 &&
	    fst.st_rdev != dst.st_rdev) {
		pr_err("tfork: inherited fd %d points to char device %u:%u, "
		       "expected /dev/vma_cherrypick = %u:%u\n",
		       env_fd, major(fst.st_rdev), minor(fst.st_rdev),
		       major(dst.st_rdev), minor(dst.st_rdev));
		return -1;
	}
	dup_fd = fcntl(env_fd, F_DUPFD_CLOEXEC, 3);
	if (dup_fd < 0) {
		pr_perror("tfork: dup inherited %s=%d",
			  VMA_CHERRYPICK_FD_ENV, env_fd);
		return -1;
	}
	return dup_fd;
}

static int tfork_open_vma_cherrypick(void)
{
	const char *env = getenv(VMA_CHERRYPICK_FD_ENV);
	int fd;

	if (env && *env) {
		char *endp = NULL;
		long env_fd = strtol(env, &endp, 10);

		if (!endp || *endp || env_fd < 0 || env_fd > INT_MAX) {
			pr_warn("tfork: %s=\"%s\" is not a valid fd; "
				"falling back to direct open\n",
				VMA_CHERRYPICK_FD_ENV, env);
		} else {
			fd = tfork_dup_inherited_vma_cherrypick((int)env_fd);
			if (fd >= 0) {

				unsetenv(VMA_CHERRYPICK_FD_ENV);
				pr_info("tfork: using inherited %s fd %ld "
					"(dup'd to %d)\n",
					VMA_CHERRYPICK_FD_ENV, env_fd, fd);
				return fd;
			}
			pr_warn("tfork: %s=%ld failed validation; "
				"falling back to direct open\n",
				VMA_CHERRYPICK_FD_ENV, env_fd);
		}
	}

	fd = open("/dev/vma_cherrypick", O_WRONLY);
	if (fd < 0)
		pr_perror("tfork: can't open /dev/vma_cherrypick");
	return fd;
}


int tfork_read_cropt(void)
{
	char path[PATH_MAX];
	FILE *f;
	char line[256];
	int nr, cap = 16;
	int pidfd_base, high_fd;
	int i;
	const char *snap_path;

	if (opts.tfork.pidfd_map_nr > 0)
		goto open_snap_root;

	snprintf(path, sizeof(path), "%s/tfork.cropt", opts.imgs_dir);
	f = fopen(path, "r");
	if (!f) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	opts.tfork.pidfd_map = xmalloc(cap * sizeof(*opts.tfork.pidfd_map));
	if (!opts.tfork.pidfd_map) {
		fclose(f);
		return -1;
	}

	nr = 0;
	while (fgets(line, sizeof(line), f)) {
		int task_uid, vpid, real_pid;

		if (sscanf(line, "pidmap=%d:%d:%d",
			   &task_uid, &vpid, &real_pid) == 3) {
			if (nr >= cap) {
				cap *= 2;
				opts.tfork.pidfd_map = xrealloc(opts.tfork.pidfd_map,
								cap * sizeof(*opts.tfork.pidfd_map));
				if (!opts.tfork.pidfd_map) {
					fclose(f);
					return -1;
				}
			}
			opts.tfork.pidfd_map[nr].uid = task_uid;
			opts.tfork.pidfd_map[nr].vpid = vpid;
			opts.tfork.pidfd_map[nr].real_pid = real_pid;
			opts.tfork.pidfd_map[nr].pidfd = -1;
			opts.tfork.pidfd_map[nr].memfd = -1;
			opts.tfork.pidfd_map[nr].pagemap_fd = -1;
			nr++;
		}
	}
	opts.tfork.pidfd_map_nr = nr;
	fclose(f);

	opts.tfork.vma_cherrypick_fd = tfork_open_vma_cherrypick();
	if (opts.tfork.vma_cherrypick_fd < 0)
		return -1;

	pidfd_base = 1 << 17;
	opts.tfork.pidfd_base = pidfd_base;

	for (i = 0; i < nr; i++) {
		int raw_fd, high_fd;
		char mem_path[64];
		char pmap_path[64];

		raw_fd = syscall(SYS_pidfd_open,
				 opts.tfork.pidfd_map[i].real_pid, 0);
		if (raw_fd < 0) {
			pr_perror("tfork: pidfd_open(%d) failed",
				  opts.tfork.pidfd_map[i].real_pid);
			return -1;
		}

		high_fd = fcntl(raw_fd, F_DUPFD, pidfd_base + i);
		if (high_fd < 0) {
			pr_perror("tfork: F_DUPFD pidfd to %d failed",
				  pidfd_base + i);
			close(raw_fd);
			return -1;
		}
		close(raw_fd);
		opts.tfork.pidfd_map[i].pidfd = high_fd;

		snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem",
			 opts.tfork.pidfd_map[i].real_pid);
		raw_fd = open(mem_path, O_RDONLY);
		if (raw_fd < 0) {
			if (errno == ESRCH) {
				pr_info("tfork: skip memfd for zombie vpid %d (real %d)\n",
					opts.tfork.pidfd_map[i].vpid,
					opts.tfork.pidfd_map[i].real_pid);
				continue;
			}
			pr_perror("tfork: open(%s) failed", mem_path);
			return -1;
		}
		high_fd = fcntl(raw_fd, F_DUPFD, pidfd_base + nr + i);
		if (high_fd < 0) {
			pr_perror("tfork: F_DUPFD memfd to %d failed",
				  pidfd_base + nr + i);
			close(raw_fd);
			return -1;
		}
		close(raw_fd);
		opts.tfork.pidfd_map[i].memfd = high_fd;

		snprintf(pmap_path, sizeof(pmap_path),
			 "/proc/%d/pagemap",
			 opts.tfork.pidfd_map[i].real_pid);
		raw_fd = open(pmap_path, O_RDONLY);
		if (raw_fd < 0) {
			if (errno != ESRCH) {
				pr_perror("tfork: open(%s) failed",
					  pmap_path);
				return -1;
			}
			pr_info("tfork: skip pagemap for zombie vpid %d (real %d)\n",
				opts.tfork.pidfd_map[i].vpid,
				opts.tfork.pidfd_map[i].real_pid);
		} else {
			high_fd = fcntl(raw_fd, F_DUPFD,
					pidfd_base + 2 * nr + i);
			if (high_fd < 0) {
				pr_perror("tfork: F_DUPFD pagemap_fd to %d failed",
					  pidfd_base + 2 * nr + i);
				close(raw_fd);
				return -1;
			}
			close(raw_fd);
			opts.tfork.pidfd_map[i].pagemap_fd = high_fd;
		}

		pr_info("tfork: pidfd %d memfd %d pagemap_fd %d for vpid %d uid %d (real %d)\n",
			opts.tfork.pidfd_map[i].pidfd,
			opts.tfork.pidfd_map[i].memfd,
			opts.tfork.pidfd_map[i].pagemap_fd,
			opts.tfork.pidfd_map[i].vpid,
			opts.tfork.pidfd_map[i].uid,
			opts.tfork.pidfd_map[i].real_pid);
	}

	high_fd = fcntl(opts.tfork.vma_cherrypick_fd, F_DUPFD,
			pidfd_base + 3 * nr);
	if (high_fd < 0) {
		pr_perror("tfork: F_DUPFD vma_cherrypick_fd failed");
		return -1;
	}
	close(opts.tfork.vma_cherrypick_fd);
	opts.tfork.vma_cherrypick_fd = high_fd;

	pr_info("tfork: cropt loaded: cherrypick_fd=%d, %d pidfds (base=%d)\n",
		opts.tfork.vma_cherrypick_fd, nr, pidfd_base);

open_snap_root:
	if (opts.tfork.snap_root_fd >= 0)
		return 0;

	snap_path = opts.tfork.snap_root;
	if (!snap_path && opts.tfork.copies >= 1 && opts.tfork.snap_roots &&
	    opts.tfork.copy_idx < opts.tfork.snap_roots_n)
		snap_path = opts.tfork.snap_roots[opts.tfork.copy_idx];

	if (!snap_path)
		return 0;

	opts.tfork.snap_root_fd = open(snap_path, O_PATH | O_DIRECTORY);
	if (opts.tfork.snap_root_fd < 0) {
		pr_perror("tfork: can't open snap-root %s", snap_path);
		return -1;
	}

	high_fd = fcntl(opts.tfork.snap_root_fd, F_DUPFD,
			opts.tfork.pidfd_base + 3 * opts.tfork.pidfd_map_nr + 1);
	if (high_fd < 0) {
		pr_perror("tfork: F_DUPFD snap_root_fd failed");
		return -1;
	}
	close(opts.tfork.snap_root_fd);
	opts.tfork.snap_root_fd = high_fd;

	pr_info("tfork: snap_root %s -> fd %d (copy_idx=%d)\n",
		snap_path, opts.tfork.snap_root_fd, opts.tfork.copy_idx);
	return 0;
}


int tfork_load_ncopy_fabric(int copy_idx)
{
	char path[PATH_MAX];
	FILE *f;
	char line[PATH_MAX + 64];
	int applied = 0;

	snprintf(path, sizeof(path), "%s/tfork.ncopy.fabric",
		 opts.imgs_dir);
	f = fopen(path, "r");
	if (!f) {
		if (errno == ENOENT)
			return 0;
		pr_perror("tfork-ncopy: can't open %s", path);
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		int idx;
		char key[64];
		char value[PATH_MAX];
		size_t len = strlen(line);

		while (len > 0 && (line[len - 1] == '\n' ||
				   line[len - 1] == '\r' ||
				   line[len - 1] == ' '))
			line[--len] = '\0';
		if (len == 0 || line[0] == '#')
			continue;

		if (sscanf(line, "copy=%d %63[^=]=%4095[^\n]",
			   &idx, key, value) != 3) {
			pr_warn("tfork-ncopy: skipping malformed fabric line: %s\n",
				line);
			continue;
		}
		if (idx != copy_idx)
			continue;

		if (!strcmp(key, "cgroup_root")) {
			char *dup = xstrdup(value);
			if (!dup)
				goto err;

			opts.new_global_cg_root = dup;
			pr_info("tfork-ncopy: copy %d cgroup_root -> %s\n",
				copy_idx, value);
			applied++;
			continue;
		}

		if (!strcmp(key, "external")) {
			if (add_external(value)) {
				pr_err("tfork-ncopy: copy %d add_external(%s) failed\n",
				       copy_idx, value);
				goto err;
			}
			pr_info("tfork-ncopy: copy %d external += %s\n",
				copy_idx, value);
			applied++;
			continue;
		}

		if (!strcmp(key, "ext_mount")) {
			char *colon = strchr(value, ':');
			if (!colon) {
				pr_err("tfork-ncopy: copy %d ext_mount needs KEY:VAL (got %s)\n",
				       copy_idx, value);
				goto err;
			}
			*colon = '\0';
			if (ext_mount_add(value, colon + 1)) {
				pr_err("tfork-ncopy: copy %d ext_mount_add(%s,%s) failed\n",
				       copy_idx, value, colon + 1);
				goto err;
			}
			pr_info("tfork-ncopy: copy %d ext_mount += %s:%s\n",
				copy_idx, value, colon + 1);
			applied++;
			continue;
		}

		pr_warn("tfork-ncopy: copy %d unknown fabric key '%s' (ignored)\n",
			copy_idx, key);
	}

	fclose(f);
	pr_info("tfork-ncopy: copy %d applied %d fabric entries\n",
		copy_idx, applied);
	return 0;
err:
	fclose(f);
	return -1;
}


void tfork_close_high_fds(void)
{
	int j;

	for (j = 0; j < opts.tfork.pidfd_map_nr; j++) {
		if (opts.tfork.pidfd_map[j].pidfd >= 0) {
			close(opts.tfork.pidfd_map[j].pidfd);
			opts.tfork.pidfd_map[j].pidfd = -1;
		}
		if (opts.tfork.pidfd_map[j].memfd >= 0) {
			close(opts.tfork.pidfd_map[j].memfd);
			opts.tfork.pidfd_map[j].memfd = -1;
		}
		if (opts.tfork.pidfd_map[j].pagemap_fd >= 0) {
			close(opts.tfork.pidfd_map[j].pagemap_fd);
			opts.tfork.pidfd_map[j].pagemap_fd = -1;
		}
	}

	if (opts.tfork.vma_cherrypick_fd >= 0) {
		close(opts.tfork.vma_cherrypick_fd);
		opts.tfork.vma_cherrypick_fd = -1;
	}

	if (opts.tfork.snap_root_fd >= 0) {
		close(opts.tfork.snap_root_fd);
		opts.tfork.snap_root_fd = -1;
	}
}


int tfork_apply_per_copy_args(int copy_idx)
{
	char *raw, *dup, *saveptr = NULL, *tok;
	int applied = 0, ret = 0;

	if (copy_idx < 0 || copy_idx >= opts.tfork.per_copy_args_n)
		return 0;
	raw = opts.tfork.per_copy_args[copy_idx];
	if (!raw)
		return 0;

	dup = xstrdup(raw);
	if (!dup)
		return -1;

	tok = strtok_r(dup, " \t", &saveptr);
	while (tok) {
		const char *flag = tok;
		char *arg = NULL;
		char *eq = strchr(tok, '=');

		if (eq) {
			*eq = '\0';
			arg = eq + 1;
		} else {
			tok = strtok_r(NULL, " \t", &saveptr);
			arg = tok;
		}

		if (!strcmp(flag, "--inherit-fd")) {
			if (!arg) {
				pr_err("tfork-per-copy %d: --inherit-fd needs FD:KEY\n", copy_idx);
				ret = -1;
				goto out;
			}
			if (inherit_fd_parse(arg) < 0) {
				pr_err("tfork-per-copy %d: --inherit-fd %s rejected\n", copy_idx, arg);
				ret = -1;
				goto out;
			}
			pr_info("tfork-per-copy %d: inherit-fd += %s\n", copy_idx, arg);
		} else if (!strcmp(flag, "--external")) {
			if (!arg) {
				pr_err("tfork-per-copy %d: --external needs KEY\n", copy_idx);
				ret = -1;
				goto out;
			}
			if (add_external(arg)) {
				pr_err("tfork-per-copy %d: --external %s rejected\n", copy_idx, arg);
				ret = -1;
				goto out;
			}
			pr_info("tfork-per-copy %d: external += %s\n", copy_idx, arg);
		} else if (!strcmp(flag, "--cgroup-root")) {
			char *new_root;

			if (!arg) {
				pr_err("tfork-per-copy %d: --cgroup-root needs PATH\n", copy_idx);
				ret = -1;
				goto out;
			}

			if (strchr(arg, ':')) {
				pr_err("tfork-per-copy %d: per-controller --cgroup-root `%s` not supported (use bare PATH)\n",
				       copy_idx, arg);
				ret = -1;
				goto out;
			}
			new_root = xstrdup(arg);
			if (!new_root) {
				ret = -1;
				goto out;
			}
			xfree(opts.new_global_cg_root);
			opts.new_global_cg_root = new_root;
			pr_info("tfork-per-copy %d: cgroup-root -> %s\n", copy_idx, arg);
		} else if (!strcmp(flag, "--tfork-snap-root")) {
			char *new_path, *new_root;

			if (!arg) {
				pr_err("tfork-per-copy %d: --tfork-snap-root needs PATH\n", copy_idx);
				ret = -1;
				goto out;
			}
			new_path = xstrdup(arg);
			if (!new_path) {
				ret = -1;
				goto out;
			}
			new_root = xstrdup(arg);
			if (!new_root) {
				xfree(new_path);
				ret = -1;
				goto out;
			}
			xfree(opts.tfork.snap_root);
			opts.tfork.snap_root = new_path;

			opts.tfork.snap_root_fd = -1;

			xfree(opts.root);
			opts.root = new_root;
			pr_info("tfork-per-copy %d: tfork-snap-root -> %s\n", copy_idx, arg);
		} else if (!strcmp(flag, "--tfork-snap-mount")) {
			char *new_mp, **grown;

			if (!arg) {
				pr_err("tfork-per-copy %d: --tfork-snap-mount needs PATH\n", copy_idx);
				ret = -1;
				goto out;
			}

			new_mp = xstrdup(arg);
			if (!new_mp) {
				ret = -1;
				goto out;
			}
			grown = xrealloc(opts.tfork.snap_mount,
					 (opts.tfork.snap_mount_n + 1) *
					 sizeof(*opts.tfork.snap_mount));
			if (!grown) {
				xfree(new_mp);
				ret = -1;
				goto out;
			}
			grown[opts.tfork.snap_mount_n++] = new_mp;
			opts.tfork.snap_mount = grown;
			pr_info("tfork-per-copy %d: snap-mount += %s\n", copy_idx, arg);
		} else {
			pr_warn("tfork-per-copy %d: unknown flag `%s` (ignored)\n", copy_idx, flag);
		}

		applied++;
		tok = strtok_r(NULL, " \t", &saveptr);
	}
	pr_info("tfork-per-copy %d: applied %d flags\n", copy_idx, applied);

out:
	xfree(dup);
	return ret;
}


static int cr_tfork_finish(int ret)
{
	int j;

	for (j = 0; j < opts.tfork.pidfd_map_nr; j++) {
		if (opts.tfork.pidfd_map[j].pidfd >= 0)
			close(opts.tfork.pidfd_map[j].pidfd);
		if (opts.tfork.pidfd_map[j].memfd >= 0)
			close(opts.tfork.pidfd_map[j].memfd);
	}
	xfree(opts.tfork.pidfd_map);
	opts.tfork.pidfd_map = NULL;
	opts.tfork.pidfd_map_nr = 0;

	if (opts.tfork.vma_cherrypick_fd >= 0) {
		close(opts.tfork.vma_cherrypick_fd);
		opts.tfork.vma_cherrypick_fd = -1;
	}

	if (opts.tfork.inflight_fd >= 0 && opts.tfork.dumpd_pid <= 0) {
		int img_dir = get_service_fd(IMG_FD_OFF);
		if (img_dir >= 0)
			(void)unlinkat(img_dir, ".dump.inflight", 0);
		close(opts.tfork.inflight_fd);
		opts.tfork.inflight_fd = -1;
	}

	close_cr_imgset(&glob_imgset);

	if (bfd_flush_images())
		ret = -1;

	cgp_fini();

	unsuspend_lsm();
	network_unlock();
	delete_link_remaps();
	clean_cr_time_mounts();

	cr_plugin_fini(CR_PLUGIN_STAGE__DUMP, ret);

	if (arch_set_thread_regs(root_item, true) < 0)
		ret = -1;

	pstree_switch_state(root_item, TASK_ALIVE);
	timing_stop(TIME_FROZEN);

	seccomp_free_entries();
	free_file_locks();
	free_link_remaps();
	free_aufs_branches();
	free_userns_maps();

	close_service_fd(CR_PROC_FD_OFF);
	close_image_dir();

	if (ret) {
		pr_err("tfork FAILED.\n");
	} else {
		write_stats(DUMP_STATS);
		pr_info("tfork finished successfully\n");
	}

	return ret;
}


struct tfork_ifd_ctx {
	char **argv;
	int *np;
};

static int tfork_ifd_append(int fd, const char *key, void *arg)
{
	struct tfork_ifd_ctx *c = arg;
	char *out;
	int wrote;
	size_t need = strlen(key) + 32;

	out = malloc(need);
	if (!out) {
		pr_err("malloc inherit-fd arg failed\n");
		return -1;
	}
	wrote = snprintf(out, need, "fd[%d]:%s", fd, key);
	if (wrote < 0 || (size_t)wrote >= need) {
		pr_err("inherit-fd arg overflow\n");
		free(out);
		return -1;
	}
	c->argv[(*c->np)++] = "--inherit-fd";
	c->argv[(*c->np)++] = out;
	return 0;
}

static int tfork_ext_append(struct external *e, void *arg)
{
	struct tfork_ifd_ctx *c = arg;

	c->argv[(*c->np)++] = "--external";
	c->argv[(*c->np)++] = e->id;
	return 0;
}

static int tfork_check_kernel_modules(void)
{
	struct {
		const char *dev;
		const char *modpath;
		bool required;
	} mods[] = {
		{ "/dev/vma_cherrypick", "kernel_module/vma_cherrypick/vma_cherrypick.ko", true },
		{ "/dev/criu_capbypass", "kernel_module/criu_capbypass/criu_capbypass.ko", true },
		{ "/dev/reparent",       "kernel_module/reparent_task/reparent_task.ko",
		  opts.tfork.memdump && opts.tfork.memdump_async },
	};
	int i, missing = 0;

	for (i = 0; i < (int)ARRAY_SIZE(mods); i++) {
		if (!mods[i].required)
			continue;
		if (access(mods[i].dev, F_OK) == 0)
			continue;
		if (missing == 0)
			pr_err("tfork: required kernel module(s) not loaded:\n");
		pr_err("  %s missing — `insmod %s` (after `make` in that dir)\n",
		       mods[i].dev, mods[i].modpath);
		missing++;
	}
	if (missing) {
		pr_err("See Documentation/CRIU_TFORK_*.md and kernel_module/README.md.\n");
		return -1;
	}
	return 0;
}

static int tfork_check_target(pid_t pid)
{
	struct stat st_self, st_target;
	int proc_dir;

	proc_dir = open_pid_proc(pid);
	if (proc_dir < 0) {
		pr_err("tfork: can't open /proc/%d\n", pid);
		return -1;
	}
	if (fstatat(proc_dir, "ns/pid", &st_target, 0)) {
		pr_perror("tfork: can't stat target pid namespace");
		return -1;
	}
	if (fstatat(open_pid_proc(PROC_SELF), "ns/pid", &st_self, 0)) {
		pr_perror("tfork: can't stat self pid namespace");
		return -1;
	}
	if (st_self.st_ino == st_target.st_ino) {
		pr_err("tfork: target pid %d is in the same pid namespace as criu\n", pid);
		pr_err("tfork requires the target to be in its own pid namespace (container)\n");
		return -1;
	}

	return 0;
}

int cr_tfork_tasks(pid_t pid)
{
	struct pstree_item *item;
	int img_dir_fd, cropt_fd, nr;
	int pidfd;
	int ret = -1;
	pid_t child;
	int status;
	FILE *f;
	int j;

	if (tfork_check_kernel_modules())
		return -1;
	if (tfork_check_target(pid))
		return -1;

	opts.tfork.active = true;
	opts.tfork.dumpd_sock = -1;
	opts.tfork.dumpd_pid = -1;
	opts.tfork.inflight_fd = -1;

	if (opts.tfork.dumpd_parent_pid > 0 && !opts.tfork.memdump_async)
		pr_warn("--tfork-dumpd-parent=%d ignored: no dumpd is "
			"forked without --tfork-memdump-async\n",
			opts.tfork.dumpd_parent_pid);

	if (!opts.tcp_skip_in_flight)
		opts.tcp_skip_in_flight = 1;
	if (!opts.unix_skip_in_flight)
		opts.unix_skip_in_flight = 1;

	opts.final_state = TASK_ALIVE;
	if (opts.tfork.memdump) {
		int img_dir = get_service_fd(IMG_FD_OFF);

		if (img_dir < 0) {
			pr_err("tfork-memdump: no image-dir fd\n");
			goto err;
		}
		opts.tfork.inflight_fd =
			openat(img_dir, ".dump.inflight",
			       O_CREAT | O_EXCL | O_WRONLY, 0644);
		if (opts.tfork.inflight_fd < 0) {
			pr_perror("tfork-memdump: can't create "
				  ".dump.inflight (concurrent dump on "
				  "this image dir, or stale lockfile?)");
			goto err;
		}
		if (flock(opts.tfork.inflight_fd,
			  LOCK_EX | LOCK_NB) < 0) {
			pr_perror("tfork-memdump: flock "
				  ".dump.inflight failed");
			close(opts.tfork.inflight_fd);
			(void)unlinkat(img_dir, ".dump.inflight", 0);
			opts.tfork.inflight_fd = -1;
			goto err;
		}

		if (opts.img_parent) {
			char inflight_path[PATH_MAX];
			char done_path[PATH_MAX];
			struct stat st;
			int waited_ms = 0;
			const int timeout_ms = 60 * 1000;
			const int sleep_ms = 100;

			snprintf(inflight_path, sizeof(inflight_path),
				 "%s/.dump.inflight", opts.img_parent);
			snprintf(done_path, sizeof(done_path),
				 "%s/.dump.done", opts.img_parent);

			while (waited_ms < timeout_ms) {
				int has_inflight = (stat(inflight_path, &st) == 0);
				int has_done = (stat(done_path, &st) == 0);

				if (has_done) {
					if (waited_ms > 0)
						pr_info("tfork-memdump: "
							"parent .dump.done "
							"appeared after %dms "
							"wait\n", waited_ms);
					break;
				}
				if (!has_inflight)
					break;

				if (waited_ms == 0)
					pr_info("tfork-memdump: parent "
						"dump in flight (%s), "
						"waiting up to %dms\n",
						opts.img_parent, timeout_ms);
				usleep(sleep_ms * 1000);
				waited_ms += sleep_ms;
			}
			if (waited_ms >= timeout_ms) {
				pr_err("tfork-memdump: parent dump "
				       "(%s) didn't publish .dump.done "
				       "within %dms — refusing to start "
				       "incremental dump on a stale parent\n",
				       opts.img_parent, timeout_ms);
				close(opts.tfork.inflight_fd);
				(void)unlinkat(img_dir, ".dump.inflight", 0);
				opts.tfork.inflight_fd = -1;
				goto err;
			}
		}

		if (opts.tfork.memdump_async) {
			int sv[2];

			if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
				       sv) < 0) {
				pr_perror("tfork: socketpair for dumpd failed");
				goto err;
			}
			opts.tfork.dumpd_pid = fork();
			if (opts.tfork.dumpd_pid < 0) {
				pr_perror("tfork: fork(dumpd) failed");
				close(sv[0]);
				close(sv[1]);
				goto err;
			}
			if (opts.tfork.dumpd_pid == 0) {
				close(sv[1]);
				_exit(run_dumpd_loop(sv[0],
						     opts.tfork.inflight_fd,
						     img_dir));
			}
			close(sv[0]);
			opts.tfork.dumpd_sock = sv[1];
			pr_info("tfork: dumpd spawned (pid=%d), .dump.inflight "
				"locked\n", opts.tfork.dumpd_pid);
		} else {
			pr_info("tfork-memdump: .dump.inflight locked "
				"(sync, criu publishes .dump.done at Phase A end)\n");
		}
	}

	ret = cr_dump_tasks(pid);
	if (ret) {
		pr_err("tfork: Phase A (dump) failed: %d\n", ret);
		goto err;
	}

	pr_info("tfork: Phase A complete. Tree still frozen.\n");

	if (opts.tfork.memdump) {
		int img_dir = get_service_fd(IMG_FD_OFF);

		if (bfd_flush_images())
			pr_warn("tfork-memdump: bfd_flush_images returned non-zero\n");

		if (opts.tfork.memdump_async) {
			int sfd = openat(img_dir, "tfork-async-memdump.done",
					 O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (sfd < 0)
				pr_pwarn("tfork-async-memdump: can't write sentinel");
			else {
				close(sfd);
				pr_info("tfork-async-memdump: wrote tfork-async-memdump.done\n");
			}

			if (opts.tfork.dumpd_sock >= 0) {
				close(opts.tfork.dumpd_sock);
				opts.tfork.dumpd_sock = -1;
				pr_info("tfork-async-memdump: closed dumpd socket "
					"(dumpd pid=%d will reap helpers and exit)\n",
					opts.tfork.dumpd_pid);
			}
			if (opts.tfork.inflight_fd >= 0) {
				close(opts.tfork.inflight_fd);
				opts.tfork.inflight_fd = -1;
			}
		} else if (img_dir >= 0) {
			int dst;

			syncfs(img_dir);
			dst = openat(img_dir, ".dump.done.tmp",
				     O_CREAT | O_WRONLY | O_TRUNC, 0644);
			if (dst < 0) {
				pr_pwarn("tfork-memdump: openat(.dump.done.tmp) failed");
			} else {
				if (write(dst, "ok\n", 3) != 3)
					pr_pwarn("tfork-memdump: write(.dump.done.tmp) failed");
				close(dst);
				if (renameat(img_dir, ".dump.done.tmp",
					     img_dir, ".dump.done") < 0)
					pr_pwarn("tfork-memdump: renameat(.dump.done) failed");
				else
					pr_info("tfork-memdump: wrote .dump.done\n");
			}
			if (unlinkat(img_dir, ".dump.inflight", 0) < 0)
				pr_pwarn("tfork-memdump: unlinkat(.dump.inflight) failed");
			if (opts.tfork.inflight_fd >= 0) {
				close(opts.tfork.inflight_fd);
				opts.tfork.inflight_fd = -1;
			}
		}
	}

	ret = run_scripts(ACT_POST_TFORK_FREEZE);
	if (ret) {
		pr_err("Post-tfork-freeze script failed: %d\n", ret);
		goto err;
	}

	pr_info("tfork: Phase B — setting up clone restore\n");

	opts.tfork.vma_cherrypick_fd = tfork_open_vma_cherrypick();
	if (opts.tfork.vma_cherrypick_fd < 0)
		goto err;

	nr = 0;
	for_each_pstree_item(item)
		nr++;

	opts.tfork.pidfd_map = xmalloc(nr * sizeof(*opts.tfork.pidfd_map));
	if (!opts.tfork.pidfd_map)
		goto err;
	opts.tfork.pidfd_map_nr = 0;

	for_each_pstree_item(item) {
		pidfd = syscall(SYS_pidfd_open, item->pid->real, 0);
		if (pidfd < 0) {
			pr_perror("pidfd_open(%d) failed", item->pid->real);
			goto err;
		}
		item->tfork_pidfd = pidfd;
		opts.tfork.pidfd_map[opts.tfork.pidfd_map_nr].uid = uid(item);
		opts.tfork.pidfd_map[opts.tfork.pidfd_map_nr].vpid = localpid(item);
		opts.tfork.pidfd_map[opts.tfork.pidfd_map_nr].real_pid = item->pid->real;
		opts.tfork.pidfd_map[opts.tfork.pidfd_map_nr].pidfd = pidfd;
		opts.tfork.pidfd_map[opts.tfork.pidfd_map_nr].memfd = -1;
		opts.tfork.pidfd_map_nr++;
		pr_info("tfork: pidfd %d for pid %d (vpid %d uid %d nsid %d level %d)\n",
			pidfd, item->pid->real, localpid(item), uid(item),
			item->pid->leaf_ns_id, item->pid->ns_level);
	}

	ret = run_scripts(ACT_PRE_TFORK_RESTORE);
	if (ret) {
		pr_err("Pre-tfork-restore script failed: %d\n", ret);
		goto err;
	}

	img_dir_fd = get_service_fd(IMG_FD_OFF);
	cropt_fd = openat(img_dir_fd, "tfork.cropt",
			  O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (cropt_fd < 0) {
		pr_perror("Can't create tfork.cropt");
		goto err;
	}
	f = fdopen(cropt_fd, "w");
	if (!f) {
		pr_perror("Can't fdopen tfork.cropt");
		close(cropt_fd);
		goto err;
	}
	for (j = 0; j < opts.tfork.pidfd_map_nr; j++)
		fprintf(f, "pidmap=%d:%d:%d\n",
			(int)opts.tfork.pidfd_map[j].uid,
			opts.tfork.pidfd_map[j].vpid,
			(int)opts.tfork.pidfd_map[j].real_pid);
	fclose(f);

	if (opts.output) {
		char phasea_path[PATH_MAX];
		int src, dst;

		snprintf(phasea_path, sizeof(phasea_path), "%s.phaseA",
			 opts.output);
		src = open(opts.output, O_RDONLY);
		dst = open(phasea_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (src >= 0 && dst >= 0) {
			char buf[4096];
			ssize_t n;
			while ((n = read(src, buf, sizeof(buf))) > 0)
				if (write(dst, buf, n) != n)
					break;
		}
		if (src >= 0)
			close(src);
		if (dst >= 0)
			close(dst);
	}

	child = fork();
	if (child < 0) {
		pr_perror("tfork: can't fork for Phase B");
		ret = -1;
		goto err;
	}

	if (child == 0) {
		char img_dir_arg[PATH_MAX];
		char pidfile_arg[PATH_MAX];
		char restore_log_arg[PATH_MAX];
		char *buf = NULL;
		size_t buf_size = 0;
		size_t off = 0;
		ssize_t n;
		char **argv_new;
		size_t argv_max;
		int argc_new = 0;
		char *p, *end;
		int img_fd, cmdline_fd;
		bool saw_pidfile = false;

		img_fd = dup(get_service_fd(IMG_FD_OFF));
		if (img_fd < 0) {
			pr_perror("Can't dup image dir fd");
			exit(1);
		}
		snprintf(img_dir_arg, sizeof(img_dir_arg),
			 "/proc/self/fd/%d", img_fd);
		snprintf(pidfile_arg, sizeof(pidfile_arg),
			 "/proc/self/fd/%d/tfork.pid", img_fd);

		snprintf(restore_log_arg, sizeof(restore_log_arg),
			 "/proc/self/fd/%d/tfork-restore.log", img_fd);

		if (opts.swrk_restore) {
			char copies_arg[32];
			char snap_roots_csv[PATH_MAX * 4];
			char snap_mounts_csv[PATH_MAX * 4];
			size_t i;
			int rpc_n_ifd = 0, rpc_n_ext = 0;
			int rpc_n_copy_args = 0;
			int rpc_n_cg_root = 0;
			struct external *ext_iter;
			struct list_head *ifd_iter;
			struct tfork_ifd_ctx ifd_ctx;
			struct cg_root_opt *cgo_iter;
			int rpc_max;
			char **rpc_argv;
			int rpc_n = 0;

			list_for_each(ifd_iter, &opts.inherit_fds)
				rpc_n_ifd++;
			list_for_each_entry(ext_iter, &opts.external, node)
				rpc_n_ext++;
			for (i = 0; i < (size_t)opts.tfork.per_copy_args_n; i++)
				if (opts.tfork.per_copy_args[i])
					rpc_n_copy_args++;
			list_for_each_entry(cgo_iter, &opts.new_cgroup_roots, node)
				rpc_n_cg_root++;

			rpc_max = 33 + 2 * (rpc_n_ifd + rpc_n_ext + rpc_n_cg_root
					    + opts.tfork.snap_mount_n)
				+ rpc_n_copy_args + 2;
			rpc_argv = calloc(rpc_max, sizeof(*rpc_argv));

			if (!rpc_argv) {
				pr_err("calloc rpc_argv failed\n");
				exit(1);
			}
			rpc_argv[rpc_n++] = "criu";
			rpc_argv[rpc_n++] = "restore";
			rpc_argv[rpc_n++] = "--tfork-restore";
			rpc_argv[rpc_n++] = "--restore-detached";
			rpc_argv[rpc_n++] = "-D";
			rpc_argv[rpc_n++] = img_dir_arg;
			rpc_argv[rpc_n++] = "--pidfile";
			rpc_argv[rpc_n++] = pidfile_arg;
			rpc_argv[rpc_n++] = "-o";
			rpc_argv[rpc_n++] = restore_log_arg;
			rpc_argv[rpc_n++] = "-v2";
			rpc_argv[rpc_n++] = "--keep-pid-hierarchy";

			if (opts.root) {
				rpc_argv[rpc_n++] = "--root";
				rpc_argv[rpc_n++] = opts.root;
			}
			if (opts.tcp_close)
				rpc_argv[rpc_n++] = "--tcp-close";

			if (opts.new_global_cg_root) {
				rpc_argv[rpc_n++] = "--cgroup-root";
				rpc_argv[rpc_n++] = opts.new_global_cg_root;
			}
			list_for_each_entry(cgo_iter, &opts.new_cgroup_roots, node) {
				char *cg_buf;
				size_t need = strlen(cgo_iter->controller) + 1 +
					      strlen(cgo_iter->newroot) + 1;
				cg_buf = malloc(need);
				if (!cg_buf) {
					pr_err("malloc cgroup-root argv slot failed\n");
					exit(1);
				}
				snprintf(cg_buf, need, "%s:%s",
					 cgo_iter->controller, cgo_iter->newroot);
				rpc_argv[rpc_n++] = "--cgroup-root";
				rpc_argv[rpc_n++] = cg_buf;
			}
			if (opts.tfork.snap_root) {
				rpc_argv[rpc_n++] = "--tfork-snap-root";
				rpc_argv[rpc_n++] = opts.tfork.snap_root;
			}
			if (opts.tfork.snap_roots_n > 0) {
				size_t off = 0;
				snap_roots_csv[0] = '\0';
				for (i = 0; i < (size_t)opts.tfork.snap_roots_n; i++) {
					int wrote = snprintf(snap_roots_csv + off,
							     sizeof(snap_roots_csv) - off,
							     "%s%s",
							     i ? "," : "",
							     opts.tfork.snap_roots[i]);
					if (wrote < 0 ||
					    (size_t)wrote >= sizeof(snap_roots_csv) - off) {
						pr_err("--tfork-snap-roots csv too long\n");
						exit(1);
					}
					off += wrote;
				}
				rpc_argv[rpc_n++] = "--tfork-snap-roots";
				rpc_argv[rpc_n++] = snap_roots_csv;
			}

			for (i = 0; i < (size_t)opts.tfork.snap_mount_n; i++) {
				rpc_argv[rpc_n++] = "--tfork-snap-mount";
				rpc_argv[rpc_n++] = opts.tfork.snap_mount[i];
			}
			if (opts.tfork.snap_mounts_n > 0) {
				size_t off = 0;
				snap_mounts_csv[0] = '\0';
				for (i = 0; i < (size_t)opts.tfork.snap_mounts_n; i++) {
					int wrote = snprintf(snap_mounts_csv + off,
							     sizeof(snap_mounts_csv) - off,
							     "%s%s",
							     i ? "," : "",
							     opts.tfork.snap_mounts[i]);
					if (wrote < 0 ||
					    (size_t)wrote >= sizeof(snap_mounts_csv) - off) {
						pr_err("--tfork-snap-mounts csv too long\n");
						exit(1);
					}
					off += wrote;
				}
				rpc_argv[rpc_n++] = "--tfork-snap-mounts";
				rpc_argv[rpc_n++] = snap_mounts_csv;
			}
			if (opts.tfork.copies >= 1) {
				snprintf(copies_arg, sizeof(copies_arg),
					 "%d", opts.tfork.copies);
				rpc_argv[rpc_n++] = "--tfork-copies";
				rpc_argv[rpc_n++] = copies_arg;
			}
			if (opts.tfork.memdump_async)
				rpc_argv[rpc_n++] = "--tfork-memdump-async";
			else if (opts.tfork.memdump)
				rpc_argv[rpc_n++] = "--tfork-memdump";
			if (opts.tfork.full_memcopy)
				rpc_argv[rpc_n++] = "--tfork-full-memcopy";
			if (opts.track_mem)
				rpc_argv[rpc_n++] = "--track-mem";
			if (opts.img_parent) {
				rpc_argv[rpc_n++] = "--prev-images-dir";
				rpc_argv[rpc_n++] = opts.img_parent;
			}
			if (opts.shell_job)
				rpc_argv[rpc_n++] = "--shell-job";

			if (opts.empty_ns & 0x40000000) {
				rpc_argv[rpc_n++] = "--empty-ns";
				rpc_argv[rpc_n++] = "net";
			}

			ifd_ctx.argv = rpc_argv;
			ifd_ctx.np = &rpc_n;
			if (inherit_fd_for_each(tfork_ifd_append, &ifd_ctx) < 0)
				exit(1);
			if (external_for_each(tfork_ext_append, &ifd_ctx) < 0)
				exit(1);

			for (i = 0; i < (size_t)opts.tfork.per_copy_args_n; i++) {
				const char *args = opts.tfork.per_copy_args[i];
				char *arg_buf;
				size_t need;
				if (!args)
					continue;

				need = strlen("--tfork-copy=") + 16 + 2 + strlen(args) + 1;
				arg_buf = malloc(need);
				if (!arg_buf) {
					pr_err("malloc tfork-copy argv slot failed\n");
					exit(1);
				}
				snprintf(arg_buf, need, "--tfork-copy=%zu::%s", i, args);
				rpc_argv[rpc_n++] = arg_buf;
			}

			rpc_argv[rpc_n] = NULL;

			execv("/proc/self/exe", rpc_argv);
			pr_perror("tfork: exec restore failed (swrk path)");
			exit(1);
		}

		cmdline_fd = open_proc(PROC_SELF, "cmdline");
		if (cmdline_fd < 0) {
			pr_perror("Can't open /proc/self/cmdline");
			exit(1);
		}
		for (;;) {
			if (off + 4096 >= buf_size) {
				size_t new_size = buf_size ? buf_size * 2 : 8192;
				char *new_buf = realloc(buf, new_size);
				if (!new_buf) {
					pr_err("realloc cmdline buf (%zu) failed\n",
					       new_size);
					free(buf);
					close(cmdline_fd);
					exit(1);
				}
				buf = new_buf;
				buf_size = new_size;
			}
			n = read(cmdline_fd, buf + off, buf_size - 1 - off);
			if (n < 0) {
				pr_perror("Failed to read cmdline");
				free(buf);
				close(cmdline_fd);
				exit(1);
			}
			if (n == 0)
				break;
			off += n;
		}
		close(cmdline_fd);
		if (off == 0) {
			pr_err("Empty cmdline\n");
			free(buf);
			exit(1);
		}
		buf[off] = '\0';
		end = buf + off;

		argv_max = 8 + 3;
		for (p = buf; p < end; p++)
			if (*p == '\0')
				argv_max++;
		argv_new = calloc(argv_max, sizeof(*argv_new));
		if (!argv_new) {
			pr_err("calloc argv_new (%zu) failed\n", argv_max);
			free(buf);
			exit(1);
		}

		for (p = buf; p < end; p += strlen(p) + 1) {

			if (!strcmp(p, "tfork")) {
				argv_new[argc_new++] = "restore";
				argv_new[argc_new++] = "--tfork-restore";
				continue;
			}

			if (!strcmp(p, "-t") || !strcmp(p, "--tree")) {
				p += strlen(p) + 1;
				continue;
			}

			if (!strcmp(p, "-D") || !strcmp(p, "--images-dir")) {
				argv_new[argc_new++] = p;
				p += strlen(p) + 1;
				argv_new[argc_new++] = img_dir_arg;
				continue;
			}

			if (!strcmp(p, "--pidfile")) {
				argv_new[argc_new++] = p;
				p += strlen(p) + 1;
				argv_new[argc_new++] = pidfile_arg;
				saw_pidfile = true;
				continue;
			}
			argv_new[argc_new++] = p;
		}

		if (!saw_pidfile) {
			argv_new[argc_new++] = "--pidfile";
			argv_new[argc_new++] = pidfile_arg;
		}
		argv_new[argc_new++] = "--keep-pid-hierarchy";
		argv_new[argc_new] = NULL;

		execv("/proc/self/exe", argv_new);
		pr_perror("tfork: exec restore failed");
		exit(1);
	}

	if (waitpid(child, &status, 0) < 0) {
		pr_perror("tfork: waitpid failed");
		ret = -1;
	} else if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (ret)
			pr_err("tfork: restore failed: %d\n", ret);
		else
			pr_info("tfork: clone tree created, unfreezing originals\n");
	} else {
		pr_err("tfork: restore child killed by signal %d\n",
		       WTERMSIG(status));
		ret = -1;
	}

err:
	return cr_tfork_finish(ret);
}
