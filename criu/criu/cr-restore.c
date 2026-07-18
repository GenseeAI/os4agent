#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/shm.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sched.h>
#include <linux/elf.h>

#include "types.h"
#include <compel/ptrace.h>
#include "common/compiler.h"

#include "linux/rseq.h"

#include "capbypass.h"
#include "pkey_state.h"
#include "clone-noasan.h"
#include "cr_options.h"
#include "cr-tfork.h"
#include "servicefd.h"
#include "image.h"
#include "img-streamer.h"
#include "util.h"
#include "util-pie.h"
#include "criu-log.h"
#include "restorer.h"
#include "sockets.h"
#include "sk-packet.h"
#include "common/lock.h"
#include "files.h"
#include "pipes.h"
#include "fifo.h"
#include "sk-inet.h"
#include "eventfd.h"
#include "eventpoll.h"
#include "signalfd.h"
#include "proc_parse.h"
#include "pie/restorer-blob.h"
#include "crtools.h"
#include "uffd.h"
#include "namespaces.h"
#include "mem.h"
#include "mount.h"
#include "fsnotify.h"
#include "pstree.h"
#include "net.h"
#include "tty.h"
#include "cpu.h"
#include "file-lock.h"
#include "vdso.h"
#include "stats.h"
#include "tun.h"
#include "vma.h"
#include "kerndat.h"
#include "rst-malloc.h"
#include "plugin.h"
#include "cgroup.h"
#include "timerfd.h"
#include "action-scripts.h"
#include "shmem.h"
#include "aio.h"
#include "lsm.h"
#include "seccomp.h"
#include "fault-injection.h"
#include "sk-queue.h"
#include "sigframe.h"
#include "fdstore.h"
#include "string.h"
#include "memfd.h"
#include "ipc_ns.h"
#include "timens.h"
#include "uts_ns.h"
#include "bpfmap.h"
#include "apparmor.h"
#include "pidfd.h"

#include "parasite-syscall.h"
#include "files-reg.h"
#include "asm/dump.h"
#include <compel/plugins/std/syscall-codes.h>
#include "compel/include/asm/syscall.h"

#include "linux/mount.h"

#include "protobuf.h"
#include "images/sa.pb-c.h"
#include "images/timer.pb-c.h"
#include "images/vma.pb-c.h"
#include "images/rlimit.pb-c.h"
#include "images/pagemap.pb-c.h"
#include "images/siginfo.pb-c.h"

#include "restore.h"

#include "cr-errno.h"
#include "timer.h"
#include "sigact.h"

#ifndef arch_export_restore_thread
#define arch_export_restore_thread __export_restore_thread
#endif

#ifndef arch_export_restore_task
#define arch_export_restore_task __export_restore_task
#endif

#ifndef arch_export_unmap
#define arch_export_unmap	 __export_unmap
#define arch_export_unmap_compat __export_unmap_compat
#endif

struct pstree_item *current;

static int restore_task_with_children(void *);
static int sigreturn_restore(struct task_restore_args *ta, unsigned long alen, CoreEntry *core);
static int prepare_restorer_blob(void);
static int prepare_rlimits(int uid, struct task_restore_args *, CoreEntry *core);
static int prepare_signals(struct task_restore_args *, CoreEntry *core);

/*
 * Architectures can overwrite this function to restore registers that are not
 * present in the sigreturn signal frame.
 */
int __attribute__((weak)) arch_set_thread_regs_nosigrt(struct pid *pid)
{
	return 0;
}

static inline int stage_participants(int next_stage)
{
	switch (next_stage) {
	case CR_STATE_FAIL:
		return 0;
	case CR_STATE_ROOT_TASK:
	case CR_STATE_PREPARE_NAMESPACES:
		return 1;
	case CR_STATE_FORKING:
		return task_entries->nr_tasks + task_entries->nr_helpers;
	case CR_STATE_RESTORE:
		return task_entries->nr_threads + task_entries->nr_helpers;
	case CR_STATE_RESTORE_SIGCHLD:
	case CR_STATE_RESTORE_CREDS:
		return task_entries->nr_threads;
	}

	BUG();
	return -1;
}

static inline int stage_current_participants(int next_stage)
{
	switch (next_stage) {
	case CR_STATE_FORKING:

		return 1;
	case CR_STATE_RESTORE:
		/*
		 * Each thread has to be reported about this stage,
		 * so if we want to wait all other tasks, we have to
		 * exclude all threads of the current process.
		 * It is supposed that we will wait other tasks,
		 * before creating threads of the current task.
		 */
		return current->nr_threads;
	}

	BUG();
	return -1;
}

static int __restore_wait_inprogress_tasks(int participants)
{
	int ret;
	futex_t *np = &task_entries->nr_in_progress;

	futex_wait_while_gt(np, participants);
	ret = (int)futex_get(np);
	if (ret < 0) {
		set_cr_errno(get_task_cr_err());
		return ret;
	}

	return 0;
}

static int restore_wait_inprogress_tasks(void)
{
	return __restore_wait_inprogress_tasks(0);
}

/* Wait all tasks except the current one */
static int restore_wait_other_tasks(void)
{
	int participants, stage;

	stage = futex_get(&task_entries->start);
	participants = stage_current_participants(stage);

	return __restore_wait_inprogress_tasks(participants);
}

static inline void __restore_switch_stage_nw(int next_stage)
{
	futex_set(&task_entries->nr_in_progress, stage_participants(next_stage));
	futex_set(&task_entries->start, next_stage);
}

static inline void __restore_switch_stage(int next_stage)
{
	if (next_stage != CR_STATE_COMPLETE)
		futex_set(&task_entries->nr_in_progress, stage_participants(next_stage));
	futex_set_and_wake(&task_entries->start, next_stage);
}

static int restore_switch_stage(int next_stage)
{
	__restore_switch_stage(next_stage);
	return restore_wait_inprogress_tasks();
}

static int restore_finish_ns_stage(int from, int to)
{
	if (root_ns_mask){
		return restore_finish_stage(task_entries, from);
	}
	/* Nobody waits for this stage change, just go ahead */
	__restore_switch_stage_nw(to);
	return 0;
}

static int crtools_prepare_shared(void)
{
	if (prepare_memfd_inodes())
		return -1;

	if (prepare_files())
		return -1;

	/* We might want to remove ghost files on failed restore */
	if (collect_remaps_and_regfiles())
		return -1;

	/* Connections are unlocked from criu */
	if (!files_collected() && collect_image(&inet_sk_cinfo))
		return -1;

	if (collect_binfmt_misc())
		return -1;

	if (tty_prep_fds())
		return -1;

	if (prepare_apparmor_namespaces())
		return -1;

	return 0;
}

/*
 * Collect order information:
 * - reg_file should be before remap, as the latter needs
 *   to find file_desc objects
 * - per-pid collects (mm and fd) should be after remap and
 *   reg_file since both per-pid ones need to get fdesc-s
 *   and bump counters on remaps if they exist
 */

static struct collect_image_info *cinfos[] = {
	&file_locks_cinfo,  &pipe_data_cinfo, &fifo_data_cinfo, &sk_queues_cinfo,
#ifdef CONFIG_HAS_LIBBPF
	&bpfmap_data_cinfo,
#endif
};

static struct collect_image_info *cinfos_files[] = {
	&unix_sk_cinfo,	      &fifo_cinfo,     &pipe_cinfo,    &nsfile_cinfo,	    &packet_sk_cinfo,
	&netlink_sk_cinfo,    &eventfd_cinfo,  &epoll_cinfo,   &epoll_tfd_cinfo,    &signalfd_cinfo,
	&tunfile_cinfo,	      &timerfd_cinfo,  &inotify_cinfo, &inotify_mark_cinfo, &fanotify_cinfo,
	&fanotify_mark_cinfo, &ext_file_cinfo, &memfd_cinfo, &pidfd_cinfo
};

/* These images are required to restore namespaces */
static struct collect_image_info *before_ns_cinfos[] = {
	&tty_info_cinfo, /* Restore devpts content */
	&tty_cdata,
};

static struct pprep_head *post_prepare_heads = NULL;

void add_post_prepare_cb(struct pprep_head *ph)
{
	ph->next = post_prepare_heads;
	post_prepare_heads = ph;
}

static int run_post_prepare(void)
{
	struct pprep_head *ph;

	for (ph = post_prepare_heads; ph != NULL; ph = ph->next)
		if (ph->actor(ph))
			return -1;

	return 0;
}

static int root_prepare_shared(void)
{
	int ret = 0;
	struct pstree_item *pi;

	pr_info("Preparing info about shared resources\n");

	if (prepare_remaps())
		return -1;

	if (seccomp_read_image())
		return -1;

	if (collect_images(cinfos, ARRAY_SIZE(cinfos)))
		return -1;

	if (!files_collected() && collect_images(cinfos_files, ARRAY_SIZE(cinfos_files)))
		return -1;

	for_each_pstree_item(pi) {
		if (pi->pid->state == TASK_HELPER)
			continue;

		ret = prepare_mm_pid(pi);
		if (ret < 0)
			break;

		ret = prepare_fd_pid(pi);
		if (ret < 0)
			break;

		ret = prepare_fs_pid(pi);
		if (ret < 0)
			break;
	}

	if (ret < 0)
		goto err;

	prepare_cow_vmas();

	ret = prepare_restorer_blob();
	if (ret)
		goto err;

	ret = add_fake_unix_queuers();
	if (ret)
		goto err;

	/*
	 * This should be called with all packets collected AND all
	 * fdescs and fles prepared BUT post-prep-s not run.
	 */
	ret = prepare_scms();
	if (ret)
		goto err;

	ret = run_post_prepare();
	if (ret)
		goto err;

	ret = unix_prepare_root_shared();
	if (ret)
		goto err;

	show_saved_files();
err:
	return ret;
}

/* This actually populates and occupies ROOT_FD_OFF sfd */
static int populate_root_fd_off(void)
{
	struct ns_id *mntns = NULL;
	int ret;

	if (root_ns_mask & CLONE_NEWNS) {
		mntns = lookup_ns_by_id(root_item->ids->mnt_ns_id, &mnt_ns_desc);
		BUG_ON(!mntns);
	}

	ret = mntns_get_root_fd(mntns);
	if (ret < 0)
		pr_err("Can't get root fd\n");
	return ret >= 0 ? 0 : -1;
}

static int populate_pid_proc(void)
{
	char buf[32];
	int len, pid;

	len = readlink("/proc/self", buf, sizeof(buf) - 1);
	if (len > 0) {
		buf[len] = '\0';
		pid = atoi(buf);
		if (pid > 0 && open_pid_proc(pid) >= 0)
			goto self;
	}

	if (open_pid_proc(localpid(current)) < 0 &&
	    open_pid_proc(realpid(current)) < 0) {
		pr_err("Can't open PROC_PID for %d(%d)\n",
		       realpid(current), localpid(current));
		return -1;
	}
self:
	if (open_pid_proc(PROC_SELF) < 0) {
		pr_err("Can't open PROC_SELF\n");
		return -1;
	}
	return 0;
}

static int __collect_child_pids(struct pstree_item *p, int state, unsigned int *n)
{
	struct pstree_item *pi;

	list_for_each_entry(pi, &p->children, sibling) {
		pid_t *child;

		if (pi->pid->state != state)
			continue;

		child = rst_mem_alloc(sizeof(*child), RM_PRIVATE);
		if (!child)
			return -1;

		(*n)++;
		*child = localpid(pi);
	}

	return 0;
}

static int collect_child_pids(int state, unsigned int *n)
{
	struct pstree_item *pi;

	*n = 0;

	/*
	 * All children of helpers and zombies will be reparented to the init
	 * process and they have to be collected too.
	 */

	if (current == root_item) {
		for_each_pstree_item(pi) {
			if (pi->pid->state != TASK_HELPER && pi->pid->state != TASK_DEAD)
				continue;
			if (__collect_child_pids(pi, state, n))
				return -1;
		}
	}

	return __collect_child_pids(current, state, n);
}

static int collect_helper_pids(struct task_restore_args *ta)
{
	ta->helpers = (pid_t *)rst_mem_align_cpos(RM_PRIVATE);
	return collect_child_pids(TASK_HELPER, &ta->helpers_n);
}

static int collect_zombie_pids(struct task_restore_args *ta)
{
	ta->zombies = (pid_t *)rst_mem_align_cpos(RM_PRIVATE);
	return collect_child_pids(TASK_DEAD, &ta->zombies_n);
}

static int collect_inotify_fds(struct task_restore_args *ta)
{
	struct list_head *list = &rsti(current)->fds;
	struct fdt *fdt = rsti(current)->fdt;
	struct fdinfo_list_entry *fle;

	/* Check we are an fdt-restorer */
	if (fdt && fdt->pid != uid(current))
		return 0;

	ta->inotify_fds = (int *)rst_mem_align_cpos(RM_PRIVATE);

	list_for_each_entry(fle, list, ps_list) {
		struct file_desc *d = fle->desc;
		int *inotify_fd;

		if (d->ops->type != FD_TYPES__INOTIFY)
			continue;

		if (fle != file_master(d))
			continue;

		inotify_fd = rst_mem_alloc(sizeof(*inotify_fd), RM_PRIVATE);
		if (!inotify_fd)
			return -1;

		ta->inotify_fds_n++;
		*inotify_fd = fle->fe->fd;

		pr_debug("Collect inotify fd %d to cleanup later\n", *inotify_fd);
	}
	return 0;
}

static int open_core(int uid, CoreEntry **pcore)
{
	int ret;
	struct cr_img *img;

	img = open_image(CR_FD_CORE, O_RSTR, uid);
	if (!img) {
		pr_err("Can't open core data for %d\n", uid);
		return -1;
	}

	ret = pb_read_one(img, pcore, PB_CORE);
	close_image(img);

	return ret <= 0 ? -1 : 0;
}

static int open_cores(int leader_uid, CoreEntry *leader_core)
{
	int i, thread_uid;
	CoreEntry **cores = NULL;

	cores = xmalloc(sizeof(*cores) * current->nr_threads);
	if (!cores)
		goto err;

	for (i = 0; i < current->nr_threads; i++) {
		thread_uid = current->threads[i].uid;

		if (thread_uid == leader_uid)
			cores[i] = leader_core;
		else if (open_core(thread_uid, &cores[i]))
			goto err;
	}

	current->core = cores;

	/*
	 * Walk over all threads and if one them is having
	 * active seccomp mode we will suspend filtering
	 * on the whole group until restore complete.
	 *
	 * Otherwise any criu code which might use same syscall
	 * if present inside a filter chain would take filter
	 * action and might break restore procedure.
	 */
	for (i = 0; i < current->nr_threads; i++) {
		ThreadCoreEntry *thread_core = cores[i]->thread_core;
		if (thread_core->seccomp_mode != SECCOMP_MODE_DISABLED) {
			rsti(current)->has_seccomp = true;
			break;
		}
	}

	for (i = 0; i < current->nr_threads; i++) {
		ThreadCoreEntry *tc = cores[i]->thread_core;
		struct rst_rseq *rseqs = rsti(current)->rseqe;
		RseqEntry *rseqe = tc->rseq_entry;

		/* compatibility with older CRIU versions */
		if (!rseqe)
			continue;

		/* rseq cs had no RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL */
		if (!rseqe->has_rseq_cs_pointer)
			continue;

		rseqs[i].rseq_abi_pointer = rseqe->rseq_abi_pointer;
		rseqs[i].rseq_cs_pointer = rseqe->rseq_cs_pointer;
	}

	return 0;
err:
	xfree(cores);
	return -1;
}

static int prepare_oom_score_adj(int value)
{
	int fd, ret = 0;
	char buf[11];

	fd = open_proc_rw(PROC_SELF, "oom_score_adj");
	if (fd < 0)
		return -1;

	snprintf(buf, 11, "%d", value);

	if (write(fd, buf, 11) < 0) {
		pr_perror("Write %s to /proc/self/oom_score_adj failed", buf);
		ret = -1;
	}

	close(fd);
	return ret;
}

static bool has_own_user_ns(struct pstree_item *item)
{
	if (item == root_item)
		return !!(root_ns_mask & CLONE_NEWUSER);

	return item->ids && item->ids->has_user_ns_id &&
	       item->ids->has_parent_user_ns_id &&
	       item->ids->user_ns_id != item->ids->parent_user_ns_id;
}

static bool is_simple_userns_tree(void)
{
	unsigned int root_uns_id;
	struct pstree_item *it;

	if (!(root_ns_mask & CLONE_NEWUSER))
		return false;
	if (!root_item || !root_item->ids || !root_item->ids->has_user_ns_id)
		return false;

	root_uns_id = root_item->ids->user_ns_id;
	for_each_pstree_item(it) {
		if (!it->ids || !it->ids->has_user_ns_id)
			continue;
		if (it->ids->user_ns_id != root_uns_id)
			return false;
	}
	return true;
}

static bool tree_has_user_ns_work(void)
{
	struct pstree_item *it;

	if (root_ns_mask & CLONE_NEWUSER)
		return true;
	for_each_pstree_item(it) {
		if (has_own_user_ns(it))
			return true;
	}
	return false;
}

static int prepare_proc_misc(struct pstree_item *item, TaskCoreEntry *tc, struct task_restore_args *args)
{
	int ret;

	if (tc->has_child_subreaper)
		args->child_subreaper = tc->child_subreaper;

	if (tc->has_membarrier_registration_mask)
		args->membarrier_registration_mask = tc->membarrier_registration_mask;

	if (kdat.luid == LUID_FULL && tc->has_loginuid && tc->loginuid != INVALID_UID) {
		ret = prepare_loginuid(tc->loginuid);
		if (ret < 0) {
			if (tree_has_user_ns_work()) {
				pr_warn("loginuid for %d(%d) skipped (non-HOST user_ns)\n",
					realpid(item), localpid(item));
				ret = 0;
			} else {
				pr_err("Setting loginuid for %d(%d) task failed\n",
				       realpid(item), localpid(item));
				return ret;
			}
		}
	}

	/* oom_score_adj is not critical: only log errors */
	if (tc->has_oom_score_adj && tc->oom_score_adj != 0)
		prepare_oom_score_adj(tc->oom_score_adj);

	return 0;
}

static int prepare_mm(struct pstree_item *item, struct task_restore_args *args);

static bool already_in_userns(int nsfd)
{
	struct stat st_self, st_target;

	if (fstatat(open_pid_proc(PROC_SELF), "ns/user", &st_self, 0) < 0)
		return false;
	if (fstat(nsfd, &st_target) < 0)
		return false;
	return st_self.st_ino == st_target.st_ino;
}

static int setns_user_ns_id(unsigned int user_ns_id)
{
	int fd, ret = 0;

	fd = userns_addr_open_nsfd(user_ns_id);
	if (fd < 0)
		return -1;
	if (!already_in_userns(fd) && setns(fd, CLONE_NEWUSER) < 0) {
		pr_perror("userns: setns into user_ns_id %u failed", user_ns_id);
		ret = -1;
	}
	close(fd);
	return ret;
}

static int finish_own_userns(unsigned int target_uns)
{
	bool have_parent_uns = current != root_item &&
		current->ids->has_parent_user_ns_id;
	bool simple_root = current == root_item && is_simple_userns_tree();
	struct pstree_item *child;

	if (have_parent_uns &&
	    setns_user_ns_id(current->ids->parent_user_ns_id) < 0)
		return -1;

	if (!simple_root) {
		if (unshare(CLONE_NEWUSER) < 0) {
			pr_perror("userns: unshare(CLONE_NEWUSER) failed");
			return -1;
		}
		futex_set_and_wake(&rsti(current)->userns_unshared_futex, 1);
		futex_wait_until(&rsti(current)->ns_written_futex, 1);
	}

	if (rsti(current)->root && rsti(current)->cwd && !rsti(current)->fs_restored) {
		if (restore_fs(current))
			return -1;
	}

	if (prepare_userns_creds()) {
		pr_perror("userns: prepare_userns_creds failed");
		return -1;
	}

	userns_addr_publish(target_uns);

	list_for_each_entry(child, &current->children, sibling) {
		if (!has_own_user_ns(child))
			continue;
		if (!child->ids->has_parent_user_ns_id ||
		    child->ids->parent_user_ns_id != target_uns)
			continue;

		if (host_user_ns_id != 0 &&
		    child->ids->has_user_ns_id &&
		    child->ids->user_ns_id == host_user_ns_id)
			continue;
		futex_wait_until(&rsti(child)->userns_unshared_futex, 1);
		if (prepare_userns(child)) {
			pr_err("userns: prepare_userns for child vpid %d failed\n",
			       localpid(child));
			return -1;
		}
	}
	return 0;
}

static int finish_shared_userns(unsigned int target_uns)
{
	int fd, ret = 0;

	fd = userns_addr_open_nsfd(target_uns);
	if (fd < 0)
		return -1;
	if (already_in_userns(fd))
		goto out;
	if (setns(fd, CLONE_NEWUSER) < 0) {
		pr_perror("userns: setns into shared user_ns %u failed", target_uns);
		ret = -1;
		goto out;
	}

	if (rsti(current)->root && rsti(current)->cwd && !rsti(current)->fs_restored) {
		if (restore_fs(current)) {
			ret = -1;
			goto out;
		}
	}
	if (prepare_userns_creds()) {
		pr_perror("userns: prepare_userns_creds (shared) failed");
		ret = -1;
	}
out:
	close(fd);
	return ret;
}

static int restore_finish_userns(void)
{
	unsigned int target_uns;

	if (!task_alive(current) || !tree_has_user_ns_work() ||
	    !current->ids || !current->ids->has_user_ns_id)
		return 0;

	target_uns = current->ids->user_ns_id;

	if (host_user_ns_id != 0 && target_uns == host_user_ns_id) {
		if (has_own_user_ns(current))
			return finish_shared_userns(target_uns);
		if (current == root_item) {
			userns_addr_publish(target_uns);
			return 0;
		}
		return finish_shared_userns(target_uns);
	}

	if (has_own_user_ns(current))
		return finish_own_userns(target_uns);

	if (current == root_item) {
		userns_addr_publish(target_uns);
		return 0;
	}

	if (current->parent && current->parent->ids &&
	    current->parent->ids->has_user_ns_id &&
	    current->parent->ids->user_ns_id == target_uns)
		return finish_shared_userns(target_uns);

	return 0;
}

static int restore_one_alive_task(struct pstree_item *item, CoreEntry *core)
{
	unsigned args_len;
	struct task_restore_args *ta;
	struct rst_info *ri;
	pr_info("Restoring resources\n");

	rst_mem_switch_to_private();

	args_len = round_up(sizeof(*ta) + sizeof(struct thread_restore_args) * current->nr_threads, page_size());
	ta = mmap(NULL, args_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	if (!ta)
		return -1;

	memzero(ta, args_len);

	if (prepare_fds(current))
		return -1;

	if (prepare_file_locks(current->pid))
		return -1;

	if (open_vmas(current))
		return -1;

	if (prepare_aios(current, ta))
		return -1;

	if (fixup_sysv_shmems())
		return -1;

	if (open_cores(uid(item), core))
		return -1;

	if (prepare_signals(ta, core))
		return -1;

	if (prepare_posix_timers(uid(current), ta, core))
		return -1;

	if (prepare_rlimits(uid(current), ta, core) < 0)
		return -1;

	if (collect_helper_pids(ta) < 0)
		return -1;

	if (collect_zombie_pids(ta) < 0)
		return -1;

	if (collect_inotify_fds(ta) < 0)
		return -1;

	if (prepare_proc_misc(current, core->tc, ta))
		return -1;

	/*
	 * Get all the tcp sockets fds into rst memory -- restorer
	 * will turn repair off before going sigreturn
	 */
	if (prepare_tcp_socks(ta))
		return -1;

	/*
	 * Copy timerfd params for restorer args, we need to proceed
	 * timer setting at the very late.
	 */
	if (prepare_timerfds(ta))
		return -1;

	if (seccomp_prepare_threads(current, ta) < 0)
		return -1;

	if (prepare_itimers(uid(current), ta, core) < 0)
		return -1;

	if (prepare_mm(current, ta))
		return -1;

	if (prepare_vmas(current, ta))
		return -1;

	/*
	 * Sockets have to be restored in their network namespaces,
	 * so a task namespace has to be restored after sockets.
	 */
	if (restore_task_net_ns(current))
		return -1;

	if (setup_uffd(uid(current), ta))
		return -1;

	ri = rsti(current);

	ri->root_fd = open_reg_fd(ri->root);
	if (ri->root_fd < 0) {
		pr_perror("Can't open root");
		return -1;
	}
	ri->cwd_fd = open_reg_fd(ri->cwd);
	if (ri->cwd_fd < 0) {
		pr_perror("Can't open cwd");
		close(ri->root_fd);
		ri->root_fd = -1;
		return -1;
	}

	if (restore_finish_userns())
		return -1;

	if (arch_shstk_prepare(current, core, ta))
		return -1;
	return sigreturn_restore(ta, args_len, core);
}

static void zombie_prepare_signals(void)
{
	sigset_t blockmask;
	int sig;
	struct sigaction act;

	sigfillset(&blockmask);
	sigprocmask(SIG_UNBLOCK, &blockmask, NULL);

	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_DFL;

	for (sig = 1; sig <= SIGMAX; sig++)
		sigaction(sig, &act, NULL);
}

#define SIG_FATAL_MASK                                                                                          \
	((1 << SIGHUP) | (1 << SIGINT) | (1 << SIGQUIT) | (1 << SIGILL) | (1 << SIGTRAP) | (1 << SIGABRT) |     \
	 (1 << SIGIOT) | (1 << SIGBUS) | (1 << SIGFPE) | (1 << SIGKILL) | (1 << SIGUSR1) | (1 << SIGSEGV) |     \
	 (1 << SIGUSR2) | (1 << SIGPIPE) | (1 << SIGALRM) | (1 << SIGTERM) | (1 << SIGXCPU) | (1 << SIGXFSZ) |  \
	 (1 << SIGVTALRM) | (1 << SIGPROF) | (1 << SIGPOLL) | (1 << SIGIO) | (1 << SIGSYS) | (1 << SIGSTKFLT) | \
	 (1 << SIGPWR))

static inline int sig_fatal(int sig)
{
	return (sig > 0) && (sig < SIGMAX) && (SIG_FATAL_MASK & (1UL << sig));
}

struct task_entries *task_entries;
static unsigned long task_entries_pos;

static int wait_on_helpers_zombies(void)
{
	struct pstree_item *pi;

	list_for_each_entry(pi, &current->children, sibling) {
		pid_t pid = localpid(pi);
		int status;

		switch (pi->pid->state) {
		case TASK_DEAD:
			if (waitid(P_PID, pid, NULL, WNOWAIT | WEXITED) < 0) {
				pr_perror("Wait on %d zombie failed", pid);
				return -1;
			}
			break;
		case TASK_HELPER:
			if (waitpid(pid, &status, 0) != pid) {
				pr_perror("waitpid for helper %d failed", pid);
				return -1;
			}
			break;
		}
	}

	return 0;
}

static int wait_exiting_children(void);

static int restore_one_zombie(CoreEntry *core)
{
	int exit_code = core->tc->exit_code;

	pr_info("Restoring zombie with %d code\n", exit_code);

	if (prepare_fds(current))
		return -1;

	if (lazy_pages_setup_zombie(uid(current)))
		return -1;

	prctl(PR_SET_NAME, (long)(void *)core->tc->comm, 0, 0, 0);

	if (task_entries != NULL) {
		wait_exiting_children();
		zombie_prepare_signals();
	}

	if (exit_code & 0x7f) {
		int signr;

		/* prevent generating core files */
		if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0))
			pr_perror("Can't drop the dumpable flag");

		signr = exit_code & 0x7F;
		if (!sig_fatal(signr)) {
			pr_warn("Exit with non fatal signal ignored\n");
			signr = SIGABRT;
		}

		if (kill(localpid(current), signr) < 0)
			pr_perror("Can't kill myself, will just exit");

		exit_code = 0;
	}

	exit((exit_code >> 8) & 0x7f);

	/* never reached */
	BUG_ON(1);
	return -1;
}

static int setup_newborn_fds(struct pstree_item *me)
{
	if (clone_service_fd(me))
		return -1;

	if (!me->parent || (rsti(me->parent)->fdt && !(rsti(me)->clone_flags & CLONE_FILES))) {
		/*
		 * When our parent has shared fd table, some of the table owners
		 * may be already created. Files, they open, will be inherited
		 * by current process, and here we close them. Also, service fds
		 * of parent are closed here. And root_item closes the files,
		 * that were inherited from criu process.
		 */
		if (close_old_fds())
			return -1;
	}

	return 0;
}

static int check_core(CoreEntry *core, struct pstree_item *me)
{
	int ret = -1;

	if (core->mtype != CORE_ENTRY__MARCH) {
		pr_err("Core march mismatch %d\n", (int)core->mtype);
		goto out;
	}

	if (!core->tc) {
		pr_err("Core task state data missed\n");
		goto out;
	}

	if (core->tc->task_state != TASK_DEAD) {
		if (!core->ids && !me->ids) {
			pr_err("Core IDS data missed for non-zombie\n");
			goto out;
		}

		if (!CORE_THREAD_ARCH_INFO(core)) {
			pr_err("Core info data missed for non-zombie\n");
			goto out;
		}

		/*
		 * Seccomp are moved to per-thread origin,
		 * so for old images we need to move per-task
		 * data into proper place.
		 */
		if (core->tc->has_old_seccomp_mode) {
			core->thread_core->has_seccomp_mode = core->tc->has_old_seccomp_mode;
			core->thread_core->seccomp_mode = core->tc->old_seccomp_mode;
		}
		if (core->tc->has_old_seccomp_filter) {
			core->thread_core->has_seccomp_filter = core->tc->has_old_seccomp_filter;
			core->thread_core->seccomp_filter = core->tc->old_seccomp_filter;
			rsti(me)->has_old_seccomp_filter = true;
		}
	}

	ret = 0;
out:
	return ret;
}

/*
 * Find if there are children which are zombies or helpers - processes
 * which are expected to die during the restore.
 */
static bool child_death_expected(void)
{
	struct pstree_item *pi;

	list_for_each_entry(pi, &current->children, sibling) {
		switch (pi->pid->state) {
		case TASK_DEAD:
		case TASK_HELPER:
			return true;
		}
	}

	return false;
}

static int wait_exiting_children(void)
{
	siginfo_t info;

	if (!child_death_expected()) {
		/*
		 * Restoree has no children that should die, during restore,
		 * wait for the next stage on futex.
		 * The default SIGCHLD handler will handle an unexpected
		 * child's death and abort the restore if someone dies.
		 */
		restore_finish_stage(task_entries, CR_STATE_RESTORE);
		return 0;
	}

	/*
	 * The restoree has children which will die - decrement itself from
	 * nr. of tasks processing the stage and wait for anyone to die.
	 * Tasks may die only when they're on the following stage.
	 * If one dies earlier - that's unexpected - treat it as an error
	 * and abort the restore.
	 */
	if (block_sigmask(NULL, SIGCHLD))
		return -1;

	/* Finish CR_STATE_RESTORE, but do not wait for the next stage. */
	futex_dec_and_wake(&task_entries->nr_in_progress);

	if (waitid(P_ALL, 0, &info, WEXITED | WNOWAIT)) {
		pr_perror("Failed to wait");
		return -1;
	}

	if (futex_get(&task_entries->start) == CR_STATE_RESTORE) {
		pr_err("Child %d died too early\n", info.si_pid);
		return -1;
	}

	if (wait_on_helpers_zombies()) {
		pr_err("Failed to wait on helpers and zombies\n");
		return -1;
	}

	return 0;
}

/*
 * Restore a helper process - artificially created by criu
 * to restore attributes of process tree.
 * - sessions for each leaders are dead
 * - process groups with dead leaders
 * - dead tasks for which /proc/<pid>/... is opened by restoring task
 * - whatnot
 */
static int restore_one_helper(void)
{
	int i;

	if (prepare_fds(current))
		return -1;

	if (wait_exiting_children())
		return -1;

	sfds_protected = false;
	close_image_dir();
	close_proc();
	for (i = SERVICE_FD_MIN + 1; i < SERVICE_FD_MAX; i++)
		close_service_fd(i);

	return 0;
}

static int restore_one_task(struct pstree_item *item, CoreEntry *core)
{
	int ret;

	/* No more fork()-s => no more per-pid logs */

	if (task_alive(item))
		ret = restore_one_alive_task(item, core);
	else if (item->pid->state == TASK_DEAD)
		ret = restore_one_zombie(core);
	else if (item->pid->state == TASK_HELPER) {
		ret = restore_one_helper();
	} else {
		pr_err("Unknown state in code %d\n", (int)core->tc->task_state);
		ret = -1;
	}

	if (core)
		core_entry__free_unpacked(core, NULL);
	return ret;
}

/* All arguments should be above stack, because it grows down */
struct cr_clone_arg {
	struct pstree_item *item;
	unsigned long clone_flags;

	CoreEntry *core;
};

static void maybe_clone_parent(struct pstree_item *item, struct cr_clone_arg *ca)
{
	/*
	 * zdtm runs in kernel 3.11, which has the problem described below. We
	 * avoid this by including the pdeath_sig test. Once users/zdtm migrate
	 * off of 3.11, this condition can be simplified to just test the
	 * options and not have the pdeath_sig test.
	 */
	if (opts.restore_sibling) {
		/*
		 * This means we're called from lib's criu_restore_child().
		 * In that case create the root task as the child one to+
		 * the caller. This is the only way to correctly restore the
		 * pdeath_sig of the root task. But also looks nice.
		 *
		 * Alternatively, if we are --restore-detached, a similar trick is
		 * needed to correctly restore pdeath_sig and prevent processes from
		 * dying once restored.
		 *
		 * There were a problem in kernel 3.11 -- CLONE_PARENT can't be
		 * set together with CLONE_NEWPID, which has been solved in further
		 * versions of the kernels, but we treat 3.11 as a base, so at
		 * least warn a user about potential problems.
		 */
		rsti(item)->clone_flags |= CLONE_PARENT;
		if (rsti(item)->clone_flags & CLONE_NEWPID)
			pr_warn("Set CLONE_PARENT | CLONE_NEWPID but it might cause restore problem,"
				"because not all kernels support such clone flags combinations!\n");
	} else if (opts.restore_detach) {
		if (ca->core->thread_core->pdeath_sig)
			pr_warn("Root task has pdeath_sig configured, so it will receive one _right_"
				"after restore on CRIU exit\n");
	}
}

static int set_next_pid(void *arg)
{
	char buf[32];
	pid_t *pid = arg;
	int len;
	int fd;

	fd = open_proc_rw(PROC_GEN, LAST_PID_PATH);
	if (fd < 0)
		return -1;

	len = snprintf(buf, sizeof(buf), "%d", *pid - 1);
	if (write(fd, buf, len) != len) {
		pr_perror("Failed to write %s to /proc/%s", buf, LAST_PID_PATH);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static inline int fork_with_pid(struct pstree_item *item)
{
	struct cr_clone_arg ca;
	struct ns_id *pid_ns = NULL;
	bool external_pidns = false;
	int ret = -1;
	pid_t pid = localpid(item);
	unsigned long strip;

	if (item->pid->state != TASK_HELPER) {
		if (open_core(uid(item), &ca.core))
			return -1;

		if (check_core(ca.core, item))
			return -1;

		item->pid->state = ca.core->tc->task_state;

		/*
		 * Zombie tasks' cgroup is not dumped/restored.
		 * cg_set == 0 is skipped in prepare_task_cgroup()
		 */
		if (item->pid->state == TASK_DEAD) {
			rsti(item)->cg_set = 0;
		} else {
			if (ca.core->thread_core->has_cg_set)
				rsti(item)->cg_set = ca.core->thread_core->cg_set;
			else
				rsti(item)->cg_set = ca.core->tc->cg_set;
		}

		if (ca.core->tc->has_stop_signo)
			item->pid->stop_signo = ca.core->tc->stop_signo;

		if (item->pid->state != TASK_DEAD && !task_alive(item)) {
			pr_err("Unknown task state %d\n", item->pid->state);
			return -1;
		}

		/*
		 * By default we assume that seccomp is not
		 * used at all (especially on dead task). Later
		 * we will walk over all threads and check in
		 * details if filter is present setting up
		 * this flag as appropriate.
		 */
		rsti(item)->has_seccomp = false;

		if (unlikely(item == root_item))
			maybe_clone_parent(item, &ca);
	} else {
		/*
		 * Helper entry will not get moved around and thus
		 * will live in the parent's cgset.
		 */
		rsti(item)->cg_set = rsti(item->parent)->cg_set;
		ca.core = NULL;
	}

	if (item->ids)
		pid_ns = lookup_ns_by_id(item->ids->pid_ns_id, &pid_ns_desc);

	if (!current && pid_ns && pid_ns->ext_key)
		external_pidns = true;

	if (external_pidns) {
		int fd;

		/* Not possible to restore into an empty PID namespace. */
		if (pid == INIT_PID) {
			pr_err("Unable to restore into an empty PID namespace\n");
			return -1;
		}

		fd = inherit_fd_lookup_id(pid_ns->ext_key);
		if (fd < 0) {
			pr_err("Unable to find an external pidns: %s\n", pid_ns->ext_key);
			return -1;
		}

		ret = switch_ns_by_fd(fd, &pid_ns_desc, NULL);
		close(fd);
		if (ret) {
			pr_err("Unable to enter existing PID namespace\n");
			return -1;
		}

		pr_info("Inheriting external pidns %s for %d\n", pid_ns->ext_key, pid);
	}

	ca.item = item;
	ca.clone_flags = rsti(item)->clone_flags;

	BUG_ON(ca.clone_flags & CLONE_VM);

	pr_info("Forking task with %d(%d) (flags 0x%lx)\n", realpid(item), pid, ca.clone_flags);

	if (!(ca.clone_flags & CLONE_NEWPID)) {
		lock_last_pid();

		if (!kdat.has_clone3_set_tid) {
			if (external_pidns) {
				/*
				 * Restoring into another namespace requires a helper
				 * to write to LAST_PID_PATH. Using clone3() this is
				 * so much easier and simpler. As long as CRIU supports
				 * clone() this is needed.
				 */
				ret = call_in_child_process(set_next_pid, (void *)&pid);
			} else {
				ret = set_next_pid((void *)&pid);
			}
			if (ret != 0) {
				pr_err("Setting PID failed\n");
				goto err_unlock;
			}
		}
	} else {
		if (!external_pidns) {
			if (pid != INIT_PID) {
				pr_err("First PID in a PID namespace needs to be %d and not %d\n", pid, INIT_PID);
				return -1;
			}
		}
	}

	strip = CLONE_NEWNET | CLONE_NEWCGROUP | CLONE_NEWTIME;
	if (!(item == root_item && is_simple_userns_tree()))
		strip |= CLONE_NEWUSER;

	if (kdat.has_clone3_set_tid) {
		if (opts.tfork.active && (ca.clone_flags & CLONE_NEWPID)) {
			pr_info("tfork: restore pidns init uid=%d local pid %d with fresh parent pid, dumped chain level=%d\n",
				uid(item), pid, item->pid->ns_level);
			ret = clone3_with_pid_noasan(restore_task_with_children, &ca,
						     ca.clone_flags & ~strip, SIGCHLD, pid);
		} else if (item->pid->ns_level == 1)
			ret = clone3_with_pid_noasan(restore_task_with_children, &ca,
						     ca.clone_flags & ~strip, SIGCHLD, pid);
		else {
			struct pid tfork_pid = {};
			struct pid *restore_pid = item->pid;

			if (opts.tfork.active && (root_ns_mask & CLONE_NEWPID) &&
			    root_item && root_item->pid->ns_level > 1 &&
			    item->pid->ns_level > 1) {
				tfork_pid = *item->pid;
				tfork_pid.ns_level--;
				restore_pid = &tfork_pid;
				pr_info("tfork: restore pid uid=%d local=%d with rebased pid chain level %d -> %d\n",
					uid(item), pid, item->pid->ns_level,
					restore_pid->ns_level);
			}
			ret = clone3_with_nested_pid_noasan(restore_task_with_children, &ca,
							    ca.clone_flags & ~strip,
							    SIGCHLD, restore_pid);
		}
	} else {
		BUG_ON(item->pid->ns_level >= 1);
		close_pid_proc();
		ret = clone_noasan(restore_task_with_children,
				   (ca.clone_flags & ~strip) | SIGCHLD, &ca);
	}
	if (ret < 0) {
		pr_err("fork_with_pid failed item uid=%d local=%d real=%d parent_local=%d flags=0x%lx stripped_flags=0x%lx ns_level=%d root_ns_mask=0x%lx tfork=%d\n",
		       uid(item), pid, realpid(item),
		       item->parent ? localpid(item->parent) : -1,
		       ca.clone_flags, ca.clone_flags & ~strip,
		       item->pid->ns_level, root_ns_mask,
		       opts.tfork.active ? 1 : 0);
		if (item->pid->ns_level > 0)
			pr_err("fork_with_pid pid chain uid=%d ns=%d/%d/%d/%d\n",
			       uid(item),
			       item->pid->ns[0].ns_pid,
			       item->pid->ns_level > 1 ? item->pid->ns[1].ns_pid : -1,
			       item->pid->ns_level > 2 ? item->pid->ns[2].ns_pid : -1,
			       item->pid->ns_level > 3 ? item->pid->ns[3].ns_pid : -1);
		pr_perror("Can't fork for %d", pid);
		if (errno == EEXIST)
			set_cr_errno(EEXIST);
		goto err_unlock;
	}

	if (opts.tfork.active || item == root_item) {
		item->pid->real = ret;
		pr_debug("PID: real %d virt %d\n", item->pid->real, localpid(item));
	}

	arch_shstk_unlock(item, ca.core, ret);

err_unlock:
	if (!(ca.clone_flags & CLONE_NEWPID))
		unlock_last_pid();

	if (ca.core)
		core_entry__free_unpacked(ca.core, NULL);
	return ret;
}

static pid_t userns_maps_helper_pid = -1;

static bool item_parent_uns_is_host(struct pstree_item *item)
{
	struct cr_img *img;
	bool host;

	if (!item->ids->has_parent_user_ns_id)
		return true;

	if (host_user_ns_id != 0)
		return item->ids->parent_user_ns_id == host_user_ns_id;

	img = open_image(CR_FD_USERNS, O_RSTR, item->ids->parent_user_ns_id);
	host = !img || empty_image(img);
	if (img)
		close_image(img);
	return host;
}

static void userns_maps_helper_main(void)
{
	struct pstree_item *it;

	for_each_pstree_item(it) {
		if (!has_own_user_ns(it))
			continue;
		if (!item_parent_uns_is_host(it))
			continue;
		futex_wait_until(&rsti(it)->userns_unshared_futex, 1);
		if (prepare_userns(it)) {
			pr_err("userns(helper): prepare_userns for vpid %d failed\n",
			       localpid(it));
			exit(1);
		}
	}
	exit(0);
}

/* Returns 0 if restore can be continued */
static int sigchld_process(int status, pid_t pid)
{
	int sig;

	if (pid == userns_maps_helper_pid) {
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			pr_info("userns(helper) %d exited cleanly\n", pid);
			userns_maps_helper_pid = -1;
			return 0;
		}
		pr_err("userns(helper) %d failed (status=0x%x)\n", pid, status);
		return -1;
	}

	if (WIFEXITED(status)) {
		pr_err("%d exited, status=%d\n", pid, WEXITSTATUS(status));
		return -1;
	} else if (WIFSIGNALED(status)) {
		sig = WTERMSIG(status);
		pr_err("%d killed by signal %d: %s\n", pid, sig, strsignal(sig));
		return -1;
	} else if (WIFSTOPPED(status)) {
		sig = WSTOPSIG(status);
		/* The root task is ptraced. Allow it to handle SIGCHLD */
		if (sig == SIGCHLD && !current) {
			if (ptrace(PTRACE_CONT, pid, 0, SIGCHLD)) {
				pr_perror("Unable to resume %d", pid);
				return -1;
			}
			return 0;
		}
		pr_err("%d stopped by signal %d: %s\n", pid, sig, strsignal(sig));
		return -1;
	} else if (WIFCONTINUED(status)) {
		pr_err("%d unexpectedly continued\n", pid);
		return -1;
	}
	pr_err("wait for %d resulted in %x status\n", pid, status);
	return -1;
}

static void sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	while (1) {
		int status;
		pid_t pid;

		pid = waitpid(-1, &status, WNOHANG);
		if (pid <= 0)
			return;

		if (sigchld_process(status, pid) < 0)
			goto err_abort;
	}

err_abort:
	futex_abort_and_wake(&task_entries->nr_in_progress);
}

static int criu_signals_setup(void)
{
	int ret;
	struct sigaction act;
	sigset_t blockmask;

	ret = sigaction(SIGCHLD, NULL, &act);
	if (ret < 0) {
		pr_perror("sigaction() failed");
		return -1;
	}

	act.sa_flags |= SA_NOCLDSTOP | SA_SIGINFO | SA_RESTART;
	act.sa_sigaction = sigchld_handler;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGCHLD);

	ret = sigaction(SIGCHLD, &act, NULL);
	if (ret < 0) {
		pr_perror("sigaction() failed");
		return -1;
	}

	/*
	 * The block mask will be restored in sigreturn.
	 *
	 * TODO: This code should be removed, when a freezer will be added.
	 */
	sigfillset(&blockmask);
	sigdelset(&blockmask, SIGCHLD);

	/*
	 * Here we use SIG_SETMASK instead of SIG_BLOCK to avoid the case where
	 * we've been forked from a parent who had blocked SIGCHLD. If SIGCHLD
	 * is blocked when a task dies (e.g. if the task fails to restore
	 * somehow), we hang because our SIGCHLD handler is never run. Since we
	 * depend on SIGCHLD being unblocked, let's set the mask explicitly.
	 */
	ret = sigprocmask(SIG_SETMASK, &blockmask, NULL);
	if (ret < 0) {
		pr_perror("Can't block signals");
		return -1;
	}

	return 0;
}

static void restore_sid(void)
{
	pid_t sid;

	/*
	 * SID can only be reset to pid or inherited from parent.
	 * Thus we restore it right here to let our kids inherit
	 * one in case they need it.
	 *
	 * PGIDs are restored late when all tasks are forked and
	 * we can call setpgid() on custom values.
	 */

	if (localpid(current) == current->sid) {
		pr_info("Restoring %d(%d) to %d sid\n", realpid(current), localpid(current), current->sid);
		sid = setsid();
		if (sid != current->sid) {
			pr_perror("Can't restore sid (%d)", sid);
			exit(1);
		}
	} else {
		sid = getsid(0);
		if (sid != current->sid) {
			/* Skip the root task if it's not init */
			if (current == root_item && localpid(root_item) != INIT_PID)
				return;
			pr_err("Requested sid %d doesn't match inherited %d\n",
				current->sid, sid);
			exit(1);
		}
	}
}

static void restore_pgid(void)
{
	/*
	 * Unlike sessions, process groups (a.k.a. pgids) can be joined
	 * by any task, provided the task with pid == pgid (group leader)
	 * exists. Thus, in order to restore pgid we must make sure that
	 * group leader was born and created the group, then join one.
	 *
	 * We do this _before_ finishing the forking stage to make sure
	 * helpers are still with us.
	 */

	pid_t pgid, my_pgid = current->pgid;

	pr_info("Restoring %d to %d(%d) pgid\n", realpid(current), localpid(current), my_pgid);

	pgid = getpgrp();
	if (my_pgid == pgid)
		return;

	if (my_pgid != localpid(current)) {
		struct pstree_item *leader;

		/*
		 * Wait for leader to become such.
		 * Missing leader means we're going to crtools
		 * group (-j option).
		 */

		leader = rsti(current)->pgrp_leader;
		if (leader) {
			BUG_ON(my_pgid != localpid(leader));
			futex_wait_until(&rsti(leader)->pgrp_set, 1);
		}
	}

	pr_info("\twill call setpgid, mine pgid is %d\n", pgid);
	if (setpgid(0, my_pgid) != 0) {
		pr_perror("process %d(%d) can't restore pgid %d->%d)",
			realpid(current), localpid(current), pgid, current->pgid);
		exit(1);
	}

	if (my_pgid == localpid(current))
		futex_set_and_wake(&rsti(current)->pgrp_set, 1);
}

static int __legacy_mount_proc(void)
{
	char proc_mountpoint[] = "/tmp/crtools-proc.XXXXXX";
	int fd;

	if (mkdtemp(proc_mountpoint) == NULL) {
		pr_perror("mkdtemp failed %s", proc_mountpoint);
		return -1;
	}

	pr_info("Mount procfs in %s\n", proc_mountpoint);
	if (mount("proc", proc_mountpoint, "proc", MS_MGC_VAL | MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL)) {
		pr_perror("mount failed");
		if (rmdir(proc_mountpoint))
			pr_perror("Unable to remove %s", proc_mountpoint);
		return -1;
	}

	fd = open_detach_mount(proc_mountpoint);
	return fd;
}

static int mount_proc(void)
{
	int fd, ret;

	if (root_ns_mask == 0)
		fd = ret = open("/proc", O_DIRECTORY);
	else {
		if (kdat.has_fsopen)
			fd = ret = mount_detached_fs("proc");
		else
			fd = ret = __legacy_mount_proc();
	}

	if (fd >= 0) {
		ret = set_proc_fd(fd);
		close(fd);
	}

	return ret;
}

/*
 * Tasks cannot change sid (session id) arbitrary, but can either
 * inherit one from ancestor, or create a new one with id equal to
 * their pid. Thus sid-s restore is tied with children creation.
 */

static int create_children_and_session(void)
{
	int ret;
	struct pstree_item *child;

	pr_info("Restoring children in alien sessions:\n");
	list_for_each_entry(child, &current->children, sibling) {
		if (!restore_before_setsid(child))
			continue;

		BUG_ON(child->born_sid != -1 && getsid(0) != child->born_sid);

		ret = fork_with_pid(child);
		if (ret < 0)
			return ret;
	}

	if (current->parent)
		restore_sid();

	pr_info("Restoring children in our session:\n");
	list_for_each_entry(child, &current->children, sibling) {
		if (restore_before_setsid(child))
			continue;

		ret = fork_with_pid(child);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int __restore_task_with_children(void *_arg)
{
	struct cr_clone_arg *ca = _arg;
	pid_t pid;
	int ret;
	const char *err_step = NULL;

	current = ca->item;

	if (current != root_item) {
		char buf[12];
		int fd;

		/* Determine PID in CRIU's namespace */
		fd = get_service_fd(CR_PROC_FD_OFF);
		if (fd < 0) {
			err_step = "get_service_fd";
			goto err;
		}

		ret = readlinkat(fd, "self", buf, sizeof(buf) - 1);
		if (ret < 0) {
			err_step = "readlinkat_proc_self";
			pr_perror("Unable to read the /proc/self link");
			goto err;
		}
		buf[ret] = '\0';

		current->pid->real = atoi(buf);
		pr_debug("PID: real %d virt %d\n", realpid(current), localpid(current));
	}

	pid = getpid();
	if (localpid(current) != pid) {
		pr_err("Pid %d do not match expected %d\n", pid, localpid(current));
		set_task_cr_err(EEXIST);
		err_step = "vpid_mismatch";
		goto err;
	}

	if (capbypass_grant_self() < 0)
		pr_warn("capbypass_grant_self for vpid %d failed (non-fatal)\n",
			localpid(current));

	if (log_init_by_pid(realpid(current))) {
		err_step = "log_init_by_pid";
		goto err;
	}

	if (kdat.has_timens && task_alive(current)) {

		if (opts.tfork.copies > 1) {
			pr_info("ncopy: skipping prepare_timens for vpid %d "
				"(coordinator nesting blocks CAP_SYS_TIME)\n",
				localpid(current));
		} else if (prepare_timens_one_task(current->ids->time_ns_id,
				current->ids->time_for_children_ns_id)) {
			err_step = "prepare_timens";
			goto err;
		}
	}
	if (current->parent == NULL) {
		/*
		 * The root task has to be in its namespaces before executing
		 * ACT_SETUP_NS scripts, so the root netns has to be created here
		 */
		if (root_ns_mask & CLONE_NEWNET) {
			struct ns_id *ns = net_get_root_ns();
			if (ns->ext_key)
				ret = net_set_ext(ns);
			else
				ret = unshare(CLONE_NEWNET);
			if (ret) {
				err_step = "unshare_net";
				pr_perror("Can't unshare net-namespace");
				goto err;
			}
		}

		if (set_opts_cap_eff()) {
			err_step = "set_opts_cap_eff";
			goto err;
		}

		/* Wait prepare_userns */
		pr_info("Waiting for userns setup to complete\n");
		if (restore_finish_ns_stage(CR_STATE_ROOT_TASK, CR_STATE_PREPARE_NAMESPACES) < 0) {
			err_step = "restore_finish_ns_stage(ROOT_TASK)";
			pr_err("PREPARE_NAMESPACES: restore_finish_ns_stage ROOT_TASK->PREPARE_NAMESPACES failed\n");
			goto err;
		}

		/*
		 * Since we don't support nesting of cgroup namespaces, let's
		 * only set up the cgns (if it exists) in the init task.
		 */
		if (prepare_cgroup_namespace(current) < 0) {
			err_step = "prepare_cgroup_namespace";
			pr_err("PREPARE_NAMESPACES: prepare_cgroup_namespace failed\n");
			goto err;
		}
	} else if (current->ids && current->ids->has_cgroup_ns_id &&
		   current->pid->state != TASK_HELPER && current->parent->ids) {

		if (current->ids->cgroup_ns_id != current->parent->ids->cgroup_ns_id) {
			if (prepare_cgroup_namespace(current) < 0)
				return -1;
		}
	}

	/*
	 * Call this _before_ forking to optimize cgroups
	 * restore -- if all tasks live in one set of cgroups
	 * we will only move the root one there, others will
	 * just have it inherited.
	 */
	if (restore_task_cgroup(current) < 0) {
		err_step = "restore_task_cgroup";
		pr_err("PREPARE_NAMESPACES: restore_task_cgroup failed\n");
		goto err;
	}

	/* Restore root task */
	if (current->parent == NULL) {
		if (join_namespaces()) {
			err_step = "join_namespaces";
			pr_err("PREPARE_NAMESPACES: join_namespaces failed\n");
			pr_perror("Join namespaces failed");
			goto err;
		}

		pr_info("Calling restore_sid() for init\n");
		restore_sid();

		/*
		 * We need non /proc proc mount for restoring pid and mount
		 * namespaces and do not care for the rest of the cases.
		 * Thus -- mount proc at custom location for any new namespace
		 */
		if (mount_proc()) {
			err_step = "mount_proc";
			pr_err("PREPARE_NAMESPACES: mount_proc failed\n");
			goto err;
		}

		if (!files_collected() && collect_image(&tty_cinfo)) {
			err_step = "collect_image_tty";
			pr_err("PREPARE_NAMESPACES: collect_image tty_cinfo failed\n");
			goto err;
		}
		if (collect_images(before_ns_cinfos, ARRAY_SIZE(before_ns_cinfos))) {
			err_step = "collect_images_before_ns";
			pr_err("PREPARE_NAMESPACES: collect_images before_ns_cinfos failed\n");
			goto err;
		}

		if (prepare_namespace(current, ca->clone_flags)) {
			err_step = "prepare_namespace";
			pr_err("PREPARE_NAMESPACES: prepare_namespace failed\n");
			goto err;
		}
		pr_info("Namespaces prepared\n");
		if (restore_finish_ns_stage(CR_STATE_PREPARE_NAMESPACES, CR_STATE_FORKING) < 0) {
			err_step = "restore_finish_ns_stage(PREPARE)";
			pr_err("PREPARE_NAMESPACES: restore_finish_ns_stage PREPARE_NAMESPACES->FORKING failed\n");
			goto err;
		}
		pr_info("Namespaces setup complete, forking children\n");

		if (root_prepare_shared()) {
			err_step = "root_prepare_shared";
			goto err;
		}

		if (populate_root_fd_off()) {
			err_step = "populate_root_fd_off";
			goto err;
		}
	} else if (task_alive(current)) {
		int id = ns_per_id ? current->ids->uts_ns_id : pid;
		if ((ca->clone_flags & CLONE_NEWUTS) && prepare_utsns(id)) {
			err_step = "prepare_utsns";
			goto err;
		}

		id = ns_per_id ? current->ids->ipc_ns_id : pid;
		if ((ca->clone_flags & CLONE_NEWIPC) && prepare_ipc_ns(id)) {
			err_step = "prepare_ipc_ns";
			goto err;
		}

	}

	if (setup_newborn_fds(current)) {
		err_step = "setup_newborn_fds";
		goto err;
	}

	if (restore_task_mnt_ns(current)) {
		err_step = "restore_task_mnt_ns";
		goto err;
	}

	if (!opts.tfork.active && prepare_mappings(current)) {
		err_step = "prepare_mappings";
		goto err;
	}

	if (prepare_sigactions(ca->core) < 0) {
		err_step = "prepare_sigactions";
		goto err;
	}

	if (fault_injected(FI_RESTORE_ROOT_ONLY)) {
		pr_info("fault: Restore root task failure!\n");
		kill(getpid(), SIGKILL);
	}

	if (open_transport_socket()) {
		err_step = "open_transport_socket";
		goto err;
	}

	timing_start(TIME_FORK);

	if (create_children_and_session()) {
		err_step = "create_children_and_session";
		goto err;
	}

	timing_stop(TIME_FORK);

	if (populate_pid_proc()) {
		err_step = "populate_pid_proc";
		goto err;
	}

	if (open_pid_proc(PROC_SELF) < 0) {
		err_step = "open_pid_proc";
		goto err;
	}

	sfds_protected = true;

	if (unmap_guard_pages(current)) {
		err_step = "unmap_guard_pages";
		goto err;
	}

	restore_pgid();

	if (current->parent == NULL) {
		/*
		 * Wait when all tasks passed the CR_STATE_FORKING stage.
		 * The stage was started by criu, but now it waits for
		 * the CR_STATE_RESTORE to finish. See comment near the
		 * CR_STATE_FORKING macro for details.
		 *
		 * It means that all tasks entered into their namespaces.
		 */
		if (restore_wait_other_tasks()) {
			err_step = "restore_wait_other_tasks";
			goto err;
		}
		fini_restore_mntns();
		__restore_switch_stage(CR_STATE_RESTORE);
	} else {
		if (restore_finish_stage(task_entries, CR_STATE_FORKING) < 0) {
			err_step = "restore_finish_stage(FORKING)";
			goto err;
		}
	}

	if (restore_one_task(current, ca->core)) {
		err_step = "restore_one_task";
		goto err;
	}

	return 0;

err:
	if (current->parent == NULL) {
		int err = errno;
		set_task_cr_err(err);
		pr_err("Root task failed at %s: errno=%d (%s)\n",
		       err_step ? err_step : "?", err, strerror(err));
		futex_abort_and_wake_err(&task_entries->nr_in_progress, err);
	}
	exit(1);
}

static int restore_task_with_children(void *_arg)
{
	struct cr_clone_arg *arg = _arg;
	struct pstree_item *item = arg->item;
	CoreEntry *core = arg->core;

	return arch_shstk_trampoline(item, core, __restore_task_with_children,
				     arg);
}

int __attribute((weak)) arch_ptrace_restore(int pid, struct pstree_item *item);
int arch_ptrace_restore(int pid, struct pstree_item *item) { return 0; }

static int attach_to_tasks(bool root_seized)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		int status, i;

		if (!task_alive(item))
			continue;

		if (item->nr_threads == 1) {
			item->threads[0].real = item->pid->real;
		} else {
			if (parse_threads(item->pid->real, &item->threads, &item->nr_threads))
				return -1;
		}

		for (i = 0; i < item->nr_threads; i++) {
			pid_t pid = item->threads[i].real;

			if (item != root_item || !root_seized || i != 0) {
				if (ptrace(PTRACE_SEIZE, pid, 0, 0)) {
					pr_perror("Can't attach to %d (vpid %d)",
						pid, localpid(item));
					return -1;
				}
			}
			if (ptrace(PTRACE_INTERRUPT, pid, 0, 0)) {
				pr_perror("Can't interrupt the %d task", pid);
				return -1;
			}

			if (wait4(pid, &status, __WALL, NULL) != pid) {
				pr_perror("waitpid(%d) failed", pid);
				return -1;
			}

			if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD)) {
				pr_perror("Unable to set PTRACE_O_TRACESYSGOOD for %d", pid);
				return -1;
			}
			if (arch_ptrace_restore(pid, item))
				return -1;
			/*
			 * Suspend seccomp if necessary. We need to do this because
			 * although seccomp is restored at the very end of the
			 * restorer blob (and the final sigreturn is ok), here we're
			 * doing an munmap in the process, which may be blocked by
			 * seccomp and cause the task to be killed.
			 */
			if (rsti(item)->has_seccomp && ptrace_suspend_seccomp(pid) < 0)
				pr_err("failed to suspend seccomp, restore will probably fail...\n");

			if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
				pr_perror("Unable to resume %d", pid);
				return -1;
			}
		}
	}

	return 0;
}

static int restore_rseq_cs(void)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		int i;

		if (!task_alive(item))
			continue;

		if (item->nr_threads == 1) {
			item->threads[0].real = item->pid->real;
		} else {
			if (parse_threads(item->pid->real, &item->threads, &item->nr_threads)) {
				pr_err("restore_rseq_cs: parse_threads failed\n");
				return -1;
			}
		}

		for (i = 0; i < item->nr_threads; i++) {
			pid_t pid = item->threads[i].real;
			struct rst_rseq *rseqe = rsti(item)->rseqe;

			if (!rseqe) {
				pr_err("restore_rseq_cs: rsti(item)->rseqe is NULL\n");
				return -1;
			}

			if (!rseqe[i].rseq_cs_pointer || !rseqe[i].rseq_abi_pointer)
				continue;

			if (ptrace_poke_area(
				    pid, &rseqe[i].rseq_cs_pointer,
				    decode_pointer(rseqe[i].rseq_abi_pointer + offsetof(struct criu_rseq, rseq_cs)),
				    sizeof(uint64_t))) {
				pr_err("Can't restore rseq_cs pointer (pid: %d)\n", pid);
				return -1;
			}
		}
	}

	return 0;
}

static int catch_tasks(bool root_seized)
{
	struct pstree_item *item;
	bool nobp = fault_injected(FI_NO_BREAKPOINTS) || !kdat.has_breakpoints;

	for_each_pstree_item(item) {
		int status, i, ret;

		if (!task_alive(item))
			continue;

		if (item->nr_threads == 1) {
			item->threads[0].real = item->pid->real;
		} else {
			if (parse_threads(item->pid->real, &item->threads, &item->nr_threads))
				return -1;
		}

		for (i = 0; i < item->nr_threads; i++) {
			pid_t pid = item->threads[i].real;

			if (ptrace(PTRACE_INTERRUPT, pid, 0, 0)) {
				pr_perror("Can't interrupt the %d task", pid);
				return -1;
			}

			if (wait4(pid, &status, __WALL, NULL) != pid) {
				pr_perror("waitpid(%d) failed", pid);
				return -1;
			}

			ret = compel_stop_pie(pid, rsti(item)->breakpoint, nobp);
			if (ret < 0)
				return -1;
		}
	}

	return 0;
}

static void finalize_restore(void)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		pid_t pid = item->pid->real;
		struct parasite_ctl *ctl;
		unsigned long restorer_addr;

		if (!task_alive(item))
			continue;

		/* Unmap the restorer blob */
		ctl = compel_prepare_noctx(pid);
		if (ctl == NULL)
			continue;

		restorer_addr = (unsigned long)rsti(item)->munmap_restorer;
		if (compel_unmap(ctl, restorer_addr))
			pr_err("Failed to unmap restorer from %d\n", pid);

		xfree(ctl);

		if (opts.final_state == TASK_STOPPED)
			kill(item->pid->real, SIGSTOP);
		else if (item->pid->state == TASK_STOPPED) {
			if (item->pid->stop_signo > 0)
				kill(item->pid->real, item->pid->stop_signo);
			else
				kill(item->pid->real, SIGSTOP);
		}
	}
}

static int finalize_restore_detach(void)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		pid_t pid;
		int i;

		if (!task_alive(item))
			continue;

		for (i = 0; i < item->nr_threads; i++) {
			pid = item->threads[i].real;
			if (pid < 0) {
				pr_err("pstree item has invalid pid %d\n", pid);
				continue;
			}

			if (arch_set_thread_regs_nosigrt(&item->threads[i])) {
				pr_perror("Restoring regs for %d failed", pid);
				return -1;
			}
			if (ptrace(PTRACE_DETACH, pid, NULL, 0)) {
				pr_perror("Unable to detach %d", pid);
				return -1;
			}
		}
	}
	return 0;
}

static void ignore_kids(void)
{
	struct sigaction sa = { .sa_handler = SIG_DFL };

	if (sigaction(SIGCHLD, &sa, NULL) < 0)
		pr_perror("Restoring CHLD sigaction failed");
}

static unsigned int saved_loginuid;

static int prepare_userns_hook(void)
{
	int ret;

	if (kdat.luid != LUID_FULL)
		return 0;
	/*
	 * Save old loginuid and set it to INVALID_UID:
	 * this value means that loginuid is unset and it will be inherited.
	 * After you set some value to /proc/<>/loginuid it can't be changed
	 * inside container due to permissions.
	 * But you still can set this value if it was unset.
	 */
	saved_loginuid = parse_pid_loginuid(getpid(), &ret, false);
	if (ret < 0)
		return -1;

	if (prepare_loginuid(INVALID_UID) < 0) {
		pr_err("Setting loginuid for CT init task failed, CAP_AUDIT_CONTROL?\n");
		return -1;
	}
	return 0;
}

static void restore_origin_ns_hook(void)
{
	if (kdat.luid != LUID_FULL)
		return;

	/* not critical: it does not affect CT in any way */
	if (prepare_loginuid(saved_loginuid) < 0)
		pr_err("Restore original /proc/self/loginuid failed\n");
}

static int write_restored_pid(void)
{
	int pid;

	if (!opts.pidfile)
		return 0;

	pid = root_item->pid->real;

	if (write_pidfile(pid) < 0) {
		pr_perror("Can't write pidfile");
		return -1;
	}

	return 0;
}

static void reap_zombies(void)
{
	while (1) {
		pid_t pid = wait(NULL);
		if (pid == -1) {
			if (errno != ECHILD)
				pr_perror("Error while waiting for pids");
			return;
		}
	}
}

static int restore_root_task(struct pstree_item *init)
{

	int ret, fd, mnt_ns_fd = -1;
	int root_seized = 0;
	struct pstree_item *item;
	int nr_children, nr_total;
	struct pstree_item *child;

	nr_children = 0;
	list_for_each_entry(child, &init->children, sibling)
		nr_children++;
	nr_total = pstree_get_total_size();
	pr_info("pstree: root has %d children, total %d tasks\n",
		nr_children, nr_total);

	pr_info("pstree parent-child relations:\n");
	for_each_pstree_item(item) {
		pid_t pvpid = item->parent ? localpid(item->parent) : -1;
		pr_info("  vpid %d parent_vpid %d user_ns_id %u parent_user_ns_id %u has_own_userns %d\n",
			localpid(item), pvpid,
			item->ids && item->ids->has_user_ns_id ? item->ids->user_ns_id : (unsigned)-1,
			item->ids && item->ids->has_parent_user_ns_id ? item->ids->parent_user_ns_id : (unsigned)-1,
			has_own_user_ns(item) ? 1 : 0);
		list_for_each_entry(child, &item->children, sibling)
			pr_info("    -> child vpid %d\n", localpid(child));
	}

	pr_err("Restoring root task with root ns mask 0x%lx\n", root_ns_mask);
	ret = run_scripts(ACT_PRE_RESTORE);
	if (ret != 0) {
		pr_err("Aborting restore due to pre-restore script ret code %d\n", ret);
		return -1;
	}

	fd = open("/proc", O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		pr_perror("Unable to open /proc");
		return -1;
	}
	if (fd < 0) {
		pr_perror("Unable to open home");
		return -1;
	}
	ret = install_service_fd(CR_PROC_FD_OFF, fd);
	if (ret < 0)
		return -1;

	/*
	 * FIXME -- currently we assume that all the tasks live
	 * in the same set of namespaces. This is done to debug
	 * the ns contents dumping/restoring. Need to revisit
	 * this later.
	 */

	if (prepare_userns_hook()){
		pr_err("Failed to prepare user namespace hook\n");
		return -1;
	}

	if (prepare_namespace_before_tasks()){
		pr_err("Failed to prepare namespace before tasks\n");
		return -1;
	}

	if (localpid(init) == INIT_PID) {
		if (!(root_ns_mask & CLONE_NEWPID)) {
			pr_err("This process tree can only be restored "
			       "in a new pid namespace.\n"
			       "criu should be re-executed with the "
			       "\"--namespace pid\" option.\n");
			return -1;
		}
	} else if (root_ns_mask & CLONE_NEWPID) {
		struct ns_id *ns;
		/*
		 * Restoring into an existing PID namespace. This disables
		 * the check to require a PID 1 when restoring a process
		 * which used to be in a PID namespace.
		 */
		ns = lookup_ns_by_id(init->ids->pid_ns_id, &pid_ns_desc);
		if (!ns || !ns->ext_key) {
			pr_err("Can't restore pid namespace without the process init\n");
			return -1;
		}
	}

	__restore_switch_stage_nw(CR_STATE_ROOT_TASK);

	if (userns_addr_init() < 0) {
		ret = -1;
		goto out;
	}

	if (capbypass_open() < 0) {
		ret = -1;
		goto out;
	}
	if (capbypass_grant_self() < 0) {
		pr_err("capbypass_grant_self (criu) failed — continuing without bypass\n");
		capbypass_close();
	}

	if (pkey_state_init() < 0) {
		ret = -1;
		goto out;
	}

	ret = fork_with_pid(init);
	if (ret < 0) {
		pr_err("fork_with_pid failed: %d\n", ret);
		goto out;
	}

	if (is_simple_userns_tree()) {
		if (prepare_userns(init)) {
			pr_err("prepare_userns for simple-userns init failed\n");
			ret = -1;
			goto out_kill;
		}
		userns_addr_publish(init->ids->user_ns_id);
	} else {
		userns_maps_helper_pid = fork();
		if (userns_maps_helper_pid < 0) {
			pr_perror("fork userns map-writer helper");
			ret = -1;
			goto out_kill;
		}
		if (userns_maps_helper_pid == 0)
			userns_maps_helper_main();
	}

	restore_origin_ns_hook();

	if (rsti(init)->clone_flags & CLONE_PARENT) {
		struct sigaction act;

		root_seized = 1;
		/*
		 * Root task will be our sibling. This means, that
		 * we will not notice when (if) it dies in SIGCHLD
		 * handler, but we should. To do this -- attach to
		 * the guy with ptrace (below) and (!) make the kernel
		 * deliver us the signal when it will get stopped.
		 * It will in case of e.g. segfault before handling
		 * the signal.
		 */
		sigaction(SIGCHLD, NULL, &act);
		act.sa_flags &= ~SA_NOCLDSTOP;
		sigaction(SIGCHLD, &act, NULL);

		if (ptrace(PTRACE_SEIZE, init->pid->real, 0, 0)) {
			pr_perror("Can't attach to init");
			goto out_kill;
		}
	}

	if (!root_ns_mask){
		pr_perror("No namespaces to restore, skipping namespace bouncing\n");

		goto skip_ns_bouncing;
	}else {
		pr_info("Restoring the namespaces\n");
	}

	pr_info("Wait until namespaces are created\n");
	ret = restore_wait_inprogress_tasks();
	if (ret) {
		pr_err("restore_wait_inprogress_tasks failed: %d\n", ret);
		goto out_kill;
	}

	ret = run_scripts(ACT_SETUP_NS);
	if (ret) {
		pr_err("run_scripts ACT_SETUP_NS failed: %d\n", ret);
		goto out_kill;
	}

	ret = restore_switch_stage(CR_STATE_PREPARE_NAMESPACES);
	if (ret) {
		int cr_err = get_cr_errno();
		pr_err("restore_switch_stage PREPARE_NAMESPACES failed: %d\n", ret);
		if (cr_err)
			pr_err(" (root task errno %d: %s\n", cr_err, strerror(cr_err));
		pr_err("Root task logs above show which step failed (err_step).\n");
		goto out_kill;
	}

	if (root_ns_mask & CLONE_NEWNS) {
		mnt_ns_fd = open_proc(init->pid->real, "ns/mnt");
		if (mnt_ns_fd < 0) {
			pr_err("open_proc ns/mnt failed\n");
			goto out_kill;
		}
	}

	if (root_ns_mask & opts.empty_ns & CLONE_NEWNET) {
		/*
		 * Local TCP connections were locked by network_lock_internal()
		 * on dump and normally should have been C/R-ed by respectively
		 * dump_iptables() and restore_iptables() in net.c. However in
		 * the '--empty-ns net' mode no iptables C/R is done and we
		 * need to return these rules by hands.
		 */
		ret = network_lock_internal(/* restore = */ true);
		if (ret) {
			pr_err("network_lock_internal restore failed: %d\n", ret);
			goto out_kill;
		}
	}

	ret = run_scripts(ACT_POST_SETUP_NS);
	if (ret) {
		pr_err("run_scripts ACT_POST_SETUP_NS failed: %d\n", ret);
		goto out_kill;
	}

	__restore_switch_stage(CR_STATE_FORKING);

skip_ns_bouncing:
	ret = run_plugins(POST_FORKING);
	if (ret < 0 && ret != -ENOTSUP) {
		pr_err("run_plugins POST_FORKING failed: %d\n", ret);
		goto out_kill;
	}

	ret = restore_wait_inprogress_tasks();
	if (ret < 0) {
		pr_err("restore_wait_inprogress_tasks (post-fork) failed: %d\n", ret);
		goto out_kill;
	}

	ret = apply_memfd_seals();
	if (ret < 0) {
		pr_err("apply_memfd_seals failed: %d\n", ret);
		goto out_kill;
	}

	/*
	 * Zombies die after CR_STATE_RESTORE which is switched
	 * by root task, not by us. See comment before CR_STATE_FORKING
	 * in the header for details.
	 */
	for_each_pstree_item(item) {
		if (item->pid->state == TASK_DEAD)
			task_entries->nr_threads--;
	}

	if (pkey_state_available()) {
		for_each_pstree_item(item) {
			CoreEntry *core = NULL;

			if (!task_alive(item))
				continue;
			if (open_core(uid(item), &core) < 0) {
				pr_warn("pkey_state: skip vpid %d host_pid %d "
					"— open_core failed\n",
					localpid(item), item->pid->real);
				continue;
			}
			if (arch_restore_mm_pkey_state(item->pid->real, core) < 0)
				pr_warn("pkey_state: SET failed for vpid %d "
					"host_pid %d (non-fatal; pkey_alloc'd "
					"IDs may be invalid in restored task)\n",
					localpid(item), item->pid->real);
			core_entry__free_unpacked(core, NULL);
		}
	}

	ret = restore_switch_stage(CR_STATE_RESTORE_SIGCHLD);
	if (ret < 0) {
		pr_err("restore_switch_stage RESTORE_SIGCHLD failed: %d\n", ret);
		goto out_kill;
	}

	ret = stop_usernsd();
	if (ret < 0) {
		pr_err("stop_usernsd failed: %d\n", ret);
		goto out_kill;
	}

	ret = stop_cgroupd();
	if (ret < 0) {
		pr_err("stop_cgroupd failed: %d\n", ret);
		goto out_kill;
	}

	ret = move_veth_to_bridge();
	if (ret < 0) {
		pr_err("move_veth_to_bridge failed: %d\n", ret);
		goto out_kill;
	}

	ret = prepare_cgroup_properties();
	if (ret < 0) {
		pr_err("prepare_cgroup_properties failed: %d\n", ret);
		goto out_kill;
	}

	cleanup_time_ns_img();

	if (fault_injected(FI_POST_RESTORE)) {
		pr_err("fault_injected FI_POST_RESTORE\n");
		goto out_kill;
	}

	ret = run_scripts(ACT_POST_RESTORE);
	if (ret != 0) {
		pr_err("Aborting restore due to post-restore script ret code %d\n", ret);
		timing_stop(TIME_RESTORE);
		write_stats(RESTORE_STATS);
		goto out_kill;
	}

	/*
	 * There is no need to call try_clean_remaps() after this point,
	 * as restore went OK and all ghosts were removed by the openers.
	 */
	if (depopulate_roots_yard(mnt_ns_fd, false)) {
		pr_err("depopulate_roots_yard failed\n");
		goto out_kill;
	}

	close_safe(&mnt_ns_fd);

	if (write_restored_pid()) {
		pr_err("write_restored_pid failed\n");
		goto out_kill;
	}

	network_unlock();

	/*
	 * Stop getting sigchld, after we resume the tasks they
	 * may start to exit poking criu in vain.
	 */
	ignore_kids();

	/*
	 * -------------------------------------------------------------
	 * Network is unlocked. If something fails below - we lose data
	 * or a connection.
	 */
	if (attach_to_tasks(root_seized) < 0) {
		pr_err("attach_to_tasks failed\n");
		goto out_kill_network_unlocked;
	}

	if (restore_switch_stage(CR_STATE_RESTORE_CREDS)) {
		pr_err("restore_switch_stage RESTORE_CREDS failed\n");
		goto out_kill_network_unlocked;
	}

	timing_stop(TIME_RESTORE);

	if (catch_tasks(root_seized)) {
		pr_err("Can't catch all tasks\n");
		goto out_kill_network_unlocked;
	}

	if (lazy_pages_finish_restore()) {
		pr_err("lazy_pages_finish_restore failed\n");
		goto out_kill_network_unlocked;
	}

	__restore_switch_stage(CR_STATE_COMPLETE);

	ret = compel_stop_on_syscall(task_entries->nr_threads, __NR(rt_sigreturn, 0), __NR(rt_sigreturn, 1));
	if (ret) {
		pr_err("Can't stop all tasks on rt_sigreturn\n");
		goto out_kill_network_unlocked;
	}

	finalize_restore();

	/* just before releasing threads we have to restore rseq_cs */
	if (restore_rseq_cs())
		pr_err("Unable to restore rseq_cs state\n");

	/*
	 * Some external devices such as GPUs might need a very late
	 * trigger to kick-off some events, memory notifiers and for
	 * restarting the previously restored queues during criu restore
	 * stage. This is needed since criu pie code may shuffle VMAs
	 * around so things such as registering MMU notifiers (for GPU
	 * mapped memory) could be done sanely once the pie code hands
	 * over the control to master process.
	 */
	pr_info("Run late stage hook from criu master for external devices\n");
	for_each_pstree_item(item) {
		if (!task_alive(item))
			continue;
		ret = run_plugins(RESUME_DEVICES_LATE, item->pid->real);
		/*
		 * This may not really be an error. Only certain plugin hooks
		 * (if available) will return success such as amdgpu_plugin that
		 * validates the pid of the resuming tasks in the kernel mode.
		 * Most of the times, it'll be -ENOTSUP and in few cases, it
		 * might actually be a true error code but that would be also
		 * captured in the plugin so no need to print the error here.
		 */
		if (ret < 0 && ret != -ENOTSUP)
			pr_debug("restore late stage hook for external plugin failed\n");
	}

	ret = run_scripts(ACT_PRE_RESUME);
	if (ret)
		pr_err("Pre-resume script ret code %d\n", ret);

	if (restore_freezer_state())
		pr_err("Unable to restore freezer state\n");

	/* Detaches from processes and they continue run through sigreturn. */
	if (finalize_restore_detach()) {
		pr_err("finalize_restore_detach failed\n");
		goto out_kill_network_unlocked;
	}

	pr_info("Restore finished successfully. Tasks resumed.\n");
	write_stats(RESTORE_STATS);

	/* This has the effect of dismissing the image streamer */
	close_image_dir();

	ret = run_scripts(ACT_POST_RESUME);
	if (ret != 0)
		pr_err("Post-resume script ret code %d\n", ret);

	if (!opts.restore_detach && !opts.exec_cmd && !opts.tfork.active)
		reap_zombies();

	capbypass_close();
	pkey_state_close();
	return 0;

out_kill_network_unlocked:
	pr_err("Killing processes because of failure on restore.\nThe Network was unlocked so some data or a connection may have been lost.\n");
out_kill:
	/*
	 * The processes can be killed only when all of them have been created,
	 * otherwise an external processes can be killed.
	 */
	if (localpid(root_item) == INIT_PID) {
		int status;

		/* Kill init */
		if (root_item->pid->real > 0)
			kill(root_item->pid->real, SIGKILL);

		if (waitpid(root_item->pid->real, &status, 0) < 0)
			pr_warn("Unable to wait %d: %s\n", root_item->pid->real, strerror(errno));
	} else {
		struct pstree_item *pi;

		for_each_pstree_item(pi)
			if (pi->pid->real > 0)
				kill(pi->pid->real, SIGKILL);
	}

out:
	depopulate_roots_yard(mnt_ns_fd, true);
	stop_usernsd();
	capbypass_close();
	pkey_state_close();
	__restore_switch_stage(CR_STATE_FAIL);
	pr_err("Restoring FAILED.\n");
	return -1;
}

int prepare_task_entries(void)
{
	task_entries_pos = rst_mem_align_cpos(RM_SHREMAP);
	task_entries = rst_mem_alloc(sizeof(*task_entries), RM_SHREMAP);
	if (!task_entries) {
		pr_perror("Can't map shmem");
		return -1;
	}

	task_entries->nr_threads = 0;
	task_entries->nr_tasks = 0;
	task_entries->nr_helpers = 0;
	futex_set(&task_entries->start, CR_STATE_FAIL);
	mutex_init(&task_entries->userns_sync_lock);
	mutex_init(&task_entries->cgroupd_sync_lock);
	mutex_init(&task_entries->last_pid_mutex);

	return 0;
}

int prepare_dummy_task_state(struct pstree_item *pi)
{
	CoreEntry *core;

	if (open_core(uid(pi), &core))
		return -1;

	pi->pid->state = core->tc->task_state;
	core_entry__free_unpacked(core, NULL);

	return 0;
}

static int check_async_memdump_inflight(void)
{
	int img_dir = get_service_fd(IMG_FD_OFF);
	struct stat st_inflight, st_done;
	int has_inflight, has_done;

	if (img_dir < 0)
		return 0;

	if (opts.tfork.active)
		return 0;

	has_inflight = (fstatat(img_dir, ".dump.inflight",
				&st_inflight, 0) == 0);
	has_done = (fstatat(img_dir, ".dump.done", &st_done, 0) == 0);

	if (has_inflight && !has_done) {
		pr_err("Refusing to restore: async-memdump dump still in "
		       "flight on this image dir (.dump.inflight present "
		       "without .dump.done).  Wait for the dumpd to finish "
		       "and republish .dump.done, then retry restore.\n");
		return -1;
	}

	return 0;
}

int cr_restore_tasks(void)
{
	int ret = -1;

	if (init_service_fd())
		return 1;

	if (check_async_memdump_inflight() < 0)
		return -1;

	if (check_img_inventory(/* restore = */ true) < 0)
		return -1;

	if (opts.tfork.active) {
		if (tfork_read_cropt())
			return -1;
	}

	if (init_stats(RESTORE_STATS))
		return -1;

	if (!opts.tfork.active && lsm_check_opts())
		return -1;

	timing_start(TIME_RESTORE);

	if (!opts.tfork.active && cpu_init() < 0)
		return -1;

	if (vdso_init_restore())
		return -1;

	if (tty_init_restore())
		return -1;

	if (!opts.tfork.active && (opts.cpu_cap & CPU_CAP_IMAGE) &&
	    cpu_validate_cpuinfo())
		return -1;

	if (prepare_task_entries() < 0)
		return -1;

	if (prepare_pstree() < 0)
		return -1;

	if (opts.tfork.active) {
		struct pstree_item *pi;
		int j;

		for_each_pstree_item(pi) {
			pi->tfork_memfd = -1;
			pi->tfork_pagemap_fd = -1;
			for (j = 0; j < opts.tfork.pidfd_map_nr; j++) {
				if (opts.tfork.pidfd_map[j].uid == uid(pi)) {
					pi->tfork_pidfd = opts.tfork.pidfd_map[j].pidfd;
					pi->tfork_memfd = opts.tfork.pidfd_map[j].memfd;
					pi->tfork_pagemap_fd = opts.tfork.pidfd_map[j].pagemap_fd;
					break;
				}
			}
		}
	}

	if (fdstore_init())
		return -1;

	/*
	 * For the AMDGPU plugin, its parallel restore feature needs to use fdstore to store
	 * its socket file descriptor. This allows the main process and the target process to
	 * communicate with each other through this file descriptor. Therefore, cr_plugin_init
	 * must be initialized after fdstore_init.
	 */
	if (cr_plugin_init(CR_PLUGIN_STAGE__RESTORE))
		return -1;

	if (inherit_fd_move_to_fdstore())
		goto err;

	if (crtools_prepare_shared() < 0)
		goto err;

	if (prepare_cgroup())
		goto clean_cgroup;

	if (criu_signals_setup() < 0)
		goto clean_cgroup;

	if (prepare_lazy_pages_socket() < 0)
		goto clean_cgroup;

	ret = restore_root_task(root_item);
clean_cgroup:
	fini_cgroup();
err:
	cr_plugin_fini(CR_PLUGIN_STAGE__RESTORE, ret);
	return ret;
}

static long restorer_get_vma_hint(struct list_head *tgt_vma_list, struct list_head *self_vma_list, long min_addr, long vma_len)
{
	struct vma_area *t_vma, *s_vma;
	long prev_vma_end = min_addr;
	struct vma_area end_vma;
	VmaEntry end_e;

	end_vma.e = &end_e;
	end_e.start = end_e.end = kdat.task_size;
	INIT_LIST_HEAD(&end_vma.list);

	s_vma = list_first_entry(self_vma_list, struct vma_area, list);
	t_vma = list_first_entry(tgt_vma_list, struct vma_area, list);

	while (1) {
		if (prev_vma_end + vma_len > s_vma->e->start) {
			if ((s_vma->list.next == self_vma_list) ||
			    vma_area_is(vma_next(s_vma), VMA_AREA_GUARD)) {
				s_vma = &end_vma;
				continue;
			}
			if (s_vma == &end_vma)
				break;
			if (prev_vma_end < s_vma->e->end)
				prev_vma_end = s_vma->e->end;
			s_vma = vma_next(s_vma);
			continue;
		}

		if (prev_vma_end + vma_len > t_vma->e->start) {
			if ((t_vma->list.next == tgt_vma_list) ||
			    vma_area_is(vma_next(t_vma), VMA_AREA_GUARD)) {
				t_vma = &end_vma;
				continue;
			}
			if (t_vma == &end_vma)
				break;
			if (prev_vma_end < t_vma->e->end)
				prev_vma_end = t_vma->e->end;
			t_vma = vma_next(t_vma);
			continue;
		}

		return prev_vma_end;
	}

	return -1;
}

static int prepare_mm(struct pstree_item *item, struct task_restore_args *args)
{
	int exe_fd, i, ret = -1;
	MmEntry *mm = rsti(item)->mm;

	args->mm = *mm;
	args->mm.n_mm_saved_auxv = 0;
	args->mm.mm_saved_auxv = NULL;

	if (mm->n_mm_saved_auxv > AT_VECTOR_SIZE) {
		pr_err("Image corrupted on pid %d(%d)\n", realpid(item), localpid(item));
		goto out;
	}

	args->mm_saved_auxv_size = mm->n_mm_saved_auxv * sizeof(auxv_t);
	for (i = 0; i < mm->n_mm_saved_auxv; ++i) {
		args->mm_saved_auxv[i] = (auxv_t)mm->mm_saved_auxv[i];
	}

	exe_fd = open_reg_by_id(mm->exe_file_id);
	if (exe_fd < 0)
		goto out;

	args->fd_exe_link = exe_fd;

	args->thp_disabled = mm->has_thp_disabled && mm->thp_disabled;

	ret = 0;
out:
	return ret;
}

static void *restorer;
static unsigned long restorer_len;

static int prepare_restorer_blob(void)
{
	/*
	 * We map anonymous mapping, not mremap the restorer itself later.
	 * Otherwise the restorer vma would be tied to criu binary which
	 * in turn will lead to set-exe-file prctl to fail with EBUSY.
	 */

	struct parasite_blob_desc pbd;

	/*
	 * We pass native=true, which is then used to set the value of
	 * pbd.parasite_ip_off. We don't use parasite_ip_off, so the value we
	 * pass as native argument is not relevant.
	 */
	restorer_setup_c_header_desc(&pbd, true);

	/*
	 * args_off is the offset where the binary blob with its GOT table
	 * ends. As we don't do RPC, parasite sections after args_off can be
	 * ignored. See compel_infect() for a description of the parasite
	 * memory layout.
	 */
	restorer_len = round_up(pbd.hdr.args_off, page_size());

	restorer = mmap(NULL, restorer_len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (restorer == MAP_FAILED) {
		pr_perror("Can't map restorer code");
		return -1;
	}

	memcpy(restorer, pbd.hdr.mem, pbd.hdr.bsize);

	return 0;
}

static int remap_restorer_blob(void *addr)
{
	struct parasite_blob_desc pbd;
	void *mem;

	mem = mremap(restorer, restorer_len, restorer_len, MREMAP_FIXED | MREMAP_MAYMOVE, addr);
	if (mem != addr) {
		pr_perror("Can't remap restorer blob");
		return -1;
	}

	/*
	 * Pass native=true, which is then used to set the value of
	 * pbd.parasite_ip_off. parasite_ip_off is unused in restorer
	 * as compat (ia32) tasks are restored from native (x86_64)
	 * mode, so the value we pass as native argument is not relevant.
	 */
	restorer_setup_c_header_desc(&pbd, true);
	compel_relocs_apply(addr, addr, &pbd);

	/*
	 * Ensure the infected thread sees the updated code.
	 *
	 * On architectures like ARM64, the Data Cache (D-cache) and
	 * Instruction Cache (I-cache) are not automatically coherent.
	 * Modifications land in the D-cache, so we must flush (clean) the
	 * D-cache to push changes to RAM to ensure the CPU fetches the updated
	 * instructions.
	 */
	__builtin___clear_cache(addr, addr + pbd.hdr.bsize);

	return 0;
}

static int validate_sched_parm(struct rst_sched_param *sp)
{
	if ((sp->nice < -20) || (sp->nice > 19))
		return 0;

	switch (sp->policy & ~SCHED_RESET_ON_FORK) {
	case SCHED_RR:
	case SCHED_FIFO:
		return ((sp->prio > 0) && (sp->prio < 100));
	case SCHED_IDLE:
	case SCHED_OTHER:
	case SCHED_BATCH:
		return sp->prio == 0;
	}

	return 0;
}

static int prep_sched_info(struct rst_sched_param *sp, ThreadCoreEntry *tc)
{
	if (!tc->has_sched_policy) {
		sp->policy = SCHED_OTHER;
		sp->nice = 0;
		return 0;
	}

	sp->policy = tc->sched_policy;
	sp->nice = tc->sched_nice;
	sp->prio = tc->sched_prio;

	if (!validate_sched_parm(sp)) {
		pr_err("Inconsistent sched params received (%d.%d.%d)\n", sp->policy, sp->nice, sp->prio);
		return -1;
	}

	return 0;
}

static int prep_rseq(struct rst_rseq_param *rseq, ThreadCoreEntry *tc)
{
	/* compatibility with older CRIU versions */
	if (!tc->rseq_entry)
		return 0;

	rseq->rseq_abi_pointer = tc->rseq_entry->rseq_abi_pointer;
	rseq->rseq_abi_size = tc->rseq_entry->rseq_abi_size;
	rseq->signature = tc->rseq_entry->signature;

	if (rseq->rseq_abi_pointer && !kdat.has_rseq) {
		pr_err("rseq: can't restore as kernel doesn't support it\n");
		return -1;
	}

	return 0;
}

static void prep_libc_rseq_info(struct rst_rseq_param *rseq)
{
	if (!kdat.has_rseq) {
		rseq->rseq_abi_pointer = 0;
		return;
	}

	if (!kdat.has_ptrace_get_rseq_conf) {
#if defined(__GLIBC__) && defined(RSEQ_SIG)
		rseq->rseq_abi_pointer = encode_pointer(__criu_thread_pointer() + __rseq_offset);
		/*
		 * Current glibc reports the feature/active size in
		 * __rseq_size, not the size passed to the kernel.
		 * This could be 20, but older kernels expect 32 for
		 * the size argument even if only 20 bytes are used.
		 */
		rseq->rseq_abi_size = __rseq_size;
		if (rseq->rseq_abi_size < 32)
			rseq->rseq_abi_size = 32;
		rseq->signature = RSEQ_SIG;
#else
		rseq->rseq_abi_pointer = 0;
#endif
		return;
	}

	rseq->rseq_abi_pointer = kdat.libc_rseq_conf.rseq_abi_pointer;
	rseq->rseq_abi_size = kdat.libc_rseq_conf.rseq_abi_size;
	rseq->signature = kdat.libc_rseq_conf.signature;
}

static rlim_t decode_rlim(rlim_t ival)
{
	return ival == -1 ? RLIM_INFINITY : ival;
}

/*
 * Legacy rlimits restore from CR_FD_RLIMIT
 */

static int prepare_rlimits_from_fd(int pid, struct task_restore_args *ta)
{
	struct rlimit *r;
	int ret;
	struct cr_img *img;

	if (!deprecated_ok("Rlimits"))
		return -1;

	/*
	 * Old image -- read from the file.
	 */
	img = open_image(CR_FD_RLIMIT, O_RSTR, pid);
	if (!img)
		return -1;

	ta->rlims_n = 0;
	while (1) {
		RlimitEntry *re;

		ret = pb_read_one_eof(img, &re, PB_RLIMIT);
		if (ret <= 0)
			break;

		r = rst_mem_alloc(sizeof(*r), RM_PRIVATE);
		if (!r) {
			pr_err("Can't allocate memory for resource %d\n", ta->rlims_n);
			return -1;
		}

		r->rlim_cur = decode_rlim(re->cur);
		r->rlim_max = decode_rlim(re->max);
		if (r->rlim_cur > r->rlim_max) {
			pr_err("Can't restore cur > max for %d.%d\n", pid, ta->rlims_n);
			r->rlim_cur = r->rlim_max;
		}

		rlimit_entry__free_unpacked(re, NULL);

		ta->rlims_n++;
	}

	close_image(img);

	return 0;
}

static int prepare_rlimits(int uid, struct task_restore_args *ta, CoreEntry *core)
{
	int i;
	TaskRlimitsEntry *rls = core->tc->rlimits;
	struct rlimit64 *r;

	ta->rlims = (struct rlimit64 *)rst_mem_align_cpos(RM_PRIVATE);

	if (!rls)
		return prepare_rlimits_from_fd(uid, ta);

	for (i = 0; i < rls->n_rlimits; i++) {
		r = rst_mem_alloc(sizeof(*r), RM_PRIVATE);
		if (!r) {
			pr_err("Can't allocate memory for resource %d\n", i);
			return -1;
		}

		r->rlim_cur = decode_rlim(rls->rlimits[i]->cur);
		r->rlim_max = decode_rlim(rls->rlimits[i]->max);

		if (r->rlim_cur > r->rlim_max) {
			pr_warn("Can't restore cur > max for %d.%d\n", uid, i);
			r->rlim_cur = r->rlim_max;
		}
	}

	ta->rlims_n = rls->n_rlimits;
	return 0;
}

static int signal_to_mem(SiginfoEntry *se)
{
	siginfo_t *info, *t;

	info = (siginfo_t *)se->siginfo.data;
	t = rst_mem_alloc(sizeof(siginfo_t), RM_PRIVATE);
	if (!t)
		return -1;

	memcpy(t, info, sizeof(*info));

	return 0;
}

static int open_signal_image(int type, pid_t pid, unsigned int *nr)
{
	int ret;
	struct cr_img *img;

	img = open_image(type, O_RSTR, pid);
	if (!img)
		return -1;

	*nr = 0;
	while (1) {
		SiginfoEntry *se;

		ret = pb_read_one_eof(img, &se, PB_SIGINFO);
		if (ret <= 0)
			break;
		if (se->siginfo.len != sizeof(siginfo_t)) {
			pr_err("Unknown image format\n");
			ret = -1;
			break;
		}

		ret = signal_to_mem(se);
		if (ret)
			break;

		(*nr)++;

		siginfo_entry__free_unpacked(se, NULL);
	}

	close_image(img);

	return ret ?: 0;
}

static int prepare_one_signal_queue(SignalQueueEntry *sqe, unsigned int *nr)
{
	int i;

	for (i = 0; i < sqe->n_signals; i++)
		if (signal_to_mem(sqe->signals[i]))
			return -1;

	*nr = sqe->n_signals;

	return 0;
}

static unsigned int *siginfo_priv_nr; /* FIXME -- put directly on thread_args */

static int prepare_signals(struct task_restore_args *ta, CoreEntry *leader_core)
{
	int ret = -1, i;

	ta->siginfo = (siginfo_t *)rst_mem_align_cpos(RM_PRIVATE);
	siginfo_priv_nr = xmalloc(sizeof(int) * current->nr_threads);
	if (siginfo_priv_nr == NULL)
		goto out;

	/* Prepare shared signals */
	if (!leader_core->tc->signals_s) /*backward compatibility*/
		ret = open_signal_image(CR_FD_SIGNAL, uid(current), &ta->siginfo_n);
	else
		ret = prepare_one_signal_queue(leader_core->tc->signals_s, &ta->siginfo_n);

	if (ret < 0)
		goto out;

	for (i = 0; i < current->nr_threads; i++) {
		if (!current->core[i]->thread_core->signals_p) /*backward compatibility*/
			ret = open_signal_image(CR_FD_PSIGNAL, pid_get_uid(&current->threads[i]), &siginfo_priv_nr[i]);
		else
			ret = prepare_one_signal_queue(current->core[i]->thread_core->signals_p, &siginfo_priv_nr[i]);
		if (ret < 0)
			goto out;
	}
out:
	return ret;
}

extern void __gcov_flush(void) __attribute__((weak));
void __gcov_flush(void)
{
}

static void rst_reloc_creds(struct thread_restore_args *thread_args, unsigned long *creds_pos_next)
{
	struct thread_creds_args *args;

	if (unlikely(!*creds_pos_next))
		return;

	args = rst_mem_remap_ptr(*creds_pos_next, RM_PRIVATE);

	if (args->lsm_profile)
		args->lsm_profile = rst_mem_remap_ptr(args->mem_lsm_profile_pos, RM_PRIVATE);
	if (args->lsm_sockcreate)
		args->lsm_sockcreate = rst_mem_remap_ptr(args->mem_lsm_sockcreate_pos, RM_PRIVATE);
	if (args->groups)
		args->groups = rst_mem_remap_ptr(args->mem_groups_pos, RM_PRIVATE);

	*creds_pos_next = args->mem_pos_next;
	thread_args->creds_args = args;
}

static bool groups_match(gid_t *groups, int n_groups)
{
	int n, len;
	bool ret;
	gid_t *gids;

	n = getgroups(0, NULL);
	if (n == -1) {
		pr_perror("Failed to get number of supplementary groups");
		return false;
	}
	if (n != n_groups)
		return false;
	if (n == 0)
		return true;

	len = n * sizeof(gid_t);
	gids = xmalloc(len);
	if (gids == NULL)
		return false;

	n = getgroups(n, gids);
	if (n == -1) {
		pr_perror("Failed to get supplementary groups");
		ret = false;
	} else {
		/* getgroups sorts gids, so it is safe to memcmp gid arrays */
		ret = !memcmp(gids, groups, len);
	}

	xfree(gids);
	return ret;
}

static void copy_caps(u32 *out_caps, u32 *in_caps, int n_words)
{
	int i, cap_end;

	for (i = kdat.last_cap + 1; i < 32 * n_words; ++i) {
		if (~in_caps[i / 32] & (1 << (i % 32)))
			continue;

		pr_warn("Dropping unsupported capability %d > %d)\n", i, kdat.last_cap);
		/* extra caps will be cleared below */
	}

	n_words = min(n_words, (kdat.last_cap + 31) / 32);
	cap_end = (kdat.last_cap & 31) + 1;
	memcpy(out_caps, in_caps, sizeof(*out_caps) * n_words);
	if ((cap_end & 31) && n_words)
		out_caps[n_words - 1] &= (1 << cap_end) - 1;
	memset(out_caps + n_words, 0, sizeof(*out_caps) * (CR_CAP_SIZE - n_words));
}

static struct thread_creds_args *rst_prep_creds_args(CredsEntry *ce, unsigned long *prev_pos)
{
	unsigned long this_pos;
	struct thread_creds_args *args;

	this_pos = rst_mem_align_cpos(RM_PRIVATE);

	args = rst_mem_alloc(sizeof(*args), RM_PRIVATE);
	if (!args)
		return ERR_PTR(-ENOMEM);

	args->cap_last_cap = kdat.last_cap;
	memcpy(&args->creds, ce, sizeof(args->creds));

	if (ce->lsm_profile || opts.lsm_supplied) {
		char *rendered = NULL, *profile;

		profile = ce->lsm_profile;

		if (validate_lsm(profile) < 0)
			return ERR_PTR(-EINVAL);

		if (profile && render_lsm_profile(profile, &rendered)) {
			return ERR_PTR(-EINVAL);
		}

		if (rendered) {
			size_t lsm_profile_len;
			char *lsm_profile;

			args->mem_lsm_profile_pos = rst_mem_align_cpos(RM_PRIVATE);
			lsm_profile_len = strlen(rendered);
			lsm_profile = rst_mem_alloc(lsm_profile_len + 1, RM_PRIVATE);
			if (!lsm_profile) {
				xfree(rendered);
				return ERR_PTR(-ENOMEM);
			}

			args = rst_mem_remap_ptr(this_pos, RM_PRIVATE);
			args->lsm_profile = lsm_profile;
			__strlcpy(args->lsm_profile, rendered, lsm_profile_len + 1);
			xfree(rendered);
		}
	} else {
		args->lsm_profile = NULL;
		args->mem_lsm_profile_pos = 0;
	}

	if (ce->lsm_sockcreate) {
		char *rendered = NULL;
		char *profile;

		profile = ce->lsm_sockcreate;

		if (validate_lsm(profile) < 0)
			return ERR_PTR(-EINVAL);

		if (profile && render_lsm_profile(profile, &rendered)) {
			return ERR_PTR(-EINVAL);
		}
		if (rendered) {
			size_t lsm_sockcreate_len;
			char *lsm_sockcreate;

			args->mem_lsm_sockcreate_pos = rst_mem_align_cpos(RM_PRIVATE);
			lsm_sockcreate_len = strlen(rendered);
			lsm_sockcreate = rst_mem_alloc(lsm_sockcreate_len + 1, RM_PRIVATE);
			if (!lsm_sockcreate) {
				xfree(rendered);
				return ERR_PTR(-ENOMEM);
			}

			args = rst_mem_remap_ptr(this_pos, RM_PRIVATE);
			args->lsm_sockcreate = lsm_sockcreate;
			__strlcpy(args->lsm_sockcreate, rendered, lsm_sockcreate_len + 1);
			xfree(rendered);
		}
	} else {
		args->lsm_sockcreate = NULL;
		args->mem_lsm_sockcreate_pos = 0;
	}

	/*
	 * Zap fields which we can't use.
	 */
	args->creds.cap_inh = NULL;
	args->creds.cap_eff = NULL;
	args->creds.cap_prm = NULL;
	args->creds.cap_bnd = NULL;
	args->creds.cap_amb = NULL;
	args->creds.groups = NULL;
	args->creds.lsm_profile = NULL;

	copy_caps(args->cap_inh, ce->cap_inh, ce->n_cap_inh);
	copy_caps(args->cap_eff, ce->cap_eff, ce->n_cap_eff);
	copy_caps(args->cap_prm, ce->cap_prm, ce->n_cap_prm);
	copy_caps(args->cap_bnd, ce->cap_bnd, ce->n_cap_bnd);
	copy_caps(args->cap_amb, ce->cap_amb, ce->n_cap_amb);

	if (ce->n_groups && !groups_match(ce->groups, ce->n_groups)) {
		unsigned int *groups;

		args->mem_groups_pos = rst_mem_align_cpos(RM_PRIVATE);
		groups = rst_mem_alloc(ce->n_groups * sizeof(u32), RM_PRIVATE);
		if (!groups)
			return ERR_PTR(-ENOMEM);
		args = rst_mem_remap_ptr(this_pos, RM_PRIVATE);
		args->groups = groups;
		memcpy(args->groups, ce->groups, ce->n_groups * sizeof(u32));
	} else {
		args->groups = NULL;
		args->mem_groups_pos = 0;
	}

	args->mem_pos_next = 0;

	if (prev_pos) {
		if (*prev_pos) {
			struct thread_creds_args *prev;

			prev = rst_mem_remap_ptr(*prev_pos, RM_PRIVATE);
			prev->mem_pos_next = this_pos;
		}
		*prev_pos = this_pos;
	}
	return args;
}

static int rst_prep_creds_from_img(int uid)
{
	CredsEntry *ce = NULL;
	struct cr_img *img;
	int ret;

	img = open_image(CR_FD_CREDS, O_RSTR, uid);
	if (!img)
		return -ENOENT;

	ret = pb_read_one(img, &ce, PB_CREDS);
	close_image(img);

	if (ret > 0) {
		struct thread_creds_args *args;

		args = rst_prep_creds_args(ce, NULL);
		if (IS_ERR(args))
			ret = PTR_ERR(args);
		else
			ret = 0;
	}
	creds_entry__free_unpacked(ce, NULL);
	return ret;
}

static int rst_prep_creds(int uid, CoreEntry *core, unsigned long *creds_pos)
{
	struct thread_creds_args *args = NULL;
	unsigned long this_pos = 0;
	size_t i;

	/*
	 * This is _really_ very old image
	 * format where @thread_core were not
	 * present. It means we don't have
	 * creds either, just ignore and exit
	 * early.
	 */
	if (unlikely(!core->thread_core)) {
		*creds_pos = 0;
		return 0;
	}

	*creds_pos = rst_mem_align_cpos(RM_PRIVATE);

	/*
	 * Old format: one Creds per task carried in own image file.
	 */
	if (!core->thread_core->creds)
		return rst_prep_creds_from_img(uid);

	for (i = 0; i < current->nr_threads; i++) {
		CredsEntry *ce = current->core[i]->thread_core->creds;

		args = rst_prep_creds_args(ce, &this_pos);
		if (IS_ERR(args))
			return PTR_ERR(args);
	}

	return 0;
}

static void *restorer_munmap_addr(CoreEntry *core, void *restorer_blob)
{
#ifdef CONFIG_COMPAT
	if (core_is_compat(core))
		return restorer_sym(restorer_blob, arch_export_unmap_compat);
#endif
	return restorer_sym(restorer_blob, arch_export_unmap);
}

void arch_rsti_init(struct pstree_item *p) __attribute__((weak));
void arch_rsti_init(struct pstree_item *p) {}

static int sigreturn_restore(struct task_restore_args *task_args, unsigned long alen, CoreEntry *core)
{
	void *mem = MAP_FAILED;
	void *restore_task_exec_start;

	long new_sp;
	long ret;

	long rst_mem_size;
	long memzone_size;
	long min_addr;

	struct thread_restore_args *thread_args;
	struct restore_mem_zone *mz;

	struct vdso_maps vdso_maps_rt;
	unsigned long vdso_rt_size = 0;

	struct vm_area_list self_vmas;
	struct vm_area_list *vmas = &rsti(current)->vmas;
	int i, j, siginfo_n;
	int leader_pid = localpid(current);

	unsigned long creds_pos = 0;
	unsigned long creds_pos_next;

	sigset_t blockmask;

	pr_info("Restore via sigreturn\n");

	/* pr_info_vma_list(&self_vma_list); */

	BUILD_BUG_ON(sizeof(struct task_restore_args) & 1);
	BUILD_BUG_ON(sizeof(struct thread_restore_args) & 1);

	/*
	 * Read creds info for every thread and allocate memory
	 * needed so we can use this data inside restorer.
	 */
	if (rst_prep_creds(uid(current), core, &creds_pos))
		goto err_nv;

	if (current->parent == NULL) {
		/* Wait when all tasks restored all files */
		if (restore_wait_other_tasks())
			goto err_nv;
		if (root_ns_mask & CLONE_NEWNS && remount_readonly_mounts())
			goto err_nv;
	}

	/*
	 * We're about to search for free VM area and inject the restorer blob
	 * into it. No irrelevant mmaps/mremaps beyond this point, otherwise
	 * this unwanted mapping might get overlapped by the restorer.
	 */

	ret = parse_self_maps_lite(&self_vmas);
	if (ret < 0)
		goto err;

	rst_mem_size = rst_mem_lock();
	memzone_size = round_up(sizeof(struct restore_mem_zone) * current->nr_threads, page_size());
	task_args->bootstrap_len = restorer_len + memzone_size + alen + rst_mem_size + shstk_restorer_stack_size();
	BUG_ON(task_args->bootstrap_len & (PAGE_SIZE - 1));
	pr_info("%d threads require %ldK of memory\n", current->nr_threads, KBYTES(task_args->bootstrap_len));

	if (core_is_compat(core))
		vdso_maps_rt = vdso_maps_compat;
	else
		vdso_maps_rt = vdso_maps;
	/*
	 * Figure out how much memory runtime vdso and vvar will need.
	 * Check if vDSO or VVAR is not provided by kernel.
	 */
	if (vdso_maps_rt.sym.vdso_size != VDSO_BAD_SIZE) {
		vdso_rt_size = vdso_maps_rt.sym.vdso_size;
		if (vdso_maps_rt.sym.vvar_size != VVAR_BAD_SIZE)
			vdso_rt_size += vdso_maps_rt.sym.vvar_size;
	}
	task_args->bootstrap_len += vdso_rt_size;

	/*
	 * Restorer is a blob (code + args) that will get mapped in some
	 * place, that should _not_ intersect with both -- current mappings
	 * and mappings of the task we're restoring here. The subsequent
	 * call finds the start address for the restorer.
	 *
	 * After the start address is found we populate it with the restorer
	 * parts one by one (some are remap-ed, some are mmap-ed and copied
	 * or inited from scratch).
	 */

	min_addr = shstk_min_mmap_addr(&task_args->shstk, kdat.mmap_min_addr);
	mem = (void *)restorer_get_vma_hint(&vmas->h, &self_vmas.h,
					    min_addr, task_args->bootstrap_len);
	if (mem == (void *)-1) {
		pr_err("No suitable area for task_restore bootstrap (%ldK)\n", task_args->bootstrap_len);
		goto err;
	}

	pr_info("Found bootstrap VMA hint at: %p (needs ~%ldK)\n", mem, KBYTES(task_args->bootstrap_len));

	ret = remap_restorer_blob(mem);
	if (ret < 0)
		goto err;

	/*
	 * Prepare a memory map for restorer. Note a thread space
	 * might be completely unused so it's here just for convenience.
	 */
	task_args->clone_restore_fn = restorer_sym(mem, arch_export_restore_thread);
	restore_task_exec_start = restorer_sym(mem, arch_export_restore_task);
	rsti(current)->munmap_restorer = restorer_munmap_addr(core, mem);

	task_args->bootstrap_start = mem;
	mem += restorer_len;

	/* VMA we need for stacks and sigframes for threads */
	if (mmap(mem, memzone_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0) != mem) {
		pr_perror("Can't mmap section for restore code");
		goto err;
	}

	memzero(mem, memzone_size);
	mz = mem;
	mem += memzone_size;

	/* New home for task_restore_args and thread_restore_args */
	task_args = mremap(task_args, alen, alen, MREMAP_MAYMOVE | MREMAP_FIXED, mem);
	if (task_args != mem) {
		pr_perror("Can't move task args");
		goto err;
	}

	task_args->rst_mem = mem;
	task_args->rst_mem_size = rst_mem_size + alen;
	thread_args = (struct thread_restore_args *)(task_args + 1);

	/*
	 * And finally -- the rest arguments referenced by task_ and
	 * thread_restore_args. Pointers will get remapped below.
	 */
	mem += alen;
	if (rst_mem_remap(mem))
		goto err;

	/*
	 * At this point we've found a gap in VM that fits in both -- current
	 * and target tasks' mappings -- and its structure is
	 *
	 * | restorer code | memzone (stacks and sigframes) | arguments |
	 *
	 * Arguments is task_restore_args, thread_restore_args-s and all
	 * the bunch of objects allocated with rst_mem_alloc().
	 * Note, that the task_args itself is inside the 3rd section and (!)
	 * it gets unmapped at the very end of __export_restore_task
	 */

	task_args->proc_fd = dup(get_service_fd(PROC_FD_OFF));
	if (task_args->proc_fd < 0) {
		pr_perror("can't dup proc fd");
		goto err;
	}

	task_args->breakpoint = &rsti(current)->breakpoint;
	task_args->fault_strategy = fi_strategy;

	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &blockmask, NULL) == -1) {
		pr_perror("Can not set mask of blocked signals");
		return -1;
	}

	task_args->task_entries = rst_mem_remap_ptr(task_entries_pos, RM_SHREMAP);

	task_args->premmapped_addr = (unsigned long)rsti(current)->premmapped_addr;
	task_args->premmapped_len = rsti(current)->premmapped_len;

	task_args->task_size = kdat.task_size;
#ifdef ARCH_HAS_LONG_PAGES
	task_args->page_size = PAGE_SIZE;
#endif

	RST_MEM_FIXUP_PPTR(task_args->vmas);
	RST_MEM_FIXUP_PPTR(task_args->rings);
	RST_MEM_FIXUP_PPTR(task_args->tcp_socks);
	RST_MEM_FIXUP_PPTR(task_args->timerfd);
	RST_MEM_FIXUP_PPTR(task_args->posix_timers);
	RST_MEM_FIXUP_PPTR(task_args->siginfo);
	RST_MEM_FIXUP_PPTR(task_args->rlims);
	RST_MEM_FIXUP_PPTR(task_args->helpers);
	RST_MEM_FIXUP_PPTR(task_args->zombies);
	RST_MEM_FIXUP_PPTR(task_args->vma_ios);
	RST_MEM_FIXUP_PPTR(task_args->inotify_fds);

	task_args->compatible_mode = core_is_compat(core);
	/*
	 * Arguments for task restoration.
	 */

	BUG_ON(core->mtype != CORE_ENTRY__MARCH);

	task_args->logfd = log_get_fd();
	task_args->loglevel = log_get_loglevel();
	log_get_logstart(&task_args->logstart);
	task_args->sigchld_act = sigchld_act;

	strncpy(task_args->comm, core->tc->comm, TASK_COMM_LEN - 1);
	task_args->comm[TASK_COMM_LEN - 1] = 0;

	prep_libc_rseq_info(&task_args->libc_rseq);

	task_args->uid = opts.uid;
	for (i = 0; i < CR_CAP_SIZE; i++)
		task_args->cap_eff[i] = opts.cap_eff[i];

	/*
	 * Fill up per-thread data.
	 */
	creds_pos_next = creds_pos;
	siginfo_n = task_args->siginfo_n;
	arch_rsti_init(current);
	for (i = 0; i < current->nr_threads; i++) {
		CoreEntry *tcore;
		struct rt_sigframe *sigframe;
#ifdef CONFIG_MIPS
		k_rtsigset_t mips_blkset;
#else
		k_rtsigset_t *blkset = NULL;

#endif
		thread_args[i].pid = current->threads[i].local;
		for (j = 0; j < current->threads[i].ns_level; j++) {
			thread_args[i].tid_in_ns[j] = current->threads[i].ns[j].ns_pid;
		}
		thread_args[i].ns_level = current->threads[i].ns_level;
		thread_args[i].siginfo_n = siginfo_priv_nr[i];
		thread_args[i].siginfo = task_args->siginfo;
		thread_args[i].siginfo += siginfo_n;
		siginfo_n += thread_args[i].siginfo_n;

		/* skip self */
		if (thread_args[i].pid == leader_pid) {
			task_args->t = thread_args + i;
			tcore = core;
#ifdef CONFIG_MIPS
			mips_blkset.sig[0] = tcore->tc->blk_sigset;
			mips_blkset.sig[1] = tcore->tc->blk_sigset_extended;
#else
			blkset = (void *)&tcore->tc->blk_sigset;
#endif
		} else {
			tcore = current->core[i];
			if (tcore->thread_core->has_blk_sigset) {
#ifdef CONFIG_MIPS
				mips_blkset.sig[0] = tcore->thread_core->blk_sigset;
				mips_blkset.sig[1] = tcore->thread_core->blk_sigset_extended;
#else
				blkset = (void *)&tcore->thread_core->blk_sigset;
#endif
			}
		}

		if ((tcore->tc || tcore->ids) && thread_args[i].pid != leader_pid) {
			pr_err("Thread has optional fields present %d\n", thread_args[i].pid);
			ret = -1;
		}

		if (ret < 0) {
			pr_err("Can't read core data for thread %d\n", thread_args[i].pid);
			goto err;
		}

		thread_args[i].ta = task_args;
		thread_args[i].gpregs = *CORE_THREAD_ARCH_INFO(tcore)->gpregs;
		thread_args[i].clear_tid_addr = CORE_THREAD_ARCH_INFO(tcore)->clear_tid_addr;
		core_get_tls(tcore, &thread_args[i].tls);

		if (tcore->thread_core->has_cg_set && rsti(current)->cg_set != tcore->thread_core->cg_set) {
			thread_args[i].cg_set = tcore->thread_core->cg_set;
			thread_args[i].cgroupd_sk = dup(get_service_fd(CGROUPD_SK));
		} else {
			thread_args[i].cg_set = -1;
		}

		ret = prep_rseq(&thread_args[i].rseq, tcore->thread_core);
		if (ret)
			goto err;

		rst_reloc_creds(&thread_args[i], &creds_pos_next);

		thread_args[i].futex_rla = tcore->thread_core->futex_rla;
		thread_args[i].futex_rla_len = tcore->thread_core->futex_rla_len;
		thread_args[i].pdeath_sig = tcore->thread_core->pdeath_sig;
		if (tcore->thread_core->pdeath_sig > _KNSIG) {
			pr_err("Pdeath signal is too big\n");
			goto err;
		}

		ret = prep_sched_info(&thread_args[i].sp, tcore->thread_core);
		if (ret)
			goto err;

		seccomp_rst_reloc(&thread_args[i]);
		thread_args[i].seccomp_force_tsync = rsti(current)->has_old_seccomp_filter;

		thread_args[i].mz = mz + i;
		sigframe = (struct rt_sigframe *)&mz[i].rt_sigframe;

#ifdef CONFIG_MIPS
		if (construct_sigframe(sigframe, sigframe, &mips_blkset, tcore))
#else
		if (construct_sigframe(sigframe, sigframe, blkset, tcore))
#endif
			goto err;

		if (tcore->thread_core->comm)
			strncpy(thread_args[i].comm, tcore->thread_core->comm, TASK_COMM_LEN - 1);
		else
			strncpy(thread_args[i].comm, core->tc->comm, TASK_COMM_LEN - 1);
		thread_args[i].comm[TASK_COMM_LEN - 1] = 0;

		if (thread_args[i].pid != leader_pid)
			core_entry__free_unpacked(tcore, NULL);

		pr_info("Thread %4d stack %8p rt_sigframe %8p\n", i, mz[i].stack, mz[i].rt_sigframe);
	}

	/*
	 * Restorer needs own copy of vdso parameters. Runtime
	 * vdso must be kept non intersecting with anything else,
	 * since we need it being accessible even when own
	 * self-vmas are unmaped.
	 */
	mem += rst_mem_size;

	shstk_set_restorer_stack(&task_args->shstk, mem);
	mem += shstk_restorer_stack_size();

	task_args->vdso_rt_parked_at = (unsigned long)mem;
	task_args->vdso_maps_rt = vdso_maps_rt;
	task_args->vdso_rt_size = vdso_rt_size;
	task_args->can_map_vdso = kdat.can_map_vdso;
	task_args->has_clone3_set_tid = kdat.has_clone3_set_tid;

	new_sp = restorer_stack(task_args->t->mz);

	/* No longer need it */
	core_entry__free_unpacked(core, NULL);
	xfree(current->core);

	/*
	 * Now prepare run-time data for threads restore.
	 */
	task_args->nr_threads = current->nr_threads;
	task_args->thread_args = thread_args;

	task_args->auto_dedup = opts.auto_dedup;

	/*
	 * In the restorer we need to know if it is SELinux or not. For SELinux
	 * we must change the process context before creating threads. For
	 * Apparmor we can change each thread after they have been created.
	 */
	task_args->lsm_type = kdat.lsm;

	task_args->tfork_mode = opts.tfork.active;
	if (opts.tfork.active) {
		task_args->vma_cherrypick_fd = opts.tfork.vma_cherrypick_fd;
		task_args->target_pidfd = current->tfork_pidfd;
		task_args->target_memfd = current->tfork_memfd;
		task_args->target_pagemap_fd = current->tfork_pagemap_fd;
		task_args->tfork_pidfd_base = opts.tfork.pidfd_base;
		task_args->tfork_snap_root_fd = opts.tfork.snap_root_fd;
		task_args->tfork_ncopy_ready_fd = opts.tfork.ncopy_ready_fd;
		task_args->tfork_full_memcopy = opts.tfork.full_memcopy;

		if (task_args->vma_cherrypick_fd < 0 || task_args->target_pidfd < 0) {
			pr_err("tfork: missing fds (cherrypick=%d pidfd=%d)\n",
			       task_args->vma_cherrypick_fd, task_args->target_pidfd);
			goto err;
		}

		if (rsti(current)->fdt && rsti(current)->fdt->tfork_cherrypick_cpos) {
			task_args->tfork_fdt_done = rst_mem_remap_ptr(
				rsti(current)->fdt->tfork_cherrypick_cpos,
				RM_SHREMAP);
			task_args->tfork_fdt_nr = rsti(current)->fdt->nr;
		} else {
			task_args->tfork_fdt_done = NULL;
			task_args->tfork_fdt_nr = 0;
		}

		pr_info("tfork: restorer args: cherrypick_fd=%d pidfd=%d fdt_nr=%d\n",
			task_args->vma_cherrypick_fd,
			task_args->target_pidfd,
			task_args->tfork_fdt_nr);
	}

	/*
	 * Make root and cwd restore _that_ late not to break any
	 * attempts to open files by paths above (e.g. /proc).
	 */

	if (restore_fs(current))
		goto err;

	sfds_protected = false;
	close_image_dir();
	close_proc();
	close_service_fd(TRANSPORT_FD_OFF);
	close_service_fd(CR_PROC_FD_OFF);
	close_service_fd(ROOT_FD_OFF);
	close_service_fd(USERNSD_SK);
	close_service_fd(FDSTORE_SK_OFF);
	close_service_fd(RPC_SK_OFF);
	close_service_fd(CGROUPD_SK);

	close_service_fd(CAPBYPASS_FD_OFF);
	close_service_fd(PKEY_STATE_FD_OFF);

	__gcov_flush();

	pr_info("task_args: %p\n"
		"task_args->pid: %d\n"
		"task_args->nr_threads: %d\n"
		"task_args->clone_restore_fn: %p\n"
		"task_args->thread_args: %p\n",
		task_args, task_args->t->pid, task_args->nr_threads, task_args->clone_restore_fn,
		task_args->thread_args);

	/*
	 * An indirect call to task_restore, note it never returns
	 * and restoring core is extremely destructive.
	 */

	JUMP_TO_RESTORER_BLOB(new_sp, restore_task_exec_start, task_args);

err:
	free_mappings(&self_vmas);
err_nv:
	/* Just to be sure */
	exit(1);
	return -1;
}
