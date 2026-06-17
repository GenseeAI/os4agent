#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/file.h>
#include <linux/capability.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/ptrace.h>
#include <asm/syscall.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>

#include "criu_capbypass.h"
#include "uapi_criu_capbypass.h"

#define CAPBYPASS_HASH_BITS	10
#define MAX_CONCURRENT_PROBES	128

struct capbypass_node {
	struct task_struct *task;
	u64  cap_mask;
	u32  syscall_mask;
	u32  flags;
	struct file *owner;
	struct hlist_node node;
};

static DEFINE_HASHTABLE(capbypass_map, CAPBYPASS_HASH_BITS);
static DEFINE_RWLOCK(map_lock);
static struct kmem_cache *capbypass_cachep;

typedef struct pid *(*pidfd_pid_t)(const struct file *file);
static pidfd_pid_t module_pidfd_pid;


static u32 *syscall_class_map;

static void build_syscall_class_map(void)
{
	syscall_class_map = kcalloc(NR_syscalls, sizeof(u32), GFP_KERNEL);
	if (!syscall_class_map)
		return;

#ifdef __NR_clone
	if (__NR_clone < NR_syscalls)
		syscall_class_map[__NR_clone] = CRIU_CB_SC_CLONE;
#endif
#ifdef __NR_clone3
	if (__NR_clone3 < NR_syscalls)
		syscall_class_map[__NR_clone3] = CRIU_CB_SC_CLONE;
#endif
#ifdef __NR_fork
	if (__NR_fork < NR_syscalls)
		syscall_class_map[__NR_fork] = CRIU_CB_SC_CLONE;
#endif
#ifdef __NR_vfork
	if (__NR_vfork < NR_syscalls)
		syscall_class_map[__NR_vfork] = CRIU_CB_SC_CLONE;
#endif
#ifdef __NR_setns
	if (__NR_setns < NR_syscalls)
		syscall_class_map[__NR_setns] = CRIU_CB_SC_SETNS;
#endif
#ifdef __NR_unshare
	if (__NR_unshare < NR_syscalls)
		syscall_class_map[__NR_unshare] = CRIU_CB_SC_UNSHARE;
#endif
#ifdef __NR_mount
	if (__NR_mount < NR_syscalls)
		syscall_class_map[__NR_mount] = CRIU_CB_SC_MOUNT;
#endif
#ifdef __NR_umount2
	if (__NR_umount2 < NR_syscalls)
		syscall_class_map[__NR_umount2] = CRIU_CB_SC_MOUNT;
#endif
#ifdef __NR_move_mount
	if (__NR_move_mount < NR_syscalls)
		syscall_class_map[__NR_move_mount] = CRIU_CB_SC_MOUNT;
#endif
#ifdef __NR_fsmount
	if (__NR_fsmount < NR_syscalls)
		syscall_class_map[__NR_fsmount] = CRIU_CB_SC_MOUNT;
#endif
#ifdef __NR_open_tree
	if (__NR_open_tree < NR_syscalls)
		syscall_class_map[__NR_open_tree] = CRIU_CB_SC_MOUNT;
#endif
#ifdef __NR_chdir
	if (__NR_chdir < NR_syscalls)
		syscall_class_map[__NR_chdir] = CRIU_CB_SC_FS;
#endif
#ifdef __NR_fchdir
	if (__NR_fchdir < NR_syscalls)
		syscall_class_map[__NR_fchdir] = CRIU_CB_SC_FS;
#endif
#ifdef __NR_chroot
	if (__NR_chroot < NR_syscalls)
		syscall_class_map[__NR_chroot] = CRIU_CB_SC_FS;
#endif
}

static inline u32 syscall_nr_to_class(long nr)
{
	if (!syscall_class_map)
		return 0;
	if (nr < 0 || nr >= NR_syscalls)
		return 0;
	return syscall_class_map[nr];
}

static bool in_allowed_syscall(u32 syscall_mask)
{
	struct pt_regs *uregs;
	long nr;
	u32 cls;

	if (current->flags & PF_KTHREAD)
		return false;
	uregs = task_pt_regs(current);
	if (!uregs)
		return false;
	nr = syscall_get_nr(current, uregs);
	if (nr < 0)
		return false;
	cls = syscall_nr_to_class(nr);
	if (cls == 0)
		return false;
	return (syscall_mask & cls) == cls;
}

struct capbypass_kretprobe_data {
	bool override;
};

static int cap_capable_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct capbypass_kretprobe_data *d = (void *)ri->data;
	int cap;
	struct capbypass_node *entry;

	d->override = false;
	if (current->flags & PF_KTHREAD)
		return 0;

	cap = (int)regs->dx;
	if (cap < 0 || cap > 63)
		return 0;

	read_lock(&map_lock);
	hash_for_each_possible(capbypass_map, entry, node, (unsigned long)current) {
		if (entry->task != current)
			continue;
		if (!(entry->cap_mask & (1ULL << cap)))
			break;
		if (!in_allowed_syscall(entry->syscall_mask))
			break;
		d->override = true;
		break;
	}
	read_unlock(&map_lock);
	return 0;
}

static int cap_capable_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct capbypass_kretprobe_data *d = (void *)ri->data;

	if (d->override)
		regs_set_return_value(regs, 0);
	return 0;
}

static struct kretprobe cap_capable_krp = {
	.kp.symbol_name = "cap_capable",
	.entry_handler  = cap_capable_pre,
	.handler        = cap_capable_ret,
	.data_size      = sizeof(struct capbypass_kretprobe_data),
	.maxactive      = MAX_CONCURRENT_PROBES,
};
static struct miscdevice criu_capbypass_dev;

static struct pid *get_target_pid(const struct criu_capbypass_args *args)
{
	struct pid *pid = NULL;

	if (args->flags & CRIU_CB_TARGET_PIDFD) {
		struct fd f = fdget(args->target_id);

		if (!fd_file(f))
			return ERR_PTR(-EBADF);
		if (!module_pidfd_pid) {
			fdput(f);
			return ERR_PTR(-ENOSYS);
		}
		pid = module_pidfd_pid(fd_file(f));
		if (IS_ERR(pid)) {
			fdput(f);
			return pid;
		}
		get_pid(pid);
		fdput(f);
	} else {
		rcu_read_lock();
		pid = find_vpid(args->target_id);
		if (pid)
			get_pid(pid);
		rcu_read_unlock();
	}

	return pid ? pid : ERR_PTR(-ESRCH);
}

static int do_grant(struct file *file, struct criu_capbypass_args *args)
{
	struct capbypass_node *new_node, *entry;
	struct task_struct *tsk;
	struct pid *pid;
	u64 cap_mask;
	u32 syscall_mask;
	int ret = 0;

	pid = get_target_pid(args);
	if (IS_ERR(pid))
		return PTR_ERR(pid);

	rcu_read_lock();
	tsk = pid_task(pid, PIDTYPE_PID);
	if (!tsk) {
		rcu_read_unlock();
		put_pid(pid);
		return -ESRCH;
	}
	get_task_struct(tsk);
	rcu_read_unlock();
	put_pid(pid);

	cap_mask     = args->cap_mask ? args->cap_mask : CRIU_CB_DEFAULT_CAPS;
	syscall_mask = args->syscall_mask ? args->syscall_mask : CRIU_CB_SC_RESTORE_DEFAULT;

	new_node = kmem_cache_alloc(capbypass_cachep, GFP_KERNEL);
	if (!new_node) {
		put_task_struct(tsk);
		return -ENOMEM;
	}
	new_node->task         = tsk;
	new_node->cap_mask     = cap_mask;
	new_node->syscall_mask = syscall_mask;
	new_node->flags        = 0;
	new_node->owner        = file;

	write_lock(&map_lock);
	hash_for_each_possible(capbypass_map, entry, node, (unsigned long)tsk) {
		if (entry->task == tsk) {
			hash_del(&entry->node);
			put_task_struct(entry->task);
			kmem_cache_free(capbypass_cachep, entry);
			dev_warn_ratelimited(criu_capbypass_dev.this_device,
				"replaced stale grant for pid=%d\n",
				task_pid_vnr(tsk));
			break;
		}
	}
	hash_add(capbypass_map, &new_node->node, (unsigned long)tsk);
	write_unlock(&map_lock);

	dev_info(criu_capbypass_dev.this_device,
		"grant: tgid=%d target_pid=%d cap_mask=0x%llx syscall_mask=0x%x flags=0x%x\n",
		current->tgid, task_pid_vnr(tsk),
		new_node->cap_mask, new_node->syscall_mask, new_node->flags);

	return ret;
}

static int do_revoke(struct file *file, struct criu_capbypass_args *args)
{
	struct capbypass_node *entry;
	struct task_struct *tsk;
	struct pid *pid;
	int ret = -ENOENT;

	pid = get_target_pid(args);
	if (IS_ERR(pid))
		return PTR_ERR(pid);
	rcu_read_lock();
	tsk = pid_task(pid, PIDTYPE_PID);
	if (!tsk) {
		rcu_read_unlock();
		put_pid(pid);
		return -ESRCH;
	}
	get_task_struct(tsk);
	rcu_read_unlock();
	put_pid(pid);

	write_lock(&map_lock);
	hash_for_each_possible(capbypass_map, entry, node, (unsigned long)tsk) {
		if (entry->task == tsk) {

			if (entry->owner != file) {
				ret = -EACCES;
				break;
			}
			hash_del(&entry->node);
			put_task_struct(entry->task);
			kmem_cache_free(capbypass_cachep, entry);
			ret = 0;
			break;
		}
	}
	write_unlock(&map_lock);

	dev_info(criu_capbypass_dev.this_device,
		"revoke: tgid=%d target_pid=%d ret=%d\n",
		current->tgid, task_pid_vnr(tsk), ret);

	put_task_struct(tsk);
	return ret;
}

static long criu_capbypass_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct criu_capbypass_args kargs;

	if (copy_from_user(&kargs, (void __user *)arg, sizeof(kargs)))
		return -EFAULT;

	if (cmd == CRIU_CB_GRANT || cmd == CRIU_CB_REVOKE) {
		struct pid *pid = get_target_pid(&kargs);
		bool is_self = false;

		if (IS_ERR(pid))
			return PTR_ERR(pid);
		rcu_read_lock();
		is_self = (pid_task(pid, PIDTYPE_PID) == current);
		rcu_read_unlock();
		put_pid(pid);

		if (!is_self &&
		    !ns_capable(&init_user_ns, CAP_SYS_ADMIN) &&
		    !ns_capable(&init_user_ns, CAP_CHECKPOINT_RESTORE))
			return -EPERM;
	}

	switch (cmd) {
	case CRIU_CB_GRANT:
		return do_grant(file, &kargs);
	case CRIU_CB_REVOKE:
		return do_revoke(file, &kargs);
	default:
		return -ENOTTY;
	}
}

static int criu_capbypass_release(struct inode *ino, struct file *file)
{
	struct capbypass_node *entry;
	struct hlist_node *tmp;
	int bkt;
	int n = 0;

	write_lock(&map_lock);
	hash_for_each_safe(capbypass_map, bkt, tmp, entry, node) {
		if (entry->owner == file) {
			hash_del(&entry->node);
			put_task_struct(entry->task);
			kmem_cache_free(capbypass_cachep, entry);
			n++;
		}
	}
	write_unlock(&map_lock);

	if (n)
		dev_info(criu_capbypass_dev.this_device,
			"release: auto-revoked %d grant(s) for fd-close\n", n);
	return 0;
}

static const struct file_operations criu_capbypass_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = criu_capbypass_ioctl,
	.release        = criu_capbypass_release,
};

static struct miscdevice criu_capbypass_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = KBUILD_MODNAME,
	.fops  = &criu_capbypass_fops,
	.mode  = 0600,
};

static int do_exit_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct capbypass_node *entry;
	struct hlist_node *tmp;
	int bkt;

	write_lock(&map_lock);
	hash_for_each_safe(capbypass_map, bkt, tmp, entry, node) {
		if (entry->task == current) {
			hash_del(&entry->node);
			put_task_struct(entry->task);
			kmem_cache_free(capbypass_cachep, entry);
		}
	}
	write_unlock(&map_lock);
	return 0;
}

static struct kprobe do_exit_kp = {
	.symbol_name = "do_exit",
	.pre_handler = do_exit_pre,
};

static int resolve_needed_syms(void)
{
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_pidfd_pid, "pidfd_pid")))
		return -ENOSYS;
	return 0;
}

static int __init criu_capbypass_init(void)
{
	int ret;

	ret = get_kallsyms_lookup_name_fn();
	if (ret)
		return ret;

	ret = resolve_needed_syms();
	if (ret)
		return ret;

	build_syscall_class_map();
	if (!syscall_class_map)
		return -ENOMEM;

	capbypass_cachep = kmem_cache_create("criu_capbypass_node",
					     sizeof(struct capbypass_node),
					     0, SLAB_HWCACHE_ALIGN, NULL);
	if (!capbypass_cachep) {
		ret = -ENOMEM;
		goto err_free_map;
	}

	ret = register_kretprobe(&cap_capable_krp);
	if (ret) {
		pr_err("register_kretprobe(cap_capable) failed: %d\n", ret);
		goto err_free_slab;
	}

	ret = register_kprobe(&do_exit_kp);
	if (ret) {
		pr_err("register_kprobe(do_exit) failed: %d\n", ret);
		goto err_unreg_krp;
	}

	ret = misc_register(&criu_capbypass_dev);
	if (ret) {
		pr_err("misc_register failed: %d\n", ret);
		goto err_unreg_do_exit_kp;
	}

	pr_info("loaded. /dev/%s ready.\n", criu_capbypass_dev.name);
	return 0;

err_unreg_do_exit_kp:
	unregister_kprobe(&do_exit_kp);
err_unreg_krp:
	unregister_kretprobe(&cap_capable_krp);
err_free_slab:
	kmem_cache_destroy(capbypass_cachep);
err_free_map:
	kfree(syscall_class_map);
	syscall_class_map = NULL;
	return ret;
}

static void __exit criu_capbypass_exit(void)
{
	struct capbypass_node *entry;
	struct hlist_node *tmp;
	int bkt;

	misc_deregister(&criu_capbypass_dev);
	unregister_kprobe(&do_exit_kp);
	unregister_kretprobe(&cap_capable_krp);

	write_lock(&map_lock);
	hash_for_each_safe(capbypass_map, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		put_task_struct(entry->task);
		kmem_cache_free(capbypass_cachep, entry);
	}
	write_unlock(&map_lock);

	kmem_cache_destroy(capbypass_cachep);
	kfree(syscall_class_map);
	syscall_class_map = NULL;

	pr_info("unloaded.\n");
}

module_init(criu_capbypass_init);
module_exit(criu_capbypass_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Per-task, syscall-scoped cap_capable bypass for CRIU restore");
