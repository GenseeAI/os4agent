#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/rwlock.h>
#include <linux/tty.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/ptrace.h>
#include <linux/pid_namespace.h>
#include <linux/miscdevice.h>

#include "reparent.h"
#include "reparent_uapi.h"

static rwlock_t *tasklist_lock_ptr;
static pidfd_get_task_t module_pidfd_get_task;
static pidfd_pid_t module_pidfd_pid;
static create_new_namespaces_t module_create_new_namespaces;
static switch_task_namespaces_t module_switch_task_namespaces;
static put_nsset_t module_put_nsset;
static deactivate_nsproxy_t module_deactivate_nsproxy;
static perf_event_namespaces_t module_perf_event_namespaces;
static ptrace_may_access_t module_ptrace_may_access;
static change_pid_t module_change_pid;
static free_pids_t module_free_pids;

static void put_required_fn_var(void)
{
    tasklist_lock_ptr = NULL;
    module_pidfd_get_task = NULL;
    module_pidfd_pid = NULL;
    module_change_pid = NULL;
    module_create_new_namespaces = NULL;
    module_switch_task_namespaces = NULL;
    module_put_nsset = NULL;
    module_deactivate_nsproxy = NULL;
    module_perf_event_namespaces = NULL;
    module_ptrace_may_access = NULL;
    module_free_pids = NULL;
}

static int get_required_fn_var(void)
{
    if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(tasklist_lock_ptr, "tasklist_lock")))
        return -ENOSYS;

    if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_pidfd_get_task, "pidfd_get_task")))
        return -ENOSYS;

    if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_pidfd_pid, "pidfd_pid")))
        return -ENOSYS;

    if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_create_new_namespaces, "create_new_namespaces")))
        return -ENOSYS;

    if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_switch_task_namespaces, "switch_task_namespaces")))
        return -ENOSYS;

    if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_put_nsset, "put_nsset")))
        return -ENOSYS;

    if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_deactivate_nsproxy, "deactivate_nsproxy")))
        return -ENOSYS;

    if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_perf_event_namespaces, "perf_event_namespaces")))
        return -ENOSYS;

    if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_ptrace_may_access, "ptrace_may_access")))
        return -ENOSYS;

    if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_change_pid, "change_pid")))
        return -ENOSYS;

    if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_free_pids, "free_pids")))
        return -ENOSYS;

    return 0;
}


static long reparent_task(struct task_struct *target, struct task_struct *new_parent)
{
    struct pid *stale_pids[PIDTYPE_MAX] = { NULL };
    struct pid *new_parent_pgid, *new_parent_sid;
    struct task_struct *old_parent = NULL, *t = new_parent;
    struct tty_struct *old_tty = NULL;

    pr_info("Attempting to reparent target PID %d to new parent PID %d\n",
            task_pid_vnr(target), task_pid_vnr(new_parent));

    if (!thread_group_leader(new_parent)) {
        pr_err("New parent PID %d is not a thread group leader!\n", task_pid_vnr(new_parent));
        return -EINVAL;
    }

    rcu_read_lock();
    while (t) {
        if (unlikely(t == target)) {
            pr_err("New parent PID %d is a descendant of target PID %d!\n",
                    task_pid_vnr(new_parent), task_pid_vnr(target));
            rcu_read_unlock();
            return -EINVAL;
        }

        if (t == &init_task || t == t->real_parent) {
            break;
        }

        t = t->real_parent;
    };
    old_parent = rcu_dereference(target->real_parent);

    if (unlikely(task_pid_nr(target) == 1 || !old_parent)) {
        pr_err("Cannot reparent the init task (PID 1)!\n");
        rcu_read_unlock();
        return -EINVAL;
    }
    rcu_read_unlock();

    if (!thread_group_leader(target)) {
        pr_err("Target PID %d is not a thread group leader!\n", task_pid_vnr(target));
        return -EINVAL;
    }

    if (get_nr_threads(target) != 1) {
        pr_err("Target PID %d has multiple threads,"
            "expected only one thread for safe reparenting!\n", task_pid_vnr(target));
        return -EINVAL;
    }

    if (!(target->flags & PF_FORKNOEXEC)) {
        pr_err("Target PID %d is not a forked-but-not-yet-exec task, "
            "cannot reparent safely!\n", task_pid_vnr(target));
        return -EINVAL;
    }

    write_lock_irq(tasklist_lock_ptr);
    spin_lock(&target->sighand->siglock);

    rcu_assign_pointer(target->real_parent, new_parent);
    if (likely(!target->ptrace))
        rcu_assign_pointer(target->parent, new_parent);
    target->parent_exec_id = new_parent->self_exec_id;
    target->signal->has_child_subreaper = new_parent->signal->has_child_subreaper ||
                                new_parent->signal->is_child_subreaper;

    list_del_init(&target->sibling);
    list_add_tail(&target->sibling, &new_parent->children);

    new_parent_pgid = task_pgrp(new_parent);
    if (task_pgrp(target) != new_parent_pgid) {
        module_change_pid(stale_pids, target, PIDTYPE_PGID, new_parent_pgid);
    }

    new_parent_sid = task_session(new_parent);
    if (task_session(target) != new_parent_sid) {
        module_change_pid(stale_pids, target, PIDTYPE_SID, new_parent_sid);

        old_tty = target->signal->tty;
        target->signal->tty = tty_kref_get(new_parent->signal->tty);
    }

    spin_unlock(&target->sighand->siglock);
    write_unlock_irq(tasklist_lock_ptr);

    if (old_tty) {
        tty_kref_put(old_tty);
    }
    module_free_pids(stale_pids);
    return 0;
}

static long reparent_task_struct_ioctl(struct file *file, unsigned long arg)
{
    struct task_struct *target = current;
    struct task_struct *new_parent = NULL;
    int pidfd_newparent;
    unsigned int f_flags;
    long ret = 0;

    if (copy_from_user(&pidfd_newparent, (int __user *)arg, sizeof(pidfd_newparent)))
        return -EFAULT;

    if (pidfd_newparent <= 0)
        return -EINVAL;

    get_task_struct(target);
    new_parent = module_pidfd_get_task(pidfd_newparent, &f_flags);
    if (IS_ERR(new_parent)) {
        ret = PTR_ERR(new_parent);
        goto err;
    }

    ret = reparent_task(target, new_parent);
    put_task_struct(new_parent);
err:
    put_task_struct(target);
    return ret;
}

static long reparent_task_arg_ioctl(struct file *file, unsigned long arg)
{
    struct reparent_task_arg karg;
    struct task_struct *target = NULL;
    struct task_struct *new_parent = NULL;
    unsigned int f_flags;
    long ret = 0;

    if (copy_from_user(&karg, (void __user *)arg, sizeof(karg)))
        return -EFAULT;

    if (karg.target_pidfd <= 0 || karg.new_parent_pidfd <= 0)
        return -EINVAL;

    target = module_pidfd_get_task(karg.target_pidfd, &f_flags);
    if (IS_ERR(target))
        return PTR_ERR(target);

    new_parent = module_pidfd_get_task(karg.new_parent_pidfd, &f_flags);
    if (IS_ERR(new_parent)) {
        ret = PTR_ERR(new_parent);
        goto out_target;
    }

    ret = reparent_task(target, new_parent);
    put_task_struct(new_parent);
out_target:
    put_task_struct(target);
    return ret;
}

static int module_prepare_nsset(unsigned flags, struct nsset *nsset)
{
	struct task_struct *me = current;

	nsset->nsproxy = module_create_new_namespaces(0, me, current_user_ns(), me->fs);
	if (IS_ERR(nsset->nsproxy))
		return PTR_ERR(nsset->nsproxy);

	nsset->cred = current_cred();
	if (!nsset->cred)
		goto out;

	nsset->flags = flags;
	return 0;

out:
	module_put_nsset(nsset);
	return -ENOMEM;
}

static int module_validate_nsset_pidns_only(struct nsset *nsset, struct pid *pid)
{
    int ret = 0;
	struct pid_namespace *pid_ns = NULL;
	struct nsproxy *nsp = NULL;
	struct task_struct *tsk = NULL;


	rcu_read_lock();
	tsk = pid_task(pid, PIDTYPE_PID);
	if (!tsk) {
		rcu_read_unlock();
		return -ESRCH;
	}

	if (!module_ptrace_may_access(tsk, PTRACE_MODE_READ_REALCREDS)) {
		rcu_read_unlock();
		return -EPERM;
	}

	task_lock(tsk);
	nsp = tsk->nsproxy;
	if (nsp)
		get_nsproxy(nsp);
	task_unlock(tsk);
	if (!nsp) {
		rcu_read_unlock();
		return -ESRCH;
	}

    pid_ns = task_active_pid_ns(tsk);
    if (unlikely(!pid_ns)) {
        rcu_read_unlock();
        ret = -ESRCH;
        goto out;
    }
    get_pid_ns(pid_ns);
	rcu_read_unlock();


    put_pid_ns(nsset->nsproxy->pid_ns_for_children);
	nsset->nsproxy->pid_ns_for_children = get_pid_ns(pid_ns);

out:
	if (pid_ns)
		put_pid_ns(pid_ns);
	if (nsp) {
        if (refcount_dec_and_test(&nsp->count))
		    module_deactivate_nsproxy(nsp);
    }
	return ret;
}


static int force_set_pidns(int fd)
{
    CLASS(fd, f)(fd);
    struct nsset nsset = {};
    const int flags = CLONE_NEWPID;
	int err = 0;

    if (fd_empty(f))
		return -EBADF;

    pr_info("force_set_pidns: Received request to set PID namespace using fd %d\n", fd);
    if (IS_ERR(module_pidfd_pid(fd_file(f))))
        return -EINVAL;

    err = module_prepare_nsset(flags, &nsset);
    if (err)
        return err;

    err = module_validate_nsset_pidns_only(&nsset, module_pidfd_pid(fd_file(f)));
    if (!err) {
		module_switch_task_namespaces(current, nsset.nsproxy);
	    nsset.nsproxy = NULL;
		module_perf_event_namespaces(current);
	}
	module_put_nsset(&nsset);
	return err;
}


static long force_set_pidns_ioctl(struct file *file, unsigned long arg)
{
    int pidfd;

    pr_info("Attempting to force set PID namespace using pidfd\n");

    if (copy_from_user(&pidfd, (int __user *)arg, sizeof(pidfd)))
        return -EFAULT;

    return force_set_pidns(pidfd);
}

static long reparent_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    if (!capable(CAP_CHECKPOINT_RESTORE) && !capable(CAP_SYS_ADMIN)) {
        pr_warn_ratelimited("reparent: Rejected access due to insufficient capabilities.\n");
        return -EPERM;
    }

    switch (cmd) {
    case REPARENT_ME_CMD:
        return reparent_task_struct_ioctl(file, arg);
    case FORCE_SET_PIDNS_CMD:
        return force_set_pidns_ioctl(file, arg);
    case REPARENT_TASK_CMD:
        return reparent_task_arg_ioctl(file, arg);
    default:
        return -ENOTTY;
    }
}

static const struct file_operations reparent_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = reparent_ioctl,
};

static struct miscdevice reparent_misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "reparent",
    .fops  = &reparent_fops,
    .mode  = 0200,
};

static int __init reparent_task_init(void)
{
    int ret;

    pr_info("Initializing module.\n");
    ret = get_kallsyms_lookup_name_fn();
    if (unlikely(ret)) {
        pr_err("Failed to initialize kallsyms_lookup_name function!\n");
        return ret;
    }

    ret = get_required_fn_var();
    if (unlikely(ret))
        goto err_cleanup;

    ret = misc_register(&reparent_misc_dev);
    if (ret) {
        pr_err("Failed to map /dev/%s\n", reparent_misc_dev.name);
        goto err_cleanup;
    }

    return 0;

err_cleanup:
    put_required_fn_var();
    put_kallsyms_lookup_name_fn();
    return ret;
}

static void __exit reparent_task_exit(void)
{
    pr_info("Unloading module.\n");
    misc_deregister(&reparent_misc_dev);
    put_required_fn_var();
    put_kallsyms_lookup_name_fn();
    pr_info("Module unloaded.\n");
}

module_init(reparent_task_init);
module_exit(reparent_task_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kernel module to reparent a task to a different parent task");
