#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/pid.h>
#include <linux/file.h>
#include <linux/capability.h>
#include <linux/uaccess.h>
#include <linux/sched/mm.h>

#include "pkey_state.h"
#include "uapi_pkey_state.h"

static long pkey_state_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static pidfd_pid_t module_pidfd_pid;

static const struct file_operations pkey_state_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = pkey_state_ioctl,
};

static struct miscdevice pkey_state_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = KBUILD_MODNAME,
	.fops  = &pkey_state_fops,
	.mode  = 0600,
};

static struct pid *get_target_pid(struct pkey_state_args *args)
{
	struct pid *pid = NULL;

	if (args->flags & PKEY_STATE_FLAG_PIDFD) {
		struct fd f = fdget(args->target_id);
		if (fd_empty(f))
			return ERR_PTR(-EBADF);

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

static struct mm_struct *pid_to_mm(struct pid *pid)
{
	struct task_struct *task;
	struct mm_struct *mm;

	rcu_read_lock();
	task = pid_task(pid, PIDTYPE_PID);
	if (!task) {
		rcu_read_unlock();
		return ERR_PTR(-ESRCH);
	}
	mm = get_task_mm(task);
	rcu_read_unlock();

	if (!mm)
		return ERR_PTR(-EINVAL);
	return mm;
}

static long do_pkey_state_get(struct pkey_state_args *kargs,
			      void __user *uarg)
{
	struct pid *pid;
	struct mm_struct *mm;

	pid = get_target_pid(kargs);
	if (IS_ERR(pid))
		return PTR_ERR(pid);

	mm = pid_to_mm(pid);
	put_pid(pid);
	if (IS_ERR(mm))
		return PTR_ERR(mm);

	mmap_read_lock(mm);
	kargs->pkey_allocation_map = mm->context.pkey_allocation_map;
	kargs->execute_only_pkey   = mm->context.execute_only_pkey;
	mmap_read_unlock(mm);

	mmput(mm);

	if (copy_to_user(uarg, kargs, sizeof(*kargs)))
		return -EFAULT;

	dev_dbg(pkey_state_dev.this_device,
		"GET pid=%d map=0x%x exec_only=%d\n",
		kargs->target_id,
		kargs->pkey_allocation_map,
		kargs->execute_only_pkey);
	return 0;
}

static long do_pkey_state_set(struct pkey_state_args *kargs)
{
	struct pid *pid;
	struct mm_struct *mm;


	if (kargs->pkey_allocation_map > 0xffff)
		return -EINVAL;
	if (!(kargs->pkey_allocation_map & 0x1))
		return -EINVAL;
	if (kargs->execute_only_pkey < -1 || kargs->execute_only_pkey > 15)
		return -EINVAL;

	pid = get_target_pid(kargs);
	if (IS_ERR(pid))
		return PTR_ERR(pid);

	mm = pid_to_mm(pid);
	put_pid(pid);
	if (IS_ERR(mm))
		return PTR_ERR(mm);

	mmap_write_lock(mm);
	mm->context.pkey_allocation_map = (u16)kargs->pkey_allocation_map;
	mm->context.execute_only_pkey   = (s16)kargs->execute_only_pkey;
	mmap_write_unlock(mm);

	mmput(mm);

	dev_dbg(pkey_state_dev.this_device,
		"SET pid=%d map=0x%x exec_only=%d\n",
		kargs->target_id,
		kargs->pkey_allocation_map,
		kargs->execute_only_pkey);
	return 0;
}


static int target_is_self(struct pkey_state_args *args)
{
	struct pid *pid;
	int self;

	pid = get_target_pid(args);
	if (IS_ERR(pid))
		return PTR_ERR(pid);

	rcu_read_lock();
	self = (pid_task(pid, PIDTYPE_PID) == current);
	rcu_read_unlock();
	put_pid(pid);
	return self;
}

static long pkey_state_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct pkey_state_args kargs;
	void __user *uarg = (void __user *)arg;
	int self;

	if (copy_from_user(&kargs, uarg, sizeof(kargs)))
		return -EFAULT;

	if (kargs.flags & ~(PKEY_STATE_FLAG_PIDFD))
		return -EINVAL;

	self = target_is_self(&kargs);
	if (self < 0)
		return self;
	if (!self &&
	    !ns_capable(&init_user_ns, CAP_SYS_ADMIN) &&
	    !ns_capable(&init_user_ns, CAP_CHECKPOINT_RESTORE))
		return -EPERM;

	switch (cmd) {
	case PKEY_STATE_GET:
		return do_pkey_state_get(&kargs, uarg);
	case PKEY_STATE_SET:
		return do_pkey_state_set(&kargs);
	default:
		return -ENOTTY;
	}
}

static int get_required_fn_var(void)
{
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_pidfd_pid, "pidfd_pid")))
		return -ENOSYS;
	return 0;
}

static int __init pkey_state_init(void)
{
	int ret;

	ret = get_kallsyms_lookup_name_fn();
	if (ret) {
		pr_err("Failed to initialize kallsyms_lookup_name function!\n");
		return ret;
	}

	ret = get_required_fn_var();
	if (unlikely(ret))
		return ret;

	ret = misc_register(&pkey_state_dev);
	if (ret) {
		pr_err("failed to register misc device\n");
		return ret;
	}

	pr_info("Module loaded. /dev/%s ready.\n", pkey_state_dev.name);
	return 0;
}

static void __exit pkey_state_exit(void)
{
	misc_deregister(&pkey_state_dev);
	pr_info("Module unloaded.\n");
}

module_init(pkey_state_init);
module_exit(pkey_state_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CRIU helper: get/set per-mm Intel MPK pkey allocation bitmap");
MODULE_AUTHOR("CRIU developers");
