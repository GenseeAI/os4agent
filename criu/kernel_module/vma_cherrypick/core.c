#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mempolicy.h>
#include <linux/mmap_lock.h>
#include <linux/pid.h>
#include <linux/file.h>
#include <linux/capability.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/maple_tree.h>

#include "vma_cherrypick.h"
#include "uapi_vma_cherrypick.h"

static pidfd_pid_t			module_pidfd_pid;
static vm_area_dup_t			module_vm_area_dup;
static vm_area_free_t			module_vm_area_free;
static anon_vma_fork_t			module_anon_vma_fork;
static copy_page_range_t		module_copy_page_range;
static vma_dup_policy_t		module_vma_dup_policy;
static dup_userfaultfd_t		module_dup_userfaultfd;
static dup_userfaultfd_complete_t	module_dup_userfaultfd_complete;
static dup_userfaultfd_fail_t	module_dup_userfaultfd_fail;
static hugetlb_dup_vma_private_t	module_hugetlb_dup_vma_private;
static security_vm_enough_memory_mm_t	module_security_vm_enough_memory_mm;
static vma_interval_tree_insert_after_t	module_vma_interval_tree_insert_after;
static vm_stat_account_t		module_vm_stat_account;
static struct percpu_counter		*module_vm_committed_as;
static int				*module_vm_committed_as_batch;
static __mpol_put_t			module___mpol_put;
static access_remote_vm_t		module_access_remote_vm;
static walk_page_range_t		module_walk_page_range;
static vm_normal_page_t		module_vm_normal_page;
static zap_page_range_single_t	module_zap_page_range_single;

static struct kmem_cache		*page_copy_cache;

static long vma_cherrypick_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg);

static long force_copy_vma_pages(struct mm_struct *src_mm,
				 unsigned long src_start,
				 unsigned long src_end,
				 unsigned long dst_start)
{
	unsigned long off;
	void *kbuf;
	int copied;

	kbuf = kmem_cache_alloc(page_copy_cache, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	for (off = 0; off < src_end - src_start; off += PAGE_SIZE) {
		copied = module_access_remote_vm(src_mm, src_start + off,
						 kbuf, PAGE_SIZE, 0);
		if (copied != PAGE_SIZE)
			memset(kbuf + copied, 0, PAGE_SIZE - copied);

		if (copy_to_user((void __user *)(dst_start + off),
				 kbuf, PAGE_SIZE)) {
			kmem_cache_free(page_copy_cache, kbuf);
			return -EFAULT;
		}
	}

	kmem_cache_free(page_copy_cache, kbuf);
	return 0;
}

struct zap_non_anon_walker {
	unsigned long *file_offsets;
	unsigned long n;
	unsigned long max;
	unsigned long base;
};

static int zap_non_anon_pte_entry(pte_t *pte, unsigned long addr,
				  unsigned long next, struct mm_walk *walk)
{
	struct zap_non_anon_walker *zw = walk->private;
	pte_t entry = ptep_get(pte);
	struct page *page;

	if (!pte_present(entry))
		return 0;

	page = module_vm_normal_page(walk->vma, addr, entry);
	if (!page)
		return 0;
	if (PageAnon(page))
		return 0;

	if (zw->n < zw->max)
		zw->file_offsets[zw->n++] = addr - zw->base;
	return 0;
}

static long zap_non_anon_ptes_range(struct vm_area_struct *new_vma,
				    unsigned long start, unsigned long end)
{
	struct zap_non_anon_walker zw = {
		.base = start,
		.max  = (end - start) >> PAGE_SHIFT,
		.n    = 0,
	};
	struct mm_walk_ops walk_ops = {
		.pte_entry = zap_non_anon_pte_entry,
		.walk_lock = PGWALK_RDLOCK,
	};
	unsigned long i;
	long ret;

	if (zw.max == 0)
		return 0;

	zw.file_offsets = kvmalloc_array(zw.max, sizeof(unsigned long),
					 GFP_KERNEL);
	if (!zw.file_offsets)
		return -ENOMEM;

	ret = module_walk_page_range(new_vma->vm_mm, start, end,
				     &walk_ops, &zw);
	if (ret)
		goto out_free;

	for (i = 0; i < zw.n; i++) {
		unsigned long addr = start + zw.file_offsets[i];
		module_zap_page_range_single(new_vma, addr, PAGE_SIZE, NULL);
	}

	ret = 0;
out_free:
	kvfree(zw.file_offsets);
	return ret;
}

struct copy_anon_walker {
	unsigned long *anon_offsets;
	unsigned long n;
	unsigned long max;
	unsigned long base;
};

static int copy_anon_pte_entry(pte_t *pte, unsigned long addr,
			       unsigned long next, struct mm_walk *walk)
{
	struct copy_anon_walker *cw = walk->private;
	pte_t entry = ptep_get(pte);
	struct page *page;

	if (!pte_present(entry))
		return 0;

	page = module_vm_normal_page(walk->vma, addr, entry);
	if (!page)
		return 0;

	if (PageAnon(page) && cw->n < cw->max)
		cw->anon_offsets[cw->n++] = addr - cw->base;
	return 0;
}

static long copy_anon_vma_pages(struct mm_struct *src_mm,
				struct vm_area_struct *src_vma,
				unsigned long dst_start)
{
	struct copy_anon_walker cw = {
		.base = src_vma->vm_start,
		.max  = (src_vma->vm_end - src_vma->vm_start) >> PAGE_SHIFT,
		.n    = 0,
	};
	struct mm_walk_ops walk_ops = {
		.pte_entry = copy_anon_pte_entry,
		.walk_lock = PGWALK_RDLOCK,
	};
	void *kbuf = NULL;
	long ret = 0;
	unsigned long i;
	int copied;

	if (cw.max == 0)
		return 0;

	cw.anon_offsets = kvmalloc_array(cw.max, sizeof(unsigned long),
					 GFP_KERNEL);
	if (!cw.anon_offsets)
		return -ENOMEM;

	ret = module_walk_page_range(src_mm, src_vma->vm_start,
				     src_vma->vm_end, &walk_ops, &cw);
	if (ret)
		goto out_free;

	if (cw.n == 0)
		goto out_free;

	kbuf = kmem_cache_alloc(page_copy_cache, GFP_KERNEL);
	if (!kbuf) {
		ret = -ENOMEM;
		goto out_free;
	}

	for (i = 0; i < cw.n; i++) {
		unsigned long off = cw.anon_offsets[i];
		unsigned long src_addr = src_vma->vm_start + off;
		unsigned long dst_addr = dst_start + off;
		int written;

		copied = module_access_remote_vm(src_mm, src_addr, kbuf,
						 PAGE_SIZE, 0);
		if (copied != PAGE_SIZE)
			memset(kbuf + copied, 0, PAGE_SIZE - copied);

		written = module_access_remote_vm(current->mm, dst_addr,
						  kbuf, PAGE_SIZE,
						  FOLL_WRITE | FOLL_FORCE);
		if (written != PAGE_SIZE) {
			ret = -EFAULT;
			break;
		}
	}

	kmem_cache_free(page_copy_cache, kbuf);
out_free:
	kvfree(cw.anon_offsets);
	return ret;
}

static const struct file_operations vma_cherrypick_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= vma_cherrypick_ioctl,
};

static struct miscdevice vma_cherrypick_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = KBUILD_MODNAME,
	.fops  = &vma_cherrypick_fops,
	.mode  = 0600,
};

static struct pid *get_target_pid(struct vma_cherrypick_args *args)
{
	struct pid *pid = NULL;
	struct fd f;

	if (args->flags & VMA_CHERRYPICK_FLAG_PIDFD) {
		f = fdget(args->target_id);

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

static long vma_cherrypick_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	struct vma_cherrypick_args kargs;
	struct mm_struct *target_mm;
	struct mm_struct *caller_mm = current->mm;
	struct vm_area_struct *src_vma, *new_vma, *overlap;
	struct task_struct *target_task;
	struct pid *pid;
	struct file *vma_file;
	struct file *clone_file = NULL;
	struct mempolicy *pol;
	struct address_space *mapping;
	unsigned long len, src_end_saved;
	const char *mode;
	bool is_dontcopy, use_clone_file;
	LIST_HEAD(uf);
	VMA_ITERATOR(vmi, caller_mm, 0);
	long ret;
	long charge = 0;

	if (!ns_capable(current_user_ns(), CAP_SYS_ADMIN) &&
	    !ns_capable(current_user_ns(), CAP_CHECKPOINT_RESTORE))
		return -EPERM;
	if (cmd != VMA_CHERRYPICK)
		return -ENOTTY;
	if (copy_from_user(&kargs, (void __user *)arg, sizeof(kargs)))
		return -EFAULT;
	if (kargs.dst_addr != kargs.src_addr)
		return -EINVAL;
	if (kargs.flags & ~VMA_CHERRYPICK_FLAGS_VALID)
		return -EINVAL;

	use_clone_file = !!(kargs.flags & VMA_CHERRYPICK_FLAG_FILE_FD);
	if (use_clone_file) {
		clone_file = fget(kargs.file_fd);
		if (!clone_file)
			return -EBADF;
	}

	pid = get_target_pid(&kargs);
	if (IS_ERR(pid)) {
		if (clone_file)
			fput(clone_file);
		return PTR_ERR(pid);
	}

	rcu_read_lock();
	target_task = pid_task(pid, PIDTYPE_PID);
	if (!target_task || !target_task->mm) {
		rcu_read_unlock();
		ret = -ESRCH;
		goto out_put_pid;
	}
	target_mm = target_task->mm;
	mmget(target_mm);
	rcu_read_unlock();

	if (target_mm == caller_mm) {
		ret = -EINVAL;
		goto out_put_mm;
	}

	mmap_write_lock(target_mm);
	src_vma = find_vma(target_mm, kargs.src_addr);
	if (!src_vma || src_vma->vm_start != kargs.src_addr) {
		ret = -ENOENT;
		goto out_unlock_target;
	}
	if (src_vma->vm_flags & VM_DONTCOPY) {
		if (!(kargs.flags & VMA_CHERRYPICK_FLAG_FORCE_COPY)) {
			ret = -EINVAL;
			goto out_unlock_target;
		}
	}

	if (use_clone_file && !src_vma->vm_file) {
		ret = -EINVAL;
		goto out_unlock_target;
	}

	if (use_clone_file) {
		unsigned long map_addr;
		unsigned long map_pgoff = src_vma->vm_pgoff;
		unsigned long map_len = src_vma->vm_end - src_vma->vm_start;
		unsigned long map_prot = 0;
		unsigned long map_flags = MAP_FIXED;
		bool copy_anon = !!(kargs.flags & VMA_CHERRYPICK_FLAG_COPY_ANON);
		bool file_fd_cow = !!(kargs.flags & VMA_CHERRYPICK_FLAG_FILE_FD_COW);
		long copy_ret;

		if (copy_anon && file_fd_cow) {
			ret = -EINVAL;
			goto out_unlock_target;
		}

		if (src_vma->vm_flags & VM_READ)
			map_prot |= PROT_READ;
		if (src_vma->vm_flags & VM_WRITE)
			map_prot |= PROT_WRITE;
		if (src_vma->vm_flags & VM_EXEC)
			map_prot |= PROT_EXEC;
		if (src_vma->vm_flags & VM_MAYSHARE)
			map_flags |= MAP_SHARED;
		else
			map_flags |= MAP_PRIVATE;

		map_addr = vm_mmap(clone_file, kargs.dst_addr, map_len,
				   map_prot, map_flags,
				   map_pgoff << PAGE_SHIFT);

		if (IS_ERR_VALUE(map_addr)) {
			mmap_write_unlock(target_mm);
			fput(clone_file);
			mmput(target_mm);
			put_pid(pid);
			return (long)map_addr;
		}
		if (map_addr != kargs.dst_addr) {
			mmap_write_unlock(target_mm);
			vm_munmap(map_addr, map_len);
			fput(clone_file);
			mmput(target_mm);
			put_pid(pid);
			return -EEXIST;
		}

		copy_ret = 0;
		if (copy_anon) {
			copy_ret = copy_anon_vma_pages(target_mm, src_vma,
						       kargs.dst_addr);
		} else if (file_fd_cow) {

			struct vm_area_struct *new_vma_local;

			mmap_write_lock(caller_mm);
			new_vma_local = find_vma(caller_mm, kargs.dst_addr);
			if (!new_vma_local ||
			    new_vma_local->vm_start > kargs.dst_addr ||
			    new_vma_local->vm_end < kargs.dst_addr + map_len) {
				mmap_write_unlock(caller_mm);
				copy_ret = -ENOENT;
				goto file_fd_cow_done;
			}
			copy_ret = module_anon_vma_fork(new_vma_local, src_vma);
			if (copy_ret) {
				mmap_write_unlock(caller_mm);
				goto file_fd_cow_done;
			}
			copy_ret = module_copy_page_range(new_vma_local,
							  src_vma);

			mmap_write_downgrade(caller_mm);
			if (copy_ret) {
				mmap_read_unlock(caller_mm);
				goto file_fd_cow_done;
			}
			copy_ret = zap_non_anon_ptes_range(new_vma_local,
							   kargs.dst_addr,
							   kargs.dst_addr +
								   map_len);
			mmap_read_unlock(caller_mm);
		}
file_fd_cow_done:

		mmap_write_unlock(target_mm);
		fput(clone_file);
		mmput(target_mm);
		put_pid(pid);

		if (copy_ret) {
			vm_munmap(map_addr, map_len);
			return copy_ret;
		}

		dev_dbg(vma_cherrypick_dev.this_device,
			"clone_file VMA %lx-%lx from %s %d (fd=%d copy_anon=%d cow=%d)\n",
			(unsigned long)kargs.src_addr,
			(unsigned long)kargs.src_addr + map_len,
			(kargs.flags & VMA_CHERRYPICK_FLAG_PIDFD) ? "pidfd" : "vpid",
			kargs.target_id,
			kargs.file_fd, copy_anon, file_fd_cow);
		return 0;
	}
	mmap_write_lock(caller_mm);

	len = src_vma->vm_end - src_vma->vm_start;
	overlap = find_vma(caller_mm, kargs.dst_addr);
	if (overlap && overlap->vm_start < kargs.dst_addr + len) {
		ret = -EEXIST;
		goto out_unlock_caller;
	}

	if (src_vma->vm_flags & VM_ACCOUNT) {
		charge = vma_pages(src_vma);
		if (module_security_vm_enough_memory_mm(target_mm, charge)) {
			ret = -ENOMEM;
			goto out_unlock_caller;
		}
	}

	new_vma = module_vm_area_dup(src_vma);
	if (!new_vma) {
		ret = -ENOMEM;
		goto err_uncharge;
	}

	ret = module_vma_dup_policy(src_vma, new_vma);
	if (ret)
		goto err_free_vma;

	new_vma->vm_mm = caller_mm;
	ret = module_dup_userfaultfd(new_vma, &uf);
	if (ret)
		goto err_put_policy;


	if ((new_vma->vm_flags & VM_WIPEONFORK) ||
	    (src_vma->vm_flags & VM_DONTCOPY))
		new_vma->anon_vma = NULL;
	else if (module_anon_vma_fork(new_vma, src_vma))
		goto err_anon_vma_fork;

	vm_flags_clear(new_vma, VM_LOCKED_MASK);

	if (is_vm_hugetlb_page(new_vma))
		module_hugetlb_dup_vma_private(new_vma);

	vma_iter_set(&vmi, new_vma->vm_start);
	vma_iter_bulk_store(&vmi, new_vma);
	caller_mm->map_count++;

	if (new_vma->vm_ops && new_vma->vm_ops->open)
		new_vma->vm_ops->open(new_vma);

	vma_file = new_vma->vm_file;
	if (vma_file) {
		get_file(vma_file);
		mapping = vma_file->f_mapping;
		i_mmap_lock_write(mapping);
		if (vma_is_shared_maywrite(new_vma))
			mapping_allow_writable(mapping);
		flush_dcache_mmap_lock(mapping);
		module_vma_interval_tree_insert_after(new_vma, src_vma,
						      &mapping->i_mmap);
		flush_dcache_mmap_unlock(mapping);
		i_mmap_unlock_write(mapping);
	}

	if (!(new_vma->vm_flags & VM_WIPEONFORK) &&
	    !(src_vma->vm_flags & VM_DONTCOPY)) {
		ret = module_copy_page_range(new_vma, src_vma);
		if (ret) {
			pr_err("copy_page_range failed: %ld\n", ret);
			module_vm_stat_account(caller_mm, new_vma->vm_flags,
					       vma_pages(new_vma));
			module_dup_userfaultfd_complete(&uf);
			goto out_unlock_caller;
		}
	}

	module_vm_stat_account(caller_mm, new_vma->vm_flags,
			       vma_pages(new_vma));

	src_end_saved = src_vma->vm_end;
	is_dontcopy = src_vma->vm_flags & VM_DONTCOPY;

	mmap_write_unlock(caller_mm);
	mmap_write_unlock(target_mm);


	if (is_dontcopy ||
	    ((new_vma->vm_flags & VM_WIPEONFORK) &&
	     (kargs.flags & VMA_CHERRYPICK_FLAG_WIPE_COPY))) {
		ret = force_copy_vma_pages(target_mm, kargs.src_addr,
					   src_end_saved, kargs.dst_addr);
		if (ret) {
			module_dup_userfaultfd_complete(&uf);
			mmput(target_mm);
			put_pid(pid);
			return ret;
		}
	}

	module_dup_userfaultfd_complete(&uf);
	mmput(target_mm);
	put_pid(pid);

	mode = "CoW";
	if (is_dontcopy)
		mode = "force-copy (VM_DONTCOPY)";
	else if ((new_vma->vm_flags & VM_WIPEONFORK) &&
		 (kargs.flags & VMA_CHERRYPICK_FLAG_WIPE_COPY))
		mode = "force-copy (VM_WIPEONFORK)";

	dev_dbg(vma_cherrypick_dev.this_device,
		"%s VMA %lx-%lx from %s %d\n",
		mode,
		(unsigned long)kargs.src_addr,
		(unsigned long)src_end_saved,
		(kargs.flags & VMA_CHERRYPICK_FLAG_PIDFD) ? "pidfd" : "vpid",
		kargs.target_id);

	return 0;

err_anon_vma_fork:
	module_dup_userfaultfd_fail(&uf);
err_put_policy:
	pol = vma_policy(new_vma);
	if (pol)
		module___mpol_put(pol);
err_free_vma:
	module_vm_area_free(new_vma);
err_uncharge:
	if (charge)
		percpu_counter_add_batch(module_vm_committed_as,
					 -charge,
					 *module_vm_committed_as_batch);
out_unlock_caller:
	mmap_write_unlock(caller_mm);
out_unlock_target:
	mmap_write_unlock(target_mm);
out_put_mm:
	mmput(target_mm);
out_put_pid:
	put_pid(pid);
	if (clone_file)
		fput(clone_file);
	return ret;
}

static int resolve_symbols(void)
{
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_pidfd_pid, "pidfd_pid")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_vm_area_dup, "vm_area_dup")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_vm_area_free, "vm_area_free")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_anon_vma_fork, "anon_vma_fork")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_copy_page_range, "copy_page_range")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_vma_dup_policy, "vma_dup_policy")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_dup_userfaultfd, "dup_userfaultfd")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_dup_userfaultfd_complete,
					  "dup_userfaultfd_complete")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_dup_userfaultfd_fail,
					  "dup_userfaultfd_fail")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_hugetlb_dup_vma_private,
					  "hugetlb_dup_vma_private")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_security_vm_enough_memory_mm,
					  "security_vm_enough_memory_mm")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_vma_interval_tree_insert_after,
					  "vma_interval_tree_insert_after")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_vm_stat_account,
					  "vm_stat_account")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_vm_committed_as,
					  "vm_committed_as")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_vm_committed_as_batch,
					  "vm_committed_as_batch")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module___mpol_put, "__mpol_put")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_access_remote_vm,
					  "access_remote_vm")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_walk_page_range,
					  "walk_page_range")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_vm_normal_page,
					  "vm_normal_page")))
		return -ENOSYS;
	if (IS_ERR_OR_NULL(RESOLVE_SYMBOL(module_zap_page_range_single,
					  "zap_page_range_single")))
		return -ENOSYS;

	return 0;
}

static int __init vma_cherrypick_init(void)
{
	int ret;

	ret = get_kallsyms_lookup_name_fn();
	if (ret) {
		pr_err("Failed to initialize kallsyms\n");
		return ret;
	}

	ret = resolve_symbols();
	if (ret)
		return ret;

	page_copy_cache = kmem_cache_create("vma_cherrypick_page",
					    PAGE_SIZE, PAGE_SIZE, 0, NULL);
	if (!page_copy_cache)
		return -ENOMEM;

	ret = misc_register(&vma_cherrypick_dev);
	if (ret) {
		pr_err("Failed to register misc device\n");
		kmem_cache_destroy(page_copy_cache);
		return ret;
	}

	pr_info("Module loaded. /dev/%s ready.\n", vma_cherrypick_dev.name);
	return 0;
}

static void __exit vma_cherrypick_exit(void)
{
	misc_deregister(&vma_cherrypick_dev);
	kmem_cache_destroy(page_copy_cache);
	pr_info("/dev/%s unloaded.\n", vma_cherrypick_dev.name);
}

module_init(vma_cherrypick_init);
module_exit(vma_cherrypick_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Per-VMA copy-on-write from a frozen target process");
