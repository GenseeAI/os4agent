#ifndef _VMA_CHERRYPICK_H
#define _VMA_CHERRYPICK_H

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/rbtree.h>
#include <linux/userfaultfd_k.h>
#include <linux/hugetlb.h>
#include <linux/percpu_counter.h>
#include <linux/pagewalk.h>

#ifndef CONFIG_KPROBES
#error "This module requires CONFIG_KPROBES"
#endif

#ifndef CONFIG_KALLSYMS_ALL
#error "This module requires CONFIG_KALLSYMS_ALL"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 0, 0)
#error "Compile failed: " KBUILD_MODNAME " requires Linux 7.0+"
#endif

#ifndef CONFIG_X86_64
#error KBUILD_MODNAME " requires x86_64"
#endif

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
int get_kallsyms_lookup_name_fn(void);
unsigned long module_kallsyms_lookup_name(const char *name);

#define RESOLVE_SYMBOL(fn_ptr, symbol_name)				\
    ({									\
	unsigned long addr = module_kallsyms_lookup_name(symbol_name);	\
	if (IS_ERR_OR_NULL((void *)addr)) {				\
	    pr_err("Failed to find %s\n", symbol_name);			\
	} else {							\
	    pr_info("Found %s at 0x%p\n", symbol_name, (void *)addr);	\
	    (fn_ptr) = (typeof(fn_ptr))addr;				\
	}								\
	(void *)addr;							\
    })

typedef struct pid *(*pidfd_pid_t)(const struct file *file);
typedef struct vm_area_struct *(*vm_area_dup_t)(struct vm_area_struct *);
typedef void (*vm_area_free_t)(struct vm_area_struct *);
typedef int (*anon_vma_fork_t)(struct vm_area_struct *,
			       struct vm_area_struct *);
typedef int (*copy_page_range_t)(struct vm_area_struct *,
				 struct vm_area_struct *);
typedef int (*vma_dup_policy_t)(struct vm_area_struct *,
				struct vm_area_struct *);
typedef int (*dup_userfaultfd_t)(struct vm_area_struct *,
				 struct list_head *);
typedef void (*dup_userfaultfd_complete_t)(struct list_head *);
typedef void (*dup_userfaultfd_fail_t)(struct list_head *);
typedef void (*hugetlb_dup_vma_private_t)(struct vm_area_struct *);
typedef int (*security_vm_enough_memory_mm_t)(struct mm_struct *, long);
typedef void (*vma_interval_tree_insert_after_t)(
    struct vm_area_struct *, struct vm_area_struct *,
    struct rb_root_cached *);
typedef void (*vm_stat_account_t)(struct mm_struct *, vm_flags_t, long);
typedef void (*__mpol_put_t)(struct mempolicy *);
typedef int (*access_remote_vm_t)(struct mm_struct *, unsigned long,
				  void *, int, unsigned int);
typedef int (*walk_page_range_t)(struct mm_struct *, unsigned long,
				 unsigned long, const struct mm_walk_ops *,
				 void *);
typedef struct page *(*vm_normal_page_t)(struct vm_area_struct *,
					 unsigned long, pte_t);
typedef void (*zap_page_range_single_t)(struct vm_area_struct *,
					unsigned long, unsigned long,
					struct zap_details *);

#endif
