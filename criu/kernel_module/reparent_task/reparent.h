#ifndef _REPARENT_TASK_H

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <linux/nsproxy.h>
#include <linux/perf_event.h>

#ifndef CONFIG_KPROBES
#error "Compilation aborted: This module requires CONFIG_KPROBES to be enabled in the target kernel."
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 0, 0)
#error "Compile failed: " KBUILD_MODNAME " requires Linux 7.0+"
#endif

#ifndef CONFIG_KALLSYMS_ALL
#error "Compilation aborted: This module requires CONFIG_KALLSYMS_ALL to be enabled in the target kernel."
#endif

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef struct task_struct *(*pidfd_get_task_t)(int pidfd, unsigned int *flags);
typedef void (*free_pids_t)(struct pid **pids);
typedef struct pid *(*pidfd_pid_t)(const struct file *file);
typedef struct nsproxy *(*create_new_namespaces_t)(u64 flags, struct task_struct *tsk,
    struct user_namespace *user_ns, struct fs_struct *new_fs);
typedef struct nsproxy *(*create_new_namespaces_t)(u64 flags, struct task_struct *tsk,
    struct user_namespace *user_ns, struct fs_struct *new_fs);
typedef int (*switch_task_namespaces_t)(struct task_struct *task, struct nsproxy *new_nsproxy);
typedef void (*put_nsset_t)(struct nsset *nsset);
typedef void (*deactivate_nsproxy_t)(struct nsproxy *ns);
typedef void (*perf_event_namespaces_t)(struct task_struct *tsk);
typedef bool (*ptrace_may_access_t)(struct task_struct *task, unsigned int mode);
typedef void (*change_pid_t)(struct pid **pids, struct task_struct *task,
        enum pid_type type, struct pid *pid);

int get_kallsyms_lookup_name_fn(void);
void put_kallsyms_lookup_name_fn(void);
unsigned long module_kallsyms_lookup_name(const char *name);
#define RESOLVE_SYMBOL(fn_ptr, symbol_name)                                 \
    ({                                                                      \
        unsigned long addr = module_kallsyms_lookup_name(symbol_name);      \
        if (IS_ERR_OR_NULL((void *)addr)) {                                 \
            pr_err("Failed to find %s address!\n", symbol_name);            \
        } else {                                                            \
            pr_info("Found %s at address 0x%p\n", symbol_name, (void *)addr);      \
            (fn_ptr) = (typeof(fn_ptr))addr;                                \
        }                                                                   \
        (void *)addr;                                                       \
    })

#endif
