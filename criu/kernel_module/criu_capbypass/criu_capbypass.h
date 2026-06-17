#ifndef _CRIU_CAPBYPASS_H
#define _CRIU_CAPBYPASS_H

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/pid.h>

#ifndef CONFIG_KPROBES
#error "Compilation aborted: This module requires CONFIG_KPROBES to be enabled in the target kernel."
#endif

#ifndef CONFIG_KALLSYMS_ALL
#error "Compilation aborted: This module requires CONFIG_KALLSYMS_ALL to be enabled in the target kernel."
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 0, 0)
#error "Compile failed: " KBUILD_MODNAME " requires Linux 7.0+"
#endif

#ifndef CONFIG_X86_64
#error "Compile failed: " KBUILD_MODNAME " is strictly bound to x86_64 for v1."
#endif

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

int get_kallsyms_lookup_name_fn(void);
unsigned long module_kallsyms_lookup_name(const char *name);

#define RESOLVE_SYMBOL(fn_ptr, symbol_name)				\
	({								\
		unsigned long addr = module_kallsyms_lookup_name(symbol_name); \
		if (IS_ERR_OR_NULL((void *)addr)) {			\
			pr_err("Failed to find %s address!\n", symbol_name); \
		} else {						\
			pr_info("Found %s at address 0x%p\n", symbol_name, (void *)addr); \
			(fn_ptr) = (typeof(fn_ptr))addr;		\
		}							\
		(void *)addr;						\
	})

#endif
