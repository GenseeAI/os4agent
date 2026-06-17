#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kprobes.h>
#include "reparent.h"

#ifndef CONFIG_KPROBES
#error "Compilation aborted: This module requires CONFIG_KPROBES to be enabled in the target kernel."
#endif

#ifndef CONFIG_KALLSYMS_ALL
#error "Compilation aborted: This module requires CONFIG_KALLSYMS_ALL to be enabled in the target kernel."
#endif

static kallsyms_lookup_name_t kallsyms_lookup_name_fn;

int get_kallsyms_lookup_name_fn(void)
{
    int ret;
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("Failed to register kprobe, returned %d\n", ret);
        return ret;
    }

    kallsyms_lookup_name_fn = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    pr_info("kallsyms_lookup_name found at address: 0x%p\n", kallsyms_lookup_name_fn);
    return 0;
}

void put_kallsyms_lookup_name_fn(void)
{
    kallsyms_lookup_name_fn = NULL;
}

unsigned long module_kallsyms_lookup_name(const char *name)
{
    if (!kallsyms_lookup_name_fn) {
        pr_err("kallsyms_lookup_name function pointer is not initialized!\n");
        return 0;
    }
    return kallsyms_lookup_name_fn(name);
}
