#ifndef __CR_ASM_DUMP_H__
#define __CR_ASM_DUMP_H__

extern int save_task_regs(pid_t pid, void *, user_regs_struct_t *, user_fpregs_struct_t *);
extern int arch_alloc_thread_info(CoreEntry *core);
extern void arch_free_thread_info(CoreEntry *core);
extern int get_task_futex_robust_list_compat(pid_t pid, ThreadCoreEntry *info);

static inline int arch_dump_mm_pkey_state(pid_t pid, CoreEntry *core) { return 0; }
static inline int arch_restore_mm_pkey_state(pid_t pid, CoreEntry *core) { return 0; }

static inline void core_put_tls(CoreEntry *core, tls_t tls)
{
	core->ti_mips->tls = tls;
}

#endif
