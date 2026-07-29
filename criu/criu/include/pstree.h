#ifndef __CR_PSTREE_H__
#define __CR_PSTREE_H__

#include "common/list.h"
#include "common/lock.h"
#include "atomic.h"
#include "pid.h"
#include "xmalloc.h"
#include "images/core.pb-c.h"

/*
 * That's the init process which usually inherit
 * all orphaned children in the system.
 */
#define INIT_PID (1)
#define ALL_PID_NS_ID (0)

#define OPT_KEEP_PID_HIERARCHY "keep-pid-hierarchy"
extern atomic_t pid_uid_generator;

#define HELPER_UID_BASE (0x40000000)

static inline void pid_init_dump(struct pid *pid, struct pstree_item *item)
{
	*pid = (struct pid){
		.item = item,
		.real = -1,
		.local = -1,
		.uid = atomic_inc_return(&pid_uid_generator),
		.state = TASK_UNDEF,
		.stop_signo = -1,
		.ns_level = -1,
		.leaf_ns_id = ALL_PID_NS_ID,
	};
	rb_init_node(&pid->leaf_ns_node);
	rb_init_node(&pid->root_ns_node);
	rb_init_node(&pid->uid_node);
}

struct pstree_item {
	struct pstree_item *parent;
	struct list_head children; /* list of my children */
	struct list_head sibling;  /* linkage in my parent's children list */

	struct pid *pid;
	pid_t pgid;
	pid_t sid;
	pid_t born_sid;

	int nr_threads;	     /* number of threads */
	struct pid *threads; /* array of threads */
	CoreEntry **core;
	TaskKobjIdsEntry *ids;
	union {
		futex_t task_st;
		unsigned long task_st_le_bits;
	};

	int tfork_pidfd;
	int tfork_memfd;
	int tfork_pagemap_fd;
};

static inline pid_t localpid(const struct pstree_item *i)
{
	return i->pid->local;
}

static inline pid_t realpid(const struct pstree_item *i)
{
	return i->pid->real;
}

static inline pid_t uid(const struct pstree_item *i)
{
	return pid_get_uid(i->pid);
}

enum {
	FDS_EVENT_BIT = 0,
};
#define FDS_EVENT (1 << FDS_EVENT_BIT)

extern struct pstree_item *current;

struct rst_info;
/* See alloc_pstree_item() for details */
static inline struct rst_info *rsti(struct pstree_item *i)
{
	return (struct rst_info *)(i + 1);
}

struct thread_lsm {
	char *profile;
	char *sockcreate;
};

struct ns_id;
struct dmp_info {
	struct ns_id *netns;
	struct page_pipe *mem_pp;
	struct parasite_ctl *parasite_ctl;
	struct parasite_thread_ctl **thread_ctls;
	uint64_t *thread_sp;
	struct criu_rseq_cs *thread_rseq_cs;

	/*
	 * Although we don't support dumping different struct creds in general,
	 * we do for threads. Let's keep track of their profiles here; a NULL
	 * entry means there was no LSM profile for this thread.
	 */
	struct thread_lsm **thread_lsms;
};

static inline struct dmp_info *dmpi(const struct pstree_item *i)
{
	return (struct dmp_info *)(i + 1);
}

/* ids is allocated and initialized for all alive tasks */
static inline int shared_fdtable(struct pstree_item *item)
{
	return (item->parent && item->ids->files_id == item->parent->ids->files_id);
}

static inline bool is_alive_state(int state)
{
	return (state == TASK_ALIVE) || (state == TASK_STOPPED);
}

static inline bool task_alive(struct pstree_item *i)
{
	return is_alive_state(i->pid->state);
}

extern void free_pstree(struct pstree_item *root_item);
extern struct pstree_item *__alloc_pstree_item(bool rst);
#define alloc_pstree_item() __alloc_pstree_item(false)
extern int init_pstree_helper(struct pstree_item *ret);

extern int pstree_insert_pid(struct pid *pid_node);
extern struct pstree_item *get_or_create_helper_item(struct pstree_item *item, pid_t pid);

extern struct pstree_item *root_item;
extern bool has_children(struct pstree_item *item);
extern struct pstree_item *pstree_item_next(struct pstree_item *item);
#define for_each_pstree_item(pi) for (pi = root_item; pi != NULL; pi = pstree_item_next(pi))

extern bool restore_before_setsid(struct pstree_item *child);
extern int prepare_pstree(void);
extern int prepare_dummy_pstree(void);
extern int pstree_get_total_size(void);

extern int dump_pstree(struct pstree_item *root_item);

struct pstree_item *pstree_item_by_pid_ns(int pidns_id, pid_t pid_in_ns);
struct pstree_item *pstree_item_by_real(pid_t global_pid);
struct pstree_item *pstree_item_by_local(void);
struct pstree_item *pstree_item_by_uid(int uid);

extern int pid_real_to_local(pid_t pid);

struct task_entries;
extern struct task_entries *task_entries;
extern int prepare_task_entries(void);
extern int prepare_dummy_task_state(struct pstree_item *pi);

extern int get_task_ids(struct pstree_item *);
extern unsigned long get_clone_mask(TaskKobjIdsEntry *i, TaskKobjIdsEntry *p);
extern TaskKobjIdsEntry *root_ids;

extern void core_entry_free(CoreEntry *core);
extern CoreEntry *core_entry_alloc(int alloc_thread_info, int alloc_tc);
extern int pstree_alloc_cores(struct pstree_item *item);
extern void pstree_free_cores(struct pstree_item *item);

extern int collect_pstree_ids(void);

extern int preorder_pstree_traversal(struct pstree_item *item, int (*f)(struct pstree_item *));
#endif /* __CR_PSTREE_H__ */
