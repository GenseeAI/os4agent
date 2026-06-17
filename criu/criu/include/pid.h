#ifndef __CR_PID_H__
#define __CR_PID_H__

#include <compel/task-state.h>
#include <compel/infect.h>
#include "log.h"
#include "common/bug.h"
#include "stdbool.h"
#include "rbtree.h"

/*
 * Task states, used in e.g. struct pid's state.
 */
enum __criu_task_state {
	/* Values shared with compel */
	TASK_ALIVE = COMPEL_TASK_ALIVE,
	TASK_DEAD = COMPEL_TASK_DEAD,
	TASK_STOPPED = COMPEL_TASK_STOPPED,
	TASK_ZOMBIE = COMPEL_TASK_ZOMBIE,
	/* Own internal states */
	TASK_HELPER = COMPEL_TASK_MAX + 1,
	TASK_THREAD,
	/* new values are to be added before this line */
	TASK_UNDEF = 0xff
};

struct pid {
	struct pstree_item *item;
	/*
	 * The @real pid is used to fetch tasks during dumping stage,
	 * This is a real pid seen from the context where the dumping
	 * is running.
	 */
	pid_t real;
	pid_t local;
	int uid;

	int state; /* TASK_XXX constants */
	/* If an item is in stopped state it has a signal number
	 * that caused task to stop.
	 */
	int stop_signo;

	int ns_level;
	int leaf_ns_id;
	struct rb_node leaf_ns_node;
	struct rb_node root_ns_node;
	struct rb_node uid_node;
	/*
	 * The @virt pid is one which used in the image itself and keeps
	 * the pid value to be restored. This pid fetched from the
	 * dumpee context, because the dumpee might have own pid namespace.
	 * 
	 * in nested pid namespace, this field is used for clone3 set_tid,
	 * 0 has inner most level, ns_level - 1 has outer most level
	 */
	struct pid_ns ns[MAX_PID_NS_LEVEL];
};

static inline pid_t pid_get_uid(const struct pid *pid)
{
	BUG_ON(pid->uid == 0);
	return pid->uid;
}

/*
 * When we have to restore a shared resource, we mush select which
 * task should do it, and make other(s) wait for it. In order to
 * avoid deadlocks, always make task with lower pid be the restorer.
 */
static inline bool pid_rst_prio(unsigned pid_a, unsigned pid_b)
{
	return pid_a < pid_b;
}

static inline bool pid_rst_prio_eq(unsigned pid_a, unsigned pid_b)
{
	return pid_a <= pid_b;
}

#endif /* __CR_PID_H__ */
