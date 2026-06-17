#ifndef _UAPI_ADOPTME_H
#define _UAPI_ADOPTME_H

#define REPARENT_DEV "/dev/reparent"

#define REPARENT_MAGIC 'R'
#define REPARENT_ME_CMD _IOW(REPARENT_MAGIC, 1, int)
#define FORCE_SET_PIDNS_CMD _IOW(REPARENT_MAGIC, 2, int)

struct reparent_task_arg {
	int target_pidfd;
	int new_parent_pidfd;
};

#define REPARENT_TASK_CMD _IOW(REPARENT_MAGIC, 3, struct reparent_task_arg)

#endif
