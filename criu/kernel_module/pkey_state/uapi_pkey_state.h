#ifndef UAPI_PKEY_STATE_H
#define UAPI_PKEY_STATE_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define PKEY_STATE_FLAG_VPID  (0)
#define PKEY_STATE_FLAG_PIDFD (1)

struct pkey_state_args {
	int   target_id;
	int   flags;
	__u32 pkey_allocation_map;
	__s32 execute_only_pkey;
};

#define PKEY_STATE_MAGIC 'P'
#define PKEY_STATE_GET _IOWR(PKEY_STATE_MAGIC, 1, struct pkey_state_args)
#define PKEY_STATE_SET _IOW (PKEY_STATE_MAGIC, 2, struct pkey_state_args)

#endif
