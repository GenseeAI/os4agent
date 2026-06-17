#ifndef UAPI_CRIU_CAPBYPASS_H
#define UAPI_CRIU_CAPBYPASS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define CRIU_CAPBYPASS_MAGIC 'R'


struct criu_capbypass_args {
	__s32  target_id;
	__u32  flags;
	__u64  cap_mask;
	__u32  syscall_mask;
	__u32  _reserved;
};


#define CRIU_CB_TARGET_VPID	(0u << 0)
#define CRIU_CB_TARGET_PIDFD	(1u << 0)

#define CRIU_CB_INHERIT_DEPRECATED	(1u << 1)


#ifndef CAP_CHECKPOINT_RESTORE
# define CAP_CHECKPOINT_RESTORE 40
#endif
#define CRIU_CB_DEFAULT_CAPS				\
	((1ULL << 21)         | \
	 (1ULL << CAP_CHECKPOINT_RESTORE)             | \
	 (1ULL << 24)         | \
	 (1ULL <<  1)         | \
	 (1ULL <<  2)       | \
	 (1ULL << 18)         | \
	 (1ULL << 19))


#define CRIU_CB_SC_CLONE	(1u << 0)
#define CRIU_CB_SC_SETNS	(1u << 1)
#define CRIU_CB_SC_UNSHARE	(1u << 2)
#define CRIU_CB_SC_MOUNT	(1u << 3)

#define CRIU_CB_SC_FS		(1u << 4)

#define CRIU_CB_SC_RESTORE_DEFAULT				\
	(CRIU_CB_SC_CLONE | CRIU_CB_SC_SETNS |			\
	 CRIU_CB_SC_UNSHARE | CRIU_CB_SC_MOUNT |		\
	 CRIU_CB_SC_FS)

#define CRIU_CB_GRANT	_IOW(CRIU_CAPBYPASS_MAGIC, 1, struct criu_capbypass_args)
#define CRIU_CB_REVOKE	_IOW(CRIU_CAPBYPASS_MAGIC, 2, struct criu_capbypass_args)

#endif
