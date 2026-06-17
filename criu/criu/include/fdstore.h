#ifndef __CRIU_FDSTORE_H__
#define __CRIU_FDSTORE_H__

/*
 * fdstore is a storage for file descriptors which is shared
 * between processes.
 *
 * tfork-N caveat: each tfork copy creates its own fdstore queue
 * post-fan-out (fdstore_init runs per-copy inside cr_restore_tasks).
 * Auto-incremented ids returned by fdstore_add are therefore
 * per-copy and order-dependent.  Storage fields that live in
 * shared-across-copies memory (e.g. nsid->mnt.nsfd_id) get the
 * last-writer-wins value, so a reader copy may read its own
 * queue at the wrong slot.  Use fdstore_add_at(fd, canonical_id)
 * to write a content-keyed id (computed from purpose + image
 * discriminator) — all copies then store the same value and each
 * resolves to its own fd at that canonical id.
 */

int fdstore_init(void);

/* Add a file descriptor to the storage and return its id */
int fdstore_add(int fd);

int fdstore_add_at(int fd, int canonical_id);

int fdstore_get(int id);

enum fdstore_purpose {
	FDSTORE_P_AUTO         = 0x00,
	FDSTORE_P_INHERIT      = 0x01,
	FDSTORE_P_MEMFD        = 0x02,
	FDSTORE_P_MNT_FD       = 0x03,
	FDSTORE_P_MP_FD        = 0x04,
	FDSTORE_P_MNTNS_NSFD   = 0x05,
	FDSTORE_P_MNTNS_ROOT   = 0x06,
	FDSTORE_P_NETNS_NSFD   = 0x07,
	FDSTORE_P_UNIX_SK      = 0x08,
	FDSTORE_P_SELF_STDIN   = 0x09,
	FDSTORE_P_TTY          = 0x0A,
	FDSTORE_P_LAZY_PAGES   = 0x0B,
};

#define FDSTORE_CANONICAL_ID(purpose, disc) \
	((int)((((unsigned)(purpose)) << 24) | ((unsigned)(disc) & 0xffffffu)))

#endif
