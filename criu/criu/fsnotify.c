#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <utime.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <linux/magic.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <aio.h>

#include <sys/fanotify.h>

#include "common/compiler.h"
#include "imgset.h"
#include "fsnotify.h"
#include "fdinfo.h"
#include "mount.h"
#include "filesystems.h"
#include "image.h"
#include "util.h"
#include "crtools.h"
#include "files.h"
#include "files-reg.h"
#include "file-ids.h"
#include "criu-log.h"
#include "kerndat.h"
#include "common/list.h"
#include "common/lock.h"
#include "irmap.h"
#include "cr_options.h"
#include "namespaces.h"
#include "pstree.h"
#include "fault-injection.h"
#include <compel/plugins/std/syscall-codes.h>

#include "protobuf.h"
#include "images/fsnotify.pb-c.h"
#include "images/mnt.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "fsnotify: "

struct fsnotify_mark_info {
	struct list_head list;
	union {
		InotifyWdEntry *iwe;
		FanotifyMarkEntry *fme;
	};
	struct pprep_head prep; /* XXX union with remap */
	struct file_remap *remap;
};

struct watched_inode {
	struct list_head list;
	unsigned int s_dev;
	unsigned long i_ino;
};
static LIST_HEAD(watched_inodes);

static void track_watched_inode(unsigned int s_dev, unsigned long i_ino)
{
	struct watched_inode *w;

	if (!opts.tfork.active)
		return;
	list_for_each_entry(w, &watched_inodes, list)
		if (w->s_dev == s_dev && w->i_ino == i_ino)
			return;
	w = xmalloc(sizeof(*w));
	if (!w)
		return;
	w->s_dev = s_dev;
	w->i_ino = i_ino;
	list_add(&w->list, &watched_inodes);
}

bool tfork_inode_has_watch(unsigned int s_dev, unsigned long i_ino)
{
	struct watched_inode *w;

	list_for_each_entry(w, &watched_inodes, list)
		if (w->s_dev == s_dev && w->i_ino == i_ino)
			return true;
	return false;
}

struct fsnotify_file_info {
	union {
		InotifyFileEntry *ife;
		FanotifyFileEntry *ffe;
	};
	struct list_head marks;
	struct file_desc d;
};

struct nodecode_sdev {
	unsigned int s_dev;
	struct nodecode_sdev *next;
};
static struct nodecode_sdev *nodecode_sdev_head;

static bool nodecode_sdev_seen(unsigned int s_dev)
{
	struct nodecode_sdev *e;

	for (e = nodecode_sdev_head; e; e = e->next)
		if (e->s_dev == s_dev)
			return true;
	return false;
}

static int nodecode_sdev_register(unsigned int s_dev)
{
	struct nodecode_sdev *e;
	struct mount_info *m;
	const char *p;
	char *path;

	if (nodecode_sdev_seen(s_dev))
		return 0;

	m = lookup_mnt_sdev(s_dev);
	if (!m) {
		pr_warn("No mount found for s_dev %#x; can't auto-register irmap scan\n", s_dev);
		return -1;
	}

	if (m->fstype->code == FSTYPE__TMPFS || m->fstype->code == FSTYPE__DEVTMPFS)
		return -1;

	if (!m->ns_mountpoint || m->ns_mountpoint[0] == '\0') {
		pr_warn("Mount for s_dev %#x has empty ns_mountpoint\n", s_dev);
		return -1;
	}

	p = m->ns_mountpoint;
	if (p[0] == '.')
		p++;
	if (p[0] != '/') {
		pr_warn("ns_mountpoint %s for s_dev %#x doesn't fit the irmap path convention\n", m->ns_mountpoint,
			s_dev);
		return -1;
	}

	if (p[1] == '\0')
		p = "/.";

	path = xstrdup(p);
	if (!path)
		return -1;

	if (irmap_scan_path_add(path)) {
		xfree(path);
		return -1;
	}
	xfree(path);

	e = xmalloc(sizeof(*e));
	if (!e)
		return -1;
	e->s_dev = s_dev;
	e->next = nodecode_sdev_head;
	nodecode_sdev_head = e;

	pr_info("Auto-registered irmap scan root for s_dev %#x: %s "
		"(no-decode export ops, e.g. overlayfs index=off)\n",
		s_dev, m->ns_mountpoint);
	return 0;
}

/* File handle */
typedef struct {
	u32 bytes;
	u32 type;
	u64 __handle[16];
} fh_t;

/* Checks if file descriptor @lfd is inotify */
int is_inotify_link(char *link)
{
	return is_anon_link_type(link, "inotify");
}

/* Checks if file descriptor @lfd is fanotify */
int is_fanotify_link(char *link)
{
	return is_anon_link_type(link, "[fanotify]");
}

static void decode_handle(fh_t *handle, FhEntry *img)
{
	memzero(handle, sizeof(*handle));

	handle->type = img->type;
	handle->bytes = img->bytes;

	memcpy(handle->__handle, img->handle, min(pb_repeated_size(img, handle), sizeof(handle->__handle)));
}

static int open_by_handle(void *arg, int fd, int pid)
{
	return syscall(__NR_open_by_handle_at, fd, arg, O_PATH);
}

enum { ERR_NO_MOUNT = -1, ERR_NO_PATH_IN_MOUNT = -2, ERR_GENERIC = -3 };

static int anon_dentry_lookup_path(struct ns_id *nsid, unsigned long i_ino,
				   char *out_rel, size_t out_rel_size)
{
#define ADL_MAX_DEPTH 12
#define ADL_MAX_NODES 200000

	struct adl_node {
		int fd;
		char path[1024];
		int depth;
	};
	struct adl_node *queue;
	int q_head = 0, q_tail = 0, q_cap = 1024;
	int nodes_walked = 0;
	struct stat root_st;
	int mntns_root, found = -1;
	char proc_path[64];

	mntns_root = mntns_get_root_fd(nsid);
	if (mntns_root < 0)
		return -1;

	if (fstat(mntns_root, &root_st) < 0)
		return -1;

	if (root_st.st_ino == i_ino) {
		if (out_rel_size < 2)
			return -1;
		out_rel[0] = '.';
		out_rel[1] = '\0';
		return 0;
	}

	queue = xmalloc(q_cap * sizeof(*queue));
	if (!queue)
		return -1;

	snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", mntns_root);
	queue[q_tail].fd = open(proc_path, O_RDONLY | O_DIRECTORY);
	queue[q_tail].path[0] = '\0';
	queue[q_tail].depth = 0;
	if (queue[q_tail].fd < 0) {
		pr_warn("fsnotify: anon dentry walk: can't reopen mntns_root fd %d as O_RDONLY|DIR: %s\n",
			mntns_root, strerror(errno));
		xfree(queue);
		return -1;
	}
	q_tail++;

	while (q_head < q_tail) {
		struct adl_node cur = queue[q_head++];
		DIR *dir;
		struct dirent *de;

		nodes_walked++;
		if (nodes_walked > ADL_MAX_NODES) {
			close(cur.fd);
			break;
		}

		dir = fdopendir(cur.fd);
		if (!dir) {
			close(cur.fd);
			continue;
		}

		while ((de = readdir(dir)) != NULL) {
			struct stat st;
			int child_fd;
			int wrote;

			if (de->d_name[0] == '.')
				continue;
			if (cur.depth == 0) {

				if (!strcmp(de->d_name, "proc") ||
				    !strcmp(de->d_name, "sys") ||
				    !strcmp(de->d_name, "dev") ||
				    !strcmp(de->d_name, "tmp") ||
				    !strcmp(de->d_name, "run") ||
				    !strcmp(de->d_name, "config"))
					continue;
			}

			if (fstatat(dirfd(dir), de->d_name, &st,
				    AT_SYMLINK_NOFOLLOW) < 0)
				continue;

			if (st.st_dev != root_st.st_dev)
				continue;

			if (st.st_ino == i_ino) {
				size_t n;
				if (cur.path[0] == '\0')
					n = snprintf(out_rel, out_rel_size, "%s",
						     de->d_name);
				else
					n = snprintf(out_rel, out_rel_size,
						     "%s/%s", cur.path,
						     de->d_name);
				if (n < out_rel_size) {
					found = 0;
					goto out_close;
				}
			}

			if (!S_ISDIR(st.st_mode))
				continue;
			if (cur.depth + 1 >= ADL_MAX_DEPTH)
				continue;

			child_fd = openat(dirfd(dir), de->d_name,
					  O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
			if (child_fd < 0)
				continue;

			if (q_tail >= q_cap) {
				int new_cap = q_cap * 2;
				struct adl_node *new_q;
				new_q = xrealloc(queue,
						 new_cap * sizeof(*queue));
				if (!new_q) {
					close(child_fd);
					continue;
				}
				queue = new_q;
				q_cap = new_cap;
			}
			queue[q_tail].fd = child_fd;
			if (cur.path[0] == '\0')
				wrote = snprintf(queue[q_tail].path,
						 sizeof(queue[q_tail].path),
						 "%s", de->d_name);
			else
				wrote = snprintf(queue[q_tail].path,
						 sizeof(queue[q_tail].path),
						 "%s/%s", cur.path, de->d_name);
			if (wrote < 0 ||
			    (size_t)wrote >= sizeof(queue[q_tail].path)) {
				close(child_fd);
				continue;
			}
			queue[q_tail].depth = cur.depth + 1;
			q_tail++;
		}

out_close:
		closedir(dir);
		if (found == 0)
			break;
	}

	while (q_head < q_tail)
		close(queue[q_head++].fd);
	xfree(queue);

	return found;
#undef ADL_MAX_DEPTH
#undef ADL_MAX_NODES
}

static char *alloc_openable(unsigned int s_dev, unsigned long i_ino, FhEntry *f_handle)
{
	struct mount_info *m;
	fh_t handle;
	int fd = -1;
	char *path;
	char suitable_mount_found = 0;

	decode_handle(&handle, f_handle);

	/*
	 * We gonna try to open the handle and then
	 * depending on command line options and type
	 * of the filesystem (tmpfs/devtmpfs do not
	 * preserve their inodes between mounts) we
	 * might need to find out an openable path
	 * get used on restore as a watch destination.
	 */
	for (m = mntinfo; m; m = m->next) {
		char buf[PATH_MAX], *__path;
		int mntfd, openable_fd;
		struct stat st;

		if (m->s_dev != s_dev)
			continue;
		if (!mnt_is_dir(m))
			continue;

		mntfd = __open_mountpoint(m);
		pr_debug("\t\tTrying via mntid %d root %s ns_mountpoint @%s (%d)\n", m->mnt_id, m->root,
			 m->ns_mountpoint, mntfd);
		if (mntfd < 0)
			continue;

		fd = userns_call(open_by_handle, UNS_FDOUT, &handle, sizeof(handle), mntfd);
		close(mntfd);
		if (fd < 0)
			continue;
		suitable_mount_found = 1;

		if (read_fd_link(fd, buf, sizeof(buf)) < 0) {
			close(fd);
			goto err;
		}
		pr_warn("debug path for handle %x:%lx is %s\n", s_dev, i_ino, buf);

		if (buf[0] == '/' && buf[1] == '\0') {
			struct stat fst;
			pr_warn("\t\t\tanon dentry — fstat'ing open_by_handle_at fd directly\n");
			if (fstat(fd, &fst) == 0 && fst.st_ino == i_ino) {
				char rel[PATH_MAX];
				int rc = anon_dentry_lookup_path(m->nsid, i_ino, rel, sizeof(rel));
				if (rc == 0) {
					close(fd);
					pr_warn("\t\t\tanon dentry path resolved: %s\n", rel);
					path = xmalloc(strlen(rel) + 2);
					if (!path)
						return ERR_PTR(ERR_GENERIC);
					path[0] = '/';
					strcpy(path + 1, rel);
					if (root_ns_mask & CLONE_NEWNS) {
						f_handle->has_mnt_id = true;
						f_handle->mnt_id = m->mnt_id;
					}
					return path;
				}
				pr_warn("\t\t\tanon dentry lookup failed (%d), continuing\n", rc);
			}
			close(fd);
			continue;
		}
		close(fd);

		/*
		 * Convert into a relative path.
		 */
		__path = (buf[1] != '\0') ? buf + 1 : ".";

		pr_warn("\t\t\tlink as %s\n", __path);

		mntfd = mntns_get_root_fd(m->nsid);
		if (mntfd < 0)
			goto err;

		openable_fd = openat(mntfd, __path, O_PATH | O_NOFOLLOW);
		if (openable_fd >= 0) {
			pr_warn("openable_fd %d for __path %s\n", openable_fd, __path);
			if (fstat(openable_fd, &st)) {
				pr_perror("Can't stat on %s", __path);
				close(openable_fd);
				goto err;
			}
			close(openable_fd);

			pr_warn("\t\t\tst_ino %lu\n", st.st_ino);
			pr_warn("\t\t\tinode %lu vs %lu\n", st.st_ino, i_ino);
			pr_warn("\t\t\topenable (inode %s) as %s\n", st.st_ino == i_ino ? "match" : "don't match",
				 __path);

			if (st.st_ino == i_ino) {
				path = xstrdup(buf);
				if (path == NULL)
					return ERR_PTR(ERR_GENERIC);
				if (root_ns_mask & CLONE_NEWNS) {
					f_handle->has_mnt_id = true;
					f_handle->mnt_id = m->mnt_id;
				}
				return path;
			}
		} else
			pr_warn("\t\t\tnot openable as %s (%s)\n", __path, strerror(errno));
	}

err:
	if (suitable_mount_found)
		return ERR_PTR(ERR_NO_PATH_IN_MOUNT);
	return ERR_PTR(ERR_NO_MOUNT);
}

static int open_handle(unsigned int s_dev, unsigned long i_ino, FhEntry *f_handle)
{
	struct mount_info *m;
	int mntfd, fd = -1;
	fh_t handle;

	decode_handle(&handle, f_handle);

	pr_debug("Opening fhandle %x:%llx...\n", s_dev, (unsigned long long)handle.__handle[0]);

	for (m = mntinfo; m; m = m->next) {
		if (m->s_dev != s_dev || !mnt_is_dir(m))
			continue;

		mntfd = __open_mountpoint(m);
		if (mntfd < 0) {
			pr_warn("Can't open mount for s_dev %x, continue\n", s_dev);
			continue;
		}

		fd = userns_call(open_by_handle, UNS_FDOUT, &handle, sizeof(handle), mntfd);
		if (fd >= 0) {
			close(mntfd);
			goto out;
		}
		close(mntfd);
	}
out:
	return fd;
}

int check_open_handle(unsigned int s_dev, unsigned long i_ino, FhEntry *f_handle)
{
	char *path, *irmap_path;
	struct mount_info *mi;

	if (fault_injected(FI_CHECK_OPEN_HANDLE))
		goto fault;

	/*
	 * Always try to fetch watchee path first. There are several reasons:
	 *
	 *  - tmpfs/devtmps do not save inode numbers between mounts,
	 *    so it is critical to have the complete path under our
	 *    hands for restore purpose;
	 *
	 *  - in case of migration the inodes might be changed as well
	 *    so the only portable solution is to carry the whole path
	 *    to the watchee inside image.
	 */
	path = alloc_openable(s_dev, i_ino, f_handle);

	if (!IS_ERR_OR_NULL(path)) {
		pr_debug("\tHandle 0x%x:0x%lx is openable\n", s_dev, i_ino);
		goto out;
	} else if (IS_ERR(path) && PTR_ERR(path) == ERR_NO_MOUNT) {

		nodecode_sdev_register(s_dev);
		goto fault;
	} else if (IS_ERR(path) && PTR_ERR(path) == ERR_GENERIC) {
		goto err;
	}

	mi = lookup_mnt_sdev(s_dev);
	if (mi == NULL) {
		pr_err("Unable to lookup a mount by dev 0x%x\n", s_dev);
		goto err;
	}

	if ((mi->fstype->code == FSTYPE__TMPFS) || (mi->fstype->code == FSTYPE__DEVTMPFS)) {
		pr_err("Can't find suitable path for handle (dev %#x ino %#lx): %d\n", s_dev, i_ino,
		       (int)PTR_ERR(path));
		goto err;
	}

	if (!opts.force_irmap)
		/*
		 * If we're not forced to do irmap, then
		 * say we have no path for watch. Otherwise
		 * do irmap scan even if the handle is
		 * working.
		 *
		 * FIXME -- no need to open-by-handle if
		 * we are in force-irmap and not on tempfs
		 */
		goto out_nopath;

fault:
	pr_warn("\tHandle 0x%x:0x%lx cannot be opened\n", s_dev, i_ino);
	irmap_path = irmap_lookup(s_dev, i_ino);
	if (!irmap_path) {
		pr_err("\tCan't dump Handle 0x%x:0x%lx\n", s_dev, i_ino);
		return -1;
	}
	path = xstrdup(irmap_path);
	if (!path)
		goto err;
out:
	pr_debug("\tDumping %s as path for handle\n", path);
	f_handle->path = path;
out_nopath:
	return 0;
err:
	return -1;
}

static int check_one_wd(InotifyWdEntry *we)
{
	pr_info("wd: wd %#08x s_dev %#08x i_ino %#16" PRIx64 " mask %#08x\n", we->wd, we->s_dev, we->i_ino, we->mask);
	pr_info("\t[fhandle] bytes %#08x type %#08x __handle %#016" PRIx64 ":%#016" PRIx64 "\n", we->f_handle->bytes,
		we->f_handle->type, we->f_handle->handle[0], we->f_handle->handle[1]);

	if (we->mask & KERNEL_FS_EVENT_ON_CHILD)
		pr_warn_once("\t\tDetected FS_EVENT_ON_CHILD bit "
			     "in mask (will be ignored on restore)\n");

	if (check_open_handle(we->s_dev, we->i_ino, we->f_handle))
		return -1;

	return 0;
}

static int dump_one_inotify(int lfd, u32 id, const struct fd_parms *p)
{
	FileEntry fe = FILE_ENTRY__INIT;
	InotifyFileEntry ie = INOTIFY_FILE_ENTRY__INIT;
	int exit_code = -1, i, ret;

	ret = fd_has_data(lfd);
	if (ret < 0)
		return -1;
	else if (ret > 0)
		pr_warn("The %#08x inotify events will be dropped\n", id);

	ie.id = id;
	ie.flags = p->flags;
	ie.fown = (FownEntry *)&p->fown;

	if (parse_fdinfo(lfd, FD_TYPES__INOTIFY, &ie))
		goto free;

	for (i = 0; i < ie.n_wd; i++)
		if (check_one_wd(ie.wd[i]))
			goto free;

	fe.type = FD_TYPES__INOTIFY;
	fe.id = ie.id;
	fe.ify = &ie;

	pr_info("id %#08x flags %#08x\n", ie.id, ie.flags);
	if (pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE))
		goto free;

	exit_code = 0;
free:
	for (i = 0; i < ie.n_wd; i++)
		xfree(ie.wd[i]);
	xfree(ie.wd);

	return exit_code;
}

static int pre_dump_one_inotify(int pid, int lfd)
{
	InotifyFileEntry ie = INOTIFY_FILE_ENTRY__INIT;
	int i;

	if (parse_fdinfo_pid(pid, lfd, FD_TYPES__INOTIFY, &ie))
		return -1;

	for (i = 0; i < ie.n_wd; i++) {
		InotifyWdEntry *we = ie.wd[i];

		if (irmap_queue_cache(we->s_dev, we->i_ino, we->f_handle))
			return -1;

		xfree(we);
	}

	return 0;
}

const struct fdtype_ops inotify_dump_ops = {
	.type = FD_TYPES__INOTIFY,
	.dump = dump_one_inotify,
	.pre_dump = pre_dump_one_inotify,
};

static int check_one_mark(FanotifyMarkEntry *fme)
{
	if (fme->type == MARK_TYPE__INODE) {
		BUG_ON(!fme->ie);

		pr_info("mark: s_dev %#08x i_ino %#016" PRIx64 " mask %#08x\n", fme->s_dev, fme->ie->i_ino, fme->mask);

		pr_info("\t[fhandle] bytes %#08x type %#08x __handle %#016" PRIx64 ":%#016" PRIx64 "\n",
			fme->ie->f_handle->bytes, fme->ie->f_handle->type, fme->ie->f_handle->handle[0],
			fme->ie->f_handle->handle[1]);

		if (check_open_handle(fme->s_dev, fme->ie->i_ino, fme->ie->f_handle))
			return -1;
	}

	if (fme->type == MARK_TYPE__MOUNT) {
		struct mount_info *m;

		BUG_ON(!fme->me);

		m = lookup_mnt_id(fme->me->mnt_id);
		if (!m) {
			pr_err("Can't find mnt_id 0x%x\n", fme->me->mnt_id);
			return -1;
		}
		if (!(root_ns_mask & CLONE_NEWNS))
			fme->me->path = m->ns_mountpoint + 1;
		fme->s_dev = m->s_dev;

		pr_info("mark: s_dev %#08x mnt_id  %#08x mask %#08x\n", fme->s_dev, fme->me->mnt_id, fme->mask);
	}

	return 0;
}

static int dump_one_fanotify(int lfd, u32 id, const struct fd_parms *p)
{
	FileEntry fle = FILE_ENTRY__INIT;
	FanotifyFileEntry fe = FANOTIFY_FILE_ENTRY__INIT;
	int ret = -1, i;

	ret = fd_has_data(lfd);
	if (ret < 0)
		return -1;
	else if (ret > 0)
		pr_warn("The %#08x fanotify events will be dropped\n", id);
	ret = -1;

	fe.id = id;
	fe.flags = p->flags;
	fe.fown = (FownEntry *)&p->fown;

	if (parse_fdinfo(lfd, FD_TYPES__FANOTIFY, &fe) < 0)
		goto free;

	for (i = 0; i < fe.n_mark; i++)
		if (check_one_mark(fe.mark[i]))
			goto free;

	pr_info("id %#08x flags %#08x\n", fe.id, fe.flags);

	fle.type = FD_TYPES__FANOTIFY;
	fle.id = fe.id;
	fle.ffy = &fe;

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fle, PB_FILE);
free:
	for (i = 0; i < fe.n_mark; i++)
		xfree(fe.mark[i]);
	xfree(fe.mark);
	return ret;
}

static int pre_dump_one_fanotify(int pid, int lfd)
{
	FanotifyFileEntry fe = FANOTIFY_FILE_ENTRY__INIT;
	int i;

	if (parse_fdinfo_pid(pid, lfd, FD_TYPES__FANOTIFY, &fe))
		return -1;

	for (i = 0; i < fe.n_mark; i++) {
		FanotifyMarkEntry *me = fe.mark[i];

		if (me->type == MARK_TYPE__INODE && irmap_queue_cache(me->s_dev, me->ie->i_ino, me->ie->f_handle))
			return -1;

		xfree(me);
	}
	xfree(fe.mark);
	return 0;
}

const struct fdtype_ops fanotify_dump_ops = {
	.type = FD_TYPES__FANOTIFY,
	.dump = dump_one_fanotify,
	.pre_dump = pre_dump_one_fanotify,
};

static const char *tfork_snap_relpath(uint32_t mnt_id, const char *full_path)
{
	struct mount_info *mi;
	const char *mp;
	size_t mp_len;
	int i;

	if (!opts.tfork.active || opts.tfork.snap_root_fd < 0)
		return NULL;
	if (opts.tfork.snap_mount_n == 0)
		return NULL;
	if (!full_path || full_path[0] != '/')
		return NULL;

	mi = lookup_mnt_id(mnt_id);
	if (!mi || !mi->ns_mountpoint)
		return NULL;

	mp = mi->ns_mountpoint;

	if (mp[0] == '.')
		mp++;
	if (mp[0] == '\0')
		mp = "/";

	for (i = 0; i < opts.tfork.snap_mount_n; i++) {
		const char *want = opts.tfork.snap_mount[i];
		if (!want)
			continue;
		if (strcmp(want, mp) != 0)
			continue;

		mp_len = strlen(mp);
		if (mp_len == 1) {
			const char *rel = full_path + 1;
			return (*rel == '\0') ? "." : rel;
		}
		if (strncmp(full_path, mp, mp_len) == 0 &&
		    (full_path[mp_len] == '/' || full_path[mp_len] == '\0')) {
			const char *rel = full_path + mp_len;
			while (*rel == '/')
				rel++;
			return (*rel == '\0') ? "." : rel;
		}

	}
	return NULL;
}

static char *get_mark_path(const char *who, struct file_remap *remap, FhEntry *f_handle, unsigned long i_ino,
			   unsigned int s_dev, char *buf, int *target)
{
	char *path = NULL;

	if (remap) {
		int mntns_root;
		const char *snap_rel;

		snap_rel = tfork_snap_relpath(remap->rmnt_id, remap->rpath);
		if (snap_rel) {
			pr_warn("tfork-snap-mount: %s remap %s -> snap_root_fd (copy %d)\n",
				who, snap_rel, opts.tfork.copy_idx);
			*target = openat(opts.tfork.snap_root_fd, snap_rel, O_PATH);
		} else {
			mntns_root = mntns_get_root_by_mnt_id(remap->rmnt_id);
			pr_debug("\t\tRestore %s watch for %#08x:%#016lx (via %s)\n", who, s_dev, i_ino, remap->rpath);
			*target = openat(mntns_root, remap->rpath, O_PATH);
		}
	} else if (f_handle->path) {
		int mntns_root;
		char *path = ".";
		uint32_t mnt_id = f_handle->has_mnt_id ? f_handle->mnt_id : -1;
		const char *snap_rel;

		/* irmap cache is collected in the root namespaces. */
		mntns_root = mntns_get_root_by_mnt_id(mnt_id);

		/* change "/foo" into "foo" and "/" into "." */
		if (f_handle->path[1] != '\0')
			path = f_handle->path + 1;

		pr_debug("\t\tRestore with path hint %d:%s\n", mnt_id, path);

		snap_rel = tfork_snap_relpath(mnt_id, f_handle->path);
		if (snap_rel) {
			pr_warn("tfork-snap-mount: %s %s -> snap_root_fd (copy %d) fd=%d\n",
				who, snap_rel, opts.tfork.copy_idx, opts.tfork.snap_root_fd);
			*target = openat(opts.tfork.snap_root_fd, snap_rel, O_PATH);
		} else {
			pr_warn("tfork-snap-mount: %s %s mnt_id=%u not snapshotted (active=%d fd=%d nmnts=%d)\n",
				who, f_handle->path, mnt_id,
				opts.tfork.active, opts.tfork.snap_root_fd,
				opts.tfork.snap_mount_n);
			*target = openat(mntns_root, path, O_PATH);
		}
	} else
		*target = open_handle(s_dev, i_ino, f_handle);

	if (*target < 0) {
		pr_perror("Unable to open %s", f_handle->path);
		goto err;
	}

	/*
	 * fanotify/inotify open syscalls want path to attach
	 * watch to. But the only thing we have is an FD obtained
	 * via fhandle. Fortunately, when trying to attach the
	 * /proc/pid/fd/ link, we will watch the inode the link
	 * points to, i.e. -- just what we want.
	 */

	sprintf(buf, "/proc/self/fd/%d", *target);
	path = buf;

	if (!pr_quelled(LOG_DEBUG)) {
		char link[PATH_MAX];

		if (read_fd_link(*target, link, sizeof(link)) < 0)
			link[0] = '\0';

		pr_debug("\t\tRestore %s watch for %#08x:%#016lx (via %s -> %s)\n", who, s_dev, i_ino, path, link);
	}
err:
	return path;
}

static int restore_one_inotify(int inotify_fd, struct fsnotify_mark_info *info)
{
	InotifyWdEntry *iwe = info->iwe;
	int ret = -1, target = -1;
	char buf[PSFDS], *path;
	uint32_t mask;

	path = get_mark_path("inotify", info->remap, iwe->f_handle, iwe->i_ino, iwe->s_dev, buf, &target);
	if (!path)
		goto err;

	mask = iwe->mask & IN_ALL_EVENTS;
	if (iwe->mask & ~IN_ALL_EVENTS) {
		pr_info("\t\tfilter event mask %#x -> %#x\n", iwe->mask, mask);
	}

	if (kdat.has_inotify_setnextwd) {
		if (ioctl(inotify_fd, INOTIFY_IOC_SETNEXTWD, iwe->wd)) {
			pr_perror("Can't set next inotify wd");
			return -1;
		}
	}

	while (1) {
		int wd;

		wd = inotify_add_watch(inotify_fd, path, mask);
		if (wd < 0) {
			pr_perror("Can't add watch for 0x%x with 0x%x", inotify_fd, iwe->wd);
			break;
		} else if (wd == iwe->wd) {
			ret = 0;
			break;
		} else if (wd > iwe->wd) {
			pr_err("Unsorted watch 0x%x found for 0x%x with 0x%x\n", wd, inotify_fd, iwe->wd);
			break;
		}

		if (kdat.has_inotify_setnextwd)
			return -1;

		inotify_rm_watch(inotify_fd, wd);
	}

err:
	close_safe(&target);
	return ret;
}

static int restore_one_fanotify(int fd, struct fsnotify_mark_info *mark)
{
	FanotifyMarkEntry *fme = mark->fme;
	unsigned int flags = FAN_MARK_ADD;
	int ret = -1, target = -1;
	char buf[PSFDS], *path = NULL;

	if (fme->type == MARK_TYPE__MOUNT) {
		struct mount_info *m;
		int mntns_root;
		char *p = fme->me->path;
		struct ns_id *nsid = NULL;

		if (root_ns_mask & CLONE_NEWNS) {
			m = lookup_mnt_id(fme->me->mnt_id);
			if (!m) {
				pr_err("Can't find mount mnt_id 0x%x\n", fme->me->mnt_id);
				return -1;
			}
			nsid = m->nsid;
			p = m->ns_mountpoint;
		}

		mntns_root = mntns_get_root_fd(nsid);

		target = openat(mntns_root, p, O_PATH);
		if (target == -1) {
			pr_perror("Unable to open %s", p);
			goto err;
		}

		flags |= FAN_MARK_MOUNT;
		snprintf(buf, sizeof(buf), "/proc/self/fd/%d", target);
		path = buf;
	} else if (fme->type == MARK_TYPE__INODE) {
		path = get_mark_path("fanotify", mark->remap, fme->ie->f_handle, fme->ie->i_ino, fme->s_dev, buf,
				     &target);
		if (!path)
			goto err;
	} else {
		pr_err("Bad fsnotify mark type 0x%x\n", fme->type);
		goto err;
	}

	flags |= fme->mflags;

	if (mark->fme->mask) {
		ret = fanotify_mark(fd, flags, fme->mask, AT_FDCWD, path);
		if (ret) {
			pr_err("Adding fanotify mask 0x%x on 0x%x/%s failed (%d)\n", fme->mask, fme->id, path, ret);
			goto err;
		}
	}

	if (fme->ignored_mask) {
		ret = fanotify_mark(fd, flags | FAN_MARK_IGNORED_MASK, fme->ignored_mask, AT_FDCWD, path);
		if (ret) {
			pr_err("Adding fanotify ignored-mask 0x%x on 0x%x/%s failed (%d)\n", fme->ignored_mask, fme->id,
			       path, ret);
			goto err;
		}
	}

err:
	close_safe(&target);
	return ret;
}

static int open_inotify_fd(struct file_desc *d, int *new_fd)
{
	struct fsnotify_file_info *info;
	struct fsnotify_mark_info *wd_info;
	int tmp;

	info = container_of(d, struct fsnotify_file_info, d);

	tmp = inotify_init1(info->ife->flags);
	if (tmp < 0) {
		pr_perror("Can't create inotify for %#08x", info->ife->id);
		return -1;
	}

	if (opts.tfork.active) {
		unsigned int skipped = 0;

		list_for_each_entry(wd_info, &info->marks, list)
			skipped++;

		if (skipped)
			pr_warn("tfork: restored inotify fd %#08x without %u watch mark(s)\n",
				info->ife->id, skipped);

		if (restore_fown(tmp, info->ife->fown))
			close_safe(&tmp);

		*new_fd = tmp;
		return tmp < 0 ? -1 : 0;
	}

	list_for_each_entry(wd_info, &info->marks, list) {
		pr_info("\tRestore 0x%x wd for %#08x\n", wd_info->iwe->wd, wd_info->iwe->id);
		if (restore_one_inotify(tmp, wd_info)) {
			close_safe(&tmp);
			return -1;
		}
		pr_info("\t 0x%x wd for %#08x is restored\n", wd_info->iwe->wd, wd_info->iwe->id);
	}

	if (restore_fown(tmp, info->ife->fown))
		close_safe(&tmp);

	*new_fd = tmp;
	return 0;
}

static int open_fanotify_fd(struct file_desc *d, int *new_fd)
{
	struct fsnotify_file_info *info;
	struct fsnotify_mark_info *mark;
	unsigned int flags = 0;
	int ret;

	info = container_of(d, struct fsnotify_file_info, d);

	flags = info->ffe->faflags;
	if (info->ffe->flags & O_CLOEXEC)
		flags |= FAN_CLOEXEC;
	if (info->ffe->flags & O_NONBLOCK)
		flags |= FAN_NONBLOCK;

	ret = fanotify_init(flags, info->ffe->evflags);
	if (ret < 0) {
		pr_perror("Can't init fanotify mark (%d)", ret);
		return -1;
	}

	list_for_each_entry(mark, &info->marks, list) {
		pr_info("\tRestore fanotify for %#08x\n", mark->fme->id);
		if (restore_one_fanotify(ret, mark)) {
			close_safe(&ret);
			return -1;
		}
	}

	if (restore_fown(ret, info->ffe->fown))
		close_safe(&ret);

	*new_fd = ret;
	return 0;
}

static struct file_desc_ops inotify_desc_ops = {
	.type = FD_TYPES__INOTIFY,
	.open = open_inotify_fd,
};

static struct file_desc_ops fanotify_desc_ops = {
	.type = FD_TYPES__FANOTIFY,
	.open = open_fanotify_fd,
};

static int inotify_resolve_remap(struct pprep_head *ph)
{
	struct fsnotify_mark_info *m;

	m = container_of(ph, struct fsnotify_mark_info, prep);
	m->remap = lookup_ghost_remap(m->iwe->s_dev, m->iwe->i_ino);
	return 0;
}

static int fanotify_resolve_remap(struct pprep_head *ph)
{
	struct fsnotify_mark_info *m;

	m = container_of(ph, struct fsnotify_mark_info, prep);
	m->remap = lookup_ghost_remap(m->fme->s_dev, m->fme->ie->i_ino);
	return 0;
}

static int __collect_inotify_mark(struct fsnotify_file_info *p, struct fsnotify_mark_info *mark)
{
	struct fsnotify_mark_info *m;

	/*
	 * We should put marks in wd ascending order. See comment
	 * in restore_one_inotify() for explanation.
	 */
	list_for_each_entry(m, &p->marks, list)
		if (m->iwe->wd > mark->iwe->wd)
			break;

	list_add_tail(&mark->list, &m->list);
	mark->prep.actor = inotify_resolve_remap;
	add_post_prepare_cb(&mark->prep);
	track_watched_inode(mark->iwe->s_dev, mark->iwe->i_ino);
	return 0;
}

static int __collect_fanotify_mark(struct fsnotify_file_info *p, struct fsnotify_mark_info *mark)
{
	list_add(&mark->list, &p->marks);
	if (mark->fme->type == MARK_TYPE__INODE) {
		mark->prep.actor = fanotify_resolve_remap;
		add_post_prepare_cb(&mark->prep);
		track_watched_inode(mark->fme->s_dev, mark->fme->ie->i_ino);
	}
	return 0;
}

static int collect_one_inotify(void *o, ProtobufCMessage *msg, struct cr_img *img)
{
	struct fsnotify_file_info *info = o;
	int i;

	info->ife = pb_msg(msg, InotifyFileEntry);
	INIT_LIST_HEAD(&info->marks);
	pr_info("Collected id %#08x flags %#08x\n", info->ife->id, info->ife->flags);

	for (i = 0; i < info->ife->n_wd; i++) {
		struct fsnotify_mark_info *mark;

		mark = xmalloc(sizeof(*mark));
		if (!mark)
			return -1;

		mark->iwe = info->ife->wd[i];
		INIT_LIST_HEAD(&mark->list);
		mark->remap = NULL;

		if (__collect_inotify_mark(info, mark))
			return -1;
	}

	return file_desc_add(&info->d, info->ife->id, &inotify_desc_ops);
}

struct collect_image_info inotify_cinfo = {
	.fd_type = CR_FD_INOTIFY_FILE,
	.pb_type = PB_INOTIFY_FILE,
	.priv_size = sizeof(struct fsnotify_file_info),
	.collect = collect_one_inotify,
};

static int collect_one_fanotify(void *o, ProtobufCMessage *msg, struct cr_img *img)
{
	struct fsnotify_file_info *info = o;
	int i;

	info->ffe = pb_msg(msg, FanotifyFileEntry);
	INIT_LIST_HEAD(&info->marks);
	pr_info("Collected id %#08x flags %#08x\n", info->ffe->id, info->ffe->flags);

	for (i = 0; i < info->ffe->n_mark; i++) {
		struct fsnotify_mark_info *mark;

		mark = xmalloc(sizeof(*mark));
		if (!mark)
			return -1;

		mark->fme = info->ffe->mark[i];
		INIT_LIST_HEAD(&mark->list);
		mark->remap = NULL;

		if (__collect_fanotify_mark(info, mark))
			return -1;
	}

	return file_desc_add(&info->d, info->ffe->id, &fanotify_desc_ops);
}

struct collect_image_info fanotify_cinfo = {
	.fd_type = CR_FD_FANOTIFY_FILE,
	.pb_type = PB_FANOTIFY_FILE,
	.priv_size = sizeof(struct fsnotify_file_info),
	.collect = collect_one_fanotify,
};

static int collect_one_inotify_mark(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct fsnotify_mark_info *mark = o;
	struct file_desc *d;

	if (!deprecated_ok("separate images for fsnotify marks"))
		return -1;

	mark->iwe = pb_msg(msg, InotifyWdEntry);
	INIT_LIST_HEAD(&mark->list);
	mark->remap = NULL;

	/*
	 * The kernel prior 4.3 might export internal event
	 * mask bits which are not part of user-space API. It
	 * is fixed in kernel but we have to keep backward
	 * compatibility with old images. So mask out
	 * inappropriate bits (in particular fdinfo might
	 * have FS_EVENT_ON_CHILD bit set).
	 */
	mark->iwe->mask &= ~KERNEL_FS_EVENT_ON_CHILD;

	d = find_file_desc_raw(FD_TYPES__INOTIFY, mark->iwe->id);
	if (!d) {
		pr_err("Can't find inotify with id %#08x\n", mark->iwe->id);
		return -1;
	}

	return __collect_inotify_mark(container_of(d, struct fsnotify_file_info, d), mark);
}

struct collect_image_info inotify_mark_cinfo = {
	.fd_type = CR_FD_INOTIFY_WD,
	.pb_type = PB_INOTIFY_WD,
	.priv_size = sizeof(struct fsnotify_mark_info),
	.collect = collect_one_inotify_mark,
};

static int collect_one_fanotify_mark(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct fsnotify_mark_info *mark = o;
	struct file_desc *d;

	if (!deprecated_ok("separate images for fsnotify marks"))
		return -1;

	mark->fme = pb_msg(msg, FanotifyMarkEntry);
	INIT_LIST_HEAD(&mark->list);
	mark->remap = NULL;

	d = find_file_desc_raw(FD_TYPES__FANOTIFY, mark->fme->id);
	if (!d) {
		pr_err("Can't find fanotify with id %#08x\n", mark->fme->id);
		return -1;
	}

	return __collect_fanotify_mark(container_of(d, struct fsnotify_file_info, d), mark);
}

struct collect_image_info fanotify_mark_cinfo = {
	.fd_type = CR_FD_FANOTIFY_MARK,
	.pb_type = PB_FANOTIFY_MARK,
	.priv_size = sizeof(struct fsnotify_mark_info),
	.collect = collect_one_fanotify_mark,
};
