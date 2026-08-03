/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2026 WukLab
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include "crun.h"
#include "checkpoint.h"
#include "run_create.h"
#include "libcrun/container.h"
#include "libcrun/utils.h"

enum
{
  OPTION_SOURCE_STATE = 1000,
  OPTION_TFORK_SNAP_ROOT,
  OPTION_IMAGE_PATH,
  OPTION_WORK_PATH,
  OPTION_PARENT_PATH,
  OPTION_TFORK_MEMDUMP,
  OPTION_TFORK_MEMDUMP_ASYNC,
  OPTION_TFORK_COPIES,
  OPTION_TRACK_MEM,
  OPTION_MANAGE_CGROUPS_MODE,
  OPTION_BUNDLE,
  OPTION_SKIP_MNT,
  OPTION_INHERIT_FD,
  OPTION_EXTERNAL,
  OPTION_TFORK_SNAP_ROOTS,
  OPTION_TFORK_COPY,
  OPTION_CGROUP_ROOT,
  OPTION_TFORK_GHOST_LIMIT,
  OPTION_TFORK_TCP_CLOSE,
  OPTION_TFORK_SNAP_MOUNT,
  OPTION_TFORK_DUMPD_PARENT,
  OPTION_TFORK_FULL_MEMCOPY,
  OPTION_NETWORK_LOCK_METHOD,
  OPTION_PID_FILE,
  OPTION_CONSOLE_SOCKET,
  OPTION_NO_PIVOT,
  OPTION_NO_NEW_KEYRING,
  OPTION_PRESERVE_FDS,
  OPTION_DETACH,
};

static const char *bundle = NULL;
static const char *config_file = "config.json";
static libcrun_context_t crun_context;
static libcrun_checkpoint_restore_t cr_options;

static struct argp_option options[]
    = { { "bundle", OPTION_BUNDLE, "DIR", 0, "container bundle (default \".\")", 0 },
        { "source-state", OPTION_SOURCE_STATE, "FILE", 0, "path to source container's state.json", 0 },
        { "tfork-snap-root", OPTION_TFORK_SNAP_ROOT, "DIR", 0, "rootfs snapshot for the clone (single-copy)", 0 },
        { "tfork-snap-roots", OPTION_TFORK_SNAP_ROOTS, "DIR", 0,
          "per-copy rootfs snapshot for N-copy fan-out (repeat N times; must match --tfork-copies)", 0 },
        { "tfork-snap-mount", OPTION_TFORK_SNAP_MOUNT, "PATH", 0,
          "tag a source-side mountpoint as snapshotted into the per-copy snap-root; repeat for multiple mounts. Per-copy form: --tfork-copy=<i>::--tfork-snap-mount=PATH. See ../criu/Documentation/CRIU_TFORK_DESIGN.md §9.", 0 },
        { "image-path", OPTION_IMAGE_PATH, "DIR", 0, "directory for criu metadata images", 0 },
        { "work-path", OPTION_WORK_PATH, "DIR", 0, "path for saving work files and logs", 0 },
        { "parent-path", OPTION_PARENT_PATH, "DIR", 0, "previous criu images dir, for incremental memdump chains", 0 },
        { "tfork-memdump", OPTION_TFORK_MEMDUMP, 0, 0, "dump pages-*.img to image-path during tfork", 0 },
        { "tfork-memdump-async", OPTION_TFORK_MEMDUMP_ASYNC, 0, 0, "async page dump (implies --tfork-memdump)", 0 },
        { "tfork-copies", OPTION_TFORK_COPIES, "N", 0, "produce N clones through the n-copy helper (omitted: legacy direct single-copy)", 0 },
        { "track-mem", OPTION_TRACK_MEM, 0, 0, "arm soft-dirty for chained incremental dumps", 0 },
        { "manage-cgroups-mode", OPTION_MANAGE_CGROUPS_MODE, "MODE", 0,
          "cgroups mode: 'soft' (default), 'ignore', 'full' and 'strict'", 0 },
        { "skip-mnt", OPTION_SKIP_MNT, "PATH", 0,
          "skip dumping the mount at PATH (repeat for several); needed for podman's per-container bind-mounts (/proc/interrupts, /etc/hosts, /run/.containerenv, ...)", 0 },
        { "inherit-fd", OPTION_INHERIT_FD, "FD:KEY", 0,
          "give the clone caller-supplied fd FD (open in this process) for the source-side resource KEY; repeat for several. KEY format matches CRIU --inherit-fd, e.g. fd[1]:tty:[abc]. Use to give the clone fresh stdio.", 0 },
        { "external", OPTION_EXTERNAL, "ID", 0,
          "mark a CRIU resource as external so it isn't restored from img — caller provides it at runtime (typically paired with --inherit-fd). E.g. tty[X:Y] for a foreign tty.", 0 },
        { "tfork-copy", OPTION_TFORK_COPY, "I::ARGS", 0,
          "per-copy CLI overrides for clone <I>. ARGS is space-separated sub-flags (--inherit-fd FD:KEY, --external KEY, --tfork-snap-root PATH) applied inside the matching N-copy fork's child. Repeatable per index.", 0 },
        { "tfork-ghost-limit", OPTION_TFORK_GHOST_LIMIT, "BYTES", 0,
          "raise CRIU's ghost-file size cap from its 1 MiB default; chromium / firefox / KDE keep multi-MiB unlinked tmp files mmap'd as anon shmem", 0 },
        { "tfork-tcp-close", OPTION_TFORK_TCP_CLOSE, 0, 0,
          "dump ESTABLISHED TCP sockets as closed; the clone wakes with sockets in closed state (apps reconnect). Required for chromium / electron / any networked workload that holds long-poll connections.", 0 },
        { "tfork-dumpd-parent", OPTION_TFORK_DUMPD_PARENT, "PID", 0,
          "host-pidns PID for dumpd to reparent itself to (so `podman stop`/`rm` cleans dumpd up via its parent). Only meaningful with --tfork-memdump-async. If unset, defaults to getppid() at exec time (conmon when invoked from podman). Same-pidns is enforced by criu — pass a host PID. See ../criu/Documentation/CRIU_TFORK_RPC_PEER_DISCONNECT_LEAK.md.", 0 },
        { "tfork-full-memcopy", OPTION_TFORK_FULL_MEMCOPY, 0, 0,
          "ablation knob: replace anon-private vma_cherrypick CoW with a userspace physical copy of every anon page (via pread from /proc/<source>/mem in the restorer). File-backed VMAs, memfds, and SysV IPC are unaffected. For measuring the anon-CoW signal vs full-copy baseline.", 0 },
        { "network-lock", OPTION_NETWORK_LOCK_METHOD, "METHOD", 0,
          "network lock backend: 'iptables', 'nftables', or 'skip'", 0 },
        { "cgroup-root", OPTION_CGROUP_ROOT, "[CTRL:]PATH", 0,
          "rewrite dumped cgroup paths under PATH on restore. Under tfork the rewrite synthesizes cgns_prefix so prepare_cgns() unshares CLONE_NEWCGROUP at the clone's own cgroup boundary. Required for recursive clone-of-clone (gen-1 → gen-2) so /proc/self/cgroup reads `/` inside gen-1.", 0 },
        { "pid-file", OPTION_PID_FILE, "FILE", 0, "where to write the PID of the container", 0 },
        { "console-socket", OPTION_CONSOLE_SOCKET, "SOCK", 0,
          "path to a socket that will receive the ptmx end of the tty", 0 },
        { "no-pivot", OPTION_NO_PIVOT, 0, 0, "do not use pivot_root", 0 },
        { "no-new-keyring", OPTION_NO_NEW_KEYRING, 0, 0, "keep the same session key", 0 },
        { "preserve-fds", OPTION_PRESERVE_FDS, "N", 0, "pass additional FDs to the container", 0 },
        { "detach", OPTION_DETACH, 0, 0, "ignored (tfork is always detached)", 0 },
        {
            0,
        } };

static char doc[] = "OCI runtime";
static char args_doc[] = "tfork [OPTION]... CONTAINER";

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case OPTION_BUNDLE:
      bundle = crun_context.bundle = argp_mandatory_argument (arg, state);
      break;

    case OPTION_SOURCE_STATE:
      cr_options.source_state = argp_mandatory_argument (arg, state);
      break;

    case OPTION_TFORK_SNAP_ROOT:
      cr_options.tfork_snap_root = argp_mandatory_argument (arg, state);
      break;

    case OPTION_IMAGE_PATH:
      cr_options.image_path = argp_mandatory_argument (arg, state);
      break;

    case OPTION_WORK_PATH:
      cr_options.work_path = argp_mandatory_argument (arg, state);
      break;

    case OPTION_PARENT_PATH:
      cr_options.parent_path = argp_mandatory_argument (arg, state);
      break;

    case OPTION_TFORK_MEMDUMP:
      cr_options.tfork_memdump = true;
      break;

    case OPTION_TFORK_MEMDUMP_ASYNC:
      cr_options.tfork_memdump = true;
      cr_options.tfork_memdump_async = true;
      break;

    case OPTION_TFORK_COPIES:
      cr_options.tfork_copies = parse_int_or_fail (argp_mandatory_argument (arg, state), "tfork-copies");
      if (cr_options.tfork_copies < 1)
        libcrun_fail_with_error (0, "--tfork-copies must be >= 1");
      break;

    case OPTION_TFORK_GHOST_LIMIT:
      {
        char *endp;
        const char *p = argp_mandatory_argument (arg, state);
        unsigned long val = strtoul (p, &endp, 0);
        if (*endp != '\0' || val == 0 || val > UINT_MAX)
          libcrun_fail_with_error (0, "--tfork-ghost-limit: invalid value `%s`", p);
        cr_options.tfork_ghost_limit = (unsigned int) val;
      }
      break;

    case OPTION_TFORK_TCP_CLOSE:
      cr_options.tcp_close = true;
      break;

    case OPTION_TFORK_DUMPD_PARENT:
      {
        char *endp;
        const char *p = argp_mandatory_argument (arg, state);
        long val = strtol (p, &endp, 10);
        if (*endp != '\0' || val <= 0 || val > INT_MAX)
          libcrun_fail_with_error (0, "--tfork-dumpd-parent: invalid PID `%s`", p);
        cr_options.tfork_dumpd_parent_pid = (int) val;
      }
      break;

    case OPTION_TFORK_FULL_MEMCOPY:
      cr_options.tfork_full_memcopy = true;
      break;

    case OPTION_NETWORK_LOCK_METHOD:
      cr_options.network_lock_method
          = crun_parse_network_lock_method (argp_mandatory_argument (arg, state));
      break;

    case OPTION_TRACK_MEM:
      cr_options.track_mem = true;
      break;

    case OPTION_MANAGE_CGROUPS_MODE:
      cr_options.manage_cgroups_mode
          = crun_parse_manage_cgroups_mode (argp_mandatory_argument (arg, state));
      break;

    case OPTION_SKIP_MNT:
      {
        const char *p = argp_mandatory_argument (arg, state);
        char **a = realloc (cr_options.skip_mnt,
                            (cr_options.skip_mnt_n + 1) * sizeof (*a));
        if (a == NULL)
          libcrun_fail_with_error (errno, "realloc skip_mnt");
        a[cr_options.skip_mnt_n] = strdup (p);
        if (a[cr_options.skip_mnt_n] == NULL)
          libcrun_fail_with_error (errno, "strdup skip_mnt");
        cr_options.skip_mnt = a;
        cr_options.skip_mnt_n++;
      }
      break;

    case OPTION_INHERIT_FD:
      {
        const char *p = argp_mandatory_argument (arg, state);
        char **a = realloc (cr_options.inherit_fd,
                            (cr_options.inherit_fd_n + 1) * sizeof (*a));
        if (a == NULL)
          libcrun_fail_with_error (errno, "realloc inherit_fd");
        a[cr_options.inherit_fd_n] = strdup (p);
        if (a[cr_options.inherit_fd_n] == NULL)
          libcrun_fail_with_error (errno, "strdup inherit_fd");
        cr_options.inherit_fd = a;
        cr_options.inherit_fd_n++;
      }
      break;

    case OPTION_EXTERNAL:
      {
        const char *p = argp_mandatory_argument (arg, state);
        char **a = realloc (cr_options.external,
                            (cr_options.external_n + 1) * sizeof (*a));
        if (a == NULL)
          libcrun_fail_with_error (errno, "realloc external");
        a[cr_options.external_n] = strdup (p);
        if (a[cr_options.external_n] == NULL)
          libcrun_fail_with_error (errno, "strdup external");
        cr_options.external = a;
        cr_options.external_n++;
      }
      break;

    case OPTION_TFORK_COPY:
      {
        const char *p = argp_mandatory_argument (arg, state);
        char **a = realloc (cr_options.tfork_copy_args,
                            (cr_options.tfork_copy_args_n + 1) * sizeof (*a));
        if (a == NULL)
          libcrun_fail_with_error (errno, "realloc tfork_copy_args");
        a[cr_options.tfork_copy_args_n] = strdup (p);
        if (a[cr_options.tfork_copy_args_n] == NULL)
          libcrun_fail_with_error (errno, "strdup tfork_copy_args");
        cr_options.tfork_copy_args = a;
        cr_options.tfork_copy_args_n++;
      }
      break;

    case OPTION_CGROUP_ROOT:
      {
        const char *p = argp_mandatory_argument (arg, state);
        char **a = realloc (cr_options.cgroup_root,
                            (cr_options.cgroup_root_n + 1) * sizeof (*a));
        if (a == NULL)
          libcrun_fail_with_error (errno, "realloc cgroup_root");
        a[cr_options.cgroup_root_n] = strdup (p);
        if (a[cr_options.cgroup_root_n] == NULL)
          libcrun_fail_with_error (errno, "strdup cgroup_root");
        cr_options.cgroup_root = a;
        cr_options.cgroup_root_n++;
      }
      break;

    case OPTION_TFORK_SNAP_ROOTS:
      {
        const char *p = argp_mandatory_argument (arg, state);
        char **a = realloc (cr_options.tfork_snap_roots,
                            (cr_options.tfork_snap_roots_n + 1) * sizeof (*a));
        if (a == NULL)
          libcrun_fail_with_error (errno, "realloc tfork_snap_roots");
        a[cr_options.tfork_snap_roots_n] = strdup (p);
        if (a[cr_options.tfork_snap_roots_n] == NULL)
          libcrun_fail_with_error (errno, "strdup tfork_snap_roots");
        cr_options.tfork_snap_roots = a;
        cr_options.tfork_snap_roots_n++;
      }
      break;

    case OPTION_TFORK_SNAP_MOUNT:
      {
        const char *p = argp_mandatory_argument (arg, state);
        char **a = realloc (cr_options.tfork_snap_mounts,
                            (cr_options.tfork_snap_mounts_n + 1) * sizeof (*a));
        if (a == NULL)
          libcrun_fail_with_error (errno, "realloc tfork_snap_mounts");
        a[cr_options.tfork_snap_mounts_n] = strdup (p);
        if (a[cr_options.tfork_snap_mounts_n] == NULL)
          libcrun_fail_with_error (errno, "strdup tfork_snap_mounts");
        cr_options.tfork_snap_mounts = a;
        cr_options.tfork_snap_mounts_n++;
      }
      break;

    case OPTION_PID_FILE:
      crun_context.pid_file = argp_mandatory_argument (arg, state);
      break;

    case OPTION_CONSOLE_SOCKET:
      crun_context.console_socket = argp_mandatory_argument (arg, state);
      break;

    case OPTION_NO_PIVOT:
      crun_context.no_pivot = true;
      break;

    case OPTION_NO_NEW_KEYRING:
      crun_context.no_new_keyring = true;
      break;

    case OPTION_PRESERVE_FDS:
      crun_context.preserve_fds = parse_int_or_fail (argp_mandatory_argument (arg, state), "preserve-fds");
      break;

    case OPTION_DETACH:
      break;

    case ARGP_KEY_NO_ARGS:
      libcrun_fail_with_error (0, "please specify a ID for the container");

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp run_argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

static unsigned int
get_options ()
{
  return 0;
}

static int
container_tfork (libcrun_context_t *context, libcrun_container_t *container, unsigned int options arg_unused,
                 libcrun_error_t *err)
{
  return libcrun_container_tfork (context, container, &cr_options, err);
}

int
crun_command_tfork (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  cr_options.manage_cgroups_mode = -1;
  cr_options.tfork_copies = 0;
  /*
   * External Unix stream sockets can make Codex/tmux stacks dumpable, but they
   * may hide unsupported socket topology. Keep the default fail-loud and expose
   * this as an explicit escape hatch for agent integrations.
   */
  if (getenv ("CRUN_TFORK_EXT_UNIX_SK") != NULL)
    cr_options.ext_unix_sk = true;
  cr_options.leave_running = true;

  return crun_run_create_internal (global_args, argc, argv, container_tfork, get_options, &crun_context, &run_argp,
                                   &config_file, &bundle, err);
}
