/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2020 Adrian Reber <areber@redhat.com>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */
#define _GNU_SOURCE

#include <config.h>

#if HAVE_CRIU && HAVE_DLOPEN

#  include <unistd.h>
#  include <sys/types.h>
#  include <criu/criu.h>
#  include <sched.h>
#  include <sys/stat.h>
#  include <sys/mount.h>
#  include <fcntl.h>

#  include "container.h"
#  include "linux.h"
#  include "status.h"
#  include "utils.h"
#  include "cgroup.h"
#  include "cgroup-utils.h"
#  include "terminal.h"

#  ifndef STATIC
#    include <dlfcn.h>
#  endif

#  define CRIU_CHECKPOINT_LOG_FILE "dump.log"
#  define CRIU_RESTORE_LOG_FILE "restore.log"
#  define DESCRIPTORS_FILENAME "descriptors.json"
#  define CRIU_RUNC_CONFIG_FILE "/etc/criu/runc.conf"
#  define CRIU_CRUN_CONFIG_FILE "/etc/criu/crun.conf"
#  define CRIU_LOG_TAIL_LINES 80
#  define CRIU_LOG_LINE_SIZE 1024

#  define CRIU_EXT_NETNS "extRootNetNS"
#  define CRIU_EXT_PIDNS "extRootPidNS"

#  ifndef CLONE_NEWTIME
#    define CLONE_NEWTIME 0x00000080 /* New time namespace */
#  endif

/* Defined in chroot_realpath.c  */
char *chroot_realpath (const char *chroot, const char *path, char resolved_path[]);

static const char *console_socket = NULL;
static int tfork_pre_restore_fd = -1;
static int tfork_source_detached_fd = -1;

#  define LIBCRIU_MIN_VERSION 31500

struct libcriu_wrapper_s
{
  void *handle;
  int (*criu_add_ext_mount) (const char *key, const char *val);
  int (*criu_add_external) (const char *key);
  int (*criu_add_inherit_fd) (int fd, const char *key);
  int (*criu_add_skip_mnt) (const char *mnt);
  int (*criu_check_version) (int minimum);
  int (*criu_dump) (void);
  int (*criu_get_orphan_pts_master_fd) (void);
  int (*criu_init_opts) (void);
#  ifdef CRIU_JOIN_NS_SUPPORT
  int (*criu_join_ns_add) (const char *ns, const char *ns_file, const char *extra_opt);
#  endif
#  ifdef CRIU_PRE_DUMP_SUPPORT
  int (*criu_feature_check) (struct criu_feature_check *features, size_t size);
  int (*criu_pre_dump) (void);
#  endif
  int (*criu_restore_child) (void);
  int (*criu_set_freeze_cgroup) (const char *name);
  void (*criu_set_file_locks) (bool file_locks);
  void (*criu_set_ext_unix_sk) (bool ext_unix_sk);
  int (*criu_set_log_file) (const char *log_file);
  void (*criu_set_log_level) (int log_level);
  void (*criu_set_ghost_limit) (unsigned int limit);
  void (*criu_set_leave_running) (bool leave_running);
  void (*criu_set_manage_cgroups) (bool manage);
  void (*criu_set_manage_cgroups_mode) (enum criu_cg_mode mode);
  int (*criu_set_network_lock) (enum criu_network_lock_method method);
  void (*criu_set_notify_cb) (int (*cb) (char *action, criu_notify_arg_t na));
  void (*criu_set_orphan_pts_master) (bool orphan_pts_master);
  void (*criu_set_images_dir_fd) (int fd);
  int (*criu_set_parent_images) (const char *path);
  void (*criu_set_pid) (int pid);
  int (*criu_set_root) (const char *root);
  int (*criu_add_cg_root) (const char *ctrl, const char *path);
  void (*criu_set_shell_job) (bool shell_job);
  void (*criu_set_tcp_established) (bool tcp_established);
  void (*criu_set_tcp_close) (bool tcp_close);
  void (*criu_set_track_mem) (bool track_mem);
  void (*criu_set_work_dir_fd) (int fd);
  int (*criu_set_lsm_profile) (const char *name);
  int (*criu_set_lsm_mount_context) (const char *name);
  int (*criu_set_config_file) (const char *path);

  int (*criu_tfork) (void);
  int (*criu_set_tfork_snap_root) (const char *path);
  int (*criu_add_tfork_snap_root) (const char *path);
  int (*criu_add_tfork_snap_mount) (const char *path);
  int (*criu_add_tfork_copy_args) (int copy_idx, const char *args);
  void (*criu_set_tfork_memdump) (bool val);
  void (*criu_set_tfork_memdump_async) (bool val);
  void (*criu_set_tfork_copies) (int copies);
  void (*criu_set_tfork_dumpd_parent_pid) (int pid);
  void (*criu_set_tfork_full_memcopy) (bool val);
  void (*criu_set_empty_ns) (int namespaces);
};

static struct libcriu_wrapper_s *libcriu_wrapper;

static inline void
cleanup_wrapper (void *p)
{
  struct libcriu_wrapper_s **w;

  w = (struct libcriu_wrapper_s **) p;
  if (*w == NULL)
    return;

#  ifndef STATIC
  if ((*w)->handle)
    dlclose ((*w)->handle);
#  endif
  free (*w);
  libcriu_wrapper = NULL;
}

#  define cleanup_wrapper __attribute__ ((cleanup (cleanup_wrapper)))

static int
load_wrapper (struct libcriu_wrapper_s **wrapper_out, libcrun_error_t *err)
{
  cleanup_free struct libcriu_wrapper_s *wrapper = xmalloc0 (sizeof (*wrapper));

#  ifdef STATIC
#    define LOAD_CRIU_FUNCTION(X, ALLOW_NULL) \
      wrapper->X = &X;
#  else
#    define LOAD_CRIU_FUNCTION(X, ALLOW_NULL)                                                    \
      do                                                                                         \
        {                                                                                        \
          wrapper->X = dlsym (wrapper->handle, #X);                                              \
          if (! ALLOW_NULL && wrapper->X == NULL)                                                \
            {                                                                                    \
              dlclose (wrapper->handle);                                                         \
              return crun_make_error (err, 0, "could not find symbol `%s` in `libcriu.so`", #X); \
            }                                                                                    \
      } while (0)
#  endif

#  ifndef STATIC
  wrapper->handle = dlopen ("libcriu.so.2", RTLD_NOW);
  if (wrapper->handle == NULL)
    return crun_make_error (err, 0, "could not load `libcriu.so.2`: `%s`", dlerror ());
#  endif

  LOAD_CRIU_FUNCTION (criu_add_ext_mount, false);
  LOAD_CRIU_FUNCTION (criu_add_external, false);
  LOAD_CRIU_FUNCTION (criu_add_inherit_fd, false);
  LOAD_CRIU_FUNCTION (criu_add_skip_mnt, true);
  LOAD_CRIU_FUNCTION (criu_check_version, false);
  LOAD_CRIU_FUNCTION (criu_dump, false);
  LOAD_CRIU_FUNCTION (criu_get_orphan_pts_master_fd, false);
  LOAD_CRIU_FUNCTION (criu_init_opts, false);

#  ifdef CRIU_JOIN_NS_SUPPORT
  /* criu_join_ns_add() API was introduced with CRIU version 3.16.1
   * Here we check if this API is available at build time to support
   * compiling with older version of CRIU, and at runtime to support
   * running crun with older versions of libcriu.so.2.
   */
  LOAD_CRIU_FUNCTION (criu_join_ns_add, true);
#  endif

#  ifdef CRIU_PRE_DUMP_SUPPORT
  LOAD_CRIU_FUNCTION (criu_feature_check, false);
  LOAD_CRIU_FUNCTION (criu_pre_dump, false);
#  endif
  LOAD_CRIU_FUNCTION (criu_restore_child, false);
  LOAD_CRIU_FUNCTION (criu_set_ext_unix_sk, false);
  LOAD_CRIU_FUNCTION (criu_set_file_locks, false);
  LOAD_CRIU_FUNCTION (criu_set_freeze_cgroup, false);
  LOAD_CRIU_FUNCTION (criu_set_images_dir_fd, false);
  LOAD_CRIU_FUNCTION (criu_set_leave_running, false);
  LOAD_CRIU_FUNCTION (criu_set_log_file, false);
  LOAD_CRIU_FUNCTION (criu_set_log_level, false);
  LOAD_CRIU_FUNCTION (criu_set_ghost_limit, false);
  LOAD_CRIU_FUNCTION (criu_set_manage_cgroups, false);
  LOAD_CRIU_FUNCTION (criu_set_manage_cgroups_mode, false);
  LOAD_CRIU_FUNCTION (criu_set_network_lock, true);
  LOAD_CRIU_FUNCTION (criu_set_notify_cb, false);
  LOAD_CRIU_FUNCTION (criu_set_orphan_pts_master, false);
  LOAD_CRIU_FUNCTION (criu_set_parent_images, false);
  LOAD_CRIU_FUNCTION (criu_set_pid, false);
  LOAD_CRIU_FUNCTION (criu_set_root, false);
  LOAD_CRIU_FUNCTION (criu_add_cg_root, false);
  LOAD_CRIU_FUNCTION (criu_set_shell_job, false);
  LOAD_CRIU_FUNCTION (criu_set_tcp_established, false);
  LOAD_CRIU_FUNCTION (criu_set_tcp_close, false);
  LOAD_CRIU_FUNCTION (criu_set_track_mem, false);
  LOAD_CRIU_FUNCTION (criu_set_work_dir_fd, false);
  LOAD_CRIU_FUNCTION (criu_set_lsm_profile, false);
  LOAD_CRIU_FUNCTION (criu_set_lsm_mount_context, false);
#  if ! defined STATIC || defined CRIU_CONFIG_FILE
  LOAD_CRIU_FUNCTION (criu_set_config_file, true);
#  endif

  LOAD_CRIU_FUNCTION (criu_tfork, true);
  LOAD_CRIU_FUNCTION (criu_set_tfork_snap_root, true);
  LOAD_CRIU_FUNCTION (criu_add_tfork_snap_root, true);
  LOAD_CRIU_FUNCTION (criu_add_tfork_snap_mount, true);
  LOAD_CRIU_FUNCTION (criu_add_tfork_copy_args, true);
  LOAD_CRIU_FUNCTION (criu_set_tfork_memdump, true);
  LOAD_CRIU_FUNCTION (criu_set_tfork_memdump_async, true);
  LOAD_CRIU_FUNCTION (criu_set_tfork_copies, true);
  LOAD_CRIU_FUNCTION (criu_set_tfork_dumpd_parent_pid, true);
  LOAD_CRIU_FUNCTION (criu_set_tfork_full_memcopy, false);
  LOAD_CRIU_FUNCTION (criu_set_empty_ns, true);

  libcriu_wrapper = *wrapper_out = wrapper;
  wrapper = NULL;
#  undef LOAD_CRIU_FUNCTION
  return 0;
}

static int
criu_notify (char *action, __attribute__ ((unused)) criu_notify_arg_t na)
{
  if (action == NULL)
    return 0;

  if (strcmp (action, "post-tfork-freeze") == 0 && tfork_pre_restore_fd >= 0)
    {
      char byte;
      ssize_t n;

      do
        n = read (tfork_pre_restore_fd, &byte, 1);
      while (n < 0 && errno == EINTR);
      if (n != 1)
        return -1;
      close (tfork_pre_restore_fd);
      tfork_pre_restore_fd = -1;
      return 0;
    }

  if (strcmp (action, "tfork-source-detached") == 0 && tfork_source_detached_fd >= 0)
    {
      char byte = 1;
      ssize_t n;

      do
        n = write (tfork_source_detached_fd, &byte, 1);
      while (n < 0 && errno == EINTR);
      if (n != 1)
        return -1;
      close (tfork_source_detached_fd);
      tfork_source_detached_fd = -1;
      return 0;
    }

  if (strncmp (action, "orphan-pts-master", 17) == 0)
    {
      /* CRIU sends us the master FD via the 'orphan-pts-master'
       * callback and we are passing it on to the '--console-socket'
       * if it exists. */
      cleanup_close int console_socket_fd = -1;
      libcrun_error_t tmp_err = NULL;
      int master_fd;
      int ret;

      if (! console_socket)
        return 0;

      master_fd = libcriu_wrapper->criu_get_orphan_pts_master_fd ();

      console_socket_fd = open_unix_domain_client_socket (console_socket, 0, &tmp_err);
      if (UNLIKELY (console_socket_fd < 0))
        {
          libcrun_error_release (&tmp_err);
          return console_socket_fd;
        }
      ret = send_fd_to_socket (console_socket_fd, master_fd, &tmp_err);
      if (UNLIKELY (ret < 0))
        {
          libcrun_error_release (&tmp_err);
          return ret;
        }
    }
  return 0;
}

#  ifdef CRIU_PRE_DUMP_SUPPORT

static int
criu_check_mem_track (libcrun_error_t *err)
{
  struct criu_feature_check features = { 0 };
  int ret;

  /* Right now we are only interested in checking memory tracking.
   * Memory tracking can be disabled at different levels. aarch64
   * for example has memory tracking not implemented. It could also
   * be not enabled on other architectures. Just ask CRIU if that
   * features exists. */

  features.mem_track = true;

  ret = libcriu_wrapper->criu_feature_check (&features, sizeof (features));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "CRIU feature checking failed: %d", ret);

  if (features.mem_track == true)
    return 1;

  return crun_make_error (err, 0, "CRIU memory tracking not supported");
}

#  endif

static int
register_masked_paths_mounts (runtime_spec_schema_config_schema *def, libcrun_container_t *container,
                              struct libcriu_wrapper_s *libcriu_wrapper, bool is_restore, libcrun_error_t *err)
{
  cleanup_free char *empty_dir_path = NULL;
  bool shared_dir_registered = false;
  size_t i;
  int ret;

  for (i = 0; i < def->linux->masked_paths_len; i++)
    {
      struct stat statbuf;
      ret = stat (def->linux->masked_paths[i], &statbuf);
      if (ret != 0)
        continue;

      if (S_ISDIR (statbuf.st_mode))
        {
          if (! shared_dir_registered)
            {
              ret = get_shared_empty_directory_path (&empty_dir_path,
                                                     (container->context ? container->context->state_root : NULL), err);
              if (UNLIKELY (ret < 0))
                return ret;

              ret = libcriu_wrapper->criu_add_ext_mount (empty_dir_path, empty_dir_path);
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, -ret, "CRIU: failed adding external mount for shared empty directory `%s`", empty_dir_path);

              shared_dir_registered = true;
            }

          ret = libcriu_wrapper->criu_add_ext_mount (def->linux->masked_paths[i], empty_dir_path);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, -ret, "CRIU: failed adding external mount for masked directory `%s`", def->linux->masked_paths[i]);
        }
      else if (S_ISREG (statbuf.st_mode))
        {
          const char *bind_target = is_restore ? "/dev/null" : def->linux->masked_paths[i];
          ret = libcriu_wrapper->criu_add_ext_mount (def->linux->masked_paths[i], bind_target);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, -ret, "CRIU: failed adding external mount to `%s`", bind_target);
        }
    }

  return 0;
}

static int
restore_cgroup_v1_mount (runtime_spec_schema_config_schema *def, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  bool has_cgroup_mount = false;
  char *saveptr = NULL;
  int cgroup_mode;
  char *from;
  int ret;
  uint32_t i;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    return 0;

  /* First check if there is actually a cgroup mount in the container. */
  for (i = 0; i < def->mounts_len; i++)
    {
      char *type = def->mounts[i]->type;
      if (type && strcmp (type, "cgroup") == 0)
        {
          has_cgroup_mount = true;
          break;
        }
    }

  if (! has_cgroup_mount)
    return 0;

  ret = read_all_file (PROC_SELF_CGROUP, &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (content == NULL || content[0] == '\0'))
    return crun_make_error (err, 0, "invalid content from `%s`", PROC_SELF_CGROUP);

  for (from = strtok_r (content, "\n", &saveptr); from; from = strtok_r (NULL, "\n", &saveptr))
    {
      cleanup_free char *destination = NULL;
      cleanup_free char *source = NULL;
      char *subsystem;
      char *subpath;
      char *it;

      subsystem = strchr (from, ':') + 1;
      subpath = strchr (subsystem, ':') + 1;
      *(subpath - 1) = '\0';

      if (subsystem[0] == '\0')
        continue;

      it = strstr (subsystem, "name=");
      if (it)
        subsystem = it + 5;

      if (strcmp (subsystem, "net_prio,net_cls") == 0)
        subsystem = "net_cls,net_prio";
      if (strcmp (subsystem, "cpuacct,cpu") == 0)
        subsystem = "cpu,cpuacct";

      ret = append_paths (&source, err, CGROUP_ROOT, subsystem, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = append_paths (&destination, err, source, subpath, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libcriu_wrapper->criu_add_ext_mount (source, destination);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret, "CRIU: failed adding external mount to `%s`", destination);
    }

  return 0;
}

static int
checkpoint_cgroup_v1_mount (runtime_spec_schema_config_schema *def, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  bool has_cgroup_mount = false;
  char *saveptr = NULL;
  char *from;
  int ret;
  uint32_t i;

  /* First check if there is actually a cgroup mount in the container. */
  for (i = 0; i < def->mounts_len; i++)
    {
      char *type = def->mounts[i]->type;
      if (type && strcmp (type, "cgroup") == 0)
        {
          has_cgroup_mount = true;
          break;
        }
    }

  if (! has_cgroup_mount)
    return 0;

  ret = read_all_file (PROC_SELF_CGROUP, &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (content == NULL || content[0] == '\0'))
    return crun_make_error (err, 0, "invalid content from `%s`", PROC_SELF_CGROUP);

  for (from = strtok_r (content, "\n", &saveptr); from; from = strtok_r (NULL, "\n", &saveptr))
    {
      cleanup_free char *source_path = NULL;
      char *subsystem;
      char *subpath;
      char *it;

      subsystem = strchr (from, ':') + 1;
      subpath = strchr (subsystem, ':') + 1;
      *(subpath - 1) = '\0';

      if (subsystem[0] == '\0')
        continue;

      it = strstr (subsystem, "name=");
      if (it)
        subsystem = it + 5;

      if (strcmp (subsystem, "net_prio,net_cls") == 0)
        subsystem = "net_cls,net_prio";
      if (strcmp (subsystem, "cpuacct,cpu") == 0)
        subsystem = "cpu,cpuacct";

      ret = append_paths (&source_path, err, CGROUP_ROOT, subsystem, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libcriu_wrapper->criu_add_ext_mount (source_path, source_path);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret, "CRIU: failed adding external mount to `%s`", source_path);
    }

  return 0;
}

static int
handle_criu_config_file (libcrun_container_t *container, libcrun_error_t *err)
{
  int ret;
  const char *criu_config_annotation;
  const char *config_file = CRIU_RUNC_CONFIG_FILE;

  criu_config_annotation = find_annotation (container, "org.criu.config");

  /* Ignore missing criu_set_config_file() API for compatibility with older CRIU versions,
   * and show an error only if config file is explicitly set with annotation.
   */
  if (libcriu_wrapper->criu_set_config_file == NULL)
    {
      if (criu_config_annotation)
        return crun_make_error (err, 0, "libcriu RPC config files supported in CRIU >= 4.2");

      return 0;
    }

  if (criu_config_annotation)
    config_file = criu_config_annotation;
  else if (access (CRIU_CRUN_CONFIG_FILE, F_OK) == 0)
    config_file = CRIU_CRUN_CONFIG_FILE;

  ret = libcriu_wrapper->criu_set_config_file (config_file);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "failed to set CRIU config file");

  return 0;
}

static int
validate_criu_version (libcrun_error_t *err)
{
  int ret;

  // validate that the libcriu version is at least LIBCRIU_MIN_VERSION
  ret = libcriu_wrapper->criu_check_version (LIBCRIU_MIN_VERSION);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "CRIU: failed checking version");

  if (ret == 0)
    return crun_make_error (err, 0, "libcriu is too old");

  return 0;
}

static void
show_criu_log (const char *work_path, const char *log)
{
  cleanup_free char *log_path = NULL;
  cleanup_free char *tail = NULL;
  libcrun_error_t *tmp_err = NULL;
  char line[CRIU_LOG_LINE_SIZE];
  size_t tail_index = 0;
  size_t tail_count = 0;
  FILE *f;

  if (UNLIKELY (append_paths (&log_path, tmp_err, work_path, log, NULL)) < 0)
    {
      crun_error_release (tmp_err);
      return;
    }

  f = fopen (log_path, "r");
  if (f == NULL)
    {
      if (errno != ENOENT)
        libcrun_error (errno, "Can't open CRIU log `%s`", log_path);
      return;
    }

  /* Log with error verbosity as this is the default. */
  libcrun_error (0, "--- excerpt from CRIU log `%s`", log_path);
  tail = calloc (CRIU_LOG_TAIL_LINES, CRIU_LOG_LINE_SIZE);
  if (tail == NULL)
    {
      fclose (f);
      return;
    }

  while (fgets (line, sizeof (line), f) != NULL)
    {
      char *slot = tail + tail_index * CRIU_LOG_LINE_SIZE;
      strncpy (slot, line, CRIU_LOG_LINE_SIZE - 1);
      slot[CRIU_LOG_LINE_SIZE - 1] = '\0';
      tail_index = (tail_index + 1) % CRIU_LOG_TAIL_LINES;
      if (tail_count < CRIU_LOG_TAIL_LINES)
        tail_count++;

      if (strstr (line, "Error ") != NULL
          || strstr (line, "failed") != NULL || strstr (line, "FAILED") != NULL
          || strstr (line, "Unable") != NULL || strstr (line, "Can't") != NULL
          || strstr (line, "No such") != NULL)
        {
          line[strcspn (line, "\n")] = '\0';
          libcrun_error (0, "%s", line);
        }
    }

  if (tail_count > 0)
    {
      size_t start = (tail_count == CRIU_LOG_TAIL_LINES) ? tail_index : 0;
      libcrun_error (0, "--- last %zu CRIU log lines", tail_count);
      for (size_t i = 0; i < tail_count; i++)
        {
          char *entry = tail + ((start + i) % CRIU_LOG_TAIL_LINES) * CRIU_LOG_LINE_SIZE;
          entry[strcspn (entry, "\n")] = '\0';
          libcrun_error (0, "%s", entry);
        }
    }

  fclose (f);
  libcrun_error (0, "--- end of excerpt");
}

int
libcrun_container_checkpoint_linux_criu (libcrun_container_status_t *status, libcrun_container_t *container,
                                         libcrun_checkpoint_restore_t *cr_options, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_wrapper struct libcriu_wrapper_s *wrapper = NULL;
  cleanup_free char *descriptors_path = NULL;
  cleanup_free char *freezer_path = NULL;
  cleanup_free char *path = NULL;
  cleanup_close int image_fd = -1;
  cleanup_close int work_fd = -1;
  int cgroup_mode;
  size_t i;
  int ret;

  ret = load_wrapper (&wrapper, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (geteuid ())
    return crun_make_error (err, 0, "checkpointing requires root");

  /* No CRIU version or feature checking yet. In configure.ac there
   * is a minimum CRIU version listed and so far it is good enough.
   *
   * The CRIU library also does not yet have an interface to CRIU
   * the version of the binary. Right now it is only possible to
   * query the version of the library via defines during buildtime.
   *
   * The whole CRIU library setup works this way, that the library
   * is only a wrapper around RPC calls to the actual library. So
   * if CRIU is updated and the SO of the library does not change,
   * and crun is not rebuilt against the newer version, the version
   * is still returning the values during buildtime and not from
   * the actual running CRIU binary. The RPC interface between the
   * library will not break, so no reason to worry, but it is not
   * possible to detect (via the library) which CRIU version is
   * actually being used. This needs to be added to CRIU upstream. */

  ret = libcriu_wrapper->criu_init_opts ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "CRIU init failed with %d", ret);

  ret = validate_criu_version (err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (cr_options->image_path == NULL))
    return crun_make_error (err, 0, "image path not set");

  ret = mkdir (cr_options->image_path, 0700);
  if (UNLIKELY ((ret == -1) && (errno != EEXIST)))
    return crun_make_error (err, errno, "error creating checkpoint directory `%s`", cr_options->image_path);

  image_fd = open (cr_options->image_path, O_DIRECTORY | O_CLOEXEC);
  if (UNLIKELY (image_fd == -1))
    return crun_make_error (err, errno, "error opening checkpoint directory `%s`", cr_options->image_path);

  libcriu_wrapper->criu_set_images_dir_fd (image_fd);

  /* Set up logging. */
  libcriu_wrapper->criu_set_log_level (4);
  libcriu_wrapper->criu_set_log_file (CRIU_CHECKPOINT_LOG_FILE);

  /* Set up CRIU config file */
  if (UNLIKELY (handle_criu_config_file (container, err)))
    return -1;

  /* Setting the pid early as we can skip a lot of checkpoint setup if
   * we just do a pre-dump. The PID needs to be set always. Do it here.
   * The main process of the container is the process CRIU will checkpoint
   * and all of its children. */
  libcriu_wrapper->criu_set_pid (status->pid);

  /* work_dir is the place CRIU will put its logfiles. If not explicitly set,
   * CRIU will put the logfiles into the images_dir from above. No need for
   * crun to set it if the user has not selected a specific directory. */
  if (cr_options->work_path != NULL)
    {
      ret = mkdir (cr_options->work_path, 0700);
      if (UNLIKELY ((ret == -1) && (errno != EEXIST)))
        return crun_make_error (err, errno, "error creating CRIU work directory `%s`", cr_options->work_path);

      work_fd = open (cr_options->work_path, O_DIRECTORY | O_CLOEXEC);
      if (UNLIKELY (work_fd == -1))
        return crun_make_error (err, errno, "error opening CRIU work directory `%s`", cr_options->work_path);

      libcriu_wrapper->criu_set_work_dir_fd (work_fd);
    }
  else
    {
      /* This is only for the error message later. */
      cr_options->work_path = cr_options->image_path;
    }

#  ifdef CRIU_PRE_DUMP_SUPPORT

  {
    int criu_can_mem_track = 0;
    /* If the user uses --pre-dump for the second time or does
     * a final dump from a previous pre-dump, setting parent_path
     * is necessary so that CRIU can find which pages have not
     * changed compared to the previous dump. */
    if (cr_options->parent_path != NULL)
      {
        criu_can_mem_track = criu_check_mem_track (err);
        if (UNLIKELY (criu_can_mem_track == -1))
          return -1;
        libcriu_wrapper->criu_set_track_mem (true);

        /* The parent path must be relative to image path (something like ../previous-dump).
           CRIU will fail with an unclear error message if the path is not right.
         */
        if (UNLIKELY (cr_options->parent_path[0] == '/'))
          return crun_make_error (err, 0, "--parent-path must be relative");
        int is_dir = crun_dir_p_at (image_fd, cr_options->parent_path, false, err);
        if (UNLIKELY (is_dir <= 0))
          {
            if (is_dir < 0)
              return crun_error_wrap (err, "invalid --parent-path");
            return crun_make_error (err, ENOTDIR, "invalid --parent-path");
          }
        ret = libcriu_wrapper->criu_set_parent_images (cr_options->parent_path);
        if (UNLIKELY (ret != 0))
          return crun_make_error (err, -ret, "error setting CRIU parent images path to `%s`", cr_options->parent_path);
      }

    if (cr_options->pre_dump)
      {
        if (criu_can_mem_track != 1)
          {
            criu_can_mem_track = criu_check_mem_track (err);
            if (UNLIKELY (criu_can_mem_track == -1))
              return -1;
          }
        libcriu_wrapper->criu_set_track_mem (true);
        ret = libcriu_wrapper->criu_pre_dump ();
        if (UNLIKELY (ret != 0))
          {
            show_criu_log (cr_options->work_path, CRIU_CHECKPOINT_LOG_FILE);
            return crun_make_error (err, 0, "CRIU pre-dump failed: %d", ret);
          }
        return 0;
      }
  }
#  endif

  /* descriptors.json is needed during restore to correctly
   * reconnect stdin, stdout, stderr. */
  ret = append_paths (&descriptors_path, err, cr_options->image_path, DESCRIPTORS_FILENAME, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = write_file (descriptors_path, status->external_descriptors, strlen (status->external_descriptors), err);
  if (UNLIKELY (ret < 0))
    return crun_error_wrap (err, "error saving CRIU descriptors file");

  ret = append_paths (&path, err, status->bundle, status->rootfs, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcriu_wrapper->criu_set_root (path);
  if (UNLIKELY (ret != 0))
    return crun_make_error (err, 0, "error setting CRIU root to `%s`", path);

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  /* For cgroup v1 we need to tell CRIU to handle all cgroup mounts as external mounts. */
  if (cgroup_mode != CGROUP_MODE_UNIFIED)
    {
      ret = checkpoint_cgroup_v1_mount (def, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* Tell CRIU about external bind mounts. */
  for (i = 0; i < def->mounts_len; i++)
    {
      bool nofollow = false;
      if (is_bind_mount (def->mounts[i], NULL, &nofollow))
        {
          /* We need to resolve mount destination inside container's root for CRIU to handle. */
          char buf[PATH_MAX];
          const char *dest_in_root;

          if (nofollow)
            return crun_make_error (err, 0, "CRIU does not support `src-nofollow` for bind mounts");

          dest_in_root = chroot_realpath (status->rootfs, def->mounts[i]->destination, buf);
          if (UNLIKELY (dest_in_root == NULL))
            {
              if (errno != ENOENT)
                return crun_make_error (err, errno, "unable to resolve external bind mount `%s` under rootfs", def->mounts[i]->destination);
              else
                dest_in_root = def->mounts[i]->destination;
            }
          else
            dest_in_root += strlen (status->rootfs);

          ret = libcriu_wrapper->criu_add_ext_mount (dest_in_root, dest_in_root);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, -ret, "CRIU: failed adding external mount to `%s`", def->mounts[i]->destination);
        }
    }

  ret = register_masked_paths_mounts (def, container, libcriu_wrapper, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* CRIU tries to checkpoint and restore all namespaces. However,
   * namespaces could be shared between containers in a pod.
   * To address this, CRIU provides support for external namespaces.
   * External namespaces allow to ignore the namespace during checkpoint
   * and restore the container into the existing namespaces.
   *
   * We are looking at config.json and if there is a path configured for
   * a namespace we are telling CRIU to ignore the namespace and
   * just restore the container into the existing namespace.
   *
   * In the case of Podman, a network namespace would be created via CNI.
   *
   * CRIU expects the information about an external namespace like this:
   * --external <namespace>[<inode>]:<key>
   */

  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      int value = libcrun_find_namespace (def->linux->namespaces[i]->type);
      if (UNLIKELY (value < 0))
        return crun_make_error (err, 0, "invalid namespace type: `%s`", def->linux->namespaces[i]->type);

      if (value == CLONE_NEWNET && def->linux->namespaces[i]->path != NULL)
        {
          cleanup_free char *external = NULL;
          struct stat statbuf;

          ret = stat (def->linux->namespaces[i]->path, &statbuf);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "unable to stat(): `%s`", def->linux->namespaces[i]->path);

          xasprintf (&external, "net[%ld]:" CRIU_EXT_NETNS, statbuf.st_ino);
          ret = libcriu_wrapper->criu_add_external (external);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, -ret, "CRIU: failed adding external namespace `%s`", external);
        }

      if (value == CLONE_NEWPID && def->linux->namespaces[i]->path != NULL)
        {
          cleanup_free char *external = NULL;
          struct stat statbuf;

          ret = stat (def->linux->namespaces[i]->path, &statbuf);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "unable to stat(): `%s`", def->linux->namespaces[i]->path);

          xasprintf (&external, "pid[%ld]:" CRIU_EXT_PIDNS, statbuf.st_ino);
          ret = libcriu_wrapper->criu_add_external (external);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, -ret, "CRIU: failed adding external namespace `%s`", external);
        }
    }

  /* Tell CRIU to use the freezer to pause all container processes. */
  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    {
      /* This needs CRIU 3.14. */
      ret = append_paths (&freezer_path, err, CGROUP_ROOT, status->cgroup_path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      ret = append_paths (&freezer_path, err, CGROUP_ROOT "/freezer", status->cgroup_path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcriu_wrapper->criu_set_freeze_cgroup (freezer_path);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "CRIU: failed setting freezer %d", ret);

  /* Set boolean options . */
  libcriu_wrapper->criu_set_leave_running (cr_options->leave_running);
  libcriu_wrapper->criu_set_ext_unix_sk (cr_options->ext_unix_sk);
  libcriu_wrapper->criu_set_shell_job (cr_options->shell_job);
  libcriu_wrapper->criu_set_tcp_established (cr_options->tcp_established);
  libcriu_wrapper->criu_set_file_locks (cr_options->file_locks);
  libcriu_wrapper->criu_set_orphan_pts_master (true);
  if (cr_options->manage_cgroups_mode == -1)
    /* Defaulting to CRIU_CG_MODE_SOFT just as runc */
    libcriu_wrapper->criu_set_manage_cgroups_mode (CRIU_CG_MODE_SOFT);
  else
    libcriu_wrapper->criu_set_manage_cgroups_mode (cr_options->manage_cgroups_mode);

  libcriu_wrapper->criu_set_manage_cgroups (true);

  if (libcriu_wrapper->criu_set_network_lock && cr_options->network_lock_method > 0)
    {
      ret = libcriu_wrapper->criu_set_network_lock (cr_options->network_lock_method);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, 0, "CRIU: failed setting network lock");
    }

  ret = libcriu_wrapper->criu_dump ();
  if (UNLIKELY (ret != 0))
    {
      show_criu_log (cr_options->work_path, CRIU_CHECKPOINT_LOG_FILE);
      return crun_make_error (err, ret < 0 ? -ret : 0, "CRIU checkpointing failed: %d", ret);
    }

  return 0;
}

static int
prepare_restore_mounts (runtime_spec_schema_config_schema *def, char *root, libcrun_error_t *err)
{
  uint32_t i;

  /* Go through all mountpoints to be able to recreate missing mountpoints. */
  for (i = 0; i < def->mounts_len; i++)
    {
      char *dest = def->mounts[i]->destination;
      char *type = def->mounts[i]->type;
      cleanup_close int root_fd = -1;
      bool nofollow = false;
      bool on_tmpfs = false;
      int is_dir = 1;
      size_t j;

      /* cgroup restore should be handled by CRIU itself */
      if (type && (strcmp (type, "cgroup") == 0 || strcmp (type, "cgroup2") == 0))
        continue;

      /* Check if the mountpoint is on a tmpfs. CRIU restores
       * all tmpfs. We do need to recreate directories on a tmpfs. */
      size_t dest_len = strlen (dest);
      for (j = 0; j < def->mounts_len; j++)
        {
          if (def->mounts[j]->type == NULL || strcmp (def->mounts[j]->type, "tmpfs") != 0)
            continue;
          size_t mount_len = strlen (def->mounts[j]->destination);
          if (mount_len < dest_len && dest[mount_len] == '/' && strncmp (dest, def->mounts[j]->destination, mount_len) == 0)
            {
              /* This is a mountpoint which is on a tmpfs.*/
              on_tmpfs = true;
              break;
            }
        }

      if (on_tmpfs)
        continue;

      /* For bind mounts check if the source is a file or a directory. */
      if (is_bind_mount (def->mounts[i], NULL, &nofollow))
        {
          if (nofollow)
            return crun_make_error (err, 0, "CRIU does not support `src-nofollow` for bind mounts");

          is_dir = crun_dir_p (def->mounts[i]->source, false, err);
          if (UNLIKELY (is_dir < 0))
            return is_dir;
        }

      root_fd = open (root, O_RDONLY | O_CLOEXEC);
      if (UNLIKELY (root_fd == -1))
        return crun_make_error (err, errno, "error opening container root directory `%s`", root);

      if (is_dir)
        {
          int ret;

          ret = crun_safe_ensure_directory_at (root_fd, root, dest, 0755, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          int ret;

          ret = crun_safe_ensure_file_at (root_fd, root, dest, 0755, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  return 0;
}

int
libcrun_container_restore_linux_criu (libcrun_container_status_t *status, libcrun_container_t *container,
                                      libcrun_checkpoint_restore_t *cr_options, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_wrapper struct libcriu_wrapper_s *wrapper = NULL;
  cleanup_close int inherit_new_net_fd = -1;
  cleanup_close int inherit_new_pid_fd = -1;
  cleanup_close int image_fd = -1;
  cleanup_free char *root = NULL;
  cleanup_free char *bundle_cleanup = NULL;
  cleanup_close int work_fd = -1;
  int ret_out;
  size_t i;
  int ret;

  ret = load_wrapper (&wrapper, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (geteuid ())
    return crun_make_error (err, 0, "restoring requires root");

  ret = libcriu_wrapper->criu_init_opts ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "CRIU init failed with %d", ret);

  ret = validate_criu_version (err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (cr_options->image_path == NULL))
    return crun_make_error (err, 0, "image path not set");

  image_fd = open (cr_options->image_path, O_DIRECTORY | O_CLOEXEC);
  if (UNLIKELY (image_fd == -1))
    return crun_make_error (err, errno, "error opening checkpoint directory `%s`", cr_options->image_path);

  libcriu_wrapper->criu_set_images_dir_fd (image_fd);

  /* Load descriptors.json to tell CRIU where those FDs should be connected to. */
  {
    cleanup_free char *descriptors_path = NULL;
    cleanup_free char *buffer = NULL;
    char err_buffer[256];
    yajl_val tree;

    ret = append_paths (&descriptors_path, err, cr_options->image_path, DESCRIPTORS_FILENAME, NULL);
    if (UNLIKELY (ret < 0))
      return ret;

    ret = read_all_file (descriptors_path, &buffer, NULL, err);
    if (UNLIKELY (ret < 0))
      return ret;

    /* descriptors.json contains a JSON array with strings
     * telling where 0, 1 and 2 have been initially been
     * pointing to. For each descriptor which points to
     * a pipe 'pipe:' we tell CRIU to reconnect that pipe
     * to the corresponding FD to have (especially) stdout
     * and stderr being correctly redirected. */
    tree = yajl_tree_parse (buffer, err_buffer, sizeof (err_buffer));
    if (UNLIKELY (tree == NULL))
      return crun_make_error (err, 0, "cannot parse descriptors file `%s`", DESCRIPTORS_FILENAME);

    if (tree && YAJL_IS_ARRAY (tree))
      {
        size_t i, len = tree->u.array.len;

        /* len will probably always be 3 as crun is currently only
         * recording the destination of FD 0, 1 and 2. */
        for (i = 0; i < len; ++i)
          {
            yajl_val s = tree->u.array.values[i];
            if (s && YAJL_IS_STRING (s))
              {
                char *str = YAJL_GET_STRING (s);
                if (has_prefix (str, "pipe:"))
                  libcriu_wrapper->criu_add_inherit_fd (i, str);
              }
          }
      }
    yajl_tree_free (tree);
  }

  /* work_dir is the place CRIU will put its logfiles. If not explicitly set,
   * CRIU will put the logfiles into the images_dir from above. No need for
   * crun to set it if the user has not selected a specific directory. */
  if (cr_options->work_path != NULL)
    {
      ret = mkdir (cr_options->work_path, 0700);
      if (UNLIKELY ((ret == -1) && (errno != EEXIST)))
        return crun_make_error (err, errno, "error creating CRIU work directory `%s`", cr_options->work_path);

      work_fd = open (cr_options->work_path, O_DIRECTORY | O_CLOEXEC);
      if (UNLIKELY (work_fd == -1))
        return crun_make_error (err, errno, "error opening CRIU work directory `%s`", cr_options->work_path);

      libcriu_wrapper->criu_set_work_dir_fd (work_fd);
    }
  else
    {
      /* This is only for the error message later. */
      cr_options->work_path = cr_options->image_path;
    }

  if (cr_options->lsm_profile != NULL)
    {
      ret = libcriu_wrapper->criu_set_lsm_profile (cr_options->lsm_profile);
      if (UNLIKELY (ret != 0))
        return crun_make_error (err, -ret, "error setting LSM profile to `%s`", cr_options->lsm_profile);
    }

  if (cr_options->lsm_mount_context != NULL)
    {
      ret = libcriu_wrapper->criu_set_lsm_mount_context (cr_options->lsm_mount_context);
      if (UNLIKELY (ret != 0))
        return crun_make_error (err, -ret, "error setting LSM mount context to `%s`", cr_options->lsm_mount_context);
    }

  /* Tell CRIU about external bind mounts. */
  for (i = 0; i < def->mounts_len; i++)
    {
      bool nofollow = false;
      if (is_bind_mount (def->mounts[i], NULL, &nofollow))
        {
          /* We need to resolve mount destination inside container's root for CRIU to handle. */
          char buf[PATH_MAX];
          const char *dest_in_root;

          if (nofollow)
            return crun_make_error (err, 0, "CRIU does not support `src-nofollow` for bind mounts");

          dest_in_root = chroot_realpath (status->rootfs, def->mounts[i]->destination, buf);
          if (UNLIKELY (dest_in_root == NULL))
            {
              if (errno != ENOENT)
                return crun_make_error (err, errno, "unable to resolve external bind mount destination `%s` under rootfs", def->mounts[i]->destination);
              dest_in_root = def->mounts[i]->destination;
            }
          else
            dest_in_root += strlen (status->rootfs);

          ret = libcriu_wrapper->criu_add_ext_mount (dest_in_root, def->mounts[i]->source);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, -ret, "CRIU: failed adding external mount to `%s`", def->mounts[i]->source);
        }
    }

  ret = register_masked_paths_mounts (def, container, libcriu_wrapper, true, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* do realpath on root */
  bundle_cleanup = realpath (status->bundle, NULL);
  if (UNLIKELY (bundle_cleanup == NULL))
    bundle_cleanup = xstrdup (status->bundle);

  /* Mount the container rootfs for CRIU. */
  ret = append_paths (&root, err, bundle_cleanup, "criu-root", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = mkdir (root, 0755);
  if (UNLIKELY (ret == -1))
    return crun_make_error (err, errno, "error creating restore directory `%s`", root);

  ret = mount (status->rootfs, root, NULL, MS_BIND | MS_REC, NULL);
  if (UNLIKELY (ret == -1))
    {
      ret = crun_make_error (err, errno, "error mounting restore directory `%s`", root);
      goto out;
    }

  /* During initial container creation, crun will create mountpoints
   * defined in config.json if they do not exist. If we are restoring
   * we need to make sure these mountpoints also exist.
   * This is not perfect, as this means crun will modify a rootfs
   * even if it marked as read-only, but runc already modifies
   * the rootfs in the same way. */

  ret = prepare_restore_mounts (def, root, err);
  if (UNLIKELY (ret < 0))
    goto out_umount;

  ret = libcriu_wrapper->criu_set_root (root);
  if (UNLIKELY (ret != 0))
    {
      ret = crun_make_error (err, -ret, "error setting CRIU root to `%s`", root);
      goto out_umount;
    }

  /* If a namespace defined in config.json we are telling
   * CRIU use that namespace when restoring the process tree.
   *
   * CRIU expects the information about the namespace like this:
   * --inherit-fd fd[<fd>]:<key>
   * The <key> needs to be the same as during checkpointing (extRootNetNS). */
  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      const int open_flags_for_inherit = O_RDONLY; /* Cannot be O_CLOEXEC as it is passed to the child process. */
      int value = libcrun_find_namespace (def->linux->namespaces[i]->type);
      if (UNLIKELY (value < 0))
        {
          ret = crun_make_error (err, 0, "invalid namespace type: `%s`", def->linux->namespaces[i]->type);
          goto out_umount;
        }

      if (value == CLONE_NEWNET && def->linux->namespaces[i]->path != NULL)
        {
          inherit_new_net_fd = open (def->linux->namespaces[i]->path, open_flags_for_inherit);
          if (UNLIKELY (inherit_new_net_fd < 0))
            {
              ret = crun_make_error (err, errno, "unable to open(): `%s`", def->linux->namespaces[i]->path);
              goto out_umount;
            }

          ret = libcriu_wrapper->criu_add_inherit_fd (inherit_new_net_fd, CRIU_EXT_NETNS);
          if (UNLIKELY (ret < 0))
            {
              ret = crun_make_error (err, -ret, "CRIU: failed adding fd");
              goto out_umount;
            }
        }

      if (value == CLONE_NEWPID && def->linux->namespaces[i]->path != NULL)
        {
          inherit_new_pid_fd = open (def->linux->namespaces[i]->path, open_flags_for_inherit);
          if (UNLIKELY (inherit_new_pid_fd < 0))
            {
              ret = crun_make_error (err, errno, "unable to open(): `%s`", def->linux->namespaces[i]->path);
              goto out_umount;
            }

          ret = libcriu_wrapper->criu_add_inherit_fd (inherit_new_pid_fd, CRIU_EXT_PIDNS);
          if (UNLIKELY (ret < 0))
            {
              ret = crun_make_error (err, -ret, "CRIU: failed adding fd");
              goto out_umount;
            }
        }

#  ifdef CRIU_JOIN_NS_SUPPORT
      if (value == CLONE_NEWTIME && def->linux->namespaces[i]->path != NULL)
        {
          if (libcriu_wrapper->criu_join_ns_add == NULL)
            {
              ret = crun_make_error (err, 0, "shared time namespace restore is supported in CRIU >= 3.16.1");
              goto out_umount;
            }

          ret = libcriu_wrapper->criu_join_ns_add ("time", def->linux->namespaces[i]->path, NULL);
          if (UNLIKELY (ret < 0))
            {
              ret = crun_make_error (err, -ret, "CRIU: failed adding external namespace `%s`", def->linux->namespaces[i]->path);
              goto out_umount;
            }
        }

      if (value == CLONE_NEWIPC && def->linux->namespaces[i]->path != NULL)
        {
          if (libcriu_wrapper->criu_join_ns_add == NULL)
            {
              ret = crun_make_error (err, 0, "shared ipc namespace restore is supported in CRIU >= 3.16.1");
              goto out_umount;
            }

          ret = libcriu_wrapper->criu_join_ns_add ("ipc", def->linux->namespaces[i]->path, NULL);
          if (UNLIKELY (ret < 0))
            {
              ret = crun_make_error (err, -ret, "CRIU: failed adding external namespace `%s`", def->linux->namespaces[i]->path);
              goto out_umount;
            }
        }

      if (value == CLONE_NEWUTS && def->linux->namespaces[i]->path != NULL)
        {
          if (libcriu_wrapper->criu_join_ns_add == NULL)
            {
              ret = crun_make_error (err, 0, "shared uts namespace restore is supported in CRIU >= 3.16.1");
              goto out_umount;
            }

          ret = libcriu_wrapper->criu_join_ns_add ("uts", def->linux->namespaces[i]->path, NULL);
          if (UNLIKELY (ret < 0))
            {
              ret = crun_make_error (err, -ret, "CRIU: failed adding external namespace `%s`", def->linux->namespaces[i]->path);
              goto out_umount;
            }
        }
#  endif
    }

  /* Set up CRIU config file */
  ret = handle_criu_config_file (container, err);
  if (UNLIKELY (ret < 0))
    goto out_umount;

  /* Tell CRIU if cgroup v1 needs to be handled. */
  ret = restore_cgroup_v1_mount (def, err);
  if (UNLIKELY (ret < 0))
    goto out_umount;

  console_socket = cr_options->console_socket;
  libcriu_wrapper->criu_set_notify_cb (criu_notify);

  /* Set boolean options . */
  libcriu_wrapper->criu_set_ext_unix_sk (cr_options->ext_unix_sk);
  libcriu_wrapper->criu_set_shell_job (cr_options->shell_job);
  libcriu_wrapper->criu_set_tcp_established (cr_options->tcp_established);
  libcriu_wrapper->criu_set_tcp_close (cr_options->tcp_close);
  libcriu_wrapper->criu_set_file_locks (cr_options->file_locks);
  libcriu_wrapper->criu_set_orphan_pts_master (true);

  if (status->cgroup_path)
    {
      ret = libcriu_wrapper->criu_add_cg_root (NULL, status->cgroup_path);
      if (UNLIKELY (ret != 0))
        {
          ret = crun_make_error (err, 0, "error setting CRIU cgroup root to `%s`", status->cgroup_path);
          goto out_umount;
        }
    }

  if (cr_options->manage_cgroups_mode == -1)
    /* Defaulting to CRIU_CG_MODE_SOFT just as runc */
    libcriu_wrapper->criu_set_manage_cgroups_mode (CRIU_CG_MODE_SOFT);
  else
    libcriu_wrapper->criu_set_manage_cgroups_mode (cr_options->manage_cgroups_mode);
  libcriu_wrapper->criu_set_manage_cgroups (true);

  if (libcriu_wrapper->criu_set_network_lock && cr_options->network_lock_method > 0)
    {
      ret = libcriu_wrapper->criu_set_network_lock (cr_options->network_lock_method);
      if (UNLIKELY (ret < 0))
        {
          ret = crun_make_error (err, 0, "CRIU: failed setting network lock");
          goto out_umount;
        }
    }

  libcriu_wrapper->criu_set_log_level (4);
  ret = libcriu_wrapper->criu_set_log_file (CRIU_RESTORE_LOG_FILE);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, -ret, "error setting CRIU log file to `%s`", CRIU_RESTORE_LOG_FILE);
      goto out_umount;
    }

  /* criu_restore() returns the PID of the process of the restored process
   * tree. This PID will not be the same as status->pid if the container is
   * running in a PID namespace. But it will always be > 0. */
  ret = libcriu_wrapper->criu_restore_child ();
  if (UNLIKELY (ret <= 0))
    {
      show_criu_log (cr_options->work_path, CRIU_RESTORE_LOG_FILE);
      ret = crun_make_error (err, 0, "CRIU restoring failed: %d", ret);
      goto out_umount;
    }

  /* Update the status struct with the newly allocated PID. This will
   * be necessary later when moving the process into its cgroup. */
  status->pid = ret;

  ret = libcrun_save_external_descriptors (container, ret, err);

out_umount:
  ret_out = umount (root);
  if (UNLIKELY (ret_out == -1))
    {
      int saved_errno = errno;
      rmdir (root);
      if (ret < 0)
        return crun_error_wrap (err, "error unmounting restore directory `%s`", root);
      else
        return crun_make_error (err, saved_errno, "error unmounting restore directory `%s`", root);
    }
out:
  ret_out = rmdir (root);
  if (UNLIKELY (ret < 0))
    return ret;
  if (UNLIKELY (ret_out == -1))
    return crun_make_error (err, errno, "error removing restore directory `%s`", root);
  return ret;
}

#  define CRIU_TFORK_LOG_FILE "tfork.log"
#  define CRIU_TFORK_RESTORE_LOG_FILE "tfork-restore.log"
#  define CRIU_TFORK_MAX_COPY_LOGS 16

static void
show_criu_tfork_restore_copy_logs (const char *image_path, int copy_count)
{
  if (copy_count < 0)
    copy_count = 0;
  if (copy_count > CRIU_TFORK_MAX_COPY_LOGS)
    copy_count = CRIU_TFORK_MAX_COPY_LOGS;

  for (int i = 0; i < copy_count; i++)
    {
      char log[64];
      snprintf (log, sizeof (log), "%s.copy%d", CRIU_TFORK_RESTORE_LOG_FILE, i);
      show_criu_log (image_path, log);
    }
}

static int
read_source_state_pid_cgroup (const char *path, pid_t *pid_out, char **cgroup_path_out, libcrun_error_t *err)
{
  cleanup_free char *buffer = NULL;
  char err_buffer[256];
  yajl_val tree, tmp;
  const char *pid_path[] = { "pid", NULL };
  const char *cgroup_path[] = { "cgroup-path", NULL };
  int ret;

  ret = read_all_file (path, &buffer, NULL, err);
  if (UNLIKELY (ret < 0))
    return crun_error_wrap (err, "cannot read source state.json `%s`", path);

  tree = yajl_tree_parse (buffer, err_buffer, sizeof (err_buffer));
  if (UNLIKELY (tree == NULL))
    return crun_make_error (err, 0, "cannot parse source state.json `%s`: %s", path, err_buffer);

  tmp = yajl_tree_get (tree, pid_path, yajl_t_number);
  if (UNLIKELY (tmp == NULL))
    {
      yajl_tree_free (tree);
      return crun_make_error (err, 0, "`pid` missing in source state.json `%s`", path);
    }

  *pid_out = (pid_t) strtoull (YAJL_GET_NUMBER (tmp), NULL, 10);

  tmp = yajl_tree_get (tree, cgroup_path, yajl_t_string);
  if (UNLIKELY (tmp == NULL))
    {
      yajl_tree_free (tree);
      return crun_make_error (err, 0, "`cgroup-path` missing in source state.json `%s`", path);
    }

  *cgroup_path_out = xstrdup (YAJL_GET_STRING (tmp));
  yajl_tree_free (tree);
  return 0;
}

static int
tfork_alloc_console_ptys (libcrun_checkpoint_restore_t *cr_options,
                          const char *console_socket_path,
                          libcrun_error_t *err)
{
  size_t i;

  if (console_socket_path == NULL || cr_options->external_n == 0)
    return 0;

  for (i = 0; i < cr_options->external_n; i++)
    {
      const char *key = cr_options->external[i];
      cleanup_close int master_fd = -1;
      cleanup_close int console_socket_fd = -1;
      cleanup_free char *pts_path = NULL;
      int j, ret;

      if (strncmp (key, "tty[", 4) != 0)
        continue;

      master_fd = libcrun_new_terminal (&pts_path, err);
      if (UNLIKELY (master_fd < 0))
        return master_fd;

      for (j = 0; j < 3; j++)
        {
          int slave_fd = open (pts_path, O_RDWR);
          if (UNLIKELY (slave_fd < 0))
            return crun_make_error (err, errno, "open pts slave `%s`", pts_path);
          ret = libcriu_wrapper->criu_add_inherit_fd (slave_fd, key);
          if (UNLIKELY (ret != 0))
            {
              close (slave_fd);
              return crun_make_error (err, 0, "criu_add_inherit_fd(%d, %s) failed: %d",
                                      slave_fd, key, ret);
            }

        }

      console_socket_fd = open_unix_domain_client_socket (console_socket_path, 0, err);
      if (UNLIKELY (console_socket_fd < 0))
        return console_socket_fd;
      ret = send_fd_to_socket (console_socket_fd, master_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;

    }

  return 0;
}

int
libcrun_container_tfork_linux_criu (libcrun_container_t *container, libcrun_checkpoint_restore_t *cr_options,
                                    pid_t *clone_pid_out, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_wrapper struct libcriu_wrapper_s *wrapper = NULL;
  cleanup_free char *freezer_path = NULL;
  cleanup_free char *rootfs_path = NULL;
  cleanup_free char *source_cgroup_path = NULL;
  cleanup_close int image_fd = -1;
  cleanup_close int work_fd = -1;
  pid_t source_pid = 0;
  int cgroup_mode;
  int ret;

  ret = load_wrapper (&wrapper, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (libcriu_wrapper->criu_tfork == NULL)
    return crun_make_error (err, 0, "loaded libcriu does not export `criu_tfork`; rebuild against criu >= 4.2 with tfork");

  if (geteuid ())
    return crun_make_error (err, 0, "tfork requires root");

  if (UNLIKELY (cr_options->tfork_snap_root == NULL
                && cr_options->tfork_snap_roots_n == 0
                && cr_options->tfork_copy_args_n == 0))
    return crun_make_error (err, 0,
                            "--tfork-snap-root, --tfork-snap-roots, or --tfork-copy=<i>::--tfork-snap-root=PATH is required");

  if (cr_options->tfork_copies >= 1 && cr_options->tfork_snap_roots_n > 0
      && (size_t) cr_options->tfork_copies != cr_options->tfork_snap_roots_n)
    return crun_make_error (err, 0,
                            "--tfork-copies=%d but --tfork-snap-roots has %zu entries",
                            cr_options->tfork_copies, cr_options->tfork_snap_roots_n);

  if (UNLIKELY (cr_options->image_path == NULL))
    return crun_make_error (err, 0, "--image-path is required");

  ret = read_source_state_pid_cgroup (cr_options->source_state, &source_pid, &source_cgroup_path, err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (UNLIKELY (source_pid <= 0))
    return crun_make_error (err, 0, "source state.json reports invalid pid %d", (int) source_pid);

  ret = libcriu_wrapper->criu_init_opts ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "criu_init_opts failed: %d", ret);

  ret = mkdir (cr_options->image_path, 0700);
  if (UNLIKELY (ret == -1 && errno != EEXIST))
    return crun_make_error (err, errno, "mkdir `%s`", cr_options->image_path);
  image_fd = open (cr_options->image_path, O_DIRECTORY | O_CLOEXEC);
  if (UNLIKELY (image_fd == -1))
    return crun_make_error (err, errno, "open `%s`", cr_options->image_path);
  libcriu_wrapper->criu_set_images_dir_fd (image_fd);

  if (cr_options->work_path != NULL)
    {
      ret = mkdir (cr_options->work_path, 0700);
      if (UNLIKELY (ret == -1 && errno != EEXIST))
        return crun_make_error (err, errno, "mkdir `%s`", cr_options->work_path);
      work_fd = open (cr_options->work_path, O_DIRECTORY | O_CLOEXEC);
      if (UNLIKELY (work_fd == -1))
        return crun_make_error (err, errno, "open `%s`", cr_options->work_path);
      libcriu_wrapper->criu_set_work_dir_fd (work_fd);
    }
  else
    {
      cr_options->work_path = cr_options->image_path;
    }

  libcriu_wrapper->criu_set_log_level (4);
  libcriu_wrapper->criu_set_log_file (CRIU_TFORK_LOG_FILE);

  if (cr_options->tfork_ghost_limit > 0)
    libcriu_wrapper->criu_set_ghost_limit (cr_options->tfork_ghost_limit);

  if (cr_options->tcp_close)
    libcriu_wrapper->criu_set_tcp_close (true);

  libcriu_wrapper->criu_set_pid (source_pid);
  libcriu_wrapper->criu_set_leave_running (true);
  libcriu_wrapper->criu_set_ext_unix_sk (cr_options->ext_unix_sk);
  libcriu_wrapper->criu_set_file_locks (true);

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    ret = append_paths (&freezer_path, err, CGROUP_ROOT, source_cgroup_path, NULL);
  else
    ret = append_paths (&freezer_path, err, CGROUP_ROOT "/freezer", source_cgroup_path, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcriu_wrapper->criu_set_freeze_cgroup (freezer_path);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "CRIU: failed setting tfork freezer %d", ret);

  if (def->root != NULL && def->root->path != NULL)
    {
      ret = append_paths (&rootfs_path, err, container->context ? container->context->bundle : ".",
                          def->root->path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;
      ret = libcriu_wrapper->criu_set_root (rootfs_path);
      if (UNLIKELY (ret != 0))
        return crun_make_error (err, 0, "criu_set_root `%s` failed: %d", rootfs_path, ret);
    }

  if (cr_options->tfork_snap_root != NULL)
    {
      ret = libcriu_wrapper->criu_set_tfork_snap_root (cr_options->tfork_snap_root);
      if (UNLIKELY (ret != 0))
        return crun_make_error (err, 0, "criu_set_tfork_snap_root failed: %d", ret);
    }

  if (cr_options->tfork_snap_roots_n > 0)
    {
      size_t i;
      if (libcriu_wrapper->criu_add_tfork_snap_root == NULL)
        return crun_make_error (err, 0,
                                "loaded libcriu lacks criu_add_tfork_snap_root; rebuild against criu >= 4.2 with N-copy");
      for (i = 0; i < cr_options->tfork_snap_roots_n; i++)
        {
          ret = libcriu_wrapper->criu_add_tfork_snap_root (cr_options->tfork_snap_roots[i]);
          if (UNLIKELY (ret != 0))
            return crun_make_error (err, 0, "criu_add_tfork_snap_root(%s) failed: %d",
                                    cr_options->tfork_snap_roots[i], ret);
        }
    }

  if (cr_options->tfork_snap_mounts_n > 0)
    {
      size_t i;
      if (libcriu_wrapper->criu_add_tfork_snap_mount == NULL)
        return crun_make_error (err, 0,
                                "loaded libcriu lacks criu_add_tfork_snap_mount; rebuild against criu with --tfork-snap-mount support");
      for (i = 0; i < cr_options->tfork_snap_mounts_n; i++)
        {
          ret = libcriu_wrapper->criu_add_tfork_snap_mount (cr_options->tfork_snap_mounts[i]);
          if (UNLIKELY (ret != 0))
            return crun_make_error (err, 0, "criu_add_tfork_snap_mount(%s) failed: %d",
                                    cr_options->tfork_snap_mounts[i], ret);
        }
    }

  if (cr_options->tfork_copies >= 1)
    libcriu_wrapper->criu_set_tfork_copies (cr_options->tfork_copies);

  if (cr_options->tfork_memdump_async)
    libcriu_wrapper->criu_set_tfork_memdump_async (true);
  if (cr_options->tfork_memdump)
    libcriu_wrapper->criu_set_tfork_memdump (true);

  if (cr_options->tfork_memdump_async)
    {
      if (libcriu_wrapper->criu_set_tfork_dumpd_parent_pid == NULL)
        return crun_make_error (err, 0,
                                "--tfork-memdump-async: linked libcriu lacks "
                                "criu_set_tfork_dumpd_parent_pid (rebuild "
                                "against criu with the RPC peer-disconnect "
                                "fix; see CRIU_TFORK_RPC_PEER_DISCONNECT_LEAK.md)");
      if (cr_options->tfork_dumpd_parent_pid <= 0)
        return crun_make_error (err, 0,
                                "--tfork-memdump-async requires --tfork-dumpd-parent=<PID> "
                                "naming a long-lived host-pidns process that will outlive "
                                "dumpd (for the podman integration, a dedicated holder "
                                "subprocess pre-forked before the runtime). No default — "
                                "caller picks a PID with the right lifetime.");
      libcriu_wrapper->criu_set_tfork_dumpd_parent_pid (cr_options->tfork_dumpd_parent_pid);
    }

  if (cr_options->tfork_full_memcopy)
    {
      if (libcriu_wrapper->criu_set_tfork_full_memcopy == NULL)
        return crun_make_error (err, 0,
                                "--tfork-full-memcopy: linked libcriu lacks "
                                "criu_set_tfork_full_memcopy (rebuild against "
                                "a criu with --tfork-full-memcopy support)");
      libcriu_wrapper->criu_set_tfork_full_memcopy (true);
    }

  if (libcriu_wrapper->criu_set_network_lock && cr_options->network_lock_method > 0)
    {
      ret = libcriu_wrapper->criu_set_network_lock (cr_options->network_lock_method);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, 0, "CRIU: failed setting tfork network lock");
    }

  if (cr_options->track_mem || cr_options->tfork_memdump)
    libcriu_wrapper->criu_set_track_mem (true);

  if (cr_options->parent_path != NULL)
    {
      ret = libcriu_wrapper->criu_set_parent_images (cr_options->parent_path);
      if (UNLIKELY (ret != 0))
        return crun_make_error (err, 0, "criu_set_parent_images `%s` failed: %d", cr_options->parent_path, ret);
    }

  if (cr_options->manage_cgroups_mode != -1)
    libcriu_wrapper->criu_set_manage_cgroups_mode (cr_options->manage_cgroups_mode);

  if (cr_options->skip_mnt_n > 0 && libcriu_wrapper->criu_add_skip_mnt != NULL)
    {
      size_t i;
      for (i = 0; i < cr_options->skip_mnt_n; i++)
        {
          ret = libcriu_wrapper->criu_add_skip_mnt (cr_options->skip_mnt[i]);
          if (UNLIKELY (ret != 0))
            return crun_make_error (err, 0, "criu_add_skip_mnt(%s) failed: %d", cr_options->skip_mnt[i], ret);
        }
    }

  if (cr_options->inherit_fd_n > 0)
    {
      size_t i;
      for (i = 0; i < cr_options->inherit_fd_n; i++)
        {

          const char *entry = cr_options->inherit_fd[i];
          const char *colon = strchr (entry, ':');
          int inh_fd;
          char *endp = NULL;
          if (colon == NULL || colon == entry)
            return crun_make_error (err, 0, "--inherit-fd `%s`: expected FD:KEY", entry);
          inh_fd = (int) strtol (entry, &endp, 10);
          if ((const char *) endp != colon || inh_fd < 0)
            return crun_make_error (err, 0, "--inherit-fd `%s`: bad FD", entry);
          ret = libcriu_wrapper->criu_add_inherit_fd (inh_fd, colon + 1);
          if (UNLIKELY (ret != 0))
            return crun_make_error (err, 0, "criu_add_inherit_fd(%d, %s) failed: %d", inh_fd, colon + 1, ret);
        }
    }

  if (cr_options->external_n > 0)
    {
      size_t i;
      for (i = 0; i < cr_options->external_n; i++)
        {
          ret = libcriu_wrapper->criu_add_external (cr_options->external[i]);
          if (UNLIKELY (ret != 0))
            return crun_make_error (err, 0, "criu_add_external(%s) failed: %d", cr_options->external[i], ret);
        }

      if (libcriu_wrapper->criu_set_orphan_pts_master != NULL)
        libcriu_wrapper->criu_set_orphan_pts_master (true);
    }

  for (size_t i = 0; i < def->mounts_len; i++)
    {
      bool nofollow = false;
      char buf[PATH_MAX];
      const char *dest_in_root;
      const char *source;

      if (! is_bind_mount (def->mounts[i], NULL, &nofollow) || nofollow)
        continue;

      source = def->mounts[i]->source;
      dest_in_root = chroot_realpath (rootfs_path, def->mounts[i]->destination, buf);
      if (UNLIKELY (dest_in_root == NULL))
        {
          if (errno != ENOENT)
            return crun_make_error (err, errno,
                                    "tfork: unable to resolve external bind mount `%s` under rootfs",
                                    def->mounts[i]->destination);
          dest_in_root = def->mounts[i]->destination;
        }
      else
        dest_in_root += strlen (rootfs_path);

      ret = libcriu_wrapper->criu_add_ext_mount (dest_in_root, source);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret,
                                "tfork: criu_add_ext_mount(%s,%s) failed",
                                dest_in_root, source);
      ret = libcriu_wrapper->criu_add_ext_mount (source, source);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret,
                                "tfork: criu_add_ext_mount(%s,%s) failed",
                                source, source);
    }

  if (cr_options->tfork_copy_args_n > 0)
    {
      size_t i;

      if (libcriu_wrapper->criu_add_tfork_copy_args == NULL)
        return crun_make_error (err, 0,
                                "loaded libcriu lacks criu_add_tfork_copy_args; rebuild against criu with the per-copy CLI machinery");
      for (i = 0; i < cr_options->tfork_copy_args_n; i++)
        {

          const char *entry = cr_options->tfork_copy_args[i];
          const char *sep = strstr (entry, "::");
          int copy_idx;
          char *endp = NULL;
          char idx_buf[16];
          size_t idx_len;

          if (sep == NULL || sep == entry)
            return crun_make_error (err, 0,
                                    "--tfork-copy `%s`: expected <I>::<ARGS>", entry);
          idx_len = sep - entry;
          if (idx_len >= sizeof (idx_buf))
            return crun_make_error (err, 0,
                                    "--tfork-copy `%s`: copy index too long", entry);
          memcpy (idx_buf, entry, idx_len);
          idx_buf[idx_len] = '\0';
          copy_idx = (int) strtol (idx_buf, &endp, 10);
          if (endp == idx_buf || *endp != '\0' || copy_idx < 0)
            return crun_make_error (err, 0,
                                    "--tfork-copy `%s`: bad copy index", entry);

          ret = libcriu_wrapper->criu_add_tfork_copy_args (copy_idx, sep + 2);
          if (UNLIKELY (ret != 0))
            return crun_make_error (err, 0,
                                    "criu_add_tfork_copy_args(%d, `%s`) failed: %d",
                                    copy_idx, sep + 2, ret);
        }
    }

  if (cr_options->cgroup_root_n > 0)
    {
      size_t i;

      if (libcriu_wrapper->criu_add_cg_root == NULL)
        return crun_make_error (err, 0,
                                "loaded libcriu lacks criu_add_cg_root");
      for (i = 0; i < cr_options->cgroup_root_n; i++)
        {

          const char *entry = cr_options->cgroup_root[i];
          const char *colon = strchr (entry, ':');
          if (colon == NULL)
            {
              ret = libcriu_wrapper->criu_add_cg_root (NULL, entry);
              if (UNLIKELY (ret != 0))
                return crun_make_error (err, 0,
                                        "criu_add_cg_root(NULL, `%s`) failed: %d",
                                        entry, ret);
            }
          else
            {
              char *ctrl_dup = strndup (entry, colon - entry);
              if (ctrl_dup == NULL)
                return crun_make_error (err, ENOMEM, "strndup cgroup-root ctrl");
              ret = libcriu_wrapper->criu_add_cg_root (ctrl_dup, colon + 1);
              free (ctrl_dup);
              if (UNLIKELY (ret != 0))
                return crun_make_error (err, 0,
                                        "criu_add_cg_root(`%s`) failed: %d",
                                        entry, ret);
            }
        }
    }

  if (libcriu_wrapper->criu_set_empty_ns != NULL)
    libcriu_wrapper->criu_set_empty_ns (0x40000000);

  ret = tfork_alloc_console_ptys (cr_options,
                                  container->context ? container->context->console_socket : NULL,
                                  err);
  if (UNLIKELY (ret < 0))
    return ret;

  tfork_pre_restore_fd = cr_options->tfork_pre_restore_fd;
  tfork_source_detached_fd = cr_options->tfork_source_detached_fd;
  libcriu_wrapper->criu_set_notify_cb (criu_notify);
  ret = libcriu_wrapper->criu_tfork();
  tfork_pre_restore_fd = -1;
  tfork_source_detached_fd = -1;
  if (UNLIKELY (ret != 0))
    {
      show_criu_log (cr_options->work_path, CRIU_TFORK_LOG_FILE);
      show_criu_log (cr_options->image_path, CRIU_TFORK_RESTORE_LOG_FILE);
      show_criu_tfork_restore_copy_logs (cr_options->image_path, cr_options->tfork_copies);
      return crun_make_error (err, 0, "criu_tfork failed: %d", ret);
    }

  if (clone_pid_out != NULL)
    {
      cleanup_free char *pidfile_path = NULL;
      cleanup_free char *pidfile_buf = NULL;
      pid_t clone_pid;
      const char *pidfile_name = "tfork.pid";

      if (cr_options->tfork_copies >= 1)
        pidfile_name = "tfork.pid.copy0";

      ret = append_paths (&pidfile_path, err, cr_options->image_path, pidfile_name, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = read_all_file (pidfile_path, &pidfile_buf, NULL, err);
      if (UNLIKELY (ret < 0))
        return crun_error_wrap (err, "tfork succeeded but cannot read `%s`", pidfile_path);

      clone_pid = (pid_t) strtoll (pidfile_buf, NULL, 10);
      if (UNLIKELY (clone_pid <= 0))
        return crun_make_error (err, 0, "invalid clone PID %d in `%s`", (int) clone_pid, pidfile_path);

      if (cr_options->tfork_copies >= 1)
        {
          char children_path[64];
          cleanup_free char *children_buf = NULL;
          pid_t init_pid;
          char *space;

          snprintf (children_path, sizeof (children_path),
                    "/proc/%d/task/%d/children", clone_pid, clone_pid);
          ret = read_all_file (children_path, &children_buf, NULL, err);
          if (LIKELY (ret >= 0) && children_buf != NULL)
            {
              space = strchr (children_buf, ' ');
              if (space != NULL)
                *space = '\0';
              init_pid = (pid_t) strtoll (children_buf, NULL, 10);
              if (init_pid > 0)
                clone_pid = init_pid;
            }
          else if (ret < 0)
            {

              libcrun_error_release (err);
            }
        }

      *clone_pid_out = clone_pid;
    }

  return 0;
}
#endif
