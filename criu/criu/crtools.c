#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sched.h>
#include <signal.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <dlfcn.h>

#include <sys/utsname.h>

#include "int.h"
#include "page.h"
#include "common/compiler.h"

#include "crtools.h"
#include "cr-tfork.h"
#include "servicefd.h"
#include "cr_options.h"
#include "external.h"
#include "files.h"
#include "sk-inet.h"
#include "net.h"
#include "page-xfer.h"
#include "tty.h"
#include "file-lock.h"
#include "cr-service.h"
#include "plugin.h"
#include "criu-log.h"
#include "util.h"
#include "protobuf-desc.h"
#include "namespaces.h"
#include "cgroup.h"
#include "cpu.h"
#include "fault-injection.h"
#include "proc_parse.h"
#include "kerndat.h"
#include "setproctitle.h"
#include "sysctl.h"

static void ncopy_init_sigterm_fwd(int sig)
{
	(void)sig;
	(void)kill(-1, SIGTERM);
}

void flush_early_log_to_stderr(void) __attribute__((destructor));

void flush_early_log_to_stderr(void)
{
	flush_early_log_buffer(STDERR_FILENO);
}

static int image_dir_mode(void)
{
	switch (opts.mode) {
	case CR_DUMP:
		/* fallthrough */
	case CR_CPUINFO_DUMP:
		/* fallthrough */
	case CR_PRE_DUMP:
		return O_DUMP;
	case CR_RESTORE:
		return O_RSTR;
	default:
		return -1;
	}

	/* never reached */
	BUG();
	return -1;
}

struct {
	char *cmd;
	int mode;
} commands[] = {
	{ "dump", CR_DUMP },
	{ "pre-dump", CR_PRE_DUMP },
	{ "restore", CR_RESTORE },
	{ "lazy-pages", CR_LAZY_PAGES },
	{ "check", CR_CHECK },
	{ "page-server", CR_PAGE_SERVER },
	{ "service", CR_SERVICE },
	{ "swrk", CR_SWRK },
	{ "dedup", CR_DEDUP },
	{ "exec", CR_EXEC_DEPRECATED },
	{ "show", CR_SHOW_DEPRECATED },
	{ "tfork", CR_TFORK },
};

static int parse_criu_mode(int argc, char **argv, int *optind)
{
	char *cmd = argv[*optind];
	bool has_sub_command = (argc - *optind) > 1;
	char *subcommand = has_sub_command ? argv[*optind + 1] : NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(cmd, commands[i].cmd))
			continue;
		opts.mode = commands[i].mode;
		return 0;
	}

	if (!strcmp(cmd, "cpuinfo")) {
		if (subcommand == NULL) {
			pr_err("cpuinfo requires an action: dump or check\n");
			return -1;
		}
		if (!strcmp(subcommand, "dump"))
			opts.mode = CR_CPUINFO_DUMP;
		else if (!strcmp(subcommand, "check"))
			opts.mode = CR_CPUINFO_CHECK;
		else {
			pr_err("unknown cpuinfo sub-command: %s\n", subcommand);
			return -1;
		}
		(*optind)++;
		return 0;
	}
	pr_err("unknown command: %s\n", argv[*optind]);
	return -1;
}

int main(int argc, char *argv[], char *envp[])
{
	int ret = -1;
	bool usage_error = true;
	bool has_exec_cmd = false;
	bool has_sub_command;
	int state = PARSING_GLOBAL_CONF;
	char *cmd;

	BUILD_BUG_ON(CTL_32 != SYSCTL_TYPE__CTL_32);
	BUILD_BUG_ON(__CTL_STR != SYSCTL_TYPE__CTL_STR);
	/* We use it for fd overlap handling in clone_service_fd() */
	BUG_ON(get_service_fd(SERVICE_FD_MIN + 1) < get_service_fd(SERVICE_FD_MAX - 1));

	if (fault_injection_init()) {
		pr_err("Failed to initialize fault injection when initializing crtools.\n");
		return 1;
	}

	cr_pb_init();
	__setproctitle_init(argc, argv, envp);

	if (argc < 2)
		goto usage;

	init_opts();

	ret = parse_options(argc, argv, &usage_error, &has_exec_cmd, state);

	if (ret == 1)
		return 1;
	if (ret == 2)
		goto usage;
	if (optind >= argc) {
		pr_err("command is required\n");
		goto usage;
	}

	log_set_loglevel(opts.log_level);

	/*
	 * There kernel might send us lethal signals in the following cases:
	 * 1) Writing a pipe which reader has disappeared.
	 * 2) Writing to a socket of type SOCK_STREAM which is no longer connected.
	 * We deal with write()/Send() failures on our own, and prefer not to get killed.
	 * So we ignore SIGPIPEs.
	 *
	 * Pipes are used in various places:
	 * 1) Receiving application page data
	 * 2) Transmitting data to the image streamer
	 * 3) Emitting logs (potentially to a pipe).
	 * Sockets are mainly used in transmitting memory data.
	 */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		pr_perror("Failed to set a SIGPIPE signal ignore.");
		return 1;
	}

	cmd = argv[optind];
	ret = parse_criu_mode(argc, argv, &optind);
	if (ret)
		goto usage;

	/*
	 * util_init initializes criu_run_id and compel_run_id so that sockets
	 * are generated with an unique name identifying the specific process
	 * even in cases where multiple processes with the same pid in
	 * different pid namespaces are sharing the same network namespace.
	 */
	util_init();
	if (opts.mode == CR_SWRK) {
		if (argc != optind + 2) {
			fprintf(stderr, "Usage: criu swrk <fd>\n");
			return 1;
		}
		/*
		 * This is to start criu service worker from libcriu calls.
		 * The usage is "criu swrk <fd>" and is not for CLI/scripts.
		 * The arguments semantics can change at any time with the
		 * corresponding lib call change.
		 */
		opts.swrk_restore = true;
		return cr_service_work(atoi(argv[optind + 1]));
	}

	if (check_caps())
		return 1;

	if (opts.imgs_dir == NULL)
		SET_CHAR_OPTS(imgs_dir, ".");

	if (opts.work_dir == NULL)
		SET_CHAR_OPTS(work_dir, opts.imgs_dir);

	has_sub_command = (argc - optind) > 1;

	if (has_exec_cmd) {
		if (!has_sub_command) {
			pr_err("--exec-cmd requires a command\n");
			goto usage;
		}

		if (opts.mode != CR_RESTORE) {
			pr_err("--exec-cmd is available for the restore command only\n");
			goto usage;
		}

		if (opts.restore_detach) {
			pr_err("--restore-detached and --exec-cmd cannot be used together\n");
			goto usage;
		}

		opts.exec_cmd = xmalloc((argc - optind) * sizeof(char *));
		if (!opts.exec_cmd)
			return 1;
		memcpy(opts.exec_cmd, &argv[optind + 1], (argc - optind - 1) * sizeof(char *));
		opts.exec_cmd[argc - optind - 1] = NULL;
	} else if (has_sub_command) {
		pr_err("excessive parameter%s for command %s\n", (argc - optind) > 2 ? "s" : "", cmd);
		goto usage;
	}

	if (opts.stream && image_dir_mode() == -1) {
		pr_err("--stream cannot be used with the %s command\n", cmd);
		goto usage;
	}

	/* We must not open imgs dir, if service is called */
	if (opts.mode != CR_SERVICE) {
		ret = open_image_dir(opts.imgs_dir, image_dir_mode());
		if (ret < 0) {
			pr_err("Couldn't open image dir %s\n", opts.imgs_dir);
			return 1;
		}
	}

	/*
	 * When a process group becomes an orphan,
	 * its processes are sent a SIGHUP signal
	 */
	if (opts.mode == CR_RESTORE && opts.restore_detach && opts.final_state == TASK_STOPPED && opts.shell_job)
		pr_warn("Stopped and detached shell job will get SIGHUP from OS.\n");

	if (chdir(opts.work_dir)) {
		pr_perror("Can't change directory to %s", opts.work_dir);
		return 1;
	}

	if (log_init(opts.output))
		return 1;

	if (kerndat_init()) {
		pr_err("Could not initialize kernel features detection.\n");
		return 1;
	}

	if (check_options())
		return 1;

	if (fault_injected(FI_CANNOT_MAP_VDSO))
		kdat.can_map_vdso = 0;

	if (!list_empty(&opts.inherit_fds)) {
		if (opts.mode != CR_RESTORE && opts.mode != CR_TFORK) {
			pr_err("--inherit-fd is restore-only option\n");
			return 1;
		}
		/* now that log file is set up, print inherit fd list */
		inherit_fd_log();
	}

	if (opts.img_parent)
		pr_info("Will do snapshot from %s\n", opts.img_parent);

	switch (opts.mode) {
	case CR_DUMP:
		if (!opts.tree_id)
			goto opt_pid_missing;

		return cr_dump_tasks(opts.tree_id);
	case CR_PRE_DUMP:
		if (!opts.tree_id)
			goto opt_pid_missing;

		if (opts.lazy_pages) {
			pr_err("Cannot pre-dump with --lazy-pages\n");
			return 1;
		}

		return cr_pre_dump_tasks(opts.tree_id) != 0;
	case CR_RESTORE:
		if (opts.tree_id)
			pr_warn("Using -t with criu restore is obsoleted\n");

		if (opts.tfork.active && opts.tfork.copies >= 1) {
			int n = opts.tfork.copies, i;
			pid_t *children;
			int (*ready_pipes)[2];
			int failed = 0;
			const char *base_log = opts.output;

			/*
			 * The n-copy helper must not create/occupy PID 1 in a new
			 * PID namespace. CRIU restores the real root task as PID 1
			 * from the image; if the helper has already consumed it,
			 * restore fails with EEXIST ("Can't fork for 1").
			 */
			const int ns_flags = CLONE_NEWNS;

			if (!opts.tfork.active) {
				pr_err("--tfork-copies requires --tfork-restore "
				       "(use 'criu tfork --tfork-copies=N', not "
				       "'criu restore --tfork-copies=N')\n");
				return 1;
			}

			if (!opts.restore_detach) {
				pr_err("--tfork-copies requires --restore-detached\n");
				return 1;
			}

			if (opts.tfork.snap_roots_n != 0 &&
			    opts.tfork.snap_roots_n != n) {
				pr_err("--tfork-snap-roots lists %d paths but --tfork-copies=%d\n",
				       opts.tfork.snap_roots_n, n);
				return 1;
			}

			if (init_service_fd())
				return 1;
			if (tfork_read_cropt()) {
				pr_err("tfork-ncopy: pre-clone tfork_read_cropt failed\n");
				return 1;
			}

			children = xmalloc(n * sizeof(*children));
			ready_pipes = xmalloc(n * sizeof(*ready_pipes));
			if (!children || !ready_pipes)
				return 1;

			pr_info("tfork-ncopy: spawning %d copies\n", n);

			for (i = 0; i < n; i++) {
				pid_t pid;

				if (pipe(ready_pipes[i]) < 0) {
					pr_perror("tfork-ncopy: pipe copy %d", i);
					children[i] = -1;
					failed++;
					continue;
				}

				pid = syscall(SYS_clone, ns_flags | SIGCHLD,
					      NULL, NULL, NULL, 0);
				if (pid < 0) {
					pr_perror("tfork-ncopy: clone copy %d", i);
					close(ready_pipes[i][0]);
					close(ready_pipes[i][1]);
					children[i] = -1;
					failed++;
					continue;
				}
				if (pid == 0) {
					char log_name[PATH_MAX];
					int ret_inner;
					int high;
					struct sigaction sa;
					int last_status = 0;
					bool any_failed = false;

					close(ready_pipes[i][0]);
					opts.tfork.copy_idx = i;

					high = fcntl(ready_pipes[i][1], F_DUPFD,
						     opts.tfork.pidfd_base +
						     4 * opts.tfork.pidfd_map_nr + 16);
					if (high >= 0) {
						close(ready_pipes[i][1]);
						ready_pipes[i][1] = high;
					} else {
						pr_pwarn("tfork-ncopy: copy %d: F_DUPFD ready_pipe", i);
					}
					opts.tfork.ncopy_ready_fd = ready_pipes[i][1];

					if (opts.tfork.snap_root_fd >= 0)
						close(opts.tfork.snap_root_fd);
					opts.tfork.snap_root_fd = -1;

					opts.pidfile = NULL;

					if (base_log && strcmp(base_log, "-") != 0) {
						int devnull;

						snprintf(log_name, sizeof(log_name),
							 "%s.copy%d", base_log, i);
						log_fini();
						if (log_init(log_name) < 0)
							exit(1);

						devnull = open("/dev/null", O_RDWR);
						if (devnull >= 0) {
							dup2(devnull, 0);
							dup2(devnull, 1);
							dup2(devnull, 2);
							if (devnull > 2)
								close(devnull);
						}
					}

					if (opts.tfork.snap_roots_n > 0)
						opts.root = opts.tfork.snap_roots[i];

					opts.keep_pid_hierarchy = 0;

					if (tfork_load_ncopy_fabric(i)) {
						pr_err("tfork-ncopy: copy %d fabric load failed\n",
						       i);
						close(ready_pipes[i][1]);
						exit(1);
					}

					if (tfork_apply_per_copy_args(i)) {
						pr_err("tfork-per-copy: copy %d args apply failed\n",
						       i);
						close(ready_pipes[i][1]);
						exit(1);
					}

					pr_info("tfork-ncopy: copy %d (host pid %d, ns-init) starting\n",
						i, getpid());

					if (mount(NULL, "/", NULL,
						  MS_SLAVE, NULL) < 0)
						pr_pwarn("tfork-ncopy: copy %d: "
							 "mount(/, MS_SLAVE)", i);
					if (mount("none", "/proc", NULL,
						  MS_PRIVATE, NULL) < 0)
						pr_pwarn("tfork-ncopy: copy %d: "
							 "mount(/proc, MS_PRIVATE)", i);
					(void)umount2("/proc", MNT_DETACH);
					if (mount("proc", "/proc", "proc",
						  MS_NOSUID | MS_NODEV | MS_NOEXEC,
						  NULL) < 0) {
						pr_perror("tfork-ncopy: copy %d: "
							  "mount /proc fresh", i);
						exit(1);
					}

					ret_inner = cr_restore_tasks();
					if (ret_inner != 0) {
						pr_err("tfork-ncopy: copy %d cr_restore_tasks failed\n", i);

						close(ready_pipes[i][1]);
						exit(1);
					}

					tfork_close_high_fds();

					pr_info("tfork-ncopy: copy %d ready, signaling and parking as ns-init\n", i);
					if (write(ready_pipes[i][1], "ok", 2) != 2) {
						pr_perror("tfork-ncopy: copy %d ready write", i);
					}
					close(ready_pipes[i][1]);

					memset(&sa, 0, sizeof(sa));
					sa.sa_handler = ncopy_init_sigterm_fwd;
					sigemptyset(&sa.sa_mask);
					sigaction(SIGTERM, &sa, NULL);
					sigaction(SIGINT, &sa, NULL);

					while (1) {
						int status;
						pid_t r = wait(&status);

						if (r > 0) {
							last_status = status;
							if (!WIFEXITED(status) ||
							    WEXITSTATUS(status) != 0)
								any_failed = true;
							continue;
						}
						if (errno == EINTR)
							continue;
						if (errno == ECHILD)
							break;
						pr_perror("tfork-ncopy: copy %d wait", i);
						exit(1);
					}
					if (any_failed) {
						if (WIFEXITED(last_status))
							exit(WEXITSTATUS(last_status));
						exit(128 + (WIFSIGNALED(last_status) ?
							    WTERMSIG(last_status) : 0));
					}
					exit(0);
				}
				close(ready_pipes[i][1]);
				children[i] = pid;
				pr_info("tfork-ncopy: copy %d → host pid %d\n", i, pid);
			}

			for (i = 0; i < n; i++) {
				char buf[4] = {0};
				int r;

				if (children[i] < 0)
					continue;

				r = read(ready_pipes[i][0], buf, 2);
				close(ready_pipes[i][0]);
				if (r != 2 || memcmp(buf, "ok", 2) != 0) {
					pr_err("tfork-ncopy: copy %d (pid %d) failed to signal ready (r=%d)\n",
					       i, children[i], r);
					failed++;
				} else {
					pr_info("tfork-ncopy: copy %d (pid %d) ready\n",
						i, children[i]);
					if (opts.pidfile) {
						char path[PATH_MAX];
						FILE *pf;

						snprintf(path, sizeof(path),
							 "%s.copy%d",
							 opts.pidfile, i);
						pf = fopen(path, "w");
						if (pf) {
							fprintf(pf, "%d\n",
								children[i]);
							fclose(pf);
						} else {
							pr_pwarn("tfork-ncopy: copy %d: open %s",
								 i, path);
						}
					}
				}
			}

			xfree(ready_pipes);
			xfree(children);
			pr_info("tfork-ncopy: %d/%d copies up, %d failed\n",
				n - failed, n, failed);
			return failed != 0;
		}

		ret = cr_restore_tasks();
		if (ret == 0 && opts.exec_cmd) {
			close_pid_proc();
			execvp(opts.exec_cmd[0], opts.exec_cmd);
			pr_perror("Failed to exec command %s", opts.exec_cmd[0]);
			ret = 1;
		}

		return ret != 0;

	case CR_LAZY_PAGES:
		return cr_lazy_pages(opts.daemon_mode) != 0;

	case CR_CHECK:
		return cr_check() != 0;

	case CR_PAGE_SERVER:
		return cr_page_server(opts.daemon_mode, false, -1) != 0;

	case CR_SERVICE:
		return cr_service(opts.daemon_mode);

	case CR_DEDUP:
		return cr_dedup() != 0;

	case CR_CPUINFO_DUMP:
		return cpuinfo_dump();

	case CR_CPUINFO_CHECK:
		return cpuinfo_check();

	case CR_TFORK:
		if (!opts.tree_id)
			goto opt_pid_missing;

		return cr_tfork_tasks(opts.tree_id);

	case CR_EXEC_DEPRECATED:
		pr_err("The \"exec\" action is deprecated by the Compel library.\n");
		return -1;

	case CR_SHOW_DEPRECATED:
		pr_err("The \"show\" action is deprecated by the CRIT utility.\n");
		pr_err("To view an image use the \"crit decode -i $name --pretty\" command.\n");
		return -1;

	case CR_UNSET:
	default:
		pr_err("unknown command: %s\n", cmd);
	}
usage:
	pr_msg("\n"
	       "Usage:\n"
	       "  criu dump|pre-dump -t PID [<options>]\n"
	       "  criu restore [<options>]\n"
	       "  criu tfork -t PID [<options>]\n"
	       "  criu check [--feature FEAT]\n"
	       "  criu page-server\n"
	       "  criu service [<options>]\n"
	       "  criu dedup\n"
	       "  criu lazy-pages -D DIR [<options>]\n"
	       "\n"
	       "Commands:\n"
	       "  dump           checkpoint a process/tree identified by pid\n"
	       "  pre-dump       pre-dump task(s) minimizing their frozen time\n"
	       "  restore        restore a process/tree\n"
	       "  tfork          fork a process/tree into a new container (CoW)\n"
	       "  check          checks whether the kernel support is up-to-date\n"
	       "  page-server    launch page server\n"
	       "  service        launch service\n"
	       "  dedup          remove duplicates in memory dump\n"
	       "  cpuinfo dump   writes cpu information into image file\n"
	       "  cpuinfo check  validates cpu information read from image file\n");

	if (usage_error) {
		pr_msg("\nTry -h|--help for more info\n");
		return 1;
	}

	pr_msg("\n"

	       "Most of the true / false long options (the ones without arguments) can be\n"
	       "prefixed with --no- to negate the option (example: --display-stats and\n"
	       "--no-display-stats).\n"
	       "\n"
	       "Dump/Restore options:\n"
	       "\n"
	       "* Generic:\n"
	       "  -t|--tree PID         checkpoint a process tree identified by PID\n"
	       "  -d|--restore-detached detach after restore\n"
	       "  -S|--restore-sibling  restore root task as sibling\n"
	       "  -s|--leave-stopped    leave tasks in stopped state after checkpoint\n"
	       "  -R|--leave-running    leave tasks in running state after checkpoint\n"
	       "  -D|--images-dir DIR   directory for image files\n"
	       "     --pidfile FILE     write root task, service or page-server pid to FILE\n"
	       "  -W|--work-dir DIR     directory to cd and write logs/pidfiles/stats to\n"
	       "                        (if not specified, value of --images-dir is used)\n"
	       "     --cpu-cap [CAP]    CPU capabilities to write/check. CAP is comma-separated\n"
	       "                        list of: cpu, fpu, all, ins, none. To disable\n"
	       "                        a capability, use ^CAP. Empty argument implies all\n"
	       "     --exec-cmd         execute the command specified after '--' on successful\n"
	       "                        restore making it the parent of the restored process\n"
	       "  --freeze-cgroup       use cgroup freezer to collect processes\n"
	       "  --weak-sysctls        skip restoring sysctls that are not available\n"
	       "  --lazy-pages          restore pages on demand\n"
	       "                        this requires running a second instance of criu\n"
	       "                        in lazy-pages mode: 'criu lazy-pages -D DIR'\n"
	       "                        --lazy-pages and lazy-pages mode require userfaultfd\n"
	       "  --stream              dump/restore images using criu-image-streamer\n"
	       "  --mntns-compat-mode   Use mount engine in compatibility mode. By default criu\n"
	       "                        tries to use mount-v2 mode with more reliable algorithm\n"
	       "                        based on MOVE_MOUNT_SET_GROUP kernel feature\n"
	       "  --network-lock METHOD network locking/unlocking method; argument\n"
	       "                        can be 'nftables' or 'iptables' (default).\n"
	       "  --unprivileged        accept limitations when running as non-root\n"
	       "  --allow-uprobes       allow dump/restore with uprobes vma\n"
	       "\n"
	       "* External resources support:\n"
	       "  --external RES        dump objects from this list as external resources:\n"
	       "                        Formats of RES on dump:\n"
	       "                            tty[rdev:dev]\n"
	       "                            file[mnt_id:inode]\n"
	       "                            dev[major/minor]:NAME\n"
	       "                            unix[ino]\n"
	       "                            mnt[MOUNTPOINT]:COOKIE\n"
	       "                            mnt[]{:AUTO_OPTIONS}\n"
	       "                        Formats of RES on restore:\n"
	       "                            dev[NAME]:DEVPATH\n"
	       "                            veth[IFNAME]:OUTNAME{@BRIDGE}\n"
	       "                            macvlan[IFNAME]:OUTNAME\n"
	       "                            mnt[COOKIE]:ROOT\n"
	       "                            netdev[IFNAME]:ORIGNAME\n"
	       "\n"
	       "* Special resources support:\n"
	       "     --" SK_EST_PARAM "  checkpoint/restore established TCP connections\n"
	       "     --" SK_INFLIGHT_PARAM "   skip (ignore) in-flight TCP connections\n"
	       "     --" UNIX_SK_INFLIGHT_PARAM "  drop pending bytes in icon-socket wqlen\n"
	       "                          (sk-unix.c:506); auto-on for tfork.\n"
	       "     --" SK_CLOSE_PARAM "        don't dump the state of, or block, established tcp\n"
	       "                        connections, and restore them in closed state.\n"
	       "  -r|--root PATH        change the root filesystem (when run in mount namespace)\n"
	       "  --evasive-devices     use any path to a device file if the original one\n"
	       "                        is inaccessible\n"
	       "  --link-remap          allow one to link unlinked files back when possible\n"
	       "  --ghost-limit size    limit max size of deleted file contents inside image\n"
	       "  --ghost-fiemap        enable dumping of deleted files using fiemap\n"
	       "  --action-script FILE  add an external action script\n"
	       "  -j|--" OPT_SHELL_JOB "        allow one to dump and restore shell jobs\n"
	       "  -l|--" OPT_FILE_LOCKS "       handle file locks, for safety, only used for container\n"
	       "  -L|--libdir           path to a plugin directory (by default " CR_PLUGIN_DEFAULT ")\n"
	       "  --timeout NUM         a timeout (in seconds) on collecting tasks during dump\n"
	       "                        (default 10 seconds)\n"
	       "  --force-irmap         force resolving names for inotify/fsnotify watches\n"
	       "  --irmap-scan-path FILE\n"
	       "                        add a path the irmap hints to scan\n"
	       "  --manage-cgroups [m]  dump/restore process' cgroups; argument can be one of\n"
	       "                        'none', 'props', 'soft' (default), 'full', 'strict'\n"
	       "                        or 'ignore'\n"
	       "  --cgroup-root [controller:]/newroot\n"
	       "                        on dump: change the root for the controller that will\n"
	       "                        be dumped. By default, only the paths with tasks in\n"
	       "                        them and below will be dumped.\n"
	       "                        on restore: change the root cgroup the controller will\n"
	       "                        be installed into. No controller means that root is the\n"
	       "                        default for all controllers not specified\n"
	       "  --cgroup-props STRING\n"
	       "                        define cgroup controllers and properties\n"
	       "                        to be checkpointed, which are described\n"
	       "                        via STRING using simplified YAML format\n"
	       "  --cgroup-props-file FILE\n"
	       "                        same as --cgroup-props, but taking description\n"
	       "                        from the path specified\n"
	       "  --cgroup-dump-controller NAME\n"
	       "                        define cgroup controller to be dumped\n"
	       "                        and skip anything else present in system\n"
	       "  --cgroup-yard PATH\n"
	       "                        instead of trying to mount cgroups in CRIU, provide\n"
	       "                        a path to a directory with already created cgroup yard.\n"
	       "                        Useful if you don't want to grant CAP_SYS_ADMIN to CRIU\n"
	       "  --lsm-profile TYPE:NAME\n"
	       "                        Specify an LSM profile to be used during restore.\n"
	       "                        The type can be either 'apparmor' or 'selinux'.\n"
	       "  --lsm-mount-context CTX\n"
	       "                        Specify a mount context to be used during restore.\n"
	       "                        Only mounts with an existing context will have their\n"
	       "                        mount context replaced with CTX.\n"
	       "  --skip-mnt PATH       ignore this mountpoint when dumping the mount namespace\n"
	       "  --enable-fs FSNAMES   a comma separated list of filesystem names or \"all\"\n"
	       "                        force criu to (try to) dump/restore these filesystem's\n"
	       "                        mountpoints even if fs is not supported\n"
	       "  --inherit-fd fd[NUM]:RES\n"
	       "                        Inherit file descriptors, treating fd NUM as being\n"
	       "                        already opened via an existing RES, which can be:\n"
	       "                            tty[rdev:dev]\n"
	       "                            pipe:[inode]\n"
	       "                            socket:[inode]\n"
	       "                            file[mnt_id:inode]\n"
	       "                            /memfd:name\n"
	       "                            path/to/file\n"
	       "  --empty-ns net        Create a namespace, but don't restore its properties\n"
	       "                        (assuming it will be restored by action scripts)\n"
	       "  -J|--join-ns NS:{PID|NS_FILE}[,OPTIONS]\n"
	       "			Join existing namespace and restore process in it.\n"
	       "			Namespace can be specified as either pid or file path.\n"
	       "			OPTIONS can be used to specify parameters for userns:\n"
	       "			    user:PID,UID,GID\n"
	       "  --file-validation METHOD\n"
	       "			pass the validation method to be used; argument\n"
	       "			can be 'filesize' or 'buildid' (default).\n"
	       "  --skip-file-rwx-check\n"
	       "			Skip checking file permissions\n"
	       "			(r/w/x for u/g/o) on restore.\n"
	       "\n"
	       "Check options:\n"
	       "  Without options, \"criu check\" checks availability of absolutely required\n"
	       "  kernel features, critical for performing dump and restore.\n"
	       "  --extra               add check for extra kernel features\n"
	       "  --experimental        add check for experimental kernel features\n"
	       "  --all                 same as --extra --experimental\n"
	       "  --feature FEAT        only check a particular feature, one of:");
	pr_check_features("                            ", ", ", 80);
	pr_msg("\n"
	       "* Logging:\n"
	       "  -o|--log-file FILE    log file name\n"
	       "     --log-pid          enable per-process logging to separate FILE.pid files\n"
	       "  -v[v...]|--verbosity  increase verbosity (can use multiple v)\n"
	       "  -vNUM|--verbosity=NUM set verbosity to NUM (higher level means more output):\n"
	       "                          -v1 - only errors and messages\n"
	       "                          -v2 - also warnings (default level)\n"
	       "                          -v3 - also information messages and timestamps\n"
	       "                          -v4 - lots of debug\n"
	       "  --display-stats       print out dump/restore stats\n"
	       "\n"
	       "* Memory dumping options:\n"
	       "  --track-mem           turn on memory changes tracker in kernel\n"
	       "  --prev-images-dir DIR path to images from previous dump (relative to -D)\n"
	       "  --page-server         send pages to page server (see options below as well)\n"
	       "  --auto-dedup          when used on dump it will deduplicate \"old\" data in\n"
	       "                        pages images of previous dump\n"
	       "                        when used on restore, as soon as page is restored, it\n"
	       "                        will be punched from the image\n"
	       "  --pre-dump-mode       splice - parasite based pre-dumping (default)\n"
	       "                        read   - process_vm_readv syscall based pre-dumping\n"
	       "\n"
	       "Page/Service server options:\n"
	       "  --address ADDR        address of server or service\n"
	       "  --port PORT           port of page server\n"
	       "  --ps-socket FD        use specified FD as page server socket\n"
	       "  -d|--daemon           run in the background after creating socket\n"
	       "  --status-fd FD        write \\0 to the FD and close it once process is ready\n"
	       "                        to handle requests\n"
#ifdef CONFIG_GNUTLS
	       "  --tls-cacert FILE     trust certificates signed only by this CA\n"
	       "  --tls-cacrl FILE      path to CA certificate revocation list file\n"
	       "  --tls-cert FILE       path to TLS certificate file\n"
	       "  --tls-key FILE        path to TLS private key file\n"
	       "  --tls                 use TLS to secure remote connection\n"
	       "  --tls-no-cn-verify    do not verify common name in server certificate\n"
#endif
	       "\n"
	       "Configuration file options:\n"
	       "  --config FILEPATH     pass a specific configuration file\n"
	       "  --no-default-config   forbid usage of default configuration files\n"
	       "\n"
	       "Other options:\n"
	       "  -h|--help             show this text\n"
	       "  -V|--version          show version\n");

	return 0;

opt_pid_missing:
	pr_err("pid not specified\n");
	return 1;
}
