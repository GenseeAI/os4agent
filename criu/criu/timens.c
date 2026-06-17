#include <time.h>
#include <sched.h>

#include "types.h"
#include "proc_parse.h"
#include "namespaces.h"
#include "timens.h"
#include "cr_options.h"

#include "protobuf.h"
#include "images/timens.pb-c.h"

static int __dump_time_ns(pid_t pid, int ns_id, struct ns_desc *nd)
{
	struct cr_img *img;
	TimensEntry te = TIMENS_ENTRY__INIT;
	Timespec b = TIMESPEC__INIT, m = TIMESPEC__INIT;
	struct timespec ts;
	int ret = -1, rst, nsfd;

	img = open_image(CR_FD_TIMENS, O_DUMP, ns_id);
	if (!img)
		return -1;

	nsfd = open_proc(pid, "ns/%s", nd->str);
	if (nsfd < 0) {
		pr_err("Unable to open ns/%s for pid %d\n", nd->str, pid);
		goto close_img;
	}
	if (switch_ns_by_fd(nsfd, &time_ns_desc, &rst))
		goto close_nsfd;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	te.monotonic = &m;
	te.monotonic->tv_sec = ts.tv_sec;
	te.monotonic->tv_nsec = ts.tv_nsec;
	clock_gettime(CLOCK_BOOTTIME, &ts);
	te.boottime = &b;
	te.boottime->tv_sec = ts.tv_sec;
	te.boottime->tv_nsec = ts.tv_nsec;

	ret = pb_write_one(img, &te, PB_TIMENS);

	restore_ns(rst, &time_ns_desc);
close_nsfd:
	close_safe(&nsfd);
close_img:
	close_image(img);
	return ret < 0 ? -1 : 0;
}

int dump_timens_one_task(pid_t pid, int time_ns_id, int time_for_children_ns_id)
{
	struct ns_id *nsid;
	int ret = 0;

	nsid = lookup_ns_by_id(time_ns_id, &time_ns_desc);
	if (nsid && !nsid->timens.dumped) {
		ret = __dump_time_ns(pid, time_ns_id, &time_ns_desc);
		if (ret < 0)
			return ret;

		nsid->timens.dumped = true;
	}

	if (time_for_children_ns_id == time_ns_id)
		return 0;

	nsid = lookup_ns_by_id(time_for_children_ns_id, &time_for_children_ns_desc);
	if (nsid && !nsid->timens.dumped) {
		ret = __dump_time_ns(pid, time_for_children_ns_id,
							&time_for_children_ns_desc);
		if (ret < 0)
			return ret;
		nsid->timens.dumped = true;
	}

	return ret;
}

int read_time_ns_img(void)
{
	struct ns_id *nsid;
	struct cr_img *img;
	int ret = 0;

	pr_info("Reading time namespaces images\n");
	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &time_ns_desc && nsid->nd != &time_for_children_ns_desc)
			continue;

		if (nsid->timens.te)
			continue;

		pr_info("reading timens-%d.img\n", nsid->id);
		nsid->timens.populated = false;
		img = open_image(CR_FD_TIMENS, O_RSTR, nsid->id);
		if (!img)
			return -1;

		if (empty_image(img)) {
			pr_err("Clocks values have not been dumped\n");
			close_image(img);
			return -1;
		}

		ret = pb_read_one(img, &nsid->timens.te, PB_TIMENS);
		close_image(img);
		if (ret <= 0) {
			pr_err("Can't read time ns image\n");
			return -1;
		}
	}
	return 0;
}

void cleanup_time_ns_img(void)
{
	struct ns_id *nsid;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &time_ns_desc && nsid->nd != &time_for_children_ns_desc)
			continue;

		if (nsid->timens.te) {
			timens_entry__free_unpacked(nsid->timens.te, NULL);
			nsid->timens.te = NULL;
		}
	}
	pr_info("Cleaned up time namespaces data\n");
}

static void normalize_timespec(struct timespec *ts)
{
	while (ts->tv_nsec >= NSEC_PER_SEC) {
		ts->tv_nsec -= NSEC_PER_SEC;
		++ts->tv_sec;
	}
	while (ts->tv_nsec < 0) {
		ts->tv_nsec += NSEC_PER_SEC;
		--ts->tv_sec;
	}
}

static inline struct ns_id *lookup_timens_by_id(unsigned int id)
{
	struct ns_id *nsid;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next)
		if ((nsid->nd == &time_ns_desc || nsid->nd == &time_for_children_ns_desc)
				&& nsid->id == id)
			return nsid;

	return NULL;
}

static int __prepare_timens(int id)
{
	int exit_code = -1;
	int fd = -1;
	struct ns_id *nsid;
	TimensEntry *te;
	struct timespec ts;
	struct timespec prev_moff = {}, prev_boff = {};

	nsid = lookup_timens_by_id(id);
	if (!nsid) {
		pr_err("No time namespace with id %d\n", id);
		return -1;
	}

	if (nsid->timens.populated)
		return 1;

	te = nsid->timens.te;
	if (unshare(CLONE_NEWTIME)) {
		pr_err("Unable to create a new time namespace");
		return -1;
	}

	if (parse_timens_offsets(&prev_boff, &prev_moff))
		return -1;

	fd = open_proc_rw(PROC_SELF, "timens_offsets");
	if (fd < 0)
		return -1;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec = ts.tv_sec - prev_moff.tv_sec;
	ts.tv_nsec = ts.tv_nsec - prev_moff.tv_nsec;

	ts.tv_sec = te->monotonic->tv_sec - ts.tv_sec;
	ts.tv_nsec = te->monotonic->tv_nsec - ts.tv_nsec;
	normalize_timespec(&ts);

	pr_debug("timens: monotonic %" PRId64 " %ld\n", (int64_t)ts.tv_sec, ts.tv_nsec);
	if (dprintf(fd, "%d %" PRId64 " %ld\n", CLOCK_MONOTONIC, (int64_t)ts.tv_sec, ts.tv_nsec) < 0) {
		pr_perror("Unable to set a monotonic clock offset");
		goto close_offset_fd;
	}

	clock_gettime(CLOCK_BOOTTIME, &ts);

	ts.tv_sec = ts.tv_sec - prev_boff.tv_sec;
	ts.tv_nsec = ts.tv_nsec - prev_boff.tv_nsec;

	ts.tv_sec = te->boottime->tv_sec - ts.tv_sec;
	ts.tv_nsec = te->boottime->tv_nsec - ts.tv_nsec;
	normalize_timespec(&ts);

	pr_debug("timens: boottime %" PRId64 " %ld\n", (int64_t)ts.tv_sec, ts.tv_nsec);
	if (dprintf(fd, "%d %" PRId64 " %ld\n", CLOCK_BOOTTIME, (int64_t)ts.tv_sec, ts.tv_nsec) < 0) {
		pr_perror("Unable to set a boottime clock offset");
		goto close_offset_fd;
	}
	exit_code = 0;
	nsid->timens.populated = true;

close_offset_fd:
	close_safe(&fd);
	return exit_code;
}

int prepare_timens_one_task(int time_ns_id, int time_for_children_ns_id)
{
	int ret, fd = -1, exit_code = -1;

	if (opts.unprivileged)
		return 0;

	pr_info("timens: time_ns for %d, and time_for_children_ns for %d\n",
		time_ns_id, time_for_children_ns_id);
	ret = __prepare_timens(time_ns_id);
	if (ret < 0)
		return -1;

	if (ret == 0) {
		fd = open_proc(PROC_SELF, "ns/time_for_children");
		if (fd < 0) {
			pr_perror("Unable to open ns/time_for_children");
			return -1;
		}
		if (switch_ns_by_fd(fd, &time_ns_desc, NULL)) {
			goto close_time_for_children_fd;
		}
	}

	if (time_ns_id != time_for_children_ns_id) {
		ret = __prepare_timens(time_for_children_ns_id);
		if (ret < 0)
			goto close_time_for_children_fd;
	}
	exit_code = 0;

close_time_for_children_fd:
	close_safe(&fd);
	return exit_code;
}
struct ns_desc time_ns_desc = NS_DESC_ENTRY(CLONE_NEWTIME, "time");
struct ns_desc time_for_children_ns_desc = NS_DESC_ENTRY(CLONE_NEWTIME, "time_for_children");
