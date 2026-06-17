#ifndef __CR_TFORK_H__
#define __CR_TFORK_H__

#include <sys/types.h>

extern int cr_tfork_tasks(pid_t pid);
extern int tfork_read_cropt(void);
extern int tfork_load_ncopy_fabric(int copy_idx);
extern void tfork_close_high_fds(void);
extern int tfork_apply_per_copy_args(int copy_idx);
extern int run_dumpd_loop(int control_sock, int inflight_fd, int img_dir_fd);

#endif
