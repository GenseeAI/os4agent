#ifndef __CR_CAPBYPASS_H__
#define __CR_CAPBYPASS_H__

#include <sys/types.h>
#include <stdbool.h>

extern int  capbypass_open(void);
extern void capbypass_close(void);
extern int  capbypass_grant(pid_t host_pid);
extern int  capbypass_grant_self(void);
extern int  capbypass_revoke(pid_t host_pid);
extern bool capbypass_available(void);

#endif
