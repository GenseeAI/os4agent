#ifndef __CR_PKEY_STATE_H__
#define __CR_PKEY_STATE_H__

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

extern int  pkey_state_init(void);
extern void pkey_state_close(void);
extern bool pkey_state_available(void);

extern int  pkey_state_get(pid_t host_pid, uint32_t *allocation_map,
			   int32_t *execute_only_pkey);
extern int  pkey_state_set(pid_t host_pid, uint32_t allocation_map,
			   int32_t execute_only_pkey);

#endif
