#ifndef __ASM_GENERIC_CURRENT_H
#define __ASM_GENERIC_CURRENT_H

#include <linux/thread_info.h>

// ARM10C 20140125
// ARM10C 20140308
#define get_current() (current_thread_info()->task)
// ARM10C 20140125
// ARM10C 20140308
// current: current_thread_info()->task
// ARM10C 20140315
// ARM10C 20140913
// ARM10C 20140920
// ARM10C 20141227
// ARM10C 20150117
// get_current(): current_thread_info()->task: &init_task
// current: &init_task
#define current get_current()

#endif /* __ASM_GENERIC_CURRENT_H */
