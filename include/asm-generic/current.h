#ifndef __ASM_GENERIC_CURRENT_H
#define __ASM_GENERIC_CURRENT_H

#include <linux/thread_info.h>

// ARM10C 20140125
#define get_current() (current_thread_info()->task)
// ARM10C 20140125
#define current get_current()

#endif /* __ASM_GENERIC_CURRENT_H */
