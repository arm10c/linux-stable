#ifndef __ASM_GENERIC_CURRENT_H
#define __ASM_GENERIC_CURRENT_H

#include <linux/thread_info.h>

// ARM10C 20140125
// ARM10C 20140308
// ARM10C 20170823
#define get_current() (current_thread_info()->task)
// ARM10C 20140125
// ARM10C 20140308
// current: current_thread_info()->task
// ARM10C 20140315
// ARM10C 20140913
// ARM10C 20140920
// ARM10C 20141227
// ARM10C 20150117
// ARM10C 20150606
// ARM10C 20151121
// ARM10C 20160402
// ARM10C 20160521
// ARM10C 20160604
// ARM10C 20160827
// ARM10C 20160910
// ARM10C 20161008
// ARM10C 20161029
// ARM10C 20161105
// ARM10C 20161203
// ARM10C 20161217
// ARM10C 20170701
// ARM10C 20170715
// get_current(): current_thread_info()->task: &init_task
// current: &init_task
// ARM10C 20170823
// ARM10C 20170830
// ARM10C 20170906
// get_current(): current_thread_info()->task: kmem_cache#15-oX (struct task_struct) (pid: 1)
// current: kmem_cache#15-oX (struct task_struct) (pid: 1)
#define current get_current()

#endif /* __ASM_GENERIC_CURRENT_H */
