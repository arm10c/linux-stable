#ifndef __ASM_ARM_SWITCH_TO_H
#define __ASM_ARM_SWITCH_TO_H

#include <linux/thread_info.h>

/*
 * For v7 SMP cores running a preemptible kernel we may be pre-empted
 * during a TLB maintenance operation, so execute an inner-shareable dsb
 * to ensure that the maintenance completes in case we migrate to another
 * CPU.
 */
#if defined(CONFIG_PREEMPT) && defined(CONFIG_SMP) && defined(CONFIG_CPU_V7)
#define finish_arch_switch(prev)	dsb(ish)
#endif

/*
 * switch_to(prev, next) should switch from task `prev' to `next'
 * `prev' will never be the same as `next'.  schedule() itself
 * contains the memory barrier to tell GCC not to cache `current'.
 */
extern struct task_struct *__switch_to(struct task_struct *, struct thread_info *, struct thread_info *);

// ARM10C 20170819
// prev: &init_task, next: kmem_cache#15-oX (struct task_struct) (pid: 1), prev: &init_task
//
// #define switch_to(&init_task, kmem_cache#15-oX (struct task_struct) (pid: 1), &init_task):
// do {
//         &init_task = __switch_to(&init_task, task_thread_info(&init_task), task_thread_info(nextkmem_cache#15-oX (struct task_struct) (pid: 1)));
// } while (0)
#define switch_to(prev,next,last)					\
do {									\
	last = __switch_to(prev,task_thread_info(prev), task_thread_info(next));	\
} while (0)

#endif /* __ASM_ARM_SWITCH_TO_H */
