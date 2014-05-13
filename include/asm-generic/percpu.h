#ifndef _ASM_GENERIC_PERCPU_H_
#define _ASM_GENERIC_PERCPU_H_

#include <linux/compiler.h>
#include <linux/threads.h>
#include <linux/percpu-defs.h>

#ifdef CONFIG_SMP

/*
 * per_cpu_offset() is the offset that has to be added to a
 * percpu variable to get to the instance for a certain processor.
 *
 * Most arches use the __per_cpu_offset array for those offsets but
 * some arches have their own ways of determining the offset (x86_64, s390).
 */
#ifndef __per_cpu_offset
extern unsigned long __per_cpu_offset[NR_CPUS];

// ARM10C 20130928
// ARM10C 20140308
// ARM10C 20140412
// per_cpu_offset(0): (__per_cpu_offset[0])
#define per_cpu_offset(x) (__per_cpu_offset[x])
#endif

/*
 * Determine the offset for the currently active processor.
 * An arch may define __my_cpu_offset to provide a more effective
 * means of obtaining the offset to the per cpu variables of the
 * current processor.
 */
#ifndef __my_cpu_offset
#define __my_cpu_offset per_cpu_offset(raw_smp_processor_id())
#endif
#ifdef CONFIG_DEBUG_PREEMPT // CONFIG_DEBUG_PREEMPT=y
// ARM10C 20140412
// smp_processor_id(): 0
// per_cpu_offset(0): (__per_cpu_offset[0])
// my_cpu_offset: (__per_cpu_offset[0])
#define my_cpu_offset per_cpu_offset(smp_processor_id())
#else
#define my_cpu_offset __my_cpu_offset
#endif

/*
 * Add a offset to a pointer but keep the pointer as is.
 *
 * Only S390 provides its own means of moving the pointer.
 */
#ifndef SHIFT_PERCPU_PTR
/* Weird cast keeps both GCC and sparse happy. */
// ARM10C 20140308
// SHIFT_PERCPU_PTR(&boot_pageset, __per_cpu_offset[0])
//
// #define SHIFT_PERCPU_PTR(&boot_pageset, __per_cpu_offset[0])	({
//      &boot_pageset + __per_cpu_offset[0]
// })
//
// ARM10C 20140405
// __verify_pcpu_ptr((&(vm_event_states.event[PGFREE]))):
// do {
// 	const void __percpu *__vpp_verify = (typeof(&(vm_event_states.event[PGFREE])))NULL;
// 	(void)__vpp_verify;
// } while (0)
// RELOC_HIDE((typeof(*(&(vm_event_states.event[PGFREE]))) __kernel __force *)(&(vm_event_states.event[PGFREE])), (__my_cpu_offset)):
// &(vm_event_states.event[PGFREE]) + __my_cpu_offset;
//
// #define SHIFT_PERCPU_PTR(&(vm_event_states.event[PGFREE]), __my_cpu_offset)	({
// 	do {
// 		const void __percpu *__vpp_verify = (typeof(&(vm_event_states.event[PGFREE]))NULL;
// 		(void)__vpp_verify;
// 	} while (0)
//	&(vm_event_states.event[PGFREE]) + __my_cpu_offset;
// })
//
// ARM10C 20140412
// __verify_pcpu_ptr((&(((&boot_pageset)->vm_stat_diff[0])))):
// do {
// 	const void __percpu *__vpp_verify = (typeof((&(((&boot_pageset)->vm_stat_diff[0])))))NULL;
// 	(void)__vpp_verify;
// } while (0)
// RELOC_HIDE((typeof(*(&(((&boot_pageset)->vm_stat_diff[0])))) __kernel __force *)(&(((&boot_pageset)->vm_stat_diff[0]))), (__my_cpu_offset)):
// &(((&boot_pageset)->vm_stat_diff[0])) + __my_cpu_offset;
//
// #define SHIFT_PERCPU_PTR(&(((&boot_pageset)->vm_stat_diff[0])), __my_cpu_offset)	({
//  	do {
// 	 	const void __percpu *__vpp_verify = (typeof((&(((&boot_pageset)->vm_stat_diff[0])))))NULL;
// 	 	(void)__vpp_verify;
//  	} while (0)
//  	&(((&boot_pageset)->vm_stat_diff[0])) + __my_cpu_offset;
// })
//
// #define SHIFT_PERCPU_PTR(&boot_pageset, (__per_cpu_offset[0]))   ({
//  	do {
// 	 	const void __percpu *__vpp_verify = (typeof(&boot_pageset))NULL;
// 	 	(void)__vpp_verify;
//  	} while (0)
//  	&boot_pageset + (__per_cpu_offset[0]);
// })
#define SHIFT_PERCPU_PTR(__p, __offset)	({				\
	__verify_pcpu_ptr((__p));					\
	RELOC_HIDE((typeof(*(__p)) __kernel __force *)(__p), (__offset)); \
})
#endif

/*
 * A percpu variable may point to a discarded regions. The following are
 * established ways to produce a usable pointer from the percpu variable
 * offset.
 */
// ARM10C 20140308
// boot_pageset, 0
// per_cpu_offset(0): __per_cpu_offset[0]
// SHIFT_PERCPU_PTR(&boot_pageset, __per_cpu_offset[0]): &boot_pageset + __per_cpu_offset[0]
//
// per_cpu(boot_pageset, __per_cpu_offset[0]): *(&boot_pageset + __per_cpu_offset[0])
#define per_cpu(var, cpu) \
	(*SHIFT_PERCPU_PTR(&(var), per_cpu_offset(cpu)))

#ifndef __this_cpu_ptr
// ARM10C 20140405
// SHIFT_PERCPU_PTR(&(vm_event_states.event[PGFREE]), __my_cpu_offset):
// ({
// 	do {
// 		const void __percpu *__vpp_verify = (typeof(&(vm_event_states.event[PGFREE]))NULL;
// 		(void)__vpp_verify;
// 	} while (0)
//	&(vm_event_states.event[PGFREE]) + __my_cpu_offset;
// })
//
// __this_cpu_ptr(&(vm_event_states.event[PGFREE])):
// ({
// 	do {
// 		const void __percpu *__vpp_verify = (typeof(&(vm_event_states.event[PGFREE]))NULL;
// 		(void)__vpp_verify;
// 	} while (0)
//	&(vm_event_states.event[PGFREE]) + __my_cpu_offset;
// })
//
// ARM10C 20140412
// SHIFT_PERCPU_PTR(&(((&boot_pageset)->vm_stat_diff[0])), __my_cpu_offset):
// ({
//  	do {
// 	 	const void __percpu *__vpp_verify = (typeof((&(((&boot_pageset)->vm_stat_diff[0])))))NULL;
// 	 	(void)__vpp_verify;
//  	} while (0)
//  	&(((&boot_pageset)->vm_stat_diff[0])) + __my_cpu_offset;
// })
//
// #define __this_cpu_ptr(&(((&boot_pageset)->vm_stat_diff[0]))):
// ({
//  	do {
// 	 	const void __percpu *__vpp_verify = (typeof((&(((&boot_pageset)->vm_stat_diff[0])))))NULL;
// 	 	(void)__vpp_verify;
//  	} while (0)
//  	&(((&boot_pageset)->vm_stat_diff[0])) + __my_cpu_offset;
// })
#define __this_cpu_ptr(ptr) SHIFT_PERCPU_PTR(ptr, __my_cpu_offset)
#endif
#ifdef CONFIG_DEBUG_PREEMPT // CONFIG_DEBUG_PREEMPT=y
// ARM10C 20140412
// my_cpu_offset: (__per_cpu_offset[0])
// SHIFT_PERCPU_PTR(&boot_pageset, (__per_cpu_offset[0])):
// ({
//  	do {
// 	 	const void __percpu *__vpp_verify = (typeof(&boot_pageset))NULL;
// 	 	(void)__vpp_verify;
//  	} while (0)
//  	&boot_pageset + (__per_cpu_offset[0]);
// })
//
// this_cpu_ptr(&boot_pageset):
// ({
//  	do {
// 	 	const void __percpu *__vpp_verify = (typeof(&boot_pageset))NULL;
// 	 	(void)__vpp_verify;
//  	} while (0)
//  	&boot_pageset + (__per_cpu_offset[0]);
// })
// ARM10C 20140510
// zone->pageset: contig_page_data->node_zones[0].pageset
#define this_cpu_ptr(ptr) SHIFT_PERCPU_PTR(ptr, my_cpu_offset)
#else
#define this_cpu_ptr(ptr) __this_cpu_ptr(ptr)
#endif

#define __get_cpu_var(var) (*this_cpu_ptr(&(var)))
#define __raw_get_cpu_var(var) (*__this_cpu_ptr(&(var)))

#ifdef CONFIG_HAVE_SETUP_PER_CPU_AREA
extern void setup_per_cpu_areas(void);
#endif

#else /* ! SMP */

#define VERIFY_PERCPU_PTR(__p) ({			\
	__verify_pcpu_ptr((__p));			\
	(typeof(*(__p)) __kernel __force *)(__p);	\
})

#define per_cpu(var, cpu)	(*((void)(cpu), VERIFY_PERCPU_PTR(&(var))))
#define __get_cpu_var(var)	(*VERIFY_PERCPU_PTR(&(var)))
#define __raw_get_cpu_var(var)	(*VERIFY_PERCPU_PTR(&(var)))
#define this_cpu_ptr(ptr)	per_cpu_ptr(ptr, 0)
#define __this_cpu_ptr(ptr)	this_cpu_ptr(ptr)

#endif	/* SMP */

#ifndef PER_CPU_BASE_SECTION
#ifdef CONFIG_SMP	// CONFIG_SMP = y 
#define PER_CPU_BASE_SECTION ".data..percpu"
#else
#define PER_CPU_BASE_SECTION ".data"
#endif
#endif

#ifdef CONFIG_SMP

#ifdef MODULE
#define PER_CPU_SHARED_ALIGNED_SECTION ""
#define PER_CPU_ALIGNED_SECTION ""
#else
#define PER_CPU_SHARED_ALIGNED_SECTION "..shared_aligned"
#define PER_CPU_ALIGNED_SECTION "..shared_aligned"
#endif
#define PER_CPU_FIRST_SECTION "..first"

#else

#define PER_CPU_SHARED_ALIGNED_SECTION ""
#define PER_CPU_ALIGNED_SECTION "..shared_aligned"
#define PER_CPU_FIRST_SECTION ""

#endif

#ifndef PER_CPU_ATTRIBUTES
#define PER_CPU_ATTRIBUTES
#endif

#ifndef PER_CPU_DEF_ATTRIBUTES
// ARM10C 20140308
// ARM10C 20140405
#define PER_CPU_DEF_ATTRIBUTES
#endif

#endif /* _ASM_GENERIC_PERCPU_H_ */
