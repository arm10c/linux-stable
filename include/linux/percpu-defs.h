#ifndef _LINUX_PERCPU_DEFS_H
#define _LINUX_PERCPU_DEFS_H

/*
 * Base implementations of per-CPU variable declarations and definitions, where
 * the section in which the variable is to be placed is provided by the
 * 'sec' argument.  This may be used to affect the parameters governing the
 * variable's storage.
 *
 * NOTE!  The sections for the DECLARE and for the DEFINE must match, lest
 * linkage errors occur due the compiler generating the wrong code to access
 * that section.
 */

// ARM10C 20140111
// sec = ""
// #define PER_CPU_BASE_SECTION ".data..percpu"
// PER_CPU_ATTRIBUTES = undefined
// ARM10C 20140308
// ARM10C 20140830
// __PCPU_ATTRS(""): __attribute__((section(".data..percpu" "")))
// ARM10C 20140830
// __PCPU_ATTRS("..shared_aligned"): __attribute__((section(".data..percpu" "..shared_aligned"))
#define __PCPU_ATTRS(sec)						\
	__percpu __attribute__((section(PER_CPU_BASE_SECTION sec)))	\
	PER_CPU_ATTRIBUTES

#define __PCPU_DUMMY_ATTRS						\
	__attribute__((section(".discard"), unused))

/*
 * Macro which verifies @ptr is a percpu pointer without evaluating
 * @ptr.  This is to be used in percpu accessors to verify that the
 * input parameter is a percpu pointer.
 *
 * + 0 is required in order to convert the pointer type from a
 * potential array type to a pointer to a single item of the array.
 */
// ARM10C 20140308
// __verify_pcpu_ptr((&boot_pageset));
// ARM10C 20140405
// #define __verify_pcpu_ptr(&(vm_event_states.event[PGFREE])):
// do {
// 	const void __percpu *__vpp_verify = (typeof(&(vm_event_states.event[PGFREE]))NULL;
// 	(void)__vpp_verify;
// } while (0)
#define __verify_pcpu_ptr(ptr)	do {					\
	const void __percpu *__vpp_verify = (typeof((ptr) + 0))NULL;	\
	(void)__vpp_verify;						\
} while (0)

/*
 * s390 and alpha modules require percpu variables to be defined as
 * weak to force the compiler to generate GOT based external
 * references for them.  This is necessary because percpu sections
 * will be located outside of the usually addressable area.
 *
 * This definition puts the following two extra restrictions when
 * defining percpu variables.
 *
 * 1. The symbol must be globally unique, even the static ones.
 * 2. Static percpu variables cannot be defined inside a function.
 *
 * Archs which need weak percpu definitions should define
 * ARCH_NEEDS_WEAK_PER_CPU in asm/percpu.h when necessary.
 *
 * To ensure that the generic code observes the above two
 * restrictions, if CONFIG_DEBUG_FORCE_WEAK_PER_CPU is set weak
 * definition is used for all cases.
 */
// ARCH_NEEDS_WEAK_PER_CPU = undefined, CONFIG_DEBUG_FORCE_WEAK_PER_CPU = n
#if defined(ARCH_NEEDS_WEAK_PER_CPU) || defined(CONFIG_DEBUG_FORCE_WEAK_PER_CPU)
/*
 * __pcpu_scope_* dummy variable is used to enforce scope.  It
 * receives the static modifier when it's used in front of
 * DEFINE_PER_CPU() and will trigger build failure if
 * DECLARE_PER_CPU() is used for the same variable.
 *
 * __pcpu_unique_* dummy variable is used to enforce symbol uniqueness
 * such that hidden weak symbol collision, which will cause unrelated
 * variables to share the same address, can be detected during build.
 */
#define DECLARE_PER_CPU_SECTION(type, name, sec)			\
	extern __PCPU_DUMMY_ATTRS char __pcpu_scope_##name;		\
	extern __PCPU_ATTRS(sec) __typeof__(type) name

#define DEFINE_PER_CPU_SECTION(type, name, sec)				\
	__PCPU_DUMMY_ATTRS char __pcpu_scope_##name;			\
	extern __PCPU_DUMMY_ATTRS char __pcpu_unique_##name;		\
	__PCPU_DUMMY_ATTRS char __pcpu_unique_##name;			\
	extern __PCPU_ATTRS(sec) __typeof__(type) name;			\
	__PCPU_ATTRS(sec) PER_CPU_DEF_ATTRIBUTES __weak			\
	__typeof__(type) name
#else
/*
 * Normal declaration and definition macros.
 */
// ARM10C 20140830
// __PCPU_ATTRS(""): __attribute__((section(".data..percpu" "")))
//
// DECLARE_PER_CPU_SECTION(struct rq, runqueues, ""):
// extern __attribute__((section(".data..percpu" ""))) __typeof__(struct rq) runqueues
// ARM10C 20150523
// DECLARE_PER_CPU_SECTION(struct tick_device, tick_cpu_device, ""):
// extern __attribute__((section(".data..percpu" ""))) __typeof__(struct tick_device) tick_cpu_device
#define DECLARE_PER_CPU_SECTION(type, name, sec)			\
	extern __PCPU_ATTRS(sec) __typeof__(type) name

// ARM10C 20140111
// type = struct per_cpu_pageset, name = boot_pageset
// __attribute__((section(.data..percpu))) struct per_cpu_pageset boot_pageset
//
// ARM10C 20140308
// __PCPU_ATTRS(""): __attribute__((section(".data..percpu" "")))
// DEFINE_PER_CPU_SECTION(struct per_cpu_pageset, boot_pageset, "")
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(struct per_cpu_pageset) boot_pageset
//
// ARM10C 20140405
// __PCPU_ATTRS(""): __attribute__((section(".data..percpu" "")))
// DEFINE_PER_CPU_SECTION(struct vm_event_state, vm_event_states, ""):
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(struct vm_event_state) vm_event_states
// ARM10C 20140830
// __PCPU_ATTRS("..shared_aligned"): __attribute__((section(".data..percpu" "..shared_aligned"))
//
// DEFINE_PER_CPU_SECTION(struct rq, runqueues, "..shared_aligned"):
// __attribute__((section(".data..percpu" "..shared_aligned"))
// __typeof__(struct rq) runqueues
#define DEFINE_PER_CPU_SECTION(type, name, sec)				\
	__PCPU_ATTRS(sec) PER_CPU_DEF_ATTRIBUTES			\
	__typeof__(type) name
#endif

/*
 * Variant on the per-CPU variable declaration/definition theme used for
 * ordinary per-CPU variables.
 */
// ARM10C 20140830
// DECLARE_PER_CPU_SECTION(struct rq, runqueues, ""):
// extern __attribute__((section(".data..percpu" ""))) __typeof__(struct rq) runqueues
//
// DECLARE_PER_CPU(struct rq, runqueues):
// extern __attribute__((section(".data..percpu" ""))) __typeof__(struct rq) runqueues
// ARM10C 20150523
// DECLARE_PER_CPU_SECTION(struct tick_device, tick_cpu_device, ""):
// extern __attribute__((section(".data..percpu" ""))) __typeof__(struct tick_device) tick_cpu_device
//
// DECLARE_PER_CPU(struct tick_device, tick_cpu_device):
// extern __attribute__((section(".data..percpu" ""))) __typeof__(struct tick_device) tick_cpu_device
#define DECLARE_PER_CPU(type, name)					\
	DECLARE_PER_CPU_SECTION(type, name, "")

// ARM10C 20140111
// type = struct per_cpu_pageset, name = boot_pageset
// ARM10C 20140308
// static DEFINE_PER_CPU(struct per_cpu_pageset, boot_pageset)
// DEFINE_PER_CPU_SECTION(struct per_cpu_pageset, boot_pageset, "")
//
// ARM10C 20140405
// DEFINE_PER_CPU_SECTION(struct vm_event_state, vm_event_states, ""):
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(struct vm_event_state) vm_event_states
//
// DEFINE_PER_CPU(struct vm_event_state, vm_event_states):
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(struct vm_event_state) vm_event_states
// ARM10C 20150418
// DEFINE_PER_CPU(struct mct_clock_event_device, percpu_mct_tick):
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(struct mct_clock_event_device) percpu_mct_tick
// ARM10C 20150711
// DEFINE_PER_CPU(struct tvec_base *, tvec_bases):
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(struct tvec_base *) tvec_bases
// ARM10C 20150912
// DEFINE_PER_CPU(unsigned long, nr_inodes):
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(unsigned long) nr_inodes
// ARM10C 20151219
// DEFINE_PER_CPU(long, nr_dentry):
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(unsigned long) nr_dentry
// ARM10C 20160319
// DEFINE_PER_CPU(unsigned int, last_ino):
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(unsigned int) last_ino
// ARM10C 20161210
// DEFINE_PER_CPU(unsigned long, process_counts):
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(unsigned long) process_counts
// ARM10C 20170715
// DEFINE_PER_CPU(struct rcu_data, rcu_sched_data):
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(struct rcu_data) rcu_sched_data
#define DEFINE_PER_CPU(type, name)					\
	DEFINE_PER_CPU_SECTION(type, name, "")

/*
 * Declaration/definition used for per-CPU variables that must come first in
 * the set of variables.
 */
#define DECLARE_PER_CPU_FIRST(type, name)				\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_FIRST_SECTION)

#define DEFINE_PER_CPU_FIRST(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_FIRST_SECTION)

/*
 * Declaration/definition used for per-CPU variables that must be cacheline
 * aligned under SMP conditions so that, whilst a particular instance of the
 * data corresponds to a particular CPU, inefficiencies due to direct access by
 * other CPUs are reduced by preventing the data from unnecessarily spanning
 * cachelines.
 *
 * An example of this would be statistical data, where each CPU's set of data
 * is updated by that CPU alone, but the data from across all CPUs is collated
 * by a CPU processing a read from a proc file.
 */
#define DECLARE_PER_CPU_SHARED_ALIGNED(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_SHARED_ALIGNED_SECTION) \
	____cacheline_aligned_in_smp

// ARM10C 20140830
// PER_CPU_SHARED_ALIGNED_SECTION: "..shared_aligned"
// ____cacheline_aligned_in_smp: __attribute__((__aligned__(64)))
//
// DEFINE_PER_CPU_SECTION(struct rq, runqueues, "..shared_aligned"):
// __attribute__((section(".data..percpu" "..shared_aligned"))
// __typeof__(struct rq) runqueues
// __attribute__((__aligned__(64)))
//
// DEFINE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues):
// __attribute__((section(".data..percpu" "..shared_aligned"))
// __typeof__(struct rq) runqueues
// __attribute__((__aligned__(64)))
//
// ARM10C 20150620
// DEFINE_PER_CPU_SHARED_ALIGNED(struct call_single_queue, call_single_queue):
// __attribute__((section(".data..percpu" "..shared_aligned"))
// __typeof__(struct call_single_queue) call_single_queue
// __attribute__((__aligned__(64)))
//
// ARM10C 20150620
// DEFINE_PER_CPU_SHARED_ALIGNED(struct call_function_data, cfd_data):
// __attribute__((section(".data..percpu" "..shared_aligned"))
// __typeof__(struct call_function_data) cfd_data
// __attribute__((__aligned__(64)))
#define DEFINE_PER_CPU_SHARED_ALIGNED(type, name)			\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_SHARED_ALIGNED_SECTION) \
	____cacheline_aligned_in_smp

#define DECLARE_PER_CPU_ALIGNED(type, name)				\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_ALIGNED_SECTION)	\
	____cacheline_aligned

#define DEFINE_PER_CPU_ALIGNED(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_ALIGNED_SECTION)	\
	____cacheline_aligned

/*
 * Declaration/definition used for per-CPU variables that must be page aligned.
 */
#define DECLARE_PER_CPU_PAGE_ALIGNED(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, "..page_aligned")		\
	__aligned(PAGE_SIZE)

#define DEFINE_PER_CPU_PAGE_ALIGNED(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, "..page_aligned")		\
	__aligned(PAGE_SIZE)

/*
 * Declaration/definition used for per-CPU variables that must be read mostly.
 */
#define DECLARE_PER_CPU_READ_MOSTLY(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, "..readmostly")

#define DEFINE_PER_CPU_READ_MOSTLY(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, "..readmostly")

/*
 * Intermodule exports for per-CPU variables.  sparse forgets about
 * address space across EXPORT_SYMBOL(), change EXPORT_SYMBOL() to
 * noop if __CHECKER__.
 */
#ifndef __CHECKER__
// ARM10C 20140405
// EXPORT_SYMBOL(vm_event_states):
// extern typeof(vm_event_states) vm_event_states;
// static const char __kstrtab_vm_event_states[]
// __attribute__((section("__ksymtab_strings"), aligned(1)))
// = "vm_event_states";
// static const struct kernel_symbol __ksymtab_vm_event_states
// __attribute__((__used__))
// __attribute__((section("___ksymtab" "" "+" "vm_event_states"), unused))
// = { (unsigned long)&vm_event_states, __kstrtab_vm_event_states }
//
// EXPORT_PER_CPU_SYMBOL(vm_event_states):
// extern typeof(vm_event_states) vm_event_states;
// static const char __kstrtab_vm_event_states[]
// __attribute__((section("__ksymtab_strings"), aligned(1)))
// = "vm_event_states";
// static const struct kernel_symbol __ksymtab_vm_event_states
// __attribute__((__used__))
// __attribute__((section("___ksymtab" "" "+" "vm_event_states"), unused))
// = { (unsigned long)&vm_event_states, __kstrtab_vm_event_states }
#define EXPORT_PER_CPU_SYMBOL(var) EXPORT_SYMBOL(var)
#define EXPORT_PER_CPU_SYMBOL_GPL(var) EXPORT_SYMBOL_GPL(var)
#else
#define EXPORT_PER_CPU_SYMBOL(var)
#define EXPORT_PER_CPU_SYMBOL_GPL(var)
#endif

#endif /* _LINUX_PERCPU_DEFS_H */
