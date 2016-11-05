/*
 *  arch/arm/include/asm/processor.h
 *
 *  Copyright (C) 1995-1999 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __ASM_ARM_PROCESSOR_H
#define __ASM_ARM_PROCESSOR_H

/*
 * Default implementation of macro that returns current
 * instruction pointer ("program counter").
 */
#define current_text_addr() ({ __label__ _l; _l: &&_l;})

#ifdef __KERNEL__

#include <asm/hw_breakpoint.h>
#include <asm/ptrace.h>
#include <asm/types.h>
#include <asm/unified.h>

#ifdef __KERNEL__
#define STACK_TOP	((current->personality & ADDR_LIMIT_32BIT) ? \
			 TASK_SIZE : TASK_SIZE_26)
#define STACK_TOP_MAX	TASK_SIZE
#endif

// ARM10C 20150919
struct debug_info {
#ifdef CONFIG_HAVE_HW_BREAKPOINT // CONFIG_HAVE_HW_BREAKPOINT=n
	struct perf_event	*hbp[ARM_MAX_HBP_SLOTS];
#endif
};

// ARM10C 20150919
// sizeof(struct thread_struct): 12 bytes
struct thread_struct {
							/* fault info	  */
	unsigned long		address;
	unsigned long		trap_no;
	unsigned long		error_code;
							/* debugging	  */
	struct debug_info	debug;
};

// ARM10C 20150808
#define INIT_THREAD  {	}

#ifdef CONFIG_MMU
#define nommu_start_thread(regs) do { } while (0)
#else
#define nommu_start_thread(regs) regs->ARM_r10 = current->mm->start_data
#endif

#define start_thread(regs,pc,sp)					\
({									\
	memset(regs->uregs, 0, sizeof(regs->uregs));			\
	if (current->personality & ADDR_LIMIT_32BIT)			\
		regs->ARM_cpsr = USR_MODE;				\
	else								\
		regs->ARM_cpsr = USR26_MODE;				\
	if (elf_hwcap & HWCAP_THUMB && pc & 1)				\
		regs->ARM_cpsr |= PSR_T_BIT;				\
	regs->ARM_cpsr |= PSR_ENDSTATE;					\
	regs->ARM_pc = pc & ~1;		/* pc */			\
	regs->ARM_sp = sp;		/* sp */			\
	nommu_start_thread(regs);					\
})

/* Forward declaration, a strange C thing */
struct task_struct;

/* Free all resources held by a thread. */
extern void release_thread(struct task_struct *);

unsigned long get_wchan(struct task_struct *p);

#if __LINUX_ARM_ARCH__ == 6 || defined(CONFIG_ARM_ERRATA_754327)
#define cpu_relax()			smp_mb()
#else
#define cpu_relax()			barrier()
#endif

// ARM10C 20161105
// THREAD_START_SP: 8184
// p: kmem_cache#15-oX (struct task_struct)
// task_stack_page(kmem_cache#15-oX (struct task_struct)): (kmem_cache#15-oX (struct task_struct))->stack
#define task_pt_regs(p) \
	((struct pt_regs *)(THREAD_START_SP + task_stack_page(p)) - 1)

#define KSTK_EIP(tsk)	task_pt_regs(tsk)->ARM_pc
#define KSTK_ESP(tsk)	task_pt_regs(tsk)->ARM_sp

#ifdef CONFIG_SMP // CONFIG_SMP=y
// ARM10C 20160326
// ARM10C 20160402
// __ALT_SMP_ASM("wfemi", "nop")
// #define __ALT_SMP_ASM(wfemi, nop):
// "9998:
// "	wfemi "\n"
// "	.pushsection \".alt.wfemi.init\", \"a\"\n"
// "	.long	9998b\n"
// "	" nop "\n"
// "	.popsection\n"
// ARM10C 20160402
// __ALT_SMP_ASM("sev", "nop"):
// "9998:
// "	sev "\n"
// "	.pushsection \".alt.sev.init\", \"a\"\n"
// "	.long	9998b\n"
// "	" nop "\n"
// "	.popsection\n"
#define __ALT_SMP_ASM(smp, up)						\
	"9998:	" smp "\n"						\
	"	.pushsection \".alt.smp.init\", \"a\"\n"		\
	"	.long	9998b\n"					\
	"	" up "\n"						\
	"	.popsection\n"
#else
#define __ALT_SMP_ASM(smp, up)	up
#endif

/*
 * Prefetching support - only ARMv5.
 */
#if __LINUX_ARM_ARCH__ >= 5 // __LINUX_ARM_ARCH__: 7

#define ARCH_HAS_PREFETCH
// ARM10C 20140329
// "pld\t%a0"의 %a0의 의미는?
// Arm Procedure Call Standard (APCS) Conventions
// Argument registers: %a0 - %a4 (aliased to %r0 - %r4)
// pld의 사용 이유?
// http://stackoverflow.com/questions/6414555/proper-use-of-the-arm-pld-instruction-arm11
//
// page: 0x20000의 해당하는 struct page의 주소
//
// ARM10C 20140719
// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712
static inline void prefetch(const void *ptr)
{
	__asm__ __volatile__(
		"pld\t%a0"
		:: "p" (ptr));
	// cache table에 page 주소를 넣음
}

#if __LINUX_ARM_ARCH__ >= 7 && defined(CONFIG_SMP)
#define ARCH_HAS_PREFETCHW
// ARM10C 20140329
// page: 0x20000의 해당하는 struct page의 주소
// ARM10C 20160319
// &inode_sb_list_lock
// ARM10C 20160326
//  &rw->lock: &(&(&file_systems_lock)->raw_lock)->lock
static inline void prefetchw(const void *ptr)
{
	__asm__ __volatile__(
		".arch_extension	mp\n"
		__ALT_SMP_ASM(
			WASM(pldw)		"\t%a0",
			WASM(pld)		"\t%a0"
		)
		:: "p" (ptr));
}
#endif
#endif

#define HAVE_ARCH_PICK_MMAP_LAYOUT

#endif

#endif /* __ASM_ARM_PROCESSOR_H */
