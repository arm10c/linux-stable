/*
 *  arch/arm/include/asm/procinfo.h
 *
 *  Copyright (C) 1996-1999 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __ASM_PROCINFO_H
#define __ASM_PROCINFO_H

#ifdef __KERNEL__

struct cpu_tlb_fns;
struct cpu_user_fns;
struct cpu_cache_fns;
struct processor;

/*
 * Note!  struct processor is always defined if we're
 * using MULTI_CPU, otherwise this entry is unused,
 * but still exists.
 *
 * NOTE! The following structure is defined by assembly
 * language, NOT C code.  For more information, check:
 *  arch/arm/mm/proc-*.S and arch/arm/kernel/head.S
 */
// ARM10C 20130914
struct proc_info_list {
	unsigned int		cpu_val;
	unsigned int		cpu_mask;
	unsigned long		__cpu_mm_mmu_flags;	/* used by head.S */
	unsigned long		__cpu_io_mmu_flags;	/* used by head.S */
	unsigned long		__cpu_flush;		/* used by head.S */
	const char		*arch_name;
	const char		*elf_name;
	unsigned int		elf_hwcap;
	const char		*cpu_name;
	struct processor	*proc;
	struct cpu_tlb_fns	*tlb;
	struct cpu_user_fns	*user;
	struct cpu_cache_fns	*cache;
};

// ARM v7의 구조체값을 만드는 값
// proc-v7.S 에 있음: __lookup_processor_type:
//
//__v7_ca15mp_proc_info:
//	.long	0x410fc0f0
//	.long	0xff0ffff0
//
//.macro __v7_proc initfunc, mm_mmuflags = 0, io_mmuflags = 0, hwcaps = 0, proc_fns = v7_processor_functions
//       ALT_SMP(.long	PMD_TYPE_SECT | PMD_SECT_AP_WRITE | PMD_SECT_AP_READ | \
//   		    PMD_SECT_AF | PMD_FLAGS_SMP | \mm_mmuflags)
//       ALT_UP(.long	PMD_TYPE_SECT | PMD_SECT_AP_WRITE | PMD_SECT_AP_READ | \
//   		    PMD_SECT_AF | PMD_FLAGS_UP | \mm_mmuflags)
//       .long	PMD_TYPE_SECT | PMD_SECT_AP_WRITE | \
//   	    PMD_SECT_AP_READ | PMD_SECT_AF | \io_mmuflags
//       W(b)	\initfunc
//       .long	cpu_arch_name
//       .long	cpu_elf_name
//       .long	HWCAP_SWP | HWCAP_HALF | HWCAP_THUMB | HWCAP_FAST_MULT | \
//   	    HWCAP_EDSP | HWCAP_TLS | \hwcaps
//       .long	cpu_v7_name
//       .long	\proc_fns
//       .long	v7wbi_tlb_fns
//       .long	v6_user_fns
//       .long	v7_cache_fns
//.endm

#else	/* __KERNEL__ */
#include <asm/elf.h>
#warning "Please include asm/elf.h instead"
#endif	/* __KERNEL__ */
#endif
