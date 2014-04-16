#ifndef __LINUX_CACHE_H
#define __LINUX_CACHE_H

#include <linux/kernel.h>
#include <asm/cache.h>

#ifndef L1_CACHE_ALIGN
#define L1_CACHE_ALIGN(x) ALIGN(x, L1_CACHE_BYTES)
#endif

// ARM10C 20130914 this
// SMP_CACHE_BYTES not defined
#ifndef SMP_CACHE_BYTES
// L1_CACHE_BYTES = 64
// SMP_CACHE_BYTES = 64
#define SMP_CACHE_BYTES L1_CACHE_BYTES
#endif

#ifndef __read_mostly
#define __read_mostly
#endif

// ARM10C 20130914
// ____cacheline_aligned 
// 64 byte align (Coretex-A15)
#ifndef ____cacheline_aligned
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif

#ifndef ____cacheline_aligned_in_smp
#ifdef CONFIG_SMP
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#else
#define ____cacheline_aligned_in_smp
#endif /* CONFIG_SMP */
#endif

#ifndef __cacheline_aligned
// ARM10C 20140412
// SMP_CACHE_BYTES: 64
#define __cacheline_aligned					\
  __attribute__((__aligned__(SMP_CACHE_BYTES),			\
		 __section__(".data..cacheline_aligned")))
#endif /* __cacheline_aligned */

#ifndef __cacheline_aligned_in_smp
#ifdef CONFIG_SMP // CONFIG_SMP=y
// ARM10C 20140412
// __cacheline_aligned:
// __attribute__((__aligned__(64), __section__(".data..cacheline_aligned")))
//
// __cacheline_aligned_in_smp:
// __attribute__((__aligned__(64), __section__(".data..cacheline_aligned")))
#define __cacheline_aligned_in_smp __cacheline_aligned
#else
#define __cacheline_aligned_in_smp
#endif /* CONFIG_SMP */
#endif

/*
 * The maximum alignment needed for some critical structures
 * These could be inter-node cacheline sizes/L3 cacheline
 * size etc.  Define this in asm/cache.h for your arch
 */
#ifndef INTERNODE_CACHE_SHIFT // undefined
// ARM10C 20131207
// ARM10C 20140125
// L1_CACHE_SHIFT: 6
// INTERNODE_CACHE_SHIFT: 6
#define INTERNODE_CACHE_SHIFT L1_CACHE_SHIFT
#endif

#if !defined(____cacheline_internodealigned_in_smp)
#if defined(CONFIG_SMP) // CONFIG_SMP=y
// ARM10C 20131207
// ARM10C 20140125
#define ____cacheline_internodealigned_in_smp \
	__attribute__((__aligned__(1 << (INTERNODE_CACHE_SHIFT))))
#else
#define ____cacheline_internodealigned_in_smp
#endif
#endif

#ifndef CONFIG_ARCH_HAS_CACHE_LINE_SIZE
#define cache_line_size()	L1_CACHE_BYTES
#endif

#endif /* __LINUX_CACHE_H */
