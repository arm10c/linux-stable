#ifndef __ASM_BARRIER_H
#define __ASM_BARRIER_H

#ifndef __ASSEMBLY__
#include <asm/outercache.h>

#define nop() __asm__ __volatile__("mov\tr0,r0\t@ nop\n\t");

#if __LINUX_ARM_ARCH__ >= 7 ||		\
	(__LINUX_ARM_ARCH__ == 6 && defined(CONFIG_CPU_32v6K))
#define sev()	__asm__ __volatile__ ("sev" : : : "memory")
#define wfe()	__asm__ __volatile__ ("wfe" : : : "memory")
#define wfi()	__asm__ __volatile__ ("wfi" : : : "memory")
#endif

#if __LINUX_ARM_ARCH__ >= 7 // __LINUX_ARM_ARCH__: 7
#define isb(option) __asm__ __volatile__ ("isb " #option : : : "memory")
// ARM10C 20131109
#define dsb(option) __asm__ __volatile__ ("dsb " #option : : : "memory")
// ARM10C 20131109
// ARM10C 20140621
// ARM10C 20141101
// A.R.M: A8.8.43 DMB
// ISH option:
// ISH Inner Shareable is the required shareability domain, reads and writes are the required
// access types. Encoded as option = 0b1011.
#define dmb(option) __asm__ __volatile__ ("dmb " #option : : : "memory")
#elif defined(CONFIG_CPU_XSC3) || __LINUX_ARM_ARCH__ == 6
#define isb(x) __asm__ __volatile__ ("mcr p15, 0, %0, c7, c5, 4" \
				    : : "r" (0) : "memory")
#define dsb(x) __asm__ __volatile__ ("mcr p15, 0, %0, c7, c10, 4" \
				    : : "r" (0) : "memory")
#define dmb(x) __asm__ __volatile__ ("mcr p15, 0, %0, c7, c10, 5" \
				    : : "r" (0) : "memory")
#elif defined(CONFIG_CPU_FA526)
#define isb(x) __asm__ __volatile__ ("mcr p15, 0, %0, c7, c5, 4" \
				    : : "r" (0) : "memory")
#define dsb(x) __asm__ __volatile__ ("mcr p15, 0, %0, c7, c10, 4" \
				    : : "r" (0) : "memory")
#define dmb(x) __asm__ __volatile__ ("" : : : "memory")
#else
#define isb(x) __asm__ __volatile__ ("" : : : "memory")
#define dsb(x) __asm__ __volatile__ ("mcr p15, 0, %0, c7, c10, 4" \
				    : : "r" (0) : "memory")
#define dmb(x) __asm__ __volatile__ ("" : : : "memory")
#endif

#ifdef CONFIG_ARCH_HAS_BARRIERS
#include <mach/barriers.h>
#elif defined(CONFIG_ARM_DMA_MEM_BUFFERABLE) || defined(CONFIG_SMP)
#define mb()		do { dsb(); outer_sync(); } while (0)
#define rmb()		dsb()
#define wmb()		do { dsb(st); outer_sync(); } while (0)
#else
#define mb()		barrier()
#define rmb()		barrier()
#define wmb()		barrier()
#endif

#ifndef CONFIG_SMP // CONFIG_SMP=y
#define smp_mb()	barrier()
#define smp_rmb()	barrier()
#define smp_wmb()	barrier()
#else
// ARM10C 20140125
// ARM10C 20140621
// A.R.M: A8.8.43 DMB
// ISH option:
// ISH Inner Shareable is the required shareability domain, reads and writes are the required
// access types. Encoded as option = 0b1011.
// 공유자원을 다른 cpu core가 사용할수 있게 해주는 옵션
#define smp_mb()	dmb(ish)
// ARM10C 20140913
#define smp_rmb()	smp_mb()
// ARM10C 20140308
// ARM10C 20140322
// ARM10C 20140913
// ARM10C 20141101
// A.R.M: A8.8.43 DMB
// ISHST option:
// Inner Shareable is the required shareability domain, writes are the required access type.
// Encoded as option = 0b1010.
// 공유자원을 다른 cpu core가 사용할수 있게 해주는 옵션
#define smp_wmb()	dmb(ishst)
#endif

#define read_barrier_depends()		do { } while(0)
#define smp_read_barrier_depends()	do { } while(0)

#define set_mb(var, value)	do { var = value; smp_mb(); } while (0)

#endif /* !__ASSEMBLY__ */
#endif /* __ASM_BARRIER_H */
