#ifndef __ASM_ARM_CACHETYPE_H
#define __ASM_ARM_CACHETYPE_H

// ARM10C 20130914
// ARM10C 20141101
// CACHEID_VIVT: 1
#define CACHEID_VIVT			(1 << 0)
// ARM10C 20141101
// CACHEID_VIPT_NONALIASING: 0x2
#define CACHEID_VIPT_NONALIASING	(1 << 1)
#define CACHEID_VIPT_ALIASING		(1 << 2)
#define CACHEID_VIPT			(CACHEID_VIPT_ALIASING|CACHEID_VIPT_NONALIASING)
// ARM10C 20141101
// CACHEID_ASID_TAGGED: 0x8
#define CACHEID_ASID_TAGGED		(1 << 3)
// ARM10C 20141101
// CACHEID_VIPT_I_ALIASING: 0x10
#define CACHEID_VIPT_I_ALIASING		(1 << 4)
// ARM10C 20130928
// ARM10C 20141101
// CACHEID_PIPT: 0x20
#define CACHEID_PIPT			(1 << 5)

extern unsigned int cacheid;

#define cache_is_vivt()			cacheid_is(CACHEID_VIVT)
#define cache_is_vipt()			cacheid_is(CACHEID_VIPT)
// ARM10C 20141101
// CACHEID_VIPT_NONALIASING: 0x2
#define cache_is_vipt_nonaliasing()	cacheid_is(CACHEID_VIPT_NONALIASING)
// ARM10C 20131019
#define cache_is_vipt_aliasing()	cacheid_is(CACHEID_VIPT_ALIASING)
#define icache_is_vivt_asid_tagged()	cacheid_is(CACHEID_ASID_TAGGED)
#define icache_is_vipt_aliasing()	cacheid_is(CACHEID_VIPT_I_ALIASING)
// ARM10C 20130928
#define icache_is_pipt()		cacheid_is(CACHEID_PIPT)

/*
 * __LINUX_ARM_ARCH__ is the minimum supported CPU architecture
 * Mask out support which will never be present on newer CPUs.
 * - v6+ is never VIVT
 * - v7+ VIPT never aliases on D-side
 */
#if __LINUX_ARM_ARCH__ >= 7
// ARM10C 20130914
// ARM10C 20141101
// CACHEID_VIPT_NONALIASING: 0x2
// CACHEID_ASID_TAGGED: 0x8
// CACHEID_VIPT_I_ALIASING: 0x10
// CACHEID_PIPT: 0x20
// __CACHEID_ARCH_MIN: 0x3A
#define __CACHEID_ARCH_MIN	(CACHEID_VIPT_NONALIASING |\
				 CACHEID_ASID_TAGGED |\
				 CACHEID_VIPT_I_ALIASING |\
				 CACHEID_PIPT)
#elif __LINUX_ARM_ARCH__ >= 6
#define	__CACHEID_ARCH_MIN	(~CACHEID_VIVT)
#else
#define __CACHEID_ARCH_MIN	(~0)
#endif

/*
 * Mask out support which isn't configured
 */
#if defined(CONFIG_CPU_CACHE_VIVT) && !defined(CONFIG_CPU_CACHE_VIPT)
#define __CACHEID_ALWAYS	(CACHEID_VIVT)
#define __CACHEID_NEVER		(~CACHEID_VIVT)
#elif !defined(CONFIG_CPU_CACHE_VIVT) && defined(CONFIG_CPU_CACHE_VIPT)
// CONFIG_CPU_CACHE_VIVT= n, CONFIG_CPU_CACHE_VIPT = y
// ARM10C 20130914
// ARM10C 20141101
// __CACHEID_ALWAYS: 0
#define __CACHEID_ALWAYS	(0)	// this
// ARM10C 20141101
// CACHEID_VIVT: 1
// __CACHEID_NEVER: 1
#define __CACHEID_NEVER		(CACHEID_VIVT)
#else
#define __CACHEID_ALWAYS	(0)
#define __CACHEID_NEVER		(0)
#endif

// ARM10C 20130914
// ARM10C 20130928
// ARM10C 20141101
// CACHEID_VIPT_NONALIASING: 0x2
static inline unsigned int __attribute__((pure)) cacheid_is(unsigned int mask)
{
	// __CACHEID_ALWAYS: 0, __CACHEID_NEVER: 1, __CACHEID_ARCH_MIN: 0x3A
	// mask: 0x2, cacheid: 0x20
	return (__CACHEID_ALWAYS & mask) |
	       (~__CACHEID_NEVER & __CACHEID_ARCH_MIN & mask & cacheid);
}

#endif
