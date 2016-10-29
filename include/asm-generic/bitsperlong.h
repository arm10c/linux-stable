#ifndef __ASM_GENERIC_BITS_PER_LONG
#define __ASM_GENERIC_BITS_PER_LONG

#include <uapi/asm-generic/bitsperlong.h>


#ifdef CONFIG_64BIT // CONFIG_64BIT=n
#define BITS_PER_LONG 64
#else
/*
// ARM10C 20141115
// ARM10C 20150530
// ARM10C 20151003
// ARM10C 20150919
// ARM10C 20151121
// ARM10C 20151212
// ARM10C 20160109
// ARM10C 20160319
// ARM10C 20160730
// ARM10C 20161015
// ARM10C 20161029
// BITS_PER_LONG: 32
*/
#define BITS_PER_LONG 32
#endif /* CONFIG_64BIT */

/*
 * FIXME: The check currently breaks x86-64 build, so it's
 * temporarily disabled. Please fix x86-64 and reenable
 */
#if 0 && BITS_PER_LONG != __BITS_PER_LONG
#error Inconsistent word size. Check asm/bitsperlong.h
#endif

#ifndef BITS_PER_LONG_LONG
#define BITS_PER_LONG_LONG 64
#endif

#endif /* __ASM_GENERIC_BITS_PER_LONG */
