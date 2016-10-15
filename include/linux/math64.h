#ifndef _LINUX_MATH64_H
#define _LINUX_MATH64_H

#include <linux/types.h>
#include <asm/div64.h>

#if BITS_PER_LONG == 64 // BITS_PER_LONG: 32

#define div64_long(x, y) div64_s64((x), (y))
#define div64_ul(x, y)   div64_u64((x), (y))

/**
 * div_u64_rem - unsigned 64bit divide with 32bit divisor with remainder
 *
 * This is commonly provided by 32bit archs to provide an optimized 64bit
 * divide.
 */
static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

/**
 * div_s64_rem - signed 64bit divide with 32bit divisor with remainder
 */
static inline s64 div_s64_rem(s64 dividend, s32 divisor, s32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

/**
 * div64_u64_rem - unsigned 64bit divide with 64bit divisor and remainder
 */
static inline u64 div64_u64_rem(u64 dividend, u64 divisor, u64 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

/**
 * div64_u64 - unsigned 64bit divide with 64bit divisor
 */
static inline u64 div64_u64(u64 dividend, u64 divisor)
{
	return dividend / divisor;
}

/**
 * div64_s64 - signed 64bit divide with 64bit divisor
 */
static inline s64 div64_s64(s64 dividend, s64 divisor)
{
	return dividend / divisor;
}

#elif BITS_PER_LONG == 32

#define div64_long(x, y) div_s64((x), (y))
#define div64_ul(x, y)   div_u64((x), (y))

#ifndef div_u64_rem
// ARM10C 20150103
// dividend: 4294967296000000000, divisor: 100, &remainder
static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	// dividend: 4294967296000000000, divisor: 100, *remainder: remainder
	*remainder = do_div(dividend, divisor);
	// dividend: 42949672960000000, *remainder: 0

	// dividend: 42949672960000000
	return dividend;
	// return 42949672960000000
}
#endif

#ifndef div_s64_rem
extern s64 div_s64_rem(s64 dividend, s32 divisor, s32 *remainder);
#endif

#ifndef div64_u64_rem
extern u64 div64_u64_rem(u64 dividend, u64 divisor, u64 *remainder);
#endif

#ifndef div64_u64
extern u64 div64_u64(u64 dividend, u64 divisor);
#endif

#ifndef div64_s64
extern s64 div64_s64(s64 dividend, s64 divisor);
#endif

#endif /* BITS_PER_LONG */

/**
 * div_u64 - unsigned 64bit divide with 32bit divisor
 *
 * This is the most common 64bit divide and should be used if possible,
 * as many 32bit archs can optimize this variant better than a full 64bit
 * divide.
 */
#ifndef div_u64
// ARM10C 20150103
// second_length: 4294967296000000000, HZ: 100
static inline u64 div_u64(u64 dividend, u32 divisor)
{
	u32 remainder;

	// dividend: 4294967296000000000, divisor: 100
	// div_u64_rem(4294967296000000000, 100, &remainder): 42949672960000000
	return div_u64_rem(dividend, divisor, &remainder);
	// return 42949672960000000
}
#endif

/**
 * div_s64 - signed 64bit divide with 32bit divisor
 */
#ifndef div_s64
static inline s64 div_s64(s64 dividend, s32 divisor)
{
	s32 remainder;
	return div_s64_rem(dividend, divisor, &remainder);
}
#endif

u32 iter_div_u64_rem(u64 dividend, u32 divisor, u64 *remainder);

// ARM10C 20160910
// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_nsec + ns: 현재의 nsec 값, NSEC_PER_SEC: 1000000000L, &ns
static __always_inline u32
__iter_div_u64_rem(u64 dividend, u32 divisor, u64 *remainder)
{
	u32 ret = 0;
	// ret: 0

	// dividend: (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_nsec + ns: 현재의 nsec 값, divisor: 1000000000L
	while (dividend >= divisor) {
		/* The following asm() prevents the compiler from
		   optimising this loop into a modulo operation.  */
		asm("" : "+rm"(dividend));

		dividend -= divisor;
		ret++;
	}

	// 위 loop  수행 결과
	// 현재의 nsec 값을 1000000000L 나눈 목과 나머지를 구함
	// ret: 현재의 nsec 값 / 1000000000L

	// *remainder: *(&ns), dividend: 현재의 nsec 값 % 1000000000L
	*remainder = dividend;
	// *remainder: *(&ns): 현재의 nsec 값 % 1000000000L

	// ret: 현재의 nsec 값 / 1000000000L
	return ret;
	// return 현재의 nsec 값 / 1000000000L
}

#if defined(CONFIG_ARCH_SUPPORTS_INT128) && defined(__SIZEOF_INT128__)

#ifndef mul_u64_u32_shr
static inline u64 mul_u64_u32_shr(u64 a, u32 mul, unsigned int shift)
{
	return (u64)(((unsigned __int128)a * mul) >> shift);
}
#endif /* mul_u64_u32_shr */

#else

#ifndef mul_u64_u32_shr
// ARM10C 20161015
// delta_exec: 6000000, fact: 0xFFFFFC00, shift: 32
static inline u64 mul_u64_u32_shr(u64 a, u32 mul, unsigned int shift)
{
	u32 ah, al;
	u64 ret;

	// a: 6000000
	al = a;
	// al: 6000000

	// a: 6000000
	ah = a >> 32;
	// ah: 0

	// al: 6000000, mul: 0xFFFFFC00, shift: 32
	ret = ((u64)al * mul) >> shift;
	// ret: 0x5B8D7E

	// ah: 0
	if (ah)
		ret += ((u64)ah * mul) << (32 - shift);

	// ret: 0x5B8D7E
	return ret;
	// return 0x5B8D7E
}
#endif /* mul_u64_u32_shr */

#endif

#endif /* _LINUX_MATH64_H */
