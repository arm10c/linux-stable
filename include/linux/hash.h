#ifndef _LINUX_HASH_H
#define _LINUX_HASH_H
/* Fast hashing routine for ints,  longs and pointers.
   (C) 2002 Nadia Yvette Chambers, IBM */

/*
 * Knuth recommends primes in approximately golden ratio to the maximum
 * integer representable by a machine word for multiplicative hashing.
 * Chuck Lever verified the effectiveness of this technique:
 * http://www.citi.umich.edu/techreports/reports/citi-tr-00-1.pdf
 *
 * These primes are chosen to be bit-sparse, that is operations on
 * them can use shifts and additions instead of multiplications for
 * machines where multiplications are slow.
 */

#include <asm/types.h>
#include <linux/compiler.h>

/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
// ARM10C 20151121
// ARM10C 20151212
// GOLDEN_RATIO_PRIME_32: 0x9e370001UL
#define GOLDEN_RATIO_PRIME_32 0x9e370001UL
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001UL

#if BITS_PER_LONG == 32 // BITS_PER_LONG: 32
// ARM10C 20151121
// GOLDEN_RATIO_PRIME_32: 0x9e370001UL
// GOLDEN_RATIO_PRIME: 0x9e370001UL
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_32
// ARM10C 20151212
// val: &(kmem_cache#4-oX)->i_state 값을 이용한 hash val 값,
// zone->wait_table_bits: (&(kmem_cache#4-oX)->i_state의 zone의 주소)->wait_table_bits
// ARM10C 20160116
// ptr: NULL, bits: 31
#define hash_long(val, bits) hash_32(val, bits)
#elif BITS_PER_LONG == 64
#define hash_long(val, bits) hash_64(val, bits)
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_64
#else
#error Wordsize not 32 or 64
#endif

static __always_inline u64 hash_64(u64 val, unsigned int bits)
{
	u64 hash = val;

	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	u64 n = hash;
	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;

	/* High bits are more random, so use them. */
	return hash >> (64 - bits);
}

// ARM10C 20151212
// val: &(kmem_cache#4-oX)->i_state 값을 이용한 hash val 값,
// zone->wait_table_bits: (&(kmem_cache#4-oX)->i_state의 zone의 주소)->wait_table_bits
// ARM10C 20160116
// ptr: NULL, bits: 31
// ARM10C 20160730
// hash_min(0xXXXXXXXX, 7)
static inline u32 hash_32(u32 val, unsigned int bits)
{
	/* On some cpus multiply is faster, on others gcc will do shifts */
	// val: &(kmem_cache#4-oX)->i_state 값을 이용한 hash val 값, GOLDEN_RATIO_PRIME_32: 0x9e370001UL
	u32 hash = val * GOLDEN_RATIO_PRIME_32;
	// hash: &(kmem_cache#4-oX)->i_state 값을 이용한 hash val 값* 0x9e370001UL

	/* High bits are more random, so use them. */
	// hash: &(kmem_cache#4-oX)->i_state 값을 이용한 hash val 값* 0x9e370001UL,
	// bits: (&(kmem_cache#4-oX)->i_state의 zone의 주소)->wait_table_bits
	return hash >> (32 - bits);
	// return 계산된 hash index 값
}

// ARM10C 20160116
// NULL, 31
static inline unsigned long hash_ptr(const void *ptr, unsigned int bits)
{
	// ptr: NULL, bits: 31
	// hash_long(NULL, 31): 계산된 hash index 값
	return hash_long((unsigned long)ptr, bits);
	// return 계산된 hash index 값
}

static inline u32 hash32_ptr(const void *ptr)
{
	unsigned long val = (unsigned long)ptr;

#if BITS_PER_LONG == 64
	val ^= (val >> 32);
#endif
	return (u32)val;
}
#endif /* _LINUX_HASH_H */
