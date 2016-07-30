#ifndef _ASM_GENERIC_BITOPS_NON_ATOMIC_H_
#define _ASM_GENERIC_BITOPS_NON_ATOMIC_H_

#include <asm/types.h>

/**
 * __set_bit - Set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Unlike set_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
// ARM10C 20140118
// ARM10C 20151107
// t: 0, bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap
// ARM10C 20160416
// t: 2, bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap
// ARM10C 20160730
// id: 0, p->bitmap: (kmem_cache#21-oX (struct idr_layer))->bitmap
static inline void __set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	// nr 값을 이용해 해당 비트를 1로 설정
	*p  |= mask;

}

// ARM10C 20140118
// bitidx + start_bitidx : 0, bitmap : &mem_section[0][2]->pageblock_flags
// ARM10C 20140621
static inline void __clear_bit(int nr, volatile unsigned long *addr)
{
	// mask : 0x1
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	// nr 값을 이용해서 해당 bit를 클리어
	*p &= ~mask;
}

/**
 * __change_bit - Toggle a bit in memory
 * @nr: the bit to change
 * @addr: the address to start counting from
 *
 * Unlike change_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static inline void __change_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	*p ^= mask;
}

/**
 * __test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int __test_and_set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old = *p;

	*p = old | mask;
	return (old & mask) != 0;
}

/**
 * __test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int __test_and_clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old = *p;

	*p = old & ~mask;
	return (old & mask) != 0;
}

/* WARNING: non atomic and it can be reordered! */
static inline int __test_and_change_bit(int nr,
					    volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old = *p;

	*p = old ^ mask;
	return (old & mask) != 0;
}

/**
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
// ARM10C 20140301
// test_bit(0, cpu_possible_mask->bits)
// ARM10C 20130322
// nr: 1, addr: &init_thread_union.thread_info.flags
// ARM10C 20141004
// offset: 1, node->tags[0]: (kmem_cache#20-o0 (RADIX_LSB: 0))->tags[0]
static inline int test_bit(int nr, const volatile unsigned long *addr)
{
	// nr: 0, BIT_WORD(0): 0, addr[0]: cpu_possible_mask->bits[0]: 0xF
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
	// return 1 & (0xF >> 0): 1
}

#endif /* _ASM_GENERIC_BITOPS_NON_ATOMIC_H_ */
