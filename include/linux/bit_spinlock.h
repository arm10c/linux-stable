#ifndef __LINUX_BIT_SPINLOCK_H
#define __LINUX_BIT_SPINLOCK_H

#include <linux/kernel.h>
#include <linux/preempt.h>
#include <linux/atomic.h>
#include <linux/bug.h>

/*
 *  bit-based spin_lock()
 *
 * Don't use this unless you really need to: spin_lock() and spin_unlock()
 * are significantly faster.
 */
// ARM10C 20140621
// PG_locked: 0, page->flags: (MIGRATE_UNMOVABLE인 page)->flags
// ARM10C 20161126
// 0, b: hash 0xXXXXXXXX 에 맞는 list table 주소값
static inline void bit_spin_lock(int bitnum, unsigned long *addr)
{
	/*
	 * Assuming the lock is uncontended, this never enters
	 * the body of the outer loop. If it is contended, then
	 * within the inner loop a non-atomic test is used to
	 * busywait with less bus contention for a good time to
	 * attempt to acquire the lock bit.
	 */
	preempt_disable();
	// preempt count 증가 후 memory barrier 적용
	// preempt count 증가 후 memory barrier 적용

#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK) // CONFIG_SMP=y, CONFIG_DEBUG_SPINLOCK=y
	// bitnum: 0, addr: &(MIGRATE_UNMOVABLE인 page)->flags
	// test_and_set_bit_lock(0, &(MIGRATE_UNMOVABLE인 page)->flags): 0
	// bitnum: 0, addr: hash 0xXXXXXXXX 에 맞는 list table 주소값
	// test_and_set_bit_lock(0, hash 0xXXXXXXXX 에 맞는 list table 주소값): 0
	while (unlikely(test_and_set_bit_lock(bitnum, addr))) {
		preempt_enable();
		do {
			cpu_relax();
		} while (test_bit(bitnum, addr));
		preempt_disable();
	}
#endif
	// __acquire(bitlock): 0
	// __acquire(bitlock): 0
	__acquire(bitlock);
}

/*
 * Return true if it was acquired
 */
static inline int bit_spin_trylock(int bitnum, unsigned long *addr)
{
	preempt_disable();
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
	if (unlikely(test_and_set_bit_lock(bitnum, addr))) {
		preempt_enable();
		return 0;
	}
#endif
	__acquire(bitlock);
	return 1;
}

/*
 *  bit-based spin_unlock()
 */
static inline void bit_spin_unlock(int bitnum, unsigned long *addr)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	BUG_ON(!test_bit(bitnum, addr));
#endif
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
	clear_bit_unlock(bitnum, addr);
#endif
	preempt_enable();
	__release(bitlock);
}

/*
 *  bit-based spin_unlock()
 *  non-atomic version, which can be used eg. if the bit lock itself is
 *  protecting the rest of the flags in the word.
 */
// ARM10C 20140621
// PG_locked: 0, page->flags: &(MIGRATE_UNMOVABLE인 page)->flags
// ARM10C 20161126
// 0, b: hash 0xXXXXXXXX 에 맞는 list table 주소값
static inline void __bit_spin_unlock(int bitnum, unsigned long *addr)
{
#ifdef CONFIG_DEBUG_SPINLOCK // CONFIG_DEBUG_SPINLOCK=y
	// bitnum: 0, addr: &(MIGRATE_UNMOVABLE인 page)->flags
	// test_bit(0, &(MIGRATE_UNMOVABLE인 page)->flags): 1
	// bitnum: 0, addr: hash 0xXXXXXXXX 에 맞는 list table 주소값
	// test_bit(0, hash 0xXXXXXXXX 에 맞는 list table 주소값): 1
	BUG_ON(!test_bit(bitnum, addr));
#endif
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK) // CONFIG_SMP=y, CONFIG_DEBUG_SPINLOCK=y
	// bitnum: 0, addr: &(MIGRATE_UNMOVABLE인 page)->flags
	// bitnum: 0, addr: hash 0xXXXXXXXX 에 맞는 list table 주소값
	__clear_bit_unlock(bitnum, addr);

	// __clear_bit_unlock 에서 한일:
	// (MIGRATE_UNMOVABLE인 page)->flags 의 bit 0을 클리어함
	// dmb(ish)를 사용하여 공유 자원 (MIGRATE_UNMOVABLE인 page)->flags 값을 갱신

	// __clear_bit_unlock 에서 한일:
	// hash 0xXXXXXXXX 에 맞는 list table 주소값 의 bit 0을 클리어함
	// dmb(ish)를 사용하여 공유 자원 hash 0xXXXXXXXX 에 맞는 list table 주소값 값을 갱신
#endif
	preempt_enable();
	// memory barrier 적용 후 preempt count 감소 시킴
	// memory barrier 적용 후 preempt count 감소 시킴

	// __release(bitlock): 0
	// __release(bitlock): 0
	__release(bitlock);
}

/*
 * Return true if the lock is held.
 */
static inline int bit_spin_is_locked(int bitnum, unsigned long *addr)
{
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
	return test_bit(bitnum, addr);
#elif defined CONFIG_PREEMPT_COUNT
	return preempt_count();
#else
	return 1;
#endif
}

#endif /* __LINUX_BIT_SPINLOCK_H */

