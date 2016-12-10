#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#if __LINUX_ARM_ARCH__ < 6
#error SMP not supported on pre-ARMv6 CPUs
#endif

#include <linux/prefetch.h>

/*
 * sev and wfe are ARMv6K extensions.  Uniprocessor ARMv6 may not have the K
 * extensions, so when running on UP, we have to patch these instructions away.
 */
#ifdef CONFIG_THUMB2_KERNEL // CONFIG_THUMB2_KERNEL=n
/*
 * For Thumb-2, special care is needed to ensure that the conditional WFE
 * instruction really does assemble to exactly 4 bytes (as required by
 * the SMP_ON_UP fixup code).   By itself "wfene" might cause the
 * assembler to insert a extra (16-bit) IT instruction, depending on the
 * presence or absence of neighbouring conditional instructions.
 *
 * To avoid this unpredictableness, an approprite IT is inserted explicitly:
 * the assembler won't change IT instructions which are explicitly present
 * in the input.
 */
#define WFE(cond)	__ALT_SMP_ASM(		\
	"it " cond "\n\t"			\
	"wfe" cond ".n",			\
						\
	"nop.w"					\
)
#else
// ARM10C 20160326
// ARM10C 20160402
// WFE("mi")
#define WFE(cond)	__ALT_SMP_ASM("wfe" cond, "nop")
#endif

// ARM10C 20160402
#define SEV		__ALT_SMP_ASM(WASM(sev), WASM(nop))

// ARM10C 20130907
// ARM10C 20140125
// ARM10C 20130322
// ARM10C 20140412
// ARM10C 20160402
static inline void dsb_sev(void)
{

	// A.R.M: A8.8.44 - Data Synchronization Barrier
	// ISHST Inner Shareable is the required shareability domain, writes are the required access type.
	// Encoded as option = 0b1010.

	dsb(ishst);

	// dsb 에서 한일:
	// Inner Shareable domain에 포함되어 있는 core 들의 instruction이 완료 될때 까지 기다리 겠다는 뜻.

	// SEV:
	// __ALT_SMP_ASM("sev", "nop"):
	// "9998:
	// "	sev "\n"
	// "	.pushsection \".alt.sev.init\", \"a\"\n"
	// "	.long	9998b\n"
	// "	" nop "\n"
	// "	.popsection\n"
	__asm__(SEV);

	// SEV 가한일:
	// 다중 프로세서 시스템 내의 모든 코어에 신호를 보낼 이벤트를 발생시킴
}

/*
 * ARMv6 ticket-based spin-locking.
 *
 * A memory barrier is required after we get a lock, and before we
 * release it, because V6 CPUs are assumed to have weakly ordered
 * memory.
 */

#define arch_spin_unlock_wait(lock) \
	do { while (arch_spin_is_locked(lock)) cpu_relax(); } while (0)

#define arch_spin_lock_flags(lock, flags) arch_spin_lock(lock)

// ARM10C 20130831
// http://lwn.net/Articles/267968/
// http://studyfoss.egloos.com/5144295 <- 필독! spin_lock 설명
// ARM10C 20140315
// TICKET_SHIFT: 16
static inline void arch_spin_lock(arch_spinlock_t *lock)
{
	unsigned long tmp;
	u32 newval; // 다음 next 값
	arch_spinlock_t lockval; // 현재 next 값

	prefetchw(&lock->slock);

// ARM10C 20130907
// 1:	ldrex	lockval, &lock->slock
// 현재 next(lockval)는 받아 놓고,
// 	add	newval, lockval, (1<<TICKET_SHIFT) // tickets.next += 1
// 다음 next(newval) 는 += 1하고 저장 한다.
// 	strex	tmp, newval, &lock->slock
// 	teq	tmp, #0\n
// 	bne	1b
	// lock->slock에서 실제 데이터를 쓸때 (next+=1) 까지 루프
	// next+=1 의 의미는 표를 받기위해 번호표 발행
	__asm__ __volatile__(
"1:	ldrex	%0, [%3]\n"
"	add	%1, %0, %4\n"
"	strex	%2, %1, [%3]\n"
"	teq	%2, #0\n"
"	bne	1b"
	: "=&r" (lockval), "=&r" (newval), "=&r" (tmp)
	: "r" (&lock->slock), "I" (1 << TICKET_SHIFT)
	: "cc");

	// 실재 lock을 걸기 위해 busylock 한다.
	// 받은 번호표의 순을 기다린다. (unlock에서 owner을 증가 시켜서)
	while (lockval.tickets.next != lockval.tickets.owner) {
		wfe(); // 이벤트대기 (irq, frq,부정확한 중단 또는 디버그 시작 요청 대기. 구현되지 않은 경우 NOP)
		// arch_spin_unlock()의 dsb_sev()가 호출될때 깨어남
		lockval.tickets.owner = ACCESS_ONCE(lock->tickets.owner);
		// local owner값 업데이트
	}

	smp_mb();
}

// ARM10C 20130831
// lock->slock : 0
// ARM10C 20140405
// ARM10C 20140517
// &lock->raw_lock: (&(&contig_page_data->node_zones[0].lock)->rlock)->raw_lock
static inline int arch_spin_trylock(arch_spinlock_t *lock)
{
	unsigned long contended, res;
	u32 slock;

	prefetchw(&lock->slock);
	do {
		// lock->slock이0 이면 unlocked
		// lock->slock이0x10000 이면 locked
		//
		//"	ldrex	slock, lock->slock\n"
		//"	subs	tmp,   slock, slock, ror #16\n"
		//위 코드의 의미
		//if( next == owner )//현재 락을 가져도 된다.
		//"	addeq	slock, slock, (1 << TICKET_SHIFT)\n"
		//"	strexeq	tmp,   slock, lock->slock"
		__asm__ __volatile__(
		"	ldrex	%0, [%3]\n"
		"	mov	%2, #0\n"
		"	subs	%1, %0, %0, ror #16\n"
		"	addeq	%0, %0, %4\n"
		"	strexeq	%2, %0, [%3]"
		: "=&r" (slock), "=&r" (contended), "=&r" (res)
		: "r" (&lock->slock), "I" (1 << TICKET_SHIFT)
		: "cc");
	} while (res);

	if (!contended) {
		smp_mb();   // ARM10C dmb()
		return 1;
	} else {
		return 0;
	}
}

// ARM10C 20130322
// ARM10C 20140412
static inline void arch_spin_unlock(arch_spinlock_t *lock)
{
	smp_mb(); // smb_mb(), dsb_sev() 중 dsb()는 owner를 보호하기위한 것
	lock->tickets.owner++;
	dsb_sev(); // 이벤트발생
}

// ARM10C 20140315
// (*(volatile struct __raw_tickets *)&((&(&(&(&cpu_add_remove_lock)->wait_lock)->rlock)->raw_lock)))
static inline int arch_spin_value_unlocked(arch_spinlock_t lock)
{
	// lock.tickets.owner: 0, lock.tickets.next: 1
	return lock.tickets.owner == lock.tickets.next;
	// return 1
}

// ARM10C 20140315
// arch_spin_is_locked(&(&(&(&cpu_add_remove_lock)->wait_lock)->rlock)->raw_lock)
// ARM10C 20151219
// &(&(kmem_cache#5-oX)->d_lock)->rlock
static inline int arch_spin_is_locked(arch_spinlock_t *lock)
{
	// lock: (&(&(&(&cpu_add_remove_lock)->wait_lock)->rlock)->raw_lock)
        // ACCESS_ONCE((&(&(&(&cpu_add_remove_lock)->wait_lock)->rlock)->raw_lock)):
	// (*(volatile struct __raw_tickets *)&((&(&(&(&cpu_add_remove_lock)->wait_lock)->rlock)->raw_lock)))
	return !arch_spin_value_unlocked(ACCESS_ONCE(*lock));
}

static inline int arch_spin_is_contended(arch_spinlock_t *lock)
{
	struct __raw_tickets tickets = ACCESS_ONCE(lock->tickets);
	return (tickets.next - tickets.owner) > 1;
}
#define arch_spin_is_contended	arch_spin_is_contended

/*
 * RWLOCKS
 *
 *
 * Write locks are easy - we just set bit 31.  When unlocking, we can
 * just write zero since the lock is exclusively held.
 */

// ARM10C 20140125
// ARM10C 20140405
// ARM10C 20151031
static inline void arch_write_lock(arch_rwlock_t *rw)
{
	unsigned long tmp;

	prefetchw(&rw->lock);
	__asm__ __volatile__(
"1:	ldrex	%0, [%1]\n"
"	teq	%0, #0\n"
	WFE("ne")
"	strexeq	%0, %2, [%1]\n"
"	teq	%0, #0\n"
"	bne	1b"
	: "=&r" (tmp)
	: "r" (&rw->lock), "r" (0x80000000)
	: "cc");

	smp_mb();
}

static inline int arch_write_trylock(arch_rwlock_t *rw)
{
	unsigned long contended, res;

	prefetchw(&rw->lock);
	do {
		__asm__ __volatile__(
		"	ldrex	%0, [%2]\n"
		"	mov	%1, #0\n"
		"	teq	%0, #0\n"
		"	strexeq	%1, %3, [%2]"
		: "=&r" (contended), "=&r" (res)
		: "r" (&rw->lock), "r" (0x80000000)
		: "cc");
	} while (res);

	if (!contended) {
		smp_mb();
		return 1;
	} else {
		return 0;
	}
}

// ARM10C 20140125
// ARM10C 20161210
// &lock->raw_lock: &(&tasklist_lock)->raw_lock
static inline void arch_write_unlock(arch_rwlock_t *rw)
{
	smp_mb();

	__asm__ __volatile__(
	"str	%1, [%0]\n"
	:
	: "r" (&rw->lock), "r" (0)
	: "cc");

	dsb_sev();
}

/* write_can_lock - would write_trylock() succeed? */
#define arch_write_can_lock(x)		(ACCESS_ONCE((x)->lock) == 0)

/*
 * Read locks are a bit more hairy:
 *  - Exclusively load the lock value.
 *  - Increment it.
 *  - Store new lock value if positive, and we still own this location.
 *    If the value is negative, we've already failed.
 *  - If we failed to store the value, we want a negative result.
 *  - If we failed, try again.
 * Unlocking is similarly hairy.  We may have multiple read locks
 * currently active.  However, we know we won't have any write
 * locks.
 */
// ARM10C 20160326
// &lock->raw_lock: &(&file_systems_lock)->raw_lock
static inline void arch_read_lock(arch_rwlock_t *rw)
{
	unsigned long tmp, tmp2;

	// &rw->lock: &(&(&file_systems_lock)->raw_lock)->lock
	prefetchw(&rw->lock);

// 2016/03/26 종료
// 2016/04/02 시작

	// prefetchw에서 한일:
	// &(&(&file_systems_lock)->raw_lock)->lock 의 값을 미리 cache에 가져옴

	// "1:  ldrex   tmp, [&rw->lock]\n"
	// "    adds    tmp, tmp, #1\n"
	// "    strexpl tmp2, tmp, [&rw->lock]\n"
	//      WFE("mi")
	// "    rsbpls   tmp, tmp2, #0\n"
	// "    bmi      1b"

	__asm__ __volatile__(
"1:	ldrex	%0, [%2]\n"
"	adds	%0, %0, #1\n"
"	strexpl	%1, %0, [%2]\n"
	WFE("mi")
"	rsbpls	%0, %1, #0\n"
"	bmi	1b"
	: "=&r" (tmp), "=&r" (tmp2)
	: "r" (&rw->lock)
	: "cc");

	smp_mb();

	// smp_mb 에서 한일:
	// 공유자원을 다른 cpu core가 사용할수 있게 해주는 옵션
}

// ARM10C 20160402
// &lock->raw_lock: &(&file_systems_lock)->raw_lock
static inline void arch_read_unlock(arch_rwlock_t *rw)
{
	unsigned long tmp, tmp2;

	smp_mb();

	// smp_mb 에서 한일:
	// 공유자원을 다른 cpu core가 사용할수 있게 해주는 옵션

	// &rw->lock: &(&(&file_systems_lock)->raw_lock)->lock
	prefetchw(&rw->lock);

	// prefetchw에서 한일:
	// &(&(&file_systems_lock)->raw_lock)->lock 의 값을 미리 cache에 가져옴

	// "1:  ldrex   tmp, [&rw->lock]\n"
	// "    sub     tmp, tmp, #1\n"
	// "    strex   tmp2, tmp, [&rw->lock]\n"
	// "    teq     tmp2, #0\n"
	// "    bne     1b"

	__asm__ __volatile__(
"1:	ldrex	%0, [%2]\n"
"	sub	%0, %0, #1\n"
"	strex	%1, %0, [%2]\n"
"	teq	%1, #0\n"
"	bne	1b"
	: "=&r" (tmp), "=&r" (tmp2)
	: "r" (&rw->lock)
	: "cc");

	// tmp: 0
	if (tmp == 0)
		dsb_sev();

		// dsb_sev 에서 한일:
		// Inner Shareable domain에 포함되어 있는 core 들의 instruction이 완료 될때 까지 기다리 겠다는 뜻.
		// 다중 프로세서 시스템 내의 모든 코어에 신호를 보낼 이벤트를 발생시킴
}

static inline int arch_read_trylock(arch_rwlock_t *rw)
{
	unsigned long contended, res;

	prefetchw(&rw->lock);
	do {
		__asm__ __volatile__(
		"	ldrex	%0, [%2]\n"
		"	mov	%1, #0\n"
		"	adds	%0, %0, #1\n"
		"	strexpl	%1, %0, [%2]"
		: "=&r" (contended), "=&r" (res)
		: "r" (&rw->lock)
		: "cc");
	} while (res);

	/* If the lock is negative, then it is already held for write. */
	if (contended < 0x80000000) {
		smp_mb();
		return 1;
	} else {
		return 0;
	}
}

/* read_can_lock - would read_trylock() succeed? */
#define arch_read_can_lock(x)		(ACCESS_ONCE((x)->lock) < 0x80000000)

#define arch_read_lock_flags(lock, flags) arch_read_lock(lock)
#define arch_write_lock_flags(lock, flags) arch_write_lock(lock)

#define arch_spin_relax(lock)	cpu_relax()
#define arch_read_relax(lock)	cpu_relax()
#define arch_write_relax(lock)	cpu_relax()

#endif /* __ASM_SPINLOCK_H */
