/*
 *  arch/arm/include/asm/atomic.h
 *
 *  Copyright (C) 1996 Russell King.
 *  Copyright (C) 2002 Deep Blue Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __ASM_ARM_ATOMIC_H
#define __ASM_ARM_ATOMIC_H

#include <linux/compiler.h>
#include <linux/prefetch.h>
#include <linux/types.h>
#include <linux/irqflags.h>
#include <asm/barrier.h>
#include <asm/cmpxchg.h>

// ARM10C 20131012
// ARM10C 20140315
// ARM10C 20140809
// ARM10C 20150808
// ARM10C 20150912
// ARM10C 20151205
// ARM10C 20160402
// ARM10C 20160409
// ARM10C 20160827
// ARM10C 20160903
// ARM10C 20160910
#define ATOMIC_INIT(i)	{ (i) }

#ifdef __KERNEL__

/*
 * On ARM, ordinary assignment (str instruction) doesn't clear the local
 * strex/ldrex monitor on some implementations. The reason we can use it for
 * atomic_set() is the clrex or dummy strex done on every exception return.
 */
// ARM10C 20140315
// atomic_read(&(&cpu_add_remove_lock)->count): (*(volatile int *)&(&(&cpu_add_remove_lock)->count)->counter)
// ARM10C 20140329
// ARM10C 20151205
// &sd->s_count: &(&sysfs_root)->s_count
// ARM10C 20160402
// &kmod_concurrent
// ARM10C 20160903
// &p->real_cred->user->processes: &(&root_user)->processes
#define atomic_read(v)	(*(volatile int *)&(v)->counter)
// ARM10C 20140118
// ARM10C 20140322
// atomic_set(&(&cpu_add_remove_lock)->count, 1): (((&(&cpu_add_remove_lock)->count)->counter) = (1))
// ARM10C 20150117
// &(&prepare_lock)->count: -1
// ARM10C 20150718
// &lock->count: &(&(&(&(kmem_cache#25-oX)->port)->buf)->lock)->count, 1
// ARM10C 20150718
// &buf->memory_used: &(&(&(kmem_cache#25-oX)->port)->buf)->memory_used, 0
// ARM10C 20150718
// &buf->priority: &(&(&(kmem_cache#25-oX)->port)->buf)->priority, 0
// ARM10C 20150808
// &init_css_set.refcount, 1
// ARM10C 20151114
// &s->s_active: &(kmem_cache#25-oX (struct super_block))->s_active, 1
// ARM10C 20151128
// &inode->i_count: &(kmem_cache#4-oX)->i_count, 1
// ARM10C 20151128
// &inode->i_writecount: &(kmem_cache#4-oX)->i_writecount, 0
// ARM10C 20151205
// &inode->i_dio_count: &(kmem_cache#4-oX)->i_dio_count, 0
// ARM10C 20160116
// &sd->s_count,: &(kmem_cache#1-oX (struct sysfs_dirent))->s_count, 1
// ARM10C 20160116
// &sd->s_active,: &(kmem_cache#1-oX (struct sysfs_dirent))->s_active, 0
// ARM10C 20160319
// &s->s_active: &(kmem_cache#25-oX (struct super_block))->s_active
// ARM10C 20160514
// &new_ns->count: (kmem_cache#30-oX (struct mnt_namespace))->count
// ARM10C 20160604
// &ent->count: &(kmem_cache#29-oX (struct proc_dir_entry))->count
// ARM10C 20160903
// &tsk->usage: &(kmem_cache#15-oX (struct task_struct))->usage, 2
// ARM10C 20160910
// &new->usage: &(kmem_cache#16-oX (struct cred))->usage, 1
#define atomic_set(v,i)	(((v)->counter) = (i))

#if __LINUX_ARM_ARCH__ >= 6

/*
 * ARMv6 UP and SMP safe atomic ops.  We use load exclusive and
 * store exclusive to ensure that these are atomic.  We may loop
 * to ensure that the update happens.
 */
// ARM10C 20140412
// i: 32, v: &contig_page_data->node_zones[ZONE_NORMAL].vm_stat[0]
// ARM10C 20160402
// kmod_concurrent.counter: 0
// ARM10C 20160409
// 1, &running_helpers
// ARM10C 20160521
// 1,, &ns->count: &(kmem_cache#30-oX (struct mnt_namespace))->count
// ARM10C 20160827
static inline void atomic_add(int i, atomic_t *v)
{
	unsigned long tmp;
	int result;

	prefetchw(&v->counter);
	__asm__ __volatile__("@ atomic_add\n"
"1:	ldrex	%0, [%3]\n"
"	add	%0, %0, %4\n"
"	strex	%1, %0, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b"
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter), "Ir" (i)
	: "cc");
}

// ARM10C 20160319
// LAST_INO_BATCH: 1024, &shared_last_ino
// ARM10C 20160730
// 1, &kref->refcount: &(&(kmem_cache#30-oX (struct kobject) (fs))->kref)->refcount
static inline int atomic_add_return(int i, atomic_t *v)
{
	unsigned long tmp;
	int result;

	smp_mb();

	__asm__ __volatile__("@ atomic_add_return\n"
"1:	ldrex	%0, [%3]\n"
"	add	%0, %0, %4\n"
"	strex	%1, %0, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b"
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter), "Ir" (i)
	: "cc");

	smp_mb();

	return result;
}

// ARM10C 20150912
// ARM10C 20160319
// v: &(kmem_cache#4-oX (struct inode))->i_sb->s_remove_count
// ARM10C 20160409
// 1, kmod_concurrent.counter: 1
static inline void atomic_sub(int i, atomic_t *v)
{
	unsigned long tmp;
	int result;

	prefetchw(&v->counter);
	__asm__ __volatile__("@ atomic_sub\n"
"1:	ldrex	%0, [%3]\n"
"	sub	%0, %0, %4\n"
"	strex	%1, %0, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b"
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter), "Ir" (i)
	: "cc");
}

// ARM10C 20140329
// 1, &page->_count
// ARM10C 20160409
// 1, &running_helpers
static inline int atomic_sub_return(int i, atomic_t *v)
{
	unsigned long tmp;
	int result;

	smp_mb();

	// i: 1, v: &page->_count
// 	__asm__ __volatile__("@ atomic_sub_return\n"
// "1:	ldrex	result, [v->counter]\n"
// "	sub	result, result, i\n"
// "	strex	tmp, result, [v->counter]\n"
// "	teq	tmp, #0\n"
// "	bne	1b"
	__asm__ __volatile__("@ atomic_sub_return\n"
"1:	ldrex	%0, [%3]\n"
"	sub	%0, %0, %4\n"
"	strex	%1, %0, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b"
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter), "Ir" (i)
	: "cc");

	smp_mb();

	return result;
}

static inline int atomic_cmpxchg(atomic_t *ptr, int old, int new)
{
	int oldval;
	unsigned long res;

	smp_mb();

	do {
		__asm__ __volatile__("@ atomic_cmpxchg\n"
		"ldrex	%1, [%3]\n"
		"mov	%0, #0\n"
		"teq	%1, %4\n"
		"strexeq %0, %5, [%3]\n"
		    : "=&r" (res), "=&r" (oldval), "+Qo" (ptr->counter)
		    : "r" (&ptr->counter), "Ir" (old), "r" (new)
		    : "cc");
	} while (res);

	smp_mb();

	return oldval;
}

#else /* ARM_ARCH_6 */

#ifdef CONFIG_SMP
#error SMP not supported on pre-ARMv6 CPUs
#endif

static inline int atomic_add_return(int i, atomic_t *v)
{
	unsigned long flags;
	int val;

	raw_local_irq_save(flags);
	val = v->counter;
	v->counter = val += i;
	raw_local_irq_restore(flags);

	return val;
}
#define atomic_add(i, v)	(void) atomic_add_return(i, v)

static inline int atomic_sub_return(int i, atomic_t *v)
{
	unsigned long flags;
	int val;

	raw_local_irq_save(flags);
	val = v->counter;
	v->counter = val -= i;
	raw_local_irq_restore(flags);

	return val;
}
#define atomic_sub(i, v)	(void) atomic_sub_return(i, v)

static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
	int ret;
	unsigned long flags;

	raw_local_irq_save(flags);
	ret = v->counter;
	if (likely(ret == old))
		v->counter = new;
	raw_local_irq_restore(flags);

	return ret;
}

#endif /* __LINUX_ARM_ARCH__ */

// ARM10C 20140315
// &lock->count: &(&cpu_add_remove_lock)->count
// atomic_xchg(&(&cpu_add_remove_lock)->count, -1):
// xchg(&((&(&cpu_add_remove_lock)->count)->counter), -1)
// ARM10C 20150117
// &lock->count: &(&prepare_lock)->count, -1
#define atomic_xchg(v, new) (xchg(&((v)->counter), new))

static inline int __atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old;

	c = atomic_read(v);
	while (c != u && (old = atomic_cmpxchg((v), c, c + a)) != c)
		c = old;
	return c;
}

// ARM10C 20151205
// &sd->s_count: &(&sysfs_root)->s_count
// ARM10C 20160123
// &sd->s_count: &(kmem_cache#1-oX (struct sysfs_dirent))->s_count: 1
// ARM10C 20160402
// kmod_concurrent.counter: 0
// ARM10C 20160409
// &running_helpers
// ARM10C 20160521
// &ns->count: &(kmem_cache#30-oX (struct mnt_namespace))->count
// ARM10C 20160910
// &gi->usage: &((kmem_cache#16-oX (struct cred))->group_info)->usage
// ARM10C 20160910
// &u->__count: &(&root_user)->__count
// ARM10C 20160910
// new->user->processes: (&root_user)->processes
// ARM10C 20160910
// &cred->usage: &(kmem_cache#16-oX (struct cred))->usage
#define atomic_inc(v)		atomic_add(1, v)
// ARM10C 20150912
// ARM10C 20160319
// v: &(kmem_cache#4-oX (struct inode))->i_sb->s_remove_count
// ARM10C 20160409
// kmod_concurrent.counter: 1
#define atomic_dec(v)		atomic_sub(1, v)

#define atomic_inc_and_test(v)	(atomic_add_return(1, v) == 0)
// ARM10C 20140329
// &page->_count: 1
// atomic_sub_return(1, &page->_count): 0
// ARM10C 20160409
// &running_helpers
#define atomic_dec_and_test(v)	(atomic_sub_return(1, v) == 0)
// ARM10C 20160730
// &kref->refcount: &(&(kmem_cache#30-oX (struct kobject) (fs))->kref)->refcount
#define atomic_inc_return(v)    (atomic_add_return(1, v))
#define atomic_dec_return(v)    (atomic_sub_return(1, v))
#define atomic_sub_and_test(i, v) (atomic_sub_return(i, v) == 0)

#define atomic_add_negative(i,v) (atomic_add_return(i, v) < 0)

#define smp_mb__before_atomic_dec()	smp_mb()
#define smp_mb__after_atomic_dec()	smp_mb()
#define smp_mb__before_atomic_inc()	smp_mb()
// ARM10C 20160409
#define smp_mb__after_atomic_inc()	smp_mb()

#ifndef CONFIG_GENERIC_ATOMIC64 // CONFIG_GENERIC_ATOMIC64=n
// ARM10C 20150919
// ARM10C 20160514
typedef struct {
	long long counter;
} atomic64_t;

// ARM10C 20160514
#define ATOMIC64_INIT(i) { (i) }

#ifdef CONFIG_ARM_LPAE
static inline long long atomic64_read(const atomic64_t *v)
{
	long long result;

	__asm__ __volatile__("@ atomic64_read\n"
"	ldrd	%0, %H0, [%1]"
	: "=&r" (result)
	: "r" (&v->counter), "Qo" (v->counter)
	);

	return result;
}

static inline void atomic64_set(atomic64_t *v, long long i)
{
	__asm__ __volatile__("@ atomic64_set\n"
"	strd	%2, %H2, [%1]"
	: "=Qo" (v->counter)
	: "r" (&v->counter), "r" (i)
	);
}
#else
static inline long long atomic64_read(const atomic64_t *v)
{
	long long result;

	__asm__ __volatile__("@ atomic64_read\n"
"	ldrexd	%0, %H0, [%1]"
	: "=&r" (result)
	: "r" (&v->counter), "Qo" (v->counter)
	);

	return result;
}

static inline void atomic64_set(atomic64_t *v, long long i)
{
	long long tmp;

	prefetchw(&v->counter);
	__asm__ __volatile__("@ atomic64_set\n"
"1:	ldrexd	%0, %H0, [%2]\n"
"	strexd	%0, %3, %H3, [%2]\n"
"	teq	%0, #0\n"
"	bne	1b"
	: "=&r" (tmp), "=Qo" (v->counter)
	: "r" (&v->counter), "r" (i)
	: "cc");
}
#endif

static inline void atomic64_add(long long i, atomic64_t *v)
{
	long long result;
	unsigned long tmp;

	prefetchw(&v->counter);
	__asm__ __volatile__("@ atomic64_add\n"
"1:	ldrexd	%0, %H0, [%3]\n"
"	adds	%Q0, %Q0, %Q4\n"
"	adc	%R0, %R0, %R4\n"
"	strexd	%1, %0, %H0, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b"
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter), "r" (i)
	: "cc");
}

// ARM10C 20160514
// 1, &mnt_ns_seq
static inline long long atomic64_add_return(long long i, atomic64_t *v)
{
	long long result;
	unsigned long tmp;

	smp_mb();

	__asm__ __volatile__("@ atomic64_add_return\n"
"1:	ldrexd	%0, %H0, [%3]\n"
"	adds	%Q0, %Q0, %Q4\n"
"	adc	%R0, %R0, %R4\n"
"	strexd	%1, %0, %H0, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b"
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter), "r" (i)
	: "cc");

	smp_mb();

	return result;
}

static inline void atomic64_sub(long long i, atomic64_t *v)
{
	long long result;
	unsigned long tmp;

	prefetchw(&v->counter);
	__asm__ __volatile__("@ atomic64_sub\n"
"1:	ldrexd	%0, %H0, [%3]\n"
"	subs	%Q0, %Q0, %Q4\n"
"	sbc	%R0, %R0, %R4\n"
"	strexd	%1, %0, %H0, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b"
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter), "r" (i)
	: "cc");
}

static inline long long atomic64_sub_return(long long i, atomic64_t *v)
{
	long long result;
	unsigned long tmp;

	smp_mb();

	__asm__ __volatile__("@ atomic64_sub_return\n"
"1:	ldrexd	%0, %H0, [%3]\n"
"	subs	%Q0, %Q0, %Q4\n"
"	sbc	%R0, %R0, %R4\n"
"	strexd	%1, %0, %H0, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b"
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter), "r" (i)
	: "cc");

	smp_mb();

	return result;
}

static inline long long atomic64_cmpxchg(atomic64_t *ptr, long long old,
					long long new)
{
	long long oldval;
	unsigned long res;

	smp_mb();

	do {
		__asm__ __volatile__("@ atomic64_cmpxchg\n"
		"ldrexd		%1, %H1, [%3]\n"
		"mov		%0, #0\n"
		"teq		%1, %4\n"
		"teqeq		%H1, %H4\n"
		"strexdeq	%0, %5, %H5, [%3]"
		: "=&r" (res), "=&r" (oldval), "+Qo" (ptr->counter)
		: "r" (&ptr->counter), "r" (old), "r" (new)
		: "cc");
	} while (res);

	smp_mb();

	return oldval;
}

static inline long long atomic64_xchg(atomic64_t *ptr, long long new)
{
	long long result;
	unsigned long tmp;

	smp_mb();

	__asm__ __volatile__("@ atomic64_xchg\n"
"1:	ldrexd	%0, %H0, [%3]\n"
"	strexd	%1, %4, %H4, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b"
	: "=&r" (result), "=&r" (tmp), "+Qo" (ptr->counter)
	: "r" (&ptr->counter), "r" (new)
	: "cc");

	smp_mb();

	return result;
}

static inline long long atomic64_dec_if_positive(atomic64_t *v)
{
	long long result;
	unsigned long tmp;

	smp_mb();

	__asm__ __volatile__("@ atomic64_dec_if_positive\n"
"1:	ldrexd	%0, %H0, [%3]\n"
"	subs	%Q0, %Q0, #1\n"
"	sbc	%R0, %R0, #0\n"
"	teq	%R0, #0\n"
"	bmi	2f\n"
"	strexd	%1, %0, %H0, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b\n"
"2:"
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter)
	: "cc");

	smp_mb();

	return result;
}

static inline int atomic64_add_unless(atomic64_t *v, long long a, long long u)
{
	long long val;
	unsigned long tmp;
	int ret = 1;

	smp_mb();

	__asm__ __volatile__("@ atomic64_add_unless\n"
"1:	ldrexd	%0, %H0, [%4]\n"
"	teq	%0, %5\n"
"	teqeq	%H0, %H5\n"
"	moveq	%1, #0\n"
"	beq	2f\n"
"	adds	%Q0, %Q0, %Q6\n"
"	adc	%R0, %R0, %R6\n"
"	strexd	%2, %0, %H0, [%4]\n"
"	teq	%2, #0\n"
"	bne	1b\n"
"2:"
	: "=&r" (val), "+r" (ret), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter), "r" (u), "r" (a)
	: "cc");

	if (ret)
		smp_mb();

	return ret;
}

#define atomic64_add_negative(a, v)	(atomic64_add_return((a), (v)) < 0)
#define atomic64_inc(v)			atomic64_add(1LL, (v))
#define atomic64_inc_return(v)		atomic64_add_return(1LL, (v))
#define atomic64_inc_and_test(v)	(atomic64_inc_return(v) == 0)
#define atomic64_sub_and_test(a, v)	(atomic64_sub_return((a), (v)) == 0)
#define atomic64_dec(v)			atomic64_sub(1LL, (v))
#define atomic64_dec_return(v)		atomic64_sub_return(1LL, (v))
#define atomic64_dec_and_test(v)	(atomic64_dec_return((v)) == 0)
#define atomic64_inc_not_zero(v)	atomic64_add_unless((v), 1LL, 0LL)

#endif /* !CONFIG_GENERIC_ATOMIC64 */
#endif
#endif
