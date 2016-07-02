#ifndef __LINUX_SPINLOCK_H
#define __LINUX_SPINLOCK_H

/*
 * include/linux/spinlock.h - generic spinlock/rwlock declarations
 *
 * here's the role of the various spinlock/rwlock related include files:
 *
 * on SMP builds:
 *
 *  asm/spinlock_types.h: contains the arch_spinlock_t/arch_rwlock_t and the
 *                        initializers
 *
 *  linux/spinlock_types.h:
 *                        defines the generic type and initializers
 *
 *  asm/spinlock.h:       contains the arch_spin_*()/etc. lowlevel
 *                        implementations, mostly inline assembly code
 *
 *   (also included on UP-debug builds:)
 *
 *  linux/spinlock_api_smp.h:
 *                        contains the prototypes for the _spin_*() APIs.
 *
 *  linux/spinlock.h:     builds the final spin_*() APIs.
 *
 * on UP builds:
 *
 *  linux/spinlock_type_up.h:
 *                        contains the generic, simplified UP spinlock type.
 *                        (which is an empty structure on non-debug builds)
 *
 *  linux/spinlock_types.h:
 *                        defines the generic type and initializers
 *
 *  linux/spinlock_up.h:
 *                        contains the arch_spin_*()/etc. version of UP
 *                        builds. (which are NOPs on non-debug, non-preempt
 *                        builds)
 *
 *   (included on UP-non-debug builds:)
 *
 *  linux/spinlock_api_up.h:
 *                        builds the _spin_*() APIs.
 *
 *  linux/spinlock.h:     builds the final spin_*() APIs.
 */

#include <linux/typecheck.h>
#include <linux/preempt.h>
#include <linux/linkage.h>
#include <linux/compiler.h>
#include <linux/irqflags.h>
#include <linux/thread_info.h>
#include <linux/kernel.h>
#include <linux/stringify.h>
#include <linux/bottom_half.h>
#include <asm/barrier.h>


/*
 * Must define these before including other files, inline functions need them
 */
#define LOCK_SECTION_NAME ".text..lock."KBUILD_BASENAME

#define LOCK_SECTION_START(extra)               \
        ".subsection 1\n\t"                     \
        extra                                   \
        ".ifndef " LOCK_SECTION_NAME "\n\t"     \
        LOCK_SECTION_NAME ":\n\t"               \
        ".endif\n"

#define LOCK_SECTION_END                        \
        ".previous\n\t"

// ARM10C 20140405
#define __lockfunc __attribute__((section(".spinlock.text")))

/*
 * Pull the arch_spinlock_t and arch_rwlock_t definitions:
 */
#include <linux/spinlock_types.h>

/*
 * Pull the arch_spin*() functions/declarations (UP-nondebug doesn't need them):
 */
#ifdef CONFIG_SMP
# include <asm/spinlock.h>
#else
# include <linux/spinlock_up.h>
#endif

// ARM10C 20130914
#ifdef CONFIG_DEBUG_SPINLOCK // CONFIG_DEBUG_SPINLOCK=y
  extern void __raw_spin_lock_init(raw_spinlock_t *lock, const char *name,
				   struct lock_class_key *key);
// ARM10C 20140830
// &rt_b->rt_runtime_lock: &(&def_rt_bandwidth)->rt_runtime_lock
// ARM10C 20150620
// &q->lock: [pcp0] &(&call_single_queue)->lock
// ARM10C 20150718
// &(_lock)->rlock: &(&(&(&(&(kmem_cache#25-oX)->port)->buf)->lock)->wait_lock)->rlock
// ARM10C 20150919
// &fbc->lock: &(&vm_committed_as)->lock
// ARM10C 20151031
// &bdi->wb_lock: &(&sysfs_backing_dev_info)->wb_lock
// ARM10C 20151031
// &pl->lock: &(&(&sysfs_backing_dev_info)->completions)->lock
// ARM10C 20151114
// &sem->wait_lock: &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_lock
// ARM10C 20151205
// &inode->i_lock: (&(kmem_cache#4-oX)->i_lock)->rlock
# define raw_spin_lock_init(lock)				\
do {								\
	static struct lock_class_key __key;	/* struct lock_class_key { }; */	\
								\
	__raw_spin_lock_init((lock), #lock, &__key);		\
} while (0)

#else
# define raw_spin_lock_init(lock)				\
	do { *(lock) = __RAW_SPIN_LOCK_UNLOCKED(lock); } while (0)
#endif

// ARM10C 20140315
// raw_spin_is_locked : 1
// &lock->rlock: &(&(&cpu_add_remove_lock)->wait_lock)->rlock
//
// raw_spin_is_locked(&(&(&cpu_add_remove_lock)->wait_lock)->rlock):
// arch_spin_is_locked(&(&(&(&cpu_add_remove_lock)->wait_lock)->rlock)->raw_lock)
//
// ARM10C 20151219
// &(&(kmem_cache#5-oX)->d_lock)->rlock
#define raw_spin_is_locked(lock)	arch_spin_is_locked(&(lock)->raw_lock)

#ifdef CONFIG_GENERIC_LOCKBREAK
#define raw_spin_is_contended(lock) ((lock)->break_lock)
#else

#ifdef arch_spin_is_contended
#define raw_spin_is_contended(lock)	arch_spin_is_contended(&(lock)->raw_lock)
#else
#define raw_spin_is_contended(lock)	(((void)(lock), 0))
#endif /*arch_spin_is_contended*/
#endif

/*
 * Despite its name it doesn't necessarily has to be a full barrier.
 * It should only guarantee that a STORE before the critical section
 * can not be reordered with a LOAD inside this section.
 * spin_lock() is the one-way barrier, this LOAD can not escape out
 * of the region. So the default implementation simply ensures that
 * a STORE can not move into the critical section, smp_wmb() should
 * serialize it with another STORE done by spin_lock().
 */
#ifndef smp_mb__before_spinlock
#define smp_mb__before_spinlock()	smp_wmb()
#endif

/**
 * raw_spin_unlock_wait - wait until the spinlock gets unlocked
 * @lock: the spinlock in question.
 */
#define raw_spin_unlock_wait(lock)	arch_spin_unlock_wait(&(lock)->raw_lock)

#ifdef CONFIG_DEBUG_SPINLOCK // CONFIG_DEBUG_SPINLOCK=y
// ARM10C 20140405
// ARM10C 20160514
 extern void do_raw_spin_lock(raw_spinlock_t *lock) __acquires(lock);
#define do_raw_spin_lock_flags(lock, flags) do_raw_spin_lock(lock)
 extern int do_raw_spin_trylock(raw_spinlock_t *lock);	// ARM10C this 
// ARM10C 20140412
 extern void do_raw_spin_unlock(raw_spinlock_t *lock) __releases(lock);
#else
static inline void do_raw_spin_lock(raw_spinlock_t *lock) __acquires(lock)
{
	__acquire(lock);
	arch_spin_lock(&lock->raw_lock);
}

static inline void
do_raw_spin_lock_flags(raw_spinlock_t *lock, unsigned long *flags) __acquires(lock)
{
	__acquire(lock);
	arch_spin_lock_flags(&lock->raw_lock, *flags);
}

static inline int do_raw_spin_trylock(raw_spinlock_t *lock)
{
	return arch_spin_trylock(&(lock)->raw_lock);
}

static inline void do_raw_spin_unlock(raw_spinlock_t *lock) __releases(lock)
{
	arch_spin_unlock(&lock->raw_lock);
	__release(lock);
}
#endif

/*
 * Define the various spin_lock methods.  Note we define these
 * regardless of whether CONFIG_SMP or CONFIG_PREEMPT are set. The
 * various methods are defined as nops in the case they are not
 * required.
 */
// ARM10C 20130907 _raw_spin_trylock(lock) = 1 
#define raw_spin_trylock(lock)	__cond_lock(lock, _raw_spin_trylock(lock))

// ARM10C 20140405
// ARM10C 20140517
// &lock->rlock: &(&contig_page_data->node_zones[0].lock)->rlock
// ARM10C 20150725
// &logbuf_lock
#define raw_spin_lock(lock)	_raw_spin_lock(lock)

#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define raw_spin_lock_nested(lock, subclass) \
	_raw_spin_lock_nested(lock, subclass)

# define raw_spin_lock_nest_lock(lock, nest_lock)			\
	 do {								\
		 typecheck(struct lockdep_map *, &(nest_lock)->dep_map);\
		 _raw_spin_lock_nest_lock(lock, &(nest_lock)->dep_map);	\
	 } while (0)
#else
# define raw_spin_lock_nested(lock, subclass)		_raw_spin_lock(lock)
# define raw_spin_lock_nest_lock(lock, nest_lock)	_raw_spin_lock(lock)
#endif

#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK) // CONFIG_SMP=y, CONFIG_DEBUG_SPINLOCK=y

// ARM10C 20150103
// ARM10C 20150328
// ARM10C 20150418
// &desc->lock: (kmem_cache#28-oX (irq 152))->lock
// ARM10C 20150606
// &base->cpu_base->lock: (&hrtimer_bases->clock_base[0])->cpu_base->lock, flags: &flags
// ARM10C 20150704
// &sem->lock: &(&console_sem)->lock
// ARM10C 20150725
// &logbuf_lock, flags
// ARM10C 20151121
// &sem->wait_lock: (&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_lock, flags
// ARM10C 20151121
// &sem->wait_lock: &(&shrinker_rwsem)->wait_lock, flags
// ARM10C 20160409
// &q->lock: &(&running_helpers_waitq)->lock, flags
// ARM10C 20160611
// &devtree_lock, flags
#define raw_spin_lock_irqsave(lock, flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = _raw_spin_lock_irqsave(lock);	\
	} while (0)

#ifdef CONFIG_DEBUG_LOCK_ALLOC
#define raw_spin_lock_irqsave_nested(lock, flags, subclass)		\
	do {								\
		typecheck(unsigned long, flags);			\
		flags = _raw_spin_lock_irqsave_nested(lock, subclass);	\
	} while (0)
#else
#define raw_spin_lock_irqsave_nested(lock, flags, subclass)		\
	do {								\
		typecheck(unsigned long, flags);			\
		flags = _raw_spin_lock_irqsave(lock);			\
	} while (0)
#endif

#else

#define raw_spin_lock_irqsave(lock, flags)		\
	do {						\
		typecheck(unsigned long, flags);	\
		_raw_spin_lock_irqsave(lock, flags);	\
	} while (0)

#define raw_spin_lock_irqsave_nested(lock, flags, subclass)	\
	raw_spin_lock_irqsave(lock, flags)

#endif

// ARM10C 20160514
// &lock->rlock: &(&proc_inum_lock)->rlock
#define raw_spin_lock_irq(lock)		_raw_spin_lock_irq(lock)
#define raw_spin_lock_bh(lock)		_raw_spin_lock_bh(lock)
// ARM10C 20140412
// ARM10C 20150725
// &logbuf_lock
#define raw_spin_unlock(lock)		_raw_spin_unlock(lock)
// ARM10C 20160514
// &lock->rlock: &(&proc_inum_lock)->rlock
#define raw_spin_unlock_irq(lock)	_raw_spin_unlock_irq(lock)

// ARM10C 20150103
// ARM10C 20150516
// ARM10C 20150620
// ARM10C 20160611
// &devtree_lock, flags
#define raw_spin_unlock_irqrestore(lock, flags)		\
	do {							\
		typecheck(unsigned long, flags);		\
		_raw_spin_unlock_irqrestore(lock, flags);	\
	} while (0)
#define raw_spin_unlock_bh(lock)	_raw_spin_unlock_bh(lock)

#define raw_spin_trylock_bh(lock) \
	__cond_lock(lock, _raw_spin_trylock_bh(lock))

#define raw_spin_trylock_irq(lock) \
({ \
	local_irq_disable(); \
	raw_spin_trylock(lock) ? \
	1 : ({ local_irq_enable(); 0;  }); \
})

#define raw_spin_trylock_irqsave(lock, flags) \
({ \
	local_irq_save(flags); \
	raw_spin_trylock(lock) ? \
	1 : ({ local_irq_restore(flags); 0; }); \
})

/**
 * raw_spin_can_lock - would raw_spin_trylock() succeed?
 * @lock: the spinlock in question.
 */
#define raw_spin_can_lock(lock)	(!raw_spin_is_locked(lock))

/* Include rwlock functions */
#include <linux/rwlock.h>

/*
 * Pull the _spin_*()/_read_*()/_write_*() functions/declarations:
 */
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
# include <linux/spinlock_api_smp.h>
#else
# include <linux/spinlock_api_up.h>
#endif

/*
 * Map the spin_lock functions to the raw variants for PREEMPT_RT=n
 */

// ARM10C 20130914
// ARM10C 20150718
// ARM10C 20151031
// DESC: 이 함수는 inline함수를 사용해서 인자가 spinlock_t*인지
//       컴파일 타임에 확인하는 트릭을 사용하고 있다.
// ARM10C 20151205
// &inode->i_lock: &(kmem_cache#4-oX)->i_lock
// ARM10C 20160409
static inline raw_spinlock_t *spinlock_check(spinlock_t *lock)
{
	return &lock->rlock;
}

// ARM10C 20130914
// ARM10C 20140809
// ARM10C 20150103
// ARM10C 20150718
// &lock->wait_lock: &(&(&(&(kmem_cache#25-oX)->port)->buf)->lock)->wait_lock
// ARM10C 20150718
// &port->lock: &(&(kmem_cache#25-oX)->port)->lock
// ARM10C 20150808
// &cgrp->event_list_lock: &(&(&cgroup_dummy_root)->top_cgroup)->event_list_lock
// ARM10C 20150808
// &xattrs->lock: &(&(&(&cgroup_dummy_root)->top_cgroup)->xattrs)->lock
// ARM10C 20150808
// &idp->lock: &(&(&cgroup_dummy_root)->cgroup_idr)->lock
// ARM10C 20151031
// &bdi->wb_lock: &(&sysfs_backing_dev_info)->wb_lock
// ARM10C 20151031
// &wb->list_lock: &(&(&sysfs_backing_dev_info)->wb)->list_lock
// ARM10C 20151114
// &lru->node[0].lock: (&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].lock
// ARM10C 20151205
// &inode->i_lock: &(kmem_cache#4-oX)->i_lock
// ARM10C 20151219
// &dentry->d_lock: &(kmem_cache#5-oX)->d_lock
// ARM10C 20160319
// &info->lock: &(kmem_cache#4-oX (struct shmem_inode_info))->lock
// ARM10C 20160423
// &sbinfo->stat_lock: &(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock
// ARM10C 20160604
// &ent->pde_unload_lock: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock
#define spin_lock_init(_lock)				\
do {							\
	spinlock_check(_lock);				\
	raw_spin_lock_init(&(_lock)->rlock);		\
} while (0)

// ARM10C 20140405
// ARM10C 20140517
// &zone->lock: &contig_page_data->node_zones[0].lock
// ARM10C 20140705
// ARM10C 20150718
// ARM10C 20150919
// &percpu_counters_lock
// ARM10C 20151114
// &kobj_ns_type_lock
// ARM10C 20151114
// &sb_lock
// ARM10C 20151114
// &unnamed_dev_lock
// ARM10C 20151128
// &inode_hash_lock
// ARM10C 20151205
// &inode->i_lock: &(kmem_cache#4-oX)->i_lock
// ARM10C 20151212
// &inode->i_lock: &(kmem_cache#4-oX)->i_lock
// ARM10C 20151219
// &inode->i_lock: &(kmem_cache#4-oX)->i_lock
// ARM10C 20151219
// &dentry->d_lock: &(kmem_cache#5-oX)->d_lock
// ARM10C 20151219
// &lockref->lock: &(&(kmem_cache#5-oX (struct dentry))->d_lockref)->lock
// ARM10C 20160109
// &sl->lock: &(&mount_lock)->lock
// ARM10C 20160116
// &sysfs_ino_lock
// ARM10C 20160319
// &unnamed_dev_lock
// ARM10C 20160319
// &inode->i_lock: &(kmem_cache#4-oX (struct inode))->i_lock
// ARM10C 20160521
// &fs->lock: &((&init_task)->fs)->lock
// ARM10C 20160521
// &fs->lock: &((&init_task)->fs)->lock
// ARM10C 20160604
// &proc_subdir_lock
// ARM10C 20160611
// &proc_subdir_lock
// ARM10C 20160702
// &sysctl_lock
static inline void spin_lock(spinlock_t *lock)
{
	// lock->rlock: (&contig_page_data->node_zones[0].lock)->rlock
	raw_spin_lock(&lock->rlock);
}

static inline void spin_lock_bh(spinlock_t *lock)
{
	raw_spin_lock_bh(&lock->rlock);
}

static inline int spin_trylock(spinlock_t *lock)
{
	return raw_spin_trylock(&lock->rlock);
}

#define spin_lock_nested(lock, subclass)			\
do {								\
	raw_spin_lock_nested(spinlock_check(lock), subclass);	\
} while (0)

#define spin_lock_nest_lock(lock, nest_lock)				\
do {									\
	raw_spin_lock_nest_lock(spinlock_check(lock), nest_lock);	\
} while (0)

// ARM10C 20160514
// &proc_inum_lock
static inline void spin_lock_irq(spinlock_t *lock)
{
	// &lock->rlock: &(&proc_inum_lock)->rlock
	raw_spin_lock_irq(&lock->rlock);
}

// ARM10C 20150711
// &base->lock: &(&boot_tvec_bases)->lock: *flags: flags
// ARM10C 20150718
// ARM10C 20151031
// &idp->lock: &(&(&mnt_id_ida)->idr)->lock, flags
// ARM10C 20151031
// &ida->idr.lock: (&mnt_id_ida)->idr.lock, flags
// ARM10C 20151031
// &idp->lock: &(&(&mnt_id_ida)->idr)->lock, flags
// ARM10C 20151107
// &ida->idr.lock: &(&mnt_id_ida)->idr.lock, flags
// ARM10C 20151114
// &ida->idr.lock: &(&unnamed_dev_ida)->idr.lock, flags
// ARM10C 20160213
// &ida->idr.lock: &(&mnt_id_ida)->idr.lock, flags
// ARM10C 20160409
// &q->lock: &(&running_helpers_waitq)->lock, flags
#define spin_lock_irqsave(lock, flags)				\
do {								\
	raw_spin_lock_irqsave(spinlock_check(lock), flags);	\
} while (0)

#define spin_lock_irqsave_nested(lock, flags, subclass)			\
do {									\
	raw_spin_lock_irqsave_nested(spinlock_check(lock), flags, subclass); \
} while (0)

// ARM10C 20140412
// ARM10C 20150919
// ARM10C 20151107
// &mnt_id_lock
// ARM10C 20151114
// &kobj_ns_type_lock
// ARM10C 20151114
// &sb_lock
// ARM10C 20151114
// &unnamed_dev_lock
// ARM10C 20151212
// &inode->i_lock: &(kmem_cache#4-oX)->i_lock
// ARM10C 20151219
// &inode->i_lock: &(kmem_cache#4-oX)->i_lock
// ARM10C 20151219
// &lockref->lock: &(&(kmem_cache#5-oX (struct dentry))->d_lockref)->lock
// ARM10C 20160109
// &sl->lock: &(&mount_lock)->lock
// ARM10C 20160116
// &sysfs_ino_lock
// ARM10C 20160319
// &inode->i_lock: &(kmem_cache#4-oX (struct inode))->i_lock
// ARM10C 20160521
// &fs->lock: &((&init_task)->fs)->lock
// ARM10C 20160521
// &fs->lock: &((&init_task)->fs)->lock
// ARM10C 20160604
// &proc_subdir_lock
// ARM10C 20160611
// &proc_subdir_lock
// ARM10C 20160702
// &sysctl_lock
static inline void spin_unlock(spinlock_t *lock)
{
	raw_spin_unlock(&lock->rlock);
}

static inline void spin_unlock_bh(spinlock_t *lock)
{
	raw_spin_unlock_bh(&lock->rlock);
}

// ARM10C 20160514
// &proc_inum_lock
static inline void spin_unlock_irq(spinlock_t *lock)
{
	// &lock->rlock: &(&proc_inum_lock)->rlock
	raw_spin_unlock_irq(&lock->rlock);
}

// ARM10C 20151114
// &ida->idr.lock: &(&unnamed_dev_ida)->idr.lock
// ARM10C 20160213
// &ida->idr.lock: &(&mnt_id_ida)->idr.lock, flags
// ARM10C 20160409
// &q->lock: &(&running_helpers_waitq)->lock, flags
static inline void spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
	raw_spin_unlock_irqrestore(&lock->rlock, flags);
}

static inline int spin_trylock_bh(spinlock_t *lock)
{
	return raw_spin_trylock_bh(&lock->rlock);
}

static inline int spin_trylock_irq(spinlock_t *lock)
{
	return raw_spin_trylock_irq(&lock->rlock);
}

#define spin_trylock_irqsave(lock, flags)			\
({								\
	raw_spin_trylock_irqsave(spinlock_check(lock), flags); \
})

static inline void spin_unlock_wait(spinlock_t *lock)
{
	raw_spin_unlock_wait(&lock->rlock);
}

// ARM10C 20140315
// spin_is_locked(&(&cpu_add_remove_lock)->wait_lock)
static inline int spin_is_locked(spinlock_t *lock)
{
	// lock->rlock: (&(&cpu_add_remove_lock)->wait_lock)->rlock
	// raw_spin_is_locked(&(&(&cpu_add_remove_lock)->wait_lock)->rlock): 1
	return raw_spin_is_locked(&lock->rlock);
}

static inline int spin_is_contended(spinlock_t *lock)
{
	return raw_spin_is_contended(&lock->rlock);
}

static inline int spin_can_lock(spinlock_t *lock)
{
	return raw_spin_can_lock(&lock->rlock);
}

// ARM10C 20151219
// &dentry->d_lock: &(kmem_cache#5-oX)->d_lock
#define assert_spin_locked(lock)	assert_raw_spin_locked(&(lock)->rlock)

/*
 * Pull the atomic_t declaration:
 * (asm-mips/atomic.h needs above definitions)
 */
#include <linux/atomic.h>
/**
 * atomic_dec_and_lock - lock on reaching reference count zero
 * @atomic: the atomic counter
 * @lock: the spinlock in question
 *
 * Decrements @atomic by 1.  If the result is 0, returns true and locks
 * @lock.  Returns false for all other cases.
 */
extern int _atomic_dec_and_lock(atomic_t *atomic, spinlock_t *lock);
#define atomic_dec_and_lock(atomic, lock) \
		__cond_lock(lock, _atomic_dec_and_lock(atomic, lock))

#endif /* __LINUX_SPINLOCK_H */
