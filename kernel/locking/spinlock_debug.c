/*
 * Copyright 2005, Red Hat, Inc., Ingo Molnar
 * Released under the General Public License (GPL).
 *
 * This file contains the spinlock/rwlock implementations for
 * DEBUG_SPINLOCK.
 */

#include <linux/spinlock.h>
#include <linux/nmi.h>
#include <linux/interrupt.h>
#include <linux/debug_locks.h>
#include <linux/delay.h>
#include <linux/export.h>

// ARM10C 20150620
// &q->lock: [pcp0] &(&call_single_queue)->lock
// ARM10C 20150718
// &(&(&(&(&(kmem_cache#25-oX)->port)->buf)->lock)->wait_lock)->rlock, "&(_lock)->rlock", &__key
// ARM10C 20150919
// &fbc->lock: &(&vm_committed_as)->lock, "&fbc->lock", &__key
// ARM10C 20151114
// &sem->wait_lock: &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_lock, "&sem->wait_lock", &__key
// ARM10C 20151205
// &inode->i_lock: (&(kmem_cache#4-oX)->i_lock)->rlock, "(&inode->i_lock)->rlock, &__key
void __raw_spin_lock_init(raw_spinlock_t *lock, const char *name,
			  struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC // CONFIG_DEBUG_LOCK_ALLOC=n
	/*
	 * Make sure we are not reinitializing a held lock:
	 */
	debug_check_no_locks_freed((void *)lock, sizeof(*lock));
	lockdep_init_map(&lock->dep_map, name, key, 0);
#endif
	// lock->raw_lock: [pcp0] (&(&call_single_queue)->lock)->raw_lock,
	// __ARCH_SPIN_LOCK_UNLOCKED: { { 0 } }
	// lock->raw_lock: (&(&(&(&(&(kmem_cache#25-oX)->port)->buf)->lock)->wait_lock)->rlock)->raw_lock,
	// __ARCH_SPIN_LOCK_UNLOCKED: { { 0 } }
	lock->raw_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	// lock->raw_lock: [pcp0] (&(&call_single_queue)->lock)->raw_lock: { { 0 } }
	// lock->raw_lock: (&(&(&(&(&(kmem_cache#25-oX)->port)->buf)->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }

	// lock->magic: [pcp0] (&(&call_single_queue)->lock)->magic, SPINLOCK_MAGIC: 0xdead4ead
	// lock->magic: (&(&(&(&(&(kmem_cache#25-oX)->port)->buf)->lock)->wait_lock)->rlock)->magic, SPINLOCK_MAGIC: 0xdead4ead
	lock->magic = SPINLOCK_MAGIC;
	// lock->magic: [pcp0] (&(&call_single_queue)->lock)->magic: 0xdead4ead
	// lock->magic: (&(&(&(&(&(kmem_cache#25-oX)->port)->buf)->lock)->wait_lock)->rlock)->magic: 0xdead4ead

	// lock->owner: [pcp0] (&(&call_single_queue)->lock)->owner, SPINLOCK_OWNER_INIT: 0xffffffff
	// lock->owner: (&(&(&(&(&(kmem_cache#25-oX)->port)->buf)->lock)->wait_lock)->rlock)->owner, SPINLOCK_OWNER_INIT: 0xffffffff
	lock->owner = SPINLOCK_OWNER_INIT;
	// lock->owner: [pcp0] (&(&call_single_queue)->lock)->owner: 0xffffffff
	// lock->owner: (&(&(&(&(&(kmem_cache#25-oX)->port)->buf)->lock)->wait_lock)->rlock)->owner: 0xffffffff

	// lock->owner_cpu: [pcp0] (&(&call_single_queue)->lock)->owner_cpu
	// lock->owner_cpu: (&(&(&(&(&(kmem_cache#25-oX)->port)->buf)->lock)->wait_lock)->rlock)->owner_cpu
	lock->owner_cpu = -1;
	// lock->owner_cpu: [pcp0] (&(&call_single_queue)->lock)->owner_cpu: 0xffffffff
	// lock->owner_cpu: (&(&(&(&(&(kmem_cache#25-oX)->port)->buf)->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
}

EXPORT_SYMBOL(__raw_spin_lock_init);

void __rwlock_init(rwlock_t *lock, const char *name,
		   struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	/*
	 * Make sure we are not reinitializing a held lock:
	 */
	debug_check_no_locks_freed((void *)lock, sizeof(*lock));
	lockdep_init_map(&lock->dep_map, name, key, 0);
#endif
	lock->raw_lock = (arch_rwlock_t) __ARCH_RW_LOCK_UNLOCKED;
	lock->magic = RWLOCK_MAGIC;
	lock->owner = SPINLOCK_OWNER_INIT;
	lock->owner_cpu = -1;
}

EXPORT_SYMBOL(__rwlock_init);

static void spin_dump(raw_spinlock_t *lock, const char *msg)
{
	struct task_struct *owner = NULL;

	if (lock->owner && lock->owner != SPINLOCK_OWNER_INIT)
		owner = lock->owner;
	printk(KERN_EMERG "BUG: spinlock %s on CPU#%d, %s/%d\n",
		msg, raw_smp_processor_id(),
		current->comm, task_pid_nr(current));
	printk(KERN_EMERG " lock: %pS, .magic: %08x, .owner: %s/%d, "
			".owner_cpu: %d\n",
		lock, lock->magic,
		owner ? owner->comm : "<none>",
		owner ? task_pid_nr(owner) : -1,
		lock->owner_cpu);
	dump_stack();
}

static void spin_bug(raw_spinlock_t *lock, const char *msg)
{
	if (!debug_locks_off())
		return;

	spin_dump(lock, msg);
}

#define SPIN_BUG_ON(cond, lock, msg) if (unlikely(cond)) spin_bug(lock, msg)

// ARM10C 20140405
// ARM10C 20140517
static inline void
debug_spin_lock_before(raw_spinlock_t *lock)
{
	SPIN_BUG_ON(lock->magic != SPINLOCK_MAGIC, lock, "bad magic");
	SPIN_BUG_ON(lock->owner == current, lock, "recursion");
	SPIN_BUG_ON(lock->owner_cpu == raw_smp_processor_id(),
							lock, "cpu recursion");
}

// ARM10C 20140405
// ARM10C 20140517
static inline void debug_spin_lock_after(raw_spinlock_t *lock)
{
	lock->owner_cpu = raw_smp_processor_id();
	lock->owner = current;
}

// ARM10C 20140412
static inline void debug_spin_unlock(raw_spinlock_t *lock)
{
	SPIN_BUG_ON(lock->magic != SPINLOCK_MAGIC, lock, "bad magic");
	SPIN_BUG_ON(!raw_spin_is_locked(lock), lock, "already unlocked");
	SPIN_BUG_ON(lock->owner != current, lock, "wrong owner");
	SPIN_BUG_ON(lock->owner_cpu != raw_smp_processor_id(),
							lock, "wrong CPU");
	lock->owner = SPINLOCK_OWNER_INIT;
	lock->owner_cpu = -1;
}

static void __spin_lock_debug(raw_spinlock_t *lock)
{
	u64 i;
	u64 loops = loops_per_jiffy * HZ;

	for (i = 0; i < loops; i++) {
		if (arch_spin_trylock(&lock->raw_lock))
			return;
		__delay(1);
	}
	/* lockup suspected: */
	spin_dump(lock, "lockup suspected");
#ifdef CONFIG_SMP
	trigger_all_cpu_backtrace();
#endif

	/*
	 * The trylock above was causing a livelock.  Give the lower level arch
	 * specific lock code a chance to acquire the lock. We have already
	 * printed a warning/backtrace at this point. The non-debug arch
	 * specific code might actually succeed in acquiring the lock.  If it is
	 * not successful, the end-result is the same - there is no forward
	 * progress.
	 */
	arch_spin_lock(&lock->raw_lock);
}

// ARM10C 20140405
// ARM10C 20140517
// &lock->rlock: &(&contig_page_data->node_zones[0].lock)->rlock
// ARM10C 20160514
// &(&proc_inum_lock)->rlock
void do_raw_spin_lock(raw_spinlock_t *lock)
{
	debug_spin_lock_before(lock);
	// &lock->raw_lock: (&(&contig_page_data->node_zones[0].lock)->rlock)->raw_lock
	if (unlikely(!arch_spin_trylock(&lock->raw_lock)))
		__spin_lock_debug(lock);
	debug_spin_lock_after(lock);
}

// ARM10C 20130831
int do_raw_spin_trylock(raw_spinlock_t *lock)
{
	int ret = arch_spin_trylock(&lock->raw_lock);

	if (ret)
		debug_spin_lock_after(lock);
#ifndef CONFIG_SMP  // ARM10C 실행안함 
	/*
	 * Must not happen on UP:
	 */
	SPIN_BUG_ON(!ret, lock, "trylock failure on UP");
#endif
	return ret;
}

// ARM10C 20140412
void do_raw_spin_unlock(raw_spinlock_t *lock)
{
	debug_spin_unlock(lock);
	arch_spin_unlock(&lock->raw_lock);
}

// ARM10C 20140125
static void rwlock_bug(rwlock_t *lock, const char *msg)
{
	if (!debug_locks_off())
		return;

	printk(KERN_EMERG "BUG: rwlock %s on CPU#%d, %s/%d, %p\n",
		msg, raw_smp_processor_id(), current->comm,
		task_pid_nr(current), lock);
	dump_stack();
}

// ARM10C 20140125
// ARM10C 20160326
// ARM10C 20160402
#define RWLOCK_BUG_ON(cond, lock, msg) if (unlikely(cond)) rwlock_bug(lock, msg)

#if 0		/* __write_lock_debug() can lock up - maybe this can too? */
static void __read_lock_debug(rwlock_t *lock)
{
	u64 i;
	u64 loops = loops_per_jiffy * HZ;
	int print_once = 1;

	for (;;) {
		for (i = 0; i < loops; i++) {
			if (arch_read_trylock(&lock->raw_lock))
				return;
			__delay(1);
		}
		/* lockup suspected: */
		if (print_once) {
			print_once = 0;
			printk(KERN_EMERG "BUG: read-lock lockup on CPU#%d, "
					"%s/%d, %p\n",
				raw_smp_processor_id(), current->comm,
				current->pid, lock);
			dump_stack();
		}
	}
}
#endif

// ARM10C 20160326
// &file_systems_lock
void do_raw_read_lock(rwlock_t *lock)
{
	// lock->magic: (&file_systems_lock)->magic: 0xdeaf1eed, RWLOCK_MAGIC: 0xdeaf1eed, lock: &file_systems_lock
	RWLOCK_BUG_ON(lock->magic != RWLOCK_MAGIC, lock, "bad magic");

	// &lock->raw_lock: &(&file_systems_lock)->raw_lock
	arch_read_lock(&lock->raw_lock);

	// arch_read_lock 에서 한일:
	// &(&(&file_systems_lock)->raw_lock)->lock 의 값을 미리 cache에 가져옴
	// &(&(&file_systems_lock)->raw_lock)->lock 의 값을 1을 더해줌
	// 공유자원을 다른 cpu core가 사용할수 있게 해주는 옵션
}

int do_raw_read_trylock(rwlock_t *lock)
{
	int ret = arch_read_trylock(&lock->raw_lock);

#ifndef CONFIG_SMP
	/*
	 * Must not happen on UP:
	 */
	RWLOCK_BUG_ON(!ret, lock, "trylock failure on UP");
#endif
	return ret;
}

// ARM10C 20160402
// lock: &file_systems_lock
void do_raw_read_unlock(rwlock_t *lock)
{
	// lock->magic: (&file_systems_lock)->magic: 0xdeaf1eed, RWLOCK_MAGIC: 0xdeaf1eed
	// lock: &file_systems_lock
	RWLOCK_BUG_ON(lock->magic != RWLOCK_MAGIC, lock, "bad magic");

	// &lock->raw_lock: &(&file_systems_lock)->raw_lock
	arch_read_unlock(&lock->raw_lock);

	// arch_read_unlock 에서 한일:
	// &(&(&file_systems_lock)->raw_lock)->lock 의 값을 미리 cache에 가져옴
	// &(&(&file_systems_lock)->raw_lock)->lock 의 값을 1 만큼 값을 감소 시킴
	// Inner Shareable domain에 포함되어 있는 core 들의 instruction이 완료 될때 까지 기다리 겠다는 뜻.
	// 다중 프로세서 시스템 내의 모든 코어에 신호를 보낼 이벤트를 발생시킴
}

// ARM10C 20140125
static inline void debug_write_lock_before(rwlock_t *lock)
{
	// RWLOCK_MAGIC: 0xdeaf1eed
	// #define RWLOCK_BUG_ON(cond, lock, msg) if (unlikely(cond)) rwlock_bug(lock, msg)
	// if (unlikely(lock->magic != RWLOCK_MAGIC))
	//    rwlock_bug(lock, "bad magic");
	RWLOCK_BUG_ON(lock->magic != RWLOCK_MAGIC, lock, "bad magic");
	RWLOCK_BUG_ON(lock->owner == current, lock, "recursion");
	RWLOCK_BUG_ON(lock->owner_cpu == raw_smp_processor_id(),
							lock, "cpu recursion");
}

// ARM10C 20140125
static inline void debug_write_lock_after(rwlock_t *lock)
{
	// raw_smp_processor_id(): 0
	lock->owner_cpu = raw_smp_processor_id();
	// current: current_thread_info()->task
	lock->owner = current;
}

// ARM10C 20140125
static inline void debug_write_unlock(rwlock_t *lock)
{
	RWLOCK_BUG_ON(lock->magic != RWLOCK_MAGIC, lock, "bad magic");
	RWLOCK_BUG_ON(lock->owner != current, lock, "wrong owner");
	RWLOCK_BUG_ON(lock->owner_cpu != raw_smp_processor_id(),
							lock, "wrong CPU");
	// SPINLOCK_OWNER_INIT: 0xFFFFFFFF
	lock->owner = SPINLOCK_OWNER_INIT;
	lock->owner_cpu = -1;
}

#if 0		/* This can cause lockups */
static void __write_lock_debug(rwlock_t *lock)
{
	u64 i;
	u64 loops = loops_per_jiffy * HZ;
	int print_once = 1;

	for (;;) {
		for (i = 0; i < loops; i++) {
			if (arch_write_trylock(&lock->raw_lock))
				return;
			__delay(1);
		}
		/* lockup suspected: */
		if (print_once) {
			print_once = 0;
			printk(KERN_EMERG "BUG: write-lock lockup on CPU#%d, "
					"%s/%d, %p\n",
				raw_smp_processor_id(), current->comm,
				current->pid, lock);
			dump_stack();
		}
	}
}
#endif

// ARM10C 20140125
// ARM10C 20140405
// ARM10C 20151031
// &file_systems_lock
void do_raw_write_lock(rwlock_t *lock)
{
	debug_write_lock_before(lock);
	arch_write_lock(&lock->raw_lock);
	debug_write_lock_after(lock);
}

// ARM10C 20140125
int do_raw_write_trylock(rwlock_t *lock)
{
	int ret = arch_write_trylock(&lock->raw_lock);

	if (ret)
		debug_write_lock_after(lock);
#ifndef CONFIG_SMP
	/*
	 * Must not happen on UP:
	 */
	RWLOCK_BUG_ON(!ret, lock, "trylock failure on UP");
#endif
	return ret;
}

// ARM10C 20140125
void do_raw_write_unlock(rwlock_t *lock)
{
	debug_write_unlock(lock);
	arch_write_unlock(&lock->raw_lock);
}
