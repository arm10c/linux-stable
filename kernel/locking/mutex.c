/*
 * kernel/locking/mutex.c
 *
 * Mutexes: blocking mutual exclusion locks
 *
 * Started by Ingo Molnar:
 *
 *  Copyright (C) 2004, 2005, 2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 * Many thanks to Arjan van de Ven, Thomas Gleixner, Steven Rostedt and
 * David Howells for suggestions and improvements.
 *
 *  - Adaptive spinning for mutexes by Peter Zijlstra. (Ported to mainline
 *    from the -rt tree, where it was originally implemented for rtmutexes
 *    by Steven Rostedt, based on work by Gregory Haskins, Peter Morreale
 *    and Sven Dietrich.
 *
 * Also see Documentation/mutex-design.txt.
 */
#include <linux/mutex.h>
#include <linux/ww_mutex.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/debug_locks.h>

/*
 * In the DEBUG case we are using the "NULL fastpath" for mutexes,
 * which forces all calls into the slowpath:
 */
#ifdef CONFIG_DEBUG_MUTEXES // defined
// ARM10C 20140315
// 여기서 define으로 되어 mutex-debug.h를 선언해서 사용한다. 
# include "mutex-debug.h"
# include <asm-generic/mutex-null.h>
#else
# include "mutex.h"
# include <asm/mutex.h>
#endif

/*
 * A negative mutex count indicates that waiters are sleeping waiting for the
 * mutex.
 */
// ARM10C 20140315
// lock: &cpu_add_remove_lock, lock->count: (&cpu_add_remove_lock)->count
// MUTEX_SHOW_NO_WAITER(&cpu_add_remove_lock): (atomic_read(&(&cpu_add_remove_lock)->count) >= 0)
// MUTEX_SHOW_NO_WAITER(&cpu_add_remove_lock): 1
#define	MUTEX_SHOW_NO_WAITER(mutex)	(atomic_read(&(mutex)->count) >= 0)

void
__mutex_init(struct mutex *lock, const char *name, struct lock_class_key *key)
{
	atomic_set(&lock->count, 1);
	spin_lock_init(&lock->wait_lock);
	INIT_LIST_HEAD(&lock->wait_list);
	mutex_clear_owner(lock);
#ifdef CONFIG_MUTEX_SPIN_ON_OWNER
	lock->spin_mlock = NULL;
#endif

	debug_mutex_init(lock, name, key);
}

EXPORT_SYMBOL(__mutex_init);

#ifndef CONFIG_DEBUG_LOCK_ALLOC
/*
 * We split the mutex lock/unlock logic into separate fastpath and
 * slowpath functions, to reduce the register pressure on the fastpath.
 * We also put the fastpath first in the kernel image, to make sure the
 * branch is predicted by the CPU as default-untaken.
 */
static __used noinline void __sched
__mutex_lock_slowpath(atomic_t *lock_count);

/**
 * mutex_lock - acquire the mutex
 * @lock: the mutex to be acquired
 *
 * Lock the mutex exclusively for this task. If the mutex is not
 * available right now, it will sleep until it can get it.
 *
 * The mutex must later on be released by the same task that
 * acquired it. Recursive locking is not allowed. The task
 * may not exit without first unlocking the mutex. Also, kernel
 * memory where the mutex resides mutex must not be freed with
 * the mutex still locked. The mutex must first be initialized
 * (or statically defined) before it can be locked. memset()-ing
 * the mutex to 0 is not allowed.
 *
 * ( The CONFIG_DEBUG_MUTEXES .config option turns on debugging
 *   checks that will enforce the restrictions and will also do
 *   deadlock debugging. )
 *
 * This function is similar to (but not equivalent to) down().
 */
// ARM10C 20140315
// lock: &cpu_add_remove_lock
// __sched: __section__(".sched.text")
void __sched mutex_lock(struct mutex *lock)
{
	might_sleep(); // null function
	/*
	 * The locking fastpath is the 1->0 transition from
	 * 'unlocked' into 'locked' state.
	 */
	// &lock->count: &(&cpu_add_remove_lock)->count: 1
	__mutex_fastpath_lock(&lock->count, __mutex_lock_slowpath);
	// (&cpu_add_remove_lock)->count: 0, __mutex_fastpath_lock: 0이 리턴됨

	// lock: &cpu_add_remove_lock
	mutex_set_owner(lock);
	// FIXME: 20140322
	// __mutex_lock_common에서 했던것을 왜 또할까?
}

EXPORT_SYMBOL(mutex_lock);
#endif

#ifdef CONFIG_MUTEX_SPIN_ON_OWNER
/*
 * In order to avoid a stampede of mutex spinners from acquiring the mutex
 * more or less simultaneously, the spinners need to acquire a MCS lock
 * first before spinning on the owner field.
 *
 * We don't inline mspin_lock() so that perf can correctly account for the
 * time spent in this lock function.
 */
struct mspin_node {
	struct mspin_node *next ;
	int		  locked;	/* 1 if lock acquired */
};
#define	MLOCK(mutex)	((struct mspin_node **)&((mutex)->spin_mlock))

static noinline
void mspin_lock(struct mspin_node **lock, struct mspin_node *node)
{
	struct mspin_node *prev;

	/* Init node */
	node->locked = 0;
	node->next   = NULL;

	prev = xchg(lock, node);
	if (likely(prev == NULL)) {
		/* Lock acquired */
		node->locked = 1;
		return;
	}
	ACCESS_ONCE(prev->next) = node;
	smp_wmb();
	/* Wait until the lock holder passes the lock down */
	while (!ACCESS_ONCE(node->locked))
		arch_mutex_cpu_relax();
}

static void mspin_unlock(struct mspin_node **lock, struct mspin_node *node)
{
	struct mspin_node *next = ACCESS_ONCE(node->next);

	if (likely(!next)) {
		/*
		 * Release the lock by setting it to NULL
		 */
		if (cmpxchg(lock, node, NULL) == node)
			return;
		/* Wait until the next pointer is set */
		while (!(next = ACCESS_ONCE(node->next)))
			arch_mutex_cpu_relax();
	}
	ACCESS_ONCE(next->locked) = 1;
	smp_wmb();
}

/*
 * Mutex spinning code migrated from kernel/sched/core.c
 */

static inline bool owner_running(struct mutex *lock, struct task_struct *owner)
{
	if (lock->owner != owner)
		return false;

	/*
	 * Ensure we emit the owner->on_cpu, dereference _after_ checking
	 * lock->owner still matches owner, if that fails, owner might
	 * point to free()d memory, if it still matches, the rcu_read_lock()
	 * ensures the memory stays valid.
	 */
	barrier();

	return owner->on_cpu;
}

/*
 * Look out! "owner" is an entirely speculative pointer
 * access and not reliable.
 */
static noinline
int mutex_spin_on_owner(struct mutex *lock, struct task_struct *owner)
{
	rcu_read_lock();
	while (owner_running(lock, owner)) {
		if (need_resched())
			break;

		arch_mutex_cpu_relax();
	}
	rcu_read_unlock();

	/*
	 * We break out the loop above on need_resched() and when the
	 * owner changed, which is a sign for heavy contention. Return
	 * success only when lock->owner is NULL.
	 */
	return lock->owner == NULL;
}

/*
 * Initial check for entering the mutex spinning loop
 */
static inline int mutex_can_spin_on_owner(struct mutex *lock)
{
	struct task_struct *owner;
	int retval = 1;

	rcu_read_lock();
	owner = ACCESS_ONCE(lock->owner);
	if (owner)
		retval = owner->on_cpu;
	rcu_read_unlock();
	/*
	 * if lock->owner is not set, the mutex owner may have just acquired
	 * it and not set the owner yet or the mutex has been released.
	 */
	return retval;
}
#endif

static __used noinline void __sched __mutex_unlock_slowpath(atomic_t *lock_count);

/**
 * mutex_unlock - release the mutex
 * @lock: the mutex to be released
 *
 * Unlock a mutex that has been locked by this task previously.
 *
 * This function must not be used in interrupt context. Unlocking
 * of a not locked mutex is not allowed.
 *
 * This function is similar to (but not equivalent to) up().
 */
// ARM10C 20140322
// &cpu_add_remove_lock
void __sched mutex_unlock(struct mutex *lock)
{
	/*
	 * The unlocking fastpath is the 0->1 transition from 'locked'
	 * into 'unlocked' state:
	 */
#ifndef CONFIG_DEBUG_MUTEXES // CONFIG_DEBUG_MUTEXES=y
	/*
	 * When debugging is enabled we must not clear the owner before time,
	 * the slow path will always be taken, and that clears the owner field
	 * after verifying that it was indeed current.
	 */
	mutex_clear_owner(lock);
#endif
	// lock->count: (&cpu_add_remove_lock)->count: 0
	__mutex_fastpath_unlock(&lock->count, __mutex_unlock_slowpath);
}

EXPORT_SYMBOL(mutex_unlock);

/**
 * ww_mutex_unlock - release the w/w mutex
 * @lock: the mutex to be released
 *
 * Unlock a mutex that has been locked by this task previously with any of the
 * ww_mutex_lock* functions (with or without an acquire context). It is
 * forbidden to release the locks after releasing the acquire context.
 *
 * This function must not be used in interrupt context. Unlocking
 * of a unlocked mutex is not allowed.
 */
void __sched ww_mutex_unlock(struct ww_mutex *lock)
{
	/*
	 * The unlocking fastpath is the 0->1 transition from 'locked'
	 * into 'unlocked' state:
	 */
	if (lock->ctx) {
#ifdef CONFIG_DEBUG_MUTEXES
		DEBUG_LOCKS_WARN_ON(!lock->ctx->acquired);
#endif
		if (lock->ctx->acquired > 0)
			lock->ctx->acquired--;
		lock->ctx = NULL;
	}

#ifndef CONFIG_DEBUG_MUTEXES
	/*
	 * When debugging is enabled we must not clear the owner before time,
	 * the slow path will always be taken, and that clears the owner field
	 * after verifying that it was indeed current.
	 */
	mutex_clear_owner(&lock->base);
#endif
	__mutex_fastpath_unlock(&lock->base.count, __mutex_unlock_slowpath);
}
EXPORT_SYMBOL(ww_mutex_unlock);

static inline int __sched
__mutex_lock_check_stamp(struct mutex *lock, struct ww_acquire_ctx *ctx)
{
	struct ww_mutex *ww = container_of(lock, struct ww_mutex, base);
	struct ww_acquire_ctx *hold_ctx = ACCESS_ONCE(ww->ctx);

	if (!hold_ctx)
		return 0;

	if (unlikely(ctx == hold_ctx))
		return -EALREADY;

	if (ctx->stamp - hold_ctx->stamp <= LONG_MAX &&
	    (ctx->stamp != hold_ctx->stamp || ctx > hold_ctx)) {
#ifdef CONFIG_DEBUG_MUTEXES
		DEBUG_LOCKS_WARN_ON(ctx->contending_lock);
		ctx->contending_lock = ww;
#endif
		return -EDEADLK;
	}

	return 0;
}

// ARM10C 20140315
// ww: lock, ww_ctx: NULL
// Wound/Wait Mutexes: blocking mutual exclusion locks with deadlock avoidance
static __always_inline void ww_mutex_lock_acquired(struct ww_mutex *ww,
						   struct ww_acquire_ctx *ww_ctx)
{
#ifdef CONFIG_DEBUG_MUTEXES // defined
	/*
	 * If this WARN_ON triggers, you used ww_mutex_lock to acquire,
	 * but released with a normal mutex_unlock in this call.
	 *
	 * This should never happen, always use ww_mutex_unlock.
	 */
        // 140315 : ww->ctx : 
	DEBUG_LOCKS_WARN_ON(ww->ctx);

	/*
	 * Not quite done after calling ww_acquire_done() ?
	 */
	DEBUG_LOCKS_WARN_ON(ww_ctx->done_acquire);

	if (ww_ctx->contending_lock) {
		/*
		 * After -EDEADLK you tried to
		 * acquire a different ww_mutex? Bad!
		 */
		DEBUG_LOCKS_WARN_ON(ww_ctx->contending_lock != ww);

		/*
		 * You called ww_mutex_lock after receiving -EDEADLK,
		 * but 'forgot' to unlock everything else first?
		 */
		DEBUG_LOCKS_WARN_ON(ww_ctx->acquired > 0);
		ww_ctx->contending_lock = NULL;
	}

	/*
	 * Naughty, using a different class will lead to undefined behavior!
	 */
	DEBUG_LOCKS_WARN_ON(ww_ctx->ww_class != ww->ww_class);
#endif
	ww_ctx->acquired++;
}

/*
 * after acquiring lock with fastpath or when we lost out in contested
 * slowpath, set ctx and wake up any waiters so they can recheck.
 *
 * This function is never called when CONFIG_DEBUG_LOCK_ALLOC is set,
 * as the fastpath and opportunistic spinning are disabled in that case.
 */
static __always_inline void
ww_mutex_set_context_fastpath(struct ww_mutex *lock,
			       struct ww_acquire_ctx *ctx)
{
	unsigned long flags;
	struct mutex_waiter *cur;

	ww_mutex_lock_acquired(lock, ctx);

	lock->ctx = ctx;

	/*
	 * The lock->ctx update should be visible on all cores before
	 * the atomic read is done, otherwise contended waiters might be
	 * missed. The contended waiters will either see ww_ctx == NULL
	 * and keep spinning, or it will acquire wait_lock, add itself
	 * to waiter list and sleep.
	 */
	smp_mb(); /* ^^^ */

	/*
	 * Check if lock is contended, if not there is nobody to wake up
	 */
	if (likely(atomic_read(&lock->base.count) == 0))
		return;

	/*
	 * Uh oh, we raced in fastpath, wake up everyone in this case,
	 * so they can see the new lock->ctx.
	 */
	spin_lock_mutex(&lock->base.wait_lock, flags);
	list_for_each_entry(cur, &lock->base.wait_list, list) {
		debug_mutex_wake_waiter(&lock->base, cur);
		wake_up_process(cur->task);
	}
	spin_unlock_mutex(&lock->base.wait_lock, flags);
}

/*
 * Lock a mutex (possibly interruptible), slowpath:
 */
// ARM10C 20140315
// lock: &cpu_add_remove_lock, state: TASK_UNINTERRUPTIBLE(2), subsclass: 0,
// nest_lock: NULL, ip: _RET_IP_, ww_ctx: NULL
static __always_inline int __sched
__mutex_lock_common(struct mutex *lock, long state, unsigned int subclass,
		    struct lockdep_map *nest_lock, unsigned long ip,
		    struct ww_acquire_ctx *ww_ctx, const bool use_ww_ctx)
{
	// current: init_task
	struct task_struct *task = current;
	// task: init_task
	struct mutex_waiter waiter;
	unsigned long flags;
	int ret;

	preempt_disable();
	// 현재 task의 preempt count값을 증가시킨다

	// lock->dep_map: (&cpu_add_remove_lock)->dep_map, subclass: 0, 0, nest_lock: NULL, ip: _REP_IP_
	mutex_acquire_nest(&lock->dep_map, subclass, 0, nest_lock, ip);
	// mutex_acquire_nest: NULL 함수로 컴피일 do{} while 0로 의미가
	// 사라지게 되어 lock->dep_map의 맴버가 선언되지 않아도 문제되지 않는다.

#ifdef CONFIG_MUTEX_SPIN_ON_OWNER // CONFIG_MUTEX_SPIN_ON_OWNER=n
	/*
	 * Optimistic spinning.
	 *
	 * We try to spin for acquisition when we find that there are no
	 * pending waiters and the lock owner is currently running on a
	 * (different) CPU.
	 *
	 * The rationale is that if the lock owner is running, it is likely to
	 * release the lock soon.
	 *
	 * Since this needs the lock owner, and this mutex implementation
	 * doesn't track the owner atomically in the lock field, we need to
	 * track it non-atomically.
	 *
	 * We can't do this for DEBUG_MUTEXES because that relies on wait_lock
	 * to serialize everything.
	 *
	 * The mutex spinners are queued up using MCS lock so that only one
	 * spinner can compete for the mutex. However, if mutex spinning isn't
	 * going to happen, there is no point in going through the lock/unlock
	 * overhead.
	 */
	if (!mutex_can_spin_on_owner(lock))
		goto slowpath;

	for (;;) {
		struct task_struct *owner;
		struct mspin_node  node;

		if (use_ww_ctx && ww_ctx->acquired > 0) {
			struct ww_mutex *ww;

			ww = container_of(lock, struct ww_mutex, base);
			/*
			 * If ww->ctx is set the contents are undefined, only
			 * by acquiring wait_lock there is a guarantee that
			 * they are not invalid when reading.
			 *
			 * As such, when deadlock detection needs to be
			 * performed the optimistic spinning cannot be done.
			 */
			if (ACCESS_ONCE(ww->ctx))
				goto slowpath;
		}

		/*
		 * If there's an owner, wait for it to either
		 * release the lock or go to sleep.
		 */
		mspin_lock(MLOCK(lock), &node);
		owner = ACCESS_ONCE(lock->owner);
		if (owner && !mutex_spin_on_owner(lock, owner)) {
			mspin_unlock(MLOCK(lock), &node);
			goto slowpath;
		}

		if ((atomic_read(&lock->count) == 1) &&
		    (atomic_cmpxchg(&lock->count, 1, 0) == 1)) {
			lock_acquired(&lock->dep_map, ip);
			if (use_ww_ctx) {
				struct ww_mutex *ww;
				ww = container_of(lock, struct ww_mutex, base);

				ww_mutex_set_context_fastpath(ww, ww_ctx);
			}

			mutex_set_owner(lock);
			mspin_unlock(MLOCK(lock), &node);
			preempt_enable();
			return 0;
		}
		mspin_unlock(MLOCK(lock), &node);

		/*
		 * When there's no owner, we might have preempted between the
		 * owner acquiring the lock and setting the owner field. If
		 * we're an RT task that will live-lock because we won't let
		 * the owner complete.
		 */
		if (!owner && (need_resched() || rt_task(task)))
			goto slowpath;

		/*
		 * The cpu_relax() call is a compiler barrier which forces
		 * everything in this loop to be re-loaded. We don't need
		 * memory barriers as we'll eventually observe the right
		 * values at the cost of a few extra spins.
		 */
		arch_mutex_cpu_relax();
	}
slowpath:
#endif
	// &lock->wait_lock: &(&cpu_add_remove_lock)->wait_lock
	spin_lock_mutex(&lock->wait_lock, flags);
	// (&cpu_add_remove_lock)->wait_lock.rlock.raw_lock에 스핀락했고 CPSR을 flag에 저장

	/* once more, can we acquire the lock? */
	// lock: &cpu_add_remove_lock, &lock->count: &(&cpu_add_remove_lock)->count
	// MUTEX_SHOW_NO_WAITER(&cpu_add_remove_lock): 1, atomic_xchg(&(&cpu_add_remove_lock)->count, -1): 1
	if (MUTEX_SHOW_NO_WAITER(lock) && (atomic_xchg(&lock->count, 0) == 1))
		// done으로 가는 조건: count가 1일때 된다.
		// atomic_xchg에 의해서 count가 -1로 바뀌고 
		goto skip_wait;
		// done으로 간다.

	// lock: &cpu_add_remove_lock
	debug_mutex_lock_common(lock, &waiter);
	// waiter의 주소를 waiter.maigic에 설정하고, INIT_LIST_HEAD로 list 자료구조를 만듬

	// lock: &cpu_add_remove_lock, &waiter, task: init_task,
	// task_thread_info(init_task): ((struct thread_info *)(init_task)->stack)
	debug_mutex_add_waiter(lock, &waiter, task_thread_info(task));
	// current_thread_info->init_task->blocked_on: waiter
	// 현재 thread가 spin lock이 걸렸다는 것을 blocked_on으로 표현함
	// blocked_on은 dead_lock을 detection할때 사용한다.

	/* add waiting tasks to the end of the waitqueue (FIFO): */
	// &lock->wait_list: &(&cpu_add_remove_lock)->wait_list
	list_add_tail(&waiter.list, &lock->wait_list);
	// __list_add(&waiter.list, (&(&cpu_add_remove_lock)->wait_list)->prev, &(&cpu_add_remove_lock)->wait_list)

	// task: init_task
	waiter.task = task;
	// waiter.task: init_task

	lock_contended(&lock->dep_map, ip);

	for (;;) {
		/*
		 * Lets try to take the lock again - this is needed even if
		 * we get here for the first time (shortly after failing to
		 * acquire the lock), to make sure that we get a wakeup once
		 * it's unlocked. Later on, if we sleep, this is the
		 * operation that gives us the lock. We xchg it to -1, so
		 * that when we release the lock, we properly wake up the
		 * other waiters:
		 */
		if (MUTEX_SHOW_NO_WAITER(lock) &&
		    (atomic_xchg(&lock->count, -1) == 1))
			break;

		/*
		 * got a signal? (This code gets eliminated in the
		 * TASK_UNINTERRUPTIBLE case.)
		 */
		if (unlikely(signal_pending_state(state, task))) {
			ret = -EINTR;
			goto err;
		}

		if (use_ww_ctx && ww_ctx->acquired > 0) {
			ret = __mutex_lock_check_stamp(lock, ww_ctx);
			if (ret)
				goto err;
		}

		__set_task_state(task, state);

		/* didn't get the lock, go to sleep: */
		spin_unlock_mutex(&lock->wait_lock, flags);
		schedule_preempt_disabled();
		spin_lock_mutex(&lock->wait_lock, flags);
	}
	// lock: &cpu_add_remove_lock, current_thread_info(): init_thread_info	
	mutex_remove_waiter(lock, &waiter, current_thread_info());
	// &waiter->list를 초기화함 waiter->task를 NULL로 초기화함
	// init_task.blocked_on을 NULL로 초기화함

	/* set it to 0 if there are no waiters left: */
	// &lock->wait_list: &(&cpu_add_remove_lock)->wait_list
	// list_empty(&(&cpu_add_remove_lock)->wait_list): 1
	if (likely(list_empty(&lock->wait_list)))
		// lock->count: (&cpu_add_remove_lock)->count: -1
		atomic_set(&lock->count, 0);
		// (&cpu_add_remove_lock)->count: 0

	debug_mutex_free_waiter(&waiter);
	// waiter 리스트가 값이 있는지 확인하고 없다면 free시킨다.

skip_wait:
	/* got the lock - cleanup and rejoice! */
	// &lock->dep_map: &(&cpu_add_remove_lock)->dep_map, ip: _RET_IP_
	lock_acquired(&lock->dep_map, ip); // NULL function

	// lock: &cpu_add_remove_lock
	mutex_set_owner(lock);
	// (&cpu_add_remove_lock)->owner: init_task가 됨

	// ww_ctx: NULL
	// __builtin_constant_p(NULL == NULL): 0, NULL == NULL: 상수므로: 0이되어 패스
	// ARM10C 20130322
	// 3.11 커널에 추가된 이 코드는 __builtin_contant_p()에 대한 컴파일 논쟁이 있었다.
	// 자세한 공유 문서를 참조, 여기서는 if문이 실행되지 않고 패스한다.
	if (use_ww_ctx) {
		struct ww_mutex *ww = container_of(lock, struct ww_mutex, base);
		struct mutex_waiter *cur;

		/*
		 * This branch gets optimized out for the common case,
		 * and is only important for ww_mutex_lock.
		 */

		// ww: lock, ww_ctx: NULL 
		ww_mutex_lock_acquired(ww, ww_ctx);
		ww->ctx = ww_ctx;

		/*
		 * Give any possible sleeping processes the chance to wake up,
		 * so they can recheck if they have to back off.
		 */
		list_for_each_entry(cur, &lock->wait_list, list) {
			debug_mutex_wake_waiter(lock, cur);
			wake_up_process(cur->task);
		}
	}

// 2014/03/15 종료
// 2014/03/22 시작

	// lock->wait_lock: (&cpu_add_remove_lock)->wait_lock,
	// flag: spin_lock_mutex시 저장한 CPSR 값
	spin_unlock_mutex(&lock->wait_lock, flags);
	// flag에 저장된 CPSR 값을 register에 restore 하고
	// (&cpu_add_remove_lock)->wait_lock.rlock.raw_lock에 spin unlock을 함

	preempt_enable();
	// 현재 task의 preempt count값을 감소시킨다.

	return 0;

err:
	mutex_remove_waiter(lock, &waiter, task_thread_info(task));
	spin_unlock_mutex(&lock->wait_lock, flags);
	debug_mutex_free_waiter(&waiter);
	mutex_release(&lock->dep_map, 1, ip);
	preempt_enable();
	return ret;
}

#ifdef CONFIG_DEBUG_LOCK_ALLOC
void __sched
mutex_lock_nested(struct mutex *lock, unsigned int subclass)
{
	might_sleep();
	__mutex_lock_common(lock, TASK_UNINTERRUPTIBLE,
			    subclass, NULL, _RET_IP_, NULL, 0);
}

EXPORT_SYMBOL_GPL(mutex_lock_nested);

void __sched
_mutex_lock_nest_lock(struct mutex *lock, struct lockdep_map *nest)
{
	might_sleep();
	__mutex_lock_common(lock, TASK_UNINTERRUPTIBLE,
			    0, nest, _RET_IP_, NULL, 0);
}

EXPORT_SYMBOL_GPL(_mutex_lock_nest_lock);

int __sched
mutex_lock_killable_nested(struct mutex *lock, unsigned int subclass)
{
	might_sleep();
	return __mutex_lock_common(lock, TASK_KILLABLE,
				   subclass, NULL, _RET_IP_, NULL, 0);
}
EXPORT_SYMBOL_GPL(mutex_lock_killable_nested);

int __sched
mutex_lock_interruptible_nested(struct mutex *lock, unsigned int subclass)
{
	might_sleep();
	return __mutex_lock_common(lock, TASK_INTERRUPTIBLE,
				   subclass, NULL, _RET_IP_, NULL, 0);
}

EXPORT_SYMBOL_GPL(mutex_lock_interruptible_nested);

static inline int
ww_mutex_deadlock_injection(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
#ifdef CONFIG_DEBUG_WW_MUTEX_SLOWPATH
	unsigned tmp;

	if (ctx->deadlock_inject_countdown-- == 0) {
		tmp = ctx->deadlock_inject_interval;
		if (tmp > UINT_MAX/4)
			tmp = UINT_MAX;
		else
			tmp = tmp*2 + tmp + tmp/2;

		ctx->deadlock_inject_interval = tmp;
		ctx->deadlock_inject_countdown = tmp;
		ctx->contending_lock = lock;

		ww_mutex_unlock(lock);

		return -EDEADLK;
	}
#endif

	return 0;
}

int __sched
__ww_mutex_lock(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
	int ret;

	might_sleep();
	ret =  __mutex_lock_common(&lock->base, TASK_UNINTERRUPTIBLE,
				   0, &ctx->dep_map, _RET_IP_, ctx, 1);
	if (!ret && ctx->acquired > 1)
		return ww_mutex_deadlock_injection(lock, ctx);

	return ret;
}
EXPORT_SYMBOL_GPL(__ww_mutex_lock);

int __sched
__ww_mutex_lock_interruptible(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
	int ret;

	might_sleep();
	ret = __mutex_lock_common(&lock->base, TASK_INTERRUPTIBLE,
				  0, &ctx->dep_map, _RET_IP_, ctx, 1);

	if (!ret && ctx->acquired > 1)
		return ww_mutex_deadlock_injection(lock, ctx);

	return ret;
}
EXPORT_SYMBOL_GPL(__ww_mutex_lock_interruptible);

#endif

/*
 * Release the lock, slowpath:
 */
// ARM10C 20140322
// lock_count: &(&cpu_add_remove_lock)->count, 1
static inline void
__mutex_unlock_common_slowpath(atomic_t *lock_count, int nested)
{
	// lock_count: &(&cpu_add_remove_lock)->count
	struct mutex *lock = container_of(lock_count, struct mutex, count);
	// container_of를 사용하여 mutex 구조체의 시작 주소를 뽑아낸다.
	// lock: &cpu_add_remove_lock
	unsigned long flags;

	// &lock->wait_lock: &(&cpu_add_remove_lock)->wait_lock
	spin_lock_mutex(&lock->wait_lock, flags);
	// flags에 CPSR을 저장했고 (&cpu_add_remove_lock)->wait_lock.rlock.raw_lock에 spinlock 설정

	// &lock->dep_map: &(&cpu_add_remove_lock)->dep_map, nested: 1
	mutex_release(&lock->dep_map, nested, _RET_IP_); // null function

	// lock: &cpu_add_remove_lock
	debug_mutex_unlock(lock);
	// lock->owner: (&cpu_add_remove_lock)->owner: NULL 로 설정

	/*
	 * some architectures leave the lock unlocked in the fastpath failure
	 * case, others need to leave it locked. In the later case we have to
	 * unlock it here
	 */
	// __mutex_slowpath_needs_to_unlock(): 1
	if (__mutex_slowpath_needs_to_unlock())
		// lock->count: (&cpu_add_remove_lock)->count: 0
		atomic_set(&lock->count, 1);
		// lock->count: (&cpu_add_remove_lock)->count: 1 로 설정

	// &lock->wait_list: &(&cpu_add_remove_lock)->wait_list
	// list_empty(&(&cpu_add_remove_lock)->wait_list): 1
	if (!list_empty(&lock->wait_list)) {
		// 20140322: 지금은 lock->wait_list가 NULL이므로 if문은 실행안함
		/* get the first entry from the wait-list: */
		struct mutex_waiter *waiter =
				list_entry(lock->wait_list.next,
					   struct mutex_waiter, list);
		// waiter: mutext_waiter 구조체의 주소

		debug_mutex_wake_waiter(lock, waiter);
		// mutex를 기다리는 것이 있으면 깨운다.

		wake_up_process(waiter->task);
		// mutex를 기다리는 task를 깨운다.
	}

	// &lock->wait_lock: &(&cpu_add_remove_lock)->wait_lock
	spin_unlock_mutex(&lock->wait_lock, flags);
	// (&cpu_add_remove_lock)->wait_lock.rlock.raw_lock에 spin unlock 하고
	// flags에 저장된 CPSR을 register에 restore함
}

/*
 * Release the lock, slowpath:
 */
// ARM10C 20140322
// __mutex_unlock_slowpath(&(&cpu_add_remove_lock)->count)
static __used noinline void
__mutex_unlock_slowpath(atomic_t *lock_count)
{
	// lock_count: &(&cpu_add_remove_lock)->count
	__mutex_unlock_common_slowpath(lock_count, 1);
}

#ifndef CONFIG_DEBUG_LOCK_ALLOC
/*
 * Here come the less common (and hence less performance-critical) APIs:
 * mutex_lock_interruptible() and mutex_trylock().
 */
static noinline int __sched
__mutex_lock_killable_slowpath(struct mutex *lock);

static noinline int __sched
__mutex_lock_interruptible_slowpath(struct mutex *lock);

/**
 * mutex_lock_interruptible - acquire the mutex, interruptible
 * @lock: the mutex to be acquired
 *
 * Lock the mutex like mutex_lock(), and return 0 if the mutex has
 * been acquired or sleep until the mutex becomes available. If a
 * signal arrives while waiting for the lock then this function
 * returns -EINTR.
 *
 * This function is similar to (but not equivalent to) down_interruptible().
 */
int __sched mutex_lock_interruptible(struct mutex *lock)
{
	int ret;

	might_sleep();
	ret =  __mutex_fastpath_lock_retval(&lock->count);
	if (likely(!ret)) {
		mutex_set_owner(lock);
		return 0;
	} else
		return __mutex_lock_interruptible_slowpath(lock);
}

EXPORT_SYMBOL(mutex_lock_interruptible);

int __sched mutex_lock_killable(struct mutex *lock)
{
	int ret;

	might_sleep();
	ret = __mutex_fastpath_lock_retval(&lock->count);
	if (likely(!ret)) {
		mutex_set_owner(lock);
		return 0;
	} else
		return __mutex_lock_killable_slowpath(lock);
}
EXPORT_SYMBOL(mutex_lock_killable);

// ARM10C 20140315
// __mutex_lock_slowpath(&(&cpu_add_remove_lock)->count)
// noinline : 절대로 인라인 함수로 사용하지 말것을 속성으로 정의,
// 함수 콜로 반드시 사용할 것
static __used noinline void __sched
__mutex_lock_slowpath(atomic_t *lock_count)
{
	// lock_count: &(&cpu_add_remove_lock)->count
	struct mutex *lock = container_of(lock_count, struct mutex, count);
	// lock: &cpu_add_remove_lock

	// TASK_UNINTERRUPTIBLE: 2
	__mutex_lock_common(lock, TASK_UNINTERRUPTIBLE, 0,
			    NULL, _RET_IP_, NULL, 0);
}

static noinline int __sched
__mutex_lock_killable_slowpath(struct mutex *lock)
{
	return __mutex_lock_common(lock, TASK_KILLABLE, 0,
				   NULL, _RET_IP_, NULL, 0);
}

static noinline int __sched
__mutex_lock_interruptible_slowpath(struct mutex *lock)
{
	return __mutex_lock_common(lock, TASK_INTERRUPTIBLE, 0,
				   NULL, _RET_IP_, NULL, 0);
}

static noinline int __sched
__ww_mutex_lock_slowpath(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
	return __mutex_lock_common(&lock->base, TASK_UNINTERRUPTIBLE, 0,
				   NULL, _RET_IP_, ctx, 1);
}

static noinline int __sched
__ww_mutex_lock_interruptible_slowpath(struct ww_mutex *lock,
					    struct ww_acquire_ctx *ctx)
{
	return __mutex_lock_common(&lock->base, TASK_INTERRUPTIBLE, 0,
				   NULL, _RET_IP_, ctx, 1);
}

#endif

/*
 * Spinlock based trylock, we take the spinlock and check whether we
 * can get the lock:
 */
static inline int __mutex_trylock_slowpath(atomic_t *lock_count)
{
	struct mutex *lock = container_of(lock_count, struct mutex, count);
	unsigned long flags;
	int prev;

	spin_lock_mutex(&lock->wait_lock, flags);

	prev = atomic_xchg(&lock->count, -1);
	if (likely(prev == 1)) {
		mutex_set_owner(lock);
		mutex_acquire(&lock->dep_map, 0, 1, _RET_IP_);
	}

	/* Set it back to 0 if there are no waiters: */
	if (likely(list_empty(&lock->wait_list)))
		atomic_set(&lock->count, 0);

	spin_unlock_mutex(&lock->wait_lock, flags);

	return prev == 1;
}

/**
 * mutex_trylock - try to acquire the mutex, without waiting
 * @lock: the mutex to be acquired
 *
 * Try to acquire the mutex atomically. Returns 1 if the mutex
 * has been acquired successfully, and 0 on contention.
 *
 * NOTE: this function follows the spin_trylock() convention, so
 * it is negated from the down_trylock() return values! Be careful
 * about this when converting semaphore users to mutexes.
 *
 * This function must not be used in interrupt context. The
 * mutex must be released by the same task that acquired it.
 */
int __sched mutex_trylock(struct mutex *lock)
{
	int ret;

	ret = __mutex_fastpath_trylock(&lock->count, __mutex_trylock_slowpath);
	if (ret)
		mutex_set_owner(lock);

	return ret;
}
EXPORT_SYMBOL(mutex_trylock);

#ifndef CONFIG_DEBUG_LOCK_ALLOC
int __sched
__ww_mutex_lock(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
	int ret;

	might_sleep();

	ret = __mutex_fastpath_lock_retval(&lock->base.count);

	if (likely(!ret)) {
		ww_mutex_set_context_fastpath(lock, ctx);
		mutex_set_owner(&lock->base);
	} else
		ret = __ww_mutex_lock_slowpath(lock, ctx);
	return ret;
}
EXPORT_SYMBOL(__ww_mutex_lock);

int __sched
__ww_mutex_lock_interruptible(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
	int ret;

	might_sleep();

	ret = __mutex_fastpath_lock_retval(&lock->base.count);

	if (likely(!ret)) {
		ww_mutex_set_context_fastpath(lock, ctx);
		mutex_set_owner(&lock->base);
	} else
		ret = __ww_mutex_lock_interruptible_slowpath(lock, ctx);
	return ret;
}
EXPORT_SYMBOL(__ww_mutex_lock_interruptible);

#endif

/**
 * atomic_dec_and_mutex_lock - return holding mutex if we dec to 0
 * @cnt: the atomic which we are to dec
 * @lock: the mutex to return holding if we dec to 0
 *
 * return true and hold lock if we dec to 0, return false otherwise
 */
int atomic_dec_and_mutex_lock(atomic_t *cnt, struct mutex *lock)
{
	/* dec if we can't possibly hit 0 */
	if (atomic_add_unless(cnt, -1, 1))
		return 0;
	/* we might hit 0, so take the lock */
	mutex_lock(lock);
	if (!atomic_dec_and_test(cnt)) {
		/* when we actually did the dec, we didn't hit 0 */
		mutex_unlock(lock);
		return 0;
	}
	/* we hit 0, and we hold the lock */
	return 1;
}
EXPORT_SYMBOL(atomic_dec_and_mutex_lock);
