/*
 * kernel/mutex-debug.c
 *
 * Debugging code for mutexes
 *
 * Started by Ingo Molnar:
 *
 *  Copyright (C) 2004, 2005, 2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 * lock debugging, locking tree, deadlock detection started by:
 *
 *  Copyright (C) 2004, LynuxWorks, Inc., Igor Manyilov, Bill Huey
 *  Released under the General Public License (GPL).
 */
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/poison.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/kallsyms.h>
#include <linux/interrupt.h>
#include <linux/debug_locks.h>

#include "mutex-debug.h"

/*
 * Must be called with lock->wait_lock held.
 */
// ARM10C 20140315
// lock: &cpu_add_remove_lock, waiter
void debug_mutex_lock_common(struct mutex *lock, struct mutex_waiter *waiter)
{
	// MUTEX_DEBUG_INIT: 0x11, sizeof(*waiter): 16
	memset(waiter, MUTEX_DEBUG_INIT, sizeof(*waiter));
	waiter->magic = waiter;
	INIT_LIST_HEAD(&waiter->list);
}

void debug_mutex_wake_waiter(struct mutex *lock, struct mutex_waiter *waiter)
{
	SMP_DEBUG_LOCKS_WARN_ON(!spin_is_locked(&lock->wait_lock));
	DEBUG_LOCKS_WARN_ON(list_empty(&lock->wait_list));
	DEBUG_LOCKS_WARN_ON(waiter->magic != waiter);
	DEBUG_LOCKS_WARN_ON(list_empty(&waiter->list));
}

// ARM10C 20130322
void debug_mutex_free_waiter(struct mutex_waiter *waiter)
{
	// list_empty(&waiter->list): 1
	DEBUG_LOCKS_WARN_ON(!list_empty(&waiter->list));

	// MUTEX_DEBUG_FREE: 0x22, sizeof(*waiter): 16
	memset(waiter, MUTEX_DEBUG_FREE, sizeof(*waiter));
}

// ARM10C 20140315
// lock: &cpu_add_remove_lock, &waiter,
// task_thread_info(init_task): ((struct thread_info *)(init_task)->stack)
//
// ((struct thread_info *)(init_task)->stack): &init_thread_info
void debug_mutex_add_waiter(struct mutex *lock, struct mutex_waiter *waiter,
			    struct thread_info *ti)
{
	// lock->wait_lock: (&cpu_add_remove_lock)->wait_lock
        // spin_is_locked(&(&cpu_add_remove_lock)->wait_lock): 1
	SMP_DEBUG_LOCKS_WARN_ON(!spin_is_locked(&lock->wait_lock));

	/* Meark the current thread as blocked on the lock: */
	// ti->task->blocked_on: init_thread_info->task->blocked_on (init_task->blocked_on)
	ti->task->blocked_on = waiter;
	// init_task->blocked_on: waiter
}

// ARM10C 20140315
// lock: &cpu_add_remove_lock, &waiter, current_thread_info(): init_thread_info	
void mutex_remove_waiter(struct mutex *lock, struct mutex_waiter *waiter,
			 struct thread_info *ti)
{
	// list_empty(&waiter->list): 0
	DEBUG_LOCKS_WARN_ON(list_empty(&waiter->list));

	// waiter->task: init_task, ti->task: init_thread_info.task: init_task
	DEBUG_LOCKS_WARN_ON(waiter->task != ti->task);

	// ti->task->blocked_on: init_thread_info.task.blocked_on: waiter
	DEBUG_LOCKS_WARN_ON(ti->task->blocked_on != waiter);

	// ti->task->blocked_on: init_thread_info.task.blocked_on: waiter
	ti->task->blocked_on = NULL;
	// init_thread_info.task.blocked_on: NULL

	list_del_init(&waiter->list);
	// &waiter->list 초기화

	// waiter->task: init_task
	waiter->task = NULL;
	// waiter->task: NULL
}

// ARM10C 20140322
// lock: &cpu_add_remove_lock
void debug_mutex_unlock(struct mutex *lock)
{
        // debug_locks: 1
	if (unlikely(!debug_locks))
		return;

	// lock->magic: (&cpu_add_remove_lock)->magic: &cpu_add_remove_lock,
	// lock: &cpu_add_remove_lock
	DEBUG_LOCKS_WARN_ON(lock->magic != lock);

	// lock->owner: (&cpu_add_remove_lock)->owner: init_task, current: init_task
	DEBUG_LOCKS_WARN_ON(lock->owner != current);

	// lock->wait_list.prev: (&cpu_add_remove_lock)->wait_list.prev: &(cpu_add_remove_lock.wait_list),
	// lock->wait_list.next: (&cpu_add_remove_lock)->wait_list.next: &(cpu_add_remove_lock.wait_list)
	DEBUG_LOCKS_WARN_ON(!lock->wait_list.prev && !lock->wait_list.next);

	// lock: &cpu_add_remove_lock
	mutex_clear_owner(lock);
	// lock->owner: (&cpu_add_remove_lock)->owner: NULL 로 설정
}

void debug_mutex_init(struct mutex *lock, const char *name,
		      struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	/*
	 * Make sure we are not reinitializing a held lock:
	 */
	debug_check_no_locks_freed((void *)lock, sizeof(*lock));
	lockdep_init_map(&lock->dep_map, name, key, 0);
#endif
	lock->magic = lock;
}

/***
 * mutex_destroy - mark a mutex unusable
 * @lock: the mutex to be destroyed
 *
 * This function marks the mutex uninitialized, and any subsequent
 * use of the mutex is forbidden. The mutex must not be locked when
 * this function is called.
 */
void mutex_destroy(struct mutex *lock)
{
	DEBUG_LOCKS_WARN_ON(mutex_is_locked(lock));
	lock->magic = NULL;
}

EXPORT_SYMBOL_GPL(mutex_destroy);
