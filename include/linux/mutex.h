/*
 * Mutexes: blocking mutual exclusion locks
 *
 * started by Ingo Molnar:
 *
 *  Copyright (C) 2004, 2005, 2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 * This file contains the main data structure and API definitions.
 */
#ifndef __LINUX_MUTEX_H
#define __LINUX_MUTEX_H

#include <asm/current.h>
#include <linux/list.h>
#include <linux/spinlock_types.h>
#include <linux/linkage.h>
#include <linux/lockdep.h>
#include <linux/atomic.h>
#include <asm/processor.h>

/*
 * Simple, straightforward mutexes with strict semantics:
 *
 * - only one task can hold the mutex at a time
 * - only the owner can unlock the mutex
 * - multiple unlocks are not permitted
 * - recursive locking is not permitted
 * - a mutex object must be initialized via the API
 * - a mutex object must not be initialized via memset or copying
 * - task may not exit with mutex held
 * - memory areas where held locks reside must not be freed
 * - held mutexes must not be reinitialized
 * - mutexes may not be used in hardware or software interrupt
 *   contexts such as tasklets and timers
 *
 * These semantics are fully enforced when DEBUG_MUTEXES is
 * enabled. Furthermore, besides enforcing the above rules, the mutex
 * debugging code also implements a number of additional features
 * that make lock debugging easier and faster:
 *
 * - uses symbolic names of mutexes, whenever they are printed in debug output
 * - point-of-acquire tracking, symbolic lookup of function names
 * - list of all locks held in the system, printout of them
 * - owner tracking
 * - detects self-recursing locks and prints out all relevant info
 * - detects multi-task circular deadlocks and prints out all affected
 *   locks and tasks (and only those tasks)
 */
// ARM10C 20140315
// ARM10C 20150117
struct mutex {
	/* 1: unlocked, 0: locked, negative: locked, possible waiters */
	atomic_t		count;
	spinlock_t		wait_lock;
	struct list_head	wait_list;
#if defined(CONFIG_DEBUG_MUTEXES) || defined(CONFIG_SMP) // CONFIG_DEBUG_MUTEXES=y, CONFIG_SMP=y
	struct task_struct	*owner;
#endif
#ifdef CONFIG_MUTEX_SPIN_ON_OWNER // CONFIG_MUTEX_SPIN_ON_OWNER=n
	void			*spin_mlock;	/* Spinner MCS lock */
#endif
#ifdef CONFIG_DEBUG_MUTEXES // CONFIG_DEBUG_MUTEXES=y
	const char 		*name;
	void			*magic;
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC // CONFIG_DEBUG_LOCK_ALLOC=n
	struct lockdep_map	dep_map;
#endif
};

/*
 * This is the control structure for tasks blocked on mutex,
 * which resides on the blocked task's kernel stack:
 */
// ARM10C 20140315
// sizeof(struct mutex_waiter): 16 bytes
struct mutex_waiter {
	struct list_head	list;
	struct task_struct	*task;
#ifdef CONFIG_DEBUG_MUTEXES // CONFIG_DEBUG_MUTEXES=y
	void			*magic;
#endif
};

#ifdef CONFIG_DEBUG_MUTEXES // define 
// ARM10C 20140315
# include <linux/mutex-debug.h>
#else
# define __DEBUG_MUTEX_INITIALIZER(lockname)
/**
 * mutex_init - initialize the mutex
 * @mutex: the mutex to be initialized
 *
 * Initialize the mutex to unlocked state.
 *
 * It is not allowed to initialize an already locked mutex.
 */
# define mutex_init(mutex) \
do {							\
	static struct lock_class_key __key;		\
							\
	__mutex_init((mutex), #mutex, &__key);		\
} while (0)
static inline void mutex_destroy(struct mutex *lock) {}
#endif

#ifdef CONFIG_DEBUG_LOCK_ALLOC // CONFIG_DEBUG_LOCK_ALLOC=n
# define __DEP_MAP_MUTEX_INITIALIZER(lockname) \
		, .dep_map = { .name = #lockname }
#else
// ARM10C 20140315
// __DEP_MAP_MUTEX_INITIALIZER(cpu_add_remove_lock):
# define __DEP_MAP_MUTEX_INITIALIZER(lockname)
#endif

// ARM10C 20140315
// ATOMIC_INIT(1): { (1) }
// __SPIN_LOCK_UNLOCKED(cpu_add_remove_lock.wait_lock):
//    (spinlock_t )
//    { { .rlock =
//	  {
//	    .raw_lock = { { 0 } },
//	    .magic = 0xdead4ead,
//	    .owner_cpu = -1,
//	    .owner = 0xffffffff,
//	  }
//    } }
// LIST_HEAD_INIT(cpu_add_remove_lock.wait_list):
// { &(cpu_add_remove_lock.wait_list), &(cpu_add_remove_lock.wait_list) }
// __DEBUG_MUTEX_INITIALIZER(cpu_add_remove_lock):
// , .magic = &cpu_add_remove_lock
// __DEP_MAP_MUTEX_INITIALIZER(cpu_add_remove_lock):
//
// #define __MUTEX_INITIALIZER(cpu_add_remove_lock):
// { .count = { (1) }
//    , .wait_lock =
//    (spinlock_t )
//    { { .rlock =
//	  {
//	  .raw_lock = { { 0 } },
//	  .magic = 0xdead4ead,
//	  .owner_cpu = -1,
//	  .owner = 0xffffffff,
//	  }
//    } }
//    , .wait_list =
//    { &(cpu_add_remove_lock.wait_list), &(cpu_add_remove_lock.wait_list) }
//    , .magic = &cpu_add_remove_lock
// }
//
// ARM10C 20140920
// __MUTEX_INITIALIZER(cpu_hotplug.lock):
// { .count = { (1) }
//    , .wait_lock =
//    (spinlock_t )
//    { { .rlock =
//	  {
//	  .raw_lock = { { 0 } },
//	  .magic = 0xdead4ead,
//	  .owner_cpu = -1,
//	  .owner = 0xffffffff,
//	  }
//    } }
//    , .wait_list =
//    { &(cpu_hotplug.lock.wait_list), &(cpu_hotplug.lock.wait_list) }
//    , .magic = &cpu_hotplug.lock
// }
#define __MUTEX_INITIALIZER(lockname) \
		{ .count = ATOMIC_INIT(1) \
		, .wait_lock = __SPIN_LOCK_UNLOCKED(lockname.wait_lock) \
		, .wait_list = LIST_HEAD_INIT(lockname.wait_list) \
		__DEBUG_MUTEX_INITIALIZER(lockname) \
		__DEP_MAP_MUTEX_INITIALIZER(lockname) }

// ARM10C 20140315
// #define __MUTEX_INITIALIZER(cpu_add_remove_lock):
// { .count = { (1) }
//    , .wait_lock =
//    (spinlock_t )
//    { { .rlock =
//	  {
//	  .raw_lock = { { 0 } },
//	  .magic = 0xdead4ead,
//	  .owner_cpu = -1,
//	  .owner = 0xffffffff,
//	  }
//    } }
//    , .wait_list =
//    { &(cpu_add_remove_lock.wait_list), &(cpu_add_remove_lock.wait_list) }
//    , .magic = &cpu_add_remove_lock
// }
//
// #define DEFINE_MUTEX(cpu_add_remove_lock):
// struct mutex cpu_add_remove_lock =
// { .count = { (1) }
//    , .wait_lock =
//    (spinlock_t )
//    { { .rlock =
//	  {
//	  .raw_lock = { { 0 } },
//	  .magic = 0xdead4ead,
//	  .owner_cpu = -1,
//	  .owner = 0xffffffff,
//	  }
//    } }
//    , .wait_list =
//    { &(cpu_add_remove_lock.wait_list), &(cpu_add_remove_lock.wait_list) }
//    , .magic = &cpu_add_remove_lock
// }
//
// ARM10C 20140920
// DEFINE_MUTEX(slab_mutex):
// struct mutex slab_mutex =
// { .count = { (1) }
//    , .wait_lock =
//    (spinlock_t )
//    { { .rlock =
//	  {
//	  .raw_lock = { { 0 } },
//	  .magic = 0xdead4ead,
//	  .owner_cpu = -1,
//	  .owner = 0xffffffff,
//	  }
//    } }
//    , .wait_list =
//    { &(slab_mutex.wait_list), &(slab_mutex.wait_list) }
//    , .magic = &slab_mutex
// }
#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)

extern void __mutex_init(struct mutex *lock, const char *name,
			 struct lock_class_key *key);

/**
 * mutex_is_locked - is the mutex locked
 * @lock: the mutex to be queried
 *
 * Returns 1 if the mutex is locked, 0 if unlocked.
 */
static inline int mutex_is_locked(struct mutex *lock)
{
	return atomic_read(&lock->count) != 1;
}

/*
 * See kernel/locking/mutex.c for detailed documentation of these APIs.
 * Also see Documentation/mutex-design.txt.
 */
#ifdef CONFIG_DEBUG_LOCK_ALLOC // CONFIG_DEBUG_LOCK_ALLOC=n
extern void mutex_lock_nested(struct mutex *lock, unsigned int subclass);
extern void _mutex_lock_nest_lock(struct mutex *lock, struct lockdep_map *nest_lock);

extern int __must_check mutex_lock_interruptible_nested(struct mutex *lock,
					unsigned int subclass);
extern int __must_check mutex_lock_killable_nested(struct mutex *lock,
					unsigned int subclass);

#define mutex_lock(lock) mutex_lock_nested(lock, 0)
#define mutex_lock_interruptible(lock) mutex_lock_interruptible_nested(lock, 0)
#define mutex_lock_killable(lock) mutex_lock_killable_nested(lock, 0)

#define mutex_lock_nest_lock(lock, nest_lock)				\
do {									\
	typecheck(struct lockdep_map *, &(nest_lock)->dep_map);	\
	_mutex_lock_nest_lock(lock, &(nest_lock)->dep_map);		\
} while (0)

#else
// ARM10C 20140315
// mutex_lock(&cpu_add_remove_lock)
extern void mutex_lock(struct mutex *lock);
extern int __must_check mutex_lock_interruptible(struct mutex *lock);
extern int __must_check mutex_lock_killable(struct mutex *lock);

# define mutex_lock_nested(lock, subclass) mutex_lock(lock)
# define mutex_lock_interruptible_nested(lock, subclass) mutex_lock_interruptible(lock)
# define mutex_lock_killable_nested(lock, subclass) mutex_lock_killable(lock)
# define mutex_lock_nest_lock(lock, nest_lock) mutex_lock(lock)
#endif

/*
 * NOTE: mutex_trylock() follows the spin_trylock() convention,
 *       not the down_trylock() convention!
 *
 * Returns 1 if the mutex has been acquired successfully, and 0 on contention.
 */
extern int mutex_trylock(struct mutex *lock);
extern void mutex_unlock(struct mutex *lock);

extern int atomic_dec_and_mutex_lock(atomic_t *cnt, struct mutex *lock);

#ifndef arch_mutex_cpu_relax
# define arch_mutex_cpu_relax() cpu_relax()
#endif

#endif
