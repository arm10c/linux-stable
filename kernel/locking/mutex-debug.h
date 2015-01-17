/*
 * Mutexes: blocking mutual exclusion locks
 *
 * started by Ingo Molnar:
 *
 *  Copyright (C) 2004, 2005, 2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 * This file contains mutex debugging related internal declarations,
 * prototypes and inline functions, for the CONFIG_DEBUG_MUTEXES case.
 * More details are in kernel/mutex-debug.c.
 */

/*
 * This must be called with lock->wait_lock held.
 */
extern void debug_mutex_lock_common(struct mutex *lock,
				    struct mutex_waiter *waiter);
extern void debug_mutex_wake_waiter(struct mutex *lock,
				    struct mutex_waiter *waiter);
extern void debug_mutex_free_waiter(struct mutex_waiter *waiter);
extern void debug_mutex_add_waiter(struct mutex *lock,
				   struct mutex_waiter *waiter,
				   struct thread_info *ti);
extern void mutex_remove_waiter(struct mutex *lock, struct mutex_waiter *waiter,
				struct thread_info *ti);
extern void debug_mutex_unlock(struct mutex *lock);
extern void debug_mutex_init(struct mutex *lock, const char *name,
			     struct lock_class_key *key);

// ARM10C 20140315
// lock: &cpu_add_remove_lock
// ARM10C 20140322
// lock: &cpu_add_remove_lock
// ARM10C 20150117
// lock: &prepare_lock
static inline void mutex_set_owner(struct mutex *lock)
{
	// lock->owner: (&cpu_add_remove_lock)->owner, current: init_task
	lock->owner = current;
	// (&cpu_add_remove_lock)->owner: init_task
}

// ARM10C 20140322
// lock: &cpu_add_remove_lock
static inline void mutex_clear_owner(struct mutex *lock)
{
	// lock->onwer: (&cpu_add_remove_lock)->onwer: init_task
	lock->owner = NULL;
	// lock->onwer: (&cpu_add_remove_lock)->onwer: NULL
}

// ARM10C 20140315
// lock: &(&cpu_add_remove_lock)->wait_lock, flags : flags
// in_interrupt(): 0, local_irq_save(flags): flags에 CPSR값을 저장
// flags에 CPSR을 저장했고 (&cpu_add_remove_lock)->wait_lock.rlock.raw_lock에 spinlock 설정
// ARM10C 20140322
// lock: &(&cpu_add_remove_lock)->wait_lock, flags : flags
// ARM10C 20150117
// &lock->wait_lock: &(&prepare_lock)->wait_lock, flags
//
// #define spin_lock_mutex(&(&prepare_lock)->wait_lock, flags):
// do {
// 	struct mutex *l = container_of(&(&prepare_lock)->wait_lock, struct mutex, wait_lock);
//
// 	DEBUG_LOCKS_WARN_ON(in_interrupt());
// 	local_irq_save(flags);
// 	arch_spin_lock(&(&(&prepare_lock)->wait_lock)->rlock.raw_lock);
// 	DEBUG_LOCKS_WARN_ON(l->magic != l);
// } while (0)
#define spin_lock_mutex(lock, flags)			\
	do {						\
		struct mutex *l = container_of(lock, struct mutex, wait_lock); \
							\
		DEBUG_LOCKS_WARN_ON(in_interrupt());	\
		local_irq_save(flags);			\
		arch_spin_lock(&(lock)->rlock.raw_lock);\
		DEBUG_LOCKS_WARN_ON(l->magic != l);	\
	} while (0)

// ARM10C 20130322
// lock: &(&cpu_add_remove_lock)->wait_lock,
// flags: spin_lock_mutex(&(&cpu_add_remove_lock)->wait_lock, flags)에서 저장했던 CPSR값
// ARM10C 20140322
// lock: &(&cpu_add_remove_lock)->wait_lock, flags: flags
// ARM10C 20150117
// &lock->wait_lock: &(&prepare_lock)->wait_lock
#define spin_unlock_mutex(lock, flags)				\
	do {							\
		arch_spin_unlock(&(lock)->rlock.raw_lock);	\
		local_irq_restore(flags);			\
		preempt_check_resched();			\
	} while (0)
