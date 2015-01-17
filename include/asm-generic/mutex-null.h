/*
 * include/asm-generic/mutex-null.h
 *
 * Generic implementation of the mutex fastpath, based on NOP :-)
 *
 * This is used by the mutex-debugging infrastructure, but it can also
 * be used by architectures that (for whatever reason) want to use the
 * spinlock based slowpath.
 */
#ifndef _ASM_GENERIC_MUTEX_NULL_H
#define _ASM_GENERIC_MUTEX_NULL_H

// ARM10C 20140315
// __mutex_fastpath_lock(&(&cpu_add_remove_lock)->count, __mutex_lock_slowpath):
// __mutex_lock_slowpath(&(&cpu_add_remove_lock)->count)
#define __mutex_fastpath_lock(count, fail_fn)		fail_fn(count)
#define __mutex_fastpath_lock_retval(count)		(-1)
// ARM10C 20140322
// __mutex_fastpath_unlock(&(&cpu_add_remove_lock)->count, __mutex_unlock_slowpath);
// __mutex_unlock_slowpath(&(&cpu_add_remove_lock)->count)
#define __mutex_fastpath_unlock(count, fail_fn)		fail_fn(count)
// ARM10C 20150117
// &lock->count: (&prepare_lock)->count, __mutex_trylock_slowpath
// __mutex_trylock_slowpath((&prepare_lock)->count)
#define __mutex_fastpath_trylock(count, fail_fn)	fail_fn(count)
// ARM10C 20140322
#define __mutex_slowpath_needs_to_unlock()		1

#endif
