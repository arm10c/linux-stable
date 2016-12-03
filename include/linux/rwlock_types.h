#ifndef __LINUX_RWLOCK_TYPES_H
#define __LINUX_RWLOCK_TYPES_H

/*
 * include/linux/rwlock_types.h - generic rwlock type definitions
 *				  and initializers
 *
 * portions Copyright 2005, Red Hat, Inc., Ingo Molnar
 * Released under the General Public License (GPL).
 */
// ARM10C 20151003
// sizeof(struct rwlock_t): 16 bytes
typedef struct {
	arch_rwlock_t raw_lock;
#ifdef CONFIG_GENERIC_LOCKBREAK // CONFIG_GENERIC_LOCKBREAK=n
	unsigned int break_lock;
#endif
#ifdef CONFIG_DEBUG_SPINLOCK // CONFIG_DEBUG_SPINLOCK=y
	unsigned int magic, owner_cpu;
	void *owner;
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC // CONFIG_DEBUG_LOCK_ALLOC=n
	struct lockdep_map dep_map;
#endif
} rwlock_t;

// ARM10C 20140125
// ARM10C 20151031
// ARM10C 20160326
// ARM10C 20160402
// RWLOCK_MAGIC: 0xdeaf1eed
#define RWLOCK_MAGIC		0xdeaf1eed

#ifdef CONFIG_DEBUG_LOCK_ALLOC // CONFIG_DEBUG_LOCK_ALLOC=n
# define RW_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname }
#else
// ARM10C 20151031
// RW_DEP_MAP_INIT(file_systems_lock):
# define RW_DEP_MAP_INIT(lockname)
#endif

#ifdef CONFIG_DEBUG_SPINLOCK // CONFIG_DEBUG_SPINLOCK=y
// ARM10C 20140125
// ARM10C 20151031
// __ARCH_RW_LOCK_UNLOCKED: { 0 }
// RWLOCK_MAGIC: 0xdeaf1eed
// SPINLOCK_OWNER_INIT: 0xffffffff
// RW_DEP_MAP_INIT(file_systems_lock):
//
// #define __RW_LOCK_UNLOCKED(file_systems_lock):
// (rwlock_t)
// {
//      .raw_lock = { 0 },
//      .magic = 0xdeaf1eed,
//      .owner = 0xffffffff,
//      .owner_cpu = -1,
// }
#define __RW_LOCK_UNLOCKED(lockname)					\
	(rwlock_t)	{	.raw_lock = __ARCH_RW_LOCK_UNLOCKED,	\
				.magic = RWLOCK_MAGIC,			\
				.owner = SPINLOCK_OWNER_INIT,		\
				.owner_cpu = -1,			\
				RW_DEP_MAP_INIT(lockname) }
#else
#define __RW_LOCK_UNLOCKED(lockname) \
	(rwlock_t)	{	.raw_lock = __ARCH_RW_LOCK_UNLOCKED,	\
				RW_DEP_MAP_INIT(lockname) }
#endif

// ARM10C 20140125
// ARM10C 20151031
// __RW_LOCK_UNLOCKED(file_systems_lock):
// (rwlock_t)
// {
//      .raw_lock = { 0 },
//      .magic = 0xdeaf1eed,
//      .owner = 0xffffffff,
//      .owner_cpu = -1,
// }
//
// #define DEFINE_RWLOCK(file_systems_lock):
// rwlock_t file_systems_lock =
// (rwlock_t)
// {
//      .raw_lock = { 0 },
//      .magic = 0xdeaf1eed,
//      .owner = 0xffffffff,
//      .owner_cpu = -1,
// }
// ARM10C 20161203
// #define DEFINE_RWLOCK(tasklist_lock):
// rwlock_t tasklist_lock =
// (rwlock_t)
// {
//      .raw_lock = { 0 },
//      .magic = 0xdeaf1eed,
//      .owner = 0xffffffff,
//      .owner_cpu = -1,
// }
#define DEFINE_RWLOCK(x)	rwlock_t x = __RW_LOCK_UNLOCKED(x)

#endif /* __LINUX_RWLOCK_TYPES_H */
