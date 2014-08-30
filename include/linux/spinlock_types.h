#ifndef __LINUX_SPINLOCK_TYPES_H
#define __LINUX_SPINLOCK_TYPES_H

/*
 * include/linux/spinlock_types.h - generic spinlock type definitions
 *                                  and initializers
 *
 * portions Copyright 2005, Red Hat, Inc., Ingo Molnar
 * Released under the General Public License (GPL).
 */

#if defined(CONFIG_SMP)
# include <asm/spinlock_types.h>
#else
# include <linux/spinlock_types_up.h>
#endif

#include <linux/lockdep.h>

// ARM10C 20130914
// arch_spinlock_t의 wrapper다.
// ARM10C 20140315
// ARM10C 20140419
// ARM10C 20140830
// sizeof(raw_spinlock_t) : 16byte
typedef struct raw_spinlock {
	arch_spinlock_t raw_lock; 
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
} raw_spinlock_t;

// ARM10C 20140315
#define SPINLOCK_MAGIC		0xdead4ead

// ARM10C 20140315
// SPINLOCK_OWNER_INIT: 0xffffffff
#define SPINLOCK_OWNER_INIT	((void *)-1L)

#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define SPIN_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname }
#else
// ARM10C 20140315
// SPIN_DEP_MAP_INIT(cpu_add_remove_lock.wait_lock)
# define SPIN_DEP_MAP_INIT(lockname)
#endif

#ifdef CONFIG_DEBUG_SPINLOCK // CONFIG_DEBUG_SPINLOCK=y
// ARM10C 20140315
// SPINLOCK_MAGIC: 0xdead4ead, SPINLOCK_OWNER_INIT: 0xffffffff
// #define SPIN_DEBUG_INIT(cpu_add_remove_lock.wait_lock)
//	.magic = 0xdead4ead,
//	.owner_cpu = -1,
//	.owner = 0xffffffff,
# define SPIN_DEBUG_INIT(lockname)		\
	.magic = SPINLOCK_MAGIC,		\
	.owner_cpu = -1,			\
	.owner = SPINLOCK_OWNER_INIT,
#else
# define SPIN_DEBUG_INIT(lockname)
#endif

// ARM10C 20130914
// ARM10C 20140315
// __ARCH_SPIN_LOCK_UNLOCKED: { { 0 } }
// SPIN_DEBUG_INIT(cpu_add_remove_lock.wait_lock):
//	.magic = 0xdead4ead,
//	.owner_cpu = -1,
//	.owner = 0xffffffff,
// SPIN_DEP_MAP_INIT(cpu_add_remove_lock.wait_lock):
// #define __RAW_SPIN_LOCK_INITIALIZER(cpu_add_remove_lock.wait_lock)
//	{
//	  .raw_lock = { { 0 } },
//	  .magic = 0xdead4ead,
//	  .owner_cpu = -1,
//	  .owner = 0xffffffff,
//	}
#define __RAW_SPIN_LOCK_INITIALIZER(lockname)	\
	{					\
	.raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,	\
	SPIN_DEBUG_INIT(lockname)		\
	SPIN_DEP_MAP_INIT(lockname) }

#define __RAW_SPIN_LOCK_UNLOCKED(lockname)	\
	(raw_spinlock_t) __RAW_SPIN_LOCK_INITIALIZER(lockname)

#define DEFINE_RAW_SPINLOCK(x)	raw_spinlock_t x = __RAW_SPIN_LOCK_UNLOCKED(x)

// ARM10C 20130914
// 여기도 raw_spinlock의 wrapper다.
// ARM10C 20140315
// ARM10C 20140419
// sizeof(spinlock_t) : 16 byte
typedef struct spinlock {
	union {
		struct raw_spinlock rlock;
#ifdef CONFIG_DEBUG_LOCK_ALLOC // CONFIG_DEBUG_LOCK_ALLOC=n
# define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
		struct {
			u8 __padding[LOCK_PADSIZE];
			struct lockdep_map dep_map;
		};
#endif
	};
} spinlock_t;

// ARM10C 20131012
// ARM10C 20140315
// __RAW_SPIN_LOCK_INITIALIZER(cpu_add_remove_lock.wait_lock):
//	{
//	  .raw_lock = { { 0 } },
//	  .magic = 0xdead4ead,
//	  .owner_cpu = -1,
//	  .owner = 0xffffffff,
//	}
// #define __SPIN_LOCK_INITIALIZER(cpu_add_remove_lock.wait_lock):
//	{ { .rlock =
//	    {
//	      .raw_lock = { { 0 } },
//	      .magic = 0xdead4ead,
//	      .owner_cpu = -1,
//	      .owner = 0xffffffff,
//	    }
//	} }
#define __SPIN_LOCK_INITIALIZER(lockname) \
	{ { .rlock = __RAW_SPIN_LOCK_INITIALIZER(lockname) } }

// ARM10C 20131012
// ARM10C 20140315
// __SPIN_LOCK_INITIALIZER(cpu_add_remove_lock.wait_lock):
//	{ { .rlock =
//	    {
//	      .raw_lock = { { 0 } },
//	      .magic = 0xdead4ead,
//	      .owner_cpu = -1,
//	      .owner = 0xffffffff,
//	    }
//	} }
//
// #define __SPIN_LOCK_UNLOCKED(cpu_add_remove_lock.wait_lock):
//	(spinlock_t )
//	{ { .rlock =
//	    {
//	      .raw_lock = { { 0 } },
//	      .magic = 0xdead4ead,
//	      .owner_cpu = -1,
//	      .owner = 0xffffffff,
//	    }
//	} }
#define __SPIN_LOCK_UNLOCKED(lockname) \
	(spinlock_t ) __SPIN_LOCK_INITIALIZER(lockname)

// ARM10C 20140531
#define DEFINE_SPINLOCK(x)	spinlock_t x = __SPIN_LOCK_UNLOCKED(x)

#include <linux/rwlock_types.h>

#endif /* __LINUX_SPINLOCK_TYPES_H */
