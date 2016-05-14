/* kernel/rwsem.c: R/W semaphores, public implementation
 *
 * Written by David Howells (dhowells@redhat.com).
 * Derived from asm-i386/semaphore.h
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/rwsem.h>

#include <linux/atomic.h>

/*
 * lock for reading
 */
void __sched down_read(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, 0, 0, _RET_IP_);

	LOCK_CONTENDED(sem, __down_read_trylock, __down_read);
}

EXPORT_SYMBOL(down_read);

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
int down_read_trylock(struct rw_semaphore *sem)
{
	int ret = __down_read_trylock(sem);

	if (ret == 1)
		rwsem_acquire_read(&sem->dep_map, 0, 1, _RET_IP_);
	return ret;
}

EXPORT_SYMBOL(down_read_trylock);

/*
 * lock for writing
 */
// ARM10C 20151114
// &s->s_umount: &(kmem_cache#25-oX (struct super_block))->s_umount, SINGLE_DEPTH_NESTING: 1
// ARM10C 20151121
// &shrinker_rwsem
void __sched down_write(struct rw_semaphore *sem)
{
	might_sleep(); // null function

	// &sem->dep_map: &(&(kmem_cache#25-oX (struct super_block))->s_umount)->dep_map
	rwsem_acquire(&sem->dep_map, 0, 0, _RET_IP_); // null function

	// sem: &(kmem_cache#25-oX (struct super_block))->s_umount
	// LOCK_CONTENDED(&(kmem_cache#25-oX (struct super_block))->s_umount, __down_write_trylock, __down_write):
	// __down_write(&(kmem_cache#25-oX (struct super_block))->s_umount)
	LOCK_CONTENDED(sem, __down_write_trylock, __down_write);

	// __down_write에서 한일:
	// sem->activity: (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: -1
}

EXPORT_SYMBOL(down_write);

/*
 * trylock for writing -- returns 1 if successful, 0 if contention
 */
int down_write_trylock(struct rw_semaphore *sem)
{
	int ret = __down_write_trylock(sem);

	if (ret == 1)
		rwsem_acquire(&sem->dep_map, 0, 1, _RET_IP_);
	return ret;
}

EXPORT_SYMBOL(down_write_trylock);

/*
 * release a read lock
 */
void up_read(struct rw_semaphore *sem)
{
	rwsem_release(&sem->dep_map, 1, _RET_IP_);

	__up_read(sem);
}

EXPORT_SYMBOL(up_read);

/*
 * release a write lock
 */
// ARM10C 20151121
// &shrinker_rwsem
// ARM10C 20151219
// &sb->s_umount: &(kmem_cache#25-oX (struct super_block))->s_umount
// ARM10C 20160326
// &sb->s_umount: &(kmem_cache#25-oX (struct super_block))->s_umount
// ARM10C 20160514
// &sb->s_umount: &(kmem_cache#25-oX (struct super_block))->s_umount
void up_write(struct rw_semaphore *sem)
{
	// &sem->dep_map: &(&shrinker_rwsem)->dep_map
	rwsem_release(&sem->dep_map, 1, _RET_IP_); // null function

	// sem: &shrinker_rwsem
	__up_write(sem);

	// __up_write에서 한일:
	// (&shrinker_rwsem)->activity: 0
}

EXPORT_SYMBOL(up_write);

/*
 * downgrade write lock to read lock
 */
void downgrade_write(struct rw_semaphore *sem)
{
	/*
	 * lockdep: a downgraded write will live on as a write
	 * dependency.
	 */
	__downgrade_write(sem);
}

EXPORT_SYMBOL(downgrade_write);

#ifdef CONFIG_DEBUG_LOCK_ALLOC

void down_read_nested(struct rw_semaphore *sem, int subclass)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, subclass, 0, _RET_IP_);

	LOCK_CONTENDED(sem, __down_read_trylock, __down_read);
}

EXPORT_SYMBOL(down_read_nested);

void _down_write_nest_lock(struct rw_semaphore *sem, struct lockdep_map *nest)
{
	might_sleep();
	rwsem_acquire_nest(&sem->dep_map, 0, 0, nest, _RET_IP_);

	LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
}

EXPORT_SYMBOL(_down_write_nest_lock);

void down_read_non_owner(struct rw_semaphore *sem)
{
	might_sleep();

	__down_read(sem);
}

EXPORT_SYMBOL(down_read_non_owner);

void down_write_nested(struct rw_semaphore *sem, int subclass)
{
	might_sleep();
	rwsem_acquire(&sem->dep_map, subclass, 0, _RET_IP_);

	LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
}

EXPORT_SYMBOL(down_write_nested);

void up_read_non_owner(struct rw_semaphore *sem)
{
	__up_read(sem);
}

EXPORT_SYMBOL(up_read_non_owner);

#endif


