/* rwsem-spinlock.c: R/W semaphores: contention handling functions for
 * generic spinlock implementation
 *
 * Copyright (c) 2001   David Howells (dhowells@redhat.com).
 * - Derived partially from idea by Andrea Arcangeli <andrea@suse.de>
 * - Derived also from comments by Linus
 */
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/export.h>

// ARM10C 20151121
enum rwsem_waiter_type {
	// RWSEM_WAITING_FOR_WRITE: 0
	RWSEM_WAITING_FOR_WRITE,
	RWSEM_WAITING_FOR_READ
};

// ARM10C 20151121
struct rwsem_waiter {
	struct list_head list;
	struct task_struct *task;
	enum rwsem_waiter_type type;
};

int rwsem_is_locked(struct rw_semaphore *sem)
{
	int ret = 1;
	unsigned long flags;

	if (raw_spin_trylock_irqsave(&sem->wait_lock, flags)) {
		ret = (sem->activity != 0);
		raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
	}
	return ret;
}
EXPORT_SYMBOL(rwsem_is_locked);

/*
 * initialise the semaphore
 */
// ARM10C 20151114
// &s->s_umount: &(kmem_cache#25-oX (struct super_block))->s_umount, "&s->s_umount", &__key
// ARM10C 20151114
// &s->s_dquot.dqptr_sem: &(kmem_cache#25-oX (struct super_block))->s_dquot.dqptr_sem, "&s->s_dquot.dqptr_sem", &__key
void __init_rwsem(struct rw_semaphore *sem, const char *name,
		  struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC // CONFIG_DEBUG_LOCK_ALLOC=n
	/*
	 * Make sure we are not reinitializing a held semaphore:
	 */
	debug_check_no_locks_freed((void *)sem, sizeof(*sem));
	lockdep_init_map(&sem->dep_map, name, key, 0);
#endif
	// sem->activity: (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity
	sem->activity = 0;
	// sem->activity: (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0

	// &sem->wait_lock: &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_lock
	raw_spin_lock_init(&sem->wait_lock);

	// raw_spin_lock_init에서 한일:
	// &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_lock을 사용한 spinlock 초기화

	// &sem->wait_list: &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list
	INIT_LIST_HEAD(&sem->wait_list);

	// INIT_LIST_HEAD에서 한일:
	// (&(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list)->next: &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list
	// (&(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list)->prev: &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list
}
EXPORT_SYMBOL(__init_rwsem);

/*
 * handle the lock release when processes blocked on it that can now run
 * - if we come here, then:
 *   - the 'active count' _reached_ zero
 *   - the 'waiting count' is non-zero
 * - the spinlock must be held by the caller
 * - woken process blocks are discarded from the list after having task zeroed
 * - writers are only woken if wakewrite is non-zero
 */
static inline struct rw_semaphore *
__rwsem_do_wake(struct rw_semaphore *sem, int wakewrite)
{
	struct rwsem_waiter *waiter;
	struct task_struct *tsk;
	int woken;

	waiter = list_entry(sem->wait_list.next, struct rwsem_waiter, list);

	if (waiter->type == RWSEM_WAITING_FOR_WRITE) {
		if (wakewrite)
			/* Wake up a writer. Note that we do not grant it the
			 * lock - it will have to acquire it when it runs. */
			wake_up_process(waiter->task);
		goto out;
	}

	/* grant an infinite number of read locks to the front of the queue */
	woken = 0;
	do {
		struct list_head *next = waiter->list.next;

		list_del(&waiter->list);
		tsk = waiter->task;
		smp_mb();
		waiter->task = NULL;
		wake_up_process(tsk);
		put_task_struct(tsk);
		woken++;
		if (next == &sem->wait_list)
			break;
		waiter = list_entry(next, struct rwsem_waiter, list);
	} while (waiter->type != RWSEM_WAITING_FOR_WRITE);

	sem->activity += woken;

 out:
	return sem;
}

/*
 * wake a single writer
 */
static inline struct rw_semaphore *
__rwsem_wake_one_writer(struct rw_semaphore *sem)
{
	struct rwsem_waiter *waiter;

	waiter = list_entry(sem->wait_list.next, struct rwsem_waiter, list);
	wake_up_process(waiter->task);

	return sem;
}

/*
 * get a read lock on the semaphore
 */
void __sched __down_read(struct rw_semaphore *sem)
{
	struct rwsem_waiter waiter;
	struct task_struct *tsk;
	unsigned long flags;

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	if (sem->activity >= 0 && list_empty(&sem->wait_list)) {
		/* granted */
		sem->activity++;
		raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
		goto out;
	}

	tsk = current;
	set_task_state(tsk, TASK_UNINTERRUPTIBLE);

	/* set up my own style of waitqueue */
	waiter.task = tsk;
	waiter.type = RWSEM_WAITING_FOR_READ;
	get_task_struct(tsk);

	list_add_tail(&waiter.list, &sem->wait_list);

	/* we don't need to touch the semaphore struct anymore */
	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);

	/* wait to be given the lock */
	for (;;) {
		if (!waiter.task)
			break;
		schedule();
		set_task_state(tsk, TASK_UNINTERRUPTIBLE);
	}

	tsk->state = TASK_RUNNING;
 out:
	;
}

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
int __down_read_trylock(struct rw_semaphore *sem)
{
	unsigned long flags;
	int ret = 0;


	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	if (sem->activity >= 0 && list_empty(&sem->wait_list)) {
		/* granted */
		sem->activity++;
		ret = 1;
	}

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);

	return ret;
}

/*
 * get a write lock on the semaphore
 */
// ARM10C 20151121
// sem: &(kmem_cache#25-oX (struct super_block))->s_umount, 0
void __sched __down_write_nested(struct rw_semaphore *sem, int subclass)
{
	struct rwsem_waiter waiter;
	struct task_struct *tsk;
	unsigned long flags;

	// &sem->wait_lock: (&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_lock
	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	// raw_spin_lock_irqsave에서 한일:
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_lock 을 사용하여 spin lock 을 수행하고 cpsr을 flags에 저장함

	/* set up my own style of waitqueue */
	// current: &init_task
	tsk = current;
	// tsk: &init_task

	// tsk: &init_task
	waiter.task = tsk;
	// waiter.task: &init_task

	// RWSEM_WAITING_FOR_WRITE: 0
	waiter.type = RWSEM_WAITING_FOR_WRITE;
	// waiter.type: 0

	// &sem->wait_list: &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list
	list_add_tail(&waiter.list, &sem->wait_list);

	// list_add_tail에서 한일:
	// head list 인 &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list에 &waiter.list을 tail로 추가함

	/* wait for someone to release the lock */
	for (;;) {
		/*
		 * That is the key to support write lock stealing: allows the
		 * task already on CPU to get the lock soon rather than put
		 * itself into sleep and waiting for system woke it or someone
		 * else in the head of the wait list up.
		 */
		// sem->activity: (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0
		if (sem->activity == 0)
			break;
			// break 수행

		set_task_state(tsk, TASK_UNINTERRUPTIBLE);
		raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
		schedule();
		raw_spin_lock_irqsave(&sem->wait_lock, flags);
	}
	/* got the lock */
	// sem->activity: (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0
	sem->activity = -1;
	// sem->activity: (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: -1

	list_del(&waiter.list);

	// list_del에서 한일:
	// head list 인 &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list에 추가된 &waiter.list을 삭제함

	// &sem->wait_lock: (&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_lock
	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);

	// raw_spin_lock_irqsave에서 한일:
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_lock 을 사용하여 spin unlock 을 수행하고 flags에 저장된 cpsr을 복원함
}

// ARM10C 20151114
// &(kmem_cache#25-oX (struct super_block))->s_umount
void __sched __down_write(struct rw_semaphore *sem)
{
	// sem: &(kmem_cache#25-oX (struct super_block))->s_umount
	__down_write_nested(sem, 0);

	// __down_write_nested에서 한일:
	// sem->activity: (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: -1
}

/*
 * trylock for writing -- returns 1 if successful, 0 if contention
 */
int __down_write_trylock(struct rw_semaphore *sem)
{
	unsigned long flags;
	int ret = 0;

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	if (sem->activity == 0) {
		/* got the lock */
		sem->activity = -1;
		ret = 1;
	}

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);

	return ret;
}

/*
 * release a read lock on the semaphore
 */
void __up_read(struct rw_semaphore *sem)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	if (--sem->activity == 0 && !list_empty(&sem->wait_list))
		sem = __rwsem_wake_one_writer(sem);

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
}

/*
 * release a write lock on the semaphore
 */
// ARM10C 20151121
// sem: &shrinker_rwsem
void __up_write(struct rw_semaphore *sem)
{
	unsigned long flags;

	// &sem->wait_lock: &(&shrinker_rwsem)->wait_lock
	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	// raw_spin_lock_irqsave에서 한일:
	// &(&shrinker_rwsem)->wait_lock 을 사용하여 spin lock 을 수행하고 cpsr을 flags에 저장함

	// sem->activity: (&shrinker_rwsem)->activity: -1
	sem->activity = 0;
	// sem->activity: (&shrinker_rwsem)->activity: 0

	// &sem->wait_list: &(&shrinker_rwsem)->wait_list
	// list_empty(&(&shrinker_rwsem)->wait_list): 1
	if (!list_empty(&sem->wait_list))
		sem = __rwsem_do_wake(sem, 1);

	// &sem->wait_lock: &(&shrinker_rwsem)->wait_lock
	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);

	// raw_spin_unlock_irqrestore에서 한일:
	// &(&shrinker_rwsem)->wait_lock 을 사용하여 spin unlock 을 수행하고 flags에 저장된 cpsr을 복원함
}

/*
 * downgrade a write lock into a read lock
 * - just wake up any readers at the front of the queue
 */
void __downgrade_write(struct rw_semaphore *sem)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	sem->activity = 1;
	if (!list_empty(&sem->wait_list))
		sem = __rwsem_do_wake(sem, 0);

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
}

