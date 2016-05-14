/*
 * Generic waiting primitives.
 *
 * (C) 2004 Nadia Yvette Chambers, Oracle
 */
#include <linux/init.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/wait.h>
#include <linux/hash.h>

// ARM10C 20140927
// &rsp->gp_wq: &(&rcu_bh_state)->gp_wq, "&rsp->gp_wq", &__key
// ARM10C 20150509
// &desc->wait_for_threads: &(kmem_cache#28-oX (irq 152))->wait_for_threads, "&desc->wait_for_threads", &__key
// ARM10C 20150718
// &port->open_wait: &(&(kmem_cache#25-oX)->port)->open_wait, "&port->open_wait", &__key
// ARM10C 20150718
// &port->close_wait: &(&(kmem_cache#25-oX)->port)->close_wait, "&port->close_wait", &__key
// ARM10C 20150718
// &port->delta_msr_wait: &(&(kmem_cache#25-oX)->port)->delta_msr_wait, "&port->delta_msr_wait", &__key
// ARM10C 20150718
// &vc->paste_wait: &(kmem_cache#25-oX)->paste_wait, "&vc->paste_wait", &__key
// ARM10C 20151114
// &s->s_writers.wait: &(kmem_cache#25-oX (struct super_block))->s_writers.wait, "&s->s_writers.wait", &__key
// ARM10C 20151114
// &s->s_writers.wait_unfrozen: &(kmem_cache#25-oX (struct super_block))->s_writers.wait_unfrozen, "&s->s_writers.wait_unfrozen", &__key
// ARM10C 20160514
// &new_ns->poll: &(kmem_cache#30-oX (struct mnt_namespace))->poll, "&new_ns->poll", &__key
void __init_waitqueue_head(wait_queue_head_t *q, const char *name, struct lock_class_key *key)
{
	// &q->lock: &(&(&rcu_bh_state)->gp_wq)->lock
	// &q->lock: &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->lock
	// &q->lock: &(&(&(kmem_cache#25-oX)->port)->open_wait)->lock
	spin_lock_init(&q->lock);
	// &q->lock: &(&(&rcu_bh_state)->gp_wq)->lock을 사용한 spinlock 초기화
	// &q->lock: &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->lock을 사용한 spinlock 초기화
	// &q->lock: &(&(&(kmem_cache#25-oX)->port)->open_wait)->lock을 사용한 spinlock 초기화

	// &q->lock: &(&(&rcu_bh_state)->gp_wq)->lock, key: &__key, name: "&rsp->gp_wq"
	// &q->lock: &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->lock, key: &__key, name: "&desc->wait_for_threads"
	// &q->lock: &(&(&(kmem_cache#25-oX)->port)->open_wait)->lock, key: &__key, name: "&port->open_wait"
	lockdep_set_class_and_name(&q->lock, key, name); // null function

	// &q->task_list: &(&(&rcu_bh_state)->gp_wq)->task_list
	// &q->task_list: &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->task_list
	// &q->task_list: &(&(&(kmem_cache#25-oX)->port)->open_wait)->task_list
	INIT_LIST_HEAD(&q->task_list);
	// &q->task_list: &(&(&rcu_bh_state)->gp_wq)->task_list를 사용한 list 초기화
	// &q->task_list: &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->task_list를 사용한 list 초기화
	// &q->task_list: &(&(&(kmem_cache#25-oX)->port)->open_wait)->task_list를 사용한 list 초기화
}

EXPORT_SYMBOL(__init_waitqueue_head);

void add_wait_queue(wait_queue_head_t *q, wait_queue_t *wait)
{
	unsigned long flags;

	wait->flags &= ~WQ_FLAG_EXCLUSIVE;
	spin_lock_irqsave(&q->lock, flags);
	__add_wait_queue(q, wait);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL(add_wait_queue);

void add_wait_queue_exclusive(wait_queue_head_t *q, wait_queue_t *wait)
{
	unsigned long flags;

	wait->flags |= WQ_FLAG_EXCLUSIVE;
	spin_lock_irqsave(&q->lock, flags);
	__add_wait_queue_tail(q, wait);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL(add_wait_queue_exclusive);

void remove_wait_queue(wait_queue_head_t *q, wait_queue_t *wait)
{
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	__remove_wait_queue(q, wait);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL(remove_wait_queue);


/*
 * The core wakeup function. Non-exclusive wakeups (nr_exclusive == 0) just
 * wake everything up. If it's an exclusive wakeup (nr_exclusive == small +ve
 * number) then we wake all the non-exclusive tasks and one exclusive task.
 *
 * There are circumstances in which we can try to wake a task which has already
 * started to run but is not in state TASK_RUNNING. try_to_wake_up() returns
 * zero in this (rare) case, and we handle it by continuing to scan the queue.
 */
// ARM10C 20160409
// q: &running_helpers_waitq, mode: 3, nr_exclusive: 1, 0, key: NULL
static void __wake_up_common(wait_queue_head_t *q, unsigned int mode,
			int nr_exclusive, int wake_flags, void *key)
{
	wait_queue_t *curr, *next;

	// &q->task_list: &(&running_helpers_waitq)->task_list
	// list_first_entry(&(&running_helpers_waitq)->task_list, typeof(*curr), task_list): &running_helpers_waitq
	// curr: &running_helpers_waitq, list_next_entry(&running_helpers_waitq, task_list): &running_helpers_waitq
	list_for_each_entry_safe(curr, next, &q->task_list, task_list) {
	// for (curr = list_first_entry(&(&running_helpers_waitq)->task_list, typeof(*curr), task_list),
	//      next = list_next_entry(curr, task_list); &curr->task_list != (&(&running_helpers_waitq)->task_list);
	//      curr = next, next = list_next_entry(next, task_list))

		unsigned flags = curr->flags;

		if (curr->func(curr, mode, wake_flags, key) &&
				(flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive)
			break;
	}
}

/**
 * __wake_up - wake up threads blocked on a waitqueue.
 * @q: the waitqueue
 * @mode: which threads
 * @nr_exclusive: how many wake-one or wake-many threads to wake up
 * @key: is directly passed to the wakeup function
 *
 * It may be assumed that this function implies a write memory barrier before
 * changing the task state if and only if any tasks are woken up.
 */
// ARM10C 20160409
// &running_helpers_waitq, TASK_NORMAL: 3, 1, NULL
void __wake_up(wait_queue_head_t *q, unsigned int mode,
			int nr_exclusive, void *key)
{
	unsigned long flags;

	// &q->lock: &(&running_helpers_waitq)->lock
	spin_lock_irqsave(&q->lock, flags);

	// spin_lock_irqsave 에서 한일:
	// &(&running_helpers_waitq)->lock 을 사용하여 spin lock을 수행 하고 cpsr을 flags에 저장함

	// q: &running_helpers_waitq, mode: 3, nr_exclusive: 1, key: NULL
	__wake_up_common(q, mode, nr_exclusive, 0, key);

	// __wake_up_common 에서 한일:
	// &running_helpers_waitq의 tasklist에 등록된 task가 없어서 수행한 일이 없음

	// &q->lock: &(&running_helpers_waitq)->lock
	spin_unlock_irqrestore(&q->lock, flags);

	// spin_unlock_irqrestore 에서 한일:
	// &(&running_helpers_waitq)->lock 을 사용하여 spin unlock을 수행 하고 flags에 저장된 cpsr을 복원함
}
EXPORT_SYMBOL(__wake_up);

/*
 * Same as __wake_up but called with the spinlock in wait_queue_head_t held.
 */
void __wake_up_locked(wait_queue_head_t *q, unsigned int mode, int nr)
{
	__wake_up_common(q, mode, nr, 0, NULL);
}
EXPORT_SYMBOL_GPL(__wake_up_locked);

void __wake_up_locked_key(wait_queue_head_t *q, unsigned int mode, void *key)
{
	__wake_up_common(q, mode, 1, 0, key);
}
EXPORT_SYMBOL_GPL(__wake_up_locked_key);

/**
 * __wake_up_sync_key - wake up threads blocked on a waitqueue.
 * @q: the waitqueue
 * @mode: which threads
 * @nr_exclusive: how many wake-one or wake-many threads to wake up
 * @key: opaque value to be passed to wakeup targets
 *
 * The sync wakeup differs that the waker knows that it will schedule
 * away soon, so while the target thread will be woken up, it will not
 * be migrated to another CPU - ie. the two threads are 'synchronized'
 * with each other. This can prevent needless bouncing between CPUs.
 *
 * On UP it can prevent extra preemption.
 *
 * It may be assumed that this function implies a write memory barrier before
 * changing the task state if and only if any tasks are woken up.
 */
void __wake_up_sync_key(wait_queue_head_t *q, unsigned int mode,
			int nr_exclusive, void *key)
{
	unsigned long flags;
	int wake_flags = 1; /* XXX WF_SYNC */

	if (unlikely(!q))
		return;

	if (unlikely(nr_exclusive != 1))
		wake_flags = 0;

	spin_lock_irqsave(&q->lock, flags);
	__wake_up_common(q, mode, nr_exclusive, wake_flags, key);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL_GPL(__wake_up_sync_key);

/*
 * __wake_up_sync - see __wake_up_sync_key()
 */
void __wake_up_sync(wait_queue_head_t *q, unsigned int mode, int nr_exclusive)
{
	__wake_up_sync_key(q, mode, nr_exclusive, NULL);
}
EXPORT_SYMBOL_GPL(__wake_up_sync);	/* For internal use only */

/*
 * Note: we use "set_current_state()" _after_ the wait-queue add,
 * because we need a memory barrier there on SMP, so that any
 * wake-function that tests for the wait-queue being active
 * will be guaranteed to see waitqueue addition _or_ subsequent
 * tests in this thread will see the wakeup having taken place.
 *
 * The spin_unlock() itself is semi-permeable and only protects
 * one way (it only protects stuff inside the critical region and
 * stops them from bleeding out - it would still allow subsequent
 * loads to move into the critical region).
 */
void
prepare_to_wait(wait_queue_head_t *q, wait_queue_t *wait, int state)
{
	unsigned long flags;

	wait->flags &= ~WQ_FLAG_EXCLUSIVE;
	spin_lock_irqsave(&q->lock, flags);
	if (list_empty(&wait->task_list))
		__add_wait_queue(q, wait);
	set_current_state(state);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL(prepare_to_wait);

void
prepare_to_wait_exclusive(wait_queue_head_t *q, wait_queue_t *wait, int state)
{
	unsigned long flags;

	wait->flags |= WQ_FLAG_EXCLUSIVE;
	spin_lock_irqsave(&q->lock, flags);
	if (list_empty(&wait->task_list))
		__add_wait_queue_tail(q, wait);
	set_current_state(state);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL(prepare_to_wait_exclusive);

long prepare_to_wait_event(wait_queue_head_t *q, wait_queue_t *wait, int state)
{
	unsigned long flags;

	if (signal_pending_state(state, current))
		return -ERESTARTSYS;

	wait->private = current;
	wait->func = autoremove_wake_function;

	spin_lock_irqsave(&q->lock, flags);
	if (list_empty(&wait->task_list)) {
		if (wait->flags & WQ_FLAG_EXCLUSIVE)
			__add_wait_queue_tail(q, wait);
		else
			__add_wait_queue(q, wait);
	}
	set_current_state(state);
	spin_unlock_irqrestore(&q->lock, flags);

	return 0;
}
EXPORT_SYMBOL(prepare_to_wait_event);

/**
 * finish_wait - clean up after waiting in a queue
 * @q: waitqueue waited on
 * @wait: wait descriptor
 *
 * Sets current thread back to running state and removes
 * the wait descriptor from the given waitqueue if still
 * queued.
 */
void finish_wait(wait_queue_head_t *q, wait_queue_t *wait)
{
	unsigned long flags;

	__set_current_state(TASK_RUNNING);
	/*
	 * We can check for list emptiness outside the lock
	 * IFF:
	 *  - we use the "careful" check that verifies both
	 *    the next and prev pointers, so that there cannot
	 *    be any half-pending updates in progress on other
	 *    CPU's that we haven't seen yet (and that might
	 *    still change the stack area.
	 * and
	 *  - all other users take the lock (ie we can only
	 *    have _one_ other CPU that looks at or modifies
	 *    the list).
	 */
	if (!list_empty_careful(&wait->task_list)) {
		spin_lock_irqsave(&q->lock, flags);
		list_del_init(&wait->task_list);
		spin_unlock_irqrestore(&q->lock, flags);
	}
}
EXPORT_SYMBOL(finish_wait);

/**
 * abort_exclusive_wait - abort exclusive waiting in a queue
 * @q: waitqueue waited on
 * @wait: wait descriptor
 * @mode: runstate of the waiter to be woken
 * @key: key to identify a wait bit queue or %NULL
 *
 * Sets current thread back to running state and removes
 * the wait descriptor from the given waitqueue if still
 * queued.
 *
 * Wakes up the next waiter if the caller is concurrently
 * woken up through the queue.
 *
 * This prevents waiter starvation where an exclusive waiter
 * aborts and is woken up concurrently and no one wakes up
 * the next waiter.
 */
void abort_exclusive_wait(wait_queue_head_t *q, wait_queue_t *wait,
			unsigned int mode, void *key)
{
	unsigned long flags;

	__set_current_state(TASK_RUNNING);
	spin_lock_irqsave(&q->lock, flags);
	if (!list_empty(&wait->task_list))
		list_del_init(&wait->task_list);
	else if (waitqueue_active(q))
		__wake_up_locked_key(q, mode, key);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL(abort_exclusive_wait);

int autoremove_wake_function(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	int ret = default_wake_function(wait, mode, sync, key);

	if (ret)
		list_del_init(&wait->task_list);
	return ret;
}
EXPORT_SYMBOL(autoremove_wake_function);

int wake_bit_function(wait_queue_t *wait, unsigned mode, int sync, void *arg)
{
	struct wait_bit_key *key = arg;
	struct wait_bit_queue *wait_bit
		= container_of(wait, struct wait_bit_queue, wait);

	if (wait_bit->key.flags != key->flags ||
			wait_bit->key.bit_nr != key->bit_nr ||
			test_bit(key->bit_nr, key->flags))
		return 0;
	else
		return autoremove_wake_function(wait, mode, sync, key);
}
EXPORT_SYMBOL(wake_bit_function);

/*
 * To allow interruptible waiting and asynchronous (i.e. nonblocking)
 * waiting, the actions of __wait_on_bit() and __wait_on_bit_lock() are
 * permitted return codes. Nonzero return codes halt waiting and return.
 */
int __sched
__wait_on_bit(wait_queue_head_t *wq, struct wait_bit_queue *q,
			int (*action)(void *), unsigned mode)
{
	int ret = 0;

	do {
		prepare_to_wait(wq, &q->wait, mode);
		if (test_bit(q->key.bit_nr, q->key.flags))
			ret = (*action)(q->key.flags);
	} while (test_bit(q->key.bit_nr, q->key.flags) && !ret);
	finish_wait(wq, &q->wait);
	return ret;
}
EXPORT_SYMBOL(__wait_on_bit);

int __sched out_of_line_wait_on_bit(void *word, int bit,
					int (*action)(void *), unsigned mode)
{
	wait_queue_head_t *wq = bit_waitqueue(word, bit);
	DEFINE_WAIT_BIT(wait, word, bit);

	return __wait_on_bit(wq, &wait, action, mode);
}
EXPORT_SYMBOL(out_of_line_wait_on_bit);

int __sched
__wait_on_bit_lock(wait_queue_head_t *wq, struct wait_bit_queue *q,
			int (*action)(void *), unsigned mode)
{
	do {
		int ret;

		prepare_to_wait_exclusive(wq, &q->wait, mode);
		if (!test_bit(q->key.bit_nr, q->key.flags))
			continue;
		ret = action(q->key.flags);
		if (!ret)
			continue;
		abort_exclusive_wait(wq, &q->wait, mode, &q->key);
		return ret;
	} while (test_and_set_bit(q->key.bit_nr, q->key.flags));
	finish_wait(wq, &q->wait);
	return 0;
}
EXPORT_SYMBOL(__wait_on_bit_lock);

int __sched out_of_line_wait_on_bit_lock(void *word, int bit,
					int (*action)(void *), unsigned mode)
{
	wait_queue_head_t *wq = bit_waitqueue(word, bit);
	DEFINE_WAIT_BIT(wait, word, bit);

	return __wait_on_bit_lock(wq, &wait, action, mode);
}
EXPORT_SYMBOL(out_of_line_wait_on_bit_lock);

// ARM10C 20151212
// bit_waitqueue(&(kmem_cache#4-oX)->i_state, 3): &(&(kmem_cache#4-oX)->i_state의 zone의 주소)->wait_table[계산된 hash index 값],
// word: &(kmem_cache#4-oX)->i_state, bit: 3
void __wake_up_bit(wait_queue_head_t *wq, void *word, int bit)
{
	// word: &(kmem_cache#4-oX)->i_state, bit: 3
	// __WAIT_BIT_KEY_INITIALIZER(&(kmem_cache#4-oX)->i_state, 3):
	// { .flags = &(kmem_cache#4-oX)->i_state, .bit_nr = 3, }
	struct wait_bit_key key = __WAIT_BIT_KEY_INITIALIZER(word, bit);

	// __WAIT_BIT_KEY_INITIALIZER에서 한읾:
	// key.flags: &(kmem_cache#4-oX)->i_state
	// key.bit_nr: 3

	// wq: &(&(kmem_cache#4-oX)->i_state의 zone의 주소)->wait_table[계산된 hash index 값]
	//i waitqueue_active(&(&(kmem_cache#4-oX)->i_state의 zone의 주소)->wait_table[계산된 hash index 값]): 0
	if (waitqueue_active(wq))
		__wake_up(wq, TASK_NORMAL, 1, &key);
}
EXPORT_SYMBOL(__wake_up_bit);

/**
 * wake_up_bit - wake up a waiter on a bit
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 *
 * There is a standard hashed waitqueue table for generic use. This
 * is the part of the hashtable's accessor API that wakes up waiters
 * on a bit. For instance, if one were to have waiters on a bitflag,
 * one would call wake_up_bit() after clearing the bit.
 *
 * In order for this to function properly, as it uses waitqueue_active()
 * internally, some kind of memory barrier must be done prior to calling
 * this. Typically, this will be smp_mb__after_clear_bit(), but in some
 * cases where bitflags are manipulated non-atomically under a lock, one
 * may need to use a less regular barrier, such fs/inode.c's smp_mb(),
 * because spin_unlock() does not guarantee a memory barrier.
 */
// ARM10C 20151212
// &inode->i_state: &(kmem_cache#4-oX)->i_state: 0x0, __I_NEW: 3
void wake_up_bit(void *word, int bit)
{
	// word: &(kmem_cache#4-oX)->i_state, bit: 3
	// bit_waitqueue(&(kmem_cache#4-oX)->i_state, 3): &(&(kmem_cache#4-oX)->i_state의 zone의 주소)->wait_table[계산된 hash index 값]
	__wake_up_bit(bit_waitqueue(word, bit), word, bit);
}
EXPORT_SYMBOL(wake_up_bit);

// ARM10C 20151212
// word: &(kmem_cache#4-oX)->i_state, bit: 3
wait_queue_head_t *bit_waitqueue(void *word, int bit)
{
	// BITS_PER_LONG: 32
	const int shift = BITS_PER_LONG == 32 ? 5 : 6;
	// shift: 5

	// word: &(kmem_cache#4-oX)->i_state
	// virt_to_page(&(kmem_cache#4-oX)->i_state): &(kmem_cache#4-oX)->i_state의 page 주소
	// page_zone(&(kmem_cache#4-oX)->i_state의 page 주소): &(kmem_cache#4-oX)->i_state의 zone의 주소
	const struct zone *zone = page_zone(virt_to_page(word));
	// zone: &(kmem_cache#4-oX)->i_state의 zone의 주소

	// word: &(kmem_cache#4-oX)->i_state, shift: 5, bit: 3
	unsigned long val = (unsigned long)word << shift | bit;
	// val: &(kmem_cache#4-oX)->i_state 값을 이용한 hash val 값

	// val: &(kmem_cache#4-oX)->i_state 값을 이용한 hash val 값,
	// zone->wait_table_bits: (&(kmem_cache#4-oX)->i_state의 zone의 주소)->wait_table_bits
	// hash_long(&(kmem_cache#4-oX)->i_state 값을 이용한 hash val 값,
	// (&(kmem_cache#4-oX)->i_state의 zone의 주소)->wait_table_bits): 계산된 hash index 값
	// &zone->wait_table[계산된 hash index 값]: &(&(kmem_cache#4-oX)->i_state의 zone의 주소)->wait_table[계산된 hash index 값]
	return &zone->wait_table[hash_long(val, zone->wait_table_bits)];
	// return &(&(kmem_cache#4-oX)->i_state의 zone의 주소)->wait_table[계산된 hash index 값]
}
EXPORT_SYMBOL(bit_waitqueue);

/*
 * Manipulate the atomic_t address to produce a better bit waitqueue table hash
 * index (we're keying off bit -1, but that would produce a horrible hash
 * value).
 */
static inline wait_queue_head_t *atomic_t_waitqueue(atomic_t *p)
{
	if (BITS_PER_LONG == 64) {
		unsigned long q = (unsigned long)p;
		return bit_waitqueue((void *)(q & ~1), q & 1);
	}
	return bit_waitqueue(p, 0);
}

static int wake_atomic_t_function(wait_queue_t *wait, unsigned mode, int sync,
				  void *arg)
{
	struct wait_bit_key *key = arg;
	struct wait_bit_queue *wait_bit
		= container_of(wait, struct wait_bit_queue, wait);
	atomic_t *val = key->flags;

	if (wait_bit->key.flags != key->flags ||
	    wait_bit->key.bit_nr != key->bit_nr ||
	    atomic_read(val) != 0)
		return 0;
	return autoremove_wake_function(wait, mode, sync, key);
}

/*
 * To allow interruptible waiting and asynchronous (i.e. nonblocking) waiting,
 * the actions of __wait_on_atomic_t() are permitted return codes.  Nonzero
 * return codes halt waiting and return.
 */
static __sched
int __wait_on_atomic_t(wait_queue_head_t *wq, struct wait_bit_queue *q,
		       int (*action)(atomic_t *), unsigned mode)
{
	atomic_t *val;
	int ret = 0;

	do {
		prepare_to_wait(wq, &q->wait, mode);
		val = q->key.flags;
		if (atomic_read(val) == 0)
			break;
		ret = (*action)(val);
	} while (!ret && atomic_read(val) != 0);
	finish_wait(wq, &q->wait);
	return ret;
}

#define DEFINE_WAIT_ATOMIC_T(name, p)					\
	struct wait_bit_queue name = {					\
		.key = __WAIT_ATOMIC_T_KEY_INITIALIZER(p),		\
		.wait	= {						\
			.private	= current,			\
			.func		= wake_atomic_t_function,	\
			.task_list	=				\
				LIST_HEAD_INIT((name).wait.task_list),	\
		},							\
	}

__sched int out_of_line_wait_on_atomic_t(atomic_t *p, int (*action)(atomic_t *),
					 unsigned mode)
{
	wait_queue_head_t *wq = atomic_t_waitqueue(p);
	DEFINE_WAIT_ATOMIC_T(wait, p);

	return __wait_on_atomic_t(wq, &wait, action, mode);
}
EXPORT_SYMBOL(out_of_line_wait_on_atomic_t);

/**
 * wake_up_atomic_t - Wake up a waiter on a atomic_t
 * @p: The atomic_t being waited on, a kernel virtual address
 *
 * Wake up anyone waiting for the atomic_t to go to zero.
 *
 * Abuse the bit-waker function and its waitqueue hash table set (the atomic_t
 * check is done by the waiter's wake function, not the by the waker itself).
 */
void wake_up_atomic_t(atomic_t *p)
{
	__wake_up_bit(atomic_t_waitqueue(p), p, WAIT_ATOMIC_T_BIT_NR);
}
EXPORT_SYMBOL(wake_up_atomic_t);
