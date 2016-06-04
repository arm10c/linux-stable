#include <linux/kdebug.h>
#include <linux/kprobes.h>
#include <linux/export.h>
#include <linux/notifier.h>
#include <linux/rcupdate.h>
#include <linux/vmalloc.h>
#include <linux/reboot.h>

/*
 *	Notifier list for kernel code which wants to be called
 *	at shutdown. This is used to stop any idling DMA operations
 *	and the like.
 */
BLOCKING_NOTIFIER_HEAD(reboot_notifier_list);

/*
 *	Notifier chain core routines.  The exported routines below
 *	are layered on top of these, with appropriate locking added.
 */

// ARM10C 20140322
// *nl: (&cpu_chain)->head: NULL, n: &page_alloc_cpu_notify_nb
// ARM10C 20140726
// nh->head: (&cpu_chain)->head: &page_alloc_cpu_notify_nb, n: &slab_notifier
// ARM10C 20140927
// &nh->head: (&pm_chain_head)->head: NULL, n: &rcu_pm_notify_nb
// ARM10C 20141129
// ARM10C 20150103
// ARM10C 20150404
// ARM10C 20150620
// ARM10C 20151003
// ARM10C 20160604
static int notifier_chain_register(struct notifier_block **nl,
		struct notifier_block *n)
{
	// *nl: (&cpu_chain)->head: NULL
	// *nl: (&cpu_chain)->head: &page_alloc_cpu_notify_nb
	// *nl: (&pm_chain_head)->head: NULL
	while ((*nl) != NULL) {
		// (*nl)->priority: (&page_alloc_cpu_notify_nb)->priority: 0,
		// (*n)->priority: (&slab_notifier)->priority: 0
		if (n->priority > (*nl)->priority)
			break;

		// &((*nl)->next): &((&page_alloc_cpu_notify_nb)->next)
		nl = &((*nl)->next);
		// nl: &((&page_alloc_cpu_notify_nb)->next)
	}

	// n->next: (&page_alloc_cpu_notify_nb)->next, *nl: (&cpu_chain)->head: NULL
	// n->next: (&slab_notifier)->next, *nl: (&page_alloc_cpu_notify_nb)->next
	// n->next: (&rcu_pm_notify_nb)->next, *nl: (&pm_chain_head)->head: NULL
	n->next = *nl;
	// n->next: (&page_alloc_cpu_notify_nb)->next: NULL
	// n->next: (&slab_notifier)->next: (&page_alloc_cpu_notify_nb)->next
	// n->next: (&rcu_pm_notify_nb)->next: NULL

	// *nl: (&cpu_chain)->head: NULL, n: &page_alloc_cpu_notify_nb
	// *nl: (&cpu_chain)->head: &page_alloc_cpu_notify_nb, n: &slab_notifier
	// *nl: (&pm_chain_head)->head: NULL, n: &rcu_pm_notify_nb
	rcu_assign_pointer(*nl, n);
	// (&cpu_chain)->head: page_alloc_cpu_notifier_nb 포인터 대입
	// (&cpu_chain)->head: slab_notifier 포인터 대입
	// (&pm_chain_head)->head: rcu_pm_notify_nb 포인터 대입

	return 0;
	// return 0
}

static int notifier_chain_cond_register(struct notifier_block **nl,
		struct notifier_block *n)
{
	while ((*nl) != NULL) {
		if ((*nl) == n)
			return 0;
		if (n->priority > (*nl)->priority)
			break;
		nl = &((*nl)->next);
	}
	n->next = *nl;
	rcu_assign_pointer(*nl, n);
	return 0;
}

static int notifier_chain_unregister(struct notifier_block **nl,
		struct notifier_block *n)
{
	while ((*nl) != NULL) {
		if ((*nl) == n) {
			rcu_assign_pointer(*nl, n->next);
			return 0;
		}
		nl = &((*nl)->next);
	}
	return -ENOENT;
}

/**
 * notifier_call_chain - Informs the registered notifiers about an event.
 *	@nl:		Pointer to head of the blocking notifier chain
 *	@val:		Value passed unmodified to notifier function
 *	@v:		Pointer passed unmodified to notifier function
 *	@nr_to_call:	Number of notifier functions to be called. Don't care
 *			value of this parameter is -1.
 *	@nr_calls:	Records the number of notifications sent. Don't care
 *			value of this field is NULL.
 *	@returns:	notifier_call_chain returns the value returned by the
 *			last notifier function called.
 */
static int __kprobes notifier_call_chain(struct notifier_block **nl,
					unsigned long val, void *v,
					int nr_to_call,	int *nr_calls)
{
	int ret = NOTIFY_DONE;
	struct notifier_block *nb, *next_nb;

	nb = rcu_dereference_raw(*nl);

	while (nb && nr_to_call) {
		next_nb = rcu_dereference_raw(nb->next);

#ifdef CONFIG_DEBUG_NOTIFIERS
		if (unlikely(!func_ptr_is_kernel_text(nb->notifier_call))) {
			WARN(1, "Invalid notifier called!");
			nb = next_nb;
			continue;
		}
#endif
		ret = nb->notifier_call(nb, val, v);

		if (nr_calls)
			(*nr_calls)++;

		if ((ret & NOTIFY_STOP_MASK) == NOTIFY_STOP_MASK)
			break;
		nb = next_nb;
		nr_to_call--;
	}
	return ret;
}

/*
 *	Atomic notifier chain routines.  Registration and unregistration
 *	use a spinlock, and call_chain is synchronized by RCU (no locks).
 */

/**
 *	atomic_notifier_chain_register - Add notifier to an atomic notifier chain
 *	@nh: Pointer to head of the atomic notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to an atomic notifier chain.
 *
 *	Currently always returns zero.
 */
int atomic_notifier_chain_register(struct atomic_notifier_head *nh,
		struct notifier_block *n)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&nh->lock, flags);
	ret = notifier_chain_register(&nh->head, n);
	spin_unlock_irqrestore(&nh->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(atomic_notifier_chain_register);

/**
 *	atomic_notifier_chain_unregister - Remove notifier from an atomic notifier chain
 *	@nh: Pointer to head of the atomic notifier chain
 *	@n: Entry to remove from notifier chain
 *
 *	Removes a notifier from an atomic notifier chain.
 *
 *	Returns zero on success or %-ENOENT on failure.
 */
int atomic_notifier_chain_unregister(struct atomic_notifier_head *nh,
		struct notifier_block *n)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&nh->lock, flags);
	ret = notifier_chain_unregister(&nh->head, n);
	spin_unlock_irqrestore(&nh->lock, flags);
	synchronize_rcu();
	return ret;
}
EXPORT_SYMBOL_GPL(atomic_notifier_chain_unregister);

/**
 *	__atomic_notifier_call_chain - Call functions in an atomic notifier chain
 *	@nh: Pointer to head of the atomic notifier chain
 *	@val: Value passed unmodified to notifier function
 *	@v: Pointer passed unmodified to notifier function
 *	@nr_to_call: See the comment for notifier_call_chain.
 *	@nr_calls: See the comment for notifier_call_chain.
 *
 *	Calls each function in a notifier chain in turn.  The functions
 *	run in an atomic context, so they must not block.
 *	This routine uses RCU to synchronize with changes to the chain.
 *
 *	If the return value of the notifier can be and'ed
 *	with %NOTIFY_STOP_MASK then atomic_notifier_call_chain()
 *	will return immediately, with the return value of
 *	the notifier function which halted execution.
 *	Otherwise the return value is the return value
 *	of the last notifier function called.
 */
int __kprobes __atomic_notifier_call_chain(struct atomic_notifier_head *nh,
					unsigned long val, void *v,
					int nr_to_call, int *nr_calls)
{
	int ret;

	rcu_read_lock();
	ret = notifier_call_chain(&nh->head, val, v, nr_to_call, nr_calls);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(__atomic_notifier_call_chain);

int __kprobes atomic_notifier_call_chain(struct atomic_notifier_head *nh,
		unsigned long val, void *v)
{
	return __atomic_notifier_call_chain(nh, val, v, -1, NULL);
}
EXPORT_SYMBOL_GPL(atomic_notifier_call_chain);

/*
 *	Blocking notifier chain routines.  All access to the chain is
 *	synchronized by an rwsem.
 */

/**
 *	blocking_notifier_chain_register - Add notifier to a blocking notifier chain
 *	@nh: Pointer to head of the blocking notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to a blocking notifier chain.
 *	Must be called in process context.
 *
 *	Currently always returns zero.
 */
// ARM10C 20140927
// &pm_chain_head, nb: &rcu_pm_notify_nb
int blocking_notifier_chain_register(struct blocking_notifier_head *nh,
		struct notifier_block *n)
{
	int ret;

	/*
	 * This code gets used during boot-up, when task switching is
	 * not yet working and interrupts must remain disabled.  At
	 * such times we must not call down_write().
	 */
	// system_state: 0, SYSTEM_BOOTING: 0
	if (unlikely(system_state == SYSTEM_BOOTING))
		// &nh->head: (&pm_chain_head)->head: NULL, n: &rcu_pm_notify_nb
		// notifier_chain_register((&pm_chain_head)->head, &rcu_pm_notify_nb): 0
		return notifier_chain_register(&nh->head, n);
		// notifier_chain_register에서 한일:
		// (&pm_chain_head)->head: rcu_pm_notify_nb 포인터 대입
		// n->next: (&rcu_pm_notify_nb)->next: NULL

	down_write(&nh->rwsem);
	ret = notifier_chain_register(&nh->head, n);
	up_write(&nh->rwsem);
	return ret;
}
EXPORT_SYMBOL_GPL(blocking_notifier_chain_register);

/**
 *	blocking_notifier_chain_cond_register - Cond add notifier to a blocking notifier chain
 *	@nh: Pointer to head of the blocking notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to a blocking notifier chain, only if not already
 *	present in the chain.
 *	Must be called in process context.
 *
 *	Currently always returns zero.
 */
int blocking_notifier_chain_cond_register(struct blocking_notifier_head *nh,
		struct notifier_block *n)
{
	int ret;

	down_write(&nh->rwsem);
	ret = notifier_chain_cond_register(&nh->head, n);
	up_write(&nh->rwsem);
	return ret;
}
EXPORT_SYMBOL_GPL(blocking_notifier_chain_cond_register);

/**
 *	blocking_notifier_chain_unregister - Remove notifier from a blocking notifier chain
 *	@nh: Pointer to head of the blocking notifier chain
 *	@n: Entry to remove from notifier chain
 *
 *	Removes a notifier from a blocking notifier chain.
 *	Must be called from process context.
 *
 *	Returns zero on success or %-ENOENT on failure.
 */
int blocking_notifier_chain_unregister(struct blocking_notifier_head *nh,
		struct notifier_block *n)
{
	int ret;

	/*
	 * This code gets used during boot-up, when task switching is
	 * not yet working and interrupts must remain disabled.  At
	 * such times we must not call down_write().
	 */
	if (unlikely(system_state == SYSTEM_BOOTING))
		return notifier_chain_unregister(&nh->head, n);

	down_write(&nh->rwsem);
	ret = notifier_chain_unregister(&nh->head, n);
	up_write(&nh->rwsem);
	return ret;
}
EXPORT_SYMBOL_GPL(blocking_notifier_chain_unregister);

/**
 *	__blocking_notifier_call_chain - Call functions in a blocking notifier chain
 *	@nh: Pointer to head of the blocking notifier chain
 *	@val: Value passed unmodified to notifier function
 *	@v: Pointer passed unmodified to notifier function
 *	@nr_to_call: See comment for notifier_call_chain.
 *	@nr_calls: See comment for notifier_call_chain.
 *
 *	Calls each function in a notifier chain in turn.  The functions
 *	run in a process context, so they are allowed to block.
 *
 *	If the return value of the notifier can be and'ed
 *	with %NOTIFY_STOP_MASK then blocking_notifier_call_chain()
 *	will return immediately, with the return value of
 *	the notifier function which halted execution.
 *	Otherwise the return value is the return value
 *	of the last notifier function called.
 */
int __blocking_notifier_call_chain(struct blocking_notifier_head *nh,
				   unsigned long val, void *v,
				   int nr_to_call, int *nr_calls)
{
	int ret = NOTIFY_DONE;

	/*
	 * We check the head outside the lock, but if this access is
	 * racy then it does not matter what the result of the test
	 * is, we re-check the list after having taken the lock anyway:
	 */
	if (rcu_dereference_raw(nh->head)) {
		down_read(&nh->rwsem);
		ret = notifier_call_chain(&nh->head, val, v, nr_to_call,
					nr_calls);
		up_read(&nh->rwsem);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(__blocking_notifier_call_chain);

int blocking_notifier_call_chain(struct blocking_notifier_head *nh,
		unsigned long val, void *v)
{
	return __blocking_notifier_call_chain(nh, val, v, -1, NULL);
}
EXPORT_SYMBOL_GPL(blocking_notifier_call_chain);

/*
 *	Raw notifier chain routines.  There is no protection;
 *	the caller must provide it.  Use at your own risk!
 */

/**
 *	raw_notifier_chain_register - Add notifier to a raw notifier chain
 *	@nh: Pointer to head of the raw notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to a raw notifier chain.
 *	All locking must be provided by the caller.
 *
 *	Currently always returns zero.
 */
// ARM10C 20140322
// nh: &cpu_chain, n: &page_alloc_cpu_notify_nb
// ARM10C 20140726
// &cpu_chain, nb: &slab_notifier
// ARM10C 20140920
// &cpu_chain, nb: &sched_ilb_notifier_nb
// ARM10C 20140927
// &cpu_chain, nb: &rcu_cpu_notify_nb
// ARM10C 20141004
// &cpu_chain, nb: &radix_tree_callback_nb
// ARM10C 20141129
// &cpu_chain, nb: &gic_cpu_notifier
// ARM10C 20141129
// &cpu_pm_notifier_chain, nb: &gic_notifier_block
// ARM10C 20150103
// &cpu_chain, nb: &timers_nb
// ARM10C 20150103
// &cpu_chain, nb: &hrtimers_nb
// ARM10C 20150404
// &cpu_chain, nb: &exynos4_mct_cpu_nb
// ARM10C 20150620
// &cpu_chain, nb: &hotplug_cfd_notifier
// ARM10C 20151003
// &cpu_chain, nb: &buffer_cpu_notify_nb
// ARM10C 20160604
// &cpu_chain, nb: &ratelimit_nb
int raw_notifier_chain_register(struct raw_notifier_head *nh,
		struct notifier_block *n)
{
	// nh->head: (&cpu_chain)->head: NULL, n: &page_alloc_cpu_notify_nb
	// notifier_chain_register(NULL, &page_alloc_cpu_notify_nb): 0
	// nh->head: (&cpu_chain)->head: &page_alloc_cpu_notify_nb, n: &slab_notifier
	// notifier_chain_register(&page_alloc_cpu_notify_nb, &slab_notifier): 0
	// nh->head: (&cpu_chain)->head: &slab_notifier, n: &sched_ilb_notifier_nb
	// notifier_chain_register(&slab_notifier, &page_alloc_cpu_notify_nb): 0
	// nh->head: (&cpu_chain)->head: &sched_ilb_notifier_nb, n: &rcu_cpu_notify_nb
	// notifier_chain_register(&sched_ilb_notifier_nb, &rcu_cpu_notify_nb): 0
	// nh->head: (&cpu_chain)->head: &rcu_cpu_notify_nb, n: &radix_tree_callback_nb
	// notifier_chain_register(&rcu_cpu_notify_nb, &radix_tree_callback_nb): 0
	// nh->head: (&cpu_chain)->head: &radix_tree_callback_nb, n: &gic_cpu_notifier
	// notifier_chain_register(&radix_tree_callback_nb, &gic_cpu_notifier): 0
	// nh->head: (&cpu_pm_notifier_chain)->head: NULL, n: &gic_notifier_block
	// notifier_chain_register(NULL, &gic_notifier_block): 0
	// nh->head: (&cpu_chain)->head: &gic_cpu_notifier, n: &timers_nb
	// notifier_chain_register(&gic_cpu_notifier, &timers_nb): 0
	// nh->head: (&cpu_chain)->head: &timers_nb, n: &hrtimers_nb
	// notifier_chain_register(&timers_nb, &hrtimers_nb): 0
	// nh->head: (&cpu_chain)->head: &hrtimers_nb, n: &exynos4_mct_cpu_nb
	// notifier_chain_register(&hrtimers_nb, &exynos4_mct_cpu_nb): 0
	// nh->head: (&cpu_chain)->head: &exynos4_mct_cpu_nb, n: &hotplug_cfd_notifier
	// notifier_chain_register(&exynos4_mct_cpu_nb, &hotplug_cfd_notifier): 0
	// nh->head: (&cpu_chain)->head: &hotplug_cfd_notifier, n: &buffer_cpu_notify_nb
	// notifier_chain_register(&hotplug_cfd_notifier, &buffer_cpu_notify_nb): 0
	// nh->head: (&cpu_chain)->head: &buffer_cpu_notify_nb, n: &ratelimit_nb
	// notifier_chain_register(&buffer_cpu_notify_nb, &ratelimit_nb): 0
	return notifier_chain_register(&nh->head, n);
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0

	// notifier_chain_register(&page_alloc_cpu_notify_nb)에서 한일:
	//
	// (&cpu_chain)->head: &page_alloc_cpu_notify_nb
	// &nh->head에 n의 포인터를 대입함

	// notifier_chain_register(&slab_notifier)에서 한일:
	//
	// (&cpu_chain)->head: &slab_notifier
	// &nh->head에 n의 포인터를 대입함

	// notifier_chain_register(&sched_ilb_notifier_nb)에서 한일:
	//
	// (&cpu_chain)->head: &sched_ilb_notifier_nb
	// &nh->head에 n의 포인터를 대입함

	// notifier_chain_register(&rcu_cpu_notify_nb)에서 한일:
	//
	// (&cpu_chain)->head: &rcu_cpu_notify_nb
	// &nh->head에 n의 포인터를 대입함

	// notifier_chain_register(&radix_tree_callback_nb)에서 한일:
	//
	// (&cpu_chain)->head: &radix_tree_callback_nb
	// &nh->head에 n의 포인터를 대입함

	// notifier_chain_register(&gic_cpu_notifier)에서 한일:
	//
	// (&cpu_chain)->head: &gic_cpu_notifier
	// &nh->head에 n의 포인터를 대입함

	// notifier_chain_register(&gic_notifier_block)에서 한일:
	//
	// (&cpu_pm_notifier_chain)->head: &gic_notifier_block
	// &nh->head에 n의 포인터를 대입함

	// notifier_chain_register(&timers_nb)에서 한일:
	//
	// (&cpu_chain)->head: &timers_nb
	// &nh->head에 n의 포인터를 대입함

	// notifier_chain_register(&hrtimers_nb)에서 한일:
	//
	// (&cpu_chain)->head: &hrtimers_nb
	// &nh->head에 n의 포인터를 대입함

	// notifier_chain_register(&exynos4_mct_cpu_nb)에서 한일:
	//
	// (&cpu_chain)->head: &exynos4_mct_cpu_nb
	// &nh->head에 n의 포인터를 대입함

	// notifier_chain_register(&hotplug_cfd_notifier)에서 한일:
	//
	// (&cpu_chain)->head: &hotplug_cfd_notifier
	// &nh->head에 n의 포인터를 대입함

	// notifier_chain_register(&buffer_cpu_notify_nb)에서 한일:
	//
	// (&cpu_chain)->head: &buffer_cpu_notify_nb
	// &nh->head에 n의 포인터를 대입함

	// notifier_chain_register(&ratelimit_nb)에서 한일:
	//
	// (&cpu_chain)->head: &ratelimit_nb
	// &nh->head에 n의 포인터를 대입함
}
EXPORT_SYMBOL_GPL(raw_notifier_chain_register);

/**
 *	raw_notifier_chain_unregister - Remove notifier from a raw notifier chain
 *	@nh: Pointer to head of the raw notifier chain
 *	@n: Entry to remove from notifier chain
 *
 *	Removes a notifier from a raw notifier chain.
 *	All locking must be provided by the caller.
 *
 *	Returns zero on success or %-ENOENT on failure.
 */
int raw_notifier_chain_unregister(struct raw_notifier_head *nh,
		struct notifier_block *n)
{
	return notifier_chain_unregister(&nh->head, n);
}
EXPORT_SYMBOL_GPL(raw_notifier_chain_unregister);

/**
 *	__raw_notifier_call_chain - Call functions in a raw notifier chain
 *	@nh: Pointer to head of the raw notifier chain
 *	@val: Value passed unmodified to notifier function
 *	@v: Pointer passed unmodified to notifier function
 *	@nr_to_call: See comment for notifier_call_chain.
 *	@nr_calls: See comment for notifier_call_chain
 *
 *	Calls each function in a notifier chain in turn.  The functions
 *	run in an undefined context.
 *	All locking must be provided by the caller.
 *
 *	If the return value of the notifier can be and'ed
 *	with %NOTIFY_STOP_MASK then raw_notifier_call_chain()
 *	will return immediately, with the return value of
 *	the notifier function which halted execution.
 *	Otherwise the return value is the return value
 *	of the last notifier function called.
 */
int __raw_notifier_call_chain(struct raw_notifier_head *nh,
			      unsigned long val, void *v,
			      int nr_to_call, int *nr_calls)
{
	return notifier_call_chain(&nh->head, val, v, nr_to_call, nr_calls);
}
EXPORT_SYMBOL_GPL(__raw_notifier_call_chain);

int raw_notifier_call_chain(struct raw_notifier_head *nh,
		unsigned long val, void *v)
{
	return __raw_notifier_call_chain(nh, val, v, -1, NULL);
}
EXPORT_SYMBOL_GPL(raw_notifier_call_chain);

/*
 *	SRCU notifier chain routines.    Registration and unregistration
 *	use a mutex, and call_chain is synchronized by SRCU (no locks).
 */

/**
 *	srcu_notifier_chain_register - Add notifier to an SRCU notifier chain
 *	@nh: Pointer to head of the SRCU notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to an SRCU notifier chain.
 *	Must be called in process context.
 *
 *	Currently always returns zero.
 */
int srcu_notifier_chain_register(struct srcu_notifier_head *nh,
		struct notifier_block *n)
{
	int ret;

	/*
	 * This code gets used during boot-up, when task switching is
	 * not yet working and interrupts must remain disabled.  At
	 * such times we must not call mutex_lock().
	 */
	if (unlikely(system_state == SYSTEM_BOOTING))
		return notifier_chain_register(&nh->head, n);

	mutex_lock(&nh->mutex);
	ret = notifier_chain_register(&nh->head, n);
	mutex_unlock(&nh->mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(srcu_notifier_chain_register);

/**
 *	srcu_notifier_chain_unregister - Remove notifier from an SRCU notifier chain
 *	@nh: Pointer to head of the SRCU notifier chain
 *	@n: Entry to remove from notifier chain
 *
 *	Removes a notifier from an SRCU notifier chain.
 *	Must be called from process context.
 *
 *	Returns zero on success or %-ENOENT on failure.
 */
int srcu_notifier_chain_unregister(struct srcu_notifier_head *nh,
		struct notifier_block *n)
{
	int ret;

	/*
	 * This code gets used during boot-up, when task switching is
	 * not yet working and interrupts must remain disabled.  At
	 * such times we must not call mutex_lock().
	 */
	if (unlikely(system_state == SYSTEM_BOOTING))
		return notifier_chain_unregister(&nh->head, n);

	mutex_lock(&nh->mutex);
	ret = notifier_chain_unregister(&nh->head, n);
	mutex_unlock(&nh->mutex);
	synchronize_srcu(&nh->srcu);
	return ret;
}
EXPORT_SYMBOL_GPL(srcu_notifier_chain_unregister);

/**
 *	__srcu_notifier_call_chain - Call functions in an SRCU notifier chain
 *	@nh: Pointer to head of the SRCU notifier chain
 *	@val: Value passed unmodified to notifier function
 *	@v: Pointer passed unmodified to notifier function
 *	@nr_to_call: See comment for notifier_call_chain.
 *	@nr_calls: See comment for notifier_call_chain
 *
 *	Calls each function in a notifier chain in turn.  The functions
 *	run in a process context, so they are allowed to block.
 *
 *	If the return value of the notifier can be and'ed
 *	with %NOTIFY_STOP_MASK then srcu_notifier_call_chain()
 *	will return immediately, with the return value of
 *	the notifier function which halted execution.
 *	Otherwise the return value is the return value
 *	of the last notifier function called.
 */
int __srcu_notifier_call_chain(struct srcu_notifier_head *nh,
			       unsigned long val, void *v,
			       int nr_to_call, int *nr_calls)
{
	int ret;
	int idx;

	idx = srcu_read_lock(&nh->srcu);
	ret = notifier_call_chain(&nh->head, val, v, nr_to_call, nr_calls);
	srcu_read_unlock(&nh->srcu, idx);
	return ret;
}
EXPORT_SYMBOL_GPL(__srcu_notifier_call_chain);

int srcu_notifier_call_chain(struct srcu_notifier_head *nh,
		unsigned long val, void *v)
{
	return __srcu_notifier_call_chain(nh, val, v, -1, NULL);
}
EXPORT_SYMBOL_GPL(srcu_notifier_call_chain);

/**
 *	srcu_init_notifier_head - Initialize an SRCU notifier head
 *	@nh: Pointer to head of the srcu notifier chain
 *
 *	Unlike other sorts of notifier heads, SRCU notifier heads require
 *	dynamic initialization.  Be sure to call this routine before
 *	calling any of the other SRCU notifier routines for this head.
 *
 *	If an SRCU notifier head is deallocated, it must first be cleaned
 *	up by calling srcu_cleanup_notifier_head().  Otherwise the head's
 *	per-cpu data (used by the SRCU mechanism) will leak.
 */
void srcu_init_notifier_head(struct srcu_notifier_head *nh)
{
	mutex_init(&nh->mutex);
	if (init_srcu_struct(&nh->srcu) < 0)
		BUG();
	nh->head = NULL;
}
EXPORT_SYMBOL_GPL(srcu_init_notifier_head);

static ATOMIC_NOTIFIER_HEAD(die_chain);

int notrace __kprobes notify_die(enum die_val val, const char *str,
	       struct pt_regs *regs, long err, int trap, int sig)
{
	struct die_args args = {
		.regs	= regs,
		.str	= str,
		.err	= err,
		.trapnr	= trap,
		.signr	= sig,

	};
	return atomic_notifier_call_chain(&die_chain, val, &args);
}

int register_die_notifier(struct notifier_block *nb)
{
	vmalloc_sync_all();
	return atomic_notifier_chain_register(&die_chain, nb);
}
EXPORT_SYMBOL_GPL(register_die_notifier);

int unregister_die_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&die_chain, nb);
}
EXPORT_SYMBOL_GPL(unregister_die_notifier);
