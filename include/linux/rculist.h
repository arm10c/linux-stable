#ifndef _LINUX_RCULIST_H
#define _LINUX_RCULIST_H

#ifdef __KERNEL__

/*
 * RCU-protected list version
 */
#include <linux/list.h>
#include <linux/rcupdate.h>

/*
 * Why is there no list_empty_rcu()?  Because list_empty() serves this
 * purpose.  The list_empty() function fetches the RCU-protected pointer
 * and compares it to the address of the list head, but neither dereferences
 * this pointer itself nor provides this pointer to the caller.  Therefore,
 * it is not necessary to use rcu_dereference(), so that list_empty() can
 * be used anywhere you would want to use a list_empty_rcu().
 */

/*
 * INIT_LIST_HEAD_RCU - Initialize a list_head visible to RCU readers
 * @list: list to be initialized
 *
 * You should instead use INIT_LIST_HEAD() for normal initialization and
 * cleanup tasks, when readers have no access to the list being initialized.
 * However, if the list being initialized is visible to readers, you
 * need to keep the compiler from being too mischievous.
 */
static inline void INIT_LIST_HEAD_RCU(struct list_head *list)
{
	ACCESS_ONCE(list->next) = list;
	ACCESS_ONCE(list->prev) = list;
}

/*
 * return the ->next pointer of a list_head in an rcu safe
 * way, we must not access it directly
 */
// ARM10C 20141108
// prev: &vmap_area_list
// list_next_rcu(&vmap_area_list):
// (*((struct list_head __rcu **)(&(&vmap_area_list)->next)))
// ARM10C 20161203
// list_next_rcu((&init_task.tasks)->prev):
// (*((struct list_head __rcu **)(&((&init_task.tasks)->prev)->next)))
#define list_next_rcu(list)	(*((struct list_head __rcu **)(&(list)->next)))

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
#ifndef CONFIG_DEBUG_LIST // CONFIG_DEBUG_LIST=n
// ARM10C 20141025
// new: &(kmem_cache#30-oX (GIC))->list, head: &vmap_area_list,
// head->next: (SYSC)->list
// ARM10C 20161203
// new: &(kmem_cache#15-oX (struct task_struct))->tasks,
// head->prev: (&init_task.tasks)->prev, head: &init_task.tasks
static inline void __list_add_rcu(struct list_head *new,
		struct list_head *prev, struct list_head *next)
{
	// new->next: ((GIC)->list)->next, next: (SYSC)->list
	// new->next: (&(kmem_cache#15-oX (struct task_struct))->tasks)->next, next: &init_task.tasks
	new->next = next;
	// new->next: ((GIC)->list)->next: (SYSC)->list
	// new->next: (&(kmem_cache#15-oX (struct task_struct))->tasks)->next: &init_task.tasks

	// new->prev: ((GIC)->list)->prev, prev: &vmap_area_list
	// new->prev: (&(kmem_cache#15-oX (struct task_struct))->tasks)->prev, prev: (&init_task.tasks)->prev
	new->prev = prev;
	// new->prev: ((GIC)->list)->prev: &vmap_area_list
	// new->prev: (&(kmem_cache#15-oX (struct task_struct))->tasks)->prev: (&init_task.tasks)->prev

	// prev: &vmap_area_list, new: &((GIC))->list
	// list_next_rcu(&vmap_area_list): (*((struct list_head __rcu **)(&(&vmap_area_list)->next)))
	// prev: (&init_task.tasks)->prev, new: &(kmem_cache#15-oX (struct task_struct))->tasks
	// list_next_rcu((&init_task.tasks)->prev): (*((struct list_head __rcu **) (&((&init_task.tasks)->prev)->next)))
	rcu_assign_pointer(list_next_rcu(prev), new);

	// rcu_assign_pointer에서 한일:
	// core간 write memory barrier 수행
	// ((*((struct list_head __rcu **)(&(&vmap_area_list)->next)))) =
	// (typeof(*&((GIC))->list) __force space *)(&((GIC))->list)

	// rcu_assign_pointer에서 한일:
	// core간 write memory barrier 수행
	// ((*((struct list_head __rcu **) (&((&init_task.tasks)->prev)->next)))):
	// (typeof(*&(kmem_cache#15-oX (struct task_struct))->tasks) __force __rcu *)(&(kmem_cache#15-oX (struct task_struct))->tasks);

	// next->prev: ((SYSC)->list)->prev, new: &(GIC)->list
	// next->prev: (&init_task.tasks)->prev, new: &(kmem_cache#15-oX (struct task_struct))->tasks
	next->prev = new;
	// next->prev: ((SYSC)->list)->prev: &(GIC)->list
	// next->prev: (&init_task.tasks)->prev: &(kmem_cache#15-oX (struct task_struct))->tasks
}
#else
extern void __list_add_rcu(struct list_head *new,
		struct list_head *prev, struct list_head *next);
#endif

/**
 * list_add_rcu - add a new entry to rcu-protected list
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as list_add_rcu()
 * or list_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * list_for_each_entry_rcu().
 */
// ARM10C 20141025
// &va->list: &(kmem_cache#30-oX (GIC#0))->list, &vmap_area_list
// ARM10C 20141108
// &va->list: &(kmem_cache#30-oX (GIC#1))->list, &prev->list: &(GIC#0)->list
// ARM10C 20141206
// &va->list: &(kmem_cache#30-oX (COMB))->list, &prev->list: &(GIC#1)->list
// ARM10C 20150321
// &va->list: &(kmem_cache#30-oX (MCT))->list, &prev->list: &(COMB)->list
static inline void list_add_rcu(struct list_head *new, struct list_head *head)
{
	// new: &(kmem_cache#30-oX (GIC#0))->list, head: &vmap_area_list,
	// head->next: (SYSC)->list
	__list_add_rcu(new, head, head->next);
}

/**
 * list_add_tail_rcu - add a new entry to rcu-protected list
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as list_add_tail_rcu()
 * or list_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * list_for_each_entry_rcu().
 */
// ARM10C 20161203
// &p->tasks: &(kmem_cache#15-oX (struct task_struct))->tasks, &init_task.tasks
// ARM10C 20170427
// &cfs_rq->leaf_cfs_rq_list: [pcp0] &(&(&runqueues)->cfs)->leaf_cfs_rq_list,
// &rq_of([pcp0] &(&runqueues)->cfs)->leaf_cfs_rq_list: [pcp0] &(&runqueues)->leaf_cfs_rq_list
static inline void list_add_tail_rcu(struct list_head *new,
					struct list_head *head)
{
	// new: &(kmem_cache#15-oX (struct task_struct))->tasks,
	// head->prev: (&init_task.tasks)->prev, head: &init_task.tasks
	__list_add_rcu(new, head->prev, head);

	// __list_add_rcu 에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->tasks)->next: &init_task.tasks
	// (&(kmem_cache#15-oX (struct task_struct))->tasks)->prev: (&init_task.tasks)->prev
	//
	// core간 write memory barrier 수행
	// ((*((struct list_head __rcu **) (&((&init_task.tasks)->prev)->next)))):
	// (typeof(*&(kmem_cache#15-oX (struct task_struct))->tasks) __force __rcu *)(&(kmem_cache#15-oX (struct task_struct))->tasks);
	//
	// (&init_task.tasks)->prev: &(kmem_cache#15-oX (struct task_struct))->tasks
}

/**
 * list_del_rcu - deletes entry from list without re-initialization
 * @entry: the element to delete from the list.
 *
 * Note: list_empty() on entry does not return true after this,
 * the entry is in an undefined state. It is useful for RCU based
 * lockfree traversal.
 *
 * In particular, it means that we can not poison the forward
 * pointers that may still be used for walking the list.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as list_del_rcu()
 * or list_add_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * list_for_each_entry_rcu().
 *
 * Note that the caller is not permitted to immediately free
 * the newly deleted entry.  Instead, either synchronize_rcu()
 * or call_rcu() must be used to defer freeing until an RCU
 * grace period has elapsed.
 */
static inline void list_del_rcu(struct list_head *entry)
{
	__list_del_entry(entry);
	entry->prev = LIST_POISON2;
}

/**
 * hlist_del_init_rcu - deletes entry from hash list with re-initialization
 * @n: the element to delete from the hash list.
 *
 * Note: list_unhashed() on the node return true after this. It is
 * useful for RCU based read lockfree traversal if the writer side
 * must know if the list entry is still hashed or already unhashed.
 *
 * In particular, it means that we can not poison the forward pointers
 * that may still be used for walking the hash list and we can only
 * zero the pprev pointer so list_unhashed() will return true after
 * this.
 *
 * The caller must take whatever precautions are necessary (such as
 * holding appropriate locks) to avoid racing with another
 * list-mutation primitive, such as hlist_add_head_rcu() or
 * hlist_del_rcu(), running on this same list.  However, it is
 * perfectly legal to run concurrently with the _rcu list-traversal
 * primitives, such as hlist_for_each_entry_rcu().
 */
static inline void hlist_del_init_rcu(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		n->pprev = NULL;
	}
}

/**
 * list_replace_rcu - replace old entry by new one
 * @old : the element to be replaced
 * @new : the new element to insert
 *
 * The @old entry will be replaced with the @new entry atomically.
 * Note: @old should not be empty.
 */
static inline void list_replace_rcu(struct list_head *old,
				struct list_head *new)
{
	new->next = old->next;
	new->prev = old->prev;
	rcu_assign_pointer(list_next_rcu(new->prev), new);
	new->next->prev = new;
	old->prev = LIST_POISON2;
}

/**
 * list_splice_init_rcu - splice an RCU-protected list into an existing list.
 * @list:	the RCU-protected list to splice
 * @head:	the place in the list to splice the first list into
 * @sync:	function to sync: synchronize_rcu(), synchronize_sched(), ...
 *
 * @head can be RCU-read traversed concurrently with this function.
 *
 * Note that this function blocks.
 *
 * Important note: the caller must take whatever action is necessary to
 *	prevent any other updates to @head.  In principle, it is possible
 *	to modify the list as soon as sync() begins execution.
 *	If this sort of thing becomes necessary, an alternative version
 *	based on call_rcu() could be created.  But only if -really-
 *	needed -- there is no shortage of RCU API members.
 */
static inline void list_splice_init_rcu(struct list_head *list,
					struct list_head *head,
					void (*sync)(void))
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;
	struct list_head *at = head->next;

	if (list_empty(list))
		return;

	/*
	 * "first" and "last" tracking list, so initialize it.  RCU readers
	 * have access to this list, so we must use INIT_LIST_HEAD_RCU()
	 * instead of INIT_LIST_HEAD().
	 */

	INIT_LIST_HEAD_RCU(list);

	/*
	 * At this point, the list body still points to the source list.
	 * Wait for any readers to finish using the list before splicing
	 * the list body into the new list.  Any new readers will see
	 * an empty list.
	 */

	sync();

	/*
	 * Readers are finished with the source list, so perform splice.
	 * The order is important if the new list is global and accessible
	 * to concurrent RCU readers.  Note that RCU readers are not
	 * permitted to traverse the prev pointers without excluding
	 * this function.
	 */

	last->next = at;
	rcu_assign_pointer(list_next_rcu(head), first);
	first->prev = head;
	at->prev = last;
}

/**
 * list_entry_rcu - get the struct for this entry
 * @ptr:        the &struct list_head pointer.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_struct within the struct.
 *
 * This primitive may safely run concurrently with the _rcu list-mutation
 * primitives such as list_add_rcu() as long as it's guarded by rcu_read_lock().
 */
// ARM10C 20170720
// list_entry_rcu((&([pcp0] &runqueues)->leaf_cfs_rq_list)->next, typeof(*cfs_rq), leaf_cfs_rq_list)
//
// #define list_entry_rcu((&([pcp0] &runqueues)->leaf_cfs_rq_list)->next, struct cfs_rq, leaf_cfs_rq_list):
// ({typeof (*(&([pcp0] &runqueues)->leaf_cfs_rq_list)->next) __rcu *__ptr =
// (typeof (*(&([pcp0] &runqueues)->leaf_cfs_rq_list)->next) __rcu __force *)(&([pcp0] &runqueues)->leaf_cfs_rq_list)->next;
// container_of((typeof((&([pcp0] &runqueues)->leaf_cfs_rq_list)->next))rcu_dereference_raw(__ptr), struct cfs_rq, leaf_cfs_rq_list);})
#define list_entry_rcu(ptr, type, member) \
	({typeof (*ptr) __rcu *__ptr = (typeof (*ptr) __rcu __force *)ptr; \
	 container_of((typeof(ptr))rcu_dereference_raw(__ptr), type, member); \
	})

/**
 * Where are list_empty_rcu() and list_first_entry_rcu()?
 *
 * Implementing those functions following their counterparts list_empty() and
 * list_first_entry() is not advisable because they lead to subtle race
 * conditions as the following snippet shows:
 *
 * if (!list_empty_rcu(mylist)) {
 *	struct foo *bar = list_first_entry_rcu(mylist, struct foo, list_member);
 *	do_something(bar);
 * }
 *
 * The list may not be empty when list_empty_rcu checks it, but it may be when
 * list_first_entry_rcu rereads the ->next pointer.
 *
 * Rereading the ->next pointer is not a problem for list_empty() and
 * list_first_entry() because they would be protected by a lock that blocks
 * writers.
 *
 * See list_first_or_null_rcu for an alternative.
 */

/**
 * list_first_or_null_rcu - get the first element from a list
 * @ptr:        the list head to take the element from.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_struct within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 *
 * This primitive may safely run concurrently with the _rcu list-mutation
 * primitives such as list_add_rcu() as long as it's guarded by rcu_read_lock().
 */
#define list_first_or_null_rcu(ptr, type, member) \
	({struct list_head *__ptr = (ptr); \
	  struct list_head *__next = ACCESS_ONCE(__ptr->next); \
	  likely(__ptr != __next) ? \
		list_entry_rcu(__next, type, member) : NULL; \
	})

/**
 * list_for_each_entry_rcu	-	iterate over rcu list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * This list-traversal primitive may safely run concurrently with
 * the _rcu list-mutation primitives such as list_add_rcu()
 * as long as the traversal is guarded by rcu_read_lock().
 */
// ARM10C 20170720
// list_for_each_entry_rcu(cfs_rq, &([pcp0] &runqueues)->leaf_cfs_rq_list, leaf_cfs_rq_list)
//
// #define list_for_each_entry_rcu(cfs_rq, &([pcp0] &runqueues)->leaf_cfs_rq_list, leaf_cfs_rq_list):
// for (cfs_rq = list_entry_rcu((&([pcp0] &runqueues)->leaf_cfs_rq_list)->next, typeof(*cfs_rq), leaf_cfs_rq_list);
// &cfs_rq->leaf_cfs_rq_list != (&([pcp0] &runqueues)->leaf_cfs_rq_list);
// cfs_rq = list_entry_rcu(cfs_rq->leaf_cfs_rq_list.next, typeof(*cfs_rq), leaf_cfs_rq_list))
#define list_for_each_entry_rcu(pos, head, member) \
	for (pos = list_entry_rcu((head)->next, typeof(*pos), member); \
		&pos->member != (head); \
		pos = list_entry_rcu(pos->member.next, typeof(*pos), member))

/**
 * list_for_each_entry_continue_rcu - continue iteration over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Continue to iterate over list of given type, continuing after
 * the current position.
 */
#define list_for_each_entry_continue_rcu(pos, head, member) 		\
	for (pos = list_entry_rcu(pos->member.next, typeof(*pos), member); \
	     &pos->member != (head);	\
	     pos = list_entry_rcu(pos->member.next, typeof(*pos), member))

/**
 * hlist_del_rcu - deletes entry from hash list without re-initialization
 * @n: the element to delete from the hash list.
 *
 * Note: list_unhashed() on entry does not return true after this,
 * the entry is in an undefined state. It is useful for RCU based
 * lockfree traversal.
 *
 * In particular, it means that we can not poison the forward
 * pointers that may still be used for walking the hash list.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as hlist_add_head_rcu()
 * or hlist_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * hlist_for_each_entry().
 */
static inline void hlist_del_rcu(struct hlist_node *n)
{
	__hlist_del(n);
	n->pprev = LIST_POISON2;
}

/**
 * hlist_replace_rcu - replace old entry by new one
 * @old : the element to be replaced
 * @new : the new element to insert
 *
 * The @old entry will be replaced with the @new entry atomically.
 */
static inline void hlist_replace_rcu(struct hlist_node *old,
					struct hlist_node *new)
{
	struct hlist_node *next = old->next;

	new->next = next;
	new->pprev = old->pprev;
	rcu_assign_pointer(*(struct hlist_node __rcu **)new->pprev, new);
	if (next)
		new->next->pprev = &new->next;
	old->pprev = LIST_POISON2;
}

/*
 * return the first or the next element in an RCU protected hlist
 */
// ARM10C 20161203
// h: &(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값]
// ARM10C 20161210
// h: &(kmem_cache#19-oX (struct pid))->tasks[0]
// ARM10C 20170624
// &pid_hash[계산된 hash index 값]
// ARM10C 20170701
// &pid->tasks[0]: &(kmem_cache#19-oX (struct pid) (pid 2))->tasks[0]
#define hlist_first_rcu(head)	(*((struct hlist_node __rcu **)(&(head)->first)))
#define hlist_next_rcu(node)	(*((struct hlist_node __rcu **)(&(node)->next)))
#define hlist_pprev_rcu(node)	(*((struct hlist_node __rcu **)((node)->pprev)))

/**
 * hlist_add_head_rcu
 * @n: the element to add to the hash list.
 * @h: the list to add to.
 *
 * Description:
 * Adds the specified element to the specified hlist,
 * while permitting racing traversals.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as hlist_add_head_rcu()
 * or hlist_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * hlist_for_each_entry_rcu(), used to prevent memory-consistency
 * problems on Alpha CPUs.  Regardless of the type of CPU, the
 * list-traversal primitive must be guarded by rcu_read_lock().
 */
// ARM10C 20161203
// &upid->pid_chain: &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain,
// &pid_hash: &(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값]
// ARM10C 20161210
// &link->node: &(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node,
// &link->pid->tasks[1]: &(&init_struct_pid)->tasks[1]
static inline void hlist_add_head_rcu(struct hlist_node *n,
					struct hlist_head *h)
{
	// h->first: (&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first: NULL
	// h->first: (&(&init_struct_pid)->tasks[1])->first: NULL
	struct hlist_node *first = h->first;
	// first: NULL
	// first: NULL

	// n->next: (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->next, first: NULL
	// n->next: (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->next, first: NULL
	n->next = first;
	// n->next: (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->next: NULL
	// n->next: (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->next: NULL

	// n->pprev: (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->pprev,
	// &h->first: &(&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first
	// n->pprev: (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->pprev,
	// &h->first: &(&(&init_struct_pid)->tasks[1])->first
	n->pprev = &h->first;
	// n->pprev: (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->pprev: &(&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first
	// n->pprev: (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->pprev: &(&(&init_struct_pid)->tasks[1])->first

	// h: &(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값]
	// hlist_first_rcu(&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값]):
	// (*((struct hlist_node __rcu **)(&(&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first))),
	// n: &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain
	// h: &(&init_struct_pid)->tasks[1]
	// hlist_first_rcu(&(&init_struct_pid)->tasks[1]):
	// (*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[1])->first)))
	// n: &(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node
	rcu_assign_pointer(hlist_first_rcu(h), n);

	// rcu_assign_pointer 에서 한일:
	// ((&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first): &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain

	// rcu_assign_pointer 에서 한일:
	// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[1])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node

	// first: NULL
	// first: NULL
	if (first)
		first->pprev = &n->next;
}

/**
 * hlist_add_before_rcu
 * @n: the new element to add to the hash list.
 * @next: the existing element to add the new element before.
 *
 * Description:
 * Adds the specified element to the specified hlist
 * before the specified node while permitting racing traversals.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as hlist_add_head_rcu()
 * or hlist_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * hlist_for_each_entry_rcu(), used to prevent memory-consistency
 * problems on Alpha CPUs.
 */
static inline void hlist_add_before_rcu(struct hlist_node *n,
					struct hlist_node *next)
{
	n->pprev = next->pprev;
	n->next = next;
	rcu_assign_pointer(hlist_pprev_rcu(n), n);
	next->pprev = &n->next;
}

/**
 * hlist_add_after_rcu
 * @prev: the existing element to add the new element after.
 * @n: the new element to add to the hash list.
 *
 * Description:
 * Adds the specified element to the specified hlist
 * after the specified node while permitting racing traversals.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as hlist_add_head_rcu()
 * or hlist_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * hlist_for_each_entry_rcu(), used to prevent memory-consistency
 * problems on Alpha CPUs.
 */
static inline void hlist_add_after_rcu(struct hlist_node *prev,
				       struct hlist_node *n)
{
	n->next = prev->next;
	n->pprev = &prev->next;
	rcu_assign_pointer(hlist_next_rcu(prev), n);
	if (n->next)
		n->next->pprev = &n->next;
}

#define __hlist_for_each_rcu(pos, head)				\
	for (pos = rcu_dereference(hlist_first_rcu(head));	\
	     pos;						\
	     pos = rcu_dereference(hlist_next_rcu(pos)))

/**
 * hlist_for_each_entry_rcu - iterate over rcu list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 *
 * This list-traversal primitive may safely run concurrently with
 * the _rcu list-mutation primitives such as hlist_add_head_rcu()
 * as long as the traversal is guarded by rcu_read_lock().
 */
// ARM10C 20170624
// hlist_for_each_entry_rcu(pnr, &pid_hash[계산된 hash index 값], pid_chain):
// for (pnr = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(&pid_hash[계산된 hash index 값])), typeof(*(pnr)), pid_chain);
//      pnr; pnr = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(&(pnr)->pid_chain)), typeof(*(pnr)), pid_chain))
#define hlist_for_each_entry_rcu(pos, head, member)			\
	for (pos = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))

/**
 * hlist_for_each_entry_rcu_notrace - iterate over rcu list of given type (for tracing)
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 *
 * This list-traversal primitive may safely run concurrently with
 * the _rcu list-mutation primitives such as hlist_add_head_rcu()
 * as long as the traversal is guarded by rcu_read_lock().
 *
 * This is the same as hlist_for_each_entry_rcu() except that it does
 * not do any RCU debugging or tracing.
 */
#define hlist_for_each_entry_rcu_notrace(pos, head, member)			\
	for (pos = hlist_entry_safe (rcu_dereference_raw_notrace(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw_notrace(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))

/**
 * hlist_for_each_entry_rcu_bh - iterate over rcu list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 *
 * This list-traversal primitive may safely run concurrently with
 * the _rcu list-mutation primitives such as hlist_add_head_rcu()
 * as long as the traversal is guarded by rcu_read_lock().
 */
#define hlist_for_each_entry_rcu_bh(pos, head, member)			\
	for (pos = hlist_entry_safe(rcu_dereference_bh(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_bh(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))

/**
 * hlist_for_each_entry_continue_rcu - iterate over a hlist continuing after current point
 * @pos:	the type * to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue_rcu(pos, member)			\
	for (pos = hlist_entry_safe(rcu_dereference((pos)->member.next),\
			typeof(*(pos)), member);			\
	     pos;							\
	     pos = hlist_entry_safe(rcu_dereference((pos)->member.next),\
			typeof(*(pos)), member))

/**
 * hlist_for_each_entry_continue_rcu_bh - iterate over a hlist continuing after current point
 * @pos:	the type * to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue_rcu_bh(pos, member)		\
	for (pos = hlist_entry_safe(rcu_dereference_bh((pos)->member.next),\
			typeof(*(pos)), member);			\
	     pos;							\
	     pos = hlist_entry_safe(rcu_dereference_bh((pos)->member.next),\
			typeof(*(pos)), member))


#endif	/* __KERNEL__ */
#endif
