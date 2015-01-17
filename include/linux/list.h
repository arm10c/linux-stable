#ifndef _LINUX_LIST_H
#define _LINUX_LIST_H

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/poison.h>
#include <linux/const.h>

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

// ARM10C 20131012
// ARM10C 20131116
// ARM10C 20131130
// ARM10C 20140315
// LIST_HEAD_INIT(cpu_add_remove_lock.wait_list):
// { &(cpu_add_remove_lock.wait_list), &(cpu_add_remove_lock.wait_list) }
#define LIST_HEAD_INIT(name) { &(name), &(name) }

// ARM10C 20131116
// ARM10C 20131130
// ARM10C 20141108
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

// ARM10C 20130824
// ARM10C 20140301
// ARM10C 20140315
// &waiter->list->next: list, &waiter->list->prev: list
// ARM10C 20140809
// ARM10C 20141004
// ARM10C 20150103
static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
#ifndef CONFIG_DEBUG_LIST // CONFIG_DEBUG_LIST=n
// ARM10C 20131130
// __list_add(new, head->prev, head);
// ARM10C 20140301
// new: &dchunk->list, prev: &pcpu_slot[11], next: &pcpu_slot[11]->next(&pcpu_slot[11])
// ARM10C 20140315
// __list_add(&waiter.list, (&(&cpu_add_remove_lock)->wait_list)->prev, &(&cpu_add_remove_lock)->wait_list)
static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	//&pcpu_slot[11]->prev = &dchunk->list;
	new->next = next;
	//&dchunk->list->next = &pcpu_slot[11];
	new->prev = prev;
	//&dchunk->list->prev = &pcpu_slot[11];
	prev->next = new;
	//&pcpu_slot[11]->next = &dchunk->list;
}
#else
extern void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next);
#endif

/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
// ARM10C 20140301
// new: &dchunk->list, head: &pcpu_slot[11]
static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}


/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
// ARM10C 20131130
// list_add_tail(&svm->list, &curr_svm->list);
// ARM10C 20140315
// list_add_tail(&waiter.list, &(&cpu_add_remove_lock)->wait_list);
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	// new: &waiter.list, head->prev: (&(&cpu_add_remove_lock)->wait_list)->prev
	// head: &(&cpu_add_remove_lock)->wait_list
	__list_add(new, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
// ARM10C 20140315
// *entry : &waiter->list
// &waiter->list->prev: prev, &waiter->list->next: next
// ARM10C 20140412
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
#ifndef CONFIG_DEBUG_LIST
// ARM10C 20140301
// ARM10C 20140315
// *entry: &waiter->list
static inline void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

// ARM10C 20140412
// ARM10C 20140517
static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);

	// LIST_POISON1: ((void *) 0x00100100)
	entry->next = LIST_POISON1;

	// LIST_POISON2: ((void *) 0x00200200)
	entry->prev = LIST_POISON2;
}
#else
extern void __list_del_entry(struct list_head *entry);
extern void list_del(struct list_head *entry);
#endif

/**
 * list_replace - replace old entry by new one
 * @old : the element to be replaced
 * @new : the new element to insert
 *
 * If @old was empty, it will be overwritten.
 */
static inline void list_replace(struct list_head *old,
				struct list_head *new)
{
	new->next = old->next;
	new->next->prev = new;
	new->prev = old->prev;
	new->prev->next = new;
}

static inline void list_replace_init(struct list_head *old,
					struct list_head *new)
{
	list_replace(old, new);
	INIT_LIST_HEAD(old);
}

/**
 * list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
// ARM10C 20140315
// *entry : &waiter->list
static inline void list_del_init(struct list_head *entry)
{
	// entry: waiter->list
	__list_del_entry(entry);
	// &waiter->list->prev: prev, &waiter->list->next: next

	INIT_LIST_HEAD(entry);
	// &waiter->list->next: &waiter->list, &waiter->list->prev: &waiter->list
}

/**
 * list_move - delete from one list and add as another's head
 * @list: the entry to move
 * @head: the head that will precede our entry
 */
// ARM10C 20140301
// list: &dchunk->list, head: &pcpu_slot[11]
static inline void list_move(struct list_head *list, struct list_head *head)
{
	// list: &dchunk->list
	__list_del_entry(list);
	// &dchunk->list->next: &dchunk->list
	// &dchunk->list->prev: &dchunk->list

	// head: &pcpu_slot[11]
	list_add(list, head);
	// &pcpu_slot[11](list)에 &dchunk->list 추가
}

/**
 * list_move_tail - delete from one list and add as another's tail
 * @list: the entry to move
 * @head: the head that will follow our entry
 */
static inline void list_move_tail(struct list_head *list,
				  struct list_head *head)
{
	__list_del_entry(list);

	list_add_tail(list, head);
}

/**
 * list_is_last - tests whether @list is the last entry in list @head
 * @list: the entry to test
 * @head: the head of the list
 */
// ARM10C 20141108
// &first->list: &(GIC#0)->list, &vmap_area_list
// ARM10C 20141206
// &first->list: &(GIC#1)->list, &vmap_area_list
// ARM10C 20150110
// &first->list: &(COMB)->list, &vmap_area_list
static inline int list_is_last(const struct list_head *list,
				const struct list_head *head)
{
	// list->next: (&(GIC#0)->list)->next: &(SYSC)->list
	// head: &vmap_area_list
	// list->next: (&(GIC#1)->list)->next: &(SYSC)->list
	// head: &vmap_area_list
	// list->next: (&(COMB)->list)->next: &(SYSC)->list
	// head: &vmap_area_list
	return list->next == head;
	// return 0
	// return 0
	// return 0
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
// ARM10C 20140315
// &waiter->list
// ARM10C 20130322
// ARM10C 20140322
// ARM10C 20140517
// list: (&boot_pageset + (__per_cpu_offset[0]))->pcp.lists[0]
// ARM10C 20150117
static inline int list_empty(const struct list_head *head)
{
	// head->next: waiter->list->next, head: waiter->list
	return head->next == head;
	// return 0
}

/**
 * list_empty_careful - tests whether a list is empty and not being modified
 * @head: the list to test
 *
 * Description:
 * tests whether a list is empty _and_ checks that no other CPU might be
 * in the process of modifying either member (next or prev)
 *
 * NOTE: using list_empty_careful() without synchronization
 * can only be safe if the only activity that can happen
 * to the list entry is list_del_init(). Eg. it cannot be used
 * if another CPU could re-list_add() it.
 */
static inline int list_empty_careful(const struct list_head *head)
{
	struct list_head *next = head->next;
	return (next == head) && (next == head->prev);
}

/**
 * list_rotate_left - rotate the list to the left
 * @head: the head of the list
 */
static inline void list_rotate_left(struct list_head *head)
{
	struct list_head *first;

	if (!list_empty(head)) {
		first = head->next;
		list_move_tail(first, head);
	}
}

/**
 * list_is_singular - tests whether a list has just one entry.
 * @head: the list to test.
 */
static inline int list_is_singular(const struct list_head *head)
{
	return !list_empty(head) && (head->next == head->prev);
}

static inline void __list_cut_position(struct list_head *list,
		struct list_head *head, struct list_head *entry)
{
	struct list_head *new_first = entry->next;
	list->next = head->next;
	list->next->prev = list;
	list->prev = entry;
	entry->next = list;
	head->next = new_first;
	new_first->prev = head;
}

/**
 * list_cut_position - cut a list into two
 * @list: a new list to add all removed entries
 * @head: a list with entries
 * @entry: an entry within head, could be the head itself
 *	and if so we won't cut the list
 *
 * This helper moves the initial part of @head, up to and
 * including @entry, from @head to @list. You should
 * pass on @entry an element you know is on @head. @list
 * should be an empty list or a list you do not care about
 * losing its data.
 *
 */
static inline void list_cut_position(struct list_head *list,
		struct list_head *head, struct list_head *entry)
{
	if (list_empty(head))
		return;
	if (list_is_singular(head) &&
		(head->next != entry && head != entry))
		return;
	if (entry == head)
		INIT_LIST_HEAD(list);
	else
		__list_cut_position(list, head, entry);
}

static inline void __list_splice(const struct list_head *list,
				 struct list_head *prev,
				 struct list_head *next)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

/**
 * list_splice - join two lists, this is designed for stacks
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void list_splice(const struct list_head *list,
				struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head, head->next);
}

/**
 * list_splice_tail - join two lists, each list being a queue
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void list_splice_tail(struct list_head *list,
				struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head->prev, head);
}

/**
 * list_splice_init - join two lists and reinitialise the emptied list.
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * The list at @list is reinitialised
 */
static inline void list_splice_init(struct list_head *list,
				    struct list_head *head)
{
	if (!list_empty(list)) {
		__list_splice(list, head, head->next);
		INIT_LIST_HEAD(list);
	}
}

/**
 * list_splice_tail_init - join two lists and reinitialise the emptied list
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * Each of the lists is a queue.
 * The list at @list is reinitialised
 */
static inline void list_splice_tail_init(struct list_head *list,
					 struct list_head *head)
{
	if (!list_empty(list)) {
		__list_splice(list, head->prev, head);
		INIT_LIST_HEAD(list);
	}
}

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
// ARM10C 20131130
// ARM10C 20140322
// ARM10C 20140329
// ARM10C 20140412
// ARM10C 20140531
// #define list_entry((&pcpu_slot[1])->next, typeof(*chunk), list):
// container_of((&pcpu_slot[1])->next, typeof(*chunk), list)
// ARM10C 20140705
// ARM10C 20141108
#define list_entry(ptr, type, member)		\
	container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
// ARM10C 20140531
// #define list_first_entry(&pcpu_slot[1], typeof(*chunk), list):
// list_entry((&pcpu_slot[1])->next, typeof(*chunk), list)
// ARM10C 20140614
// ARM10C 20140705
// ARM10C 20141011
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

/**
 * list_last_entry - get the last element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

/**
 * list_first_entry_or_null - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 */
// ARM10C 20141129
// #define list_first_entry_or_null(&intc_parent_list, struct intc_desc, list):
// (!list_empty(&intc_parent_list) ? list_first_entry(&intc_parent_list, struct intc_desc, list) : NULL)
#define list_first_entry_or_null(ptr, type, member) \
	(!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)

/**
 * list_next_entry - get the next element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_struct within the struct.
 */
// ARM10C 20140614
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

/**
 * list_prev_entry - get the prev element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_struct within the struct.
 */
#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)

/**
 * list_for_each	-	iterate over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * list_for_each_prev	-	iterate over a list backwards
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)

/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:	the &struct list_head to use as a loop cursor.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/**
 * list_for_each_prev_safe - iterate over a list backwards safe against removal of list entry
 * @pos:	the &struct list_head to use as a loop cursor.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define list_for_each_prev_safe(pos, n, head) \
	for (pos = (head)->prev, n = pos->prev; \
	     pos != (head); \
	     pos = n, n = pos->prev)

/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
// ARM10C 20131130
// ARM10C 20140329
// ARM10C 20140531
// #define list_for_each_entry(chunk, &pcpu_slot[slot], list):
// for (chunk = list_first_entry(&pcpu_slot[1], typeof(*chunk), list);
//      &chunk->list != (&pcpu_slot[1]); chunk = list_next_entry(chunk, list))
// ARM10C 20140705
// #define list_for_each_entry(p, &n->partial, lru):
// for (p = list_first_entry(&n->partial, typeof(*p), lru);
//      &p->lru != (&n->partial); p = list_next_entry(p, lru))
//
// ARM10C 20140920
// #define: list_for_each_entry(s, &slab_caches, list):
// for (s = list_first_entry(&slab_caches, typeof(*s), list);
//      &s->list != (&slab_caches); s = list_next_entry(s, list))
//
// ARM10C 20140927
// list_for_each_entry((rsp), &rcu_struct_flavors, flavors):
// for (rsp = list_first_entry(&rcu_struct_flavors, typeof(*rsp), flavors);
//     &rsp->flavors != (&rcu_struct_flavors); rsp = list_next_entry(rsp, flavors))
//
// ARM10C 20141018
// #define list_for_each_entry(svm, &static_vmlist, list):
// for (svm = list_first_entry(&static_vmlist, typeof(*svm), list);
//     &svm->list != (&static_vmlist); svm = list_next_entry(svm, list))
//
// ARM10C 20141213
// #define list_for_each_entry(h, &irq_domain_list, link):
// for (h = list_first_entry(&irq_domain_list, typeof(*h), link);
//     &h->link != (&irq_domain_list); h = list_next_entry(h, link))
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_last_entry(head, typeof(*pos), member);		\
	     &pos->member != (head); 					\
	     pos = list_prev_entry(pos, member))

/**
 * list_prepare_entry - prepare a pos entry for use in list_for_each_entry_continue()
 * @pos:	the type * to use as a start point
 * @head:	the head of the list
 * @member:	the name of the list_struct within the struct.
 *
 * Prepares a pos entry for use as a start point in list_for_each_entry_continue().
 */
#define list_prepare_entry(pos, head, member) \
	((pos) ? : list_entry(head, typeof(*pos), member))

/**
 * list_for_each_entry_continue - continue iteration over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Continue to iterate over list of given type, continuing after
 * the current position.
 */
#define list_for_each_entry_continue(pos, head, member) 		\
	for (pos = list_next_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_continue_reverse - iterate backwards from the given point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Start to iterate over list of given type backwards, continuing after
 * the current position.
 */
#define list_for_each_entry_continue_reverse(pos, head, member)		\
	for (pos = list_prev_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = list_prev_entry(pos, member))

/**
 * list_for_each_entry_from - iterate over list of given type from the current point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate over list of given type, continuing from current position.
 */
#define list_for_each_entry_from(pos, head, member) 			\
	for (; &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
// ARM10C 20140614
// #define list_for_each_entry_safe(page, page2, &n->partial, lru):
// for (page = list_first_entry(&n->partial, typeof(*page), lru),
// 	page2 = list_next_entry(page, lru);
// 	&page->lru != (&n->partial);
// 	page = page2, page2 = list_next_entry(page2, lru))
// ARM10C 20141011
// #define list_for_each_entry_safe(desc, temp_desc, &intc_desc_list, list)
// for (desc = list_first_entry(&intc_desc_list, typeof(*desc), list),
// 	temp_desc = list_next_entry(desc, list);
//      &desc->list != (&intc_desc_list);
//      desc = temp_desc, temp_desc = list_next_entry(temp_desc, list))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = list_next_entry(n, member))

/**
 * list_for_each_entry_safe_continue - continue list iteration safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate over list of given type, continuing after current point,
 * safe against removal of list entry.
 */
#define list_for_each_entry_safe_continue(pos, n, head, member) 		\
	for (pos = list_next_entry(pos, member), 				\
		n = list_next_entry(pos, member);				\
	     &pos->member != (head);						\
	     pos = n, n = list_next_entry(n, member))

/**
 * list_for_each_entry_safe_from - iterate over list from current point safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate over list of given type from current point, safe against
 * removal of list entry.
 */
#define list_for_each_entry_safe_from(pos, n, head, member) 			\
	for (n = list_next_entry(pos, member);					\
	     &pos->member != (head);						\
	     pos = n, n = list_next_entry(n, member))

/**
 * list_for_each_entry_safe_reverse - iterate backwards over list safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate backwards over list of given type, safe against removal
 * of list entry.
 */
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_last_entry(head, typeof(*pos), member),		\
		n = list_prev_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = list_prev_entry(n, member))

/**
 * list_safe_reset_next - reset a stale list_for_each_entry_safe loop
 * @pos:	the loop cursor used in the list_for_each_entry_safe loop
 * @n:		temporary storage used in list_for_each_entry_safe
 * @member:	the name of the list_struct within the struct.
 *
 * list_safe_reset_next is not safe to use in general if the list may be
 * modified concurrently (eg. the lock is dropped in the loop body). An
 * exception to this is if the cursor element (pos) is pinned in the list,
 * and list_safe_reset_next is called after re-taking the lock and before
 * completing the current iteration of the loop body.
 */
#define list_safe_reset_next(pos, n, member)				\
	n = list_next_entry(pos, member)

/*
 * Double linked lists with a single pointer list head.
 * Mostly useful for hash tables where the two pointer list head is
 * too wasteful.
 * You lose the ability to access the tail in O(1).
 */

#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
static inline void INIT_HLIST_NODE(struct hlist_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

static inline int hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

static inline int hlist_empty(const struct hlist_head *h)
{
	return !h->first;
}

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}

static inline void hlist_del_init(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}

// ARM10C 20150117
// &clk->child_node: &(kmem_cache#29-oX)->child_node, &clk_root_list
static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	// h->first: (&clk_root_list)->first: NULL
	struct hlist_node *first = h->first;
	// first: NULL

	// n->next: (&(kmem_cache#29-oX)->child_node)->next, first: NULL
	n->next = first;
	// n->next: (&(kmem_cache#29-oX)->child_node)->next: NULL

	// first: NULL
	if (first)
		first->pprev = &n->next;

	// h->first: (&clk_root_list)->first: NULL, n: &(kmem_cache#29-oX)->child_node
	h->first = n;
	// h->first: (&clk_root_list)->first: &(kmem_cache#29-oX)->child_node

	// n->pprev: (&(kmem_cache#29-oX)->child_node)->pprev,
	// &h->first: &(&clk_root_list)->first: &(&(kmem_cache#29-oX)->child_node)
	n->pprev = &h->first;
	// n->pprev: (&(kmem_cache#29-oX)->child_node)->pprev: &(&(kmem_cache#29-oX)->child_node)
}

/* next must be != NULL */
static inline void hlist_add_before(struct hlist_node *n,
					struct hlist_node *next)
{
	n->pprev = next->pprev;
	n->next = next;
	next->pprev = &n->next;
	*(n->pprev) = n;
}

static inline void hlist_add_after(struct hlist_node *n,
					struct hlist_node *next)
{
	next->next = n->next;
	n->next = next;
	next->pprev = &n->next;

	if(next->next)
		next->next->pprev  = &next->next;
}

/* after that we'll appear to be on some hlist and hlist_del will work */
static inline void hlist_add_fake(struct hlist_node *n)
{
	n->pprev = &n->next;
}

/*
 * Move a list from one list head to another. Fixup the pprev
 * reference of the first entry if it exists.
 */
static inline void hlist_move_list(struct hlist_head *old,
				   struct hlist_head *new)
{
	new->first = old->first;
	if (new->first)
		new->first->pprev = &new->first;
	old->first = NULL;
}

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos ; pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)

// ARM10C 20150117
// hlist_entry_safe((&clk_root_list)->first, typeof(*(root_clk)), child_node)
// ARM10C 20150117
// hlist_entry_safe((&clk_orphan_list)->first, typeof(*orphan), child_node)
#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})

/**
 * hlist_for_each_entry	- iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
// ARM10C 20150117
// #define hlist_for_each_entry(root_clk, &clk_root_list, child_node):
// for (root_clk = hlist_entry_safe((&clk_root_list)->first, typeof(*(root_clk)), child_node);
//      root_clk; root_clk = hlist_entry_safe((root_clk)->child_node.next, typeof(*(root_clk)), child_node))
// ARM10C 20150117
// #define hlist_for_each_entry(root_clk, &clk_orphan_list, child_node):
// for (root_clk = hlist_entry_safe((&clk_orphan_list)->first, typeof(*(root_clk)), child_node);
//      root_clk; root_clk = hlist_entry_safe((root_clk)->child_node.next, typeof(*(root_clk)), child_node))
#define hlist_for_each_entry(pos, head, member)				\
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

/**
 * hlist_for_each_entry_continue - iterate over a hlist continuing after current point
 * @pos:	the type * to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue(pos, member)			\
	for (pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

/**
 * hlist_for_each_entry_from - iterate over a hlist continuing from current point
 * @pos:	the type * to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_from(pos, member)				\
	for (; pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

/**
 * hlist_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another &struct hlist_node to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
// ARM10C 20150117
// #define hlist_for_each_entry_safe(orphan, tmp2, &clk_orphan_list, child_node):
// for (orphan = hlist_entry_safe((&clk_orphan_list)->first, typeof(*orphan), child_node);
//      orphan && ({ tmp2 = orphan->child_node.next; 1; }); orphan = hlist_entry_safe(tmp2, typeof(*orphan), child_node))
#define hlist_for_each_entry_safe(pos, n, head, member) 		\
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member);\
	     pos && ({ n = pos->member.next; 1; });			\
	     pos = hlist_entry_safe(n, typeof(*pos), member))

#endif
