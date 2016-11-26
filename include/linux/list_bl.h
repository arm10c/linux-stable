#ifndef _LINUX_LIST_BL_H
#define _LINUX_LIST_BL_H

#include <linux/list.h>
#include <linux/bit_spinlock.h>

/*
 * Special version of lists, where head of the list has a lock in the lowest
 * bit. This is useful for scalable hash tables without increasing memory
 * footprint overhead.
 *
 * For modification operations, the 0 bit of hlist_bl_head->first
 * pointer must be set.
 *
 * With some small modifications, this can easily be adapted to store several
 * arbitrary bits (not just a single lock bit), if the need arises to store
 * some fast and compact auxiliary data.
 */

#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK) // CONFIG_SMP=y, CONFIG_DEBUG_SPINLOCK=y
// ARM10C 20161126
// LIST_BL_LOCKMASK: 1UL
#define LIST_BL_LOCKMASK	1UL
#else
#define LIST_BL_LOCKMASK	0UL
#endif

#ifdef CONFIG_DEBUG_LIST // CONFIG_DEBUG_LIST=n
#define LIST_BL_BUG_ON(x) BUG_ON(x)
#else
// ARM10C 20161126
#define LIST_BL_BUG_ON(x)
#endif

// hlist_bl_head 에서 bl의 의미:
// bitlocked linked list
// https://lwn.net/Articles/609904/

// ARM10C 20140322
// sizeof(struct hlist_bl_head): 4 bytes
struct hlist_bl_head {
	struct hlist_bl_node *first;
};

// ARM10C 20151003
// ARM10C 20151219
// ARM10C 20161126
// sizeof(struct hlist_bl_node): 8 bytes
struct hlist_bl_node {
	struct hlist_bl_node *next, **pprev;
};
// ARM10C 20151114
// &s->s_anon: &(kmem_cache#25-oX (struct super_block))->s_anon
// ARM10C 20160319
// &s->s_anon: &(kmem_cache#25-oX (struct super_block))->s_anon
#define INIT_HLIST_BL_HEAD(ptr) \
	((ptr)->first = NULL)

// ARM10C 20151219
// &dentry->d_hash: &(kmem_cache#5-oX)->d_hash
static inline void INIT_HLIST_BL_NODE(struct hlist_bl_node *h)
{
	// h->next: (&(kmem_cache#5-oX)->d_hash)->next
	h->next = NULL;
	// h->next: (&(kmem_cache#5-oX)->d_hash)->next: NULL

	// h->pprev: (&(kmem_cache#5-oX)->d_hash)->pprev
	h->pprev = NULL;
	// h->pprev: (&(kmem_cache#5-oX)->d_hash)->pprev: NULL
}

#define hlist_bl_entry(ptr, type, member) container_of(ptr,type,member)

// ARM10C 20161126
// &dentry->d_hash: &(kmem_cache#5-oX (struct dentry))->d_hash
static inline int hlist_bl_unhashed(const struct hlist_bl_node *h)
{
	// h->pprev: (&(kmem_cache#5-oX (struct dentry))->d_hash)->pprev: NULL
	return !h->pprev;
	// return 1
}

// ARM10C 20161126
// h: hash 0xXXXXXXXX 에 맞는 list table 주소값
static inline struct hlist_bl_node *hlist_bl_first(struct hlist_bl_head *h)
{
	// h->first: (hash 0xXXXXXXXX 에 맞는 list table 주소값)->first: NULL, LIST_BL_LOCKMASK: 1UL
	return (struct hlist_bl_node *)
		((unsigned long)h->first & ~LIST_BL_LOCKMASK);
	// return NULL
}

static inline void hlist_bl_set_first(struct hlist_bl_head *h,
					struct hlist_bl_node *n)
{
	LIST_BL_BUG_ON((unsigned long)n & LIST_BL_LOCKMASK);
	LIST_BL_BUG_ON(((unsigned long)h->first & LIST_BL_LOCKMASK) !=
							LIST_BL_LOCKMASK);
	h->first = (struct hlist_bl_node *)((unsigned long)n | LIST_BL_LOCKMASK);
}

static inline int hlist_bl_empty(const struct hlist_bl_head *h)
{
	return !((unsigned long)h->first & ~LIST_BL_LOCKMASK);
}

static inline void hlist_bl_add_head(struct hlist_bl_node *n,
					struct hlist_bl_head *h)
{
	struct hlist_bl_node *first = hlist_bl_first(h);

	n->next = first;
	if (first)
		first->pprev = &n->next;
	n->pprev = &h->first;
	hlist_bl_set_first(h, n);
}

static inline void __hlist_bl_del(struct hlist_bl_node *n)
{
	struct hlist_bl_node *next = n->next;
	struct hlist_bl_node **pprev = n->pprev;

	LIST_BL_BUG_ON((unsigned long)n & LIST_BL_LOCKMASK);

	/* pprev may be `first`, so be careful not to lose the lock bit */
	*pprev = (struct hlist_bl_node *)
			((unsigned long)next |
			 ((unsigned long)*pprev & LIST_BL_LOCKMASK));
	if (next)
		next->pprev = pprev;
}

static inline void hlist_bl_del(struct hlist_bl_node *n)
{
	__hlist_bl_del(n);
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}

static inline void hlist_bl_del_init(struct hlist_bl_node *n)
{
	if (!hlist_bl_unhashed(n)) {
		__hlist_bl_del(n);
		INIT_HLIST_BL_NODE(n);
	}
}

// ARM10C 20161126
// b: hash 0xXXXXXXXX 에 맞는 list table 주소값
static inline void hlist_bl_lock(struct hlist_bl_head *b)
{
	// b: hash 0xXXXXXXXX 에 맞는 list table 주소값
	bit_spin_lock(0, (unsigned long *)b);

	// bit_spin_lock 에서 한일:
	// hash 0xXXXXXXXX 에 맞는 list table 주소값의 0 bit 를 1로 set
}

// ARM10C 20161126
// b: hash 0xXXXXXXXX 에 맞는 list table 주소값
static inline void hlist_bl_unlock(struct hlist_bl_head *b)
{
	// b: hash 0xXXXXXXXX 에 맞는 list table 주소값
	__bit_spin_unlock(0, (unsigned long *)b);

	// __bit_spin_unlock 에서 한일:
	// hash 0xXXXXXXXX 에 맞는 list table 주소값 의 bit 0을 클리어함
	// dmb(ish)를 사용하여 공유 자원 hash 0xXXXXXXXX 에 맞는 list table 주소값 값을 갱신
}

static inline bool hlist_bl_is_locked(struct hlist_bl_head *b)
{
	return bit_spin_is_locked(0, (unsigned long *)b);
}

/**
 * hlist_bl_for_each_entry	- iterate over list of given type
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct hlist_node to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 *
 */
#define hlist_bl_for_each_entry(tpos, pos, head, member)		\
	for (pos = hlist_bl_first(head);				\
	     pos &&							\
		({ tpos = hlist_bl_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

/**
 * hlist_bl_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct hlist_node to use as a loop cursor.
 * @n:		another &struct hlist_node to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_bl_for_each_entry_safe(tpos, pos, n, head, member)	 \
	for (pos = hlist_bl_first(head);				 \
	     pos && ({ n = pos->next; 1; }) && 				 \
		({ tpos = hlist_bl_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)

#endif
