/*
 * 2002-10-18  written by Jim Houston jim.houston@ccur.com
 *	Copyright (C) 2002 by Concurrent Computer Corporation
 *	Distributed under the GNU GPL license version 2.
 *
 * Modified by George Anzinger to reuse immediately and to use
 * find bit instructions.  Also removed _irq on spinlocks.
 *
 * Modified by Nadia Derbey to make it RCU safe.
 *
 * Small id to pointer translation service.
 *
 * It uses a radix tree like structure as a sparse array indexed
 * by the id to obtain the pointer.  The bitmap makes allocating
 * a new id quick.
 *
 * You call it to allocate an id (an int) an associate with that id a
 * pointer or what ever, we treat it as a (void *).  You can pass this
 * id to a user for him to pass back at a later time.  You then pass
 * that id to this code and it returns your pointer.

 * You can release ids at any time. When all ids are released, most of
 * the memory is returned (we keep MAX_IDR_FREE) in a local pool so we
 * don't need to go to the memory "store" during an id allocate, just
 * so you don't need to be too concerned about locking and conflicts
 * with the slab allocator.
 */

#ifndef TEST                        // to test in user space...
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/export.h>
#endif
#include <linux/err.h>
#include <linux/string.h>
#include <linux/idr.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>

// ARM10C 20151031
// ARM10C 20151107
// MAX_IDR_SHIFT: 31
#define MAX_IDR_SHIFT		(sizeof(int) * 8 - 1)
// ARM10C 20151107
// MAX_IDR_SHIFT: 31
// MAX_IDR_BIT: 0x80000000
#define MAX_IDR_BIT		(1U << MAX_IDR_SHIFT)

/* Leave the possibility of an incomplete final layer */
// ARM10C 20151031
// ARM10C 20160730
// MAX_IDR_SHIFT: 31
// IDR_BITS: 8
// MAX_IDR_LEVEL: 4
#define MAX_IDR_LEVEL ((MAX_IDR_SHIFT + IDR_BITS - 1) / IDR_BITS)

/* Number of id_layer structs to leave in free list */
// ARM10C 20151031
// MAX_IDR_LEVEL: 4
// MAX_IDR_FREE: 8
#define MAX_IDR_FREE (MAX_IDR_LEVEL * 2)

// ARM10C 20140920
// ARM10C 20151031
static struct kmem_cache *idr_layer_cache;
static DEFINE_PER_CPU(struct idr_layer *, idr_preload_head);
static DEFINE_PER_CPU(int, idr_preload_cnt);
static DEFINE_SPINLOCK(simple_ida_lock);

/* the maximum ID which can be allocated given idr->layers */
// ARM10C 20151107
// layers: 1
static int idr_max(int layers)
{
	// layers: 1, IDR_BITS: 8, MAX_IDR_SHIFT: 31, min_t(int, 8, 31): 8
	int bits = min_t(int, layers * IDR_BITS, MAX_IDR_SHIFT);
	// bits: 8

	// bits: 8
	return (1 << bits) - 1;
	// return 255
}

/*
 * Prefix mask for an idr_layer at @layer.  For layer 0, the prefix mask is
 * all bits except for the lower IDR_BITS.  For layer 1, 2 * IDR_BITS, and
 * so on.
 */
static int idr_layer_prefix_mask(int layer)
{
	return ~idr_max(layer + 1);
}

// ARM10C 20151031
// layer_idr: &(&mnt_id_ida)->idr
// ARM10C 20151031
// &ida->idr: &(&mnt_id_ida)->idr
// ARM10C 20151107
// &ida->idr: &(&mnt_id_ida)->idr
// ARM10C 20151114
// layer_idr: &(&unnamed_dev_ida)->idr
// ARM10C 20151114
// layer_idr: &(&unnamed_dev_ida)->idr
// ARM10C 20160116
// layer_idr: &(&sysfs_ino_ida)->idr
// ARM10C 20160116
// layer_idr: &(&sysfs_ino_ida)->idr
// ARM10C 20160305
// &ida->idr: &(&mnt_id_ida)->idr
// ARM10C 20160319
// &ida->idr: &(&unnamed_dev_ida)->idr
// ARM10C 20160416
// &ida->idr: &(&mnt_id_ida)->idr
static struct idr_layer *get_from_free_list(struct idr *idp)
{
	struct idr_layer *p;
	unsigned long flags;

	// &idp->lock: &(&(&mnt_id_ida)->idr)->lock
	// &idp->lock: &(&(&unnamed_dev_ida)->idr)->lock
	// &idp->lock: &(&(&sysfs_ino_ida)->idr)->lock
	// &idp->lock: &(&(&sysfs_ino_ida)->idr)->lock
	spin_lock_irqsave(&idp->lock, flags);

	// spin_lock_irqsave에서 한일:
	// &(&(&mnt_id_ida)->idr)->lock을 사용하여 spin lock 을 수행하고 cpsr을 flag에 저장함

	// spin_lock_irqsave에서 한일:
	// &(&(&unnamed_dev_ida)->idr)->lock을 사용하여 spin lock 을 수행하고 cpsr을 flag에 저장함

	// spin_lock_irqsave에서 한일:
	// &(&(&sysfs_ino_ida)->idr)->lock을 사용하여 spin lock 을 수행하고 cpsr을 flag에 저장함

	// spin_lock_irqsave에서 한일:
	// &(&(&sysfs_ino_ida)->idr)->lock을 사용하여 spin lock 을 수행하고 cpsr을 flag에 저장함

	// idp->id_free: (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8), p: kmem_cache#21-oX (idr object 8)
	// idp->id_free: (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8), p: kmem_cache#21-oX (idr object 8)
	// idp->id_free: (&(&sysfs_ino_ida)->idr)->id_free: NULL, p: NULL
	// idp->id_free: (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8), p: kmem_cache#21-oX (idr object 8)
	if ((p = idp->id_free)) {
		// idp->id_free: (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
		// p->ary[0]: (kmem_cache#21-oX (idr object 8))->ary[0]: kmem_cache#21-oX (idr object 7)
		// idp->id_free: (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
		// p->ary[0]: (kmem_cache#21-oX (idr object 8))->ary[0]: kmem_cache#21-oX (idr object 7)
		// idp->id_free: (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
		// p->ary[0]: (kmem_cache#21-oX (idr object 8))->ary[0]: kmem_cache#21-oX (idr object 7)
		idp->id_free = p->ary[0];
		// idp->id_free: (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 7)
		// idp->id_free: (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 7)
		// idp->id_free: (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 7)

		// idp->id_free_cnt: (&(&mnt_id_ida)->idr)->id_free_cnt: 8
		// idp->id_free_cnt: (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
		// idp->id_free_cnt: (&(&sysfs_ino_ida)->idr)->id_free_cnt: 8
		idp->id_free_cnt--;
		// idp->id_free_cnt: (&(&mnt_id_ida)->idr)->id_free_cnt: 7
		// idp->id_free_cnt: (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
		// idp->id_free_cnt: (&(&sysfs_ino_ida)->idr)->id_free_cnt: 7

		// p->ary[0]: (kmem_cache#21-oX (idr object 8))->ary[0]: kmem_cache#21-oX (idr object 7)
		// p->ary[0]: (kmem_cache#21-oX (idr object 8))->ary[0]: kmem_cache#21-oX (idr object 7)
		// p->ary[0]: (kmem_cache#21-oX (idr object 8))->ary[0]: kmem_cache#21-oX (idr object 7)
		p->ary[0] = NULL;
		// p->ary[0]: (kmem_cache#21-oX (idr object 8))->ary[0]: NULL
		// p->ary[0]: (kmem_cache#21-oX (idr object 8))->ary[0]: NULL
		// p->ary[0]: (kmem_cache#21-oX (idr object 8))->ary[0]: NULL
	}

	// &idp->lock: &(&(&mnt_id_ida)->idr)->lock
	// &idp->lock: &(&(&unnamed_dev_ida)->idr)->lock
	// &idp->lock: &(&(&sysfs_ino_ida)->idr)->lock
	// &idp->lock: &(&(&sysfs_ino_ida)->idr)->lock
	spin_unlock_irqrestore(&idp->lock, flags);

	// spin_unlock_irqrestore에서 한일:
	// &(&(&mnt_id_ida)->idr)->lock을 사용하여 spin unlock 을 수행하고 flag에 저장된 cpsr을 복원함

	// spin_unlock_irqrestore에서 한일:
	// &(&(&unnamed_dev_ida)->idr)->lock을 사용하여 spin unlock 을 수행하고 flag에 저장된 cpsr을 복원함

	// spin_unlock_irqrestore에서 한일:
	// &(&(&sysfs_ino_ida)->idr)->lock을 사용하여 spin unlock 을 수행하고 flag에 저장된 cpsr을 복원함

	// spin_unlock_irqrestore에서 한일:
	// &(&(&sysfs_ino_ida)->idr)->lock을 사용하여 spin unlock 을 수행하고 flag에 저장된 cpsr을 복원함

	// p: kmem_cache#21-oX (idr object 8)
	// p: kmem_cache#21-oX (idr object 8)
	// p: NULL
	// p: kmem_cache#21-oX (idr object 8)
	return(p);
	// return kmem_cache#21-oX (idr object 8)
	// return kmem_cache#21-oX (idr object 8)
	// return NULL
	// return kmem_cache#21-oX (idr object 8)
}

/**
 * idr_layer_alloc - allocate a new idr_layer
 * @gfp_mask: allocation mask
 * @layer_idr: optional idr to allocate from
 *
 * If @layer_idr is %NULL, directly allocate one using @gfp_mask or fetch
 * one from the per-cpu preload buffer.  If @layer_idr is not %NULL, fetch
 * an idr_layer from @idr->id_free.
 *
 * @layer_idr is to maintain backward compatibility with the old alloc
 * interface - idr_pre_get() and idr_get_new*() - and will be removed
 * together with per-pool preload buffer.
 */
// ARM10C 20151031
// gfp_mask: 0, layer_idr: &(&mnt_id_ida)->idr
// ARM10C 20151114
// gfp_mask: 0, layer_idr: &(&unnamed_dev_ida)->idr
// ARM10C 20160116
// gfp_mask: 0, layer_idr: &(&sysfs_ino_ida)->idr
// ARM10C 20160116
// gfp_mask: 0, layer_idr: &(&sysfs_ino_ida)->idr
// ARM10C 20160730
// gfp_mask: 0xD0, layer_idr: NULL
static struct idr_layer *idr_layer_alloc(gfp_t gfp_mask, struct idr *layer_idr)
{
	struct idr_layer *new;

	/* this is the old path, bypass to get_from_free_list() */
	// layer_idr: &(&mnt_id_ida)->idr
	// layer_idr: &(&unnamed_dev_ida)->idr
	// layer_idr: &(&sysfs_ino_ida)->idr
	// layer_idr: &(&sysfs_ino_ida)->idr
	// layer_idr: NULL
	if (layer_idr)
		// layer_idr: &(&mnt_id_ida)->idr
		// get_from_free_list(&(&mnt_id_ida)->idr): kmem_cache#21-oX (idr object 8)
		// layer_idr: &(&unnamed_dev_ida)->idr
		// get_from_free_list(&(&unnamed_dev_ida)->idr): kmem_cache#21-oX (idr object 8)
		// layer_idr: &(&sysfs_ino_ida)->idr
		// get_from_free_list(&(&sysfs_ino_ida)->idr): NULL
		// layer_idr: &(&sysfs_ino_ida)->idr
		// get_from_free_list(&(&sysfs_ino_ida)->idr): kmem_cache#21-oX (idr object 8)
		return get_from_free_list(layer_idr);
		// return kmem_cache#21-oX (idr object 8)
		// return kmem_cache#21-oX (idr object 8)
		// return NULL
		// return kmem_cache#21-oX (idr object 8)

		// get_from_free_list에서 한일:
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 7)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
		// (kmem_cache#21-oX (idr object 8))->ary[0]: NULL

		// get_from_free_list에서 한일:
		// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 7)
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
		// (kmem_cache#21-oX (idr object 8))->ary[0]: NULL

		// get_from_free_list에서 한일:
		// (&(&sysfs_ino_ida)->idr)->id_free: NULL 이므로 NULL 을 리턴함

		// get_from_free_list에서 한일:
		// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 7)
		// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 7
		// (kmem_cache#21-oX (idr object 8))->ary[0]: NULL

	/*
	 * Try to allocate directly from kmem_cache.  We want to try this
	 * before preload buffer; otherwise, non-preloading idr_alloc()
	 * users will end up taking advantage of preloading ones.  As the
	 * following is allowed to fail for preloaded cases, suppress
	 * warning this time.
	 */
	// idr_layer_cache: kmem_cache#21, gfp_mask: 0xD0, __GFP_NOWARN: 0x200u
	// kmem_cache_zalloc(kmem_cache#21, 0x2D0): kmem_cache#21-oX (struct idr_layer)
	new = kmem_cache_zalloc(idr_layer_cache, gfp_mask | __GFP_NOWARN);
	// new: kmem_cache#21-oX (struct idr_layer)

	// new: kmem_cache#21-oX (struct idr_layer)
	if (new)
		// new: kmem_cache#21-oX (struct idr_layer)
		return new;
		// return kmem_cache#21-oX (struct idr_layer)

	/*
	 * Try to fetch one from the per-cpu preload buffer if in process
	 * context.  See idr_preload() for details.
	 */
	if (!in_interrupt()) {
		preempt_disable();
		new = __this_cpu_read(idr_preload_head);
		if (new) {
			__this_cpu_write(idr_preload_head, new->ary[0]);
			__this_cpu_dec(idr_preload_cnt);
			new->ary[0] = NULL;
		}
		preempt_enable();
		if (new)
			return new;
	}

	/*
	 * Both failed.  Try kmem_cache again w/o adding __GFP_NOWARN so
	 * that memory allocation failure warning is printed as intended.
	 */
	return kmem_cache_zalloc(idr_layer_cache, gfp_mask);
}

static void idr_layer_rcu_free(struct rcu_head *head)
{
	struct idr_layer *layer;

	layer = container_of(head, struct idr_layer, rcu_head);
	kmem_cache_free(idr_layer_cache, layer);
}

static inline void free_layer(struct idr *idr, struct idr_layer *p)
{
	if (idr->hint && idr->hint == p)
		RCU_INIT_POINTER(idr->hint, NULL);
	call_rcu(&p->rcu_head, idr_layer_rcu_free);
}

/* only called when idp->lock is held */
// ARM10C 20151031
// idp: &(&mnt_id_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
// ARM10C 20151114
// idp: &(&unnamed_dev_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
// ARM10C 20160116
// idp: &(&sysfs_ino_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
// ARM10C 20160213
// idp: &(&mnt_id_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
// ARM10C 20160319
// idp: &(&unnamed_dev_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
// ARM10C 20160416
// idp: &(&mnt_id_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
// ARM10C 20160416
// idp: &(&unnamed_dev_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
static void __move_to_free_list(struct idr *idp, struct idr_layer *p)
{
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: NULL, idp->id_free: (&(&mnt_id_ida)->idr)->id_free: NULL
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: NULL, idp->id_free: (&(&unnamed_dev_ida)->idr)->id_free: NULL
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: NULL, idp->id_free: (&(&sysfs_ino_ida)->idr)->id_free: NULL
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: NULL, idp->id_free: (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (idr object 6)
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: NULL, idp->id_free: (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (idr object 6)
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: NULL, idp->id_free: (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (idr object new 0)
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: NULL, idp->id_free: (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (idr object 0)
	p->ary[0] = idp->id_free;
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: NULL
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: NULL
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: NULL
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: kmem_cache#21-oX (struct idr_layer) (idr object 6)
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: kmem_cache#21-oX (struct idr_layer) (idr object 6)
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: kmem_cache#21-oX (struct idr_layer) (idr object new 0)
	// p->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0]: kmem_cache#21-oX (struct idr_layer) (idr object new 0)

	// idp->id_free: (&(&mnt_id_ida)->idr)->id_free: NULL, p: kmem_cache#21-oX (struct idr_layer)
	// idp->id_free: (&(&unnamed_dev_ida)->idr)->id_free: NULL, p: kmem_cache#21-oX (struct idr_layer)
	// idp->id_free: (&(&sysfs_ino_ida)->idr)->id_free: NULL, p: kmem_cache#21-oX (struct idr_layer)
	// idp->id_free: (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (idr object 6), p: kmem_cache#21-oX (struct idr_layer) (new)
	// idp->id_free: (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (idr object 6), p: kmem_cache#21-oX (struct idr_layer) (new)
	// idp->id_free: (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (idr object new 0), p: kmem_cache#21-oX (struct idr_layer) (new)
	// idp->id_free: (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (idr object 0), p: kmem_cache#21-oX (struct idr_layer) (new)
	idp->id_free = p;
	// idp->id_free: (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer)
	// idp->id_free: (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer)
	// idp->id_free: (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer)
	// idp->id_free: (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (new)
	// idp->id_free: (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (new)
	// idp->id_free: (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (new)
	// idp->id_free: (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (new)

	// idp->id_free_cnt: (&(&mnt_id_ida)->idr)->id_free_cnt: 0
	// idp->id_free_cnt: (&(&unnamed_dev_ida)->idr)->id_free_cnt: 0
	// idp->id_free_cnt: (&(&sysfs_ino_ida)->idr)->id_free_cnt: 0
	// idp->id_free_cnt: (&(&mnt_id_ida)->idr)->id_free_cnt: 6
	// idp->id_free_cnt: (&(&unnamed_dev_ida)->idr)->id_free_cnt: 6
	// idp->id_free_cnt: (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	// idp->id_free_cnt: (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	idp->id_free_cnt++;
	// idp->id_free_cnt: (&(&mnt_id_ida)->idr)->id_free_cnt: 1
	// idp->id_free_cnt: (&(&unnamed_dev_ida)->idr)->id_free_cnt: 1
	// idp->id_free_cnt: (&(&sysfs_ino_ida)->idr)->id_free_cnt: 1
	// idp->id_free_cnt: (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	// idp->id_free_cnt: (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	// idp->id_free_cnt: (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	// idp->id_free_cnt: (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
}

// ARM10C 20151031
// idp: &(&mnt_id_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
// ARM10C 20151114
// idp: &(&unnamed_dev_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
// ARM10C 20160116
// idp: &(&sysfs_ino_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
// ARM10C 20160213
// idp: &(&mnt_id_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
// ARM10C 20160319
// idp: &(&unnamed_dev_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
// ARM10C 20160416
// idp: &(&mnt_id_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
// ARM10C 20160416
// idp: &(&unnamed_dev_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
static void move_to_free_list(struct idr *idp, struct idr_layer *p)
{
	unsigned long flags;

	/*
	 * Depends on the return element being zeroed.
	 */
	// &idp->lock: &(&(&mnt_id_ida)->idr)->lock
	// &idp->lock: &(&(&unnamed_dev_ida)->idr)->lock
	// &idp->lock: &(&(&sysfs_ino_ida)->idr)->lock
	// &idp->lock: &(&(&mnt_id_ida)->idr)->lock
	// &idp->lock: &(&(&unnamed_dev_ida)->idr)->lock
	// &idp->lock: &(&(&mnt_id_ida)->idr)->lock
	// &idp->lock: &(&(&unnamed_dev_ida)->idr)->lock
	spin_lock_irqsave(&idp->lock, flags);

	// spin_lock_irqsave에서 한일:
	// &(&(&mnt_id_ida)->idr)->lock을 사용하여 spin lock을 수행하고 cpsr을 flags에 저장함

	// spin_lock_irqsave에서 한일:
	// &(&(&unnamed_dev_ida)->idr)->lock을 사용하여 spin lock을 수행하고 cpsr을 flags에 저장함

	// spin_lock_irqsave에서 한일:
	// &(&(&sysfs_ino_ida)->idr)->lock을 사용하여 spin lock을 수행하고 cpsr을 flags에 저장함

	// spin_lock_irqsave에서 한일:
	// &(&(&mnt_id_ida)->idr)->lock을 사용하여 spin lock을 수행하고 cpsr을 flags에 저장함

	// spin_lock_irqsave에서 한일:
	// &(&(&unnamed_dev_ida)->idr)->lock을 사용하여 spin lock을 수행하고 cpsr을 flags에 저장함

	// spin_lock_irqsave에서 한일:
	// &(&(&mnt_id_ida)->idr)->lock을 사용하여 spin lock을 수행하고 cpsr을 flags에 저장함

	// spin_lock_irqsave에서 한일:
	// &(&(&unnamed_dev_ida)->idr)->lock을 사용하여 spin lock을 수행하고 cpsr을 flags에 저장함

	// idp: &(&mnt_id_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
	// idp: &(&unnamed_dev_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
	// idp: &(&sysfs_ino_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
	// idp: &(&mnt_id_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
	// idp: &(&unnamed_dev_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
	// idp: &(&mnt_id_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
	// idp: &(&unnamed_dev_ida)->idr, p: kmem_cache#21-oX (struct idr_layer)
	__move_to_free_list(idp, p);

	// __move_to_free_list에서 한일:
	// (kmem_cache#21-oX)->ary[0]: NULL
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 1

	// __move_to_free_list에서 한일:
	// (kmem_cache#21-oX)->ary[0]: NULL
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 1

	// __move_to_free_list에서 한일:
	// (kmem_cache#21-oX)->ary[0]: NULL
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 1

	// __move_to_free_list에서 한일:
	// (kmem_cache#21-oX (struct idr_layer) (new))->ary[0]: kmem_cache#21-oX (struct idr_layer) (idr object 6)
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (new)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7

	// __move_to_free_list에서 한일:
	// (kmem_cache#21-oX (struct idr_layer) (new))->ary[0]: kmem_cache#21-oX (struct idr_layer) (idr object 6)
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (new)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7

	// __move_to_free_list에서 한일:
	// (kmem_cache#21-oX (struct idr_layer) (new))->ary[0]: kmem_cache#21-oX (struct idr_layer) (idr object new 0)
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (new)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8

	// __move_to_free_list에서 한일:
	// (kmem_cache#21-oX (struct idr_layer) (new))->ary[0]: kmem_cache#21-oX (struct idr_layer) (idr object 6)
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (new)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8

	spin_unlock_irqrestore(&idp->lock, flags);

	// spin_unlock_irqrestore에서 한일:
	// &(&(&mnt_id_ida)->idr)->lock을 사용하여 spin unlock을 수행하고 flags에 저장된 cpsr을 복원

	// spin_unlock_irqrestore에서 한일:
	// &(&(&unnamed_dev_ida)->idr)->lock을 사용하여 spin unlock을 수행하고 flags에 저장된 cpsr을 복원

	// spin_unlock_irqrestore에서 한일:
	// &(&(&sysfs_ino_ida)->idr)->lock을 사용하여 spin unlock을 수행하고 flags에 저장된 cpsr을 복원

	// spin_unlock_irqrestore에서 한일:
	// &(&(&mnt_id_ida)->idr)->lock을 사용하여 spin unlock을 수행하고 flags에 저장된 cpsr을 복원

	// spin_unlock_irqrestore에서 한일:
	// &(&(&unnamed_dev_ida)->idr)->lock을 사용하여 spin unlock을 수행하고 flags에 저장된 cpsr을 복원

	// spin_unlock_irqrestore에서 한일:
	// &(&(&mnt_id_ida)->idr)->lock을 사용하여 spin unlock을 수행하고 flags에 저장된 cpsr을 복원

	// spin_unlock_irqrestore에서 한일:
	// &(&(&unnamed_dev_ida)->idr)->lock을 사용하여 spin unlock을 수행하고 flags에 저장된 cpsr을 복원
}

// ARM10C 20160730
// pa, id: 0
static void idr_mark_full(struct idr_layer **pa, int id)
{
	// pa[0]: kmem_cache#21-oX (struct idr_layer)
	struct idr_layer *p = pa[0];
	// p: kmem_cache#21-oX (struct idr_layer)

	int l = 0;
	// l: 0

	// id: 0, IDR_MASK: 0xff, p->bitmap: (kmem_cache#21-oX (struct idr_layer))->bitmap
	__set_bit(id & IDR_MASK, p->bitmap);

	// __set_bit 에서 한일:
	// (kmem_cache#21-oX (struct idr_layer))->bitmap 의 0 bit를 1로 set 함

	/*
	 * If this layer is full mark the bit in the layer above to
	 * show that this part of the radix tree is full.  This may
	 * complete the layer above and require walking up the radix
	 * tree.
	 */
	// p->bitmap: (kmem_cache#21-oX (struct idr_layer))->bitmap, IDR_SIZE: 0x100
	// bitmap_full((kmem_cache#21-oX (struct idr_layer))->bitmap, 0x100): 1
	while (bitmap_full(p->bitmap, IDR_SIZE)) {
		// l: 1, pa[1]: NULL, p: NULL
		if (!(p = pa[++l]))
			break;
			// break 수행

		id = id >> IDR_BITS;
		__set_bit((id & IDR_MASK), p->bitmap);
	}
}

// ARM10C 20151031
// &ida->idr: &(&mnt_id_ida)->idr, gfp_mask: 0xD0
// ARM10C 20151114
// &ida->idr: &(&unnamed_dev_ida)->idr, gfp_mask: 0x20
// ARM10C 20160116
// &ida->idr: &(&sysfs_ino_ida)->idr, gfp_mask: 0x40
// ARM10C 20160213
// &ida->idr: &(&mnt_id_ida)->idr, gfp_mask: 0xD0
// ARM10C 20160319
// &ida->idr: &(&unnamed_dev_ida)->idr, gfp_mask: 0x20
// ARM10C 20160416
// &ida->idr: &(&mnt_id_ida)->idr, gfp_mask: 0xD0
// ARM10C 20160416
// &ida->idr: &(&unnamed_dev_ida)->idr, gfp_mask: 0x20
int __idr_pre_get(struct idr *idp, gfp_t gfp_mask)
{
	// NOTE:
	// MAX_IDR_FREE 값이 8 인 이유는?
	// We want shallower trees and thus more bits covered at each layer.  8
	// bits gives us large enough first layer for most use cases and maximum
	// tree depth of 4.  Each idr_layer is slightly larger than 2k on 64bit and
	// 1k on 32bit.

	// idp->id_free_cnt: (&(&mnt_id_ida)->idr)->id_free_cnt: 0, MAX_IDR_FREE: 8
	// idp->id_free_cnt: (&(&unnamed_dev_ida)->idr)->id_free_cnt: 0, MAX_IDR_FREE: 8
	// idp->id_free_cnt: (&(&sysfs_ino_ida)->idr)->id_free_cnt: 0, MAX_IDR_FREE: 8
	// idp->id_free_cnt: (&(&mnt_id_ida)->idr)->id_free_cnt: 6, MAX_IDR_FREE: 8
	// idp->id_free_cnt: (&(&unnamed_dev_ida)->idr)->id_free_cnt: 6, MAX_IDR_FREE: 8
	// idp->id_free_cnt: (&(&mnt_id_ida)->idr)->id_free_cnt: 7, MAX_IDR_FREE: 8
	// idp->id_free_cnt: (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7, MAX_IDR_FREE: 8
	while (idp->id_free_cnt < MAX_IDR_FREE) {
		struct idr_layer *new;

		// idr_layer_cache: kmem_cache#21, gfp_mask: 0xD0
		// kmem_cache_zalloc(kmem_cache#21, 0xD0): kmem_cache#21-oX (struct idr_layer)
		// idr_layer_cache: kmem_cache#21, gfp_mask: 0x20
		// kmem_cache_zalloc(kmem_cache#21, 0x20): kmem_cache#21-oX (struct idr_layer)
		// idr_layer_cache: kmem_cache#21, gfp_mask: 0x20
		// kmem_cache_zalloc(kmem_cache#21, 0x20): kmem_cache#21-oX (struct idr_layer)
		// idr_layer_cache: kmem_cache#21, gfp_mask: 0xD0
		// kmem_cache_zalloc(kmem_cache#21, 0xD0): kmem_cache#21-oX (struct idr_layer)
		// idr_layer_cache: kmem_cache#21, gfp_mask: 0xD0
		// kmem_cache_zalloc(kmem_cache#21, 0xD0): kmem_cache#21-oX (struct idr_layer)
		// idr_layer_cache: kmem_cache#21, gfp_mask: 0xD0
		// kmem_cache_zalloc(kmem_cache#21, 0xD0): kmem_cache#21-oX (struct idr_layer)
		// idr_layer_cache: kmem_cache#21, gfp_mask: 0xD0
		// kmem_cache_zalloc(kmem_cache#21, 0xD0): kmem_cache#21-oX (struct idr_layer)
		new = kmem_cache_zalloc(idr_layer_cache, gfp_mask);
		// new: kmem_cache#21-oX (struct idr_layer)
		// new: kmem_cache#21-oX (struct idr_layer)
		// new: kmem_cache#21-oX (struct idr_layer)
		// new: kmem_cache#21-oX (struct idr_layer)
		// new: kmem_cache#21-oX (struct idr_layer)
		// new: kmem_cache#21-oX (struct idr_layer)
		// new: kmem_cache#21-oX (struct idr_layer)

		// new: kmem_cache#21-oX (struct idr_layer)
		// new: kmem_cache#21-oX (struct idr_layer)
		// new: kmem_cache#21-oX (struct idr_layer)
		// new: kmem_cache#21-oX (struct idr_layer)
		// new: kmem_cache#21-oX (struct idr_layer)
		// new: kmem_cache#21-oX (struct idr_layer)
		// new: kmem_cache#21-oX (struct idr_layer)
		if (new == NULL)
			return (0);

		// idp: &(&mnt_id_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
		// idp: &(&unnamed_dev_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
		// idp: &(&sysfs_ino_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
		// idp: &(&mnt_id_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
		// idp: &(&unnamed_dev_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
		// idp: &(&mnt_id_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
		// idp: &(&unnamed_dev_ida)->idr, new: kmem_cache#21-oX (struct idr_layer)
		move_to_free_list(idp, new);

		// move_to_free_list에서 한일:
		// (kmem_cache#21-oX)->ary[0]: NULL
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 1
		//
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 2...8 까지 loop 수행
		//
		// loop를8 번 수행한 결과
		// (&(&mnt_id_ida)->idr)->id_free 이 idr object 8 번을 가르킴
		// |
		// |-> ---------------------------------------------------------------------------------------------------------------------------
		//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 8

		// move_to_free_list에서 한일:
		// (kmem_cache#21-oX)->ary[0]: NULL
		// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 1
		//
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 2...8 까지 loop 수행
		//
		// loop를8 번 수행한 결과
		// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object 8 번을 가르킴
		// |
		// |-> ---------------------------------------------------------------------------------------------------------------------------
		//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//
		// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8

		// move_to_free_list에서 한일:
		// (kmem_cache#21-oX)->ary[0]: NULL
		// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX
		// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 1
		//
		// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 2...8 까지 loop 수행
		//
		// loop를8 번 수행한 결과
		// (&(&sysfs_ino_ida)->idr)->id_free 이 idr object 8 번을 가르킴
		// |
		// |-> ---------------------------------------------------------------------------------------------------------------------------
		//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//
		// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
		// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 8

		// move_to_free_list에서 한일:
		// (kmem_cache#21-oX (struct idr_layer) (new 0))->ary[0]: kmem_cache#21-oX (struct idr_layer) (idr object 6)
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (new 0)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
		//
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 7...8 까지 loop 수행
		//
		// loop를2 번 수행한 결과
		// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 1번을 가르킴
		// |
		// |-> ---------------------------------------------------------------------------------------------------------------------------
		//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 8

		// move_to_free_list에서 한일:
		// (kmem_cache#21-oX (struct idr_layer) (new 0))->ary[0]: kmem_cache#21-oX (struct idr_layer) (idr object 6)
		// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (new 0)
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
		//
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7...8 까지 loop 수행
		//
		// loop를2 번 수행한 결과
		// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 1번을 가르킴
		// |
		// |-> ---------------------------------------------------------------------------------------------------------------------------
		//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//
		// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8

		// move_to_free_list에서 한일:
		// (kmem_cache#21-oX (struct idr_layer) (new 2))->ary[0]: kmem_cache#21-oX (struct idr_layer) (idr object new 0)
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (new 2)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
		//
		// loop를1 번 수행한 결과
		// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 2번을 가르킴
		// |
		// |-> ---------------------------------------------------------------------------------------------------------------------------
		//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 8

		// move_to_free_list에서 한일:
		// (kmem_cache#21-oX (struct idr_layer) (new 0))->ary[0]: kmem_cache#21-oX (struct idr_layer) (idr object 6)
		// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (struct idr_layer) (new 2)
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
		//
		// loop를1 번 수행한 결과
		// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 1번을 가르킴
		// |
		// |-> ---------------------------------------------------------------------------------------------------------------------------
		//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//
		// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	}
	return 1;
	// return 1
	// return 1
	// return 1
	// return 1
	// return 1
	// return 1
}
EXPORT_SYMBOL(__idr_pre_get);

/**
 * sub_alloc - try to allocate an id without growing the tree depth
 * @idp: idr handle
 * @starting_id: id to start search at
 * @pa: idr_layer[MAX_IDR_LEVEL] used as backtrack buffer
 * @gfp_mask: allocation mask for idr_layer_alloc()
 * @layer_idr: optional idr passed to idr_layer_alloc()
 *
 * Allocate an id in range [@starting_id, INT_MAX] from @idp without
 * growing its depth.  Returns
 *
 *  the allocated id >= 0 if successful,
 *  -EAGAIN if the tree needs to grow for allocation to succeed,
 *  -ENOSPC if the id space is exhausted,
 *  -ENOMEM if more idr_layers need to be allocated.
 */
// ARM10C 20151107
// idp: &(&mnt_id_ida)->idr, id: 0, pa, gfp_mask: 0, layer_idr: &(&mnt_id_ida)->idr
// ARM10C 20151114
// idp: &(&unnamed_dev_ida)->idr, id: 0, pa, gfp_mask: 0, layer_idr: &(&unnamed_dev_ida)->idr
// ARM10C 20160116
// idp: &(&sysfs_ino_ida)->idr, id: 0, pa, gfp_mask: 0, layer_idr: &(&sysfs_ino_ida)->idr
// ARM10C 20160213
// idp: &(&mnt_id_ida)->idr, id: 0, pa, gfp_mask: 0, layer_idr: &(&mnt_id_ida)->idr
// ARM10C 20160319
// idp: &(&unnamed_dev_ida)->idr, id: 0, pa, gfp_mask: 0, layer_idr: &(&unnamed_dev_ida)->idr
// ARM10C 20160416
// idp: &(&mnt_id_ida)->idr, id: 0, pa, gfp_mask: 0, layer_idr: &(&mnt_id_ida)->idr
// ARM10C 20160730
// &(&cgroup_hierarchy_idr)->idr, &id, pa, 0xD0, &(&cgroup_hierarchy_idr)->idr
static int sub_alloc(struct idr *idp, int *starting_id, struct idr_layer **pa,
		     gfp_t gfp_mask, struct idr *layer_idr)
{
	int n, m, sh;
	struct idr_layer *p, *new;
	int l, id, oid;

	// *starting_id: 0
	// *starting_id: 0
	// *starting_id: 0
	// *starting_id: 0
	// *starting_id: 0
	// *starting_id: 0
	// *starting_id: 0
	id = *starting_id;
	// id: 0
	// id: 0
	// id: 0
	// id: 0
	// id: 0
	// id: 0
	// id: 0

 restart:
	// idp->top: (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// idp->top: (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// idp->top: (&(&sysfs_ino_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// idp->top: (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// idp->top: (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// idp->top: (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// idp->top: (&(&cgroup_hierarchy_idr)->idr)->top: kmem_cache#21-oX (struct idr_layer)
	p = idp->top;
	// p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// p: kmem_cache#21-oX (struct idr_layer)

	// idp->layers: (&(&mnt_id_ida)->idr)->layers: 1
	// idp->layers: (&(&unnamed_dev_ida)->idr)->layers: 1
	// idp->layers: (&(&sysfs_ino_ida)->idr)->layers: 1
	// idp->layers: (&(&mnt_id_ida)->idr)->layers: 1
	// idp->layers: (&(&unnamed_dev_ida)->idr)->layers: 1
	// idp->layers: (&(&mnt_id_ida)->idr)->layers: 1
	// idp->layers: (&(&cgroup_hierarchy_idr)->idr)->layers: 1
	l = idp->layers;
	// l: 1
	// l: 1
	// l: 1
	// l: 1
	// l: 1
	// l: 1
	// l: 1

	// l: 1
	// l: 1
	// l: 1
	// l: 1
	// l: 1
	// l: 1
	// l: 1
	pa[l--] = NULL;
	// pa[1]: NULL, l: 0
	// pa[1]: NULL, l: 0
	// pa[1]: NULL, l: 0
	// pa[1]: NULL, l: 0
	// pa[1]: NULL, l: 0
	// pa[1]: NULL, l: 0
	// pa[1]: NULL, l: 0

	while (1) {
		/*
		 * We run around this while until we reach the leaf node...
		 */
		// id: 0, IDR_BITS: 8, l: 0, IDR_MASK: 0xFF
		// id: 0, IDR_BITS: 8, l: 0, IDR_MASK: 0xFF
		// id: 0, IDR_BITS: 8, l: 0, IDR_MASK: 0xFF
		// id: 0, IDR_BITS: 8, l: 0, IDR_MASK: 0xFF
		// id: 0, IDR_BITS: 8, l: 0, IDR_MASK: 0xFF
		// id: 0, IDR_BITS: 8, l: 0, IDR_MASK: 0xFF
		// id: 0, IDR_BITS: 8, l: 0, IDR_MASK: 0xFF
		n = (id >> (IDR_BITS*l)) & IDR_MASK;
		// n: 0
		// n: 0
		// n: 0
		// n: 0
		// n: 0
		// n: 0
		// n: 0

		// p->bitmap: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->bitmap, IDR_SIZE: 0x100, n: 0
		// find_next_zero_bit((kmem_cache#21-oX (struct idr_layer) (idr object 8))->bitmap, 0x100, 0): 0
		// p->bitmap: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->bitmap, IDR_SIZE: 0x100, n: 0
		// find_next_zero_bit((kmem_cache#21-oX (struct idr_layer) (idr object 8))->bitmap, 0x100, 0): 0
		// p->bitmap: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->bitmap, IDR_SIZE: 0x100, n: 0
		// find_next_zero_bit((kmem_cache#21-oX (struct idr_layer) (idr object 8))->bitmap, 0x100, 0): 0
		// p->bitmap: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->bitmap, IDR_SIZE: 0x100, n: 0
		// find_next_zero_bit((kmem_cache#21-oX (struct idr_layer) (idr object 8))->bitmap, 0x100, 0): 0
		// p->bitmap: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->bitmap, IDR_SIZE: 0x100, n: 0
		// find_next_zero_bit((kmem_cache#21-oX (struct idr_layer) (idr object 8))->bitmap, 0x100, 0): 0
		// p->bitmap: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->bitmap, IDR_SIZE: 0x100, n: 0
		// find_next_zero_bit((kmem_cache#21-oX)->bitmap (struct idr_layer), 0x100, 0): 0
		// p->bitmap: (kmem_cache#21-oX (struct idr_layer))->bitmap, IDR_SIZE: 0x100, n: 0
		// find_next_zero_bit((kmem_cache#21-oX)->bitmap (struct idr_layer), 0x100, 0): 0
		m = find_next_zero_bit(p->bitmap, IDR_SIZE, n);
		// m: 0
		// m: 0
		// m: 0
		// m: 0
		// m: 0
		// m: 0
		// m: 0

		// m: 0, IDR_SIZE: 0x100
		// m: 0, IDR_SIZE: 0x100
		// m: 0, IDR_SIZE: 0x100
		// m: 0, IDR_SIZE: 0x100
		// m: 0, IDR_SIZE: 0x100
		// m: 0, IDR_SIZE: 0x100
		// m: 0, IDR_SIZE: 0x100
		if (m == IDR_SIZE) {
			/* no space available go back to previous layer. */
			l++;

			oid = id;

			id = (id | ((1 << (IDR_BITS * l)) - 1)) + 1;

			/* if already at the top layer, we need to grow */
			if (id >= 1 << (idp->layers * IDR_BITS)) {
				*starting_id = id;
				return -EAGAIN;
			}
			p = pa[l];
			BUG_ON(!p);

			/* If we need to go up one layer, continue the
			 * loop; otherwise, restart from the top.
			 */
			sh = IDR_BITS * (l + 1);
			if (oid >> sh == id >> sh)
				continue;
			else
				goto restart;
		}

		// m: 0, n: 0
		// m: 0, n: 0
		// m: 0, n: 0
		// m: 0, n: 0
		// m: 0, n: 0
		// m: 0, n: 0
		// m: 0, n: 0
		if (m != n) {
			sh = IDR_BITS*l;
			id = ((id >> sh) ^ n ^ m) << sh;
		}

		// id: 0, MAX_IDR_BIT: 0x80000000
		// id: 0, MAX_IDR_BIT: 0x80000000
		// id: 0, MAX_IDR_BIT: 0x80000000
		// id: 0, MAX_IDR_BIT: 0x80000000
		// id: 0, MAX_IDR_BIT: 0x80000000
		// id: 0, MAX_IDR_BIT: 0x80000000
		if ((id >= MAX_IDR_BIT) || (id < 0))
			return -ENOSPC;

		// l: 0
		// l: 0
		// l: 0
		// l: 0
		// l: 0
		// l: 0
		// l: 0
		if (l == 0)
			break;
			// break 수행
			// break 수행
			// break 수행
			// break 수행
			// break 수행
			// break 수행
			// break 수행
		/*
		 * Create the layer below if it is missing.
		 */
		if (!p->ary[m]) {
			new = idr_layer_alloc(gfp_mask, layer_idr);
			if (!new)
				return -ENOMEM;
			new->layer = l-1;
			new->prefix = id & idr_layer_prefix_mask(new->layer);
			rcu_assign_pointer(p->ary[m], new);
			p->count++;
		}
		pa[l--] = p;
		p = p->ary[m];
	}

	// l: 0, p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// l: 0, p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// l: 0, p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// l: 0, p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// l: 0, p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// l: 0, p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// l: 0, p: kmem_cache#21-oX (struct idr_layer)
	pa[l] = p;
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// pa[0]: kmem_cache#21-oX (struct idr_layer)

	// id: 0
	// id: 0
	// id: 0
	// id: 0
	// id: 0
	// id: 0
	// id: 0
	return id;
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
}

// ARM10C 20151031
// &ida->idr: &(&mnt_id_ida)->idr, idr_id: 0, pa, 0, &ida->idr: &(&mnt_id_ida)->idr
// ARM10C 20151114
// &ida->idr: &(&unnamed_dev_ida)->idr, idr_id: 0, pa, 0, &ida->idr: &(&unnamed_dev_ida)->idr
// ARM10C 20160116
// &ida->idr: &(&sysfs_ino_ida)->idr, idr_id: 0, pa, 0, &ida->idr: &(&sysfs_ino_ida)->idr
// ARM10C 20160116
// &ida->idr: &(&sysfs_ino_ida)->idr, idr_id: 0, pa, 0, &ida->idr: &(&sysfs_ino_ida)->idr
// ARM10C 20160213
// &ida->idr: &(&mnt_id_ida)->idr, idr_id: 0, pa, 0, &ida->idr: &(&mnt_id_ida)->idr
// ARM10C 20160319
// &ida->idr: &(&unnamed_dev_ida)->idr, idr_id: 0, pa, 0, &ida->idr: &(&unnamed_dev_ida)->idr
// ARM10C 20160416
// &ida->idr: &(&mnt_id_ida)->idr, idr_id: 0, pa, 0, &ida->idr: &(&mnt_id_ida)->idr
// ARM10C 20160730
// idr: &cgroup_hierarchy_idr, start: 0, pa, gfp_mask: 0xD0, NULL
//
// ARM10C 20160730
// idr: &cgroup_dummy_root.cgroup_idr, start: 0, pa, gfp_mask: 0xD0, NULL
static int idr_get_empty_slot(struct idr *idp, int starting_id,
			      struct idr_layer **pa, gfp_t gfp_mask,
			      struct idr *layer_idr)
{
	struct idr_layer *p, *new;
	int layers, v, id;
	unsigned long flags;

	// starting_id: 0
	// starting_id: 0
	// starting_id: 0
	// starting_id: 0
	// starting_id: 0
	// starting_id: 0
	// starting_id: 0
	// starting_id: 0
	id = starting_id;
	// id: 0
	// id: 0
	// id: 0
	// id: 0
	// id: 0
	// id: 0
	// id: 0
	// id: 0

build_up:
	// idp->top: (&(&mnt_id_ida)->idr)->top: NULL
	// idp->top: (&(&unnamed_dev_ida)->idr)->top: NULL
	// idp->top: (&(&sysfs_ino_ida)->idr)->top: NULL
	// idp->top: (&(&sysfs_ino_ida)->idr)->top: NULL
	// idp->top: ((&(&mnt_id_ida)->idr)->top): kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// idp->top: ((&(&unnamed_dev_ida)->idr)->top): kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// idp->top: ((&(&mnt_id_ida)->idr)->top): kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// idp->top: (&cgroup_hierarchy_idr)->top: NULL
	p = idp->top;
	// p: NULL
	// p: NULL
	// p: NULL
	// p: NULL
	// p: ((&(&mnt_id_ida)->idr)->top): kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// p: ((&(&unnamed_dev_ida)->idr)->top): kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// p: ((&(&mnt_id_ida)->idr)->top): kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// p: NULL

	// idp->layers: (&(&mnt_id_ida)->idr)->layers: 0
	// idp->layers: (&(&unnamed_dev_ida)->idr)->layers: 0
	// idp->layers: (&(&sysfs_ino_ida)->idr)->layers: 0
	// idp->layers: (&(&sysfs_ino_ida)->idr)->layers: 0
	// idp->layers: (&(&mnt_id_ida)->idr)->layers: 1
	// idp->layers: (&(&unnamed_dev_ida)->idr)->layers: 1
	// idp->layers: (&(&mnt_id_ida)->idr)->layers: 1
	// idp->layers: (&(&cgroup_hierarchy_idr)->idr)->layers: 0
	layers = idp->layers;
	// layers: 0
	// layers: 0
	// layers: 0
	// layers: 0
	// layers: 1
	// layers: 1
	// layers: 1
	// layers: 0

	// p: NULL
	// p: NULL
	// p: NULL
	// p: NULL
	// p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// p: NULL
	if (unlikely(!p)) {
		// gfp_mask: 0, layer_idr: &(&mnt_id_ida)->idr
		// idr_layer_alloc(0, &(&mnt_id_ida)->idr): kmem_cache#21-oX (idr object 8), p: kmem_cache#21-oX (idr object 8)
		// gfp_mask: 0, layer_idr: &(&unnamed_dev_ida)->idr
		// idr_layer_alloc(0, &(&unnamed_dev_ida)->idr): kmem_cache#21-oX (idr object 8), p: kmem_cache#21-oX (idr object 8)
		// gfp_mask: 0, layer_idr: &(&sysfs_ino_ida)->idr
		// idr_layer_alloc(0, &(&sysfs_ino_ida)->idr): NULL, p: NULL
		// gfp_mask: 0, layer_idr: &(&sysfs_ino_ida)->idr
		// idr_layer_alloc(0, &(&sysfs_ino_ida)->idr): kmem_cache#21-oX (idr object 8), p: kmem_cache#21-oX (idr object 8)
		// gfp_mask: 0xD0, layer_idr: NULL,
		// idr_layer_alloc(0xD0, NULL): kmem_cache#21-oX (struct idr_layer), p: kmem_cache#21-oX (struct idr_layer)
		if (!(p = idr_layer_alloc(gfp_mask, layer_idr)))
			// ENOMEM: 12
			return -ENOMEM;
			// return -12

		// idr_layer_alloc에서 한일:
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 7)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
		// (kmem_cache#21-oX (idr object 8))->ary[0]: NULL

		// idr_layer_alloc에서 한일:
		// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 7)
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
		// (kmem_cache#21-oX (idr object 8))->ary[0]: NULL

		// idr_layer_alloc에서 한일:
		// (&(&sysfs_ino_ida)->idr)->id_free: NULL 이므로 NULL 을 리턴함

		// idr_layer_alloc에서 한일:
		// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 7)
		// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 7
		// (kmem_cache#21-oX (idr object 8))->ary[0]: NULL

		// idr_layer_alloc에서 한일:
		// idr_layer_cache: kmem_cache#21 을 사용하여 struct idr_layer 만큼의 메모리를 할당 받음
		// kmem_cache#21-oX (struct idr_layer)

		// p->layer: (kmem_cache#21-oX (idr object 8))->layer
		// p->layer: (kmem_cache#21-oX (idr object 8))->layer
		// p->layer: (kmem_cache#21-oX (idr object 8))->layer
		// p->layer: (kmem_cache#21-oX (struct idr_layer))->layer
		p->layer = 0;
		// p->layer: (kmem_cache#21-oX (idr object 8))->layer: 0
		// p->layer: (kmem_cache#21-oX (idr object 8))->layer: 0
		// p->layer: (kmem_cache#21-oX (idr object 8))->layer: 0
		// p->layer: (kmem_cache#21-oX (struct idr_layer))->layer: 0

		// layers: 0
		// layers: 0
		// layers: 0
		// layers: 0
		layers = 1;
		// layers: 1
		// layers: 1
		// layers: 1
		// layers: 1
	}

// 2015/10/31 종료
// 2015/11/07 시작

	/*
	 * Add a new layer to the top of the tree if the requested
	 * id is larger than the currently allocated space.
	 */
	// id: 0, layers: 1, idr_max(1): 255
	// id: 0, layers: 1, idr_max(1): 255
	// id: 0, layers: 1, idr_max(1): 255
	// id: 0, layers: 1, idr_max(1): 255
	// id: 0, layers: 1, idr_max(1): 255
	// id: 0, layers: 1, idr_max(1): 255
	// id: 0, layers: 1, idr_max(1): 255
	// id: 0, layers: 1, idr_max(1): 255
	while (id > idr_max(layers)) {
		layers++;
		if (!p->count) {
			/* special case: if the tree is currently empty,
			 * then we grow the tree by moving the top node
			 * upwards.
			 */
			p->layer++;
			WARN_ON_ONCE(p->prefix);
			continue;
		}
		if (!(new = idr_layer_alloc(gfp_mask, layer_idr))) {
			/*
			 * The allocation failed.  If we built part of
			 * the structure tear it down.
			 */
			spin_lock_irqsave(&idp->lock, flags);
			for (new = p; p && p != idp->top; new = p) {
				p = p->ary[0];
				new->ary[0] = NULL;
				new->count = 0;
				bitmap_clear(new->bitmap, 0, IDR_SIZE);
				__move_to_free_list(idp, new);
			}
			spin_unlock_irqrestore(&idp->lock, flags);
			return -ENOMEM;
		}
		new->ary[0] = p;
		new->count = 1;
		new->layer = layers-1;
		new->prefix = id & idr_layer_prefix_mask(new->layer);
		if (bitmap_full(p->bitmap, IDR_SIZE))
			__set_bit(0, new->bitmap);
		p = new;
	}

	// idp->top: (&(&mnt_id_ida)->idr)->top, p: kmem_cache#21-oX (idr object 8)
	// __rcu_assign_pointer((&(&mnt_id_ida)->idr)->top, kmem_cache#21-oX (idr object 8), __rcu):
	// do {
	//      smp_wmb();
	//      ((&(&mnt_id_ida)->idr)->top) = (typeof(*kmem_cache#21-oX (idr object 8)) __force space *)(kmem_cache#21-oX (idr object 8));
	// } while (0)
	// idp->top: (&(&unnamed_dev_ida)->idr)->top, p: kmem_cache#21-oX (idr object 8)
	// __rcu_assign_pointer((&(&unnamed_dev_ida)->idr)->top, kmem_cache#21-oX (idr object 8), __rcu):
	// do {
	//      smp_wmb();
	//      ((&(&unnamed_dev_ida)->idr)->top) = (typeof(*kmem_cache#21-oX (idr object 8)) __force space *)(kmem_cache#21-oX (idr object 8));
	// } while (0)
	// idp->top: (&(&sysfs_ino_ida)->idr)->top, p: kmem_cache#21-oX (idr object 8)
	// __rcu_assign_pointer((&(&sysfs_ino_ida)->idr)->top, kmem_cache#21-oX (idr object 8), __rcu):
	// do {
	//      smp_wmb();
	//      ((&(&sysfs_ino_ida)->idr)->top) = (typeof(*kmem_cache#21-oX (idr object 8)) __force space *)(kmem_cache#21-oX (idr object 8));
	// } while (0)
	// idp->top: (&(&mnt_id_ida)->idr)->top, p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// __rcu_assign_pointer((&(&mnt_id_ida)->idr)->top, kmem_cache#21-oX (struct idr_layer) (idr object 8), __rcu):
	// do {
	//      smp_wmb();
	//      ((&(&mnt_id_ida)->idr)->top) = (typeof(*kmem_cache#21-oX (struct idr_layer) (idr object 8)) __force space *)(kmem_cache#21-oX (struct idr_layer) (idr object 8));
	// } while (0)
	// idp->top: (&(&unnamed_dev_ida)->idr)->top, p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// __rcu_assign_pointer((&(&unnamed_dev_ida)->idr)->top, kmem_cache#21-oX (struct idr_layer) (idr object 8), __rcu):
	// do {
	//      smp_wmb();
	//      ((&(&unnamed_dev_ida)->idr)->top) = (typeof(*kmem_cache#21-oX (struct idr_layer) (idr object 8)) __force space *)(kmem_cache#21-oX (struct idr_layer) (idr object 8));
	// } while (0)
	// idp->top: (&(&mnt_id_ida)->idr)->top, p: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// __rcu_assign_pointer((&(&mnt_id_ida)->idr)->top, kmem_cache#21-oX (struct idr_layer) (idr object 8), __rcu):
	// do {
	//      smp_wmb();
	//      ((&(&mnt_id_ida)->idr)->top) = (typeof(*kmem_cache#21-oX (struct idr_layer) (idr object 8)) __force space *)(kmem_cache#21-oX (struct idr_layer) (idr object 8));
	// } while (0)
	// idp->top: (&(&cgroup_hierarchy_idr)->idr)->top, p: kmem_cache#21-oX (struct idr_layer)
	// __rcu_assign_pointer((&(&cgroup_hierarchy_idr)->idr)->top, kmem_cache#21-oX (struct idr_layer), __rcu):
	// do {
	//      smp_wmb();
	//      ((&(&cgroup_hierarchy_idr)->idr)->top) = (typeof(*kmem_cache#21-oX (struct idr_layer)) __force space *)(kmem_cache#21-oX (struct idr_layer));
	// } while (0)
	rcu_assign_pointer(idp->top, p);
	// ((&(&mnt_id_ida)->idr)->top): (typeof(*kmem_cache#21-o7) __force space *)(kmem_cache#21-o7 (idr object 8))
	// ((&(&unnamed_dev_ida)->idr)->top): (typeof(*kmem_cache#21-o7) __force space *)(kmem_cache#21-o7 (idr object 8))
	// ((&(&sysfs_ino_ida)->idr)->top): (typeof(*kmem_cache#21-o7) __force space *)(kmem_cache#21-o7 (idr object 8))
	// ((&(&mnt_id_ida)->idr)->top): (typeof(*kmem_cache#21-oX (struct idr_layer) (idr object 8)) __force space *)(kmem_cache#21-oX (struct idr_layer) (idr object 8))
	// ((&(&unnamed_dev_ida)->idr)->top): (typeof(*kmem_cache#21-oX (struct idr_layer) (idr object 8)) __force space *)(kmem_cache#21-oX (struct idr_layer) (idr object 8))
	// ((&(&mnt_id_ida)->idr)->top): (typeof(*kmem_cache#21-oX (struct idr_layer) (idr object 8)) __force space *)(kmem_cache#21-oX (struct idr_layer) (idr object 8))
	// ((&(&cgroup_hierarchy_idr)->idr)->top): (typeof(*kmem_cache#21-oX (struct idr_layer)) __force space *)(kmem_cache#21-oX (struct idr_layer))

	// idp->layers: (&(&mnt_id_ida)->idr)->layers, layers: 1
	// idp->layers: (&(&unnamed_dev_ida)->idr)->layers, layers: 1
	// idp->layers: (&(&sysfs_ino_ida)->idr)->layers, layers: 1
	// idp->layers: (&(&mnt_id_ida)->idr)->layers, layers: 1
	// idp->layers: (&(&unnamed_dev_ida)->idr)->layers, layers: 1
	// idp->layers: (&(&mnt_id_ida)->idr)->layers, layers: 1
	// idp->layers: (&(&cgroup_hierarchy_idr)->idr)->layers, layers: 1
	idp->layers = layers;
	// idp->layers: (&(&mnt_id_ida)->idr)->layers: 1
	// idp->layers: (&(&unnamed_dev_ida)->idr)->layers: 1
	// idp->layers: (&(&sysfs_ino_ida)->idr)->layers: 1
	// idp->layers: (&(&mnt_id_ida)->idr)->layers: 1
	// idp->layers: (&(&unnamed_dev_ida)->idr)->layers: 1
	// idp->layers: (&(&mnt_id_ida)->idr)->layers: 1
	// idp->layers: (&(&cgroup_hierarchy_idr)->idr)->layers: 1

	// idp: &(&mnt_id_ida)->idr, id: 0, pa, gfp_mask: 0, layer_idr: &(&mnt_id_ida)->idr
	// sub_alloc(&(&mnt_id_ida)->idr, &id, pa, 0, &(&mnt_id_ida)->idr): 0
	// idp: &(&unnamed_dev_ida)->idr, id: 0, pa, gfp_mask: 0, layer_idr: &(&unnamed_dev_ida)->idr
	// sub_alloc(&(&unnamed_dev_ida)->idr, &id, pa, 0, &(&unnamed_dev_ida)->idr): 0
	// idp: &(&sysfs_ino_ida)->idr, id: 0, pa, gfp_mask: 0, layer_idr: &(&sysfs_ino_ida)->idr
	// sub_alloc(&(&sysfs_ino_ida)->idr, &id, pa, 0, &(&sysfs_ino_ida)->idr): 0
	// idp: &(&mnt_id_ida)->idr, id: 0, pa, gfp_mask: 0, layer_idr: &(&mnt_id_ida)->idr
	// sub_alloc(&(&mnt_id_ida)->idr, &id, pa, 0, &(&mnt_id_ida)->idr): 0
	// idp: &(&unnamed_dev_ida)->idr, id: 0, pa, gfp_mask: 0, layer_idr: &(&unnamed_dev_ida)->idr
	// sub_alloc(&(&unnamed_dev_ida)->idr, &id, pa, 0, &(&unnamed_dev_ida)->idr): 0
	// idp: &(&mnt_id_ida)->idr, id: 0, pa, gfp_mask: 0, layer_idr: &(&mnt_id_ida)->idr
	// sub_alloc(&(&mnt_id_ida)->idr, &id, pa, 0, &(&mnt_id_ida)->idr): 0
	// idp: &(&cgroup_hierarchy_idr)->idr, id: 0, pa, gfp_mask: 0xD0, layer_idr: &(&cgroup_hierarchy_idr)->idr
	// sub_alloc(&(&cgroup_hierarchy_idr)->idr, &id, pa, 0xD0, &(&cgroup_hierarchy_idr)->idr): 0
	v = sub_alloc(idp, &id, pa, gfp_mask, layer_idr);
	// v: 0
	// v: 0
	// v: 0
	// v: 0
	// v: 0
	// v: 0
	// v: 0

	// sub_alloc에서 한일:
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)

	// sub_alloc에서 한일:
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)

	// sub_alloc에서 한일:
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)

	// sub_alloc에서 한일:
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)

	// sub_alloc에서 한일:
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)

	// sub_alloc에서 한일:
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)

	// sub_alloc에서 한일:
	// pa[0]: kmem_cache#21-oX (struct idr_layer)

	// v: 0, EAGAIN: 11
	// v: 0, EAGAIN: 11
	// v: 0, EAGAIN: 11
	// v: 0, EAGAIN: 11
	// v: 0, EAGAIN: 11
	// v: 0, EAGAIN: 11
	// v: 0, EAGAIN: 11
	if (v == -EAGAIN)
		goto build_up;

	// v: 0
	// v: 0
	// v: 0
	// v: 0
	// v: 0
	// v: 0
	// v: 0
	return(v);
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
}

/*
 * @id and @pa are from a successful allocation from idr_get_empty_slot().
 * Install the user pointer @ptr and mark the slot full.
 */
// ARM10C 20160730
// idr: &cgroup_hierarchy_idr, ptr: &cgroup_dummy_root, id: 0, pa
// ARM10C 20160730
// idr: &cgroup_dummy_root.cgroup_idr, ptr: cgroup_dummy_top: &cgroup_dummy_root.top_cgroup, id: 0, pa
static void idr_fill_slot(struct idr *idr, void *ptr, int id,
			  struct idr_layer **pa)
{
	/* update hint used for lookup, cleared from free_layer() */
	// idr->hint: (&cgroup_hierarchy_idr)->hint, pa[0]: kmem_cache#21-oX (struct idr_layer)
	rcu_assign_pointer(idr->hint, pa[0]);

	// rcu_assign_pointer 에서 한일:
	// (&cgroup_hierarchy_idr)->hint: kmem_cache#21-oX (struct idr_layer)

	// id: 0, IDR_MASK: 0xFF, pa[0]->ary[0]: (kmem_cache#21-oX (struct idr_layer))->ary[0],
	// ptr: &cgroup_dummy_root
	rcu_assign_pointer(pa[0]->ary[id & IDR_MASK], (struct idr_layer *)ptr);

	// rcu_assign_pointer 에서 한일:
	// (kmem_cache#21-oX (struct idr_layer))->ary[0]: &cgroup_dummy_root

	// pa[0]->count: (kmem_cache#21-oX (struct idr_layer))->count: 0
	pa[0]->count++;
	// pa[0]->count: (kmem_cache#21-oX (struct idr_layer))->count: 1

	// id: 0
	idr_mark_full(pa, id);

	// idr_mark_full 에서 한일:
	// (kmem_cache#21-oX (struct idr_layer))->bitmap 의 0 bit를 1로 set 함
}

int __idr_get_new_above(struct idr *idp, void *ptr, int starting_id, int *id)
{
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	int rv;

	rv = idr_get_empty_slot(idp, starting_id, pa, 0, idp);
	if (rv < 0)
		return rv == -ENOMEM ? -EAGAIN : rv;

	idr_fill_slot(idp, ptr, rv, pa);
	*id = rv;
	return 0;
}
EXPORT_SYMBOL(__idr_get_new_above);

/**
 * idr_preload - preload for idr_alloc()
 * @gfp_mask: allocation mask to use for preloading
 *
 * Preload per-cpu layer buffer for idr_alloc().  Can only be used from
 * process context and each idr_preload() invocation should be matched with
 * idr_preload_end().  Note that preemption is disabled while preloaded.
 *
 * The first idr_alloc() in the preloaded section can be treated as if it
 * were invoked with @gfp_mask used for preloading.  This allows using more
 * permissive allocation masks for idrs protected by spinlocks.
 *
 * For example, if idr_alloc() below fails, the failure can be treated as
 * if idr_alloc() were called with GFP_KERNEL rather than GFP_NOWAIT.
 *
 *	idr_preload(GFP_KERNEL);
 *	spin_lock(lock);
 *
 *	id = idr_alloc(idr, ptr, start, end, GFP_NOWAIT);
 *
 *	spin_unlock(lock);
 *	idr_preload_end();
 *	if (id < 0)
 *		error;
 */
void idr_preload(gfp_t gfp_mask)
{
	/*
	 * Consuming preload buffer from non-process context breaks preload
	 * allocation guarantee.  Disallow usage from those contexts.
	 */
	WARN_ON_ONCE(in_interrupt());
	might_sleep_if(gfp_mask & __GFP_WAIT);

	preempt_disable();

	/*
	 * idr_alloc() is likely to succeed w/o full idr_layer buffer and
	 * return value from idr_alloc() needs to be checked for failure
	 * anyway.  Silently give up if allocation fails.  The caller can
	 * treat failures from idr_alloc() as if idr_alloc() were called
	 * with @gfp_mask which should be enough.
	 */
	while (__this_cpu_read(idr_preload_cnt) < MAX_IDR_FREE) {
		struct idr_layer *new;

		preempt_enable();
		new = kmem_cache_zalloc(idr_layer_cache, gfp_mask);
		preempt_disable();
		if (!new)
			break;

		/* link the new one to per-cpu preload list */
		new->ary[0] = __this_cpu_read(idr_preload_head);
		__this_cpu_write(idr_preload_head, new);
		__this_cpu_inc(idr_preload_cnt);
	}
}
EXPORT_SYMBOL(idr_preload);

/**
 * idr_alloc - allocate new idr entry
 * @idr: the (initialized) idr
 * @ptr: pointer to be associated with the new id
 * @start: the minimum id (inclusive)
 * @end: the maximum id (exclusive, <= 0 for max)
 * @gfp_mask: memory allocation flags
 *
 * Allocate an id in [start, end) and associate it with @ptr.  If no ID is
 * available in the specified range, returns -ENOSPC.  On memory allocation
 * failure, returns -ENOMEM.
 *
 * Note that @end is treated as max when <= 0.  This is to always allow
 * using @start + N as @end as long as N is inside integer range.
 *
 * The user is responsible for exclusively synchronizing all operations
 * which may modify @idr.  However, read-only accesses such as idr_find()
 * or iteration can be performed under RCU read lock provided the user
 * destroys @ptr in RCU-safe way after removal from idr.
 */
// ARM10C 20160730
// idr: &cgroup_hierarchy_idr, ptr: &cgroup_dummy_root, 0, end: 1, gfp_mask: 0xD0
// ARM10C 20160730
// &cgroup_dummy_root.cgroup_idr, cgroup_dummy_top, 0, 1, GFP_KERNEL: 0xD0
int idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp_mask)
{
	// end: 1
	// end: 1
	int max = end > 0 ? end - 1 : INT_MAX;	/* inclusive upper limit */
	// max: 0
	// max: 0

	// MAX_IDR_LEVEL: 4
	// MAX_IDR_LEVEL: 4
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	int id;

	// gfp_mask: 0xD0, __GFP_WAIT: 0x10u
	// gfp_mask: 0xD0, __GFP_WAIT: 0x10u
	might_sleep_if(gfp_mask & __GFP_WAIT); // null function

	/* sanity checks */
	// start: 0
	// start: 0
	if (WARN_ON_ONCE(start < 0))
		return -EINVAL;

	// max: 0, start: 0
	// max: 0, start: 0
	if (unlikely(max < start))
		return -ENOSPC;

	/* allocate id */
	// idr: &cgroup_hierarchy_idr, start: 0, gfp_mask: 0xD0
	// idr_get_empty_slot(&cgroup_hierarchy_idr, 0, pa, 0xD0, NULL): 0
	// idr: &cgroup_dummy_root.cgroup_idr, start: 0, gfp_mask: 0xD0
	// idr_get_empty_slot(&cgroup_dummy_root.cgroup_idr, 0, pa, 0xD0, NULL): 0
	id = idr_get_empty_slot(idr, start, pa, gfp_mask, NULL);
	// id: 0
	// id: 0

	// idr_get_empty_slot에서 한일:
	// idr_layer_cache: kmem_cache#21 을 사용하여 struct idr_layer 만큼의 메모리를 할당 받음
	// kmem_cache#21-oX (struct idr_layer)
	//
	// (&(&cgroup_hierarchy_idr)->idr)->layers: 1
	// (&(&cgroup_hierarchy_idr)->idr)->top: kmem_cache#21-oX (struct idr_layer)
	//
	// (kmem_cache#21-oX (struct idr_layer))->layer: 0
	// pa[0]: kmem_cache#21-oX (struct idr_layer)

	// idr_get_empty_slot에서 한일:
	// idr_layer_cache: kmem_cache#21 을 사용하여 struct idr_layer 만큼의 메모리를 할당 받음
	// kmem_cache#21-oX (struct idr_layer)
	//
	// (&(&cgroup_dummy_root.cgroup_idr)->idr)->layers: 1
	// (&(&cgroup_dummy_root.cgroup_idr)->idr)->top: kmem_cache#21-oX (struct idr_layer)
	//
	// (kmem_cache#21-oX (struct idr_layer))->layer: 0
	// pa[0]: kmem_cache#21-oX (struct idr_layer)

	// id: 0
	// id: 0
	if (unlikely(id < 0))
		return id;

	// id: 0, max: 0
	// id: 0, max: 0
	if (unlikely(id > max))
		return -ENOSPC;

	// idr: &cgroup_hierarchy_idr, ptr: &cgroup_dummy_root, id: 0
	// idr: &cgroup_dummy_root.cgroup_idr, ptr: cgroup_dummy_top: &cgroup_dummy_root.top_cgroup, id: 0
	idr_fill_slot(idr, ptr, id, pa);

	// idr_fill_slot 에서 한일:
	// (&cgroup_hierarchy_idr)->hint: kmem_cache#21-oX (struct idr_layer)
	// (kmem_cache#21-oX (struct idr_layer))->ary[0]: &cgroup_dummy_root
	// (kmem_cache#21-oX (struct idr_layer))->count: 1
	// (kmem_cache#21-oX (struct idr_layer))->bitmap 의 0 bit를 1로 set 함

	// idr_fill_slot 에서 한일:
	// (&cgroup_dummy_root.cgroup_idr)->hint: kmem_cache#21-oX (struct idr_layer)
	// (kmem_cache#21-oX (struct idr_layer))->ary[0]: &cgroup_dummy_root.top_cgroup
	// (kmem_cache#21-oX (struct idr_layer))->count: 1
	// (kmem_cache#21-oX (struct idr_layer))->bitmap 의 0 bit를 1로 set 함

	// id: 0
	// id: 0
	return id;
	// return 0
	// return 0
}
EXPORT_SYMBOL_GPL(idr_alloc);

/**
 * idr_alloc_cyclic - allocate new idr entry in a cyclical fashion
 * @idr: the (initialized) idr
 * @ptr: pointer to be associated with the new id
 * @start: the minimum id (inclusive)
 * @end: the maximum id (exclusive, <= 0 for max)
 * @gfp_mask: memory allocation flags
 *
 * Essentially the same as idr_alloc, but prefers to allocate progressively
 * higher ids if it can. If the "cur" counter wraps, then it will start again
 * at the "start" end of the range and allocate one that has already been used.
 */
// ARM10C 20160730
// &cgroup_hierarchy_idr, root: &cgroup_dummy_root, start: 0, end: 1, GFP_KERNEL: 0xD0
int idr_alloc_cyclic(struct idr *idr, void *ptr, int start, int end,
			gfp_t gfp_mask)
{
	int id;

	// idr: &cgroup_hierarchy_idr, ptr: &cgroup_dummy_root, start: 0, idr->cur: (&cgroup_hierarchy_idr)->cur
	// max(0, 0): 0, end: 1, gfp_mask: 0xD0
	// idr_alloc(&cgroup_hierarchy_idr, &cgroup_dummy_root, 0, 1, 0xD0): 0
	id = idr_alloc(idr, ptr, max(start, idr->cur), end, gfp_mask);
	// id: 0

	// idr_alloc 에서 한일:
	// idr_layer_cache: kmem_cache#21 을 사용하여 struct idr_layer 만큼의 메모리를 할당 받음
	// kmem_cache#21-oX (struct idr_layer)
	//
	// (&(&cgroup_hierarchy_idr)->idr)->layers: 1
	// (&(&cgroup_hierarchy_idr)->idr)->top: kmem_cache#21-oX (struct idr_layer)
	//
	// (kmem_cache#21-oX (struct idr_layer))->layer: 0
	// pa[0]: kmem_cache#21-oX (struct idr_layer)
	//
	// (&cgroup_hierarchy_idr)->hint: kmem_cache#21-oX (struct idr_layer)
	// (kmem_cache#21-oX (struct idr_layer))->ary[0]: &cgroup_dummy_root
	// (kmem_cache#21-oX (struct idr_layer))->count: 1
	// (kmem_cache#21-oX (struct idr_layer))->bitmap 의 0 bit를 1로 set 함

	// id: 0, ENOSPC: 28
	if (id == -ENOSPC)
		id = idr_alloc(idr, ptr, start, end, gfp_mask);

	// id: 0
	if (likely(id >= 0))
		// idr->cur: (&cgroup_hierarchy_idr)->cur, id: 0
		idr->cur = id + 1;
		// idr->cur: (&cgroup_hierarchy_idr)->cur: 1

	// id: 0
	return id;
	// return 0
}
EXPORT_SYMBOL(idr_alloc_cyclic);

static void idr_remove_warning(int id)
{
	WARN(1, "idr_remove called for id=%d which is not allocated.\n", id);
}

static void sub_remove(struct idr *idp, int shift, int id)
{
	struct idr_layer *p = idp->top;
	struct idr_layer **pa[MAX_IDR_LEVEL + 1];
	struct idr_layer ***paa = &pa[0];
	struct idr_layer *to_free;
	int n;

	*paa = NULL;
	*++paa = &idp->top;

	while ((shift > 0) && p) {
		n = (id >> shift) & IDR_MASK;
		__clear_bit(n, p->bitmap);
		*++paa = &p->ary[n];
		p = p->ary[n];
		shift -= IDR_BITS;
	}
	n = id & IDR_MASK;
	if (likely(p != NULL && test_bit(n, p->bitmap))) {
		__clear_bit(n, p->bitmap);
		rcu_assign_pointer(p->ary[n], NULL);
		to_free = NULL;
		while(*paa && ! --((**paa)->count)){
			if (to_free)
				free_layer(idp, to_free);
			to_free = **paa;
			**paa-- = NULL;
		}
		if (!*paa)
			idp->layers = 0;
		if (to_free)
			free_layer(idp, to_free);
	} else
		idr_remove_warning(id);
}

/**
 * idr_remove - remove the given id and free its slot
 * @idp: idr handle
 * @id: unique key
 */
void idr_remove(struct idr *idp, int id)
{
	struct idr_layer *p;
	struct idr_layer *to_free;

	if (id < 0)
		return;

	sub_remove(idp, (idp->layers - 1) * IDR_BITS, id);
	if (idp->top && idp->top->count == 1 && (idp->layers > 1) &&
	    idp->top->ary[0]) {
		/*
		 * Single child at leftmost slot: we can shrink the tree.
		 * This level is not needed anymore since when layers are
		 * inserted, they are inserted at the top of the existing
		 * tree.
		 */
		to_free = idp->top;
		p = idp->top->ary[0];
		rcu_assign_pointer(idp->top, p);
		--idp->layers;
		to_free->count = 0;
		bitmap_clear(to_free->bitmap, 0, IDR_SIZE);
		free_layer(idp, to_free);
	}
	while (idp->id_free_cnt >= MAX_IDR_FREE) {
		p = get_from_free_list(idp);
		/*
		 * Note: we don't call the rcu callback here, since the only
		 * layers that fall into the freelist are those that have been
		 * preallocated.
		 */
		kmem_cache_free(idr_layer_cache, p);
	}
	return;
}
EXPORT_SYMBOL(idr_remove);

void __idr_remove_all(struct idr *idp)
{
	int n, id, max;
	int bt_mask;
	struct idr_layer *p;
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];

	n = idp->layers * IDR_BITS;
	p = idp->top;
	rcu_assign_pointer(idp->top, NULL);
	max = idr_max(idp->layers);

	id = 0;
	while (id >= 0 && id <= max) {
		while (n > IDR_BITS && p) {
			n -= IDR_BITS;
			*paa++ = p;
			p = p->ary[(id >> n) & IDR_MASK];
		}

		bt_mask = id;
		id += 1 << n;
		/* Get the highest bit that the above add changed from 0->1. */
		while (n < fls(id ^ bt_mask)) {
			if (p)
				free_layer(idp, p);
			n += IDR_BITS;
			p = *--paa;
		}
	}
	idp->layers = 0;
}
EXPORT_SYMBOL(__idr_remove_all);

/**
 * idr_destroy - release all cached layers within an idr tree
 * @idp: idr handle
 *
 * Free all id mappings and all idp_layers.  After this function, @idp is
 * completely unused and can be freed / recycled.  The caller is
 * responsible for ensuring that no one else accesses @idp during or after
 * idr_destroy().
 *
 * A typical clean-up sequence for objects stored in an idr tree will use
 * idr_for_each() to free all objects, if necessay, then idr_destroy() to
 * free up the id mappings and cached idr_layers.
 */
void idr_destroy(struct idr *idp)
{
	__idr_remove_all(idp);

	while (idp->id_free_cnt) {
		struct idr_layer *p = get_from_free_list(idp);
		kmem_cache_free(idr_layer_cache, p);
	}
}
EXPORT_SYMBOL(idr_destroy);

void *idr_find_slowpath(struct idr *idp, int id)
{
	int n;
	struct idr_layer *p;

	if (id < 0)
		return NULL;

	p = rcu_dereference_raw(idp->top);
	if (!p)
		return NULL;
	n = (p->layer+1) * IDR_BITS;

	if (id > idr_max(p->layer + 1))
		return NULL;
	BUG_ON(n == 0);

	while (n > 0 && p) {
		n -= IDR_BITS;
		BUG_ON(n != p->layer*IDR_BITS);
		p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
	}
	return((void *)p);
}
EXPORT_SYMBOL(idr_find_slowpath);

/**
 * idr_for_each - iterate through all stored pointers
 * @idp: idr handle
 * @fn: function to be called for each pointer
 * @data: data passed back to callback function
 *
 * Iterate over the pointers registered with the given idr.  The
 * callback function will be called for each pointer currently
 * registered, passing the id, the pointer and the data pointer passed
 * to this function.  It is not safe to modify the idr tree while in
 * the callback, so functions such as idr_get_new and idr_remove are
 * not allowed.
 *
 * We check the return of @fn each time. If it returns anything other
 * than %0, we break out and return that value.
 *
 * The caller must serialize idr_for_each() vs idr_get_new() and idr_remove().
 */
int idr_for_each(struct idr *idp,
		 int (*fn)(int id, void *p, void *data), void *data)
{
	int n, id, max, error = 0;
	struct idr_layer *p;
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];

	n = idp->layers * IDR_BITS;
	p = rcu_dereference_raw(idp->top);
	max = idr_max(idp->layers);

	id = 0;
	while (id >= 0 && id <= max) {
		while (n > 0 && p) {
			n -= IDR_BITS;
			*paa++ = p;
			p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
		}

		if (p) {
			error = fn(id, (void *)p, data);
			if (error)
				break;
		}

		id += 1 << n;
		while (n < fls(id)) {
			n += IDR_BITS;
			p = *--paa;
		}
	}

	return error;
}
EXPORT_SYMBOL(idr_for_each);

/**
 * idr_get_next - lookup next object of id to given id.
 * @idp: idr handle
 * @nextidp:  pointer to lookup key
 *
 * Returns pointer to registered object with id, which is next number to
 * given id. After being looked up, *@nextidp will be updated for the next
 * iteration.
 *
 * This function can be called under rcu_read_lock(), given that the leaf
 * pointers lifetimes are correctly managed.
 */
void *idr_get_next(struct idr *idp, int *nextidp)
{
	struct idr_layer *p, *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];
	int id = *nextidp;
	int n, max;

	/* find first ent */
	p = rcu_dereference_raw(idp->top);
	if (!p)
		return NULL;
	n = (p->layer + 1) * IDR_BITS;
	max = idr_max(p->layer + 1);

	while (id >= 0 && id <= max) {
		while (n > 0 && p) {
			n -= IDR_BITS;
			*paa++ = p;
			p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
		}

		if (p) {
			*nextidp = id;
			return p;
		}

		/*
		 * Proceed to the next layer at the current level.  Unlike
		 * idr_for_each(), @id isn't guaranteed to be aligned to
		 * layer boundary at this point and adding 1 << n may
		 * incorrectly skip IDs.  Make sure we jump to the
		 * beginning of the next layer using round_up().
		 */
		id = round_up(id + 1, 1 << n);
		while (n < fls(id)) {
			n += IDR_BITS;
			p = *--paa;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(idr_get_next);


/**
 * idr_replace - replace pointer for given id
 * @idp: idr handle
 * @ptr: pointer you want associated with the id
 * @id: lookup key
 *
 * Replace the pointer registered with an id and return the old value.
 * A %-ENOENT return indicates that @id was not found.
 * A %-EINVAL return indicates that @id was not within valid constraints.
 *
 * The caller must serialize with writers.
 */
void *idr_replace(struct idr *idp, void *ptr, int id)
{
	int n;
	struct idr_layer *p, *old_p;

	if (id < 0)
		return ERR_PTR(-EINVAL);

	p = idp->top;
	if (!p)
		return ERR_PTR(-EINVAL);

	n = (p->layer+1) * IDR_BITS;

	if (id >= (1 << n))
		return ERR_PTR(-EINVAL);

	n -= IDR_BITS;
	while ((n > 0) && p) {
		p = p->ary[(id >> n) & IDR_MASK];
		n -= IDR_BITS;
	}

	n = id & IDR_MASK;
	if (unlikely(p == NULL || !test_bit(n, p->bitmap)))
		return ERR_PTR(-ENOENT);

	old_p = p->ary[n];
	rcu_assign_pointer(p->ary[n], ptr);

	return old_p;
}
EXPORT_SYMBOL(idr_replace);

// ARM10C 20140920
void __init idr_init_cache(void)
{
	// sizeof(struct idr_layer): 1076 bytes, SLAB_PANIC: 0x00040000UL
	// kmem_cache_create("idr_layer_cache", 1076, 0, SLAB_PANIC: 0x00040000UL, NULL): kmem_cache#21
	idr_layer_cache = kmem_cache_create("idr_layer_cache",
				sizeof(struct idr_layer), 0, SLAB_PANIC, NULL);
	// idr_layer_cache: kmem_cache#21
}

/**
 * idr_init - initialize idr handle
 * @idp:	idr handle
 *
 * This function is use to set up the handle (@idp) that you will pass
 * to the rest of the functions.
 */
// ARM10C 20150808
// &root->cgroup_idr: &(&cgroup_dummy_root)->cgroup_idr
// ARM10C 20160116
void idr_init(struct idr *idp)
{
	// idp: &(&cgroup_dummy_root)->cgroup_idr, sizeof(struct idr): 40 bytes
	memset(idp, 0, sizeof(struct idr));

	// memset에서 한일:
	// (&cgroup_dummy_root)->cgroup_idr의 맵버값을 0으로 초기화 수행

	// &idp->lock: &(&(&cgroup_dummy_root)->cgroup_idr)->lock
	spin_lock_init(&idp->lock);

	// spin_lock_init에서 한일:
	// (&(&(&cgroup_dummy_root)->cgroup_idr)->lock)->raw_lock: { { 0 } }
	// (&(&(&cgroup_dummy_root)->cgroup_idr)->lock)->magic: 0xdead4ead
	// (&(&(&cgroup_dummy_root)->cgroup_idr)->lock)->owner: 0xffffffff
	// (&(&(&cgroup_dummy_root)->cgroup_idr)->lock)->owner_cpu: 0xffffffff
}
EXPORT_SYMBOL(idr_init);


/**
 * DOC: IDA description
 * IDA - IDR based ID allocator
 *
 * This is id allocator without id -> pointer translation.  Memory
 * usage is much lower than full blown idr because each id only
 * occupies a bit.  ida uses a custom leaf node which contains
 * IDA_BITMAP_BITS slots.
 *
 * 2007-04-25  written by Tejun Heo <htejun@gmail.com>
 */

// ARM10C 20151031
// ida: &mnt_id_ida, bitmap: kmem_cache#27-oX (struct ida_bitmap)
// ARM10C 20151114
// ida: &unnamed_dev_ida, bitmap: kmem_cache#27-oX (struct ida_bitmap)
// ARM10C 20160116
// ida: &sysfs_ino_ida, bitmap: kmem_cache#27-oX (struct ida_bitmap)
// ARM10C 20160305
// ida: &mnt_id_ida, bitmap: kmem_cache#27-oX (struct ida_bitmap)
// ARM10C 20160319
// ida: &unnamed_dev_ida, bitmap: kmem_cache#27-oX (struct ida_bitmap)
static void free_bitmap(struct ida *ida, struct ida_bitmap *bitmap)
{
	unsigned long flags;

	// ida->free_bitmap: (&mnt_id_ida)->free_bitmap: NULL
	if (!ida->free_bitmap) {
		// &ida->idr.lock: (&mnt_id_ida)->idr.lock
		spin_lock_irqsave(&ida->idr.lock, flags);

		// spin_lock_irqsave에서 한일:
		// (&mnt_id_ida)->idr.lock을 사용하여 spin lock 을 수행하고 cpsr을 flags에 저장함

		// ida->free_bitmap: (&mnt_id_ida)->free_bitmap: NULL
		if (!ida->free_bitmap) {
			// ida->free_bitmap: (&mnt_id_ida)->free_bitmap: NULL, bitmap: kmem_cache#27-oX (struct ida_bitmap)
			ida->free_bitmap = bitmap;
			// ida->free_bitmap: (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)

			// bitmap: kmem_cache#27-oX
			bitmap = NULL;
			// bitmap: NULL
		}
		spin_unlock_irqrestore(&ida->idr.lock, flags);

		// spin_unlock_irqrestore에서 한일:
		// (&mnt_id_ida)->idr.lock을 사용하여 spin unlock 을 수행하고 flags에 저장된 cpsr을 복원함
	}

	// bitmap: NULL
	kfree(bitmap);
}

/**
 * ida_pre_get - reserve resources for ida allocation
 * @ida:	ida handle
 * @gfp_mask:	memory allocation flag
 *
 * This function should be called prior to locking and calling the
 * following function.  It preallocates enough memory to satisfy the
 * worst possible allocation.
 *
 * If the system is REALLY out of memory this function returns %0,
 * otherwise %1.
 */
// ARM10C 20151031
// &mnt_id_ida, GFP_KERNEL: 0xD0
// ARM10C 20151114
// &unnamed_dev_ida, GFP_ATOMIC: 0x20u
// ARM10C 20160116
// &sysfs_ino_ida, GFP_KERNEL: 0xD0
// ARM10C 20160213
// &mnt_id_ida, GFP_KERNEL: 0xD0
// ARM10C 20160319
// &unnamed_dev_ida, GFP_ATOMIC: 0x20
// ARM10C 20160416
// &mnt_id_ida, GFP_KERNEL: 0xD0
// ARM10C 20160416
// &unnamed_dev_ida, GFP_ATOMIC: 0x20
// ARM10C 20160514
// &proc_inum_ida, GFP_KERNEL: 0xD0
// ARM10C 20160521
// &unnamed_dev_ida, GFP_ATOMIC: 0x20
// ARM10C 20160604
// &proc_inum_ida, GFP_KERNEL: 0xD0
// ARM10C 20160611
// &proc_inum_ida, GFP_KERNEL: 0xD0
// ARM10C 20161112
// &unnamed_dev_ida, GFP_ATOMIC: 0x20
int ida_pre_get(struct ida *ida, gfp_t gfp_mask)
{
	/* allocate idr_layers */
	// &ida->idr: &(&mnt_id_ida)->idr, gfp_mask: 0xD0
	// __idr_pre_get(&(&mnt_id_ida)->idr, 0xD0): 1
	// &ida->idr: &(&unnamed_dev_ida)->idr, gfp_mask: 0x20
	// __idr_pre_get(&(&unnamed_dev_ida)->idr, 0x20): 1
	// &ida->idr: &(&sysfs_ino_ida)->idr, gfp_mask: 0x40
	// __idr_pre_get(&(&sysfs_ino_ida)->idr, 0x40): 1
	// &ida->idr: &(&mnt_id_ida)->idr, gfp_mask: 0xD0
	// __idr_pre_get(&(&mnt_id_ida)->idr, 0xD0): 1
	// &ida->idr: &(&unnamed_dev_ida)->idr, gfp_mask: 0x20
	// __idr_pre_get(&(&unnamed_dev_ida)->idr, 0x20): 1
	// &ida->idr: &(&mnt_id_ida)->idr, gfp_mask: 0xD0
	// __idr_pre_get(&(&mnt_id_ida)->idr, 0xD0): 1
	// &ida->idr: &(&unnamed_dev_ida)->idr, gfp_mask: 0x20
	// __idr_pre_get(&(&unnamed_dev_ida)->idr, 0x20): 1
	// &ida->idr: &(&proc_inum_ida)->idr, gfp_mask: 0xD0
	// __idr_pre_get(&(&proc_inum_ida)->idr, 0xD0): 1
	if (!__idr_pre_get(&ida->idr, gfp_mask))
		return 0;

	// __idr_pre_get에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8

	// __idr_pre_get에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8

	// __idr_pre_get에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&sysfs_ino_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 8

	// __idr_pre_get에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 2 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 1번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8

	// __idr_pre_get에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 2 개를 할당 받음
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 1번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8

	// __idr_pre_get에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 2번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8

	// __idr_pre_get에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 2번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8

	// __idr_pre_get에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&proc_inum_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&proc_inum_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 8

	/* allocate free_bitmap */
	// ida->free_bitmap: (&mnt_id_ida)->free_bitmap: NULL
	// ida->free_bitmap: (&unnamed_dev_ida)->free_bitmap: NULL
	// ida->free_bitmap: (&sysfs_ino_ida)->free_bitmap: NULL
	// ida->free_bitmap: (&mnt_id_ida)->free_bitmap: NULL
	// ida->free_bitmap: (&unnamed_dev_ida)->free_bitmap: NULL
	// ida->free_bitmap: (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	// ida->free_bitmap: (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	// ida->free_bitmap: (&proc_inum_ida)->free_bitmap: NULL
	if (!ida->free_bitmap) {
		struct ida_bitmap *bitmap;

		// sizeof(struct ida_bitmap): 172 bytes, gfp_mask: 0xD0
		// kmalloc(172, 0xD0): kmem_cache#27-oX
		// sizeof(struct ida_bitmap): 172 bytes, gfp_mask: 0x20
		// kmalloc(172, 0x20): kmem_cache#27-oX
		// sizeof(struct ida_bitmap): 172 bytes, gfp_mask: 0x20
		// kmalloc(172, 0x20): kmem_cache#27-oX
		// sizeof(struct ida_bitmap): 172 bytes, gfp_mask: 0x20
		// kmalloc(172, 0x20): kmem_cache#27-oX
		// sizeof(struct ida_bitmap): 172 bytes, gfp_mask: 0x20
		// kmalloc(172, 0x20): kmem_cache#27-oX
		bitmap = kmalloc(sizeof(struct ida_bitmap), gfp_mask);
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)

		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		if (!bitmap)
			return 0;

		// ida: &mnt_id_ida, bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// ida: &unnamed_dev_ida, bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// ida: &sysfs_ino_ida, bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// ida: &mnt_id_ida, bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// ida: &unnamed_dev_ida, bitmap: kmem_cache#27-oX (struct ida_bitmap)
		free_bitmap(ida, bitmap);

		// free_bitmap에서 한일:
		// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)

		// free_bitmap에서 한일:
		// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)

		// free_bitmap에서 한일:
		// (&sysfs_ino_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)

		// free_bitmap에서 한일:
		// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)

		// free_bitmap에서 한일:
		// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	}

	return 1;
	// return 1
	// return 1
	// return 1
	// return 1
	// return 1
	// return 1
	// return 1
	// return 1
}
EXPORT_SYMBOL(ida_pre_get);

/**
 * ida_get_new_above - allocate new ID above or equal to a start id
 * @ida:	ida handle
 * @starting_id: id to start search at
 * @p_id:	pointer to the allocated handle
 *
 * Allocate new ID above or equal to @starting_id.  It should be called
 * with any required locks.
 *
 * If memory is required, it will return %-EAGAIN, you should unlock
 * and go back to the ida_pre_get() call.  If the ida is full, it will
 * return %-ENOSPC.
 *
 * @p_id returns a value in the range @starting_id ... %0x7fffffff.
 */
// ARM10C 20151031
// &mnt_id_ida, mnt_id_start: 0, &mnt->mnt_id: &(kmem_cache#2-oX)->mnt_id
// ARM10C 20151114
// &unnamed_dev_ida, unnamed_dev_start: 0, &dev
// ARM10C 20160116
// &sysfs_ino_ida, 2, &ino
// ARM10C 20160116
// &sysfs_ino_ida, 2, &ino
// ARM10C 20160213
// &mnt_id_ida, mnt_id_start: 1, &mnt->mnt_id: &(kmem_cache#2-oX)->mnt_id
// ARM10C 20160319
// &unnamed_dev_ida, 1, &dev
// ARM10C 20160416
// &mnt_id_ida, mnt_id_start: 2, &mnt->mnt_id: &(kmem_cache#2-oX)->mnt_id
// ARM10C 20160416
// &unnamed_dev_ida, 2, &dev
// ARM10C 20160514
// ida: &proc_inum_ida, 0, p_id: &i
// ARM10C 20160521
// &mnt_id_ida, mnt_id_start: 3, &mnt->mnt_id: &(kmem_cache#2-oX)->mnt_id
// ARM10C 20160521
// &unnamed_dev_ida, 3, &dev
// ARM10C 20160604
// ida: &proc_inum_ida, p_id: &i
// ARM10C 20160611
// ida: &proc_inum_ida, p_id: &i
// ARM10C 20160730
// ida: &sysfs_ino_ida, 2, &ino
// ARM10C 20161112
// &unnamed_dev_ida, 4, &dev
int ida_get_new_above(struct ida *ida, int starting_id, int *p_id)
{
	// MAX_IDR_LEVEL: 4
	// MAX_IDR_LEVEL: 4
	// MAX_IDR_LEVEL: 4
	// MAX_IDR_LEVEL: 4
	// MAX_IDR_LEVEL: 4
	// MAX_IDR_LEVEL: 4
	// MAX_IDR_LEVEL: 4
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	struct ida_bitmap *bitmap;
	unsigned long flags;

	// starting_id: 0, IDA_BITMAP_BITS: 992
	// starting_id: 0, IDA_BITMAP_BITS: 992
	// starting_id: 2, IDA_BITMAP_BITS: 992
	// starting_id: 2, IDA_BITMAP_BITS: 992
	// starting_id: 1, IDA_BITMAP_BITS: 992
	// starting_id: 1, IDA_BITMAP_BITS: 992
	// starting_id: 2, IDA_BITMAP_BITS: 992
	int idr_id = starting_id / IDA_BITMAP_BITS;
	// idr_id: 0
	// idr_id: 0
	// idr_id: 0
	// idr_id: 0
	// idr_id: 0
	// idr_id: 0
	// idr_id: 0

	// starting_id: 0, IDA_BITMAP_BITS: 992
	// starting_id: 0, IDA_BITMAP_BITS: 992
	// starting_id: 2, IDA_BITMAP_BITS: 992
	// starting_id: 2, IDA_BITMAP_BITS: 992
	// starting_id: 1, IDA_BITMAP_BITS: 992
	// starting_id: 1, IDA_BITMAP_BITS: 992
	// starting_id: 2, IDA_BITMAP_BITS: 992
	int offset = starting_id % IDA_BITMAP_BITS;
	// offset: 0
	// offset: 0
	// offset: 2
	// offset: 2
	// offset: 1
	// offset: 1
	// offset: 2

	int t, id;

 restart:
	/* get vacant slot */
	// &ida->idr: &(&mnt_id_ida)->idr, idr_id: 0
	// idr_get_empty_slot(&(&mnt_id_ida)->idr, 0, pa, 0, &(&mnt_id_ida)->idr): 0
	// &ida->idr: &(&unnamed_dev_ida)->idr, idr_id: 0
	// idr_get_empty_slot(&(&unnamed_dev_ida)->idr, 0, pa, 0, &(&unnamed_dev_ida)->idr): 0
	// &ida->idr: &(&sysfs_ino_ida)->idr, idr_id: 0
	// idr_get_empty_slot(&(&sysfs_ino_ida)->idr, 0, pa, 0, &(&sysfs_ino_ida)->idr): -12
	// &ida->idr: &(&sysfs_ino_ida)->idr, idr_id: 0
	// idr_get_empty_slot(&(&sysfs_ino_ida)->idr, 0, pa, 0, &(&sysfs_ino_ida)->idr): 0
	// &ida->idr: &(&mnt_id_ida)->idr, idr_id: 0
	// idr_get_empty_slot(&(&mnt_id_ida)->idr, 0, pa, 0, &(&mnt_id_ida)->idr): 0
	// &ida->idr: &(&unnamed_dev_ida)->idr, idr_id: 0
	// idr_get_empty_slot(&(&unnamed_dev_ida)->idr, 0, pa, 0, &(&unnamed_dev_ida)->idr): 0
	// &ida->idr: &(&mnt_id_ida)->idr, idr_id: 0
	// idr_get_empty_slot(&(&mnt_id_ida)->idr, 0, pa, 0, &(&mnt_id_ida)->idr): 0
	t = idr_get_empty_slot(&ida->idr, idr_id, pa, 0, &ida->idr);
	// t: 0
	// t: 0
	// t: -12
	// t: 0
	// t: 0
	// t: 0
	// t: 0

	// idr_get_empty_slot에서 한일:
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 7)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	// (&(&mnt_id_ida)->idr)->layers: 1
	// ((&(&mnt_id_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->ary[0]: NULL
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)

	// idr_get_empty_slot에서 한일:
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 7)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// ((&(&unnamed_dev_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->ary[0]: NULL
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)

	// idr_get_empty_slot에서 한일:
	// (&(&sysfs_ino_ida)->idr)->id_free: NULL 이므로 -12 을 리턴함

	// idr_get_empty_slot에서 한일:
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 7)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 7
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// ((&(&sysfs_ino_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->ary[0]: NULL
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)

	// idr_get_empty_slot에서 한일:
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)

	// idr_get_empty_slot에서 한일:
	// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)

	// idr_get_empty_slot에서 한일:
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8)

	// t: 0
	// t: 0
	// t: -12
	// t: 0
	// t: 0
	// t: 0
	// t: 0
	if (t < 0)
		// t: -12, ENOMEM: 12, EAGAIN: 11
		return t == -ENOMEM ? -EAGAIN : t;
		// return -11

	// FIXME:
	// MAX_IDR_BIT이 왜 0x80000000 이 값으로 정해졌는지 확인 필요

	// t: 0, IDA_BITMAP_BITS: 992, MAX_IDR_BIT: 0x80000000
	// t: 0, IDA_BITMAP_BITS: 992, MAX_IDR_BIT: 0x80000000
	// t: 0, IDA_BITMAP_BITS: 992, MAX_IDR_BIT: 0x80000000
	// t: 0, IDA_BITMAP_BITS: 992, MAX_IDR_BIT: 0x80000000
	// t: 0, IDA_BITMAP_BITS: 992, MAX_IDR_BIT: 0x80000000
	// t: 0, IDA_BITMAP_BITS: 992, MAX_IDR_BIT: 0x80000000
	if (t * IDA_BITMAP_BITS >= MAX_IDR_BIT)
		return -ENOSPC;

	// t: 0, idr_id: 0
	// t: 0, idr_id: 0
	// t: 0, idr_id: 0
	// t: 0, idr_id: 0
	// t: 0, idr_id: 0
	// t: 0, idr_id: 0
	if (t != idr_id)
		offset = 0;

	// idr_id: 0, t: 0
	// idr_id: 0, t: 0
	// idr_id: 0, t: 0
	// idr_id: 0, t: 0
	// idr_id: 0, t: 0
	// idr_id: 0, t: 0
	idr_id = t;
	// idr_id: 0
	// idr_id: 0
	// idr_id: 0
	// idr_id: 0
	// idr_id: 0
	// idr_id: 0

	/* if bitmap isn't there, create a new one */
	// pa[0]: kmem_cache#21-o7 (struct idr_layer) (idr object 8), idr_id: 0, IDR_MASK: 0xFF
	// pa[0]->ary[0]: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]: NULL
	// pa[0]: kmem_cache#21-o7 (struct idr_layer) (idr object 8), idr_id: 0, IDR_MASK: 0xFF
	// pa[0]->ary[0]: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]: NULL
	// pa[0]: kmem_cache#21-o7 (struct idr_layer) (idr object 8), idr_id: 0, IDR_MASK: 0xFF
	// pa[0]->ary[0]: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]: NULL
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8), idr_id: 0, IDR_MASK: 0xFF
	// pa[0]->ary[0]: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]: kmem_cache#27-oX (struct ida_bitmap)
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8), idr_id: 0, IDR_MASK: 0xFF
	// pa[0]->ary[0]: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]: kmem_cache#27-oX (struct ida_bitmap)
	// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8), idr_id: 0, IDR_MASK: 0xFF
	// pa[0]->ary[0]: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]: kmem_cache#27-oX (struct ida_bitmap)
	bitmap = (void *)pa[0]->ary[idr_id & IDR_MASK];
	// bitmap: NULL
	// bitmap: NULL
	// bitmap: NULL
	// bitmap: kmem_cache#27-oX (struct ida_bitmap)
	// bitmap: kmem_cache#27-oX (struct ida_bitmap)
	// bitmap: kmem_cache#27-oX (struct ida_bitmap)

	// bitmap: NULL
	// bitmap: NULL
	// bitmap: NULL
	// bitmap: kmem_cache#27-oX (struct ida_bitmap)
	// bitmap: kmem_cache#27-oX (struct ida_bitmap)
	// bitmap: kmem_cache#27-oX (struct ida_bitmap)
	if (!bitmap) {
		// &ida->idr.lock: &(&mnt_id_ida)->idr.lock
		// &ida->idr.lock: &(&unnamed_dev_ida)->idr.lock
		// &ida->idr.lock: &(&sysfs_ino_ida)->idr.lock
		spin_lock_irqsave(&ida->idr.lock, flags);

		// spin_lock_irqsave에서 한일:
		// &(&(&mnt_id_ida)->idr)->lock을 사용하여 spin lock을 수행하고 cpsr을 flags에 저장함

		// spin_lock_irqsave에서 한일:
		// &(&(&unnamed_dev_ida)->idr)->lock을 사용하여 spin lock을 수행하고 cpsr을 flags에 저장함

		// spin_lock_irqsave에서 한일:
		// &(&(&sysfs_ino_ida)->idr)->lock을 사용하여 spin lock을 수행하고 cpsr을 flags에 저장함

		// ida->free_bitmap: (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// ida->free_bitmap: (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// ida->free_bitmap: (&sysfs_ino_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
		bitmap = ida->free_bitmap;
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)

		// ida->free_bitmap: (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// ida->free_bitmap: (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// ida->free_bitmap: (&sysfs_ino_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
		ida->free_bitmap = NULL;
		// ida->free_bitmap: (&mnt_id_ida)->free_bitmap: NULL
		// ida->free_bitmap: (&unnamed_dev_ida)->free_bitmap: NULL
		// ida->free_bitmap: (&sysfs_ino_ida)->free_bitmap: NULL

		// &ida->idr.lock: &(&mnt_id_ida)->idr.lock
		// &ida->idr.lock: &(&unnamed_dev_ida)->idr.lock
		// &ida->idr.lock: &(&sysfs_ino_ida)->idr.lock
		spin_unlock_irqrestore(&ida->idr.lock, flags);

		// spin_unlock_irqrestore에서 한일:
		// &(&(&mnt_id_ida)->idr)->lock을 사용하여 spin unlock을 수행하고 flags에 저장된 cpsr을 복원

		// spin_unlock_irqrestore에서 한일:
		// &(&(&unnamed_dev_ida)->idr)->lock을 사용하여 spin unlock을 수행하고 flags에 저장된 cpsr을 복원

		// spin_unlock_irqrestore에서 한일:
		// &(&(&sysfs_ino_ida)->idr)->lock을 사용하여 spin unlock을 수행하고 flags에 저장된 cpsr을 복원

		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		if (!bitmap)
			return -EAGAIN;

		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		memset(bitmap, 0, sizeof(struct ida_bitmap));

		// memset에서 한일:
		// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화

		// memset에서 한일:
		// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화

		// memset에서 한일:
		// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화

		// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8), idr_id: 0, IDR_MASK: 0xFF
		// pa[0]->ary[0]: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]: NULL
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// __rcu_assign_pointer((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0], kmem_cache#27-oX (struct ida_bitmap), __rcu):
		// do {
		//      smp_wmb();
		//      (kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]) = (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap));
		// } while (0)
		// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8), idr_id: 0, IDR_MASK: 0xFF
		// pa[0]->ary[0]: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]: NULL
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// __rcu_assign_pointer((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0], kmem_cache#27-oX (struct ida_bitmap), __rcu):
		// do {
		//      smp_wmb();
		//      (kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]) = (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap));
		// } while (0)
		// pa[0]: kmem_cache#21-oX (struct idr_layer) (idr object 8), idr_id: 0, IDR_MASK: 0xFF
		// pa[0]->ary[0]: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]: NULL
		// bitmap: kmem_cache#27-oX (struct ida_bitmap)
		// __rcu_assign_pointer((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0], kmem_cache#27-oX (struct ida_bitmap), __rcu):
		// do {
		//      smp_wmb();
		//      (kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]) = (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap));
		// } while (0)
		rcu_assign_pointer(pa[0]->ary[idr_id & IDR_MASK],
				(void *)bitmap);
		// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
		// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
		// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))

		// pa[0]->count: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 0
		// pa[0]->count: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 0
		// pa[0]->count: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 0
		pa[0]->count++;
		// pa[0]->count: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
		// pa[0]->count: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
		// pa[0]->count: (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	}

	/* lookup for empty slot */
	// bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap, IDA_BITMAP_BITS: 992, offset: 0
	// find_next_zero_bit((kmem_cache#27-oX (struct ida_bitmap))->bitmap, 992, 0): 0
	// bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap, IDA_BITMAP_BITS: 992, offset: 0
	// find_next_zero_bit((kmem_cache#27-oX (struct ida_bitmap))->bitmap, 992, 0): 0
	// bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap, IDA_BITMAP_BITS: 992, offset: 2
	// find_next_zero_bit((kmem_cache#27-oX (struct ida_bitmap))->bitmap, 992, 0): 0
	// bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap, IDA_BITMAP_BITS: 992, offset: 1
	// find_next_zero_bit((kmem_cache#27-oX (struct ida_bitmap))->bitmap, 992, 1): 1
	// bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap, IDA_BITMAP_BITS: 992, offset: 1
	// find_next_zero_bit((kmem_cache#27-oX (struct ida_bitmap))->bitmap, 992, 1): 1
	// bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap, IDA_BITMAP_BITS: 992, offset: 2
	// find_next_zero_bit((kmem_cache#27-oX (struct ida_bitmap))->bitmap, 992, 1): 2
	t = find_next_zero_bit(bitmap->bitmap, IDA_BITMAP_BITS, offset);
	// t: 0
	// t: 0
	// t: 2
	// t: 1
	// t: 1
	// t: 2

	// t: 0, IDA_BITMAP_BITS: 992
	// t: 0, IDA_BITMAP_BITS: 992
	// t: 2, IDA_BITMAP_BITS: 992
	// t: 1, IDA_BITMAP_BITS: 992
	// t: 1, IDA_BITMAP_BITS: 992
	// t: 2, IDA_BITMAP_BITS: 992
	if (t == IDA_BITMAP_BITS) {
		/* no empty slot after offset, continue to the next chunk */
		idr_id++;
		offset = 0;
		goto restart;
	}

	// idr_id: 0, IDA_BITMAP_BITS: 992, t: 0
	// idr_id: 0, IDA_BITMAP_BITS: 992, t: 0
	// idr_id: 0, IDA_BITMAP_BITS: 992, t: 2
	// idr_id: 0, IDA_BITMAP_BITS: 992, t: 1
	// idr_id: 0, IDA_BITMAP_BITS: 992, t: 1
	// idr_id: 0, IDA_BITMAP_BITS: 992, t: 2
	id = idr_id * IDA_BITMAP_BITS + t;
	// id: 0
	// id: 0
	// id: 2
	// id: 1
	// id: 1
	// id: 2

	// id: 0, MAX_IDR_BIT: 0x80000000
	// id: 0, MAX_IDR_BIT: 0x80000000
	// id: 2, MAX_IDR_BIT: 0x80000000
	// id: 1, MAX_IDR_BIT: 0x80000000
	// id: 1, MAX_IDR_BIT: 0x80000000
	// id: 2, MAX_IDR_BIT: 0x80000000
	if (id >= MAX_IDR_BIT)
		return -ENOSPC;

	// t: 0, bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap
	// t: 0, bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap
	// t: 2, bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap
	// t: 1, bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap
	// t: 1, bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap
	// t: 2, bitmap->bitmap: (kmem_cache#27-oX (struct ida_bitmap))->bitmap
	__set_bit(t, bitmap->bitmap);

	// __set_bit에서 한일:
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행

	// __set_bit에서 한일:
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행

	// __set_bit에서 한일:
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행

	// __set_bit에서 한일:
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행

	// __set_bit에서 한일:
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행

	// __set_bit에서 한일:
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행

	// bitmap->nr_busy: (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 1, IDA_BITMAP_BITS: 992
	// bitmap->nr_busy: (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 1, IDA_BITMAP_BITS: 992
	// bitmap->nr_busy: (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 1, IDA_BITMAP_BITS: 992
	// bitmap->nr_busy: (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2, IDA_BITMAP_BITS: 992
	// bitmap->nr_busy: (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2, IDA_BITMAP_BITS: 992
	// bitmap->nr_busy: (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 3, IDA_BITMAP_BITS: 992
	if (++bitmap->nr_busy == IDA_BITMAP_BITS)
		idr_mark_full(pa, idr_id);

	// *p_id: (kmem_cache#2-oX (struct mount))->mnt_id, id: 0
	// *p_id: *(&dev), id: 0
	// *p_id: *(&ino), id: 2
	// *p_id: (kmem_cache#2-oX (struct mount))->mnt_id, id: 1
	// *p_id: *(&dev), id: 1
	// *p_id: (kmem_cache#2-oX (struct mount))->mnt_id, id: 2
	*p_id = id;
	// *p_id: (kmem_cache#2-oX (struct mount))->mnt_id: 0
	// *p_id: *(&dev): 0
	// *p_id: *(&ino): 2
	// *p_id: (kmem_cache#2-oX (struct mount))->mnt_id: 1
	// *p_id: *(&dev): 1
	// *p_id: (kmem_cache#2-oX (struct mount))->mnt_id: 2

	/* Each leaf node can handle nearly a thousand slots and the
	 * whole idea of ida is to have small memory foot print.
	 * Throw away extra resources one by one after each successful
	 * allocation.
	 */
	// ida->idr.id_free_cnt: (&mnt_id_ida)->idr.id_free_cnt: 7, ida->free_bitmap: (&mnt_id_ida)->free_bitmap: NULL
	// ida->idr.id_free_cnt: (&unnamed_dev_ida)->idr.id_free_cnt: 7, ida->free_bitmap: (&unnamed_dev_ida)->free_bitmap: NULL
	// ida->idr.id_free_cnt: (&sysfs_ino_ida)->idr.id_free_cnt: 7, ida->free_bitmap: (&sysfs_ino_ida)->free_bitmap: NULL
	// ida->idr.id_free_cnt: (&mnt_id_ida)->idr.id_free_cnt: 8, ida->free_bitmap: (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	// ida->idr.id_free_cnt: (&unnamed_dev_ida)->idr.id_free_cnt: 8, ida->free_bitmap: (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	// ida->idr.id_free_cnt: (&mnt_id_ida)->idr.id_free_cnt: 8, ida->free_bitmap: (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	if (ida->idr.id_free_cnt || ida->free_bitmap) {
		// &ida->idr: &(&mnt_id_ida)->idr
		// get_from_free_list(&(&mnt_id_ida)->idr): kmem_cache#21-oX (idr object 7)
		// &ida->idr: &(&unnamed_dev_ida)->idr
		// get_from_free_list(&(&unnamed_dev_ida)->idr): kmem_cache#21-oX (idr object 7)
		// &ida->idr: &(&sysfs_ino_ida)->idr
		// get_from_free_list(&(&sysfs_ino_ida)->idr): kmem_cache#21-oX (idr object 7)
		// &ida->idr: &(&mnt_id_ida)->idr
		// get_from_free_list(&(&mnt_id_ida)->idr): kmem_cache#21-oX (idr object new 1)
		// &ida->idr: &(&unnamed_dev_ida)->idr
		// get_from_free_list(&(&unnamed_dev_ida)->idr): kmem_cache#21-oX (idr object new 1)
		//
		// &ida->idr: &(&mnt_id_ida)->idr
		// get_from_free_list(&(&mnt_id_ida)->idr): kmem_cache#21-oX (idr object new 1)
		struct idr_layer *p = get_from_free_list(&ida->idr);
		// p: kmem_cache#21-oX (idr object 7)
		// p: kmem_cache#21-oX (idr object 7)
		// p: kmem_cache#21-oX (idr object 7)
		// p: kmem_cache#21-oX (idr object new 1)
		// p: kmem_cache#21-oX (idr object new 1)

		// get_from_free_list에서 한일:
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 6
		//
		// (kmem_cache#21-oX (idr object 7))->ary[0]: NULL

		// get_from_free_list에서 한일:
		// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 6
		//
		// (kmem_cache#21-oX (idr object 7))->ary[0]: NULL

		// get_from_free_list에서 한일:
		// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
		// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 6
		//
		// (kmem_cache#21-oX (idr object 7))->ary[0]: NULL

		// get_from_free_list에서 한일:
		// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
		//
		// (kmem_cache#21-oX (idr object new 1))->ary[0]: NULL

		// get_from_free_list에서 한일:
		// (&(&unnamed_dev_ida)->idr)->id_free: (idr object new 0)
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
		//
		// (kmem_cache#21-oX (idr object new 1))->ary[0]: NULL

		// get_from_free_list에서 한일:
		// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
		//
		// (kmem_cache#21-oX (idr object new 2))->ary[0]: NULL

// 2016/02/20 종료
// 2016/02/27 시작

		// p: kmem_cache#21-oX (idr object 7)
		// p: kmem_cache#21-oX (idr object 7)
		// p: kmem_cache#21-oX (idr object 7)
		// p: kmem_cache#21-oX (idr object new 1)
		// p: kmem_cache#21-oX (idr object new 1)
		// p: kmem_cache#21-oX (idr object new 2)
		if (p)
			// idr_layer_cache: kmem_cache#21, p: kmem_cache#21-oX (idr object 7)
			// idr_layer_cache: kmem_cache#21, p: kmem_cache#21-oX (idr object 7)
			// idr_layer_cache: kmem_cache#21, p: kmem_cache#21-oX (idr object 7)
			// idr_layer_cache: kmem_cache#21, p: kmem_cache#21-oX (idr object new 1)
			// idr_layer_cache: kmem_cache#21, p: kmem_cache#21-oX (idr object new 1)
			// idr_layer_cache: kmem_cache#21, p: kmem_cache#21-oX (idr object new 2)
			kmem_cache_free(idr_layer_cache, p);
			
			// kmem_cache_free에서 한일:
			// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
			
			// kmem_cache_free에서 한일:
			// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
			
			// kmem_cache_free에서 한일:
			// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
			
			// kmem_cache_free에서 한일:
			// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함
			
			// kmem_cache_free에서 한일:
			// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함
			
			// kmem_cache_free에서 한일:
			// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 2) 의 memory 공간을 반환함

		// FIXME:
		// ida->idr.id_free_cnt: (&mnt_id_ida)->idr.id_free_cnt 값이 있을 경우에
		// 기존에 할당 되어 있는 메모리를 가져오고 다시 free 시키는 이유는?
		// 위의 영문 주석으로는 이해가 잘 안됨. 확인필요함
	}

	return 0;
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
}
EXPORT_SYMBOL(ida_get_new_above);

/**
 * ida_remove - remove the given ID
 * @ida:	ida handle
 * @id:		ID to free
 */
void ida_remove(struct ida *ida, int id)
{
	struct idr_layer *p = ida->idr.top;
	int shift = (ida->idr.layers - 1) * IDR_BITS;
	int idr_id = id / IDA_BITMAP_BITS;
	int offset = id % IDA_BITMAP_BITS;
	int n;
	struct ida_bitmap *bitmap;

	/* clear full bits while looking up the leaf idr_layer */
	while ((shift > 0) && p) {
		n = (idr_id >> shift) & IDR_MASK;
		__clear_bit(n, p->bitmap);
		p = p->ary[n];
		shift -= IDR_BITS;
	}

	if (p == NULL)
		goto err;

	n = idr_id & IDR_MASK;
	__clear_bit(n, p->bitmap);

	bitmap = (void *)p->ary[n];
	if (!test_bit(offset, bitmap->bitmap))
		goto err;

	/* update bitmap and remove it if empty */
	__clear_bit(offset, bitmap->bitmap);
	if (--bitmap->nr_busy == 0) {
		__set_bit(n, p->bitmap);	/* to please idr_remove() */
		idr_remove(&ida->idr, idr_id);
		free_bitmap(ida, bitmap);
	}

	return;

 err:
	WARN(1, "ida_remove called for id=%d which is not allocated.\n", id);
}
EXPORT_SYMBOL(ida_remove);

/**
 * ida_destroy - release all cached layers within an ida tree
 * @ida:		ida handle
 */
void ida_destroy(struct ida *ida)
{
	idr_destroy(&ida->idr);
	kfree(ida->free_bitmap);
}
EXPORT_SYMBOL(ida_destroy);

/**
 * ida_simple_get - get a new id.
 * @ida: the (initialized) ida.
 * @start: the minimum id (inclusive, < 0x8000000)
 * @end: the maximum id (exclusive, < 0x8000000 or 0)
 * @gfp_mask: memory allocation flags
 *
 * Allocates an id in the range start <= id < end, or returns -ENOSPC.
 * On memory allocation failure, returns -ENOMEM.
 *
 * Use ida_simple_remove() to get rid of an id.
 */
int ida_simple_get(struct ida *ida, unsigned int start, unsigned int end,
		   gfp_t gfp_mask)
{
	int ret, id;
	unsigned int max;
	unsigned long flags;

	BUG_ON((int)start < 0);
	BUG_ON((int)end < 0);

	if (end == 0)
		max = 0x80000000;
	else {
		BUG_ON(end < start);
		max = end - 1;
	}

again:
	if (!ida_pre_get(ida, gfp_mask))
		return -ENOMEM;

	spin_lock_irqsave(&simple_ida_lock, flags);
	ret = ida_get_new_above(ida, start, &id);
	if (!ret) {
		if (id > max) {
			ida_remove(ida, id);
			ret = -ENOSPC;
		} else {
			ret = id;
		}
	}
	spin_unlock_irqrestore(&simple_ida_lock, flags);

	if (unlikely(ret == -EAGAIN))
		goto again;

	return ret;
}
EXPORT_SYMBOL(ida_simple_get);

/**
 * ida_simple_remove - remove an allocated id.
 * @ida: the (initialized) ida.
 * @id: the id returned by ida_simple_get.
 */
void ida_simple_remove(struct ida *ida, unsigned int id)
{
	unsigned long flags;

	BUG_ON((int)id < 0);
	spin_lock_irqsave(&simple_ida_lock, flags);
	ida_remove(ida, id);
	spin_unlock_irqrestore(&simple_ida_lock, flags);
}
EXPORT_SYMBOL(ida_simple_remove);

/**
 * ida_init - initialize ida handle
 * @ida:	ida handle
 *
 * This function is use to set up the handle (@ida) that you will pass
 * to the rest of the functions.
 */
void ida_init(struct ida *ida)
{
	memset(ida, 0, sizeof(struct ida));
	idr_init(&ida->idr);

}
EXPORT_SYMBOL(ida_init);
