/*
 * Copyright (C) 2001 Momchil Velikov
 * Portions Copyright (C) 2001 Christoph Hellwig
 * Copyright (C) 2005 SGI, Christoph Lameter
 * Copyright (C) 2006 Nick Piggin
 * Copyright (C) 2012 Konstantin Khlebnikov
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/radix-tree.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/string.h>
#include <linux/bitops.h>
#include <linux/rcupdate.h>
#include <linux/hardirq.h>		/* in_interrupt() */


#ifdef __KERNEL__
// ARM10C 20141004
// ARM10C 20141122
// CONFIG_BASE_SMALL: 0
// RADIX_TREE_MAP_SHIFT: 6
#define RADIX_TREE_MAP_SHIFT	(CONFIG_BASE_SMALL ? 4 : 6)
#else
#define RADIX_TREE_MAP_SHIFT	3	/* For more stressful testing */
#endif

// ARM10C 20141004
// RADIX_TREE_MAP_SHIFT: 6
// RADIX_TREE_MAP_SIZE: 64
#define RADIX_TREE_MAP_SIZE	(1UL << RADIX_TREE_MAP_SHIFT)
// ARM10C 20141004
// ARM10C 20141122
// RADIX_TREE_MAP_SIZE: 64
// RADIX_TREE_MAP_MASK: 0x3f
#define RADIX_TREE_MAP_MASK	(RADIX_TREE_MAP_SIZE-1)

// ARM10C 20141004
// RADIX_TREE_MAP_SIZE: 64
// BITS_PER_LONG: 32
// RADIX_TREE_TAG_LONGS: 2
#define RADIX_TREE_TAG_LONGS	\
	((RADIX_TREE_MAP_SIZE + BITS_PER_LONG - 1) / BITS_PER_LONG)

// ARM10C 20141004
// ARM10C 20141115
// ARM10C 20141122
// sizeof(struct radix_tree_node): 296 bytes
struct radix_tree_node {
	unsigned int	height;		/* Height from the bottom */
	unsigned int	count;
	union {
		struct radix_tree_node *parent;	/* Used when ascending tree */
		struct rcu_head	rcu_head;	/* Used when freeing node */
	};
	// RADIX_TREE_MAP_SIZE: 64
	void __rcu	*slots[RADIX_TREE_MAP_SIZE];
	// RADIX_TREE_MAX_TAGS: 3, RADIX_TREE_TAG_LONGS: 2
	unsigned long	tags[RADIX_TREE_MAX_TAGS][RADIX_TREE_TAG_LONGS];
};

// ARM10C 20141004
// RADIX_TREE_INDEX_BITS: 32
#define RADIX_TREE_INDEX_BITS  (8 /* CHAR_BIT */ * sizeof(unsigned long))
// ARM10C 20141004
// RADIX_TREE_INDEX_BITS: 32, RADIX_TREE_MAP_SHIFT: 6
// DIV_ROUND_UP(32, 6): 6
// RADIX_TREE_MAX_PATH: 6
#define RADIX_TREE_MAX_PATH (DIV_ROUND_UP(RADIX_TREE_INDEX_BITS, \
					  RADIX_TREE_MAP_SHIFT))

/*
 * The height_to_maxindex array needs to be one deeper than the maximum
 * path as height 0 holds only 1 entry.
 */
// ARM10C 20141004
// RADIX_TREE_MAX_PATH: 6
static unsigned long height_to_maxindex[RADIX_TREE_MAX_PATH + 1] __read_mostly;

/*
 * Radix tree node cache.
 */
// ARM10C 20141004
static struct kmem_cache *radix_tree_node_cachep;

/*
 * The radix tree is variable-height, so an insert operation not only has
 * to build the branch to its corresponding item, it also has to build the
 * branch to existing items if the size has to be increased (by
 * radix_tree_extend).
 *
 * The worst case is a zero height tree with just a single item at index 0,
 * and then inserting an item at index ULONG_MAX. This requires 2 new branches
 * of RADIX_TREE_MAX_PATH size to be created, with only the root node shared.
 * Hence:
 */
#define RADIX_TREE_PRELOAD_SIZE (RADIX_TREE_MAX_PATH * 2 - 1)

/*
 * Per-cpu pool of preloaded nodes
 */
struct radix_tree_preload {
	int nr;
	struct radix_tree_node *nodes[RADIX_TREE_PRELOAD_SIZE];
};
static DEFINE_PER_CPU(struct radix_tree_preload, radix_tree_preloads) = { 0, };

// ARM10C 20141004
// node: kmem_cache#20-o0
// ARM10C 20141115
// node: kmem_cache#20-o1
static inline void *ptr_to_indirect(void *ptr)
{
	// ptr: kmem_cache#20-o0, RADIX_TREE_INDIRECT_PTR: 1
	return (void *)((unsigned long)ptr | RADIX_TREE_INDIRECT_PTR);
	// return kmem_cache#20-o0 (RADIX_LSB: 1)
	// NOTE:
	// "RADIX_LSB: 1" 의 의미는 RADIX tree에서 최하위 bit를 1로 설정하여
	// RADIX tree의 INDIRECT 주소임을 나타내는 것을 의미함
}

// ARM10C 20141004
// root->rnode: (&irq_desc_tree)->rnode: NULL
// ARM10C 20141004
// root->rnode: (&irq_desc_tree)->rnode: kmem_cache#20-o0 (RADIX_LSB: 1)
// ARM10C 20141115
// slot: kmem_cache#20-o0 (radix height 1 관리 주소)
// ARM10C 20141115
// root->rnode: (&irq_desc_tree)->rnode: kmem_cache#20-o1 (RADIX_LSB: 1)
// ARM10C 20141122
// node: kmem_cache#20-o1 (RADIX_LSB: 1)
static inline void *indirect_to_ptr(void *ptr)
{
	// ptr: NULL, RADIX_TREE_INDIRECT_PTR: 1
	return (void *)((unsigned long)ptr & ~RADIX_TREE_INDIRECT_PTR);
	// return 0
}

// ARM10C 20141004
// root: &irq_desc_tree
static inline gfp_t root_gfp_mask(struct radix_tree_root *root)
{
	// root->gfp_mask: (&irq_desc_tree)->gfp_mask: GFP_KERNEL: 0xD0,
	// __GFP_BITS_MASK: 0x1ffffff
	return root->gfp_mask & __GFP_BITS_MASK;
	// return GFP_KERNEL: 0xD0
}

static inline void tag_set(struct radix_tree_node *node, unsigned int tag,
		int offset)
{
	__set_bit(offset, node->tags[tag]);
}

static inline void tag_clear(struct radix_tree_node *node, unsigned int tag,
		int offset)
{
	__clear_bit(offset, node->tags[tag]);
}

// ARM10C 20141004
// node: kmem_cache#20-o0 (RADIX_LSB: 0), 0, offset: 1
// ARM10C 20141004
// node: kmem_cache#20-o0 (RADIX_LSB: 0), 1, offset: 1
static inline int tag_get(struct radix_tree_node *node, unsigned int tag,
		int offset)
{
	// offset: 1, tag: 0, node->tags[0]: (kmem_cache#20-o0 (RADIX_LSB: 0))->tags[0]
	// test_bit(1, (kmem_cache#20-o0 (RADIX_LSB: 0))->tags[0]): 0
	return test_bit(offset, node->tags[tag]);
	// return 0
}

static inline void root_tag_set(struct radix_tree_root *root, unsigned int tag)
{
	root->gfp_mask |= (__force gfp_t)(1 << (tag + __GFP_BITS_SHIFT));
}

static inline void root_tag_clear(struct radix_tree_root *root, unsigned int tag)
{
	root->gfp_mask &= (__force gfp_t)~(1 << (tag + __GFP_BITS_SHIFT));
}

static inline void root_tag_clear_all(struct radix_tree_root *root)
{
	root->gfp_mask &= __GFP_BITS_MASK;
}

// ARM10C 20141004
// root: &irq_desc_tree, 0
// ARM10C 20141004
// root: &irq_desc_tree, 1
// ARM10C 20141004
// root: &irq_desc_tree, tag: 0
static inline int root_tag_get(struct radix_tree_root *root, unsigned int tag)
{
	// root->gfp_mask: (&irq_desc_tree)->gfp_mask: GFP_KERNEL: 0xD0, tag: 0, __GFP_BITS_SHIFT: 25
	return (__force unsigned)root->gfp_mask & (1 << (tag + __GFP_BITS_SHIFT));
	// return 0
}

/*
 * Returns 1 if any slot in the node has this tag set.
 * Otherwise returns 0.
 */
static inline int any_tag_set(struct radix_tree_node *node, unsigned int tag)
{
	int idx;
	for (idx = 0; idx < RADIX_TREE_TAG_LONGS; idx++) {
		if (node->tags[tag][idx])
			return 1;
	}
	return 0;
}

/**
 * radix_tree_find_next_bit - find the next set bit in a memory region
 *
 * @addr: The address to base the search on
 * @size: The bitmap size in bits
 * @offset: The bitnumber to start searching at
 *
 * Unrollable variant of find_next_bit() for constant size arrays.
 * Tail bits starting from size to roundup(size, BITS_PER_LONG) must be zero.
 * Returns next bit offset, or size if nothing found.
 */
static __always_inline unsigned long
radix_tree_find_next_bit(const unsigned long *addr,
			 unsigned long size, unsigned long offset)
{
	if (!__builtin_constant_p(size))
		return find_next_bit(addr, size, offset);

	if (offset < size) {
		unsigned long tmp;

		addr += offset / BITS_PER_LONG;
		tmp = *addr >> (offset % BITS_PER_LONG);
		if (tmp)
			return __ffs(tmp) + offset;
		offset = (offset + BITS_PER_LONG) & ~(BITS_PER_LONG - 1);
		while (offset < size) {
			tmp = *++addr;
			if (tmp)
				return __ffs(tmp) + offset;
			offset += BITS_PER_LONG;
		}
	}
	return size;
}

/*
 * This assumes that the caller has performed appropriate preallocation, and
 * that the caller has pinned this thread of control to the current CPU.
 */
// ARM10C 20141004
// root: &irq_desc_tree
// ARM10C 20141115
// root: &irq_desc_tree
// ARM10C 20141115
// root: &irq_desc_tree
static struct radix_tree_node *
radix_tree_node_alloc(struct radix_tree_root *root)
{
	struct radix_tree_node *ret = NULL;
	// ret: NULL

	// root: &irq_desc_tree, root_gfp_mask(&irq_desc_tree): GFP_KERNEL: 0xD0
	gfp_t gfp_mask = root_gfp_mask(root);
	// gfp_mask: GFP_KERNEL: 0xD0

	/*
	 * Preload code isn't irq safe and it doesn't make sence to use
	 * preloading in the interrupt anyway as all the allocations have to
	 * be atomic. So just do normal allocation when in interrupt.
	 */
	// gfp_mask: GFP_KERNEL: 0xD0, __GFP_WAIT: 0x10u, in_interrupt(): 0
	if (!(gfp_mask & __GFP_WAIT) && !in_interrupt()) {
		struct radix_tree_preload *rtp;

		/*
		 * Provided the caller has preloaded here, we will always
		 * succeed in getting a node here (and never reach
		 * kmem_cache_alloc)
		 */
		rtp = &__get_cpu_var(radix_tree_preloads);
		if (rtp->nr) {
			ret = rtp->nodes[rtp->nr - 1];
			rtp->nodes[rtp->nr - 1] = NULL;
			rtp->nr--;
		}
	}

	// ret: NULL
	if (ret == NULL)
		// radix_tree_node_cachep: kmem_cache#20, gfp_mask: GFP_KERNEL: 0xD0
		// kmem_cache_alloc(kmem_cache#20, GFP_KERNEL: 0xD0): kmem_cache#20-o0
		ret = kmem_cache_alloc(radix_tree_node_cachep, gfp_mask);
		// ret: kmem_cache#20-o0

	// ret: kmem_cache#20-o0
	// radix_tree_is_indirect_ptr(kmem_cache#20-o0): 0
	BUG_ON(radix_tree_is_indirect_ptr(ret));

	// ret: kmem_cache#20-o0
	return ret;
	// return kmem_cache#20-o0
}

static void radix_tree_node_rcu_free(struct rcu_head *head)
{
	struct radix_tree_node *node =
			container_of(head, struct radix_tree_node, rcu_head);
	int i;

	/*
	 * must only free zeroed nodes into the slab. radix_tree_shrink
	 * can leave us with a non-NULL entry in the first slot, so clear
	 * that here to make sure.
	 */
	for (i = 0; i < RADIX_TREE_MAX_TAGS; i++)
		tag_clear(node, i, 0);

	node->slots[0] = NULL;
	node->count = 0;

	kmem_cache_free(radix_tree_node_cachep, node);
}

static inline void
radix_tree_node_free(struct radix_tree_node *node)
{
	call_rcu(&node->rcu_head, radix_tree_node_rcu_free);
}

/*
 * Load up this CPU's radix_tree_node buffer with sufficient objects to
 * ensure that the addition of a single element in the tree cannot fail.  On
 * success, return zero, with preemption disabled.  On error, return -ENOMEM
 * with preemption not disabled.
 *
 * To make use of this facility, the radix tree must be initialised without
 * __GFP_WAIT being passed to INIT_RADIX_TREE().
 */
static int __radix_tree_preload(gfp_t gfp_mask)
{
	struct radix_tree_preload *rtp;
	struct radix_tree_node *node;
	int ret = -ENOMEM;

	preempt_disable();
	rtp = &__get_cpu_var(radix_tree_preloads);
	while (rtp->nr < ARRAY_SIZE(rtp->nodes)) {
		preempt_enable();
		node = kmem_cache_alloc(radix_tree_node_cachep, gfp_mask);
		if (node == NULL)
			goto out;
		preempt_disable();
		rtp = &__get_cpu_var(radix_tree_preloads);
		if (rtp->nr < ARRAY_SIZE(rtp->nodes))
			rtp->nodes[rtp->nr++] = node;
		else
			kmem_cache_free(radix_tree_node_cachep, node);
	}
	ret = 0;
out:
	return ret;
}

/*
 * Load up this CPU's radix_tree_node buffer with sufficient objects to
 * ensure that the addition of a single element in the tree cannot fail.  On
 * success, return zero, with preemption disabled.  On error, return -ENOMEM
 * with preemption not disabled.
 *
 * To make use of this facility, the radix tree must be initialised without
 * __GFP_WAIT being passed to INIT_RADIX_TREE().
 */
int radix_tree_preload(gfp_t gfp_mask)
{
	/* Warn on non-sensical use... */
	WARN_ON_ONCE(!(gfp_mask & __GFP_WAIT));
	return __radix_tree_preload(gfp_mask);
}
EXPORT_SYMBOL(radix_tree_preload);

/*
 * The same as above function, except we don't guarantee preloading happens.
 * We do it, if we decide it helps. On success, return zero with preemption
 * disabled. On error, return -ENOMEM with preemption not disabled.
 */
int radix_tree_maybe_preload(gfp_t gfp_mask)
{
	if (gfp_mask & __GFP_WAIT)
		return __radix_tree_preload(gfp_mask);
	/* Preloading doesn't help anything with this gfp mask, skip it */
	preempt_disable();
	return 0;
}
EXPORT_SYMBOL(radix_tree_maybe_preload);

/*
 *	Return the maximum key which can be store into a
 *	radix tree with height HEIGHT.
 */
// ARM10C 20141004
// root->height: (&irq_desc_tree)->height: 0
// ARM10C 20141004
// height: 1
// ARM10C 20141115
// height: 1
// ARM10C 20141122
// height: 2
static inline unsigned long radix_tree_maxindex(unsigned int height)
{
	// height: 0, height_to_maxindex[0]: 0
	// height: 1, height_to_maxindex[1]: 63
	// height: 2, height_to_maxindex[2]: 4095
	return height_to_maxindex[height];
	// return 0
	// return 63
	// return 4095
}

/*
 *	Extend a radix tree so it can store key @index.
 */
// ARM10C 20141004
// root: &irq_desc_tree, index: 1
// ARM10C 20141115
// root: &irq_desc_tree, index: 64
static int radix_tree_extend(struct radix_tree_root *root, unsigned long index)
{
	struct radix_tree_node *node;
	struct radix_tree_node *slot;
	unsigned int height;
	int tag;

	/* Figure out what the height should be.  */
	// root->height: (&irq_desc_tree)->height: 0
	// root->height: (&irq_desc_tree)->height: 1
	height = root->height + 1;
	// height: 1
	// height: 2

	// index: 1, height: 1, radix_tree_maxindex(1): 63
	// index: 64, height: 2, radix_tree_maxindex(2): 4095
	while (index > radix_tree_maxindex(height))
		height++;

	// root->rnode: (&irq_desc_tree)->rnode: kmem_cache#28-o0 (irq 0)
	// root->rnode: (&irq_desc_tree)->rnode: kmem_cache#20-o0 (radix height 1 관리 주소)
	if (root->rnode == NULL) {
		root->height = height;
		goto out;
	}

	do {
		unsigned int newheight;

		// root: &irq_desc_tree, radix_tree_node_alloc(&irq_desc_tree): kmem_cache#20-o0
		// node: kmem_cache#20-o0
		// root: &irq_desc_tree, radix_tree_node_alloc(&irq_desc_tree): kmem_cache#20-o1
		// node: kmem_cache#20-o1
		if (!(node = radix_tree_node_alloc(root)))
			return -ENOMEM;

		/* Propagate the aggregated tag info into the new root */
		// RADIX_TREE_MAX_TAGS: 3
		// RADIX_TREE_MAX_TAGS: 3
		for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++) {
			// root: &irq_desc_tree, tag: 0, root_tag_get(&irq_desc_tree, 0): 0
			// root: &irq_desc_tree, tag: 1, root_tag_get(&irq_desc_tree, 1): 0
			// root: &irq_desc_tree, tag: 2, root_tag_get(&irq_desc_tree, 2): 0
			// root: &irq_desc_tree, tag: 0, root_tag_get(&irq_desc_tree, 0): 0
			// root: &irq_desc_tree, tag: 1, root_tag_get(&irq_desc_tree, 1): 0
			// root: &irq_desc_tree, tag: 2, root_tag_get(&irq_desc_tree, 2): 0
			if (root_tag_get(root, tag))
				tag_set(node, tag, 0);
		}

		/* Increase the height.  */
		// root->height: (&irq_desc_tree)->height: 0
		// root->height: (&irq_desc_tree)->height: 1
		newheight = root->height+1;
		// newheight: 1
		// newheight: 2

		// node->height: (kmem_cache#20-o0)->height, newheight: 1
		// node->height: (kmem_cache#20-o1)->height, newheight: 2
		node->height = newheight;
		// node->height: (kmem_cache#20-o0)->height: 1
		// node->height: (kmem_cache#20-o1)->height: 2

		// node->count: (kmem_cache#20-o0)->count
		// node->count: (kmem_cache#20-o1)->count
		node->count = 1;
		// node->count: (kmem_cache#20-o0)->count: 1
		// node->count: (kmem_cache#20-o1)->count: 1

		// node->parent: (kmem_cache#20-o0)->parent
		// node->parent: (kmem_cache#20-o1)->parent
		node->parent = NULL;
		// node->parent: (kmem_cache#20-o0)->parent: NULL
		// node->parent: (kmem_cache#20-o1)->parent: NULL

		// root->rnode: (&irq_desc_tree)->rnode: kmem_cache#28-o0 (irq 0)
		// root->rnode: (&irq_desc_tree)->rnode: kmem_cache#20-o0 (radix height 1 관리 주소)
		slot = root->rnode;
		// slot: kmem_cache#28-o0 (irq 0)
		// slot: kmem_cache#20-o0 (radix height 1 관리 주소)

		// newheight: 1
		// newheight: 2
		if (newheight > 1) {
			// slot: kmem_cache#20-o0 (radix height 1 관리 주소)
			// indirect_to_ptr(kmem_cache#20-o0): kmem_cache#20-o0 (radix height 1 관리 주소)
			slot = indirect_to_ptr(slot);
			// slot: kmem_cache#20-o0 (radix height 1 관리 주소)

			// slot->parent: (kmem_cache#20-o0 (radix height 1 관리 주소))->parent,
			// node: kmem_cache#20-o1
			slot->parent = node;
			// slot->parent: (kmem_cache#20-o0 (radix height 1 관리 주소))->parent: kmem_cache#20-o1
		}

		// node->slots[0]: (kmem_cache#20-o0)->slots[0], slot: kmem_cache#28-o0 (irq 0)
		// node->slots[0]: (kmem_cache#20-o1)->slots[0], slot: kmem_cache#20-o0 (radix height 1 관리 주소)
		node->slots[0] = slot;
		// node->slots[0]: (kmem_cache#20-o0)->slots[0]: kmem_cache#28-o0 (irq 0)
		// node->slots[0]: (kmem_cache#20-o1)->slots[0]: kmem_cache#20-o0 (radix height 1 관리 주소)

		// node: kmem_cache#20-o0
		// ptr_to_indirect(kmem_cache#20-o0): kmem_cache#20-o0 (RADIX_LSB: 1)
		// node: kmem_cache#20-o1
		// ptr_to_indirect(kmem_cache#20-o1): kmem_cache#20-o1 (RADIX_LSB: 1)
		node = ptr_to_indirect(node);
		// node: kmem_cache#20-o0 (RADIX_LSB: 1)
		// node: kmem_cache#20-o1 (RADIX_LSB: 1)

		// root->rnode: (&irq_desc_tree)->rnode: kmem_cache#28-o0 (irq 0),
		// node: kmem_cache#20-o0 (RADIX_LSB: 1)
		// root->rnode: (&irq_desc_tree)->rnode: kmem_cache#20-o0,
		// node: kmem_cache#20-o1 (RADIX_LSB: 1)
		rcu_assign_pointer(root->rnode, node);
		// root->rnode: (&irq_desc_tree)->rnode: kmem_cache#20-o0 (RADIX_LSB: 1)
		// root->rnode: (&irq_desc_tree)->rnode: kmem_cache#20-o1 (RADIX_LSB: 1)

		// root->height: (&irq_desc_tree)->height: 0, newheight: 1
		// root->height: (&irq_desc_tree)->height: 1, newheight: 2
		root->height = newheight;
		// root->height: (&irq_desc_tree)->height: 1
		// root->height: (&irq_desc_tree)->height: 2

		// height: 1, root->height: (&irq_desc_tree)->height: 1
		// height: 2, root->height: (&irq_desc_tree)->height: 2
	} while (height > root->height);
out:
	return 0;
	// return 0
	// return 0
}

/**
 *	radix_tree_insert    -    insert into a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *	@item:		item to insert
 *
 *	Insert an item into the radix tree at position @index.
 */
// ARM10C 20141004
// &irq_desc_tree, irq: 0, desc: kmem_cache#28-o0
// ARM10C 20141004
// &irq_desc_tree, irq: 1, desc: kmem_cache#28-o1
// ARM10C 20141115
// &irq_desc_tree, irq: 64, desc: kmem_cache#28-oX (irq 64)
int radix_tree_insert(struct radix_tree_root *root,
			unsigned long index, void *item)
{
	struct radix_tree_node *node = NULL, *slot;
	// node: NULL
	// node: NULL
	// node: NULL
	unsigned int height, shift;
	int offset;
	int error;

	// item: kmem_cache#28-o0
	// radix_tree_is_indirect_ptr(kmem_cache#28-o0): 0
	// item: kmem_cache#28-o1
	// radix_tree_is_indirect_ptr(kmem_cache#28-o1): 0
	// item: kmem_cache#28-oX (irq 64)
	// radix_tree_is_indirect_ptr(kmem_cache#28-oX (irq 64)): 0
	BUG_ON(radix_tree_is_indirect_ptr(item));

	/* Make sure the tree is high enough.  */
	// index: 0, root->height: (&irq_desc_tree)->height: 0, radix_tree_maxindex(0): 0
	// index: 1, root->height: (&irq_desc_tree)->height: 0, radix_tree_maxindex(0): 0
	// index: 64, root->height: (&irq_desc_tree)->height: 1, radix_tree_maxindex(1): 63
	if (index > radix_tree_maxindex(root->height)) {
		// root: &irq_desc_tree, index: 1
		// radix_tree_extend(&irq_desc_tree, 1): 0
		// root: &irq_desc_tree, index: 64
		// radix_tree_extend(&irq_desc_tree, 64): 0
		error = radix_tree_extend(root, index);
		// error: 0
		// error: 0

		// radix_tree_extend(1)에서 한일:
		// radix_tree_node_cachep를 사용한 struct radix_tree_node 용 메모리 할당: kmem_cache#20-o0
		// (kmem_cache#20-o0)->height: 1
		// (kmem_cache#20-o0)->count: 1
		// (kmem_cache#20-o0)->parent: NULL
		// (kmem_cache#20-o0)->slots[0]: kmem_cache#28-o0 (irq 0)
		// radix tree의 root node: &irq_desc_tree 값을 변경
		// (&irq_desc_tree)->rnode: kmem_cache#20-o0 (RADIX_LSB: 1)
		// (&irq_desc_tree)->height: 1

		// radix_tree_extend(64)에서 한일:
		// radix_tree_node_cachep를 사용한 struct radix_tree_node 용 메모리 할당: kmem_cache#20-o1
		// (kmem_cache#20-o0 (radix height 1 관리 주소))->parent: kmem_cache#20-o1
		// (kmem_cache#20-o1)->height: 2
		// (kmem_cache#20-o1)->count: 1
		// (kmem_cache#20-o1)->parent: NULL
		// (kmem_cache#20-o1)->slots[0]: kmem_cache#20-o0 (radix height 1 관리 주소)
		// radix tree의 root node: &irq_desc_tree 값을 변경
		// (&irq_desc_tree)->rnode: kmem_cache#20-o1 (RADIX_LSB: 1)
		// (&irq_desc_tree)->height: 2

		// error: 0
		// error: 0
		if (error)
			return error;
	}

	// root->rnode: (&irq_desc_tree)->rnode: NULL
	// indirect_to_ptr(NULL): NULL
	// root->rnode: (&irq_desc_tree)->rnode: kmem_cache#20-o0 (RADIX_LSB: 1)
	// indirect_to_ptr(kmem_cache#20-o0): kmem_cache#20-o0 (RADIX_LSB: 0)
	// root->rnode: (&irq_desc_tree)->rnode: kmem_cache#20-o1 (RADIX_LSB: 1)
	// indirect_to_ptr(kmem_cache#20-o1): kmem_cache#20-o1 (RADIX_LSB: 0)
	slot = indirect_to_ptr(root->rnode);
	// slot: NULL
	// slot: kmem_cache#20-o0 (RADIX_LSB: 0)
	// slot: kmem_cache#20-o1 (RADIX_LSB: 0)

	// root->height: (&irq_desc_tree)->height: 0
	// root->height: (&irq_desc_tree)->height: 1
	// root->height: (&irq_desc_tree)->height: 2
	height = root->height;
	// height: 0
	// height: 1
	// height: 2

	// height: 0, RADIX_TREE_MAP_SHIFT: 6
	// height: 1, RADIX_TREE_MAP_SHIFT: 6
	// height: 2, RADIX_TREE_MAP_SHIFT: 6
	shift = (height-1) * RADIX_TREE_MAP_SHIFT;
	// shift: 0xfffffffa
	// shift: 0
	// shift: 6

	offset = 0;			/* uninitialised var warning */
	// offset: 0
	// offset: 0
	// offset: 0

	// height: 0
	// height: 1
	// height: 2
	while (height > 0) {
		// slot: kmem_cache#20-o0 (RADIX_LSB: 0)
		// slot: kmem_cache#20-o1 (RADIX_LSB: 0)
		// slot: NULL
		if (slot == NULL) {
			/* Have to add a child node.  */
			// slot: NULL, root: &irq_desc_tree,
			// radix_tree_node_alloc(&irq_desc_tree): kmem_cache#20-o2
			// slot: kmem_cache#20-o2
			if (!(slot = radix_tree_node_alloc(root)))
				return -ENOMEM;

			// slot->height: (kmem_cache#20-o2)->height, height: 1
			slot->height = height;
			// slot->height: (kmem_cache#20-o2)->height: 1

			// slot->parent: (kmem_cache#20-o2)->parent,
			// node: kmem_cache#20-o1 (RADIX_LSB: 0)
			slot->parent = node;
			// slot->parent: (kmem_cache#20-o2)->parent: kmem_cache#20-o1 (RADIX_LSB: 0)

			// node: kmem_cache#20-o1 (RADIX_LSB: 0)
			if (node) {
				// offset: 1, node->slots[1]: (kmem_cache#20-o1 (RADIX_LSB: 0))->slots[1],
				// slot: kmem_cache#20-o2
				rcu_assign_pointer(node->slots[offset], slot);
				// node->slots[1]: (kmem_cache#20-o1 (RADIX_LSB: 0))->slots[1]: kmem_cache#20-o2

				// node->count: (kmem_cache#20-o1 (RADIX_LSB: 0))->count: 1
				node->count++;
				// node->count: (kmem_cache#20-o1 (RADIX_LSB: 0))->count: 2
			} else
				rcu_assign_pointer(root->rnode, ptr_to_indirect(slot));
		}

		/* Go a level down */
		// offset: 0, index: 1, shift: 0, RADIX_TREE_MAP_MASK: 0x3f
		// offset: 0, index: 64, shift: 6, RADIX_TREE_MAP_MASK: 0x3f
		// offset: 1, index: 64, shift: 0, RADIX_TREE_MAP_MASK: 0x3f
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;
		// offset: 1
		// offset: 1
		// offset: 0

		// node: NULL, slot: kmem_cache#20-o0 (RADIX_LSB: 0)
		// node: NULL, slot: kmem_cache#20-o1 (RADIX_LSB: 0)
		// node: NULL, slot: kmem_cache#20-o2 (RADIX_LSB: 0)
		node = slot;
		// node: kmem_cache#20-o0 (RADIX_LSB: 0)
		// node: kmem_cache#20-o1 (RADIX_LSB: 0)
		// node: kmem_cache#20-o2 (RADIX_LSB: 0)

		// offset: 1, node->slots[1]: (kmem_cache#20-o0 (RADIX_LSB: 0))->slots[1]: NULL
		// offset: 1, node->slots[1]: (kmem_cache#20-o1 (RADIX_LSB: 0))->slots[1]: NULL
		// offset: 0, node->slots[0]: (kmem_cache#20-o2 (RADIX_LSB: 0))->slots[0]: NULL
		slot = node->slots[offset];
		// slot: NULL
		// slot: NULL
		// slot: NULL

		// shift: 0, RADIX_TREE_MAP_SHIFT: 6
		// shift: 6, RADIX_TREE_MAP_SHIFT: 6
		// shift: 0, RADIX_TREE_MAP_SHIFT: 6
		shift -= RADIX_TREE_MAP_SHIFT;
		// shift: 0xfffffffa
		// shift: 0
		// shift: 0xfffffffa

		// height: 1
		// height: 2
		// height: 1
		height--;
		// height: 0
		// height: 1
		// height: 0
	}

	// slot: NULL
	// slot: NULL
	// slot: NULL
	if (slot != NULL)
		return -EEXIST;

	// node: NULL
	// node: kmem_cache#20-o0 (RADIX_LSB: 0)
	// node: kmem_cache#20-o2 (RADIX_LSB: 0)
	if (node) {
		// node->count: (kmem_cache#20-o0 (RADIX_LSB: 0))->count: 1
		// node->count: (kmem_cache#20-o2 (RADIX_LSB: 0))->count: 0
		node->count++;
		// node->count: (kmem_cache#20-o0 (RADIX_LSB: 0))->count: 2
		// node->count: (kmem_cache#20-o2 (RADIX_LSB: 0))->count: 1

		// offset: 1, node->slots[1]: (kmem_cache#20-o0 (RADIX_LSB: 0))->slots[1], item: kmem_cache#28-o1 (irq 1)
		// offset: 0, node->slots[0]: (kmem_cache#20-o2 (RADIX_LSB: 0))->slots[0], item: kmem_cache#28-oX (irq 64)
		rcu_assign_pointer(node->slots[offset], item);
		// node->slots[1]: (kmem_cache#20-o0 (RADIX_LSB: 0))->slots[1]: kmem_cache#28-o1 (irq 1)
		// node->slots[0]: (kmem_cache#20-o2 (RADIX_LSB: 0))->slots[0]: kmem_cache#28-oX (irq 64)

		// node: kmem_cache#20-o0 (RADIX_LSB: 0), offset: 1
		// tag_get(kmem_cache#20-o0 (RADIX_LSB: 0), 0, 1): 0
		// node: kmem_cache#20-o2 (RADIX_LSB: 0), offset: 0
		// tag_get(kmem_cache#20-o2 (RADIX_LSB: 0), 0, 1): 0
		BUG_ON(tag_get(node, 0, offset));

		// node: kmem_cache#20-o0 (RADIX_LSB: 0), offset: 1
		// tag_get(kmem_cache#20-o0 (RADIX_LSB: 0), 1, 1): 0
		// node: kmem_cache#20-o2 (RADIX_LSB: 0), offset: 0
		// tag_get(kmem_cache#20-o2 (RADIX_LSB: 0), 1, 1): 0
		BUG_ON(tag_get(node, 1, offset));
	} else {
		// root->rnode: (&irq_desc_tree)->rnode: NULL, item: kmem_cache#28-o0
		rcu_assign_pointer(root->rnode, item);
		// rcu_assign_pointer에서 한일:
		// ((&irq_desc_tree)->rnode) = (typeof(*kmem_cache#28-o0) __force rcu *)(kmem_cache#28-o0);

		// root: &irq_desc_tree, root_tag_get(&irq_desc_tree, 0): 0
		BUG_ON(root_tag_get(root, 0));

		// root: &irq_desc_tree, root_tag_get(&irq_desc_tree, 1): 0
		BUG_ON(root_tag_get(root, 1));
	}

	return 0;
	// return 0
	// return 0
	// return 0
}
EXPORT_SYMBOL(radix_tree_insert);

/*
 * is_slot == 1 : search for the slot.
 * is_slot == 0 : search for the node.
 */
// ARM10C 20141122
// root: &irq_desc_tree, index: 16, 0
// ARM10C 20150321
// root: &irq_desc_tree, index: 347, 0
static void *radix_tree_lookup_element(struct radix_tree_root *root,
				unsigned long index, int is_slot)
{
	unsigned int height, shift;
	struct radix_tree_node *node, **slot;

	// root->rnode: (&irq_desc_tree)->rnode: kmem_cache#20-o1 (RADIX_LSB: 1)
	// rcu_dereference_raw((&irq_desc_tree)->rnode): kmem_cache#20-o1 (RADIX_LSB: 1)
	node = rcu_dereference_raw(root->rnode);
	// node: kmem_cache#20-o1 (RADIX_LSB: 1)

	// node: kmem_cache#20-o1 (RADIX_LSB: 1)
	if (node == NULL)
		return NULL;

	// node: kmem_cache#20-o1 (RADIX_LSB: 1)
	// radix_tree_is_indirect_ptr(kmem_cache#20-o1 (RADIX_LSB: 1)): 1
	if (!radix_tree_is_indirect_ptr(node)) {
		if (index > 0)
			return NULL;
		return is_slot ? (void *)&root->rnode : node;
	}

	// node: kmem_cache#20-o1 (RADIX_LSB: 1)
	// indirect_to_ptr(kmem_cache#20-o1 (RADIX_LSB: 1)): kmem_cache#20-o1 (RADIX_LSB: 0)
	node = indirect_to_ptr(node);
	// node: kmem_cache#20-o1 (RADIX_LSB: 0)

	// node->height: (kmem_cache#20-o1)->height: 2
	height = node->height;
	// height: 2

	// index: 16, height: 2, radix_tree_maxindex(2): 4095
	if (index > radix_tree_maxindex(height))
		return NULL;

	// height: 2, RADIX_TREE_MAP_SHIFT: 6
	shift = (height-1) * RADIX_TREE_MAP_SHIFT;
	// shift: 6

	do {
		// node->slots: (kmem_cache#20-o1)->slots, index: 16, shift: 6, RADIX_TREE_MAP_MASK: 0x3f
		// node->slots: (kmem_cache#20-o0)->slots, index: 16, shift: 0, RADIX_TREE_MAP_MASK: 0x3f
		slot = (struct radix_tree_node **)
			(node->slots + ((index>>shift) & RADIX_TREE_MAP_MASK));
		// slot: &(kmem_cache#20-o1)->slots[0]
		// slot: &(kmem_cache#20-o0)->slots[16]

		// *slot: (kmem_cache#20-o1)->slots[0]
		// rcu_dereference_raw((kmem_cache#20-o1)->slots[0]): kmem_cache#20-o0
		// *slot: (kmem_cache#20-o0)->slots[16]
		// rcu_dereference_raw((kmem_cache#20-o0)->slots[16]): kmem_cache#28-oX (irq 16)
		node = rcu_dereference_raw(*slot);
		// node: kmem_cache#20-o0
		// node: kmem_cache#28-oX (irq 16)

		// node: kmem_cache#20-o0
		// node: kmem_cache#28-oX (irq 16)
		if (node == NULL)
			return NULL;

		// shift: 6, RADIX_TREE_MAP_SHIFT: 6
		// shift: 0, RADIX_TREE_MAP_SHIFT: 6
		shift -= RADIX_TREE_MAP_SHIFT;
		// shift: 0
		// shift: 0xfffffffa

		// height: 2
		// height: 1
		height--;
		// height: 1
		// height: 0

		// height: 1
		// height: 0
	} while (height > 0);

	// is_slot: 0, node: kmem_cache#28-oX (irq 16)
	// indirect_to_ptr(kmem_cache#28-oX (irq 16)): kmem_cache#28-oX (irq 16)
	return is_slot ? (void *)slot : indirect_to_ptr(node);
	// return kmem_cache#28-oX (irq 16)
}

/**
 *	radix_tree_lookup_slot    -    lookup a slot in a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *
 *	Returns:  the slot corresponding to the position @index in the
 *	radix tree @root. This is useful for update-if-exists operations.
 *
 *	This function can be called under rcu_read_lock iff the slot is not
 *	modified by radix_tree_replace_slot, otherwise it must be called
 *	exclusive from other writers. Any dereference of the slot must be done
 *	using radix_tree_deref_slot.
 */
void **radix_tree_lookup_slot(struct radix_tree_root *root, unsigned long index)
{
	return (void **)radix_tree_lookup_element(root, index, 1);
}
EXPORT_SYMBOL(radix_tree_lookup_slot);

/**
 *	radix_tree_lookup    -    perform lookup operation on a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *
 *	Lookup the item at the position @index in the radix tree @root.
 *
 *	This function can be called under rcu_read_lock, however the caller
 *	must manage lifetimes of leaf nodes (eg. RCU may also be used to free
 *	them safely). No RCU barriers are required to access or modify the
 *	returned item, however.
 */
// ARM10C 20141122
// &irq_desc_tree, irq: 16
// ARM10C 20150321
// &irq_desc_tree, irq: 347
void *radix_tree_lookup(struct radix_tree_root *root, unsigned long index)
{
	// root: &irq_desc_tree, index: 16
	// radix_tree_lookup_element(&irq_desc_tree, 16, 0): kmem_cache#28-oX (irq 16)
	// root: &irq_desc_tree, index: 347
	// radix_tree_lookup_element(&irq_desc_tree, 347, 0): kmem_cache#28-oX (irq 347)
	return radix_tree_lookup_element(root, index, 0);
	// return kmem_cache#28-oX (irq 16)
	// return kmem_cache#28-oX (irq 347)
}
EXPORT_SYMBOL(radix_tree_lookup);

/**
 *	radix_tree_tag_set - set a tag on a radix tree node
 *	@root:		radix tree root
 *	@index:		index key
 *	@tag: 		tag index
 *
 *	Set the search tag (which must be < RADIX_TREE_MAX_TAGS)
 *	corresponding to @index in the radix tree.  From
 *	the root all the way down to the leaf node.
 *
 *	Returns the address of the tagged item.   Setting a tag on a not-present
 *	item is a bug.
 */
void *radix_tree_tag_set(struct radix_tree_root *root,
			unsigned long index, unsigned int tag)
{
	unsigned int height, shift;
	struct radix_tree_node *slot;

	height = root->height;
	BUG_ON(index > radix_tree_maxindex(height));

	slot = indirect_to_ptr(root->rnode);
	shift = (height - 1) * RADIX_TREE_MAP_SHIFT;

	while (height > 0) {
		int offset;

		offset = (index >> shift) & RADIX_TREE_MAP_MASK;
		if (!tag_get(slot, tag, offset))
			tag_set(slot, tag, offset);
		slot = slot->slots[offset];
		BUG_ON(slot == NULL);
		shift -= RADIX_TREE_MAP_SHIFT;
		height--;
	}

	/* set the root's tag bit */
	if (slot && !root_tag_get(root, tag))
		root_tag_set(root, tag);

	return slot;
}
EXPORT_SYMBOL(radix_tree_tag_set);

/**
 *	radix_tree_tag_clear - clear a tag on a radix tree node
 *	@root:		radix tree root
 *	@index:		index key
 *	@tag: 		tag index
 *
 *	Clear the search tag (which must be < RADIX_TREE_MAX_TAGS)
 *	corresponding to @index in the radix tree.  If
 *	this causes the leaf node to have no tags set then clear the tag in the
 *	next-to-leaf node, etc.
 *
 *	Returns the address of the tagged item on success, else NULL.  ie:
 *	has the same return value and semantics as radix_tree_lookup().
 */
void *radix_tree_tag_clear(struct radix_tree_root *root,
			unsigned long index, unsigned int tag)
{
	struct radix_tree_node *node = NULL;
	struct radix_tree_node *slot = NULL;
	unsigned int height, shift;
	int uninitialized_var(offset);

	height = root->height;
	if (index > radix_tree_maxindex(height))
		goto out;

	shift = height * RADIX_TREE_MAP_SHIFT;
	slot = indirect_to_ptr(root->rnode);

	while (shift) {
		if (slot == NULL)
			goto out;

		shift -= RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;
		node = slot;
		slot = slot->slots[offset];
	}

	if (slot == NULL)
		goto out;

	while (node) {
		if (!tag_get(node, tag, offset))
			goto out;
		tag_clear(node, tag, offset);
		if (any_tag_set(node, tag))
			goto out;

		index >>= RADIX_TREE_MAP_SHIFT;
		offset = index & RADIX_TREE_MAP_MASK;
		node = node->parent;
	}

	/* clear the root's tag bit */
	if (root_tag_get(root, tag))
		root_tag_clear(root, tag);

out:
	return slot;
}
EXPORT_SYMBOL(radix_tree_tag_clear);

/**
 * radix_tree_tag_get - get a tag on a radix tree node
 * @root:		radix tree root
 * @index:		index key
 * @tag: 		tag index (< RADIX_TREE_MAX_TAGS)
 *
 * Return values:
 *
 *  0: tag not present or not set
 *  1: tag set
 *
 * Note that the return value of this function may not be relied on, even if
 * the RCU lock is held, unless tag modification and node deletion are excluded
 * from concurrency.
 */
int radix_tree_tag_get(struct radix_tree_root *root,
			unsigned long index, unsigned int tag)
{
	unsigned int height, shift;
	struct radix_tree_node *node;

	/* check the root's tag bit */
	if (!root_tag_get(root, tag))
		return 0;

	node = rcu_dereference_raw(root->rnode);
	if (node == NULL)
		return 0;

	if (!radix_tree_is_indirect_ptr(node))
		return (index == 0);
	node = indirect_to_ptr(node);

	height = node->height;
	if (index > radix_tree_maxindex(height))
		return 0;

	shift = (height - 1) * RADIX_TREE_MAP_SHIFT;

	for ( ; ; ) {
		int offset;

		if (node == NULL)
			return 0;

		offset = (index >> shift) & RADIX_TREE_MAP_MASK;
		if (!tag_get(node, tag, offset))
			return 0;
		if (height == 1)
			return 1;
		node = rcu_dereference_raw(node->slots[offset]);
		shift -= RADIX_TREE_MAP_SHIFT;
		height--;
	}
}
EXPORT_SYMBOL(radix_tree_tag_get);

/**
 * radix_tree_next_chunk - find next chunk of slots for iteration
 *
 * @root:	radix tree root
 * @iter:	iterator state
 * @flags:	RADIX_TREE_ITER_* flags and tag index
 * Returns:	pointer to chunk first slot, or NULL if iteration is over
 */
void **radix_tree_next_chunk(struct radix_tree_root *root,
			     struct radix_tree_iter *iter, unsigned flags)
{
	unsigned shift, tag = flags & RADIX_TREE_ITER_TAG_MASK;
	struct radix_tree_node *rnode, *node;
	unsigned long index, offset;

	if ((flags & RADIX_TREE_ITER_TAGGED) && !root_tag_get(root, tag))
		return NULL;

	/*
	 * Catch next_index overflow after ~0UL. iter->index never overflows
	 * during iterating; it can be zero only at the beginning.
	 * And we cannot overflow iter->next_index in a single step,
	 * because RADIX_TREE_MAP_SHIFT < BITS_PER_LONG.
	 *
	 * This condition also used by radix_tree_next_slot() to stop
	 * contiguous iterating, and forbid swithing to the next chunk.
	 */
	index = iter->next_index;
	if (!index && iter->index)
		return NULL;

	rnode = rcu_dereference_raw(root->rnode);
	if (radix_tree_is_indirect_ptr(rnode)) {
		rnode = indirect_to_ptr(rnode);
	} else if (rnode && !index) {
		/* Single-slot tree */
		iter->index = 0;
		iter->next_index = 1;
		iter->tags = 1;
		return (void **)&root->rnode;
	} else
		return NULL;

restart:
	shift = (rnode->height - 1) * RADIX_TREE_MAP_SHIFT;
	offset = index >> shift;

	/* Index outside of the tree */
	if (offset >= RADIX_TREE_MAP_SIZE)
		return NULL;

	node = rnode;
	while (1) {
		if ((flags & RADIX_TREE_ITER_TAGGED) ?
				!test_bit(offset, node->tags[tag]) :
				!node->slots[offset]) {
			/* Hole detected */
			if (flags & RADIX_TREE_ITER_CONTIG)
				return NULL;

			if (flags & RADIX_TREE_ITER_TAGGED)
				offset = radix_tree_find_next_bit(
						node->tags[tag],
						RADIX_TREE_MAP_SIZE,
						offset + 1);
			else
				while (++offset	< RADIX_TREE_MAP_SIZE) {
					if (node->slots[offset])
						break;
				}
			index &= ~((RADIX_TREE_MAP_SIZE << shift) - 1);
			index += offset << shift;
			/* Overflow after ~0UL */
			if (!index)
				return NULL;
			if (offset == RADIX_TREE_MAP_SIZE)
				goto restart;
		}

		/* This is leaf-node */
		if (!shift)
			break;

		node = rcu_dereference_raw(node->slots[offset]);
		if (node == NULL)
			goto restart;
		shift -= RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;
	}

	/* Update the iterator state */
	iter->index = index;
	iter->next_index = (index | RADIX_TREE_MAP_MASK) + 1;

	/* Construct iter->tags bit-mask from node->tags[tag] array */
	if (flags & RADIX_TREE_ITER_TAGGED) {
		unsigned tag_long, tag_bit;

		tag_long = offset / BITS_PER_LONG;
		tag_bit  = offset % BITS_PER_LONG;
		iter->tags = node->tags[tag][tag_long] >> tag_bit;
		/* This never happens if RADIX_TREE_TAG_LONGS == 1 */
		if (tag_long < RADIX_TREE_TAG_LONGS - 1) {
			/* Pick tags from next element */
			if (tag_bit)
				iter->tags |= node->tags[tag][tag_long + 1] <<
						(BITS_PER_LONG - tag_bit);
			/* Clip chunk size, here only BITS_PER_LONG tags */
			iter->next_index = index + BITS_PER_LONG;
		}
	}

	return node->slots + offset;
}
EXPORT_SYMBOL(radix_tree_next_chunk);

/**
 * radix_tree_range_tag_if_tagged - for each item in given range set given
 *				   tag if item has another tag set
 * @root:		radix tree root
 * @first_indexp:	pointer to a starting index of a range to scan
 * @last_index:		last index of a range to scan
 * @nr_to_tag:		maximum number items to tag
 * @iftag:		tag index to test
 * @settag:		tag index to set if tested tag is set
 *
 * This function scans range of radix tree from first_index to last_index
 * (inclusive).  For each item in the range if iftag is set, the function sets
 * also settag. The function stops either after tagging nr_to_tag items or
 * after reaching last_index.
 *
 * The tags must be set from the leaf level only and propagated back up the
 * path to the root. We must do this so that we resolve the full path before
 * setting any tags on intermediate nodes. If we set tags as we descend, then
 * we can get to the leaf node and find that the index that has the iftag
 * set is outside the range we are scanning. This reults in dangling tags and
 * can lead to problems with later tag operations (e.g. livelocks on lookups).
 *
 * The function returns number of leaves where the tag was set and sets
 * *first_indexp to the first unscanned index.
 * WARNING! *first_indexp can wrap if last_index is ULONG_MAX. Caller must
 * be prepared to handle that.
 */
unsigned long radix_tree_range_tag_if_tagged(struct radix_tree_root *root,
		unsigned long *first_indexp, unsigned long last_index,
		unsigned long nr_to_tag,
		unsigned int iftag, unsigned int settag)
{
	unsigned int height = root->height;
	struct radix_tree_node *node = NULL;
	struct radix_tree_node *slot;
	unsigned int shift;
	unsigned long tagged = 0;
	unsigned long index = *first_indexp;

	last_index = min(last_index, radix_tree_maxindex(height));
	if (index > last_index)
		return 0;
	if (!nr_to_tag)
		return 0;
	if (!root_tag_get(root, iftag)) {
		*first_indexp = last_index + 1;
		return 0;
	}
	if (height == 0) {
		*first_indexp = last_index + 1;
		root_tag_set(root, settag);
		return 1;
	}

	shift = (height - 1) * RADIX_TREE_MAP_SHIFT;
	slot = indirect_to_ptr(root->rnode);

	for (;;) {
		unsigned long upindex;
		int offset;

		offset = (index >> shift) & RADIX_TREE_MAP_MASK;
		if (!slot->slots[offset])
			goto next;
		if (!tag_get(slot, iftag, offset))
			goto next;
		if (shift) {
			/* Go down one level */
			shift -= RADIX_TREE_MAP_SHIFT;
			node = slot;
			slot = slot->slots[offset];
			continue;
		}

		/* tag the leaf */
		tagged++;
		tag_set(slot, settag, offset);

		/* walk back up the path tagging interior nodes */
		upindex = index;
		while (node) {
			upindex >>= RADIX_TREE_MAP_SHIFT;
			offset = upindex & RADIX_TREE_MAP_MASK;

			/* stop if we find a node with the tag already set */
			if (tag_get(node, settag, offset))
				break;
			tag_set(node, settag, offset);
			node = node->parent;
		}

		/*
		 * Small optimization: now clear that node pointer.
		 * Since all of this slot's ancestors now have the tag set
		 * from setting it above, we have no further need to walk
		 * back up the tree setting tags, until we update slot to
		 * point to another radix_tree_node.
		 */
		node = NULL;

next:
		/* Go to next item at level determined by 'shift' */
		index = ((index >> shift) + 1) << shift;
		/* Overflow can happen when last_index is ~0UL... */
		if (index > last_index || !index)
			break;
		if (tagged >= nr_to_tag)
			break;
		while (((index >> shift) & RADIX_TREE_MAP_MASK) == 0) {
			/*
			 * We've fully scanned this node. Go up. Because
			 * last_index is guaranteed to be in the tree, what
			 * we do below cannot wander astray.
			 */
			slot = slot->parent;
			shift += RADIX_TREE_MAP_SHIFT;
		}
	}
	/*
	 * We need not to tag the root tag if there is no tag which is set with
	 * settag within the range from *first_indexp to last_index.
	 */
	if (tagged > 0)
		root_tag_set(root, settag);
	*first_indexp = index;

	return tagged;
}
EXPORT_SYMBOL(radix_tree_range_tag_if_tagged);


/**
 *	radix_tree_next_hole    -    find the next hole (not-present entry)
 *	@root:		tree root
 *	@index:		index key
 *	@max_scan:	maximum range to search
 *
 *	Search the set [index, min(index+max_scan-1, MAX_INDEX)] for the lowest
 *	indexed hole.
 *
 *	Returns: the index of the hole if found, otherwise returns an index
 *	outside of the set specified (in which case 'return - index >= max_scan'
 *	will be true). In rare cases of index wrap-around, 0 will be returned.
 *
 *	radix_tree_next_hole may be called under rcu_read_lock. However, like
 *	radix_tree_gang_lookup, this will not atomically search a snapshot of
 *	the tree at a single point in time. For example, if a hole is created
 *	at index 5, then subsequently a hole is created at index 10,
 *	radix_tree_next_hole covering both indexes may return 10 if called
 *	under rcu_read_lock.
 */
unsigned long radix_tree_next_hole(struct radix_tree_root *root,
				unsigned long index, unsigned long max_scan)
{
	unsigned long i;

	for (i = 0; i < max_scan; i++) {
		if (!radix_tree_lookup(root, index))
			break;
		index++;
		if (index == 0)
			break;
	}

	return index;
}
EXPORT_SYMBOL(radix_tree_next_hole);

/**
 *	radix_tree_prev_hole    -    find the prev hole (not-present entry)
 *	@root:		tree root
 *	@index:		index key
 *	@max_scan:	maximum range to search
 *
 *	Search backwards in the range [max(index-max_scan+1, 0), index]
 *	for the first hole.
 *
 *	Returns: the index of the hole if found, otherwise returns an index
 *	outside of the set specified (in which case 'index - return >= max_scan'
 *	will be true). In rare cases of wrap-around, ULONG_MAX will be returned.
 *
 *	radix_tree_next_hole may be called under rcu_read_lock. However, like
 *	radix_tree_gang_lookup, this will not atomically search a snapshot of
 *	the tree at a single point in time. For example, if a hole is created
 *	at index 10, then subsequently a hole is created at index 5,
 *	radix_tree_prev_hole covering both indexes may return 5 if called under
 *	rcu_read_lock.
 */
unsigned long radix_tree_prev_hole(struct radix_tree_root *root,
				   unsigned long index, unsigned long max_scan)
{
	unsigned long i;

	for (i = 0; i < max_scan; i++) {
		if (!radix_tree_lookup(root, index))
			break;
		index--;
		if (index == ULONG_MAX)
			break;
	}

	return index;
}
EXPORT_SYMBOL(radix_tree_prev_hole);

/**
 *	radix_tree_gang_lookup - perform multiple lookup on a radix tree
 *	@root:		radix tree root
 *	@results:	where the results of the lookup are placed
 *	@first_index:	start the lookup from this key
 *	@max_items:	place up to this many items at *results
 *
 *	Performs an index-ascending scan of the tree for present items.  Places
 *	them at *@results and returns the number of items which were placed at
 *	*@results.
 *
 *	The implementation is naive.
 *
 *	Like radix_tree_lookup, radix_tree_gang_lookup may be called under
 *	rcu_read_lock. In this case, rather than the returned results being
 *	an atomic snapshot of the tree at a single point in time, the semantics
 *	of an RCU protected gang lookup are as though multiple radix_tree_lookups
 *	have been issued in individual locks, and results stored in 'results'.
 */
unsigned int
radix_tree_gang_lookup(struct radix_tree_root *root, void **results,
			unsigned long first_index, unsigned int max_items)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned int ret = 0;

	if (unlikely(!max_items))
		return 0;

	radix_tree_for_each_slot(slot, root, &iter, first_index) {
		results[ret] = indirect_to_ptr(rcu_dereference_raw(*slot));
		if (!results[ret])
			continue;
		if (++ret == max_items)
			break;
	}

	return ret;
}
EXPORT_SYMBOL(radix_tree_gang_lookup);

/**
 *	radix_tree_gang_lookup_slot - perform multiple slot lookup on radix tree
 *	@root:		radix tree root
 *	@results:	where the results of the lookup are placed
 *	@indices:	where their indices should be placed (but usually NULL)
 *	@first_index:	start the lookup from this key
 *	@max_items:	place up to this many items at *results
 *
 *	Performs an index-ascending scan of the tree for present items.  Places
 *	their slots at *@results and returns the number of items which were
 *	placed at *@results.
 *
 *	The implementation is naive.
 *
 *	Like radix_tree_gang_lookup as far as RCU and locking goes. Slots must
 *	be dereferenced with radix_tree_deref_slot, and if using only RCU
 *	protection, radix_tree_deref_slot may fail requiring a retry.
 */
unsigned int
radix_tree_gang_lookup_slot(struct radix_tree_root *root,
			void ***results, unsigned long *indices,
			unsigned long first_index, unsigned int max_items)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned int ret = 0;

	if (unlikely(!max_items))
		return 0;

	radix_tree_for_each_slot(slot, root, &iter, first_index) {
		results[ret] = slot;
		if (indices)
			indices[ret] = iter.index;
		if (++ret == max_items)
			break;
	}

	return ret;
}
EXPORT_SYMBOL(radix_tree_gang_lookup_slot);

/**
 *	radix_tree_gang_lookup_tag - perform multiple lookup on a radix tree
 *	                             based on a tag
 *	@root:		radix tree root
 *	@results:	where the results of the lookup are placed
 *	@first_index:	start the lookup from this key
 *	@max_items:	place up to this many items at *results
 *	@tag:		the tag index (< RADIX_TREE_MAX_TAGS)
 *
 *	Performs an index-ascending scan of the tree for present items which
 *	have the tag indexed by @tag set.  Places the items at *@results and
 *	returns the number of items which were placed at *@results.
 */
unsigned int
radix_tree_gang_lookup_tag(struct radix_tree_root *root, void **results,
		unsigned long first_index, unsigned int max_items,
		unsigned int tag)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned int ret = 0;

	if (unlikely(!max_items))
		return 0;

	radix_tree_for_each_tagged(slot, root, &iter, first_index, tag) {
		results[ret] = indirect_to_ptr(rcu_dereference_raw(*slot));
		if (!results[ret])
			continue;
		if (++ret == max_items)
			break;
	}

	return ret;
}
EXPORT_SYMBOL(radix_tree_gang_lookup_tag);

/**
 *	radix_tree_gang_lookup_tag_slot - perform multiple slot lookup on a
 *					  radix tree based on a tag
 *	@root:		radix tree root
 *	@results:	where the results of the lookup are placed
 *	@first_index:	start the lookup from this key
 *	@max_items:	place up to this many items at *results
 *	@tag:		the tag index (< RADIX_TREE_MAX_TAGS)
 *
 *	Performs an index-ascending scan of the tree for present items which
 *	have the tag indexed by @tag set.  Places the slots at *@results and
 *	returns the number of slots which were placed at *@results.
 */
unsigned int
radix_tree_gang_lookup_tag_slot(struct radix_tree_root *root, void ***results,
		unsigned long first_index, unsigned int max_items,
		unsigned int tag)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned int ret = 0;

	if (unlikely(!max_items))
		return 0;

	radix_tree_for_each_tagged(slot, root, &iter, first_index, tag) {
		results[ret] = slot;
		if (++ret == max_items)
			break;
	}

	return ret;
}
EXPORT_SYMBOL(radix_tree_gang_lookup_tag_slot);

#if defined(CONFIG_SHMEM) && defined(CONFIG_SWAP)
#include <linux/sched.h> /* for cond_resched() */

/*
 * This linear search is at present only useful to shmem_unuse_inode().
 */
static unsigned long __locate(struct radix_tree_node *slot, void *item,
			      unsigned long index, unsigned long *found_index)
{
	unsigned int shift, height;
	unsigned long i;

	height = slot->height;
	shift = (height-1) * RADIX_TREE_MAP_SHIFT;

	for ( ; height > 1; height--) {
		i = (index >> shift) & RADIX_TREE_MAP_MASK;
		for (;;) {
			if (slot->slots[i] != NULL)
				break;
			index &= ~((1UL << shift) - 1);
			index += 1UL << shift;
			if (index == 0)
				goto out;	/* 32-bit wraparound */
			i++;
			if (i == RADIX_TREE_MAP_SIZE)
				goto out;
		}

		shift -= RADIX_TREE_MAP_SHIFT;
		slot = rcu_dereference_raw(slot->slots[i]);
		if (slot == NULL)
			goto out;
	}

	/* Bottom level: check items */
	for (i = 0; i < RADIX_TREE_MAP_SIZE; i++) {
		if (slot->slots[i] == item) {
			*found_index = index + i;
			index = 0;
			goto out;
		}
	}
	index += RADIX_TREE_MAP_SIZE;
out:
	return index;
}

/**
 *	radix_tree_locate_item - search through radix tree for item
 *	@root:		radix tree root
 *	@item:		item to be found
 *
 *	Returns index where item was found, or -1 if not found.
 *	Caller must hold no lock (since this time-consuming function needs
 *	to be preemptible), and must check afterwards if item is still there.
 */
unsigned long radix_tree_locate_item(struct radix_tree_root *root, void *item)
{
	struct radix_tree_node *node;
	unsigned long max_index;
	unsigned long cur_index = 0;
	unsigned long found_index = -1;

	do {
		rcu_read_lock();
		node = rcu_dereference_raw(root->rnode);
		if (!radix_tree_is_indirect_ptr(node)) {
			rcu_read_unlock();
			if (node == item)
				found_index = 0;
			break;
		}

		node = indirect_to_ptr(node);
		max_index = radix_tree_maxindex(node->height);
		if (cur_index > max_index)
			break;

		cur_index = __locate(node, item, cur_index, &found_index);
		rcu_read_unlock();
		cond_resched();
	} while (cur_index != 0 && cur_index <= max_index);

	return found_index;
}
#else
unsigned long radix_tree_locate_item(struct radix_tree_root *root, void *item)
{
	return -1;
}
#endif /* CONFIG_SHMEM && CONFIG_SWAP */

/**
 *	radix_tree_shrink    -    shrink height of a radix tree to minimal
 *	@root		radix tree root
 */
static inline void radix_tree_shrink(struct radix_tree_root *root)
{
	/* try to shrink tree height */
	while (root->height > 0) {
		struct radix_tree_node *to_free = root->rnode;
		struct radix_tree_node *slot;

		BUG_ON(!radix_tree_is_indirect_ptr(to_free));
		to_free = indirect_to_ptr(to_free);

		/*
		 * The candidate node has more than one child, or its child
		 * is not at the leftmost slot, we cannot shrink.
		 */
		if (to_free->count != 1)
			break;
		if (!to_free->slots[0])
			break;

		/*
		 * We don't need rcu_assign_pointer(), since we are simply
		 * moving the node from one part of the tree to another: if it
		 * was safe to dereference the old pointer to it
		 * (to_free->slots[0]), it will be safe to dereference the new
		 * one (root->rnode) as far as dependent read barriers go.
		 */
		slot = to_free->slots[0];
		if (root->height > 1) {
			slot->parent = NULL;
			slot = ptr_to_indirect(slot);
		}
		root->rnode = slot;
		root->height--;

		/*
		 * We have a dilemma here. The node's slot[0] must not be
		 * NULLed in case there are concurrent lookups expecting to
		 * find the item. However if this was a bottom-level node,
		 * then it may be subject to the slot pointer being visible
		 * to callers dereferencing it. If item corresponding to
		 * slot[0] is subsequently deleted, these callers would expect
		 * their slot to become empty sooner or later.
		 *
		 * For example, lockless pagecache will look up a slot, deref
		 * the page pointer, and if the page is 0 refcount it means it
		 * was concurrently deleted from pagecache so try the deref
		 * again. Fortunately there is already a requirement for logic
		 * to retry the entire slot lookup -- the indirect pointer
		 * problem (replacing direct root node with an indirect pointer
		 * also results in a stale slot). So tag the slot as indirect
		 * to force callers to retry.
		 */
		if (root->height == 0)
			*((unsigned long *)&to_free->slots[0]) |=
						RADIX_TREE_INDIRECT_PTR;

		radix_tree_node_free(to_free);
	}
}

/**
 *	radix_tree_delete    -    delete an item from a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *
 *	Remove the item at @index from the radix tree rooted at @root.
 *
 *	Returns the address of the deleted item, or NULL if it was not present.
 */
void *radix_tree_delete(struct radix_tree_root *root, unsigned long index)
{
	struct radix_tree_node *node = NULL;
	struct radix_tree_node *slot = NULL;
	struct radix_tree_node *to_free;
	unsigned int height, shift;
	int tag;
	int uninitialized_var(offset);

	height = root->height;
	if (index > radix_tree_maxindex(height))
		goto out;

	slot = root->rnode;
	if (height == 0) {
		root_tag_clear_all(root);
		root->rnode = NULL;
		goto out;
	}
	slot = indirect_to_ptr(slot);
	shift = height * RADIX_TREE_MAP_SHIFT;

	do {
		if (slot == NULL)
			goto out;

		shift -= RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;
		node = slot;
		slot = slot->slots[offset];
	} while (shift);

	if (slot == NULL)
		goto out;

	/*
	 * Clear all tags associated with the item to be deleted.
	 * This way of doing it would be inefficient, but seldom is any set.
	 */
	for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++) {
		if (tag_get(node, tag, offset))
			radix_tree_tag_clear(root, index, tag);
	}

	to_free = NULL;
	/* Now free the nodes we do not need anymore */
	while (node) {
		node->slots[offset] = NULL;
		node->count--;
		/*
		 * Queue the node for deferred freeing after the
		 * last reference to it disappears (set NULL, above).
		 */
		if (to_free)
			radix_tree_node_free(to_free);

		if (node->count) {
			if (node == indirect_to_ptr(root->rnode))
				radix_tree_shrink(root);
			goto out;
		}

		/* Node with zero slots in use so free it */
		to_free = node;

		index >>= RADIX_TREE_MAP_SHIFT;
		offset = index & RADIX_TREE_MAP_MASK;
		node = node->parent;
	}

	root_tag_clear_all(root);
	root->height = 0;
	root->rnode = NULL;
	if (to_free)
		radix_tree_node_free(to_free);

out:
	return slot;
}
EXPORT_SYMBOL(radix_tree_delete);

/**
 *	radix_tree_tagged - test whether any items in the tree are tagged
 *	@root:		radix tree root
 *	@tag:		tag to test
 */
int radix_tree_tagged(struct radix_tree_root *root, unsigned int tag)
{
	return root_tag_get(root, tag);
}
EXPORT_SYMBOL(radix_tree_tagged);

// ARM10C 20141004
static void
radix_tree_node_ctor(void *node)
{
	memset(node, 0, sizeof(struct radix_tree_node));
}

// ARM10C 20141004
// 0
// 1
static __init unsigned long __maxindex(unsigned int height)
{
	// RADIX_TREE_MAP_SHIFT: 6
	// RADIX_TREE_MAP_SHIFT: 6
	unsigned int width = height * RADIX_TREE_MAP_SHIFT;
	// width: 0
	// width: 6
	// RADIX_TREE_INDEX_BITS: 32
	// RADIX_TREE_INDEX_BITS: 32
	int shift = RADIX_TREE_INDEX_BITS - width;
	// shift: 32
	// shift: 26

	// shift: 32
	// shift: 26
	if (shift < 0)
		return ~0UL;

	// shift: 32, BITS_PER_LONG: 32
	// shift: 26, BITS_PER_LONG: 32
	if (shift >= BITS_PER_LONG)
		return 0UL;
		// return 0

	// shift: 26
	return ~0UL >> shift;
	// return 0x3F
}

// ARM10C 20141004
static __init void radix_tree_init_maxindex(void)
{
	unsigned int i;

	// ARRAY_SIZE(height_to_maxindex): 7
	for (i = 0; i < ARRAY_SIZE(height_to_maxindex); i++)
		// i: 0, __maxindex(0): 0
		// i: 1, __maxindex(1): 0x3f
		// i: 2, __maxindex(2): 0xfff
		// i: 3, __maxindex(3): 0x3ffff
		// i: 4, __maxindex(4): 0xffffff
		// i: 5, __maxindex(5): 0x3fffffff
		// i: 6, __maxindex(5): 0xffffffff
		height_to_maxindex[i] = __maxindex(i);
		// height_to_maxindex[0]: 0
		// height_to_maxindex[1]: 0x3f
		// height_to_maxindex[2]: 0xfff
		// height_to_maxindex[3]: 0x3ffff
		// height_to_maxindex[4]: 0xffffff
		// height_to_maxindex[5]: 0x3fffffff
		// height_to_maxindex[6]: 0xffffffff
}

// ARM10C 20141004
static int radix_tree_callback(struct notifier_block *nfb,
                            unsigned long action,
                            void *hcpu)
{
       int cpu = (long)hcpu;
       struct radix_tree_preload *rtp;

       /* Free per-cpu pool of perloaded nodes */
       if (action == CPU_DEAD || action == CPU_DEAD_FROZEN) {
               rtp = &per_cpu(radix_tree_preloads, cpu);
               while (rtp->nr) {
                       kmem_cache_free(radix_tree_node_cachep,
                                       rtp->nodes[rtp->nr-1]);
                       rtp->nodes[rtp->nr-1] = NULL;
                       rtp->nr--;
               }
       }
       return NOTIFY_OK;
}

// ARM10C 20141004
void __init radix_tree_init(void)
{
	// sizeof(struct radix_tree_node): 296 bytes,
	// SLAB_PANIC: 0x00040000UL, SLAB_RECLAIM_ACCOUNT: 0x00020000UL
	// kmem_cache_create("radix_tree_node", 296, 0x00060000UL, radix_tree_node_ctor): kmem_cache#20
	radix_tree_node_cachep = kmem_cache_create("radix_tree_node",
			sizeof(struct radix_tree_node), 0,
			SLAB_PANIC | SLAB_RECLAIM_ACCOUNT,
			radix_tree_node_ctor);
	// radix_tree_node_cachep: kmem_cache#20

	radix_tree_init_maxindex();
	// radix_tree_init_maxindex에서 한일:
	// height_to_maxindex[0]: 0
	// height_to_maxindex[1]: 0x3f
	// height_to_maxindex[2]: 0xfff
	// height_to_maxindex[3]: 0x3ffff
	// height_to_maxindex[4]: 0xffffff
	// height_to_maxindex[5]: 0x3fffffff
	// height_to_maxindex[6]: 0xffffffff

	hotcpu_notifier(radix_tree_callback, 0);
	// hotcpu_notifier에서 한일:
	// (&cpu_chain)->head: radix_tree_callback_nb 포인터 대입
	// (&radix_tree_callback_nb)->next은 (&rcu_cpu_notify_nb)->next로 대입
}
