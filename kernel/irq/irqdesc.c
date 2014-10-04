/*
 * Copyright (C) 1992, 1998-2006 Linus Torvalds, Ingo Molnar
 * Copyright (C) 2005-2006, Thomas Gleixner, Russell King
 *
 * This file contains the interrupt descriptor management code
 *
 * Detailed information is available in Documentation/DocBook/genericirq
 *
 */
#include <linux/irq.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/radix-tree.h>
#include <linux/bitmap.h>

#include "internals.h"

/*
 * lockdep: we want to handle all irq_desc locks as a single lock-class:
 */
// ARM10C 20141004
static struct lock_class_key irq_desc_lock_class;

#if defined(CONFIG_SMP) // CONFIG_SMP=y
// ARM10C 20141004
static void __init init_irq_default_affinity(void)
{
	// GFP_NOWAIT: 0
	// alloc_cpumask_var(&irq_default_affinity, 0): 0
	alloc_cpumask_var(&irq_default_affinity, GFP_NOWAIT);
	cpumask_setall(irq_default_affinity);
	// irq_default_affinity->bits[0]: 0xF
}
#else
static void __init init_irq_default_affinity(void)
{
}
#endif

#ifdef CONFIG_SMP // CONFIG_SMP=y
// ARM10C 20141004
// desc: kmem_cache#28-o0, gfp: GFP_KERNEL: 0xD0, node: 0
static int alloc_masks(struct irq_desc *desc, gfp_t gfp, int node)
{
	// desc->irq_data.affinity: &(kmem_cache#28-o0)->irq_data.affinity, gfp: GFP_KERNEL: 0xD0, node: 0
	// zalloc_cpumask_var_node(&(kmem_cache#28-o0)->irq_data.affinity, GFP_KERNEL: 0xD0, 0): true
	if (!zalloc_cpumask_var_node(&desc->irq_data.affinity, gfp, node))
		return -ENOMEM;
	// (kmem_cache#28-o0)->irq_data.affinity.bits[0]: 0

#ifdef CONFIG_GENERIC_PENDING_IRQ // CONFIG_GENERIC_PENDING_IRQ=n
	if (!zalloc_cpumask_var_node(&desc->pending_mask, gfp, node)) {
		free_cpumask_var(desc->irq_data.affinity);
		return -ENOMEM;
	}
#endif
	return 0;
}

// ARM10C 20141004
// desc: kmem_cache#28-o0, node: 0
static void desc_smp_init(struct irq_desc *desc, int node)
{
	// desc->irq_data.node: (kmem_cache#28-o0)->irq_data.node, node: 0
	desc->irq_data.node = node;
	// desc->irq_data.node: (kmem_cache#28-o0)->irq_data.node: 0

	// desc->irq_data.affinity: (kmem_cache#28-o0)->irq_data.affinity,
	// irq_default_affinity->bits[0]: 0xF
	cpumask_copy(desc->irq_data.affinity, irq_default_affinity);
	// desc->irq_data.affinity: (kmem_cache#28-o0)->irq_data.affinity.bits[0]: 0xF

#ifdef CONFIG_GENERIC_PENDING_IRQ // CONFIG_GENERIC_PENDING_IRQ=n
	cpumask_clear(desc->pending_mask);
#endif
}

static inline int desc_node(struct irq_desc *desc)
{
	return desc->irq_data.node;
}

#else
static inline int
alloc_masks(struct irq_desc *desc, gfp_t gfp, int node) { return 0; }
static inline void desc_smp_init(struct irq_desc *desc, int node) { }
static inline int desc_node(struct irq_desc *desc) { return 0; }
#endif

// ARM10C 20141004
// irq: 0, desc: kmem_cache#28-o0, node: 0, owner: null
static void desc_set_defaults(unsigned int irq, struct irq_desc *desc, int node,
		struct module *owner)
{
	int cpu;

	// desc->irq_data.irq: (kmem_cache#28-o0)->irq_data.irq, irq: 0
	desc->irq_data.irq = irq;
	// desc->irq_data.irq: (kmem_cache#28-o0)->irq_data.irq: 0

	// desc->irq_data.chip: (kmem_cache#28-o0)->irq_data.chip
	desc->irq_data.chip = &no_irq_chip;
	// desc->irq_data.chip: (kmem_cache#28-o0)->irq_data.chip: &no_irq_chip

	// desc->irq_data.chip_data: (kmem_cache#28-o0)->irq_data.chip_data
	desc->irq_data.chip_data = NULL;
	// desc->irq_data.chip_data: (kmem_cache#28-o0)->irq_data.chip_data: NULL

	// desc->irq_data.handler_data: (kmem_cache#28-o0)->irq_data.handler_data
	desc->irq_data.handler_data = NULL;
	// desc->irq_data.handler_data: (kmem_cache#28-o0)->irq_data.handler_data: NULL

	// desc->irq_data.msi_desc: (kmem_cache#28-o0)->irq_data.msi_desc
	desc->irq_data.msi_desc = NULL;
	// desc->irq_data.msi_desc: (kmem_cache#28-o0)->irq_data.msi_desc: NULL

	// desc: kmem_cache#28-o0, 0xFFFFFFFF, _IRQ_DEFAULT_INIT_FLAGS: 0xc00
	irq_settings_clr_and_set(desc, ~0, _IRQ_DEFAULT_INIT_FLAGS);
	// irq_settings_clr_and_set에서 한일:
	// desc->status_use_accessors: (kmem_cache#28-o0)->status_use_accessors: 0xc00

	// &desc->irq_data: &(kmem_cache#28-o0)->irq_data, IRQD_IRQ_DISABLED: 0x10000
	irqd_set(&desc->irq_data, IRQD_IRQ_DISABLED);
	// irqd_set에서 한일:
	// d->state_use_accessors: (&(kmem_cache#28-o0)->irq_data)->state_use_accessors: 0x10000

	// desc->handle_irq: (kmem_cache#28-o0)->handle_irq
	desc->handle_irq = handle_bad_irq;
	// desc->handle_irq: (kmem_cache#28-o0)->handle_irq: handle_bad_irq

	// desc->depth: (kmem_cache#28-o0)->depth
	desc->depth = 1;
	// desc->depth: (kmem_cache#28-o0)->depth: 1

	// desc->irq_count: (kmem_cache#28-o0)->irq_count
	desc->irq_count = 0;
	// desc->irq_count: (kmem_cache#28-o0)->irq_count: 0

	// desc->irqs_unhandled: (kmem_cache#28-o0)->irqs_unhandled
	desc->irqs_unhandled = 0;
	// desc->irqs_unhandled: (kmem_cache#28-o0)->irqs_unhandled: 0

	// desc->name: (kmem_cache#28-o0)->name
	desc->name = NULL;
	// desc->name: (kmem_cache#28-o0)->name: NULL

	// desc->owner: (kmem_cache#28-o0)->owner, owner: null
	desc->owner = owner;
	// desc->owner: (kmem_cache#28-o0)->owner: null

	for_each_possible_cpu(cpu)
	// for ((cpu) = -1; (cpu) = cpumask_next((cpu), (cpu_possible_mask)), (cpu) < nr_cpu_ids; )
		// desc->kstat_irqs: (kmem_cache#28-o0)->kstat_irqs, cpu: 0
		*per_cpu_ptr(desc->kstat_irqs, cpu) = 0;
		// [pcp0] (kmem_cache#28-o0)->kstat_irqs: 0
		// cpu: 1 .. 3 수행

	// desc: kmem_cache#28-o0, node: 0
	desc_smp_init(desc, node);
	// desc_smp_init에서 한일:
	// desc->irq_data.node: (kmem_cache#28-o0)->irq_data.node: 0
	// desc->irq_data.affinity: (kmem_cache#28-o0)->irq_data.affinity.bits[0]: 0xF
}

// ARM10C 20141004
// NR_IRQS: 16
// nr_irqs: 16
int nr_irqs = NR_IRQS;
EXPORT_SYMBOL_GPL(nr_irqs);

static DEFINE_MUTEX(sparse_irq_lock);
// ARM10C 20141004
// IRQ_BITMAP_BITS: 8212
// DECLARE_BITMAP(allocated_irqs, 8212): allocated_irqs[257]
static DECLARE_BITMAP(allocated_irqs, IRQ_BITMAP_BITS);

#ifdef CONFIG_SPARSE_IRQ // CONFIG_SPARSE_IRQ=y

// ARM10C 20141004
// GFP_KERNEL: 0xD0
// RADIX_TREE(irq_desc_tree, GFP_KERNEL):
// struct radix_tree_root irq_desc_tree =
// {
//	.height = 0,
//	.gfp_mask = (GFP_KERNEL),
//	.rnode = NULL,
// }
static RADIX_TREE(irq_desc_tree, GFP_KERNEL);

// ARM10C 20141004
// i: 0, desc: kmem_cache#28-o0
static void irq_insert_desc(unsigned int irq, struct irq_desc *desc)
{
	// irq: 0, desc: kmem_cache#28-o0
	radix_tree_insert(&irq_desc_tree, irq, desc);
	// radix tree에 kmem_cache#28-o0를 노드로 추가
}

struct irq_desc *irq_to_desc(unsigned int irq)
{
	return radix_tree_lookup(&irq_desc_tree, irq);
}
EXPORT_SYMBOL(irq_to_desc);

static void delete_irq_desc(unsigned int irq)
{
	radix_tree_delete(&irq_desc_tree, irq);
}

#ifdef CONFIG_SMP
static void free_masks(struct irq_desc *desc)
{
#ifdef CONFIG_GENERIC_PENDING_IRQ
	free_cpumask_var(desc->pending_mask);
#endif
	free_cpumask_var(desc->irq_data.affinity);
}
#else
static inline void free_masks(struct irq_desc *desc) { }
#endif

// ARM10C 20141004
// i: 0, node: 0, null
static struct irq_desc *alloc_desc(int irq, int node, struct module *owner)
{
	struct irq_desc *desc;
	// GFP_KERNEL: 0xD0
	gfp_t gfp = GFP_KERNEL;
	// gfp: GFP_KERNEL: 0xD0

	// sizeof(struct irq_desc): 156 bytes, gfp: GFP_KERNEL: 0xD0, node: 0
	// kzalloc_node(156, GFP_KERNEL: 0xD0, 0): kmem_cache#28-o0
	desc = kzalloc_node(sizeof(*desc), gfp, node);
	// desc: kmem_cache#28-o0

	// desc: kmem_cache#28-o0
	if (!desc)
		return NULL;

	/* allocate based on nr_cpu_ids */
	// desc->kstat_irqs: (kmem_cache#28-o0)->kstat_irqs
	// alloc_percpu(unsigned int): pcp 4 byte 공간 할당
	desc->kstat_irqs = alloc_percpu(unsigned int);
	// desc->kstat_irqs: (kmem_cache#28-o0)->kstat_irqs: pcp 4 byte 공간

	// desc->kstat_irqs: (kmem_cache#28-o0)->kstat_irqs: pcp 4 byte 공간
	if (!desc->kstat_irqs)
		goto err_desc;

	// desc: kmem_cache#28-o0, gfp: GFP_KERNEL: 0xD0, node: 0
	// alloc_masks(kmem_cache#28-o0, GFP_KERNEL: 0xD0, 0): 0
	if (alloc_masks(desc, gfp, node))
		goto err_kstat;
	// alloc_masks에서 한일:
	// (kmem_cache#28-o0)->irq_data.affinity.bits[0]: 0

	// desc->lock: (kmem_cache#28-o0)->lock
	raw_spin_lock_init(&desc->lock);
	// desc->lock: (kmem_cache#28-o0)->lock 을 이용한 spinlock 초기화 수행

	// desc->lock: (kmem_cache#28-o0)->lock
	lockdep_set_class(&desc->lock, &irq_desc_lock_class); // null function

	// irq: 0, desc: kmem_cache#28-o0, node: 0, owner: null
	desc_set_defaults(irq, desc, node, owner);
	// desc_set_defaults에서 한일:
	// (kmem_cache#28-o0)->irq_data.irq: 0
	// (kmem_cache#28-o0)->irq_data.chip: &no_irq_chip
	// (kmem_cache#28-o0)->irq_data.chip_data: NULL
	// (kmem_cache#28-o0)->irq_data.handler_data: NULL
	// (kmem_cache#28-o0)->irq_data.msi_desc: NULL
	// (kmem_cache#28-o0)->status_use_accessors: 0xc00
	// (&(kmem_cache#28-o0)->irq_data)->state_use_accessors: 0x10000
	// (kmem_cache#28-o0)->handle_irq: handle_bad_irq
	// (kmem_cache#28-o0)->depth: 1
	// (kmem_cache#28-o0)->irq_count: 0
	// (kmem_cache#28-o0)->irqs_unhandled: 0
	// (kmem_cache#28-o0)->name: NULL
	// (kmem_cache#28-o0)->owner: null
	// [pcp0...3] (kmem_cache#28-o0)->kstat_irqs: 0
	// (kmem_cache#28-o0)->irq_data.node: 0
	// (kmem_cache#28-o0)->irq_data.affinity.bits[0]: 0xF

	return desc;

err_kstat:
	free_percpu(desc->kstat_irqs);
err_desc:
	kfree(desc);
	return NULL;
}

static void free_desc(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	unregister_irq_proc(irq, desc);

	mutex_lock(&sparse_irq_lock);
	delete_irq_desc(irq);
	mutex_unlock(&sparse_irq_lock);

	free_masks(desc);
	free_percpu(desc->kstat_irqs);
	kfree(desc);
}

static int alloc_descs(unsigned int start, unsigned int cnt, int node,
		       struct module *owner)
{
	struct irq_desc *desc;
	int i;

	for (i = 0; i < cnt; i++) {
		desc = alloc_desc(start + i, node, owner);
		if (!desc)
			goto err;
		mutex_lock(&sparse_irq_lock);
		irq_insert_desc(start + i, desc);
		mutex_unlock(&sparse_irq_lock);
	}
	return start;

err:
	for (i--; i >= 0; i--)
		free_desc(start + i);

	mutex_lock(&sparse_irq_lock);
	bitmap_clear(allocated_irqs, start, cnt);
	mutex_unlock(&sparse_irq_lock);
	return -ENOMEM;
}

static int irq_expand_nr_irqs(unsigned int nr)
{
	if (nr > IRQ_BITMAP_BITS)
		return -ENOMEM;
	nr_irqs = nr;
	return 0;
}

// ARM10C 20141004
int __init early_irq_init(void)
{
	// first_online_node: 0
	int i, initcnt, node = first_online_node;
	// node: 0
	struct irq_desc *desc;

	init_irq_default_affinity();
	// init_irq_default_affinity에서 한일:
	// irq_default_affinity->bits[0]: 0xF

	/* Let arch update nr_irqs and return the nr of preallocated irqs */
	// arch_probe_nr_irqs(): 16
	initcnt = arch_probe_nr_irqs();
	// initcnt: 16

	// NR_IRQS: 16, nr_irqs: 16, initcnt: 16
	printk(KERN_INFO "NR_IRQS:%d nr_irqs:%d %d\n", NR_IRQS, nr_irqs, initcnt);
	// "NR_IRQS:16 nr_irqs:16 16"

	// nr_irqs: 16, IRQ_BITMAP_BITS: 8212
	if (WARN_ON(nr_irqs > IRQ_BITMAP_BITS))
		nr_irqs = IRQ_BITMAP_BITS;

	// initcnt: 16, IRQ_BITMAP_BITS: 8212
	if (WARN_ON(initcnt > IRQ_BITMAP_BITS))
		initcnt = IRQ_BITMAP_BITS;

	// initcnt: 16, nr_irqs: 16
	if (initcnt > nr_irqs)
		nr_irqs = initcnt;

	// initcnt: 16
	for (i = 0; i < initcnt; i++) {
		// i: 0, node: 0
		// alloc_desc(0, 0, NULL): kmem_cache#28-o0
		desc = alloc_desc(i, node, NULL);
		// desc: kmem_cache#28-o0

		// alloc_desc(0)에서 한일:
		// (kmem_cache#28-o0)->kstat_irqs: pcp 4 byte 공간
		// (kmem_cache#28-o0)->lock 을 이용한 spinlock 초기화 수행
		// (kmem_cache#28-o0)->irq_data.irq: 0
		// (kmem_cache#28-o0)->irq_data.chip: &no_irq_chip
		// (kmem_cache#28-o0)->irq_data.chip_data: NULL
		// (kmem_cache#28-o0)->irq_data.handler_data: NULL
		// (kmem_cache#28-o0)->irq_data.msi_desc: NULL
		// (kmem_cache#28-o0)->status_use_accessors: 0xc00
		// (&(kmem_cache#28-o0)->irq_data)->state_use_accessors: 0x10000
		// (kmem_cache#28-o0)->handle_irq: handle_bad_irq
		// (kmem_cache#28-o0)->depth: 1
		// (kmem_cache#28-o0)->irq_count: 0
		// (kmem_cache#28-o0)->irqs_unhandled: 0
		// (kmem_cache#28-o0)->name: NULL
		// (kmem_cache#28-o0)->owner: null
		// [pcp0...3] (kmem_cache#28-o0)->kstat_irqs: 0
		// (kmem_cache#28-o0)->irq_data.node: 0
		// (kmem_cache#28-o0)->irq_data.affinity.bits[0]: 0xF

		// i: 0
		set_bit(i, allocated_irqs);
		// allocated_irqs[0]: 0x1

		// i: 0, desc: kmem_cache#28-o0
		irq_insert_desc(i, desc);
		// radix tree에 kmem_cache#28-o0를 노드로 추가

		// i: 1 ... 15 수행
	}

	// arch_early_irq_init(): 0
	return arch_early_irq_init();
	// return 0
}

#else /* !CONFIG_SPARSE_IRQ */

struct irq_desc irq_desc[NR_IRQS] __cacheline_aligned_in_smp = {
	[0 ... NR_IRQS-1] = {
		.handle_irq	= handle_bad_irq,
		.depth		= 1,
		.lock		= __RAW_SPIN_LOCK_UNLOCKED(irq_desc->lock),
	}
};

int __init early_irq_init(void)
{
	int count, i, node = first_online_node;
	struct irq_desc *desc;

	init_irq_default_affinity();

	printk(KERN_INFO "NR_IRQS:%d\n", NR_IRQS);

	desc = irq_desc;
	count = ARRAY_SIZE(irq_desc);

	for (i = 0; i < count; i++) {
		desc[i].kstat_irqs = alloc_percpu(unsigned int);
		alloc_masks(&desc[i], GFP_KERNEL, node);
		raw_spin_lock_init(&desc[i].lock);
		lockdep_set_class(&desc[i].lock, &irq_desc_lock_class);
		desc_set_defaults(i, &desc[i], node, NULL);
	}
	return arch_early_irq_init();
}

struct irq_desc *irq_to_desc(unsigned int irq)
{
	return (irq < NR_IRQS) ? irq_desc + irq : NULL;
}
EXPORT_SYMBOL(irq_to_desc);

static void free_desc(unsigned int irq)
{
	dynamic_irq_cleanup(irq);
}

static inline int alloc_descs(unsigned int start, unsigned int cnt, int node,
			      struct module *owner)
{
	u32 i;

	for (i = 0; i < cnt; i++) {
		struct irq_desc *desc = irq_to_desc(start + i);

		desc->owner = owner;
	}
	return start;
}

static int irq_expand_nr_irqs(unsigned int nr)
{
	return -ENOMEM;
}

#endif /* !CONFIG_SPARSE_IRQ */

/**
 * generic_handle_irq - Invoke the handler for a particular irq
 * @irq:	The irq number to handle
 *
 */
int generic_handle_irq(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc)
		return -EINVAL;
	generic_handle_irq_desc(irq, desc);
	return 0;
}
EXPORT_SYMBOL_GPL(generic_handle_irq);

/* Dynamic interrupt handling */

/**
 * irq_free_descs - free irq descriptors
 * @from:	Start of descriptor range
 * @cnt:	Number of consecutive irqs to free
 */
void irq_free_descs(unsigned int from, unsigned int cnt)
{
	int i;

	if (from >= nr_irqs || (from + cnt) > nr_irqs)
		return;

	for (i = 0; i < cnt; i++)
		free_desc(from + i);

	mutex_lock(&sparse_irq_lock);
	bitmap_clear(allocated_irqs, from, cnt);
	mutex_unlock(&sparse_irq_lock);
}
EXPORT_SYMBOL_GPL(irq_free_descs);

/**
 * irq_alloc_descs - allocate and initialize a range of irq descriptors
 * @irq:	Allocate for specific irq number if irq >= 0
 * @from:	Start the search from this irq number
 * @cnt:	Number of consecutive irqs to allocate.
 * @node:	Preferred node on which the irq descriptor should be allocated
 * @owner:	Owning module (can be NULL)
 *
 * Returns the first irq number or error code
 */
int __ref
__irq_alloc_descs(int irq, unsigned int from, unsigned int cnt, int node,
		  struct module *owner)
{
	int start, ret;

	if (!cnt)
		return -EINVAL;

	if (irq >= 0) {
		if (from > irq)
			return -EINVAL;
		from = irq;
	}

	mutex_lock(&sparse_irq_lock);

	start = bitmap_find_next_zero_area(allocated_irqs, IRQ_BITMAP_BITS,
					   from, cnt, 0);
	ret = -EEXIST;
	if (irq >=0 && start != irq)
		goto err;

	if (start + cnt > nr_irqs) {
		ret = irq_expand_nr_irqs(start + cnt);
		if (ret)
			goto err;
	}

	bitmap_set(allocated_irqs, start, cnt);
	mutex_unlock(&sparse_irq_lock);
	return alloc_descs(start, cnt, node, owner);

err:
	mutex_unlock(&sparse_irq_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(__irq_alloc_descs);

/**
 * irq_reserve_irqs - mark irqs allocated
 * @from:	mark from irq number
 * @cnt:	number of irqs to mark
 *
 * Returns 0 on success or an appropriate error code
 */
int irq_reserve_irqs(unsigned int from, unsigned int cnt)
{
	unsigned int start;
	int ret = 0;

	if (!cnt || (from + cnt) > nr_irqs)
		return -EINVAL;

	mutex_lock(&sparse_irq_lock);
	start = bitmap_find_next_zero_area(allocated_irqs, nr_irqs, from, cnt, 0);
	if (start == from)
		bitmap_set(allocated_irqs, start, cnt);
	else
		ret = -EEXIST;
	mutex_unlock(&sparse_irq_lock);
	return ret;
}

/**
 * irq_get_next_irq - get next allocated irq number
 * @offset:	where to start the search
 *
 * Returns next irq number after offset or nr_irqs if none is found.
 */
unsigned int irq_get_next_irq(unsigned int offset)
{
	return find_next_bit(allocated_irqs, nr_irqs, offset);
}

struct irq_desc *
__irq_get_desc_lock(unsigned int irq, unsigned long *flags, bool bus,
		    unsigned int check)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (desc) {
		if (check & _IRQ_DESC_CHECK) {
			if ((check & _IRQ_DESC_PERCPU) &&
			    !irq_settings_is_per_cpu_devid(desc))
				return NULL;

			if (!(check & _IRQ_DESC_PERCPU) &&
			    irq_settings_is_per_cpu_devid(desc))
				return NULL;
		}

		if (bus)
			chip_bus_lock(desc);
		raw_spin_lock_irqsave(&desc->lock, *flags);
	}
	return desc;
}

void __irq_put_desc_unlock(struct irq_desc *desc, unsigned long flags, bool bus)
{
	raw_spin_unlock_irqrestore(&desc->lock, flags);
	if (bus)
		chip_bus_sync_unlock(desc);
}

int irq_set_percpu_devid(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc)
		return -EINVAL;

	if (desc->percpu_enabled)
		return -EINVAL;

	desc->percpu_enabled = kzalloc(sizeof(*desc->percpu_enabled), GFP_KERNEL);

	if (!desc->percpu_enabled)
		return -ENOMEM;

	irq_set_percpu_devid_flags(irq);
	return 0;
}

/**
 * dynamic_irq_cleanup - cleanup a dynamically allocated irq
 * @irq:	irq number to initialize
 */
void dynamic_irq_cleanup(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);
	unsigned long flags;

	raw_spin_lock_irqsave(&desc->lock, flags);
	desc_set_defaults(irq, desc, desc_node(desc), NULL);
	raw_spin_unlock_irqrestore(&desc->lock, flags);
}

unsigned int kstat_irqs_cpu(unsigned int irq, int cpu)
{
	struct irq_desc *desc = irq_to_desc(irq);

	return desc && desc->kstat_irqs ?
			*per_cpu_ptr(desc->kstat_irqs, cpu) : 0;
}

unsigned int kstat_irqs(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);
	int cpu;
	int sum = 0;

	if (!desc || !desc->kstat_irqs)
		return 0;
	for_each_possible_cpu(cpu)
		sum += *per_cpu_ptr(desc->kstat_irqs, cpu);
	return sum;
}
