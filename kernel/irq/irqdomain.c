#define pr_fmt(fmt)  "irq: " fmt

#include <linux/debugfs.h>
#include <linux/hardirq.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/topology.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/fs.h>

// ARM10C 20141122
static LIST_HEAD(irq_domain_list);
// ARM10C 20141122
static DEFINE_MUTEX(irq_domain_mutex);

static DEFINE_MUTEX(revmap_trees_mutex);
static struct irq_domain *irq_default_domain;

/**
 * __irq_domain_add() - Allocate a new irq_domain data structure
 * @of_node: optional device-tree node of the interrupt controller
 * @size: Size of linear map; 0 for radix mapping only
 * @direct_max: Maximum value of direct maps; Use ~0 for no limit; 0 for no
 *              direct mapping
 * @ops: map/unmap domain callbacks
 * @host_data: Controller private data pointer
 *
 * Allocates and initialize and irq_domain structure.  Caller is expected to
 * register allocated irq_domain with irq_domain_register().  Returns pointer
 * to IRQ domain, or NULL on failure.
 */
// ARM10C 20141122
// of_node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
// 160, 160, 0, ops: &gic_irq_domain_ops, host_data: &gic_data[0]
// ARM10C 20141206
// of_node: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소,
// size: 256, size: 256, 0, ops: &combiner_irq_domain_ops, host_data: kmem_cache#26-oX
struct irq_domain *__irq_domain_add(struct device_node *of_node, int size,
				    irq_hw_number_t hwirq_max, int direct_max,
				    const struct irq_domain_ops *ops,
				    void *host_data)
{
	struct irq_domain *domain;

	// sizeof(struct irq_domain): 52, sizeof(unsigned int): 4, size: 160, GFP_KERNEL: 0xD0
	// of_node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_node_to_nid(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소): 0
	// kzalloc_node(692, GFP_KERNEL: 0xD0, 0): kmem_cache#25-o0
	// sizeof(struct irq_domain): 52, sizeof(unsigned int): 4, size: 256, GFP_KERNEL: 0xD0
	// of_node: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	// of_node_to_nid(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소): 0
	// kzalloc_node(1076, GFP_KERNEL: 0xD0, 0): kmem_cache#24-o0
	domain = kzalloc_node(sizeof(*domain) + (sizeof(unsigned int) * size),
			      GFP_KERNEL, of_node_to_nid(of_node));
	// domain: kmem_cache#25-o0
	// domain: kmem_cache#24-o0

	// domain: kmem_cache#25-o0
	// domain: kmem_cache#24-o0
	if (WARN_ON(!domain))
		return NULL;

	/* Fill structure */
	// &domain->revmap_tree: &(kmem_cache#25-o0)->revmap_tree, GFP_KERNEL: 0xD0
	// &domain->revmap_tree: &(kmem_cache#24-o0)->revmap_tree, GFP_KERNEL: 0xD0
	INIT_RADIX_TREE(&domain->revmap_tree, GFP_KERNEL);
	// INIT_RADIX_TREE(&(kmem_cache#25-o0)->revmap_tree, GFP_KERNEL: 0xD0):
	// do {
	// 	(&(kmem_cache#25-o0)->revmap_tree)->height = 0;
	// 	(&(kmem_cache#25-o0)->revmap_tree)->gfp_mask = (GFP_KERNEL: 0xD0);
	// 	(&(kmem_cache#25-o0)->revmap_tree)->rnode = NULL;
	// } while (0)
	// INIT_RADIX_TREE(&(kmem_cache#24-o0)->revmap_tree, GFP_KERNEL: 0xD0):
	// do {
	// 	(&(kmem_cache#24-o0)->revmap_tree)->height = 0;
	// 	(&(kmem_cache#24-o0)->revmap_tree)->gfp_mask = (GFP_KERNEL: 0xD0);
	// 	(&(kmem_cache#24-o0)->revmap_tree)->rnode = NULL;
	// } while (0)

	// domain->ops: (kmem_cache#25-o0)->ops, ops: &gic_irq_domain_ops
	// domain->ops: (kmem_cache#24-o0)->ops, ops: &combiner_irq_domain_ops
	domain->ops = ops;
	// domain->ops: (kmem_cache#25-o0)->ops: &gic_irq_domain_ops
	// domain->ops: (kmem_cache#24-o0)->ops: &combiner_irq_domain_ops

	// domain->host_data: (kmem_cache#25-o0)->host_data, host_data: &gic_data[0]
	// domain->host_data: (kmem_cache#24-o0)->host_data, host_data: kmem_cache#26-oX (combiner_data)
	domain->host_data = host_data;
	// domain->host_data: (kmem_cache#25-o0)->host_data: &gic_data[0]
	// domain->host_data: (kmem_cache#24-o0)->host_data: kmem_cache#26-oX (combiner_data)

	// domain->of_node: (kmem_cache#25-o0)->of_node,
	// of_node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_node_get(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소):
	// devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// domain->of_node: (kmem_cache#24-o0)->of_node,
	// of_node: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	// of_node_get(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소):
	// devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	domain->of_node = of_node_get(of_node);
	// domain->of_node: (kmem_cache#25-o0)->of_node:
	// devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// domain->of_node: (kmem_cache#24-o0)->of_node:
	// devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소

	// domain->hwirq_max: (kmem_cache#25-o0)->hwirq_max, hwirq_max: 160
	// domain->hwirq_max: (kmem_cache#24-o0)->hwirq_max, hwirq_max: 256
	domain->hwirq_max = hwirq_max;
	// domain->hwirq_max: (kmem_cache#25-o0)->hwirq_max: 160
	// domain->hwirq_max: (kmem_cache#24-o0)->hwirq_max: 256

	// domain->revmap_size: (kmem_cache#25-o0)->revmap_size, size: 160
	// domain->revmap_size: (kmem_cache#24-o0)->revmap_size, size: 256
	domain->revmap_size = size;
	// domain->revmap_size: (kmem_cache#25-o0)->revmap_size: 160
	// domain->revmap_size: (kmem_cache#24-o0)->revmap_size: 256

	// domain->revmap_direct_max_irq: (kmem_cache#25-o0)->revmap_direct_max_irq, direct_max: 0
	// domain->revmap_direct_max_irq: (kmem_cache#24-o0)->revmap_direct_max_irq, direct_max: 0
	domain->revmap_direct_max_irq = direct_max;
	// domain->revmap_direct_max_irq: (kmem_cache#25-o0)->revmap_direct_max_irq: 0
	// domain->revmap_direct_max_irq: (kmem_cache#24-o0)->revmap_direct_max_irq: 0

	mutex_lock(&irq_domain_mutex);
	// irq_domain_mutex을 사용한 mutex lock 설정
	// irq_domain_mutex을 사용한 mutex lock 설정

	// domain->link: (kmem_cache#25-o0)->link
	// domain->link: (kmem_cache#24-o0)->link
	list_add(&domain->link, &irq_domain_list);
	// irq_domain_list에 (kmem_cache#25-o0)->link를 추가
	// irq_domain_list에 (kmem_cache#24-o0)->link를 추가

	mutex_unlock(&irq_domain_mutex);
	// irq_domain_mutex을 사용한 mutex lock 해재
	// irq_domain_mutex을 사용한 mutex lock 해재

	// domain->name: (kmem_cache#25-o0)->name: NULL
	// domain->name: (kmem_cache#24-o0)->name: NULL
	pr_debug("Added domain %s\n", domain->name);

	// domain: kmem_cache#25-o0
	// domain: kmem_cache#24-o0
	return domain;
	// return kmem_cache#25-o0
	// return kmem_cache#24-o0
}
EXPORT_SYMBOL_GPL(__irq_domain_add);

/**
 * irq_domain_remove() - Remove an irq domain.
 * @domain: domain to remove
 *
 * This routine is used to remove an irq domain. The caller must ensure
 * that all mappings within the domain have been disposed of prior to
 * use, depending on the revmap type.
 */
void irq_domain_remove(struct irq_domain *domain)
{
	mutex_lock(&irq_domain_mutex);

	/*
	 * radix_tree_delete() takes care of destroying the root
	 * node when all entries are removed. Shout if there are
	 * any mappings left.
	 */
	WARN_ON(domain->revmap_tree.height);

	list_del(&domain->link);

	/*
	 * If the going away domain is the default one, reset it.
	 */
	if (unlikely(irq_default_domain == domain))
		irq_set_default_host(NULL);

	mutex_unlock(&irq_domain_mutex);

	pr_debug("Removed domain %s\n", domain->name);

	of_node_put(domain->of_node);
	kfree(domain);
}
EXPORT_SYMBOL_GPL(irq_domain_remove);

/**
 * irq_domain_add_simple() - Register an irq_domain and optionally map a range of irqs
 * @of_node: pointer to interrupt controller's device tree node.
 * @size: total number of irqs in mapping
 * @first_irq: first number of irq block assigned to the domain,
 *	pass zero to assign irqs on-the-fly. If first_irq is non-zero, then
 *	pre-map all of the irqs in the domain to virqs starting at first_irq.
 * @ops: map/unmap domain callbacks
 * @host_data: Controller private data pointer
 *
 * Allocates an irq_domain, and optionally if first_irq is positive then also
 * allocate irq_descs and map all of the hwirqs to virqs starting at first_irq.
 *
 * This is intended to implement the expected behaviour for most
 * interrupt controllers. If device tree is used, then first_irq will be 0 and
 * irqs get mapped dynamically on the fly. However, if the controller requires
 * static virq assignments (non-DT boot) then it will set that up correctly.
 */
// ARM10C 20141206
// np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소,
// nr_irq: 256, irq_base: 160, &combiner_irq_domain_ops, combiner_data: kmem_cache#26-oX
struct irq_domain *irq_domain_add_simple(struct device_node *of_node,
					 unsigned int size,
					 unsigned int first_irq,
					 const struct irq_domain_ops *ops,
					 void *host_data)
{
	struct irq_domain *domain;

	// of_node: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소,
	// size: 256, ops: &combiner_irq_domain_ops, host_data: kmem_cache#26-oX
	// __irq_domain_add(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소,
	// 256, 256, 0, &combiner_irq_domain_ops, kmem_cache#26-oX (combiner_data)): kmem_cache#24-o0
	domain = __irq_domain_add(of_node, size, size, 0, ops, host_data);
	// domain: kmem_cache#24-o0

	// __irq_domain_add에서 한일:
	// struct irq_domain를 위한 메모리 할당: kmem_cache#24-o0
	// (&(kmem_cache#24-o0)->revmap_tree)->height: 0
	// (&(kmem_cache#24-o0)->revmap_tree)->gfp_mask: (GFP_KERNEL: 0xD0)
	// (&(kmem_cache#24-o0)->revmap_tree)->rnode: NULL
	// (kmem_cache#24-o0)->ops: &combiner_irq_domain_ops
	// (kmem_cache#24-o0)->host_data: kmem_cache#26-oX (combiner_data)
	// (kmem_cache#24-o0)->of_node: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	// (kmem_cache#24-o0)->hwirq_max: 256
	// (kmem_cache#24-o0)->revmap_size: 256
	// (kmem_cache#24-o0)->revmap_direct_max_irq: 0
	//
	// irq_domain_list에 (kmem_cache#24-o0)->link를 추가

// 2014/12/06 종료
// 2014/12/13 시작

	// domain: kmem_cache#24-o0
	if (!domain)
		return NULL;

	// first_irq: 160
	if (first_irq > 0) {
		// CONFIG_SPARSE_IRQ=y, IS_ENABLED(CONFIG_SPARSE_IRQ): 1
		if (IS_ENABLED(CONFIG_SPARSE_IRQ)) {
			/* attempt to allocated irq_descs */
			// first_irq: 160, size: 256a, of_node: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
			// of_node_to_nid(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소): 0
			int rc = irq_alloc_descs(first_irq, first_irq, size,
						 of_node_to_nid(of_node));
			// rc: 160

			/*
			// irq_alloc_descs에서 한일:
			// struct irq_desc의 자료 구조크기 만큼 160개의 메모리를 할당 받아
			// radix tree 구조로 구성
			//
			//   (&irq_desc_tree)->rnode -->  +-----------------------+
			//                                |    radix_tree_node    |
			//                                |   (kmem_cache#20-o1)  |
			//                                +-----------------------+
			//                                | height: 2 | count: 7  |
			//                                +-----------------------+
			//                                | radix_tree_node 0 ~ 6 | \
			//                              / +-----------------------+ \ \
			//                            /  /           |  |          \  \ \ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
			//    slot: 0               /   | slot: 1    |  |           |   \              slot: 2    |
			//    +-----------------------+ | +-----------------------+ | +-----------------------+   |
			//    |    radix_tree_node    | | |    radix_tree_node    | | |    radix_tree_node    |   |
			//    |   (kmem_cache#20-o0)  | | |   (kmem_cache#20-o2)  | | |   (kmem_cache#20-o3)  |   |
			//    +-----------------------+ | +-----------------------+ | +-----------------------+   |
			//    | height: 1 | count: 64 | | | height: 1 | count: 64 | | | height: 1 | count: 64 |   |
			//    +-----------------------+ | +-----------------------+ | +-----------------------+   |
			//    |    irq  0 ~ 63        | | |    irq 64 ~ 127       | | |    irq 128 ~ 191      |   |
			//    +-----------------------+ | +-----------------------+ | +-----------------------+   |
			//                             /                |            \                            |
			//    slot: 3                /    slot: 4       |              \                slot: 5    \                slot: 6
			//    +-----------------------+   +-----------------------+   +-----------------------+   +-----------------------+
			//    |    radix_tree_node    |   |    radix_tree_node    |   |    radix_tree_node    |   |    radix_tree_node    |
			//    |   (kmem_cache#20-o4)  |   |   (kmem_cache#20-o5)  |   |   (kmem_cache#20-o6)  |   |   (kmem_cache#20-o7)  |
			//    +-----------------------+   +-----------------------+   +-----------------------+   +-----------------------+
			//    | height: 1 | count: 64 |   | height: 1 | count: 64 |   | height: 1 | count: 64 |   | height: 1 | count: 32 |
			//    +-----------------------+   +-----------------------+   +-----------------------+   +-----------------------+
			//    |    irq  192 ~ 255     |   |    irq 256 ~ 319      |   |    irq 320 ~ 383      |   |    irq 384 ~ 415      |
			//    +-----------------------+   +-----------------------+   +-----------------------+   +-----------------------+
			*/

			// rc: 160
			if (rc < 0)
				pr_info("Cannot allocate irq_descs @ IRQ%d, assuming pre-allocated\n",
					first_irq);
		}

		// domain: kmem_cache#24-o0, first_irq: 160, 256
		// irq_domain_associate_many(kmem_cache#24-o0, 160, 0, 256):
		irq_domain_associate_many(domain, first_irq, 0, size);

		// irq_domain_associate_many 에서 한일:
		// irq 160...415까지의 struct irq_data에 값을 설정
		//
		// (&(kmem_cache#28-oX (irq 160...415))->irq_data)->hwirq: 0...255
		// (&(kmem_cache#28-oX (irq 160...415))->irq_data)->domain: kmem_cache#24-o0
		//
		// combiner_irq_domain_map에서 한일:
		// (kmem_cache#28-oX (irq 160...415))->irq_data.chip: &combiner_chip
		// (kmem_cache#28-oX (irq 160...415))->handle_irq: handle_level_irq
		// (kmem_cache#28-oX (irq 160...415))->name: NULL
		//
		// (kmem_cache#28-oX (irq 160...167))->irq_data.chip_data: &(kmem_cache#26-oX)[0] (combiner_data)
		// (kmem_cache#28-oX (irq 168...175))->irq_data.chip_data: &(kmem_cache#26-oX)[1] (combiner_data)
		// ......
		// (kmem_cache#28-oX (irq 408...415))->irq_data.chip_data: &(kmem_cache#26-oX)[31] (combiner_data)
		//
		// (kmem_cache#28-oX (irq 160...415))->status_use_accessors: 0x31600
		//
		// (kmem_cache#24-o0)->name: "COMBINER"
		// (kmem_cache#24-o0)->linear_revmap[0...255]: 160...415
	}

	// domain: kmem_cache#24-o0
	return domain;
	// return kmem_cache#24-o0
}
EXPORT_SYMBOL_GPL(irq_domain_add_simple);

/**
 * irq_domain_add_legacy() - Allocate and register a legacy revmap irq_domain.
 * @of_node: pointer to interrupt controller's device tree node.
 * @size: total number of irqs in legacy mapping
 * @first_irq: first number of irq block assigned to the domain
 * @first_hwirq: first hwirq number to use for the translation. Should normally
 *               be '0', but a positive integer can be used if the effective
 *               hwirqs numbering does not begin at zero.
 * @ops: map/unmap domain callbacks
 * @host_data: Controller private data pointer
 *
 * Note: the map() callback will be called before this function returns
 * for all legacy interrupts except 0 (which is always the invalid irq for
 * a legacy controller).
 */
// ARM10C 20141122
// node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
// gic_irqs: 144, irq_base: 16, hwirq_base: 16, &gic_irq_domain_ops, gic: &gic_data[0]
struct irq_domain *irq_domain_add_legacy(struct device_node *of_node,
					 unsigned int size,
					 unsigned int first_irq,
					 irq_hw_number_t first_hwirq,
					 const struct irq_domain_ops *ops,
					 void *host_data)
{
	struct irq_domain *domain;

	// of_node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// first_hwirq: 16, size: 144, ops: &gic_irq_domain_ops, host_data: &gic_data[0]
	// __irq_domain_add(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, 160, 160, 0,
	// &gic_irq_domain_ops, &gic_data[0]): kmem_cache#25-o0
	domain = __irq_domain_add(of_node, first_hwirq + size,
				  first_hwirq + size, 0, ops, host_data);
	// domain: kmem_cache#25-o0

	// __irq_domain_add에서 한일:
	// (&(kmem_cache#25-o0)->revmap_tree)->height: 0
	// (&(kmem_cache#25-o0)->revmap_tree)->gfp_mask: GFP_KERNEL: 0xD0
	// (&(kmem_cache#25-o0)->revmap_tree)->rnode: NULL
	// (kmem_cache#25-o0)->ops: &gic_irq_domain_ops
	// (kmem_cache#25-o0)->host_data: &gic_data[0]
	// (kmem_cache#25-o0)->of_node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// (kmem_cache#25-o0)->hwirq_max: 160
	// (kmem_cache#25-o0)->revmap_size: 160
	// (kmem_cache#25-o0)->revmap_direct_max_irq: 0
	//
	// irq_domain_list에 (kmem_cache#25-o0)->link를 추가

	// domain: kmem_cache#25-o0
	if (!domain)
		return NULL;

	// domain: kmem_cache#25-o0, first_irq: 16, first_hwirq: 16, size: 144
	irq_domain_associate_many(domain, first_irq, first_hwirq, size);

	// irq_domain_associate_many에서 한일:
	// irq 16...159까지의 struct irq_data에 값을 설정
	//
	// (&(kmem_cache#28-oX (irq 16...159))->irq_data)->hwirq: 16...159
	// (&(kmem_cache#28-oX (irq 16...159))->irq_data)->domain: kmem_cache#25-o0
	// (&(kmem_cache#28-oX (irq 16...159))->irq_data)->state_use_accessors: 0x10800
	//
	// (kmem_cache#28-oX (irq 16...159))->percpu_enabled: kmem_cache#30-oX
	// (kmem_cache#28-oX (irq 16...159))->status_use_accessors: 0x31600
	// (kmem_cache#28-oX (irq 16...159))->irq_data.chip: &gic_chip
	// (kmem_cache#28-oX (irq 16...159))->handle_irq: handle_percpu_devid_irq
	// (kmem_cache#28-oX (irq 16...159))->name: NULL
	// (kmem_cache#28-oX (irq 16...159))->irq_data.chip_data: &gic_data[0]
	// (kmem_cache#28-oX (irq 16...159))->status_use_accessors: 0x31600
	//
	// (kmem_cache#25-o0)->name: "GIC"
	// (kmem_cache#25-o0)->linear_revmap[16...159]: 16...159

	// domain: kmem_cache#25-o0
	return domain;
	// return kmem_cache#25-o0
}
EXPORT_SYMBOL_GPL(irq_domain_add_legacy);

/**
 * irq_find_host() - Locates a domain for a given device node
 * @node: device-tree node of the interrupt controller
 */
struct irq_domain *irq_find_host(struct device_node *node)
{
	struct irq_domain *h, *found = NULL;
	int rc;

	/* We might want to match the legacy controller last since
	 * it might potentially be set to match all interrupts in
	 * the absence of a device node. This isn't a problem so far
	 * yet though...
	 */
	mutex_lock(&irq_domain_mutex);
	list_for_each_entry(h, &irq_domain_list, link) {
		if (h->ops->match)
			rc = h->ops->match(h, node);
		else
			rc = (h->of_node != NULL) && (h->of_node == node);

		if (rc) {
			found = h;
			break;
		}
	}
	mutex_unlock(&irq_domain_mutex);
	return found;
}
EXPORT_SYMBOL_GPL(irq_find_host);

/**
 * irq_set_default_host() - Set a "default" irq domain
 * @domain: default domain pointer
 *
 * For convenience, it's possible to set a "default" domain that will be used
 * whenever NULL is passed to irq_create_mapping(). It makes life easier for
 * platforms that want to manipulate a few hard coded interrupt numbers that
 * aren't properly represented in the device-tree.
 */
void irq_set_default_host(struct irq_domain *domain)
{
	pr_debug("Default domain set to @0x%p\n", domain);

	irq_default_domain = domain;
}
EXPORT_SYMBOL_GPL(irq_set_default_host);

static void irq_domain_disassociate(struct irq_domain *domain, unsigned int irq)
{
	struct irq_data *irq_data = irq_get_irq_data(irq);
	irq_hw_number_t hwirq;

	if (WARN(!irq_data || irq_data->domain != domain,
		 "virq%i doesn't exist; cannot disassociate\n", irq))
		return;

	hwirq = irq_data->hwirq;
	irq_set_status_flags(irq, IRQ_NOREQUEST);

	/* remove chip and handler */
	irq_set_chip_and_handler(irq, NULL, NULL);

	/* Make sure it's completed */
	synchronize_irq(irq);

	/* Tell the PIC about it */
	if (domain->ops->unmap)
		domain->ops->unmap(domain, irq);
	smp_mb();

	irq_data->domain = NULL;
	irq_data->hwirq = 0;

	/* Clear reverse map for this hwirq */
	if (hwirq < domain->revmap_size) {
		domain->linear_revmap[hwirq] = 0;
	} else {
		mutex_lock(&revmap_trees_mutex);
		radix_tree_delete(&domain->revmap_tree, hwirq);
		mutex_unlock(&revmap_trees_mutex);
	}
}

// ARM10C 20141122
// domain: kmem_cache#25-o0, irq_base: 16, hwirq_base: 16
// ARM10C 20141213
// domain: kmem_cache#24-o0, irq_base: 160, hwirq_base: 0
int irq_domain_associate(struct irq_domain *domain, unsigned int virq,
			 irq_hw_number_t hwirq)
{
	// virq: 16, irq_get_irq_data(16): &(kmem_cache#28-oX (irq 16))->irq_data
	// virq: 160, irq_get_irq_data(160): &(kmem_cache#28-oX (irq 160))->irq_data
	struct irq_data *irq_data = irq_get_irq_data(virq);
	// irq_data: &(kmem_cache#28-oX (irq 16))->irq_data
	// irq_data: &(kmem_cache#28-oX (irq 160))->irq_data

	int ret;

	// hwirq: 16, domain->hwirq_max: (kmem_cache#25-o0)->hwirq_max: 160
	// hwirq: 0, domain->hwirq_max: (kmem_cache#24-o0)->hwirq_max: 256
	if (WARN(hwirq >= domain->hwirq_max,
		 "error: hwirq 0x%x is too large for %s\n", (int)hwirq, domain->name))
		return -EINVAL;

	// irq_data: &(kmem_cache#28-oX (irq 16))->irq_data, virq: 16
	// irq_data: &(kmem_cache#28-oX (irq 160))->irq_data, virq: 160
	if (WARN(!irq_data, "error: virq%i is not allocated", virq))
		return -EINVAL;

	// irq_data->domain: (&(kmem_cache#28-oX (irq 16))->irq_data)->domain: NULL
	// irq_data->domain: (&(kmem_cache#28-oX (irq 160))->irq_data)->domain: NULL
	if (WARN(irq_data->domain, "error: virq%i is already associated", virq))
		return -EINVAL;

	mutex_lock(&irq_domain_mutex);
	// irq_domain_mutex을 사용한 mutex lock 설정
	// irq_domain_mutex을 사용한 mutex lock 설정

	// irq_data->hwirq: (&(kmem_cache#28-oX (irq 16))->irq_data)->hwirq, hwirq: 16
	// irq_data->hwirq: (&(kmem_cache#28-oX (irq 160))->irq_data)->hwirq, hwirq: 0
	irq_data->hwirq = hwirq;
	// irq_data->hwirq: (&(kmem_cache#28-oX (irq 16))->irq_data)->hwirq: 16
	// irq_data->hwirq: (&(kmem_cache#28-oX (irq 160))->irq_data)->hwirq: 0

	// irq_data->domain: (&(kmem_cache#28-oX (irq 16))->irq_data)->domain, domain: kmem_cache#25-o0
	// irq_data->domain: (&(kmem_cache#28-oX (irq 160))->irq_data)->domain, domain: kmem_cache#24-o0
	irq_data->domain = domain;
	// irq_data->domain: (&(kmem_cache#28-oX (irq 16))->irq_data)->domain: kmem_cache#25-o0
	// irq_data->domain: (&(kmem_cache#28-oX (irq 160))->irq_data)->domain: kmem_cache#24-o0

	// domain->ops->map: (kmem_cache#25-o0)->ops->map: gic_irq_domain_map
	// domain->ops->map: (kmem_cache#24-o0)->ops->map: combiner_irq_domain_map
	if (domain->ops->map) {
		// domain->ops->map: (kmem_cache#25-o0)->ops->map: gic_irq_domain_map
		// domain: kmem_cache#25-o0, virq: 16, hwirq: 16
		// gic_irq_domain_map(kmem_cache#25-o0, 16, 16): 0
		// domain->ops->map: (kmem_cache#24-o0)->ops->map: combiner_irq_domain_map
		// domain: kmem_cache#24-o0, virq: 160, hwirq: 0
		// combiner_irq_domain_map(kmem_cache#24-o0, 160, 0): 0
		ret = domain->ops->map(domain, virq, hwirq);
		// ret: 0
		// ret: 0

		// gic_irq_domain_map에서 한일:
		// (kmem_cache#28-oX (irq 16))->percpu_enabled: kmem_cache#30-oX
		// (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600
		// (&(kmem_cache#28-oX (irq 16))->irq_data)->state_use_accessors: 0x10800
		// (kmem_cache#28-oX (irq 16))->irq_data.chip: &gic_chip
		// (kmem_cache#28-oX (irq 16))->handle_irq: handle_percpu_devid_irq
		// (kmem_cache#28-oX (irq 16))->name: NULL
		// (kmem_cache#28-oX (irq 16))->irq_data.chip_data: &gic_data[0]

		// combiner_irq_domain_map에서 한일:
		// (kmem_cache#28-oX (irq 160))->irq_data.chip: &combiner_chip
		// (kmem_cache#28-oX (irq 160))->handle_irq: handle_level_irq
		// (kmem_cache#28-oX (irq 160))->name: NULL
		// (kmem_cache#28-oX (irq 160))->irq_data.chip_data: &(kmem_cache#26-oX)[0] (combiner_data)
		// (kmem_cache#28-oX (irq 160))->status_use_accessors: 0x31600
		// (&(kmem_cache#28-oX (irq 160))->irq_data)->state_use_accessors: 0x10800

		// ret: 0
		// ret: 0
		if (ret != 0) {
			/*
			 * If map() returns -EPERM, this interrupt is protected
			 * by the firmware or some other service and shall not
			 * be mapped. Don't bother telling the user about it.
			 */
			if (ret != -EPERM) {
				pr_info("%s didn't like hwirq-0x%lx to VIRQ%i mapping (rc=%d)\n",
				       domain->name, hwirq, virq, ret);
			}
			irq_data->domain = NULL;
			irq_data->hwirq = 0;
			mutex_unlock(&irq_domain_mutex);
			return ret;
		}

		/* If not already assigned, give the domain the chip's name */
		// domain->name: (kmem_cache#25-o0)->name: NULL,
		// irq_data->chip: (&(kmem_cache#28-oX (irq 16))->irq_data)->chip: &gic_chip
		// domain->name: (kmem_cache#24-o0)->name: NULL,
		// irq_data->chip: (&(kmem_cache#28-oX (irq 160))->irq_data)->chip: &combiner_chip
		if (!domain->name && irq_data->chip)
			// domain->name: (kmem_cache#25-o0)->name: NULL,
			// irq_data->chip->name: ((&(kmem_cache#28-oX (irq 16))->irq_data)->chip)->name: "GIC"
			// domain->name: (kmem_cache#24-o0)->name: NULL,
			// irq_data->chip->name: ((&(kmem_cache#28-oX (irq 160))->irq_data)->chip)->name: "COMBINER"
			domain->name = irq_data->chip->name;
			// domain->name: (kmem_cache#25-o0)->name: "GIC"
			// domain->name: (kmem_cache#24-o0)->name: "COMBINER"
	}

	// hwirq: 16, domain->revmap_size: (kmem_cache#25-o0)->revmap_size: 160
	// hwirq: 0, domain->revmap_size: (kmem_cache#24-o0)->revmap_size: 256
	if (hwirq < domain->revmap_size) {
		// hwirq: 16, domain->linear_revmap[16]: (kmem_cache#25-o0)->linear_revmap[16], virq: 16
		// hwirq: 0, domain->linear_revmap[0]: (kmem_cache#24-o0)->linear_revmap[0], virq: 160
		domain->linear_revmap[hwirq] = virq;
		// domain->linear_revmap[16]: (kmem_cache#25-o0)->linear_revmap[16]: 16
		// domain->linear_revmap[0]: (kmem_cache#24-o0)->linear_revmap[0]: 160
	} else {
		mutex_lock(&revmap_trees_mutex);
		radix_tree_insert(&domain->revmap_tree, hwirq, irq_data);
		mutex_unlock(&revmap_trees_mutex);
	}
	mutex_unlock(&irq_domain_mutex);
	// irq_domain_mutex을 사용한 mutex lock 해재
	// irq_domain_mutex을 사용한 mutex lock 해재

	// virq: 16, IRQ_NOREQUEST: 0x800
	// virq: 160, IRQ_NOREQUEST: 0x800
	irq_clear_status_flags(virq, IRQ_NOREQUEST);
	// irq_clear_status_flags(16)에서 한일:
	// (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600

	// irq_clear_status_flags(160)에서 한일:
	// (kmem_cache#28-oX (irq 160))->status_use_accessors: 0x31600

	return 0;
	// return 0
	// return 0
}
EXPORT_SYMBOL_GPL(irq_domain_associate);

// ARM10C 20141122
// domain: kmem_cache#25-o0, first_irq: 16, first_hwirq: 16, size: 144
// ARM10C 20141213
// domain: kmem_cache#24-o0, first_irq: 160, 0, 256
void irq_domain_associate_many(struct irq_domain *domain, unsigned int irq_base,
			       irq_hw_number_t hwirq_base, int count)
{
	int i;

	// domain->of_node: (kmem_cache#25-o0)->of_node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_node_full_name(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소): "/interrupt-controller@10481000"
	// irq_base: 16, hwirq_base: 16, count: 144
	// domain->of_node: (kmem_cache#24-o0)->of_node: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	// of_node_full_name(ddevtree에서 allnext로 순회 하면서 찾은 combiner node의 주소): "interrupt-controller@10440000"
	// irq_base: 160, hwirq_base: 0, count: 256
	pr_debug("%s(%s, irqbase=%i, hwbase=%i, count=%i)\n", __func__,
		of_node_full_name(domain->of_node), irq_base, (int)hwirq_base, count);
	// "irq_domain_associate_many(/interrupt-controller@10481000, irqbase=16, hwbase=16, count=144)\n"
	// "irq_domain_associate_many(/interrupt-controller@10440000, irqbase=160, hwbase=0, count=256)\n"

	// count: 144
	// count: 256
	for (i = 0; i < count; i++) {
		// domain: kmem_cache#25-o0, irq_base: 16, i: 0, hwirq_base: 16
		// irq_domain_associate(kmem_cache#25-o0, 16, 16): 0
		// domain: kmem_cache#24-o0, irq_base: 160, i: 0, hwirq_base: 0
		// irq_domain_associate(kmem_cache#24-o0, 160, 0): 0
		irq_domain_associate(domain, irq_base + i, hwirq_base + i);

		// irq_domain_associate(16) 에서 한일:
		// (&(kmem_cache#28-oX (irq 16))->irq_data)->hwirq: 16
		// (&(kmem_cache#28-oX (irq 16))->irq_data)->domain: kmem_cache#25-o0
		// (&(kmem_cache#28-oX (irq 16))->irq_data)->state_use_accessors: 0x10800
		//
		// (kmem_cache#28-oX (irq 16))->percpu_enabled: kmem_cache#30-oX
		// (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600
		// (kmem_cache#28-oX (irq 16))->irq_data.chip: &gic_chip
		// (kmem_cache#28-oX (irq 16))->handle_irq: handle_percpu_devid_irq
		// (kmem_cache#28-oX (irq 16))->name: NULL
		// (kmem_cache#28-oX (irq 16))->irq_data.chip_data: &gic_data[0]
		// (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600
		//
		// (kmem_cache#25-o0)->name: "GIC"
		// (kmem_cache#25-o0)->linear_revmap[16]: 16

		// irq_domain_associate(160) 에서 한일:
		// (&(kmem_cache#28-oX (irq 160))->irq_data)->hwirq: 0
		// (&(kmem_cache#28-oX (irq 160))->irq_data)->domain: kmem_cache#24-o0
		//
		// combiner_irq_domain_map에서 한일:
		// (kmem_cache#28-oX (irq 160))->irq_data.chip: &combiner_chip
		// (kmem_cache#28-oX (irq 160))->handle_irq: handle_level_irq
		// (kmem_cache#28-oX (irq 160))->name: NULL
		// (kmem_cache#28-oX (irq 160))->irq_data.chip_data: &(kmem_cache#26-oX)[0] (combiner_data)
		// (kmem_cache#28-oX (irq 160))->status_use_accessors: 0x31600
		//
		// (kmem_cache#24-o0)->name: "COMBINER"
		// (kmem_cache#24-o0)->linear_revmap[0]: 160

// 2014/11/22 종료
// 2014/11/29 시작

		// i: 1...144 까지 수행, irq 17...159 까지 수행
		// i: 1...255 까지 수행, irq 160...415 까지 수행
	}
}
EXPORT_SYMBOL_GPL(irq_domain_associate_many);

/**
 * irq_create_direct_mapping() - Allocate an irq for direct mapping
 * @domain: domain to allocate the irq for or NULL for default domain
 *
 * This routine is used for irq controllers which can choose the hardware
 * interrupt numbers they generate. In such a case it's simplest to use
 * the linux irq as the hardware interrupt number. It still uses the linear
 * or radix tree to store the mapping, but the irq controller can optimize
 * the revmap path by using the hwirq directly.
 */
unsigned int irq_create_direct_mapping(struct irq_domain *domain)
{
	unsigned int virq;

	if (domain == NULL)
		domain = irq_default_domain;

	virq = irq_alloc_desc_from(1, of_node_to_nid(domain->of_node));
	if (!virq) {
		pr_debug("create_direct virq allocation failed\n");
		return 0;
	}
	if (virq >= domain->revmap_direct_max_irq) {
		pr_err("ERROR: no free irqs available below %i maximum\n",
			domain->revmap_direct_max_irq);
		irq_free_desc(virq);
		return 0;
	}
	pr_debug("create_direct obtained virq %d\n", virq);

	if (irq_domain_associate(domain, virq, virq)) {
		irq_free_desc(virq);
		return 0;
	}

	return virq;
}
EXPORT_SYMBOL_GPL(irq_create_direct_mapping);

/**
 * irq_create_mapping() - Map a hardware interrupt into linux irq space
 * @domain: domain owning this hardware interrupt or NULL for default domain
 * @hwirq: hardware irq number in that domain space
 *
 * Only one mapping per hardware interrupt is permitted. Returns a linux
 * irq number.
 * If the sense/trigger is to be specified, set_irq_type() should be called
 * on the number returned from that call.
 */
unsigned int irq_create_mapping(struct irq_domain *domain,
				irq_hw_number_t hwirq)
{
	unsigned int hint;
	int virq;

	pr_debug("irq_create_mapping(0x%p, 0x%lx)\n", domain, hwirq);

	/* Look for default domain if nececssary */
	if (domain == NULL)
		domain = irq_default_domain;
	if (domain == NULL) {
		WARN(1, "%s(, %lx) called with NULL domain\n", __func__, hwirq);
		return 0;
	}
	pr_debug("-> using domain @%p\n", domain);

	/* Check if mapping already exists */
	virq = irq_find_mapping(domain, hwirq);
	if (virq) {
		pr_debug("-> existing mapping on virq %d\n", virq);
		return virq;
	}

	/* Allocate a virtual interrupt number */
	hint = hwirq % nr_irqs;
	if (hint == 0)
		hint++;
	virq = irq_alloc_desc_from(hint, of_node_to_nid(domain->of_node));
	if (virq <= 0)
		virq = irq_alloc_desc_from(1, of_node_to_nid(domain->of_node));
	if (virq <= 0) {
		pr_debug("-> virq allocation failed\n");
		return 0;
	}

	if (irq_domain_associate(domain, virq, hwirq)) {
		irq_free_desc(virq);
		return 0;
	}

	pr_debug("irq %lu on domain %s mapped to virtual irq %u\n",
		hwirq, of_node_full_name(domain->of_node), virq);

	return virq;
}
EXPORT_SYMBOL_GPL(irq_create_mapping);

/**
 * irq_create_strict_mappings() - Map a range of hw irqs to fixed linux irqs
 * @domain: domain owning the interrupt range
 * @irq_base: beginning of linux IRQ range
 * @hwirq_base: beginning of hardware IRQ range
 * @count: Number of interrupts to map
 *
 * This routine is used for allocating and mapping a range of hardware
 * irqs to linux irqs where the linux irq numbers are at pre-defined
 * locations. For use by controllers that already have static mappings
 * to insert in to the domain.
 *
 * Non-linear users can use irq_create_identity_mapping() for IRQ-at-a-time
 * domain insertion.
 *
 * 0 is returned upon success, while any failure to establish a static
 * mapping is treated as an error.
 */
int irq_create_strict_mappings(struct irq_domain *domain, unsigned int irq_base,
			       irq_hw_number_t hwirq_base, int count)
{
	int ret;

	ret = irq_alloc_descs(irq_base, irq_base, count,
			      of_node_to_nid(domain->of_node));
	if (unlikely(ret < 0))
		return ret;

	irq_domain_associate_many(domain, irq_base, hwirq_base, count);
	return 0;
}
EXPORT_SYMBOL_GPL(irq_create_strict_mappings);

unsigned int irq_create_of_mapping(struct of_phandle_args *irq_data)
{
	struct irq_domain *domain;
	irq_hw_number_t hwirq;
	unsigned int type = IRQ_TYPE_NONE;
	unsigned int virq;

	domain = irq_data->np ? irq_find_host(irq_data->np) : irq_default_domain;
	if (!domain) {
		pr_warn("no irq domain found for %s !\n",
			of_node_full_name(irq_data->np));
		return 0;
	}

	/* If domain has no translation, then we assume interrupt line */
	if (domain->ops->xlate == NULL)
		hwirq = irq_data->args[0];
	else {
		if (domain->ops->xlate(domain, irq_data->np, irq_data->args,
					irq_data->args_count, &hwirq, &type))
			return 0;
	}

	/* Create mapping */
	virq = irq_create_mapping(domain, hwirq);
	if (!virq)
		return virq;

	/* Set type if specified and different than the current one */
	if (type != IRQ_TYPE_NONE &&
	    type != irq_get_trigger_type(virq))
		irq_set_irq_type(virq, type);
	return virq;
}
EXPORT_SYMBOL_GPL(irq_create_of_mapping);

/**
 * irq_dispose_mapping() - Unmap an interrupt
 * @virq: linux irq number of the interrupt to unmap
 */
void irq_dispose_mapping(unsigned int virq)
{
	struct irq_data *irq_data = irq_get_irq_data(virq);
	struct irq_domain *domain;

	if (!virq || !irq_data)
		return;

	domain = irq_data->domain;
	if (WARN_ON(domain == NULL))
		return;

	irq_domain_disassociate(domain, virq);
	irq_free_desc(virq);
}
EXPORT_SYMBOL_GPL(irq_dispose_mapping);

/**
 * irq_find_mapping() - Find a linux irq from an hw irq number.
 * @domain: domain owning this hardware interrupt
 * @hwirq: hardware irq number in that domain space
 */
unsigned int irq_find_mapping(struct irq_domain *domain,
			      irq_hw_number_t hwirq)
{
	struct irq_data *data;

	/* Look for default domain if nececssary */
	if (domain == NULL)
		domain = irq_default_domain;
	if (domain == NULL)
		return 0;

	if (hwirq < domain->revmap_direct_max_irq) {
		data = irq_get_irq_data(hwirq);
		if (data && (data->domain == domain) && (data->hwirq == hwirq))
			return hwirq;
	}

	/* Check if the hwirq is in the linear revmap. */
	if (hwirq < domain->revmap_size)
		return domain->linear_revmap[hwirq];

	rcu_read_lock();
	data = radix_tree_lookup(&domain->revmap_tree, hwirq);
	rcu_read_unlock();
	return data ? data->irq : 0;
}
EXPORT_SYMBOL_GPL(irq_find_mapping);

#ifdef CONFIG_IRQ_DOMAIN_DEBUG
static int virq_debug_show(struct seq_file *m, void *private)
{
	unsigned long flags;
	struct irq_desc *desc;
	struct irq_domain *domain;
	struct radix_tree_iter iter;
	void *data, **slot;
	int i;

	seq_printf(m, " %-16s  %-6s  %-10s  %-10s  %s\n",
		   "name", "mapped", "linear-max", "direct-max", "devtree-node");
	mutex_lock(&irq_domain_mutex);
	list_for_each_entry(domain, &irq_domain_list, link) {
		int count = 0;
		radix_tree_for_each_slot(slot, &domain->revmap_tree, &iter, 0)
			count++;
		seq_printf(m, "%c%-16s  %6u  %10u  %10u  %s\n",
			   domain == irq_default_domain ? '*' : ' ', domain->name,
			   domain->revmap_size + count, domain->revmap_size,
			   domain->revmap_direct_max_irq,
			   domain->of_node ? of_node_full_name(domain->of_node) : "");
	}
	mutex_unlock(&irq_domain_mutex);

	seq_printf(m, "%-5s  %-7s  %-15s  %-*s  %6s  %-14s  %s\n", "irq", "hwirq",
		      "chip name", (int)(2 * sizeof(void *) + 2), "chip data",
		      "active", "type", "domain");

	for (i = 1; i < nr_irqs; i++) {
		desc = irq_to_desc(i);
		if (!desc)
			continue;

		raw_spin_lock_irqsave(&desc->lock, flags);
		domain = desc->irq_data.domain;

		if (domain) {
			struct irq_chip *chip;
			int hwirq = desc->irq_data.hwirq;
			bool direct;

			seq_printf(m, "%5d  ", i);
			seq_printf(m, "0x%05x  ", hwirq);

			chip = irq_desc_get_chip(desc);
			seq_printf(m, "%-15s  ", (chip && chip->name) ? chip->name : "none");

			data = irq_desc_get_chip_data(desc);
			seq_printf(m, data ? "0x%p  " : "  %p  ", data);

			seq_printf(m, "   %c    ", (desc->action && desc->action->handler) ? '*' : ' ');
			direct = (i == hwirq) && (i < domain->revmap_direct_max_irq);
			seq_printf(m, "%6s%-8s  ",
				   (hwirq < domain->revmap_size) ? "LINEAR" : "RADIX",
				   direct ? "(DIRECT)" : "");
			seq_printf(m, "%s\n", desc->irq_data.domain->name);
		}

		raw_spin_unlock_irqrestore(&desc->lock, flags);
	}

	return 0;
}

static int virq_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, virq_debug_show, inode->i_private);
}

static const struct file_operations virq_debug_fops = {
	.open = virq_debug_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int __init irq_debugfs_init(void)
{
	if (debugfs_create_file("irq_domain_mapping", S_IRUGO, NULL,
				 NULL, &virq_debug_fops) == NULL)
		return -ENOMEM;

	return 0;
}
__initcall(irq_debugfs_init);
#endif /* CONFIG_IRQ_DOMAIN_DEBUG */

/**
 * irq_domain_xlate_onecell() - Generic xlate for direct one cell bindings
 *
 * Device Tree IRQ specifier translation function which works with one cell
 * bindings where the cell value maps directly to the hwirq number.
 */
int irq_domain_xlate_onecell(struct irq_domain *d, struct device_node *ctrlr,
			     const u32 *intspec, unsigned int intsize,
			     unsigned long *out_hwirq, unsigned int *out_type)
{
	if (WARN_ON(intsize < 1))
		return -EINVAL;
	*out_hwirq = intspec[0];
	*out_type = IRQ_TYPE_NONE;
	return 0;
}
EXPORT_SYMBOL_GPL(irq_domain_xlate_onecell);

/**
 * irq_domain_xlate_twocell() - Generic xlate for direct two cell bindings
 *
 * Device Tree IRQ specifier translation function which works with two cell
 * bindings where the cell values map directly to the hwirq number
 * and linux irq flags.
 */
int irq_domain_xlate_twocell(struct irq_domain *d, struct device_node *ctrlr,
			const u32 *intspec, unsigned int intsize,
			irq_hw_number_t *out_hwirq, unsigned int *out_type)
{
	if (WARN_ON(intsize < 2))
		return -EINVAL;
	*out_hwirq = intspec[0];
	*out_type = intspec[1] & IRQ_TYPE_SENSE_MASK;
	return 0;
}
EXPORT_SYMBOL_GPL(irq_domain_xlate_twocell);

/**
 * irq_domain_xlate_onetwocell() - Generic xlate for one or two cell bindings
 *
 * Device Tree IRQ specifier translation function which works with either one
 * or two cell bindings where the cell values map directly to the hwirq number
 * and linux irq flags.
 *
 * Note: don't use this function unless your interrupt controller explicitly
 * supports both one and two cell bindings.  For the majority of controllers
 * the _onecell() or _twocell() variants above should be used.
 */
int irq_domain_xlate_onetwocell(struct irq_domain *d,
				struct device_node *ctrlr,
				const u32 *intspec, unsigned int intsize,
				unsigned long *out_hwirq, unsigned int *out_type)
{
	if (WARN_ON(intsize < 1))
		return -EINVAL;
	*out_hwirq = intspec[0];
	*out_type = (intsize > 1) ? intspec[1] : IRQ_TYPE_NONE;
	return 0;
}
EXPORT_SYMBOL_GPL(irq_domain_xlate_onetwocell);

const struct irq_domain_ops irq_domain_simple_ops = {
	.xlate = irq_domain_xlate_onetwocell,
};
EXPORT_SYMBOL_GPL(irq_domain_simple_ops);
