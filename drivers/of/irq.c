/*
 *  Derived from arch/i386/kernel/irq.c
 *    Copyright (C) 1992 Linus Torvalds
 *  Adapted from arch/i386 by Gary Thomas
 *    Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *  Updated and modified by Cort Dougan <cort@fsmlabs.com>
 *    Copyright (C) 1996-2001 Cort Dougan
 *  Adapted for Power Macintosh by Paul Mackerras
 *    Copyright (C) 1996 Paul Mackerras (paulus@cs.anu.edu.au)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * This file contains the code used to make IRQ descriptions in the
 * device tree to actual irq numbers on an interrupt controller
 * driver.
 */

#include <linux/errno.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/string.h>
#include <linux/slab.h>

/**
 * irq_of_parse_and_map - Parse and map an interrupt into linux virq space
 * @dev: Device node of the device whose interrupt is to be mapped
 * @index: Index of the interrupt to map
 *
 * This function is a wrapper that chains of_irq_parse_one() and
 * irq_create_of_mapping() to make things easier to callers
 */
unsigned int irq_of_parse_and_map(struct device_node *dev, int index)
{
	struct of_phandle_args oirq;

	if (of_irq_parse_one(dev, index, &oirq))
		return 0;

	return irq_create_of_mapping(&oirq);
}
EXPORT_SYMBOL_GPL(irq_of_parse_and_map);

/**
 * of_irq_find_parent - Given a device node, find its interrupt parent node
 * @child: pointer to device node
 *
 * Returns a pointer to the interrupt parent node, or NULL if the interrupt
 * parent could not be determined.
 */
// ARM10C 20141004
// ARM10C 20141011
// np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
// np: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
struct device_node *of_irq_find_parent(struct device_node *child)
{
	struct device_node *p;
	const __be32 *parp;

	// child: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	// of_node_get(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소):
	// devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	// child: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_node_get(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소):
	// devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	if (!of_node_get(child))
		return NULL;

	do {
		// NOTE:
		// exynos.dtsi의 combiner node에는 interrupt-parent property가 없음, 상위의 root node에는 interrupt-parent property가 존재함
		// root node에 있는 interrupt-parent property를 combiner node가 상속함
		// property를 상속관련 내용은 아래 링크 참조
		// http://forum.falinux.com/zbxe/index.php?document_srl=784693&mid=lecture_tip

		// child: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
		// of_get_property(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, "interrupt-parent", NULL): gic 의 주소
		// child: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		// of_get_property(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, "interrupt-parent", NULL): gic 의 주소
		parp = of_get_property(child, "interrupt-parent", NULL);
		// parp: exynos5420 dtb상의 gic 의 주소
		// parp: exynos5420 dtb상의 gic 의 주소

		// parp: gic 의 주소
		// parp: gic 의 주소
		if (parp == NULL)
			p = of_get_parent(child);
		else {
			// of_irq_workarounds: 0, OF_IMAP_NO_PHANDLE: 0x00000002
			// of_irq_workarounds: 0, OF_IMAP_NO_PHANDLE: 0x00000002
			if (of_irq_workarounds & OF_IMAP_NO_PHANDLE)
				p = of_node_get(of_irq_dflt_pic);
			else
				// parp: exynos5420 dtb상의 gic 의 주소, of_find_node_by_phandle(exynos5420 dtb상의 gic 의 주소): gic node의 주소
				// parp: exynos5420 dtb상의 gic 의 주소, of_find_node_by_phandle(exynos5420 dtb상의 gic 의 주소): gic node의 주소
				p = of_find_node_by_phandle(be32_to_cpup(parp));
				// p: gic node의 주소
				// p: gic node의 주소
		}

		// child: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
		// child: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		of_node_put(child); // null function

		// child: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, p: gic node의 주소
		// child: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, p: gic node의 주소
		child = p;
		// child: gic node의 주소
		// child: gic node의 주소

		// p: gic node의 주소, of_get_property(gic node의 주소, "#interrupt-cells", NULL): 2
		// p: gic node의 주소, of_get_property(gic node의 주소, "#interrupt-cells", NULL): 2
	} while (p && of_get_property(p, "#interrupt-cells", NULL) == NULL);

	// p: gic node의 주소
	// p: gic node의 주소
	return p;
	// return gic node의 주소
	// return gic node의 주소
}

/**
 * of_irq_parse_raw - Low level interrupt tree parsing
 * @parent:	the device interrupt parent
 * @addr:	address specifier (start of "reg" property of the device) in be32 format
 * @out_irq:	structure of_irq updated by this function
 *
 * Returns 0 on success and a negative number on error
 *
 * This function is a low-level interrupt tree walking function. It
 * can be used to do a partial walk with synthetized reg and interrupts
 * properties, for example when resolving PCI interrupts when no device
 * node exist for the parent. It takes an interrupt specifier structure as
 * input, walks the tree looking for any interrupt-map properties, translates
 * the specifier for each map, and then returns the translated map.
 */
int of_irq_parse_raw(const __be32 *addr, struct of_phandle_args *out_irq)
{
	struct device_node *ipar, *tnode, *old = NULL, *newpar = NULL;
	__be32 initial_match_array[MAX_PHANDLE_ARGS];
	const __be32 *match_array = initial_match_array;
	const __be32 *tmp, *imap, *imask, dummy_imask[] = { [0 ... MAX_PHANDLE_ARGS] = ~0 };
	u32 intsize = 1, addrsize, newintsize = 0, newaddrsize = 0;
	int imaplen, match, i;

#ifdef DEBUG
	of_print_phandle_args("of_irq_parse_raw: ", out_irq);
#endif

	ipar = of_node_get(out_irq->np);

	/* First get the #interrupt-cells property of the current cursor
	 * that tells us how to interpret the passed-in intspec. If there
	 * is none, we are nice and just walk up the tree
	 */
	do {
		tmp = of_get_property(ipar, "#interrupt-cells", NULL);
		if (tmp != NULL) {
			intsize = be32_to_cpu(*tmp);
			break;
		}
		tnode = ipar;
		ipar = of_irq_find_parent(ipar);
		of_node_put(tnode);
	} while (ipar);
	if (ipar == NULL) {
		pr_debug(" -> no parent found !\n");
		goto fail;
	}

	pr_debug("of_irq_parse_raw: ipar=%s, size=%d\n", of_node_full_name(ipar), intsize);

	if (out_irq->args_count != intsize)
		return -EINVAL;

	/* Look for this #address-cells. We have to implement the old linux
	 * trick of looking for the parent here as some device-trees rely on it
	 */
	old = of_node_get(ipar);
	do {
		tmp = of_get_property(old, "#address-cells", NULL);
		tnode = of_get_parent(old);
		of_node_put(old);
		old = tnode;
	} while (old && tmp == NULL);
	of_node_put(old);
	old = NULL;
	addrsize = (tmp == NULL) ? 2 : be32_to_cpu(*tmp);

	pr_debug(" -> addrsize=%d\n", addrsize);

	/* Range check so that the temporary buffer doesn't overflow */
	if (WARN_ON(addrsize + intsize > MAX_PHANDLE_ARGS))
		goto fail;

	/* Precalculate the match array - this simplifies match loop */
	for (i = 0; i < addrsize; i++)
		initial_match_array[i] = addr ? addr[i] : 0;
	for (i = 0; i < intsize; i++)
		initial_match_array[addrsize + i] = cpu_to_be32(out_irq->args[i]);

	/* Now start the actual "proper" walk of the interrupt tree */
	while (ipar != NULL) {
		/* Now check if cursor is an interrupt-controller and if it is
		 * then we are done
		 */
		if (of_get_property(ipar, "interrupt-controller", NULL) !=
				NULL) {
			pr_debug(" -> got it !\n");
			return 0;
		}

		/*
		 * interrupt-map parsing does not work without a reg
		 * property when #address-cells != 0
		 */
		if (addrsize && !addr) {
			pr_debug(" -> no reg passed in when needed !\n");
			goto fail;
		}

		/* Now look for an interrupt-map */
		imap = of_get_property(ipar, "interrupt-map", &imaplen);
		/* No interrupt map, check for an interrupt parent */
		if (imap == NULL) {
			pr_debug(" -> no map, getting parent\n");
			newpar = of_irq_find_parent(ipar);
			goto skiplevel;
		}
		imaplen /= sizeof(u32);

		/* Look for a mask */
		imask = of_get_property(ipar, "interrupt-map-mask", NULL);
		if (!imask)
			imask = dummy_imask;

		/* Parse interrupt-map */
		match = 0;
		while (imaplen > (addrsize + intsize + 1) && !match) {
			/* Compare specifiers */
			match = 1;
			for (i = 0; i < (addrsize + intsize); i++, imaplen--)
				match &= !((match_array[i] ^ *imap++) & imask[i]);

			pr_debug(" -> match=%d (imaplen=%d)\n", match, imaplen);

			/* Get the interrupt parent */
			if (of_irq_workarounds & OF_IMAP_NO_PHANDLE)
				newpar = of_node_get(of_irq_dflt_pic);
			else
				newpar = of_find_node_by_phandle(be32_to_cpup(imap));
			imap++;
			--imaplen;

			/* Check if not found */
			if (newpar == NULL) {
				pr_debug(" -> imap parent not found !\n");
				goto fail;
			}

			/* Get #interrupt-cells and #address-cells of new
			 * parent
			 */
			tmp = of_get_property(newpar, "#interrupt-cells", NULL);
			if (tmp == NULL) {
				pr_debug(" -> parent lacks #interrupt-cells!\n");
				goto fail;
			}
			newintsize = be32_to_cpu(*tmp);
			tmp = of_get_property(newpar, "#address-cells", NULL);
			newaddrsize = (tmp == NULL) ? 0 : be32_to_cpu(*tmp);

			pr_debug(" -> newintsize=%d, newaddrsize=%d\n",
			    newintsize, newaddrsize);

			/* Check for malformed properties */
			if (WARN_ON(newaddrsize + newintsize > MAX_PHANDLE_ARGS))
				goto fail;
			if (imaplen < (newaddrsize + newintsize))
				goto fail;

			imap += newaddrsize + newintsize;
			imaplen -= newaddrsize + newintsize;

			pr_debug(" -> imaplen=%d\n", imaplen);
		}
		if (!match)
			goto fail;

		/*
		 * Successfully parsed an interrrupt-map translation; copy new
		 * interrupt specifier into the out_irq structure
		 */
		out_irq->np = newpar;

		match_array = imap - newaddrsize - newintsize;
		for (i = 0; i < newintsize; i++)
			out_irq->args[i] = be32_to_cpup(imap - newintsize + i);
		out_irq->args_count = intsize = newintsize;
		addrsize = newaddrsize;

	skiplevel:
		/* Iterate again with new parent */
		pr_debug(" -> new parent: %s\n", of_node_full_name(newpar));
		of_node_put(ipar);
		ipar = newpar;
		newpar = NULL;
	}
 fail:
	of_node_put(ipar);
	of_node_put(newpar);

	return -EINVAL;
}
EXPORT_SYMBOL_GPL(of_irq_parse_raw);

/**
 * of_irq_parse_one - Resolve an interrupt for a device
 * @device: the device whose interrupt is to be resolved
 * @index: index of the interrupt to resolve
 * @out_irq: structure of_irq filled by this function
 *
 * This function resolves an interrupt for a node by walking the interrupt tree,
 * finding which interrupt controller node it is attached to, and returning the
 * interrupt specifier that can be used to retrieve a Linux IRQ number.
 */
int of_irq_parse_one(struct device_node *device, int index, struct of_phandle_args *out_irq)
{
	struct device_node *p;
	const __be32 *intspec, *tmp, *addr;
	u32 intsize, intlen;
	int i, res = -EINVAL;

	pr_debug("of_irq_parse_one: dev=%s, index=%d\n", of_node_full_name(device), index);

	/* OldWorld mac stuff is "special", handle out of line */
	if (of_irq_workarounds & OF_IMAP_OLDWORLD_MAC)
		return of_irq_parse_oldworld(device, index, out_irq);

	/* Get the reg property (if any) */
	addr = of_get_property(device, "reg", NULL);

	/* Get the interrupts property */
	intspec = of_get_property(device, "interrupts", &intlen);
	if (intspec == NULL) {
		/* Try the new-style interrupts-extended */
		res = of_parse_phandle_with_args(device, "interrupts-extended",
						"#interrupt-cells", index, out_irq);
		if (res)
			return -EINVAL;
		return of_irq_parse_raw(addr, out_irq);
	}
	intlen /= sizeof(*intspec);

	pr_debug(" intspec=%d intlen=%d\n", be32_to_cpup(intspec), intlen);

	/* Look for the interrupt parent. */
	p = of_irq_find_parent(device);
	if (p == NULL)
		return -EINVAL;

	/* Get size of interrupt specifier */
	tmp = of_get_property(p, "#interrupt-cells", NULL);
	if (tmp == NULL)
		goto out;
	intsize = be32_to_cpu(*tmp);

	pr_debug(" intsize=%d intlen=%d\n", intsize, intlen);

	/* Check index */
	if ((index + 1) * intsize > intlen)
		goto out;

	/* Copy intspec into irq structure */
	intspec += index * intsize;
	out_irq->np = p;
	out_irq->args_count = intsize;
	for (i = 0; i < intsize; i++)
		out_irq->args[i] = be32_to_cpup(intspec++);

	/* Check if there are any interrupt-map translations to process */
	res = of_irq_parse_raw(addr, out_irq);
 out:
	of_node_put(p);
	return res;
}
EXPORT_SYMBOL_GPL(of_irq_parse_one);

/**
 * of_irq_to_resource - Decode a node's IRQ and return it as a resource
 * @dev: pointer to device tree node
 * @index: zero-based index of the irq
 * @r: pointer to resource structure to return result into.
 */
int of_irq_to_resource(struct device_node *dev, int index, struct resource *r)
{
	int irq = irq_of_parse_and_map(dev, index);

	/* Only dereference the resource if both the
	 * resource and the irq are valid. */
	if (r && irq) {
		const char *name = NULL;

		memset(r, 0, sizeof(*r));
		/*
		 * Get optional "interrupts-names" property to add a name
		 * to the resource.
		 */
		of_property_read_string_index(dev, "interrupt-names", index,
					      &name);

		r->start = r->end = irq;
		r->flags = IORESOURCE_IRQ | irqd_get_trigger_type(irq_get_irq_data(irq));
		r->name = name ? name : of_node_full_name(dev);
	}

	return irq;
}
EXPORT_SYMBOL_GPL(of_irq_to_resource);

/**
 * of_irq_count - Count the number of IRQs a node uses
 * @dev: pointer to device tree node
 */
int of_irq_count(struct device_node *dev)
{
	struct of_phandle_args irq;
	int nr = 0;

	while (of_irq_parse_one(dev, nr, &irq) == 0)
		nr++;

	return nr;
}

/**
 * of_irq_to_resource_table - Fill in resource table with node's IRQ info
 * @dev: pointer to device tree node
 * @res: array of resources to fill in
 * @nr_irqs: the number of IRQs (and upper bound for num of @res elements)
 *
 * Returns the size of the filled in table (up to @nr_irqs).
 */
int of_irq_to_resource_table(struct device_node *dev, struct resource *res,
		int nr_irqs)
{
	int i;

	for (i = 0; i < nr_irqs; i++, res++)
		if (!of_irq_to_resource(dev, i, res))
			break;

	return i;
}
EXPORT_SYMBOL_GPL(of_irq_to_resource_table);

// ARM10C 20141004
// sizeof(struct intc_desc): 16 bytes
struct intc_desc {
	struct list_head	list;
	struct device_node	*dev;
	struct device_node	*interrupt_parent;
};

/**
 * of_irq_init - Scan and init matching interrupt controllers in DT
 * @matches: 0 terminated array of nodes to match and init function to call
 *
 * This function scans the device tree for matching interrupt controller nodes,
 * and calls their initialization functions in order with parents first.
 */
// ARM10C 20141004
// __irqchip_begin: irqchip_of_match_exynos4210_combiner
void __init of_irq_init(const struct of_device_id *matches)
{
	struct device_node *np, *parent = NULL;
	// parent: NULL
	struct intc_desc *desc, *temp_desc;
	struct list_head intc_desc_list, intc_parent_list;

	INIT_LIST_HEAD(&intc_desc_list);
	// intc_desc_list 리스트 초기화 수행

	INIT_LIST_HEAD(&intc_parent_list);
	// intc_parent_list 리스트 초기화 수행

	// matches: irqchip_of_match_exynos4210_combiner
	for_each_matching_node(np, matches) {
	// for (np = of_find_matching_node(NULL, matches); np; np = of_find_matching_node(np, matches))

		// np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
		// of_find_property(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, "interrupt-controller", NULL):
		// combiner node의 "interrupt-controller" property의 주소
		// np: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		// of_find_property(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, "interrupt-controller", NULL):
		// gic node의 "interrupt-controller" property의 주소
		if (!of_find_property(np, "interrupt-controller", NULL))
			continue;
		/*
		 * Here, we allocate and populate an intc_desc with the node
		 * pointer, interrupt-parent device_node etc.
		 */
		// sizeof(struct intc_desc): 16 bytes, GFP_KERNEL: 0xD0
		// kzalloc(16, GFP_KERNEL: 0xD0): kmem_cache#30-o10
		// sizeof(struct intc_desc): 16 bytes, GFP_KERNEL: 0xD0
		// kzalloc(16, GFP_KERNEL: 0xD0): kmem_cache#30-o11
		desc = kzalloc(sizeof(*desc), GFP_KERNEL);
		// desc: kmem_cache#30-o10
		// desc: kmem_cache#30-o11

		// desc: kmem_cache#30-o10
		// desc: kmem_cache#30-o11
		if (WARN_ON(!desc))
			goto err;

		// desc->dev: (kmem_cache#30-o10)->dev, np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
		// desc->dev: (kmem_cache#30-o11)->dev, np: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		desc->dev = np;
		// desc->dev: (kmem_cache#30-o10)->dev: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
		// desc->dev: (kmem_cache#30-o11)->dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소

// 2014/10/04 종료
// 2014/10/11 시작

		// desc->interrupt_parent: (kmem_cache#30-o10)->interrupt_parent, np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
		// of_irq_find_parent(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소): gic node 주소
		// desc->interrupt_parent: (kmem_cache#30-o11)->interrupt_parent, np: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		// of_irq_find_parent(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소): gic node 주소
		desc->interrupt_parent = of_irq_find_parent(np);
		// desc->interrupt_parent: (kmem_cache#30-o10)->interrupt_parent: gic node 주소
		// desc->interrupt_parent: (kmem_cache#30-o11)->interrupt_parent: gic node 주소

		// desc->interrupt_parent: (kmem_cache#30-o10)->interrupt_parent: gic node 주소
		// np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
		// desc->interrupt_parent: (kmem_cache#30-o11)->interrupt_parent: gic node 주소
		// np: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		if (desc->interrupt_parent == np)
			// desc->interrupt_parent: (kmem_cache#30-o11)->interrupt_parent: gic node 주소
			desc->interrupt_parent = NULL;
			// desc->interrupt_parent: (kmem_cache#30-o11)->interrupt_parent: NULL

		// &desc->list: &(kmem_cache#30-o10)->list
		// &desc->list: &(kmem_cache#30-o11)->list
		list_add_tail(&desc->list, &intc_desc_list);
		// intc_desc_list에 (kmem_cache#30-o10)->list를 tail에 추가
		// intc_desc_list에 (kmem_cache#30-o11)->list를 tail에 추가
	}

	// irqchip_of_match_exynos4210_combiner, irqchip_of_match_cortex_a15_gic 의
	// struct intc_desc 메모리 할당, intc_desc 맴버가 초기화 된 값이 intc_desc_list list의 tail로 추가됨

	/*
	 * The root irq controller is the one without an interrupt-parent.
	 * That one goes first, followed by the controllers that reference it,
	 * followed by the ones that reference the 2nd level controllers, etc.
	 */
	// list_empty(&intc_desc_list): 0
	while (!list_empty(&intc_desc_list)) {
		/*
		 * Process all controllers with the current 'parent'.
		 * First pass will be looking for NULL as the parent.
		 * The assumption is that NULL parent means a root controller.
		 */
		list_for_each_entry_safe(desc, temp_desc, &intc_desc_list, list) {
		// for (desc = list_first_entry(&intc_desc_list, typeof(*desc), list),
		// 	temp_desc = list_next_entry(desc, list);
		//      &desc->list != (&intc_desc_list);
		//      desc = temp_desc, temp_desc = list_next_entry(temp_desc, list))

			// desc: kmem_cache#30-o10 (exynos4210_combiner), temp_desc: kmem_cache#30-o11 (cortex_a15_gic)
			// desc: kmem_cache#30-o11 (cortex_a15_gic), temp_desc: NULL

			const struct of_device_id *match;
			int ret;
			of_irq_init_cb_t irq_init_cb;

			// desc->interrupt_parent: (kmem_cache#30-o10)->interrupt_parent: gic node 주소, parent: NULL
			// desc->interrupt_parent: (kmem_cache#30-o11)->interrupt_parent: NULL, parent: NULL
			if (desc->interrupt_parent != parent)
				continue;
				// continue 수행 (exynos4210_combiner)

			// &desc->list: (kmem_cache#30-o11)->list
			list_del(&desc->list);
			// intc_desc_list에서 (kmem_cache#30-o11)->list를 삭제

			// matches: irqchip_of_match_cortex_a15_gic,
			// desc->dev: (kmem_cache#30-o11)->dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
			// of_match_node(cortex_a15_gic, devtree에서 allnext로 순회 하면서 찾은 gic node의 주소):
			// irqchip_of_match_cortex_a15_gic
			match = of_match_node(matches, desc->dev);
			// match: irqchip_of_match_cortex_a15_gic

			// match->data; irqchip_of_match_cortex_a15_gic.data: gic_of_init
			if (WARN(!match->data,
			    "of_irq_init: no init function for %s\n",
			    match->compatible)) {
				kfree(desc);
				continue;
			}

			// match->compatible: irqchip_of_match_cortex_a15_gic.compatible: "arm,cortex-a15-gic",
			// desc->dev: (kmem_cache#30-o11)->dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
			// desc->interrupt_parent: (kmem_cache#30-o11)->interrupt_parent: NULL
			pr_debug("of_irq_init: init %s @ %p, parent %p\n",
				 match->compatible,
				 desc->dev, desc->interrupt_parent);
			// "of_irq_init: init arm,cortex-a15-gic @ 0x(gic node의 주소), parent 0\n"

// 2014/10/11 종료
// 2014/10/18 시작

			// match->data; irqchip_of_match_cortex_a15_gic.data: gic_of_init
			irq_init_cb = (of_irq_init_cb_t)match->data;
			// irq_init_cb: gic_of_init

			// desc->dev: (kmem_cache#30-o11)->dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
			// desc->interrupt_parent: (kmem_cache#30-o11)->interrupt_parent: NULL
			// gic_of_init(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, NULL):
			ret = irq_init_cb(desc->dev, desc->interrupt_parent);
			if (ret) {
				kfree(desc);
				continue;
			}

			/*
			 * This one is now set up; add it to the parent list so
			 * its children can get processed in a subsequent pass.
			 */
			list_add_tail(&desc->list, &intc_parent_list);
		}

		/* Get the next pending parent that might have children */
		desc = list_first_entry_or_null(&intc_parent_list,
						typeof(*desc), list);
		if (!desc) {
			pr_err("of_irq_init: children remain, but no parents\n");
			break;
		}
		list_del(&desc->list);
		parent = desc->dev;
		kfree(desc);
	}

	list_for_each_entry_safe(desc, temp_desc, &intc_parent_list, list) {
		list_del(&desc->list);
		kfree(desc);
	}
err:
	list_for_each_entry_safe(desc, temp_desc, &intc_desc_list, list) {
		list_del(&desc->list);
		kfree(desc);
	}
}
