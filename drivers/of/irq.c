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
// ARM10C 20141213
// np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, i: 0
unsigned int irq_of_parse_and_map(struct device_node *dev, int index)
{
	struct of_phandle_args oirq;

	// dev: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, index: 0
	// of_irq_parse_one(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, 0, &oirq): 0
	if (of_irq_parse_one(dev, index, &oirq))
		return 0;

	// of_irq_parse_one(0)에서 한일:
	// (&oirq)->np: gic node의 주소
	// (&oirq)->args_count: 3
	// (&oirq)->args[0]: 0
	// (&oirq)->args[1]: 0
	// (&oirq)->args[2]: 0

	// irq_create_of_mapping(&oriq): 32
	return irq_create_of_mapping(&oirq);
	// return 32
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
// ARM10C 20141213
// device: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
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
// ARM10C 20141213
// addr: reg의 property의 값의 주소, out_irq: &oirq
int of_irq_parse_raw(const __be32 *addr, struct of_phandle_args *out_irq)
{
	struct device_node *ipar, *tnode, *old = NULL, *newpar = NULL;
	// old: NULL, newpar: NULL

	// MAX_PHANDLE_ARGS: 8
	__be32 initial_match_array[MAX_PHANDLE_ARGS];
	const __be32 *match_array = initial_match_array;
	// match_array: initial_match_array

	// MAX_PHANDLE_ARGS: 8
	const __be32 *tmp, *imap, *imask, dummy_imask[] = { [0 ... MAX_PHANDLE_ARGS] = ~0 };
	// dummy_imask[0...7]: 0xffffffff

	u32 intsize = 1, addrsize, newintsize = 0, newaddrsize = 0;
	// intsize: 1, newintsize: 0, newaddrsize: 0

	int imaplen, match, i;

#ifdef DEBUG // undefined
	of_print_phandle_args("of_irq_parse_raw: ", out_irq);
#endif

	// out_irq->np: (&oirq)->np: gic node의 주소
	// of_node_get((&oirq)->np): gic node의 주소
	ipar = of_node_get(out_irq->np);
	// ipar: gic node의 주소

	/* First get the #interrupt-cells property of the current cursor
	 * that tells us how to interpret the passed-in intspec. If there
	 * is none, we are nice and just walk up the tree
	 */
	do {
		// ipar: gic node의 주소
		// of_get_property(gic node의 주소, "#interrupt-cells", NULL):
		// #interrupt-cells의 property 값의 주소
		tmp = of_get_property(ipar, "#interrupt-cells", NULL);
		// tmp: #interrupt-cells의 property 값의 주소

		// tmp: #interrupt-cells의 property 값의 주소
		if (tmp != NULL) {
			// tmp: #interrupt-cells의 property 값의 주소
			// be32_to_cpu(*(#interrupt-cells의 property 값의 주소)): 3
			intsize = be32_to_cpu(*tmp);
			// intsize: 3
			break;
			// break 수행
		}
		tnode = ipar;
		ipar = of_irq_find_parent(ipar);
		of_node_put(tnode);
	} while (ipar);

	// ipar: gic node의 주소
	if (ipar == NULL) {
		pr_debug(" -> no parent found !\n");
		goto fail;
	}

	// ipar: gic node의 주소,
	// of_node_full_name(gic node의 주소): "interrupt-controller@10481000", intsize: 3
	pr_debug("of_irq_parse_raw: ipar=%s, size=%d\n", of_node_full_name(ipar), intsize);
	// "of_irq_parse_raw: ipar=interrupt-controller@10481000, size=3\n"

	// out_irq->args_count: (&oirq)->args_count: 3, intsize: 3
	if (out_irq->args_count != intsize)
		return -EINVAL;

	/* Look for this #address-cells. We have to implement the old linux
	 * trick of looking for the parent here as some device-trees rely on it
	 */
	// ipar: gic node의 주소, of_node_get(gic node의 주소): gic node의 주소
	old = of_node_get(ipar);
	// old: gic node의 주소

	do {
		// old: gic node의 주소,
		// of_get_property(gic node의 주소, "#address-cells", NULL): NULL
		// old: root node의 주소,
		// of_get_property(root node의 주소, "#address-cells", NULL): #address-cells의 property 값의 주소
		tmp = of_get_property(old, "#address-cells", NULL);
		// tmp: NULL
		// tmp: #address-cells의 property 값의 주소

		// old: gic node의 주소, of_get_parent(gic node의 주소): root node의 주소
		// old: root node의 주소, of_get_parent(root node의 주소): NULL
		tnode = of_get_parent(old);
		// tnode: root node의 주소
		// tnode: NULL

		// old: gic node의 주소
		// old: root node의 주소
		of_node_put(old); // null function

		// tnode: root node의 주소
		// tnode: NULL
		old = tnode;
		// old: root node의 주소
		// old: NULL

		// old: root node의 주소, tmp: NULL
		// old: NULL, tmp: #address-cells의 property 값의 주소
	} while (old && tmp == NULL);

	// old: NULL
	of_node_put(old); // null function

	// old: NULL
	old = NULL;
	// old: NULL

	// tmp: #address-cells의 property 값의 주소
	// be32_to_cpu(*(#address-cells의 property 값의 주소)): 1
	addrsize = (tmp == NULL) ? 2 : be32_to_cpu(*tmp);
	// addrsize: 1

	// addrsize: 1
	pr_debug(" -> addrsize=%d\n", addrsize);
	// " -> addrsize=1\n"

	/* Range check so that the temporary buffer doesn't overflow */
	// addrsize: 1, intsize: 3, MAX_PHANDLE_ARGS: 8
	if (WARN_ON(addrsize + intsize > MAX_PHANDLE_ARGS))
		goto fail;

	/* Precalculate the match array - this simplifies match loop */
	// addrsize: 1
	for (i = 0; i < addrsize; i++)
		// i: 0, initial_match_array[0], addr: reg의 property의 값의 주소
		// addr[0]: (reg의 property의 값의 주소)[0]: 0x10440000
		initial_match_array[i] = addr ? addr[i] : 0;
		// initial_match_array[0]: 0x10440000

	// intsize: 3
	for (i = 0; i < intsize; i++)
		// i: 0, addrsize: 1, initial_match_array[1],
		// out_irq->args[0], (&oirq)->args[0], cpu_to_be32((&oirq)->args[0]): 0
		// i: 1, addrsize: 1, initial_match_array[2],
		// out_irq->args[1], (&oirq)->args[1], cpu_to_be32((&oirq)->args[1]): 0
		// i: 2, addrsize: 1, initial_match_array[3],
		// out_irq->args[2], (&oirq)->args[2], cpu_to_be32((&oirq)->args[2]): 0
		initial_match_array[addrsize + i] = cpu_to_be32(out_irq->args[i]);
		// initial_match_array[1]: 0
		// initial_match_array[2]: 0
		// initial_match_array[3]: 0

	/* Now start the actual "proper" walk of the interrupt tree */
	// ipar: gic node의 주소
	while (ipar != NULL) {
		/* Now check if cursor is an interrupt-controller and if it is
		 * then we are done
		 */
		// ipar: gic node의 주소,
		// of_get_property(gic node의 주소, "interrupt-controller", NULL): NULL 아닌값
		if (of_get_property(ipar, "interrupt-controller", NULL) !=
				NULL) {
			pr_debug(" -> got it !\n");
			// " -> got it !\n"

			return 0;
			// return 0
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
// ARM10C 20141213
// dev: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, index: 0, &oirq
int of_irq_parse_one(struct device_node *device, int index, struct of_phandle_args *out_irq)
{
	struct device_node *p;
	const __be32 *intspec, *tmp, *addr;
	u32 intsize, intlen;

	// EINVAL: 23
	int i, res = -EINVAL;
	// res: -23

	// device: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	// of_node_full_name(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소):
	// "interrupt-controller@10440000", index: 0
	pr_debug("of_irq_parse_one: dev=%s, index=%d\n", of_node_full_name(device), index);
	// "of_irq_parse_one: dev=interrupt-controller@10440000, index=0\n"

	/* OldWorld mac stuff is "special", handle out of line */
	// of_irq_workarounds: 0, OF_IMAP_OLDWORLD_MAC: 0x00000001
	if (of_irq_workarounds & OF_IMAP_OLDWORLD_MAC)
		return of_irq_parse_oldworld(device, index, out_irq);

	/* Get the reg property (if any) */
	// device: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	// of_get_property(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, "reg", NULL):
	// reg의 property의 값의 주소
	addr = of_get_property(device, "reg", NULL);
	// addr: reg의 property의 값의 주소

	/* Get the interrupts property */
	// device: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	// of_get_property(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, "interrups", &intlen):
	// interrupts의 property의 값의 주소
	intspec = of_get_property(device, "interrupts", &intlen);
	// intspec: interrupts의 property의 값의 주소, intlen: 384

	// intspec: interrupts의 property의 값의 주소
	if (intspec == NULL) {
		/* Try the new-style interrupts-extended */
		res = of_parse_phandle_with_args(device, "interrupts-extended",
						"#interrupt-cells", index, out_irq);
		if (res)
			return -EINVAL;
		return of_irq_parse_raw(addr, out_irq);
	}

	// intspec: interrupts의 property의 값의 주소
	// intlen: 384, sizeof(*interrupts의 property의 값의 주소): 4
	intlen /= sizeof(*intspec);
	// intlen: 96

	// intspec: interrupts의 property의 값의 주소
	// be32_to_cpup(interrupts의 property의 값의 주소): 0, intlen: 96
	pr_debug(" intspec=%d intlen=%d\n", be32_to_cpup(intspec), intlen);
	// " intspec=0 intlen=96\n"

	/* Look for the interrupt parent. */
	// device: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	// of_irq_find_parent(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소)
	// gic node의 주소
	p = of_irq_find_parent(device);
	// p: gic node의 주소

	// p: gic node의 주소
	if (p == NULL)
		return -EINVAL;

	/* Get size of interrupt specifier */
	// p: gic node의 주소
	// of_get_property(gic node의 주소 "#interrupt-cells", NULL):
	// #interrupt-cells의 property의 값의 주소
	tmp = of_get_property(p, "#interrupt-cells", NULL);
	// tmp: #interrupt-cells의 property의 값의 주소

	// tmp: #interrupt-cells의 property의 값의 주소
	if (tmp == NULL)
		goto out;

	// tmp: #interrupt-cells의 property의 값의 주소
	// be32_to_cpu(*(#interrupt-cells의 property의 값의 주소)): 3
	intsize = be32_to_cpu(*tmp);
	// intsize: 3

	// intsize: 3, intlen: 96
	pr_debug(" intsize=%d intlen=%d\n", intsize, intlen);
	// " intsize=3 intlen=96\n"

	/* Check index */
	// index: 0, intsize: 3, intlen: 96
	if ((index + 1) * intsize > intlen)
		goto out;

	/* Copy intspec into irq structure */
	// intspec: interrupts의 property의 값의 주소, index: 0, intsize: 3
	intspec += index * intsize;
	// intspec: interrupts의 property의 값의 주소

	// out_irq->np: (&oirq)->np, p: gic node의 주소
	out_irq->np = p;
	// out_irq->np: (&oirq)->np: gic node의 주소

	// out_irq->args_count: (&oirq)->args_count, intsize: 3
	out_irq->args_count = intsize;
	// out_irq->args_count: (&oirq)->args_count: 3

	// intsize: 3
	for (i = 0; i < intsize; i++)
		// i: 0, out_irq->args[0]: (&oirq)->args[0], intspec: interrupts의 property의 값의 주소
		// be32_to_cpup(interrupts의 property의 값의 주소): 0
		// i: 1, out_irq->args[1]: (&oirq)->args[1], intspec: interrupts의 property의 값의 주소 + 1
		// be32_to_cpup(interrupts의 property의 값의 주소 + 1): 0
		// i: 2, out_irq->args[2]: (&oirq)->args[2], intspec: interrupts의 property의 값의 주소 + 2
		// be32_to_cpup(interrupts의 property의 값의 주소 + 2): 0
		out_irq->args[i] = be32_to_cpup(intspec++);
		// out_irq->args[0]: (&oirq)->args[0]: 0, intspec: interrupts의 property의 값의 주소 + 1
		// out_irq->args[1]: (&oirq)->args[1]: 0, intspec: interrupts의 property의 값의 주소 + 2
		// out_irq->args[2]: (&oirq)->args[2]: 0, intspec: interrupts의 property의 값의 주소 + 3

	/* Check if there are any interrupt-map translations to process */
	// addr: reg의 property의 값의 주소, out_irq: &oirq
	// of_irq_parse_raw(reg의 property의 값의 주소, &oirq): 0
	res = of_irq_parse_raw(addr, out_irq);
	// res: 0
 out:
	// p: gic node의 주소
	of_node_put(p); // null function

	// res: 0
	return res;
	// return 0
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
// ARM10C 20141129
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

		// NOTE:
		// while의 1st loop 수행을 [w1] 로, 2nd loop 수행을 [w2] 로 주석에 prefix 로 추가

		list_for_each_entry_safe(desc, temp_desc, &intc_desc_list, list) {
		// for (desc = list_first_entry(&intc_desc_list, typeof(*desc), list),
		// 	temp_desc = list_next_entry(desc, list);
		//      &desc->list != (&intc_desc_list);
		//      desc = temp_desc, temp_desc = list_next_entry(temp_desc, list))

			// NOTE:
			// for 의 1st loop 수행을 [f1] 로, 2nd loop 수행을 [f2] 로 주석에 prefix 로 추가

			// [w1][f1] desc: kmem_cache#30-o10 (exynos4210_combiner), temp_desc: kmem_cache#30-o11 (cortex_a15_gic), parent: NULL
			// [w1][f2] desc: kmem_cache#30-o11 (cortex_a15_gic), &temp_desc->list: &intc_desc_list, parent: NULL

			// [w2][f1] desc: kmem_cache#30-o10 (exynos4210_combiner), &temp_desc->list: &intc_desc_list,
			// [w2][f1] parent: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소

			const struct of_device_id *match;
			int ret;
			of_irq_init_cb_t irq_init_cb;

			// [w1][f1] desc->interrupt_parent: (kmem_cache#30-o10)->interrupt_parent: gic node 주소, parent: NULL
			// [w1][f2] desc->interrupt_parent: (kmem_cache#30-o11)->interrupt_parent: NULL, parent: NULL
			// [w2][f1] desc->interrupt_parent: (kmem_cache#30-o10)->interrupt_parent: gic node 주소,
			// [w2][f1] parent: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
			if (desc->interrupt_parent != parent)
				continue;
				// [w1][f1] continue 수행 (exynos4210_combiner)

			// [w1][f2] &desc->list: (kmem_cache#30-o11)->list
			// [w2][f1] &desc->list: (kmem_cache#30-o10)->list
			list_del(&desc->list);
			// [w1][f2] intc_desc_list에서 (kmem_cache#30-o11)->list를 삭제
			// [w2][f1] intc_desc_list에서 (kmem_cache#30-o10)->list를 삭제

			// [w1][f2] matches: irqchip_of_match_cortex_a15_gic,
			// [w1][f2] desc->dev: (kmem_cache#30-o11)->dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
			// [w1][f2] of_match_node(cortex_a15_gic, devtree에서 allnext로 순회 하면서 찾은 gic node의 주소):
			// [w1][f2] irqchip_of_match_cortex_a15_gic
			// [w2][f1] matches: irqchip_of_match_cortex_a15_gic,
			// [w2][f1] desc->dev: (kmem_cache#30-o10)->dev: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
			// [w2][f1] of_match_node(cortex_a15_gic, devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소):
			// [w2][f1] irqchip_of_match_exynos4210_combiner
			match = of_match_node(matches, desc->dev);
			// [w1][f2] match: irqchip_of_match_cortex_a15_gic
			// [w2][f1] match: irqchip_of_match_exynos4210_combiner

			// [w1][f2] match->data; irqchip_of_match_cortex_a15_gic.data: gic_of_init
			// [w2][f1] match->data; irqchip_of_match_exynos4210_combiner.data: combiner_of_init
			if (WARN(!match->data,
			    "of_irq_init: no init function for %s\n",
			    match->compatible)) {
				kfree(desc);
				continue;
			}

			// [w1][f2] match->compatible: irqchip_of_match_cortex_a15_gic.compatible: "arm,cortex-a15-gic",
			// [w1][f2] desc->dev: (kmem_cache#30-o11)->dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
			// [w1][f2] desc->interrupt_parent: (kmem_cache#30-o11)->interrupt_parent: NULL
			// [w2][f1] match->compatible: irqchip_of_match_exynos4210_combiner.compatible: "samsung,exynos4210-combiner",
			// [w2][f1] desc->dev: (kmem_cache#30-o10)->dev: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
			// [w2][f1] desc->interrupt_parent: (kmem_cache#30-o10)->interrupt_parent: NULL
			pr_debug("of_irq_init: init %s @ %p, parent %p\n",
				 match->compatible,
				 desc->dev, desc->interrupt_parent);
			// [w1][f2] "of_irq_init: init arm,cortex-a15-gic @ 0x(gic node의 주소), parent 0\n"
			// [w2][f1] "of_irq_init: init samsung,exynos4210-combiner @ 0x(combiner node의 주소), parent 0\n"

// 2014/10/11 종료
// 2014/10/18 시작

			// [w1][f2] match->data; irqchip_of_match_cortex_a15_gic.data: gic_of_init
			// [w2][f1] match->data; irqchip_of_match_exynos4210_combiner.data: combiner_of_init
			irq_init_cb = (of_irq_init_cb_t)match->data;
			// [w1][f2] irq_init_cb: gic_of_init
			// [w2][f1] irq_init_cb: combiner_of_init

			// [w1][f2] desc->dev: (kmem_cache#30-o11)->dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
			// [w1][f2] desc->interrupt_parent: (kmem_cache#30-o11)->interrupt_parent: NULL
			// [w1][f2] gic_of_init(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, NULL): 0
			// [w2][f1] desc->dev: (kmem_cache#30-o10)->dev: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소,
			// [w2][f1] desc->interrupt_parent: (kmem_cache#30-o10)->interrupt_parent: NULL
			// [w2][f1] combiner_of_init(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, NULL): 0
			ret = irq_init_cb(desc->dev, desc->interrupt_parent);
			// [w1][f2] ret: 0
			// [w2][f1] ret: 0

			// [w1][f2] gic_of_init에서 한일:
			//
			// device tree 있는  gic node에서 node의 resource 값을 가져옴
			// (&res)->start: 0x10481000
			// (&res)->end: 0x10481fff
			// (&res)->flags: IORESOURCE_MEM: 0x00000200
			// (&res)->name: "/interrupt-controller@10481000"
			/*
			// alloc area (GIC#0) 를 만들고 rb tree에 alloc area 를 추가
			// 가상주소 va_start 기준으로 GIC#0 를 RB Tree 추가한 결과
			//
			//                                  CHID-b
			//                               (0xF8000000)
			//                              /            \
			//                         TMR-r               PMU-r
			//                    (0xF6300000)             (0xF8180000)
			//                      /      \               /           \
			//                 SYSC-b      WDT-b         CMU-b         SRAM-b
			//            (0xF6100000)   (0xF6400000)  (0xF8100000)   (0xF8400000)
			//             /                                                 \
			//        GIC#0-r                                                 ROMC-r
			//   (0xF0000000)                                                 (0xF84C0000)
			//
			// vmap_area_list에 GIC#0 - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
			// 순서로 리스트에 연결이 됨
			//
			// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
			// (kmem_cache#30-oX (vm_struct))->addr: 0xf0000000
			// (kmem_cache#30-oX (vm_struct))->size: 0x2000
			// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
			//
			// (kmem_cache#30-oX (vmap_area GIC#0))->vm: kmem_cache#30-oX (vm_struct)
			// (kmem_cache#30-oX (vmap_area GIC#0))->flags: 0x04
			*/
			// device tree 있는  gic node에서 node의 resource 값을 pgtable에 매핑함
			// 0xc0004780이 가리키는 pte의 시작주소에 0x10481653 값을 갱신
			// (linux pgtable과 hardware pgtable의 값 같이 갱신)
			//
			//  pgd                   pte
			// |              |
			// +--------------+
			// |              |       +--------------+ +0
			// |              |       |  0xXXXXXXXX  | ---> 0x10481653 에 매칭되는 linux pgtable 값
			// +- - - - - - - +       |  Linux pt 0  |
			// |              |       +--------------+ +1024
			// |              |       |              |
			// +--------------+ +0    |  Linux pt 1  |
			// | *(c0004780)  |-----> +--------------+ +2048
			// |              |       |  0x10481653  | ---> 2052
			// +- - - - - - - + +4    |   h/w pt 0   |
			// | *(c0004784)  |-----> +--------------+ +3072
			// |              |       +              +
			// +--------------+ +8    |   h/w pt 1   |
			// |              |       +--------------+ +4096
			//
			// cache의 값을 전부 메모리에 반영
			//
			// device tree 있는  gic node에서 node의 resource 값을 가져옴
			// (&res)->start: 0x10482000
			// (&res)->end: 0x10482fff
			// (&res)->flags: IORESOURCE_MEM: 0x00000200
			// (&res)->name: "/interrupt-controller@10481000"
			/*
			// alloc area (GIC#1) 를 만들고 rb tree에 alloc area 를 추가
			// 가상주소 va_start 기준으로 GIC#1 를 RB Tree 추가한 결과
			//
			//                                  CHID-b
			//                               (0xF8000000)
			//                              /            \
			//                         TMR-r               PMU-r
			//                    (0xF6300000)             (0xF8180000)
			//                      /      \               /           \
			//                GIC#1-b      WDT-b         CMU-b         SRAM-b
			//            (0xF0002000)   (0xF6400000)  (0xF8100000)   (0xF8400000)
			//             /       \                                          \
			//        GIC#0-r     SYSC-r                                       ROMC-r
			//    (0xF0000000)   (0xF6100000)                                 (0xF84C0000)
			//
			// vmap_area_list에 GIC#0 - GIC#1 - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
			// 순서로 리스트에 연결이 됨
			//
			// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
			// (kmem_cache#30-oX (vm_struct))->addr: 0xf0002000
			// (kmem_cache#30-oX (vm_struct))->size: 0x2000
			// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
			//
			// (kmem_cache#30-oX (vmap_area GIC#1))->vm: kmem_cache#30-oX (vm_struct)
			// (kmem_cache#30-oX (vmap_area GIC#1))->flags: 0x04
			*/
			// device tree 있는  gic node에서 node의 resource 값을 pgtable에 매핑함
			// 0xc0004780이 가리키는 pte의 시작주소에 0x10482653 값을 갱신
			// (linux pgtable과 hardware pgtable의 값 같이 갱신)
			//
			//  pgd                   pte
			// |              |
			// +--------------+
			// |              |       +--------------+ +0
			// |              |       |  0xXXXXXXXX  | ---> 0x10482653 에 매칭되는 linux pgtable 값
			// +- - - - - - - +       |  Linux pt 0  |
			// |              |       +--------------+ +1024
			// |              |       |              |
			// +--------------+ +0    |  Linux pt 1  |
			// | *(c0004780)  |-----> +--------------+ +2048
			// |              |       |  0x10482653  | ---> 2060
			// +- - - - - - - + +4    |   h/w pt 0   |
			// | *(c0004784)  |-----> +--------------+ +3072
			// |              |       +              +
			// +--------------+ +8    |   h/w pt 1   |
			// |              |       +--------------+ +4096
			//
			// cache의 값을 전부 메모리에 반영
			//
			// (&gic_data[0])->dist_base.common_base: 0xf0000000
			// (&gic_data[0])->cpu_base.common_base: 0xf0002000
			// (&gic_data[0])->gic_irqs: 160
			/*
			// struct irq_desc의 자료 구조크기 만큼 160개의 메모리를 할당 받아
			// radix tree 구조로 구성
			//
			// radix tree의 root node: &irq_desc_tree 값을 변경
			// (&irq_desc_tree)->rnode: kmem_cache#20-o1 (RADIX_LSB: 1)
			// (&irq_desc_tree)->height: 2
			//
			// (kmem_cache#20-o1)->height: 2
			// (kmem_cache#20-o1)->count: 3
			// (kmem_cache#20-o1)->parent: NULL
			// (kmem_cache#20-o1)->slots[0]: kmem_cache#20-o0 (radix height 1 관리 주소)
			// (kmem_cache#20-o1)->slots[1]: kmem_cache#20-o2 (radix height 1 관리 주소)
			// (kmem_cache#20-o1)->slots[2]: kmem_cache#20-o3 (radix height 1 관리 주소)
			//
			// (kmem_cache#20-o0)->height: 1
			// (kmem_cache#20-o0)->count: 63
			// (kmem_cache#20-o0)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
			// (kmem_cache#20-o0)->slots[0...63]: kmem_cache#28-oX (irq 0...63)
			//
			// (kmem_cache#20-o2)->height: 1
			// (kmem_cache#20-o2)->count: 63
			// (kmem_cache#20-o2)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
			// (kmem_cache#20-o2)->slots[0...63]: kmem_cache#28-oX (irq 63...127)
			//
			// (kmem_cache#20-o3)->height: 1
			// (kmem_cache#20-o3)->count: 32
			// (kmem_cache#20-o3)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
			// (kmem_cache#20-o3)->slots[0...32]: kmem_cache#28-oX (irq 127...160)
			//
			// (&irq_desc_tree)->rnode --> +-----------------------+
			//                             |    radix_tree_node    |
			//                             |   (kmem_cache#20-o1)  |
			//                             +-----------------------+
			//                             | height: 2 | count: 3  |
			//                             +-----------------------+
			//                             | radix_tree_node 0 ~ 2 |
			//                             +-----------------------+
			//                            /            |             \
			//    slot: 0                /   slot: 1   |              \ slot: 2
			//    +-----------------------+  +-----------------------+  +-----------------------+
			//    |    radix_tree_node    |  |    radix_tree_node    |  |    radix_tree_node    |
			//    |   (kmem_cache#20-o0)  |  |   (kmem_cache#20-o2)  |  |   (kmem_cache#20-o3)  |
			//    +-----------------------+  +-----------------------+  +-----------------------+
			//    | height: 1 | count: 64 |  | height: 1 | count: 64 |  | height: 1 | count: 32 |
			//    +-----------------------+  +-----------------------+  +-----------------------+
			//    |    irq  0 ~ 63        |  |    irq 64 ~ 127       |  |    irq 128 ~ 160      |
			//    +-----------------------+  +-----------------------+  +-----------------------+
			*/
			// (&gic_data[0])->domain: kmem_cache#25-o0
			// (&(kmem_cache#25-o0)->revmap_tree)->height: 0
			// (&(kmem_cache#25-o0)->revmap_tree)->gfp_mask: GFP_KERNEL: 0xD0
			// (&(kmem_cache#25-o0)->revmap_tree)->rnode: NULL
			// (kmem_cache#25-o0)->ops: &gic_irq_domain_ops
			// (kmem_cache#25-o0)->host_data: &gic_data[0]
			// (kmem_cache#25-o0)->of_node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
			// (kmem_cache#25-o0)->hwirq_max: 160
			// (kmem_cache#25-o0)->revmap_size: 160
			// (kmem_cache#25-o0)->revmap_direct_max_irq: 0
			// (kmem_cache#25-o0)->name: "GIC"
			// (kmem_cache#25-o0)->linear_revmap[16...160]: 16...160
			//
			// irq_domain_list에 (kmem_cache#25-o0)->link를 추가
			//
			// irq 16...160까지의 struct irq_data에 값을 설정
			// (&(kmem_cache#28-oX (irq 16...160))->irq_data)->hwirq: 16...160
			// (&(kmem_cache#28-oX (irq 16...160))->irq_data)->domain: kmem_cache#25-o0
			// (&(kmem_cache#28-oX (irq 16...160))->irq_data)->state_use_accessors: 0x10800
			// (kmem_cache#28-oX (irq 16...160))->percpu_enabled: kmem_cache#30-oX
			// (kmem_cache#28-oX (irq 16...160))->status_use_accessors: 0x31600
			// (kmem_cache#28-oX (irq 16...160))->irq_data.chip: &gic_chip
			// (kmem_cache#28-oX (irq 16...160))->handle_irq: handle_percpu_devid_irq
			// (kmem_cache#28-oX (irq 16...160))->name: NULL
			// (kmem_cache#28-oX (irq 16...160))->irq_data.chip_data: &gic_data[0]
			// (kmem_cache#28-oX (irq 16...160))->status_use_accessors: 0x31600
			//
			// smp_cross_call: gic_raise_softirq
			//
			// (&cpu_chain)->head: gic_cpu_notifier 포인터 대입
			// (&gic_cpu_notifier)->next은 (&radix_tree_callback_nb)->next로 대입
			//
			// handle_arch_irq: gic_handle_irq
			//
			// gic_chip.flags: 0
			//
			// register GICD_CTLR을 0으로 초기화
			// 0 값의 의미: Disable the forwarding of pending interrupts from the Distributor to the CPU interfaces.
			// register GICD_ICFGR2 ~ GICD_ICFGR9 까지의 값을 0으로 초기화 수행
			// register GICD_ITARGETSR8 ~ GICD_ITARGETSR39 값을 0x01010101으로 세팅
			// 0x01010101의 의미: CPU targets, byte offset 0 ~ 4까지의 interrupt target을 "CPU interface 0"으로 설정
			// register GICD_IPRIORITYR8 ~ GICD_ITARGETSR39 값을 0xa0a0a0a0으로 세팅
			// 0xa0a0a0a0의 의미: Priority, byte offset 0 ~ 4까지의 interrupt priority value을 160 (0xa0)로 설정
			// register GICD_ICENABLER1 ~ GICD_ICENABLER4 값을 0xffffffff으로 세팅
			// 0xffffffff의 의미: 각각의 For SPIs and PPIs 값을 interrupt disable로 설정
			// register GICD_CTLR 값을 1로 세팅
			// 1 값의 의미: Enables the forwarding of pending interrupts from the Distributor to the CPU interfaces.
			//
			// gic_cpu_map[0]: 0x01
			// gic_cpu_map[1...7]: 0xfe
			//
			// register GICD_ICENABLER0 값을 0xffff0000으로 세팅
			// 0xffff0000 값의 의미: 0~15 bit는 SGI, 16~31 PPI를 컨트롤함, PPI를 전부 disable
			// register GICD_ISENABLER0 값을 0x0000ffff으로 세팅
			// 0x0000ffff 값의 의미: 0~15 bit는 SGI, 16~31 PPI를 컨트롤함, SGI를 전부 enable 함
			// register GICD_IPRIORITYR1 ~ GICD_ITARGETSR8 값을 0xa0a0a0a0으로 세팅
			// 0xa0a0a0a0의 의미: Priority, byte offset 0 ~ 4까지의 interrupt priority value을 160 (0xa0)로 설정
			// register GICC_PMR 값을 0xf0으로 세팅
			// 0xf0 값의 의미: interrupt priority가 240(0xf0) 이상인 interrupt만 cpu에 interrupt를 전달
			// register GICC_CTLR에 값을 1로 세팅
			// 1 값의 의미: cpu에 전달되는 interrupt를 enable 함
			//
			// (&gic_data[0])->saved_ppi_enable: kmem_cache#26-o0 에서의 4 byte 할당된 주소 (pcp)
			// (&gic_data[0])->saved_ppi_conf: kmem_cache#26-o0 에서의 8 byte 할당된 주소 (pcp)
			// (&cpu_pm_notifier_chain)->head: &gic_notifier_block
			//
			// gic_cnt: 1

			// [w2][f1] combiner_of_init에서 한일:
			//
			// device tree 있는  combiner node에서 node의 resource 값을 가져옴
			// (&res)->start: 0x10440000
			// (&res)->end: 0x10440fff
			// (&res)->flags: IORESOURCE_MEM: 0x00000200
			// (&res)->name: "/interrupt-controller@10440000"
			/*
			// alloc area (COMB) 를 만들고 rb tree에 alloc area 를 추가
			// 가상주소 va_start 기준으로 COMB 를 RB Tree 추가한 결과
			//
			//                                  CHID-b
			//                               (0xF8000000)
			//                              /            \
			//                         TMR-b               PMU-b
			//                    (0xF6300000)             (0xF8180000)
			//                      /      \               /           \
			//                GIC#1-r      WDT-b         CMU-b         SRAM-b
			//            (0xF0002000)   (0xF6400000)  (0xF8100000)   (0xF8400000)
			//             /       \                                          \
			//        GIC#0-b     SYSC-b                                       ROMC-r
			//    (0xF0000000)   (0xF6100000)                                 (0xF84C0000)
			//                   /
			//               COMB-r
			//          (0xF0004000)
			//
			// vmap_area_list에 GIC#0 - GIC#1 - COMB - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
			// 순서로 리스트에 연결이 됨
			//
			// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
			// (kmem_cache#30-oX (vm_struct))->addr: 0xf0004000
			// (kmem_cache#30-oX (vm_struct))->size: 0x2000
			// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
			//
			// (kmem_cache#30-oX (vmap_area COMB))->vm: kmem_cache#30-oX (vm_struct)
			// (kmem_cache#30-oX (vmap_area COMB))->flags: 0x04
			*/
			// device tree 있는 combiner node에서 node의 resource 값을 pgtable에 매핑함
			// 0xc0004780이 가리키는 pte의 시작주소에 0x10440653 값을 갱신
			// (linux pgtable과 hardware pgtable의 값 같이 갱신)
			//
			//  pgd                   pte
			// |              |
			// +--------------+
			// |              |       +--------------+ +0
			// |              |       |  0xXXXXXXXX  | ---> 0x10440653 에 매칭되는 linux pgtable 값
			// +- - - - - - - +       |  Linux pt 0  |
			// |              |       +--------------+ +1024
			// |              |       |              |
			// +--------------+ +0    |  Linux pt 1  |
			// | *(c0004780)  |-----> +--------------+ +2048
			// |              |       |  0x10440653  | ---> 2068
			// +- - - - - - - + +4    |   h/w pt 0   |
			// | *(c0004784)  |-----> +--------------+ +3072
			// |              |       +              +
			// +--------------+ +8    |   h/w pt 1   |
			// |              |       +--------------+ +4096
			//
			// cache의 값을 전부 메모리에 반영
			//
			// combiner_init에서 한일:
			// struct irq_domain를 위한 메모리 할당: kmem_cache#24-o0
			// combiner_irq_domain: kmem_cache#24-o0
			//
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
			/*
			// struct irq_desc의 자료 구조크기 만큼 256개의 메모리를 할당 받아
			// radix tree 구조로 구성
			//
			// radix tree의 root node: &irq_desc_tree 값을 변경
			// (&irq_desc_tree)->rnode: kmem_cache#20-o1 (RADIX_LSB: 1)
			// (&irq_desc_tree)->height: 2
			//
			// (kmem_cache#20-o1)->height: 2
			// (kmem_cache#20-o1)->count: 7
			// (kmem_cache#20-o1)->parent: NULL
			// (kmem_cache#20-o1)->slots[0]: kmem_cache#20-o0 (radix height 1 관리 주소)
			// (kmem_cache#20-o1)->slots[1]: kmem_cache#20-o2 (radix height 1 관리 주소)
			// (kmem_cache#20-o1)->slots[2]: kmem_cache#20-o3 (radix height 1 관리 주소)
			// (kmem_cache#20-o1)->slots[3]: kmem_cache#20-o4 (radix height 1 관리 주소)
			// (kmem_cache#20-o1)->slots[4]: kmem_cache#20-o5 (radix height 1 관리 주소)
			// (kmem_cache#20-o1)->slots[5]: kmem_cache#20-o6 (radix height 1 관리 주소)
			// (kmem_cache#20-o1)->slots[6]: kmem_cache#20-o7 (radix height 1 관리 주소)
			//
			// (kmem_cache#20-o0)->height: 1
			// (kmem_cache#20-o0)->count: 64
			// (kmem_cache#20-o0)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
			// (kmem_cache#20-o0)->slots[0...63]: kmem_cache#28-oX (irq 0...63)
			//
			// (kmem_cache#20-o2)->height: 1
			// (kmem_cache#20-o2)->count: 64
			// (kmem_cache#20-o2)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
			// (kmem_cache#20-o2)->slots[0...63]: kmem_cache#28-oX (irq 63...127)
			//
			// (kmem_cache#20-o3)->height: 1
			// (kmem_cache#20-o3)->count: 64
			// (kmem_cache#20-o3)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
			// (kmem_cache#20-o3)->slots[0...63]: kmem_cache#28-oX (irq 127...191)
			//
			// (kmem_cache#20-o4)->height: 1
			// (kmem_cache#20-o4)->count: 64
			// (kmem_cache#20-o4)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
			// (kmem_cache#20-o4)->slots[0...63]: kmem_cache#28-oX (irq 192...255)
			//
			// (kmem_cache#20-o5)->height: 1
			// (kmem_cache#20-o5)->count: 64
			// (kmem_cache#20-o5)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
			// (kmem_cache#20-o5)->slots[0...63]: kmem_cache#28-oX (irq 256...319)
			//
			// (kmem_cache#20-o6)->height: 1
			// (kmem_cache#20-o6)->count: 64
			// (kmem_cache#20-o6)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
			// (kmem_cache#20-o6)->slots[0...63]: kmem_cache#28-oX (irq 320...383)
			//
			// (kmem_cache#20-o7)->height: 1
			// (kmem_cache#20-o7)->count: 32
			// (kmem_cache#20-o7)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
			// (kmem_cache#20-o7)->slots[0...31]: kmem_cache#28-oX (irq 384...415)
			//
			// (&irq_desc_tree)->rnode -->  +-----------------------+
			//                              |    radix_tree_node    |
			//                              |   (kmem_cache#20-o1)  |
			//                              +-----------------------+
			//                              | height: 2 | count: 7  |
			//                              +-----------------------+
			//                              | radix_tree_node 0 ~ 6 | \
			//                            / +-----------------------+ \ \
			//                          /  /           |  |          \  \ \ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
			//  slot: 0               /   | slot: 1    |  |           |   \              slot: 2    |
			//  +-----------------------+ | +-----------------------+ | +-----------------------+   |
			//  |    radix_tree_node    | | |    radix_tree_node    | | |    radix_tree_node    |   |
			//  |   (kmem_cache#20-o0)  | | |   (kmem_cache#20-o2)  | | |   (kmem_cache#20-o3)  |   |
			//  +-----------------------+ | +-----------------------+ | +-----------------------+   |
			//  | height: 1 | count: 64 | | | height: 1 | count: 64 | | | height: 1 | count: 64 |   |
			//  +-----------------------+ | +-----------------------+ | +-----------------------+   |
			//  |    irq  0 ~ 63        | | |    irq 64 ~ 127       | | |    irq 128 ~ 191      |   |
			//  +-----------------------+ | +-----------------------+ | +-----------------------+   |
			//                           /                |            \                            |
			//  slot: 3                /    slot: 4       |              \                slot: 5    \                slot: 6
			//  +-----------------------+   +-----------------------+   +-----------------------+   +-----------------------+
			//  |    radix_tree_node    |   |    radix_tree_node    |   |    radix_tree_node    |   |    radix_tree_node    |
			//  |   (kmem_cache#20-o4)  |   |   (kmem_cache#20-o5)  |   |   (kmem_cache#20-o6)  |   |   (kmem_cache#20-o7)  |
			//  +-----------------------+   +-----------------------+   +-----------------------+   +-----------------------+
			//  | height: 1 | count: 64 |   | height: 1 | count: 64 |   | height: 1 | count: 64 |   | height: 1 | count: 32 |
			//  +-----------------------+   +-----------------------+   +-----------------------+   +-----------------------+
			//  |    irq  192 ~ 255     |   |    irq 256 ~ 319      |   |    irq 320 ~ 383      |   |    irq 384 ~ 415      |
			//  +-----------------------+   +-----------------------+   +-----------------------+   +-----------------------+
			*/
			// irq 160...415까지의 struct irq_data에 값을 설정
			//
			// (&(kmem_cache#28-oX (irq 160...415))->irq_data)->hwirq: 0...255
			// (&(kmem_cache#28-oX (irq 160...415))->irq_data)->domain: kmem_cache#24-o0
			// (&(kmem_cache#28-oX (irq 160...415))->irq_data)->state_use_accessors: 0x10800
			//
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
			//
			// (&combiner_data[0])->base: 0xf0004000
			// (&combiner_data[0])->hwirq_offset: 0
			// (&combiner_data[0])->irq_mask: 0xff
			// (&combiner_data[0])->parent_irq: 32
			// group 0 의 interrupt disable 설정
			//
			// (&combiner_data[1])->base: 0xf0004000
			// (&combiner_data[1])->hwirq_offset: 0
			// (&combiner_data[1])->irq_mask: 0xff00
			// (&combiner_data[1])->parent_irq: 33
			// group 1 의 interrupt disable 설정
			//
			// (&combiner_data[2])->base: 0xf0004000
			// (&combiner_data[2])->hwirq_offset: 0
			// (&combiner_data[2])->irq_mask: 0xff0000
			// (&combiner_data[2])->parent_irq: 34
			// group 2 의 interrupt disable 설정
			//
			// (&combiner_data[3])->base: 0xf0004000
			// (&combiner_data[3])->hwirq_offset: 0
			// (&combiner_data[3])->irq_mask: 0xff000000
			// (&combiner_data[3])->parent_irq: 35
			// group 3 의 interrupt disable 설정
			//
			// (&combiner_data[4])->base: 0xf0004010
			// (&combiner_data[4])->hwirq_offset: 32
			// (&combiner_data[4])->irq_mask: 0xff
			// (&combiner_data[4])->parent_irq: 36
			// group 4 의 interrupt disable 설정
			//
			// .....
			//
			// (&combiner_data[31])->base: 0xf0004070
			// (&combiner_data[31])->hwirq_offset: 224
			// (&combiner_data[31])->irq_mask: 0xff000000
			// (&combiner_data[31])->parent_irq: 63
			// group 31 의 interrupt disable 설정
			//
			// (kmem_cache#28-oX (irq 32...63))->irq_data.handler_data: &combiner_data[0...31]
			// (kmem_cache#28-oX (irq 32...63))->handle_irq: combiner_handle_cascade_irq
			// (kmem_cache#28-oX (irq 32...63))->status_use_accessors: 0x31e00
			// (kmem_cache#28-oX (irq 32...63))->depth: 0
			// (&(kmem_cache#28-oX (irq 32...63))->irq_data)->state_use_accessors: 0x800
			//
			// register GICD_ISENABLER1 의 값을 세팅 하여 irq 32~63의 interrupt를 enable 시킴

			// [w1][f2] ret: 0
			// [w2][f1] ret: 0
			if (ret) {
				kfree(desc);
				continue;
			}

			/*
			 * This one is now set up; add it to the parent list so
			 * its children can get processed in a subsequent pass.
			 */
			// [w1][f2] &desc->list: &(kmem_cache#30-o11)->list
			// [w2][f1] &desc->list: &(kmem_cache#30-o10)->list
			list_add_tail(&desc->list, &intc_parent_list);
			// [w1][f2] intc_parent_list에 tail로 &(kmem_cache#30-o11)->list를 추가
			// [w2][f1] intc_parent_list에 tail로 &(kmem_cache#30-o10)->list를 추가
		}
		// [w1] &desc->list: &intc_desc_list 이므로 loop 탈출
		// [w2] &desc->list: &intc_desc_list 이므로 loop 탈출

		/* Get the next pending parent that might have children */
		// [w1] typeof(*desc): struct intc_desc
		// [w1] list_first_entry_or_null(&intc_parent_list, struct intc_desc, list):
		// [w1] (!list_empty(&intc_parent_list) ? list_first_entry(&intc_parent_list, struct intc_desc, list) : NULL)
		// [w1] list_first_entry(&intc_parent_list, struct intc_desc, list): kmem_cache#30-o11 (cortex_a15_gic)
		// [w2] typeof(*desc): struct intc_desc
		// [w2] list_first_entry_or_null(&intc_parent_list, struct intc_desc, list):
		// [w2] (!list_empty(&intc_parent_list) ? list_first_entry(&intc_parent_list, struct intc_desc, list) : NULL)
		// [w2] list_first_entry(&intc_parent_list, struct intc_desc, list): kmem_cache#30-o11 (exynos4210_combiner)
		desc = list_first_entry_or_null(&intc_parent_list,
						typeof(*desc), list);
		// [w1] desc: kmem_cache#30-o11 (cortex_a15_gic)
		// [w2] desc: kmem_cache#30-o10 (exynos4210_combiner)

		// [w1] desc: kmem_cache#30-o11 (cortex_a15_gic)
		// [w2] desc: kmem_cache#30-o10 (exynos4210_combiner)
		if (!desc) {
			pr_err("of_irq_init: children remain, but no parents\n");
			break;
		}

		// [w1] &desc->list: &(kmem_cache#30-o11 (cortex_a15_gic))->list
		// [w2] &desc->list: &(kmem_cache#30-o10 (exynos4210_combiner))->list
		list_del(&desc->list);
		// [w1] &(kmem_cache#30-o11 (cortex_a15_gic))->list에 연결된 list 삭제
		// [w2] &(kmem_cache#30-o10 (exynos4210_combiner))->list에 연결된 list 삭제

		// [w1] parent: NULL
		// [w1] desc->dev: (kmem_cache#30-o11)->dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		// [w2] parent: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		// [w2] desc->dev: (kmem_cache#30-o10)->dev: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
		parent = desc->dev;
		// [w1] parent: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		// [w2] parent: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소

		// [w1] desc: kmem_cache#30-o11 (cortex_a15_gic)
		// [w2] desc: kmem_cache#30-o10 (exynos4210_combiner)
		kfree(desc);

		// [w1] kfree (cortex_a15_gic) 에서 한일:
		// (kmem_cache#30)->cpu_slab: struct kmem_cache_cpu 자료구조를 사용하기 위해 할당받은 pcp 16 byte 메모리 공간을 구하여
		// kmem_cache#30-o11의 freepointer의 값을
		// ((kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)->freelist 값으로 세팅
		// 값 s->cpu_slab->freelist와 c->freelist를 비교, 값 s->cpu_slab->tid와 tid을 비교 하여
		// 같을 경우에 s->cpu_slab->freelist와 s->cpu_slab->tid을 각각 object, next_tid(tid) 값으로 갱신하여
		// freelist와 tid 값을 변경함
		// kmem_cache_cpu의 freelist, tid 의 값을 변경함

		// [w2] kfree (exynos4210_combiner) 에서 한일:
		// (kmem_cache#30)->cpu_slab: struct kmem_cache_cpu 자료구조를 사용하기 위해 할당받은 pcp 16 byte 메모리 공간을 구하여
		// kmem_cache#30-o10의 freepointer의 값을
		// ((kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)->freelist 값으로 세팅
		// 값 s->cpu_slab->freelist와 c->freelist를 비교, 값 s->cpu_slab->tid와 tid을 비교 하여
		// 같을 경우에 s->cpu_slab->freelist와 s->cpu_slab->tid을 각각 object, next_tid(tid) 값으로 갱신하여
		// freelist와 tid 값을 변경함
		// kmem_cache_cpu의 freelist, tid 의 값을 변경함

		// [w1] list_empty(&intc_desc_list): 0
		// [w2] list_empty(&intc_desc_list): 1
	}

	list_for_each_entry_safe(desc, temp_desc, &intc_parent_list, list) {
	// for (desc = list_first_entry(&intc_parent_list, typeof(*desc), list),
	// 	temp_desc = list_next_entry(desc, list); &desc->list != (&intc_parent_list);
	//      desc = temp_desc, temp_desc = list_next_entry(temp_desc, list))

		list_del(&desc->list);
		kfree(desc);
	}
err:
	list_for_each_entry_safe(desc, temp_desc, &intc_desc_list, list) {
	// for (desc = list_first_entry(&intc_desc_list, typeof(*desc), list),
	// 	temp_desc = list_next_entry(desc, list); &desc->list != (&intc_desc_list);
	//      desc = temp_desc, temp_desc = list_next_entry(temp_desc, list))

		list_del(&desc->list);
		kfree(desc);
	}
}
