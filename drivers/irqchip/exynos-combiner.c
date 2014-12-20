/*
 * Copyright (c) 2010-2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Combiner irqchip for EXYNOS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/err.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/irqdomain.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <asm/mach/irq.h>

#include "irqchip.h"

#define COMBINER_ENABLE_SET	0x0
// ARM10C 20141213
// COMBINER_ENABLE_CLEAR: 0x4
#define COMBINER_ENABLE_CLEAR	0x4
#define COMBINER_INT_STATUS	0xC

// ARM10C 20141206
// ARM10C 20141213
// IRQ_IN_COMBINER: 8
#define IRQ_IN_COMBINER		8

static DEFINE_SPINLOCK(irq_controller_lock);

// ARM10C 20141206
// ARM10C 20141213
// sizeof(struct combiner_chip_data): 16 bytes
struct combiner_chip_data {
	unsigned int hwirq_offset;
	unsigned int irq_mask;
	void __iomem *base;
	unsigned int parent_irq;
};

// ARM10C 20141206
static struct irq_domain *combiner_irq_domain;

static inline void __iomem *combiner_base(struct irq_data *data)
{
	struct combiner_chip_data *combiner_data =
		irq_data_get_irq_chip_data(data);

	return combiner_data->base;
}

static void combiner_mask_irq(struct irq_data *data)
{
	u32 mask = 1 << (data->hwirq % 32);

	__raw_writel(mask, combiner_base(data) + COMBINER_ENABLE_CLEAR);
}

static void combiner_unmask_irq(struct irq_data *data)
{
	u32 mask = 1 << (data->hwirq % 32);

	__raw_writel(mask, combiner_base(data) + COMBINER_ENABLE_SET);
}

// ARM10C 20141220
static void combiner_handle_cascade_irq(unsigned int irq, struct irq_desc *desc)
{
	struct combiner_chip_data *chip_data = irq_get_handler_data(irq);
	struct irq_chip *chip = irq_get_chip(irq);
	unsigned int cascade_irq, combiner_irq;
	unsigned long status;

	chained_irq_enter(chip, desc);

	spin_lock(&irq_controller_lock);
	status = __raw_readl(chip_data->base + COMBINER_INT_STATUS);
	spin_unlock(&irq_controller_lock);
	status &= chip_data->irq_mask;

	if (status == 0)
		goto out;

	combiner_irq = chip_data->hwirq_offset + __ffs(status);
	cascade_irq = irq_find_mapping(combiner_irq_domain, combiner_irq);

	if (unlikely(!cascade_irq))
		do_bad_IRQ(irq, desc);
	else
		generic_handle_irq(cascade_irq);

 out:
	chained_irq_exit(chip, desc);
}

#ifdef CONFIG_SMP
static int combiner_set_affinity(struct irq_data *d,
				 const struct cpumask *mask_val, bool force)
{
	struct combiner_chip_data *chip_data = irq_data_get_irq_chip_data(d);
	struct irq_chip *chip = irq_get_chip(chip_data->parent_irq);
	struct irq_data *data = irq_get_irq_data(chip_data->parent_irq);

	if (chip && chip->irq_set_affinity)
		return chip->irq_set_affinity(data, mask_val, force);
	else
		return -EINVAL;
}
#endif

// ARM10C 20141213
static struct irq_chip combiner_chip = {
	.name			= "COMBINER",
	.irq_mask		= combiner_mask_irq,
	.irq_unmask		= combiner_unmask_irq,
#ifdef CONFIG_SMP // CONFIG_SMP=y
	.irq_set_affinity	= combiner_set_affinity,
#endif
};

// ARM10C 20141220
// &combiner_data[0], irq: 32
static void __init combiner_cascade_irq(struct combiner_chip_data *combiner_data,
					unsigned int irq)
{
	// irq: 32, combiner_data: &combiner_data[0]
	if (irq_set_handler_data(irq, combiner_data) != 0)
		BUG();

	// irq_set_handler_data(32) 에서 한일:
	// (kmem_cache#28-oX (irq 32))->irq_data.handler_data: &combiner_data[0]

	// irq: 32
	irq_set_chained_handler(irq, combiner_handle_cascade_irq);

	// irq_set_chained_handler에서 한일:
	// (kmem_cache#28-oX (irq 32))->handle_irq: combiner_handle_cascade_irq
	// (kmem_cache#28-oX (irq 32))->status_use_accessors: 0x31e00
	// (kmem_cache#28-oX (irq 32))->depth: 0
	// (&(kmem_cache#28-oX (irq 32))->irq_data)->state_use_accessors: 0x800
	//
	// register GICD_ISENABLER1 의 값을 세팅 하여 irq 32의 interrupt를 enable 시킴
}

// ARM10C 20141213
// &combiner_data[0], i: 0, combiner_base: 0xf0004000, irq: 32
static void __init combiner_init_one(struct combiner_chip_data *combiner_data,
				     unsigned int combiner_nr,
				     void __iomem *base, unsigned int irq)
{
	// combiner_data->base: (&combiner_data[0])->base, base: 0xf0004000
	combiner_data->base = base;
	// combiner_data->base: (&combiner_data[0])->base: 0xf0004000

	// combiner_data->hwirq_offset: (&combiner_data[0])->hwirq_offset,
	// combiner_nr: 0, IRQ_IN_COMBINER: 8
	combiner_data->hwirq_offset = (combiner_nr & ~3) * IRQ_IN_COMBINER;
	// combiner_data->hwirq_offset: (&combiner_data[0])->hwirq_offset: 0

	// combiner_data->irq_mask: (&combiner_data[0])->irq_mask, combiner_nr: 0
	combiner_data->irq_mask = 0xff << ((combiner_nr % 4) << 3);
	// combiner_data->irq_mask: (&combiner_data[0])->irq_mask: 0xff

	// combiner_data->parent_irq: (&combiner_data[0])->parent_irq, irq: 32
	combiner_data->parent_irq = irq;
	// combiner_data->parent_irq: (&combiner_data[0])->parent_irq: 32

	// NOTE:
	// E.R.M: exynos5 reference manual의 약자로 정의함

	/* Disable all interrupts */
	// E.R.M: 7.5.1.2 IECR0
	// Interrupt enable clear register for group 0 to 3

	// combiner_data->irq_mask: (&combiner_data[0])->irq_mask: 0xff
	// base: 0xf0004000, COMBINER_ENABLE_CLEAR: 0x4
	__raw_writel(combiner_data->irq_mask, base + COMBINER_ENABLE_CLEAR);
	// 0xff 값의 의미: group 0 의 interrupt disable 설정

// 2014/12/13 종료
// 2014/12/20 시작
}

static int combiner_irq_domain_xlate(struct irq_domain *d,
				     struct device_node *controller,
				     const u32 *intspec, unsigned int intsize,
				     unsigned long *out_hwirq,
				     unsigned int *out_type)
{
	if (d->of_node != controller)
		return -EINVAL;

	if (intsize < 2)
		return -EINVAL;

	*out_hwirq = intspec[0] * IRQ_IN_COMBINER + intspec[1];
	*out_type = 0;

	return 0;
}

// ARM10C 20141213
// kmem_cache#24-o0, 160, 0
static int combiner_irq_domain_map(struct irq_domain *d, unsigned int irq,
				   irq_hw_number_t hw)
{
	// d->host_data: (kmem_cache#24-o0)->host_data: kmem_cache#26-oX (combiner_data)
	struct combiner_chip_data *combiner_data = d->host_data;
	// combiner_data: kmem_cache#26-oX (combiner_data)

	// irq: 160
	irq_set_chip_and_handler(irq, &combiner_chip, handle_level_irq);

	// irq_set_chip_and_handler(160)에서 한일:
	// (kmem_cache#28-oX (irq 160))->irq_data.chip: &combiner_chip
	// (kmem_cache#28-oX (irq 160))->handle_irq: handle_level_irq
	// (kmem_cache#28-oX (irq 160))->name: NULL

	// irq: 160, hw: 0, &combiner_data[0]: &(kmem_cache#26-oX)[0]
	irq_set_chip_data(irq, &combiner_data[hw >> 3]);

	// irq_set_chip_data(160)에서 한일:
	// (kmem_cache#28-oX (irq 160))->irq_data.chip_data: &(kmem_cache#26-oX)[0] (combiner_data)

	// irq: 160, IRQF_VALID: 1, IRQF_PROBE: 0x2
	set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);

	// set_irq_flags(160)에서 한일:
	// (kmem_cache#28-oX (irq 160))->status_use_accessors: 0x31600
	// (&(kmem_cache#28-oX (irq 160))->irq_data)->state_use_accessors: 0x10800

	return 0;
	// return 0
}

// ARM10C 20141206
static struct irq_domain_ops combiner_irq_domain_ops = {
	.xlate	= combiner_irq_domain_xlate,
	.map	= combiner_irq_domain_map,
};

// ARM10C 20141206
// combiner_base: 0xf0004000, np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소,
// max_nr: 32, irq_base: 160
static void __init combiner_init(void __iomem *combiner_base,
				 struct device_node *np,
				 unsigned int max_nr,
				 int irq_base)
{
	int i, irq;
	unsigned int nr_irq;
	struct combiner_chip_data *combiner_data;

	// max_nr: 32, IRQ_IN_COMBINER: 8
	nr_irq = max_nr * IRQ_IN_COMBINER;
	// nr_irq: 256

	// max_nr: 32, sizeof(struct combiner_chip_data): 16 bytes, GFP_KERNEL: 0xD0
	// kcalloc(32, 16, GFP_KERNEL: 0xD0): kmem_cache#26-oX
	combiner_data = kcalloc(max_nr, sizeof (*combiner_data), GFP_KERNEL);
	// combiner_data: kmem_cache#26-oX

	// combiner_data: kmem_cache#26-oX
	if (!combiner_data) {
		pr_warning("%s: could not allocate combiner data\n", __func__);
		return;
	}

	// np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소,
	// nr_irq: 256, irq_base: 160, combiner_data: kmem_cache#26-oX
	// irq_domain_add_simple(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, 256
	// 160, &combiner_irq_domain_ops, kmem_cache#26-oX (combiner_data): kmem_cache#24-o0
	combiner_irq_domain = irq_domain_add_simple(np, nr_irq, irq_base,
				&combiner_irq_domain_ops, combiner_data);
	// combiner_irq_domain: kmem_cache#24-o0

	// irq_domain_add_simple에서 한일:
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

	// combiner_irq_domain: kmem_cache#24-o0
	if (WARN_ON(!combiner_irq_domain)) {
		pr_warning("%s: irq domain init failed\n", __func__);
		return;
	}

	// max_nr: 32
	for (i = 0; i < max_nr; i++) {
		// np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, i: 0
		// irq_of_parse_and_map(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, 0): 32
		irq = irq_of_parse_and_map(np, i);
		// irq: 32

		// i: 0, &combiner_data[0], combiner_base: 0xf0004000, irq: 32
		combiner_init_one(&combiner_data[i], i,
				  combiner_base + (i >> 2) * 0x10, irq);

		// combiner_init_one에서 한일:
		// (&combiner_data[0])->base: 0xf0004000
		// (&combiner_data[0])->hwirq_offset: 0
		// (&combiner_data[0])->irq_mask: 0xff
		// (&combiner_data[0])->parent_irq: 32
		// group 0 의 interrupt disable 설정

		// i: 0, &combiner_data[0], irq: 32
		combiner_cascade_irq(&combiner_data[i], irq);

		// combiner_cascade_irq에서 한일:
		// (kmem_cache#28-oX (irq 32))->irq_data.handler_data: &combiner_data[0]
		// (kmem_cache#28-oX (irq 32))->handle_irq: combiner_handle_cascade_irq
		// (kmem_cache#28-oX (irq 32))->status_use_accessors: 0x31e00
		// (kmem_cache#28-oX (irq 32))->depth: 0
		// (&(kmem_cache#28-oX (irq 32))->irq_data)->state_use_accessors: 0x800
		//
		// register GICD_ISENABLER1 의 값을 세팅 하여 irq 32의 interrupt를 enable 시킴
		
		// i: 1 ... 31 수행
	}

	// 위 loop의 수행결과:
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
	// (&combiner_data[5])->base: 0xf0004010
	// (&combiner_data[5])->hwirq_offset: 32
	// (&combiner_data[5])->irq_mask: 0xff00
	// (&combiner_data[5])->parent_irq: 37
	// group 5 의 interrupt disable 설정
	//
	// (&combiner_data[6])->base: 0xf0004010
	// (&combiner_data[6])->hwirq_offset: 32
	// (&combiner_data[6])->irq_mask: 0xff0000
	// (&combiner_data[6])->parent_irq: 38
	// group 6 의 interrupt disable 설정
	//
	// (&combiner_data[7])->base: 0xf0004010
	// (&combiner_data[7])->hwirq_offset: 32
	// (&combiner_data[7])->irq_mask: 0xff000000
	// (&combiner_data[7])->parent_irq: 39
	// group 7 의 interrupt disable 설정
	//
	// (&combiner_data[8])->base: 0xf0004020
	// (&combiner_data[8])->hwirq_offset: 64
	// (&combiner_data[8])->irq_mask: 0xff
	// (&combiner_data[8])->parent_irq: 40
	// group 8 의 interrupt disable 설정
	//
	// (&combiner_data[9])->base: 0xf0004020
	// (&combiner_data[9])->hwirq_offset: 64
	// (&combiner_data[9])->irq_mask: 0xff00
	// (&combiner_data[9])->parent_irq: 41
	// group 9 의 interrupt disable 설정
	//
	// (&combiner_data[10])->base: 0xf0004020
	// (&combiner_data[10])->hwirq_offset: 64
	// (&combiner_data[10])->irq_mask: 0xff0000
	// (&combiner_data[10])->parent_irq: 42
	// group 10 의 interrupt disable 설정
	//
	// (&combiner_data[11])->base: 0xf0004020
	// (&combiner_data[11])->hwirq_offset: 64
	// (&combiner_data[11])->irq_mask: 0xff000000
	// (&combiner_data[11])->parent_irq: 43
	// group 11 의 interrupt disable 설정
	//
	// (&combiner_data[12])->base: 0xf0004030
	// (&combiner_data[12])->hwirq_offset: 96
	// (&combiner_data[12])->irq_mask: 0xff
	// (&combiner_data[12])->parent_irq: 44
	// group 12 의 interrupt disable 설정
	//
	// (&combiner_data[13])->base: 0xf0004030
	// (&combiner_data[13])->hwirq_offset: 96
	// (&combiner_data[13])->irq_mask: 0xff00
	// (&combiner_data[13])->parent_irq: 45
	// group 13 의 interrupt disable 설정
	//
	// (&combiner_data[14])->base: 0xf0004030
	// (&combiner_data[14])->hwirq_offset: 96
	// (&combiner_data[14])->irq_mask: 0xff0000
	// (&combiner_data[14])->parent_irq: 46
	// group 14 의 interrupt disable 설정
	//
	// (&combiner_data[15])->base: 0xf0004030
	// (&combiner_data[15])->hwirq_offset: 96
	// (&combiner_data[15])->irq_mask: 0xff000000
	// (&combiner_data[15])->parent_irq: 47
	// group 15 의 interrupt disable 설정
	//
	// (&combiner_data[16])->base: 0xf0004040
	// (&combiner_data[16])->hwirq_offset: 128
	// (&combiner_data[16])->irq_mask: 0xff
	// (&combiner_data[16])->parent_irq: 48
	// group 16 의 interrupt disable 설정
	//
	// (&combiner_data[17])->base: 0xf0004040
	// (&combiner_data[17])->hwirq_offset: 128
	// (&combiner_data[17])->irq_mask: 0xff00
	// (&combiner_data[17])->parent_irq: 49
	// group 17 의 interrupt disable 설정
	//
	// (&combiner_data[18])->base: 0xf0004040
	// (&combiner_data[18])->hwirq_offset: 128
	// (&combiner_data[18])->irq_mask: 0xff0000
	// (&combiner_data[18])->parent_irq: 50
	// group 18 의 interrupt disable 설정
	//
	// (&combiner_data[19])->base: 0xf0004040
	// (&combiner_data[19])->hwirq_offset: 128
	// (&combiner_data[19])->irq_mask: 0xff000000
	// (&combiner_data[19])->parent_irq: 51
	// group 19 의 interrupt disable 설정
	//
	// (&combiner_data[20])->base: 0xf0004050
	// (&combiner_data[20])->hwirq_offset: 160
	// (&combiner_data[20])->irq_mask: 0xff
	// (&combiner_data[20])->parent_irq: 52
	// group 20 의 interrupt disable 설정
	//
	// (&combiner_data[21])->base: 0xf0004050
	// (&combiner_data[21])->hwirq_offset: 160
	// (&combiner_data[21])->irq_mask: 0xff00
	// (&combiner_data[21])->parent_irq: 53
	// group 21 의 interrupt disable 설정
	//
	// (&combiner_data[22])->base: 0xf0004050
	// (&combiner_data[22])->hwirq_offset: 160
	// (&combiner_data[22])->irq_mask: 0xff0000
	// (&combiner_data[22])->parent_irq: 54
	// group 22 의 interrupt disable 설정
	//
	// (&combiner_data[23])->base: 0xf0004050
	// (&combiner_data[23])->hwirq_offset: 160
	// (&combiner_data[23])->irq_mask: 0xff000000
	// (&combiner_data[23])->parent_irq: 55
	// group 23 의 interrupt disable 설정
	//
	// (&combiner_data[24])->base: 0xf0004060
	// (&combiner_data[24])->hwirq_offset: 192
	// (&combiner_data[24])->irq_mask: 0xff
	// (&combiner_data[24])->parent_irq: 56
	// group 24 의 interrupt disable 설정
	//
	// (&combiner_data[25])->base: 0xf0004060
	// (&combiner_data[25])->hwirq_offset: 192
	// (&combiner_data[25])->irq_mask: 0xff00
	// (&combiner_data[25])->parent_irq: 57
	// group 25 의 interrupt disable 설정
	//
	// (&combiner_data[26])->base: 0xf0004060
	// (&combiner_data[26])->hwirq_offset: 192
	// (&combiner_data[26])->irq_mask: 0xff0000
	// (&combiner_data[26])->parent_irq: 58
	// group 26 의 interrupt disable 설정
	//
	// (&combiner_data[27])->base: 0xf0004060
	// (&combiner_data[27])->hwirq_offset: 192
	// (&combiner_data[27])->irq_mask: 0xff000000
	// (&combiner_data[27])->parent_irq: 59
	// group 27 의 interrupt disable 설정
	//
	// (&combiner_data[28])->base: 0xf0004070
	// (&combiner_data[28])->hwirq_offset: 224
	// (&combiner_data[28])->irq_mask: 0xff
	// (&combiner_data[28])->parent_irq: 60
	// group 28 의 interrupt disable 설정
	//
	// (&combiner_data[29])->base: 0xf0004070
	// (&combiner_data[29])->hwirq_offset: 224
	// (&combiner_data[29])->irq_mask: 0xff00
	// (&combiner_data[29])->parent_irq: 61
	// group 29 의 interrupt disable 설정
	//
	// (&combiner_data[30])->base: 0xf0004070
	// (&combiner_data[30])->hwirq_offset: 224
	// (&combiner_data[30])->irq_mask: 0xff0000
	// (&combiner_data[30])->parent_irq: 62
	// group 30 의 interrupt disable 설정
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
	// register GICD_ISENABLER1 의 값을 세팅 하여 irq 32의 interrupt를 enable 시킴
}

// ARM10C 20141206
// desc->dev: (kmem_cache#30-o10)->dev: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소,
// desc->interrupt_parent: (kmem_cache#30-o10)->interrupt_parent: NULL
static int __init combiner_of_init(struct device_node *np,
				   struct device_node *parent)
{
	void __iomem *combiner_base;
	unsigned int max_nr = 20;
	// max_nr: 20

	int irq_base = -1;
	// irq_base: -1

	// np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	// of_iomap(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, 0): 0xf0004000
	combiner_base = of_iomap(np, 0);
	// combiner_base: 0xf0004000

	// of_iomap에서 한일:
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

	// combiner_base: 0xf0004000
	if (!combiner_base) {
		pr_err("%s: failed to map combiner registers\n", __func__);
		return -ENXIO;
	}

	// np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, max_nr: 20
	// of_property_read_u32(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, &max_nr): 0
	if (of_property_read_u32(np, "samsung,combiner-nr", &max_nr)) {
		pr_info("%s: number of combiners not specified, "
			"setting default as %d.\n",
			__func__, max_nr);
	}
	// of_property_read_u32에서 한일:
	// devtree에서 allnext로 순회 하면서 찾은 combiner node의 property "samsung,combiner-nr"
	// 값을 max_nr에 가져옴
	// max_nr: 32 (exynos5.dtsi 참고)


	/*
	 * FIXME: This is a hardwired COMBINER_IRQ(0,0). Once all devices
	 * get their IRQ from DT, remove this in order to get dynamic
	 * allocation.
	 */
	// irq_base: -1
	irq_base = 160;
	// irq_base: 160;

	// combiner_base: 0xf0004000, np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소,
	// max_nr: 32, irq_base: 160;
	combiner_init(combiner_base, np, max_nr, irq_base);

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
	// register GICD_ISENABLER1 의 값을 세팅 하여 irq 32의 interrupt를 enable 시킴

	return 0;
}

// ARM10C 20141004
// #define IRQCHIP_DECLARE(exynos4210_combiner, "samsung,exynos4210-combiner", combiner_of_init):
// 	static const struct of_device_id irqchip_of_match_exynos4210_combiner
// 	__used __section(__irqchip_of_table)
// 	= { .compatible = "samsung,exynos4210-combiner", .data = combiner_of_init }
IRQCHIP_DECLARE(exynos4210_combiner, "samsung,exynos4210-combiner",
		combiner_of_init);
