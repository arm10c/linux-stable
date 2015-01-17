/*
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 * Copyright (c) 2013 Linaro Ltd.
 * Author: Thomas Abraham <thomas.ab@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This file includes utility functions to register clocks to common
 * clock framework for Samsung platforms.
*/

#include <linux/syscore_ops.h>
#include "clk.h"

static DEFINE_SPINLOCK(lock);
// ARM10C 20150110
// ARM10C 20150117
static struct clk **clk_table;
// ARM10C 20150110
static void __iomem *reg_base;
#ifdef CONFIG_OF // CONFIG_OF=y
// ARM10C 20150110
static struct clk_onecell_data clk_data;
#endif

#ifdef CONFIG_PM_SLEEP // CONFIG_PM_SLEEP=y
static struct samsung_clk_reg_dump *reg_dump;
// ARM10C 20150110
static unsigned long nr_reg_dump;

static int samsung_clk_suspend(void)
{
	struct samsung_clk_reg_dump *rd = reg_dump;
	unsigned long i;

	for (i = 0; i < nr_reg_dump; i++, rd++)
		rd->value = __raw_readl(reg_base + rd->offset);

	return 0;
}

static void samsung_clk_resume(void)
{
	struct samsung_clk_reg_dump *rd = reg_dump;
	unsigned long i;

	for (i = 0; i < nr_reg_dump; i++, rd++)
		__raw_writel(rd->value, reg_base + rd->offset);
}

// ARM10C 20150110
static struct syscore_ops samsung_clk_syscore_ops = {
	.suspend	= samsung_clk_suspend,
	.resume		= samsung_clk_resume,
};
#endif /* CONFIG_PM_SLEEP */

/* setup the essentials required to support clock lookup using ccf */
// ARM10C 20150110
// np: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소, reg_base: 0xf0040000, nr_clks: 769
// exynos5420_clk_regs, ARRAY_SIZE(exynos5420_clk_regs): 59, NULL, 0
void __init samsung_clk_init(struct device_node *np, void __iomem *base,
		unsigned long nr_clks, unsigned long *rdump,
		unsigned long nr_rdump, unsigned long *soc_rdump,
		unsigned long nr_soc_rdump)
{
	// base: 0xf0040000
	reg_base = base;
	// reg_base: 0xf0040000

#ifdef CONFIG_PM_SLEEP // CONFIG_PM_SLEEP=y
	// rdump: exynos5420_clk_regs, nr_rdump: 59
	if (rdump && nr_rdump) {
		unsigned int idx;

		// sizeof(struct samsung_clk_reg_dump): 8 bytes, nr_rdump: 59, nr_soc_rdump: 0
		// kzalloc(472, GFP_KERNEL: 0xD0): kmem_cache#26-oX
		reg_dump = kzalloc(sizeof(struct samsung_clk_reg_dump)
				* (nr_rdump + nr_soc_rdump), GFP_KERNEL);
		// reg_dump: kmem_cache#26-oX

		// reg_dump: kmem_cache#26-oX
		if (!reg_dump) {
			pr_err("%s: memory alloc for register dump failed\n",
					__func__);
			return;
		}

		// nr_rdump: 59
		for (idx = 0; idx < nr_rdump; idx++)
			// idx: 0, reg_dump[0].offset: (kmem_cache#26-oX)[0].offset, rdump[0]: exynos5420_clk_regs[0]
			reg_dump[idx].offset = rdump[idx];
			// reg_dump[0].offset: (kmem_cache#26-oX)[0].offset: exynos5420_clk_regs[0]
			//
			// idx: 1...58 까지 루프 수행

		// nr_soc_rdump: 0
		for (idx = 0; idx < nr_soc_rdump; idx++)
			reg_dump[nr_rdump + idx].offset = soc_rdump[idx];

		// nr_rdump: 59, nr_soc_rdump: 0
		nr_reg_dump = nr_rdump + nr_soc_rdump;
		// nr_reg_dump: 59

		register_syscore_ops(&samsung_clk_syscore_ops);

		// register_syscore_ops에서 한일:
		// syscore_ops_list의 tail에 (&samsung_clk_syscore_ops)->node 를 추가
	}
#endif

	// sizeof(struct clk *): 4, nr_clks: 769
	// kzalloc(3076, GFP_KERNEL: 0xD0): kmem_cache#23-o0
	clk_table = kzalloc(sizeof(struct clk *) * nr_clks, GFP_KERNEL);
	// clk_table: kmem_cache#23-o0

	// clk_table: kmem_cache#23-o0
	if (!clk_table)
		panic("could not allocate clock lookup table\n");

	// np: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소
	if (!np)
		return;

#ifdef CONFIG_OF // CONFIG_OF=y
	// clk_table: kmem_cache#23-o0
	clk_data.clks = clk_table;
	// clk_data.clks: kmem_cache#23-o0 (clk_table)

	// nr_clks: 769
	clk_data.clk_num = nr_clks;
	// clk_data.clk_num: 769

	// np: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소
	of_clk_add_provider(np, of_clk_src_onecell_get, &clk_data);

	// of_clk_add_provider에서 한일:
	// struct of_clk_provider 의 메모리(kmem_cache#30-oX)를 할당 받고 맴버값 초기화 수행
	//
	// (kmem_cache#30-oX)->node: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소
	// (kmem_cache#30-oX)->data: &clk_data
	// (kmem_cache#30-oX)->get: of_clk_src_onecell_get
	//
	// list인 of_clk_providers의 head에 (kmem_cache#30-oX)->link를 추가
#endif
}

/* add a clock instance to the clock lookup table used for dt based lookup */
// ARM10C 20150117
// clk: kmem_cache#29-oX, list->id: exynos5420_fixed_rate_ext_clks.id: 1
void samsung_clk_add_lookup(struct clk *clk, unsigned int id)
{
	// clk_table: kmem_cache#23-o0, id: 1
	if (clk_table && id)
		// clk_table: kmem_cache#23-o0, id: 1, clk_table[1]: (kmem_cache#23-o0)[1],
		// clk: kmem_cache#29-oX
		clk_table[id] = clk;
		// clk_table[1]: (kmem_cache#23-o0)[1]: kmem_cache#29-oX
}

/* register a list of aliases */
void __init samsung_clk_register_alias(struct samsung_clock_alias *list,
					unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx, ret;

	if (!clk_table) {
		pr_err("%s: clock table missing\n", __func__);
		return;
	}

	for (idx = 0; idx < nr_clk; idx++, list++) {
		if (!list->id) {
			pr_err("%s: clock id missing for index %d\n", __func__,
				idx);
			continue;
		}

		clk = clk_table[list->id];
		if (!clk) {
			pr_err("%s: failed to find clock %d\n", __func__,
				list->id);
			continue;
		}

		ret = clk_register_clkdev(clk, list->alias, list->dev_name);
		if (ret)
			pr_err("%s: failed to register lookup %s\n",
					__func__, list->alias);
	}
}

/* register a list of fixed clocks */
// ARM10C 20150110
// fixed_rate_clk: exynos5420_fixed_rate_ext_clks, nr_fixed_rate_clk: 1
void __init samsung_clk_register_fixed_rate(
		struct samsung_fixed_rate_clock *list, unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx, ret;

	// nr_clk: 1
	for (idx = 0; idx < nr_clk; idx++, list++) {

		// list->name: exynos5420_fixed_rate_ext_clks.name: "fin_pll",
		// list->parent_name: exynos5420_fixed_rate_ext_clks.parent_name: NULL,
		// list->flags: exynos5420_fixed_rate_ext_clks.flags: CLK_IS_ROOT,
		// list->fixed_rate: exynos5420_fixed_rate_ext_clks.fixed_rate: 24000000
		// clk_register_fixed_rate(NULL, "fin_pll", NULL, CLK_IS_ROOT: 0x10, 24000000): kmem_cache#29-oX
		clk = clk_register_fixed_rate(NULL, list->name,
			list->parent_name, list->flags, list->fixed_rate);
		// clk: kmem_cache#29-oX

		// clk_register_fixed_rate 에서 한일:
		// struct clk_fixed_rate 만큼 메모리를 kmem_cache#30-oX 할당 받고 struct clk_fixed_rate 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->fixed_rate: 24000000
		// (kmem_cache#30-oX)->hw.init: &init
		// (&(kmem_cache#30-oX)->hw)->clk: kmem_cache#29-oX
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX)->name: kmem_cache#30-oX ("fin_pll")
		// (kmem_cache#29-oX)->ops: &clk_fixed_rate_ops
		// (kmem_cache#29-oX)->hw: &(kmem_cache#30-oX)->hw
		// (kmem_cache#29-oX)->flags: 0x30
		// (kmem_cache#29-oX)->num_parents: 0
		// (kmem_cache#29-oX)->parent_names: ((void *)16)
		// (kmem_cache#29-oX)->parent: NULL
		// (kmem_cache#29-oX)->rate: 24000000
		//
		// (&(kmem_cache#29-oX)->child_node)->next: NULL
		// (&(kmem_cache#29-oX)->child_node)->pprev: &(&(kmem_cache#29-oX)->child_node)
		//
		// (&clk_root_list)->first: &(kmem_cache#29-oX)->child_node

		// clk: kmem_cache#29-oX
		// IS_ERR(kmem_cache#29-oX): 0
		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		// clk: kmem_cache#29-oX, list->id: exynos5420_fixed_rate_ext_clks.id: 1 (fin_pll)
		samsung_clk_add_lookup(clk, list->id);

		// samsung_clk_add_lookup에서 한일
		// clk_table[1]: (kmem_cache#23-o0)[1]: kmem_cache#29-oX

		/*
		 * Unconditionally add a clock lookup for the fixed rate clocks.
		 * There are not many of these on any of Samsung platforms.
		 */
		// clk: kmem_cache#29-oX, list->name: exynos5420_fixed_rate_ext_clks.name: "fin_pll"
		// clk_register_clkdev(kmem_cache#29-oX, "fin_pll", NULL): 0
		ret = clk_register_clkdev(clk, list->name, NULL);
		// ret: 0

		// clk_register_clkdev에서 한일:
		// struct clk_lookup_alloc 의 메모리를 kmem_cache#30-oX 할당 받고
		// struct clk_lookup_alloc 맴버값 초기화 수행
		//
		// (kmem_cache#30-oX)->cl.clk: kmem_cache#29-oX
		// (kmem_cache#30-oX)->con_id: "fin_pll"
		// (kmem_cache#30-oX)->cl.con_id: (kmem_cache#30-oX)->con_id: "fin_pll"
		//
		// list clocks에 &(&(kmem_cache#30-oX)->cl)->nade를 tail로 추가

		// ret: 0
		if (ret)
			pr_err("%s: failed to register clock lookup for %s",
				__func__, list->name);
	}
}

/* register a list of fixed factor clocks */
void __init samsung_clk_register_fixed_factor(
		struct samsung_fixed_factor_clock *list, unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx;

	for (idx = 0; idx < nr_clk; idx++, list++) {
		clk = clk_register_fixed_factor(NULL, list->name,
			list->parent_name, list->flags, list->mult, list->div);
		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		samsung_clk_add_lookup(clk, list->id);
	}
}

/* register a list of mux clocks */
void __init samsung_clk_register_mux(struct samsung_mux_clock *list,
					unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx, ret;

	for (idx = 0; idx < nr_clk; idx++, list++) {
		clk = clk_register_mux(NULL, list->name, list->parent_names,
			list->num_parents, list->flags, reg_base + list->offset,
			list->shift, list->width, list->mux_flags, &lock);
		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		samsung_clk_add_lookup(clk, list->id);

		/* register a clock lookup only if a clock alias is specified */
		if (list->alias) {
			ret = clk_register_clkdev(clk, list->alias,
						list->dev_name);
			if (ret)
				pr_err("%s: failed to register lookup %s\n",
						__func__, list->alias);
		}
	}
}

/* register a list of div clocks */
void __init samsung_clk_register_div(struct samsung_div_clock *list,
					unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx, ret;

	for (idx = 0; idx < nr_clk; idx++, list++) {
		if (list->table)
			clk = clk_register_divider_table(NULL, list->name,
					list->parent_name, list->flags,
					reg_base + list->offset, list->shift,
					list->width, list->div_flags,
					list->table, &lock);
		else
			clk = clk_register_divider(NULL, list->name,
					list->parent_name, list->flags,
					reg_base + list->offset, list->shift,
					list->width, list->div_flags, &lock);
		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		samsung_clk_add_lookup(clk, list->id);

		/* register a clock lookup only if a clock alias is specified */
		if (list->alias) {
			ret = clk_register_clkdev(clk, list->alias,
						list->dev_name);
			if (ret)
				pr_err("%s: failed to register lookup %s\n",
						__func__, list->alias);
		}
	}
}

/* register a list of gate clocks */
void __init samsung_clk_register_gate(struct samsung_gate_clock *list,
						unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx, ret;

	for (idx = 0; idx < nr_clk; idx++, list++) {
		clk = clk_register_gate(NULL, list->name, list->parent_name,
				list->flags, reg_base + list->offset,
				list->bit_idx, list->gate_flags, &lock);
		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		/* register a clock lookup only if a clock alias is specified */
		if (list->alias) {
			ret = clk_register_clkdev(clk, list->alias,
							list->dev_name);
			if (ret)
				pr_err("%s: failed to register lookup %s\n",
					__func__, list->alias);
		}

		samsung_clk_add_lookup(clk, list->id);
	}
}

/*
 * obtain the clock speed of all external fixed clock sources from device
 * tree and register it
 */
#ifdef CONFIG_OF // CONFIG_OF=y
// ARM10C 20150110
// exynos5420_fixed_rate_ext_clks, ARRAY_SIZE(exynos5420_fixed_rate_ext_clks): 1, ext_clk_match
void __init samsung_clk_of_register_fixed_ext(
			struct samsung_fixed_rate_clock *fixed_rate_clk,
			unsigned int nr_fixed_rate_clk,
			struct of_device_id *clk_matches)
{
	const struct of_device_id *match;
	struct device_node *np;
	u32 freq;

	// clk_matches: ext_clk_match
	for_each_matching_node_and_match(np, clk_matches, &match) {
	// for (np = of_find_matching_node_and_match(NULL, clk_matches, &match);
	//      np; np = of_find_matching_node_and_match(np, clk_matches, &match))

		// np: devtree에서 allnext로 순회 하면서 찾은 fixed-rate-clocks node의 주소, match: &ext_clk_match[0]

		// np: devtree에서 allnext로 순회 하면서 찾은 fixed-rate-clocks node의 주소
		// of_property_read_u32(devtree에서 allnext로 순회 하면서 찾은 fixed-rate-clocks node의 주소, "clock-frequency", &freq)): 0
		if (of_property_read_u32(np, "clock-frequency", &freq))
			continue;

		// of_property_read_u32에서 한일:
		// fixed-rate-clocks node에서 "clock-frequency" property값을 freq에 읽어옴
		// freq: 24000000

		// fixed_rate_clk: exynos5420_fixed_rate_ext_clks
		// match->data: (&ext_clk_match[0])->data: 0
		// exynos5420_fixed_rate_ext_clks[0].fixed_rate, freq: 24000000
		fixed_rate_clk[(u32)match->data].fixed_rate = freq;
		// exynos5420_fixed_rate_ext_clks[0].fixed_rate: 24000000
	}
	
	// fixed_rate_clk: exynos5420_fixed_rate_ext_clks, nr_fixed_rate_clk: 1
	samsung_clk_register_fixed_rate(fixed_rate_clk, nr_fixed_rate_clk);

	// samsung_clk_register_fixed_rate 에서 한일:
	// struct clk_fixed_rate 만큼 메모리를 kmem_cache#30-oX 할당 받고 struct clk_fixed_rate 의 멤버 값을 아래와 같이 초기화 수행
	//
	// (kmem_cache#30-oX)->fixed_rate: 24000000
	// (kmem_cache#30-oX)->hw.init: &init
	// (&(kmem_cache#30-oX)->hw)->clk: kmem_cache#29-oX
	//
	// struct clk 만큼 메모리를 kmem_cache#29-oX 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
	//
	// (kmem_cache#29-oX)->name: kmem_cache#30-oX ("fin_pll")
	// (kmem_cache#29-oX)->ops: &clk_fixed_rate_ops
	// (kmem_cache#29-oX)->hw: &(kmem_cache#30-oX)->hw
	// (kmem_cache#29-oX)->flags: 0x30
	// (kmem_cache#29-oX)->num_parents: 0
	// (kmem_cache#29-oX)->parent_names: ((void *)16)
	// (kmem_cache#29-oX)->parent: NULL
	// (kmem_cache#29-oX)->rate: 24000000
	//
	// (&(kmem_cache#29-oX)->child_node)->next: NULL
	// (&(kmem_cache#29-oX)->child_node)->pprev: &(&(kmem_cache#29-oX)->child_node)
	//
	// (&clk_root_list)->first: &(kmem_cache#29-oX)->child_node
	//
	// clk_table[1]: (kmem_cache#23-o0)[1]: kmem_cache#29-oX
	//
	// struct clk_lookup_alloc 의 메모리를 kmem_cache#30-oX 할당 받고
	// struct clk_lookup_alloc 맴버값 초기화 수행
	//
	// (kmem_cache#30-oX)->cl.clk: kmem_cache#29-oX
	// (kmem_cache#30-oX)->con_id: "fin_pll"
	// (kmem_cache#30-oX)->cl.con_id: (kmem_cache#30-oX)->con_id: "fin_pll"
	//
	// list clocks에 &(&(kmem_cache#30-oX)->cl)->nade를 tail로 추가
}
#endif

/* utility function to get the rate of a specified clock */
unsigned long _get_rate(const char *clk_name)
{
	struct clk *clk;

	clk = __clk_lookup(clk_name);
	if (!clk) {
		pr_err("%s: could not find clock %s\n", __func__, clk_name);
		return 0;
	}

	return clk_get_rate(clk);
}
