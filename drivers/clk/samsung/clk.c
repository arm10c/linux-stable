o/*
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

// ARM10C 20150131
// ARM10C 20150228
static DEFINE_SPINLOCK(lock);
// ARM10C 20150110
// ARM10C 20150117
static struct clk **clk_table;
// ARM10C 20150110
// ARM10C 20150228
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
// ARM10C 20150124
// clk: kmem_cache#29-oX (apll), pll_clk->id: (&exynos5420_plls[0])->id: fout_apll: 2
// ARM10C 20150124
// clk: kmem_cache#29-oX (epll), pll_clk->id: (&exynos5420_plls[3])->id: fout_epll: 5
// ARM10C 20150131
// clk: kmem_cache#29-oX (mout_mspll_kfc), list->id: exynos5420_mux_clks[0].id: 0
// ARM10C 20150228
// clk: kmem_cache#29-oX (sclk_dpll), list->id: exynos5420_mux_clks[44].id: 0
// ARM10C 20150307
// clk: kmem_cache#29-oX (sclk_apll), list->id: exynos5420_div_clks[1].id: 0
// ARM10C 20150307
// clk: kmem_cache#29-oX (sclk_fimd1), list->id: exynos5420_gate_clks[13].id: 128
void samsung_clk_add_lookup(struct clk *clk, unsigned int id)
{
	// clk_table: kmem_cache#23-o0, id: 1
	// clk_table: kmem_cache#23-o0, id: 2
	// clk_table: kmem_cache#23-o0, id: 5
	// clk_table: kmem_cache#23-o0, id: 0
	// clk_table: kmem_cache#23-o0, id: 0
	// clk_table: kmem_cache#23-o0, id: 0
	// clk_table: kmem_cache#23-o0, id: 128
	if (clk_table && id)
		// clk_table: kmem_cache#23-o0, id: 1, clk_table[1]: (kmem_cache#23-o0)[1],
		// clk: kmem_cache#29-oX
		// clk_table: kmem_cache#23-o0, id: 2, clk_table[2]: (kmem_cache#23-o0)[2],
		// clk: kmem_cache#29-oX (apll)
		// clk_table: kmem_cache#23-o0, id: 5, clk_table[5]: (kmem_cache#23-o0)[5],
		// clk: kmem_cache#29-oX (epll)
		// clk_table: kmem_cache#23-o0, id: 128, clk_table[128]: (kmem_cache#23-o0)[128],
		// clk: kmem_cache#29-oX (sclk_fimd1)
		clk_table[id] = clk;
		// clk_table[1]: (kmem_cache#23-o0)[1]: kmem_cache#29-oX (fin)
		// clk_table[2]: (kmem_cache#23-o0)[2]: kmem_cache#29-oX (apll)
		// clk_table[5]: (kmem_cache#23-o0)[5]: kmem_cache#29-oX (epll)
		// clk_table[5]: (kmem_cache#23-o0)[5]: kmem_cache#29-oX (epll)
		// clk_table[128]: (kmem_cache#23-o0)[128]: kmem_cache#29-oX (sclk_fimd1)
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
// ARM10C 20150124
// exynos5420_fixed_rate_clks, ARRAY_SIZE(exynos5420_fixed_rate_clks): 5
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

		// clk: kmem_cache#29-oX, IS_ERR(kmem_cache#29-oX): 0
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
// ARM10C 20150124
// exynos5420_fixed_factor_clks, ARRAY_SIZE(exynos5420_fixed_factor_clks): 1
void __init samsung_clk_register_fixed_factor(
		struct samsung_fixed_factor_clock *list, unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx;

	// nr_clk: 1
	for (idx = 0; idx < nr_clk; idx++, list++) {
		// list->name: exynos5420_fixed_factor_clks[0].name: "sclk_hsic_12m",
		// list->parent_name: exynos5420_fixed_factor_clks[0].parent_name: "fin_pll",
		// list->flags: exynos5420_fixed_factor_clks[0].flags: 0,
		// list->multi: exynos5420_fixed_factor_clks[0].mult: 1,
		// list->div: exynos5420_fixed_factor_clks[0].div: 2
		// clk_register_fixed_factor(NULL, "sclk_hsic_12m", "fin_pll", 0, 1, 2): kmem_cache#29-oX (sclk_hsic_12m)
		clk = clk_register_fixed_factor(NULL, list->name,
			list->parent_name, list->flags, list->mult, list->div);
		// clk: kmem_cache#29-oX (sclk_hsic_12m)

		// clk_register_fixed_factor에서 한일:
		// struct clk_fixed_factor 만큼 메모리를 kmem_cache#30-oX 할당 받고 struct clk_fixed_factor 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->mult: 1
		// (kmem_cache#30-oX)->div: 2
		// (kmem_cache#30-oX)->hw.init: &init
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX (sclk_hsic_12m) 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX (sclk_hsic_12m))->name: kmem_cache#30-oX ("sclk_hsic_12m")
		// (kmem_cache#29-oX (sclk_hsic_12m))->ops: &clk_fixed_factor_ops
		// (kmem_cache#29-oX (sclk_hsic_12m))->hw: &(kmem_cache#30-oX (sclk_hsic_12m))->hw
		// (kmem_cache#29-oX (sclk_hsic_12m))->flags: 0x20
		// (kmem_cache#29-oX (sclk_hsic_12m))->num_parents: 1
		// (kmem_cache#29-oX (sclk_hsic_12m))->parent_names: kmem_cache#30-oX
		// (kmem_cache#29-oX (sclk_hsic_12m))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// (kmem_cache#29-oX (sclk_hsic_12m))->parent: kmem_cache#29-oX (fin_pll)
		// (kmem_cache#29-oX (sclk_hsic_12m))->rate: 12000000
		//
		// (&(kmem_cache#29-oX (sclk_hsic_12m))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_hsic_12m))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_hsic_12m))->child_node)
		//
		// (&(kmem_cache#29-oX (fin_pll))->children)->first: &(kmem_cache#29-oX (sclk_hsic_12m))->child_node
		//
		// (&(kmem_cache#30-oX (sclk_hsic_12m))->hw)->clk: kmem_cache#29-oX (sclk_hsic_12m)

		// clk: kmem_cache#29-oX (sclk_hsic_12m), IS_ERR(kmem_cache#29-oX (sclk_hsic_12m)): 0
		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		// clk: kmem_cache#29-oX (sclk_hsic_12m), list->id: exynos5420_fixed_factor_clks[0].id: none: 0
		samsung_clk_add_lookup(clk, list->id);

		// samsung_clk_add_lookup에서 한일:
		// clk_table[0]: (kmem_cache#23-o0)[0]: kmem_cache#29-oX (sclk_hsic_12m)
	}
}

/* register a list of mux clocks */
// ARM10C 20150131
// exynos5420_mux_clks, ARRAY_SIZE(exynos5420_mux_clks): 85
void __init samsung_clk_register_mux(struct samsung_mux_clock *list,
					unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx, ret;

	// nr_clk: 85
	for (idx = 0; idx < nr_clk; idx++, list++) {
		// idx: 0, list->name: exynos5420_mux_clks[0].name: "mout_mspll_kfc",
		// list->parent_names: exynos5420_mux_clks[0].parent_names: mspll_cpu_p,
		// list->num_parents: exynos5420_mux_clks[0].num_parents: 4,
		// list->flags: exynos5420_mux_clks[0].flags: 0x80, reg_base: 0xf0040000,
		// list->offset: exynos5420_mux_clks[0].offset: 0x1021c,
		// list->shift: exynos5420_mux_clks[0].shift: 8,
		// list->width: exynos5420_mux_clks[0].width: 2,
		// list->mux_flags: exynos5420_mux_clks[0].mux_flags: 0
		// clk_register_mux(NULL, "mout_mspll_kfc", mspll_cpu_p, 4, 0x80, 0xf005021c, 8, 2, 0, &lock): kmem_cache#29-oX (mout_mspll_kfc)
		// idx: 44, list->name: exynos5420_mux_clks[44].name: "sclk_spll",
		// list->parent_names: exynos5420_mux_clks[44].parent_names: spll_p,
		// list->num_parents: exynos5420_mux_clks[44].num_parents: 2,
		// list->flags: exynos5420_mux_clks[44].flags: 0x80, reg_base: 0xf0040000,
		// list->offset: exynos5420_mux_clks[44].offset: 0x10218,
		// list->shift: exynos5420_mux_clks[44].shift: 8,
		// list->width: exynos5420_mux_clks[44].width: 1,
		// list->mux_flags: exynos5420_mux_clks[44].mux_flags: 0
		// clk_register_mux(NULL, "sclk_spll", spll_p, 2, 0x80, 0xf0050218, 24, 1, 0, &lock): kmem_cache#29-oX (sclk_spll)
		clk = clk_register_mux(NULL, list->name, list->parent_names,
			list->num_parents, list->flags, reg_base + list->offset,
			list->shift, list->width, list->mux_flags, &lock);
		// clk: kmem_cache#29-oX (mout_mspll_kfc)
		// clk: kmem_cache#29-oX (sclk_spll)

		// clk_register_mux_table(mout_mspll_kfc) 에서 한일:
		// struct clk_mux 만큼 메모리를 kmem_cache#30-oX (mout_mspll_kfc) 할당 받고 struct clk_mux 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->reg: 0xf005021c
		// (kmem_cache#30-oX)->shift: 8
		// (kmem_cache#30-oX)->mask: 0x3
		// (kmem_cache#30-oX)->flags: 0
		// (kmem_cache#30-oX)->lock: &lock
		// (kmem_cache#30-oX)->table: NULL
		// (kmem_cache#30-oX)->hw.init: &init
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX (mout_mspll_kfc) 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX (mout_mspll_kfc))->name: kmem_cache#30-oX ("mout_mspll_kfc")
		// (kmem_cache#29-oX (mout_mspll_kfc))->ops: &clk_mux_ops
		// (kmem_cache#29-oX (mout_mspll_kfc))->hw: &(kmem_cache#30-oX (mout_mspll_kfc))->hw
		// (kmem_cache#29-oX (mout_mspll_kfc))->flags: 0xa0
		// (kmem_cache#29-oX (mout_mspll_kfc))->num_parents 4
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names: kmem_cache#30-oX
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "sclk_cpll"
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[1]: (kmem_cache#30-oX)[1]: kmem_cache#30-oX: "sclk_dpll"
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[2]: (kmem_cache#30-oX)[2]: kmem_cache#30-oX: "sclk_mpll"
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[3]: (kmem_cache#30-oX)[3]: kmem_cache#30-oX: "sclk_spll"
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent: NULL
		// (kmem_cache#29-oX (mout_mspll_kfc))->rate: 0
		//
		// (kmem_cache#29-oX (mout_mspll_kfc))->parents: kmem_cache#30-oX
		// (kmem_cache#29-oX (mout_mspll_kfc))->parents[0...3]: (kmem_cache#30-oX)[0...3]: NULL
		//
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
		//
		// (&clk_orphan_list)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
		//
		// (&(kmem_cache#30-oX (mout_mspll_kfc))->hw)->clk: kmem_cache#29-oX (mout_mspll_kfc)

		// clk_register_mux_table(sclk_spll) 에서 한일:
		// struct clk_mux 만큼 메모리를 kmem_cache#30-oX (sclk_spll) 할당 받고 struct clk_mux 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->reg: 0xf0050218
		// (kmem_cache#30-oX)->shift: 8
		// (kmem_cache#30-oX)->mask: 0x3
		// (kmem_cache#30-oX)->flags: 0
		// (kmem_cache#30-oX)->lock: &lock
		// (kmem_cache#30-oX)->table: NULL
		// (kmem_cache#30-oX)->hw.init: &init
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX (sclk_spll) 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX (sclk_spll))->name: kmem_cache#30-oX ("sclk_spll")
		// (kmem_cache#29-oX (sclk_spll))->ops: &clk_mux_ops
		// (kmem_cache#29-oX (sclk_spll))->hw: &(kmem_cache#30-oX (sclk_spll))->hw
		// (kmem_cache#29-oX (sclk_spll))->flags: 0xa0
		// (kmem_cache#29-oX (sclk_spll))->num_parents 2
		// (kmem_cache#29-oX (sclk_spll))->parent_names: kmem_cache#30-oX
		// (kmem_cache#29-oX (sclk_spll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// (kmem_cache#29-oX (sclk_spll))->parent_names[1]: (kmem_cache#30-oX)[1]: kmem_cache#30-oX: "fout_spll"
		// (kmem_cache#29-oX (sclk_spll))->parent: NULL
		// (kmem_cache#29-oX (sclk_spll))->rate: 600000000
		//
		// (kmem_cache#29-oX (sclk_spll))->parents: kmem_cache#30-oX
		// (kmem_cache#29-oX (sclk_spll))->parents[0]: (kmem_cache#30-oX)[0]: kmem_cache#29-oX (fin_pll)
		// (kmem_cache#29-oX (sclk_spll))->parents[1]: (kmem_cache#30-oX)[1]: kmem_cache#29-oX (fout_spll)
		//
		// parents 인 "fin_pll", "fout_spll" 값들 중에
		// register CLK_SRC_TOP6 의 값을 읽어서 mux 할 parent clock 을 선택함
		// return된 값이 선택된 parent clock의 index 값임
		// parent clock 중에 선택된 parent clock의 이름으로 등록된 clk struct를 반환함
		//
		// (&(kmem_cache#29-oX (sclk_spll))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_spll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_spll))->child_node)
		//
		// (&(kmem_cache#29-oX (fout_spll))->children)->first: &(kmem_cache#29-oX (sclk_dpll))->child_node
		//
		// (&(kmem_cache#30-oX (sclk_spll))->hw)->clk: kmem_cache#29-oX (sclk_spll)
		//
		// orphan 으로 등록된 mout_mspll_kfc의 값을 갱신
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
		//
		// (&(kmem_cache#29-oX (sclk_spll))->children)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
		//
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent: kmem_cache#29-oX (sclk_spll)
		//
		// parent가 있는지 확인후 parent의 clock rate 값으로 clock rate 값을 세팅
		// (kmem_cache#29-oX (mout_mspll_kfc))->rate: 600000000

		// clk: kmem_cache#29-oX (mout_mspll_kfc)
		// clk: kmem_cache#29-oX (sclk_spll)
		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		// clk: kmem_cache#29-oX (mout_mspll_kfc), list->id: exynos5420_mux_clks[0].id: 0
		// clk: kmem_cache#29-oX (sclk_spll), list->id: exynos5420_mux_clks[44].id: 0
		samsung_clk_add_lookup(clk, list->id);

		/* register a clock lookup only if a clock alias is specified */
		// list->alias: exynos5420_mux_clks[0].alias: NULL
		// list->alias: exynos5420_mux_clks[44].alias: NULL
		if (list->alias) {
			ret = clk_register_clkdev(clk, list->alias,
						list->dev_name);
			if (ret)
				pr_err("%s: failed to register lookup %s\n",
						__func__, list->alias);
		}

		// idx: 1...43...84 loop 수행
	}
}

/* register a list of div clocks */
// ARM10C 20150228
// exynos5420_div_clks, ARRAY_SIZE(exynos5420_div_clks): 53
void __init samsung_clk_register_div(struct samsung_div_clock *list,
					unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx, ret;

	// NOTE:
	// exynos5420_div_clks의 div 들 중에 array index 1번의
	// DIV(none, "sclk_apll", "mout_apll", DIV_CPU0, 24, 3) 을 가지고 분석 진행

	// nr_clk: 53
	for (idx = 0; idx < nr_clk; idx++, list++) {
		// idx: 1, list->table: exynos5420_div_clks[1].table: NULL
		if (list->table)
			clk = clk_register_divider_table(NULL, list->name,
					list->parent_name, list->flags,
					reg_base + list->offset, list->shift,
					list->width, list->div_flags,
					list->table, &lock);
		else
			// list->name: exynos5420_div_clks[1].name: "sclk_apll",
			// list->parent_name: exynos5420_div_clks[1].parent_name: "mout_apll",
			// list->flags: exynos5420_div_clks[1].flags: 0,
			// list->offset: exynos5420_div_clks[1].offset: DIV_CPU0: 0x500,
			// list->shift: exynos5420_div_clks[1].shift: 24,
			// list->width: exynos5420_div_clks[1].width: 3,
			// list->div_flags: exynos5420_div_clks[1].div_flags: 0,
			// reg_base: 0xf0040000
			// clk_register_divider("sclk_apll", "mout_apll", 0, 0xf0040500, 24, 3, 0, &lock): kmem_cache#29-oX (sclk_apll)
			clk = clk_register_divider(NULL, list->name,
					list->parent_name, list->flags,
					reg_base + list->offset, list->shift,
					list->width, list->div_flags, &lock);
			// clk: kmem_cache#29-oX (sclk_apll)

			// clk_register_divider(sclk_apll)에서 한일:
			// struct clk_divider 만큼 메모리를 할당 받아 맴버값 초기화 수행
			// kmem_cache#30-oX (sclk_apll)
			// (kmem_cache#30-oX (sclk_apll))->reg: 0xf0040500
			// (kmem_cache#30-oX (sclk_apll))->shift: 24
			// (kmem_cache#30-oX (sclk_apll))->width: 3
			// (kmem_cache#30-oX (sclk_apll))->flags: 0
			// (kmem_cache#30-oX (sclk_apll))->lock: &lock
			// (kmem_cache#30-oX (sclk_apll))->hw.init: &init
			// (kmem_cache#30-oX (sclk_apll))->table: NULL
			//
			// struct clk 만큼 메모리를 할당 받아 맴버값 초기화 수행
			// kmem_cache#29-oX (sclk_apll)
			// (kmem_cache#29-oX (sclk_apll))->name: kmem_cache#30-oX ("sclk_apll")
			// (kmem_cache#29-oX (sclk_apll))->ops: &clk_divider_ops
			// (kmem_cache#29-oX (sclk_apll))->hw: &(kmem_cache#30-oX (sclk_apll))->hw
			// (kmem_cache#29-oX (sclk_apll))->flags: 0x0
			// (kmem_cache#29-oX (sclk_apll))->num_parents 1
			// (kmem_cache#29-oX (sclk_apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "mout_apll"
			// (kmem_cache#29-oX (sclk_apll))->parent: kmem_cache#29-oX (mout_apll)
			// (kmem_cache#29-oX (sclk_apll))->rate: 800000000
			//
			// clk 의 이름이 "mout_apll"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행
			//
			// (&(kmem_cache#29-oX (sclk_apll))->child_node)->next: NULL
			// (&(kmem_cache#29-oX (sclk_apll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_apll))->child_node)
			//
			// (&(kmem_cache#29-oX (fout_dpll))->children)->first: &(kmem_cache#29-oX (sclk_apll))->child_node

		// clk: kmem_cache#29-oX (sclk_apll), IS_ERR(kmem_cache#29-oX (sclk_apll)): 0
		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		// clk: kmem_cache#29-oX (sclk_apll), list->id: exynos5420_div_clks[1].id: 0
		samsung_clk_add_lookup(clk, list->id);

		/* register a clock lookup only if a clock alias is specified */
		// list->alias: exynos5420_div_clks[1].alias: NULL
		if (list->alias) {
			ret = clk_register_clkdev(clk, list->alias,
						list->dev_name);
			if (ret)
				pr_err("%s: failed to register lookup %s\n",
						__func__, list->alias);
		}

		// idx 0, 2...52 까지 loop 수행
	}
}

/* register a list of gate clocks */
// ARM10C 20150307
// exynos5420_gate_clks, ARRAY_SIZE(exynos5420_gate_clks): 136
void __init samsung_clk_register_gate(struct samsung_gate_clock *list,
						unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx, ret;

	// NOTE:
	// exynos5420_gate_clks의 gate 들 중에 array index 36번의
	// GATE(sclk_fimd1, "sclk_fimd1", "dout_fimd1", GATE_TOP_SCLK_PERIC, 0, CLK_SET_RATE_PARENT, 0) 을 가지고 분석 진행

	// nr_clk: 136
	for (idx = 0; idx < nr_clk; idx++, list++) {
		// idx: 36,
		// list->name: exynos5420_gate_clks[36].name: "sclk_fimd1",
		// list->parent_name: exynos5420_gate_clks[36].parent_name: "dout_fimd1",
		// list->flags: exynos5420_gate_clks[36].flags: 0x4,
		// list->offset: exynos5420_gate_clks[36].offset: 0x10828,
		// list->bit_idx: exynos5420_gate_clks[36].bit_idx: 0,
		// list->gate_flags: exynos5420_gate_clks[36].gate_flags: 0,
		// &lock
		// reg_base: 0xf0040000
		// clk_register_gate(NULL, "sclk_fimd1", "dout_fimd1", 0x4, 0xf0050828, 0, 0, &lock): kmem_cache#29-oX (sclk_fimd1)
		clk = clk_register_gate(NULL, list->name, list->parent_name,
				list->flags, reg_base + list->offset,
				list->bit_idx, list->gate_flags, &lock);
		// clk: kmem_cache#29-oX (sclk_fimd1)

		// clk_register_gate(sclk_fimd1)에서 한일:
		// struct clk_gate 만큼 메모리를 할당 받아 맴버값 초기화 수행
		// kmem_cache#30-oX (sclk_fimd1)
		// (kmem_cache#30-oX (sclk_fimd1))->reg: 0xf0050828
		// (kmem_cache#30-oX (sclk_fimd1))->bit_idx: 0
		// (kmem_cache#30-oX (sclk_fimd1))->flags: 0
		// (kmem_cache#30-oX (sclk_fimd1))->lock: &lock
		// (kmem_cache#30-oX (sclk_fimd1))->hw.init: &init
		// (kmem_cache#30-oX (sclk_fimd1))->table: NULL
		//
		// struct clk 만큼 메모리를 할당 받아 맴버값 초기화 수행
		// kmem_cache#29-oX (sclk_fimd1)
		// (kmem_cache#29-oX (sclk_fimd1))->name: kmem_cache#30-oX ("sclk_fimd1")
		// (kmem_cache#29-oX (sclk_fimd1))->ops: &clk_gate_ops
		// (kmem_cache#29-oX (sclk_fimd1))->hw: &(kmem_cache#30-oX (sclk_fimd1))->hw
		// (kmem_cache#29-oX (sclk_fimd1))->flags: 0x0
		// (kmem_cache#29-oX (sclk_fimd1))->num_parents 1
		// (kmem_cache#29-oX (sclk_fimd1))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "mout_apll"
		// (kmem_cache#29-oX (sclk_fimd1))->parent: kmem_cache#29-oX (dout_fimd1)
		// (kmem_cache#29-oX (sclk_fimd1))->rate: 266000000
		//
		// clk 의 이름이 "dout_fimd1"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행
		//
		// (&(kmem_cache#29-oX (sclk_fimd1))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_fimd1))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_fimd1))->child_node)
		//
		// (&(kmem_cache#29-oX (sclk_fimd1))->children)->first: &(kmem_cache#29-oX (sclk_fimd1))->child_node

		// clk: kmem_cache#29-oX (sclk_fimd1), IS_ERR(kmem_cache#29-oX (sclk_fimd1)): 0
		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		/* register a clock lookup only if a clock alias is specified */
		// list->alias: exynos5420_gate_clks[36].alias: NULL
		if (list->alias) {
			ret = clk_register_clkdev(clk, list->alias,
							list->dev_name);
			if (ret)
				pr_err("%s: failed to register lookup %s\n",
					__func__, list->alias);
		}

		// clk: kmem_cache#29-oX (sclk_fimd1), list->id: exynos5420_gate_clks[36].id: 136
		samsung_clk_add_lookup(clk, list->id);

		// samsung_clk_add_lookup(sclk_fimd1) 에서 한일:
		// clk_table[136]: (kmem_cache#23-o0)[136]: kmem_cache#29-oX (sclk_fimd1)

		// idx: 0...12...136 loop 수행
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
