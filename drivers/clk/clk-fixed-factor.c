/*
 * Copyright (C) 2011 Sascha Hauer, Pengutronix <s.hauer@pengutronix.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Standard functionality for the common clock API.
 */
#include <linux/module.h>
#include <linux/clk-provider.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/of.h>

/*
 * DOC: basic fixed multiplier and divider clock that cannot gate
 *
 * Traits of this clock:
 * prepare - clk_prepare only ensures that parents are prepared
 * enable - clk_enable only ensures that parents are enabled
 * rate - rate is fixed.  clk->rate = parent->rate / div * mult
 * parent - fixed parent.  No clk_set_parent support
 */

// ARM10C 20150124
#define to_clk_fixed_factor(_hw) container_of(_hw, struct clk_fixed_factor, hw)

// ARM10C 20150124
// &(kmem_cache#30-oX (sclk_hsic_12m))->hw, 24000000
static unsigned long clk_factor_recalc_rate(struct clk_hw *hw,
		unsigned long parent_rate)
{
	// hw: &(kmem_cache#30-oX (sclk_hsic_12m))->hw,
	// to_clk_fixed_factor(&(kmem_cache#30-oX (sclk_hsic_12m))->hw): kmem_cache#30-oX (sclk_hsic_12m)
	struct clk_fixed_factor *fix = to_clk_fixed_factor(hw);
	// fix: kmem_cache#30-oX (sclk_hsic_12m)

	unsigned long long int rate;

	// parent_rate: 24000000,
	// fix->mult: (kmem_cache#30-oX (sclk_hsic_12m))->mult: 1
	rate = (unsigned long long int)parent_rate * fix->mult;
	// rate: 24000000,

	// rate: 24000000, fix->div: (kmem_cache#30-oX (sclk_hsic_12m))->div: 2
	do_div(rate, fix->div);
	// rate: 12000000

	// rate: 12000000
	return (unsigned long)rate;
	// return 12000000
}

static long clk_factor_round_rate(struct clk_hw *hw, unsigned long rate,
				unsigned long *prate)
{
	struct clk_fixed_factor *fix = to_clk_fixed_factor(hw);

	if (__clk_get_flags(hw->clk) & CLK_SET_RATE_PARENT) {
		unsigned long best_parent;

		best_parent = (rate / fix->mult) * fix->div;
		*prate = __clk_round_rate(__clk_get_parent(hw->clk),
				best_parent);
	}

	return (*prate / fix->div) * fix->mult;
}

static int clk_factor_set_rate(struct clk_hw *hw, unsigned long rate,
				unsigned long parent_rate)
{
	return 0;
}

// ARM10C 20150124
struct clk_ops clk_fixed_factor_ops = {
	.round_rate = clk_factor_round_rate,
	.set_rate = clk_factor_set_rate,
	.recalc_rate = clk_factor_recalc_rate,
};
EXPORT_SYMBOL_GPL(clk_fixed_factor_ops);

// ARM10C 20150124
// NULL,
// list->name: exynos5420_fixed_factor_clks[0].name: "sclk_hsic_12m",
// list->parent_name: exynos5420_fixed_factor_clks[0].parent_name: "fin_pll",
// list->flags: exynos5420_fixed_factor_clks[0].flags: 0,
// list->multi: exynos5420_fixed_factor_clks[0].mult: 1,
// list->div: exynos5420_fixed_factor_clks[0].div: 2
struct clk *clk_register_fixed_factor(struct device *dev, const char *name,
		const char *parent_name, unsigned long flags,
		unsigned int mult, unsigned int div)
{
	struct clk_fixed_factor *fix;
	struct clk_init_data init;
	struct clk *clk;

	// sizeof(struct clk_fixed_factor): 16 bytes, GFP_KERNEL: 0xD0
	// kmalloc(16, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	fix = kmalloc(sizeof(*fix), GFP_KERNEL);
	// fix: kmem_cache#30-oX

	// fix: kmem_cache#30-oX
	if (!fix) {
		pr_err("%s: could not allocate fixed factor clk\n", __func__);
		return ERR_PTR(-ENOMEM);
	}

	/* struct clk_fixed_factor assignments */
	// fix->mult: (kmem_cache#30-oX)->mult, mult: 1
	fix->mult = mult;
	// fix->mult: (kmem_cache#30-oX)->mult: 1

	// fix->div: (kmem_cache#30-oX)->div, div: 2
	fix->div = div;
	// fix->div: (kmem_cache#30-oX)->div: 2

	// fix->hw.init: (kmem_cache#30-oX)->hw.init
	fix->hw.init = &init;
	// fix->hw.init: (kmem_cache#30-oX)->hw.init: &init

	// name: "sclk_hsic_12m"
	init.name = name;
	// init.name: "sclk_hsic_12m"

	init.ops = &clk_fixed_factor_ops;
	// init.ops: &clk_fixed_factor_ops

	// flags: 0, CLK_IS_BASIC: 0x20
	init.flags = flags | CLK_IS_BASIC;
	// init.flags: 0x20

	// parent_name: "fin_pll"
	init.parent_names = &parent_name;
	// init.parent_names: "fin_pll"

	init.num_parents = 1;
	// init.num_parents: 1

	// dev: NULL, &fix->hw: &(kmem_cache#30-oX (sclk_hsic_12m))->hw
	clk = clk_register(dev, &fix->hw);
	// clk: kmem_cache#29-oX (sclk_hsic_12m)

	// clk_register(sclk_hsic_12m)에서 한일:
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

	if (IS_ERR(clk))
		kfree(fix);

	// clk: kmem_cache#29-oX (sclk_hsic_12m)
	return clk;
	// return kmem_cache#29-oX (sclk_hsic_12m)
}
EXPORT_SYMBOL_GPL(clk_register_fixed_factor);

#ifdef CONFIG_OF
/**
 * of_fixed_factor_clk_setup() - Setup function for simple fixed factor clock
 */
void __init of_fixed_factor_clk_setup(struct device_node *node)
{
	struct clk *clk;
	const char *clk_name = node->name;
	const char *parent_name;
	u32 div, mult;

	if (of_property_read_u32(node, "clock-div", &div)) {
		pr_err("%s Fixed factor clock <%s> must have a clock-div property\n",
			__func__, node->name);
		return;
	}

	if (of_property_read_u32(node, "clock-mult", &mult)) {
		pr_err("%s Fixed factor clock <%s> must have a clock-mult property\n",
			__func__, node->name);
		return;
	}

	of_property_read_string(node, "clock-output-names", &clk_name);
	parent_name = of_clk_get_parent_name(node, 0);

	clk = clk_register_fixed_factor(NULL, clk_name, parent_name, 0,
					mult, div);
	if (!IS_ERR(clk))
		of_clk_add_provider(node, of_clk_src_simple_get, clk);
}
EXPORT_SYMBOL_GPL(of_fixed_factor_clk_setup);

// ARM10C 20150103
// #define CLK_OF_DECLARE(fixed_factor_clk, "fixed-factor-clock", of_fixed_factor_clk_setup):
// static const struct of_device_id __clk_of_table_fixed_factor_clk __used __section(__clk_of_table)
// = { .compatible = "fixed-factor-clock", .data = of_fixed_factor_clk_setup };
CLK_OF_DECLARE(fixed_factor_clk, "fixed-factor-clock",
		of_fixed_factor_clk_setup);
#endif
