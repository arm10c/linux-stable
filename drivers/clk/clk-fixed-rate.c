/*
 * Copyright (C) 2010-2011 Canonical Ltd <jeremy.kerr@canonical.com>
 * Copyright (C) 2011-2012 Mike Turquette, Linaro Ltd <mturquette@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Fixed rate clock implementation
 */

#include <linux/clk-provider.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/err.h>
#include <linux/of.h>

/*
 * DOC: basic fixed-rate clock that cannot gate
 *
 * Traits of this clock:
 * prepare - clk_(un)prepare only ensures parents are prepared
 * enable - clk_enable only ensures parents are enabled
 * rate - rate is always a fixed value.  No clk_set_rate support
 * parent - fixed parent.  No clk_set_parent support
 */

#define to_clk_fixed_rate(_hw) container_of(_hw, struct clk_fixed_rate, hw)

static unsigned long clk_fixed_rate_recalc_rate(struct clk_hw *hw,
		unsigned long parent_rate)
{
	return to_clk_fixed_rate(hw)->fixed_rate;
}

// ARM10C 20150110
const struct clk_ops clk_fixed_rate_ops = {
	.recalc_rate = clk_fixed_rate_recalc_rate,
};
EXPORT_SYMBOL_GPL(clk_fixed_rate_ops);

/**
 * clk_register_fixed_rate - register fixed-rate clock with the clock framework
 * @dev: device that is registering this clock
 * @name: name of this clock
 * @parent_name: name of clock's parent
 * @flags: framework-specific flags
 * @fixed_rate: non-adjustable clock rate
 */
// ARM10C 20150110
// NULL,
// list->name: exynos5420_fixed_rate_ext_clks.name: "fin_pll",
// list->parent_name: exynos5420_fixed_rate_ext_clks.parent_name: NULL,
// list->flags: exynos5420_fixed_rate_ext_clks.flags: CLK_IS_ROOT,
// list->fixed_rate: exynos5420_fixed_rate_ext_clks.fixed_rate: 24000000
struct clk *clk_register_fixed_rate(struct device *dev, const char *name,
		const char *parent_name, unsigned long flags,
		unsigned long fixed_rate)
{
	struct clk_fixed_rate *fixed;
	struct clk *clk;
	struct clk_init_data init;

	/* allocate fixed-rate clock */
	// sizeof(struct clk_fixed_rate): 13 bytes, GFP_KERNEL: 0xD0
	// kzalloc(13, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	fixed = kzalloc(sizeof(struct clk_fixed_rate), GFP_KERNEL);
	// fixed: kmem_cache#30-oX

	// fixed: kmem_cache#30-oX
	if (!fixed) {
		pr_err("%s: could not allocate fixed clk\n", __func__);
		return ERR_PTR(-ENOMEM);
	}

	// name: "fin_pll"
	init.name = name;
	// init.name: "fin_pll"

	init.ops = &clk_fixed_rate_ops;
	// init.ops: &clk_fixed_rate_ops

	// flags: CLK_IS_ROOT: 0x10, CLK_IS_BASIC: 0x20
	init.flags = flags | CLK_IS_BASIC;
	// init.flags: 0x30

	// parent_name: NULL
	init.parent_names = (parent_name ? &parent_name: NULL);
	// init.parent_names: NULL

	// parent_name: NULL
	init.num_parents = (parent_name ? 1 : 0);
	// init.num_parents: 0

	/* struct clk_fixed_rate assignments */
	// fixed->fixed_rate: (kmem_cache#30-oX)->fixed_rate, fixed_rate: 24000000
	fixed->fixed_rate = fixed_rate;
	// fixed->fixed_rate: (kmem_cache#30-oX)->fixed_rate: 24000000

	// fixed->hw.init: (kmem_cache#30-oX)->hw.init
	fixed->hw.init = &init;
	// fixed->hw.init: (kmem_cache#30-oX)->hw.init: &init

// 2015/01/10 종료

	/* register the clock */
	// dev: NULL, fixed->hw: (kmem_cache#30-oX)->hw
	clk = clk_register(dev, &fixed->hw);

	if (IS_ERR(clk))
		kfree(fixed);

	return clk;
}
EXPORT_SYMBOL_GPL(clk_register_fixed_rate);

#ifdef CONFIG_OF
/**
 * of_fixed_clk_setup() - Setup function for simple fixed rate clock
 */
void of_fixed_clk_setup(struct device_node *node)
{
	struct clk *clk;
	const char *clk_name = node->name;
	u32 rate;

	if (of_property_read_u32(node, "clock-frequency", &rate))
		return;

	of_property_read_string(node, "clock-output-names", &clk_name);

	clk = clk_register_fixed_rate(NULL, clk_name, NULL, CLK_IS_ROOT, rate);
	if (!IS_ERR(clk))
		of_clk_add_provider(node, of_clk_src_simple_get, clk);
}
EXPORT_SYMBOL_GPL(of_fixed_clk_setup);

// #define CLK_OF_DECLARE(fixed_clk, "fixed-clock", of_fixed_clk_setup):
// static const struct of_device_id __clk_of_table_fixed_clk __used __section(__clk_of_table)
// = { .compatible = "fixed-clock", .data = of_fixed_clk_setup };
CLK_OF_DECLARE(fixed_clk, "fixed-clock", of_fixed_clk_setup);
#endif
