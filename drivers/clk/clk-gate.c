/*
 * Copyright (C) 2010-2011 Canonical Ltd <jeremy.kerr@canonical.com>
 * Copyright (C) 2011-2012 Mike Turquette, Linaro Ltd <mturquette@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Gated clock implementation
 */

#include <linux/clk-provider.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/err.h>
#include <linux/string.h>

/**
 * DOC: basic gatable clock which can gate and ungate it's ouput
 *
 * Traits of this clock:
 * prepare - clk_(un)prepare only ensures parent is (un)prepared
 * enable - clk_enable and clk_disable are functional & control gating
 * rate - inherits rate from parent.  No clk_set_rate support
 * parent - fixed parent.  No clk_set_parent support
 */

#define to_clk_gate(_hw) container_of(_hw, struct clk_gate, hw)

/*
 * It works on following logic:
 *
 * For enabling clock, enable = 1
 *	set2dis = 1	-> clear bit	-> set = 0
 *	set2dis = 0	-> set bit	-> set = 1
 *
 * For disabling clock, enable = 0
 *	set2dis = 1	-> set bit	-> set = 1
 *	set2dis = 0	-> clear bit	-> set = 0
 *
 * So, result is always: enable xor set2dis.
 */
static void clk_gate_endisable(struct clk_hw *hw, int enable)
{
	struct clk_gate *gate = to_clk_gate(hw);
	int set = gate->flags & CLK_GATE_SET_TO_DISABLE ? 1 : 0;
	unsigned long flags = 0;
	u32 reg;

	set ^= enable;

	if (gate->lock)
		spin_lock_irqsave(gate->lock, flags);

	if (gate->flags & CLK_GATE_HIWORD_MASK) {
		reg = BIT(gate->bit_idx + 16);
		if (set)
			reg |= BIT(gate->bit_idx);
	} else {
		reg = clk_readl(gate->reg);

		if (set)
			reg |= BIT(gate->bit_idx);
		else
			reg &= ~BIT(gate->bit_idx);
	}

	clk_writel(reg, gate->reg);

	if (gate->lock)
		spin_unlock_irqrestore(gate->lock, flags);
}

static int clk_gate_enable(struct clk_hw *hw)
{
	clk_gate_endisable(hw, 1);

	return 0;
}

static void clk_gate_disable(struct clk_hw *hw)
{
	clk_gate_endisable(hw, 0);
}

static int clk_gate_is_enabled(struct clk_hw *hw)
{
	u32 reg;
	struct clk_gate *gate = to_clk_gate(hw);

	reg = clk_readl(gate->reg);

	/* if a set bit disables this clk, flip it before masking */
	if (gate->flags & CLK_GATE_SET_TO_DISABLE)
		reg ^= BIT(gate->bit_idx);

	reg &= BIT(gate->bit_idx);

	return reg ? 1 : 0;
}

// ARM10C 20150307
const struct clk_ops clk_gate_ops = {
	.enable = clk_gate_enable,
	.disable = clk_gate_disable,
	.is_enabled = clk_gate_is_enabled,
};
EXPORT_SYMBOL_GPL(clk_gate_ops);

/**
 * clk_register_gate - register a gate clock with the clock framework
 * @dev: device that is registering this clock
 * @name: name of this clock
 * @parent_name: name of this clock's parent
 * @flags: framework-specific flags for this clock
 * @reg: register address to control gating of this clock
 * @bit_idx: which bit in the register controls gating of this clock
 * @clk_gate_flags: gate-specific flags for this clock
 * @lock: shared register lock for this clock
 */
// ARM10C 20150307
// NULL,
// list->name: exynos5420_gate_clks[36].name: "sclk_fimd1",
// list->parent_name: exynos5420_gate_clks[36].parent_name: "dout_fimd1",
// list->flags: exynos5420_gate_clks[36].flags: 0x4,
// 0xf0050828,
// list->bit_idx: exynos5420_gate_clks[36].bit_idx: 0,
// list->gate_flags: exynos5420_gate_clks[36].gate_flags: 0,
// &lock
struct clk *clk_register_gate(struct device *dev, const char *name,
		const char *parent_name, unsigned long flags,
		void __iomem *reg, u8 bit_idx,
		u8 clk_gate_flags, spinlock_t *lock)
{
	struct clk_gate *gate;
	struct clk *clk;
	struct clk_init_data init;

	// clk_gate_flags: 0, CLK_GATE_HIWORD_MASK: 0x2
	if (clk_gate_flags & CLK_GATE_HIWORD_MASK) {
		if (bit_idx > 16) {
			pr_err("gate bit exceeds LOWORD field\n");
			return ERR_PTR(-EINVAL);
		}
	}

	/* allocate the gate */
	// sizeof(struct clk_gate): 18 bytes, GFP_KERNEL: 0xD0
	// kzalloc(18, GFP_KERNEL: 0xD0): kmem_cache#30-oX (sclk_fimd1)
	gate = kzalloc(sizeof(struct clk_gate), GFP_KERNEL);
	// gate: kmem_cache#30-oX (sclk_fimd1)

	// gate: kmem_cache#30-oX (sclk_fimd1)
	if (!gate) {
		pr_err("%s: could not allocate gated clk\n", __func__);
		return ERR_PTR(-ENOMEM);
	}

	// name: "sclk_fimd1"
	init.name = name;
	// init.name: "sclk_fimd1"

	init.ops = &clk_gate_ops;
	// init.ops: &clk_gate_ops

	// flags: 0x4, CLK_IS_BASIC: 0x20
	init.flags = flags | CLK_IS_BASIC;
	// init.flags: 0x24

	// parent_name: "dout_fimd1"
	init.parent_names = (parent_name ? &parent_name: NULL);
	// init.parent_names: "dout_fimd1"

	// parent_name: "dout_fimd1"
	init.num_parents = (parent_name ? 1 : 0);
	// init.num_parents: 1

	/* struct clk_gate assignments */
	// gate->reg: (kmem_cache#30-oX (sclk_fimd1))->reg, reg: 0xf0050828
	gate->reg = reg;
	// gate->reg: (kmem_cache#30-oX (sclk_fimd1))->reg: 0xf0050828

	// gate->bit_idx: (kmem_cache#30-oX (sclk_fimd1))->bit_idx, bit_idx: 0
	gate->bit_idx = bit_idx;
	// gate->bit_idx: (kmem_cache#30-oX (sclk_fimd1))->bit_idx: 0

	// gate->flags: (kmem_cache#30-oX (sclk_fimd1))->flags, clk_gate_flags: 0
	gate->flags = clk_gate_flags;
	// gate->flags: (kmem_cache#30-oX (sclk_fimd1))->flags: 0

	// gate->lock: (kmem_cache#30-oX (sclk_fimd1))->lock, lock: &lock
	gate->lock = lock;
	// gate->lock: (kmem_cache#30-oX (sclk_fimd1))->lock: &lock

	// gate->hw.init: (kmem_cache#30-oX (sclk_fimd1))->hw.init
	gate->hw.init = &init;
	// gate->hw.init: (kmem_cache#30-oX (sclk_fimd1))->hw.init: &init

	// dev: NULL, &gate->hw: &(kmem_cache#30-oX (sclk_fimd1))->hw
	// clk_register(NULL, &(kmem_cache#30-oX (sclk_fimd1))->hw): kmem_cache#29-oX (sclk_fimd1)
	clk = clk_register(dev, &gate->hw);
	// clk: kmem_cache#29-oX (sclk_fimd1)

	// clk_register(sclk_fimd1) 에서 한일:
	// (kmem_cache#29-oX (sclk_fimd1))->name: kmem_cache#30-oX ("sclk_fimd1")
	// (kmem_cache#29-oX (sclk_fimd1))->ops: &clk_gate_ops
	// (kmem_cache#29-oX (sclk_fimd1))->hw: &(kmem_cache#30-oX (sclk_fimd1))->hw
	// (kmem_cache#29-oX (sclk_fimd1))->flags: 0x24
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
	if (IS_ERR(clk))
		kfree(gate);

	// clk: kmem_cache#29-oX (sclk_fimd1)
	return clk;
	// return kmem_cache#29-oX (sclk_fimd1)
}
EXPORT_SYMBOL_GPL(clk_register_gate);
