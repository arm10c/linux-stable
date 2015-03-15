/*
 * Copyright (C) 2011 Sascha Hauer, Pengutronix <s.hauer@pengutronix.de>
 * Copyright (C) 2011 Richard Zhao, Linaro <richard.zhao@linaro.org>
 * Copyright (C) 2011-2012 Mike Turquette, Linaro Ltd <mturquette@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Adjustable divider clock implementation
 */

#include <linux/clk-provider.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/log2.h>

/*
 * DOC: basic adjustable divider clock that cannot gate
 *
 * Traits of this clock:
 * prepare - clk_prepare only ensures that parents are prepared
 * enable - clk_enable only ensures that parents are enabled
 * rate - rate is adjustable.  clk->rate = parent->rate / divisor
 * parent - fixed parent.  No clk_set_parent support
 */

// ARM10C 20150228
#define to_clk_divider(_hw) container_of(_hw, struct clk_divider, hw)

// ARM10C 20150228
// divider: kmem_cache#30-oX (sclk_apll)
// divider->width: (kmem_cache#30-oX (sclk_apll))->width: 3
// div_mask(kmem_cache#30-oX (sclk_apll)): 0x4
#define div_mask(d)	((1 << ((d)->width)) - 1)

static unsigned int _get_table_maxdiv(const struct clk_div_table *table)
{
	unsigned int maxdiv = 0;
	const struct clk_div_table *clkt;

	for (clkt = table; clkt->div; clkt++)
		if (clkt->div > maxdiv)
			maxdiv = clkt->div;
	return maxdiv;
}

static unsigned int _get_maxdiv(struct clk_divider *divider)
{
	if (divider->flags & CLK_DIVIDER_ONE_BASED)
		return div_mask(divider);
	if (divider->flags & CLK_DIVIDER_POWER_OF_TWO)
		return 1 << div_mask(divider);
	if (divider->table)
		return _get_table_maxdiv(divider->table);
	return div_mask(divider) + 1;
}

static unsigned int _get_table_div(const struct clk_div_table *table,
							unsigned int val)
{
	const struct clk_div_table *clkt;

	for (clkt = table; clkt->div; clkt++)
		if (clkt->val == val)
			return clkt->div;
	return 0;
}

// ARM10C 20150228
// divider: kmem_cache#30-oX (sclk_apll), val: 0
static unsigned int _get_div(struct clk_divider *divider, unsigned int val)
{
	// divider->flags: (kmem_cache#30-oX (sclk_apll))->flags: 0, CLK_DIVIDER_ONE_BASED: 0x1
	if (divider->flags & CLK_DIVIDER_ONE_BASED)
		return val;

	// divider->flags: (kmem_cache#30-oX (sclk_apll))->flags: 0, CLK_DIVIDER_POWER_OF_TWO: 0x2
	if (divider->flags & CLK_DIVIDER_POWER_OF_TWO)
		return 1 << val;

	// divider->table: (kmem_cache#30-oX (sclk_apll))->table: NULL
	if (divider->table)
		return _get_table_div(divider->table, val);

	// val: 0
	return val + 1;
	// return 1
}

static unsigned int _get_table_val(const struct clk_div_table *table,
							unsigned int div)
{
	const struct clk_div_table *clkt;

	for (clkt = table; clkt->div; clkt++)
		if (clkt->div == div)
			return clkt->val;
	return 0;
}

static unsigned int _get_val(struct clk_divider *divider, unsigned int div)
{
	if (divider->flags & CLK_DIVIDER_ONE_BASED)
		return div;
	if (divider->flags & CLK_DIVIDER_POWER_OF_TWO)
		return __ffs(div);
	if (divider->table)
		return  _get_table_val(divider->table, div);
	return div - 1;
}

// ARM10C 20150228
// &(kmem_cache#30-oX (sclk_apll))->hw, 800000000
static unsigned long clk_divider_recalc_rate(struct clk_hw *hw,
		unsigned long parent_rate)
{
	// hw: &(kmem_cache#30-oX (sclk_apll))->hw,
	// to_clk_divider(&(kmem_cache#30-oX (sclk_apll))->hw): kmem_cache#30-oX (sclk_apll)
	struct clk_divider *divider = to_clk_divider(hw);
	// divider: kmem_cache#30-oX (sclk_apll)

	unsigned int div, val;

	// E.R.M: 7.9.1.6 CLK_DIV_CPU0
	// APLL_RATIO[26:24]: CLKDIV_APLL clock divider ratio
	// SCLK_APLL = MOUT_APLL/(APLL_RATIO + 1)

	// NOTE:
	// register CLK_DIV_CPU0 의 값을 알수 없음.
	// APLL_RATIO[26:24]의 값을 0이라 가정하고 분석 진행

	// divider->reg: (kmem_cache#30-oX (sclk_apll))->reg: 0xf0040500
	// divider->shift: (kmem_cache#30-oX (sclk_apll))->shift: 24
	// clk_readl(0xf0040500): 0x0
	val = clk_readl(divider->reg) >> divider->shift;
	// val: 0

	// divider: kmem_cache#30-oX (sclk_apll), div_mask(kmem_cache#30-oX (sclk_apll)): 0x4
	val &= div_mask(divider);
	// val: 0

	// divider: kmem_cache#30-oX (sclk_apll), val: 0
	// _get_div(kmem_cache#30-oX (sclk_apll), 0): 1
	div = _get_div(divider, val);
	// div: 1

	// div: 1
	if (!div) {
		WARN(!(divider->flags & CLK_DIVIDER_ALLOW_ZERO),
			"%s: Zero divisor and CLK_DIVIDER_ALLOW_ZERO not set\n",
			__clk_get_name(hw->clk));
		return parent_rate;
	}

	// parent_rate: 800000000, div: 1
	return parent_rate / div;
	// return 800000000
}

/*
 * The reverse of DIV_ROUND_UP: The maximum number which
 * divided by m is r
 */
#define MULT_ROUND_UP(r, m) ((r) * (m) + (m) - 1)

static bool _is_valid_table_div(const struct clk_div_table *table,
							 unsigned int div)
{
	const struct clk_div_table *clkt;

	for (clkt = table; clkt->div; clkt++)
		if (clkt->div == div)
			return true;
	return false;
}

static bool _is_valid_div(struct clk_divider *divider, unsigned int div)
{
	if (divider->flags & CLK_DIVIDER_POWER_OF_TWO)
		return is_power_of_2(div);
	if (divider->table)
		return _is_valid_table_div(divider->table, div);
	return true;
}

static int clk_divider_bestdiv(struct clk_hw *hw, unsigned long rate,
		unsigned long *best_parent_rate)
{
	struct clk_divider *divider = to_clk_divider(hw);
	int i, bestdiv = 0;
	unsigned long parent_rate, best = 0, now, maxdiv;
	unsigned long parent_rate_saved = *best_parent_rate;

	if (!rate)
		rate = 1;

	maxdiv = _get_maxdiv(divider);

	if (!(__clk_get_flags(hw->clk) & CLK_SET_RATE_PARENT)) {
		parent_rate = *best_parent_rate;
		bestdiv = DIV_ROUND_UP(parent_rate, rate);
		bestdiv = bestdiv == 0 ? 1 : bestdiv;
		bestdiv = bestdiv > maxdiv ? maxdiv : bestdiv;
		return bestdiv;
	}

	/*
	 * The maximum divider we can use without overflowing
	 * unsigned long in rate * i below
	 */
	maxdiv = min(ULONG_MAX / rate, maxdiv);

	for (i = 1; i <= maxdiv; i++) {
		if (!_is_valid_div(divider, i))
			continue;
		if (rate * i == parent_rate_saved) {
			/*
			 * It's the most ideal case if the requested rate can be
			 * divided from parent clock without needing to change
			 * parent rate, so return the divider immediately.
			 */
			*best_parent_rate = parent_rate_saved;
			return i;
		}
		parent_rate = __clk_round_rate(__clk_get_parent(hw->clk),
				MULT_ROUND_UP(rate, i));
		now = parent_rate / i;
		if (now <= rate && now > best) {
			bestdiv = i;
			best = now;
			*best_parent_rate = parent_rate;
		}
	}

	if (!bestdiv) {
		bestdiv = _get_maxdiv(divider);
		*best_parent_rate = __clk_round_rate(__clk_get_parent(hw->clk), 1);
	}

	return bestdiv;
}

static long clk_divider_round_rate(struct clk_hw *hw, unsigned long rate,
				unsigned long *prate)
{
	int div;
	div = clk_divider_bestdiv(hw, rate, prate);

	return *prate / div;
}

static int clk_divider_set_rate(struct clk_hw *hw, unsigned long rate,
				unsigned long parent_rate)
{
	struct clk_divider *divider = to_clk_divider(hw);
	unsigned int div, value;
	unsigned long flags = 0;
	u32 val;

	div = parent_rate / rate;
	value = _get_val(divider, div);

	if (value > div_mask(divider))
		value = div_mask(divider);

	if (divider->lock)
		spin_lock_irqsave(divider->lock, flags);

	if (divider->flags & CLK_DIVIDER_HIWORD_MASK) {
		val = div_mask(divider) << (divider->shift + 16);
	} else {
		val = clk_readl(divider->reg);
		val &= ~(div_mask(divider) << divider->shift);
	}
	val |= value << divider->shift;
	clk_writel(val, divider->reg);

	if (divider->lock)
		spin_unlock_irqrestore(divider->lock, flags);

	return 0;
}

// ARM10C 20150228
const struct clk_ops clk_divider_ops = {
	.recalc_rate = clk_divider_recalc_rate,
	.round_rate = clk_divider_round_rate,
	.set_rate = clk_divider_set_rate,
};
EXPORT_SYMBOL_GPL(clk_divider_ops);

// ARM10C 20150228
// dev: NULL, name: "sclk_apll", parent_name: "mout_apll", flags: 0x0, reg: 0xf0040500,
// shift: 24, width: 3, clk_divider_flags: 0, NULL, lock: &lock
static struct clk *_register_divider(struct device *dev, const char *name,
		const char *parent_name, unsigned long flags,
		void __iomem *reg, u8 shift, u8 width,
		u8 clk_divider_flags, const struct clk_div_table *table,
		spinlock_t *lock)
{
	struct clk_divider *div;
	struct clk *clk;
	struct clk_init_data init;

	// clk_divider_flags: 0, CLK_DIVIDER_HIWORD_MASK: 0x8
	if (clk_divider_flags & CLK_DIVIDER_HIWORD_MASK) {
		if (width + shift > 16) {
			pr_warn("divider value exceeds LOWORD field\n");
			return ERR_PTR(-EINVAL);
		}
	}

	/* allocate the divider */
	// sizeof(struct clk_divider): 23 bytes, GFP_KERNEL: 0xD0
	// kzalloc(23, GFP_KERNEL: 0xD0): kmem_cache#30-oX (sclk_apll)
	div = kzalloc(sizeof(struct clk_divider), GFP_KERNEL);
	// div: kmem_cache#30-oX (sclk_apll)

	// div: kmem_cache#30-oX (sclk_apll)
	if (!div) {
		pr_err("%s: could not allocate divider clk\n", __func__);
		return ERR_PTR(-ENOMEM);
	}

	// name: "sclk_apll"
	init.name = name;
	// init.name: "sclk_apll"

	init.ops = &clk_divider_ops;
	// init.ops: &clk_divider_ops;

	// flags: 0, CLK_IS_BASIC: 0x20
	init.flags = flags | CLK_IS_BASIC;
	// init.flags: 0x20

	// parent_name: "mout_apll"
	init.parent_names = (parent_name ? &parent_name: NULL);
	// init.parent_names: "mout_apll"

	// parent_name: "mout_apll"
	init.num_parents = (parent_name ? 1 : 0);
	// init.num_parents: 1

	/* struct clk_divider assignments */
	// div->reg: (kmem_cache#30-oX (sclk_apll))->reg, reg: 0xf0040500
	div->reg = reg;
	// div->reg: (kmem_cache#30-oX (sclk_apll))->reg: 0xf0040500

	// div->shift: (kmem_cache#30-oX (sclk_apll))->shift, shift: 24
	div->shift = shift;
	// div->shift: (kmem_cache#30-oX (sclk_apll))->shift: 24

	// div->width: (kmem_cache#30-oX (sclk_apll))->width, width: 3
	div->width = width;
	// div->width: (kmem_cache#30-oX (sclk_apll))->width: 3

	// div->flags: (kmem_cache#30-oX (sclk_apll))->flags, clk_divider_flags: 0
	div->flags = clk_divider_flags;
	// div->flags: (kmem_cache#30-oX (sclk_apll))->flags: 0

	// div->lock: (kmem_cache#30-oX (sclk_apll))->lock, lock: &lock
	div->lock = lock;
	// div->lock: (kmem_cache#30-oX (sclk_apll))->lock: &lock

	// div->hw.init: (kmem_cache#30-oX (sclk_apll))->hw.init
	div->hw.init = &init;
	// div->hw.init: (kmem_cache#30-oX (sclk_apll))->hw.init: &init

	// div->table: (kmem_cache#30-oX (sclk_apll))->table, table: NULL
	div->table = table;
	// div->table: (kmem_cache#30-oX (sclk_apll))->table: NULL

	/* register the clock */
	// dev: NULL, &div->hw: &(kmem_cache#30-oX (sclk_apll))->hw
	// clk_register(NULL, &(kmem_cache#30-oX (sclk_apll))->hw): kmem_cache#29-oX (sclk_apll)
	clk = clk_register(dev, &div->hw);
	// clk: kmem_cache#29-oX (sclk_apll)

	// clk_register(sclk_apll) 에서 한일:
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
	// (&(kmem_cache#29-oX (mout_apll))->children)->first: &(kmem_cache#29-oX (sclk_apll))->child_node

	// clk: kmem_cache#29-oX (sclk_apll), IS_ERR(kmem_cache#29-oX (sclk_apll)): 0
	if (IS_ERR(clk))
		kfree(div);

	// clk: kmem_cache#29-oX (sclk_apll)
	return clk;
	// return kmem_cache#29-oX (sclk_apll)
}

/**
 * clk_register_divider - register a divider clock with the clock framework
 * @dev: device registering this clock
 * @name: name of this clock
 * @parent_name: name of clock's parent
 * @flags: framework-specific flags
 * @reg: register address to adjust divider
 * @shift: number of bits to shift the bitfield
 * @width: width of the bitfield
 * @clk_divider_flags: divider-specific flags for this clock
 * @lock: shared register lock for this clock
 */
// ARM10C 20150228
// NULL,
// list->name: exynos5420_div_clks[1].name: "sclk_apll",
// list->parent_name: exynos5420_div_clks[1].parent_name: "mout_apll",
// list->flags: exynos5420_div_clks[1].flags: 0,
// 0xf0040000 + 0x500,
// list->shift: exynos5420_div_clks[1].shift: 24,
// list->width: exynos5420_div_clks[1].width: 3,
// list->div_flags: exynos5420_div_clks[1].div_flags: 0,
// &lock
struct clk *clk_register_divider(struct device *dev, const char *name,
		const char *parent_name, unsigned long flags,
		void __iomem *reg, u8 shift, u8 width,
		u8 clk_divider_flags, spinlock_t *lock)
{
	// dev: NULL, name: "sclk_apll", parent_name: "mout_apll", flags: 0x0, reg: 0xf0040500,
	// shift: 24, width: 3, clk_divider_flags: 0, lock: &lock
	// _register_divider(NULL, "sclk_apll", "mout_apll", 0x0, 0xf0040500, 24, 1, 0, NULL, &lock): kmem_cache#29-oX (sclk_apll)
	return _register_divider(dev, name, parent_name, flags, reg, shift,
			width, clk_divider_flags, NULL, lock);
	// return kmem_cache#29-oX (sclk_apll)

	// _register_divider(sclk_apll)에서 한일:
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
	// (&(kmem_cache#29-oX (mout_apll))->children)->first: &(kmem_cache#29-oX (sclk_apll))->child_node
}
EXPORT_SYMBOL_GPL(clk_register_divider);

/**
 * clk_register_divider_table - register a table based divider clock with
 * the clock framework
 * @dev: device registering this clock
 * @name: name of this clock
 * @parent_name: name of clock's parent
 * @flags: framework-specific flags
 * @reg: register address to adjust divider
 * @shift: number of bits to shift the bitfield
 * @width: width of the bitfield
 * @clk_divider_flags: divider-specific flags for this clock
 * @table: array of divider/value pairs ending with a div set to 0
 * @lock: shared register lock for this clock
 */
struct clk *clk_register_divider_table(struct device *dev, const char *name,
		const char *parent_name, unsigned long flags,
		void __iomem *reg, u8 shift, u8 width,
		u8 clk_divider_flags, const struct clk_div_table *table,
		spinlock_t *lock)
{
	return _register_divider(dev, name, parent_name, flags, reg, shift,
			width, clk_divider_flags, table, lock);
}
EXPORT_SYMBOL_GPL(clk_register_divider_table);
