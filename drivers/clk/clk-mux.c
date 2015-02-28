/*
 * Copyright (C) 2011 Sascha Hauer, Pengutronix <s.hauer@pengutronix.de>
 * Copyright (C) 2011 Richard Zhao, Linaro <richard.zhao@linaro.org>
 * Copyright (C) 2011-2012 Mike Turquette, Linaro Ltd <mturquette@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Simple multiplexer clock implementation
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/err.h>

/*
 * DOC: basic adjustable multiplexer clock that cannot gate
 *
 * Traits of this clock:
 * prepare - clk_prepare only ensures that parents are prepared
 * enable - clk_enable only ensures that parents are enabled
 * rate - rate is only affected by parent switching.  No clk_set_rate support
 * parent - parent is adjustable through clk_set_parent
 */

// ARM10C 20150131
#define to_clk_mux(_hw) container_of(_hw, struct clk_mux, hw)

// ARM10C 20150131
// clk->hw: (kmem_cache#29-oX (mout_mspll_kfc))->hw
// ARM10C 20150131
// clk->hw: (kmem_cache#29-oX (sclk_dpll))->hw
static u8 clk_mux_get_parent(struct clk_hw *hw)
{
	// hw: (kmem_cache#29-oX (mout_mspll_kfc))->hw
	// to_clk_mux((kmem_cache#29-oX (mout_mspll_kfc))->hw): kmem_cache#29-oX (mout_mspll_kfc)
	// hw: (kmem_cache#29-oX (sclk_dpll))->hw
	// to_clk_mux((kmem_cache#29-oX (sclk_dpll))->hw): kmem_cache#29-oX (sclk_dpll)
	struct clk_mux *mux = to_clk_mux(hw);
	// mux: kmem_cache#29-oX (mout_mspll_kfc)
	// mux: kmem_cache#29-oX (sclk_dpll)

	// hw->clk: ((kmem_cache#29-oX (mout_mspll_kfc))->hw)->clk
	// __clk_get_num_parents(((kmem_cache#29-oX (mout_mspll_kfc))->hw)->clk): 4
	// hw->clk: ((kmem_cache#29-oX (sclk_dpll))->hw)->clk
	// __clk_get_num_parents(((kmem_cache#29-oX (sclk_dpll))->hw)->clk): 2
	int num_parents = __clk_get_num_parents(hw->clk);
	// num_parents: 4
	// num_parents: 2

	u32 val;

	// NOTE:
	// E.R.M: 5.9.1.92 CLK_SRC_TOP3
	// 현재 5420 code 상에서는 0x1002_021c가 CLK_SRC_TOP7으로 되어 있는 상태임
	// exynos 5250 manual 상에서는 0x1002_021c 주소가 CLK_SRC_TOP3으로 되어 있음
	// exynos 5420 manual이 없으므로 관련 5250 manual 내용으로 분석진행
	// reset value: 0x0000_0000 으로 진행

	// NOTE:
	// E.R.M: 5.9.1.91 CLK_SRC_TOP2
	// 현재 5420 code 상에서는 0x1002_0218가 CLK_SRC_TOP6으로 되어 있는 상태임
	// exynos 5250 manual 상에서는 0x1002_0218 주소가 CLK_SRC_TOP2으로 되어 있음
	// CLK_SRC_TOP6의 28 bit의 값이 fin_pll: 0, fout_dpll: 1 로 선택하는 값을 가질것이라 예상됨
	// fout_dpll 로 가정하고 분석 진행 (24 bit: 1)

	/*
	 * FIXME need a mux-specific flag to determine if val is bitwise or numeric
	 * e.g. sys_clkin_ck's clksel field is 3 bits wide, but ranges from 0x1
	 * to 0x7 (index starts at one)
	 * OTOH, pmd_trace_clk_mux_ck uses a separate bit for each clock, so
	 * val = 0x4 really means "bit 2, index starts at bit 0"
	 */
	// mux->reg: (kmem_cache#29-oX (mout_mspll_kfc))->reg: 0xf005021c,
	// mux->shift: (kmem_cache#29-oX (mout_mspll_kfc))->shift: 8
	// clk_readl(0xf005021c): 0x0
	// mux->reg: (kmem_cache#29-oX (sclk_dpll))->reg: 0xf0050218,
	// mux->shift: (kmem_cache#29-oX (sclk_dpll))->shift: 24
	// clk_readl(0xf0050218): 0xX1XXXXXX
	val = clk_readl(mux->reg) >> mux->shift;
	// val: 0
	// val: 1

	// val: 0, mux->mask: (kmem_cache#29-oX (mout_mspll_kfc))->mask: 0x3
	// val: 1, mux->mask: (kmem_cache#29-oX (sclk_dpll))->mask: 0x3
	val &= mux->mask;
	// val: 0
	// val: 1

	// mux->table: (kmem_cache#29-oX (mout_mspll_kfc))->table: NULL
	// mux->table: (kmem_cache#29-oX (sclk_dpll))->table: NULL
	if (mux->table) {
		int i;

		for (i = 0; i < num_parents; i++)
			if (mux->table[i] == val)
				return i;
		return -EINVAL;
	}

	// val: 0, mux->flags: (kmem_cache#29-oX (mout_mspll_kfc))->flags: 0, CLK_MUX_INDEX_BIT: 0x2
	// val: 1, mux->flags: (kmem_cache#29-oX (sclk_dpll))->flags: 0, CLK_MUX_INDEX_BIT: 0x2
	if (val && (mux->flags & CLK_MUX_INDEX_BIT))
		val = ffs(val) - 1;

	// val: 0, mux->flags: (kmem_cache#29-oX (mout_mspll_kfc))->flags: 0, CLK_MUX_INDEX_ONE: 0x1
	// val: 1, mux->flags: (kmem_cache#29-oX (sclk_dpll))->flags: 0, CLK_MUX_INDEX_ONE: 0x1
	if (val && (mux->flags & CLK_MUX_INDEX_ONE))
		val--;

	// val: 0, num_parents: 4
	// val: 1, num_parents: 2
	if (val >= num_parents)
		return -EINVAL;

	// val: 0
	// val: 1
	return val;
	// return 0
	// return 1
}

static int clk_mux_set_parent(struct clk_hw *hw, u8 index)
{
	struct clk_mux *mux = to_clk_mux(hw);
	u32 val;
	unsigned long flags = 0;

	if (mux->table)
		index = mux->table[index];

	else {
		if (mux->flags & CLK_MUX_INDEX_BIT)
			index = (1 << ffs(index));

		if (mux->flags & CLK_MUX_INDEX_ONE)
			index++;
	}

	if (mux->lock)
		spin_lock_irqsave(mux->lock, flags);

	if (mux->flags & CLK_MUX_HIWORD_MASK) {
		val = mux->mask << (mux->shift + 16);
	} else {
		val = clk_readl(mux->reg);
		val &= ~(mux->mask << mux->shift);
	}
	val |= index << mux->shift;
	clk_writel(val, mux->reg);

	if (mux->lock)
		spin_unlock_irqrestore(mux->lock, flags);

	return 0;
}

// ARM10C 20150131
// ARM10C 20150228
const struct clk_ops clk_mux_ops = {
	.get_parent = clk_mux_get_parent,
	.set_parent = clk_mux_set_parent,
	.determine_rate = __clk_mux_determine_rate,
};
EXPORT_SYMBOL_GPL(clk_mux_ops);

const struct clk_ops clk_mux_ro_ops = {
	.get_parent = clk_mux_get_parent,
};
EXPORT_SYMBOL_GPL(clk_mux_ro_ops);

// ARM10C 20150131
// dev: NULL, name: "mout_mspll_kfc", parent_names: mspll_cpu_p, num_parents: 4,
// flags: 0x80, reg: 0xf005021c, shift: 8, mask: 0x3, clk_mux_flags: 0, NULL, lock: &lock
// ARM10C 20150131
// dev: NULL, name: "sclk_dpll", parent_names: dpll_p, num_parents: 2,
// flags: 0x80, reg: 0xf0050218, shift: 24, mask: 0x3, clk_mux_flags: 0, lock: &lock
struct clk *clk_register_mux_table(struct device *dev, const char *name,
		const char **parent_names, u8 num_parents, unsigned long flags,
		void __iomem *reg, u8 shift, u32 mask,
		u8 clk_mux_flags, u32 *table, spinlock_t *lock)
{
	struct clk_mux *mux;
	struct clk *clk;
	struct clk_init_data init;
	u8 width = 0;
	// width: 0
	// width: 0

	// clk_mux_flags: 0, CLK_MUX_HIWORD_MASK: 0x4
	// clk_mux_flags: 0, CLK_MUX_HIWORD_MASK: 0x4
	if (clk_mux_flags & CLK_MUX_HIWORD_MASK) {
		width = fls(mask) - ffs(mask) + 1;
		if (width + shift > 16) {
			pr_err("mux value exceeds LOWORD field\n");
			return ERR_PTR(-EINVAL);
		}
	}

	/* allocate the mux */
	// sizeof(struct clk_mux): 26 bytes, GFP_KERNEL: 0xD0
	// kzalloc(26, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	// sizeof(struct clk_mux): 26 bytes, GFP_KERNEL: 0xD0
	// kzalloc(26, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	mux = kzalloc(sizeof(struct clk_mux), GFP_KERNEL);
	// mux: kmem_cache#30-oX (mout_mspll_kfc)
	// mux: kmem_cache#30-oX (sclk_dpll)

	// mux: kmem_cache#30-oX (mout_mspll_kfc)
	// mux: kmem_cache#30-oX (sclk_dpll)
	if (!mux) {
		pr_err("%s: could not allocate mux clk\n", __func__);
		return ERR_PTR(-ENOMEM);
	}

	// name: "mout_mspll_kfc"
	// name: "sclk_dpll"
	init.name = name;
	// init.name: "mout_mspll_kfc"
	// init.name: "sclk_dpll"

	// clk_mux_flags: 0, CLK_MUX_READ_ONLY: 0x8
	// clk_mux_flags: 0, CLK_MUX_READ_ONLY: 0x8
	if (clk_mux_flags & CLK_MUX_READ_ONLY)
		init.ops = &clk_mux_ro_ops;
	else
		init.ops = &clk_mux_ops;
		// init.ops: &clk_mux_ops
		// init.ops: &clk_mux_ops

	// flags: 0x80, CLK_IS_BASIC: 0x20
	// flags: 0x80, CLK_IS_BASIC: 0x20
	init.flags = flags | CLK_IS_BASIC;
	// init.flags: 0xa0
	// init.flags: 0xa0

	// parent_names: mspll_cpu_p
	// parent_names: dpll_p
	init.parent_names = parent_names;
	// init.parent_names: mspll_cpu_p
	// init.parent_names: dpll_p

	// num_parents: 4
	// num_parents: 2
	init.num_parents = num_parents;
	// init.num_parents: 4
	// init.num_parents: 2

	/* struct clk_mux assignments */
	// mux->reg: (kmem_cache#30-oX (mout_mspll_kfc))->reg, reg: 0xf005021c
	// mux->reg: (kmem_cache#30-oX (sclk_dpll))->reg, reg: 0xf0050218
	mux->reg = reg;
	// mux->reg: (kmem_cache#30-oX (mout_mspll_kfc))->reg: 0xf005021c
	// mux->reg: (kmem_cache#30-oX (sclk_dpll))->reg: 0xf0050218

	// mux->shift: (kmem_cache#30-oX (mout_mspll_kfc))->shift, shift: 8
	// mux->shift: (kmem_cache#30-oX (sclk_dpll))->shift, shift: 24
	mux->shift = shift;
	// mux->shift: (kmem_cache#30-oX (mout_mspll_kfc))->shift: 8
	// mux->shift: (kmem_cache#30-oX (sclk_dpll))->shift: 24

	// mux->mask: (kmem_cache#30-oX (mout_mspll_kfc))->mask, mask: 0x3
	// mux->mask: (kmem_cache#30-oX (sclk_dpll))->mask, mask: 0x3
	mux->mask = mask;
	// mux->mask: (kmem_cache#30-oX (mout_mspll_kfc))->mask: 0x3
	// mux->mask: (kmem_cache#30-oX (sclk_dpll))->mask: 0x3

	// mux->flags: (kmem_cache#30-oX (mout_mspll_kfc))->flags, clk_mux_flags: 0
	// mux->flags: (kmem_cache#30-oX (sclk_dpll))->flags, clk_mux_flags: 0
	mux->flags = clk_mux_flags;
	// mux->flags: (kmem_cache#30-oX (mout_mspll_kfc))->flags: 0
	// mux->flags: (kmem_cache#30-oX (sclk_dpll))->flags: 0

	// mux->lock: (kmem_cache#30-oX (mout_mspll_kfc))->lock, lock: &lock
	// mux->lock: (kmem_cache#30-oX (sclk_dpll))->lock, lock: &lock
	mux->lock = lock;
	// mux->lock: (kmem_cache#30-oX (mout_mspll_kfc))->lock: &lock
	// mux->lock: (kmem_cache#30-oX (sclk_dpll))->lock: &lock

	// mux->table: (kmem_cache#30-oX (mout_mspll_kfc))->table, table: NULL
	// mux->table: (kmem_cache#30-oX (sclk_dpll))->table, table: NULL
	mux->table = table;
	// mux->table: (kmem_cache#30-oX (mout_mspll_kfc))->table: NULL
	// mux->table: (kmem_cache#30-oX (sclk_dpll))->table: NULL

	// mux->hw.init: (kmem_cache#30-oX (mout_mspll_kfc))->hw.init
	// mux->hw.init: (kmem_cache#30-oX (sclk_dpll))->hw.init
	mux->hw.init = &init;
	// mux->hw.init: (kmem_cache#30-oX (mout_mspll_kfc))->hw.init: &init
	// mux->hw.init: (kmem_cache#30-oX (sclk_dpll))->hw.init: &init

	// dev: NULL, &mux->hw: &(kmem_cache#30-oX (mout_mspll_kfc))->hw
	// clk_register(NULL, &(kmem_cache#30-oX (mout_mspll_kfc))->hw): kmem_cache#29-oX (mout_mspll_kfc)
	// dev: NULL, &mux->hw: &(kmem_cache#30-oX (sclk_dpll))->hw
	// clk_register(NULL, &(kmem_cache#30-oX (sclk_dpll))->hw): kmem_cache#29-oX (sclk_dpll)
	clk = clk_register(dev, &mux->hw);
	// clk: kmem_cache#29-oX (mout_mspll_kfc)
	// clk: kmem_cache#29-oX (sclk_dpll)

	// clk_register(mout_mspll_kfc)에서 한일:
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

	// clk_register(sclk_dpll)에서 한일:
	// (kmem_cache#29-oX (sclk_dpll))->name: kmem_cache#30-oX ("sclk_dpll")
	// (kmem_cache#29-oX (sclk_dpll))->ops: &clk_mux_ops
	// (kmem_cache#29-oX (sclk_dpll))->hw: &(kmem_cache#30-oX (sclk_dpll))->hw
	// (kmem_cache#29-oX (sclk_dpll))->flags: 0xa0
	// (kmem_cache#29-oX (sclk_dpll))->num_parents 2
	// (kmem_cache#29-oX (sclk_dpll))->parent_names: kmem_cache#30-oX
	// (kmem_cache#29-oX (sclk_dpll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
	// (kmem_cache#29-oX (sclk_dpll))->parent_names[1]: (kmem_cache#30-oX)[1]: kmem_cache#30-oX: "fout_dpll"
	// (kmem_cache#29-oX (sclk_dpll))->parent: NULL
	// (kmem_cache#29-oX (sclk_dpll))->rate: 600000000
	//
	// (kmem_cache#29-oX (sclk_dpll))->parents: kmem_cache#30-oX
	// (kmem_cache#29-oX (sclk_dpll))->parents[0]: (kmem_cache#30-oX)[0]: kmem_cache#29-oX (fin_pll)
	// (kmem_cache#29-oX (sclk_dpll))->parents[1]: (kmem_cache#30-oX)[1]: kmem_cache#29-oX (fout_dpll)
	//
	// parents 인 "fin_pll", "fout_dpll" 값들 중에
	// register CLK_SRC_TOP6 의 값을 읽어서 mux 할 parent clock 을 선택함
	// return된 값이 선택된 parent clock의 index 값임
	// parent clock 중에 선택된 parent clock의 이름으로 등록된 clk struct를 반환함
	//
	// (&(kmem_cache#29-oX (sclk_dpll))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (sclk_dpll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_dpll))->child_node)
	//
	// (&(kmem_cache#29-oX (fout_dpll))->children)->first: &(kmem_cache#29-oX (sclk_dpll))->child_node
	//
	// (&(kmem_cache#30-oX (sclk_dpll))->hw)->clk: kmem_cache#29-oX (sclk_dpll)
	//
	// orphan 으로 등록된 mout_mspll_kfc의 값을 갱신
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
	//
	// (&(kmem_cache#29-oX (sclk_dpll))->children)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
	//
	// (kmem_cache#29-oX (mout_mspll_kfc))->parent: kmem_cache#29-oX (sclk_dpll)
	//
	// parent가 있는지 확인후 parent의 clock rate 값으로 clock rate 값을 세팅
	// (kmem_cache#29-oX (mout_mspll_kfc))->rate: 600000000

	if (IS_ERR(clk))
		kfree(mux);

	// clk: kmem_cache#29-oX (mout_mspll_kfc)
	// clk: kmem_cache#29-oX (sclk_dpll)
	return clk;
	// return kmem_cache#29-oX (mout_mspll_kfc)
	// return kmem_cache#29-oX (sclk_dpll)
}
EXPORT_SYMBOL_GPL(clk_register_mux_table);

// ARM10C 20150131
// NULL,
// list->name: exynos5420_mux_clks[0].name: "mout_mspll_kfc",
// list->parent_names: exynos5420_mux_clks[0].parent_names: mspll_cpu_p,
// list->num_parents: exynos5420_mux_clks[0].num_parents: 4,
// list->flags: exynos5420_mux_clks[0].flags: 0x80,
// 0xf005021c,
// list->shift: exynos5420_mux_clks[0].shift: 8,
// list->width: exynos5420_mux_clks[0].width: 2,
// list->mux_flags: exynos5420_mux_clks[0].mux_flags: 0,
// &lock
// ARM10C 20150131
// NULL,
// list->name: exynos5420_mux_clks[44].name: "sclk_dpll",
// list->parent_names: exynos5420_mux_clks[44].parent_names: dpll_p,
// list->num_parents: exynos5420_mux_clks[44].num_parents: 2,
// list->flags: exynos5420_mux_clks[44].flags: 0x80,
// 0xf0050218,
// list->shift: exynos5420_mux_clks[44].shift: 24,
// list->width: exynos5420_mux_clks[44].width: 1,
// list->mux_flags: exynos5420_mux_clks[44].mux_flags: 0
// &lock
struct clk *clk_register_mux(struct device *dev, const char *name,
		const char **parent_names, u8 num_parents, unsigned long flags,
		void __iomem *reg, u8 shift, u8 width,
		u8 clk_mux_flags, spinlock_t *lock)
{
	// width: 2, BIT(2): 0x4
	// width: 2, BIT(2): 0x4
	u32 mask = BIT(width) - 1;
	// mask: 0x3
	// mask: 0x3

	// dev: NULL, name: "mout_mspll_kfc", parent_names: mspll_cpu_p, num_parents: 4,
	// flags: 0x80, reg: 0xf005021c, shift: 8, mask: 0x3, clk_mux_flags: 0, lock: &lock
	// clk_register_mux_table(NULL, "mout_mspll_kfc", mspll_cpu_p, 4, 0x80, 0xf005021c, 8, 0x3, 0, NULL, &lock):
	// kmem_cache#29-oX (mout_mspll_kfc)
	// dev: NULL, name: "sclk_dpll", parent_names: cpll_p, num_parents: 2,
	// flags: 0x80, reg: 0xf0050218, shift: 28, mask: 0x3, clk_mux_flags: 0, lock: &lock
	// clk_register_mux_table(NULL, "sclk_dpll", dpll_p, 2, 0x80, 0xf0050218, 24, 0x3, 0, NULL, &lock):
	// kmem_cache#29-oX (sclk_dpll)
	return clk_register_mux_table(dev, name, parent_names, num_parents,
				      flags, reg, shift, mask, clk_mux_flags,
				      NULL, lock);
	// return kmem_cache#29-oX (mout_mspll_kfc)
	// return kmem_cache#29-oX (sclk_dpll)

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

	// clk_register_mux_table(sclk_dpll) 에서 한일:
	// struct clk_mux 만큼 메모리를 kmem_cache#30-oX (sclk_dpll) 할당 받고 struct clk_mux 의 멤버 값을 아래와 같이 초기화 수행
	//
	// (kmem_cache#30-oX)->reg: 0xf0050218
	// (kmem_cache#30-oX)->shift: 24
	// (kmem_cache#30-oX)->mask: 0x3
	// (kmem_cache#30-oX)->flags: 0
	// (kmem_cache#30-oX)->lock: &lock
	// (kmem_cache#30-oX)->table: NULL
	// (kmem_cache#30-oX)->hw.init: &init
	//
	// struct clk 만큼 메모리를 kmem_cache#29-oX (sclk_dpll) 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
	//
	// (kmem_cache#29-oX (sclk_dpll))->name: kmem_cache#30-oX ("sclk_dpll")
	// (kmem_cache#29-oX (sclk_dpll))->ops: &clk_mux_ops
	// (kmem_cache#29-oX (sclk_dpll))->hw: &(kmem_cache#30-oX (sclk_dpll))->hw
	// (kmem_cache#29-oX (sclk_dpll))->flags: 0xa0
	// (kmem_cache#29-oX (sclk_dpll))->num_parents 2
	// (kmem_cache#29-oX (sclk_dpll))->parent_names: kmem_cache#30-oX
	// (kmem_cache#29-oX (sclk_dpll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
	// (kmem_cache#29-oX (sclk_dpll))->parent_names[1]: (kmem_cache#30-oX)[1]: kmem_cache#30-oX: "fout_dpll"
	// (kmem_cache#29-oX (sclk_dpll))->parent: NULL
	// (kmem_cache#29-oX (sclk_dpll))->rate: 600000000
	//
	// (kmem_cache#29-oX (sclk_dpll))->parents: kmem_cache#30-oX
	// (kmem_cache#29-oX (sclk_dpll))->parents[0]: (kmem_cache#30-oX)[0]: kmem_cache#29-oX (fin_pll)
	// (kmem_cache#29-oX (sclk_dpll))->parents[1]: (kmem_cache#30-oX)[1]: kmem_cache#29-oX (fout_dpll)
	//
	// parents 인 "fin_pll", "fout_dpll" 값들 중에
	// register CLK_SRC_TOP6 의 값을 읽어서 mux 할 parent clock 을 선택함
	// return된 값이 선택된 parent clock의 index 값임
	// parent clock 중에 선택된 parent clock의 이름으로 등록된 clk struct를 반환함
	//
	// (&(kmem_cache#29-oX (sclk_dpll))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (sclk_dpll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_dpll))->child_node)
	//
	// (&(kmem_cache#29-oX (fout_dpll))->children)->first: &(kmem_cache#29-oX (sclk_dpll))->child_node
	//
	// (&(kmem_cache#30-oX (sclk_dpll))->hw)->clk: kmem_cache#29-oX (sclk_dpll)
	//
	// orphan 으로 등록된 mout_mspll_kfc의 값을 갱신
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
	//
	// (&(kmem_cache#29-oX (sclk_dpll))->children)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
	//
	// (kmem_cache#29-oX (mout_mspll_kfc))->parent: kmem_cache#29-oX (sclk_dpll)
	//
	// parent가 있는지 확인후 parent의 clock rate 값으로 clock rate 값을 세팅
	// (kmem_cache#29-oX (mout_mspll_kfc))->rate: 600000000
}
EXPORT_SYMBOL_GPL(clk_register_mux);
