/* linux/arch/arm/mach-exynos4/mct.c
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * EXYNOS4 MCT(Multi-Core Timer) support
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/err.h>
#include <linux/clk.h>
#include <linux/clockchips.h>
#include <linux/cpu.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/percpu.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/clocksource.h>

#include <asm/mach/time.h>

#define EXYNOS4_MCTREG(x)		(x)
#define EXYNOS4_MCT_G_CNT_L		EXYNOS4_MCTREG(0x100)
#define EXYNOS4_MCT_G_CNT_U		EXYNOS4_MCTREG(0x104)
#define EXYNOS4_MCT_G_CNT_WSTAT		EXYNOS4_MCTREG(0x110)
#define EXYNOS4_MCT_G_COMP0_L		EXYNOS4_MCTREG(0x200)
#define EXYNOS4_MCT_G_COMP0_U		EXYNOS4_MCTREG(0x204)
#define EXYNOS4_MCT_G_COMP0_ADD_INCR	EXYNOS4_MCTREG(0x208)
#define EXYNOS4_MCT_G_TCON		EXYNOS4_MCTREG(0x240)
#define EXYNOS4_MCT_G_INT_CSTAT		EXYNOS4_MCTREG(0x244)
#define EXYNOS4_MCT_G_INT_ENB		EXYNOS4_MCTREG(0x248)
#define EXYNOS4_MCT_G_WSTAT		EXYNOS4_MCTREG(0x24C)
#define _EXYNOS4_MCT_L_BASE		EXYNOS4_MCTREG(0x300)
#define EXYNOS4_MCT_L_BASE(x)		(_EXYNOS4_MCT_L_BASE + (0x100 * x))
#define EXYNOS4_MCT_L_MASK		(0xffffff00)

#define MCT_L_TCNTB_OFFSET		(0x00)
#define MCT_L_ICNTB_OFFSET		(0x08)
#define MCT_L_TCON_OFFSET		(0x20)
#define MCT_L_INT_CSTAT_OFFSET		(0x30)
#define MCT_L_INT_ENB_OFFSET		(0x34)
#define MCT_L_WSTAT_OFFSET		(0x40)
#define MCT_G_TCON_START		(1 << 8)
#define MCT_G_TCON_COMP0_AUTO_INC	(1 << 1)
#define MCT_G_TCON_COMP0_ENABLE		(1 << 0)
#define MCT_L_TCON_INTERVAL_MODE	(1 << 2)
#define MCT_L_TCON_INT_START		(1 << 1)
#define MCT_L_TCON_TIMER_START		(1 << 0)

#define TICK_BASE_CNT	1

// ARM10C 20150307
// ARM10C 20150328
enum {
	// MCT_INT_SPI: 0
	MCT_INT_SPI,
	// MCT_INT_PPI: 1
	MCT_INT_PPI
};

// ARM10C 20150307
// ARM10C 20150328
enum {
	// MCT_G0_IRQ: 0
	MCT_G0_IRQ,
	MCT_G1_IRQ,
	MCT_G2_IRQ,
	MCT_G3_IRQ,
	// MCT_L0_IRQ: 4
	MCT_L0_IRQ,
	MCT_L1_IRQ,
	MCT_L2_IRQ,
	MCT_L3_IRQ,
	// MCT_NR_IRQS: 8
	MCT_NR_IRQS,
};

// ARM10C 20150328
static void __iomem *reg_base;
static unsigned long clk_rate;
// ARM10C 20150307
// ARM10C 20150328
static unsigned int mct_int_type;
// ARM10C 20150307
// ARM10C 20150321
// MCT_NR_IRQS: 8
static int mct_irqs[MCT_NR_IRQS];

// ARM10C 20150321
struct mct_clock_event_device {
	struct clock_event_device evt;
	unsigned long base;
	char name[10];
};

static void exynos4_mct_write(unsigned int value, unsigned long offset)
{
	unsigned long stat_addr;
	u32 mask;
	u32 i;

	__raw_writel(value, reg_base + offset);

	if (likely(offset >= EXYNOS4_MCT_L_BASE(0))) {
		stat_addr = (offset & ~EXYNOS4_MCT_L_MASK) + MCT_L_WSTAT_OFFSET;
		switch (offset & EXYNOS4_MCT_L_MASK) {
		case MCT_L_TCON_OFFSET:
			mask = 1 << 3;		/* L_TCON write status */
			break;
		case MCT_L_ICNTB_OFFSET:
			mask = 1 << 1;		/* L_ICNTB write status */
			break;
		case MCT_L_TCNTB_OFFSET:
			mask = 1 << 0;		/* L_TCNTB write status */
			break;
		default:
			return;
		}
	} else {
		switch (offset) {
		case EXYNOS4_MCT_G_TCON:
			stat_addr = EXYNOS4_MCT_G_WSTAT;
			mask = 1 << 16;		/* G_TCON write status */
			break;
		case EXYNOS4_MCT_G_COMP0_L:
			stat_addr = EXYNOS4_MCT_G_WSTAT;
			mask = 1 << 0;		/* G_COMP0_L write status */
			break;
		case EXYNOS4_MCT_G_COMP0_U:
			stat_addr = EXYNOS4_MCT_G_WSTAT;
			mask = 1 << 1;		/* G_COMP0_U write status */
			break;
		case EXYNOS4_MCT_G_COMP0_ADD_INCR:
			stat_addr = EXYNOS4_MCT_G_WSTAT;
			mask = 1 << 2;		/* G_COMP0_ADD_INCR w status */
			break;
		case EXYNOS4_MCT_G_CNT_L:
			stat_addr = EXYNOS4_MCT_G_CNT_WSTAT;
			mask = 1 << 0;		/* G_CNT_L write status */
			break;
		case EXYNOS4_MCT_G_CNT_U:
			stat_addr = EXYNOS4_MCT_G_CNT_WSTAT;
			mask = 1 << 1;		/* G_CNT_U write status */
			break;
		default:
			return;
		}
	}

	/* Wait maximum 1 ms until written values are applied */
	for (i = 0; i < loops_per_jiffy / 1000 * HZ; i++)
		if (__raw_readl(reg_base + stat_addr) & mask) {
			__raw_writel(mask, reg_base + stat_addr);
			return;
		}

	panic("MCT hangs after writing %d (offset:0x%lx)\n", value, offset);
}

/* Clocksource handling */
static void exynos4_mct_frc_start(u32 hi, u32 lo)
{
	u32 reg;

	exynos4_mct_write(lo, EXYNOS4_MCT_G_CNT_L);
	exynos4_mct_write(hi, EXYNOS4_MCT_G_CNT_U);

	reg = __raw_readl(reg_base + EXYNOS4_MCT_G_TCON);
	reg |= MCT_G_TCON_START;
	exynos4_mct_write(reg, EXYNOS4_MCT_G_TCON);
}

static cycle_t exynos4_frc_read(struct clocksource *cs)
{
	unsigned int lo, hi;
	u32 hi2 = __raw_readl(reg_base + EXYNOS4_MCT_G_CNT_U);

	do {
		hi = hi2;
		lo = __raw_readl(reg_base + EXYNOS4_MCT_G_CNT_L);
		hi2 = __raw_readl(reg_base + EXYNOS4_MCT_G_CNT_U);
	} while (hi != hi2);

	return ((cycle_t)hi << 32) | lo;
}

static void exynos4_frc_resume(struct clocksource *cs)
{
	exynos4_mct_frc_start(0, 0);
}

struct clocksource mct_frc = {
	.name		= "mct-frc",
	.rating		= 400,
	.read		= exynos4_frc_read,
	.mask		= CLOCKSOURCE_MASK(64),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
	.resume		= exynos4_frc_resume,
};

static void __init exynos4_clocksource_init(void)
{
	exynos4_mct_frc_start(0, 0);

	if (clocksource_register_hz(&mct_frc, clk_rate))
		panic("%s: can't register clocksource\n", mct_frc.name);
}

static void exynos4_mct_comp0_stop(void)
{
	unsigned int tcon;

	tcon = __raw_readl(reg_base + EXYNOS4_MCT_G_TCON);
	tcon &= ~(MCT_G_TCON_COMP0_ENABLE | MCT_G_TCON_COMP0_AUTO_INC);

	exynos4_mct_write(tcon, EXYNOS4_MCT_G_TCON);
	exynos4_mct_write(0, EXYNOS4_MCT_G_INT_ENB);
}

static void exynos4_mct_comp0_start(enum clock_event_mode mode,
				    unsigned long cycles)
{
	unsigned int tcon;
	cycle_t comp_cycle;

	tcon = __raw_readl(reg_base + EXYNOS4_MCT_G_TCON);

	if (mode == CLOCK_EVT_MODE_PERIODIC) {
		tcon |= MCT_G_TCON_COMP0_AUTO_INC;
		exynos4_mct_write(cycles, EXYNOS4_MCT_G_COMP0_ADD_INCR);
	}

	comp_cycle = exynos4_frc_read(&mct_frc) + cycles;
	exynos4_mct_write((u32)comp_cycle, EXYNOS4_MCT_G_COMP0_L);
	exynos4_mct_write((u32)(comp_cycle >> 32), EXYNOS4_MCT_G_COMP0_U);

	exynos4_mct_write(0x1, EXYNOS4_MCT_G_INT_ENB);

	tcon |= MCT_G_TCON_COMP0_ENABLE;
	exynos4_mct_write(tcon , EXYNOS4_MCT_G_TCON);
}

static int exynos4_comp_set_next_event(unsigned long cycles,
				       struct clock_event_device *evt)
{
	exynos4_mct_comp0_start(evt->mode, cycles);

	return 0;
}

static void exynos4_comp_set_mode(enum clock_event_mode mode,
				  struct clock_event_device *evt)
{
	unsigned long cycles_per_jiffy;
	exynos4_mct_comp0_stop();

	switch (mode) {
	case CLOCK_EVT_MODE_PERIODIC:
		cycles_per_jiffy =
			(((unsigned long long) NSEC_PER_SEC / HZ * evt->mult) >> evt->shift);
		exynos4_mct_comp0_start(mode, cycles_per_jiffy);
		break;

	case CLOCK_EVT_MODE_ONESHOT:
	case CLOCK_EVT_MODE_UNUSED:
	case CLOCK_EVT_MODE_SHUTDOWN:
	case CLOCK_EVT_MODE_RESUME:
		break;
	}
}

static struct clock_event_device mct_comp_device = {
	.name		= "mct-comp",
	.features       = CLOCK_EVT_FEAT_PERIODIC | CLOCK_EVT_FEAT_ONESHOT,
	.rating		= 250,
	.set_next_event	= exynos4_comp_set_next_event,
	.set_mode	= exynos4_comp_set_mode,
};

static irqreturn_t exynos4_mct_comp_isr(int irq, void *dev_id)
{
	struct clock_event_device *evt = dev_id;

	exynos4_mct_write(0x1, EXYNOS4_MCT_G_INT_CSTAT);

	evt->event_handler(evt);

	return IRQ_HANDLED;
}

static struct irqaction mct_comp_event_irq = {
	.name		= "mct_comp_irq",
	.flags		= IRQF_TIMER | IRQF_IRQPOLL,
	.handler	= exynos4_mct_comp_isr,
	.dev_id		= &mct_comp_device,
};

static void exynos4_clockevent_init(void)
{
	mct_comp_device.cpumask = cpumask_of(0);
	clockevents_config_and_register(&mct_comp_device, clk_rate,
					0xf, 0xffffffff);
	setup_irq(mct_irqs[MCT_G0_IRQ], &mct_comp_event_irq);
}

// ARM10C 20150321
static DEFINE_PER_CPU(struct mct_clock_event_device, percpu_mct_tick);

/* Clock event handling */
static void exynos4_mct_tick_stop(struct mct_clock_event_device *mevt)
{
	unsigned long tmp;
	unsigned long mask = MCT_L_TCON_INT_START | MCT_L_TCON_TIMER_START;
	unsigned long offset = mevt->base + MCT_L_TCON_OFFSET;

	tmp = __raw_readl(reg_base + offset);
	if (tmp & mask) {
		tmp &= ~mask;
		exynos4_mct_write(tmp, offset);
	}
}

static void exynos4_mct_tick_start(unsigned long cycles,
				   struct mct_clock_event_device *mevt)
{
	unsigned long tmp;

	exynos4_mct_tick_stop(mevt);

	tmp = (1 << 31) | cycles;	/* MCT_L_UPDATE_ICNTB */

	/* update interrupt count buffer */
	exynos4_mct_write(tmp, mevt->base + MCT_L_ICNTB_OFFSET);

	/* enable MCT tick interrupt */
	exynos4_mct_write(0x1, mevt->base + MCT_L_INT_ENB_OFFSET);

	tmp = __raw_readl(reg_base + mevt->base + MCT_L_TCON_OFFSET);
	tmp |= MCT_L_TCON_INT_START | MCT_L_TCON_TIMER_START |
	       MCT_L_TCON_INTERVAL_MODE;
	exynos4_mct_write(tmp, mevt->base + MCT_L_TCON_OFFSET);
}

static int exynos4_tick_set_next_event(unsigned long cycles,
				       struct clock_event_device *evt)
{
	struct mct_clock_event_device *mevt = this_cpu_ptr(&percpu_mct_tick);

	exynos4_mct_tick_start(cycles, mevt);

	return 0;
}

static inline void exynos4_tick_set_mode(enum clock_event_mode mode,
					 struct clock_event_device *evt)
{
	struct mct_clock_event_device *mevt = this_cpu_ptr(&percpu_mct_tick);
	unsigned long cycles_per_jiffy;

	exynos4_mct_tick_stop(mevt);

	switch (mode) {
	case CLOCK_EVT_MODE_PERIODIC:
		cycles_per_jiffy =
			(((unsigned long long) NSEC_PER_SEC / HZ * evt->mult) >> evt->shift);
		exynos4_mct_tick_start(cycles_per_jiffy, mevt);
		break;

	case CLOCK_EVT_MODE_ONESHOT:
	case CLOCK_EVT_MODE_UNUSED:
	case CLOCK_EVT_MODE_SHUTDOWN:
	case CLOCK_EVT_MODE_RESUME:
		break;
	}
}

static int exynos4_mct_tick_clear(struct mct_clock_event_device *mevt)
{
	struct clock_event_device *evt = &mevt->evt;

	/*
	 * This is for supporting oneshot mode.
	 * Mct would generate interrupt periodically
	 * without explicit stopping.
	 */
	if (evt->mode != CLOCK_EVT_MODE_PERIODIC)
		exynos4_mct_tick_stop(mevt);

	/* Clear the MCT tick interrupt */
	if (__raw_readl(reg_base + mevt->base + MCT_L_INT_CSTAT_OFFSET) & 1) {
		exynos4_mct_write(0x1, mevt->base + MCT_L_INT_CSTAT_OFFSET);
		return 1;
	} else {
		return 0;
	}
}

static irqreturn_t exynos4_mct_tick_isr(int irq, void *dev_id)
{
	struct mct_clock_event_device *mevt = dev_id;
	struct clock_event_device *evt = &mevt->evt;

	exynos4_mct_tick_clear(mevt);

	evt->event_handler(evt);

	return IRQ_HANDLED;
}

static int exynos4_local_timer_setup(struct clock_event_device *evt)
{
	struct mct_clock_event_device *mevt;
	unsigned int cpu = smp_processor_id();

	mevt = container_of(evt, struct mct_clock_event_device, evt);

	mevt->base = EXYNOS4_MCT_L_BASE(cpu);
	sprintf(mevt->name, "mct_tick%d", cpu);

	evt->name = mevt->name;
	evt->cpumask = cpumask_of(cpu);
	evt->set_next_event = exynos4_tick_set_next_event;
	evt->set_mode = exynos4_tick_set_mode;
	evt->features = CLOCK_EVT_FEAT_PERIODIC | CLOCK_EVT_FEAT_ONESHOT;
	evt->rating = 450;
	clockevents_config_and_register(evt, clk_rate / (TICK_BASE_CNT + 1),
					0xf, 0x7fffffff);

	exynos4_mct_write(TICK_BASE_CNT, mevt->base + MCT_L_TCNTB_OFFSET);

	if (mct_int_type == MCT_INT_SPI) {
		evt->irq = mct_irqs[MCT_L0_IRQ + cpu];
		if (request_irq(evt->irq, exynos4_mct_tick_isr,
				IRQF_TIMER | IRQF_NOBALANCING,
				evt->name, mevt)) {
			pr_err("exynos-mct: cannot register IRQ %d\n",
				evt->irq);
			return -EIO;
		}
	} else {
		enable_percpu_irq(mct_irqs[MCT_L0_IRQ], 0);
	}

	return 0;
}

static void exynos4_local_timer_stop(struct clock_event_device *evt)
{
	evt->set_mode(CLOCK_EVT_MODE_UNUSED, evt);
	if (mct_int_type == MCT_INT_SPI)
		free_irq(evt->irq, this_cpu_ptr(&percpu_mct_tick));
	else
		disable_percpu_irq(mct_irqs[MCT_L0_IRQ]);
}

static int exynos4_mct_cpu_notify(struct notifier_block *self,
					   unsigned long action, void *hcpu)
{
	struct mct_clock_event_device *mevt;
	unsigned int cpu;

	/*
	 * Grab cpu pointer in each case to avoid spurious
	 * preemptible warnings
	 */
	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_STARTING:
		mevt = this_cpu_ptr(&percpu_mct_tick);
		exynos4_local_timer_setup(&mevt->evt);
		break;
	case CPU_ONLINE:
		cpu = (unsigned long)hcpu;
		if (mct_int_type == MCT_INT_SPI)
			irq_set_affinity(mct_irqs[MCT_L0_IRQ + cpu],
						cpumask_of(cpu));
		break;
	case CPU_DYING:
		mevt = this_cpu_ptr(&percpu_mct_tick);
		exynos4_local_timer_stop(&mevt->evt);
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block exynos4_mct_cpu_nb = {
	.notifier_call = exynos4_mct_cpu_notify,
};

// ARM10C 20150321
// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소, 0xf0006000
static void __init exynos4_timer_resources(struct device_node *np, void __iomem *base)
{
	int err;
	struct mct_clock_event_device *mevt = this_cpu_ptr(&percpu_mct_tick);
	// mevt: [pcp0] &percpu_mct_tick

	struct clk *mct_clk, *tick_clk;

	// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소
	// of_clk_get_by_name(devtree에서 allnext로 순회 하면서 찾은 mct node의 주소, "fin_pll"): kmem_cache#29-oX (fin_pll)
	tick_clk = np ? of_clk_get_by_name(np, "fin_pll") :
				clk_get(NULL, "fin_pll");
	// tick_clk: kmem_cache#29-oX (fin_pll)

	// of_clk_get_by_name에서 한일:
	// mct node의 property "clock-names" 의 값을 찾아서 "fin_pll" 이 있는 위치를 찾고
	// 몇번째 값인지 index를 구함
	//
	// mct node 에서 "clocks" property의 이용하여 devtree의 값을 파싱하여 clkspec에 값을 가져옴
	// (&clkspec)->np: clock node의 주소
	// (&clkspec)->args_count: 1
	// (&clkspec)->args[0]: 1
	//
	// list of_clk_providers 에 등록된 정보들 중에 clkspec 와 매치되는 정보를 찾음
	// 이전에 만들어 놓은 clk_data의 clk_table 정보를 이용하여 clkspec에 있는 arg 값을 이용하여 clk을 찾음
	// tick_clk: kmem_cache#29-oX (fin_pll)

	// tick_clk: kmem_cache#29-oX (fin_pll), IS_ERR(kmem_cache#29-oX (fin_pll)): 0
	if (IS_ERR(tick_clk))
		panic("%s: unable to determine tick clock rate\n", __func__);

	// tick_clk: kmem_cache#29-oX (fin_pll)
	// clk_get_rate(kmem_cache#29-oX (fin_pll)): 24000000
	clk_rate = clk_get_rate(tick_clk);
	// clk_rate: 24000000

	// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소
	// of_clk_get_by_name(devtree에서 allnext로 순회 하면서 찾은 mct node의 주소, "mct"):  kmem_cache#29-oX (mct)
	mct_clk = np ? of_clk_get_by_name(np, "mct") : clk_get(NULL, "mct");
	// mct_clk: kmem_cache#29-oX (mct)

	// of_clk_get_by_name에서 한일:
	// mct node의 property "clock-names" 의 값을 찾아서 "mct" 이 있는 위치를 찾고
	// 몇번째 값인지 index를 구함
	//
	// mct node 에서 "clocks" property의 이용하여 devtree의 값을 파싱하여 clkspec에 값을 가져옴
	// (&clkspec)->np: clock node의 주소
	// (&clkspec)->args_count: 1
	// (&clkspec)->args[0]: 315
	//
	// list of_clk_providers 에 등록된 정보들 중에 clkspec 와 매치되는 정보를 찾음
	// 이전에 만들어 놓은 clk_data의 clk_table 정보를 이용하여 clkspec에 있는 arg 값을 이용하여 clk을 찾음
	// mct_clk: kmem_cache#29-oX (mct)

	// mct_clk: kmem_cache#29-oX (mct), IS_ERR(kmem_cache#29-oX (mct)): 0
	if (IS_ERR(mct_clk))
		panic("%s: unable to retrieve mct clock instance\n", __func__);

	// mct_clk: kmem_cache#29-oX (mct)
	// clk_prepare_enable(kmem_cache#29-oX (mct)): 0
	clk_prepare_enable(mct_clk);

	// clk_prepare_enable에서 한일:
	// mct clock의 상위 clock 들의 ops->prepare 함수들을 수행.
	// mct clock의 상위 clock 들의 ops->enable 함수들을 수행.
	// sck_cpll -- Group1_p -- mout_aclk66 -- dout_aclk66 -- mct
	// sck_ppll -|
	// sck_mpll -|
	//
	// sck_cpll, mout_aclk66, dout_aclk66 의 주석을 만들지 않았기 때문에
	// 분석내용을 skip 하도록함

	// base: 0xf0006000
	reg_base = base;
	// reg_base: 0xf0006000

	// reg_base: 0xf0006000
	if (!reg_base)
		panic("%s: unable to ioremap mct address space\n", __func__);

	// mct_int_type: 0, MCT_INT_PPI: 1
	if (mct_int_type == MCT_INT_PPI) {

		err = request_percpu_irq(mct_irqs[MCT_L0_IRQ],
					 exynos4_mct_tick_isr, "MCT",
					 &percpu_mct_tick);
		WARN(err, "MCT: can't request IRQ %d (%d)\n",
		     mct_irqs[MCT_L0_IRQ], err);
	} else {
		// MCT_L0_IRQ: 4, mct_irqs[4]: 152, cpumask_of(0): &cpu_bit_bitmap[1][0]
		irq_set_affinity(mct_irqs[MCT_L0_IRQ], cpumask_of(0));
	}

	err = register_cpu_notifier(&exynos4_mct_cpu_nb);
	if (err)
		goto out_irq;

	/* Immediately configure the timer on the boot CPU */
	exynos4_local_timer_setup(&mevt->evt);
	return;

out_irq:
	free_percpu_irq(mct_irqs[MCT_L0_IRQ], &percpu_mct_tick);
}

void __init mct_init(void __iomem *base, int irq_g0, int irq_l0, int irq_l1)
{
	mct_irqs[MCT_G0_IRQ] = irq_g0;
	mct_irqs[MCT_L0_IRQ] = irq_l0;
	mct_irqs[MCT_L1_IRQ] = irq_l1;
	mct_int_type = MCT_INT_SPI;

	exynos4_timer_resources(NULL, base);
	exynos4_clocksource_init();
	exynos4_clockevent_init();
}

// ARM10C 20150307
// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소, MCT_INT_SPI: 0
static void __init mct_init_dt(struct device_node *np, unsigned int int_type)
{
	u32 nr_irqs, i;

	// int_type: 0
	mct_int_type = int_type;
	// mct_int_type: 0

	/* This driver uses only one global timer interrupt */
	// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소, MCT_G0_IRQ: 0
	// irq_of_parse_and_map(devtree에서 allnext로 순회 하면서 찾은 mct node의 주소, 0): 347
	mct_irqs[MCT_G0_IRQ] = irq_of_parse_and_map(np, MCT_G0_IRQ);
	// mct_irqs[0]: 347

	// irq_of_parse_and_map(mct node, 0)에서 한일:
	// devtree의 mct node의 interrupt의 property의 값을 dtb에  분석하여 oirq 값을 가져옴
	//
	// (&oirq)->np: combiner node의 주소
	// (&oirq)->args_count: 2
	// (&oirq)->args[0]: 23
	// (&oirq)->args[1]: 3
	//
	// oirq 값을 사용하여 combiner domain에서 virq 값을 찾음
	// virq: 347

	/*
	 * Find out the number of local irqs specified. The local
	 * timer irqs are specified after the four global timer
	 * irqs are specified.
	 */
#ifdef CONFIG_OF // CONFIG_OF=y
	// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소
	// of_irq_count(devtree에서 allnext로 순회 하면서 찾은 mct node의 주소): 8
	nr_irqs = of_irq_count(np);
	// nr_irqs: 8
	
	// of_irq_count(mct node)에서 한일:
	// devtree에 등록된 mct node에 irq 의 갯수를 구함
#else
	nr_irqs = 0;
#endif

	// nr_irqs: 8, MCT_L0_IRQ: 4
	for (i = MCT_L0_IRQ; i < nr_irqs; i++)
		// i: 4, np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소
		// irq_of_parse_and_map(devtree에서 allnext로 순회 하면서 찾은 mct node의 주소, 4): 152
		mct_irqs[i] = irq_of_parse_and_map(np, i);
		// mct_irqs[4]: 152
		
		// irq_of_parse_and_map(mct node, 4)에서 한일:
		// devtree의 mct node의 interrupt의 property의 값을 dtb에  분석하여 oirq 값을 가져옴
		//
		// (&oirq)->np: gic node의 주소
		// (&oirq)->args_count: 3
		// (&oirq)->args[0]: 0
		// (&oirq)->args[1]: 120
		// (&oirq)->args[2]: 0
		//
		// oirq 값을 사용하여 gic domain에서 virq 값을 찾음
		// virq: 152

		// i: 5...7 loop 수행

	// 위 loop의 수행 결과
	// mct_irqs[4]: 152
	// mct_irqs[5]: 153
	// mct_irqs[6]: 154
	// mct_irqs[7]: 155

	// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소
	// of_iomap(devtree에서 allnext로 순회 하면서 찾은 mct node의 주소, 0): 0xf0006000
	exynos4_timer_resources(np, of_iomap(np, 0));

	// of_iomap에서 한일:
	// device tree 있는  mct node에서 node의 resource 값을 가져옴
	// (&res)->start: 0x101C0000
	// (&res)->end: 0x101C07ff
	// (&res)->flags: IORESOURCE_MEM: 0x00000200
	// (&res)->name: "/mct@101C0000"
	/*
	// alloc area (MCT) 를 만들고 rb tree에 alloc area 를 추가
	// 가상주소 va_start 기준으로 MCT 를 RB Tree 추가한 결과
	//
	//                                      CHID-b
	//                                    (0xF8000000)
	//                                  /              \
	//                            CLK-b                  PMU-b
	//                         (0xF0040000)              (0xF8180000)
	//                        /          \                /        \
	//                 GIC#1-r            TMR-r        CMU-b         SRAM-b
	//             (0xF0002000)         (0xF6300000)   (0xF8100000)  (0xF8400000)
	//              /       \              /    \                         \
	//        GIC#0-b       COMB-b     SYSC-b     WDT-b                   ROMC-r
	//    (0xF0000000) (0xF0004000) (0xF6100000)  (0xF6400000)            (0xF84C0000)
	//                          \
	//                          MCT-r
	//                       (0xF0006000)
	//
	// vmap_area_list에 GIC#0 - GIC#1 - COMB - MCT - CLK - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
	// 순서로 리스트에 연결이 됨
	//
	// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
	// (kmem_cache#30-oX (vm_struct))->addr: 0xf0006000
	// (kmem_cache#30-oX (vm_struct))->size: 0x2000
	// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
	//
	// (kmem_cache#30-oX (vmap_area CLK))->vm: kmem_cache#30-oX (vm_struct)
	// (kmem_cache#30-oX (vmap_area CLK))->flags: 0x04
	*/
	// device tree 있는 mct node에서 node의 resource 값을 pgtable에 매핑함
	// 0xc0004780이 가리키는 pte의 시작주소에 0x101C0653 값을 갱신
	// (linux pgtable과 hardware pgtable의 값 같이 갱신)
	//
	//  pgd                   pte
	// |              |
	// +--------------+
	// |              |       +--------------+ +0
	// |              |       |  0xXXXXXXXX  | ---> 0x101C0653 에 매칭되는 linux pgtable 값
	// +- - - - - - - +       |  Linux pt 0  |
	// |              |       +--------------+ +1024
	// |              |       |              |
	// +--------------+ +0    |  Linux pt 1  |
	// | *(c0004780)  |-----> +--------------+ +2048
	// |              |       |  0x101C0653  | ---> 2076
	// +- - - - - - - + +4    |   h/w pt 0   |
	// | *(c0004784)  |-----> +--------------+ +3072
	// |              |       +              +
	// +--------------+ +8    |   h/w pt 1   |
	// |              |       +--------------+ +4096
	//
	// cache의 값을 전부 메모리에 반영

	exynos4_clocksource_init();
	exynos4_clockevent_init();
}


// ARM10C 20150307
// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소
static void __init mct_init_spi(struct device_node *np)
{
	// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소, MCT_INT_SPI: 0
	return mct_init_dt(np, MCT_INT_SPI);
}

static void __init mct_init_ppi(struct device_node *np)
{
	return mct_init_dt(np, MCT_INT_PPI);
}
// ARM10C 20150307
// #define CLOCKSOURCE_OF_DECLARE(exynos4210, "samsung,exynos4210-mct", mct_init_spi):
// static const struct of_device_id __clksrc_of_table_exynos4210 __used __section(__clksrc_of_table)
// = { .compatible = "samsung,exynos4210-mct",
//     .data = (mct_init_spi == (clocksource_of_init_fn)NULL) ? mct_init_spi : mct_init_spi }
CLOCKSOURCE_OF_DECLARE(exynos4210, "samsung,exynos4210-mct", mct_init_spi);

// ARM10C 20150307
// #define CLOCKSOURCE_OF_DECLARE(exynos4412, "samsung,exynos4412-mct", mct_init_ppi):
// static const struct of_device_id __clksrc_of_table_exynos4412 __used __section(__clksrc_of_table)
// = { .compatible = "samsung,exynos4412-mct",
//     .data = (mct_init_ppi == (clocksource_of_init_fn)NULL) ? mct_init_ppi : mct_init_ppi }
CLOCKSOURCE_OF_DECLARE(exynos4412, "samsung,exynos4412-mct", mct_init_ppi);
