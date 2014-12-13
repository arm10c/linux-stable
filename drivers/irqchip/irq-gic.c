/*
 *  linux/arch/arm/common/gic.c
 *
 *  Copyright (C) 2002 ARM Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Interrupt architecture for the GIC:
 *
 * o There is one Interrupt Distributor, which receives interrupts
 *   from system devices and sends them to the Interrupt Controllers.
 *
 * o There is one CPU Interface per CPU, which sends interrupts sent
 *   by the Distributor, and interrupts generated locally, to the
 *   associated CPU. The base address of the CPU interface is usually
 *   aliased so that the same address points to different chips depending
 *   on the CPU it is accessed from.
 *
 * Note that IRQs 0-31 are special - they are local to each CPU.
 * As such, the enable set/clear, pending set/clear and active bit
 * registers are banked per-cpu for these sources.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/cpu_pm.h>
#include <linux/cpumask.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/irqdomain.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqchip/arm-gic.h>

#include <asm/irq.h>
#include <asm/exception.h>
#include <asm/smp_plat.h>

#include "irqchip.h"

union gic_base {
	void __iomem *common_base;
	void __percpu __iomem **percpu_base;
};

// ARM10C 20141108
struct gic_chip_data {
	union gic_base dist_base;
	union gic_base cpu_base;
#ifdef CONFIG_CPU_PM // CONFIG_CPU_PM=y
	u32 saved_spi_enable[DIV_ROUND_UP(1020, 32)];
	u32 saved_spi_conf[DIV_ROUND_UP(1020, 16)];
	u32 saved_spi_target[DIV_ROUND_UP(1020, 4)];
	u32 __percpu *saved_ppi_enable;
	u32 __percpu *saved_ppi_conf;
#endif
	struct irq_domain *domain;
	unsigned int gic_irqs;
#ifdef CONFIG_GIC_NON_BANKED // CONFIG_GIC_NON_BANKED=n
	void __iomem *(*get_base)(union gic_base *);
#endif
};

static DEFINE_RAW_SPINLOCK(irq_controller_lock);

/*
 * The GIC mapping of CPU interfaces does not necessarily match
 * the logical CPU numbering.  Let's use a mapping as returned
 * by the GIC itself.
 */
// ARM10C 20141108
// ARM10C 20141129
// NR_GIC_CPU_IF: 8
#define NR_GIC_CPU_IF 8

// ARM10C 20141108
// ARM10C 20141129
// NR_GIC_CPU_IF: 8
static u8 gic_cpu_map[NR_GIC_CPU_IF] __read_mostly;

/*
 * Supported arch specific GIC irq extension.
 * Default make them NULL.
 */
// ARM10C 20141129
struct irq_chip gic_arch_extn = {
	.irq_eoi	= NULL,
	.irq_mask	= NULL,
	.irq_unmask	= NULL,
	.irq_retrigger	= NULL,
	.irq_set_type	= NULL,
	.irq_set_wake	= NULL,
};

#ifndef MAX_GIC_NR
// ARM10C 20141108
// MAX_GIC_NR: 1
#define MAX_GIC_NR	1
#endif

// ARM10C 20141108
// MAX_GIC_NR: 1
static struct gic_chip_data gic_data[MAX_GIC_NR] __read_mostly;

#ifdef CONFIG_GIC_NON_BANKED // CONFIG_GIC_NON_BANKED=n
static void __iomem *gic_get_percpu_base(union gic_base *base)
{
	return *__this_cpu_ptr(base->percpu_base);
}

static void __iomem *gic_get_common_base(union gic_base *base)
{
	return base->common_base;
}

static inline void __iomem *gic_data_dist_base(struct gic_chip_data *data)
{
	return data->get_base(&data->dist_base);
}

static inline void __iomem *gic_data_cpu_base(struct gic_chip_data *data)
{
	return data->get_base(&data->cpu_base);
}

static inline void gic_set_base_accessor(struct gic_chip_data *data,
					 void __iomem *(*f)(union gic_base *))
{
	data->get_base = f;
}
#else
// ARM10C 20141108
// ARM10C 20141129
// gic: &gic_data[0]
// gic_data_dist_base(&gic_data[0]): 0xf0000000
#define gic_data_dist_base(d)	((d)->dist_base.common_base)
// ARM10C 20141129
// gic: &gic_data[0]
// gic_data_cpu_base(&gic_data[0]): 0xf0002000
#define gic_data_cpu_base(d)	((d)->cpu_base.common_base)
// ARM10C 20141108
#define gic_set_base_accessor(d, f)
#endif

static inline void __iomem *gic_dist_base(struct irq_data *d)
{
	struct gic_chip_data *gic_data = irq_data_get_irq_chip_data(d);
	return gic_data_dist_base(gic_data);
}

static inline void __iomem *gic_cpu_base(struct irq_data *d)
{
	struct gic_chip_data *gic_data = irq_data_get_irq_chip_data(d);
	return gic_data_cpu_base(gic_data);
}

static inline unsigned int gic_irq(struct irq_data *d)
{
	return d->hwirq;
}

/*
 * Routines to acknowledge, disable and enable interrupts
 */
static void gic_mask_irq(struct irq_data *d)
{
	u32 mask = 1 << (gic_irq(d) % 32);

	raw_spin_lock(&irq_controller_lock);
	writel_relaxed(mask, gic_dist_base(d) + GIC_DIST_ENABLE_CLEAR + (gic_irq(d) / 32) * 4);
	if (gic_arch_extn.irq_mask)
		gic_arch_extn.irq_mask(d);
	raw_spin_unlock(&irq_controller_lock);
}

static void gic_unmask_irq(struct irq_data *d)
{
	u32 mask = 1 << (gic_irq(d) % 32);

	raw_spin_lock(&irq_controller_lock);
	if (gic_arch_extn.irq_unmask)
		gic_arch_extn.irq_unmask(d);
	writel_relaxed(mask, gic_dist_base(d) + GIC_DIST_ENABLE_SET + (gic_irq(d) / 32) * 4);
	raw_spin_unlock(&irq_controller_lock);
}

static void gic_eoi_irq(struct irq_data *d)
{
	if (gic_arch_extn.irq_eoi) {
		raw_spin_lock(&irq_controller_lock);
		gic_arch_extn.irq_eoi(d);
		raw_spin_unlock(&irq_controller_lock);
	}

	writel_relaxed(gic_irq(d), gic_cpu_base(d) + GIC_CPU_EOI);
}

static int gic_set_type(struct irq_data *d, unsigned int type)
{
	void __iomem *base = gic_dist_base(d);
	unsigned int gicirq = gic_irq(d);
	u32 enablemask = 1 << (gicirq % 32);
	u32 enableoff = (gicirq / 32) * 4;
	u32 confmask = 0x2 << ((gicirq % 16) * 2);
	u32 confoff = (gicirq / 16) * 4;
	bool enabled = false;
	u32 val;

	/* Interrupt configuration for SGIs can't be changed */
	if (gicirq < 16)
		return -EINVAL;

	if (type != IRQ_TYPE_LEVEL_HIGH && type != IRQ_TYPE_EDGE_RISING)
		return -EINVAL;

	raw_spin_lock(&irq_controller_lock);

	if (gic_arch_extn.irq_set_type)
		gic_arch_extn.irq_set_type(d, type);

	val = readl_relaxed(base + GIC_DIST_CONFIG + confoff);
	if (type == IRQ_TYPE_LEVEL_HIGH)
		val &= ~confmask;
	else if (type == IRQ_TYPE_EDGE_RISING)
		val |= confmask;

	/*
	 * As recommended by the spec, disable the interrupt before changing
	 * the configuration
	 */
	if (readl_relaxed(base + GIC_DIST_ENABLE_SET + enableoff) & enablemask) {
		writel_relaxed(enablemask, base + GIC_DIST_ENABLE_CLEAR + enableoff);
		enabled = true;
	}

	writel_relaxed(val, base + GIC_DIST_CONFIG + confoff);

	if (enabled)
		writel_relaxed(enablemask, base + GIC_DIST_ENABLE_SET + enableoff);

	raw_spin_unlock(&irq_controller_lock);

	return 0;
}

static int gic_retrigger(struct irq_data *d)
{
	if (gic_arch_extn.irq_retrigger)
		return gic_arch_extn.irq_retrigger(d);

	/* the genirq layer expects 0 if we can't retrigger in hardware */
	return 0;
}

#ifdef CONFIG_SMP
static int gic_set_affinity(struct irq_data *d, const struct cpumask *mask_val,
			    bool force)
{
	void __iomem *reg = gic_dist_base(d) + GIC_DIST_TARGET + (gic_irq(d) & ~3);
	unsigned int shift = (gic_irq(d) % 4) * 8;
	unsigned int cpu = cpumask_any_and(mask_val, cpu_online_mask);
	u32 val, mask, bit;

	if (cpu >= NR_GIC_CPU_IF || cpu >= nr_cpu_ids)
		return -EINVAL;

	raw_spin_lock(&irq_controller_lock);
	mask = 0xff << shift;
	bit = gic_cpu_map[cpu] << shift;
	val = readl_relaxed(reg) & ~mask;
	writel_relaxed(val | bit, reg);
	raw_spin_unlock(&irq_controller_lock);

	return IRQ_SET_MASK_OK;
}
#endif

#ifdef CONFIG_PM
static int gic_set_wake(struct irq_data *d, unsigned int on)
{
	int ret = -ENXIO;

	if (gic_arch_extn.irq_set_wake)
		ret = gic_arch_extn.irq_set_wake(d, on);

	return ret;
}

#else
#define gic_set_wake	NULL
#endif

// ARM10C 20141129
// __exception_irq_entry: __attribute__((section(".exception.text")))
static asmlinkage void __exception_irq_entry gic_handle_irq(struct pt_regs *regs)
{
	u32 irqstat, irqnr;
	struct gic_chip_data *gic = &gic_data[0];
	void __iomem *cpu_base = gic_data_cpu_base(gic);

	do {
		irqstat = readl_relaxed(cpu_base + GIC_CPU_INTACK);
		irqnr = irqstat & ~0x1c00;

		if (likely(irqnr > 15 && irqnr < 1021)) {
			irqnr = irq_find_mapping(gic->domain, irqnr);
			handle_IRQ(irqnr, regs);
			continue;
		}
		if (irqnr < 16) {
			writel_relaxed(irqstat, cpu_base + GIC_CPU_EOI);
#ifdef CONFIG_SMP
			handle_IPI(irqnr, regs);
#endif
			continue;
		}
		break;
	} while (1);
}

static void gic_handle_cascade_irq(unsigned int irq, struct irq_desc *desc)
{
	struct gic_chip_data *chip_data = irq_get_handler_data(irq);
	struct irq_chip *chip = irq_get_chip(irq);
	unsigned int cascade_irq, gic_irq;
	unsigned long status;

	chained_irq_enter(chip, desc);

	raw_spin_lock(&irq_controller_lock);
	status = readl_relaxed(gic_data_cpu_base(chip_data) + GIC_CPU_INTACK);
	raw_spin_unlock(&irq_controller_lock);

	gic_irq = (status & 0x3ff);
	if (gic_irq == 1023)
		goto out;

	cascade_irq = irq_find_mapping(chip_data->domain, gic_irq);
	if (unlikely(gic_irq < 32 || gic_irq > 1020))
		handle_bad_irq(cascade_irq, desc);
	else
		generic_handle_irq(cascade_irq);

 out:
	chained_irq_exit(chip, desc);
}

// ARM10C 20141122
static struct irq_chip gic_chip = {
	.name			= "GIC",
	.irq_mask		= gic_mask_irq,
	.irq_unmask		= gic_unmask_irq,
	.irq_eoi		= gic_eoi_irq,
	.irq_set_type		= gic_set_type,
	.irq_retrigger		= gic_retrigger,
#ifdef CONFIG_SMP // CONFIG_SMP=y
	.irq_set_affinity	= gic_set_affinity,
#endif
	.irq_set_wake		= gic_set_wake,
};

void __init gic_cascade_irq(unsigned int gic_nr, unsigned int irq)
{
	if (gic_nr >= MAX_GIC_NR)
		BUG();
	if (irq_set_handler_data(irq, &gic_data[gic_nr]) != 0)
		BUG();
	irq_set_chained_handler(irq, gic_handle_cascade_irq);
}

// ARM10C 20141129
// ARM10C 20141129
// gic: &gic_data[0]
static u8 gic_get_cpumask(struct gic_chip_data *gic)
{
	// gic: &gic_data[0], gic_data_dist_base(&gic_data[0]): 0xf0000000
	void __iomem *base = gic_data_dist_base(gic);
	// base: 0xf0000000

	u32 mask, i;

	for (i = mask = 0; i < 32; i += 4) {
		// G.A.S: 4.3.12 Interrupt Processor Targets Registers, GICD_ITARGETSRn
		//
		// base: 0xf0000000, GIC_DIST_TARGET: 0x800, i: 0
		// readl_relaxed(0xf0000800): 0x01010101 (reset 값)
		mask = readl_relaxed(base + GIC_DIST_TARGET + i);
		// mask: 0x01010101 (reset 값)
		//
		// mask 0x01010101의 의미:
		// CPU targets, byte offset 0 ~ 4까지의 interrupt target을 "CPU interface 0"으로 설정

		// mask: 0x01010101
		mask |= mask >> 16;
		// mask: 0x01010101

		// mask: 0x01010101
		mask |= mask >> 8;
		// mask: 0x01010101

		// mask: 0x01010101
		if (mask)
			break;
			// break 수행
	}

	// mask: 0x01010101
	if (!mask)
		pr_crit("GIC CPU mask not found - kernel will fail to boot.\n");

	// mask: 0x01010101
	return mask;
	// return 0x01010101
}

// ARM10C 20141129
// gic: &gic_data[0]
static void __init gic_dist_init(struct gic_chip_data *gic)
{
	unsigned int i;
	u32 cpumask;

	// gic->gic_irqs: (&gic_data[0])->gic_irqs: 160
	unsigned int gic_irqs = gic->gic_irqs;
	// gic_irqs: 160

	// gic: &gic_data[0], gic_data_dist_base(&gic_data[0]): 0xf0000000
	void __iomem *base = gic_data_dist_base(gic);
	// base: 0xf0000000

	// Note:
	// G.A.S: gic architecture specification 의 약자로 정의

	// G.A.S: 4.3.1 Distributor Control Register, GICD_CTLR
	//
	// base: 0xf0000000, GIC_DIST_CTRL: 0x000
	writel_relaxed(0, base + GIC_DIST_CTRL);
	// register GICD_CTLR을 0으로 초기화

	// 0 값의 의미:
	// Disable the forwarding of pending interrupts from the Distributor to the CPU interfaces.

	/*
	 * Set all global interrupts to be level triggered, active low.
	 */
	// gic_irqs: 160
	for (i = 32; i < gic_irqs; i += 16)
		// G.A.S: 4.3.13 Interrupt Configuration Registers, GICD_ICFGRn
		//
		// base: 0xf0000000, GIC_DIST_CONFIG: 0xc00, i: 32
		writel_relaxed(0, base + GIC_DIST_CONFIG + i * 4 / 16);
		// register GICD_ICFGR2 의 값을 0으로 초기화
		//
		// i: 48...144까지 loop를 8번 수행 GICD_ICFGR2 ~ GICD_ICFGR9 까지의 값을 0으로 초기화 수행

	// Interrupt Configuration Register의 bit 들의 의미:
	// Softwared Generated Interrupts (SGIs[15:0], ID[15:0])
	// Private Peripheral Interrupts (PPIs[15:0], ID[31:16])
	// Shared Peripheral Interrupts (SPIs[127:0], ID[159:32])

	/*
	 * Set all global interrupts to this CPU only.
	 */
	// gic: &gic_data[0], gic_get_cpumask(&gic_data[0]): 0x01010101
	cpumask = gic_get_cpumask(gic);
	// cpumask: 0x01010101

	// cpumask: 0x01010101
	cpumask |= cpumask << 8;
	// cpumask: 0x01010101

	// cpumask: 0x01010101
	cpumask |= cpumask << 16;
	// cpumask: 0x01010101

	// gic_irqs: 160
	for (i = 32; i < gic_irqs; i += 4)
		// G.A.S: 4.3.12 Interrupt Processor Targets Registers, GICD_ITARGETSRn
		//
		// cpumask: 0x01010101, base: 0xf0000000, GIC_DIST_TARGET: 0x800, i: 32
		writel_relaxed(cpumask, base + GIC_DIST_TARGET + i * 4 / 4);
		// register GICD_ITARGETSR8 값을 0x01010101으로 세팅
		//
		// i: 32...156 까지 수행 되어 register GICD_ITARGETSR9 ~ GICD_ITARGETSR39 값을 0x01010101으로 세팅

	// cpumask 0x01010101의 의미:
	// CPU targets, byte offset 0 ~ 4까지의 interrupt target을 "CPU interface 0"으로 설정

	/*
	 * Set priority on all global interrupts.
	 */
	// gic_irqs: 160
	for (i = 32; i < gic_irqs; i += 4)
		// G.A.S: 4.3.11 Interrupt Priority Registers, GICD_IPRIORITYRn
		//
		// base: 0xf0000000, GIC_DIST_PRI: 0x400, i: 32
		writel_relaxed(0xa0a0a0a0, base + GIC_DIST_PRI + i * 4 / 4);
		// register GICD_IPRIORITYR8 값을 0xa0a0a0a0으로 세팅
		//
		// i: 32...156 까지 수행 되어 register GICD_IPRIORITYR9 ~ GICD_ITARGETSR39 값을 0xa0a0a0a0으로 세팅

	// 0xa0a0a0a0의 의미:
	// Priority, byte offset 0 ~ 4까지의 interrupt priority value을 160 (0xa0)로 설정

	/*
	 * Disable all interrupts.  Leave the PPI and SGIs alone
	 * as these enables are banked registers.
	 */
	// gic_irqs: 160
	for (i = 32; i < gic_irqs; i += 32)
		// G.A.S: 4.3.6 Interrupt Clear-Enable Registers, GICD_ICENABLERn
		//
		// base: 0xf0000000, GIC_DIST_ENABLE_CLEAR: 0x180, i: 32
		writel_relaxed(0xffffffff, base + GIC_DIST_ENABLE_CLEAR + i * 4 / 32);
		// register GICD_ICENABLER1 값을 0xffffffff으로 세팅
		//
		// i: 32...128 까지 수행 되어 register GICD_ICENABLER2 ~ GICD_ICENABLER4 값을 0xffffffff으로 세팅

	// 0xffffffff의 의미:
	// 각각의 For SPIs and PPIs 값을 interrupt disable로 설정

	// base: 0xf0000000, GIC_DIST_CTRL: 0x000
	writel_relaxed(1, base + GIC_DIST_CTRL);
	// register GICD_CTLR 값을 1로 세팅

	// 1 값의 의미:
	// Enables the forwarding of pending interrupts from the Distributor to the CPU interfaces.
}

// ARM10C 20141129
// gic: &gic_data[0]
static void gic_cpu_init(struct gic_chip_data *gic)
{
	// gic: &gic_data[0], gic_data_dist_base(&gic_data[0]): 0xf0000000
	void __iomem *dist_base = gic_data_dist_base(gic);
	// dist_base: 0xf0000000

	// gic: &gic_data[0], gic_data_cpu_base(&gic_data[0]): 0xf0002000
	void __iomem *base = gic_data_cpu_base(gic);
	// base: 0xf0002000

	// smp_processor_id(): 0
	unsigned int cpu_mask, cpu = smp_processor_id();
	// cpu: 0

	int i;

	/*
	 * Get what the GIC says our CPU mask is.
	 */
	// cpu: 0, NR_GIC_CPU_IF: 8
	BUG_ON(cpu >= NR_GIC_CPU_IF);

	// gic: &gic_data[0], gic_get_cpumask(&gic_data[0]): 0x01010101
	cpu_mask = gic_get_cpumask(gic);
	// cpu_mask: 0x01010101

	// cpu: 0, cpu_mask: 0x01010101
	gic_cpu_map[cpu] = cpu_mask;
	// gic_cpu_map[0]: 0x01

	/*
	 * Clear our mask from the other map entries in case they're
	 * still undefined.
	 */
	// NR_GIC_CPU_IF: 8
	for (i = 0; i < NR_GIC_CPU_IF; i++)
		// i: 0, cpu: 0
		// i: 1, cpu: 0
		if (i != cpu)
			// i: 1, gic_cpu_map[1]: 0xff, cpu_mask: 0x01010101
			gic_cpu_map[i] &= ~cpu_mask;
			// gic_cpu_map[1]: 0xfe

	// loop 수행 결과
	// gic_cpu_map[1...7]: 0xfe

	/*
	 * Deal with the banked PPI and SGI interrupts - disable all
	 * PPI interrupts, ensure all SGI interrupts are enabled.
	 */
	// dist_base: 0xf0000000, GIC_DIST_ENABLE_CLEAR 0x180
	writel_relaxed(0xffff0000, dist_base + GIC_DIST_ENABLE_CLEAR);
	// register GICD_ICENABLER0 값을 0xffff0000으로 세팅

	// 0xffff0000 값의 의미:
	// 0~15 bit는 SGI, 16~31 PPI를 컨트롤함, PPI를 전부 disable

	// G.A.S: 4.3.5 Interrupt Set-Enable Registers, GICD_ISENABLERn
	//
	// dist_base: 0xf0000000, GIC_DIST_ENABLE_SET: 0x100
	writel_relaxed(0x0000ffff, dist_base + GIC_DIST_ENABLE_SET);
	// register GICD_ISENABLER0 값을 0x0000ffff으로 세팅

	// 0x0000ffff 값의 의미:
	// 0~15 bit는 SGI, 16~31 PPI를 컨트롤함, SGI를 전부 enable 함

	/*
	 * Set priority on PPI and SGI interrupts
	 */
	for (i = 0; i < 32; i += 4)
		// dist_base: 0xf0000000, GIC_DIST_PRI: 0x400, i: 0
		writel_relaxed(0xa0a0a0a0, dist_base + GIC_DIST_PRI + i * 4 / 4);
		// register GICD_IPRIORITYR0 값을 0xa0a0a0a0으로 세팅
		//
		// i: 4...28 까지 수행 되어 register GICD_IPRIORITYR1 ~ GICD_ITARGETSR8 값을 0xa0a0a0a0으로 세팅

	// G.A.S: 4.4.2 Interrupt Priority Mask Register, GICC_PMR
	//
	// base: 0xf0002000, GIC_CPU_PRIMASK: 0x04
	writel_relaxed(0xf0, base + GIC_CPU_PRIMASK);
	// register GICC_PMR 값을 0xf0으로 세팅
	//
	// 0xf0 값의 의미:
	// interrupt priority가 240(0xf0) 이상인 interrupt만 cpu에 interrupt를 전달

	// G.A.S: 4.4.1 CPU Interface Control Register, GICC_CTLR
	//
	// base: 0xf0002000, GIC_CPU_CTRL: 0x00
	writel_relaxed(1, base + GIC_CPU_CTRL);
	// register GICC_CTLR에 값을 1로 세팅
	//
	// 1 값의 의미:
	// cpu에 전달되는 interrupt를 enable 함
}

void gic_cpu_if_down(void)
{
	void __iomem *cpu_base = gic_data_cpu_base(&gic_data[0]);
	writel_relaxed(0, cpu_base + GIC_CPU_CTRL);
}

#ifdef CONFIG_CPU_PM // CONFIG_CPU_PM=y
/*
 * Saves the GIC distributor registers during suspend or idle.  Must be called
 * with interrupts disabled but before powering down the GIC.  After calling
 * this function, no interrupts will be delivered by the GIC, and another
 * platform-specific wakeup source must be enabled.
 */
static void gic_dist_save(unsigned int gic_nr)
{
	unsigned int gic_irqs;
	void __iomem *dist_base;
	int i;

	if (gic_nr >= MAX_GIC_NR)
		BUG();

	gic_irqs = gic_data[gic_nr].gic_irqs;
	dist_base = gic_data_dist_base(&gic_data[gic_nr]);

	if (!dist_base)
		return;

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 16); i++)
		gic_data[gic_nr].saved_spi_conf[i] =
			readl_relaxed(dist_base + GIC_DIST_CONFIG + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 4); i++)
		gic_data[gic_nr].saved_spi_target[i] =
			readl_relaxed(dist_base + GIC_DIST_TARGET + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 32); i++)
		gic_data[gic_nr].saved_spi_enable[i] =
			readl_relaxed(dist_base + GIC_DIST_ENABLE_SET + i * 4);
}

/*
 * Restores the GIC distributor registers during resume or when coming out of
 * idle.  Must be called before enabling interrupts.  If a level interrupt
 * that occured while the GIC was suspended is still present, it will be
 * handled normally, but any edge interrupts that occured will not be seen by
 * the GIC and need to be handled by the platform-specific wakeup source.
 */
static void gic_dist_restore(unsigned int gic_nr)
{
	unsigned int gic_irqs;
	unsigned int i;
	void __iomem *dist_base;

	if (gic_nr >= MAX_GIC_NR)
		BUG();

	gic_irqs = gic_data[gic_nr].gic_irqs;
	dist_base = gic_data_dist_base(&gic_data[gic_nr]);

	if (!dist_base)
		return;

	writel_relaxed(0, dist_base + GIC_DIST_CTRL);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 16); i++)
		writel_relaxed(gic_data[gic_nr].saved_spi_conf[i],
			dist_base + GIC_DIST_CONFIG + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 4); i++)
		writel_relaxed(0xa0a0a0a0,
			dist_base + GIC_DIST_PRI + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 4); i++)
		writel_relaxed(gic_data[gic_nr].saved_spi_target[i],
			dist_base + GIC_DIST_TARGET + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 32); i++)
		writel_relaxed(gic_data[gic_nr].saved_spi_enable[i],
			dist_base + GIC_DIST_ENABLE_SET + i * 4);

	writel_relaxed(1, dist_base + GIC_DIST_CTRL);
}

static void gic_cpu_save(unsigned int gic_nr)
{
	int i;
	u32 *ptr;
	void __iomem *dist_base;
	void __iomem *cpu_base;

	if (gic_nr >= MAX_GIC_NR)
		BUG();

	dist_base = gic_data_dist_base(&gic_data[gic_nr]);
	cpu_base = gic_data_cpu_base(&gic_data[gic_nr]);

	if (!dist_base || !cpu_base)
		return;

	ptr = __this_cpu_ptr(gic_data[gic_nr].saved_ppi_enable);
	for (i = 0; i < DIV_ROUND_UP(32, 32); i++)
		ptr[i] = readl_relaxed(dist_base + GIC_DIST_ENABLE_SET + i * 4);

	ptr = __this_cpu_ptr(gic_data[gic_nr].saved_ppi_conf);
	for (i = 0; i < DIV_ROUND_UP(32, 16); i++)
		ptr[i] = readl_relaxed(dist_base + GIC_DIST_CONFIG + i * 4);

}

static void gic_cpu_restore(unsigned int gic_nr)
{
	int i;
	u32 *ptr;
	void __iomem *dist_base;
	void __iomem *cpu_base;

	if (gic_nr >= MAX_GIC_NR)
		BUG();

	dist_base = gic_data_dist_base(&gic_data[gic_nr]);
	cpu_base = gic_data_cpu_base(&gic_data[gic_nr]);

	if (!dist_base || !cpu_base)
		return;

	ptr = __this_cpu_ptr(gic_data[gic_nr].saved_ppi_enable);
	for (i = 0; i < DIV_ROUND_UP(32, 32); i++)
		writel_relaxed(ptr[i], dist_base + GIC_DIST_ENABLE_SET + i * 4);

	ptr = __this_cpu_ptr(gic_data[gic_nr].saved_ppi_conf);
	for (i = 0; i < DIV_ROUND_UP(32, 16); i++)
		writel_relaxed(ptr[i], dist_base + GIC_DIST_CONFIG + i * 4);

	for (i = 0; i < DIV_ROUND_UP(32, 4); i++)
		writel_relaxed(0xa0a0a0a0, dist_base + GIC_DIST_PRI + i * 4);

	writel_relaxed(0xf0, cpu_base + GIC_CPU_PRIMASK);
	writel_relaxed(1, cpu_base + GIC_CPU_CTRL);
}

static int gic_notifier(struct notifier_block *self, unsigned long cmd,	void *v)
{
	int i;

	for (i = 0; i < MAX_GIC_NR; i++) {
#ifdef CONFIG_GIC_NON_BANKED
		/* Skip over unused GICs */
		if (!gic_data[i].get_base)
			continue;
#endif
		switch (cmd) {
		case CPU_PM_ENTER:
			gic_cpu_save(i);
			break;
		case CPU_PM_ENTER_FAILED:
		case CPU_PM_EXIT:
			gic_cpu_restore(i);
			break;
		case CPU_CLUSTER_PM_ENTER:
			gic_dist_save(i);
			break;
		case CPU_CLUSTER_PM_ENTER_FAILED:
		case CPU_CLUSTER_PM_EXIT:
			gic_dist_restore(i);
			break;
		}
	}

	return NOTIFY_OK;
}

// ARM10C 20141129
static struct notifier_block gic_notifier_block = {
	.notifier_call = gic_notifier,
};

// ARM10C 20141129
// gic: &gic_data[0]
static void __init gic_pm_init(struct gic_chip_data *gic)
{
	// gic->saved_ppi_enable: (&gic_data[0])->saved_ppi_enable
	// DIV_ROUND_UP(32, 32): 1, sizeof(u32): 4
	// __alloc_percpu(4, 4): kmem_cache#26-o0 에서의 4 byte 할당된 주소
	gic->saved_ppi_enable = __alloc_percpu(DIV_ROUND_UP(32, 32) * 4,
		sizeof(u32));
	// gic->saved_ppi_enable: (&gic_data[0])->saved_ppi_enable: kmem_cache#26-o0 에서의 4 byte 할당된 주소

	// gic->saved_ppi_enable: (&gic_data[0])->saved_ppi_enable: kmem_cache#26-o0 에서의 4 byte 할당된 주소
	BUG_ON(!gic->saved_ppi_enable);

	// gic->saved_ppi_conf: (&gic_data[0])->saved_ppi_conf
	// DIV_ROUND_UP(32, 16): 2, sizeof(u32): 4
	// __alloc_percpu(8, 4): kmem_cache#26-o0 에서의 8 byte 할당된 주소
	gic->saved_ppi_conf = __alloc_percpu(DIV_ROUND_UP(32, 16) * 4,
		sizeof(u32));
	// gic->saved_ppi_conf: (&gic_data[0])->saved_ppi_conf: kmem_cache#26-o0 에서의 8 byte 할당된 주소

	// gic->saved_ppi_conf: (&gic_data[0])->saved_ppi_conf: kmem_cache#26-o0 에서의 8 byte 할당된 주소
	BUG_ON(!gic->saved_ppi_conf);

	// gic: &gic_data[0]
	if (gic == &gic_data[0])
		cpu_pm_register_notifier(&gic_notifier_block);
		// cpu_pm_register_notifier에서 한일:
		// (&cpu_pm_notifier_chain)->head: &gic_notifier_block
		// &nh->head에 n의 포인터를 대입함
}
#else
static void __init gic_pm_init(struct gic_chip_data *gic)
{
}
#endif

#ifdef CONFIG_SMP // CONFIG_SMP=y
// ARM10C 20141129
void gic_raise_softirq(const struct cpumask *mask, unsigned int irq)
{
	int cpu;
	unsigned long flags, map = 0;

	raw_spin_lock_irqsave(&irq_controller_lock, flags);

	/* Convert our logical CPU mask into a physical one. */
	for_each_cpu(cpu, mask)
		map |= gic_cpu_map[cpu];

	/*
	 * Ensure that stores to Normal memory are visible to the
	 * other CPUs before issuing the IPI.
	 */
	dsb();

	/* this always happens on GIC0 */
	writel_relaxed(map << 16 | irq, gic_data_dist_base(&gic_data[0]) + GIC_DIST_SOFTINT);

	raw_spin_unlock_irqrestore(&irq_controller_lock, flags);
}
#endif

#ifdef CONFIG_BL_SWITCHER // CONFIG_BL_SWITCHER=n
/*
 * gic_send_sgi - send a SGI directly to given CPU interface number
 *
 * cpu_id: the ID for the destination CPU interface
 * irq: the IPI number to send a SGI for
 */
void gic_send_sgi(unsigned int cpu_id, unsigned int irq)
{
	BUG_ON(cpu_id >= NR_GIC_CPU_IF);
	cpu_id = 1 << cpu_id;
	/* this always happens on GIC0 */
	writel_relaxed((cpu_id << 16) | irq, gic_data_dist_base(&gic_data[0]) + GIC_DIST_SOFTINT);
}

/*
 * gic_get_cpu_id - get the CPU interface ID for the specified CPU
 *
 * @cpu: the logical CPU number to get the GIC ID for.
 *
 * Return the CPU interface ID for the given logical CPU number,
 * or -1 if the CPU number is too large or the interface ID is
 * unknown (more than one bit set).
 */
int gic_get_cpu_id(unsigned int cpu)
{
	unsigned int cpu_bit;

	if (cpu >= NR_GIC_CPU_IF)
		return -1;
	cpu_bit = gic_cpu_map[cpu];
	if (cpu_bit & (cpu_bit - 1))
		return -1;
	return __ffs(cpu_bit);
}

/*
 * gic_migrate_target - migrate IRQs to another CPU interface
 *
 * @new_cpu_id: the CPU target ID to migrate IRQs to
 *
 * Migrate all peripheral interrupts with a target matching the current CPU
 * to the interface corresponding to @new_cpu_id.  The CPU interface mapping
 * is also updated.  Targets to other CPU interfaces are unchanged.
 * This must be called with IRQs locally disabled.
 */
void gic_migrate_target(unsigned int new_cpu_id)
{
	unsigned int cur_cpu_id, gic_irqs, gic_nr = 0;
	void __iomem *dist_base;
	int i, ror_val, cpu = smp_processor_id();
	u32 val, cur_target_mask, active_mask;

	if (gic_nr >= MAX_GIC_NR)
		BUG();

	dist_base = gic_data_dist_base(&gic_data[gic_nr]);
	if (!dist_base)
		return;
	gic_irqs = gic_data[gic_nr].gic_irqs;

	cur_cpu_id = __ffs(gic_cpu_map[cpu]);
	cur_target_mask = 0x01010101 << cur_cpu_id;
	ror_val = (cur_cpu_id - new_cpu_id) & 31;

	raw_spin_lock(&irq_controller_lock);

	/* Update the target interface for this logical CPU */
	gic_cpu_map[cpu] = 1 << new_cpu_id;

	/*
	 * Find all the peripheral interrupts targetting the current
	 * CPU interface and migrate them to the new CPU interface.
	 * We skip DIST_TARGET 0 to 7 as they are read-only.
	 */
	for (i = 8; i < DIV_ROUND_UP(gic_irqs, 4); i++) {
		val = readl_relaxed(dist_base + GIC_DIST_TARGET + i * 4);
		active_mask = val & cur_target_mask;
		if (active_mask) {
			val &= ~active_mask;
			val |= ror32(active_mask, ror_val);
			writel_relaxed(val, dist_base + GIC_DIST_TARGET + i*4);
		}
	}

	raw_spin_unlock(&irq_controller_lock);

	/*
	 * Now let's migrate and clear any potential SGIs that might be
	 * pending for us (cur_cpu_id).  Since GIC_DIST_SGI_PENDING_SET
	 * is a banked register, we can only forward the SGI using
	 * GIC_DIST_SOFTINT.  The original SGI source is lost but Linux
	 * doesn't use that information anyway.
	 *
	 * For the same reason we do not adjust SGI source information
	 * for previously sent SGIs by us to other CPUs either.
	 */
	for (i = 0; i < 16; i += 4) {
		int j;
		val = readl_relaxed(dist_base + GIC_DIST_SGI_PENDING_SET + i);
		if (!val)
			continue;
		writel_relaxed(val, dist_base + GIC_DIST_SGI_PENDING_CLEAR + i);
		for (j = i; j < i + 4; j++) {
			if (val & 0xff)
				writel_relaxed((1 << (new_cpu_id + 16)) | j,
						dist_base + GIC_DIST_SOFTINT);
			val >>= 8;
		}
	}
}

/*
 * gic_get_sgir_physaddr - get the physical address for the SGI register
 *
 * REturn the physical address of the SGI register to be used
 * by some early assembly code when the kernel is not yet available.
 */
static unsigned long gic_dist_physaddr;

unsigned long gic_get_sgir_physaddr(void)
{
	if (!gic_dist_physaddr)
		return 0;
	return gic_dist_physaddr + GIC_DIST_SOFTINT;
}

void __init gic_init_physaddr(struct device_node *node)
{
	struct resource res;
	if (of_address_to_resource(node, 0, &res) == 0) {
		gic_dist_physaddr = res.start;
		pr_info("GIC physical location is %#lx\n", gic_dist_physaddr);
	}
}

#else
// ARM10C 20141129
#define gic_init_physaddr(node)  do { } while (0)
#endif

// ARM10C 20141122
// kmem_cache#25-o0, 16, 16
static int gic_irq_domain_map(struct irq_domain *d, unsigned int irq,
				irq_hw_number_t hw)
{
	// hw: 16
	if (hw < 32) {
		// irq: 16
		irq_set_percpu_devid(irq);
		// irq_set_percpu_devid에서 한일:
		// (kmem_cache#28-oX (irq 16))->percpu_enabled: kmem_cache#30-oX
		// (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600
		// (&(kmem_cache#28-oX (irq 16))->irq_data)->state_use_accessors: 0x10800

		// irq: 16
		irq_set_chip_and_handler(irq, &gic_chip,
					 handle_percpu_devid_irq);
		// irq_set_chip_and_handler에서 한일:
		// (kmem_cache#28-oX (irq 16))->irq_data.chip: &gic_chip
		// (kmem_cache#28-oX (irq 16))->handle_irq: handle_percpu_devid_irq
		// (kmem_cache#28-oX (irq 16))->name: NULL

		// irq: 16, IRQF_VALID: 1, IRQF_NOAUTOEN: 0x4
		set_irq_flags(irq, IRQF_VALID | IRQF_NOAUTOEN);
		// set_irq_flags에서 한일:
		// (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600
		// (&(kmem_cache#28-oX (irq 16))->irq_data)->state_use_accessors: 0x10800
	} else {
		irq_set_chip_and_handler(irq, &gic_chip,
					 handle_fasteoi_irq);
		set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);
	}
	// irq: 16, d->host_data: (kmem_cache#25-o0)->host_data: &gic_data[0]
	irq_set_chip_data(irq, d->host_data);
	// irq_set_chip_data에서 한일:
	// desc->irq_data.chip_data: (kmem_cache#28-oX (irq 16))->irq_data.chip_data: &gic_data[0]

	return 0;
	// return 0
}

static int gic_irq_domain_xlate(struct irq_domain *d,
				struct device_node *controller,
				const u32 *intspec, unsigned int intsize,
				unsigned long *out_hwirq, unsigned int *out_type)
{
	if (d->of_node != controller)
		return -EINVAL;
	if (intsize < 3)
		return -EINVAL;

	/* Get the interrupt number and add 16 to skip over SGIs */
	*out_hwirq = intspec[1] + 16;

	/* For SPIs, we need to add 16 more to get the GIC irq ID number */
	if (!intspec[0])
		*out_hwirq += 16;

	*out_type = intspec[2] & IRQ_TYPE_SENSE_MASK;
	return 0;
}

#ifdef CONFIG_SMP // CONFIG_SMP=y
// ARM10C 20141129
static int gic_secondary_init(struct notifier_block *nfb, unsigned long action,
			      void *hcpu)
{
	if (action == CPU_STARTING || action == CPU_STARTING_FROZEN)
		gic_cpu_init(&gic_data[0]);
	return NOTIFY_OK;
}

/*
 * Notifier for enabling the GIC CPU interface. Set an arbitrarily high
 * priority because the GIC needs to be up before the ARM generic timers.
 */
// ARM10C 20141129
static struct notifier_block gic_cpu_notifier = {
	.notifier_call = gic_secondary_init,
	.priority = 100,
};
#endif

// ARM10C 20141122
const struct irq_domain_ops gic_irq_domain_ops = {
	.map = gic_irq_domain_map,
	.xlate = gic_irq_domain_xlate,
};

// ARM10C 20141108
// gic_cnt: 0, -1, dist_base: 0xf0000000, cpu_base: 0xf0002000, percpu_offset: 0,
// node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
void __init gic_init_bases(unsigned int gic_nr, int irq_start,
			   void __iomem *dist_base, void __iomem *cpu_base,
			   u32 percpu_offset, struct device_node *node)
{
	irq_hw_number_t hwirq_base;
	struct gic_chip_data *gic;
	int gic_irqs, irq_base, i;

	// gic_nr: 0, MAX_GIC_NR: 1
	BUG_ON(gic_nr >= MAX_GIC_NR);

	// gic_nr: 0
	gic = &gic_data[gic_nr];
	// gic: &gic_data[0]

#ifdef CONFIG_GIC_NON_BANKED // CONFIG_GIC_NON_BANKED=n
	if (percpu_offset) { /* Frankein-GIC without banked registers... */
		unsigned int cpu;

		gic->dist_base.percpu_base = alloc_percpu(void __iomem *);
		gic->cpu_base.percpu_base = alloc_percpu(void __iomem *);
		if (WARN_ON(!gic->dist_base.percpu_base ||
			    !gic->cpu_base.percpu_base)) {
			free_percpu(gic->dist_base.percpu_base);
			free_percpu(gic->cpu_base.percpu_base);
			return;
		}

		for_each_possible_cpu(cpu) {
			unsigned long offset = percpu_offset * cpu_logical_map(cpu);
			*per_cpu_ptr(gic->dist_base.percpu_base, cpu) = dist_base + offset;
			*per_cpu_ptr(gic->cpu_base.percpu_base, cpu) = cpu_base + offset;
		}

		gic_set_base_accessor(gic, gic_get_percpu_base);
	} else
#endif
	{			/* Normal, sane GIC... */
		// percpu_offset: 0
		WARN(percpu_offset,
		     "GIC_NON_BANKED not enabled, ignoring %08x offset!",
		     percpu_offset);
		// gic->dist_base.common_base: (&gic_data[0])->dist_base.common_base, dist_base: 0xf0000000
		gic->dist_base.common_base = dist_base;
		// gic->dist_base.common_base: (&gic_data[0])->dist_base.common_base: 0xf0000000

		// gic->cpu_base.common_base: (&gic_data[0])->cpu_base.common_base, cpu_base: 0xf0002000
		gic->cpu_base.common_base = cpu_base;
		// gic->cpu_base.common_base: (&gic_data[0])->cpu_base.common_base: 0xf0002000

		// gic: &gic_data[0]
		gic_set_base_accessor(gic, gic_get_common_base); // null function
	}

	/*
	 * Initialize the CPU interface map to all CPUs.
	 * It will be refined as each CPU probes its ID.
	 */
	// NR_GIC_CPU_IF: 8
	for (i = 0; i < NR_GIC_CPU_IF; i++)
		// i: 0
		gic_cpu_map[i] = 0xff;
		// gic_cpu_map[0]: 0xff
		// i: 1...7 까지 수행

	// gic_cpu_map[0...7]: 0xff

	/*
	 * For primary GICs, skip over SGIs.
	 * For secondary GICs, skip over PPIs, too.
	 */
	// gic_nr: 0, irq_start: -1
	if (gic_nr == 0 && (irq_start & 31) > 0) {
		hwirq_base = 16;
		// hwirq_base: 16

		// irq_start: -1
		if (irq_start != -1)
			irq_start = (irq_start & ~31) + 16;
	} else {
		hwirq_base = 32;
	}

	/*
	 * Find out how many interrupts are supported.
	 * The GIC only supports up to 1020 interrupt sources.
	 */
	// T.R.M: 8.3.2 Distributor register descriptions
	// Interrupt Controller Type Register:
	// b00100 Up to 160 interrupts, 128 external interrupt lines.
	//
	// gic: &gic_data[0], gic_data_dist_base(&gic_data[0]): 0xf0000000, GIC_DIST_CTR: 0x004
	// readl_relaxed(0xf0000000 + 0x004): 0x0000FC24
	gic_irqs = readl_relaxed(gic_data_dist_base(gic) + GIC_DIST_CTR) & 0x1f;
	// gic_irqs: 0x4

// 2014/11/08 종료
// 2014/11/15 시작

	// gic_irqs: 0x4
	gic_irqs = (gic_irqs + 1) * 32;
	// gic_irqs: 160

	// gic_irqs: 160
	if (gic_irqs > 1020)
		gic_irqs = 1020;

	// gic->gic_irqs: (&gic_data[0])->gic_irqs, gic_irqs: 160
	gic->gic_irqs = gic_irqs;
	// gic->gic_irqs: (&gic_data[0])->gic_irqs: 160

	// gic_irqs: 160, hwirq_base: 16
	gic_irqs -= hwirq_base; /* calculate # of irqs to allocate */
	// gic_irqs: 144

	// irq_start: -1, gic_irqs: 144, numa_node_id(): 0
	// irq_alloc_descs(-1, 16, 144, 0): 16
	irq_base = irq_alloc_descs(irq_start, 16, gic_irqs, numa_node_id());
	// irq_base: 16

	/*
	// irq_alloc_descs에서 한일:
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

	// irq_base: 16, IS_ERR_VALUE(16): 0
	if (IS_ERR_VALUE(irq_base)) {
		WARN(1, "Cannot allocate irq_descs @ IRQ%d, assuming pre-allocated\n",
		     irq_start);
		irq_base = irq_start;
	}
	// gic->domain: (&gic_data[0])->domain
	// node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// gic_irqs: 144, irq_base: 16, hwirq_base: 16, gic: &gic_data[0]
	// irq_domain_add_legacy(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, 144, 16, 16,
	// &gic_irq_domain_ops, &gic_data[0]): kmem_cache#25-o0
	gic->domain = irq_domain_add_legacy(node, gic_irqs, irq_base,
				    hwirq_base, &gic_irq_domain_ops, gic);
	// gic->domain: (&gic_data[0])->domain: kmem_cache#25-o0

	// irq_domain_add_legacy에서 한일:
	// (&(kmem_cache#25-o0)->revmap_tree)->height: 0
	// (&(kmem_cache#25-o0)->revmap_tree)->gfp_mask: GFP_KERNEL: 0xD0
	// (&(kmem_cache#25-o0)->revmap_tree)->rnode: NULL
	// (kmem_cache#25-o0)->ops: &gic_irq_domain_ops
	// (kmem_cache#25-o0)->host_data: &gic_data[0]
	// (kmem_cache#25-o0)->of_node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// (kmem_cache#25-o0)->hwirq_max: 160
	// (kmem_cache#25-o0)->revmap_size: 160
	// (kmem_cache#25-o0)->revmap_direct_max_irq: 0
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
	// (kmem_cache#25-o0)->name: "GIC"
	// (kmem_cache#25-o0)->linear_revmap[16...160]: 16...160

	// gic->domain: (&gic_data[0])->domain: kmem_cache#25-o0
	if (WARN_ON(!gic->domain))
		return;

	// gic_nr: 0
	if (gic_nr == 0) {
#ifdef CONFIG_SMP // CONFIG_SMP=y
		set_smp_cross_call(gic_raise_softirq);
		// set_smp_cross_call에서 한일:
		// smp_cross_call: gic_raise_softirq

		register_cpu_notifier(&gic_cpu_notifier);
		// register_cpu_notifier에서 한일:
		// (&cpu_chain)->head: gic_cpu_notifier 포인터 대입
		// (&gic_cpu_notifier)->next은 (&radix_tree_callback_nb)->next로 대입
#endif
		set_handle_irq(gic_handle_irq);
		// set_handle_irq에서 한일:
		// handle_arch_irq: gic_handle_irq
	}

	// gic_chip.flags: 0, gic_arch_extn.flags: 0
	gic_chip.flags |= gic_arch_extn.flags;
	// gic_chip.flags: 0

	// gic: &gic_data[0]
	gic_dist_init(gic);
	// gic_dist_init에서 한일:
	//
	// register GICD_CTLR을 0으로 초기화
	// 0 값의 의미: Disable the forwarding of pending interrupts from the Distributor to the CPU interfaces.
	//
	// register GICD_ICFGR2 ~ GICD_ICFGR9 까지의 값을 0으로 초기화 수행
	//
	// register GICD_ITARGETSR8 ~ GICD_ITARGETSR39 값을 0x01010101으로 세팅
	// 0x01010101의 의미: CPU targets, byte offset 0 ~ 4까지의 interrupt target을 "CPU interface 0"으로 설정
	//
	// register GICD_IPRIORITYR8 ~ GICD_ITARGETSR39 값을 0xa0a0a0a0으로 세팅
	// 0xa0a0a0a0의 의미: Priority, byte offset 0 ~ 4까지의 interrupt priority value을 160 (0xa0)로 설정
	//
	// register GICD_ICENABLER1 ~ GICD_ICENABLER4 값을 0xffffffff으로 세팅
	// 0xffffffff의 의미: 각각의 For SPIs and PPIs 값을 interrupt disable로 설정
	//
	// register GICD_CTLR 값을 1로 세팅
	// 1 값의 의미: Enables the forwarding of pending interrupts from the Distributor to the CPU interfaces.

	// gic: &gic_data[0]
	gic_cpu_init(gic);
	// gic_cpu_init에서 한일:
	//
	// gic_cpu_map[0]: 0x01
	// gic_cpu_map[1...7]: 0xfe
	//
	// register GICD_ICENABLER0 값을 0xffff0000으로 세팅
	// 0xffff0000 값의 의미: 0~15 bit는 SGI, 16~31 PPI를 컨트롤함, PPI를 전부 disable
	//
	// register GICD_ISENABLER0 값을 0x0000ffff으로 세팅
	// 0x0000ffff 값의 의미: 0~15 bit는 SGI, 16~31 PPI를 컨트롤함, SGI를 전부 enable 함
	//
	// register GICD_IPRIORITYR1 ~ GICD_ITARGETSR8 값을 0xa0a0a0a0으로 세팅
	// 0xa0a0a0a0의 의미: Priority, byte offset 0 ~ 4까지의 interrupt priority value을 160 (0xa0)로 설정
	//
	// register GICC_PMR 값을 0xf0으로 세팅
	// 0xf0 값의 의미: interrupt priority가 240(0xf0) 이상인 interrupt만 cpu에 interrupt를 전달
	//
	// register GICC_CTLR에 값을 1로 세팅
	// 1 값의 의미: cpu에 전달되는 interrupt를 enable 함

	// gic: &gic_data[0]
	gic_pm_init(gic);
	// gic_pm_init에서 한일:
	//
	// (&gic_data[0])->saved_ppi_enable: kmem_cache#26-o0 에서의 4 byte 할당된 주소 (pcp)
	// (&gic_data[0])->saved_ppi_conf: kmem_cache#26-o0 에서의 8 byte 할당된 주소 (pcp)
	// (&cpu_pm_notifier_chain)->head: &gic_notifier_block
}

#ifdef CONFIG_OF // CONFIG_OF=y
// ARM10C 20141108
static int gic_cnt __initdata;

// ARM10C 20141018
// desc->dev: (kmem_cache#30-o11)->dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
// desc->interrupt_parent: (kmem_cache#30-o11)->interrupt_parent: NULL
int __init gic_of_init(struct device_node *node, struct device_node *parent)
{
	void __iomem *cpu_base;
	void __iomem *dist_base;
	u32 percpu_offset;
	int irq;

	// node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	if (WARN_ON(!node))
		return -ENODEV;

	// node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_iomap(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, 0): 0xf0000000
	dist_base = of_iomap(node, 0);
	// dist_base: 0xf0000000

	// of_iomap에서 한일:
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

	// dist_base: 0xf000000
	WARN(!dist_base, "unable to map gic dist registers\n");

	// node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_iomap(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, 1): 0xf002000
	cpu_base = of_iomap(node, 1);
	// cpu_base: 0xf0002000

	// of_iomap에서 한일:
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

	// cpu_base: 0xf0002000
	WARN(!cpu_base, "unable to map gic cpu registers\n");

	// node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_property_read_u32(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, "cpu-offset", &percpu_offset):
	// 0이 아닌 err 값
	if (of_property_read_u32(node, "cpu-offset", &percpu_offset))
		percpu_offset = 0;
		// percpu_offset: 0

	// gic_cnt: 0, dist_base: 0xf0000000, cpu_base: 0xf0002000, percpu_offset: 0,
	// node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	gic_init_bases(gic_cnt, -1, dist_base, cpu_base, percpu_offset, node);
	// gic_init_bases에서 한일:
	//
	// (&gic_data[0])->dist_base.common_base: 0xf0000000
	// (&gic_data[0])->cpu_base.common_base: 0xf0002000
	// (&gic_data[0])->gic_irqs: 160
	//
	/*
	 * struct irq_desc의 자료 구조크기 만큼 160개의 메모리를 할당 받아
	 * radix tree 구조로 구성
	 *
	 * radix tree의 root node: &irq_desc_tree 값을 변경
	 * (&irq_desc_tree)->rnode: kmem_cache#20-o1 (RADIX_LSB: 1)
	 * (&irq_desc_tree)->height: 2
	 *
	 * (kmem_cache#20-o1)->height: 2
	 * (kmem_cache#20-o1)->count: 3
	 * (kmem_cache#20-o1)->parent: NULL
	 * (kmem_cache#20-o1)->slots[0]: kmem_cache#20-o0 (radix height 1 관리 주소)
	 * (kmem_cache#20-o1)->slots[1]: kmem_cache#20-o2 (radix height 1 관리 주소)
	 * (kmem_cache#20-o1)->slots[2]: kmem_cache#20-o3 (radix height 1 관리 주소)
	 *
	 * (kmem_cache#20-o0)->height: 1
	 * (kmem_cache#20-o0)->count: 63
	 * (kmem_cache#20-o0)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
	 * (kmem_cache#20-o0)->slots[0...63]: kmem_cache#28-oX (irq 0...63)
	 *
	 * (kmem_cache#20-o2)->height: 1
	 * (kmem_cache#20-o2)->count: 63
	 * (kmem_cache#20-o2)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
	 * (kmem_cache#20-o2)->slots[0...63]: kmem_cache#28-oX (irq 63...127)
	 *
	 * (kmem_cache#20-o3)->height: 1
	 * (kmem_cache#20-o3)->count: 32
	 * (kmem_cache#20-o3)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
	 * (kmem_cache#20-o3)->slots[0...32]: kmem_cache#28-oX (irq 127...160)
	 *
	 * (&irq_desc_tree)->rnode --> +-----------------------+
	 *                             |    radix_tree_node    |
	 *                             |   (kmem_cache#20-o1)  |
	 *                             +-----------------------+
	 *                             | height: 2 | count: 3  |
	 *                             +-----------------------+
	 *                             | radix_tree_node 0 ~ 2 |
	 *                             +-----------------------+
	 *                            /            |             \
	 *    slot: 0                /   slot: 1   |              \ slot: 2
	 *    +-----------------------+  +-----------------------+  +-----------------------+
	 *    |    radix_tree_node    |  |    radix_tree_node    |  |    radix_tree_node    |
	 *    |   (kmem_cache#20-o0)  |  |   (kmem_cache#20-o2)  |  |   (kmem_cache#20-o3)  |
	 *    +-----------------------+  +-----------------------+  +-----------------------+
	 *    | height: 1 | count: 64 |  | height: 1 | count: 64 |  | height: 1 | count: 32 |
	 *    +-----------------------+  +-----------------------+  +-----------------------+
	 *    |    irq  0 ~ 63        |  |    irq 64 ~ 127       |  |    irq 128 ~ 160      |
	 *    +-----------------------+  +-----------------------+  +-----------------------+
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

	// gic_cnt: 0
	if (!gic_cnt)
		// node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		gic_init_physaddr(node); // null function

	// parent: NULL
	if (parent) {
		irq = irq_of_parse_and_map(node, 0);
		gic_cascade_irq(gic_cnt, irq);
	}

	// gic_cnt: 0
	gic_cnt++;
	// gic_cnt: 1

	return 0;
	// return 0
}

// ARM10C 20141011
// #define IRQCHIP_DECLARE(cortex_a15_gic,"arm,cortex-a15-gic",gic_of_init)
// 	static const struct of_device_id irqchip_of_match_cortex_a15_gic
// 	__used __section(__irqchip_of_table)
// 	= { .compatible = "arm,cortex-a15-gic", .data = gic_of_init }
IRQCHIP_DECLARE(cortex_a15_gic, "arm,cortex-a15-gic", gic_of_init);

// ARM10C 20141011
// #define IRQCHIP_DECLARE(cortex_a9_gic,"arm,cortex-a9-gic",gic_of_init)
// 	static const struct of_device_id irqchip_of_match_cortex_a9_gic
// 	__used __section(__irqchip_of_table)
// 	= { .compatible = "arm,cortex-a9-gic", .data = gic_of_init }
IRQCHIP_DECLARE(cortex_a9_gic, "arm,cortex-a9-gic", gic_of_init);

// ARM10C 20141011
// #define IRQCHIP_DECLARE(msm_8660_qgic,"qcom,msm-8660-qgic",gic_of_init)
// 	static const struct of_device_id irqchip_of_match_msm_8660_qgic
// 	__used __section(__irqchip_of_table)
// 	= { .compatible = "qcom,msm-8660-qgic", .data = gic_of_init }
IRQCHIP_DECLARE(msm_8660_qgic, "qcom,msm-8660-qgic", gic_of_init);

// ARM10C 20141011
// #define IRQCHIP_DECLARE(msm_qgic2,"qcom,msm-qgic2",gic_of_init)
// 	static const struct of_device_id irqchip_of_match_msm_qgic2
// 	__used __section(__irqchip_of_table)
// 	= { .compatible = "qcom,msm-qgic2", .data = gic_of_init }
IRQCHIP_DECLARE(msm_qgic2, "qcom,msm-qgic2", gic_of_init);

#endif
