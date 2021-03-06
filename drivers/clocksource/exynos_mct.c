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

// ARM10C 20150404
#define EXYNOS4_MCTREG(x)		(x)
// ARM10C 20150516
// EXYNOS4_MCT_G_CNT_L: 0x100
#define EXYNOS4_MCT_G_CNT_L		EXYNOS4_MCTREG(0x100)
// ARM10C 20150516
// EXYNOS4_MCT_G_CNT_U: 0x104
#define EXYNOS4_MCT_G_CNT_U		EXYNOS4_MCTREG(0x104)
// ARM10C 20150516
// EXYNOS4_MCT_G_CNT_WSTAT: 0x110
#define EXYNOS4_MCT_G_CNT_WSTAT		EXYNOS4_MCTREG(0x110)
// ARM10C 20150516
// EXYNOS4_MCT_G_COMP0_L: 0x200
#define EXYNOS4_MCT_G_COMP0_L		EXYNOS4_MCTREG(0x200)
// ARM10C 20150516
// EXYNOS4_MCT_G_COMP0_U: 0x204
#define EXYNOS4_MCT_G_COMP0_U		EXYNOS4_MCTREG(0x204)
// ARM10C 20150516
// EXYNOS4_MCT_G_COMP0_ADD_INCR: 0x208
#define EXYNOS4_MCT_G_COMP0_ADD_INCR	EXYNOS4_MCTREG(0x208)
// ARM10C 20150516
// ARM10C 20150523
// EXYNOS4_MCT_G_TCON: 0x240
#define EXYNOS4_MCT_G_TCON		EXYNOS4_MCTREG(0x240)
#define EXYNOS4_MCT_G_INT_CSTAT		EXYNOS4_MCTREG(0x244)
// ARM10C 20150523
// EXYNOS4_MCT_G_INT_ENB: 0x248
#define EXYNOS4_MCT_G_INT_ENB		EXYNOS4_MCTREG(0x248)
// ARM10C 20150523
// EXYNOS4_MCT_G_WSTAT: 0x24C
#define EXYNOS4_MCT_G_WSTAT		EXYNOS4_MCTREG(0x24C)
// ARM10C 20150404
// EXYNOS4_MCTREG(0x300): 0x300
// _EXYNOS4_MCT_L_BASE: 0x300
#define _EXYNOS4_MCT_L_BASE		EXYNOS4_MCTREG(0x300)
// ARM10C 20150404
// ARM10C 20150509
// _EXYNOS4_MCT_L_BASE: 0x300
// EXYNOS4_MCT_L_BASE(0): 0x300
#define EXYNOS4_MCT_L_BASE(x)		(_EXYNOS4_MCT_L_BASE + (0x100 * x))
// ARM10C 20150509
// EXYNOS4_MCT_L_MASK: 0xffffff00
#define EXYNOS4_MCT_L_MASK		(0xffffff00)

// ARM10C 20150509
// ARM10C 20150509
// MCT_L_TCNTB_OFFSET: 0x00
#define MCT_L_TCNTB_OFFSET		(0x00)
// ARM10C 20150509
// ARM10C 20150509
// MCT_L_ICNTB_OFFSET: 0x08
#define MCT_L_ICNTB_OFFSET		(0x08)
// ARM10C 20150418
// ARM10C 20150509
// MCT_L_TCON_OFFSET: 0x20
#define MCT_L_TCON_OFFSET		(0x20)
#define MCT_L_INT_CSTAT_OFFSET		(0x30)
// ARM10C 20150509
// MCT_L_INT_ENB_OFFSET: 0x34
#define MCT_L_INT_ENB_OFFSET		(0x34)
// ARM10C 20150509
// MCT_L_WSTAT_OFFSET: 0x40
#define MCT_L_WSTAT_OFFSET		(0x40)
// ARM10C 20150523
// MCT_G_TCON_START: 0x100
#define MCT_G_TCON_START		(1 << 8)
// ARM10C 20150523
// MCT_G_TCON_COMP0_AUTO_INC: 0x2
#define MCT_G_TCON_COMP0_AUTO_INC	(1 << 1)
// ARM10C 20150523
// MCT_G_TCON_COMP0_ENABLE: 0x1
#define MCT_G_TCON_COMP0_ENABLE		(1 << 0)
// ARM10C 20150509
// MCT_L_TCON_INTERVAL_MODE: 0x4
#define MCT_L_TCON_INTERVAL_MODE	(1 << 2)
// ARM10C 20150418
// ARM10C 20150509
// MCT_L_TCON_INT_START: 0x2
#define MCT_L_TCON_INT_START		(1 << 1)
// ARM10C 20150418
// ARM10C 20150509
// MCT_L_TCON_TIMER_START: 0x1
#define MCT_L_TCON_TIMER_START		(1 << 0)

// ARM10C 20150404
// ARM10C 20150509
// TICK_BASE_CNT: 1
#define TICK_BASE_CNT	1

// ARM10C 20150307
// ARM10C 20150328
// ARM10C 20150509
enum {
	// MCT_INT_SPI: 0
	MCT_INT_SPI,
	// MCT_INT_PPI: 1
	MCT_INT_PPI
};

// ARM10C 20150307
// ARM10C 20150328
// ARM10C 20150509
// ARM10C 20150523
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
// ARM10C 20150418
static void __iomem *reg_base;
// ARM10C 20150321
// ARM10C 20150404
static unsigned long clk_rate;
// ARM10C 20150307
// ARM10C 20150328
// ARM10C 20150509
static unsigned int mct_int_type;
// ARM10C 20150307
// ARM10C 20150321
// MCT_NR_IRQS: 8
static int mct_irqs[MCT_NR_IRQS];

// ARM10C 20150321
// ARM10C 20150404
// ARM10C 20150411
// ARM10C 20150620
struct mct_clock_event_device {
	struct clock_event_device evt;
	unsigned long base;
	char name[10];
};

// ARM10C 20150509
// tmp: 0x8001D4C0, 0x308
// ARM10C 20150509
// 0x1, 0x334
// ARM10C 20150509
// tmp: 0x7, 0x320
// ARM10C 20150509
// TICK_BASE_CNT: 1, 0x300
// ARM10C 20150516
// lo: 0, EXYNOS4_MCT_G_CNT_L: 0x100
// ARM10C 20150516
// hi: 0, EXYNOS4_MCT_G_CNT_U: 0x104
// ARM10C 20150523
// reg: 0x100, EXYNOS4_MCT_G_TCON: 0x240
// ARM10C 20150523
// tcon: 0x100, EXYNOS4_MCT_G_TCON: 0x240
// ARM10C 20150523
// 0, EXYNOS4_MCT_G_INT_ENB: 0x248
// ARM10C 20150620
// tmp: 0x80001FFF, 0x308
// ARM10C 20150620
// 0x1, 0x334
// ARM10C 20150620
// tmp: 0x7, 0x320
static void exynos4_mct_write(unsigned int value, unsigned long offset)
{
	unsigned long stat_addr;
	u32 mask;
	u32 i;

	// E.R.M: 21.4.1.23 L0_ICNTB
	// L_ICNTB: Specifies the interrupt count buffer register
	// 31 bit   - interrupt manual update
	// 30~0 bit - interrupt count buffer

	// E.R.M: 21.4.1.29 L0_INT_ENB
	// L_INT_ENB: Specifies the interrupt enable for L_IRQ0
	// 1 bit  - FRCEIE: free running counter expired (L0_FRCCNT = 0) interrupt enable
	// 0 bit  - ICNTEIE: interrupt counter expired (L0_INTCNT = 0) interrupt enable

	// E.R.M: 21.4.1.27 L0_TCON
	// L_TCON: Specifies the timer control register
	// 3 bit  - frc start/stop
	// 2 bit  - interrupt type
	// 1 bit  - interrupt start/stop
	// 0 bit  - timer start/stop

	// E.R.M: 21.4.1.21 L0_TCNTB
	// L_TCNTB: Specifies the tick integer count buffer register
	// 31~0 bit - tick count buffer

	// E.R.M: 21.4.1.2 G_CNT_L
	// G_CNT_L: Specifies the lower 32 bit value of FRC buffer register
	// 31~0 bit - FRC count buffer

	// E.R.M: 21.4.1.2 G_CNT_U
	// G_CNT_U: Specifies the upper 32 bit value of FRC buffer register
	// 31~0 bit - FRC count buffer

	// E.R.M: 21.4.1.17 G_TCON
	// G_TCON: Specifies the global timer control register
	// 8 bit  - timer enable
	// 7 bit  - auto increment3
	// 6 bit  - comp3 enable
	// 5 bit  - auto increment2
	// 4 bit  - comp2 enable
	// 3 bit  - auto increment1
	// 2 bit  - comp1 enable
	// 1 bit  - auto increment0
	// 0 bit  - comp0 enable

	// E.R.M: 21.4.1.19 G_INT_ENB
	// G_INT_ENB: Specifies the interrupt enable for G_IRQ0 to 3
	// 3 bit  - C_INT3_ENABLE
	// 2 bit  - C_INT2_ENABLE
	// 1 bit  - C_INT1_ENABLE
	// 0 bit  - C_INT0_ENABLE

	// E.R.M: 21.4.1.23 L0_ICNTB
	// L_ICNTB: Specifies the interrupt count buffer register
	// 31 bit   - interrupt manual update
	// 30~0 bit - interrupt count buffer

	// E.R.M: 21.4.1.29 L0_INT_ENB
	// L_INT_ENB: Specifies the interrupt enable for L_IRQ0
	// 1 bit  - FRCEIE: free running counter expired (L0_FRCCNT = 0) interrupt enable
	// 0 bit  - ICNTEIE: interrupt counter expired (L0_INTCNT = 0) interrupt enable

	// E.R.M: 21.4.1.27 L0_TCON
	// L_TCON: Specifies the timer control register
	// 3 bit  - frc start/stop
	// 2 bit  - interrupt type
	// 1 bit  - interrupt start/stop
	// 0 bit  - timer start/stop

	// value: 0x8001D4C0, reg_base: 0xf0006000, offset: 0x308
	// value: 0x1, reg_base: 0xf0006000, offset: 0x334
	// value: 0x7, reg_base: 0xf0006000, offset: 0x320
	// value: 0x1, reg_base: 0xf0006000, offset: 0x300
	// value: 0x0, reg_base: 0xf0006000, offset: 0x100
	// value: 0x0, reg_base: 0xf0006000, offset: 0x104
	// value: 0x100, reg_base: 0xf0006000, offset: 0x240
	// value: 0x0, reg_base: 0xf0006000, offset: 0x248
	// value: 0x80001FFF, reg_base: 0xf0006000, offset: 0x308
	// value: 0x1, reg_base: 0xf0006000, offset: 0x334
	// value: 0x7, reg_base: 0xf0006000, offset: 0x320
	__raw_writel(value, reg_base + offset);

	// __raw_writel에서 한일:
	// register L_ICNTB 에 0x8001D4C0 write함
	// local timer 0 의 interrupt count buffer 값을 120000 (0x1D4C0)을 write 하고
	// interrupt manual update를 enable 시킴

	// __raw_writel에서 한일:
	// register L_INT_ENB 에 0x1 write함
	// local timer 0 의 ICNTEIE 값을 0x1을 write 하여 L0_INTCNT 값이 0 이 되었을 때
	// interrupt counter expired interrupt 가 발생하도록 함

	// __raw_writel에서 한일:
	// register L_TCON 에 0x7 write함
	// local timer 0 의 interrupt type을 interval mode로 설정하고 interrupt, timer 를 start 시킴

	// __raw_writel에서 한일:
	// register L_TCNTB 에 0x1 write함
	// local timer 0 의 tick count 값을 1로 write 함

	// __raw_writel에서 한일:
	// register G_CNT_L 에 0x0 write함
	// FRC count buffer 의 tick count 값을 0로 write 함

	// __raw_writel에서 한일:
	// register G_CNT_U 에 0x0 write함
	// FRC count buffer 의 tick count 값을 0로 write 함

	// __raw_writel에서 한일:
	// register G_TCON 에 0x100 write함
	// global timer enable 의 값을 1로 write 함

	// __raw_writel에서 한일:
	// register G_INT_ENB 에 0x0 write함
	// global timer interrupt enable 의 값을 0로 write 함

	// __raw_writel에서 한일:
	// register L_ICNTB 에 0x80001FFF write함
	// local timer 0 의 interrupt count buffer 값을 120000 (0x1FFF)을 write 하고
	// interrupt manual update를 enable 시킴

	// __raw_writel에서 한일:
	// register L_INT_ENB 에 0x1 write함
	// local timer 0 의 ICNTEIE 값을 0x1을 write 하여 L0_INTCNT 값이 0 이 되었을 때
	// interrupt counter expired interrupt 가 발생하도록 함

	// __raw_writel에서 한일:
	// register L_TCON 에 0x7 write함
	// local timer 0 의 interrupt type을 interval mode로 설정하고 interrupt, timer 를 start 시킴

	// offset: 0x308, EXYNOS4_MCT_L_BASE(0): 0x300
	// offset: 0x334, EXYNOS4_MCT_L_BASE(0): 0x300
	// offset: 0x320, EXYNOS4_MCT_L_BASE(0): 0x300
	// offset: 0x300, EXYNOS4_MCT_L_BASE(0): 0x300
	// offset: 0x100, EXYNOS4_MCT_L_BASE(0): 0x300
	// offset: 0x104, EXYNOS4_MCT_L_BASE(0): 0x300
	// offset: 0x240, EXYNOS4_MCT_L_BASE(0): 0x300
	// offset: 0x248, EXYNOS4_MCT_L_BASE(0): 0x300
	// offset: 0x308, EXYNOS4_MCT_L_BASE(0): 0x300
	// offset: 0x334, EXYNOS4_MCT_L_BASE(0): 0x300
	// offset: 0x320, EXYNOS4_MCT_L_BASE(0): 0x300
	if (likely(offset >= EXYNOS4_MCT_L_BASE(0))) {
		// offset: 0x308, EXYNOS4_MCT_L_MASK: 0xffffff00, MCT_L_WSTAT_OFFSET: 0x40
		// offset: 0x334, EXYNOS4_MCT_L_MASK: 0xffffff00, MCT_L_WSTAT_OFFSET: 0x40
		// offset: 0x320, EXYNOS4_MCT_L_MASK: 0xffffff00, MCT_L_WSTAT_OFFSET: 0x40
		// offset: 0x300, EXYNOS4_MCT_L_MASK: 0xffffff00, MCT_L_WSTAT_OFFSET: 0x40
		// offset: 0x308, EXYNOS4_MCT_L_MASK: 0xffffff00, MCT_L_WSTAT_OFFSET: 0x40
		// offset: 0x334, EXYNOS4_MCT_L_MASK: 0xffffff00, MCT_L_WSTAT_OFFSET: 0x40
		// offset: 0x320, EXYNOS4_MCT_L_MASK: 0xffffff00, MCT_L_WSTAT_OFFSET: 0x40
		stat_addr = (offset & ~EXYNOS4_MCT_L_MASK) + MCT_L_WSTAT_OFFSET;
		// stat_addr: 0x48
		// stat_addr: 0x74
		// stat_addr: 0x60
		// stat_addr: 0x40
		// stat_addr: 0x48
		// stat_addr: 0x74
		// stat_addr: 0x60

		// offset: 0x308, EXYNOS4_MCT_L_MASK: 0xffffff00
		// offset: 0x334, EXYNOS4_MCT_L_MASK: 0xffffff00
		// offset: 0x320, EXYNOS4_MCT_L_MASK: 0xffffff00
		// offset: 0x300, EXYNOS4_MCT_L_MASK: 0xffffff00
		// offset: 0x308, EXYNOS4_MCT_L_MASK: 0xffffff00
		// offset: 0x334, EXYNOS4_MCT_L_MASK: 0xffffff00
		// offset: 0x320, EXYNOS4_MCT_L_MASK: 0xffffff00
		switch (offset & EXYNOS4_MCT_L_MASK) {
		case MCT_L_TCON_OFFSET:  // MCT_L_TCON_OFFSET: 0x20
			mask = 1 << 3;		/* L_TCON write status */
			break;
		case MCT_L_ICNTB_OFFSET: // MCT_L_ICNTB_OFFSET: 0x08
			mask = 1 << 1;		/* L_ICNTB write status */
			break;
		case MCT_L_TCNTB_OFFSET: // MCT_L_TCNTB_OFFSET: 0x00
			mask = 1 << 0;		/* L_TCNTB write status */
			break;
		default:
			return;
			// return 수행
			// return 수행
			// return 수행
			// return 수행
			// return 수행
			// return 수행
			// return 수행
		}
	} else {
		// offset: 0x100
		// offset: 0x104
		// offset: 0x240
		// offset: 0x248
		switch (offset) {
		case EXYNOS4_MCT_G_TCON: // EXYNOS4_MCT_G_TCON: 0x240
			// EXYNOS4_MCT_G_WSTAT: 0x24C
			stat_addr = EXYNOS4_MCT_G_WSTAT;
			// stat_addr: 0x24C

			mask = 1 << 16;		/* G_TCON write status */
			// mask: 0x10000
			break;
			// break 수행
		case EXYNOS4_MCT_G_COMP0_L: // EXYNOS4_MCT_G_COMP0_L: 0x200
			stat_addr = EXYNOS4_MCT_G_WSTAT;
			mask = 1 << 0;		/* G_COMP0_L write status */
			break;
		case EXYNOS4_MCT_G_COMP0_U: // EXYNOS4_MCT_G_COMP0_U: 0x204
			stat_addr = EXYNOS4_MCT_G_WSTAT;
			mask = 1 << 1;		/* G_COMP0_U write status */
			break;
		case EXYNOS4_MCT_G_COMP0_ADD_INCR: // EXYNOS4_MCT_G_COMP0_ADD_INCR: 0x208
			stat_addr = EXYNOS4_MCT_G_WSTAT;
			mask = 1 << 2;		/* G_COMP0_ADD_INCR w status */
			break;
		case EXYNOS4_MCT_G_CNT_L: // EXYNOS4_MCT_G_CNT_L: 0x100
			// EXYNOS4_MCT_G_CNT_WSTAT: 0x110
			stat_addr = EXYNOS4_MCT_G_CNT_WSTAT;
			// stat_addr: 0x110

			mask = 1 << 0;		/* G_CNT_L write status */
			// mask: 0x1

			break;
			// break 수행
		case EXYNOS4_MCT_G_CNT_U: // EXYNOS4_MCT_G_CNT_U: 0x104
			// EXYNOS4_MCT_G_CNT_WSTAT: 0x110
			stat_addr = EXYNOS4_MCT_G_CNT_WSTAT;
			// stat_addr: 0x110

			mask = 1 << 1;		/* G_CNT_U write status */
			// mask: 0x2

			break;
			// break 수행
		default:
			return;
			// return 수행
		}
	}

	/* Wait maximum 1 ms until written values are applied */
	// loops_per_jiffy: 4096, HZ: 100
	// loops_per_jiffy: 4096, HZ: 100
	// loops_per_jiffy: 4096, HZ: 100
	for (i = 0; i < loops_per_jiffy / 1000 * HZ; i++)
		// E.R.M: 21.4.1.4 G_CNT_WSTAT
		// G_CNT_WSTAT: Specifies G_CNT_L and G_CNT_U SFR write status register
		// 0 bit - G_CNT_L write status

		// E.R.M: 21.4.1.4 G_CNT_WSTAT
		// G_CNT_WSTAT: Specifies G_CNT_L and G_CNT_U SFR write status register
		// 1 bit - G_CNT_U write status

		// E.R.M: 21.4.1.20 G_WSTAT
		// G_WSTAT: Specifies the write status for comparator 0 to 3
		// 16 bit - G_TCON write status
		// 14 bit - G_COMP3_ADD_INCR write status
		// 13 bit - G_COMP3_U write status
		// 12 bit - G_COMP3_L write status
		// 10 bit - G_COMP2_ADD_INCR write status
		//  9 bit - G_COMP2_U write status
		//  8 bit - G_COMP2_L write status
		//  6 bit - G_COMP1_ADD_INCR write status
		//  5 bit - G_COMP1_U write status
		//  4 bit - G_COMP1_L write status
		//  2 bit - G_COMP0_ADD_INCR write status
		//  1 bit - G_COMP0_U write status
		//  0 bit - G_COMP0_L write status

		// reg_base: 0xf0006000, stat_addr: 0x110, mask: 0x1, __raw_readl(0xf0006110): 0x1
		// reg_base: 0xf0006000, stat_addr: 0x110, mask: 0x2, __raw_readl(0xf0006110): 0x1
		// reg_base: 0xf0006000, stat_addr: 0x24C, mask: 0x10000, __raw_readl(0xf000624C): 0x10000
		if (__raw_readl(reg_base + stat_addr) & mask) {
			// mask: 0x1, reg_base: 0xf0006000, stat_addr: 0x110
			// mask: 0x2, reg_base: 0xf0006000, stat_addr: 0x110
			// mask: 0x10000, reg_base: 0xf0006000, stat_addr: 0x24C
			__raw_writel(mask, reg_base + stat_addr);

			// __raw_writel에서 한일:
			// register G_CNT_WSTAT 에 0x1 write함
			// G_CNT_L write status 의 값을 1로 write 함

			// __raw_writel에서 한일:
			// register G_CNT_WSTAT 에 0x2 write함
			// G_CNT_L write status 의 값을 2로 write 함

			// __raw_writel에서 한일:
			// register G_WSTAT 에 0x10000 write함
			// G_TCON write status 의 값을 1로 write 함

			return;
			// return 수행
			// return 수행
			// return 수행
		}

	panic("MCT hangs after writing %d (offset:0x%lx)\n", value, offset);
}

/* Clocksource handling */
// ARM10C 20150516
// 0, 0
static void exynos4_mct_frc_start(u32 hi, u32 lo)
{
	u32 reg;

	// lo: 0, EXYNOS4_MCT_G_CNT_L: 0x100
	exynos4_mct_write(lo, EXYNOS4_MCT_G_CNT_L);

	// exynos4_mct_write 에서 한일:
	// register G_CNT_L 에 0x0 write함
	// FRC count buffer 의 tick count 값을 0로 write 함
	//
	// register G_CNT_WSTAT 에 0x1 write함
	// G_CNT_L write status 의  값을 1로 write 함

	// hi: 0, EXYNOS4_MCT_G_CNT_U: 0x104
	exynos4_mct_write(hi, EXYNOS4_MCT_G_CNT_U);

	// exynos4_mct_write 에서 한일:
	// register G_CNT_U 에 0x0 write함
	// FRC count buffer 의 tick count 값을 0로 write 함
	//
	// register G_CNT_WSTAT 에 0x1 write함
	// G_CNT_U write status 의  값을 1로 write 함

// 2015/05/16 종료
// 2015/05/23 시작

	// E.R.M: 21.4.1.17 G_TCON
	// G_TCON: Specifies the global timer control register
	// 8 bit  - timer enable
	// 7 bit  - auto increment3
	// 6 bit  - comp3 enable
	// 5 bit  - auto increment2
	// 4 bit  - comp2 enable
	// 3 bit  - auto increment1
	// 2 bit  - comp1 enable
	// 1 bit  - auto increment0
	// 0 bit  - comp0 enable
	
	// NOTE:
	// register G_TCON 값이 reset 값인 0x0으로 읽히는 것으로 가정하고 코드 분석 진행

	// reg_base: 0xf0006000, EXYNOS4_MCT_G_TCON: 0x240
	// __raw_readl(0xf0006240): 0x0
	reg = __raw_readl(reg_base + EXYNOS4_MCT_G_TCON);
	// reg: 0x0

	// MCT_G_TCON_START: 0x100
	reg |= MCT_G_TCON_START;
	// reg: 0x100

	// reg: 0x100, EXYNOS4_MCT_G_TCON: 0x240
	exynos4_mct_write(reg, EXYNOS4_MCT_G_TCON);

	// exynos4_mct_write 에서 한일:
	// register G_TCON 에 0x100 write함
	// global timer enable 의 값을 1로 write 함
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

// ARM10C 20150523
struct clocksource mct_frc = {
	.name		= "mct-frc",
	.rating		= 400,
	.read		= exynos4_frc_read,
	// CLOCKSOURCE_MASK(64): 0xFFFFFFFF
	.mask		= CLOCKSOURCE_MASK(64),
	// CLOCK_SOURCE_IS_CONTINUOUS: 0x01
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
	.resume		= exynos4_frc_resume,
};

// ARM10C 20150516
static void __init exynos4_clocksource_init(void)
{
	exynos4_mct_frc_start(0, 0);

	// exynos4_mct_frc_start에서 한일:
	// register G_CNT_L 에 0x0 write함
	// FRC count buffer 의 tick count 값을 0로 write 함
	//
	// register G_CNT_WSTAT 에 0x1 write함
	// G_CNT_L write status 의  값을 1로 write 함
	//
	// register G_CNT_U 에 0x0 write함
	// FRC count buffer 의 tick count 값을 0로 write 함
	//
	// register G_CNT_WSTAT 에 0x1 write함
	// G_CNT_U write status 의  값을 1로 write 함
	//
	// register G_TCON 에 0x100 write함
	// global timer enable 의 값을 1로 write 함

	// clk_rate: 24000000, clocksource_register_hz(&mct_frc, 24000000): 0
	if (clocksource_register_hz(&mct_frc, clk_rate))
		panic("%s: can't register clocksource\n", mct_frc.name);

	// clocksource_register_hz에서 한일:
	// (&mct_frc)->mult: 0xA6AAAAAA
	// (&mct_frc)->shift: 26
	// (&mct_frc)->maxadj: 0x12555555
	// (&mct_frc)->max_idle_ns: 0x103955554C
	// (&mct_frc)->flags: 0x21
	//
	// list clocksource_list의 next에 &(&mct_frc)->list를 추가함
}

// ARM10C 20150523
static void exynos4_mct_comp0_stop(void)
{
	unsigned int tcon;

	// E.R.M: 21.4.1.17 G_TCON
	// G_TCON: Specifies the global timer control register
	// 8 bit  - timer enable
	// 7 bit  - auto increment3
	// 6 bit  - comp3 enable
	// 5 bit  - auto increment2
	// 4 bit  - comp2 enable
	// 3 bit  - auto increment1
	// 2 bit  - comp1 enable
	// 1 bit  - auto increment0
	// 0 bit  - comp0 enable

	// reg_base: 0xf0006000, EXYNOS4_MCT_G_TCON: 0x240
	// __raw_readl(0xf0006240): 0x100
	tcon = __raw_readl(reg_base + EXYNOS4_MCT_G_TCON);
	// tcon: 0x100

	// tcon: 0x100, MCT_G_TCON_COMP0_ENABLE: 0x1, MCT_G_TCON_COMP0_AUTO_INC: 0x2
	tcon &= ~(MCT_G_TCON_COMP0_ENABLE | MCT_G_TCON_COMP0_AUTO_INC);
	// tcon: 0x100

	// tcon: 0x100, EXYNOS4_MCT_G_TCON: 0x240
	exynos4_mct_write(tcon, EXYNOS4_MCT_G_TCON);

	// exynos4_mct_write에서 한일:
	// register G_TCON 에 0x100 write함
	// global timer enable 의 값을 1로 write 함

	// EXYNOS4_MCT_G_INT_ENB: 0x248
	exynos4_mct_write(0, EXYNOS4_MCT_G_INT_ENB);

	// exynos4_mct_write에서 한일:
	// register G_INT_ENB 에 0x0 write함
	// global timer interrupt enable 의 값을 0로 write 함
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

// ARM10C 20150523
// mode: 1, dev: &mct_comp_device
static void exynos4_comp_set_mode(enum clock_event_mode mode,
				  struct clock_event_device *evt)
{
	unsigned long cycles_per_jiffy;

	exynos4_mct_comp0_stop();

	// exynos4_mct_comp0_stop에서 한일:
	// register G_TCON 에 0x100 write함
	// global timer enable 의 값을 1로 write 함
	//
	// register G_INT_ENB 에 0x0 write함
	// global timer interrupt enable 의 값을 0로 write 함
	//
	// comparator 0의 auto increment0, comp0 enable,comp0 interrupt enable 값을
	// 0으로 clear 하여 comparator 0를 동작하지 않도록 함

	// mode: 1
	switch (mode) {
	case CLOCK_EVT_MODE_PERIODIC: // CLOCK_EVT_MODE_PERIODIC: 2
		cycles_per_jiffy =
			(((unsigned long long) NSEC_PER_SEC / HZ * evt->mult) >> evt->shift);
		exynos4_mct_comp0_start(mode, cycles_per_jiffy);
		break;

	case CLOCK_EVT_MODE_ONESHOT:  // CLOCK_EVT_MODE_ONESHOT: 3
	case CLOCK_EVT_MODE_UNUSED:   // CLOCK_EVT_MODE_UNUSED: 0
	case CLOCK_EVT_MODE_SHUTDOWN: // CLOCK_EVT_MODE_SHUTDOWN: 1
	case CLOCK_EVT_MODE_RESUME:   // CLOCK_EVT_MODE_RESUME: 4
		break;
		// break 수행
	}
}

// ARM10C 20150523
static struct clock_event_device mct_comp_device = {
	.name		= "mct-comp",
	// CLOCK_EVT_FEAT_PERIODIC: 0x000001, CLOCK_EVT_FEAT_ONESHOT: 0x000002
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

// ARM10C 20150523
static struct irqaction mct_comp_event_irq = {
	.name		= "mct_comp_irq",
	// IRQF_TIMER: 0x14200, IRQF_IRQPOLL: 0x00001000
	.flags		= IRQF_TIMER | IRQF_IRQPOLL,
	.handler	= exynos4_mct_comp_isr,
	.dev_id		= &mct_comp_device,
};

// ARM10C 20150523
static void exynos4_clockevent_init(void)
{
	// cpumask_of(0): &cpu_bit_bitmap[1][0]
	mct_comp_device.cpumask = cpumask_of(0);
	// mct_comp_device.cpumask: &cpu_bit_bitmap[1][0

	// clk_rate: 24000000
	// clockevents_config_and_register(&mct_comp_device, 24000000, 0xf, 0xffffffff)
	clockevents_config_and_register(&mct_comp_device, clk_rate,
					0xf, 0xffffffff);

	// clockevents_config_and_register에서 한일:
	// mct_comp_device.cpumask: &cpu_bit_bitmap[1][0
	// (&mct_comp_device)->min_delta_ticks: 0xf
	// (&mct_comp_device)->max_delta_ticks: 0xffffffff
	// (&mct_comp_device)->mult: 0x3126E98
	// (&mct_comp_device)->shift: 31
	// (&mct_comp_device)->min_delta_ns: 0x3E8
	// (&mct_comp_device)->max_delta_ns: 0x29AAAAA46E
	// (&mct_comp_device)->mode: 1
	// (&mct_comp_device)->next_event.tv64: 0x7FFFFFFFFFFFFFFF
	//
	// list clockevent_devices에 (&mct_comp_device)->list를 추가함
	//
	// register G_TCON 에 0x100 write함
	// global timer enable 의 값을 1로 write 함
	//
	// register G_INT_ENB 에 0x0 write함
	// global timer interrupt enable 의 값을 0로 write 함
	//
	// comparator 0의 auto increment0, comp0 enable,comp0 interrupt enable 값을
	// 0으로 clear 하여 comparator 0를 동작하지 않도록 함
	//
	// tick_broadcast_device.evtdev: &mct_comp_device
	// [pcp0] &(&tick_cpu_sched)->check_clocks: 0xf

	// MCT_G0_IRQ: 0, mct_irqs[0]: 347, setup_irq(347, &mct_comp_event_irq): 0
	setup_irq(mct_irqs[MCT_G0_IRQ], &mct_comp_event_irq);

	// setup_irq에서 한일:
	// &(&(kmem_cache#28-oX (irq 347))->wait_for_threads)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#28-oX (irq 347))->wait_for_threads)->task_list를 사용한 list 초기화
	// &(kmem_cache#28-oX (irq 347))->istate: 0
	// (kmem_cache#28-oX (irq 347))->depth: 0
	// (kmem_cache#28-oX (irq 347))->action: &mct_comp_event_irq
	// (kmem_cache#28-oX (irq 347))->irq_count: 0
	// (kmem_cache#28-oX (irq 347))->irqs_unhandled: 0
	//
	// (&(kmem_cache#28-oX (irq 347))->irq_data)->state_use_accessors: 0x10000
	// (&(kmem_cache#28-oX (irq 347))->irq_data)->affinity->bits[0]: 1
	//
	// register IESR5의 MCT_G0 bit 를 1 로 write 하여 MCT_G0 의 interrupt 를 enable 시킴
	//
	// GICD_ITARGETSR46 값을 모르기 때문에 0x00000000 로
	// 읽히는 것으로 가정하고 GICD_ITARGETSR46에 0x1000000를 write 함
	// CPU interface 0에 interrupt가 발생을 나타냄
	//
	// struct irqaction 멤버 값 세팅
	// (&mct_comp_event_irq)->irq: 347
	// (&mct_comp_event_irq)->dir: NULL
}

// ARM10C 20150321
// ARM10C 20150418
// ARM10C 20150620
static DEFINE_PER_CPU(struct mct_clock_event_device, percpu_mct_tick);

/* Clock event handling */
// ARM10C 20150418
// mevt: [pcp0] &percpu_mct_tick
// ARM10C 20150509
// mevt: [pcp0] &percpu_mct_tick
// ARM10C 20150509
// mevt: [pcp0] &percpu_mct_tick
// ARM10C 20150620
// mevt: [pcp0] &percpu_mct_tick
static void exynos4_mct_tick_stop(struct mct_clock_event_device *mevt)
{
	unsigned long tmp;

	// MCT_L_TCON_INT_START: 0x2, MCT_L_TCON_TIMER_START: 0x1
	unsigned long mask = MCT_L_TCON_INT_START | MCT_L_TCON_TIMER_START;
	// mask: 0x3

	// mevt->base: [pcp0] (&percpu_mct_tick)->base: 0x300, MCT_L_TCON_OFFSET: 0x20
	unsigned long offset = mevt->base + MCT_L_TCON_OFFSET;
	// offset: 0x320

	// E.R.M: 21.4.1.27 L0_TCON
	// L_TCON: Specifies the timer control register
	// 3 bit  - frc start/stop
	// 2 bit  - interrupt type
	// 1 bit  - interrupt start/stop
	// 0 bit  - timer start/stop

	// NOTE:
	// register L0_TCON 값이 reset 값인 0x0으로 읽히는 것으로 가정하고 코드 분석 진행

	// reg_base: 0xf0006000, offset: 0x320
	// __raw_readl(0xf0006320): 0
	tmp = __raw_readl(reg_base + offset);
	// tmp: 0

	// tmp: 0, mask: 0x3
	if (tmp & mask) {
		tmp &= ~mask;
		exynos4_mct_write(tmp, offset);
	}
}

// ARM10C 20150509
// cycles_per_jiffy: 120000 (0x1D4C0), mevt: [pcp0] &percpu_mct_tick
// ARM10C 20150620
// cycles: 0x1FFF, mevt: [pcp0] &percpu_mct_tick
static void exynos4_mct_tick_start(unsigned long cycles,
				   struct mct_clock_event_device *mevt)
{
	unsigned long tmp;

	// mevt: [pcp0] &percpu_mct_tick
	// mevt: [pcp0] &percpu_mct_tick
	exynos4_mct_tick_stop(mevt);

	// exynos4_mct_tick_stop에서 한일:
	// timer control register L0_TCON 값을 읽어 timer start, timer interrupt 설정을
	// 동작하지 않도록 변경함
	// L0_TCON 값이 0 으로 가정하였으므로 timer는 동작하지 않은 상태임

	// exynos4_mct_tick_stop에서 한일:
	// timer control register L0_TCON 값을 읽어 timer start, timer interrupt 설정을
	// 동작하지 않도록 변경함
	// L0_TCON 값이 0 으로 가정하였으므로 timer는 동작하지 않은 상태임

	// cycles: 0x1D4C0
	// cycles: 0x1FFF
	tmp = (1 << 31) | cycles;	/* MCT_L_UPDATE_ICNTB */
	// tmp: 0x8001D4C0
	// tmp: 0x80001FFF

	/* update interrupt count buffer */
	// tmp: 0x8001D4C0, mevt->base: [pcp0] (&percpu_mct_tick)->base: 0x300, MCT_L_ICNTB_OFFSET: 0x08
	// tmp: 0x80001FFF, mevt->base: [pcp0] (&percpu_mct_tick)->base: 0x300, MCT_L_ICNTB_OFFSET: 0x08
	exynos4_mct_write(tmp, mevt->base + MCT_L_ICNTB_OFFSET);

	// exynos4_mct_write에서 한일:
	// register L_ICNTB 에 0x8001D4C0 write함
	// local timer 0 의 interrupt count buffer 값을 120000 (0x1D4C0) write 하고
	// interrupt manual update를 enable 시킴

	// exynos4_mct_write에서 한일:
	// register L_ICNTB 에 0x80001FFF write함
	// local timer 0 의 interrupt count buffer 값을 120000 (0x1FFF) write 하고
	// interrupt manual update를 enable 시킴

	/* enable MCT tick interrupt */
	// mevt->base: [pcp0] (&percpu_mct_tick)->base: 0x300, MCT_L_INT_ENB_OFFSET: 0x34
	// mevt->base: [pcp0] (&percpu_mct_tick)->base: 0x300, MCT_L_INT_ENB_OFFSET: 0x34
	exynos4_mct_write(0x1, mevt->base + MCT_L_INT_ENB_OFFSET);

	// exynos4_mct_write에서 한일:
	// register L_INT_ENB 에 0x1 write함
	// local timer 0 의 ICNTEIE 값을 0x1을 write 하여 L0_INTCNT 값이 0 이 되었을 때
	// interrupt counter expired interrupt 가 발생하도록 함

	// exynos4_mct_write에서 한일:
	// register L_INT_ENB 에 0x1 write함
	// local timer 0 의 ICNTEIE 값을 0x1을 write 하여 L0_INTCNT 값이 0 이 되었을 때
	// interrupt counter expired interrupt 가 발생하도록 함

	// E.R.M: 21.4.1.27 L0_TCON
	// L_TCON: Specifies the timer control register
	// 3 bit  - frc start/stop
	// 2 bit  - interrupt type
	// 1 bit  - interrupt start/stop
	// 0 bit  - timer start/stop

	// NOTE:
	// register L0_TCON 값이 reset 값인 0x0으로 읽히는 것으로 가정하고 코드 분석 진행

	// reg_base: 0xf0006000, mevt->base: [pcp0] (&percpu_mct_tick)->base: 0x300, MCT_L_TCON_OFFSET: 0x20
	// reg_base: 0xf0006000, mevt->base: [pcp0] (&percpu_mct_tick)->base: 0x300, MCT_L_TCON_OFFSET: 0x20
	tmp = __raw_readl(reg_base + mevt->base + MCT_L_TCON_OFFSET);
	// tmp: 0
	// tmp: 0x7

	// tmp: 0, MCT_L_TCON_INT_START: 0x2, MCT_L_TCON_TIMER_START: 0x1, MCT_L_TCON_INTERVAL_MODE: 0x4
	// tmp: 0, MCT_L_TCON_INT_START: 0x2, MCT_L_TCON_TIMER_START: 0x1, MCT_L_TCON_INTERVAL_MODE: 0x4
	tmp |= MCT_L_TCON_INT_START | MCT_L_TCON_TIMER_START |
	       MCT_L_TCON_INTERVAL_MODE;
	// tmp: 0x7
	// tmp: 0x7

	// tmp: 0x7, mevt->base: [pcp0] (&percpu_mct_tick)->base: 0x300, MCT_L_TCON_OFFSET: 0x20
	// tmp: 0x7, mevt->base: [pcp0] (&percpu_mct_tick)->base: 0x300, MCT_L_TCON_OFFSET: 0x20
	exynos4_mct_write(tmp, mevt->base + MCT_L_TCON_OFFSET);

	// exynos4_mct_write에서 한일:
	// register L_TCON 에 0x7 write함
	// local timer 0 의 interrupt type을 interval mode로 설정하고 interrupt, timer 를 start 시킴

	// exynos4_mct_write에서 한일:
	// register L_TCON 에 0x7 write함
	// local timer 0 의 interrupt type을 interval mode로 설정하고 interrupt, timer 를 start 시킴
}

// ARM10C 20150404
// ARM10C 20150620
// clc: 0x1FFF, dev: [pcp0] &(&percpu_mct_tick)->evt
static int exynos4_tick_set_next_event(unsigned long cycles,
				       struct clock_event_device *evt)
{
	// this_cpu_ptr(&percpu_mct_tick): [pcp0] &percpu_mct_tick
	struct mct_clock_event_device *mevt = this_cpu_ptr(&percpu_mct_tick);
	// mevt: [pcp0] &percpu_mct_tick

	// cycles: 0x1FFF, mevt: [pcp0] &percpu_mct_tick
	exynos4_mct_tick_start(cycles, mevt);

	// exynos4_mct_tick_start에서 한일:
	// timer control register L0_TCON 값을 읽어 timer start, timer interrupt 설정을
	// 동작하지 않도록 변경함
	// L0_TCON 값이 0 으로 가정하였으므로 timer는 동작하지 않은 상태임
	//
	// register L_ICNTB 에 0x80001FFF write함
	// local timer 0 의 interrupt count buffer 값을 120000 (0x1FFF) write 하고
	// interrupt manual update를 enable 시킴
	//
	// register L_INT_ENB 에 0x1 write함
	// local timer 0 의 ICNTEIE 값을 0x1을 write 하여 L0_INTCNT 값이 0 이 되었을 때
	// interrupt counter expired interrupt 가 발생하도록 함
	//
	// register L_TCON 에 0x7 write함
	// local timer 0 의 interrupt type을 interval mode로 설정하고 interrupt, timer 를 start 시킴

	return 0;
}

// ARM10C 20150404
// ARM10C 20150411
// mode: 1, dev: [pcp0] &(&percpu_mct_tick)->evt
// ARM10C 20150509
// mode: 2, dev: [pcp0] &(&percpu_mct_tick)->evt
static inline void exynos4_tick_set_mode(enum clock_event_mode mode,
					 struct clock_event_device *evt)
{
	// this_cpu_ptr(&percpu_mct_tick): [pcp0] &percpu_mct_tick
	// this_cpu_ptr(&percpu_mct_tick): [pcp0] &percpu_mct_tick
	struct mct_clock_event_device *mevt = this_cpu_ptr(&percpu_mct_tick);
	// mevt: [pcp0] &percpu_mct_tick
	// mevt: [pcp0] &percpu_mct_tick

	unsigned long cycles_per_jiffy;

	// mevt: [pcp0] &percpu_mct_tick
	// mevt: [pcp0] &percpu_mct_tick
	exynos4_mct_tick_stop(mevt);

	// exynos4_mct_tick_stop에서 한일:
	// timer control register L0_TCON 값을 읽어 timer start, timer interrupt 설정을
	// 동작하지 않도록 변경함
	// L0_TCON 값이 0 으로 가정하였으므로 timer는 동작하지 않은 상태임

	// exynos4_mct_tick_stop에서 한일:
	// timer control register L0_TCON 값을 읽어 timer start, timer interrupt 설정을
	// 동작하지 않도록 변경함
	// L0_TCON 값이 0 으로 가정하였으므로 timer는 동작하지 않은 상태임

	// mode: 1
	// mode: 2
	switch (mode) {
	case CLOCK_EVT_MODE_PERIODIC: // CLOCK_EVT_MODE_PERIODIC: 2
		// NSEC_PER_SEC: 1000000000L, HZ: 100,
		// evt->mult: [pcp0] (&(&percpu_mct_tick)->evt)->mult: 0x3126E98,
		// evt->shift: [pcp0] (&(&percpu_mct_tick)->evt)->shift: 32
		cycles_per_jiffy =
			(((unsigned long long) NSEC_PER_SEC / HZ * evt->mult) >> evt->shift);
		// cycles_per_jiffy: 120000 (0x1D4C0)

		// cycles_per_jiffy: 120000 (0x1D4C0), mevt: [pcp0] &percpu_mct_tick
		exynos4_mct_tick_start(cycles_per_jiffy, mevt);

		// exynos4_mct_tick_start에서 한일:
		// timer control register L0_TCON 값을 읽어 timer start, timer interrupt 설정을
		// 동작하지 않도록 변경함
		// L0_TCON 값이 0 으로 가정하였으므로 timer는 동작하지 않은 상태임
		//
		// register L_ICNTB 에 0x8001D4C0 write함
		// local timer 0 의 interrupt count buffer 값을 120000 (0x1D4C0) write 하고
		// interrupt manual update를 enable 시킴
		//
		// register L_INT_ENB 에 0x1 write함
		// local timer 0 의 ICNTEIE 값을 0x1을 write 하여 L0_INTCNT 값이 0 이 되었을 때
		// interrupt counter expired interrupt 가 발생하도록 함
		//
		// register L_TCON 에 0x7 write함
		// local timer 0 의 interrupt type을 interval mode로 설정하고 interrupt, timer 를 start 시킴

		break;
		// break 수행

	case CLOCK_EVT_MODE_ONESHOT:  // CLOCK_EVT_MODE_ONESHOT: 3
	case CLOCK_EVT_MODE_UNUSED:   // CLOCK_EVT_MODE_UNUSED: 0
	case CLOCK_EVT_MODE_SHUTDOWN: // CLOCK_EVT_MODE_SHUTDOWN: 1
	case CLOCK_EVT_MODE_RESUME:   // CLOCK_EVT_MODE_RESUME: 4
		break;
		// break 수행
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

// ARM10C 20150509
static irqreturn_t exynos4_mct_tick_isr(int irq, void *dev_id)
{
	struct mct_clock_event_device *mevt = dev_id;
	struct clock_event_device *evt = &mevt->evt;

	exynos4_mct_tick_clear(mevt);

	evt->event_handler(evt);

	return IRQ_HANDLED;
}

// ARM10C 20150404
// &mevt->evt: [pcp0] &(&percpu_mct_tick)->evt
static int exynos4_local_timer_setup(struct clock_event_device *evt)
{
	struct mct_clock_event_device *mevt;

	// smp_processor_id(): 0
	unsigned int cpu = smp_processor_id();
	// cpu: 0

	// evt: [pcp0] &(&percpu_mct_tick)->evt
	// container_of([pcp0] &(&percpu_mct_tick)->evt, struct mct_clock_event_device, evt): [pcp0] &percpu_mct_tick
	mevt = container_of(evt, struct mct_clock_event_device, evt);
	// mevt: [pcp0] &percpu_mct_tick

	// mevt->base: [pcp0] (&percpu_mct_tick)->base,
	// cpu: 0, EXYNOS4_MCT_L_BASE(0): 0x300
	mevt->base = EXYNOS4_MCT_L_BASE(cpu);
	// mevt->base: [pcp0] (&percpu_mct_tick)->base: 0x300

	// mevt->name: [pcp0] (&percpu_mct_tick)->name, cpu: 0
	sprintf(mevt->name, "mct_tick%d", cpu);
	// mevt->name: [pcp0] (&percpu_mct_tick)->name: "mct_tick0"

	// evt->name: [pcp0] (&(&percpu_mct_tick)->evt)->name,
	// mevt->name: [pcp0] (&percpu_mct_tick)->name: "mct_tick0"
	evt->name = mevt->name;
	// evt->name: [pcp0] (&(&percpu_mct_tick)->evt)->name: "mct_tick0"

	// evt->cpumask: [pcp0] (&(&percpu_mct_tick)->evt)->cpumask,
	// cpu: 0, cpumask_of(0): &cpu_bit_bitmap[1][0]
	evt->cpumask = cpumask_of(cpu);
	// evt->cpumask: [pcp0] (&(&percpu_mct_tick)->evt)->cpumask: &cpu_bit_bitmap[1][0]

	// evt->set_next_event: [pcp0] (&(&percpu_mct_tick)->evt)->set_next_event
	evt->set_next_event = exynos4_tick_set_next_event;
	// evt->set_next_event: [pcp0] (&(&percpu_mct_tick)->evt)->set_next_event: exynos4_tick_set_next_event

	// evt->set_mode: [pcp0] (&(&percpu_mct_tick)->evt)->set_mode
	evt->set_mode = exynos4_tick_set_mode;
	// evt->set_mode: [pcp0] (&(&percpu_mct_tick)->evt)->set_mode: exynos4_tick_set_mode

	// evt->features: [pcp0] (&(&percpu_mct_tick)->evt)->features,
	// CLOCK_EVT_FEAT_PERIODIC: 0x000001, CLOCK_EVT_FEAT_ONESHOT: 0x000002
	evt->features = CLOCK_EVT_FEAT_PERIODIC | CLOCK_EVT_FEAT_ONESHOT;
	// evt->features: [pcp0] (&(&percpu_mct_tick)->evt)->features: 0x3

	// evt->rating: [pcp0] (&(&percpu_mct_tick)->evt)->rating
	evt->rating = 450;
	// evt->rating: [pcp0] (&(&percpu_mct_tick)->evt)->rating: 450

	// evt: [pcp0] &(&percpu_mct_tick)->evt, clk_rate: 24000000, TICK_BASE_CNT: 1
	clockevents_config_and_register(evt, clk_rate / (TICK_BASE_CNT + 1),
					0xf, 0x7fffffff);

	// clockevents_config_and_register에서 한일:
	// [pcp0] (&(&percpu_mct_tick)->evt)->min_delta_ticks: 0xf
	// [pcp0] (&(&percpu_mct_tick)->evt)->max_delta_ticks: 0x7fffffff
	// [pcp0] (&(&percpu_mct_tick)->evt)->mult: 0x3126E98
	// [pcp0] (&(&percpu_mct_tick)->evt)->shift: 32
	// [pcp0] (&(&percpu_mct_tick)->evt)->min_delta_ns: 0x4E2
	// [pcp0] (&(&percpu_mct_tick)->evt)->max_delta_ns: 0x29AAAAA444
	// [pcp0] (&(&percpu_mct_tick)->evt)->next_event.tv64: 0x7FFFFFFFFFFFFFFF
	// [pcp0] (&(&percpu_mct_tick)->evt)->event_handler: tick_handle_periodic
	// [pcp0] (&(&percpu_mct_tick)->evt)->mode: 2
	//
	// [pcp0] (&tick_cpu_device)->mode: 0
	// [pcp0] (&tick_cpu_device)->evtdev: [pcp0] &(&percpu_mct_tick)->evt
	//
	// [pcp0] (&tick_cpu_sched)->check_clocks: 1
	//
	// list clockevent_devices에 [pcp0] (&(&percpu_mct_tick)->evt)->list를 추가함
	//
	// tick_do_timer_cpu: 0
	// tick_next_period.tv64: 0
	// tick_period.tv64: 10000000
	//
	// timer control register L0_TCON 값을 읽어 timer start, timer interrupt 설정을
	// 동작하지 않도록 변경함
	// L0_TCON 값이 0 으로 가정하였으므로 timer는 동작하지 않은 상태임
	//
	// register L_ICNTB 에 0x8001D4C0 write함
	// local timer 0 의 interrupt count buffer 값을 120000 (0x1D4C0) write 하고
	// interrupt manual update를 enable 시킴
	//
	// register L_INT_ENB 에 0x1 write함
	// local timer 0 의 ICNTEIE 값을 0x1을 write 하여 L0_INTCNT 값이 0 이 되었을 때
	// interrupt counter expired interrupt 가 발생하도록 함
	//
	// register L_TCON 에 0x7 write함
	// local timer 0 의 interrupt type을 interval mode로 설정하고 interrupt, timer 를 start 시킴

	// TICK_BASE_CNT: 1 mevt->base: [pcp0] (&percpu_mct_tick)->base: 0x300, MCT_L_TCNTB_OFFSET: 0x00
	exynos4_mct_write(TICK_BASE_CNT, mevt->base + MCT_L_TCNTB_OFFSET);

	// exynos4_mct_write에서 한일:
	// register L_TCNTB 에 0x1 write함
	// local timer 0 의 tick count 값을 1로 write 함

	// mct_int_type: 0, MCT_INT_SPI: 0
	if (mct_int_type == MCT_INT_SPI) {
		// evt->irq: [pcp0] (&(&percpu_mct_tick)->evt)->irq,
		// MCT_L0_IRQ: 4, cpu: 0, mct_irqs[4]: 152
		evt->irq = mct_irqs[MCT_L0_IRQ + cpu];
		// evt->irq: [pcp0] (&(&percpu_mct_tick)->evt)->irq: 152

		// evt->irq: [pcp0] (&(&percpu_mct_tick)->evt)->irq: 152, IRQF_TIMER: 0x14200, IRQF_NOBALANCING: 0x00000800,
		// evt->name: [pcp0] (&(&percpu_mct_tick)->evt)->name: "mct_tick0", mevt: [pcp0] &percpu_mct_tick
		// request_irq(152, exynos4_mct_tick_isr, 0x14a00, "mct_tick0", [pcp0] &percpu_mct_tick): 0
		if (request_irq(evt->irq, exynos4_mct_tick_isr,
				IRQF_TIMER | IRQF_NOBALANCING,
				evt->name, mevt)) {
			pr_err("exynos-mct: cannot register IRQ %d\n",
				evt->irq);
			return -EIO;
		}

		// request_irq에서 한일:
		// struct irqaction의 메모리 공간을 할당 받고 맴버값 세팅
		//
		// (kmem_cache#30-oX)->handler: exynos4_mct_tick_isr
		// (kmem_cache#30-oX)->thread_fn: NULL
		// (kmem_cache#30-oX)->flags: 0x14A00
		// (kmem_cache#30-oX)->name: "mct_tick0"
		// (kmem_cache#30-oX)->dev_id: [pcp0] &percpu_mct_tick
		// (kmem_cache#30-oX)->irq: 152
		// (kmem_cache#30-oX)->dir: NULL
		//
		// irq_desc 152의 맴버값을 초기화
		// &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->lock을 사용한 spinlock 초기화
		// &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->task_list를 사용한 list 초기화
		// (kmem_cache#28-oX (irq 152))->istate: 0
		// (kmem_cache#28-oX (irq 152))->depth: 1
		// (kmem_cache#28-oX (irq 152))->action: kmem_cache#30-oX (irqaction)
		// (kmem_cache#28-oX (irq 152))->status_use_accessors: 0x3400
		// (kmem_cache#28-oX (irq 152))->irq_count: 0
		// (kmem_cache#28-oX (irq 152))->irqs_unhandled: 0
		// (&(kmem_cache#28-oX (irq 152))->irq_data)->state_use_accessors: 0x11400
	} else {
		enable_percpu_irq(mct_irqs[MCT_L0_IRQ], 0);
	}

	return 0;
	// return 0
}

static void exynos4_local_timer_stop(struct clock_event_device *evt)
{
	evt->set_mode(CLOCK_EVT_MODE_UNUSED, evt);
	if (mct_int_type == MCT_INT_SPI)
		free_irq(evt->irq, this_cpu_ptr(&percpu_mct_tick));
	else
		disable_percpu_irq(mct_irqs[MCT_L0_IRQ]);
}

// ARM10C 20150404
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

// ARM10C 20150404
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
		// irq_set_affinity(152, &cpu_bit_bitmap[1][0]): 0
		irq_set_affinity(mct_irqs[MCT_L0_IRQ], cpumask_of(0));

		// irq_set_affinity에서 한일:
		//
		// Interrupt pending register인 GICD_ITARGETSR38 값을 읽고
		// 그 값과 mask 값인 cpu_bit_bitmap[1][0] 을 or 연산한 값을 GICD_ITARGETSR38에
		// 다시 write함
		//
		// GICD_ITARGETSR38 값을 모르기 때문에 0x00000000 로
		// 읽히는 것으로 가정하고 GICD_ITARGETSR38에 0x00000001를 write 함
		// CPU interface 0에 interrupt가 발생을 나타냄
		//
		// (&(kmem_cache#28-oX (irq 152))->irq_data)->affinity->bits[0]: 1
		// (&(kmem_cache#28-oX (irq 152))->irq_data)->state_use_accessors: 0x11000
	}

	// register_cpu_notifier(&exynos4_mct_cpu_nb): 0
	err = register_cpu_notifier(&exynos4_mct_cpu_nb);
	// err: 0

	// register_cpu_notifier 에서 한일:
	// (&cpu_chain)->head: &exynos4_mct_cpu_nb 포인터 대입
	// (&exynos4_mct_cpu_nb)->next은 (&hrtimers_nb)->next로 대입

	// err: 0
	if (err)
		goto out_irq;

	/* Immediately configure the timer on the boot CPU */
	// &mevt->evt: [pcp0] &(&percpu_mct_tick)->evt
	// exynos4_local_timer_setup([pcp0] &(&percpu_mct_tick)->evt): 0
	exynos4_local_timer_setup(&mevt->evt);

	// exynos4_local_timer_setup에서 한일:
	//
	// [pcp0] (&percpu_mct_tick)->base: 0x300
	// [pcp0] (&percpu_mct_tick)->name: "mct_tick0"
	// [pcp0] (&(&percpu_mct_tick)->evt)->name: "mct_tick0"
	// [pcp0] (&(&percpu_mct_tick)->evt)->cpumask: &cpu_bit_bitmap[1][0]
	// [pcp0] (&(&percpu_mct_tick)->evt)->set_next_event: exynos4_tick_set_next_event
	// [pcp0] (&(&percpu_mct_tick)->evt)->set_mode: exynos4_tick_set_mode
	// [pcp0] (&(&percpu_mct_tick)->evt)->features: 0x3
	// [pcp0] (&(&percpu_mct_tick)->evt)->rating: 450
	// [pcp0] (&(&percpu_mct_tick)->evt)->min_delta_ticks: 0xf
	// [pcp0] (&(&percpu_mct_tick)->evt)->max_delta_ticks: 0x7fffffff
	// [pcp0] (&(&percpu_mct_tick)->evt)->mult: 0x3126E98
	// [pcp0] (&(&percpu_mct_tick)->evt)->shift: 32
	// [pcp0] (&(&percpu_mct_tick)->evt)->min_delta_ns: 0x4E2
	// [pcp0] (&(&percpu_mct_tick)->evt)->max_delta_ns: 0x29AAAAA444
	// [pcp0] (&(&percpu_mct_tick)->evt)->next_event.tv64: 0x7FFFFFFFFFFFFFFF
	// [pcp0] (&(&percpu_mct_tick)->evt)->event_handler: tick_handle_periodic
	// [pcp0] (&(&percpu_mct_tick)->evt)->mode: 2
	// [pcp0] (&(&percpu_mct_tick)->evt)->irq: 152
	//
	// [pcp0] (&tick_cpu_device)->mode: 0
	// [pcp0] (&tick_cpu_device)->evtdev: [pcp0] &(&percpu_mct_tick)->evt
	//
	// [pcp0] (&tick_cpu_sched)->check_clocks: 1
	//
	// list clockevent_devices에 [pcp0] (&(&percpu_mct_tick)->evt)->list를 추가함
	//
	// tick_do_timer_cpu: 0
	// tick_next_period.tv64: 0
	// tick_period.tv64: 10000000
	//
	// timer control register L0_TCON 값을 읽어 timer start, timer interrupt 설정을
	// 동작하지 않도록 변경함
	// L0_TCON 값이 0 으로 가정하였으므로 timer는 동작하지 않은 상태임
	//
	// register L_ICNTB 에 0x8001D4C0 write함
	// local timer 0 의 interrupt count buffer 값을 120000 (0x1D4C0) write 하고
	// interrupt manual update를 enable 시킴
	//
	// register L_INT_ENB 에 0x1 write함
	// local timer 0 의 ICNTEIE 값을 0x1을 write 하여 L0_INTCNT 값이 0 이 되었을 때
	// interrupt counter expired interrupt 가 발생하도록 함
	//
	// register L_TCON 에 0x7 write함
	// local timer 0 의 interrupt type을 interval mode로 설정하고 interrupt, timer 를 start 시킴
	//
	// register L_TCNTB 에 0x1 write함
	// local timer 0 의 tick count 값을 1로 write 함
	//
	// struct irqaction의 메모리 공간을 할당 받고 맴버값 세팅
	// (kmem_cache#30-oX)->handler: exynos4_mct_tick_isr
	// (kmem_cache#30-oX)->thread_fn: NULL
	// (kmem_cache#30-oX)->flags: 0x14A00
	// (kmem_cache#30-oX)->name: "mct_tick0"
	// (kmem_cache#30-oX)->dev_id: [pcp0] &percpu_mct_tick
	// (kmem_cache#30-oX)->irq: 152
	// (kmem_cache#30-oX)->dir: NULL
	//
	// irq_desc 152의 맴버값을 초기화
	// &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->task_list를 사용한 list 초기화
	// (kmem_cache#28-oX (irq 152))->istate: 0
	// (kmem_cache#28-oX (irq 152))->depth: 1
	// (kmem_cache#28-oX (irq 152))->action: kmem_cache#30-oX (irqaction)
	// (kmem_cache#28-oX (irq 152))->status_use_accessors: 0x3400
	// (kmem_cache#28-oX (irq 152))->irq_count: 0
	// (kmem_cache#28-oX (irq 152))->irqs_unhandled: 0
	// (&(kmem_cache#28-oX (irq 152))->irq_data)->state_use_accessors: 0x11400

	return;
	// return 수행

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

	// exynos4_timer_resources에서 한일:
	//
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
	//
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
	//
	// clk_prepare_enable에서 한일:
	// mct clock의 상위 clock 들의 ops->prepare 함수들을 수행.
	// mct clock의 상위 clock 들의 ops->enable 함수들을 수행.
	// sck_cpll -- Group1_p -- mout_aclk66 -- dout_aclk66 -- mct
	// sck_ppll -|
	// sck_mpll -|
	//
	// sck_cpll, mout_aclk66, dout_aclk66 의 주석을 만들지 않았기 때문에
	// 분석내용을 skip 하도록함
	//
	// Interrupt pending register인 GICD_ITARGETSR38 값을 읽고
	// 그 값과 mask 값인 cpu_bit_bitmap[1][0] 을 or 연산한 값을 GICD_ITARGETSR38에
	// 다시 write함
	//
	// GICD_ITARGETSR38 값을 모르기 때문에 0x00000000 로
	// 읽히는 것으로 가정하고 GICD_ITARGETSR38에 0x00000001를 write 함
	// CPU interface 0에 interrupt가 발생을 나타냄
	//
	// (&(kmem_cache#28-oX (irq 152))->irq_data)->affinity->bits[0]: 1
	// (&(kmem_cache#28-oX (irq 152))->irq_data)->state_use_accessors: 0x11000
	//
	// register_cpu_notifier 에서 한일:
	// (&cpu_chain)->head: &exynos4_mct_cpu_nb 포인터 대입
	// (&exynos4_mct_cpu_nb)->next은 (&hrtimers_nb)->next로 대입
	//
	// [pcp0] (&percpu_mct_tick)->base: 0x300
	// [pcp0] (&percpu_mct_tick)->name: "mct_tick0"
	// [pcp0] (&(&percpu_mct_tick)->evt)->name: "mct_tick0"
	// [pcp0] (&(&percpu_mct_tick)->evt)->cpumask: &cpu_bit_bitmap[1][0]
	// [pcp0] (&(&percpu_mct_tick)->evt)->set_next_event: exynos4_tick_set_next_event
	// [pcp0] (&(&percpu_mct_tick)->evt)->set_mode: exynos4_tick_set_mode
	// [pcp0] (&(&percpu_mct_tick)->evt)->features: 0x3
	// [pcp0] (&(&percpu_mct_tick)->evt)->rating: 450
	// [pcp0] (&(&percpu_mct_tick)->evt)->min_delta_ticks: 0xf
	// [pcp0] (&(&percpu_mct_tick)->evt)->max_delta_ticks: 0x7fffffff
	// [pcp0] (&(&percpu_mct_tick)->evt)->mult: 0x3126E98
	// [pcp0] (&(&percpu_mct_tick)->evt)->shift: 32
	// [pcp0] (&(&percpu_mct_tick)->evt)->min_delta_ns: 0x4E2
	// [pcp0] (&(&percpu_mct_tick)->evt)->max_delta_ns: 0x29AAAAA444
	// [pcp0] (&(&percpu_mct_tick)->evt)->next_event.tv64: 0x7FFFFFFFFFFFFFFF
	// [pcp0] (&(&percpu_mct_tick)->evt)->event_handler: tick_handle_periodic
	// [pcp0] (&(&percpu_mct_tick)->evt)->mode: 2
	// [pcp0] (&(&percpu_mct_tick)->evt)->irq: 152
	//
	// [pcp0] (&tick_cpu_device)->mode: 0
	// [pcp0] (&tick_cpu_device)->evtdev: [pcp0] &(&percpu_mct_tick)->evt
	//
	// [pcp0] (&tick_cpu_sched)->check_clocks: 1
	//
	// list clockevent_devices에 [pcp0] (&(&percpu_mct_tick)->evt)->list를 추가함
	//
	// tick_do_timer_cpu: 0
	// tick_next_period.tv64: 0
	// tick_period.tv64: 10000000
	//
	// timer control register L0_TCON 값을 읽어 timer start, timer interrupt 설정을
	// 동작하지 않도록 변경함
	// L0_TCON 값이 0 으로 가정하였으므로 timer는 동작하지 않은 상태임
	//
	// register L_ICNTB 에 0x8001D4C0 write함
	// local timer 0 의 interrupt count buffer 값을 120000 (0x1D4C0) write 하고
	// interrupt manual update를 enable 시킴
	//
	// register L_INT_ENB 에 0x1 write함
	// local timer 0 의 ICNTEIE 값을 0x1을 write 하여 L0_INTCNT 값이 0 이 되었을 때
	// interrupt counter expired interrupt 가 발생하도록 함
	//
	// register L_TCON 에 0x7 write함
	// local timer 0 의 interrupt type을 interval mode로 설정하고 interrupt, timer 를 start 시킴
	//
	// register L_TCNTB 에 0x1 write함
	// local timer 0 의 tick count 값을 1로 write 함
	//
	// struct irqaction의 메모리 공간을 할당 받고 맴버값 세팅
	// (kmem_cache#30-oX)->handler: exynos4_mct_tick_isr
	// (kmem_cache#30-oX)->thread_fn: NULL
	// (kmem_cache#30-oX)->flags: 0x14A00
	// (kmem_cache#30-oX)->name: "mct_tick0"
	// (kmem_cache#30-oX)->dev_id: [pcp0] &percpu_mct_tick
	// (kmem_cache#30-oX)->irq: 152
	// (kmem_cache#30-oX)->dir: NULL
	//
	// irq_desc 152의 맴버값을 초기화
	// &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->task_list를 사용한 list 초기화
	// (kmem_cache#28-oX (irq 152))->istate: 0
	// (kmem_cache#28-oX (irq 152))->depth: 1
	// (kmem_cache#28-oX (irq 152))->action: kmem_cache#30-oX (irqaction)
	// (kmem_cache#28-oX (irq 152))->status_use_accessors: 0x3400
	// (kmem_cache#28-oX (irq 152))->irq_count: 0
	// (kmem_cache#28-oX (irq 152))->irqs_unhandled: 0
	// (&(kmem_cache#28-oX (irq 152))->irq_data)->state_use_accessors: 0x11400

	exynos4_clocksource_init();

	// exynos4_clocksource_init에서 한일:
	// register G_CNT_L 에 0x0 write함
	// FRC count buffer 의 tick count 값을 0로 write 함
	//
	// register G_CNT_WSTAT 에 0x1 write함
	// G_CNT_L write status 의  값을 1로 write 함
	//
	// register G_CNT_U 에 0x0 write함
	// FRC count buffer 의 tick count 값을 0로 write 함
	//
	// register G_CNT_WSTAT 에 0x1 write함
	// G_CNT_U write status 의  값을 1로 write 함
	//
	// register G_TCON 에 0x100 write함
	// global timer enable 의 값을 1로 write 함
	//
	// (&mct_frc)->mult: 0xA6AAAAAA
	// (&mct_frc)->shift: 26
	// (&mct_frc)->maxadj: 0x12555555
	// (&mct_frc)->max_idle_ns: 0x103955554C
	// (&mct_frc)->flags: 0x21
	//
	// list clocksource_list의 next에 &(&mct_frc)->list를 추가함

	exynos4_clockevent_init();

	// exynos4_clockevent_init에서 한일:
	// mct_comp_device.cpumask: &cpu_bit_bitmap[1][0
	//
	// (&mct_comp_device)->min_delta_ticks: 0xf
	// (&mct_comp_device)->max_delta_ticks: 0xffffffff
	// (&mct_comp_device)->mult: 0x3126E98
	// (&mct_comp_device)->shift: 31
	// (&mct_comp_device)->min_delta_ns: 0x3E8
	// (&mct_comp_device)->max_delta_ns: 0x29AAAAA46E
	// (&mct_comp_device)->mode: 1
	// (&mct_comp_device)->next_event.tv64: 0x7FFFFFFFFFFFFFFF
	//
	// list clockevent_devices에 (&mct_comp_device)->list를 추가함
	//
	// register G_TCON 에 0x100 write함
	// global timer enable 의 값을 1로 write 함
	//
	// register G_INT_ENB 에 0x0 write함
	// global timer interrupt enable 의 값을 0로 write 함
	//
	// comparator 0의 auto increment0, comp0 enable,comp0 interrupt enable 값을
	// 0으로 clear 하여 comparator 0를 동작하지 않도록 함
	//
	// tick_broadcast_device.evtdev: &mct_comp_device
	// [pcp0] &(&tick_cpu_sched)->check_clocks: 0xf
	//
	// &(&(kmem_cache#28-oX (irq 347))->wait_for_threads)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#28-oX (irq 347))->wait_for_threads)->task_list를 사용한 list 초기화
	// &(kmem_cache#28-oX (irq 347))->istate: 0
	// (kmem_cache#28-oX (irq 347))->depth: 0
	// (kmem_cache#28-oX (irq 347))->action: &mct_comp_event_irq
	// (kmem_cache#28-oX (irq 347))->irq_count: 0
	// (kmem_cache#28-oX (irq 347))->irqs_unhandled: 0
	//
	// (&(kmem_cache#28-oX (irq 347))->irq_data)->state_use_accessors: 0x10000
	// (&(kmem_cache#28-oX (irq 347))->irq_data)->affinity->bits[0]: 1
	//
	// register IESR5의 MCT_G0 bit 를 1 로 write 하여 MCT_G0 의 interrupt 를 enable 시킴
	//
	// GICD_ITARGETSR46 값을 모르기 때문에 0x00000000 로
	// 읽히는 것으로 가정하고 GICD_ITARGETSR46에 0x1000000를 write 함
	// CPU interface 0에 interrupt가 발생을 나타냄
	//
	// struct irqaction 멤버 값 세팅
	// (&mct_comp_event_irq)->irq: 347
	// (&mct_comp_event_irq)->dir: NULL
}


// ARM10C 20150307
// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소
static void __init mct_init_spi(struct device_node *np)
{
	// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소, MCT_INT_SPI: 0
	// mct_init_dt(devtree에서 allnext로 순회 하면서 찾은 mct node의 주소, 0)
	return mct_init_dt(np, MCT_INT_SPI);

	// mct_init_dt에서 한일:
	// mct_int_type: 0
	//
	// devtree의 mct node의 interrupt의 property의 값을 dtb에  분석하여 oirq 값을 가져옴
	//
	// (&oirq)->np: combiner node의 주소
	// (&oirq)->args_count: 2
	// (&oirq)->args[0]: 23
	// (&oirq)->args[1]: 3
	//
	// oirq 값을 사용하여 combiner domain에서 virq 값을 찾음
	// virq: 347
	//
	// mct_irqs[4]: 152
	// mct_irqs[5]: 153
	// mct_irqs[6]: 154
	// mct_irqs[7]: 155
	//
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
	//
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
	//
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
	//
	// clk_prepare_enable에서 한일:
	// mct clock의 상위 clock 들의 ops->prepare 함수들을 수행.
	// mct clock의 상위 clock 들의 ops->enable 함수들을 수행.
	// sck_cpll -- Group1_p -- mout_aclk66 -- dout_aclk66 -- mct
	// sck_ppll -|
	// sck_mpll -|
	//
	// sck_cpll, mout_aclk66, dout_aclk66 의 주석을 만들지 않았기 때문에
	// 분석내용을 skip 하도록함
	//
	// Interrupt pending register인 GICD_ITARGETSR38 값을 읽고
	// 그 값과 mask 값인 cpu_bit_bitmap[1][0] 을 or 연산한 값을 GICD_ITARGETSR38에
	// 다시 write함
	//
	// GICD_ITARGETSR38 값을 모르기 때문에 0x00000000 로
	// 읽히는 것으로 가정하고 GICD_ITARGETSR38에 0x00000001를 write 함
	// CPU interface 0에 interrupt가 발생을 나타냄
	//
	// (&(kmem_cache#28-oX (irq 152))->irq_data)->affinity->bits[0]: 1
	// (&(kmem_cache#28-oX (irq 152))->irq_data)->state_use_accessors: 0x11000
	//
	// register_cpu_notifier 에서 한일:
	// (&cpu_chain)->head: &exynos4_mct_cpu_nb 포인터 대입
	// (&exynos4_mct_cpu_nb)->next은 (&hrtimers_nb)->next로 대입
	//
	// [pcp0] (&percpu_mct_tick)->base: 0x300
	// [pcp0] (&percpu_mct_tick)->name: "mct_tick0"
	// [pcp0] (&(&percpu_mct_tick)->evt)->name: "mct_tick0"
	// [pcp0] (&(&percpu_mct_tick)->evt)->cpumask: &cpu_bit_bitmap[1][0]
	// [pcp0] (&(&percpu_mct_tick)->evt)->set_next_event: exynos4_tick_set_next_event
	// [pcp0] (&(&percpu_mct_tick)->evt)->set_mode: exynos4_tick_set_mode
	// [pcp0] (&(&percpu_mct_tick)->evt)->features: 0x3
	// [pcp0] (&(&percpu_mct_tick)->evt)->rating: 450
	// [pcp0] (&(&percpu_mct_tick)->evt)->min_delta_ticks: 0xf
	// [pcp0] (&(&percpu_mct_tick)->evt)->max_delta_ticks: 0x7fffffff
	// [pcp0] (&(&percpu_mct_tick)->evt)->mult: 0x3126E98
	// [pcp0] (&(&percpu_mct_tick)->evt)->shift: 32
	// [pcp0] (&(&percpu_mct_tick)->evt)->min_delta_ns: 0x4E2
	// [pcp0] (&(&percpu_mct_tick)->evt)->max_delta_ns: 0x29AAAAA444
	// [pcp0] (&(&percpu_mct_tick)->evt)->next_event.tv64: 0x7FFFFFFFFFFFFFFF
	// [pcp0] (&(&percpu_mct_tick)->evt)->event_handler: tick_handle_periodic
	// [pcp0] (&(&percpu_mct_tick)->evt)->mode: 2
	// [pcp0] (&(&percpu_mct_tick)->evt)->irq: 152
	//
	// [pcp0] (&tick_cpu_device)->mode: 0
	// [pcp0] (&tick_cpu_device)->evtdev: [pcp0] &(&percpu_mct_tick)->evt
	//
	// [pcp0] (&tick_cpu_sched)->check_clocks: 1
	//
	// list clockevent_devices에 [pcp0] (&(&percpu_mct_tick)->evt)->list를 추가함
	//
	// tick_do_timer_cpu: 0
	// tick_next_period.tv64: 0
	// tick_period.tv64: 10000000
	//
	// timer control register L0_TCON 값을 읽어 timer start, timer interrupt 설정을
	// 동작하지 않도록 변경함
	// L0_TCON 값이 0 으로 가정하였으므로 timer는 동작하지 않은 상태임
	//
	// register L_ICNTB 에 0x8001D4C0 write함
	// local timer 0 의 interrupt count buffer 값을 120000 (0x1D4C0) write 하고
	// interrupt manual update를 enable 시킴
	//
	// register L_INT_ENB 에 0x1 write함
	// local timer 0 의 ICNTEIE 값을 0x1을 write 하여 L0_INTCNT 값이 0 이 되었을 때
	// interrupt counter expired interrupt 가 발생하도록 함
	//
	// register L_TCON 에 0x7 write함
	// local timer 0 의 interrupt type을 interval mode로 설정하고 interrupt, timer 를 start 시킴
	//
	// register L_TCNTB 에 0x1 write함
	// local timer 0 의 tick count 값을 1로 write 함
	//
	// struct irqaction의 메모리 공간을 할당 받고 맴버값 세팅
	// (kmem_cache#30-oX)->handler: exynos4_mct_tick_isr
	// (kmem_cache#30-oX)->thread_fn: NULL
	// (kmem_cache#30-oX)->flags: 0x14A00
	// (kmem_cache#30-oX)->name: "mct_tick0"
	// (kmem_cache#30-oX)->dev_id: [pcp0] &percpu_mct_tick
	// (kmem_cache#30-oX)->irq: 152
	// (kmem_cache#30-oX)->dir: NULL
	//
	// irq_desc 152의 맴버값을 초기화
	// &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->task_list를 사용한 list 초기화
	// (kmem_cache#28-oX (irq 152))->istate: 0
	// (kmem_cache#28-oX (irq 152))->depth: 1
	// (kmem_cache#28-oX (irq 152))->action: kmem_cache#30-oX (irqaction)
	// (kmem_cache#28-oX (irq 152))->status_use_accessors: 0x3400
	// (kmem_cache#28-oX (irq 152))->irq_count: 0
	// (kmem_cache#28-oX (irq 152))->irqs_unhandled: 0
	// (&(kmem_cache#28-oX (irq 152))->irq_data)->state_use_accessors: 0x11400
	//
	// register G_CNT_L 에 0x0 write함
	// FRC count buffer 의 tick count 값을 0로 write 함
	//
	// register G_CNT_WSTAT 에 0x1 write함
	// G_CNT_L write status 의  값을 1로 write 함
	//
	// register G_CNT_U 에 0x0 write함
	// FRC count buffer 의 tick count 값을 0로 write 함
	//
	// register G_CNT_WSTAT 에 0x1 write함
	// G_CNT_U write status 의  값을 1로 write 함
	//
	// register G_TCON 에 0x100 write함
	// global timer enable 의 값을 1로 write 함
	//
	// (&mct_frc)->mult: 0xA6AAAAAA
	// (&mct_frc)->shift: 26
	// (&mct_frc)->maxadj: 0x12555555
	// (&mct_frc)->max_idle_ns: 0x103955554C
	// (&mct_frc)->flags: 0x21
	//
	// list clocksource_list의 next에 &(&mct_frc)->list를 추가함
	//
	// mct_comp_device.cpumask: &cpu_bit_bitmap[1][0
	//
	// (&mct_comp_device)->min_delta_ticks: 0xf
	// (&mct_comp_device)->max_delta_ticks: 0xffffffff
	// (&mct_comp_device)->mult: 0x3126E98
	// (&mct_comp_device)->shift: 31
	// (&mct_comp_device)->min_delta_ns: 0x3E8
	// (&mct_comp_device)->max_delta_ns: 0x29AAAAA46E
	// (&mct_comp_device)->mode: 1
	// (&mct_comp_device)->next_event.tv64: 0x7FFFFFFFFFFFFFFF
	//
	// list clockevent_devices에 (&mct_comp_device)->list를 추가함
	//
	// register G_TCON 에 0x100 write함
	// global timer enable 의 값을 1로 write 함
	//
	// register G_INT_ENB 에 0x0 write함
	// global timer interrupt enable 의 값을 0로 write 함
	//
	// comparator 0의 auto increment0, comp0 enable,comp0 interrupt enable 값을
	// 0으로 clear 하여 comparator 0를 동작하지 않도록 함
	//
	// tick_broadcast_device.evtdev: &mct_comp_device
	// [pcp0] &(&tick_cpu_sched)->check_clocks: 0xf
	//
	// &(&(kmem_cache#28-oX (irq 347))->wait_for_threads)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#28-oX (irq 347))->wait_for_threads)->task_list를 사용한 list 초기화
	// &(kmem_cache#28-oX (irq 347))->istate: 0
	// (kmem_cache#28-oX (irq 347))->depth: 0
	// (kmem_cache#28-oX (irq 347))->action: &mct_comp_event_irq
	// (kmem_cache#28-oX (irq 347))->irq_count: 0
	// (kmem_cache#28-oX (irq 347))->irqs_unhandled: 0
	//
	// (&(kmem_cache#28-oX (irq 347))->irq_data)->state_use_accessors: 0x10000
	// (&(kmem_cache#28-oX (irq 347))->irq_data)->affinity->bits[0]: 1
	//
	// register IESR5의 MCT_G0 bit 를 1 로 write 하여 MCT_G0 의 interrupt 를 enable 시킴
	//
	// GICD_ITARGETSR46 값을 모르기 때문에 0x00000000 로
	// 읽히는 것으로 가정하고 GICD_ITARGETSR46에 0x1000000를 write 함
	// CPU interface 0에 interrupt가 발생을 나타냄
	//
	// struct irqaction 멤버 값 세팅
	// (&mct_comp_event_irq)->irq: 347
	// (&mct_comp_event_irq)->dir: NULL
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
