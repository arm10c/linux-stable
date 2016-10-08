/*
 * sched_clock.c: support for extending counters to full 64-bit ns counter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/clocksource.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/syscore_ops.h>
#include <linux/hrtimer.h>
#include <linux/sched_clock.h>
#include <linux/seqlock.h>
#include <linux/bitops.h>

// ARM10C 20140913
// ARM10C 20150530
// ARM10C 20161008
struct clock_data {
	ktime_t wrap_kt;
	u64 epoch_ns;
	u64 epoch_cyc;
	seqcount_t seq;
	unsigned long rate;
	u32 mult;
	u32 shift;
	bool suspended;
};

// ARM10C 20150530
static struct hrtimer sched_clock_timer;
// ARM10C 20150530
static int irqtime = -1;

core_param(irqtime, irqtime, int, 0400);

// ARM10C 20140913
// ARM10C 20150530
// ARM10C 20161008
// NSEC_PER_SEC: 1000000000L, HZ: 100
static struct clock_data cd = {
	.mult	= NSEC_PER_SEC / HZ,
};

// ARM10C 20140913
// ARM10C 20150530
static u64 __read_mostly sched_clock_mask;

// ARM10C 20140913
// ARM10C 20150530
// ARM10C 20161008
static u64 notrace jiffy_sched_clock_read(void)
{
	/*
	 * We don't need to use get_jiffies_64 on 32-bit arches here
	 * because we register with BITS_PER_LONG
	 */
	// jiffies: -30000 (0xFFFFFFFFFFFF8AD0), INITIAL_JIFFIES: -30000 (0xFFFF8AD0)
	return (u64)(jiffies - INITIAL_JIFFIES);
	// return 0
}

static u32 __read_mostly (*read_sched_clock_32)(void);

static u64 notrace read_sched_clock_32_wrapper(void)
{
	return read_sched_clock_32();
}

// ARM10C 20140913
// ARM10C 20150530
// ARM10C 20161008
static u64 __read_mostly (*read_sched_clock)(void) = jiffy_sched_clock_read;

// ARM10C 20140913
// cyc: 0, cd.mult: 10000000, cd.shift: 0
// ARM10C 20150530
// 1, cd.mult: 0x98968000 cd.shift: 8
// ARM10C 20150530
// 0, cd.mult: 0x98968000 cd.shift: 8
static inline u64 notrace cyc_to_ns(u64 cyc, u32 mult, u32 shift)
{
	// cyc: 0, mult: 10000000, shift: 0
	// cyc: 1, mult: 0x98968000, shift: 8
	// cyc: 0, mult: 0x98968000, shift: 8
	return (cyc * mult) >> shift;
	// return 0
	// return 0x989680
	// return 0
}

// ARM10C 20140913
// ARM10C 20161008
unsigned long long notrace sched_clock(void)
{
	u64 epoch_ns;
	u64 epoch_cyc;
	u64 cyc;
	unsigned long seq;

	// cd.suspended: 0
	if (cd.suspended)
		return cd.epoch_ns;

	do {
		// raw_read_seqcount_begin(&cd.seq): 0
		seq = raw_read_seqcount_begin(&cd.seq);
		// seq: 0

		// cd.epoch_cyc: 0
		epoch_cyc = cd.epoch_cyc;
		// epoch_cyc: 0

		// cd.epoch_ns: 0
		epoch_ns = cd.epoch_ns;
		// epoch_ns: 0

		// seq: 0, read_seqcount_retry(&cd.seq, 0): 0
	} while (read_seqcount_retry(&cd.seq, seq));

	// read_sched_clock(): 0
	cyc = read_sched_clock();
	// cyc: 0

	// cyc: 0, epoch_cyc: 0, sched_clock_mask: 0
	cyc = (cyc - epoch_cyc) & sched_clock_mask;
	// cyc: 0

	// epoch_ns: 0, cyc: 0, cd.mult: 10000000, cd.shift: 0
	// cyc_to_ns(0, 10000000, 0): 0
	return epoch_ns + cyc_to_ns(cyc, cd.mult, cd.shift);
	// return 0
}

/*
 * Atomically update the sched_clock epoch.
 */
// ARM10C 20150530
// ARM10C 20150530
static void notrace update_sched_clock(void)
{
	unsigned long flags;
	u64 cyc;
	u64 ns;

	// read_sched_clock(): 0
	// read_sched_clock(): 0
	cyc = read_sched_clock();
	// cyc: 0
	// cyc: 0

	// epoch_ns: 0, cyc: 0, cd.epoch_cyc: 0, 0xFFFFFFFF, cd.mult: 0x98968000, cd.shift: 8
	// cyc_to_ns(0, 0x98968000, 8): 0
	// epoch_ns: 0, cyc: 0, cd.epoch_cyc: 0, 0xFFFFFFFF, cd.mult: 0x98968000, cd.shift: 8
	// cyc_to_ns(0, 0x98968000, 8): 0
	ns = cd.epoch_ns +
		cyc_to_ns((cyc - cd.epoch_cyc) & sched_clock_mask,
			  cd.mult, cd.shift);
	// ns: 0
	// ns: 0

	raw_local_irq_save(flags);

	// raw_local_irq_save에서 한일:
	// flags에 cpsr을 저장하고 interrupt disable 함

	// raw_local_irq_save에서 한일:
	// flags에 cpsr을 저장하고 interrupt disable 함

	raw_write_seqcount_begin(&cd.seq);

	// raw_write_seqcount_begin에서 한일:
	// s->sequence: (&cd.seq)->sequence: 1

	// raw_write_seqcount_begin에서 한일:
	// s->sequence: (&cd.seq)->sequence: 3

	// ns: 0
	// ns: 0
	cd.epoch_ns = ns;
	// cd.epoch_ns: 0
	// cd.epoch_ns: 0

	// cyc: 0
	// cyc: 0
	cd.epoch_cyc = cyc;
	// cd.epoch_cyc: 0
	// cd.epoch_cyc: 0

	raw_write_seqcount_end(&cd.seq);

	// raw_write_seqcount_end에서 한일:
	// s->sequence: (&cd.seq)->sequence: 2

	// raw_write_seqcount_end에서 한일:
	// s->sequence: (&cd.seq)->sequence: 4

	raw_local_irq_restore(flags);

	// raw_local_irq_restore에서 한일:
	// flags에 저장된 cpsr을 복원하고 interrupt enable 함

	// raw_local_irq_restore에서 한일:
	// flags에 저장된 cpsr을 복원하고 interrupt enable 함
}

// ARM10C 20150530
static enum hrtimer_restart sched_clock_poll(struct hrtimer *hrt)
{
	update_sched_clock();
	hrtimer_forward_now(hrt, cd.wrap_kt);
	return HRTIMER_RESTART;
}

// ARM10C 20150530
// jiffy_sched_clock_read, BITS_PER_LONG: 32, HZ: 100
void __init sched_clock_register(u64 (*read)(void), int bits,
				 unsigned long rate)
{
	unsigned long r;
	u64 res, wrap;
	char r_unit;

	// cd.rate: 0, rate: 100
	if (cd.rate > rate)
		return;

	// irqs_disabled(): 1
	WARN_ON(!irqs_disabled());

	// read: jiffy_sched_clock_read
	read_sched_clock = read;
	// read_sched_clock: jiffy_sched_clock_read

	// bits: 32, CLOCKSOURCE_MASK(32): 0xFFFFFFFF
	sched_clock_mask = CLOCKSOURCE_MASK(bits);
	// sched_clock_mask: 0xFFFFFFFF

	// cd.rate: 0, rate: 100
	cd.rate = rate;
	// cd.rate: 100

	/* calculate the mult/shift to convert counter ticks to ns. */
	// rate: 100, NSEC_PER_SEC: 1000000000L
	clocks_calc_mult_shift(&cd.mult, &cd.shift, rate, NSEC_PER_SEC, 3600);

	// clocks_calc_mult_shift에서 한일:
	// (&cd)->mult: 0x98968000
	// (&cd)->shift: 8

	// rate: 100
	r = rate;
	// r: 100

	// r: 100
	if (r >= 4000000) {
		r /= 1000000;
		r_unit = 'M';
	} else if (r >= 1000) {
		r /= 1000;
		r_unit = 'k';
	} else
		r_unit = ' ';
		// r_unit: ' '

	/* calculate how many ns until we wrap */
	// cd.mult: 0x98968000 cd.shift: 8, sched_clock_mask: 0xFFFFFFFF
	// clocks_calc_max_nsecs(0x98968000, 8, 0, 0xFFFFFFFF): 0x4C4B4000000000
	wrap = clocks_calc_max_nsecs(cd.mult, cd.shift, 0, sched_clock_mask);
	// wrap: 0x4C4B4000000000

	// wrap: 0x4C4B4000000000, ns_to_ktime(0x42C1D800000000): 0x42C1D83B9ACA00
	cd.wrap_kt = ns_to_ktime(wrap - (wrap >> 3));
	// cd.wrap_kt: 0x42C1D83B9ACA00

	/* calculate the ns resolution of this counter */
	// cd.mult: 0x98968000 cd.shift: 8, cyc_to_ns(1, 0x98968000, 8): 0x989680
	res = cyc_to_ns(1ULL, cd.mult, cd.shift);
	// res: 0x989680

	// bits: 32, r: 100, r_unit: ' ', res: 0x989680, wrap: 0x4C4B4000000000
	pr_info("sched_clock: %u bits at %lu%cHz, resolution %lluns, wraps every %lluns\n",
		bits, r, r_unit, res, wrap);
	// "sched_clock: 32 bits at 100 Hz, resolution 10000000ns, wraps every 21474836480000000ns"

	update_sched_clock();

	// update_sched_clock에서 한일:
	// cd.epoch_ns: 0
	// cd.epoch_cyc: 0
	// (&cd.seq)->sequence: 2

	/*
	 * Ensure that sched_clock() starts off at 0ns
	 */
	cd.epoch_ns = 0;
	// cd.epoch_ns: 0

	/* Enable IRQ time accounting if we have a fast enough sched_clock */
	// irqtime: -1, rate: 100
	if (irqtime > 0 || (irqtime == -1 && rate >= 1000000))
		enable_sched_clock_irqtime();

	// read: jiffy_sched_clock_read
	pr_debug("Registered %pF as sched_clock source\n", read);
	// Registered 0xXXXXXXXXF as sched_clock source"
}

void __init setup_sched_clock(u32 (*read)(void), int bits, unsigned long rate)
{
	read_sched_clock_32 = read;
	sched_clock_register(read_sched_clock_32_wrapper, bits, rate);
}

// ARM10C 20150530
void __init sched_clock_postinit(void)
{
	/*
	 * If no sched_clock function has been provided at that point,
	 * make it the final one one.
	 */
	// read_sched_clock: jiffy_sched_clock_read
	if (read_sched_clock == jiffy_sched_clock_read)
		// BITS_PER_LONG: 32, HZ: 100
		sched_clock_register(jiffy_sched_clock_read, BITS_PER_LONG, HZ);

		// sched_clock_register에서 한일:
		// read_sched_clock: jiffy_sched_clock_read
		// sched_clock_mask: 0xFFFFFFFF
		// cd.rate: 100
		// cd.epoch_ns: 0
		// cd.epoch_cyc: 0
		// cd.wrap_kt: 0x42C1D83B9ACA00
		// (&cd)->mult: 0x98968000
		// (&cd)->shift: 8
		// (&cd.seq)->sequence: 2

	update_sched_clock();

	// update_sched_clock에서 한일:
	// cd.epoch_ns: 0
	// cd.epoch_cyc: 0
	// (&cd.seq)->sequence: 4

	/*
	 * Start the timer to keep sched_clock() properly updated and
	 * sets the initial epoch.
	 */
	// CLOCK_MONOTONIC: 1, HRTIMER_MODE_REL: 1
	hrtimer_init(&sched_clock_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);

	// hrtimer_init에서 한일:
	// sched_clock_timer의 값을 0으로 초기화
	// (&sched_clock_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// RB Tree의 &(&sched_clock_timer)->node 를 초기화

	sched_clock_timer.function = sched_clock_poll;
	// sched_clock_timer.function: sched_clock_poll

// 2015/05/30 종료
// 2015/06/06 시작

	// cd.wrap_kt: 0x42C1D83B9ACA00, HRTIMER_MODE_REL: 1
	hrtimer_start(&sched_clock_timer, cd.wrap_kt, HRTIMER_MODE_REL);

	// hrtimer_start에서 한일:
	// (&sched_clock_timer)->_softexpires: 0x42C1D83B9ACA00
	// (&sched_clock_timer)->node.expires: 0x42C1D83B9ACA00
	//
	// (&(&(&sched_clock_timer)->node)->node)->__rb_parent_color: NULL
	// (&(&(&sched_clock_timer)->node)->node)->rb_left: NULL
	// (&(&(&sched_clock_timer)->node)->node)->rb_right: NULL
	// [pcp0] (&(&(&hrtimer_bases)->clock_base[0])->active)->head.rb_node: &(&(&sched_clock_timer)->node)->node
	//
	// [pcp0] &(&(&(&hrtimer_bases)->clock_base[0])->active)->head 에 RB Tree 형태로
	// &(&(&sched_clock_timer)->node)->node 를 추가함
	//
	// [pcp0] &(&(&(&hrtimer_bases)->clock_base[0])->active)->next: &(&sched_clock_timer)->node
	// [pcp0] (&(&hrtimer_bases)->clock_base[0])->cpu_base->active_bases: 1
	//
	// (&sched_clock_timer)->state: 0x01
	//
	// [pcp0] (&(&percpu_mct_tick)->evt)->next_event.tv64: 0x42C1D83B9ACA00
	//
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
	//
	// [pcp0] (&hrtimer_bases)->expires_next: 0x42C1D83B9ACA00
}

static int sched_clock_suspend(void)
{
	sched_clock_poll(&sched_clock_timer);
	cd.suspended = true;
	return 0;
}

static void sched_clock_resume(void)
{
	cd.epoch_cyc = read_sched_clock();
	cd.suspended = false;
}

static struct syscore_ops sched_clock_ops = {
	.suspend = sched_clock_suspend,
	.resume = sched_clock_resume,
};

static int __init sched_clock_syscore_init(void)
{
	register_syscore_ops(&sched_clock_ops);
	return 0;
}
device_initcall(sched_clock_syscore_init);
