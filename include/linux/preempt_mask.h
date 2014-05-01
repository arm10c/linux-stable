#ifndef LINUX_PREEMPT_MASK_H
#define LINUX_PREEMPT_MASK_H

#include <linux/preempt.h>
#include <asm/hardirq.h>

/*
 * We put the hardirq and softirq counter into the preemption
 * counter. The bitmask has the following meaning:
 *
 * - bits 0-7 are the preemption count (max preemption depth: 256)
 * - bits 8-15 are the softirq count (max # of softirqs: 256)
 *
 * The hardirq count could in theory be the same as the number of
 * interrupts in the system, but we run all interrupt handlers with
 * interrupts disabled, so we cannot have nesting interrupts. Though
 * there are a few palaeontologic drivers which reenable interrupts in
 * the handler, so we need more than one bit here.
 *
 * PREEMPT_MASK:	0x000000ff
 * SOFTIRQ_MASK:	0x0000ff00
 * HARDIRQ_MASK:	0x000f0000
 *     NMI_MASK:	0x00100000
 * PREEMPT_ACTIVE:	0x00200000
 */
// ARM10C 20140315
#define PREEMPT_BITS	8
// ARM10C 20140315
#define SOFTIRQ_BITS	8
// ARM10C 20140315
#define HARDIRQ_BITS	4
#define NMI_BITS	1

#define PREEMPT_SHIFT	0
// ARM10C 20140315
// SOFTIRQ_SHIFT : 8 : (PREEMPT_SHIFT :0  + PREEMPT_BITS : 8)
#define SOFTIRQ_SHIFT	(PREEMPT_SHIFT + PREEMPT_BITS)
// ARM10C 20140315
// HARDIQR_SHIFT : 16 : SOFTIRQ_SHIFT : 8   + SOFTIRQ_BITS : 8 
#define HARDIRQ_SHIFT	(SOFTIRQ_SHIFT + SOFTIRQ_BITS)
// ARM10C 20140315
// NMI_SHIFT : 26 : HARDIRQ_SHIFT : 16 + HARDIRQ_BITS : 10 )
#define NMI_SHIFT	(HARDIRQ_SHIFT + HARDIRQ_BITS)

// ARM10C 20140315
// HARDIRQ_BITS x : 10 : 0x3FF
// SOFTIRQ_BITS x : 8 : 0xFF
#define __IRQ_MASK(x)	((1UL << (x))-1)

// ARM10C 20140315
// PREEMPT_BITS: 8, PREEMPT_SHIFT: 0
// PREEMPT_MASK: 0xFF
#define PREEMPT_MASK	(__IRQ_MASK(PREEMPT_BITS) << PREEMPT_SHIFT)
// ARM10C 20140315
// SOFTIRQ_MASK : 0xFF00 : 0xFF << 8 : __IRQ_MASK(SOFTIRQ_BITS : 8) << SOFTIRQ_SHIFT : 8
#define SOFTIRQ_MASK	(__IRQ_MASK(SOFTIRQ_BITS) << SOFTIRQ_SHIFT)
// ARM10C 20140315
#define HARDIRQ_MASK	(__IRQ_MASK(HARDIRQ_BITS) << HARDIRQ_SHIFT)
// ARM10C 20140315
// NMI_MASK : 0x4000000 : 0x1 << 26 : __IQR_MASK(NMI_BITS :1) << 26
#define NMI_MASK	(__IRQ_MASK(NMI_BITS)     << NMI_SHIFT)

#define PREEMPT_OFFSET	(1UL << PREEMPT_SHIFT)
#define SOFTIRQ_OFFSET	(1UL << SOFTIRQ_SHIFT)
#define HARDIRQ_OFFSET	(1UL << HARDIRQ_SHIFT)
#define NMI_OFFSET	(1UL << NMI_SHIFT)

#define SOFTIRQ_DISABLE_OFFSET	(2 * SOFTIRQ_OFFSET)

#define PREEMPT_ACTIVE_BITS	1
#define PREEMPT_ACTIVE_SHIFT	(NMI_SHIFT + NMI_BITS)
#define PREEMPT_ACTIVE	(__IRQ_MASK(PREEMPT_ACTIVE_BITS) << PREEMPT_ACTIVE_SHIFT)

#define hardirq_count()	(preempt_count() & HARDIRQ_MASK)
#define softirq_count()	(preempt_count() & SOFTIRQ_MASK)
// ARM10C 20140315
// preept_count() : 0x4000 0001, & HARDIRQ_BITS : 10 
// HARDIRQ_MASK : 0x3FF0000 : 0x3FF << 16 : (__IRQ_MASK(HARDIRQ_BITS : 10 ) : 0x3FF << HARDIRQ_SHIFT : 16)
// SOFTIRQ_MASK : 0xFF00
// NMI_MASK     : 0x4000000
// irq_count() : 0 : (0x4000 0001 & 0x07FFFF00)
// 지금(140315)은 인터럽트가 0이다. 
#define irq_count()	(preempt_count() & (HARDIRQ_MASK | SOFTIRQ_MASK \
				 | NMI_MASK))

/*
 * Are we doing bottom half or hardware interrupt processing?
 * Are we in a softirq context? Interrupt context?
 * in_softirq - Are we currently processing softirq or have bh disabled?
 * in_serving_softirq - Are we currently processing softirq?
 */
#define in_irq()		(hardirq_count())
#define in_softirq()		(softirq_count())
// ARM10C 20140315
// in_interrupt() : 0
#define in_interrupt()		(irq_count())
#define in_serving_softirq()	(softirq_count() & SOFTIRQ_OFFSET)

/*
 * Are we in NMI context?
 */
#define in_nmi()	(preempt_count() & NMI_MASK)

#if defined(CONFIG_PREEMPT_COUNT)
# define PREEMPT_CHECK_OFFSET 1
#else
# define PREEMPT_CHECK_OFFSET 0
#endif

/*
 * Are we running in atomic context?  WARNING: this macro cannot
 * always detect atomic context; in particular, it cannot know about
 * held spinlocks in non-preemptible kernels.  Thus it should not be
 * used in the general case to determine whether sleeping is possible.
 * Do not use in_atomic() in driver code.
 */
#define in_atomic()	((preempt_count() & ~PREEMPT_ACTIVE) != 0)

/*
 * Check whether we were atomic before we did preempt_disable():
 * (used by the scheduler, *after* releasing the kernel lock)
 */
#define in_atomic_preempt_off() \
		((preempt_count() & ~PREEMPT_ACTIVE) != PREEMPT_CHECK_OFFSET)

#ifdef CONFIG_PREEMPT_COUNT
# define preemptible()	(preempt_count() == 0 && !irqs_disabled())
#else
# define preemptible()	0
#endif

#endif /* LINUX_PREEMPT_MASK_H */
