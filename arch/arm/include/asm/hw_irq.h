/*
 * Nothing to see here yet
 */
#ifndef _ARCH_ARM_HW_IRQ_H
#define _ARCH_ARM_HW_IRQ_H

static inline void ack_bad_irq(int irq)
{
	extern unsigned long irq_err_count;
	irq_err_count++;
}

void set_irq_flags(unsigned int irq, unsigned int flags);

// ARM10C 20141122
// ARM10C 20141213
// IRQF_VALID: 1
#define IRQF_VALID	(1 << 0)
// ARM10C 20141122
// ARM10C 20141213
// IRQF_PROBE: 0x2
#define IRQF_PROBE	(1 << 1)
// ARM10C 20141122
// IRQF_NOAUTOEN: 0x4
#define IRQF_NOAUTOEN	(1 << 2)

// ARM10C 20141004
// IRQ_NOPROBE: 0x400, IRQ_NOREQUEST: 0x800
// ARCH_IRQ_INIT_FLAGS: 0xc00
#define ARCH_IRQ_INIT_FLAGS	(IRQ_NOREQUEST | IRQ_NOPROBE)

#endif
