/*
 * linux/kernel/irq/chip.c
 *
 * Copyright (C) 1992, 1998-2006 Linus Torvalds, Ingo Molnar
 * Copyright (C) 2005-2006, Thomas Gleixner, Russell King
 *
 * This file contains the core interrupt handling code, for irq-chip
 * based architectures.
 *
 * Detailed information is available in Documentation/DocBook/genericirq
 */

#include <linux/irq.h>
#include <linux/msi.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>

#include <trace/events/irq.h>

#include "internals.h"

/**
 *	irq_set_chip - set the irq chip for an irq
 *	@irq:	irq number
 *	@chip:	pointer to irq chip description structure
 */
// ARM10C 20141122
// irq: 16, chip: &gic_chip
// ARM10C 20141213
// irq: 160, chip: &combiner_chip
int irq_set_chip(unsigned int irq, struct irq_chip *chip)
{
	unsigned long flags;

	// irq: 16, irq_get_desc_lock(16, &flags, 0): kmem_cache#28-oX (irq 16)
	// irq: 160, irq_get_desc_lock(160, &flags, 0): kmem_cache#28-oX (irq 160)
	struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);
	// desc: kmem_cache#28-oX (irq 16)
	// desc: kmem_cache#28-oX (irq 160)

	// irq_get_desc_lock(16)에서 한일:
	// irq 16의 desc: kmem_cache#28-oX (irq 16) 값을 가져옴
	// &(kmem_cache#28-oX (irq 16))->lock을 사용하여 spinlock을 설정하고 cpsr을 flags에 저장

	// irq_get_desc_lock(160)에서 한일:
	// irq 160의 desc: kmem_cache#28-oX (irq 160) 값을 가져옴
	// &(kmem_cache#28-oX (irq 160))->lock을 사용하여 spinlock을 설정하고 cpsr을 flags에 저장

	// desc: kmem_cache#28-oX (irq 16)
	// desc: kmem_cache#28-oX (irq 160)
	if (!desc)
		return -EINVAL;

	// chip: &gic_chip
	// chip: &combiner_chip
	if (!chip)
		chip = &no_irq_chip;

	// desc->irq_data.chip: (kmem_cache#28-oX (irq 16))->irq_data.chip, chip: &gic_chip
	// desc->irq_data.chip: (kmem_cache#28-oX (irq 160))->irq_data.chip, chip: &combiner_chip
	desc->irq_data.chip = chip;
	// desc->irq_data.chip: (kmem_cache#28-oX (irq 16))->irq_data.chip: &gic_chip
	// desc->irq_data.chip: (kmem_cache#28-oX (irq 160))->irq_data.chip: &combiner_chip

	// desc: kmem_cache#28-oX (irq 16)
	// desc: kmem_cache#28-oX (irq 160)
	irq_put_desc_unlock(desc, flags);

	// irq_put_desc_unlock에서 한일:
	// &(kmem_cache#28-oX (irq 16))->lock을 사용한 spinlock 해재하고 flags에 저장된 cpsr을 복원

	// irq_put_desc_unlock에서 한일:
	// &(kmem_cache#28-oX (irq 160))->lock을 사용한 spinlock 해재하고 flags에 저장된 cpsr을 복원

	/*
	 * For !CONFIG_SPARSE_IRQ make the irq show up in
	 * allocated_irqs. For the CONFIG_SPARSE_IRQ case, it is
	 * already marked, and this call is harmless.
	 */
	// irq: 16, irq_reserve_irq(16): -17 (EEXIST)
	// irq: 160, irq_reserve_irq(160): -17 (EEXIST)
	irq_reserve_irq(irq);

	return 0;
	// return 0
	// return 0
}
EXPORT_SYMBOL(irq_set_chip);

/**
 *	irq_set_type - set the irq trigger type for an irq
 *	@irq:	irq number
 *	@type:	IRQ_TYPE_{LEVEL,EDGE}_* value - see include/linux/irq.h
 */
int irq_set_irq_type(unsigned int irq, unsigned int type)
{
	unsigned long flags;
	struct irq_desc *desc = irq_get_desc_buslock(irq, &flags, IRQ_GET_DESC_CHECK_GLOBAL);
	int ret = 0;

	if (!desc)
		return -EINVAL;

	type &= IRQ_TYPE_SENSE_MASK;
	ret = __irq_set_trigger(desc, irq, type);
	irq_put_desc_busunlock(desc, flags);
	return ret;
}
EXPORT_SYMBOL(irq_set_irq_type);

/**
 *	irq_set_handler_data - set irq handler data for an irq
 *	@irq:	Interrupt number
 *	@data:	Pointer to interrupt specific data
 *
 *	Set the hardware irq controller data for an irq
 */
int irq_set_handler_data(unsigned int irq, void *data)
{
	unsigned long flags;
	struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);

	if (!desc)
		return -EINVAL;
	desc->irq_data.handler_data = data;
	irq_put_desc_unlock(desc, flags);
	return 0;
}
EXPORT_SYMBOL(irq_set_handler_data);

/**
 *	irq_set_msi_desc_off - set MSI descriptor data for an irq at offset
 *	@irq_base:	Interrupt number base
 *	@irq_offset:	Interrupt number offset
 *	@entry:		Pointer to MSI descriptor data
 *
 *	Set the MSI descriptor entry for an irq at offset
 */
int irq_set_msi_desc_off(unsigned int irq_base, unsigned int irq_offset,
			 struct msi_desc *entry)
{
	unsigned long flags;
	struct irq_desc *desc = irq_get_desc_lock(irq_base + irq_offset, &flags, IRQ_GET_DESC_CHECK_GLOBAL);

	if (!desc)
		return -EINVAL;
	desc->irq_data.msi_desc = entry;
	if (entry && !irq_offset)
		entry->irq = irq_base;
	irq_put_desc_unlock(desc, flags);
	return 0;
}

/**
 *	irq_set_msi_desc - set MSI descriptor data for an irq
 *	@irq:	Interrupt number
 *	@entry:	Pointer to MSI descriptor data
 *
 *	Set the MSI descriptor entry for an irq
 */
int irq_set_msi_desc(unsigned int irq, struct msi_desc *entry)
{
	return irq_set_msi_desc_off(irq, 0, entry);
}

/**
 *	irq_set_chip_data - set irq chip data for an irq
 *	@irq:	Interrupt number
 *	@data:	Pointer to chip specific data
 *
 *	Set the hardware irq chip data for an irq
 */
// ARM10C 20141122
// irq: 16, d->host_data: (kmem_cache#25-o0)->host_data: &gic_data[0]
// ARM10C 20141213
// irq: 160, &combiner_data[0]: &(kmem_cache#26-oX)[0]
int irq_set_chip_data(unsigned int irq, void *data)
{
	unsigned long flags;
	// irq: 16, irq_get_desc_lock(16, &flags, 0): kmem_cache#28-oX (irq 16)
	// irq: 160, irq_get_desc_lock(160, &flags, 0): kmem_cache#28-oX (irq 160)
	struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);
	// desc: kmem_cache#28-oX (irq 16)
	// desc: kmem_cache#28-oX (irq 160)

	// irq_get_desc_lock(16)에서 한일:
	// irq 16의 desc: kmem_cache#28-oX (irq 16) 값을 가져옴
	// &(kmem_cache#28-oX (irq 16))->lock을 사용하여 spinlock을 설정하고 cpsr을 flags에 저장

	// irq_get_desc_lock(160)에서 한일:
	// irq 160의 desc: kmem_cache#28-oX (irq 160) 값을 가져옴
	// &(kmem_cache#28-oX (irq 160))->lock을 사용하여 spinlock을 설정하고 cpsr을 flags에 저장

	// desc: kmem_cache#28-oX (irq 16)
	// desc: kmem_cache#28-oX (irq 160)
	if (!desc)
		return -EINVAL;

	// desc->irq_data.chip_data: (kmem_cache#28-oX (irq 16))->irq_data.chip_data,
	// data: &gic_data[0]
	// desc->irq_data.chip_data: (kmem_cache#28-oX (irq 160))->irq_data.chip_data,
	// data: &(kmem_cache#26-oX)[0] (combiner_data)
	desc->irq_data.chip_data = data;
	// desc->irq_data.chip_data: (kmem_cache#28-oX (irq 16))->irq_data.chip_data: &gic_data[0]
	// desc->irq_data.chip_data: (kmem_cache#28-oX (irq 160))->irq_data.chip_data: &(kmem_cache#26-oX)[0] (combiner_data)

	irq_put_desc_unlock(desc, flags);
	// irq_put_desc_unlock에서 한일:
	// &(kmem_cache#28-oX (irq 16))->lock을 사용한 spinlock 해재하고 flags에 저장된 cpsr을 복원

	// irq_put_desc_unlock에서 한일:
	// &(kmem_cache#28-oX (irq 160))->lock을 사용한 spinlock 해재하고 flags에 저장된 cpsr을 복원

	return 0;
	// return 0
	// return 0
}
EXPORT_SYMBOL(irq_set_chip_data);

// ARM10C 20141122
// virq: 16
// ARM10C 20141213
// virq: 160
struct irq_data *irq_get_irq_data(unsigned int irq)
{
	// irq: 16, irq_to_desc(16): kmem_cache#28-oX (irq 16)
	struct irq_desc *desc = irq_to_desc(irq);
	// desc: kmem_cache#28-oX (irq 16)

	// desc: kmem_cache#28-oX (irq 16)
	// &desc->irq_data: &(kmem_cache#28-oX (irq 16))->irq_data
	return desc ? &desc->irq_data : NULL;
	// return &(kmem_cache#28-oX (irq 16))->irq_data
}
EXPORT_SYMBOL_GPL(irq_get_irq_data);

static void irq_state_clr_disabled(struct irq_desc *desc)
{
	irqd_clear(&desc->irq_data, IRQD_IRQ_DISABLED);
}

static void irq_state_set_disabled(struct irq_desc *desc)
{
	irqd_set(&desc->irq_data, IRQD_IRQ_DISABLED);
}

static void irq_state_clr_masked(struct irq_desc *desc)
{
	irqd_clear(&desc->irq_data, IRQD_IRQ_MASKED);
}

static void irq_state_set_masked(struct irq_desc *desc)
{
	irqd_set(&desc->irq_data, IRQD_IRQ_MASKED);
}

int irq_startup(struct irq_desc *desc, bool resend)
{
	int ret = 0;

	irq_state_clr_disabled(desc);
	desc->depth = 0;

	if (desc->irq_data.chip->irq_startup) {
		ret = desc->irq_data.chip->irq_startup(&desc->irq_data);
		irq_state_clr_masked(desc);
	} else {
		irq_enable(desc);
	}
	if (resend)
		check_irq_resend(desc, desc->irq_data.irq);
	return ret;
}

void irq_shutdown(struct irq_desc *desc)
{
	irq_state_set_disabled(desc);
	desc->depth = 1;
	if (desc->irq_data.chip->irq_shutdown)
		desc->irq_data.chip->irq_shutdown(&desc->irq_data);
	else if (desc->irq_data.chip->irq_disable)
		desc->irq_data.chip->irq_disable(&desc->irq_data);
	else
		desc->irq_data.chip->irq_mask(&desc->irq_data);
	irq_state_set_masked(desc);
}

void irq_enable(struct irq_desc *desc)
{
	irq_state_clr_disabled(desc);
	if (desc->irq_data.chip->irq_enable)
		desc->irq_data.chip->irq_enable(&desc->irq_data);
	else
		desc->irq_data.chip->irq_unmask(&desc->irq_data);
	irq_state_clr_masked(desc);
}

/**
 * irq_disable - Mark interrupt disabled
 * @desc:	irq descriptor which should be disabled
 *
 * If the chip does not implement the irq_disable callback, we
 * use a lazy disable approach. That means we mark the interrupt
 * disabled, but leave the hardware unmasked. That's an
 * optimization because we avoid the hardware access for the
 * common case where no interrupt happens after we marked it
 * disabled. If an interrupt happens, then the interrupt flow
 * handler masks the line at the hardware level and marks it
 * pending.
 */
void irq_disable(struct irq_desc *desc)
{
	irq_state_set_disabled(desc);
	if (desc->irq_data.chip->irq_disable) {
		desc->irq_data.chip->irq_disable(&desc->irq_data);
		irq_state_set_masked(desc);
	}
}

void irq_percpu_enable(struct irq_desc *desc, unsigned int cpu)
{
	if (desc->irq_data.chip->irq_enable)
		desc->irq_data.chip->irq_enable(&desc->irq_data);
	else
		desc->irq_data.chip->irq_unmask(&desc->irq_data);
	cpumask_set_cpu(cpu, desc->percpu_enabled);
}

void irq_percpu_disable(struct irq_desc *desc, unsigned int cpu)
{
	if (desc->irq_data.chip->irq_disable)
		desc->irq_data.chip->irq_disable(&desc->irq_data);
	else
		desc->irq_data.chip->irq_mask(&desc->irq_data);
	cpumask_clear_cpu(cpu, desc->percpu_enabled);
}

static inline void mask_ack_irq(struct irq_desc *desc)
{
	if (desc->irq_data.chip->irq_mask_ack)
		desc->irq_data.chip->irq_mask_ack(&desc->irq_data);
	else {
		desc->irq_data.chip->irq_mask(&desc->irq_data);
		if (desc->irq_data.chip->irq_ack)
			desc->irq_data.chip->irq_ack(&desc->irq_data);
	}
	irq_state_set_masked(desc);
}

void mask_irq(struct irq_desc *desc)
{
	if (desc->irq_data.chip->irq_mask) {
		desc->irq_data.chip->irq_mask(&desc->irq_data);
		irq_state_set_masked(desc);
	}
}

void unmask_irq(struct irq_desc *desc)
{
	if (desc->irq_data.chip->irq_unmask) {
		desc->irq_data.chip->irq_unmask(&desc->irq_data);
		irq_state_clr_masked(desc);
	}
}

/*
 *	handle_nested_irq - Handle a nested irq from a irq thread
 *	@irq:	the interrupt number
 *
 *	Handle interrupts which are nested into a threaded interrupt
 *	handler. The handler function is called inside the calling
 *	threads context.
 */
void handle_nested_irq(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);
	struct irqaction *action;
	irqreturn_t action_ret;

	might_sleep();

	raw_spin_lock_irq(&desc->lock);

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);
	kstat_incr_irqs_this_cpu(irq, desc);

	action = desc->action;
	if (unlikely(!action || irqd_irq_disabled(&desc->irq_data))) {
		desc->istate |= IRQS_PENDING;
		goto out_unlock;
	}

	irqd_set(&desc->irq_data, IRQD_IRQ_INPROGRESS);
	raw_spin_unlock_irq(&desc->lock);

	action_ret = action->thread_fn(action->irq, action->dev_id);
	if (!noirqdebug)
		note_interrupt(irq, desc, action_ret);

	raw_spin_lock_irq(&desc->lock);
	irqd_clear(&desc->irq_data, IRQD_IRQ_INPROGRESS);

out_unlock:
	raw_spin_unlock_irq(&desc->lock);
}
EXPORT_SYMBOL_GPL(handle_nested_irq);

static bool irq_check_poll(struct irq_desc *desc)
{
	if (!(desc->istate & IRQS_POLL_INPROGRESS))
		return false;
	return irq_wait_for_poll(desc);
}

/**
 *	handle_simple_irq - Simple and software-decoded IRQs.
 *	@irq:	the interrupt number
 *	@desc:	the interrupt description structure for this irq
 *
 *	Simple interrupts are either sent from a demultiplexing interrupt
 *	handler or come from hardware, where no interrupt hardware control
 *	is necessary.
 *
 *	Note: The caller is expected to handle the ack, clear, mask and
 *	unmask issues if necessary.
 */
void
handle_simple_irq(unsigned int irq, struct irq_desc *desc)
{
	raw_spin_lock(&desc->lock);

	if (unlikely(irqd_irq_inprogress(&desc->irq_data)))
		if (!irq_check_poll(desc))
			goto out_unlock;

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);
	kstat_incr_irqs_this_cpu(irq, desc);

	if (unlikely(!desc->action || irqd_irq_disabled(&desc->irq_data))) {
		desc->istate |= IRQS_PENDING;
		goto out_unlock;
	}

	handle_irq_event(desc);

out_unlock:
	raw_spin_unlock(&desc->lock);
}
EXPORT_SYMBOL_GPL(handle_simple_irq);

/*
 * Called unconditionally from handle_level_irq() and only for oneshot
 * interrupts from handle_fasteoi_irq()
 */
static void cond_unmask_irq(struct irq_desc *desc)
{
	/*
	 * We need to unmask in the following cases:
	 * - Standard level irq (IRQF_ONESHOT is not set)
	 * - Oneshot irq which did not wake the thread (caused by a
	 *   spurious interrupt or a primary handler handling it
	 *   completely).
	 */
	if (!irqd_irq_disabled(&desc->irq_data) &&
	    irqd_irq_masked(&desc->irq_data) && !desc->threads_oneshot)
		unmask_irq(desc);
}

/**
 *	handle_level_irq - Level type irq handler
 *	@irq:	the interrupt number
 *	@desc:	the interrupt description structure for this irq
 *
 *	Level type interrupts are active as long as the hardware line has
 *	the active level. This may require to mask the interrupt and unmask
 *	it after the associated handler has acknowledged the device, so the
 *	interrupt line is back to inactive.
 */
// ARM10C 20141213
void
handle_level_irq(unsigned int irq, struct irq_desc *desc)
{
	raw_spin_lock(&desc->lock);
	mask_ack_irq(desc);

	if (unlikely(irqd_irq_inprogress(&desc->irq_data)))
		if (!irq_check_poll(desc))
			goto out_unlock;

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);
	kstat_incr_irqs_this_cpu(irq, desc);

	/*
	 * If its disabled or no action available
	 * keep it masked and get out of here
	 */
	if (unlikely(!desc->action || irqd_irq_disabled(&desc->irq_data))) {
		desc->istate |= IRQS_PENDING;
		goto out_unlock;
	}

	handle_irq_event(desc);

	cond_unmask_irq(desc);

out_unlock:
	raw_spin_unlock(&desc->lock);
}
EXPORT_SYMBOL_GPL(handle_level_irq);

#ifdef CONFIG_IRQ_PREFLOW_FASTEOI
static inline void preflow_handler(struct irq_desc *desc)
{
	if (desc->preflow_handler)
		desc->preflow_handler(&desc->irq_data);
}
#else
static inline void preflow_handler(struct irq_desc *desc) { }
#endif

/**
 *	handle_fasteoi_irq - irq handler for transparent controllers
 *	@irq:	the interrupt number
 *	@desc:	the interrupt description structure for this irq
 *
 *	Only a single callback will be issued to the chip: an ->eoi()
 *	call when the interrupt has been serviced. This enables support
 *	for modern forms of interrupt handlers, which handle the flow
 *	details in hardware, transparently.
 */
void
handle_fasteoi_irq(unsigned int irq, struct irq_desc *desc)
{
	raw_spin_lock(&desc->lock);

	if (unlikely(irqd_irq_inprogress(&desc->irq_data)))
		if (!irq_check_poll(desc))
			goto out;

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);
	kstat_incr_irqs_this_cpu(irq, desc);

	/*
	 * If its disabled or no action available
	 * then mask it and get out of here:
	 */
	if (unlikely(!desc->action || irqd_irq_disabled(&desc->irq_data))) {
		desc->istate |= IRQS_PENDING;
		mask_irq(desc);
		goto out;
	}

	if (desc->istate & IRQS_ONESHOT)
		mask_irq(desc);

	preflow_handler(desc);
	handle_irq_event(desc);

	if (desc->istate & IRQS_ONESHOT)
		cond_unmask_irq(desc);

out_eoi:
	desc->irq_data.chip->irq_eoi(&desc->irq_data);
out_unlock:
	raw_spin_unlock(&desc->lock);
	return;
out:
	if (!(desc->irq_data.chip->flags & IRQCHIP_EOI_IF_HANDLED))
		goto out_eoi;
	goto out_unlock;
}

/**
 *	handle_edge_irq - edge type IRQ handler
 *	@irq:	the interrupt number
 *	@desc:	the interrupt description structure for this irq
 *
 *	Interrupt occures on the falling and/or rising edge of a hardware
 *	signal. The occurrence is latched into the irq controller hardware
 *	and must be acked in order to be reenabled. After the ack another
 *	interrupt can happen on the same source even before the first one
 *	is handled by the associated event handler. If this happens it
 *	might be necessary to disable (mask) the interrupt depending on the
 *	controller hardware. This requires to reenable the interrupt inside
 *	of the loop which handles the interrupts which have arrived while
 *	the handler was running. If all pending interrupts are handled, the
 *	loop is left.
 */
void
handle_edge_irq(unsigned int irq, struct irq_desc *desc)
{
	raw_spin_lock(&desc->lock);

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);
	/*
	 * If we're currently running this IRQ, or its disabled,
	 * we shouldn't process the IRQ. Mark it pending, handle
	 * the necessary masking and go out
	 */
	if (unlikely(irqd_irq_disabled(&desc->irq_data) ||
		     irqd_irq_inprogress(&desc->irq_data) || !desc->action)) {
		if (!irq_check_poll(desc)) {
			desc->istate |= IRQS_PENDING;
			mask_ack_irq(desc);
			goto out_unlock;
		}
	}
	kstat_incr_irqs_this_cpu(irq, desc);

	/* Start handling the irq */
	desc->irq_data.chip->irq_ack(&desc->irq_data);

	do {
		if (unlikely(!desc->action)) {
			mask_irq(desc);
			goto out_unlock;
		}

		/*
		 * When another irq arrived while we were handling
		 * one, we could have masked the irq.
		 * Renable it, if it was not disabled in meantime.
		 */
		if (unlikely(desc->istate & IRQS_PENDING)) {
			if (!irqd_irq_disabled(&desc->irq_data) &&
			    irqd_irq_masked(&desc->irq_data))
				unmask_irq(desc);
		}

		handle_irq_event(desc);

	} while ((desc->istate & IRQS_PENDING) &&
		 !irqd_irq_disabled(&desc->irq_data));

out_unlock:
	raw_spin_unlock(&desc->lock);
}
EXPORT_SYMBOL(handle_edge_irq);

#ifdef CONFIG_IRQ_EDGE_EOI_HANDLER
/**
 *	handle_edge_eoi_irq - edge eoi type IRQ handler
 *	@irq:	the interrupt number
 *	@desc:	the interrupt description structure for this irq
 *
 * Similar as the above handle_edge_irq, but using eoi and w/o the
 * mask/unmask logic.
 */
void handle_edge_eoi_irq(unsigned int irq, struct irq_desc *desc)
{
	struct irq_chip *chip = irq_desc_get_chip(desc);

	raw_spin_lock(&desc->lock);

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);
	/*
	 * If we're currently running this IRQ, or its disabled,
	 * we shouldn't process the IRQ. Mark it pending, handle
	 * the necessary masking and go out
	 */
	if (unlikely(irqd_irq_disabled(&desc->irq_data) ||
		     irqd_irq_inprogress(&desc->irq_data) || !desc->action)) {
		if (!irq_check_poll(desc)) {
			desc->istate |= IRQS_PENDING;
			goto out_eoi;
		}
	}
	kstat_incr_irqs_this_cpu(irq, desc);

	do {
		if (unlikely(!desc->action))
			goto out_eoi;

		handle_irq_event(desc);

	} while ((desc->istate & IRQS_PENDING) &&
		 !irqd_irq_disabled(&desc->irq_data));

out_eoi:
	chip->irq_eoi(&desc->irq_data);
	raw_spin_unlock(&desc->lock);
}
#endif

/**
 *	handle_percpu_irq - Per CPU local irq handler
 *	@irq:	the interrupt number
 *	@desc:	the interrupt description structure for this irq
 *
 *	Per CPU interrupts on SMP machines without locking requirements
 */
void
handle_percpu_irq(unsigned int irq, struct irq_desc *desc)
{
	struct irq_chip *chip = irq_desc_get_chip(desc);

	kstat_incr_irqs_this_cpu(irq, desc);

	if (chip->irq_ack)
		chip->irq_ack(&desc->irq_data);

	handle_irq_event_percpu(desc, desc->action);

	if (chip->irq_eoi)
		chip->irq_eoi(&desc->irq_data);
}

/**
 * handle_percpu_devid_irq - Per CPU local irq handler with per cpu dev ids
 * @irq:	the interrupt number
 * @desc:	the interrupt description structure for this irq
 *
 * Per CPU interrupts on SMP machines without locking requirements. Same as
 * handle_percpu_irq() above but with the following extras:
 *
 * action->percpu_dev_id is a pointer to percpu variables which
 * contain the real device id for the cpu on which this handler is
 * called
 */
// ARM10C 20141122
void handle_percpu_devid_irq(unsigned int irq, struct irq_desc *desc)
{
	struct irq_chip *chip = irq_desc_get_chip(desc);
	struct irqaction *action = desc->action;
	void *dev_id = __this_cpu_ptr(action->percpu_dev_id);
	irqreturn_t res;

	kstat_incr_irqs_this_cpu(irq, desc);

	if (chip->irq_ack)
		chip->irq_ack(&desc->irq_data);

	trace_irq_handler_entry(irq, action);
	res = action->handler(irq, dev_id);
	trace_irq_handler_exit(irq, action, res);

	if (chip->irq_eoi)
		chip->irq_eoi(&desc->irq_data);
}

// ARM10C 20141122
// irq: 16, handle: handle_percpu_devid_irq, 0, name: NULL
// ARM10C 20141213
// irq: 160, handle: handle_level_irq, 0, name: NULL
void
__irq_set_handler(unsigned int irq, irq_flow_handler_t handle, int is_chained,
		  const char *name)
{
	unsigned long flags;

	// irq: 16
	// irq_get_desc_buslock(16, &flags, 0): kmem_cache#28-oX (irq 16)
	// irq: 160
	// irq_get_desc_buslock(160, &flags, 0): kmem_cache#28-oX (irq 160)
	struct irq_desc *desc = irq_get_desc_buslock(irq, &flags, 0);
	// desc: kmem_cache#28-oX (irq 16)
	// desc: kmem_cache#28-oX (irq 160)

	// irq_get_desc_buslock(16)에서 한일:
	// irq 16의 desc: kmem_cache#28-oX (irq 16) 값을 가져옴
	// &(kmem_cache#28-oX (irq 16))->lock을 사용하여 spinlock을 설정하고 cpsr을 flags에 저장

	// irq_get_desc_buslock(160)에서 한일:
	// irq 16의 desc: kmem_cache#28-oX (irq 160) 값을 가져옴
	// &(kmem_cache#28-oX (irq 160))->lock을 사용하여 spinlock을 설정하고 cpsr을 flags에 저장

	// desc: kmem_cache#28-oX (irq 16)
	// desc: kmem_cache#28-oX (irq 160)
	if (!desc)
		return;

	// handle: handle_percpu_devid_irq
	// handle: handle_level_irq
	if (!handle) {
		handle = handle_bad_irq;
	} else {
		// desc->irq_data.chip: (kmem_cache#28-oX (irq 16))->irq_data.chip: &gic_chip
		// desc->irq_data.chip: (kmem_cache#28-oX (irq 160))->irq_data.chip: &combiner_chip
		if (WARN_ON(desc->irq_data.chip == &no_irq_chip))
			goto out;
	}

	/* Uninstall? */
	// handle: handle_percpu_devid_irq
	// handle: handle_level_irq
	if (handle == handle_bad_irq) {
		if (desc->irq_data.chip != &no_irq_chip)
			mask_ack_irq(desc);
		irq_state_set_disabled(desc);
		desc->depth = 1;
	}

	// desc->handle_irq: (kmem_cache#28-oX (irq 16))->handle_irq,
	// handle: handle_percpu_devid_irq
	// desc->handle_irq: (kmem_cache#28-oX (irq 160))->handle_irq,
	// handle: handle_level_irq
	desc->handle_irq = handle;
	// desc->handle_irq: (kmem_cache#28-oX (irq 16))->handle_irq: handle_percpu_devid_irq
	// desc->handle_irq: (kmem_cache#28-oX (irq 160))->handle_irq: handle_level_irq

	// desc->name: (kmem_cache#28-oX (irq 16))->name, name: NULL
	// desc->name: (kmem_cache#28-oX (irq 160))->name, name: NULL
	desc->name = name;
	// desc->name: (kmem_cache#28-oX (irq 16))->name: NULL
	// desc->name: (kmem_cache#28-oX (irq 160))->name: NULL

	// handle: handle_percpu_devid_irq, is_chained: 0
	// handle: handle_level_irq, is_chained: 0
	if (handle != handle_bad_irq && is_chained) {
		irq_settings_set_noprobe(desc);
		irq_settings_set_norequest(desc);
		irq_settings_set_nothread(desc);
		irq_startup(desc, true);
	}
out:
	// desc: kmem_cache#28-oX (irq 16)
	// desc: kmem_cache#28-oX (irq 160)
	irq_put_desc_busunlock(desc, flags);

	// irq_put_desc_busunlock에서 한일:
	// &(kmem_cache#28-oX (irq 16))->lock을 사용한 spinlock 해재하고 flags에 저장된 cpsr을 복원

	// irq_put_desc_busunlock에서 한일:
	// &(kmem_cache#28-oX (irq 160))->lock을 사용한 spinlock 해재하고 flags에 저장된 cpsr을 복원
}
EXPORT_SYMBOL_GPL(__irq_set_handler);

// ARM10C 20141122
// irq: 16, chip: &gic_chip, handle: handle_percpu_devid_irq, NULL
// ARM10C 20141213
// irq: 160, chip: &combiner_chip, handle: handle_level_irq, NULL
void
irq_set_chip_and_handler_name(unsigned int irq, struct irq_chip *chip,
			      irq_flow_handler_t handle, const char *name)
{
	// irq: 16, chip: &gic_chip
	// irq: 160, chip: &combiner_chip
	irq_set_chip(irq, chip);
	// irq_set_chip(16)에서 한일:
	// (kmem_cache#28-oX (irq 16))->irq_data.chip: &gic_chip

	// irq_set_chip(160)에서 한일:
	// (kmem_cache#28-oX (irq 160))->irq_data.chip: &combiner_chip

	// irq: 16, handle: handle_percpu_devid_irq, name: NULL
	// irq: 160, handle: handle_level_irq, name: NULL
	__irq_set_handler(irq, handle, 0, name);
	// __irq_set_handler(16)에서 한일:
	// (kmem_cache#28-oX (irq 16))->handle_irq: handle_percpu_devid_irq
	// (kmem_cache#28-oX (irq 16))->name: NULL

	// __irq_set_handler(160)에서 한일:
	// (kmem_cache#28-oX (irq 160))->handle_irq: handle_level_irq
	// (kmem_cache#28-oX (irq 160))->name: NULL
}
EXPORT_SYMBOL_GPL(irq_set_chip_and_handler_name);

// ARM10C 20141122
// irq: 16, 0, set: 0x31600
// ARM10C 20141122
// irq: 16, clr: 0x800, 0x1400
// ARM10C 20141122
// irq: 16, clr: 0x800, 0
// ARM10C 20141213
// irq: 160, clr: 0x1c00, 0
void irq_modify_status(unsigned int irq, unsigned long clr, unsigned long set)
{
	unsigned long flags;

	// irq: 16, irq_get_desc_lock(16, &flags, 0): kmem_cache#28-oX (irq 16)
	// irq: 16, irq_get_desc_lock(16, &flags, 0): kmem_cache#28-oX (irq 16)
	struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);
	// desc: kmem_cache#28-oX (irq 16)
	// desc: kmem_cache#28-oX (irq 16)

	// irq_get_desc_lock(16)에서 한일:
	// irq 16의 desc: kmem_cache#28-oX (irq 16) 값을 가져옴
	// &(kmem_cache#28-oX (irq 16))->lock을 사용하여 spinlock을 설정하고 cpsr을 flags에 저장
	// irq_get_desc_lock(16)에서 한일:
	// irq 16의 desc: kmem_cache#28-oX (irq 16) 값을 가져옴
	// &(kmem_cache#28-oX (irq 16))->lock을 사용하여 spinlock을 설정하고 cpsr을 flags에 저장

	// desc: kmem_cache#28-oX (irq 16)
	// desc: kmem_cache#28-oX (irq 16)
	if (!desc)
		return;

	// desc: kmem_cache#28-oX (irq 16), clr: 0, set: 0x31600
	// desc: kmem_cache#28-oX (irq 16), clr: 0x800, set: 0x1400
	irq_settings_clr_and_set(desc, clr, set);
	// irq_settings_clr_and_set에서 한일:
	// (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600
	// irq_settings_clr_and_set에서 한일:
	// (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600

	// &desc->irq_data: &(kmem_cache#28-oX (irq 16))->irq_data
	// IRQD_NO_BALANCING: 0x400, IRQD_PER_CPU: 0x800, IRQD_TRIGGER_MASK: 0xf
	// IRQD_LEVEL: 0x2000, IRQD_MOVE_PCNTXT: 0x8000
	// &desc->irq_data: &(kmem_cache#28-oX (irq 16))->irq_data
	// IRQD_NO_BALANCING: 0x400, IRQD_PER_CPU: 0x800, IRQD_TRIGGER_MASK: 0xf
	// IRQD_LEVEL: 0x2000, IRQD_MOVE_PCNTXT: 0x8000
	irqd_clear(&desc->irq_data, IRQD_NO_BALANCING | IRQD_PER_CPU |
		   IRQD_TRIGGER_MASK | IRQD_LEVEL | IRQD_MOVE_PCNTXT);
	// irqd_clear에서한일:
	// (&(kmem_cache#28-oX (irq 16))->irq_data)->state_use_accessors: 0x10000
	// irqd_clear에서한일:
	// (&(kmem_cache#28-oX (irq 16))->irq_data)->state_use_accessors: 0x10000

	// desc: kmem_cache#28-oX (irq 16)
	// irq_settings_has_no_balance_set(kmem_cache#28-oX (irq 16)): 0
	// desc: kmem_cache#28-oX (irq 16)
	// irq_settings_has_no_balance_set(kmem_cache#28-oX (irq 16)): 0
	if (irq_settings_has_no_balance_set(desc))
		irqd_set(&desc->irq_data, IRQD_NO_BALANCING);

	// desc: kmem_cache#28-oX (irq 16)
	// irq_settings_is_per_cpu(kmem_cache#28-oX (irq 16)): 0x200
	// desc: kmem_cache#28-oX (irq 16)
	// irq_settings_is_per_cpu(kmem_cache#28-oX (irq 16)): 0x200
	if (irq_settings_is_per_cpu(desc))
		// &desc->irq_data: &(kmem_cache#28-oX (irq 16))->irq_data, IRQD_PER_CPU: 0x800
		// &desc->irq_data: &(kmem_cache#28-oX (irq 16))->irq_data, IRQD_PER_CPU: 0x800
		irqd_set(&desc->irq_data, IRQD_PER_CPU);
		// irqd_set에서 한일:
		// (&(kmem_cache#28-oX (irq 16))->irq_data)->state_use_accessors: 0x10800
		// irqd_set에서 한일:
		// (&(kmem_cache#28-oX (irq 16))->irq_data)->state_use_accessors: 0x10800

	// desc: kmem_cache#28-oX (irq 16)
	// irq_settings_can_move_pcntxt(kmem_cache#28-oX (irq 16)): 0
	// desc: kmem_cache#28-oX (irq 16)
	// irq_settings_can_move_pcntxt(kmem_cache#28-oX (irq 16)): 0
	if (irq_settings_can_move_pcntxt(desc))
		irqd_set(&desc->irq_data, IRQD_MOVE_PCNTXT);

	// desc: kmem_cache#28-oX (irq 16)
	// irq_settings_is_level(kmem_cache#28-oX (irq 16)): 0
	// desc: kmem_cache#28-oX (irq 16)
	// irq_settings_is_level(kmem_cache#28-oX (irq 16)): 0
	if (irq_settings_is_level(desc))
		irqd_set(&desc->irq_data, IRQD_LEVEL);

	// &desc->irq_data: &(kmem_cache#28-oX (irq 16))->irq_data
	// desc: kmem_cache#28-oX (irq 16)
	// irq_settings_get_trigger_mask(kmem_cache#28-oX (irq 16)): 0
	// &desc->irq_data: &(kmem_cache#28-oX (irq 16))->irq_data
	// desc: kmem_cache#28-oX (irq 16)
	// irq_settings_get_trigger_mask(kmem_cache#28-oX (irq 16)): 0
	irqd_set(&desc->irq_data, irq_settings_get_trigger_mask(desc));
	// irqd_set에서 한일:
	// (&(kmem_cache#28-oX (irq 16))->irq_data)->state_use_accessors: 0x10800
	// irqd_set에서 한일:
	// (&(kmem_cache#28-oX (irq 16))->irq_data)->state_use_accessors: 0x10800

	// desc: kmem_cache#28-oX (irq 16)
	// desc: kmem_cache#28-oX (irq 16)
	irq_put_desc_unlock(desc, flags);
	// irq_put_desc_unlock에서 한일:
	// &(kmem_cache#28-oX (irq 16))->lock을 사용한 spinlock 해재하고 flags에 저장된 cpsr을 복원
	// irq_put_desc_unlock에서 한일:
	// &(kmem_cache#28-oX (irq 16))->lock을 사용한 spinlock 해재하고 flags에 저장된 cpsr을 복원
}
EXPORT_SYMBOL_GPL(irq_modify_status);

/**
 *	irq_cpu_online - Invoke all irq_cpu_online functions.
 *
 *	Iterate through all irqs and invoke the chip.irq_cpu_online()
 *	for each.
 */
void irq_cpu_online(void)
{
	struct irq_desc *desc;
	struct irq_chip *chip;
	unsigned long flags;
	unsigned int irq;

	for_each_active_irq(irq) {
		desc = irq_to_desc(irq);
		if (!desc)
			continue;

		raw_spin_lock_irqsave(&desc->lock, flags);

		chip = irq_data_get_irq_chip(&desc->irq_data);
		if (chip && chip->irq_cpu_online &&
		    (!(chip->flags & IRQCHIP_ONOFFLINE_ENABLED) ||
		     !irqd_irq_disabled(&desc->irq_data)))
			chip->irq_cpu_online(&desc->irq_data);

		raw_spin_unlock_irqrestore(&desc->lock, flags);
	}
}

/**
 *	irq_cpu_offline - Invoke all irq_cpu_offline functions.
 *
 *	Iterate through all irqs and invoke the chip.irq_cpu_offline()
 *	for each.
 */
void irq_cpu_offline(void)
{
	struct irq_desc *desc;
	struct irq_chip *chip;
	unsigned long flags;
	unsigned int irq;

	for_each_active_irq(irq) {
		desc = irq_to_desc(irq);
		if (!desc)
			continue;

		raw_spin_lock_irqsave(&desc->lock, flags);

		chip = irq_data_get_irq_chip(&desc->irq_data);
		if (chip && chip->irq_cpu_offline &&
		    (!(chip->flags & IRQCHIP_ONOFFLINE_ENABLED) ||
		     !irqd_irq_disabled(&desc->irq_data)))
			chip->irq_cpu_offline(&desc->irq_data);

		raw_spin_unlock_irqrestore(&desc->lock, flags);
	}
}
