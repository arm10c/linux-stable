/*
 * linux/kernel/time/tick-oneshot.c
 *
 * This file contains functions which manage high resolution tick
 * related events.
 *
 * Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 * Copyright(C) 2006-2007, Timesys Corp., Thomas Gleixner
 *
 * This code is licenced under the GPL version 2. For details see
 * kernel-base/COPYING.
 */
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/profile.h>
#include <linux/sched.h>

#include "tick-internal.h"

/**
 * tick_program_event
 */
// ARM10C 20150620
// expires.tv64: 0x42C1D83B9ACA00, 0
int tick_program_event(ktime_t expires, int force)
{
	// __this_cpu_read(tick_cpu_device.evtdev): [pcp0] tick_cpu_device.evtdev: [pcp0] &(&percpu_mct_tick)->evt
	struct clock_event_device *dev = __this_cpu_read(tick_cpu_device.evtdev);
	// dev: [pcp0] tick_cpu_device.evtdev: [pcp0] &(&percpu_mct_tick)->evt

	// dev: [pcp0] tick_cpu_device.evtdev: [pcp0] &(&percpu_mct_tick)->evt, expires.tv64: 0x42C1D83B9ACA00, force: 0
	// clockevents_program_event([pcp0] &(&percpu_mct_tick)->evt, 0x42C1D83B9ACA00, 0): -62
	return clockevents_program_event(dev, expires, force);
	// return -62
}

/**
 * tick_resume_onshot - resume oneshot mode
 */
void tick_resume_oneshot(void)
{
	struct clock_event_device *dev = __this_cpu_read(tick_cpu_device.evtdev);

	clockevents_set_mode(dev, CLOCK_EVT_MODE_ONESHOT);
	clockevents_program_event(dev, ktime_get(), true);
}

/**
 * tick_setup_oneshot - setup the event device for oneshot mode (hres or nohz)
 */
void tick_setup_oneshot(struct clock_event_device *newdev,
			void (*handler)(struct clock_event_device *),
			ktime_t next_event)
{
	newdev->event_handler = handler;

	clockevents_set_mode(newdev, CLOCK_EVT_MODE_ONESHOT);
	clockevents_program_event(newdev, next_event, true);
}

/**
 * tick_switch_to_oneshot - switch to oneshot mode
 */
int tick_switch_to_oneshot(void (*handler)(struct clock_event_device *))
{
	struct tick_device *td = &__get_cpu_var(tick_cpu_device);
	struct clock_event_device *dev = td->evtdev;

	if (!dev || !(dev->features & CLOCK_EVT_FEAT_ONESHOT) ||
		    !tick_device_is_functional(dev)) {

		printk(KERN_INFO "Clockevents: "
		       "could not switch to one-shot mode:");
		if (!dev) {
			printk(" no tick device\n");
		} else {
			if (!tick_device_is_functional(dev))
				printk(" %s is not functional.\n", dev->name);
			else
				printk(" %s does not support one-shot mode.\n",
				       dev->name);
		}
		return -EINVAL;
	}

	td->mode = TICKDEV_MODE_ONESHOT;
	dev->event_handler = handler;
	clockevents_set_mode(dev, CLOCK_EVT_MODE_ONESHOT);
	tick_broadcast_switch_to_oneshot();
	return 0;
}

/**
 * tick_check_oneshot_mode - check whether the system is in oneshot mode
 *
 * returns 1 when either nohz or highres are enabled. otherwise 0.
 */
// ARM10C 20150523
int tick_oneshot_mode_active(void)
{
	unsigned long flags;
	int ret;

	local_irq_save(flags);

	// local_irq_save에서 한일:
	// flags에 CPSR값을 저장함

	// __this_cpu_read(tick_cpu_device.mode): [pcp0] tick_cpu_device.mode: 0, TICKDEV_MODE_ONESHOT: 1
	ret = __this_cpu_read(tick_cpu_device.mode) == TICKDEV_MODE_ONESHOT;
	// ret: 0

	local_irq_restore(flags);

	// local_irq_restore에서 한일:
	// flags에 저정된 CPSR을 복원함

	// ret: 0
	return ret;
	// return 0
}

#ifdef CONFIG_HIGH_RES_TIMERS
/**
 * tick_init_highres - switch to high resolution mode
 *
 * Called with interrupts disabled.
 */
int tick_init_highres(void)
{
	return tick_switch_to_oneshot(hrtimer_interrupt);
}
#endif
