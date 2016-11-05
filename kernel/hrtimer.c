/*
 *  linux/kernel/hrtimer.c
 *
 *  Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 *  Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 *  Copyright(C) 2006-2007  Timesys Corp., Thomas Gleixner
 *
 *  High-resolution kernel timers
 *
 *  In contrast to the low-resolution timeout API implemented in
 *  kernel/timer.c, hrtimers provide finer resolution and accuracy
 *  depending on system configuration and capabilities.
 *
 *  These timers are currently used for:
 *   - itimers
 *   - POSIX timers
 *   - nanosleep
 *   - precise in-kernel timing
 *
 *  Started by: Thomas Gleixner and Ingo Molnar
 *
 *  Credits:
 *	based on kernel/timer.c
 *
 *	Help, testing, suggestions, bugfixes, improvements were
 *	provided by:
 *
 *	George Anzinger, Andrew Morton, Steven Rostedt, Roman Zippel
 *	et. al.
 *
 *  For licencing details see kernel-base/COPYING
 */

#include <linux/cpu.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/hrtimer.h>
#include <linux/notifier.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/interrupt.h>
#include <linux/tick.h>
#include <linux/seq_file.h>
#include <linux/err.h>
#include <linux/debugobjects.h>
#include <linux/sched.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/rt.h>
#include <linux/timer.h>
#include <linux/freezer.h>

#include <asm/uaccess.h>

#include <trace/events/timer.h>

/*
 * The timer bases:
 *
 * There are more clockids then hrtimer bases. Thus, we index
 * into the timer bases by the hrtimer_base_type enum. When trying
 * to reach a base using a clockid, hrtimer_clockid_to_base()
 * is used to convert from clockid to the proper hrtimer_base_type.
 */
// ARM10C 20140830
// ARM10C 20150103
// ARM10C 20150606
// DEFINE_PER_CPU(struct hrtimer_cpu_base, hrtimer_bases):
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(struct hrtimer_cpu_base) hrtimer_bases
DEFINE_PER_CPU(struct hrtimer_cpu_base, hrtimer_bases) =
{

	.lock = __RAW_SPIN_LOCK_UNLOCKED(hrtimer_bases.lock),
	.clock_base =
	{
		{
			// HRTIMER_BASE_MONOTONIC: 0
			.index = HRTIMER_BASE_MONOTONIC,
			.clockid = CLOCK_MONOTONIC,
			.get_time = &ktime_get,
			.resolution = KTIME_LOW_RES,
		},
		{
			.index = HRTIMER_BASE_REALTIME,
			.clockid = CLOCK_REALTIME,
			.get_time = &ktime_get_real,
			.resolution = KTIME_LOW_RES,
		},
		{
			.index = HRTIMER_BASE_BOOTTIME,
			.clockid = CLOCK_BOOTTIME,
			.get_time = &ktime_get_boottime,
			.resolution = KTIME_LOW_RES,
		},
		{
			.index = HRTIMER_BASE_TAI,
			.clockid = CLOCK_TAI,
			.get_time = &ktime_get_clocktai,
			.resolution = KTIME_LOW_RES,
		},
	}
};

// ARM10C 20140830
// MAX_CLOCKS: 16
// CLOCK_REALTIME: 0, CLOCK_MONOTONIC: 1
// CLOCK_BOOTTIME: 7, CLOCK_TAI: 11
// HRTIMER_BASE_MONOTONIC: 0, HRTIMER_BASE_REALTIME: 1
// HRTIMER_BASE_BOOTTIME: 2, HRTIMER_BASE_TAI: 3
static const int hrtimer_clock_to_base_table[MAX_CLOCKS] = {
	[CLOCK_REALTIME]	= HRTIMER_BASE_REALTIME,
	[CLOCK_MONOTONIC]	= HRTIMER_BASE_MONOTONIC,
	[CLOCK_BOOTTIME]	= HRTIMER_BASE_BOOTTIME,
	[CLOCK_TAI]		= HRTIMER_BASE_TAI,
};

// ARM10C 20140830
// clock_id: 1
// ARM10C 20150530
// clock_id: 1
static inline int hrtimer_clockid_to_base(clockid_t clock_id)
{
	// clock_id: 1, hrtimer_clock_to_base_table[1]: 0
	return hrtimer_clock_to_base_table[clock_id];
	// return 0
}


/*
 * Get the coarse grained time at the softirq based on xtime and
 * wall_to_monotonic.
 */
static void hrtimer_get_softirq_time(struct hrtimer_cpu_base *base)
{
	ktime_t xtim, mono, boot;
	struct timespec xts, tom, slp;
	s32 tai_offset;

	get_xtime_and_monotonic_and_sleep_offset(&xts, &tom, &slp);
	tai_offset = timekeeping_get_tai_offset();

	xtim = timespec_to_ktime(xts);
	mono = ktime_add(xtim, timespec_to_ktime(tom));
	boot = ktime_add(mono, timespec_to_ktime(slp));
	base->clock_base[HRTIMER_BASE_REALTIME].softirq_time = xtim;
	base->clock_base[HRTIMER_BASE_MONOTONIC].softirq_time = mono;
	base->clock_base[HRTIMER_BASE_BOOTTIME].softirq_time = boot;
	base->clock_base[HRTIMER_BASE_TAI].softirq_time =
				ktime_add(xtim,	ktime_set(tai_offset, 0));
}

/*
 * Functions and macros which are different for UP/SMP systems are kept in a
 * single place
 */
#ifdef CONFIG_SMP // CONFIG_SMP=y

/*
 * We are using hashed locking: holding per_cpu(hrtimer_bases)[n].lock
 * means that all timers which are tied to this base via timer->base are
 * locked, and the base itself is locked too.
 *
 * So __run_timers/migrate_timers can safely modify all timers which could
 * be found on the lists/queues.
 *
 * When the timer's base is locked, and the timer removed from list, it is
 * possible to set timer->base = NULL and drop the lock: the timer remains
 * locked.
 */
// ARM10C 20150606
// timer: &sched_clock_timer, &flags
static
struct hrtimer_clock_base *lock_hrtimer_base(const struct hrtimer *timer,
					     unsigned long *flags)
{
	struct hrtimer_clock_base *base;

	for (;;) {
		// timer->base: (&sched_clock_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
		base = timer->base;
		// base: [pcp0] &(&hrtimer_bases)->clock_base[0]

		// base: [pcp0] &(&hrtimer_bases)->clock_base[0]
		if (likely(base != NULL)) {
			// &base->cpu_base->lock: [pcp0] (&(&hrtimer_bases)->clock_base[0])->cpu_base->lock, flags: &flags
			raw_spin_lock_irqsave(&base->cpu_base->lock, *flags);

			// raw_spin_lock_irqsave에서 한일:
			// [pcp0] (&(&hrtimer_bases)->clock_base[0])->cpu_base->lock을 사용하여 spin lock을 수행하고 cpsr을 flags에 저장

			// base: [pcp0] &(&hrtimer_bases)->clock_base[0],
			// timer->base: (&sched_clock_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
			if (likely(base == timer->base))
				// base: [pcp0] &(&hrtimer_bases)->clock_base[0]
				return base;
				// return [pcp0] &(&hrtimer_bases)->clock_base[0]

			/* The timer has migrated to another CPU: */
			raw_spin_unlock_irqrestore(&base->cpu_base->lock, *flags);
		}
		cpu_relax();
	}
}


/*
 * Get the preferred target CPU for NOHZ
 */
// ARM10C 20150606
// this_cpu: 0, pinned: 0
static int hrtimer_get_target(int this_cpu, int pinned)
{
#ifdef CONFIG_NO_HZ_COMMON // CONFIG_NO_HZ_COMMON=y
	// pinned: 0, get_sysctl_timer_migration(): 1, this_cpu: 0, idle_cpu(0): 1
	if (!pinned && get_sysctl_timer_migration() && idle_cpu(this_cpu))
		// get_nohz_timer_target(): 0
		return get_nohz_timer_target();
		// return 0
#endif
	return this_cpu;
}

/*
 * With HIGHRES=y we do not migrate the timer when it is expiring
 * before the next event on the target cpu because we cannot reprogram
 * the target cpu hardware and we would cause it to fire late.
 *
 * Called with cpu_base->lock of target cpu held.
 */
static int
hrtimer_check_target(struct hrtimer *timer, struct hrtimer_clock_base *new_base)
{
#ifdef CONFIG_HIGH_RES_TIMERS
	ktime_t expires;

	if (!new_base->cpu_base->hres_active)
		return 0;

	expires = ktime_sub(hrtimer_get_expires(timer), new_base->offset);
	return expires.tv64 <= new_base->cpu_base->expires_next.tv64;
#else
	return 0;
#endif
}

/*
 * Switch the timer base to the current CPU when possible.
 */
// ARM10C 20150606
// timer: &sched_clock_timer, base: [pcp0] &(&hrtimer_bases)->clock_base[0], 0
static inline struct hrtimer_clock_base *
switch_hrtimer_base(struct hrtimer *timer, struct hrtimer_clock_base *base,
		    int pinned)
{
	struct hrtimer_clock_base *new_base;
	struct hrtimer_cpu_base *new_cpu_base;

	// smp_processor_id(): 0
	int this_cpu = smp_processor_id();
	// this_cpu: 0

	// this_cpu: 0, pinned: 0, hrtimer_get_target(0, 0): 0
	int cpu = hrtimer_get_target(this_cpu, pinned);
	// cpu: 0

	// base->index: [pcp0] (&(&hrtimer_bases)->clock_base[0])->index: 0
	int basenum = base->index;
	// basenum: 0

again:
	// cpu: 0, &per_cpu(hrtimer_bases, 0): [pcp0] &hrtimer_bases
	new_cpu_base = &per_cpu(hrtimer_bases, cpu);
	// new_cpu_base: [pcp0] &hrtimer_bases

	// basenum: 0, &new_cpu_base->clock_base[0]: [pcp0] &(&hrtimer_bases)->clock_base[0]
	new_base = &new_cpu_base->clock_base[basenum];
	// new_base: [pcp0] &(&hrtimer_bases)->clock_base[0]

	// base: [pcp0] &(&hrtimer_bases)->clock_base[0], new_base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	if (base != new_base) {
		/*
		 * We are trying to move timer to new_base.
		 * However we can't change timer's base while it is running,
		 * so we keep it on the same CPU. No hassle vs. reprogramming
		 * the event source in the high resolution case. The softirq
		 * code will take care of this when the timer function has
		 * completed. There is no conflict as we hold the lock until
		 * the timer is enqueued.
		 */
		if (unlikely(hrtimer_callback_running(timer)))
			return base;

		/* See the comment in lock_timer_base() */
		timer->base = NULL;
		raw_spin_unlock(&base->cpu_base->lock);
		raw_spin_lock(&new_base->cpu_base->lock);

		if (cpu != this_cpu && hrtimer_check_target(timer, new_base)) {
			cpu = this_cpu;
			raw_spin_unlock(&new_base->cpu_base->lock);
			raw_spin_lock(&base->cpu_base->lock);
			timer->base = base;
			goto again;
		}
		timer->base = new_base;
	}

	// new_base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	return new_base;
	// return [pcp0] &(&hrtimer_bases)->clock_base[0]
}

#else /* CONFIG_SMP */

static inline struct hrtimer_clock_base *
lock_hrtimer_base(const struct hrtimer *timer, unsigned long *flags)
{
	struct hrtimer_clock_base *base = timer->base;

	raw_spin_lock_irqsave(&base->cpu_base->lock, *flags);

	return base;
}

# define switch_hrtimer_base(t, b, p)	(b)

#endif	/* !CONFIG_SMP */

/*
 * Functions for the union type storage format of ktime_t which are
 * too large for inlining:
 */
#if BITS_PER_LONG < 64
# ifndef CONFIG_KTIME_SCALAR
/**
 * ktime_add_ns - Add a scalar nanoseconds value to a ktime_t variable
 * @kt:		addend
 * @nsec:	the scalar nsec value to add
 *
 * Returns the sum of kt and nsec in ktime_t format
 */
ktime_t ktime_add_ns(const ktime_t kt, u64 nsec)
{
	ktime_t tmp;

	if (likely(nsec < NSEC_PER_SEC)) {
		tmp.tv64 = nsec;
	} else {
		unsigned long rem = do_div(nsec, NSEC_PER_SEC);

		/* Make sure nsec fits into long */
		if (unlikely(nsec > KTIME_SEC_MAX))
			return (ktime_t){ .tv64 = KTIME_MAX };

		tmp = ktime_set((long)nsec, rem);
	}

	return ktime_add(kt, tmp);
}

EXPORT_SYMBOL_GPL(ktime_add_ns);

/**
 * ktime_sub_ns - Subtract a scalar nanoseconds value from a ktime_t variable
 * @kt:		minuend
 * @nsec:	the scalar nsec value to subtract
 *
 * Returns the subtraction of @nsec from @kt in ktime_t format
 */
ktime_t ktime_sub_ns(const ktime_t kt, u64 nsec)
{
	ktime_t tmp;

	if (likely(nsec < NSEC_PER_SEC)) {
		tmp.tv64 = nsec;
	} else {
		unsigned long rem = do_div(nsec, NSEC_PER_SEC);

		tmp = ktime_set((long)nsec, rem);
	}

	return ktime_sub(kt, tmp);
}

EXPORT_SYMBOL_GPL(ktime_sub_ns);
# endif /* !CONFIG_KTIME_SCALAR */

/*
 * Divide a ktime value by a nanosecond value
 */
u64 ktime_divns(const ktime_t kt, s64 div)
{
	u64 dclc;
	int sft = 0;

	dclc = ktime_to_ns(kt);
	/* Make sure the divisor is less than 2^32: */
	while (div >> 32) {
		sft++;
		div >>= 1;
	}
	dclc >>= sft;
	do_div(dclc, (unsigned long) div);

	return dclc;
}
#endif /* BITS_PER_LONG >= 64 */

/*
 * Add two ktime values and do a safety check for overflow:
 */
// ARM10C 20150606
// tim: 0x42C1D83B9ACA00, ktime_get(): (ktime_t) { .tv64 = 0}
// ARM10C 20150606
// time: 0x42C1D83B9ACA00, ns_to_ktime(0): (ktime_t){ .tv64 = 0 + (0) }
ktime_t ktime_add_safe(const ktime_t lhs, const ktime_t rhs)
{
	// lhs.tv64: 0x42C1D83B9ACA00, rhs.tv64: 0,
	// ktime_add(0x42C1D83B9ACA00, 0): 0x42C1D83B9ACA00
	ktime_t res = ktime_add(lhs, rhs);
	// res.tv64: 0x42C1D83B9ACA00

	/*
	 * We use KTIME_SEC_MAX here, the maximum timeout which we can
	 * return to user space in a timespec:
	 */
	// res.tv64: 0x42C1D83B9ACA00, lhs.tv64: 0x42C1D83B9ACA00, rhs.tv64: 0
	if (res.tv64 < 0 || res.tv64 < lhs.tv64 || res.tv64 < rhs.tv64)
		res = ktime_set(KTIME_SEC_MAX, 0);

	// res.tv64: 0x42C1D83B9ACA00
	return res;
	// return (ktime_t) { .tv64 = 0x42C1D83B9ACA00}
}

EXPORT_SYMBOL_GPL(ktime_add_safe);

#ifdef CONFIG_DEBUG_OBJECTS_TIMERS // CONFIG_DEBUG_OBJECTS_TIMERS=n

static struct debug_obj_descr hrtimer_debug_descr;

static void *hrtimer_debug_hint(void *addr)
{
	return ((struct hrtimer *) addr)->function;
}

/*
 * fixup_init is called when:
 * - an active object is initialized
 */
static int hrtimer_fixup_init(void *addr, enum debug_obj_state state)
{
	struct hrtimer *timer = addr;

	switch (state) {
	case ODEBUG_STATE_ACTIVE:
		hrtimer_cancel(timer);
		debug_object_init(timer, &hrtimer_debug_descr);
		return 1;
	default:
		return 0;
	}
}

/*
 * fixup_activate is called when:
 * - an active object is activated
 * - an unknown object is activated (might be a statically initialized object)
 */
static int hrtimer_fixup_activate(void *addr, enum debug_obj_state state)
{
	switch (state) {

	case ODEBUG_STATE_NOTAVAILABLE:
		WARN_ON_ONCE(1);
		return 0;

	case ODEBUG_STATE_ACTIVE:
		WARN_ON(1);

	default:
		return 0;
	}
}

/*
 * fixup_free is called when:
 * - an active object is freed
 */
static int hrtimer_fixup_free(void *addr, enum debug_obj_state state)
{
	struct hrtimer *timer = addr;

	switch (state) {
	case ODEBUG_STATE_ACTIVE:
		hrtimer_cancel(timer);
		debug_object_free(timer, &hrtimer_debug_descr);
		return 1;
	default:
		return 0;
	}
}

static struct debug_obj_descr hrtimer_debug_descr = {
	.name		= "hrtimer",
	.debug_hint	= hrtimer_debug_hint,
	.fixup_init	= hrtimer_fixup_init,
	.fixup_activate	= hrtimer_fixup_activate,
	.fixup_free	= hrtimer_fixup_free,
};

static inline void debug_hrtimer_init(struct hrtimer *timer)
{
	debug_object_init(timer, &hrtimer_debug_descr);
}

static inline void debug_hrtimer_activate(struct hrtimer *timer)
{
	debug_object_activate(timer, &hrtimer_debug_descr);
}

static inline void debug_hrtimer_deactivate(struct hrtimer *timer)
{
	debug_object_deactivate(timer, &hrtimer_debug_descr);
}

static inline void debug_hrtimer_free(struct hrtimer *timer)
{
	debug_object_free(timer, &hrtimer_debug_descr);
}

static void __hrtimer_init(struct hrtimer *timer, clockid_t clock_id,
			   enum hrtimer_mode mode);

void hrtimer_init_on_stack(struct hrtimer *timer, clockid_t clock_id,
			   enum hrtimer_mode mode)
{
	debug_object_init_on_stack(timer, &hrtimer_debug_descr);
	__hrtimer_init(timer, clock_id, mode);
}
EXPORT_SYMBOL_GPL(hrtimer_init_on_stack);

void destroy_hrtimer_on_stack(struct hrtimer *timer)
{
	debug_object_free(timer, &hrtimer_debug_descr);
}

#else
// ARM10C 20140830
// timer: &(&def_rt_bandwidth)->rt_period_timer
// ARM10C 20140913
// timer: &(&runqueues)->hrtick_timer
// ARM10C 20150530
// timer: &sched_clock_timer
static inline void debug_hrtimer_init(struct hrtimer *timer) { }
// ARM10C 20150606
// timer: &sched_clock_timer
static inline void debug_hrtimer_activate(struct hrtimer *timer) { }
static inline void debug_hrtimer_deactivate(struct hrtimer *timer) { }
#endif

// ARM10C 20140830
// timer: &(&def_rt_bandwidth)->rt_period_timer, clock_id: 1, mode: 1
// ARM10C 20140913
// timer: &(&runqueues)->hrtick_timer, clock_id: 1, mode: 1
// ARM10C 20150530
// timer: &sched_clock_timer, clock_id: 1, mode: 1
static inline void
debug_init(struct hrtimer *timer, clockid_t clockid,
	   enum hrtimer_mode mode)
{
	// timer: &(&def_rt_bandwidth)->rt_period_timer
	// timer: &(&runqueues)->hrtick_timer
	// timer: &sched_clock_timer
	debug_hrtimer_init(timer); // null function

	// timer: &(&def_rt_bandwidth)->rt_period_timer, clock_id: 1, mode: 1
	// timer: &(&runqueues)->hrtick_timer, clock_id: 1, mode: 1
	// timer: &sched_clock_timer, clock_id: 1, mode: 1
	trace_hrtimer_init(timer, clockid, mode);
}

// ARM10C 20150606
// timer: &sched_clock_timer
// ARM10C 20150711
// timer: &console_timer, expires: xx_64 + 60000
static inline void debug_activate(struct hrtimer *timer)
{
	// timer: &sched_clock_timer
	debug_hrtimer_activate(timer); // null funtion

	// timer: &sched_clock_timer
	trace_hrtimer_start(timer);
}

static inline void debug_deactivate(struct hrtimer *timer)
{
	debug_hrtimer_deactivate(timer);
	trace_hrtimer_cancel(timer);
}

/* High resolution timer related functions */
#ifdef CONFIG_HIGH_RES_TIMERS // CONFIG_HIGH_RES_TIMERS=y

/*
 * High resolution timer enabled ?
 */
static int hrtimer_hres_enabled __read_mostly  = 1;

/*
 * Enable / Disable high resolution mode
 */
static int __init setup_hrtimer_hres(char *str)
{
	if (!strcmp(str, "off"))
		hrtimer_hres_enabled = 0;
	else if (!strcmp(str, "on"))
		hrtimer_hres_enabled = 1;
	else
		return 0;
	return 1;
}

__setup("highres=", setup_hrtimer_hres);

/*
 * hrtimer_high_res_enabled - query, if the highres mode is enabled
 */
static inline int hrtimer_is_hres_enabled(void)
{
	return hrtimer_hres_enabled;
}

/*
 * Is the high resolution mode active ?
 */
static inline int hrtimer_hres_active(void)
{
	return __this_cpu_read(hrtimer_bases.hres_active);
}

/*
 * Reprogram the event source with checking both queues for the
 * next event
 * Called with interrupts disabled and base->lock held
 */
static void
hrtimer_force_reprogram(struct hrtimer_cpu_base *cpu_base, int skip_equal)
{
	int i;
	struct hrtimer_clock_base *base = cpu_base->clock_base;
	ktime_t expires, expires_next;

	expires_next.tv64 = KTIME_MAX;

	for (i = 0; i < HRTIMER_MAX_CLOCK_BASES; i++, base++) {
		struct hrtimer *timer;
		struct timerqueue_node *next;

		next = timerqueue_getnext(&base->active);
		if (!next)
			continue;
		timer = container_of(next, struct hrtimer, node);

		expires = ktime_sub(hrtimer_get_expires(timer), base->offset);
		/*
		 * clock_was_set() has changed base->offset so the
		 * result might be negative. Fix it up to prevent a
		 * false positive in clockevents_program_event()
		 */
		if (expires.tv64 < 0)
			expires.tv64 = 0;
		if (expires.tv64 < expires_next.tv64)
			expires_next = expires;
	}

	if (skip_equal && expires_next.tv64 == cpu_base->expires_next.tv64)
		return;

	cpu_base->expires_next.tv64 = expires_next.tv64;

	if (cpu_base->expires_next.tv64 != KTIME_MAX)
		tick_program_event(cpu_base->expires_next, 1);
}

/*
 * Shared reprogramming for clock_realtime and clock_monotonic
 *
 * When a timer is enqueued and expires earlier than the already enqueued
 * timers, we have to check, whether it expires earlier than the timer for
 * which the clock event device was armed.
 *
 * Called with interrupts disabled and base->cpu_base.lock held
 */
// ARM10C 20150613
// timer: &sched_clock_timer, base: [pcp0] &(&hrtimer_bases)->clock_base[0]
static int hrtimer_reprogram(struct hrtimer *timer,
			     struct hrtimer_clock_base *base)
{
	// &__get_cpu_var(hrtimer_bases): [pcp0] &hrtimer_bases
	struct hrtimer_cpu_base *cpu_base = &__get_cpu_var(hrtimer_bases);
	// cpu_base: [pcp0] &hrtimer_bases

	// timer: &sched_clock_timer, hrtimer_get_expires(&sched_clock_timer): 0x42C1D83B9ACA00
	// base->offset: [pcp0] (&(&hrtimer_bases)->clock_base[0])->offset: 0
	// ktime_sub(0x42C1D83B9ACA00, 0): 0x42C1D83B9ACA00
	ktime_t expires = ktime_sub(hrtimer_get_expires(timer), base->offset);
	// expires.tv64: 0x42C1D83B9ACA00

	int res;

	// timer: &sched_clock_timer, hrtimer_get_expires_tv64(&sched_clock_timer): 0x42C1D83B9ACA00
	WARN_ON_ONCE(hrtimer_get_expires_tv64(timer) < 0);

	/*
	 * When the callback is running, we do not reprogram the clock event
	 * device. The timer callback is either running on a different CPU or
	 * the callback is executed in the hrtimer_interrupt context. The
	 * reprogramming is handled either by the softirq, which called the
	 * callback or at the end of the hrtimer_interrupt.
	 */
	// timer: &sched_clock_timer, hrtimer_callback_running(&sched_clock_timer): 0
	if (hrtimer_callback_running(timer))
		return 0;

	/*
	 * CLOCK_REALTIME timer might be requested with an absolute
	 * expiry time which is less than base->offset. Nothing wrong
	 * about that, just avoid to call into the tick code, which
	 * has now objections against negative expiry values.
	 */
	// expires.tv64: 0x42C1D83B9ACA00
	if (expires.tv64 < 0)
		return -ETIME;

	// expires.tv64: 0x42C1D83B9ACA00
	// cpu_base->expires_next.tv64: [pcp0] (&hrtimer_bases)->expires_next.tv64: 0x7FFFFFFFFFFFFFFF
	if (expires.tv64 >= cpu_base->expires_next.tv64)
		return 0;

	/*
	 * If a hang was detected in the last timer interrupt then we
	 * do not schedule a timer which is earlier than the expiry
	 * which we enforced in the hang detection. We want the system
	 * to make progress.
	 */
	// cpu_base->hang_detected: [pcp0] (&hrtimer_bases)->hang_detected: 0
	if (cpu_base->hang_detected)
		return 0;

	/*
	 * Clockevents returns -ETIME, when the event was in the past.
	 */
	// expires.tv64: 0x42C1D83B9ACA00, tick_program_event(0x42C1D83B9ACA00, 0): -62
	// tick_program_event(0x42C1D83B9ACA00, 0): 0
	res = tick_program_event(expires, 0);
	// res: 0

	// tick_program_event에서 한일:
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

	// res: 0, IS_ERR_VALUE(0): 0
	if (!IS_ERR_VALUE(res))
		// cpu_base->expires_next: [pcp0] (&hrtimer_bases)->expires_next, expires.tv64: 0x42C1D83B9ACA00
		cpu_base->expires_next = expires;
		// cpu_base->expires_next: [pcp0] (&hrtimer_bases)->expires_next: 0x42C1D83B9ACA00

	// res: 0
	return res;
	// return 0
}

/*
 * Initialize the high resolution related parts of cpu_base
 */
// ARM10C 20150103
// cpu_base: [pcp0] &hrtimer_bases
static inline void hrtimer_init_hres(struct hrtimer_cpu_base *base)
{
	// base->expires_next.tv64: [pcp0] (&hrtimer_bases)->expires_next.tv64,
	// KTIME_MAX: 0x7FFFFFFFFFFFFFFF
	base->expires_next.tv64 = KTIME_MAX;
	// base->expires_next.tv64: [pcp0] (&hrtimer_bases)->expires_next.tv64: 0x7FFFFFFFFFFFFFFF

	// base->hres_active: [pcp0] (&hrtimer_bases)->hres_active
	base->hres_active = 0;
	// base->hres_active: [pcp0] (&hrtimer_bases)->hres_active: 0
}

/*
 * When High resolution timers are active, try to reprogram. Note, that in case
 * the state has HRTIMER_STATE_CALLBACK set, no reprogramming and no expiry
 * check happens. The timer gets enqueued into the rbtree. The reprogramming
 * and expiry check is done in the hrtimer_interrupt or in the softirq.
 */
// ARM10C 20150613
// timer: &sched_clock_timer, new_base: [pcp0] &(&hrtimer_bases)->clock_base[0]
static inline int hrtimer_enqueue_reprogram(struct hrtimer *timer,
					    struct hrtimer_clock_base *base)
{
	// base->cpu_base->hres_active: [pcp0] (&(&hrtimer_bases)->clock_base[0])->cpu_base->hres_active: 0
	// timer: &sched_clock_timer, base: [pcp0] &(&hrtimer_bases)->clock_base[0],
	// hrtimer_reprogram(&sched_clock_timer, [pcp0] &(&hrtimer_bases)->clock_base[0]): 0
	return base->cpu_base->hres_active && hrtimer_reprogram(timer, base);
	// return 0

	// hrtimer_reprogram에서 한일:
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

static inline ktime_t hrtimer_update_base(struct hrtimer_cpu_base *base)
{
	ktime_t *offs_real = &base->clock_base[HRTIMER_BASE_REALTIME].offset;
	ktime_t *offs_boot = &base->clock_base[HRTIMER_BASE_BOOTTIME].offset;
	ktime_t *offs_tai = &base->clock_base[HRTIMER_BASE_TAI].offset;

	return ktime_get_update_offsets(offs_real, offs_boot, offs_tai);
}

/*
 * Retrigger next event is called after clock was set
 *
 * Called with interrupts disabled via on_each_cpu()
 */
static void retrigger_next_event(void *arg)
{
	struct hrtimer_cpu_base *base = &__get_cpu_var(hrtimer_bases);

	if (!hrtimer_hres_active())
		return;

	raw_spin_lock(&base->lock);
	hrtimer_update_base(base);
	hrtimer_force_reprogram(base, 0);
	raw_spin_unlock(&base->lock);
}

/*
 * Switch to high resolution mode
 */
static int hrtimer_switch_to_hres(void)
{
	int i, cpu = smp_processor_id();
	struct hrtimer_cpu_base *base = &per_cpu(hrtimer_bases, cpu);
	unsigned long flags;

	if (base->hres_active)
		return 1;

	local_irq_save(flags);

	if (tick_init_highres()) {
		local_irq_restore(flags);
		printk(KERN_WARNING "Could not switch to high resolution "
				    "mode on CPU %d\n", cpu);
		return 0;
	}
	base->hres_active = 1;
	for (i = 0; i < HRTIMER_MAX_CLOCK_BASES; i++)
		base->clock_base[i].resolution = KTIME_HIGH_RES;

	tick_setup_sched_timer();
	/* "Retrigger" the interrupt to get things going */
	retrigger_next_event(NULL);
	local_irq_restore(flags);
	return 1;
}

static void clock_was_set_work(struct work_struct *work)
{
	clock_was_set();
}

static DECLARE_WORK(hrtimer_work, clock_was_set_work);

/*
 * Called from timekeeping and resume code to reprogramm the hrtimer
 * interrupt device on all cpus.
 */
void clock_was_set_delayed(void)
{
	schedule_work(&hrtimer_work);
}

#else

static inline int hrtimer_hres_active(void) { return 0; }
static inline int hrtimer_is_hres_enabled(void) { return 0; }
static inline int hrtimer_switch_to_hres(void) { return 0; }
static inline void
hrtimer_force_reprogram(struct hrtimer_cpu_base *base, int skip_equal) { }
static inline int hrtimer_enqueue_reprogram(struct hrtimer *timer,
					    struct hrtimer_clock_base *base)
{
	return 0;
}
static inline void hrtimer_init_hres(struct hrtimer_cpu_base *base) { }
static inline void retrigger_next_event(void *arg) { }

#endif /* CONFIG_HIGH_RES_TIMERS */

/*
 * Clock realtime was set
 *
 * Change the offset of the realtime clock vs. the monotonic
 * clock.
 *
 * We might have to reprogram the high resolution timer interrupt. On
 * SMP we call the architecture specific code to retrigger _all_ high
 * resolution timer interrupts. On UP we just disable interrupts and
 * call the high resolution interrupt code.
 */
void clock_was_set(void)
{
#ifdef CONFIG_HIGH_RES_TIMERS
	/* Retrigger the CPU local events everywhere */
	on_each_cpu(retrigger_next_event, NULL, 1);
#endif
	timerfd_clock_was_set();
}

/*
 * During resume we might have to reprogram the high resolution timer
 * interrupt on all online CPUs.  However, all other CPUs will be
 * stopped with IRQs interrupts disabled so the clock_was_set() call
 * must be deferred.
 */
void hrtimers_resume(void)
{
	WARN_ONCE(!irqs_disabled(),
		  KERN_INFO "hrtimers_resume() called with IRQs enabled!");

	/* Retrigger on the local CPU */
	retrigger_next_event(NULL);
	/* And schedule a retrigger for all others */
	clock_was_set_delayed();
}

// ARM10C 20150606
// timer: &sched_clock_timer
static inline void timer_stats_hrtimer_set_start_info(struct hrtimer *timer)
{
#ifdef CONFIG_TIMER_STATS // CONFIG_TIMER_STATS=n
	if (timer->start_site)
		return;
	timer->start_site = __builtin_return_address(0);
	memcpy(timer->start_comm, current->comm, TASK_COMM_LEN);
	timer->start_pid = current->pid;
#endif
}

static inline void timer_stats_hrtimer_clear_start_info(struct hrtimer *timer)
{
#ifdef CONFIG_TIMER_STATS
	timer->start_site = NULL;
#endif
}

static inline void timer_stats_account_hrtimer(struct hrtimer *timer)
{
#ifdef CONFIG_TIMER_STATS
	if (likely(!timer_stats_active))
		return;
	timer_stats_update_stats(timer, timer->start_pid, timer->start_site,
				 timer->function, timer->start_comm, 0);
#endif
}

/*
 * Counterpart to lock_hrtimer_base above:
 */
// ARM10C 20150620
// timer: &sched_clock_timer, &flags
static inline
void unlock_hrtimer_base(const struct hrtimer *timer, unsigned long *flags)
{
	// timer->base: (&sched_clock_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// &timer->base->cpu_base->lock: [pcp0] (&(&hrtimer_bases)->clock_base[0])->cpu_base->lock, *flags: flags
	raw_spin_unlock_irqrestore(&timer->base->cpu_base->lock, *flags);

	// raw_spin_unlock_irqrestore에서 한일:
	// [pcp0] (&(&hrtimer_bases)->clock_base[0])->cpu_base->lock을 사용하여 spin unlock을 수행하고 flags에 저장된 cpsr을 복원
}

/**
 * hrtimer_forward - forward the timer expiry
 * @timer:	hrtimer to forward
 * @now:	forward past this time
 * @interval:	the interval to forward
 *
 * Forward the timer expiry so it will expire in the future.
 * Returns the number of overruns.
 */
u64 hrtimer_forward(struct hrtimer *timer, ktime_t now, ktime_t interval)
{
	u64 orun = 1;
	ktime_t delta;

	delta = ktime_sub(now, hrtimer_get_expires(timer));

	if (delta.tv64 < 0)
		return 0;

	if (interval.tv64 < timer->base->resolution.tv64)
		interval.tv64 = timer->base->resolution.tv64;

	if (unlikely(delta.tv64 >= interval.tv64)) {
		s64 incr = ktime_to_ns(interval);

		orun = ktime_divns(delta, incr);
		hrtimer_add_expires_ns(timer, incr * orun);
		if (hrtimer_get_expires_tv64(timer) > now.tv64)
			return orun;
		/*
		 * This (and the ktime_add() below) is the
		 * correction for exact:
		 */
		orun++;
	}
	hrtimer_add_expires(timer, interval);

	return orun;
}
EXPORT_SYMBOL_GPL(hrtimer_forward);

/*
 * enqueue_hrtimer - internal function to (re)start a timer
 *
 * The timer is inserted in expiry order. Insertion into the
 * red black tree is O(log(n)). Must hold the base lock.
 *
 * Returns 1 when the new timer is the leftmost timer in the tree.
 */
// ARM10C 20150606
// timer: &sched_clock_timer, new_base: [pcp0] &(&hrtimer_bases)->clock_base[0]
static int enqueue_hrtimer(struct hrtimer *timer,
			   struct hrtimer_clock_base *base)
{
	// timer: &sched_clock_timer
	debug_activate(timer); // null function

	// &base->active: [pcp0] &(&(&hrtimer_bases)->clock_base[0])->active
	// &timer->node: &(&sched_clock_timer)->node
	timerqueue_add(&base->active, &timer->node);

	// timerqueue_add에서 한읾;
	// (&(&(&sched_clock_timer)->node)->node)->__rb_parent_color: NULL
	// (&(&(&sched_clock_timer)->node)->node)->rb_left: NULL
	// (&(&(&sched_clock_timer)->node)->node)->rb_right: NULL
	// [pcp0] (&(&(&hrtimer_bases)->clock_base[0])->active)->head.rb_node: &(&(&sched_clock_timer)->node)->node
	//
	// [pcp0] &(&(&(&hrtimer_bases)->clock_base[0])->active)->head 에 RB Tree 형태로
	// &(&(&sched_clock_timer)->node)->node 를 추가함
	//
	// [pcp0] &(&(&(&hrtimer_bases)->clock_base[0])->active)->next: &(&sched_clock_timer)->node

	// base->cpu_base->active_bases: [pcp0] (&(&hrtimer_bases)->clock_base[0])->cpu_base->active_bases: 0
	// base->index: [pcp0] (&(&hrtimer_bases)->clock_base[0])->index: 0
	base->cpu_base->active_bases |= 1 << base->index;
	// base->cpu_base->active_bases: [pcp0] (&(&hrtimer_bases)->clock_base[0])->cpu_base->active_bases: 1

	/*
	 * HRTIMER_STATE_ENQUEUED is or'ed to the current state to preserve the
	 * state of a possibly running callback.
	 */
	// timer->state: (&sched_clock_timer)->state: 0, HRTIMER_STATE_ENQUEUED: 0x01
	timer->state |= HRTIMER_STATE_ENQUEUED;
	// timer->state: (&sched_clock_timer)->state: 0x01

	// &timer->node: &(&sched_clock_timer)->node,
	// base->active.next: [pcp0] (&(&hrtimer_bases)->clock_base[0])->active.next: &(&sched_clock_timer)->node
	return (&timer->node == base->active.next);
	// return 1
}

/*
 * __remove_hrtimer - internal function to remove a timer
 *
 * Caller must hold the base lock.
 *
 * High resolution timer mode reprograms the clock event device when the
 * timer is the one which expires next. The caller can disable this by setting
 * reprogram to zero. This is useful, when the context does a reprogramming
 * anyway (e.g. timer interrupt)
 */
static void __remove_hrtimer(struct hrtimer *timer,
			     struct hrtimer_clock_base *base,
			     unsigned long newstate, int reprogram)
{
	struct timerqueue_node *next_timer;
	if (!(timer->state & HRTIMER_STATE_ENQUEUED))
		goto out;

	next_timer = timerqueue_getnext(&base->active);
	timerqueue_del(&base->active, &timer->node);
	if (&timer->node == next_timer) {
#ifdef CONFIG_HIGH_RES_TIMERS
		/* Reprogram the clock event device. if enabled */
		if (reprogram && hrtimer_hres_active()) {
			ktime_t expires;

			expires = ktime_sub(hrtimer_get_expires(timer),
					    base->offset);
			if (base->cpu_base->expires_next.tv64 == expires.tv64)
				hrtimer_force_reprogram(base->cpu_base, 1);
		}
#endif
	}
	if (!timerqueue_getnext(&base->active))
		base->cpu_base->active_bases &= ~(1 << base->index);
out:
	timer->state = newstate;
}

/*
 * remove hrtimer, called with base lock held
 */
// ARM10C 20150606
// timer: &sched_clock_timer, base: [pcp0] &(&hrtimer_bases)->clock_base[0]
static inline int
remove_hrtimer(struct hrtimer *timer, struct hrtimer_clock_base *base)
{
	// timer: &sched_clock_timer, hrtimer_is_queued(&sched_clock_timer): 0
	if (hrtimer_is_queued(timer)) {
		unsigned long state;
		int reprogram;

		/*
		 * Remove the timer and force reprogramming when high
		 * resolution mode is active and the timer is on the current
		 * CPU. If we remove a timer on another CPU, reprogramming is
		 * skipped. The interrupt event on this CPU is fired and
		 * reprogramming happens in the interrupt handler. This is a
		 * rare case and less expensive than a smp call.
		 */
		debug_deactivate(timer);
		timer_stats_hrtimer_clear_start_info(timer);
		reprogram = base->cpu_base == &__get_cpu_var(hrtimer_bases);
		/*
		 * We must preserve the CALLBACK state flag here,
		 * otherwise we could move the timer base in
		 * switch_hrtimer_base.
		 */
		state = timer->state & HRTIMER_STATE_CALLBACK;
		__remove_hrtimer(timer, base, state, reprogram);
		return 1;
	}
	return 0;
	// return 0
}

// ARM10C 20150530
// timer: &sched_clock_timer, tim: 0x42C1D83B9ACA00, 0, mode: 1, 1
int __hrtimer_start_range_ns(struct hrtimer *timer, ktime_t tim,
		unsigned long delta_ns, const enum hrtimer_mode mode,
		int wakeup)
{
	struct hrtimer_clock_base *base, *new_base;
	unsigned long flags;
	int ret, leftmost;

	// timer: &sched_clock_timer
	// lock_hrtimer_base(&sched_clock_timer, &flags): [pcp0] &(&hrtimer_bases)->clock_base[0]
	base = lock_hrtimer_base(timer, &flags);
	// base: [pcp0] &(&hrtimer_bases)->clock_base[0]

	// lock_hrtimer_base에서 한일:
	// [pcp0] (&(&hrtimer_bases)->clock_base[0])->cpu_base->lock을 사용하여 spin lock을 수행하고 cpsr을 flags에 저장
	// (&sched_clock_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0] 을 리턴
	// flags에 cpsr값을 가져옴

	/* Remove an active timer from the queue: */
	// timer: &sched_clock_timer, base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// remove_hrtimer(&sched_clock_timer, [pcp0] &(&hrtimer_bases)->clock_base[0]): 0
	ret = remove_hrtimer(timer, base);
	// ret: 0

	/* Switch the timer base, if necessary: */
	// timer: &sched_clock_timer, base: [pcp0] &(&hrtimer_bases)->clock_base[0], mode: 1,
	// HRTIMER_MODE_PINNED: 0x02
	// switch_hrtimer_base(&sched_clock_timer, [pcp0] &(&hrtimer_bases)->clock_base[0], 0):
	// [pcp0] &(&hrtimer_bases)->clock_base[0]
	new_base = switch_hrtimer_base(timer, base, mode & HRTIMER_MODE_PINNED);
	// new_base: [pcp0] &(&hrtimer_bases)->clock_base[0]

	// mode: 1, HRTIMER_MODE_REL: 1
	if (mode & HRTIMER_MODE_REL) {
		// tim.tv64: 0x42C1D83B9ACA00,
		// new_base->get_time: [pcp0] (&(&hrtimer_bases)->clock_base[0])->get_time: &ktime_get,
		// ktime_get(): (ktime_t) { .tv64 = 0}
		// ktime_add_safe(0x42C1D83B9ACA00, (ktime_t) { .tv64 = 0}): (ktime_t) { .tv64 = 0x42C1D83B9ACA00}
		tim = ktime_add_safe(tim, new_base->get_time());
		// tim.tv64: 0x42C1D83B9ACA00

		/*
		 * CONFIG_TIME_LOW_RES is a temporary way for architectures
		 * to signal that they simply return xtime in
		 * do_gettimeoffset(). In this case we want to round up by
		 * resolution when starting a relative timer, to avoid short
		 * timeouts. This will go away with the GTOD framework.
		 */
#ifdef CONFIG_TIME_LOW_RES // CONFIG_TIME_LOW_RES=n
		tim = ktime_add_safe(tim, base->resolution);
#endif
	}

	// timer: &sched_clock_timer, tim: 0x42C1D83B9ACA00, delta_ns: 0
	hrtimer_set_expires_range_ns(timer, tim, delta_ns);

	// hrtimer_set_expires_range_ns에서 한일:
	// timer->_softexpires: (&sched_clock_timer)->_softexpires: 0x42C1D83B9ACA00
	// timer->node.expires: (&sched_clock_timer)->node.expires: 0x42C1D83B9ACA00

	// timer: &sched_clock_timer
	timer_stats_hrtimer_set_start_info(timer); // null function

	// timer: &sched_clock_timer, new_base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// enqueue_hrtimer(&sched_clock_timer, [pcp0] &(&hrtimer_bases)->clock_base[0]): 1
	leftmost = enqueue_hrtimer(timer, new_base);
	// leftmost: 1

	// enqueue_hrtimer에서 한일:
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

// 2015/06/13 종료
// 2015/06/20 시작

	/*
	 * Only allow reprogramming if the new base is on this CPU.
	 * (it might still be on another CPU if the timer was pending)
	 *
	 * XXX send_remote_softirq() ?
	 */
	// leftmost: 1, new_base->cpu_base: [pcp0] (&(&hrtimer_bases)->clock_base[0])->cpu_base: [pcp0] &hrtimer_bases,
	// &__get_cpu_var(hrtimer_bases): [pcp0] &hrtimer_bases,
	// timer: &sched_clock_timer, new_base: [pcp0] &(&hrtimer_bases)->clock_base[0],
	// hrtimer_enqueue_reprogram(&sched_clock_timer, [pcp0] &(&hrtimer_bases)->clock_base[0]): 0
	if (leftmost && new_base->cpu_base == &__get_cpu_var(hrtimer_bases)
		&& hrtimer_enqueue_reprogram(timer, new_base)) {
		if (wakeup) {
			/*
			 * We need to drop cpu_base->lock to avoid a
			 * lock ordering issue vs. rq->lock.
			 */
			raw_spin_unlock(&new_base->cpu_base->lock);
			raise_softirq_irqoff(HRTIMER_SOFTIRQ);
			local_irq_restore(flags);
			return ret;
		} else {
			__raise_softirq_irqoff(HRTIMER_SOFTIRQ);
		}
	}

	// hrtimer_enqueue_reprogram에서 한일:
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

	// timer: &sched_clock_timer
	unlock_hrtimer_base(timer, &flags);

	// unlock_hrtimer_base에서 한일:
	// [pcp0] (&(&hrtimer_bases)->clock_base[0])->cpu_base->lock을 사용하여 spin unlock을 수행하고 flags에 저장된 cpsr을 복원

	// ret: 0
	return ret;
	// return 0
}

/**
 * hrtimer_start_range_ns - (re)start an hrtimer on the current CPU
 * @timer:	the timer to be added
 * @tim:	expiry time
 * @delta_ns:	"slack" range for the timer
 * @mode:	expiry mode: absolute (HRTIMER_MODE_ABS) or
 *		relative (HRTIMER_MODE_REL)
 *
 * Returns:
 *  0 on success
 *  1 when the timer was active
 */
int hrtimer_start_range_ns(struct hrtimer *timer, ktime_t tim,
		unsigned long delta_ns, const enum hrtimer_mode mode)
{
	return __hrtimer_start_range_ns(timer, tim, delta_ns, mode, 1);
}
EXPORT_SYMBOL_GPL(hrtimer_start_range_ns);

/**
 * hrtimer_start - (re)start an hrtimer on the current CPU
 * @timer:	the timer to be added
 * @tim:	expiry time
 * @mode:	expiry mode: absolute (HRTIMER_MODE_ABS) or
 *		relative (HRTIMER_MODE_REL)
 *
 * Returns:
 *  0 on success
 *  1 when the timer was active
 */
// ARM10C 20150530
// &sched_clock_timer, cd.wrap_kt: 0x42C1D83B9ACA00, HRTIMER_MODE_REL: 1
int
hrtimer_start(struct hrtimer *timer, ktime_t tim, const enum hrtimer_mode mode)
{
	// timer: &sched_clock_timer, tim: 0x42C1D83B9ACA00, mode: 1
	// __hrtimer_start_range_ns(&sched_clock_timer, 0x42C1D83B9ACA00, 1): 0
	return __hrtimer_start_range_ns(timer, tim, 0, mode, 1);
	// return 0

	// __hrtimer_start_range_ns에서 한일:
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
EXPORT_SYMBOL_GPL(hrtimer_start);


/**
 * hrtimer_try_to_cancel - try to deactivate a timer
 * @timer:	hrtimer to stop
 *
 * Returns:
 *  0 when the timer was not active
 *  1 when the timer was active
 * -1 when the timer is currently excuting the callback function and
 *    cannot be stopped
 */
int hrtimer_try_to_cancel(struct hrtimer *timer)
{
	struct hrtimer_clock_base *base;
	unsigned long flags;
	int ret = -1;

	base = lock_hrtimer_base(timer, &flags);

	if (!hrtimer_callback_running(timer))
		ret = remove_hrtimer(timer, base);

	unlock_hrtimer_base(timer, &flags);

	return ret;

}
EXPORT_SYMBOL_GPL(hrtimer_try_to_cancel);

/**
 * hrtimer_cancel - cancel a timer and wait for the handler to finish.
 * @timer:	the timer to be cancelled
 *
 * Returns:
 *  0 when the timer was not active
 *  1 when the timer was active
 */
int hrtimer_cancel(struct hrtimer *timer)
{
	for (;;) {
		int ret = hrtimer_try_to_cancel(timer);

		if (ret >= 0)
			return ret;
		cpu_relax();
	}
}
EXPORT_SYMBOL_GPL(hrtimer_cancel);

/**
 * hrtimer_get_remaining - get remaining time for the timer
 * @timer:	the timer to read
 */
ktime_t hrtimer_get_remaining(const struct hrtimer *timer)
{
	unsigned long flags;
	ktime_t rem;

	lock_hrtimer_base(timer, &flags);
	rem = hrtimer_expires_remaining(timer);
	unlock_hrtimer_base(timer, &flags);

	return rem;
}
EXPORT_SYMBOL_GPL(hrtimer_get_remaining);

#ifdef CONFIG_NO_HZ_COMMON
/**
 * hrtimer_get_next_event - get the time until next expiry event
 *
 * Returns the delta to the next expiry event or KTIME_MAX if no timer
 * is pending.
 */
ktime_t hrtimer_get_next_event(void)
{
	struct hrtimer_cpu_base *cpu_base = &__get_cpu_var(hrtimer_bases);
	struct hrtimer_clock_base *base = cpu_base->clock_base;
	ktime_t delta, mindelta = { .tv64 = KTIME_MAX };
	unsigned long flags;
	int i;

	raw_spin_lock_irqsave(&cpu_base->lock, flags);

	if (!hrtimer_hres_active()) {
		for (i = 0; i < HRTIMER_MAX_CLOCK_BASES; i++, base++) {
			struct hrtimer *timer;
			struct timerqueue_node *next;

			next = timerqueue_getnext(&base->active);
			if (!next)
				continue;

			timer = container_of(next, struct hrtimer, node);
			delta.tv64 = hrtimer_get_expires_tv64(timer);
			delta = ktime_sub(delta, base->get_time());
			if (delta.tv64 < mindelta.tv64)
				mindelta.tv64 = delta.tv64;
		}
	}

	raw_spin_unlock_irqrestore(&cpu_base->lock, flags);

	if (mindelta.tv64 < 0)
		mindelta.tv64 = 0;
	return mindelta;
}
#endif

// ARM10C 20140830
// timer: &(&def_rt_bandwidth)->rt_period_timer, clock_id: 1, mode: 1
// ARM10C 20140913
// timer: &(&runqueues)->hrtick_timer, clock_id: 1, mode: 1
// ARM10C 20150530
// timer: &sched_clock_timer, clock_id: 1, mode: 1
static void __hrtimer_init(struct hrtimer *timer, clockid_t clock_id,
			   enum hrtimer_mode mode)
{
	struct hrtimer_cpu_base *cpu_base;
	int base;

	// timer: &(&def_rt_bandwidth)->rt_period_timer, sizeof(struct hrtimer): 40 bytes
	// timer: &(&runqueues)->hrtick_timer, sizeof(struct hrtimer): 40 bytes
	// timer: &sched_clock_timer, sizeof(struct hrtimer): 40 bytes
	memset(timer, 0, sizeof(struct hrtimer));

	// (&def_rt_bandwidth)->rt_period_timer의 값을 0으로 초기화
	// (&runqueues)->hrtick_timer의 값을 0으로 초기화
	// sched_clock_timer의 값을 0으로 초기화

	// __raw_get_cpu_var(hrtimer_bases):
	// *({
	//  	do {
	// 	 	const void __percpu *__vpp_verify = (typeof((&(hrtimer_bases))))NULL;
	// 	 	(void)__vpp_verify;
	//  	} while (0)
	//  	&(hrtimer_bases) + __my_cpu_offset;
	// })
	cpu_base = &__raw_get_cpu_var(hrtimer_bases);
	// cpu_base:
	// ({
	//  	do {
	// 	 	const void __percpu *__vpp_verify = (typeof((&(hrtimer_bases))))NULL;
	// 	 	(void)__vpp_verify;
	//  	} while (0)
	//  	&(hrtimer_bases) + __my_cpu_offset;
	// })

	// clock_id: 1, CLOCK_REALTIME: 0, mode: 1, HRTIMER_MODE_ABS: 0
	// clock_id: 1, CLOCK_REALTIME: 0, mode: 1, HRTIMER_MODE_ABS: 0
	// clock_id: 1, CLOCK_REALTIME: 0, mode: 1, HRTIMER_MODE_ABS: 0
	if (clock_id == CLOCK_REALTIME && mode != HRTIMER_MODE_ABS)
		clock_id = CLOCK_MONOTONIC;

	// clock_id: 1, hrtimer_clockid_to_base(1): 0
	// clock_id: 1, hrtimer_clockid_to_base(1): 0
	// clock_id: 1, hrtimer_clockid_to_base(1): 0
	base = hrtimer_clockid_to_base(clock_id);
	// base: 0
	// base: 0
	// base: 0

	// timer->base: (&(&def_rt_bandwidth)->rt_period_timer)->base,
	// base: 0, &cpu_base->clock_base: [pcp0] &(&hrtimer_bases)->clock_base
	// timer->base: (&(&runqueues)->hrtick_timer)->base,
	// base: 0, &cpu_base->clock_base: [pcp0] &(&hrtimer_bases)->clock_base
	// timer->base: (&sched_clock_timer)->base,
	// base: 0, &cpu_base->clock_base: [pcp0] &(&hrtimer_bases)->clock_base
	timer->base = &cpu_base->clock_base[base];
	// timer->base: (&(&def_rt_bandwidth)->rt_period_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// timer->base: (&(&runqueues)->hrtick_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// timer->base: (&sched_clock_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]

	// &timer->node: &(&(&def_rt_bandwidth)->rt_period_timer)->node
	// &timer->node: &(&(&runqueues)->hrtick_timer)->node
	// &timer->node: &(&sched_clock_timer)->node
	timerqueue_init(&timer->node);

	// timerqueue_init에서 한일:
	// RB Tree의 (&(&(&def_rt_bandwidth)->rt_period_timer)->node)->node 를 초기화

	// timerqueue_init에서 한일:
	// RB Tree의 &(&(&runqueues)->hrtick_timer)->node 를 초기화

	// timerqueue_init에서 한일:
	// RB Tree의 &(&sched_clock_timer)->node 를 초기화

#ifdef CONFIG_TIMER_STATS // CONFIG_TIMER_STATS=n
	timer->start_site = NULL;
	timer->start_pid = -1;
	memset(timer->start_comm, 0, TASK_COMM_LEN);
#endif
}

/**
 * hrtimer_init - initialize a timer to the given clock
 * @timer:	the timer to be initialized
 * @clock_id:	the clock to be used
 * @mode:	timer mode abs/rel
 */
// ARM10C 20140830
// &rt_b->rt_period_timer: &(&def_rt_bandwidth)->rt_period_timer,
// CLOCK_MONOTONIC: 1, HRTIMER_MODE_REL: 1
// ARM10C 20140913
// &rq->hrtick_timer: &(&runqueues)->hrtick_timer, CLOCK_MONOTONIC: 1, HRTIMER_MODE_REL: 1
// ARM10C 20150530
// &sched_clock_timer, CLOCK_MONOTONIC: 1, HRTIMER_MODE_REL: 1
// ARM10C 20161105
// &sig->real_timer: &(kmem_cache#13-oX (struct signal_struct))->real_timer, CLOCK_MONOTONIC: 1, HRTIMER_MODE_REL: 1
void hrtimer_init(struct hrtimer *timer, clockid_t clock_id,
		  enum hrtimer_mode mode)
{
	// timer: &(&def_rt_bandwidth)->rt_period_timer, clock_id: 1, mode: 1
	// timer: &(&runqueues)->hrtick_timer, clock_id: 1, mode: 1
	// timer: &sched_clock_timer, clock_id: 1, mode: 1
	debug_init(timer, clock_id, mode);

	// timer: &(&def_rt_bandwidth)->rt_period_timer, clock_id: 1, mode: 1
	// timer: &(&runqueues)->hrtick_timer, clock_id: 1, mode: 1
	// timer: &sched_clock_timer, clock_id: 1, mode: 1
	__hrtimer_init(timer, clock_id, mode);

	// __hrtimer_init(rt_period_timer) 한일:
	// (&def_rt_bandwidth)->rt_period_timer의 값을 0으로 초기화
	// (&(&def_rt_bandwidth)->rt_period_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// RB Tree의 (&(&(&def_rt_bandwidth)->rt_period_timer)->node)->node 를 초기화

	// __hrtimer_init(hrtick_timer) 한일:
	// (&runqueues)->hrtick_timer의 값을 0으로 초기화
	// (&(&runqueues)->hrtick_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// RB Tree의 (&(&(&runqueues)->hrtick_timer)->node)->node 를 초기화

	// __hrtimer_init(sched_clock_timer) 한일:
	// sched_clock_timer의 값을 0으로 초기화
	// (&sched_clock_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// RB Tree의 &(&sched_clock_timer)->node 를 초기화
}
EXPORT_SYMBOL_GPL(hrtimer_init);

/**
 * hrtimer_get_res - get the timer resolution for a clock
 * @which_clock: which clock to query
 * @tp:		 pointer to timespec variable to store the resolution
 *
 * Store the resolution of the clock selected by @which_clock in the
 * variable pointed to by @tp.
 */
int hrtimer_get_res(const clockid_t which_clock, struct timespec *tp)
{
	struct hrtimer_cpu_base *cpu_base;
	int base = hrtimer_clockid_to_base(which_clock);

	cpu_base = &__raw_get_cpu_var(hrtimer_bases);
	*tp = ktime_to_timespec(cpu_base->clock_base[base].resolution);

	return 0;
}
EXPORT_SYMBOL_GPL(hrtimer_get_res);

static void __run_hrtimer(struct hrtimer *timer, ktime_t *now)
{
	struct hrtimer_clock_base *base = timer->base;
	struct hrtimer_cpu_base *cpu_base = base->cpu_base;
	enum hrtimer_restart (*fn)(struct hrtimer *);
	int restart;

	WARN_ON(!irqs_disabled());

	debug_deactivate(timer);
	__remove_hrtimer(timer, base, HRTIMER_STATE_CALLBACK, 0);
	timer_stats_account_hrtimer(timer);
	fn = timer->function;

	/*
	 * Because we run timers from hardirq context, there is no chance
	 * they get migrated to another cpu, therefore its safe to unlock
	 * the timer base.
	 */
	raw_spin_unlock(&cpu_base->lock);
	trace_hrtimer_expire_entry(timer, now);
	restart = fn(timer);
	trace_hrtimer_expire_exit(timer);
	raw_spin_lock(&cpu_base->lock);

	/*
	 * Note: We clear the CALLBACK bit after enqueue_hrtimer and
	 * we do not reprogramm the event hardware. Happens either in
	 * hrtimer_start_range_ns() or in hrtimer_interrupt()
	 */
	if (restart != HRTIMER_NORESTART) {
		BUG_ON(timer->state != HRTIMER_STATE_CALLBACK);
		enqueue_hrtimer(timer, base);
	}

	WARN_ON_ONCE(!(timer->state & HRTIMER_STATE_CALLBACK));

	timer->state &= ~HRTIMER_STATE_CALLBACK;
}

#ifdef CONFIG_HIGH_RES_TIMERS

/*
 * High resolution timer interrupt
 * Called with interrupts disabled
 */
void hrtimer_interrupt(struct clock_event_device *dev)
{
	struct hrtimer_cpu_base *cpu_base = &__get_cpu_var(hrtimer_bases);
	ktime_t expires_next, now, entry_time, delta;
	int i, retries = 0;

	BUG_ON(!cpu_base->hres_active);
	cpu_base->nr_events++;
	dev->next_event.tv64 = KTIME_MAX;

	raw_spin_lock(&cpu_base->lock);
	entry_time = now = hrtimer_update_base(cpu_base);
retry:
	expires_next.tv64 = KTIME_MAX;
	/*
	 * We set expires_next to KTIME_MAX here with cpu_base->lock
	 * held to prevent that a timer is enqueued in our queue via
	 * the migration code. This does not affect enqueueing of
	 * timers which run their callback and need to be requeued on
	 * this CPU.
	 */
	cpu_base->expires_next.tv64 = KTIME_MAX;

	for (i = 0; i < HRTIMER_MAX_CLOCK_BASES; i++) {
		struct hrtimer_clock_base *base;
		struct timerqueue_node *node;
		ktime_t basenow;

		if (!(cpu_base->active_bases & (1 << i)))
			continue;

		base = cpu_base->clock_base + i;
		basenow = ktime_add(now, base->offset);

		while ((node = timerqueue_getnext(&base->active))) {
			struct hrtimer *timer;

			timer = container_of(node, struct hrtimer, node);

			/*
			 * The immediate goal for using the softexpires is
			 * minimizing wakeups, not running timers at the
			 * earliest interrupt after their soft expiration.
			 * This allows us to avoid using a Priority Search
			 * Tree, which can answer a stabbing querry for
			 * overlapping intervals and instead use the simple
			 * BST we already have.
			 * We don't add extra wakeups by delaying timers that
			 * are right-of a not yet expired timer, because that
			 * timer will have to trigger a wakeup anyway.
			 */

			if (basenow.tv64 < hrtimer_get_softexpires_tv64(timer)) {
				ktime_t expires;

				expires = ktime_sub(hrtimer_get_expires(timer),
						    base->offset);
				if (expires.tv64 < 0)
					expires.tv64 = KTIME_MAX;
				if (expires.tv64 < expires_next.tv64)
					expires_next = expires;
				break;
			}

			__run_hrtimer(timer, &basenow);
		}
	}

	/*
	 * Store the new expiry value so the migration code can verify
	 * against it.
	 */
	cpu_base->expires_next = expires_next;
	raw_spin_unlock(&cpu_base->lock);

	/* Reprogramming necessary ? */
	if (expires_next.tv64 == KTIME_MAX ||
	    !tick_program_event(expires_next, 0)) {
		cpu_base->hang_detected = 0;
		return;
	}

	/*
	 * The next timer was already expired due to:
	 * - tracing
	 * - long lasting callbacks
	 * - being scheduled away when running in a VM
	 *
	 * We need to prevent that we loop forever in the hrtimer
	 * interrupt routine. We give it 3 attempts to avoid
	 * overreacting on some spurious event.
	 *
	 * Acquire base lock for updating the offsets and retrieving
	 * the current time.
	 */
	raw_spin_lock(&cpu_base->lock);
	now = hrtimer_update_base(cpu_base);
	cpu_base->nr_retries++;
	if (++retries < 3)
		goto retry;
	/*
	 * Give the system a chance to do something else than looping
	 * here. We stored the entry time, so we know exactly how long
	 * we spent here. We schedule the next event this amount of
	 * time away.
	 */
	cpu_base->nr_hangs++;
	cpu_base->hang_detected = 1;
	raw_spin_unlock(&cpu_base->lock);
	delta = ktime_sub(now, entry_time);
	if (delta.tv64 > cpu_base->max_hang_time.tv64)
		cpu_base->max_hang_time = delta;
	/*
	 * Limit it to a sensible value as we enforce a longer
	 * delay. Give the CPU at least 100ms to catch up.
	 */
	if (delta.tv64 > 100 * NSEC_PER_MSEC)
		expires_next = ktime_add_ns(now, 100 * NSEC_PER_MSEC);
	else
		expires_next = ktime_add(now, delta);
	tick_program_event(expires_next, 1);
	printk_once(KERN_WARNING "hrtimer: interrupt took %llu ns\n",
		    ktime_to_ns(delta));
}

/*
 * local version of hrtimer_peek_ahead_timers() called with interrupts
 * disabled.
 */
static void __hrtimer_peek_ahead_timers(void)
{
	struct tick_device *td;

	if (!hrtimer_hres_active())
		return;

	td = &__get_cpu_var(tick_cpu_device);
	if (td && td->evtdev)
		hrtimer_interrupt(td->evtdev);
}

/**
 * hrtimer_peek_ahead_timers -- run soft-expired timers now
 *
 * hrtimer_peek_ahead_timers will peek at the timer queue of
 * the current cpu and check if there are any timers for which
 * the soft expires time has passed. If any such timers exist,
 * they are run immediately and then removed from the timer queue.
 *
 */
void hrtimer_peek_ahead_timers(void)
{
	unsigned long flags;

	local_irq_save(flags);
	__hrtimer_peek_ahead_timers();
	local_irq_restore(flags);
}

// ARM10C 20150103
static void run_hrtimer_softirq(struct softirq_action *h)
{
	hrtimer_peek_ahead_timers();
}

#else /* CONFIG_HIGH_RES_TIMERS */

static inline void __hrtimer_peek_ahead_timers(void) { }

#endif	/* !CONFIG_HIGH_RES_TIMERS */

/*
 * Called from timer softirq every jiffy, expire hrtimers:
 *
 * For HRT its the fall back code to run the softirq in the timer
 * softirq context in case the hrtimer initialization failed or has
 * not been done yet.
 */
void hrtimer_run_pending(void)
{
	if (hrtimer_hres_active())
		return;

	/*
	 * This _is_ ugly: We have to check in the softirq context,
	 * whether we can switch to highres and / or nohz mode. The
	 * clocksource switch happens in the timer interrupt with
	 * xtime_lock held. Notification from there only sets the
	 * check bit in the tick_oneshot code, otherwise we might
	 * deadlock vs. xtime_lock.
	 */
	if (tick_check_oneshot_change(!hrtimer_is_hres_enabled()))
		hrtimer_switch_to_hres();
}

/*
 * Called from hardirq context every jiffy
 */
void hrtimer_run_queues(void)
{
	struct timerqueue_node *node;
	struct hrtimer_cpu_base *cpu_base = &__get_cpu_var(hrtimer_bases);
	struct hrtimer_clock_base *base;
	int index, gettime = 1;

	if (hrtimer_hres_active())
		return;

	for (index = 0; index < HRTIMER_MAX_CLOCK_BASES; index++) {
		base = &cpu_base->clock_base[index];
		if (!timerqueue_getnext(&base->active))
			continue;

		if (gettime) {
			hrtimer_get_softirq_time(cpu_base);
			gettime = 0;
		}

		raw_spin_lock(&cpu_base->lock);

		while ((node = timerqueue_getnext(&base->active))) {
			struct hrtimer *timer;

			timer = container_of(node, struct hrtimer, node);
			if (base->softirq_time.tv64 <=
					hrtimer_get_expires_tv64(timer))
				break;

			__run_hrtimer(timer, &base->softirq_time);
		}
		raw_spin_unlock(&cpu_base->lock);
	}
}

/*
 * Sleep related functions:
 */
static enum hrtimer_restart hrtimer_wakeup(struct hrtimer *timer)
{
	struct hrtimer_sleeper *t =
		container_of(timer, struct hrtimer_sleeper, timer);
	struct task_struct *task = t->task;

	t->task = NULL;
	if (task)
		wake_up_process(task);

	return HRTIMER_NORESTART;
}

void hrtimer_init_sleeper(struct hrtimer_sleeper *sl, struct task_struct *task)
{
	sl->timer.function = hrtimer_wakeup;
	sl->task = task;
}
EXPORT_SYMBOL_GPL(hrtimer_init_sleeper);

static int __sched do_nanosleep(struct hrtimer_sleeper *t, enum hrtimer_mode mode)
{
	hrtimer_init_sleeper(t, current);

	do {
		set_current_state(TASK_INTERRUPTIBLE);
		hrtimer_start_expires(&t->timer, mode);
		if (!hrtimer_active(&t->timer))
			t->task = NULL;

		if (likely(t->task))
			freezable_schedule();

		hrtimer_cancel(&t->timer);
		mode = HRTIMER_MODE_ABS;

	} while (t->task && !signal_pending(current));

	__set_current_state(TASK_RUNNING);

	return t->task == NULL;
}

static int update_rmtp(struct hrtimer *timer, struct timespec __user *rmtp)
{
	struct timespec rmt;
	ktime_t rem;

	rem = hrtimer_expires_remaining(timer);
	if (rem.tv64 <= 0)
		return 0;
	rmt = ktime_to_timespec(rem);

	if (copy_to_user(rmtp, &rmt, sizeof(*rmtp)))
		return -EFAULT;

	return 1;
}

long __sched hrtimer_nanosleep_restart(struct restart_block *restart)
{
	struct hrtimer_sleeper t;
	struct timespec __user  *rmtp;
	int ret = 0;

	hrtimer_init_on_stack(&t.timer, restart->nanosleep.clockid,
				HRTIMER_MODE_ABS);
	hrtimer_set_expires_tv64(&t.timer, restart->nanosleep.expires);

	if (do_nanosleep(&t, HRTIMER_MODE_ABS))
		goto out;

	rmtp = restart->nanosleep.rmtp;
	if (rmtp) {
		ret = update_rmtp(&t.timer, rmtp);
		if (ret <= 0)
			goto out;
	}

	/* The other values in restart are already filled in */
	ret = -ERESTART_RESTARTBLOCK;
out:
	destroy_hrtimer_on_stack(&t.timer);
	return ret;
}

long hrtimer_nanosleep(struct timespec *rqtp, struct timespec __user *rmtp,
		       const enum hrtimer_mode mode, const clockid_t clockid)
{
	struct restart_block *restart;
	struct hrtimer_sleeper t;
	int ret = 0;
	unsigned long slack;

	slack = current->timer_slack_ns;
	if (rt_task(current))
		slack = 0;

	hrtimer_init_on_stack(&t.timer, clockid, mode);
	hrtimer_set_expires_range_ns(&t.timer, timespec_to_ktime(*rqtp), slack);
	if (do_nanosleep(&t, mode))
		goto out;

	/* Absolute timers do not update the rmtp value and restart: */
	if (mode == HRTIMER_MODE_ABS) {
		ret = -ERESTARTNOHAND;
		goto out;
	}

	if (rmtp) {
		ret = update_rmtp(&t.timer, rmtp);
		if (ret <= 0)
			goto out;
	}

	restart = &current_thread_info()->restart_block;
	restart->fn = hrtimer_nanosleep_restart;
	restart->nanosleep.clockid = t.timer.base->clockid;
	restart->nanosleep.rmtp = rmtp;
	restart->nanosleep.expires = hrtimer_get_expires_tv64(&t.timer);

	ret = -ERESTART_RESTARTBLOCK;
out:
	destroy_hrtimer_on_stack(&t.timer);
	return ret;
}

SYSCALL_DEFINE2(nanosleep, struct timespec __user *, rqtp,
		struct timespec __user *, rmtp)
{
	struct timespec tu;

	if (copy_from_user(&tu, rqtp, sizeof(tu)))
		return -EFAULT;

	if (!timespec_valid(&tu))
		return -EINVAL;

	return hrtimer_nanosleep(&tu, rmtp, HRTIMER_MODE_REL, CLOCK_MONOTONIC);
}

/*
 * Functions related to boot-time initialization:
 */
// ARM10C 20150103
// scpu: 0
static void init_hrtimers_cpu(int cpu)
{
	// cpu: 0, &per_cpu(hrtimer_bases, 0): [pcp0] &hrtimer_bases
	struct hrtimer_cpu_base *cpu_base = &per_cpu(hrtimer_bases, cpu);
	// cpu_base: [pcp0] &hrtimer_bases

	int i;

	// HRTIMER_MAX_CLOCK_BASES: 4
	for (i = 0; i < HRTIMER_MAX_CLOCK_BASES; i++) {
		// i: 0, cpu_base->clock_base[0].cpu_base: [pcp0] (&hrtimer_bases)->clock_base[0].cpu_base
		// cpu_base: [pcp0] &hrtimer_bases
		cpu_base->clock_base[i].cpu_base = cpu_base;
		// cpu_base->clock_base[0].cpu_base: [pcp0] (&hrtimer_bases)->clock_base[0].cpu_base: [pcp0] &hrtimer_bases

		// &cpu_base->clock_base[i].active: [pcp0] &(&hrtimer_bases)->clock_base[0].active
		timerqueue_init_head(&cpu_base->clock_base[i].active);

		// timerqueue_init_head에서 한일:
		// [pcp0] (&(&hrtimer_bases)->clock_base[0].active)->head: NULL
		// [pcp0] (&(&hrtimer_bases)->clock_base[0].active)->next: NULL
		
		// i: 1...3 루프 수행
	}

	// cpu_base: [pcp0] &hrtimer_bases
	hrtimer_init_hres(cpu_base);

	// hrtimer_init_hres에서 한일:
	// [pcp0] (&hrtimer_bases)->expires_next.tv64: 0x7FFFFFFFFFFFFFFF
	// [pcp0] (&hrtimer_bases)->hres_active: 0
}

#ifdef CONFIG_HOTPLUG_CPU

static void migrate_hrtimer_list(struct hrtimer_clock_base *old_base,
				struct hrtimer_clock_base *new_base)
{
	struct hrtimer *timer;
	struct timerqueue_node *node;

	while ((node = timerqueue_getnext(&old_base->active))) {
		timer = container_of(node, struct hrtimer, node);
		BUG_ON(hrtimer_callback_running(timer));
		debug_deactivate(timer);

		/*
		 * Mark it as STATE_MIGRATE not INACTIVE otherwise the
		 * timer could be seen as !active and just vanish away
		 * under us on another CPU
		 */
		__remove_hrtimer(timer, old_base, HRTIMER_STATE_MIGRATE, 0);
		timer->base = new_base;
		/*
		 * Enqueue the timers on the new cpu. This does not
		 * reprogram the event device in case the timer
		 * expires before the earliest on this CPU, but we run
		 * hrtimer_interrupt after we migrated everything to
		 * sort out already expired timers and reprogram the
		 * event device.
		 */
		enqueue_hrtimer(timer, new_base);

		/* Clear the migration state bit */
		timer->state &= ~HRTIMER_STATE_MIGRATE;
	}
}

static void migrate_hrtimers(int scpu)
{
	struct hrtimer_cpu_base *old_base, *new_base;
	int i;

	BUG_ON(cpu_online(scpu));
	tick_cancel_sched_timer(scpu);

	local_irq_disable();
	old_base = &per_cpu(hrtimer_bases, scpu);
	new_base = &__get_cpu_var(hrtimer_bases);
	/*
	 * The caller is globally serialized and nobody else
	 * takes two locks at once, deadlock is not possible.
	 */
	raw_spin_lock(&new_base->lock);
	raw_spin_lock_nested(&old_base->lock, SINGLE_DEPTH_NESTING);

	for (i = 0; i < HRTIMER_MAX_CLOCK_BASES; i++) {
		migrate_hrtimer_list(&old_base->clock_base[i],
				     &new_base->clock_base[i]);
	}

	raw_spin_unlock(&old_base->lock);
	raw_spin_unlock(&new_base->lock);

	/* Check, if we got expired work to do */
	__hrtimer_peek_ahead_timers();
	local_irq_enable();
}

#endif /* CONFIG_HOTPLUG_CPU */

// ARM10C 20150103
// &hrtimers_nb, CPU_UP_PREPARE: 0x0003, smp_processor_id(): 0
static int hrtimer_cpu_notify(struct notifier_block *self,
					unsigned long action, void *hcpu)
{
	// hcpu: 0
	int scpu = (long)hcpu;
	// scpu: 0

	// action: CPU_UP_PREPARE: 0x0003
	switch (action) {

	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		// scpu: 0
		init_hrtimers_cpu(scpu);

		// init_hrtimers_cpu에서 한일:
		// [pcp0] (&hrtimer_bases)->clock_base[0...3].cpu_base: [pcp0] &hrtimer_bases
		// [pcp0] (&(&hrtimer_bases)->clock_base[0...3].active)->head: NULL
		// [pcp0] (&(&hrtimer_bases)->clock_base[0...3].active)->next: NULL
		// [pcp0] (&hrtimer_bases)->expires_next.tv64: 0x7FFFFFFFFFFFFFFF
		// [pcp0] (&hrtimer_bases)->hres_active: 0

		break;

#ifdef CONFIG_HOTPLUG_CPU
	case CPU_DYING:
	case CPU_DYING_FROZEN:
		clockevents_notify(CLOCK_EVT_NOTIFY_CPU_DYING, &scpu);
		break;
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
	{
		clockevents_notify(CLOCK_EVT_NOTIFY_CPU_DEAD, &scpu);
		migrate_hrtimers(scpu);
		break;
	}
#endif

	default:
		break;
	}

	return NOTIFY_OK;
}

// ARM10C 20150103
static struct notifier_block hrtimers_nb = {
	.notifier_call = hrtimer_cpu_notify,
};

// ARM10C 20150103
void __init hrtimers_init(void)
{
	// CPU_UP_PREPARE: 0x0003, smp_processor_id(): 0
	hrtimer_cpu_notify(&hrtimers_nb, (unsigned long)CPU_UP_PREPARE,
			  (void *)(long)smp_processor_id());

	// hrtimer_cpu_notify에서 한일:
	// [pcp0] (&hrtimer_bases)->clock_base[0...3].cpu_base: [pcp0] &hrtimer_bases
	// [pcp0] (&(&hrtimer_bases)->clock_base[0...3].active)->head: NULL
	// [pcp0] (&(&hrtimer_bases)->clock_base[0...3].active)->next: NULL
	// [pcp0] (&hrtimer_bases)->expires_next.tv64: 0x7FFFFFFFFFFFFFFF
	// [pcp0] (&hrtimer_bases)->hres_active: 0

	register_cpu_notifier(&hrtimers_nb);

	// register_cpu_notifier에서 한일:
	// (&cpu_chain)->head: &hrtimers_nb 포인터 대입
	// (&hrtimers_nb)->next은 (&timers_nb)->next로 대입

#ifdef CONFIG_HIGH_RES_TIMERS // CONFIG_HIGH_RES_TIMERS=y
	// HRTIMER_SOFTIRQ: 8
	open_softirq(HRTIMER_SOFTIRQ, run_hrtimer_softirq);

	// open_softirq에서 한일:
	// softirq_vec[8].action: run_hrtimer_softirq
#endif
}

/**
 * schedule_hrtimeout_range_clock - sleep until timeout
 * @expires:	timeout value (ktime_t)
 * @delta:	slack in expires timeout (ktime_t)
 * @mode:	timer mode, HRTIMER_MODE_ABS or HRTIMER_MODE_REL
 * @clock:	timer clock, CLOCK_MONOTONIC or CLOCK_REALTIME
 */
int __sched
schedule_hrtimeout_range_clock(ktime_t *expires, unsigned long delta,
			       const enum hrtimer_mode mode, int clock)
{
	struct hrtimer_sleeper t;

	/*
	 * Optimize when a zero timeout value is given. It does not
	 * matter whether this is an absolute or a relative time.
	 */
	if (expires && !expires->tv64) {
		__set_current_state(TASK_RUNNING);
		return 0;
	}

	/*
	 * A NULL parameter means "infinite"
	 */
	if (!expires) {
		schedule();
		__set_current_state(TASK_RUNNING);
		return -EINTR;
	}

	hrtimer_init_on_stack(&t.timer, clock, mode);
	hrtimer_set_expires_range_ns(&t.timer, *expires, delta);

	hrtimer_init_sleeper(&t, current);

	hrtimer_start_expires(&t.timer, mode);
	if (!hrtimer_active(&t.timer))
		t.task = NULL;

	if (likely(t.task))
		schedule();

	hrtimer_cancel(&t.timer);
	destroy_hrtimer_on_stack(&t.timer);

	__set_current_state(TASK_RUNNING);

	return !t.task ? 0 : -EINTR;
}

/**
 * schedule_hrtimeout_range - sleep until timeout
 * @expires:	timeout value (ktime_t)
 * @delta:	slack in expires timeout (ktime_t)
 * @mode:	timer mode, HRTIMER_MODE_ABS or HRTIMER_MODE_REL
 *
 * Make the current task sleep until the given expiry time has
 * elapsed. The routine will return immediately unless
 * the current task state has been set (see set_current_state()).
 *
 * The @delta argument gives the kernel the freedom to schedule the
 * actual wakeup to a time that is both power and performance friendly.
 * The kernel give the normal best effort behavior for "@expires+@delta",
 * but may decide to fire the timer earlier, but no earlier than @expires.
 *
 * You can set the task state as follows -
 *
 * %TASK_UNINTERRUPTIBLE - at least @timeout time is guaranteed to
 * pass before the routine returns.
 *
 * %TASK_INTERRUPTIBLE - the routine may return early if a signal is
 * delivered to the current task.
 *
 * The current task state is guaranteed to be TASK_RUNNING when this
 * routine returns.
 *
 * Returns 0 when the timer has expired otherwise -EINTR
 */
int __sched schedule_hrtimeout_range(ktime_t *expires, unsigned long delta,
				     const enum hrtimer_mode mode)
{
	return schedule_hrtimeout_range_clock(expires, delta, mode,
					      CLOCK_MONOTONIC);
}
EXPORT_SYMBOL_GPL(schedule_hrtimeout_range);

/**
 * schedule_hrtimeout - sleep until timeout
 * @expires:	timeout value (ktime_t)
 * @mode:	timer mode, HRTIMER_MODE_ABS or HRTIMER_MODE_REL
 *
 * Make the current task sleep until the given expiry time has
 * elapsed. The routine will return immediately unless
 * the current task state has been set (see set_current_state()).
 *
 * You can set the task state as follows -
 *
 * %TASK_UNINTERRUPTIBLE - at least @timeout time is guaranteed to
 * pass before the routine returns.
 *
 * %TASK_INTERRUPTIBLE - the routine may return early if a signal is
 * delivered to the current task.
 *
 * The current task state is guaranteed to be TASK_RUNNING when this
 * routine returns.
 *
 * Returns 0 when the timer has expired otherwise -EINTR
 */
int __sched schedule_hrtimeout(ktime_t *expires,
			       const enum hrtimer_mode mode)
{
	return schedule_hrtimeout_range(expires, 0, mode);
}
EXPORT_SYMBOL_GPL(schedule_hrtimeout);
