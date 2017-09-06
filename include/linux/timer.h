#ifndef _LINUX_TIMER_H
#define _LINUX_TIMER_H

#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/stddef.h>
#include <linux/debugobjects.h>
#include <linux/stringify.h>

struct tvec_base;

// ARM10C 20150704
// ARM10C 20170906
// sizeof(struct timer_list): 28 bytes
struct timer_list {
	/*
	 * All fields that change during normal runtime grouped to the
	 * same cacheline
	 */
	struct list_head entry;
	unsigned long expires;
	struct tvec_base *base;

	void (*function)(unsigned long);
	unsigned long data;

	int slack;

#ifdef CONFIG_TIMER_STATS // CONFIG_TIMER_STATS=n
	int start_pid;
	void *start_site;
	char start_comm[16];
#endif
#ifdef CONFIG_LOCKDEP // CONFIG_LOCKDEP=n
	struct lockdep_map lockdep_map;
#endif
};

extern struct tvec_base boot_tvec_bases;

#ifdef CONFIG_LOCKDEP // CONFIG_LOCKDEP=n
/*
 * NB: because we have to copy the lockdep_map, setting the lockdep_map key
 * (second argument) here is required, otherwise it could be initialised to
 * the copy of the lockdep_map later! We use the pointer to and the string
 * "<file>:<line>" as the key resp. the name of the lockdep_map.
 */
#define __TIMER_LOCKDEP_MAP_INITIALIZER(_kn)				\
	.lockdep_map = STATIC_LOCKDEP_MAP_INIT(_kn, &_kn),
#else
// ARM10C 20150704
// #define __TIMER_LOCKDEP_MAP_INITIALIZER(__FILE__ ":" __stringify(__LINE__)):
#define __TIMER_LOCKDEP_MAP_INITIALIZER(_kn)
#endif

/*
 * Note that all tvec_bases are at least 4 byte aligned and lower two bits
 * of base in timer_list is guaranteed to be zero. Use them for flags.
 *
 * A deferrable timer will work normally when the system is busy, but
 * will not cause a CPU to come out of idle just to service it; instead,
 * the timer will be serviced when the CPU eventually wakes up with a
 * subsequent non-deferrable timer.
 *
 * An irqsafe timer is executed with IRQ disabled and it's safe to wait for
 * the completion of the running instance from IRQ handlers, for example,
 * by calling del_timer_sync().
 *
 * Note: The irq disabled callback execution is a special case for
 * workqueue locking issues. It's not meant for executing random crap
 * with interrupts disabled. Abuse is monitored!
 */
// ARM10C 20150711
// TIMER_DEFERRABLE: 0x1
#define TIMER_DEFERRABLE		0x1LU
// ARM10C 20151031
// TIMER_IRQSAFE: 0x2
#define TIMER_IRQSAFE			0x2LU

// ARM10C 20150103
// ARM10C 20150711
// TIMER_FLAG_MASK: 0x3LU
#define TIMER_FLAG_MASK			0x3LU

// ARM10C 20150704
// TIMER_ENTRY_STATIC: ((void *) 0x74737461)
// __TIMER_LOCKDEP_MAP_INITIALIZER(__FILE__ ":" __stringify(__LINE__)):
//
// #define __TIMER_INITIALIZER((blank_screen_t), (0), (0), 0):
// {
//     .entry = { .prev = ((void *) 0x74737461) },
//     .function = (blank_screen_t),
//     .expires = (0),
//     .data = (0),
//     .base = (void *)((unsigned long)&boot_tvec_bases + (0)),
//     .slack = -1
// }
#define __TIMER_INITIALIZER(_function, _expires, _data, _flags) { \
		.entry = { .prev = TIMER_ENTRY_STATIC },	\
		.function = (_function),			\
		.expires = (_expires),				\
		.data = (_data),				\
		.base = (void *)((unsigned long)&boot_tvec_bases + (_flags)), \
		.slack = -1,					\
		__TIMER_LOCKDEP_MAP_INITIALIZER(		\
			__FILE__ ":" __stringify(__LINE__))	\
	}

// ARM10C 20150704
// __TIMER_INITIALIZER((blank_screen_t), (0), (0), 0):
// {
//     .entry = { .prev = ((void *) 0x74737461) },
//     .function = (blank_screen_t),
//     .expires = (0),
//     .data = (0),
//     .base = (void *)((unsigned long)&boot_tvec_bases + (0)),
//     .slack = -1
// }
//
// #define TIMER_INITIALIZER(blank_screen_t, 0, 0):
// {
//     .entry = { .prev = ((void *) 0x74737461) },
//     .function = (blank_screen_t),
//     .expires = (0),
//     .data = (0),
//     .base = (void *)((unsigned long)&boot_tvec_bases + (0)),
//     .slack = -1
// }
#define TIMER_INITIALIZER(_function, _expires, _data)		\
	__TIMER_INITIALIZER((_function), (_expires), (_data), 0)

#define TIMER_DEFERRED_INITIALIZER(_function, _expires, _data)	\
	__TIMER_INITIALIZER((_function), (_expires), (_data), TIMER_DEFERRABLE)

// ARM10C 20150704
// TIMER_INITIALIZER(blank_screen_t, 0, 0):
// {
//     .entry = { .prev = ((void *) 0x74737461) },
//     .function = (blank_screen_t),
//     .expires = (0),
//     .data = (0),
//     .base = (void *)((unsigned long)&boot_tvec_bases + (0)),
//     .slack = -1
// }
//
// #define DEFINE_TIMER(console_timer, blank_screen_t, 0, 0):
// struct timer_list console_timer =
// {
//     .entry = { .prev = ((void *) 0x74737461) },
//     .function = (blank_screen_t),
//     .expires = (0),
//     .data = (0),
//     .base = (void *)((unsigned long)&boot_tvec_bases + (0)),
//     .slack = -1
// }
#define DEFINE_TIMER(_name, _function, _expires, _data)		\
	struct timer_list _name =				\
		TIMER_INITIALIZER(_function, _expires, _data)

void init_timer_key(struct timer_list *timer, unsigned int flags,
		    const char *name, struct lock_class_key *key);

#ifdef CONFIG_DEBUG_OBJECTS_TIMERS
extern void init_timer_on_stack_key(struct timer_list *timer,
				    unsigned int flags, const char *name,
				    struct lock_class_key *key);
extern void destroy_timer_on_stack(struct timer_list *timer);
#else
static inline void destroy_timer_on_stack(struct timer_list *timer) { }
static inline void init_timer_on_stack_key(struct timer_list *timer,
					   unsigned int flags, const char *name,
					   struct lock_class_key *key)
{
	init_timer_key(timer, flags, name, key);
}
#endif

#ifdef CONFIG_LOCKDEP // CONFIG_LOCKDEP=n
#define __init_timer(_timer, _flags)					\
	do {								\
		static struct lock_class_key __key;			\
		init_timer_key((_timer), (_flags), #_timer, &__key);	\
	} while (0)

#define __init_timer_on_stack(_timer, _flags)				\
	do {								\
		static struct lock_class_key __key;			\
		init_timer_on_stack_key((_timer), (_flags), #_timer, &__key); \
	} while (0)
#else
// ARM10C 20151031
// #define __init_timer((&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->timer), ((0) | TIMER_IRQSAFE)):
// init_timer_key(((&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->timer)), (((0) | TIMER_IRQSAFE)), NULL, NULL)
#define __init_timer(_timer, _flags)					\
	init_timer_key((_timer), (_flags), NULL, NULL)
#define __init_timer_on_stack(_timer, _flags)				\
	init_timer_on_stack_key((_timer), (_flags), NULL, NULL)
#endif

#define init_timer(timer)						\
	__init_timer((timer), 0)
#define init_timer_deferrable(timer)					\
	__init_timer((timer), TIMER_DEFERRABLE)
#define init_timer_on_stack(timer)					\
	__init_timer_on_stack((timer), 0)

// ARM10C 20151031
// __init_timer((&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->timer), ((0) | TIMER_IRQSAFE)):
// init_timer_key(((&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->timer)), (((0) | TIMER_IRQSAFE)), NULL, NULL)
//
// #define __setup_timer(&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->timer, delayed_work_timer_fn, (unsigned long)(&(&(&sysfs_backing_dev_info)->wb)->dwork), (0) | TIMER_IRQSAFE):
// do {
//      init_timer_key(((&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->timer)), (((0) | TIMER_IRQSAFE)), NULL, NULL)
//      (&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->timer)->function = (delayed_work_timer_fn);
//      (&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->timer)->data = ((unsigned long)(&(&(&sysfs_backing_dev_info)->wb)->dwork));
// } while (0)
#define __setup_timer(_timer, _fn, _data, _flags)			\
	do {								\
		__init_timer((_timer), (_flags));			\
		(_timer)->function = (_fn);				\
		(_timer)->data = (_data);				\
	} while (0)

#define __setup_timer_on_stack(_timer, _fn, _data, _flags)		\
	do {								\
		__init_timer_on_stack((_timer), (_flags));		\
		(_timer)->function = (_fn);				\
		(_timer)->data = (_data);				\
	} while (0)

#define setup_timer(timer, fn, data)					\
	__setup_timer((timer), (fn), (data), 0)
#define setup_timer_on_stack(timer, fn, data)				\
	__setup_timer_on_stack((timer), (fn), (data), 0)
#define setup_deferrable_timer_on_stack(timer, fn, data)		\
	__setup_timer_on_stack((timer), (fn), (data), TIMER_DEFERRABLE)

/**
 * timer_pending - is a timer pending?
 * @timer: the timer in question
 *
 * timer_pending will tell whether a given timer is currently pending,
 * or not. Callers must ensure serialization wrt. other operations done
 * to this timer, eg. interrupt contexts, or other CPUs on SMP.
 *
 * return value: 1 if the timer is pending, 0 if not.
 */
// ARM10C 20150711
// timer: &console_timer
static inline int timer_pending(const struct timer_list * timer)
{
	// timer->entry.next: (&console_timer)->entry.next: NULL
	return timer->entry.next != NULL;
	// return 0
}

extern void add_timer_on(struct timer_list *timer, int cpu);
extern int del_timer(struct timer_list * timer);
extern int mod_timer(struct timer_list *timer, unsigned long expires);
extern int mod_timer_pending(struct timer_list *timer, unsigned long expires);
extern int mod_timer_pinned(struct timer_list *timer, unsigned long expires);

extern void set_timer_slack(struct timer_list *time, int slack_hz);

// ARM10C 20150711
// TIMER_NOT_PINNED: 0
#define TIMER_NOT_PINNED	0
#define TIMER_PINNED		1
/*
 * The jiffies value which is added to now, when there is no timer
 * in the timer wheel:
 */
#define NEXT_TIMER_MAX_DELTA	((1UL << 30) - 1)

/*
 * Return when the next timer-wheel timeout occurs (in absolute jiffies),
 * locks the timer base and does the comparison against the given
 * jiffie.
 */
extern unsigned long get_next_timer_interrupt(unsigned long now);

/*
 * Timer-statistics info:
 */
#ifdef CONFIG_TIMER_STATS // CONFIG_TIMER_STATS=n

extern int timer_stats_active;

#define TIMER_STATS_FLAG_DEFERRABLE	0x1

extern void init_timer_stats(void);

extern void timer_stats_update_stats(void *timer, pid_t pid, void *startf,
				     void *timerf, char *comm,
				     unsigned int timer_flag);

extern void __timer_stats_timer_set_start_info(struct timer_list *timer,
					       void *addr);

static inline void timer_stats_timer_set_start_info(struct timer_list *timer)
{
	if (likely(!timer_stats_active))
		return;
	__timer_stats_timer_set_start_info(timer, __builtin_return_address(0));
}

static inline void timer_stats_timer_clear_start_info(struct timer_list *timer)
{
	timer->start_site = NULL;
}
#else
// ARM10C 20150103
static inline void init_timer_stats(void)
{
}

// ARM10C 20150711
// timer: &console_timer
static inline void timer_stats_timer_set_start_info(struct timer_list *timer)
{
}

static inline void timer_stats_timer_clear_start_info(struct timer_list *timer)
{
}
#endif

extern void add_timer(struct timer_list *timer);

extern int try_to_del_timer_sync(struct timer_list *timer);

#ifdef CONFIG_SMP
  extern int del_timer_sync(struct timer_list *timer);
#else
# define del_timer_sync(t)		del_timer(t)
#endif

#define del_singleshot_timer_sync(t) del_timer_sync(t)

extern void init_timers(void);
extern void run_local_timers(void);
struct hrtimer;
extern enum hrtimer_restart it_real_fn(struct hrtimer *);

unsigned long __round_jiffies(unsigned long j, int cpu);
unsigned long __round_jiffies_relative(unsigned long j, int cpu);
unsigned long round_jiffies(unsigned long j);
unsigned long round_jiffies_relative(unsigned long j);

unsigned long __round_jiffies_up(unsigned long j, int cpu);
unsigned long __round_jiffies_up_relative(unsigned long j, int cpu);
unsigned long round_jiffies_up(unsigned long j);
unsigned long round_jiffies_up_relative(unsigned long j);

#endif
