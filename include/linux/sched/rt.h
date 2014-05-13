#ifndef _SCHED_RT_H
#define _SCHED_RT_H

/*
 * Priority of a process goes from 0..MAX_PRIO-1, valid RT
 * priority is 0..MAX_RT_PRIO-1, and SCHED_NORMAL/SCHED_BATCH
 * tasks are in the range MAX_RT_PRIO..MAX_PRIO-1. Priority
 * values are inverted: lower p->prio value means higher priority.
 *
 * The MAX_USER_RT_PRIO value allows the actual maximum
 * RT priority to be separate from the value exported to
 * user-space.  This allows kernel threads to set their
 * priority to a value higher than any user task. Note:
 * MAX_RT_PRIO must not be smaller than MAX_USER_RT_PRIO.
 */

// ARM10C 20140510
#define MAX_USER_RT_PRIO	100
// ARM10C 20140510
// MAX_USER_RT_PRIO: 100
// MAX_RT_PRIO: 100
#define MAX_RT_PRIO		MAX_USER_RT_PRIO

// ARM10C 20140510
// MAX_RT_PRIO: 100
// MAX_PRIO: 140
#define MAX_PRIO		(MAX_RT_PRIO + 40)
#define DEFAULT_PRIO		(MAX_RT_PRIO + 20)

// ARM10C 20140510
// p->prio: init_task->prio: 120
static inline int rt_prio(int prio)
{
	// prio: 120, MAX_RT_PRIO: 100
	if (unlikely(prio < MAX_RT_PRIO))
		return 1;
	return 0;
}

// ARM10C 20140510
// tsk: init_task
static inline int rt_task(struct task_struct *p)
{
	// p->prio: init_task->prio: 120
	// rt_prio(120): 0
	return rt_prio(p->prio);
	// return 0
}

#ifdef CONFIG_RT_MUTEXES
extern int rt_mutex_getprio(struct task_struct *p);
extern void rt_mutex_setprio(struct task_struct *p, int prio);
extern void rt_mutex_adjust_pi(struct task_struct *p);
static inline bool tsk_is_pi_blocked(struct task_struct *tsk)
{
	return tsk->pi_blocked_on != NULL;
}
#else
static inline int rt_mutex_getprio(struct task_struct *p)
{
	return p->normal_prio;
}
# define rt_mutex_adjust_pi(p)		do { } while (0)
static inline bool tsk_is_pi_blocked(struct task_struct *tsk)
{
	return false;
}
#endif

extern void normalize_rt_tasks(void);


/*
 * default timeslice is 100 msecs (used only for SCHED_RR tasks).
 * Timeslices get refilled after they expire.
 */
#define RR_TIMESLICE		(100 * HZ / 1000)

#endif /* _SCHED_RT_H */
