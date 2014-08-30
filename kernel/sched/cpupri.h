#ifndef _LINUX_CPUPRI_H
#define _LINUX_CPUPRI_H

#include <linux/sched.h>

// ARM10C 20140830
// MAX_RT_PRIO: 100
// CPUPRI_NR_PRIORITIES: 102
#define CPUPRI_NR_PRIORITIES	(MAX_RT_PRIO + 2)

// ARM10C 20140830
#define CPUPRI_INVALID -1
#define CPUPRI_IDLE     0
#define CPUPRI_NORMAL   1
/* values 2-101 are RT priorities 0-99 */

// ARM10C 20140830
// sizeof(struct cpupri_vec): 8 bytes
struct cpupri_vec {
	atomic_t	count;
	cpumask_var_t	mask;
};

// ARM10C 20140830
// CPUPRI_NR_PRIORITIES: 102
// NR_CPUS: 4
// sizeof(struct cpupri): 832 bytes
struct cpupri {
	struct cpupri_vec pri_to_cpu[CPUPRI_NR_PRIORITIES];
	int               cpu_to_pri[NR_CPUS];
};

#ifdef CONFIG_SMP // CONFIG_SMP=y
int  cpupri_find(struct cpupri *cp,
		 struct task_struct *p, struct cpumask *lowest_mask);
void cpupri_set(struct cpupri *cp, int cpu, int pri);
// ARM10C 20140830
// &rd->cpupri: &def_root_domain->cpupri
int cpupri_init(struct cpupri *cp);
void cpupri_cleanup(struct cpupri *cp);
#else
#define cpupri_set(cp, cpu, pri) do { } while (0)
#define cpupri_init() do { } while (0)
#endif

#endif /* _LINUX_CPUPRI_H */
