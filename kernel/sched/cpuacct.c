#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/cpumask.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <linux/kernel_stat.h>
#include <linux/err.h>

#include "sched.h"

/*
 * CPU accounting code for task groups.
 *
 * Based on the work by Paul Menage (menage@google.com) and Balbir Singh
 * (balbir@in.ibm.com).
 */

/* Time spent by the tasks of the cpu accounting group executing in ... */
enum cpuacct_stat_index {
	CPUACCT_STAT_USER,	/* ... user mode */
	CPUACCT_STAT_SYSTEM,	/* ... kernel mode */

	CPUACCT_STAT_NSTATS,
};

/* track cpu usage of a group of tasks and its child groups */
// ARM10C 20150822
// ARM10C 20170913
// ARM10C 20170913
struct cpuacct {
	struct cgroup_subsys_state css;
	/* cpuusage holds pointer to a u64-type object on every cpu */
	u64 __percpu *cpuusage;
	struct kernel_cpustat __percpu *cpustat;
};

// ARM10C 20170913
// &root_cpuacct.css
// ARM10C 20170913
// css_parent(&(&root_cpuacct)->css): NULL
static inline struct cpuacct *css_ca(struct cgroup_subsys_state *css)
{
	// css: &root_cpuacct.css, container_of(&root_cpuacct.css, struct cpuacct, css): &root_cpuacct
	// css: NULL
	return css ? container_of(css, struct cpuacct, css) : NULL;
	// return &root_cpuacct
	// return NULL
}

/* return cpu accounting group to which this task belongs */
// ARM10C 20170913
// tsk: kmem_cache#15-oX (struct task_struct) (pid: 1)
static inline struct cpuacct *task_ca(struct task_struct *tsk)
{
	// tsk: kmem_cache#15-oX (struct task_struct) (pid: 1), cpuacct_subsys_id: 2
	// task_css(kmem_cache#15-oX (struct task_struct) (pid: 1), 2): &root_cpuacct.css
	// css_ca(&root_cpuacct.css): &root_cpuacct
	return css_ca(task_css(tsk, cpuacct_subsys_id));
	// return &root_cpuacct
}

// ARM10C 20170913
// ca: &root_cpuacct
static inline struct cpuacct *parent_ca(struct cpuacct *ca)
{
	// &ca->css: &(&root_cpuacct)->css, css_parent(&(&root_cpuacct)->css): NULL
	// css_ca(NULL): NULL
	return css_ca(css_parent(&ca->css));
	// return NULL
}

// ARM10C 20170913
// DEFINE_PER_CPU(u64, root_cpuacct_cpuusage):
// __attribute__((section(".data..percpu" "")))
// __typeof__(u64) root_cpuacct_cpuusage
static DEFINE_PER_CPU(u64, root_cpuacct_cpuusage);
// ARM10C 20170913
static struct cpuacct root_cpuacct = {
	.cpustat	= &kernel_cpustat,
	.cpuusage	= &root_cpuacct_cpuusage,
};

/* create a new cpu accounting group */
// ARM10C 20150822
// (&cgroup_dummy_root.top_cgroup)->subsys[2]
static struct cgroup_subsys_state *
cpuacct_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct cpuacct *ca;

	// parent_css: (&cgroup_dummy_root.top_cgroup)->subsys[2]: NULL
	if (!parent_css)
		return &root_cpuacct.css;
		// return &root_cpuacct.css

	ca = kzalloc(sizeof(*ca), GFP_KERNEL);
	if (!ca)
		goto out;

	ca->cpuusage = alloc_percpu(u64);
	if (!ca->cpuusage)
		goto out_free_ca;

	ca->cpustat = alloc_percpu(struct kernel_cpustat);
	if (!ca->cpustat)
		goto out_free_cpuusage;

	return &ca->css;

out_free_cpuusage:
	free_percpu(ca->cpuusage);
out_free_ca:
	kfree(ca);
out:
	return ERR_PTR(-ENOMEM);
}

/* destroy an existing cpu accounting group */
// ARM10C 20150822
static void cpuacct_css_free(struct cgroup_subsys_state *css)
{
	struct cpuacct *ca = css_ca(css);

	free_percpu(ca->cpustat);
	free_percpu(ca->cpuusage);
	kfree(ca);
}

static u64 cpuacct_cpuusage_read(struct cpuacct *ca, int cpu)
{
	u64 *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);
	u64 data;

#ifndef CONFIG_64BIT
	/*
	 * Take rq->lock to make 64-bit read safe on 32-bit platforms.
	 */
	raw_spin_lock_irq(&cpu_rq(cpu)->lock);
	data = *cpuusage;
	raw_spin_unlock_irq(&cpu_rq(cpu)->lock);
#else
	data = *cpuusage;
#endif

	return data;
}

static void cpuacct_cpuusage_write(struct cpuacct *ca, int cpu, u64 val)
{
	u64 *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);

#ifndef CONFIG_64BIT
	/*
	 * Take rq->lock to make 64-bit write safe on 32-bit platforms.
	 */
	raw_spin_lock_irq(&cpu_rq(cpu)->lock);
	*cpuusage = val;
	raw_spin_unlock_irq(&cpu_rq(cpu)->lock);
#else
	*cpuusage = val;
#endif
}

/* return total cpu usage (in nanoseconds) of a group */
static u64 cpuusage_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct cpuacct *ca = css_ca(css);
	u64 totalcpuusage = 0;
	int i;

	for_each_present_cpu(i)
		totalcpuusage += cpuacct_cpuusage_read(ca, i);

	return totalcpuusage;
}

static int cpuusage_write(struct cgroup_subsys_state *css, struct cftype *cft,
			  u64 reset)
{
	struct cpuacct *ca = css_ca(css);
	int err = 0;
	int i;

	if (reset) {
		err = -EINVAL;
		goto out;
	}

	for_each_present_cpu(i)
		cpuacct_cpuusage_write(ca, i, 0);

out:
	return err;
}

static int cpuacct_percpu_seq_read(struct cgroup_subsys_state *css,
				   struct cftype *cft, struct seq_file *m)
{
	struct cpuacct *ca = css_ca(css);
	u64 percpu;
	int i;

	for_each_present_cpu(i) {
		percpu = cpuacct_cpuusage_read(ca, i);
		seq_printf(m, "%llu ", (unsigned long long) percpu);
	}
	seq_printf(m, "\n");
	return 0;
}

static const char * const cpuacct_stat_desc[] = {
	[CPUACCT_STAT_USER] = "user",
	[CPUACCT_STAT_SYSTEM] = "system",
};

static int cpuacct_stats_show(struct cgroup_subsys_state *css,
			      struct cftype *cft, struct cgroup_map_cb *cb)
{
	struct cpuacct *ca = css_ca(css);
	int cpu;
	s64 val = 0;

	for_each_online_cpu(cpu) {
		struct kernel_cpustat *kcpustat = per_cpu_ptr(ca->cpustat, cpu);
		val += kcpustat->cpustat[CPUTIME_USER];
		val += kcpustat->cpustat[CPUTIME_NICE];
	}
	val = cputime64_to_clock_t(val);
	cb->fill(cb, cpuacct_stat_desc[CPUACCT_STAT_USER], val);

	val = 0;
	for_each_online_cpu(cpu) {
		struct kernel_cpustat *kcpustat = per_cpu_ptr(ca->cpustat, cpu);
		val += kcpustat->cpustat[CPUTIME_SYSTEM];
		val += kcpustat->cpustat[CPUTIME_IRQ];
		val += kcpustat->cpustat[CPUTIME_SOFTIRQ];
	}

	val = cputime64_to_clock_t(val);
	cb->fill(cb, cpuacct_stat_desc[CPUACCT_STAT_SYSTEM], val);

	return 0;
}

// ARM10C 20150822
static struct cftype files[] = {
	{
		.name = "usage",
		.read_u64 = cpuusage_read,
		.write_u64 = cpuusage_write,
	},
	{
		.name = "usage_percpu",
		.read_seq_string = cpuacct_percpu_seq_read,
	},
	{
		.name = "stat",
		.read_map = cpuacct_stats_show,
	},
	{ }	/* terminate */
};

/*
 * charge this task's execution time to its accounting group.
 *
 * called with rq->lock held.
 */
// ARM10C 20170913
// [20170906] curtask: kmem_cache#15-oX (struct task_struct) (pid: 1), delta_exec: 실행된 시간차이값
void cpuacct_charge(struct task_struct *tsk, u64 cputime)
{
	struct cpuacct *ca;
	int cpu;

	// tsk: kmem_cache#15-oX (struct task_struct) (pid: 1), task_cpu(kmem_cache#15-oX (struct task_struct) (pid: 1)): 0
	cpu = task_cpu(tsk);
	// cpu: 0

	rcu_read_lock();

	// rcu_read_lock 에서 한일:
	// (kmem_cache#15-oX (struct task_struct) (pid: 1))->rcu_read_lock_nesting: 1

	// tsk: kmem_cache#15-oX (struct task_struct) (pid: 1), task_ca(kmem_cache#15-oX (struct task_struct) (pid: 1)): &root_cpuacct
	ca = task_ca(tsk);
	// ca: &root_cpuacct

	while (true) {
		// ca->cpuusage: (&root_cpuacct)->cpuusage: &root_cpuacct_cpuusage, cpu: 0
		// per_cpu_ptr(&root_cpuacct_cpuusage, 0): [pcp0] &root_cpuacct_cpuusage
		u64 *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);
		// cpuusage: [pcp0] &root_cpuacct_cpuusage

		// *cpuusage: root_cpuacct_cpuusage: 0, cputime: 실행된 시간차이값
		*cpuusage += cputime;
		// *cpuusage: root_cpuacct_cpuusage: 실행된 시간차이값

		// ca: &root_cpuacct, parent_ca(&root_cpuacct): NULL
		ca = parent_ca(ca);
		// ca: NULL

		// ca: NULL
		if (!ca)
			break;
			// break 수행
	}

	rcu_read_unlock();

	// rcu_read_unlock 에서 한일:
	// (kmem_cache#15-oX (struct task_struct) (pid: 1))->rcu_read_lock_nesting: 0
}

/*
 * Add user/system time to cpuacct.
 *
 * Note: it's the caller that updates the account of the root cgroup.
 */
void cpuacct_account_field(struct task_struct *p, int index, u64 val)
{
	struct kernel_cpustat *kcpustat;
	struct cpuacct *ca;

	rcu_read_lock();
	ca = task_ca(p);
	while (ca != &root_cpuacct) {
		kcpustat = this_cpu_ptr(ca->cpustat);
		kcpustat->cpustat[index] += val;
		ca = parent_ca(ca);
	}
	rcu_read_unlock();
}

// ARM10C 20150822
// ARM10C 20161210
struct cgroup_subsys cpuacct_subsys = {
	.name		= "cpuacct",
	.css_alloc	= cpuacct_css_alloc,
	.css_free	= cpuacct_css_free,
	.subsys_id	= cpuacct_subsys_id,
	.base_cftypes	= files,
	.early_init	= 1,
};
