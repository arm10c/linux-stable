/*
 * Fast batching percpu counters.
 */

#include <linux/percpu_counter.h>
#include <linux/notifier.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/debugobjects.h>

#ifdef CONFIG_HOTPLUG_CPU // CONFIG_HOTPLUG_CPU=y
// ARM10C 20150919
// LIST_HEAD(percpu_counters):
// struct list_head percpu_counters =
// { &(percpu_counters), &(percpu_counters) }
static LIST_HEAD(percpu_counters);
// ARM10C 20150919
// DEFINE_SPINLOCK(percpu_counters_lock):
// spinlock_t percpu_counters_lock = (spinlock_t )
// { { .rlock =
//     {
//       .raw_lock = { { 0 } },
//       .magic = 0xdead4ead,
//       .owner_cpu = -1,
//       .owner = 0xffffffff,
//     }
// } }
static DEFINE_SPINLOCK(percpu_counters_lock);
#endif

#ifdef CONFIG_DEBUG_OBJECTS_PERCPU_COUNTER // CONFIG_DEBUG_OBJECTS_PERCPU_COUNTER=n

static struct debug_obj_descr percpu_counter_debug_descr;

static int percpu_counter_fixup_free(void *addr, enum debug_obj_state state)
{
	struct percpu_counter *fbc = addr;

	switch (state) {
	case ODEBUG_STATE_ACTIVE:
		percpu_counter_destroy(fbc);
		debug_object_free(fbc, &percpu_counter_debug_descr);
		return 1;
	default:
		return 0;
	}
}

static struct debug_obj_descr percpu_counter_debug_descr = {
	.name		= "percpu_counter",
	.fixup_free	= percpu_counter_fixup_free,
};

static inline void debug_percpu_counter_activate(struct percpu_counter *fbc)
{
	debug_object_init(fbc, &percpu_counter_debug_descr);
	debug_object_activate(fbc, &percpu_counter_debug_descr);
}

static inline void debug_percpu_counter_deactivate(struct percpu_counter *fbc)
{
	debug_object_deactivate(fbc, &percpu_counter_debug_descr);
	debug_object_free(fbc, &percpu_counter_debug_descr);
}

#else	/* CONFIG_DEBUG_OBJECTS_PERCPU_COUNTER */
// ARM10C 20150919
static inline void debug_percpu_counter_activate(struct percpu_counter *fbc)
{ }
static inline void debug_percpu_counter_deactivate(struct percpu_counter *fbc)
{ }
#endif	/* CONFIG_DEBUG_OBJECTS_PERCPU_COUNTER */

void percpu_counter_set(struct percpu_counter *fbc, s64 amount)
{
	int cpu;
	unsigned long flags;

	raw_spin_lock_irqsave(&fbc->lock, flags);
	for_each_possible_cpu(cpu) {
		s32 *pcount = per_cpu_ptr(fbc->counters, cpu);
		*pcount = 0;
	}
	fbc->count = amount;
	raw_spin_unlock_irqrestore(&fbc->lock, flags);
}
EXPORT_SYMBOL(percpu_counter_set);

void __percpu_counter_add(struct percpu_counter *fbc, s64 amount, s32 batch)
{
	s64 count;

	preempt_disable();
	count = __this_cpu_read(*fbc->counters) + amount;
	if (count >= batch || count <= -batch) {
		unsigned long flags;
		raw_spin_lock_irqsave(&fbc->lock, flags);
		fbc->count += count;
		__this_cpu_sub(*fbc->counters, count - amount);
		raw_spin_unlock_irqrestore(&fbc->lock, flags);
	} else {
		this_cpu_add(*fbc->counters, amount);
	}
	preempt_enable();
}
EXPORT_SYMBOL(__percpu_counter_add);

/*
 * Add up all the per-cpu counts, return the result.  This is a more accurate
 * but much slower version of percpu_counter_read_positive()
 */
s64 __percpu_counter_sum(struct percpu_counter *fbc)
{
	s64 ret;
	int cpu;
	unsigned long flags;

	raw_spin_lock_irqsave(&fbc->lock, flags);
	ret = fbc->count;
	for_each_online_cpu(cpu) {
		s32 *pcount = per_cpu_ptr(fbc->counters, cpu);
		ret += *pcount;
	}
	raw_spin_unlock_irqrestore(&fbc->lock, flags);
	return ret;
}
EXPORT_SYMBOL(__percpu_counter_sum);

// ARM10C 20150919
// &vm_committed_as, 0, &__key
// ARM10C 20151024
// &nr_files, 0, &__key
// ARM10C 20151031
// &bdi->bdi_stat[0]: &(&sysfs_backing_dev_info)->bdi_stat[0], 0, &__key
// ARM10C 20151114
// &s->s_writers.counter[0]: &(kmem_cache#25-oX (struct super_block))->s_writers.counter[0], 0, &__key
// ARM10C 20160319
// &sbinfo->used_blocks: &(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks
int __percpu_counter_init(struct percpu_counter *fbc, s64 amount,
			  struct lock_class_key *key)
{
	// &fbc->lock: &(&vm_committed_as)->lock
	raw_spin_lock_init(&fbc->lock);

	// raw_spin_lock_init에서 한일:
	// (&(&(&(&vm_committed_as)->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&vm_committed_as)->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&vm_committed_as)->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&vm_committed_as)->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff

	// &fbc->lock: &(&vm_committed_as)->lock, key: &__key
	lockdep_set_class(&fbc->lock, key); // null function

	// fbc->count: (&vm_committed_as)->count, amount: 0
	fbc->count = amount;
	// fbc->count: (&vm_committed_as)->count: 0

	// fbc->counters: (&vm_committed_as)->counters,
	// alloc_percpu(s32): kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	fbc->counters = alloc_percpu(s32);
	// fbc->counters: (&vm_committed_as)->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소

	// fbc->counters: (&vm_committed_as)->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	if (!fbc->counters)
		return -ENOMEM;

	// fbc: &vm_committed_as
	debug_percpu_counter_activate(fbc); // null function

#ifdef CONFIG_HOTPLUG_CPU // CONFIG_HOTPLUG_CPU=y
	// &fbc->list: &(&vm_committed_as)->list
	INIT_LIST_HEAD(&fbc->list);

	// INIT_LIST_HEAD에서 한일:
	// (&(&vm_committed_as)->list)->next: &(&vm_committed_as)->list
	// (&(&vm_committed_as)->list)->prev: &(&vm_committed_as)->list

	spin_lock(&percpu_counters_lock);

	// spin_lock에서 한일:
	// &percpu_counters_lock을 사용한 spin lock 수행

	// &fbc->list: &(&vm_committed_as)->list
	list_add(&fbc->list, &percpu_counters);

	// list_add에서 한일:
	// list head 인 &percpu_counters에 &(&vm_committed_as)->list를 연결함

	spin_unlock(&percpu_counters_lock);

	// spin_lock에서 한일:
	// &percpu_counters_lock을 사용한 spin unlock 수행
#endif
	return 0;
	// return 0
}
EXPORT_SYMBOL(__percpu_counter_init);

void percpu_counter_destroy(struct percpu_counter *fbc)
{
	if (!fbc->counters)
		return;

	debug_percpu_counter_deactivate(fbc);

#ifdef CONFIG_HOTPLUG_CPU
	spin_lock(&percpu_counters_lock);
	list_del(&fbc->list);
	spin_unlock(&percpu_counters_lock);
#endif
	free_percpu(fbc->counters);
	fbc->counters = NULL;
}
EXPORT_SYMBOL(percpu_counter_destroy);

int percpu_counter_batch __read_mostly = 32;
EXPORT_SYMBOL(percpu_counter_batch);

static void compute_batch_value(void)
{
	int nr = num_online_cpus();

	percpu_counter_batch = max(32, nr*2);
}

static int percpu_counter_hotcpu_callback(struct notifier_block *nb,
					unsigned long action, void *hcpu)
{
#ifdef CONFIG_HOTPLUG_CPU
	unsigned int cpu;
	struct percpu_counter *fbc;

	compute_batch_value();
	if (action != CPU_DEAD)
		return NOTIFY_OK;

	cpu = (unsigned long)hcpu;
	spin_lock(&percpu_counters_lock);
	list_for_each_entry(fbc, &percpu_counters, list) {
		s32 *pcount;
		unsigned long flags;

		raw_spin_lock_irqsave(&fbc->lock, flags);
		pcount = per_cpu_ptr(fbc->counters, cpu);
		fbc->count += *pcount;
		*pcount = 0;
		raw_spin_unlock_irqrestore(&fbc->lock, flags);
	}
	spin_unlock(&percpu_counters_lock);
#endif
	return NOTIFY_OK;
}

/*
 * Compare counter against given value.
 * Return 1 if greater, 0 if equal and -1 if less
 */
int percpu_counter_compare(struct percpu_counter *fbc, s64 rhs)
{
	s64	count;

	count = percpu_counter_read(fbc);
	/* Check to see if rough count will be sufficient for comparison */
	if (abs(count - rhs) > (percpu_counter_batch*num_online_cpus())) {
		if (count > rhs)
			return 1;
		else
			return -1;
	}
	/* Need to use precise count */
	count = percpu_counter_sum(fbc);
	if (count > rhs)
		return 1;
	else if (count < rhs)
		return -1;
	else
		return 0;
}
EXPORT_SYMBOL(percpu_counter_compare);

static int __init percpu_counter_startup(void)
{
	compute_batch_value();
	hotcpu_notifier(percpu_counter_hotcpu_callback, 0);
	return 0;
}
module_init(percpu_counter_startup);
