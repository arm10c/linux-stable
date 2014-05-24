#ifndef _LINUX_VMSTAT_H
#define _LINUX_VMSTAT_H

#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/vm_event_item.h>
#include <linux/atomic.h>

extern int sysctl_stat_interval;

// ARM10C 20140405
#ifdef CONFIG_VM_EVENT_COUNTERS // CONFIG_VM_EVENT_COUNTERS=y
/*
 * Light weight per cpu counter implementation.
 *
 * Counters should only be incremented and no critical kernel component
 * should rely on the counter values.
 *
 * Counters are handled completely inline. On many platforms the code
 * generated will simply be the increment of a global address.
 */

// ARM10C 20140405
struct vm_event_state {
	// NR_VM_EVENT_ITEMS: 52
	unsigned long event[NR_VM_EVENT_ITEMS];
};

DECLARE_PER_CPU(struct vm_event_state, vm_event_states);

// ARM10C 20140412
// PGFREE: 7
static inline void __count_vm_event(enum vm_event_item item)
{
	// item: PGFREE: 7, vm_event_states.event[7]: 0
	__this_cpu_inc(vm_event_states.event[item]);
	// *(&(vm_event_states.event[PGFREE]) + __my_cpu_offset): 1
}

static inline void count_vm_event(enum vm_event_item item)
{
	this_cpu_inc(vm_event_states.event[item]);
}

// ARM10C 20140405
// item: 7, delta: 32
// ARM10C 20140524
// PGALLOC_NORMAL: 4, ZONE_NORMAL: 0, zone_idx(contig_page_data->node_zones[0]): 0
// __count_vm_events(PGALLOC_NORMAL - ZONE_NORMAL + zone_idx(contig_page_data->node_zones[0]), 1)
// item: 4, delta: 1
static inline void __count_vm_events(enum vm_event_item item, long delta)
{
	// vm_event_states.event[PGFREE]: 0, delta: 32
	// ARM10C 20140524
	// vm_event_states.event[PGALLOC_NORMAL]: 0, delta: 1
	__this_cpu_add(vm_event_states.event[item], delta);

	// __pcpu_size_call(__this_cpu_add_, vm_event_states.event[PGFREE], delta)

	//	__verify_pcpu_ptr(&(vm_event_states.event[PGFREE]));
	//		경고용
	//	
	//	sizeof(vm_event_states.event[PGFREE]): 4
	//	switch(sizeof(vm_event_states.event[PGFREE])) {
	//		case 1: __this_cpu_add_1(vm_event_states.event[PGFREE], __VA_ARGS__);break;
	//		case 2: __this_cpu_add_2(vm_event_states.event[PGFREE], __VA_ARGS__);break;
	//		case 4: __this_cpu_add_4(vm_event_states.event[PGFREE], __VA_ARGS__);break;
	//		case 8: __this_cpu_add_8(vm_event_states.event[PGFREE], __VA_ARGS__);break;
	//		default:
	//			__bad_size_call_parameter();break;
	//	}
	//
	//	__this_cpu_add_4:
	//		*__this_cpu_ptr(&(vm_event_states.event[7])) += delta;
	//	
	// vm_event_states.event[PGFREE]: 32
	// ARM10C 20140524
	// vm_event_states.event[PGALLOC_NORMAL]: 1
}

static inline void count_vm_events(enum vm_event_item item, long delta)
{
	this_cpu_add(vm_event_states.event[item], delta);
}

extern void all_vm_events(unsigned long *);

extern void vm_events_fold_cpu(int cpu);

#else

/* Disable counters */
static inline void count_vm_event(enum vm_event_item item)
{
}
static inline void count_vm_events(enum vm_event_item item, long delta)
{
}
static inline void __count_vm_event(enum vm_event_item item)
{
}
static inline void __count_vm_events(enum vm_event_item item, long delta)
{
}
static inline void all_vm_events(unsigned long *ret)
{
}
static inline void vm_events_fold_cpu(int cpu)
{
}

#endif /* CONFIG_VM_EVENT_COUNTERS */

#ifdef CONFIG_NUMA_BALANCING
#define count_vm_numa_event(x)     count_vm_event(x)
#define count_vm_numa_events(x, y) count_vm_events(x, y)
#else
#define count_vm_numa_event(x) do {} while (0)
#define count_vm_numa_events(x, y) do { (void)(y); } while (0)
#endif /* CONFIG_NUMA_BALANCING */

// ARM10C 20140524
// PGALLOC, zone: contig_page_data->node_zones[0], 1
// #define __count_zone_vm_events(PGALLOC, contig_page_data->node_zones[0], 1)
// 		__count_vm_events(PGALLOC_NORMAL - ZONE_NORMAL + zone_idx(contig_page_data->node_zones[0]), 1)
#define __count_zone_vm_events(item, zone, delta) \
		__count_vm_events(item##_NORMAL - ZONE_NORMAL + \
		zone_idx(zone), delta)

/*
 * Zone based page accounting with per cpu differentials.
 */
extern atomic_long_t vm_stat[NR_VM_ZONE_STAT_ITEMS];

// ARM10C 20140412
// x: 32, zone: &(&contig_page_data)->node_zones[ZONE_NORMAL], item: 0
static inline void zone_page_state_add(long x, struct zone *zone,
				 enum zone_stat_item item)
{
	// x: 32, item: 0, &zone->vm_stat[0]: &(&contig_page_data)->node_zones[ZONE_NORMAL].vm_stat[0]: 0
	atomic_long_add(x, &zone->vm_stat[item]);
	// zone->vm_stat[0]: (&contig_page_data)->node_zones[ZONE_NORMAL].vm_stat[0]: 32

	// item: 0, vm_stat[0]: 0
	atomic_long_add(x, &vm_stat[item]);
	// vm_stat[0]: 32
}

// ARM10C 20140419
// NR_FREE_PAGES: 0
static inline unsigned long global_page_state(enum zone_stat_item item)
{
	long x = atomic_long_read(&vm_stat[item]);
#ifdef CONFIG_SMP // CONFIG_SMP=y
	if (x < 0)
		x = 0;
#endif
	return x;
}

// ARM10C 20140510
// zone: contig_page_data->node_zones[0], NR_ALLOC_BATCH: 1
// ARM10C 20140510
// zone: contig_page_data->node_zones[0], NR_FREE_PAGES: 0
// zone: contig_page_data->node_zones[0], NR_INACTIVE_FILE: 4
// zone: contig_page_data->node_zones[0], NR_ACTIVE_FILE: 5
// zone: contig_page_data->node_zones[0], NR_FILE_DIRTY: 11
// zone: contig_page_data->node_zones[0], NR_UNSTABLE_NFS: 17
// zone: contig_page_data->node_zones[0], NR_WRITEBACK: 12
static inline unsigned long zone_page_state(struct zone *zone,
					enum zone_stat_item item)
{
	// item: 1, zone->vm_stat[1]: contig_page_data->node_zones[0].vm_stat[1]
	// atomic_long_read(&contig_page_data->node_zones[0].vm_stat[1]): 0x2efd6
	// item: 0, zone->vm_stat[0]: contig_page_data->node_zones[0].vm_stat[0]
	// atomic_long_read(&contig_page_data->node_zones[0].vm_stat[0]): ???? (32)
	// item: 4, zone->vm_stat[4]: contig_page_data->node_zones[0].vm_stat[4]
	// atomic_long_read(&contig_page_data->node_zones[0].vm_stat[4]): 0
	// item: 5, zone->vm_stat[5]: contig_page_data->node_zones[0].vm_stat[5]
	// atomic_long_read(&contig_page_data->node_zones[0].vm_stat[5]): 0
	long x = atomic_long_read(&zone->vm_stat[item]);
	// x: 0x2efd6
	// x: ???? (32)
	// x: 0
	// x: 0

	// vm_stat[NR_FREE_PAGES] 사용가능한 page 수를 의미함
	// vm_stat[NR_ALLOC_BATCH] buddy에서 할당 가능한 총 page 수
	// batch 의 의미: chunk size for buddy add/remove

#ifdef CONFIG_SMP // CONFIG_SMP=y
	if (x < 0)
		x = 0;
#endif
	// x: 0x2efd6
	// x: ???? (32)
	// x: 0
	// x: 0
	return x;
	// return 0x2efd6
	// return ???? (32)
	// return 0
	// return 0
}

/*
 * More accurate version that also considers the currently pending
 * deltas. For that we need to loop over all cpus to find the current
 * deltas. There is no synchronization so the result cannot be
 * exactly accurate either.
 */
static inline unsigned long zone_page_state_snapshot(struct zone *zone,
					enum zone_stat_item item)
{
	long x = atomic_long_read(&zone->vm_stat[item]);

#ifdef CONFIG_SMP
	int cpu;
	for_each_online_cpu(cpu)
		x += per_cpu_ptr(zone->pageset, cpu)->vm_stat_diff[item];

	if (x < 0)
		x = 0;
#endif
	return x;
}

#ifdef CONFIG_NUMA // CONFIG_NUMA=n
/*
 * Determine the per node value of a stat item. This function
 * is called frequently in a NUMA machine, so try to be as
 * frugal as possible.
 */
static inline unsigned long node_page_state(int node,
				 enum zone_stat_item item)
{
	struct zone *zones = NODE_DATA(node)->node_zones;

	return
#ifdef CONFIG_ZONE_DMA
		zone_page_state(&zones[ZONE_DMA], item) +
#endif
#ifdef CONFIG_ZONE_DMA32
		zone_page_state(&zones[ZONE_DMA32], item) +
#endif
#ifdef CONFIG_HIGHMEM
		zone_page_state(&zones[ZONE_HIGHMEM], item) +
#endif
		zone_page_state(&zones[ZONE_NORMAL], item) +
		zone_page_state(&zones[ZONE_MOVABLE], item);
}

extern void zone_statistics(struct zone *, struct zone *, gfp_t gfp);

#else

#define node_page_state(node, item) global_page_state(item)
// ARM10C 20140524
#define zone_statistics(_zl, _z, gfp) do { } while (0)

#endif /* CONFIG_NUMA */

#define add_zone_page_state(__z, __i, __d) mod_zone_page_state(__z, __i, __d)
#define sub_zone_page_state(__z, __i, __d) mod_zone_page_state(__z, __i, -(__d))

extern void inc_zone_state(struct zone *, enum zone_stat_item);

#ifdef CONFIG_SMP // CONFIG_SMP=y
// ARM10C 20140412
// ARM10C 20140510
void __mod_zone_page_state(struct zone *, enum zone_stat_item item, int);
void __inc_zone_page_state(struct page *, enum zone_stat_item);
void __dec_zone_page_state(struct page *, enum zone_stat_item);

// ARM10C 20140510
// ARM10C 20140517
void mod_zone_page_state(struct zone *, enum zone_stat_item, int);
void inc_zone_page_state(struct page *, enum zone_stat_item);
void dec_zone_page_state(struct page *, enum zone_stat_item);

extern void inc_zone_state(struct zone *, enum zone_stat_item);
extern void __inc_zone_state(struct zone *, enum zone_stat_item);
extern void dec_zone_state(struct zone *, enum zone_stat_item);
extern void __dec_zone_state(struct zone *, enum zone_stat_item);

void cpu_vm_stats_fold(int cpu);
void refresh_zone_stat_thresholds(void);

void drain_zonestat(struct zone *zone, struct per_cpu_pageset *);

int calculate_pressure_threshold(struct zone *zone);
int calculate_normal_threshold(struct zone *zone);
void set_pgdat_percpu_threshold(pg_data_t *pgdat,
				int (*calculate_pressure)(struct zone *));
#else /* CONFIG_SMP */

/*
 * We do not maintain differentials in a single processor configuration.
 * The functions directly modify the zone and global counters.
 */
static inline void __mod_zone_page_state(struct zone *zone,
			enum zone_stat_item item, int delta)
{
	zone_page_state_add(delta, zone, item);
}

static inline void __inc_zone_state(struct zone *zone, enum zone_stat_item item)
{
	atomic_long_inc(&zone->vm_stat[item]);
	atomic_long_inc(&vm_stat[item]);
}

static inline void __inc_zone_page_state(struct page *page,
			enum zone_stat_item item)
{
	__inc_zone_state(page_zone(page), item);
}

static inline void __dec_zone_state(struct zone *zone, enum zone_stat_item item)
{
	atomic_long_dec(&zone->vm_stat[item]);
	atomic_long_dec(&vm_stat[item]);
}

static inline void __dec_zone_page_state(struct page *page,
			enum zone_stat_item item)
{
	__dec_zone_state(page_zone(page), item);
}

/*
 * We only use atomic operations to update counters. So there is no need to
 * disable interrupts.
 */
#define inc_zone_page_state __inc_zone_page_state
#define dec_zone_page_state __dec_zone_page_state
#define mod_zone_page_state __mod_zone_page_state

#define set_pgdat_percpu_threshold(pgdat, callback) { }

static inline void refresh_cpu_vm_stats(int cpu) { }
static inline void refresh_zone_stat_thresholds(void) { }
static inline void cpu_vm_stats_fold(int cpu) { }

static inline void drain_zonestat(struct zone *zone,
			struct per_cpu_pageset *pset) { }
#endif		/* CONFIG_SMP */

// ARM10C 20140405
// ARM10C 20140412
// zone: &contig_page_data->node_zones[ZONE_NORMAL], nr_pages: 32, migratetype: 0x2
static inline void __mod_zone_freepage_state(struct zone *zone, int nr_pages,
					     int migratetype)
{
	// zone: &contig_page_data->node_zones[ZONE_NORMAL], NR_FREE_PAGES: 0, nr_pages: 32
	__mod_zone_page_state(zone, NR_FREE_PAGES, nr_pages);
	// &contig_page_data->node_zones[ZONE_NORMAL].vm_stat[NR_FREE_PAGES]: 32 로 설정
	// vmstat.c의 vm_stat[NR_FREE_PAGES] 전역 변수에도 32로 설정

	// migratetype: 0x2
	// is_migrate_cma(0x2): false
	if (is_migrate_cma(migratetype))
		__mod_zone_page_state(zone, NR_FREE_CMA_PAGES, nr_pages);
}

extern const char * const vmstat_text[];

#endif /* _LINUX_VMSTAT_H */
