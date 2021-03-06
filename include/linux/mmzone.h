﻿#ifndef _LINUX_MMZONE_H
#define _LINUX_MMZONE_H

#ifndef __ASSEMBLY__
#ifndef __GENERATING_BOUNDS_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <linux/numa.h>
#include <linux/init.h>
#include <linux/seqlock.h>
#include <linux/nodemask.h>
#include <linux/pageblock-flags.h>
#include <linux/page-flags-layout.h>
#include <linux/atomic.h>
#include <asm/page.h>

/* Free memory management - zoned buddy allocator.  */
#ifndef CONFIG_FORCE_MAX_ZONEORDER // CONFIG_FORCE_MAX_ZONEORDER=y
#define MAX_ORDER 11
#else
// ARM10C 20140329
// ARM10C 20140517
// ARM10C 20151024
// CONFIG_FORCE_MAX_ZONEORDER: 11
// MAX_ORDER: 11
#define MAX_ORDER CONFIG_FORCE_MAX_ZONEORDER
#endif
// ARM10C 20140329
// MAX_ORDER: 11
// MAX_ORDER_NR_PAGES: 0x400
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))

/*
 * PAGE_ALLOC_COSTLY_ORDER is the order at which allocations are deemed
 * costly to service.  That is between allocation orders which should
 * coalesce naturally under reasonable reclaim pressure and those which
 * will not.
 */
// ARM10C 20140419
#define PAGE_ALLOC_COSTLY_ORDER 3

// ARM10C 20140111
// ARM10C 20140412
// ARM10C 20160903
enum {
	MIGRATE_UNMOVABLE,
	MIGRATE_RECLAIMABLE,
	MIGRATE_MOVABLE,
	MIGRATE_PCPTYPES,	/* the number of types on the pcp lists */
	MIGRATE_RESERVE = MIGRATE_PCPTYPES,
#ifdef CONFIG_CMA
	/*
	 * MIGRATE_CMA migration type is designed to mimic the way
	 * ZONE_MOVABLE works.  Only movable pages can be allocated
	 * from MIGRATE_CMA pageblocks and page allocator never
	 * implicitly change migration type of MIGRATE_CMA pageblock.
	 *
	 * The way to use it is to change migratetype of a range of
	 * pageblocks to MIGRATE_CMA which can be done by
	 * __free_pageblock_cma() function.  What is important though
	 * is that a range of pageblocks must be aligned to
	 * MAX_ORDER_NR_PAGES should biggest page be bigger then
	 * a single pageblock.
	 */
	MIGRATE_CMA,
#endif
#ifdef CONFIG_MEMORY_ISOLATION
	MIGRATE_ISOLATE,	/* can't allocate from here */
#endif
	MIGRATE_TYPES	// 4
};

#ifdef CONFIG_CMA // CONFIG_CMA=n
#  define is_migrate_cma(migratetype) unlikely((migratetype) == MIGRATE_CMA)
#else
// ARM10C 20140412
// ARM10C 20140517
#  define is_migrate_cma(migratetype) false
#endif

// ARM10C 20140111
// MAX_ORDER: 11
// MIGRATE_TYPES: 4
#define for_each_migratetype_order(order, type) \
	for (order = 0; order < MAX_ORDER; order++) \
		for (type = 0; type < MIGRATE_TYPES; type++)

extern int page_group_by_mobility_disabled;

// ARM10C 20140405
// page : 0x20000 (pfn)
// ARM10C 20140412
static inline int get_pageblock_migratetype(struct page *page)
{
	// page : 0x20000 (pfn), PB_migrate: 0, PB_migrate_end: 2 
	return get_pageblock_flags_group(page, PB_migrate, PB_migrate_end);
	// return 0x2
}

// ARM10C 20140125
// ARM10C 20140517
// MIGRATE_TYPES: 4
struct free_area {
	struct list_head	free_list[MIGRATE_TYPES];
	unsigned long		nr_free;
};

struct pglist_data;

/*
 * zone->lock and zone->lru_lock are two of the hottest locks in the kernel.
 * So add a wild amount of padding here to ensure that they fall into separate
 * cachelines.  There are very few zone structures in the machine, so space
 * consumption is not a concern here.
 */
#if defined(CONFIG_SMP) // CONFIG_SMP=7
struct zone_padding {
	char x[0];
} ____cacheline_internodealigned_in_smp;
// ARM10C 20140125
#define ZONE_PADDING(name)	struct zone_padding name;
#else
#define ZONE_PADDING(name)
#endif

// ARM10C 20140125
// ARM10C 20140308
// ARM10C 20140412
// ARM10C 20140419
// ARM10C 20140510
// ARM10C 20160528
// ARM10C 20160903
enum zone_stat_item {
	/* First 128 byte cacheline (assuming 64 bit words) */
	// NR_FREE_PAGES: 0
	NR_FREE_PAGES,
	NR_ALLOC_BATCH,
	NR_LRU_BASE,
	NR_INACTIVE_ANON = NR_LRU_BASE, /* must match order of LRU_[IN]ACTIVE */
	NR_ACTIVE_ANON,		/*  "     "     "   "       "         */
	// NR_INACTIVE_FILE: 4
	NR_INACTIVE_FILE,	/*  "     "     "   "       "         */
	// NR_ACTIVE_FILE: 5
	NR_ACTIVE_FILE,		/*  "     "     "   "       "         */
	NR_UNEVICTABLE,		/*  "     "     "   "       "         */
	NR_MLOCK,		/* mlock()ed pages found and moved off LRU */
	NR_ANON_PAGES,	/* Mapped anonymous pages */
	NR_FILE_MAPPED,	/* pagecache pages mapped into pagetables.
			   only modified from process context */
	NR_FILE_PAGES,
	// NR_FILE_DIRTY: 11
	NR_FILE_DIRTY,
	// NR_WRITEBACK: 12
	NR_WRITEBACK,
	// NR_SLAB_RECLAIMABLE: 13
	NR_SLAB_RECLAIMABLE,
	// NR_SLAB_UNRECLAIMABLE: 14
	NR_SLAB_UNRECLAIMABLE,
	NR_PAGETABLE,		/* used for pagetables */
	// NR_KERNEL_STACK: 16
	NR_KERNEL_STACK,
	/* Second 128 byte cacheline */
	// NR_UNSTABLE_NFS: 17
	NR_UNSTABLE_NFS,	/* NFS unstable pages */
	NR_BOUNCE,
	NR_VMSCAN_WRITE,
	NR_VMSCAN_IMMEDIATE,	/* Prioritise for reclaim when writeback ends */
	NR_WRITEBACK_TEMP,	/* Writeback using temporary buffers */
	NR_ISOLATED_ANON,	/* Temporary isolated pages from anon lru */
	NR_ISOLATED_FILE,	/* Temporary isolated pages from file lru */
	NR_SHMEM,		/* shmem pages (included tmpfs/GEM pages) */
	NR_DIRTIED,		/* page dirtyings since bootup */
	NR_WRITTEN,		/* page writings since bootup */
#ifdef CONFIG_NUMA // CONFIG_NUMA=n
	NUMA_HIT,		/* allocated in intended node */
	NUMA_MISS,		/* allocated in non intended node */
	NUMA_FOREIGN,		/* was intended here, hit elsewhere */
	NUMA_INTERLEAVE_HIT,	/* interleaver preferred this zone */
	NUMA_LOCAL,		/* allocation from local node */
	NUMA_OTHER,		/* allocation from other node */
#endif
	NR_ANON_TRANSPARENT_HUGEPAGES,
	NR_FREE_CMA_PAGES,
	// NR_VM_ZONE_STAT_ITEMS: 29
	NR_VM_ZONE_STAT_ITEMS };

/*
 * We do arithmetic on the LRU lists in various places in the code,
 * so it is important to keep the active lists LRU_ACTIVE higher in
 * the array than the corresponding inactive lists, and to keep
 * the *_FILE lists LRU_FILE higher than the corresponding _ANON lists.
 *
 * This has to be kept in sync with the statistics in zone_stat_item
 * above and the descriptions in vmstat_text in mm/vmstat.c
 */
#define LRU_BASE 0
#define LRU_ACTIVE 1
#define LRU_FILE 2

// ARM10C 20140125
enum lru_list {
	LRU_INACTIVE_ANON = LRU_BASE,
	LRU_ACTIVE_ANON = LRU_BASE + LRU_ACTIVE,
	LRU_INACTIVE_FILE = LRU_BASE + LRU_FILE,
	LRU_ACTIVE_FILE = LRU_BASE + LRU_FILE + LRU_ACTIVE,
	LRU_UNEVICTABLE,
	NR_LRU_LISTS
};

#define for_each_lru(lru) for (lru = 0; lru < NR_LRU_LISTS; lru++)

#define for_each_evictable_lru(lru) for (lru = 0; lru <= LRU_ACTIVE_FILE; lru++)

static inline int is_file_lru(enum lru_list lru)
{
	return (lru == LRU_INACTIVE_FILE || lru == LRU_ACTIVE_FILE);
}

static inline int is_active_lru(enum lru_list lru)
{
	return (lru == LRU_ACTIVE_ANON || lru == LRU_ACTIVE_FILE);
}

static inline int is_unevictable_lru(enum lru_list lru)
{
	return (lru == LRU_UNEVICTABLE);
}

// ARM10C 20140125
struct zone_reclaim_stat {
	/*
	 * The pageout code in vmscan.c keeps track of how many of the
	 * mem/swap backed and file backed pages are referenced.
	 * The higher the rotated/scanned ratio, the more valuable
	 * that cache is.
	 *
	 * The anon LRU stats live in [0], file LRU stats in [1]
	 */
	unsigned long		recent_rotated[2];
	unsigned long		recent_scanned[2];
};

// ARM10C 20140111 
// ARM10C 20140125
// NR_LRU_LISTS: 5
struct lruvec {
	struct list_head lists[NR_LRU_LISTS];
	struct zone_reclaim_stat reclaim_stat;
#ifdef CONFIG_MEMCG	// CONFIG_MEMCG = n 
	struct zone *zone;
#endif
};

/* Mask used at gathering information at once (see memcontrol.c) */
#define LRU_ALL_FILE (BIT(LRU_INACTIVE_FILE) | BIT(LRU_ACTIVE_FILE))
#define LRU_ALL_ANON (BIT(LRU_INACTIVE_ANON) | BIT(LRU_ACTIVE_ANON))
#define LRU_ALL	     ((1 << NR_LRU_LISTS) - 1)

/* Isolate clean file */
#define ISOLATE_CLEAN		((__force isolate_mode_t)0x1)
/* Isolate unmapped file */
#define ISOLATE_UNMAPPED	((__force isolate_mode_t)0x2)
/* Isolate for asynchronous migration */
#define ISOLATE_ASYNC_MIGRATE	((__force isolate_mode_t)0x4)
/* Isolate unevictable pages */
#define ISOLATE_UNEVICTABLE	((__force isolate_mode_t)0x8)

/* LRU Isolation modes. */
typedef unsigned __bitwise__ isolate_mode_t;

// ARM10C 20140125
// ARM10C 20140426
// ARM10C 20140510
enum zone_watermarks {
	WMARK_MIN,
	WMARK_LOW,
	WMARK_HIGH,
	NR_WMARK
};

#define min_wmark_pages(z) (z->watermark[WMARK_MIN])
#define low_wmark_pages(z) (z->watermark[WMARK_LOW])
// ARM10C 20140308
// zone: contig_page_data->node_zones[0]
// WMARK_HIGH: 2
// high_wmark_pages(contig_page_data->node_zones[0]): contig_page_data->node_zones[0]->watermark[2]: 0
#define high_wmark_pages(z) (z->watermark[WMARK_HIGH])

// ARM10C 20140308
// ARM10C 20150912
// sizeof(struct per_cpu_pages): 36 bytes
struct per_cpu_pages {
	int count;		/* number of pages in the list */
	int high;		/* high watermark, emptying needed */
	int batch;		/* chunk size for buddy add/remove */

	/* Lists of pages, one per migrate type stored on the pcp-lists */
	// MIGRATE_PCPTYPES: 3
	struct list_head lists[MIGRATE_PCPTYPES];
};

// ARM10C 20140111
// ARM10C 20140308
// ARM10C 20140412
// ARM10C 20150912
// sizeof(struct per_cpu_pageset): 66 bytes
struct per_cpu_pageset {
	struct per_cpu_pages pcp;
#ifdef CONFIG_NUMA // CONFIG_NUMA=n
	s8 expire;
#endif
#ifdef CONFIG_SMP // CONFIG_SMP=y
	s8 stat_threshold;
	// NR_VM_ZONE_STAT_ITEMS: 29
	s8 vm_stat_diff[NR_VM_ZONE_STAT_ITEMS];
#endif
};

#endif /* !__GENERATING_BOUNDS.H */

// ARM10C 20140308
// ARM10C 20160903
enum zone_type {
#ifdef CONFIG_ZONE_DMA	// ARM10C CONFIG_ZONE_DMA = n
	/*
	 * ZONE_DMA is used when there are devices that are not able
	 * to do DMA to all of addressable memory (ZONE_NORMAL). Then we
	 * carve out the portion of memory that is needed for these devices.
	 * The range is arch specific.
	 *
	 * Some examples
	 *
	 * Architecture		Limit
	 * ---------------------------
	 * parisc, ia64, sparc	<4G
	 * s390			<2G
	 * arm			Various
	 * alpha		Unlimited or 0-16MB.
	 *
	 * i386, x86_64 and multiple other arches
	 * 			<16M.
	 */
	ZONE_DMA,
#endif
#ifdef CONFIG_ZONE_DMA32	// ARM10C CONFIG_ZONE_DMA32 = n
	/*
	 * x86_64 needs two ZONE_DMAs because it supports devices that are
	 * only able to do DMA to the lower 16M but also 32 bit devices that
	 * can only do DMA areas below 4G.
	 */
	ZONE_DMA32,
#endif
	/*
	 * Normal addressable memory is in ZONE_NORMAL. DMA operations can be
	 * performed on pages in ZONE_NORMAL if the DMA devices support
	 * transfers to all addressable memory.
	 */
	ZONE_NORMAL,	// ARM10C ZONE_NORMAL = 0
#ifdef CONFIG_HIGHMEM	// ARM10C CONFIG_HIGHMEM = y
	/*
	 * A memory area that is only addressable by the kernel through
	 * mapping portions into its own address space. This is for example
	 * used by i386 to allow the kernel to address the memory beyond
	 * 900MB. The kernel will set up special mappings (page
	 * table entries on i386) for each page that the kernel needs to
	 * access.
	 */
	ZONE_HIGHMEM,	// ARM10C ZONE_HIGHMEM = 1
#endif
	ZONE_MOVABLE,	// ARM10C ZONE_MOVABLE = 2
	__MAX_NR_ZONES	// ARM10C __MAX_NR_ZONES = 3
};

#ifndef __GENERATING_BOUNDS_H

// ARM10C 20140125
// sizeof(struct zone): 804 bytes
// ARM10C 20140308
// ARM10C 20150912
// ARM10C 20151212
// ARM10C 20160528
// ARM10C 20160903
struct zone {
	/* Fields commonly accessed by the page allocator */

	/* zone watermarks, access with *_wmark_pages(zone) macros */
	// ARM10C 20140125
	// NR_WMARK: 3
	unsigned long watermark[NR_WMARK];

	/*
	 * When free pages are below this point, additional steps are taken
	 * when reading the number of free pages to avoid per-cpu counter
	 * drift allowing watermarks to be breached
	 */
	unsigned long percpu_drift_mark;

	/*
	 * We don't know if the memory that we're going to allocate will be freeable
	 * or/and it will be released eventually, so to avoid totally wasting several
	 * GB of ram we must reserve some of the lower zone memory (otherwise we risk
	 * to run OOM on the lower zones despite there's tons of freeable ram
	 * on the higher zones). This array is recalculated at runtime if the
	 * sysctl_lowmem_reserve_ratio sysctl changes.
	 */
	// ARM10C 20140125
	// MAX_NR_ZONES: 3
	unsigned long		lowmem_reserve[MAX_NR_ZONES];

	/*
	 * This is a per-zone reserve of pages that should not be
	 * considered dirtyable memory.
	 */
	unsigned long		dirty_balance_reserve;

#ifdef CONFIG_NUMA // CONFIG_NUMA=n
	int node;
	/*
	 * zone reclaim becomes active if more unmapped pages exist.
	 */
	unsigned long		min_unmapped_pages;
	unsigned long		min_slab_pages;
#endif
	struct per_cpu_pageset __percpu *pageset;
	/*
	 * free areas of different sizes
	 */
	// ARM10C 20140125
	// sizeof(spinlock_t): 16 bytes
	spinlock_t		lock;
#if defined CONFIG_COMPACTION || defined CONFIG_CMA // CONFIG_COMPACTION=y, CONFIG_CMA=n
	/* Set to true when the PG_migrate_skip bits should be cleared */
	bool			compact_blockskip_flush;

	/* pfns where compaction scanners should start */
	unsigned long		compact_cached_free_pfn;
	unsigned long		compact_cached_migrate_pfn;
#endif
#ifdef CONFIG_MEMORY_HOTPLUG // CONFIG_MEMORY_HOTPLUG=n
	/* see spanned/present_pages for more description */
	seqlock_t		span_seqlock;
#endif
	// ARM10C 20140125
	// MAX_ORDER: 11
	// sizeof(struct free_area): 36
	// sizeof(free_area[MAX_ORDER]): 396
	struct free_area	free_area[MAX_ORDER];

#ifndef CONFIG_SPARSEMEM // CONFIG_SPARSEMEM=y
	/*
	 * Flags for a pageblock_nr_pages block. See pageblock-flags.h.
	 * In SPARSEMEM, this map is stored in struct mem_section
	 */
	unsigned long		*pageblock_flags;
#endif /* CONFIG_SPARSEMEM */

#ifdef CONFIG_COMPACTION // CONFIG_COMPACTION=y
	/*
	 * On compaction failure, 1<<compact_defer_shift compactions
	 * are skipped before trying again. The number attempted since
	 * last failure is tracked with compact_considered.
	 */
	unsigned int		compact_considered;
	unsigned int		compact_defer_shift;
	int			compact_order_failed;
#endif

	// ARM10C 20140125
	// #define ZONE_PADDING(_pad1_)	struct zone_padding _pad1_;
	// sizeof(struct zone_padding): 64 bytes
	ZONE_PADDING(_pad1_)

	/* Fields commonly accessed by the page reclaim scanner */
	// ARM10C 20140125
	// sizeof(spinlock_t): 16 bytes
	spinlock_t		lru_lock;

	// ARM10C 20140125
	// sizeof(struct lruvec): 56 bytes
	struct lruvec		lruvec;

	// ARM10C 20140405
	unsigned long		pages_scanned;	   /* since last reclaim */
	unsigned long		flags;		   /* zone flags, see below */

	/* Zone statistics */
	// ARM10C 20140125
	// sizeof(atomic_long_t): 4bytes
	// NR_VM_ZONE_STAT_ITEMS: 28
	// sizeof(vm_stat[NR_VM_ZONE_STAT_ITEMS]): 112 bytes
	atomic_long_t		vm_stat[NR_VM_ZONE_STAT_ITEMS];

	/*
	 * The target ratio of ACTIVE_ANON to INACTIVE_ANON pages on
	 * this zone's LRU.  Maintained by the pageout code.
	 */
	unsigned int inactive_ratio;


	// ARM10C 20140125
	// #define ZONE_PADDING(_pad2_)	struct zone_padding _pad2_;
	// sizeof(struct zone_padding): 64 bytes
	ZONE_PADDING(_pad2_)
	/* Rarely used or read-mostly fields */

	/*
	 * wait_table		-- the array holding the hash table
	 * wait_table_hash_nr_entries	-- the size of the hash table array
	 * wait_table_bits	-- wait_table_size == (1 << wait_table_bits)
	 *
	 * The purpose of all these is to keep track of the people
	 * waiting for a page to become available and make them
	 * runnable again when possible. The trouble is that this
	 * consumes a lot of space, especially when so few things
	 * wait on pages at a given time. So instead of using
	 * per-page waitqueues, we use a waitqueue hash table.
	 *
	 * The bucket discipline is to sleep on the same queue when
	 * colliding and wake all in that wait queue when removing.
	 * When something wakes, it must check to be sure its page is
	 * truly available, a la thundering herd. The cost of a
	 * collision is great, but given the expected load of the
	 * table, they should be so rare as to be outweighed by the
	 * benefits from the saved space.
	 *
	 * __wait_on_page_locked() and unlock_page() in mm/filemap.c, are the
	 * primary users of these fields, and in mm/page_alloc.c
	 * free_area_init_core() performs the initialization of them.
	 */
	wait_queue_head_t	* wait_table;
	unsigned long		wait_table_hash_nr_entries;
	unsigned long		wait_table_bits;

	/*
	 * Discontig memory support fields.
	 */
	struct pglist_data	*zone_pgdat;
	/* zone_start_pfn == zone_start_paddr >> PAGE_SHIFT */
	unsigned long		zone_start_pfn;

	/*
	 * spanned_pages is the total pages spanned by the zone, including
	 * holes, which is calculated as:
	 * 	spanned_pages = zone_end_pfn - zone_start_pfn;
	 *
	 * present_pages is physical pages existing within the zone, which
	 * is calculated as:
	 *	present_pages = spanned_pages - absent_pages(pages in holes);
	 *
	 * managed_pages is present pages managed by the buddy system, which
	 * is calculated as (reserved_pages includes pages allocated by the
	 * bootmem allocator):
	 *	managed_pages = present_pages - reserved_pages;
	 *
	 * So present_pages may be used by memory hotplug or memory power
	 * management logic to figure out unmanaged pages by checking
	 * (present_pages - managed_pages). And managed_pages should be used
	 * by page allocator and vm scanner to calculate all kinds of watermarks
	 * and thresholds.
	 *
	 * Locking rules:
	 *
	 * zone_start_pfn and spanned_pages are protected by span_seqlock.
	 * It is a seqlock because it has to be read outside of zone->lock,
	 * and it is done in the main allocator path.  But, it is written
	 * quite infrequently.
	 *
	 * The span_seq lock is declared along with zone->lock because it is
	 * frequently read in proximity to zone->lock.  It's good to
	 * give them a chance of being in the same cacheline.
	 *
	 * Write access to present_pages at runtime should be protected by
	 * lock_memory_hotplug()/unlock_memory_hotplug().  Any reader who can't
	 * tolerant drift of present_pages should hold memory hotplug lock to
	 * get a stable value.
	 *
	 * Read access to managed_pages should be safe because it's unsigned
	 * long. Write access to zone->managed_pages and totalram_pages are
	 * protected by managed_page_count_lock at runtime. Idealy only
	 * adjust_managed_page_count() should be used instead of directly
	 * touching zone->managed_pages and totalram_pages.
	 */
	unsigned long		spanned_pages;
	unsigned long		present_pages;
	unsigned long		managed_pages;

	/*
	 * rarely used fields:
	 */
	const char		*name;
} ____cacheline_internodealigned_in_smp;

typedef enum {
	ZONE_RECLAIM_LOCKED,		/* prevents concurrent reclaim */
	ZONE_OOM_LOCKED,		/* zone is in OOM killer zonelist */
	ZONE_CONGESTED,			/* zone has many dirty pages backed by
					 * a congested BDI
					 */
	ZONE_TAIL_LRU_DIRTY,		/* reclaim scanning has recently found
					 * many dirty file pages at the tail
					 * of the LRU.
					 */
	ZONE_WRITEBACK,			/* reclaim scanning has recently found
					 * many pages under writeback
					 */
} zone_flags_t;

static inline void zone_set_flag(struct zone *zone, zone_flags_t flag)
{
	set_bit(flag, &zone->flags);
}

static inline int zone_test_and_set_flag(struct zone *zone, zone_flags_t flag)
{
	return test_and_set_bit(flag, &zone->flags);
}

static inline void zone_clear_flag(struct zone *zone, zone_flags_t flag)
{
	clear_bit(flag, &zone->flags);
}

static inline int zone_is_reclaim_congested(const struct zone *zone)
{
	return test_bit(ZONE_CONGESTED, &zone->flags);
}

static inline int zone_is_reclaim_dirty(const struct zone *zone)
{
	return test_bit(ZONE_TAIL_LRU_DIRTY, &zone->flags);
}

static inline int zone_is_reclaim_writeback(const struct zone *zone)
{
	return test_bit(ZONE_WRITEBACK, &zone->flags);
}

static inline int zone_is_reclaim_locked(const struct zone *zone)
{
	return test_bit(ZONE_RECLAIM_LOCKED, &zone->flags);
}

static inline int zone_is_oom_locked(const struct zone *zone)
{
	return test_bit(ZONE_OOM_LOCKED, &zone->flags);
}

static inline unsigned long zone_end_pfn(const struct zone *zone)
{
	return zone->zone_start_pfn + zone->spanned_pages;
}

// ARM10C 20140118
// ARM10C 20140517
// zone: contig_page_data->node_zones[0], start_pfn: 0x20000
static inline bool zone_spans_pfn(const struct zone *zone, unsigned long pfn)
{
	return zone->zone_start_pfn <= pfn && pfn < zone_end_pfn(zone);
}

// ARM10C 20140405
static inline bool zone_is_initialized(struct zone *zone)
{
	return !!zone->wait_table;
}

static inline bool zone_is_empty(struct zone *zone)
{
	return zone->spanned_pages == 0;
}

/*
 * The "priority" of VM scanning is how much of the queues we will scan in one
 * go. A value of 12 for DEF_PRIORITY implies that we will scan 1/4096th of the
 * queues ("queue_length >> 12") during an aging round.
 */
#define DEF_PRIORITY 12

/* Maximum number of zones on a zonelist */
// ARM10C 20140426
// MAX_NUMNODES: 1, MAX_NR_ZONES 3
// MAX_ZONES_PER_ZONELIST: 3
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)

#ifdef CONFIG_NUMA // CONFIG_NUMA=n

/*
 * The NUMA zonelists are doubled because we need zonelists that restrict the
 * allocations to a single node for GFP_THISNODE.
 *
 * [0]	: Zonelist with fallback
 * [1]	: No fallback (GFP_THISNODE)
 */
#define MAX_ZONELISTS 2


/*
 * We cache key information from each zonelist for smaller cache
 * footprint when scanning for free pages in get_page_from_freelist().
 *
 * 1) The BITMAP fullzones tracks which zones in a zonelist have come
 *    up short of free memory since the last time (last_fullzone_zap)
 *    we zero'd fullzones.
 * 2) The array z_to_n[] maps each zone in the zonelist to its node
 *    id, so that we can efficiently evaluate whether that node is
 *    set in the current tasks mems_allowed.
 *
 * Both fullzones and z_to_n[] are one-to-one with the zonelist,
 * indexed by a zones offset in the zonelist zones[] array.
 *
 * The get_page_from_freelist() routine does two scans.  During the
 * first scan, we skip zones whose corresponding bit in 'fullzones'
 * is set or whose corresponding node in current->mems_allowed (which
 * comes from cpusets) is not set.  During the second scan, we bypass
 * this zonelist_cache, to ensure we look methodically at each zone.
 *
 * Once per second, we zero out (zap) fullzones, forcing us to
 * reconsider nodes that might have regained more free memory.
 * The field last_full_zap is the time we last zapped fullzones.
 *
 * This mechanism reduces the amount of time we waste repeatedly
 * reexaming zones for free memory when they just came up low on
 * memory momentarilly ago.
 *
 * The zonelist_cache struct members logically belong in struct
 * zonelist.  However, the mempolicy zonelists constructed for
 * MPOL_BIND are intentionally variable length (and usually much
 * shorter).  A general purpose mechanism for handling structs with
 * multiple variable length members is more mechanism than we want
 * here.  We resort to some special case hackery instead.
 *
 * The MPOL_BIND zonelists don't need this zonelist_cache (in good
 * part because they are shorter), so we put the fixed length stuff
 * at the front of the zonelist struct, ending in a variable length
 * zones[], as is needed by MPOL_BIND.
 *
 * Then we put the optional zonelist cache on the end of the zonelist
 * struct.  This optional stuff is found by a 'zlcache_ptr' pointer in
 * the fixed length portion at the front of the struct.  This pointer
 * both enables us to find the zonelist cache, and in the case of
 * MPOL_BIND zonelists, (which will just set the zlcache_ptr to NULL)
 * to know that the zonelist cache is not there.
 *
 * The end result is that struct zonelists come in two flavors:
 *  1) The full, fixed length version, shown below, and
 *  2) The custom zonelists for MPOL_BIND.
 * The custom MPOL_BIND zonelists have a NULL zlcache_ptr and no zlcache.
 *
 * Even though there may be multiple CPU cores on a node modifying
 * fullzones or last_full_zap in the same zonelist_cache at the same
 * time, we don't lock it.  This is just hint data - if it is wrong now
 * and then, the allocator will still function, perhaps a bit slower.
 */


struct zonelist_cache {
	unsigned short z_to_n[MAX_ZONES_PER_ZONELIST];		/* zone->nid */
	DECLARE_BITMAP(fullzones, MAX_ZONES_PER_ZONELIST);	/* zone full? */
	unsigned long last_full_zap;		/* when last zap'd (jiffies) */
};
#else
// ARM10C 20140308
#define MAX_ZONELISTS 1
struct zonelist_cache;
#endif

/*
 * This struct contains information about a zone in a zonelist. It is stored
 * here to avoid dereferences into large structures and lookups of tables
 */
// ARM10C 20140308
struct zoneref {
	struct zone *zone;	/* Pointer to actual zone */
	int zone_idx;		/* zone_idx(zoneref->zone) */
};

/*
 * One allocation request operates on a zonelist. A zonelist
 * is a list of zones, the first one is the 'goal' of the
 * allocation, the other zones are fallback zones, in decreasing
 * priority.
 *
 * If zlcache_ptr is not NULL, then it is just the address of zlcache,
 * as explained above.  If zlcache_ptr is NULL, there is no zlcache.
 * *
 * To speed the reading of the zonelist, the zonerefs contain the zone index
 * of the entry being read. Helper functions to access information given
 * a struct zoneref are
 *
 * zonelist_zone()	- Return the struct zone * for an entry in _zonerefs
 * zonelist_zone_idx()	- Return the index of the zone for an entry
 * zonelist_node_idx()	- Return the index of the node for an entry
 */
// ARM10C 20140426
struct zonelist {
	struct zonelist_cache *zlcache_ptr;		     // NULL or &zlcache
	// MAX_ZONES_PER_ZONELIST: 3
	struct zoneref _zonerefs[MAX_ZONES_PER_ZONELIST + 1];
#ifdef CONFIG_NUMA
	struct zonelist_cache zlcache;			     // optional ...
#endif
};

#ifdef CONFIG_HAVE_MEMBLOCK_NODE_MAP
struct node_active_region {
	unsigned long start_pfn;
	unsigned long end_pfn;
	int nid;
};
#endif /* CONFIG_HAVE_MEMBLOCK_NODE_MAP */

#ifndef CONFIG_DISCONTIGMEM
/* The array of struct pages - for discontigmem use pgdat->lmem_map */
extern struct page *mem_map;
#endif

/*
 * The pg_data_t structure is used in machines with CONFIG_DISCONTIGMEM
 * (mostly NUMA machines?) to denote a higher-level memory zone than the
 * zone denotes.
 *
 * On NUMA machines, each NUMA node would have a pg_data_t to describe
 * it's memory layout.
 *
 * Memory statistics and page replacement data structures are maintained on a
 * per-zone basis.
 */
struct bootmem_data;

// ARM10C 20131207
// ARM10C 20140308
// ARM10C 20150912
typedef struct pglist_data {
	// MAX_NR_ZONES: 3
	struct zone node_zones[MAX_NR_ZONES];
	// MAX_ZONELISTS: 1
	struct zonelist node_zonelists[MAX_ZONELISTS];
	int nr_zones;
#ifdef CONFIG_FLAT_NODE_MEM_MAP	/* means !SPARSEMEM */
	struct page *node_mem_map;
#ifdef CONFIG_MEMCG
	struct page_cgroup *node_page_cgroup;
#endif
#endif
#ifndef CONFIG_NO_BOOTMEM // CONFIG_NO_BOOTMEM=n
	// ARM10C 20131207
	struct bootmem_data *bdata;
#endif
#ifdef CONFIG_MEMORY_HOTPLUG
	/*
	 * Must be held any time you expect node_start_pfn, node_present_pages
	 * or node_spanned_pages stay constant.  Holding this will also
	 * guarantee that any pfn_valid() stays that way.
	 *
	 * pgdat_resize_lock() and pgdat_resize_unlock() are provided to
	 * manipulate node_size_lock without checking for CONFIG_MEMORY_HOTPLUG.
	 *
	 * Nests above zone->lock and zone->span_seqlock
	 */
	spinlock_t node_size_lock;
#endif
	unsigned long node_start_pfn;
	unsigned long node_present_pages; /* total number of physical pages */
	unsigned long node_spanned_pages; /* total size of physical page
					     range, including holes */
	int node_id;
	nodemask_t reclaim_nodes;	/* Nodes allowed to reclaim from */
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	struct task_struct *kswapd;	/* Protected by lock_memory_hotplug() */
	int kswapd_max_order;
	enum zone_type classzone_idx;
#ifdef CONFIG_NUMA_BALANCING
	/*
	 * Lock serializing the per destination node AutoNUMA memory
	 * migration rate limiting data.
	 */
	spinlock_t numabalancing_migrate_lock;

	/* Rate limiting time interval */
	unsigned long numabalancing_migrate_next_window;

	/* Number of pages migrated during the rate limiting time interval */
	unsigned long numabalancing_migrate_nr_pages;
#endif
} pg_data_t;

// ARM10C 20140419
// node_present_pages(nid):
// (&contig_page_data)->node_present_pages
#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#ifdef CONFIG_FLAT_NODE_MEM_MAP
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#else
#define pgdat_page_nr(pgdat, pagenr)	pfn_to_page((pgdat)->node_start_pfn + (pagenr))
#endif
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))

#define node_start_pfn(nid)	(NODE_DATA(nid)->node_start_pfn)
#define node_end_pfn(nid) pgdat_end_pfn(NODE_DATA(nid))

static inline unsigned long pgdat_end_pfn(pg_data_t *pgdat)
{
	return pgdat->node_start_pfn + pgdat->node_spanned_pages;
}

static inline bool pgdat_is_empty(pg_data_t *pgdat)
{
	return !pgdat->node_start_pfn && !pgdat->node_spanned_pages;
}

#include <linux/memory_hotplug.h>

extern struct mutex zonelists_mutex;
void build_all_zonelists(pg_data_t *pgdat, struct zone *zone);
void wakeup_kswapd(struct zone *zone, int order, enum zone_type classzone_idx);
bool zone_watermark_ok(struct zone *z, int order, unsigned long mark,
		int classzone_idx, int alloc_flags);
bool zone_watermark_ok_safe(struct zone *z, int order, unsigned long mark,
		int classzone_idx, int alloc_flags);

// ARM10C 20140111 
enum memmap_context {
	MEMMAP_EARLY,
	MEMMAP_HOTPLUG,
};
extern int init_currently_empty_zone(struct zone *zone, unsigned long start_pfn,
				     unsigned long size,
				     enum memmap_context context);

extern void lruvec_init(struct lruvec *lruvec);

static inline struct zone *lruvec_zone(struct lruvec *lruvec)
{
#ifdef CONFIG_MEMCG
	return lruvec->zone;
#else
	return container_of(lruvec, struct zone, lruvec);
#endif
}

#ifdef CONFIG_HAVE_MEMORY_PRESENT // CONFIG_HAVE_MEMORY_PRESENT=y
// ARM10C 20131207
void memory_present(int nid, unsigned long start, unsigned long end);
#else
static inline void memory_present(int nid, unsigned long start, unsigned long end) {}
#endif

#ifdef CONFIG_HAVE_MEMORYLESS_NODES
int local_memory_node(int node_id);
#else
static inline int local_memory_node(int node_id) { return node_id; };
#endif

#ifdef CONFIG_NEED_NODE_MEMMAP_SIZE
unsigned long __init node_memmap_size_bytes(int, unsigned long, unsigned long);
#endif

/*
 * zone_idx() returns 0 for the ZONE_DMA zone, 1 for the ZONE_NORMAL zone, etc.
 */
// ARM10C 20140111
// ARM10C 20140308
// zone: contig_page_data->node_zones[1]
// ARM10C 20140510
// preferred_zone: (&contig_page_data)->node_zones[0]
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)

// ARM10C 20140308
// zone: contig_page_data->node_zones[2]
// zone: contig_page_data->node_zones[1]
// zone: contig_page_data->node_zones[0]
// ARM10C 20150912
// zone: &(&contig_page_data)->node_zones[0]
static inline int populated_zone(struct zone *zone)
{
	// zone->present_pages: contig_page_data->node_zones[2].present_pages: 0
	// zone->present_pages: contig_page_data->node_zones[1].present_pages: 0x50800
	// zone->present_pages: contig_page_data->node_zones[0].present_pages: 0x2f800
	return (!!zone->present_pages);
	// return 0
	// return 1
	// return 1
}

extern int movable_zone;

// ARM10C 20140111
static inline int zone_movable_is_highmem(void)
{
#if defined(CONFIG_HIGHMEM) && defined(CONFIG_HAVE_MEMBLOCK_NODE_MAP) // CONFIG_HIGHMEM=y, CONFIG_HAVE_MEMBLOCK_NODE_MAP=n
	return movable_zone == ZONE_HIGHMEM;
#else
	return 0; // this
#endif
}

// ARM10C 20140111
// idx = 0
static inline int is_highmem_idx(enum zone_type idx)
{
#ifdef CONFIG_HIGHMEM // CONFIG_HIGHMEM=y
	// idx = 0 -> return 0;
	return (idx == ZONE_HIGHMEM ||
		(idx == ZONE_MOVABLE && zone_movable_is_highmem()));
#else
	return 0;
#endif
}

/**
 * is_highmem - helper function to quickly check if a struct zone is a 
 *              highmem zone or not.  This is an attempt to keep references
 *              to ZONE_{DMA/NORMAL/HIGHMEM/etc} in general code to a minimum.
 * @zone - pointer to struct zone variable
 */
// ARM10C 20140125
// ARM10C 20140405
// ARM10C 20140531
static inline int is_highmem(struct zone *zone)
{
#ifdef CONFIG_HIGHMEM // CONFIG_HIGHMEM=y
	// zone_off: zone의 offset을 구함, zone_off: 0
	int zone_off = (char *)zone - (char *)zone->zone_pgdat->node_zones;

	// sizeof(*zone): 804, ZONE_HIGHMEM: 1, ZONE_MOVABLE: 2
	return zone_off == ZONE_HIGHMEM * sizeof(*zone) ||
	       (zone_off == ZONE_MOVABLE * sizeof(*zone) &&
		zone_movable_is_highmem());
	// return 0
#else
	return 0;
#endif
}

/* These two functions are used to setup the per zone pages min values */
struct ctl_table;
int min_free_kbytes_sysctl_handler(struct ctl_table *, int,
					void __user *, size_t *, loff_t *);
extern int sysctl_lowmem_reserve_ratio[MAX_NR_ZONES-1];
int lowmem_reserve_ratio_sysctl_handler(struct ctl_table *, int,
					void __user *, size_t *, loff_t *);
int percpu_pagelist_fraction_sysctl_handler(struct ctl_table *, int,
					void __user *, size_t *, loff_t *);
int sysctl_min_unmapped_ratio_sysctl_handler(struct ctl_table *, int,
			void __user *, size_t *, loff_t *);
int sysctl_min_slab_ratio_sysctl_handler(struct ctl_table *, int,
			void __user *, size_t *, loff_t *);

extern int numa_zonelist_order_handler(struct ctl_table *, int,
			void __user *, size_t *, loff_t *);
extern char numa_zonelist_order[];
#define NUMA_ZONELIST_ORDER_LEN 16	/* string buffer size */

#ifndef CONFIG_NEED_MULTIPLE_NODES

extern struct pglist_data contig_page_data;	// bitmap 정보가 들어가있음 
// ARM10C 20131207
// ARM10C 20140308
// ARM10C 20140329
// ARM10C 20140419
// ARM10C 20160528
#define NODE_DATA(nid)		(&contig_page_data)
// ARM10C 20140329
#define NODE_MEM_MAP(nid)	mem_map

#else /* CONFIG_NEED_MULTIPLE_NODES */

#include <asm/mmzone.h>

#endif /* !CONFIG_NEED_MULTIPLE_NODES */

extern struct pglist_data *first_online_pgdat(void);
extern struct pglist_data *next_online_pgdat(struct pglist_data *pgdat);
extern struct zone *next_zone(struct zone *zone);

/**
 * for_each_online_pgdat - helper macro to iterate over all online nodes
 * @pgdat - pointer to a pg_data_t variable
 */
// ARM10C 20140329
#define for_each_online_pgdat(pgdat)			\
	for (pgdat = first_online_pgdat();		\
	     pgdat;					\
	     pgdat = next_online_pgdat(pgdat))
/**
 * for_each_zone - helper macro to iterate over all memory zones
 * @zone - pointer to struct zone variable
 *
 * The user only needs to declare the zone variable, for_each_zone
 * fills it in.
 */
#define for_each_zone(zone)			        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))

// ARM10C 20150912
#define for_each_populated_zone(zone)		        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))			\
		if (!populated_zone(zone))		\
			; /* do nothing */		\
		else

// ARM10C 20140308
// ARM10C 20140426
// z: contig_page_data->node_zonelists->_zonerefs[1]
static inline struct zone *zonelist_zone(struct zoneref *zoneref)
{
	// zoneref->zone: contig_page_data->node_zonelists->_zonerefs[1]->zone: contig_page_data->node_zones[0]
	return zoneref->zone;
	// zoneref->zone: contig_page_data->node_zones[0]
}

// ARM10C 20140308
// z: contig_page_data->node_zonelists->_zonerefs
// ARM10C 20140426
// z: contig_page_data->node_zonelists->_zonerefs
static inline int zonelist_zone_idx(struct zoneref *zoneref)
{
	// zoneref->zone_idx: contig_page_data->node_zonelists[0]->_zonerefs[0]->zone_idx
	return zoneref->zone_idx;
	// zoneref->zone_idx: contig_page_data->node_zonelists[0]->_zonerefs[0]->zone_idx: 1
}

static inline int zonelist_node_idx(struct zoneref *zoneref)
{
#ifdef CONFIG_NUMA
	/* zone_to_nid not available in this context */
	return zoneref->zone->node;
#else
	return 0;
#endif /* CONFIG_NUMA */
}

/**
 * next_zones_zonelist - Returns the next zone at or below highest_zoneidx within the allowed nodemask using a cursor within a zonelist as a starting point
 * @z - The cursor used as a starting point for the search
 * @highest_zoneidx - The zone index of the highest zone to return
 * @nodes - An optional nodemask to filter the zonelist with
 * @zone - The first suitable zone found is returned via this parameter
 *
 * This function returns the next zone at or below a given zone index that is
 * within the allowed nodemask using a cursor as the starting point for the
 * search. The zoneref returned is a cursor that represents the current zone
 * being examined. It should be advanced by one before calling
 * next_zones_zonelist again.
 */
struct zoneref *next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes,
					struct zone **zone);

/**
 * first_zones_zonelist - Returns the first zone at or below highest_zoneidx within the allowed nodemask in a zonelist
 * @zonelist - The zonelist to search for a suitable zone
 * @highest_zoneidx - The zone index of the highest zone to return
 * @nodes - An optional nodemask to filter the zonelist with
 * @zone - The first suitable zone found is returned via this parameter
 *
 * This function returns the first zone at or below a given zone index that is
 * within the allowed nodemask. The zoneref returned is a cursor that can be
 * used to iterate the zonelist with next_zones_zonelist by advancing it by
 * one before calling.
 */
// ARM10C 20140308
// first_zones_zonelist(contig_page_data->node_zonelists, 0, 0, &zone);
// ARM10C 20140426
// zonelist: contig_page_data->node_zonelists, high_zoneidx: ZONE_NORMAL: 0
// cpuset_current_mems_allowed: node_states[N_HIGH_MEMORY], &preferred_zone
// ARM10C 20140510
// first_zones_zonelist(contig_page_data->node_zonelists, ZONE_NORMAL, NULL, &zone)
static inline struct zoneref *first_zones_zonelist(struct zonelist *zonelist,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes,
					struct zone **zone)
{
	// zonelist->_zonerefs: contig_page_data->node_zonelists->_zonerefs
	// highest_zoneidx: 0, nodes: 0, &zone
	// ARM10C 20140426
	// zonelist->_zonerefs: contig_page_data->node_zonelists->_zonerefs
	// highest_zoneidx: 0, nodes: &node_states[N_HIGH_MEMORY], zone: &preferred_zone
	return next_zones_zonelist(zonelist->_zonerefs, highest_zoneidx, nodes,
								zone);
	// return contig_page_data->node_zonelists->_zonerefs[1]
}

/**
 * for_each_zone_zonelist_nodemask - helper macro to iterate over valid zones in a zonelist at or below a given zone index and within a nodemask
 * @zone - The current zone in the iterator
 * @z - The current pointer within zonelist->zones being iterated
 * @zlist - The zonelist being iterated
 * @highidx - The zone index of the highest zone to return
 * @nodemask - Nodemask allowed by the allocator
 *
 * This iterator iterates though all zones at or below a given zone index and
 * within a given nodemask
 */
// ARM10C 20140308
// for_each_zone_zonelist_nodemask(zone, z, contig_page_data->node_zonelists, 0, NULL)
//
// #define for_each_zone_zonelist_0(zone, z, contig_page_data->node_zonelists, 0, 0)
//	for (z = first_zones_zonelist(contig_page_data->node_zonelists, 0, 0, &zone);
//		zone;
//		z = next_zones_zonelist(++z, 0, 0, &zone))
//
// ARM10C 20140510
// for_each_zone_zonelist_nodemask(zone, z, contig_page_data->node_zonelists, ZONE_NORMAL, NULL):
//
// for (z = first_zones_zonelist(contig_page_data->node_zonelists, ZONE_NORMAL, NULL, &zone);
//	zone;
//	z = next_zones_zonelist(++z, ZONE_NORMAL, NULL, &zone))
#define for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, nodemask) \
	for (z = first_zones_zonelist(zlist, highidx, nodemask, &zone);	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask, &zone))	\

/**
 * for_each_zone_zonelist - helper macro to iterate over valid zones in a zonelist at or below a given zone index
 * @zone - The current zone in the iterator
 * @z - The current pointer within zonelist->zones being iterated
 * @zlist - The zonelist being iterated
 * @highidx - The zone index of the highest zone to return
 *
 * This iterator iterates though all zones at or below a given zone index.
 */
// ARM10C 20140308
// zonelist: contig_page_data->node_zonelists, offset: 0
//
// #define for_each_zone_zonelist(zone, z, contig_page_data->node_zonelists, 0)
// 	for_each_zone_zonelist_nodemask(zone, z, contig_page_data->node_zonelists, 0, NULL)
#define for_each_zone_zonelist(zone, z, zlist, highidx) \
	for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, NULL)

#ifdef CONFIG_SPARSEMEM
#include <asm/sparsemem.h>
#endif

#if !defined(CONFIG_HAVE_ARCH_EARLY_PFN_TO_NID) && \
	!defined(CONFIG_HAVE_MEMBLOCK_NODE_MAP)
static inline unsigned long early_pfn_to_nid(unsigned long pfn)
{
	return 0;
}
#endif

#ifdef CONFIG_FLATMEM
#define pfn_to_nid(pfn)		(0)
#endif

#ifdef CONFIG_SPARSEMEM // CONFIG_SPARSEMEM=y

/*
 * SECTION_SHIFT    		#bits space required to store a section #
 *
 * PA_SECTION_SHIFT		physical address to/from section number
 * PFN_SECTION_SHIFT		pfn to/from section number
 */
#define PA_SECTION_SHIFT	(SECTION_SIZE_BITS)
// ARM10C 20131207
// SECTION_SIZE_BITS: 28
// PFN_SECTION_SHIFT: 16
#define PFN_SECTION_SHIFT	(SECTION_SIZE_BITS - PAGE_SHIFT)

// ARM10C 20131207
// SECTIONS_SHIFT: 4
// NR_MEM_SECTIONS: 0x10
#define NR_MEM_SECTIONS		(1UL << SECTIONS_SHIFT)

// ARM10C 20131207
// ARM10C 20140329
// PFN_SECTION_SHIFT: 16
// PAGES_PER_SECTION: 0x10000
#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
// ARM10C 20131207
// PAGE_SECTION_MASK
// PAGES_PER_SECTION: 0x10000
// PAGE_SECTION_MASK: 0xFFFF0000
#define PAGE_SECTION_MASK	(~(PAGES_PER_SECTION-1))

// ARM10C 20131214
// PFN_SECTION_SHIFT: 16, pageblock_order: 9, NR_PAGEBLOCK_BITS: 4
// PFN_SECTION_SHIFT - pageblock_order: 7
// SECTION_BLOCKFLAGS_BITS: (1UL << 7) * 4: 0x80 * 4: 0x200
#define SECTION_BLOCKFLAGS_BITS \
	((1UL << (PFN_SECTION_SHIFT - pageblock_order)) * NR_PAGEBLOCK_BITS)

#if (MAX_ORDER - 1 + PAGE_SHIFT) > SECTION_SIZE_BITS
#error Allocator MAX_ORDER exceeds SECTION_SIZE
#endif

// ARM10C 20131207
// PFN_SECTION_SHIFT: 16
// ARM10C 20140118
// ARM10C 20140329
// 0xA0000
#define pfn_to_section_nr(pfn) ((pfn) >> PFN_SECTION_SHIFT)
// ARM10C 20131221
// PFN_SECTION_SHIFT: 16
#define section_nr_to_pfn(sec) ((sec) << PFN_SECTION_SHIFT)

#define SECTION_ALIGN_UP(pfn)	(((pfn) + PAGES_PER_SECTION - 1) & PAGE_SECTION_MASK)
#define SECTION_ALIGN_DOWN(pfn)	((pfn) & PAGE_SECTION_MASK)

struct page;
struct page_cgroup;
// ARM10C 20131207
struct mem_section {
	/*
	 * This is, logically, a pointer to an array of struct
	 * pages.  However, it is stored with some other magic.
	 * (see sparse.c::sparse_init_one_section())
	 *
	 * Additionally during early boot we encode node id of
	 * the location of the section here to guide allocation.
	 * (see sparse.c::memory_present())
	 *
	 * Making it a UL at least makes someone do a cast
	 * before using it wrong.
	 */
	unsigned long section_mem_map;

	/* See declaration of similar field in struct zone */
	unsigned long *pageblock_flags;
#ifdef CONFIG_MEMCG // CONFIG_MEMCG=n
	/*
	 * If !SPARSEMEM, pgdat doesn't have page_cgroup pointer. We use
	 * section. (see memcontrol.h/page_cgroup.h about this.)
	 */
	struct page_cgroup *page_cgroup;
	unsigned long pad;
#endif
	/*
	 * WARNING: mem_section must be a power-of-2 in size for the
	 * calculation and use of SECTION_ROOT_MASK to make sense.
	 */
};

#ifdef CONFIG_SPARSEMEM_EXTREME // CONFIG_SPARSEMEM_EXTREME=y
// ARM10C 20131207
// PAGE_SIZE: 0x1000, sizeof (struct mem_section): 8
// SECTIONS_PER_ROOT: 0x200
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#else
#define SECTIONS_PER_ROOT	1
#endif

// ARM10C 20131207
// SECTIONS_PER_ROOT: 0x200
#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
// ARM10C 20131207
// NR_MEM_SECTIONS: 0x10, SECTIONS_PER_ROOT: 0x200
// DIV_ROUND_UP(0x10,0x200): 1 
// NR_SECTION_ROOTS: 1
#define NR_SECTION_ROOTS	DIV_ROUND_UP(NR_MEM_SECTIONS, SECTIONS_PER_ROOT)
// ARM10C 20131214
// SECTION_ROOT_MASK: 0x1FF
#define SECTION_ROOT_MASK	(SECTIONS_PER_ROOT - 1)

#ifdef CONFIG_SPARSEMEM_EXTREME // CONFIG_SPARSEMEM_EXTREME=y
// ARM10C 20131214
extern struct mem_section *mem_section[NR_SECTION_ROOTS];
#else
extern struct mem_section mem_section[NR_SECTION_ROOTS][SECTIONS_PER_ROOT];
#endif

// ARM10C 20131214
// section: 0x2
static inline struct mem_section *__nr_to_section(unsigned long nr)
{
	// SECTION_NR_TO_ROOT(0x2): 0x0
	// mem_section[0]: NULL 아닌 값
	if (!mem_section[SECTION_NR_TO_ROOT(nr)])
		return NULL;

	// SECTION_ROOT_MASK: 0x1FF
	// &mem_section[0][2] 
	return &mem_section[SECTION_NR_TO_ROOT(nr)][nr & SECTION_ROOT_MASK];
}
extern int __section_nr(struct mem_section* ms);
extern unsigned long usemap_size(void);

/*
 * We use the lower bits of the mem_map pointer to store
 * a little bit of information.  There should be at least
 * 3 bits here due to 32-bit alignment.
 */
// ARM10C 20131214
// SECTION_MARKED_PRESENT: 1
#define	SECTION_MARKED_PRESENT	(1UL<<0)
// ARM10C 20131221
// SECTION_HAS_MEM_MAP : 2
#define SECTION_HAS_MEM_MAP	(1UL<<1)
#define SECTION_MAP_LAST_BIT	(1UL<<2)
// ARM10C 20131221
// SECTION_MAP_MASK : 0xFFFFFFFC
#define SECTION_MAP_MASK	(~(SECTION_MAP_LAST_BIT-1))
// ARM10C 20131214
#define SECTION_NID_SHIFT	2

// ARM10C 20140118
// __sec : &mem_section[0][2]
// ARM10C 20140329
// &mem_section[0][0xA]
static inline struct page *__section_mem_map_addr(struct mem_section *section)
{
	unsigned long map = section->section_mem_map;
	// 이전에 할당받은 섹션에 대한 struct page용 공간의 시작 주소 정보
	map &= SECTION_MAP_MASK;
	return (struct page *)map;
}

// ARM10C 20131214
static inline int present_section(struct mem_section *section)
{
	// SECTION_MARKED_PRESENT: 1
	return (section && (section->section_mem_map & SECTION_MARKED_PRESENT));
}

// ARM10C 20131214
static inline int present_section_nr(unsigned long nr)
{
	return present_section(__nr_to_section(nr));
}

static inline int valid_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_HAS_MEM_MAP));
}

static inline int valid_section_nr(unsigned long nr)
{
	return valid_section(__nr_to_section(nr));
}

// ARM10C 20140118
// pfn : 0x20000
// ARM10C 20140329
// __pfn_to_section(0xA0000)
static inline struct mem_section *__pfn_to_section(unsigned long pfn)
{
	// pfn_to_section_nr(pfn) : 2
	// pfn_to_section_nr(pfn) : 0xA
	return __nr_to_section(pfn_to_section_nr(pfn));
	// return : &mem_section[0][2]
	// return : &mem_section[0][0xA]
}

#ifndef CONFIG_HAVE_ARCH_PFN_VALID
static inline int pfn_valid(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return valid_section(__nr_to_section(pfn_to_section_nr(pfn)));
}
#endif

static inline int pfn_present(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return present_section(__nr_to_section(pfn_to_section_nr(pfn)));
}

/*
 * These are _only_ used during initialisation, therefore they
 * can use __initdata ...  They could have names to indicate
 * this restriction.
 */
#ifdef CONFIG_NUMA
#define pfn_to_nid(pfn)							\
({									\
	unsigned long __pfn_to_nid_pfn = (pfn);				\
	page_to_nid(pfn_to_page(__pfn_to_nid_pfn));			\
})
#else
#define pfn_to_nid(pfn)		(0)
#endif

// ARM10C 20140118
#define early_pfn_valid(pfn)	pfn_valid(pfn)
void sparse_init(void);
#else
#define sparse_init()	do {} while (0)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#endif /* CONFIG_SPARSEMEM */

#ifdef CONFIG_NODES_SPAN_OTHER_NODES	// N
bool early_pfn_in_nid(unsigned long pfn, int nid);
#else
// ARM10C 20140118
#define early_pfn_in_nid(pfn, nid)	(1)
#endif

#ifndef early_pfn_valid
#define early_pfn_valid(pfn)	(1)
#endif

void memory_present(int nid, unsigned long start, unsigned long end);
unsigned long __init node_memmap_size_bytes(int, unsigned long, unsigned long);

/*
 * If it is possible to have holes within a MAX_ORDER_NR_PAGES, then we
 * need to check pfn validility within that MAX_ORDER_NR_PAGES block.
 * pfn_valid_within() should be used in this case; we optimise this away
 * when we have no holes within a MAX_ORDER_NR_PAGES block.
 */
#ifdef CONFIG_HOLES_IN_ZONE // CONFIG_HOLES_IN_ZONE=n
#define pfn_valid_within(pfn) pfn_valid(pfn)
#else
// ARM10C 20140405
// ARM10C 20140517
#define pfn_valid_within(pfn) (1)
#endif

#ifdef CONFIG_ARCH_HAS_HOLES_MEMORYMODEL
/*
 * pfn_valid() is meant to be able to tell if a given PFN has valid memmap
 * associated with it or not. In FLATMEM, it is expected that holes always
 * have valid memmap as long as there is valid PFNs either side of the hole.
 * In SPARSEMEM, it is assumed that a valid section has a memmap for the
 * entire section.
 *
 * However, an ARM, and maybe other embedded architectures in the future
 * free memmap backing holes to save memory on the assumption the memmap is
 * never used. The page_zone linkages are then broken even though pfn_valid()
 * returns true. A walker of the full memmap must then do this additional
 * check to ensure the memmap they are looking at is sane by making sure
 * the zone and PFN linkages are still valid. This is expensive, but walkers
 * of the full memmap are extremely rare.
 */
int memmap_valid_within(unsigned long pfn,
					struct page *page, struct zone *zone);
#else
static inline int memmap_valid_within(unsigned long pfn,
					struct page *page, struct zone *zone)
{
	return 1;
}
#endif /* CONFIG_ARCH_HAS_HOLES_MEMORYMODEL */

#endif /* !__GENERATING_BOUNDS.H */
#endif /* !__ASSEMBLY__ */
#endif /* _LINUX_MMZONE_H */
