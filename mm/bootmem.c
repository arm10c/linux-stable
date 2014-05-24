/*
 *  bootmem - A boot-time physical memory allocator and configurator
 *
 *  Copyright (C) 1999 Ingo Molnar
 *                1999 Kanoj Sarcar, SGI
 *                2008 Johannes Weiner
 *
 * Access to this subsystem has to be serialized externally (which is true
 * for the boot process anyway).
 */
#include <linux/init.h>
#include <linux/pfn.h>
#include <linux/slab.h>
#include <linux/bootmem.h>
#include <linux/export.h>
#include <linux/kmemleak.h>
#include <linux/range.h>
#include <linux/memblock.h>

#include <asm/bug.h>
#include <asm/io.h>
#include <asm/processor.h>

#include "internal.h"

#ifndef CONFIG_NEED_MULTIPLE_NODES // CONFIG_NEED_MULTIPLE_NODES=n
// ARM10C 20131207
struct pglist_data __refdata contig_page_data = {
	.bdata = &bootmem_node_data[0]
};
EXPORT_SYMBOL(contig_page_data);
#endif

// ARM10C 20140118
// ARM10C 20140419
// max_low_pfn : 0x2F800
unsigned long max_low_pfn;
unsigned long min_low_pfn;
// ARM10C 20140329
// max_pfn : 0x80000
unsigned long max_pfn;

// ARM10C 20131207
// MAX_NUMNODES: 1
// ARM10C 20140329
bootmem_data_t bootmem_node_data[MAX_NUMNODES] __initdata;

// ARM10C 20131207
// ARM10C 20140329
static struct list_head bdata_list __initdata = LIST_HEAD_INIT(bdata_list);

static int bootmem_debug;

static int __init bootmem_debug_setup(char *buf)
{
	bootmem_debug = 1;
	return 0;
}
early_param("bootmem_debug", bootmem_debug_setup);

#define bdebug(fmt, args...) ({				\
	if (unlikely(bootmem_debug))			\
		printk(KERN_INFO			\
			"bootmem::%s " fmt,		\
			__func__, ## args);		\
})

// ARM10C 20131207
// pages: 0x2f800
static unsigned long __init bootmap_bytes(unsigned long pages)
{
	// pages: 0x2f800
	// DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
	// bytes: 0x5F00
	unsigned long bytes = DIV_ROUND_UP(pages, 8);

	return ALIGN(bytes, sizeof(long));
}

/**
 * bootmem_bootmap_pages - calculate bitmap size in pages
 * @pages: number of pages the bitmap has to represent
 */
// ARM10C 20131207
// end_pfn - start_pfn: 0x2f800
// ARM10C 20140412
// 0x2f800
unsigned long __init bootmem_bootmap_pages(unsigned long pages)
{
	// pages: 0x2f800, bytes: 0x5F00
	unsigned long bytes = bootmap_bytes(pages);

	// bytes: 0x5F00, PAGE_ALIGN(0x5F00): 0x6000
	// PAGE_ALIGN(0x5F00) >> PAGE_SHIFT: 0x6
	return PAGE_ALIGN(bytes) >> PAGE_SHIFT;
}

/*
 * link bdata in order
 */
// ARM10C 20131207
static void __init link_bootmem(bootmem_data_t *bdata)
{
	bootmem_data_t *ent;

	list_for_each_entry(ent, &bdata_list, list) {
		if (bdata->node_min_pfn < ent->node_min_pfn) {
			list_add_tail(&bdata->list, &ent->list);
			return;
		}
	}

	list_add_tail(&bdata->list, &bdata_list);
}

/*
 * Called once to set up the allocator itself.
 */
// ARM10C 20131207
// pgdat->bdata: ?, freepfn: ?, startpfn: 0x20000, endpfn: 0x4f800
static unsigned long __init init_bootmem_core(bootmem_data_t *bdata,
	unsigned long mapstart, unsigned long start, unsigned long end)
{
	unsigned long mapsize;

	// start: 0x20000, end: 0x4f800
	mminit_validate_memmodel_limits(&start, &end);
	bdata->node_bootmem_map = phys_to_virt(PFN_PHYS(mapstart));
	// bdata->node_min_pfn: 0x20000
	bdata->node_min_pfn = start;
	// bdata->node_low_pfn: 0x4f800
	bdata->node_low_pfn = end;
	link_bootmem(bdata);

	/*
	 * Initially all pages are reserved - setup_arch() has to
	 * register free RAM areas explicitly.
	 */
	// start: 0x20000, end: 0x4f800, end - start: 0x2f800
	// mapsize: 0x5F00
	mapsize = bootmap_bytes(end - start);
	memset(bdata->node_bootmem_map, 0xff, mapsize);

	bdebug("nid=%td start=%lx map=%lx end=%lx mapsize=%lx\n",
		bdata - bootmem_node_data, start, mapstart, end, mapsize);

	// mapsize: 0x5F00
	return mapsize;
}

/**
 * init_bootmem_node - register a node as boot memory
 * @pgdat: node to register
 * @freepfn: pfn where the bitmap for this node is to be placed
 * @startpfn: first pfn on the node
 * @endpfn: first pfn after the node
 *
 * Returns the number of bytes needed to hold the bitmap for this node.
 */
// ARM10C 20131207
// pgdat: ?, __phys_to_pfn(bitmap): ?, start_pfn: 0x20000, end_pfn: 0x4f800
unsigned long __init init_bootmem_node(pg_data_t *pgdat, unsigned long freepfn,
				unsigned long startpfn, unsigned long endpfn)
{
	// pgdat->bdata: ?, freepfn: ?, startpfn: 0x20000, endpfn: 0x4f800
	return init_bootmem_core(pgdat->bdata, freepfn, startpfn, endpfn);
}

/**
 * init_bootmem - register boot memory
 * @start: pfn where the bitmap is to be placed
 * @pages: number of available physical pages
 *
 * Returns the number of bytes needed to hold the bitmap.
 */
unsigned long __init init_bootmem(unsigned long start, unsigned long pages)
{
	max_low_pfn = pages;
	min_low_pfn = start;
	return init_bootmem_core(NODE_DATA(0)->bdata, start, 0, pages);
}

/*
 * free_bootmem_late - free bootmem pages directly to page allocator
 * @addr: starting physical address of the range
 * @size: size of the range in bytes
 *
 * This is only useful when the bootmem allocator has already been torn
 * down, but we are still initializing the system.  Pages are given directly
 * to the page allocator, no bootmem metadata is updated because it is gone.
 */
void __init free_bootmem_late(unsigned long physaddr, unsigned long size)
{
	unsigned long cursor, end;

	kmemleak_free_part(__va(physaddr), size);

	cursor = PFN_UP(physaddr);
	end = PFN_DOWN(physaddr + size);

	for (; cursor < end; cursor++) {
		__free_pages_bootmem(pfn_to_page(cursor), 0);
		totalram_pages++;
	}
}

// ARM10C 20140329
// bdata: &bdata_list
static unsigned long __init free_all_bootmem_core(bootmem_data_t *bdata)
{
	struct page *page;
	unsigned long *map, start, end, pages, count = 0;

	// bdata->node_bootmem_map: (&bdata_list)->node_bootmem_map: NULL 아닌 값
	if (!bdata->node_bootmem_map)
		return 0;

	// bdata->node_bootmem_map: (&bdata_list)->node_bootmem_map
	map = bdata->node_bootmem_map;
	// map: (&bdata_list)->node_bootmem_map

	// bdata->node_min_pfn: (&bdata_list)->node_min_pfn: 0x20000
	start = bdata->node_min_pfn;
	// start: 0x20000

	// bdata->node_low_pfn: (&bdata_list)->node_low_pfn: 0x4f800
	end = bdata->node_low_pfn;
	// end: 0x4f800

	bdebug("nid=%td start=%lx end=%lx\n",
		bdata - bootmem_node_data, start, end);
	// "nid=0 start=0x20000 end=0x4f800"

	// start: 0x20000, end: 0x4f800
	while (start < end) {
		unsigned long idx, vec;
		unsigned shift;

		// start: 0x20000
		// bdata->node_min_pfn: (&bdata_list)->node_min_pfn: 0x20000
		idx = start - bdata->node_min_pfn;
		// idx: 0

		// BITS_PER_LONG: 32
		shift = idx & (BITS_PER_LONG - 1);
		// shift: 0

		/*
		 * vec holds at most BITS_PER_LONG map bits,
		 * bit 0 corresponds to start.
		 */
		// idx: 0, BITS_PER_LONG: 32
		// map: (&bdata_list)->node_bootmem_map
		vec = ~map[idx / BITS_PER_LONG];
		// vec: ~((&bdata_list)->node_bootmem_map[0])

		// shift: 0
		if (shift) {
			vec >>= shift;
			if (end - start >= BITS_PER_LONG)
				vec |= ~map[idx / BITS_PER_LONG + 1] <<
					(BITS_PER_LONG - shift);
		}
		/*
		 * If we have a properly aligned and fully unreserved
		 * BITS_PER_LONG block of pages in front of us, free
		 * it in one go.
		 */
		// start: 0x20000, BITS_PER_LONG: 32, ~0: 0xFFFFFFFF
		// vec: ~((&bdata_list)->node_bootmem_map[0])
		if (IS_ALIGNED(start, BITS_PER_LONG) && vec == ~0UL) {
			// node_bootmem_map[0]의 값이 0일 경우로 가정

			// BITS_PER_LONG: 32, ilog2(BITS_PER_LONG): 5
			int order = ilog2(BITS_PER_LONG);
			// order: 5

			// start: 0x20000, pfn_to_page(0x20000): 0x20000의 해당하는 struct page의 주소
			__free_pages_bootmem(pfn_to_page(start), order);
			// CPU0의 vm_event_states.event[PGFREE] 를 32로 설정함
			// page에 해당하는 pageblock의 migrate flag를 반환함
			// struct page의 index 멤버에 migratetype을 저장함
			// struct page의 _count 멥버의 값을 0 으로 초기화함
			// order 5 buddy를 contig_page_data에 추가함
			// (&contig_page_data)->node_zones[ZONE_NORMAL].vm_stat[NR_FREE_PAGES]: 32 로 설정
			// vmstat.c의 vm_stat[NR_FREE_PAGES] 전역 변수에도 32로 설정

			// count: 0, BITS_PER_LONG: 32
			count += BITS_PER_LONG;
			// count: 32

			// start: 0x20000 (pfn), BITS_PER_LONG: 32
			start += BITS_PER_LONG;
			// start: 0x20020
		} else {
			// node_bootmem_map[0]의 값이 0아닐 경우로 가정
			// node_bootmem_map[0]의 값이 0x000000F0 로 가정하고 분석

			// start: 0x20000
			unsigned long cur = start;
			// cur: 0x20000

			// start: 0x20000, BITS_PER_LONG: 32
			start = ALIGN(start + 1, BITS_PER_LONG);
			// start: 0x20020

			// vec: ~((&bdata_list)->node_bootmem_map[0]): 0xffffff0f,
			// start: 0x20020, cur: 0x20000
			while (vec && cur != start) {
				// vec: 0xffffff0f
				if (vec & 1) {
					// cur: 0x20000
					page = pfn_to_page(cur);
					// page: 0x20000 (pfn)

					// page: 0x20000 (pfn), 0
					__free_pages_bootmem(page, 0);
					// CPU0의 vm_event_states.event[PGFREE] 를 1로 설정함
					// page에 해당하는 pageblock의 migrate flag를 반환함
					// struct page의 index 멤버에 migratetype을 저장함
					// struct page의 _count 멥버의 값을 0 으로 초기화함
					// order 0 buddy를 contig_page_data에 추가함
					// (&contig_page_data)->node_zones[ZONE_NORMAL].vm_stat[NR_FREE_PAGES]: 1 로 설정
					// vmstat.c의 vm_stat[NR_FREE_PAGES] 전역 변수에도 1로 설정

					// count: 0
					count++;
					// count: 1
				}
				// vec: 0xffffff0f
				vec >>= 1;
				// vec: 0x7fffff87

				// cur: 0x20000
				++cur;
				// cur: 0x20001
			}
			// cur이 0x20000 ~ 0x20020까지 수행됨
		}
	}
	
	// CPU0의 vm_event_states.event[PGFREE] 를 order로 설정함
	// page에 해당하는 pageblock의 migrate flag를 반환함
	// struct page의 index 멤버에 migratetype을 저장함
	// order 값의 buddy를 contig_page_data에 추가함
	// (&contig_page_data)->node_zones[ZONE_NORMAL].vm_stat[NR_FREE_PAGES]: 2^order 값으로 설정
	// vmstat.c의 vm_stat[NR_FREE_PAGES] 전역 변수에도 2^order 로 설정
	// 현재 page의 page->private값과 buddy의 page->private값이 같으면 page order를 합치는 작업 수행

	// bdata->node_bootmem_map: (&bdata_list)->node_bootmem_map: NULL 아닌 값
	page = virt_to_page(bdata->node_bootmem_map);
	// page: bdata->node_bootmem_map (pfn)

	// bdata->node_low_pfn: (&bdata_list)->node_low_pfn: 0x4f800
	// bdata->node_min_pfn: (&bdata_list)->node_min_pfn: 0x20000
	pages = bdata->node_low_pfn - bdata->node_min_pfn;
	// pages: 0x2f800

	// bootmem_bootmap_pages(0x2f800): 0x6
	pages = bootmem_bootmap_pages(pages);
	// pages: 0x6

	// count: 총 free된 page 수
	count += pages;
	// count: 총 free된 page 수 + 0x6

	// pages: 0x6
	while (pages--)
		__free_pages_bootmem(page++, 0);
		// bdata->node_bootmem_map에서 사용하던 page를 free시킴
		// 이제부터는 buddy로 관리

	// count: 총 free된 page 수 + 0x6
	bdebug("nid=%td released=%lx\n", bdata - bootmem_node_data, count);
	// "nid=0 released=????"

	// count: 총 free된 page 수 + 0x6
	return count;
}

// ARM10C 20140329
// reset_managed_pages_done: 1
static int reset_managed_pages_done __initdata;

// ARM10C 20140329
// pgdat: &contig_page_data
static inline void __init reset_node_managed_pages(pg_data_t *pgdat)
{
	struct zone *z;

	// reset_managed_pages_done: 0
	if (reset_managed_pages_done)
		return;

	// pgdat->node_zones: (&contig_page_data)->node_zones, MAX_NR_ZONES: 3
	for (z = pgdat->node_zones; z < pgdat->node_zones + MAX_NR_ZONES; z++)
		// [1st] z->managed_pages: (&contig_page_data)->node_zones[0].managed_pages: 0x2efd6
		// [2nd] z->managed_pages: (&contig_page_data)->node_zones[1].managed_pages: 0x50800
		// [3rd] z->managed_pages: (&contig_page_data)->node_zones[2].managed_pages: 0x0
		z->managed_pages = 0;
		// [1st] z->managed_pages: (&contig_page_data)->node_zones[0].managed_pages: 0x0
		// [2nd] z->managed_pages: (&contig_page_data)->node_zones[1].managed_pages: 0x0
		// [3rd] z->managed_pages: (&contig_page_data)->node_zones[2].managed_pages: 0x0
}

// ARM10C 20140329
void __init reset_all_zones_managed_pages(void)
{
	struct pglist_data *pgdat;

	for_each_online_pgdat(pgdat)
	// for (pgdat = first_online_pgdat(); pgdat; pgdat = next_online_pgdat(pgdat))
		// first_online_pgdat(): &contig_page_data, pgdat: &contig_page_data
		reset_node_managed_pages(pgdat);

	// reset_managed_pages_done: 0
	reset_managed_pages_done = 1;
	// reset_managed_pages_done: 1
}

/**
 * free_all_bootmem - release free pages to the buddy allocator
 *
 * Returns the number of pages actually released.
 */
// ARM10C 20140329
unsigned long __init free_all_bootmem(void)
{
	unsigned long total_pages = 0;
	bootmem_data_t *bdata;

	reset_all_zones_managed_pages();

	list_for_each_entry(bdata, &bdata_list, list)
	// for (bdata = list_entry((&bdata_list)->next, typeof(*bdata), list);
	//     &bdata->list != (&bdata_list);
	//     bdata = list_entry(bdata->list.next, typeof(*bdata), list))
		// bdata: &bdata_list, &bdata->list: (&bdata_list)->list
		total_pages += free_all_bootmem_core(bdata);
		// total_page: 총 free된 page 수 + 0x6

	// totalram_pages: 0
	totalram_pages += total_pages;
	// totalram_pages: 총 free된 page 수 + 0x6

	// total_page: 총 free된 page 수 + 0x6
	return total_pages;
}

// ARM10C 20131207
// bdata: ?, sidx: 0x0, eidx: 0x2f800
static void __init __free(bootmem_data_t *bdata,
			unsigned long sidx, unsigned long eidx)
{
	unsigned long idx;

	// sidx: 0x0, bdata->node_min_pfn: 0x20000
	// sidx + bdata->node_min_pfn: 0x20000
	// eidx: 0x2f800
	// eidx + bdata->node_min_pfn: 0x4f800
	bdebug("nid=%td start=%lx end=%lx\n", bdata - bootmem_node_data,
		sidx + bdata->node_min_pfn,
		eidx + bdata->node_min_pfn);

	// bdata->hint_idx: 0, sidx: 0x0
	if (bdata->hint_idx > sidx)
		bdata->hint_idx = sidx;

	// sidx: 0x0, eidx: 0x2f800
	for (idx = sidx; idx < eidx; idx++)
		if (!test_and_clear_bit(idx, bdata->node_bootmem_map))
			BUG();
}

// ARM10C 20131207
// bdata: ?, sidx: 0x4, eidx: 0x8, flags: 0
static int __init __reserve(bootmem_data_t *bdata, unsigned long sidx,
			unsigned long eidx, int flags)
{
	unsigned long idx;
	// BOOTMEM_EXCLUSIVE: 1, exclusive: 0
	int exclusive = flags & BOOTMEM_EXCLUSIVE;

	// sidx: 0x4, bdata->node_min_pfn: 0x20000
	// sidx + bdata->node_min_pfn: 0x20004
	// eidx: 0x8
	// eidx + bdata->node_min_pfn: 0x20008
	bdebug("nid=%td start=%lx end=%lx flags=%x\n",
		bdata - bootmem_node_data,
		sidx + bdata->node_min_pfn,
		eidx + bdata->node_min_pfn,
		flags);

	// sidx: 0x4, eidx: 0x8
	for (idx = sidx; idx < eidx; idx++)
		if (test_and_set_bit(idx, bdata->node_bootmem_map)) {
			// exclusive: 0
			if (exclusive) {
				__free(bdata, sidx, idx);
				return -EBUSY;
			}
			bdebug("silent double reserve of PFN %lx\n",
				idx + bdata->node_min_pfn);
		}
	return 0;
}

// ARM10C 20131207
// bdata: ?, pos: 0x20000, max: 0x4f800, reserve: 0, flags: 0
// bdata: ?, pos: 0x20004, max: 0x20008, reserve: 1, flags: 0
static int __init mark_bootmem_node(bootmem_data_t *bdata,
				unsigned long start, unsigned long end,
				int reserve, int flags)
{
	unsigned long sidx, eidx;

	// start: 0x20000, end: 0x4f800, reserve: 0, flags: 0
	// start: 0x20004, end: 0x20008, reserve: 1, flags: 0
	bdebug("nid=%td start=%lx end=%lx reserve=%d flags=%x\n",
		bdata - bootmem_node_data, start, end, reserve, flags);

	// start: 0x20000, bdata->node_min_pfn: 0x20000
	// start: 0x20004, bdata->node_min_pfn: 0x20000
	BUG_ON(start < bdata->node_min_pfn);

	// end: 0x4f800, bdata->node_low_pfn: 0x4f800
	// end: 0x20008, bdata->node_low_pfn: 0x4f800
	BUG_ON(end > bdata->node_low_pfn);

	// start: 0x20000, bdata->node_min_pfn: 0x20000
	// sidx: 0x0
	// start: 0x20004, bdata->node_min_pfn: 0x20000
	// sidx: 0x4
	sidx = start - bdata->node_min_pfn;

	// end: 0x4f800, bdata->node_min_pfn: 0x20000
	// eidx: 0x2f800
	// end: 0x20008, bdata->node_min_pfn: 0x20000
	// eidx: 0x8
	eidx = end - bdata->node_min_pfn;

	// reserve: 0
	// reserve: 1
	if (reserve)
		// sidx: 0x4, eidx: 0x8, flags: 0
		return __reserve(bdata, sidx, eidx, flags);
	else
		// sidx: 0x0, eidx: 0x2f800
		__free(bdata, sidx, eidx);
	return 0;
}

// ARM10C 20131207
// start: 0x20000, end: 0x4f800, resere: 0, flags: 0
// start: 0x40004, end: 0x40008, resere: 1, flags: 0
static int __init mark_bootmem(unsigned long start, unsigned long end,
				int reserve, int flags)
{
	unsigned long pos;
	bootmem_data_t *bdata;

	// pos: 0x20000
	// pos: 0x40004
	pos = start;
	list_for_each_entry(bdata, &bdata_list, list) {
		int err;
		unsigned long max;

		// pos: 0x20000
		// bdata->node_min_pfn: 0x20000, bdata->node_low_pfn: 0x4f800
		// pos: 0x40004
		// bdata->node_min_pfn: 0x20000, bdata->node_low_pfn: 0x4f800
		if (pos < bdata->node_min_pfn ||
		    pos >= bdata->node_low_pfn) {
			BUG_ON(pos != start);
			continue;
		}

		// bdata->node_low_pfn: 0x4f800, end: 0x4f800
		// max: 0x4f800
		// bdata->node_low_pfn: 0x4f800, end: 0x40008
		// max: 0x40008
		max = min(bdata->node_low_pfn, end);

		// pos: 0x20000, max: 0x4f800, reserve: 0, flags: 0
		// pos: 0x40004, max: 0x40008, reserve: 1, flags: 0
		err = mark_bootmem_node(bdata, pos, max, reserve, flags);
		// resere: 0
		if (reserve && err) {
			mark_bootmem(start, pos, 0, 0);
			return err;
		}

		// max: 0x4f800, end: 0x4f800
		if (max == end)
			return 0;
		pos = bdata->node_low_pfn;
	}
	BUG();
}

/**
 * free_bootmem_node - mark a page range as usable
 * @pgdat: node the range resides on
 * @physaddr: starting address of the range
 * @size: size of the range in bytes
 *
 * Partial pages will be considered reserved and left as they are.
 *
 * The range must reside completely on the specified node.
 */
void __init free_bootmem_node(pg_data_t *pgdat, unsigned long physaddr,
			      unsigned long size)
{
	unsigned long start, end;

	kmemleak_free_part(__va(physaddr), size);

	start = PFN_UP(physaddr);
	end = PFN_DOWN(physaddr + size);

	mark_bootmem_node(pgdat->bdata, start, end, 0, 0);
}

/**
 * free_bootmem - mark a page range as usable
 * @addr: starting physical address of the range
 * @size: size of the range in bytes
 *
 * Partial pages will be considered reserved and left as they are.
 *
 * The range must be contiguous but may span node boundaries.
 */
// ARM10C 20131207
// ARM10C 20131221
// __pfn_to_phys(0x20000): 0x20000000, (end - start) << PAGE_SHIFT: 0x2f800000
// ARM10C 20140308
// __pa(ai): ???, ai->__ai_size: 0x1000
void __init free_bootmem(unsigned long physaddr, unsigned long size)
{
	unsigned long start, end;

	// __va(0x20000000): 0xC0000000, size: 0x2f800000
	kmemleak_free_part(__va(physaddr), size);

	// PFN_UP(0x20000000): 0x20000
	start = PFN_UP(physaddr);
	// PFN_DOWN(0x20000000 + 0x2f800000): 0x4f800
	end = PFN_DOWN(physaddr + size);

	// start: 0x20000, end: 0x4f800
	mark_bootmem(start, end, 0, 0);
}

/**
 * reserve_bootmem_node - mark a page range as reserved
 * @pgdat: node the range resides on
 * @physaddr: starting address of the range
 * @size: size of the range in bytes
 * @flags: reservation flags (see linux/bootmem.h)
 *
 * Partial pages will be reserved.
 *
 * The range must reside completely on the specified node.
 */
int __init reserve_bootmem_node(pg_data_t *pgdat, unsigned long physaddr,
				 unsigned long size, int flags)
{
	unsigned long start, end;

	start = PFN_DOWN(physaddr);
	end = PFN_UP(physaddr + size);

	return mark_bootmem_node(pgdat->bdata, start, end, 1, flags);
}

/**
 * reserve_bootmem - mark a page range as reserved
 * @addr: starting address of the range
 * @size: size of the range in bytes
 * @flags: reservation flags (see linux/bootmem.h)
 *
 * Partial pages will be reserved.
 *
 * The range must be contiguous but may span node boundaries.
 */
// ARM10C 20131207
// __pfn_to_phys(0x40004): 0x40004000, (end - start) << PAGE_SHIFT: 0x4000
// BOOTMEM_DEFAULT: 0
int __init reserve_bootmem(unsigned long addr, unsigned long size,
			    int flags)
{
	unsigned long start, end;

	// PFN_DOWN(0x40004000): 0x40004
	// start: 0x40004
	start = PFN_DOWN(addr);

	// PFN_UP(0x40008000): 0x40008
	// end: 0x40008
	end = PFN_UP(addr + size);

	// start: 0x40004, end: 0x40008, flags: 0
	return mark_bootmem(start, end, 1, flags);
}

// ARM10C 20131214
// bdata: ?, sidx: ?, step: 1
static unsigned long __init align_idx(struct bootmem_data *bdata,
				      unsigned long idx, unsigned long step)
{
	// bdata->node_min_pfn: 0x20000, base: 0x20000
	unsigned long base = bdata->node_min_pfn;

	/*
	 * Align the index with respect to the node start so that the
	 * combination of both satisfies the requested alignment.
	 */

	// base: 0x20000, idx: ?, step: 1 
	return ALIGN(base + idx, step) - base;
}

static unsigned long __init align_off(struct bootmem_data *bdata,
				      unsigned long off, unsigned long align)
{
	unsigned long base = PFN_PHYS(bdata->node_min_pfn);

	/* Same as align_idx for byte offsets */

	return ALIGN(base + off, align) - base;
}

// ARM10C 20131207
// pgdat: ?, size: 0x1000, align: 64, goal: 0x5FFFFFFF, limit: 0
// ARM10C 20131221
// bdata: ?, size: 0x800, align: 64, goal: 0x5FFFFFFF, limit: 0
// ARM10C 20140125
// bdata: ?, size: 0x1C, align: 64, goal: 0x0, limit: 0xFFFFFFFF
static void * __init alloc_bootmem_bdata(struct bootmem_data *bdata,
					unsigned long size, unsigned long align,
					unsigned long goal, unsigned long limit)
{
	// fallback: 대비책 
	// hint_idx 부터 빈공간 찾음
	// 없으면 fallback 으로 돌아가서 다시 검색
	unsigned long fallback = 0;
	unsigned long min, max, start, sidx, midx, step;

	// size: 0x1000, PAGE_ALIGN(0x1000) >> PAGE_SHIFT: 0x1, align: 64 
	// goal: 0x5FFFFFFF, limit: 0
	bdebug("nid=%td size=%lx [%lu pages] align=%lx goal=%lx limit=%lx\n",
		bdata - bootmem_node_data, size, PAGE_ALIGN(size) >> PAGE_SHIFT,
		align, goal, limit);

	// size: 0x1000
	BUG_ON(!size);

	// align: 64, align & (align - 1): 0
	BUG_ON(align & (align - 1));

	// goal: 0x5FFFFFFF, limit: 0, goal + size: 0x60000FFF
	BUG_ON(limit && goal + size > limit);

	// bdata->node_bootmem_map: 0 이 아님
	if (!bdata->node_bootmem_map)
		return NULL;

	// min: 0x20000
	min = bdata->node_min_pfn;
	// max: 0x4f800
	max = bdata->node_low_pfn;

	// goal: 0x5FFFF
	goal >>= PAGE_SHIFT;
	// limit: 0
	limit >>= PAGE_SHIFT;

	// limit: 0, max: 0x4f800
	if (limit && max > limit)
		max = limit;

	// max: 0x4f800, min: 0x20000
	if (max <= min)
		return NULL;

	// align: 0x40, align >> PAGE_SHIFT: 0x0
	// step: 1
	step = max(align >> PAGE_SHIFT, 1UL);

	// goal: 0x5FFFF, max: 0x4f800, min: 0x20000
	if (goal && min < goal && goal < max)
		start = ALIGN(goal, step);
	else
		// min: 0x20000, step: 1
		// start: 0x20000
		start = ALIGN(min, step);

	// start: 0x20000, bdata->node_min_pfn: 0x20000
	// sidx: 0x0
	sidx = start - bdata->node_min_pfn;
	// max: 0x4f800, bdata->node_min_pfn: 0x20000
	// midx: 0x2f800
	midx = max - bdata->node_min_pfn;

	// bdata->hint_idx: 0, sidx: 0x0
	if (bdata->hint_idx > sidx) {
		/*
		 * Handle the valid case of sidx being zero and still
		 * catch the fallback below.
		 */
		fallback = sidx + 1;
		sidx = align_idx(bdata, bdata->hint_idx, step);
	}

	while (1) {
		int merge;
		void *region;
		unsigned long eidx, i, start_off, end_off;
find_block:
	// 2013/12/07 종료
	// 2013/12/14 시작
		// bdata->node_bootmem_map: ?, midx: 0x2f800, sidx: 0x0
		sidx = find_next_zero_bit(bdata->node_bootmem_map, midx, sidx);
		
		// bdata: ?, sidx: ?, step: 1
		sidx = align_idx(bdata, sidx, step);
		// sidx: ?, size: 0x1000, PFN_UP(0x1000): 1
		eidx = sidx + PFN_UP(size);

		// sidx: ?, eidx: ?, midx: 0x2f800
		if (sidx >= midx || eidx > midx)
			break;

		// size 만큼 루프를 돌며 first fit 된 영역을 찾음
		for (i = sidx; i < eidx; i++)
			if (test_bit(i, bdata->node_bootmem_map)) {
				sidx = align_idx(bdata, i, step);
				if (sidx == i)
					sidx += step;
				goto find_block;
			}

		// bdata->last_end_off: 0, (PAGE_SIZE - 1): 0xFFF
		if (bdata->last_end_off & (PAGE_SIZE - 1) &&
				PFN_DOWN(bdata->last_end_off) + 1 == sidx)
			start_off = align_off(bdata, bdata->last_end_off, align);
		else
			// start_off: sidx << 12
			start_off = PFN_PHYS(sidx);

		// merge: 0
		merge = PFN_DOWN(start_off) < sidx;
		// size: 0x1000
		end_off = start_off + size;

		bdata->last_end_off = end_off;
		bdata->hint_idx = PFN_UP(end_off);

		/*
		 * Reserve the area now:
		 */
		// BOOTMEM_EXCLUSIVE: 1
		if (__reserve(bdata, PFN_DOWN(start_off) + merge,
				PFN_UP(end_off), BOOTMEM_EXCLUSIVE))
			BUG();

		// bdata->node_min_pfn: 0x20000, PFN_PHYS(0x20000): 0x20000000
		region = phys_to_virt(PFN_PHYS(bdata->node_min_pfn) +
				start_off);
		// size: 0x1000
		memset(region, 0, size);
		/*
		 * The min_count is set to 0 so that bootmem allocated blocks
		 * are never reported as leaks.
		 */
		// region: ?, size: 0x1000
		kmemleak_alloc(region, size, 0, 0);
		return region;
	}

	if (fallback) {
		sidx = align_idx(bdata, fallback - 1, step);
		fallback = 0;
		goto find_block;
	}

	return NULL;
}

// ARM10C 20131214
// size: 0x1000, align: 64, goal: 0x5FFFFFFF, limit: 0
//
// size: 0x40, align: 64, goal: 0x5FFFFFFF, limit: 0
// size: 0x40, align: 64, goal: 0x0, limit: 0
// ARM10C 20140125
// size: 0x1C, align: 64, goal: 0, limit: 0xffffffffUL
static void * __init alloc_bootmem_core(unsigned long size,
					unsigned long align,
					unsigned long goal,
					unsigned long limit)
{
	bootmem_data_t *bdata;
	void *region;

	// slab_is_available(): 0
	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc(size, GFP_NOWAIT);

	list_for_each_entry(bdata, &bdata_list, list) {
		// ARM10C 20131214
		// goal: 0x5FFFFFFF, bdata->node_low_pfn: 0x4f800, PFN_DOWN(0x5FFFFFFF): 0x5FFFF
		// ARM10C 20140125
		// goal: 0, bdata->node_low_pfn: 0x4f800, PFN_DOWN(0): 0
		if (goal && bdata->node_low_pfn <= PFN_DOWN(goal))
			continue;

		// ARM10C 20131214
		// limit: 0, bdata->node_min_pfn: 0x20000, PFN_DOWN(0): 0
		// ARM10C 20140125
		// limit: 0xffffffff, bdata->node_low_pfn: 0x4f800, PFN_DOWN(0xffffffff): 0xFFFFF
		if (limit && bdata->node_min_pfn >= PFN_DOWN(limit))
			break;

		// ARM10C 20131214
		// bdata: ?, size: 0x40, align: 64, goal: 0x0, limit: 0
		// ARM10C 20140125
		// bdata: ?, size: 0x1C, align: 64, goal: 0x0, limit: 0xFFFFFFFF
		region = alloc_bootmem_bdata(bdata, size, align, goal, limit);
		if (region)
			return region;
	}

	return NULL;
}

// ARM10C 20131214
// size: 0x40, align: 64, goal: 0x5FFFFFFF, limit: 0
// ARM10C 20140125
// size: 0x1C, align: 64, goal: 0, limit: 0xffffffffUL
static void * __init ___alloc_bootmem_nopanic(unsigned long size,
					      unsigned long align,
					      unsigned long goal,
					      unsigned long limit)
{
	void *ptr;

restart:
	// ARM10C 20131214
	// size: 0x40, align: 64, goal: 0x5FFFFFFF, limit: 0
	// restart 이후: size: 0x40, align: 64, goal: 0x0, limit: 0
	// ARM10C 20140125
	// size: 0x1C, align: 64, goal: 0, limit: 0xffffffffUL
	ptr = alloc_bootmem_core(size, align, goal, limit);
	// restart 이후: ptr: NULL 아닌 값
	if (ptr)
		return ptr;
	if (goal) {
		goal = 0;
		goto restart;
	}

	return NULL;
}

/**
 * __alloc_bootmem_nopanic - allocate boot memory without panicking
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may happen on any node in the system.
 *
 * Returns NULL on failure.
 */
// ARM10C 20140322
void * __init __alloc_bootmem_nopanic(unsigned long size, unsigned long align,
					unsigned long goal)
{
	unsigned long limit = 0;

	return ___alloc_bootmem_nopanic(size, align, goal, limit);
}

// ARM10C 20131214
// size: 0x40, align: 64, goal: 0x5FFFFFFF, limit: 0
// ARM10C 20140125
// size: 28, align: 64, goal: 0, ARCH_LOW_ADDRESS_LIMIT: 0xffffffffUL
static void * __init ___alloc_bootmem(unsigned long size, unsigned long align,
					unsigned long goal, unsigned long limit)
{
	// size: 0x40, align: 64, goal: 0x5FFFFFFF, limit: 0
	// size: 0x1C, align: 64, goal: 0, limit: 0xffffffffUL
	void *mem = ___alloc_bootmem_nopanic(size, align, goal, limit);

	// mem: NULL 아닌 값
	if (mem)
		return mem;
	/*
	 * Whoops, we cannot satisfy the allocation request.
	 */
	printk(KERN_ALERT "bootmem alloc of %lu bytes failed!\n", size);
	panic("Out of memory");
	return NULL;
}

/**
 * __alloc_bootmem - allocate boot memory
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may happen on any node in the system.
 *
 * The function panics if the request can not be satisfied.
 */
// ARM10C 20131214
// size: 0x40, align: 64, goal: 0x5FFFFFFF
void * __init __alloc_bootmem(unsigned long size, unsigned long align,
			      unsigned long goal)
{
	unsigned long limit = 0;

	// size: 0x40, align: 64, goal: 0x5FFFFFFF, limit: 0
	return ___alloc_bootmem(size, align, goal, limit);
}

// ARM10C 20131207
// pgdat: ?, size: 0x1000, align: 64, goal: 0x5FFFFFFF
// ARM10C 20131221
// pgdat : &contig_page_data, size : 0x800, align : 64, goal : 0x5FFFFFFF
void * __init ___alloc_bootmem_node_nopanic(pg_data_t *pgdat,
				unsigned long size, unsigned long align,
				unsigned long goal, unsigned long limit)
{
	void *ptr;

	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc(size, GFP_NOWAIT);
again:

	/* do not panic in alloc_bootmem_bdata() */
	// limit: 0, goal + size: 0x5FFFFFFF + 0x1000: 0x60000FFF
	if (limit && goal + size > limit)
		limit = 0;

	// 2013/12/07 종료
	// 2013/12/14 시작
	// pgdat: ?, size: 0x1000, align: 64, goal: 0x5FFFFFFF, limit: 0
	// pgdat : &contig_page_data, size : 0x800, align : 64, goal : 0x5FFFFFFF
	ptr = alloc_bootmem_bdata(pgdat->bdata, size, align, goal, limit);
	if (ptr)
		// ptr 값 리턴
		return ptr;

	ptr = alloc_bootmem_core(size, align, goal, limit);
	if (ptr)
		return ptr;

	if (goal) {
		goal = 0;
		goto again;
	}

	return NULL;
}

// ARM10C 20131221
void * __init __alloc_bootmem_node_nopanic(pg_data_t *pgdat, unsigned long size,
				   unsigned long align, unsigned long goal)
{
	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc_node(size, GFP_NOWAIT, pgdat->node_id);

	return ___alloc_bootmem_node_nopanic(pgdat, size, align, goal, 0);
}

// ARM10C 20131207
// pgdat: ?, size: 0x1000, align: 64, goal: 0x5FFFFFFF
void * __init ___alloc_bootmem_node(pg_data_t *pgdat, unsigned long size,
				    unsigned long align, unsigned long goal,
				    unsigned long limit)
{
	void *ptr;

	// pgdat: ?, size: 0x1000, align: 64, goal: 0x5FFFFFFF
	ptr = ___alloc_bootmem_node_nopanic(pgdat, size, align, goal, 0);
	if (ptr)
		// ptr 값 리턴
		return ptr;

	printk(KERN_ALERT "bootmem alloc of %lu bytes failed!\n", size);
	panic("Out of memory");
	return NULL;
}

/**
 * __alloc_bootmem_node - allocate boot memory from a specific node
 * @pgdat: node to allocate from
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may fall back to any node in the system if the specified node
 * can not hold the requested memory.
 *
 * The function panics if the request can not be satisfied.
 */
// ARM10C 20131207
// pgdat: ?, array_size: 0x1000
// SMP_CACHE_BYTES = 64, BOOTMEM_LOW_LIMIT: 0x5FFFFFFF
void * __init __alloc_bootmem_node(pg_data_t *pgdat, unsigned long size,
				   unsigned long align, unsigned long goal)
{
	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc_node(size, GFP_NOWAIT, pgdat->node_id);

	// pgdat: ?, size: 0x1000, align: 64, goal: 0x5FFFFFFF
	return  ___alloc_bootmem_node(pgdat, size, align, goal, 0);
}

// ARM10C 20131221
// NODE_DATA(nid) : &contig_page_data, size : 0x2C0000, PAGE_SIZE : 0x1000, __pa : 0x5FFFFFFF
void * __init __alloc_bootmem_node_high(pg_data_t *pgdat, unsigned long size,
				   unsigned long align, unsigned long goal)
{
#ifdef MAX_DMA32_PFN
	unsigned long end_pfn;

	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc_node(size, GFP_NOWAIT, pgdat->node_id);

	/* update goal according ...MAX_DMA32_PFN */
	end_pfn = pgdat_end_pfn(pgdat);

	if (end_pfn > MAX_DMA32_PFN + (128 >> (20 - PAGE_SHIFT)) &&
	    (goal >> PAGE_SHIFT) < MAX_DMA32_PFN) {
		void *ptr;
		unsigned long new_goal;

		new_goal = MAX_DMA32_PFN << PAGE_SHIFT;
		ptr = alloc_bootmem_bdata(pgdat->bdata, size, align,
						 new_goal, 0);
		if (ptr)
			return ptr;
	}
#endif

	// pgdat : &contig_page_data, size : 0x2C0000, align : 0x1000, goal : 0x5FFFFFFF
	return __alloc_bootmem_node(pgdat, size, align, goal);
	// 2816K 만큼 할당 받고, 가상 주소를 리턴

}

#ifndef ARCH_LOW_ADDRESS_LIMIT
// ARM10C 20140125
#define ARCH_LOW_ADDRESS_LIMIT	0xffffffffUL
#endif

/**
 * __alloc_bootmem_low - allocate low boot memory
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may happen on any node in the system.
 *
 * The function panics if the request can not be satisfied.
 */
// ARM10C 20140125
// 28, SMP_CACHE_BYTES: 64, 0
void * __init __alloc_bootmem_low(unsigned long size, unsigned long align,
				  unsigned long goal)
{
	// size: 28, align: 64, goal: 0, ARCH_LOW_ADDRESS_LIMIT: 0xffffffffUL
	return ___alloc_bootmem(size, align, goal, ARCH_LOW_ADDRESS_LIMIT);
	// 4K 메모리 할당
}

void * __init __alloc_bootmem_low_nopanic(unsigned long size,
					  unsigned long align,
					  unsigned long goal)
{
	return ___alloc_bootmem_nopanic(size, align, goal,
					ARCH_LOW_ADDRESS_LIMIT);
}

/**
 * __alloc_bootmem_low_node - allocate low boot memory from a specific node
 * @pgdat: node to allocate from
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may fall back to any node in the system if the specified node
 * can not hold the requested memory.
 *
 * The function panics if the request can not be satisfied.
 */
void * __init __alloc_bootmem_low_node(pg_data_t *pgdat, unsigned long size,
				       unsigned long align, unsigned long goal)
{
	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc_node(size, GFP_NOWAIT, pgdat->node_id);

	return ___alloc_bootmem_node(pgdat, size, align,
				     goal, ARCH_LOW_ADDRESS_LIMIT);
}
