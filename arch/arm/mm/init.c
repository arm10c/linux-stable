/*
 *  linux/arch/arm/mm/init.c
 *
 *  Copyright (C) 1995-2005 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/swap.h>
#include <linux/init.h>
#include <linux/bootmem.h>
#include <linux/mman.h>
#include <linux/export.h>
#include <linux/nodemask.h>
#include <linux/initrd.h>
#include <linux/of_fdt.h>
#include <linux/highmem.h>
#include <linux/gfp.h>
#include <linux/memblock.h>
#include <linux/dma-contiguous.h>
#include <linux/sizes.h>

#include <asm/mach-types.h>
#include <asm/memblock.h>
#include <asm/prom.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/tlb.h>
#include <asm/fixmap.h>

#include <asm/mach/arch.h>
#include <asm/mach/map.h>

#include "mm.h"

// ARM10C 20131012
static phys_addr_t phys_initrd_start __initdata = 0;
static unsigned long phys_initrd_size __initdata = 0;

static int __init early_initrd(char *p)
{
	phys_addr_t start;
	unsigned long size;
	char *endp;

	start = memparse(p, &endp);
	if (*endp == ',') {
		size = memparse(endp + 1, NULL);

		phys_initrd_start = start;
		phys_initrd_size = size;
	}
	return 0;
}
early_param("initrd", early_initrd);

static int __init parse_tag_initrd(const struct tag *tag)
{
	printk(KERN_WARNING "ATAG_INITRD is deprecated; "
		"please update your bootloader.\n");
	phys_initrd_start = __virt_to_phys(tag->u.initrd.start);
	phys_initrd_size = tag->u.initrd.size;
	return 0;
}

__tagtable(ATAG_INITRD, parse_tag_initrd);

static int __init parse_tag_initrd2(const struct tag *tag)
{
	phys_initrd_start = tag->u.initrd.start;
	phys_initrd_size = tag->u.initrd.size;
	return 0;
}

__tagtable(ATAG_INITRD2, parse_tag_initrd2);

/*
 * This keeps memory configuration data used by a couple memory
 * initialization functions, as well as show_mem() for the skipping
 * of holes in the memory map.  It is populated by arm_add_memory().
 */
// ARM10C 20131012
// ARM10C 20131207
// ARM10C 20140329
struct meminfo meminfo;

void show_mem(unsigned int filter)
{
	int free = 0, total = 0, reserved = 0;
	int shared = 0, cached = 0, slab = 0, i;
	struct meminfo * mi = &meminfo;

	printk("Mem-info:\n");
	show_free_areas(filter);

	if (filter & SHOW_MEM_FILTER_PAGE_COUNT)
		return;

	for_each_bank (i, mi) {
		struct membank *bank = &mi->bank[i];
		unsigned int pfn1, pfn2;
		struct page *page, *end;

		pfn1 = bank_pfn_start(bank);
		pfn2 = bank_pfn_end(bank);

		page = pfn_to_page(pfn1);
		end  = pfn_to_page(pfn2 - 1) + 1;

		do {
			total++;
			if (PageReserved(page))
				reserved++;
			else if (PageSwapCache(page))
				cached++;
			else if (PageSlab(page))
				slab++;
			else if (!page_count(page))
				free++;
			else
				shared += page_count(page) - 1;
			page++;
		} while (page < end);
	}

	printk("%d pages of RAM\n", total);
	printk("%d free pages\n", free);
	printk("%d reserved pages\n", reserved);
	printk("%d slab pages\n", slab);
	printk("%d pages shared\n", shared);
	printk("%d pages swap cached\n", cached);
}

// ARM10C 20131130
// ARM10C 20131207
static void __init find_limits(unsigned long *min, unsigned long *max_low,
			       unsigned long *max_high)
{
	struct meminfo *mi = &meminfo;
	int i;

	/* This assumes the meminfo array is properly sorted */
	// mi->bank[0].start: 0x20000000, bank_pfn_start(&mi->bank[0]): 0x20000
	// *min: 0x20000
	*min = bank_pfn_start(&mi->bank[0]);

	// #define for_each_bank(i,mi)
	// for (i = 0; i < (mi)->nr_banks; i++)
	//
	// mi->nr_banks: 2, mi->bank[1].highmem: 1
	for_each_bank (i, mi)
		if (mi->bank[i].highmem)
				break;

	// i: 1, mi->bank[0].start: 0x20000000, mi->bank[0].size: 0x2f800000
	// bank_pfn_end(&mi->bank[i - 1]): 0x4f800
	// *max_low: 0x4f800
	*max_low = bank_pfn_end(&mi->bank[i - 1]);

	// mi->bank[1].start: 0x4f800000, mi->bank[1].size: 0x50800000 
	// bank_pfn_end(&mi->bank[mi->nr_banks - 1]): 0xA0000
	// *max_high: 0xA0000
	*max_high = bank_pfn_end(&mi->bank[mi->nr_banks - 1]);
}

// ARM10C 20131207
// min: 0x20000, max_low: 0x4f800
// contig_page_data에 bitmap을 저장한다.
static void __init arm_bootmem_init(unsigned long start_pfn,
	unsigned long end_pfn)
{
	struct memblock_region *reg;
	unsigned int boot_pages;
	phys_addr_t bitmap;
	pg_data_t *pgdat;

	/*
	 * Allocate the bootmem bitmap page.  This must be in a region
	 * of memory which has already been mapped.
	 */
	// start_pfn: 0x20000, end_pfn: 0x4f800, end_pfn - start_pfn: 0x2f800
	// boot_pages: 0x6
	boot_pages = bootmem_bootmap_pages(end_pfn - start_pfn);

	// boot_pages << PAGE_SHIFT: 0x6000, L1_CACHE_BYTES: 64
	// __pfn_to_phys(0x4f800); 0x4f800000
	bitmap = memblock_alloc_base(boot_pages << PAGE_SHIFT, L1_CACHE_BYTES,
				__pfn_to_phys(end_pfn));

	/*
	 * Initialise the bootmem allocator, handing the
	 * memory banks over to bootmem.
	 */
	node_set_online(0);

	// pglist_data.bdata 의 bootmem_node_data 주소로 설정
	pgdat = NODE_DATA(0);

	// pgdat: ?, __phys_to_pfn(bitmap): ?, start_pfn: 0x20000, end_pfn: 0x4f800
	init_bootmem_node(pgdat, __phys_to_pfn(bitmap), start_pfn, end_pfn);

	/* Free the lowmem regions from memblock into bootmem. */
	for_each_memblock(memory, reg) {
		// start: 0x20000
		unsigned long start = memblock_region_memory_base_pfn(reg);
		// end: 0xA0000
		unsigned long end = memblock_region_memory_end_pfn(reg);

		// end: 0xA0000, end_pfn: 0x4f800
		if (end >= end_pfn)
			// end: 0x4f800
			end = end_pfn;
		// start: 0x20000, end: 0x4f800
		if (start >= end)
			break;

		// __pfn_to_phys(0x20000): 0x20000000, (end - start) << PAGE_SHIFT: 0x2f800000
		free_bootmem(__pfn_to_phys(start), (end - start) << PAGE_SHIFT);
	}

	/* Reserve the lowmem memblock reserved regions in bootmem. */
	for_each_memblock(reserved, reg) {
		// start: 0x40004
		unsigned long start = memblock_region_reserved_base_pfn(reg);
		// end: 0x40008
		unsigned long end = memblock_region_reserved_end_pfn(reg);

		// end: 0x40008, end_pfn: 0x4f800
		if (end >= end_pfn)
			end = end_pfn;
		// start: 0x40004, end: 0x40008
		if (start >= end)
			break;

		// __pfn_to_phys(0x40004): 0x40004000, (end - start) << PAGE_SHIFT: 0x4000
		// BOOTMEM_DEFAULT: 0
		reserve_bootmem(__pfn_to_phys(start),
			        (end - start) << PAGE_SHIFT, BOOTMEM_DEFAULT);
	}
}

#ifdef CONFIG_ZONE_DMA

phys_addr_t arm_dma_zone_size __read_mostly;
EXPORT_SYMBOL(arm_dma_zone_size);

/*
 * The DMA mask corresponding to the maximum bus address allocatable
 * using GFP_DMA.  The default here places no restriction on DMA
 * allocations.  This must be the smallest DMA mask in the system,
 * so a successful GFP_DMA allocation will always satisfy this.
 */
phys_addr_t arm_dma_limit;
unsigned long arm_dma_pfn_limit;

static void __init arm_adjust_dma_zone(unsigned long *size, unsigned long *hole,
	unsigned long dma_size)
{
	if (size[0] <= dma_size)
		return;

	size[ZONE_NORMAL] = size[0] - dma_size;
	size[ZONE_DMA] = dma_size;
	hole[ZONE_NORMAL] = hole[0];
	hole[ZONE_DMA] = 0;
}
#endif

// ARM10C 20131012
void __init setup_dma_zone(const struct machine_desc *mdesc)
{
#ifdef CONFIG_ZONE_DMA // CONFIG_ZONE_DMA=n
	if (mdesc->dma_zone_size) {
		arm_dma_zone_size = mdesc->dma_zone_size;
		arm_dma_limit = PHYS_OFFSET + arm_dma_zone_size - 1;
	} else
		arm_dma_limit = 0xffffffff;
	arm_dma_pfn_limit = arm_dma_limit >> PAGE_SHIFT;
#endif
}

// ARM10C 20140111
// min: 0x20000, max_low: 0x4f800, max_high: 0xA0000
static void __init arm_bootmem_free(unsigned long min, unsigned long max_low,
	unsigned long max_high)
{
	unsigned long zone_size[MAX_NR_ZONES], zhole_size[MAX_NR_ZONES];
	struct memblock_region *reg;

	/*
	 * initialise the zones.
	 */
	memset(zone_size, 0, sizeof(zone_size));

	/*
	 * The memory size has already been determined.  If we need
	 * to do anything fancy with the allocation of this memory
	 * to the zones, now is the time to do it.
	 */

	// zone_size[0] = 0x4f800 - 0x20000 = 0x2f800
	zone_size[0] = max_low - min;
#ifdef CONFIG_HIGHMEM	//CONFIG_HIGHMEM = y
	// ZONE_HIGHMEM = 1 
	// zone_size[1] = A0000 - 0x4f800 = 0x50800  
	zone_size[ZONE_HIGHMEM] = max_high - max_low;
#endif

	/*
	 * Calculate the size of the holes.
	 *  holes = node_size - sum(bank_sizes)
	 */
	memcpy(zhole_size, zone_size, sizeof(zhole_size));
	for_each_memblock(memory, reg) {
		// start = 0x20000
		unsigned long start = memblock_region_memory_base_pfn(reg);
		// end = 0xA0000 
		unsigned long end = memblock_region_memory_end_pfn(reg);

		if (start < max_low) {
			// low_end = 0x4f800
			unsigned long low_end = min(end, max_low);
			// zhole_size[0] = 0x2f800 - (0x4f800 - 0x20000) = 0
			zhole_size[0] -= low_end - start;
		}
#ifdef CONFIG_HIGHMEM	// ARM10C CONFIG_HIGHMEM = y 
		if (end > max_low) {
			// high_start = 0x4f800
			unsigned long high_start = max(start, max_low);
			// zhole_size[1] = 0x50800 - (0xA0000 - 0x4f800) = 0
			zhole_size[ZONE_HIGHMEM] -= end - high_start;
		}
#endif
	}

#ifdef CONFIG_ZONE_DMA	// ARM10C CONFIG_ZONE_DMA = n 
	/*
	 * Adjust the sizes according to any special requirements for
	 * this machine type.
	 */
	if (arm_dma_zone_size)
		arm_adjust_dma_zone(zone_size, zhole_size,
			arm_dma_zone_size >> PAGE_SHIFT);
#endif

	//min = 0x20000 
	free_area_init_node(0, zone_size, min, zhole_size);
}

#ifdef CONFIG_HAVE_ARCH_PFN_VALID // CONFIG_HAVE_ARCH_PFN_VALID=y
// ARM10C 20140118
// pfn : 0x20000
// ARM10C 20141025
// pfn: 0x10481
int pfn_valid(unsigned long pfn)
{
	// __pfn_to_phys(pfn) : 0x20000000
	// pfn: 0x10481, __pfn_to_phys(0x10481): 0x10481000
	// memblock_is_memory(0x10481000): 0
	return memblock_is_memory(__pfn_to_phys(pfn));
	// return 0
}
EXPORT_SYMBOL(pfn_valid);
#endif

#ifndef CONFIG_SPARSEMEM // CONFIG_SPARSEMEM=y
static void __init arm_memory_present(void)
{
}
#else
// ARM10C 20131207
static void __init arm_memory_present(void)
{
	struct memblock_region *reg;

	for_each_memblock(memory, reg)
		// memblock_region_memory_base_pfn(reg): 0x20000
		// memblock_region_memory_end_pfn(reg):  0xA0000
		memory_present(0, memblock_region_memory_base_pfn(reg),
			       memblock_region_memory_end_pfn(reg));
}
#endif

// ARM10C 20131026
static bool arm_memblock_steal_permitted = true;

phys_addr_t __init arm_memblock_steal(phys_addr_t size, phys_addr_t align)
{
	phys_addr_t phys;

	BUG_ON(!arm_memblock_steal_permitted);

	phys = memblock_alloc_base(size, align, MEMBLOCK_ALLOC_ANYWHERE);
	memblock_free(phys, size);
	memblock_remove(phys, size);

	return phys;
}

// ARM10C 20131019
void __init arm_memblock_init(struct meminfo *mi,
	const struct machine_desc *mdesc)
{
	int i;

	// 메모리 영역을 검사 후 추가 혹은 합치는 작업 수행.
	// mi->nr_banks: 2
	for (i = 0; i < mi->nr_banks; i++)
		memblock_add(mi->bank[i].start, mi->bank[i].size);

	/* Register the kernel text, kernel data and initrd with memblock. */
#ifdef CONFIG_XIP_KERNEL // CONFIG_XIP_KERNEL=n
	memblock_reserve(__pa(_sdata), _end - _sdata);
#else
	// kernel이 사용하는 영역으로 reserve 함.
	// _stext: 0xC0008000, __pa(_stext): 0x40008000
	memblock_reserve(__pa(_stext), _end - _stext);
#endif
#ifdef CONFIG_BLK_DEV_INITRD // CONFIG_BLK_DEV_INITRD=y
	/* FDT scan will populate initrd_start */
	if (initrd_start && !phys_initrd_size) {
		phys_initrd_start = __virt_to_phys(initrd_start);
		phys_initrd_size = initrd_end - initrd_start;
	}
	initrd_start = initrd_end = 0;

	// initrd로 넘어온 메모리 영역이 memblock.memory 안에 있는지 체크 
	if (phys_initrd_size &&
	    !memblock_is_region_memory(phys_initrd_start, phys_initrd_size)) {
		pr_err("INITRD: 0x%08llx+0x%08lx is not a memory region - disabling initrd\n",
		       (u64)phys_initrd_start, phys_initrd_size);
		phys_initrd_start = phys_initrd_size = 0;
	}
	// initrd로 넘어온 메모리 영역이 memblock.reserved 안에 있는지 체크 
	if (phys_initrd_size &&
	    memblock_is_region_reserved(phys_initrd_start, phys_initrd_size)) {
		pr_err("INITRD: 0x%08llx+0x%08lx overlaps in-use memory region - disabling initrd\n",
		       (u64)phys_initrd_start, phys_initrd_size);
		phys_initrd_start = phys_initrd_size = 0;
	}
	if (phys_initrd_size) {
		// memblock.reserved 안에 initrd 를 추가
		memblock_reserve(phys_initrd_start, phys_initrd_size);

		/* Now convert initrd to virtual addresses */
		initrd_start = __phys_to_virt(phys_initrd_start);
		initrd_end = initrd_start + phys_initrd_size;
	}
#endif

	// memblock.reserved 안에 page table을 추가
	arm_mm_memblock_reserve();
	// memblock.reserved 안에 dtb을 추가
	arm_dt_memblock_reserve();

	/* reserve any platform specific memblock areas */
	// chip관련 특별한 메모리 영역을 reserve 함
	if (mdesc->reserve)
		mdesc->reserve();

	/*
	 * reserve memory for DMA contigouos allocations,
	 * must come from DMA area inside low memory
	 */
	// arm_dma_limit: 0xFFFFFFFF, arm_lowmem_limit: 0
	//
	// DMA 메모리 영역을 reserve 함 (현재 설정에 따라 해당 사항 없음)
	dma_contiguous_reserve(min(arm_dma_limit, arm_lowmem_limit));

	// 메모리를 할당시 steal 가능여부 설정
	arm_memblock_steal_permitted = false;
	memblock_allow_resize();
	// debug 용도록 메모리 영역의 base, size를 출력
	memblock_dump_all();
}

// ARM10C 20131130
// ARM10C 20131207
void __init bootmem_init(void)
{
	unsigned long min, max_low, max_high;

	max_low = max_high = 0;

	// min: 0x20000, max_low: 0x4f800, max_high: 0xA0000
	find_limits(&min, &max_low, &max_high);

	// min: 0x20000, max_low: 0x4f800
	// memory block을 free, reserved 영역에 맞게 memory bitmap을 생성
	arm_bootmem_init(min, max_low);

	/*
	 * Sparsemem tries to allocate bootmem in memory_present(),
	 * so must be done after the fixed reservations
	 */
	// memory block을 free, reserved 영역에 맞게 memory bitmap을 설정 
	// 200 개의 mem_section 할당 받고 256MB 단위로 8개를 section_mem_map을 1로 마스킹
	arm_memory_present();

	/*
	 * sparse_init() needs the bootmem allocator up and running.
	 */
	// ms->section_mem_map에 256MB를 위한 struct page용 공간 정보 저장
	// ms->pageblock_bitmap : 할당받은 주소 + offset가 저장
	sparse_init();

// 2013/12/21 종료
// 2014/01/11 시작
	
	/*
	 * Now free the memory - free_area_init_node needs
	 * the sparse mem_map arrays initialized by sparse_init()
	 * for memmap_init_zone(), otherwise all PFNs are invalid.
	 */
	// min: 0x20000, max_low: 0x4f800, max_high: 0xA0000
	arm_bootmem_free(min, max_low, max_high);
	// contig_page_data 내부 값을 설정

	/*
	 * This doesn't seem to be used by the Linux memory manager any
	 * more, but is used by ll_rw_block.  If we can get rid of it, we
	 * also get rid of some of the stuff above as well.
	 */
	// min: 0x20000
	min_low_pfn = min;
	// min_low_pfn: 0x20000

	// max_low: 0x4f800
	max_low_pfn = max_low;
	// max_low_pfn: 0x4f800

	// max_high: 0xA0000
	max_pfn = max_high;
	// max_pfn: 0xA0000
}

/*
 * Poison init memory with an undefined instruction (ARM) or a branch to an
 * undefined instruction (Thumb).
 */
static inline void poison_init_mem(void *s, size_t count)
{
	u32 *p = (u32 *)s;
	for (; count != 0; count -= 4)
		*p++ = 0xe7fddef0;
}

static inline void
free_memmap(unsigned long start_pfn, unsigned long end_pfn)
{
	struct page *start_pg, *end_pg;
	phys_addr_t pg, pgend;

	/*
	 * Convert start_pfn/end_pfn to a struct page pointer.
	 */
	start_pg = pfn_to_page(start_pfn - 1) + 1;
	end_pg = pfn_to_page(end_pfn - 1) + 1;

	/*
	 * Convert to physical addresses, and
	 * round start upwards and end downwards.
	 */
	pg = PAGE_ALIGN(__pa(start_pg));
	pgend = __pa(end_pg) & PAGE_MASK;

	/*
	 * If there are free pages between these,
	 * free the section of the memmap array.
	 */
	if (pg < pgend)
		free_bootmem(pg, pgend - pg);
}

/*
 * The mem_map array can get very big.  Free the unused area of the memory map.
 */
// ARM10C 20140329
static void __init free_unused_memmap(struct meminfo *mi)
{
	unsigned long bank_start, prev_bank_end = 0;
	unsigned int i;

	/*
	 * This relies on each bank being in address order.
	 * The banks are sorted previously in bootmem_init().
	 */
	// mi: &meminfo, (&meminfo)->nr_banks: 2
	for_each_bank(i, mi) {
	// for (i = 0; i < (&meminfo)->nr_banks; i++)

		struct membank *bank = &mi->bank[i];
		// [1st] bank: &(&meminfo)->bank[0]
		// [2nd] bank: &(&meminfo)->bank[1]

		// [1st] bank_pfn_start(&(&meminfo)->bank[0]): 0x20000
		// [2nd] bank_pfn_start(&(&meminfo)->bank[1]): 0x4f800
		bank_start = bank_pfn_start(bank);
		// [1st] bank_start: 0x20000
		// [2nd] bank_start: 0x4f800

#ifdef CONFIG_SPARSEMEM // CONFIG_SPARSEMEM=y
		/*
		 * Take care not to free memmap entries that don't exist
		 * due to SPARSEMEM sections which aren't present.
		 */
		// [1st] bank_start: 0x20000, prev_bank_end: 0, PAGES_PER_SECTION: 0x10000
		// [1st] ALIGN(0x0, 0x10000): 0x0
		// [2nd] bank_start: 0x4f800, prev_bank_end: 0x4f800, PAGES_PER_SECTION: 0x10000
		// [2nd] ALIGN(0x4f800, 0x10000): 0x50000
		bank_start = min(bank_start,
				 ALIGN(prev_bank_end, PAGES_PER_SECTION));
		// [1st] bank_start: 0
		// [2nd] bank_start: 0x4f800
#else
		/*
		 * Align down here since the VM subsystem insists that the
		 * memmap entries are valid from the bank start aligned to
		 * MAX_ORDER_NR_PAGES.
		 */
		bank_start = round_down(bank_start, MAX_ORDER_NR_PAGES);
#endif
		/*
		 * If we had a previous bank, and there is a space
		 * between the current bank and the previous, free it.
		 */
		// [1st] prev_bank_end: 0, bank_start: 0
		// [2nd] prev_bank_end: 0x4f800, bank_start: 0x4f800
		if (prev_bank_end && prev_bank_end < bank_start)
			free_memmap(prev_bank_end, bank_start);

		/*
		 * Align up here since the VM subsystem insists that the
		 * memmap entries are valid from the bank end aligned to
		 * MAX_ORDER_NR_PAGES.
		 */
		// [1st] bank: &(&meminfo)->bank[0], MAX_ORDER_NR_PAGES: 0x400
		// [1st] bank_pfn_end(&(&meminfo)->bank[0]): 0x4f800
		// [2nd] bank: &(&meminfo)->bank[1], MAX_ORDER_NR_PAGES: 0x400
		// [2nd] bank_pfn_end(&(&meminfo)->bank[1]): 0xa0000
		prev_bank_end = ALIGN(bank_pfn_end(bank), MAX_ORDER_NR_PAGES);
		// [1st] prev_bank_end: 0x4f800
		// [2nd] prev_bank_end: 0xa0000
	}

#ifdef CONFIG_SPARSEMEM // CONFIG_SPARSEMEM=y
	// prev_bank_end: 0xa0000, PAGES_PER_SECTION: 0x10000
	if (!IS_ALIGNED(prev_bank_end, PAGES_PER_SECTION))
		free_memmap(prev_bank_end,
			    ALIGN(prev_bank_end, PAGES_PER_SECTION));
#endif
}

#ifdef CONFIG_HIGHMEM // CONFIG_HIGHMEM=y
// ARM10C 20140419
// start: 0x4F800, res_start: 0x50000
static inline void free_area_high(unsigned long pfn, unsigned long end)
{
	// pfn: 0x4F800, end: 0x50000
	for (; pfn < end; pfn++)
		// pfn_to_page(0x4F800): 0x4F800 (pfn)
		free_highmem_page(pfn_to_page(pfn));
		// page를 order 0 으로 buddy에 추가.
		// totalram_pages, (&(&contig_page_data)->node_zones[1])->managed_pages, totalhigh_pages
		// 변수를 free된 page 만큼 증가
}
#endif

// ARM10C 20140419
static void __init free_highpages(void)
{
#ifdef CONFIG_HIGHMEM // CONFIG_HIGHMEM=y
	// max_low_pfn: 0x4F800
	unsigned long max_low = max_low_pfn;
	// max_low: 0x4F800
	struct memblock_region *mem, *res;
	
	/* set highmem page free */
	// memblock.memory.cnt : 1
	for_each_memblock(memory, mem) {
	// for (mem = memblock.memory.regions;
	//      mem < (memblock.memory.regions + memblock.memory.cnt); mem++)

		// mem: memblock.memory.regions
		unsigned long start = memblock_region_memory_base_pfn(mem);
		// start: 0x20000
		// mem: memblock.memory.regions
		unsigned long end = memblock_region_memory_end_pfn(mem);
		// end: 0xA0000

		/* Ignore complete lowmem entries */
		// end: 0xA0000, max_low: 0x4F800
		if (end <= max_low)
			continue;

		/* Truncate partial highmem entries */
		// start: 0x20000, max_low: 0x4F800
		if (start < max_low)
			start = max_low;
			// start: 0x4F800

		/* Find and exclude any reserved regions */
		// res: memblock.reserved.regions, memblock.reserved.cnt: ??(4개 이상)
		for_each_memblock(reserved, res) {
		// for (res = memblock.reserved.regions;
		//      res < (memblock.reserved.regions + memblock.reserved.cnt); res++)
		
			// 현재 highmem은 매핑되지 않았다.
			// 가정: 0x50000 (pfn) ~ 0x50100 (pfn) highmem 영역이 reserved 되어있다.

			unsigned long res_start, res_end;

			// res: memblock.reserved.regions
			res_start = memblock_region_reserved_base_pfn(res);

			// res: memblock.reserved.regions
			res_end = memblock_region_reserved_end_pfn(res);

			// 가정값:
			// res_start: 0x50000 (pfn), res_end: 0x50100 (pfn)

			// res_end: 0x50100, start: 0x4F800
			if (res_end < start)
				continue;
				// lowmem의 reserved 영역은 skip

			// highmem의 reserved 영역만 체크

			// res_start: 0x50000, start: 0x4F800
			if (res_start < start)
				res_start = start;

			// res_start: 0x50000, end: 0xA0000
			if (res_start > end)
				res_start = end;

			// res_end: 0x50100, end: 0xA0000
			if (res_end > end)
				res_end = end;

			// res_start: 0x50000, start: 0x4F800
			if (res_start != start)
				// start: 0x4F800, res_start: 0x50000
				free_area_high(start, res_start);
				// page를 order 0 으로 buddy에 추가.
				// totalram_pages, (&(&contig_page_data)->node_zones[1])->managed_pages, totalhigh_pages
				// 변수를 free된 page 만큼 증가

			// start: 0x4F800, res_end: 0x50100
			start = res_end;
			// start: 0x50100

			// start: 0x50100, end: 0xA0000
			if (start == end)
				break;
		}

		/* And now free anything which remains */
		if (start < end)
			free_area_high(start, end);
			// highmem에 reserved 영역이 없을땐 highmem 영역 전체를 한번에 buddy order 0 에 추가.
	}
#endif
}

/*
 * mem_init() marks the free areas in the mem_map and tells us how much
 * memory is free.  This is done after various parts of the system have
 * claimed their memory after the kernel image.
 */
// ARM10C 20140329
void __init mem_init(void)
{
#ifdef CONFIG_HAVE_TCM // CONFIG_HAVE_TCM=n
	/* These pointers are filled in on TCM detection */
	extern u32 dtcm_end;
	extern u32 itcm_end;
#endif

	// max_pfn : 0x80000, PHYS_PFN_OFFSET: 0x20000, *mem_map: NULL
	// pfn_to_page(0xA0000): page 10번째 section 주소 + 0xA0000
	max_mapnr   = pfn_to_page(max_pfn + PHYS_PFN_OFFSET) - mem_map;
	// max_mapnr: page 10번째 section 주소 + 0xA0000

	/* this will put all unused low memory onto the freelists */
	free_unused_memmap(&meminfo);
	// bank 0, 1에 대해 bank 0, 1 사이에 사용하지 않는 공간이 있거나
	// align이 되어 있지 않으면 free_memmap을 수행

	free_all_bootmem();
	// bootmem으로 관리하던 메모리를 buddy로 이관.

// 2014/04/12 종료
// 2014/04/19 시작

#ifdef CONFIG_SA1111 // CONFIG_SA1111=n
	/* now that our DMA memory is actually so designated, we can free it */
	free_reserved_area(__va(PHYS_OFFSET), swapper_pg_dir, -1, NULL);
#endif

	free_highpages();
	// highmem의 reserved 영역을 제외하고 buddy order 0 에 추가.

	mem_init_print_info(NULL);
	// 각 메모리 섹션의 정보를 구하여 출력.

#define MLK(b, t) b, t, ((t) - (b)) >> 10
#define MLM(b, t) b, t, ((t) - (b)) >> 20
#define MLK_ROUNDUP(b, t) b, t, DIV_ROUND_UP(((t) - (b)), SZ_1K)

	printk(KERN_NOTICE "Virtual kernel memory layout:\n"
			"    vector  : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#ifdef CONFIG_HAVE_TCM // CONFIG_HAVE_TCM=n
			"    DTCM    : 0x%08lx - 0x%08lx   (%4ld kB)\n"
			"    ITCM    : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#endif
			"    fixmap  : 0x%08lx - 0x%08lx   (%4ld kB)\n"
			"    vmalloc : 0x%08lx - 0x%08lx   (%4ld MB)\n"
			"    lowmem  : 0x%08lx - 0x%08lx   (%4ld MB)\n"
#ifdef CONFIG_HIGHMEM // CONFIG_HIGHMEM=y
			"    pkmap   : 0x%08lx - 0x%08lx   (%4ld MB)\n"
#endif
#ifdef CONFIG_MODULES // CONFIG_MODULES=y
			"    modules : 0x%08lx - 0x%08lx   (%4ld MB)\n"
#endif
			"      .text : 0x%p" " - 0x%p" "   (%4d kB)\n"
			"      .init : 0x%p" " - 0x%p" "   (%4d kB)\n"
			"      .data : 0x%p" " - 0x%p" "   (%4d kB)\n"
			"       .bss : 0x%p" " - 0x%p" "   (%4d kB)\n",

			// CONFIG_VECTORS_BASE: 0xffff0000, PAGE_SIZE: 0x1000
			// MLK(0xffff0000UL, 0xffff1000UL): 0xffff0000UL, 0xffff1000UL, 4
			MLK(UL(CONFIG_VECTORS_BASE), UL(CONFIG_VECTORS_BASE) +
				(PAGE_SIZE)),
#ifdef CONFIG_HAVE_TCM // CONFIG_HAVE_TCM=n
			MLK(DTCM_OFFSET, (unsigned long) dtcm_end),
			MLK(ITCM_OFFSET, (unsigned long) itcm_end),
#endif
			// FIXADDR_START: 0xfff00000, FIXADDR_TOP: 0xfffe0000
			MLK(FIXADDR_START, FIXADDR_TOP),

			// VMALLOC_START: 0xf0000000, VMALLOC_END: 0xff000000
			MLM(VMALLOC_START, VMALLOC_END),
			// PAGE_OFFSET: 0xC0000000
			MLM(PAGE_OFFSET, (unsigned long)high_memory),
#ifdef CONFIG_HIGHMEM // CONFIG_HIGHMEM=y
			// PKMAP_BASE: 0xBFE00000, LAST_PKMAP: 512, PAGE_SIZE: 0x1000
			MLM(PKMAP_BASE, (PKMAP_BASE) + (LAST_PKMAP) *
				(PAGE_SIZE)),
#endif
#ifdef CONFIG_MODULES // CONFIG_MODULES=y
			// MODULES_VADDR: 0xBF000000, MODULES_END: 0xBFE00000
			MLM(MODULES_VADDR, MODULES_END),
#endif

			MLK_ROUNDUP(_text, _etext),
			MLK_ROUNDUP(__init_begin, __init_end),
			MLK_ROUNDUP(_sdata, _edata),
			MLK_ROUNDUP(__bss_start, __bss_stop));

#undef MLK
#undef MLM
#undef MLK_ROUNDUP

	/*
	 * Check boundaries twice: Some fundamental inconsistencies can
	 * be detected at build time already.
	 */
#ifdef CONFIG_MMU // CONFIG_MMU=y
	// TASK_SIZE: 0xBF000000, MODULES_VADDR: 0xBF000000
	BUILD_BUG_ON(TASK_SIZE				> MODULES_VADDR);
	BUG_ON(TASK_SIZE 				> MODULES_VADDR);
#endif

#ifdef CONFIG_HIGHMEM // CONFIG_HIGHMEM=y
	// PKMAP_BASE: 0xBFE00000, LAST_PKMAP: 512, PAGE_SIZE: 0x1000, PAGE_OFFSET: 0xC0000000
	BUILD_BUG_ON(PKMAP_BASE + LAST_PKMAP * PAGE_SIZE > PAGE_OFFSET);
	BUG_ON(PKMAP_BASE + LAST_PKMAP * PAGE_SIZE	> PAGE_OFFSET);
#endif
	// PAGE_SIZE: 0x1000 (4096), get_num_physpages(): 0x80000
	if (PAGE_SIZE >= 16384 && get_num_physpages() <= 128) {
		// PAGE_SIZE 가 16K 보다 크고 물리 메모리가 512K 이하면 수행.
		extern int sysctl_overcommit_memory;
		/*
		 * On a machine this small we won't get
		 * anywhere without overcommit, so turn
		 * it on by default.
		 */
		sysctl_overcommit_memory = OVERCOMMIT_ALWAYS;
	}
}

void free_initmem(void)
{
#ifdef CONFIG_HAVE_TCM
	extern char __tcm_start, __tcm_end;

	poison_init_mem(&__tcm_start, &__tcm_end - &__tcm_start);
	free_reserved_area(&__tcm_start, &__tcm_end, -1, "TCM link");
#endif

	poison_init_mem(__init_begin, __init_end - __init_begin);
	if (!machine_is_integrator() && !machine_is_cintegrator())
		free_initmem_default(-1);
}

#ifdef CONFIG_BLK_DEV_INITRD

static int keep_initrd;

void free_initrd_mem(unsigned long start, unsigned long end)
{
	if (!keep_initrd) {
		poison_init_mem((void *)start, PAGE_ALIGN(end) - start);
		free_reserved_area((void *)start, (void *)end, -1, "initrd");
	}
}

static int __init keepinitrd_setup(char *__unused)
{
	keep_initrd = 1;
	return 1;
}

__setup("keepinitrd", keepinitrd_setup);
#endif
