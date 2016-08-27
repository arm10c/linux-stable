/*
 *  linux/arch/arm/mm/fault-armv.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 *  Modifications for ARM processor (c) 1995-2002 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/bitops.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/gfp.h>

#include <asm/bugs.h>
#include <asm/cacheflush.h>
#include <asm/cachetype.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include "mm.h"

static pteval_t shared_pte_mask = L_PTE_MT_BUFFERABLE;

#if __LINUX_ARM_ARCH__ < 6
/*
 * We take the easy way out of this problem - we make the
 * PTE uncacheable.  However, we leave the write buffer on.
 *
 * Note that the pte lock held when calling update_mmu_cache must also
 * guard the pte (somewhere else in the same mm) that we modify here.
 * Therefore those configurations which might call adjust_pte (those
 * without CONFIG_CPU_CACHE_VIPT) cannot support split page_table_lock.
 */
static int do_adjust_pte(struct vm_area_struct *vma, unsigned long address,
	unsigned long pfn, pte_t *ptep)
{
	pte_t entry = *ptep;
	int ret;

	/*
	 * If this page is present, it's actually being shared.
	 */
	ret = pte_present(entry);

	/*
	 * If this page isn't present, or is already setup to
	 * fault (ie, is old), we can safely ignore any issues.
	 */
	if (ret && (pte_val(entry) & L_PTE_MT_MASK) != shared_pte_mask) {
		flush_cache_page(vma, address, pfn);
		outer_flush_range((pfn << PAGE_SHIFT),
				  (pfn << PAGE_SHIFT) + PAGE_SIZE);
		pte_val(entry) &= ~L_PTE_MT_MASK;
		pte_val(entry) |= shared_pte_mask;
		set_pte_at(vma->vm_mm, address, ptep, entry);
		flush_tlb_page(vma, address);
	}

	return ret;
}

#if USE_SPLIT_PTE_PTLOCKS
/*
 * If we are using split PTE locks, then we need to take the page
 * lock here.  Otherwise we are using shared mm->page_table_lock
 * which is already locked, thus cannot take it.
 */
static inline void do_pte_lock(spinlock_t *ptl)
{
	/*
	 * Use nested version here to indicate that we are already
	 * holding one similar spinlock.
	 */
	spin_lock_nested(ptl, SINGLE_DEPTH_NESTING);
}

static inline void do_pte_unlock(spinlock_t *ptl)
{
	spin_unlock(ptl);
}
#else /* !USE_SPLIT_PTE_PTLOCKS */
static inline void do_pte_lock(spinlock_t *ptl) {}
static inline void do_pte_unlock(spinlock_t *ptl) {}
#endif /* USE_SPLIT_PTE_PTLOCKS */

static int adjust_pte(struct vm_area_struct *vma, unsigned long address,
	unsigned long pfn)
{
	spinlock_t *ptl;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int ret;

	pgd = pgd_offset(vma->vm_mm, address);
	if (pgd_none_or_clear_bad(pgd))
		return 0;

	pud = pud_offset(pgd, address);
	if (pud_none_or_clear_bad(pud))
		return 0;

	pmd = pmd_offset(pud, address);
	if (pmd_none_or_clear_bad(pmd))
		return 0;

	/*
	 * This is called while another page table is mapped, so we
	 * must use the nested version.  This also means we need to
	 * open-code the spin-locking.
	 */
	ptl = pte_lockptr(vma->vm_mm, pmd);
	pte = pte_offset_map(pmd, address);
	do_pte_lock(ptl);

	ret = do_adjust_pte(vma, address, pfn, pte);

	do_pte_unlock(ptl);
	pte_unmap(pte);

	return ret;
}

static void
make_coherent(struct address_space *mapping, struct vm_area_struct *vma,
	unsigned long addr, pte_t *ptep, unsigned long pfn)
{
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *mpnt;
	unsigned long offset;
	pgoff_t pgoff;
	int aliases = 0;

	pgoff = vma->vm_pgoff + ((addr - vma->vm_start) >> PAGE_SHIFT);

	/*
	 * If we have any shared mappings that are in the same mm
	 * space, then we need to handle them specially to maintain
	 * cache coherency.
	 */
	flush_dcache_mmap_lock(mapping);
	vma_interval_tree_foreach(mpnt, &mapping->i_mmap, pgoff, pgoff) {
		/*
		 * If this VMA is not in our MM, we can ignore it.
		 * Note that we intentionally mask out the VMA
		 * that we are fixing up.
		 */
		if (mpnt->vm_mm != mm || mpnt == vma)
			continue;
		if (!(mpnt->vm_flags & VM_MAYSHARE))
			continue;
		offset = (pgoff - mpnt->vm_pgoff) << PAGE_SHIFT;
		aliases += adjust_pte(mpnt, mpnt->vm_start + offset, pfn);
	}
	flush_dcache_mmap_unlock(mapping);
	if (aliases)
		do_adjust_pte(vma, addr, pfn, ptep);
}

/*
 * Take care of architecture specific things when placing a new PTE into
 * a page table, or changing an existing PTE.  Basically, there are two
 * things that we need to take care of:
 *
 *  1. If PG_dcache_clean is not set for the page, we need to ensure
 *     that any cache entries for the kernels virtual memory
 *     range are written back to the page.
 *  2. If we have multiple shared mappings of the same space in
 *     an object, we need to deal with the cache aliasing issues.
 *
 * Note that the pte lock will be held.
 */
void update_mmu_cache(struct vm_area_struct *vma, unsigned long addr,
	pte_t *ptep)
{
	unsigned long pfn = pte_pfn(*ptep);
	struct address_space *mapping;
	struct page *page;

	if (!pfn_valid(pfn))
		return;

	/*
	 * The zero page is never written to, so never has any dirty
	 * cache lines, and therefore never needs to be flushed.
	 */
	page = pfn_to_page(pfn);
	if (page == ZERO_PAGE(0))
		return;

	mapping = page_mapping(page);
	if (!test_and_set_bit(PG_dcache_clean, &page->flags))
		__flush_dcache_page(mapping, page);
	if (mapping) {
		if (cache_is_vivt())
			make_coherent(mapping, vma, addr, ptep, pfn);
		else if (vma->vm_flags & VM_EXEC)
			__flush_icache_all();
	}
}
#endif	/* __LINUX_ARM_ARCH__ < 6 */

/*
 * Check whether the write buffer has physical address aliasing
 * issues.  If it has, we need to avoid them for the case where
 * we have several shared mappings of the same object in user
 * space.
 */
// ARM10C 20160820
// p1: 할당받은 page의 mmu에 반영된 가상주소, p2: 할당받은 page의 mmu에 반영된 가상주소
static int __init check_writebuffer(unsigned long *p1, unsigned long *p2)
{
	register unsigned long zero = 0, one = 1, val;
	// zero: 0, one: 1

	local_irq_disable();

	// local_irq_disable 에서 한일:
	// interrupt disable 수행

	mb();

	// mb 에서 한일:
	// data sync barrier 작업 수행

	// *p1: *(할당받은 page의 mmu에 반영된 가상주소), one: 1
	*p1 = one;
	// *p1: *(할당받은 page의 mmu에 반영된 가상주소): 1

	mb();

	// mb 에서 한일:
	// data sync barrier 작업 수행

	// *p2: *(할당받은 page의 mmu에 반영된 가상주소), zero: 0
	*p2 = zero;
	// *p2: *(할당받은 page의 mmu에 반영된 가상주소): 0

	mb();

	// mb 에서 한일:
	// data sync barrier 작업 수행

	// *p1: *(할당받은 page의 mmu에 반영된 가상주소): 1
	val = *p1;
	// val: 1

	mb();

	// mb 에서 한일:
	// data sync barrier 작업 수행

	local_irq_enable();

	// local_irq_disable 에서 한일:
	// interrupt enable 수행

	// val: 1, zero: 0
	return val != zero;
	// return 0
}

// ARM10C 20160813
void __init check_writebuffer_bugs(void)
{
	struct page *page;
	const char *reason;
	unsigned long v = 1;
	// v: 1

	printk(KERN_INFO "CPU: Testing write buffer coherency: ");

	// GFP_KERNEL: 0xD0
	// alloc_page(GFP_KERNEL): page 1개(4K)의 할당된 메모리 주소
	page = alloc_page(GFP_KERNEL);
	// page: page 1개(4K)의 할당된 메모리 주소

	// page: page 1개(4K)의 할당된 메모리 주소
	if (page) {
		unsigned long *p1, *p2;

		// PAGE_KERNEL: pgprot_kernel에 0x200 를 or 한 값
		// L_PTE_MT_MASK: 0x3c, L_PTE_MT_BUFFERABLE: 0x4
		// __pgprot_modify(pgprot_kernel에 0x200 를 or 한 값, 0x3c, 0x04): pgprot_kernel에 0x204 를 or 한 값
		pgprot_t prot = __pgprot_modify(PAGE_KERNEL,
					L_PTE_MT_MASK, L_PTE_MT_BUFFERABLE);
		// prot: pgprot_kernel에 0x204 를 or 한 값

		// page: page 1개(4K)의 할당된 메모리 주소, VM_IOREMAP: 0x00000001, prot: pgprot_kernel에 0x204 를 or 한 값
		// vmap(page 1개(4K)의 할당된 메모리 주소, 1, 0x00000001, pgprot_kernel에 0x204 를 or 한 값): 할당받은 page의 mmu에 반영된 가상주소
		p1 = vmap(&page, 1, VM_IOREMAP, prot);
		// p1: 할당받은 page의 mmu에 반영된 가상주소

		// vmap 에서 한일:
		// 할당 받은 가상 주소값을 가지고 있는 page table section 하위 pte table을 갱신함
		// cache의 값을 전부 메모리에 반영

		// page: page 1개(4K)의 할당된 메모리 주소, VM_IOREMAP: 0x00000001, prot: pgprot_kernel에 0x204 를 or 한 값
		// vmap(page 1개(4K)의 할당된 메모리 주소, 1, 0x00000001, pgprot_kernel에 0x204 를 or 한 값): 할당받은 page의 mmu에 반영된 가상주소
		p2 = vmap(&page, 1, VM_IOREMAP, prot);
		// p2: 할당받은 page의 mmu에 반영된 가상주소

		// vmap 에서 한일:
		// 할당 받은 가상 주소값을 가지고 있는 page table section 하위 pte table을 갱신함
		// cache의 값을 전부 메모리에 반영

		// p1: 할당받은 page의 mmu에 반영된 가상주소, p2: 할당받은 page의 mmu에 반영된 가상주소
		if (p1 && p2) {
			// p1: 할당받은 page의 mmu에 반영된 가상주소, p2: 할당받은 page의 mmu에 반영된 가상주소
			// check_writebuffer(할당받은 page의 mmu에 반영된 가상주소, 할당받은 page의 mmu에 반영된 가상주소): 0
			v = check_writebuffer(p1, p2);
			// v: 0

			// check_writebuffer에서 한일:
			// 할당받은 page의 mmu에 반영된 가상주소 값을 써서 비교함

			reason = "enabling work-around";
		} else {
			reason = "unable to map memory\n";
		}

		// p1: 할당받은 page의 mmu에 반영된 가상주소
		vunmap(p1);

		// vunmap 한일:
		// vmap_area_root.rb_node 에서 가지고 있는 rb tree의 주소를 기준으로
		// 할당받은 page의 mmu에 반영된 가상주소의 vmap_area 의 위치를 찾음
		// cache 에 있는 변화된 값을 실제 메모리에 전부 반영
		// 가상주소에 매핑 되어 있는 pte 에 값을 0 으로 초기화 함
		// free 되는 page 수를 계산하여 vmap_lazy_nr 에 더함
		// vmap_lazy_nr 이 0x2000 개가 넘을 경우 purge를 수행
		// &(할당받은 page의 mmu에 반영된 가상주소 가 포함된 vmap_area 주소)->vm 의 page 주소를 구하고, 등록된 kmem_cache 주소를 찾음
		// &(할당받은 page의 mmu에 반영된 가상주소 가 포함된 vmap_area 주소)->vm 의 object 을 등록된 kmem_cache 를 이용하여 free 하도록 함

		// p2: 할당받은 page의 mmu에 반영된 가상주소
		vunmap(p2);

		// vunmap 한일:
		// vmap_area_root.rb_node 에서 가지고 있는 rb tree의 주소를 기준으로
		// 할당받은 page의 mmu에 반영된 가상주소의 vmap_area 의 위치를 찾음
		// cache 에 있는 변화된 값을 실제 메모리에 전부 반영
		// 가상주소에 매핑 되어 있는 pte 에 값을 0 으로 초기화 함
		// free 되는 page 수를 계산하여 vmap_lazy_nr 에 더함
		// vmap_lazy_nr 이 0x2000 개가 넘을 경우 purge를 수행
		// &(할당받은 page의 mmu에 반영된 가상주소 가 포함된 vmap_area 주소)->vm 의 page 주소를 구하고, 등록된 kmem_cache 주소를 찾음
		// &(할당받은 page의 mmu에 반영된 가상주소 가 포함된 vmap_area 주소)->vm 의 object 을 등록된 kmem_cache 를 이용하여 free 하도록 함

		// page: page 1개(4K)의 할당된 메모리 주소
		put_page(page);

		// put_page 에서 한일:
		// page 1개(4K)의 할당된 메모리 주소를 buddy 에 0 order를 갖는 free 한 page list에 등록함
	} else {
		reason = "unable to grab page\n";
	}

	// v: 0
	if (v) {
		printk("failed, %s\n", reason);
		shared_pte_mask = L_PTE_MT_UNCACHED;
	} else {
		printk("ok\n");
	}
}
