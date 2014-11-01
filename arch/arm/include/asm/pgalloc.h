/*
 *  arch/arm/include/asm/pgalloc.h
 *
 *  Copyright (C) 2000-2001 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef _ASMARM_PGALLOC_H
#define _ASMARM_PGALLOC_H

#include <linux/pagemap.h>

#include <asm/domain.h>
#include <asm/pgtable-hwdef.h>
#include <asm/processor.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#define check_pgt_cache()		do { } while (0)

#ifdef CONFIG_MMU

#define _PAGE_USER_TABLE	(PMD_TYPE_TABLE | PMD_BIT4 | PMD_DOMAIN(DOMAIN_USER))
// ARM10C 20131130
// ARM10C 20141101
// PMD_TYPE_TABLE: 0x1, PMD_BIT4: 0x10
// DOMAIN_KERNEL: 0, PMD_DOMAIN(DOMAIN_KERNEL): 0
// _PAGE_KERNEL_TABLE: 0x11
#define _PAGE_KERNEL_TABLE	(PMD_TYPE_TABLE | PMD_BIT4 | PMD_DOMAIN(DOMAIN_KERNEL))

#ifdef CONFIG_ARM_LPAE

static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return (pmd_t *)get_zeroed_page(GFP_KERNEL | __GFP_REPEAT);
}

static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	BUG_ON((unsigned long)pmd & (PAGE_SIZE-1));
	free_page((unsigned long)pmd);
}

static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	set_pud(pud, __pud(__pa(pmd) | PMD_TYPE_TABLE));
}

#else	/* !CONFIG_ARM_LPAE */

/*
 * Since we have only two-level page tables, these are trivial
 */
#define pmd_alloc_one(mm,addr)		({ BUG(); ((pmd_t *)2); })
#define pmd_free(mm, pmd)		do { } while (0)
#define pud_populate(mm,pmd,pte)	BUG()

#endif	/* CONFIG_ARM_LPAE */

extern pgd_t *pgd_alloc(struct mm_struct *mm);
extern void pgd_free(struct mm_struct *mm, pgd_t *pgd);

// ARM10C 20141101
// GFP_KERNEL: 0xD0
// __GFP_NOTRACK: 0x200000u
// __GFP_REPEAT: 0x400u
// __GFP_ZERO: 0x8000u
// PGALLOC_GFP: 0x2084D0
#define PGALLOC_GFP	(GFP_KERNEL | __GFP_NOTRACK | __GFP_REPEAT | __GFP_ZERO)

// ARM10C 20141101
// pte: migratetype이 MIGRATE_UNMOVABLE인 page의 가상주소
static inline void clean_pte_table(pte_t *pte)
{
	// pte: migratetype이 MIGRATE_UNMOVABLE인 page의 가상주소
	// PTE_HWTABLE_PTRS: 512, PTE_HWTABLE_SIZE: 2048
	clean_dcache_area(pte + PTE_HWTABLE_PTRS, PTE_HWTABLE_SIZE);
	// migratetype이 MIGRATE_UNMOVABLE인 page의 가상주의 dcache를 메모리에 반영
}

/*
 * Allocate one PTE table.
 *
 * This actually allocates two hardware PTE tables, but we wrap this up
 * into one table thus:
 *
 *  +------------+ 0
 *  | Linux pt 0 |
 *  +------------+ 256
 *  | Linux pt 1 |
 *  +------------+ 512
 *  |  h/w pt 0  |
 *  +------------+ 768
 *  |  h/w pt 1  |
 *  +------------+ 1024
 */
// ARM10C 20141101
// &init_mm, addr: 0xf0000000
static inline pte_t *
pte_alloc_one_kernel(struct mm_struct *mm, unsigned long addr)
{
	pte_t *pte;

	// PGALLOC_GFP: 0x2084D0
	// __get_free_page(PGALLOC_GFP: 0x2084D0):
	// migratetype이 MIGRATE_UNMOVABLE인 page의 가상주소
	pte = (pte_t *)__get_free_page(PGALLOC_GFP);
	// pte: migratetype이 MIGRATE_UNMOVABLE인 page의 가상주소

	// pte: migratetype이 MIGRATE_UNMOVABLE인 page의 가상주소
	if (pte)
		// pte: migratetype이 MIGRATE_UNMOVABLE인 page의 가상주소
		clean_pte_table(pte);
		// clean_pte_table에서 한일:
		// migratetype이 MIGRATE_UNMOVABLE인 page의 가상주의 dcache를 메모리에 반영

	// pte: migratetype이 MIGRATE_UNMOVABLE인 page의 가상주소
	return pte;
	// return migratetype이 MIGRATE_UNMOVABLE인 page의 가상주소
}

static inline pgtable_t
pte_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	struct page *pte;

#ifdef CONFIG_HIGHPTE
	pte = alloc_pages(PGALLOC_GFP | __GFP_HIGHMEM, 0);
#else
	pte = alloc_pages(PGALLOC_GFP, 0);
#endif
	if (!pte)
		return NULL;
	if (!PageHighMem(pte))
		clean_pte_table(page_address(pte));
	if (!pgtable_page_ctor(pte)) {
		__free_page(pte);
		return NULL;
	}
	return pte;
}

/*
 * Free one PTE table.
 */
static inline void pte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
	if (pte)
		free_page((unsigned long)pte);
}

static inline void pte_free(struct mm_struct *mm, pgtable_t pte)
{
	pgtable_page_dtor(pte);
	__free_page(pte);
}

// ARM10C 20131123
// pmd: 0xc0007FF8, __pa(pte): 0x4F7FD000,
// ARM10C 20141101
// pmdp: 0xc0004780, migratetype이 MIGRATE_UNMOVABLE인 page의 물리주소, _PAGE_KERNEL_TABLE: 0x11
static inline void __pmd_populate(pmd_t *pmdp, phys_addr_t pte,
				  pmdval_t prot)
{
	// pte: 0x4F7FD000, PTE_HWTABLE_OFF: 0x800
	// pmdval: 0x4F7FD8XX
	pmdval_t pmdval = (pte + PTE_HWTABLE_OFF) | prot;
	// pmdp[0]: 0x4F7FD8XX
	pmdp[0] = __pmd(pmdval);
#ifndef CONFIG_ARM_LPAE // CONFIG_ARM_LPAE=n
	// pmdp[1]: 0x4F7FDCXX
	pmdp[1] = __pmd(pmdval + 256 * sizeof(pte_t));
#endif
	flush_pmd_entry(pmdp);
}

/*
 * Populate the pmdp entry with a pointer to the pte.  This pmd is part
 * of the mm address space.
 *
 * Ensure that we always set both PMD entries.
 */
// ARM10C 20141101
// &init_mm, pmd: 0xc0004780, new: migratetype이 MIGRATE_UNMOVABLE인 page의 가상주소
static inline void
pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp, pte_t *ptep)
{
	/*
	 * The pmd must be loaded with the physical address of the PTE table
	 */
	// pmdp: 0xc0004780, ptep: migratetype이 MIGRATE_UNMOVABLE인 page의 가상주소,
	// __pa(migratetype이 MIGRATE_UNMOVABLE인 page의 가상주소): migratetype이 MIGRATE_UNMOVABLE인 page의 물리주소
	// _PAGE_KERNEL_TABLE: 0x11
	__pmd_populate(pmdp, __pa(ptep), _PAGE_KERNEL_TABLE);
	// __pmd_populate에서 한일:
	// 0xc0004780, 0xc0004784에 할당받은 pte의 주소를 연결하고 메모리에 반영
}

static inline void
pmd_populate(struct mm_struct *mm, pmd_t *pmdp, pgtable_t ptep)
{
	__pmd_populate(pmdp, page_to_phys(ptep), _PAGE_USER_TABLE);
}
#define pmd_pgtable(pmd) pmd_page(pmd)

#endif /* CONFIG_MMU */

#endif
