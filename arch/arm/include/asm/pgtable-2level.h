/*
 *  arch/arm/include/asm/pgtable-2level.h
 *
 *  Copyright (C) 1995-2002 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef _ASM_PGTABLE_2LEVEL_H
#define _ASM_PGTABLE_2LEVEL_H

/*
 * Hardware-wise, we have a two level page table structure, where the first
 * level has 4096 entries, and the second level has 256 entries.  Each entry
 * is one 32-bit word.  Most of the bits in the second level entry are used
 * by hardware, and there aren't any "accessed" and "dirty" bits.
 *
 * Linux on the other hand has a three level page table structure, which can
 * be wrapped to fit a two level page table structure easily - using the PGD
 * and PTE only.  However, Linux also expects one "PTE" table per page, and
 * at least a "dirty" bit.
 *
 * Therefore, we tweak the implementation slightly - we tell Linux that we
 * have 2048 entries in the first level, each of which is 8 bytes (iow, two
 * hardware pointers to the second level.)  The second level contains two
 * hardware PTE tables arranged contiguously, preceded by Linux versions
 * which contain the state information Linux needs.  We, therefore, end up
 * with 512 entries in the "PTE" level.
 *
 * This leads to the page tables having the following layout:
 *
 *    pgd             pte
 * |        |
 * +--------+
 * |        |       +------------+ +0
 * +- - - - +       | Linux pt 0 |
 * |        |       +------------+ +1024
 * +--------+ +0    | Linux pt 1 |
 * |        |-----> +------------+ +2048
 * +- - - - + +4    |  h/w pt 0  |
 * |        |-----> +------------+ +3072
 * +--------+ +8    |  h/w pt 1  |
 * |        |       +------------+ +4096
 *
 * See L_PTE_xxx below for definitions of bits in the "Linux pt", and
 * PTE_xxx for definitions of bits appearing in the "h/w pt".
 *
 * PMD_xxx definitions refer to bits in the first level page table.
 *
 * The "dirty" bit is emulated by only granting hardware write permission
 * iff the page is marked "writable" and "dirty" in the Linux PTE.  This
 * means that a write to a clean page will cause a permission fault, and
 * the Linux MM layer will mark the page dirty via handle_pte_fault().
 * For the hardware to notice the permission change, the TLB entry must
 * be flushed, and ptep_set_access_flags() does that for us.
 *
 * The "accessed" or "young" bit is emulated by a similar method; we only
 * allow accesses to the page if the "young" bit is set.  Accesses to the
 * page will cause a fault, and handle_pte_fault() will set the young bit
 * for us as long as the page is marked present in the corresponding Linux
 * PTE entry.  Again, ptep_set_access_flags() will ensure that the TLB is
 * up to date.
 *
 * However, when the "young" bit is cleared, we deny access to the page
 * by clearing the hardware PTE.  Currently Linux does not flush the TLB
 * for us in this case, which means the TLB will retain the transation
 * until either the TLB entry is evicted under pressure, or a context
 * switch which changes the user space mapping occurs.
 */
// ARM10C 20131123
// ARM10C 20140419
#define PTRS_PER_PTE		512
#define PTRS_PER_PMD		1
// ARM10C 20131026
#define PTRS_PER_PGD		2048

#define PTE_HWTABLE_PTRS	(PTRS_PER_PTE)
// ARM10C 20131123
// PTE_HWTABLE_PTRS: 512, sizeof(pte_t): 4
// PTE_HWTABLE_OFF: 2048
#define PTE_HWTABLE_OFF		(PTE_HWTABLE_PTRS * sizeof(pte_t))
// ARM10C 20131123
// PTRS_PER_PTE: 512, sizeof(u32): 4
// PTE_HWTABLE_SIZE: 2048
#define PTE_HWTABLE_SIZE	(PTRS_PER_PTE * sizeof(u32))

/*
 * PMD_SHIFT determines the size of the area a second-level page table can map
 * PGDIR_SHIFT determines what a third-level page table entry can map
 */
// ARM10C 20140419
#define PMD_SHIFT		21
// ARM10C 20131102
#define PGDIR_SHIFT		21

// ARM10C 20131102
// ARM10C 20140419
// PMD_SHIFT: 21
// PMD_SIZE: 0x200000
#define PMD_SIZE		(1UL << PMD_SHIFT)
// ARM10C 20131130
// PMD_MASK: 0xFFE00000
#define PMD_MASK		(~(PMD_SIZE-1))
// ARM10C 20131109
// PGDIR_SIZE: 0x00200000
#define PGDIR_SIZE		(1UL << PGDIR_SHIFT)
// PGDIR_MASK: 0xFFE00000
#define PGDIR_MASK		(~(PGDIR_SIZE-1))

/*
 * section address mask and size definitions.
 */
#define SECTION_SHIFT		20
// ARM10C 20131109
// SECTION_SIZE: 0x00100000
#define SECTION_SIZE		(1UL << SECTION_SHIFT)
// ARM10C 20131109
// SECTION_MASK: 0xFFF00000
#define SECTION_MASK		(~(SECTION_SIZE-1))

/*
 * ARMv6 supersection address mask and size definitions.
 */
// ARM10C 20141018
// SUPERSECTION_SHIFT: 24
#define SUPERSECTION_SHIFT	24
// ARM10C 20141018
// SUPERSECTION_SHIFT: 24
// SUPERSECTION_SIZE: 0x1000000
#define SUPERSECTION_SIZE	(1UL << SUPERSECTION_SHIFT)
// ARM10C 20141018
// SUPERSECTION_SIZE: 0x1000000
// SUPERSECTION_MASK: 0xff000000
#define SUPERSECTION_MASK	(~(SUPERSECTION_SIZE-1))

#define USER_PTRS_PER_PGD	(TASK_SIZE / PGDIR_SIZE)

/*
 * "Linux" PTE definitions.
 *
 * We keep two sets of PTEs - the hardware and the linux version.
 * This allows greater flexibility in the way we map the Linux bits
 * onto the hardware tables, and allows us to have YOUNG and DIRTY
 * bits.
 *
 * The PTE table pointer refers to the hardware entries; the "Linux"
 * entries are stored 1024 bytes below.
 */
// ARM10C 20131123
// L_PTE_VALID: 0x1
#define L_PTE_VALID		(_AT(pteval_t, 1) << 0)		/* Valid */
// ARM10C 20141025
// L_PTE_PRESENT: 0x1
#define L_PTE_PRESENT		(_AT(pteval_t, 1) << 0)
// ARM10C 20131123
// ARM10C 20141025
// L_PTE_YOUNG: 0x2
#define L_PTE_YOUNG		(_AT(pteval_t, 1) << 1)
#define L_PTE_FILE		(_AT(pteval_t, 1) << 2)	/* only when !PRESENT */
// ARM10C 20131123
// ARM10C 20141025
// L_PTE_DIRTY: 0x40
#define L_PTE_DIRTY		(_AT(pteval_t, 1) << 6)
// ARM10C 20131123
// L_PTE_RDONLY: 0x80
#define L_PTE_RDONLY		(_AT(pteval_t, 1) << 7)
// ARM10C 20131123
// L_PTE_USER: 0x100
#define L_PTE_USER		(_AT(pteval_t, 1) << 8)
// ARM10C 20131123
// ARM10C 20141025
// L_PTE_XN: 0x200
#define L_PTE_XN		(_AT(pteval_t, 1) << 9)
// ARM10C 20141025
// L_PTE_SHARED: 0x400
#define L_PTE_SHARED		(_AT(pteval_t, 1) << 10)	/* shared(v6), coherent(xsc3) */
// ARM10C 20131123
// L_PTE_NONE: 0x800 
#define L_PTE_NONE		(_AT(pteval_t, 1) << 11)

/*
 * These are the memory types, defined to be compatible with
 * pre-ARMv6 CPUs cacheable and bufferable bits:   XXCB
 */
#define L_PTE_MT_UNCACHED	(_AT(pteval_t, 0x00) << 2)	/* 0000 */
#define L_PTE_MT_BUFFERABLE	(_AT(pteval_t, 0x01) << 2)	/* 0001 */
#define L_PTE_MT_WRITETHROUGH	(_AT(pteval_t, 0x02) << 2)	/* 0010 */
#define L_PTE_MT_WRITEBACK	(_AT(pteval_t, 0x03) << 2)	/* 0011 */
#define L_PTE_MT_MINICACHE	(_AT(pteval_t, 0x06) << 2)	/* 0110 (sa1100, xscale) */
#define L_PTE_MT_WRITEALLOC	(_AT(pteval_t, 0x07) << 2)	/* 0111 */
// ARM10C 20141025
// L_PTE_MT_DEV_SHARED: 0x10
#define L_PTE_MT_DEV_SHARED	(_AT(pteval_t, 0x04) << 2)	/* 0100 */
#define L_PTE_MT_DEV_NONSHARED	(_AT(pteval_t, 0x0c) << 2)	/* 1100 */
#define L_PTE_MT_DEV_WC		(_AT(pteval_t, 0x09) << 2)	/* 1001 */
#define L_PTE_MT_DEV_CACHED	(_AT(pteval_t, 0x0b) << 2)	/* 1011 */
#define L_PTE_MT_MASK		(_AT(pteval_t, 0x0f) << 2)

#ifndef __ASSEMBLY__

/*
 * The "pud_xxx()" functions here are trivial when the pmd is folded into
 * the pud: the pud entry is never bad, always exists, and can't be set or
 * cleared.
 */
#define pud_none(pud)		(0)
#define pud_bad(pud)		(0)
#define pud_present(pud)	(1)
#define pud_clear(pudp)		do { } while (0)
#define set_pud(pud,pudp)	do { } while (0)

// ARM10C 20131102
static inline pmd_t *pmd_offset(pud_t *pud, unsigned long addr)
{
	return (pmd_t *)pud;
}

// ARM10C 20131109
#define pmd_bad(pmd)		(pmd_val(pmd) & 2)

#define copy_pmd(pmdpd,pmdps)		\
	do {				\
		pmdpd[0] = pmdps[0];	\
		pmdpd[1] = pmdps[1];	\
		flush_pmd_entry(pmdpd);	\
	} while (0)

// ARM10C 20131102
#define pmd_clear(pmdp)			\
	do {				\
		pmdp[0] = __pmd(0);	\
		pmdp[1] = __pmd(0);	\
		clean_pmd_entry(pmdp);	\
	} while (0)

/* we don't need complex calculations here as the pmd is folded into the pgd */
#define pmd_addr_end(addr,end) (end)

// ARM10C 20131123
// pte: 0xEF7FD1F0, pfn_pte(0x4F7FE, __pgprot(type->prot_pte)): 0x4F7FEXXX, 0
// ptep: 0xEF7FD1F0, pte: 0x4F7FEXXX, ext:0
#define set_pte_ext(ptep,pte,ext) cpu_set_pte_ext(ptep,pte,ext)

/*
 * We don't have huge page support for short descriptors, for the moment
 * define empty stubs for use by pin_page_for_write.
 */
#define pmd_hugewillfault(pmd)	(0)
#define pmd_thp_or_huge(pmd)	(0)

#endif /* __ASSEMBLY__ */

#endif /* _ASM_PGTABLE_2LEVEL_H */
