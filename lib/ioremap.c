/*
 * Re-map IO memory to kernel address space so that we can access it.
 * This is needed for high PCI addresses that aren't mapped in the
 * 640k-1MB IO memory area on PC's
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 */
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <linux/export.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>

static int ioremap_pte_range(pmd_t *pmd, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pte_t *pte;
	u64 pfn;

	pfn = phys_addr >> PAGE_SHIFT;
	pte = pte_alloc_kernel(pmd, addr);
	if (!pte)
		return -ENOMEM;
	do {
		BUG_ON(!pte_none(*pte));
		set_pte_at(&init_mm, addr, pte, pfn_pte(pfn, prot));
		pfn++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	return 0;
}

static inline int ioremap_pmd_range(pud_t *pud, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;

	phys_addr -= addr;
	pmd = pmd_alloc(&init_mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);
		if (ioremap_pte_range(pmd, addr, next, phys_addr + addr, prot))
			return -ENOMEM;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

// ARM10C 20141025
// pgd: 0xc0004780, addr: 0xf0000000, next: 0xf0001000, phys_addr: 0x20481000, prot: 0x653
static inline int ioremap_pud_range(pgd_t *pgd, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;

	phys_addr -= addr;
	pud = pud_alloc(&init_mm, pgd, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (ioremap_pmd_range(pud, addr, next, phys_addr + addr, prot))
			return -ENOMEM;
	} while (pud++, addr = next, addr != end);
	return 0;
}

// ARM10C 20141025
// addr: 0xf0000000, end: 0xf0001000, paddr: 0x10481000,
// type->prot_pte: (&mem_types[0])->prot_pte: PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED (0x653)
int ioremap_page_range(unsigned long addr,
		       unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pgd_t *pgd;
	unsigned long start;
	unsigned long next;
	int err;

	// addr: 0xf0000000, end: 0xf0001000
	BUG_ON(addr >= end);

	// addr: 0xf0000000
	start = addr;
	// start: 0xf0000000

	// phys_addr: 0x10481000, addr: 0xf0000000
	phys_addr -= addr;
	// phys_addr: 0x20481000

	// addr: 0xf0000000, pgd_offset_k(0xf0000000): (0xc0004000 + 0x780)
	pgd = pgd_offset_k(addr);
	// pgd: (0xc0004000 + 0x780)

	do {
		// addr: 0xf0000000, end: 0xf0001000
		// pgd_addr_end(0xf0000000, 0xf0001000): 0xf0001000
		next = pgd_addr_end(addr, end);
		// next: 0xf0001000

// 2014/10/25 종료

		// pgd: 0xc0004780, addr: 0xf0000000, next: 0xf0001000, phys_addr: 0x20481000, prot: 0x653
		err = ioremap_pud_range(pgd, addr, next, phys_addr+addr, prot);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);

	flush_cache_vmap(start, end);

	return err;
}
EXPORT_SYMBOL_GPL(ioremap_page_range);
