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

// ARM10C 20141101
// pmd: 0xc0004780, addr: 0xf0000000, next: 0xf0001000, phys_addr: 0x10481000, prot: 0x653
static int ioremap_pte_range(pmd_t *pmd, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pte_t *pte;
	u64 pfn;

	// phys_addr: 0x10481000, PAGE_SHIFT: 12
	pfn = phys_addr >> PAGE_SHIFT;
	// pfn: 0x10481

	// pmd: 0xc0004780, addr: 0xf0000000
	// pte_offset_kernel(0xc0004780,0xf0000000): 0xc0004780이 가리키는 pte의 시작주소
	pte = pte_alloc_kernel(pmd, addr);
	// pte: 0xc0004780이 가리키는 pte의 시작주소

	// pte: 0xc0004780이 가리키는 pte의 시작주소
	if (!pte)
		return -ENOMEM;
	do {
		// pte: 0xc0004780이 가리키는 pte의 시작주소
		// pte_none(*(0xc0004780이 가리키는 pte의 시작주소)): 1
		BUG_ON(!pte_none(*pte));

		// addr: 0xf0000000, pte: 0xc0004780이 가리키는 pte의 시작주소, pfn: 0x10481, prot: 0x653
		// pfn_pte(0x10481,0x653): 0x10481653
		set_pte_at(&init_mm, addr, pte, pfn_pte(pfn, prot));

		// set_pte_at에서 한일:
		// 0xc0004780이 가리키는 pte의 시작주소에 0x10481653 값을 갱신
		// (linux pgtable과 hardware pgtable의 값 같이 갱신)
		//
		//  pgd                   pte
		// |              |
		// +--------------+
		// |              |       +--------------+ +0
		// |              |       |  0xXXXXXXXX  | ---> 0x10481653 에 매칭되는 linux pgtable 값
		// +- - - - - - - +       |  Linux pt 0  |
		// |              |       +--------------+ +1024
		// |              |       |              |
		// +--------------+ +0    |  Linux pt 1  |
		// | *(c0004780)  |-----> +--------------+ +2048
		// |              |       |  0x10481653  | ---> 2052
		// +- - - - - - - + +4    |   h/w pt 0   |
		// | *(c0004784)  |-----> +--------------+ +3072
		// |              |       +              +
		// +--------------+ +8    |   h/w pt 1   |
		// |              |       +--------------+ +4096

		// pfn: 0x10481
		pfn++;
		// pfn: 0x10482

		// pte: 0xc0004780이 가리키는 pte의 시작주소, addr: 0xf0000000,
		// PAGE_SIZE: 0x1000, end: 0xf0001000
	} while (pte++, addr += PAGE_SIZE, addr != end);
	// addr: 0xf0001000

	return 0;
	// return 0
}

// ARM10C 20141101
// pud: 0xc0004780, addr: 0xf0000000, next: 0xf0001000, phys_addr: 0x10481000, prot: 0x653
static inline int ioremap_pmd_range(pud_t *pud, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;

	// phys_addr: 0x10481000, addr: 0xf0000000
	phys_addr -= addr;
	// phys_addr: 0x20481000

	// pud: 0xc0004780, addr: 0xf0000000
	// pmd_alloc(&init_mm, 0xc0004780, 0xf0000000): 0xc0004780
	pmd = pmd_alloc(&init_mm, pud, addr);
	// pmd: 0xc0004780

	// pmd: 0xc0004780
	if (!pmd)
		return -ENOMEM;
	do {
		// addr: 0xf0000000, end: 0xf0001000
		// pmd_addr_end(0xf0000000, 0xf0001000): 0xf0001000
		next = pmd_addr_end(addr, end);
		// next: 0xf0001000

		// pmd: 0xc0004780, addr: 0xf0000000, next: 0xf0001000, phys_addr: 0x20481000, prot: 0x653
		// ioremap_pte_range(0xc0004780, 0xf0000000, 0xf0001000, 0x10481000, 0x653): 0
		if (ioremap_pte_range(pmd, addr, next, phys_addr + addr, prot))
			return -ENOMEM;

		// ioremap_pte_range에서 한일:
		// 0xc0004780이 가리키는 pte의 시작주소에 0x10481653 값을 갱신
		// (linux pgtable과 hardware pgtable의 값 같이 갱신)
		//
		//  pgd                   pte
		// |              |
		// +--------------+
		// |              |       +--------------+ +0
		// |              |       |  0xXXXXXXXX  | ---> 0x10481653 에 매칭되는 linux pgtable 값
		// +- - - - - - - +       |  Linux pt 0  |
		// |              |       +--------------+ +1024
		// |              |       |              |
		// +--------------+ +0    |  Linux pt 1  |
		// | *(c0004780)  |-----> +--------------+ +2048
		// |              |       |  0x10481653  | ---> 2052
		// +- - - - - - - + +4    |   h/w pt 0   |
		// | *(c0004784)  |-----> +--------------+ +3072
		// |              |       +              +
		// +--------------+ +8    |   h/w pt 1   |
		// |              |       +--------------+ +4096

		// pmd: 0xc0004780, addr: 0xf0000000, next: 0xf0001000, end: 0xf0001000
	} while (pmd++, addr = next, addr != end);
	// addr: 0xf0001000

	return 0;
	// return 0
}

// ARM10C 20141025
// pgd: 0xc0004780, addr: 0xf0000000, next: 0xf0001000, phys_addr: 0x10481000, prot: 0x653
static inline int ioremap_pud_range(pgd_t *pgd, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;

	// phys_addr: 0x10481000, addr: 0xf0000000
	phys_addr -= addr;
	// phys_addr: 0x20481000

	// pgd: 0xc0004780, addr: 0xf0000000
	// pud_alloc(&init_mm, 0xc0004780, 0xf0000000): 0xc0004780
	pud = pud_alloc(&init_mm, pgd, addr);
	// pud: 0xc0004780

	// pud: 0xc0004780
	if (!pud)
		return -ENOMEM;
	do {
		// addr: 0xf0000000, end: 0xf0001000
		// pud_addr_end(0xf0000000, 0xf0001000): 0xf0001000
		next = pud_addr_end(addr, end);
		// next: 0xf0001000

		// pud: 0xc0004780, addr: 0xf0000000, next: 0xf0001000, phys_addr: 0x20481000, prot: 0x653
		// ioremap_pmd_range(0xc0004780, 0xf0000000, 0xf0001000, 0x10481000, 0x653): 0
		if (ioremap_pmd_range(pud, addr, next, phys_addr + addr, prot))
			return -ENOMEM;

		// ioremap_pmd_range에서 한일:
		// 0xc0004780이 가리키는 pte의 시작주소에 0x10481653 값을 갱신
		// (linux pgtable과 hardware pgtable의 값 같이 갱신)
		//
		//  pgd                   pte
		// |              |
		// +--------------+
		// |              |       +--------------+ +0
		// |              |       |  0xXXXXXXXX  | ---> 0x10481653 에 매칭되는 linux pgtable 값
		// +- - - - - - - +       |  Linux pt 0  |
		// |              |       +--------------+ +1024
		// |              |       |              |
		// +--------------+ +0    |  Linux pt 1  |
		// | *(c0004780)  |-----> +--------------+ +2048
		// |              |       |  0x10481653  | ---> 2052
		// +- - - - - - - + +4    |   h/w pt 0   |
		// | *(c0004784)  |-----> +--------------+ +3072
		// |              |       +              +
		// +--------------+ +8    |   h/w pt 1   |
		// |              |       +--------------+ +4096

		// pud: 0xc0004780, addr: 0xf0000000, next: 0xf0001000, end: 0xf0001000
	} while (pud++, addr = next, addr != end);
	// addr: 0xf0001000

	return 0;
	// return 0
}

// ARM10C 20141025
// addr: 0xf0000000, end: 0xf0001000, paddr: 0x10481000,
// type->prot_pte: (&mem_types[0])->prot_pte: PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED (0x653)
// ARM10C 20141108
// addr: 0xf0002000, size: 0x1000, paddr: 0x10482000,
// type->prot_pte: (&mem_types[0])->prot_pte: PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED (0x653)
// ARM10C 20141206
// addr: 0xf0004000, size: 0x1000, paddr: 0x10440000,
// type->prot_pte: (&mem_types[0])->prot_pte: PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED (0x653)
// ARM10C 20150110
// addr: 0xf0040000, size: 0x31000, paddr: 0x10010000,
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
// 2014/11/01 시작

		// pgd: 0xc0004780, addr: 0xf0000000, next: 0xf0001000, phys_addr: 0x20481000, prot: 0x653
		// ioremap_pud_range(0xc0004780, 0xf0000000, 0xf0001000, 0x10481000, 0x653): 0
		err = ioremap_pud_range(pgd, addr, next, phys_addr+addr, prot);
		// err: 0

		// ioremap_pud_range에서 한일:
		// 0xc0004780이 가리키는 pte의 시작주소에 0x10481653 값을 갱신
		// (linux pgtable과 hardware pgtable의 값 같이 갱신)
		//
		//  pgd                   pte
		// |              |
		// +--------------+
		// |              |       +--------------+ +0
		// |              |       |  0xXXXXXXXX  | ---> 0x10481653 에 매칭되는 linux pgtable 값
		// +- - - - - - - +       |  Linux pt 0  |
		// |              |       +--------------+ +1024
		// |              |       |              |
		// +--------------+ +0    |  Linux pt 1  |
		// | *(c0004780)  |-----> +--------------+ +2048
		// |              |       |  0x10481653  | ---> 2052
		// +- - - - - - - + +4    |   h/w pt 0   |
		// | *(c0004784)  |-----> +--------------+ +3072
		// |              |       +              +
		// +--------------+ +8    |   h/w pt 1   |
		// |              |       +--------------+ +4096

		// err: 0
		if (err)
			break;

		// pgd: 0xc0004780, addr: 0xf0000000, next: 0xf0001000, end: 0xf0001000
	} while (pgd++, addr = next, addr != end);
	// addr: 0xf0001000

	// start: 0xf0000000, end: 0xf0001000
	flush_cache_vmap(start, end);
	// flush_cache_vmap에서 한일:
	// cache의 값을 전부 메모리에 반영

	// err: 0
	return err;
	// return 0
}
EXPORT_SYMBOL_GPL(ioremap_page_range);
