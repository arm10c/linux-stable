/*
 *  linux/arch/arm/mm/ioremap.c
 *
 * Re-map IO memory to kernel address space so that we can access it.
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 *
 * Hacked for ARM by Phil Blundell <philb@gnu.org>
 * Hacked to allow all architectures to build, and various cleanups
 * by Russell King
 *
 * This allows a driver to remap an arbitrary region of bus memory into
 * virtual space.  One should *only* use readl, writel, memcpy_toio and
 * so on with such remapped areas.
 *
 * Because the ARM only has a 32-bit address space we can't address the
 * whole of the (physical) PCI space at once.  PCI huge-mode addressing
 * allows us to circumvent this restriction by splitting PCI space into
 * two 2GB chunks and mapping only one at a time into processor memory.
 * We use MMU protection domains to trap any attempt to access the bank
 * that is not currently mapped.  (This isn't fully implemented yet.)
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <linux/sizes.h>

#include <asm/cp15.h>
#include <asm/cputype.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/system_info.h>

#include <asm/mach/map.h>
#include <asm/mach/pci.h>
#include "mm.h"


// ARM10C 20131116
// ARM10C 20131130
// SYSC: 0xf6100000 +  64kB   PA:0x10050000
// TMR : 0xf6300000 +  16kB   PA:0x12DD0000
// WDT : 0xf6400000 +   4kB   PA:0x101D0000
// CHID: 0xf8000000 +   4kB   PA:0x10000000
// CMU : 0xf8100000 + 144kB   PA:0x10010000
// PMU : 0xf8180000 +  64kB   PA:0x10040000
// SRAM: 0xf8400000 +   4kB   PA:0x02020000
// ROMC: 0xf84c0000 +   4kB   PA:0x12250000
LIST_HEAD(static_vmlist);

// ARM10C 20141018
// paddr: 0x10481000 size: 0x1000, mtype: MT_DEVICE: 0
// ARM10C 20141101
// paddr: 0x10482000 size: 0x1000, mtype: MT_DEVICE: 0
// ARM10C 20141206
// paddr: 0x10440000 size: 0x1000, mtype: MT_DEVICE: 0
// ARM10C 20150110
// paddr: 0x10010000 size: 0x30000, mtype: MT_DEVICE: 0
static struct static_vm *find_static_vm_paddr(phys_addr_t paddr,
			size_t size, unsigned int mtype)
{
	struct static_vm *svm;
	struct vm_struct *vm;

	list_for_each_entry(svm, &static_vmlist, list) {
	// for (svm = list_first_entry(&static_vmlist, typeof(*svm), list);
	//     &svm->list != (&static_vmlist); svm = list_next_entry(svm, list))

		// svm: SYSC의 svm

		// svm->vm: (SYSC의 svm)->vm
		vm = &svm->vm;
		// vm: &(SYSC의 svm)->vm
		// vm->addr: 0xF6100000, vm->size: 0x10000, vm->phys_addr: 0x10050000, vm->flags: 0x40000001

		// vm->flags: 0x40000001, VM_ARM_STATIC_MAPPING: 0x40000000
		if (!(vm->flags & VM_ARM_STATIC_MAPPING))
			continue;

		// vm->flags: 0x40000001, VM_ARM_MTYPE_MASK: 0x1f00000
		// mtype: MT_DEVICE: 0, VM_ARM_MTYPE(MT_DEVICE: 0): 0
		if ((vm->flags & VM_ARM_MTYPE_MASK) != VM_ARM_MTYPE(mtype))
			continue;

		// vm->phys_addr: 0x10050000, paddr: 0x10481000, size: 0x1000, vm->size: 0x10000
		if (vm->phys_addr > paddr ||
			paddr + size - 1 > vm->phys_addr + vm->size - 1)
			continue;

		return svm;
	}
	// loop 수행 결과 static_vmlist에 등록된 svm 중에 해당하는 영역이 없음

	return NULL;
	// return NULL
}

struct static_vm *find_static_vm_vaddr(void *vaddr)
{
	struct static_vm *svm;
	struct vm_struct *vm;

	list_for_each_entry(svm, &static_vmlist, list) {
		vm = &svm->vm;

		/* static_vmlist is ascending order */
		if (vm->addr > vaddr)
			break;

		if (vm->addr <= vaddr && vm->addr + vm->size > vaddr)
			return svm;
	}

	return NULL;
}

// ARM10C 20131116
// ARM10C 20131130
// vm->addr: 0xF8000000
// vm->phys_addr: 0x10000000
// vm->size: 0x1000
// vm->flags: 0x40000001
//
// S3C_VA_SYS
// vm->addr: 0xF6100000
// vm->size: 0x10000 
// vm->phys_addr: 0x10050000
// vm->flags: 0x40000001
void __init add_static_vm_early(struct static_vm *svm)
{
	struct static_vm *curr_svm;
	struct vm_struct *vm;
	void *vaddr;

	vm = &svm->vm;
	// vm 을 vmlist에 삽입, vmlist은 오름차순 정렬
	vm_area_add_early(vm);
	// vm->addr: 0xF8000000, vaddr: 0xF8000000
	// vm->addr: 0xF6100000, vaddr: 0xF6100000
	vaddr = vm->addr;

	// #define list_for_each_entry(curr_svm, &static_vmlist, list)
	// for (curr_svm = list_entry((&static_vmlist)->next, typeof(*curr_svm), list);
	//     &curr_svm->list != (&static_vmlist);
	//     curr_svm = list_entry(curr_svm->list.next, typeof(*curr_svm), list))

	list_for_each_entry(curr_svm, &static_vmlist, list) {
		vm = &curr_svm->vm;

		// vm->addr:0xF8000000, vaddr: 0xF6100000
		if (vm->addr > vaddr)
			break;
	}
	// svm 을 static_vmlist에 insert함
	list_add_tail(&svm->list, &curr_svm->list);
}

int ioremap_page(unsigned long virt, unsigned long phys,
		 const struct mem_type *mtype)
{
	return ioremap_page_range(virt, virt + PAGE_SIZE, phys,
				  __pgprot(mtype->prot_pte));
}
EXPORT_SYMBOL(ioremap_page);

void __check_vmalloc_seq(struct mm_struct *mm)
{
	unsigned int seq;

	do {
		seq = init_mm.context.vmalloc_seq;
		memcpy(pgd_offset(mm, VMALLOC_START),
		       pgd_offset_k(VMALLOC_START),
		       sizeof(pgd_t) * (pgd_index(VMALLOC_END) -
					pgd_index(VMALLOC_START)));
		mm->context.vmalloc_seq = seq;
	} while (seq != init_mm.context.vmalloc_seq);
}

#if !defined(CONFIG_SMP) && !defined(CONFIG_ARM_LPAE)
/*
 * Section support is unsafe on SMP - If you iounmap and ioremap a region,
 * the other CPUs will not see this change until their next context switch.
 * Meanwhile, (eg) if an interrupt comes in on one of those other CPUs
 * which requires the new ioremap'd region to be referenced, the CPU will
 * reference the _old_ region.
 *
 * Note that get_vm_area_caller() allocates a guard 4K page, so we need to
 * mask the size back to 1MB aligned or we will overflow in the loop below.
 */
static void unmap_area_sections(unsigned long virt, unsigned long size)
{
	unsigned long addr = virt, end = virt + (size & ~(SZ_1M - 1));
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmdp;

	flush_cache_vunmap(addr, end);
	pgd = pgd_offset_k(addr);
	pud = pud_offset(pgd, addr);
	pmdp = pmd_offset(pud, addr);
	do {
		pmd_t pmd = *pmdp;

		if (!pmd_none(pmd)) {
			/*
			 * Clear the PMD from the page table, and
			 * increment the vmalloc sequence so others
			 * notice this change.
			 *
			 * Note: this is still racy on SMP machines.
			 */
			pmd_clear(pmdp);
			init_mm.context.vmalloc_seq++;

			/*
			 * Free the page table, if there was one.
			 */
			if ((pmd_val(pmd) & PMD_TYPE_MASK) == PMD_TYPE_TABLE)
				pte_free_kernel(&init_mm, pmd_page_vaddr(pmd));
		}

		addr += PMD_SIZE;
		pmdp += 2;
	} while (addr < end);

	/*
	 * Ensure that the active_mm is up to date - we want to
	 * catch any use-after-iounmap cases.
	 */
	if (current->active_mm->context.vmalloc_seq != init_mm.context.vmalloc_seq)
		__check_vmalloc_seq(current->active_mm);

	flush_tlb_kernel_range(virt, end);
}

static int
remap_area_sections(unsigned long virt, unsigned long pfn,
		    size_t size, const struct mem_type *type)
{
	unsigned long addr = virt, end = virt + size;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	/*
	 * Remove and free any PTE-based mapping, and
	 * sync the current kernel mapping.
	 */
	unmap_area_sections(virt, size);

	pgd = pgd_offset_k(addr);
	pud = pud_offset(pgd, addr);
	pmd = pmd_offset(pud, addr);
	do {
		pmd[0] = __pmd(__pfn_to_phys(pfn) | type->prot_sect);
		pfn += SZ_1M >> PAGE_SHIFT;
		pmd[1] = __pmd(__pfn_to_phys(pfn) | type->prot_sect);
		pfn += SZ_1M >> PAGE_SHIFT;
		flush_pmd_entry(pmd);

		addr += PMD_SIZE;
		pmd += 2;
	} while (addr < end);

	return 0;
}

static int
remap_area_supersections(unsigned long virt, unsigned long pfn,
			 size_t size, const struct mem_type *type)
{
	unsigned long addr = virt, end = virt + size;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	/*
	 * Remove and free any PTE-based mapping, and
	 * sync the current kernel mapping.
	 */
	unmap_area_sections(virt, size);

	pgd = pgd_offset_k(virt);
	pud = pud_offset(pgd, addr);
	pmd = pmd_offset(pud, addr);
	do {
		unsigned long super_pmd_val, i;

		super_pmd_val = __pfn_to_phys(pfn) | type->prot_sect |
				PMD_SECT_SUPER;
		super_pmd_val |= ((pfn >> (32 - PAGE_SHIFT)) & 0xf) << 20;

		for (i = 0; i < 8; i++) {
			pmd[0] = __pmd(super_pmd_val);
			pmd[1] = __pmd(super_pmd_val);
			flush_pmd_entry(pmd);

			addr += PMD_SIZE;
			pmd += 2;
		}

		pfn += SUPERSECTION_SIZE >> PAGE_SHIFT;
	} while (addr < end);

	return 0;
}
#endif

// ARM10C 20141018
// pfn: 0x10481, offset: 0, size: 0x1000, mtype: MT_DEVICE: 0, caller: __builtin_return_address(0)
// ARM10C 20141101
// pfn: 0x10482, offset: 0, size: 0x1000, mtype: MT_DEVICE: 0, caller: __builtin_return_address(0)
// ARM10C 20141206
// pfn: 0x10440, offset: 0, size: 0x1000, mtype: MT_DEVICE: 0, caller: __builtin_return_address(0)
// ARM10C 20150110
// pfn: 0x10010, offset: 0, size: 0x30000, mtype: MT_DEVICE: 0, caller: __builtin_return_address(0)
void __iomem * __arm_ioremap_pfn_caller(unsigned long pfn,
	unsigned long offset, size_t size, unsigned int mtype, void *caller)
{
	const struct mem_type *type;
	int err;
	unsigned long addr;
	struct vm_struct *area;
	// pfn: 0x10481, __pfn_to_phys(0x10481): 0x10481000
	// pfn: 0x10482, __pfn_to_phys(0x10482): 0x10482000
	// pfn: 0x10440, __pfn_to_phys(0x10440): 0x10440000
	// pfn: 0x10010, __pfn_to_phys(0x10010): 0x10010000
	phys_addr_t paddr = __pfn_to_phys(pfn);
	// paddr: 0x10481000
	// paddr: 0x10482000
	// paddr: 0x10440000
	// paddr: 0x10010000

#ifndef CONFIG_ARM_LPAE // CONFIG_ARM_LPAE=n
	/*
	 * High mappings must be supersection aligned
	 */
	// pfn: 0x10481, paddr: 0x10481000, SUPERSECTION_MASK: 0xff000000
	// pfn: 0x10482, paddr: 0x10482000, SUPERSECTION_MASK: 0xff000000
	// pfn: 0x10440, paddr: 0x10440000, SUPERSECTION_MASK: 0xff000000
	// pfn: 0x10010, paddr: 0x10010000, SUPERSECTION_MASK: 0xff000000
	if (pfn >= 0x100000 && (paddr & ~SUPERSECTION_MASK))
		return NULL;
#endif

	// mtype: MT_DEVICE: 0
	// get_mem_type(MT_DEVICE: 0): &mem_types[0]
	// mtype: MT_DEVICE: 0
	// get_mem_type(MT_DEVICE: 0): &mem_types[0]
	// mtype: MT_DEVICE: 0
	// get_mem_type(MT_DEVICE: 0): &mem_types[0]
	// mtype: MT_DEVICE: 0
	// get_mem_type(MT_DEVICE: 0): &mem_types[0]
	type = get_mem_type(mtype);
	// type: &mem_types[0]
	// type: &mem_types[0]
	// type: &mem_types[0]
	// type: &mem_types[0]

	// type: &mem_types[0]
	// type: &mem_types[0]
	// type: &mem_types[0]
	// type: &mem_types[0]
	if (!type)
		return NULL;

	/*
	 * Page align the mapping size, taking account of any offset.
	 */
	// offset: 0, size: 0x1000, PAGE_ALIGN(0x1000): 0x1000
	// offset: 0, size: 0x1000, PAGE_ALIGN(0x1000): 0x1000
	// offset: 0, size: 0x1000, PAGE_ALIGN(0x1000): 0x1000
	// offset: 0, size: 0x30000, PAGE_ALIGN(0x30000): 0x30000
	size = PAGE_ALIGN(offset + size);
	// size: 0x1000
	// size: 0x1000
	// size: 0x1000
	// size: 0x30000

	/*
	 * Try to reuse one of the static mapping whenever possible.
	 */
	// size: 0x1000, sizeof(phys_addr_t): 4, pfn: 0x10481
	// size: 0x1000, sizeof(phys_addr_t): 4, pfn: 0x10482
	// size: 0x1000, sizeof(phys_addr_t): 4, pfn: 0x10440
	// size: 0x30000, sizeof(phys_addr_t): 4, pfn: 0x10010
	if (size && !(sizeof(phys_addr_t) == 4 && pfn >= 0x100000)) {
		struct static_vm *svm;

		// paddr: 0x10481000 size: 0x1000, mtype: MT_DEVICE: 0
		// find_static_vm_paddr(0x10481000, 0x1000, MT_DEVICE: 0): NULL
		// paddr: 0x10482000 size: 0x1000, mtype: MT_DEVICE: 0
		// find_static_vm_paddr(0x10482000, 0x1000, MT_DEVICE: 0): NULL
		// paddr: 0x10440000 size: 0x1000, mtype: MT_DEVICE: 0
		// find_static_vm_paddr(0x10440000, 0x1000, MT_DEVICE: 0): NULL
		// paddr: 0x10010000 size: 0x30000, mtype: MT_DEVICE: 0
		// find_static_vm_paddr(0x10010000, 0x30000, MT_DEVICE: 0): NULL
		svm = find_static_vm_paddr(paddr, size, mtype);
		// svm: NULL
		// svm: NULL
		// svm: NULL
		// svm: NULL

		// svm: NULL
		// svm: NULL
		// svm: NULL
		// svm: NULL
		if (svm) {
			addr = (unsigned long)svm->vm.addr;
			addr += paddr - svm->vm.phys_addr;
			return (void __iomem *) (offset + addr);
		}
	}

// 2014/10/18 종료
// 2014/10/25 시작

	/*
	 * Don't allow RAM to be mapped - this causes problems with ARMv6+
	 */
	// pfn: 0x10481, pfn_valid(0x10481): 0
	// pfn: 0x10482, pfn_valid(0x10482): 0
	// pfn: 0x10440, pfn_valid(0x10440): 0
	// pfn: 0x10010, pfn_valid(0x10010): 0
	if (WARN_ON(pfn_valid(pfn)))
		return NULL;

	// size: 0x1000, VM_IOREMAP: 0x00000001, caller: __builtin_return_address(0)
	// get_vm_area_caller(0x1000, 0x00000001, __builtin_return_address(0)): kmem_cache#30-oX (vm_struct)
	// size: 0x1000, VM_IOREMAP: 0x00000001, caller: __builtin_return_address(0)
	// get_vm_area_caller(0x1000, 0x00000001, __builtin_return_address(0)): kmem_cache#30-oX (vm_struct)
	// size: 0x1000, VM_IOREMAP: 0x00000001, caller: __builtin_return_address(0)
	// get_vm_area_caller(0x1000, 0x00000001, __builtin_return_address(0)): kmem_cache#30-oX (vm_struct)
	// size: 0x30000, VM_IOREMAP: 0x00000001, caller: __builtin_return_address(0)
	// get_vm_area_caller(0x30000, 0x00000001, __builtin_return_address(0)): kmem_cache#30-oX (vm_struct)
	area = get_vm_area_caller(size, VM_IOREMAP, caller);
	// area: kmem_cache#30-oX (vm_struct)
	// area: kmem_cache#30-oX (vm_struct)
	// area: kmem_cache#30-oX (vm_struct)
	// area: kmem_cache#30-oX (vm_struct)

	/*
	// get_vm_area_caller이 한일:
	// alloc area (GIC#0) 를 만들고 rb tree에 alloc area 를 추가
	// 가상주소 va_start 기준으로 GIC#0 를 RB Tree 추가한 결과
	//
	//                                  CHID-b
	//                               (0xF8000000)
	//                              /            \
	//                         TMR-r               PMU-r
	//                    (0xF6300000)             (0xF8180000)
	//                      /      \               /           \
	//                 SYSC-b      WDT-b         CMU-b         SRAM-b
	//            (0xF6100000)   (0xF6400000)  (0xF8100000)   (0xF8400000)
	//             /                                                 \
	//        GIC#0-r                                                 ROMC-r
	//   (0xF0000000)                                                 (0xF84C0000)
	//
	// vmap_area_list에 GIC#0 - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
	// 순서로 리스트에 연결이 됨
	//
	// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
	// (kmem_cache#30-oX (vm_struct))->addr: 0xf0000000
	// (kmem_cache#30-oX (vm_struct))->size: 0x2000
	// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
	//
	// (kmem_cache#30-oX (vmap_area GIC#0))->vm: kmem_cache#30-oX (vm_struct)
	// (kmem_cache#30-oX (vmap_area GIC#0))->flags: 0x04
	*/

	/*
	// get_vm_area_caller이 한일:
	// alloc area (GIC#1) 를 만들고 rb tree에 alloc area 를 추가
	// 가상주소 va_start 기준으로 GIC#1 를 RB Tree 추가한 결과
	//
	//                                  CHID-b
	//                               (0xF8000000)
	//                              /            \
	//                         TMR-r               PMU-r
	//                    (0xF6300000)             (0xF8180000)
	//                      /      \               /           \
	//                GIC#1-b      WDT-b         CMU-b         SRAM-b
	//            (0xF0002000)   (0xF6400000)  (0xF8100000)   (0xF8400000)
	//             /       \                                          \
	//        GIC#0-r     SYSC-r                                       ROMC-r
	//    (0xF0000000)   (0xF6100000)                                 (0xF84C0000)
	//
	// vmap_area_list에 GIC#0 - GIC#1 - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
	// 순서로 리스트에 연결이 됨
	//
	// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
	// (kmem_cache#30-oX (vm_struct))->addr: 0xf0002000
	// (kmem_cache#30-oX (vm_struct))->size: 0x2000
	// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
	//
	// (kmem_cache#30-oX (vmap_area GIC#1))->vm: kmem_cache#30-oX (vm_struct)
	// (kmem_cache#30-oX (vmap_area GIC#1))->flags: 0x04
	*/

	/*
	// get_vm_area_caller이 한일:
	// alloc area (COMB) 를 만들고 rb tree에 alloc area 를 추가
	// 가상주소 va_start 기준으로 COMB 를 RB Tree 추가한 결과
	//
	//                                  CHID-b
	//                               (0xF8000000)
	//                              /            \
	//                         TMR-b               PMU-b
	//                    (0xF6300000)             (0xF8180000)
	//                      /      \               /           \
	//                GIC#1-r      WDT-b         CMU-b         SRAM-b
	//            (0xF0002000)   (0xF6400000)  (0xF8100000)   (0xF8400000)
	//             /       \                                          \
	//        GIC#0-b     SYSC-b                                       ROMC-r
	//    (0xF0000000)   (0xF6100000)                                 (0xF84C0000)
	//                   /
	//               COMB-r
	//          (0xF0004000)
	//
	// vmap_area_list에 GIC#0 - GIC#1 - COMB - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
	// 순서로 리스트에 연결이 됨
	//
	// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
	// (kmem_cache#30-oX (vm_struct))->addr: 0xf0004000
	// (kmem_cache#30-oX (vm_struct))->size: 0x2000
	// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
	//
	// (kmem_cache#30-oX (vmap_area COMB))->vm: kmem_cache#30-oX (vm_struct)
	// (kmem_cache#30-oX (vmap_area COMB))->flags: 0x04
	*/

	/*
	// get_vm_area_caller이 한일:
	// alloc area (CLK) 를 만들고 rb tree에 alloc area 를 추가
	// 가상주소 va_start 기준으로 CLK 를 RB Tree 추가한 결과
	//
	//                                  CHID-b
	//                               (0xF8000000)
	//                              /            \
	//                         TMR-b               PMU-b
	//                    (0xF6300000)             (0xF8180000)
	//                      /      \               /           \
	//                GIC#1-r      WDT-b         CMU-b         SRAM-b
	//            (0xF0002000)   (0xF6400000)  (0xF8100000)   (0xF8400000)
	//             /       \                                          \
	//        GIC#0-b     CLK-b                                        ROMC-r
	//    (0xF0000000)   (0xF0040000)                                 (0xF84C0000)
	//                   /      \
	//               COMB-r     SYSC-r
	//          (0xF0004000)   (0xF6100000)
	//
	// vmap_area_list에 GIC#0 - GIC#1 - COMB - CLK - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
	// 순서로 리스트에 연결이 됨
	//
	// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
	// (kmem_cache#30-oX (vm_struct))->addr: 0xf0040000
	// (kmem_cache#30-oX (vm_struct))->size: 0x31000
	// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
	//
	// (kmem_cache#30-oX (vmap_area CLK))->vm: kmem_cache#30-oX (vm_struct)
	// (kmem_cache#30-oX (vmap_area CLK))->flags: 0x04
	*/

	// area: kmem_cache#30-oX (vm_struct)
	// area: kmem_cache#30-oX (vm_struct)
	// area: kmem_cache#30-oX (vm_struct)
	// area: kmem_cache#30-oX (vm_struct)
 	if (!area)
 		return NULL;

	// area->addr: (kmem_cache#30-oX (vm_struct))->addr: 0xf0000000
	// area->addr: (kmem_cache#30-oX (vm_struct))->addr: 0xf0002000
	// area->addr: (kmem_cache#30-oX (vm_struct))->addr: 0xf0004000
	// area->addr: (kmem_cache#30-oX (vm_struct))->addr: 0xf0040000
 	addr = (unsigned long)area->addr;
	// addr: 0xf0000000
	// addr: 0xf0002000
	// addr: 0xf0004000
	// addr: 0xf0040000

	// area->phys_addr: (kmem_cache#30-oX (vm_struct))->phys_addr, paddr: 0x10481000
	// area->phys_addr: (kmem_cache#30-oX (vm_struct))->phys_addr, paddr: 0x10482000
	// area->phys_addr: (kmem_cache#30-oX (vm_struct))->phys_addr, paddr: 0x10440000
	// area->phys_addr: (kmem_cache#30-oX (vm_struct))->phys_addr, paddr: 0x10010000
	area->phys_addr = paddr;
	// area->phys_addr: (kmem_cache#30-oX (vm_struct))->phys_addr: 0x10481000
	// area->phys_addr: (kmem_cache#30-oX (vm_struct))->phys_addr: 0x10482000
	// area->phys_addr: (kmem_cache#30-oX (vm_struct))->phys_addr: 0x10440000
	// area->phys_addr: (kmem_cache#30-oX (vm_struct))->phys_addr: 0x10010000

#if !defined(CONFIG_SMP) && !defined(CONFIG_ARM_LPAE) // CONFIG_SMP=y, CONFIG_ARM_LPAE=n
	if (DOMAIN_IO == 0 &&
	    (((cpu_architecture() >= CPU_ARCH_ARMv6) && (get_cr() & CR_XP)) ||
	       cpu_is_xsc3()) && pfn >= 0x100000 &&
	       !((paddr | size | addr) & ~SUPERSECTION_MASK)) {
		area->flags |= VM_ARM_SECTION_MAPPING;
		err = remap_area_supersections(addr, pfn, size, type);
	} else if (!((paddr | size | addr) & ~PMD_MASK)) {
		area->flags |= VM_ARM_SECTION_MAPPING;
		err = remap_area_sections(addr, pfn, size, type);
	} else
#endif
		// addr: 0xf0000000, size: 0x1000, paddr: 0x10481000,
		// type->prot_pte: (&mem_types[0])->prot_pte: PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED (0x653)
		// ioremap_page_range(0xf0000000, 0xf0001000, 0x10481000, PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED (0x653)): 0
		// addr: 0xf0002000, size: 0x1000, paddr: 0x10482000,
		// type->prot_pte: (&mem_types[0])->prot_pte: PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED (0x653)
		// ioremap_page_range(0xf0002000, 0xf0003000, 0x10482000, PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED (0x653)): 0
		// addr: 0xf0004000, size: 0x1000, paddr: 0x10440000,
		// type->prot_pte: (&mem_types[0])->prot_pte: PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED (0x653)
		// ioremap_page_range(0xf0004000, 0xf0005000, 0x10440000, PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED (0x653)): 0
		// addr: 0xf0040000, size: 0x31000, paddr: 0x10010000,
		// type->prot_pte: (&mem_types[0])->prot_pte: PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED (0x653)
		// ioremap_page_range(0xf0040000, 0xf0071000, 0x10010000, PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED (0x653)): 0
		err = ioremap_page_range(addr, addr + size, paddr,
					 __pgprot(type->prot_pte));
		// err: 0
		// err: 0
		// err: 0
		// err: 0

		// ioremap_page_range에서 한일:
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

		// ioremap_page_range에서 한일:
		// 0xc0004780이 가리키는 pte의 시작주소에 0x10482653 값을 갱신
		// (linux pgtable과 hardware pgtable의 값 같이 갱신)
		//
		//  pgd                   pte
		// |              |
		// +--------------+
		// |              |       +--------------+ +0
		// |              |       |  0xXXXXXXXX  | ---> 0x10482653 에 매칭되는 linux pgtable 값
		// +- - - - - - - +       |  Linux pt 0  |
		// |              |       +--------------+ +1024
		// |              |       |              |
		// +--------------+ +0    |  Linux pt 1  |
		// | *(c0004780)  |-----> +--------------+ +2048
		// |              |       |  0x10482653  | ---> 2060
		// +- - - - - - - + +4    |   h/w pt 0   |
		// | *(c0004784)  |-----> +--------------+ +3072
		// |              |       +              +
		// +--------------+ +8    |   h/w pt 1   |
		// |              |       +--------------+ +4096

		// ioremap_page_range에서 한일:
		// 0xc0004780이 가리키는 pte의 시작주소에 0x10440653 값을 갱신
		// (linux pgtable과 hardware pgtable의 값 같이 갱신)
		//
		//  pgd                   pte
		// |              |
		// +--------------+
		// |              |       +--------------+ +0
		// |              |       |  0xXXXXXXXX  | ---> 0x10440653 에 매칭되는 linux pgtable 값
		// +- - - - - - - +       |  Linux pt 0  |
		// |              |       +--------------+ +1024
		// |              |       |              |
		// +--------------+ +0    |  Linux pt 1  |
		// | *(c0004780)  |-----> +--------------+ +2048
		// |              |       |  0x10440653  | ---> 2068
		// +- - - - - - - + +4    |   h/w pt 0   |
		// | *(c0004784)  |-----> +--------------+ +3072
		// |              |       +              +
		// +--------------+ +8    |   h/w pt 1   |
		// |              |       +--------------+ +4096

		// ioremap_page_range에서 한일:
		// 0xc0004780이 가리키는 pte의 시작주소에 0x10010000 값을 갱신
		// (linux pgtable과 hardware pgtable의 값 같이 갱신)
		//
		//  pgd                   pte
		// |              |
		// +--------------+
		// |              |       +--------------+ +0
		// |              |       |  0xXXXXXXXX  | ---> 0x10010653 에 매칭되는 linux pgtable 값
		// +- - - - - - - +       |  Linux pt 0  |
		// |              |       +--------------+ +1024
		// |              |       |              |
		// +--------------+ +0    |  Linux pt 1  |
		// | *(c0004780)  |-----> +--------------+ +2048
		// |              |       |  0x10010653  | ---> 2076
		// +- - - - - - - + +4    |   h/w pt 0   |
		// | *(c0004784)  |-----> +--------------+ +3072
		// |              |       +              +
		// +--------------+ +8    |   h/w pt 1   |
		// |              |       +--------------+ +4096
	
	// err: 0
	// err: 0
	// err: 0
	// err: 0
	if (err) {
 		vunmap((void *)addr);
 		return NULL;
 	}

	// addr: 0xf0000000, size: 0x1000
	// addr: 0xf0002000, size: 0x1000
	// addr: 0xf0004000, size: 0x1000
	// addr: 0xf0040000, size: 0x30000
	flush_cache_vmap(addr, addr + size);
	// cache의 값을 전부 메모리에 반영
	// cache의 값을 전부 메모리에 반영
	// cache의 값을 전부 메모리에 반영
	// cache의 값을 전부 메모리에 반영

	// offset: 0, addr: 0xf0000000
	// offset: 0, addr: 0xf0002000
	// offset: 0, addr: 0xf0004000
	// offset: 0, addr: 0xf0040000
	return (void __iomem *) (offset + addr);
	// return 0xf0000000
	// return 0xf0002000
	// return 0xf0004000
	// return 0xf0040000
}

// ARM10C 20141018
// phys_addr: 0x10481000, size: 0x1000, mtype: MT_DEVICE: 0, __builtin_return_address(0)
// ARM10C 20141101
// phys_addr: 0x10482000, size: 0x1000, mtype: MT_DEVICE: 0, __builtin_return_address(0)
// ARM10C 20141206
// phys_addr: 0x10440000, size: 0x1000, mtype: MT_DEVICE: 0, __builtin_return_address(0)
// ARM10C 20150110
// phys_addr: 0x10010000, size: 0x30000, mtype: MT_DEVICE: 0, __builtin_return_address(0)
void __iomem *__arm_ioremap_caller(phys_addr_t phys_addr, size_t size,
	unsigned int mtype, void *caller)
{
	phys_addr_t last_addr;
	// phys_addr: 0x10481000, PAGE_MASK: 0xFFFFF000
	// phys_addr: 0x10482000, PAGE_MASK: 0xFFFFF000
	// phys_addr: 0x10440000, PAGE_MASK: 0xFFFFF000
	// phys_addr: 0x10010000, PAGE_MASK: 0xFFFFF000
 	unsigned long offset = phys_addr & ~PAGE_MASK;
	// offset: 0
	// offset: 0
	// offset: 0
	// offset: 0

	// phys_addr: 0x10481000, __phys_to_pfn(0x10481000): 0x10481
	// phys_addr: 0x10482000, __phys_to_pfn(0x10482000): 0x10482
	// phys_addr: 0x10440000, __phys_to_pfn(0x10440000): 0x10440
	// phys_addr: 0x10010000, __phys_to_pfn(0x10010000): 0x10010
 	unsigned long pfn = __phys_to_pfn(phys_addr);
	// pfn: 0x10481
	// pfn: 0x10482
	// pfn: 0x10440
	// pfn: 0x10010

 	/*
 	 * Don't allow wraparound or zero size
	 */
	// phys_addr: 0x10481000, size: 0x1000
	// phys_addr: 0x10482000, size: 0x1000
	// phys_addr: 0x10440000, size: 0x1000
	// phys_addr: 0x10010000, size: 0x30000
	last_addr = phys_addr + size - 1;
	// last_addr: 0x10481fff
	// last_addr: 0x10482fff
	// last_addr: 0x10440fff
	// last_addr: 0x1003ffff

	// size: 0x1000, last_addr: 0x10481fff, phys_addr: 0x10481000
	// size: 0x1000, last_addr: 0x10482fff, phys_addr: 0x10482000
	// size: 0x1000, last_addr: 0x10440fff, phys_addr: 0x10440000
	// size: 0x30000, last_addr: 0x1003ffff, phys_addr: 0x10010000
	if (!size || last_addr < phys_addr)
		return NULL;

	// pfn: 0x10481, offset: 0, size: 0x1000, mtype: MT_DEVICE: 0, caller: __builtin_return_address(0)
	// __arm_ioremap_pfn_caller(0x10481, 0, 0x1000, MT_DEVICE: 0, __builtin_return_address(0)): 0xf0000000
	// pfn: 0x10482, offset: 0, size: 0x1000, mtype: MT_DEVICE: 0, caller: __builtin_return_address(0)
	// __arm_ioremap_pfn_caller(0x10482, 0, 0x1000, MT_DEVICE: 0, __builtin_return_address(0)): 0xf0002000
	// pfn: 0x10440, offset: 0, size: 0x1000, mtype: MT_DEVICE: 0, caller: __builtin_return_address(0)
	// __arm_ioremap_pfn_caller(0x10440, 0, 0x1000, MT_DEVICE: 0, __builtin_return_address(0)): 0xf0004000
	// pfn: 0x10010, offset: 0, size: 0x30000, mtype: MT_DEVICE: 0, caller: __builtin_return_address(0)
	// __arm_ioremap_pfn_caller(0x10010, 0, 0x30000, MT_DEVICE: 0, __builtin_return_address(0)): 0xf0040000
	return __arm_ioremap_pfn_caller(pfn, offset, size, mtype,
			caller);
	// return 0xf0000000
	// return 0xf0002000
	// return 0xf0004000
	// return 0xf0040000
}

/*
 * Remap an arbitrary physical address space into the kernel virtual
 * address space. Needed when the kernel wants to access high addresses
 * directly.
 *
 * NOTE! We need to allow non-page-aligned mappings too: we will obviously
 * have to convert them into an offset in a page-aligned mapping, but the
 * caller shouldn't need to know that small detail.
 */
void __iomem *
__arm_ioremap_pfn(unsigned long pfn, unsigned long offset, size_t size,
		  unsigned int mtype)
{
	return __arm_ioremap_pfn_caller(pfn, offset, size, mtype,
			__builtin_return_address(0));
}
EXPORT_SYMBOL(__arm_ioremap_pfn);

// ARM10C 20141018
// ARM10C 20141101
// ARM10C 20141206
// ARM10C 20150110
void __iomem * (*arch_ioremap_caller)(phys_addr_t, size_t,
				      unsigned int, void *) =
	__arm_ioremap_caller;

// ARM10C 20141018
// res.start: 0x10481000, resource_size(&res): 0x1000, MT_DEVICE: 0
// ARM10C 20141101
// res.start: 0x10482000, resource_size(&res): 0x1000, MT_DEVICE: 0
// ARM10C 20141206
// res.start: 0x10440000, resource_size(&res): 0x1000, MT_DEVICE: 0
// ARM10C 20150110
// res.start: 0x10010000, resource_size(&res): 0x30000, MT_DEVICE: 0
void __iomem *
__arm_ioremap(phys_addr_t phys_addr, size_t size, unsigned int mtype)
{
	// phys_addr: 0x10481000, size: 0x1000, mtype: MT_DEVICE: 0
	// arch_ioremap_caller(0x10481000, 0x1000, MT_DEVICE: 0, __builtin_return_address(0)): 0xf0000000
	// phys_addr: 0x10482000, size: 0x1000, mtype: MT_DEVICE: 0
	// arch_ioremap_caller(0x10482000, 0x1000, MT_DEVICE: 0, __builtin_return_address(0)): 0xf0002000
	// phys_addr: 0x10440000, size: 0x1000, mtype: MT_DEVICE: 0
	// arch_ioremap_caller(0x10440000, 0x1000, MT_DEVICE: 0, __builtin_return_address(0)): 0xf0004000
	// phys_addr: 0x10010000, size: 0x30000, mtype: MT_DEVICE: 0
	// arch_ioremap_caller(0x10010000, 0x30000, MT_DEVICE: 0, __builtin_return_address(0)): 0xf0040000
	return arch_ioremap_caller(phys_addr, size, mtype,
		__builtin_return_address(0));
	// return 0xf0000000
	// return 0xf0002000
	// return 0xf0004000
	// return 0xf0040000
}
EXPORT_SYMBOL(__arm_ioremap);

/*
 * Remap an arbitrary physical address space into the kernel virtual
 * address space as memory. Needed when the kernel wants to execute
 * code in external memory. This is needed for reprogramming source
 * clocks that would affect normal memory for example. Please see
 * CONFIG_GENERIC_ALLOCATOR for allocating external memory.
 */
void __iomem *
__arm_ioremap_exec(phys_addr_t phys_addr, size_t size, bool cached)
{
	unsigned int mtype;

	if (cached)
		mtype = MT_MEMORY;
	else
		mtype = MT_MEMORY_NONCACHED;

	return __arm_ioremap_caller(phys_addr, size, mtype,
			__builtin_return_address(0));
}

void __iounmap(volatile void __iomem *io_addr)
{
	void *addr = (void *)(PAGE_MASK & (unsigned long)io_addr);
	struct static_vm *svm;

	/* If this is a static mapping, we must leave it alone */
	svm = find_static_vm_vaddr(addr);
	if (svm)
		return;

#if !defined(CONFIG_SMP) && !defined(CONFIG_ARM_LPAE)
	{
		struct vm_struct *vm;

		vm = find_vm_area(addr);

		/*
		 * If this is a section based mapping we need to handle it
		 * specially as the VM subsystem does not know how to handle
		 * such a beast.
		 */
		if (vm && (vm->flags & VM_ARM_SECTION_MAPPING))
			unmap_area_sections((unsigned long)vm->addr, vm->size);
	}
#endif

	vunmap(addr);
}

void (*arch_iounmap)(volatile void __iomem *) = __iounmap;

void __arm_iounmap(volatile void __iomem *io_addr)
{
	arch_iounmap(io_addr);
}
EXPORT_SYMBOL(__arm_iounmap);

#ifdef CONFIG_PCI
int pci_ioremap_io(unsigned int offset, phys_addr_t phys_addr)
{
	BUG_ON(offset + SZ_64K > IO_SPACE_LIMIT);

	return ioremap_page_range(PCI_IO_VIRT_BASE + offset,
				  PCI_IO_VIRT_BASE + offset + SZ_64K,
				  phys_addr,
				  __pgprot(get_mem_type(MT_DEVICE)->prot_pte));
}
EXPORT_SYMBOL_GPL(pci_ioremap_io);
#endif
