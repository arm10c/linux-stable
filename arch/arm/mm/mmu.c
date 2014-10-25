/*
 *  linux/arch/arm/mm/mmu.c
 *
 *  Copyright (C) 1995-2005 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/mman.h>
#include <linux/nodemask.h>
#include <linux/memblock.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/sizes.h>

#include <asm/cp15.h>
#include <asm/cputype.h>
#include <asm/sections.h>
#include <asm/cachetype.h>
#include <asm/setup.h>
#include <asm/smp_plat.h>
#include <asm/tlb.h>
#include <asm/highmem.h>
#include <asm/system_info.h>
#include <asm/traps.h>
#include <asm/procinfo.h>
#include <asm/memory.h>

#include <asm/mach/arch.h>
#include <asm/mach/map.h>
#include <asm/mach/pci.h>

#include "mm.h"
#include "tcm.h"

/*
 * empty_zero_page is a special page that is used for
 * zero-initialized data and COW.
 */
struct page *empty_zero_page;
EXPORT_SYMBOL(empty_zero_page);

/*
 * The pmd table for the upper-most set of pages.
 */
// ARM10C 20131130
pmd_t *top_pmd;

#define CPOLICY_UNCACHED	0
#define CPOLICY_BUFFERED	1
#define CPOLICY_WRITETHROUGH	2
#define CPOLICY_WRITEBACK	3
#define CPOLICY_WRITEALLOC	4

static unsigned int cachepolicy __initdata = CPOLICY_WRITEBACK;
// ARM10C 20131102
static unsigned int ecc_mask __initdata = 0;
// ARM10C 20131102
pgprot_t pgprot_user;
// ARM10C 20131102
pgprot_t pgprot_kernel;
pgprot_t pgprot_hyp_device;
// ARM10C 20131102
pgprot_t pgprot_s2;
pgprot_t pgprot_s2_device;

EXPORT_SYMBOL(pgprot_user);
EXPORT_SYMBOL(pgprot_kernel);

// ARM10C 20131026
struct cachepolicy {
	const char	policy[16];
	unsigned int	cr_mask;
	pmdval_t	pmd;
	pteval_t	pte;
	pteval_t	pte_s2;
};

#ifdef CONFIG_ARM_LPAE // CONFIG_ARM_LPAE=n
#define s2_policy(policy)	policy
#else
// ARM10C 20131026
#define s2_policy(policy)	0
#endif

// ARM10C 20131026
static struct cachepolicy cache_policies[] __initdata = {
	{
		.policy		= "uncached",
		.cr_mask	= CR_W|CR_C,
		.pmd		= PMD_SECT_UNCACHED,
		.pte		= L_PTE_MT_UNCACHED,
		.pte_s2		= s2_policy(L_PTE_S2_MT_UNCACHED),
	}, {
		.policy		= "buffered",
		.cr_mask	= CR_C,
		.pmd		= PMD_SECT_BUFFERED,
		.pte		= L_PTE_MT_BUFFERABLE,
		.pte_s2		= s2_policy(L_PTE_S2_MT_UNCACHED),
	}, {
		.policy		= "writethrough",
		.cr_mask	= 0,
		.pmd		= PMD_SECT_WT,
		.pte		= L_PTE_MT_WRITETHROUGH,
		.pte_s2		= s2_policy(L_PTE_S2_MT_WRITETHROUGH),
	}, {
		.policy		= "writeback",
		.cr_mask	= 0,
		.pmd		= PMD_SECT_WB,
		.pte		= L_PTE_MT_WRITEBACK,
		.pte_s2		= s2_policy(L_PTE_S2_MT_WRITEBACK),
	}, {
		.policy		= "writealloc",
		.cr_mask	= 0,
// ARM10C 20131102
// PMD_SECT_WBWA: (PMD_SECT_TEX(1) | PMD_SECT_CACHEABLE | PMD_SECT_BUFFERABLE)
		.pmd		= PMD_SECT_WBWA,
		.pte		= L_PTE_MT_WRITEALLOC,
		.pte_s2		= s2_policy(L_PTE_S2_MT_WRITEBACK),
	}
};

#ifdef CONFIG_CPU_CP15
/*
 * These are useful for identifying cache coherency
 * problems by allowing the cache or the cache and
 * writebuffer to be turned off.  (Note: the write
 * buffer should not be on and the cache off).
 */
static int __init early_cachepolicy(char *p)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cache_policies); i++) {
		int len = strlen(cache_policies[i].policy);

		if (memcmp(p, cache_policies[i].policy, len) == 0) {
			cachepolicy = i;
			cr_alignment &= ~cache_policies[i].cr_mask;
			cr_no_alignment &= ~cache_policies[i].cr_mask;
			break;
		}
	}
	if (i == ARRAY_SIZE(cache_policies))
		printk(KERN_ERR "ERROR: unknown or unsupported cache policy\n");
	/*
	 * This restriction is partly to do with the way we boot; it is
	 * unpredictable to have memory mapped using two different sets of
	 * memory attributes (shared, type, and cache attribs).  We can not
	 * change these attributes once the initial assembly has setup the
	 * page tables.
	 */
	if (cpu_architecture() >= CPU_ARCH_ARMv6) {
		printk(KERN_WARNING "Only cachepolicy=writeback supported on ARMv6 and later\n");
		cachepolicy = CPOLICY_WRITEBACK;
	}
	flush_cache_all();
	set_cr(cr_alignment);
	return 0;
}
early_param("cachepolicy", early_cachepolicy);

static int __init early_nocache(char *__unused)
{
	char *p = "buffered";
	printk(KERN_WARNING "nocache is deprecated; use cachepolicy=%s\n", p);
	early_cachepolicy(p);
	return 0;
}
early_param("nocache", early_nocache);

static int __init early_nowrite(char *__unused)
{
	char *p = "uncached";
	printk(KERN_WARNING "nowb is deprecated; use cachepolicy=%s\n", p);
	early_cachepolicy(p);
	return 0;
}
early_param("nowb", early_nowrite);

#ifndef CONFIG_ARM_LPAE
static int __init early_ecc(char *p)
{
	if (memcmp(p, "on", 2) == 0)
		ecc_mask = PMD_PROTECTION;
	else if (memcmp(p, "off", 3) == 0)
		ecc_mask = 0;
	return 0;
}
early_param("ecc", early_ecc);
#endif

static int __init noalign_setup(char *__unused)
{
	cr_alignment &= ~CR_A;
	cr_no_alignment &= ~CR_A;
	set_cr(cr_alignment);
	return 1;
}
__setup("noalign", noalign_setup);

#ifndef CONFIG_SMP
void adjust_cr(unsigned long mask, unsigned long set)
{
	unsigned long flags;

	mask &= ~CR_A;

	set &= mask;

	local_irq_save(flags);

	cr_no_alignment = (cr_no_alignment & ~mask) | set;
	cr_alignment = (cr_alignment & ~mask) | set;

	set_cr((get_cr() & ~mask) | set);

	local_irq_restore(flags);
}
#endif

#else /* ifdef CONFIG_CPU_CP15 */

static int __init early_cachepolicy(char *p)
{
	pr_warning("cachepolicy kernel parameter not supported without cp15\n");
}
early_param("cachepolicy", early_cachepolicy);

static int __init noalign_setup(char *__unused)
{
	pr_warning("noalign kernel parameter not supported without cp15\n");
}
__setup("noalign", noalign_setup);

#endif /* ifdef CONFIG_CPU_CP15 / else */

// ARM10C 20141025
// L_PTE_PRESENT: 0x1
// L_PTE_YOUNG: 0x2
// L_PTE_DIRTY: 0x40
// L_PTE_XN: 0x200
// PROT_PTE_DEVICE: 0x243
#define PROT_PTE_DEVICE		L_PTE_PRESENT|L_PTE_YOUNG|L_PTE_DIRTY|L_PTE_XN
#define PROT_PTE_S2_DEVICE	PROT_PTE_DEVICE
#define PROT_SECT_DEVICE	PMD_TYPE_SECT|PMD_SECT_AP_WRITE

// ARM10C 20131026
// ARM10C 20141018
// ARM10C 20141025
static struct mem_type mem_types[] = {
	[MT_DEVICE] = {		  /* Strongly ordered / ARMv6 shared device */
		// PROT_PTE_DEVICE: 0x243, L_PTE_MT_DEV_SHARED: 0x10, L_PTE_SHARED: 0x400
		.prot_pte	= PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED |
				  L_PTE_SHARED,
		.prot_pte_s2	= s2_policy(PROT_PTE_S2_DEVICE) |
				  s2_policy(L_PTE_S2_MT_DEV_SHARED) |
				  L_PTE_SHARED,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PROT_SECT_DEVICE | PMD_SECT_S,
		.domain		= DOMAIN_IO,
	},
	[MT_DEVICE_NONSHARED] = { /* ARMv6 non-shared device */
		.prot_pte	= PROT_PTE_DEVICE | L_PTE_MT_DEV_NONSHARED,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PROT_SECT_DEVICE,
		.domain		= DOMAIN_IO,
	},
	[MT_DEVICE_CACHED] = {	  /* ioremap_cached */
		.prot_pte	= PROT_PTE_DEVICE | L_PTE_MT_DEV_CACHED,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PROT_SECT_DEVICE | PMD_SECT_WB,
		.domain		= DOMAIN_IO,
	},
	// 쓰기 버퍼 및 cache 미사용 device
	[MT_DEVICE_WC] = {	/* ioremap_wc */
		.prot_pte	= PROT_PTE_DEVICE | L_PTE_MT_DEV_WC,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PROT_SECT_DEVICE,
		.domain		= DOMAIN_IO,
	},
	[MT_UNCACHED] = {
		.prot_pte	= PROT_PTE_DEVICE,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PMD_TYPE_SECT | PMD_SECT_XN,
		.domain		= DOMAIN_IO,
	},
	[MT_CACHECLEAN] = {
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_XN,
		.domain    = DOMAIN_KERNEL,
	},
#ifndef CONFIG_ARM_LPAE // CONFIG_ARM_LPAE=n
	[MT_MINICLEAN] = {
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_XN | PMD_SECT_MINICACHE,
		.domain    = DOMAIN_KERNEL,
	},
#endif
	[MT_LOW_VECTORS] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_RDONLY,
		.prot_l1   = PMD_TYPE_TABLE,
		.domain    = DOMAIN_USER,
	},
	[MT_HIGH_VECTORS] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_USER | L_PTE_RDONLY,
		.prot_l1   = PMD_TYPE_TABLE,
		.domain    = DOMAIN_USER,
	},
	[MT_MEMORY] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY,
		.prot_l1   = PMD_TYPE_TABLE,
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_AP_WRITE,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_ROM] = {
		.prot_sect = PMD_TYPE_SECT,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_NONCACHED] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_MT_BUFFERABLE,
		.prot_l1   = PMD_TYPE_TABLE,
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_AP_WRITE,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_DTCM] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_XN,
		.prot_l1   = PMD_TYPE_TABLE,
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_XN,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_ITCM] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY,
		.prot_l1   = PMD_TYPE_TABLE,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_SO] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_MT_UNCACHED | L_PTE_XN,
		.prot_l1   = PMD_TYPE_TABLE,
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_AP_WRITE | PMD_SECT_S |
				PMD_SECT_UNCACHED | PMD_SECT_XN,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_DMA_READY] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY,
		.prot_l1   = PMD_TYPE_TABLE,
		.domain    = DOMAIN_KERNEL,
	},
};

// ARM10C 20141018
// mtype: MT_DEVICE: 0
const struct mem_type *get_mem_type(unsigned int type)
{
	// type: MT_DEVICE: 0, ARRAY_SIZE(mem_types): 16
	return type < ARRAY_SIZE(mem_types) ? &mem_types[type] : NULL;
	// return &mem_types[0]
}
EXPORT_SYMBOL(get_mem_type);

/*
 * Adjust the PMD section entries according to the CPU in use.
 */
// ARM10C 20131026
static void __init build_mem_type_table(void)
{
	struct cachepolicy *cp;
	unsigned int cr = get_cr(); // cr = system control register.
	pteval_t user_pgprot, kern_pgprot, vecs_pgprot;
	pteval_t hyp_device_pgprot, s2_pgprot, s2_device_pgprot;
	// cpu_arch: CPU_ARCH_ARMv7: 9
	int cpu_arch = cpu_architecture();
	int i;

	if (cpu_arch < CPU_ARCH_ARMv6) {
#if defined(CONFIG_CPU_DCACHE_DISABLE) // CONFIG_CPU_DCACHE_DISABLE=n
		if (cachepolicy > CPOLICY_BUFFERED)
			cachepolicy = CPOLICY_BUFFERED;
#elif defined(CONFIG_CPU_DCACHE_WRITETHROUGH) // CONFIG_CPU_DCACHE_WRITETHROUGH=n
		if (cachepolicy > CPOLICY_WRITETHROUGH)
			cachepolicy = CPOLICY_WRITETHROUGH;
#endif
	}
	if (cpu_arch < CPU_ARCH_ARMv5) {
		if (cachepolicy >= CPOLICY_WRITEALLOC)
			cachepolicy = CPOLICY_WRITEBACK;
		ecc_mask = 0;
	}
	if (is_smp())
		// CPOLICY_WRITEALLOC: 4
		cachepolicy = CPOLICY_WRITEALLOC;

	/*
	 * Strip out features not present on earlier architectures.
	 * Pre-ARMv5 CPUs don't have TEX bits.  Pre-ARMv6 CPUs or those
	 * without extended page tables don't have the 'Shared' bit.
	 */
	if (cpu_arch < CPU_ARCH_ARMv5)
		for (i = 0; i < ARRAY_SIZE(mem_types); i++)
			mem_types[i].prot_sect &= ~PMD_SECT_TEX(7);

    // CR_XP는 reserved 되어 있어서 for에 안들어 감.
	if ((cpu_arch < CPU_ARCH_ARMv6 || !(cr & CR_XP)) && !cpu_is_xsc3())
		for (i = 0; i < ARRAY_SIZE(mem_types); i++)
			mem_types[i].prot_sect &= ~PMD_SECT_S;

	/*
	 * ARMv5 and lower, bit 4 must be set for page tables (was: cache
	 * "update-able on write" bit on ARM610).  However, Xscale and
	 * Xscale3 require this bit to be cleared.
	 */
	if (cpu_is_xscale() || cpu_is_xsc3()) {
		for (i = 0; i < ARRAY_SIZE(mem_types); i++) {
			mem_types[i].prot_sect &= ~PMD_BIT4;
			mem_types[i].prot_l1 &= ~PMD_BIT4;
		}
	} else if (cpu_arch < CPU_ARCH_ARMv6) {
		for (i = 0; i < ARRAY_SIZE(mem_types); i++) {
			if (mem_types[i].prot_l1)
				mem_types[i].prot_l1 |= PMD_BIT4;
			if (mem_types[i].prot_sect)
				mem_types[i].prot_sect |= PMD_BIT4;
		}
	}

	/*
	 * Mark the device areas according to the CPU/architecture.
	 */
	// CR_XP: (1 << 23) - Extended page tables
	// A.R.M: B4.1.130 - SCTLR, System Control Register, VMSA
	// (cr & CR_XP): 1
	// v7_crval:
	//	.word 0x2120c302  (r5) (clear)
	//	.word 0x10c03c7d  (r6) (mmuset)
	if (cpu_is_xsc3() || (cpu_arch >= CPU_ARCH_ARMv6 && (cr & CR_XP))) {
		if (!cpu_is_xsc3()) {
			/*
			 * Mark device regions on ARMv6+ as execute-never
			 * to prevent speculative instruction fetches.
			 */
			// XN: execute-never
			mem_types[MT_DEVICE].prot_sect |= PMD_SECT_XN;
			mem_types[MT_DEVICE_NONSHARED].prot_sect |= PMD_SECT_XN;
			mem_types[MT_DEVICE_CACHED].prot_sect |= PMD_SECT_XN;
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_XN;
		}

		// CR_TRE: (1 << 28) - TEX remap enable
		if (cpu_arch >= CPU_ARCH_ARMv7 && (cr & CR_TRE)) {
			/*
			 * For ARMv7 with TEX remapping,
			 * - shared device is SXCB=1100
			 * - nonshared device is SXCB=0100
			 * - write combine device mem is SXCB=0001
			 * (Uncached Normal memory)
			 */
			// SXCB: S - shared, X - TEX[0], C - cachable, B - bufferable
		    // PMD_SECT_TEX(x) (_AT(pmdval_t, (x)) << 12)
			mem_types[MT_DEVICE].prot_sect |= PMD_SECT_TEX(1);
			mem_types[MT_DEVICE_NONSHARED].prot_sect |= PMD_SECT_TEX(1);
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_BUFFERABLE;
		} else if (cpu_is_xsc3()) {
			/*
			 * For Xscale3,
			 * - shared device is TEXCB=00101
			 * - nonshared device is TEXCB=01000
			 * - write combine device mem is TEXCB=00100
			 * (Inner/Outer Uncacheable in xsc3 parlance)
			 */
			mem_types[MT_DEVICE].prot_sect |= PMD_SECT_TEX(1) | PMD_SECT_BUFFERED;
			mem_types[MT_DEVICE_NONSHARED].prot_sect |= PMD_SECT_TEX(2);
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_TEX(1);
		} else {
			/*
			 * For ARMv6 and ARMv7 without TEX remapping,
			 * - shared device is TEXCB=00001
			 * - nonshared device is TEXCB=01000
			 * - write combine device mem is TEXCB=00100
			 * (Uncached Normal in ARMv6 parlance).
			 */
			mem_types[MT_DEVICE].prot_sect |= PMD_SECT_BUFFERED;
			mem_types[MT_DEVICE_NONSHARED].prot_sect |= PMD_SECT_TEX(2);
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_TEX(1);
		}
	} else {
		/*
		 * On others, write combining is "Uncached/Buffered"
		 */
		mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_BUFFERABLE;
	}

	/*
	 * Now deal with the memory-type mappings
	 */
	// cachepolicy: 4 - CPOLICY_WRITEALLOC
	cp = &cache_policies[cachepolicy];
	// cp->pte: L_PTE_MT_WRITEALLOC
	vecs_pgprot = kern_pgprot = user_pgprot = cp->pte;
	// cp->pte_s2: 0 - s2_policy(L_PTE_S2_MT_WRITEBACK)
	s2_pgprot = cp->pte_s2;
	// mem_types[MT_DEVICE].prot_pte: PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED,
	hyp_device_pgprot = mem_types[MT_DEVICE].prot_pte;
	s2_device_pgprot = mem_types[MT_DEVICE].prot_pte_s2;

	/*
	 * ARMv6 and above have extended page tables.
	 */
	if (cpu_arch >= CPU_ARCH_ARMv6 && (cr & CR_XP)) {
#ifndef CONFIG_ARM_LPAE // CONFIG_ARM_LPAE=n
		/*
		 * Mark cache clean areas and XIP ROM read only
		 * from SVC mode and no access from userspace.
		 */
		// A.R.M: B3.7 Memory access control
		// PMD_SECT_APX - Access permission
		mem_types[MT_ROM].prot_sect |= PMD_SECT_APX|PMD_SECT_AP_WRITE;
		mem_types[MT_MINICLEAN].prot_sect |= PMD_SECT_APX|PMD_SECT_AP_WRITE;
		mem_types[MT_CACHECLEAN].prot_sect |= PMD_SECT_APX|PMD_SECT_AP_WRITE;
#endif

		if (is_smp()) {
			/*
			 * Mark memory with the "shared" attribute
			 * for SMP systems
			 */
			// L_PTE_SHARED, PMD_SECT_S 설정
			user_pgprot |= L_PTE_SHARED;
			kern_pgprot |= L_PTE_SHARED;
			vecs_pgprot |= L_PTE_SHARED;
			s2_pgprot |= L_PTE_SHARED;
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_S;
			mem_types[MT_DEVICE_WC].prot_pte |= L_PTE_SHARED;
			mem_types[MT_DEVICE_CACHED].prot_sect |= PMD_SECT_S;
			mem_types[MT_DEVICE_CACHED].prot_pte |= L_PTE_SHARED;
			mem_types[MT_MEMORY].prot_sect |= PMD_SECT_S;
			mem_types[MT_MEMORY].prot_pte |= L_PTE_SHARED;
			mem_types[MT_MEMORY_DMA_READY].prot_pte |= L_PTE_SHARED;
			mem_types[MT_MEMORY_NONCACHED].prot_sect |= PMD_SECT_S;
			mem_types[MT_MEMORY_NONCACHED].prot_pte |= L_PTE_SHARED;
		}
	}

	/*
	 * Non-cacheable Normal - intended for memory areas that must
	 * not cause dirty cache line writebacks when used
	 */
	if (cpu_arch >= CPU_ARCH_ARMv6) {
		// CR_TRE: (1 << 28) - TEX remap enable
		if (cpu_arch >= CPU_ARCH_ARMv7 && (cr & CR_TRE)) {
			/* Non-cacheable Normal is XCB = 001 */
			mem_types[MT_MEMORY_NONCACHED].prot_sect |=
				PMD_SECT_BUFFERED;
		} else {
			/* For both ARMv6 and non-TEX-remapping ARMv7 */
			mem_types[MT_MEMORY_NONCACHED].prot_sect |=
				PMD_SECT_TEX(1);
		}
	} else {
		mem_types[MT_MEMORY_NONCACHED].prot_sect |= PMD_SECT_BUFFERABLE;
	}

#ifdef CONFIG_ARM_LPAE // CONFIG_ARM_LPAE=n
	/*
	 * Do not generate access flag faults for the kernel mappings.
	 */
	for (i = 0; i < ARRAY_SIZE(mem_types); i++) {
		mem_types[i].prot_pte |= PTE_EXT_AF;
		if (mem_types[i].prot_sect)
			mem_types[i].prot_sect |= PMD_SECT_AF;
	}
	kern_pgprot |= PTE_EXT_AF;
	vecs_pgprot |= PTE_EXT_AF;
#endif

	// user page protection 설정값 추가
	for (i = 0; i < 16; i++) {
		pteval_t v = pgprot_val(protection_map[i]);
		protection_map[i] = __pgprot(v | user_pgprot);
	}

// 2013/10/26 종료
// 2013/11/02 시작
	// vecs_pgprot: L_PTE_MT_WRITEALLOC | L_PTE_SHARED;
	mem_types[MT_LOW_VECTORS].prot_pte |= vecs_pgprot;
	mem_types[MT_HIGH_VECTORS].prot_pte |= vecs_pgprot;

	// user_pgprot: L_PTE_MT_WRITEALLOC | L_PTE_SHARED
	pgprot_user   = __pgprot(L_PTE_PRESENT | L_PTE_YOUNG | user_pgprot);
	// kern_pgprot: L_PTE_MT_WRITEALLOC | L_PTE_SHARED
	pgprot_kernel = __pgprot(L_PTE_PRESENT | L_PTE_YOUNG |
				 L_PTE_DIRTY | kern_pgprot);

	// s2_pgprot: L_PTE_SHARED
	pgprot_s2  = __pgprot(L_PTE_PRESENT | L_PTE_YOUNG | s2_pgprot);
	// s2_device_pgprot: PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED,
	pgprot_s2_device  = __pgprot(s2_device_pgprot);
	// hyp_device_pgprot: PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED,
	pgprot_hyp_device  = __pgprot(hyp_device_pgprot);

	// ecc_mask: 0
	mem_types[MT_LOW_VECTORS].prot_l1 |= ecc_mask;
	mem_types[MT_HIGH_VECTORS].prot_l1 |= ecc_mask;
	// cp->pmd: PMD_SECT_WBWA: (PMD_SECT_TEX(1) | PMD_SECT_CACHEABLE | PMD_SECT_BUFFERABLE)
	mem_types[MT_MEMORY].prot_sect |= ecc_mask | cp->pmd;
	// kern_pgprot: L_PTE_MT_WRITEALLOC | L_PTE_SHARED
	mem_types[MT_MEMORY].prot_pte |= kern_pgprot;
	mem_types[MT_MEMORY_DMA_READY].prot_pte |= kern_pgprot;
	mem_types[MT_MEMORY_NONCACHED].prot_sect |= ecc_mask;
	mem_types[MT_ROM].prot_sect |= cp->pmd;

	// cp->pmd: PMD_SECT_WBWA
	switch (cp->pmd) {
	case PMD_SECT_WT:
		mem_types[MT_CACHECLEAN].prot_sect |= PMD_SECT_WT;
		break;
	case PMD_SECT_WB:
	case PMD_SECT_WBWA:
		mem_types[MT_CACHECLEAN].prot_sect |= PMD_SECT_WB;
		break;
	}

	//  ecc_mask: 0, cp->palicy: "writealloc"
	pr_info("Memory policy: %sData cache %s\n",
		ecc_mask ? "ECC enabled, " : "", cp->policy);

	// ARRAY_SIZE: 15
	for (i = 0; i < ARRAY_SIZE(mem_types); i++) {
		struct mem_type *t = &mem_types[i];
		if (t->prot_l1)
			t->prot_l1 |= PMD_DOMAIN(t->domain);
		if (t->prot_sect)
			t->prot_sect |= PMD_DOMAIN(t->domain);
	}
}

#ifdef CONFIG_ARM_DMA_MEM_BUFFERABLE
pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
			      unsigned long size, pgprot_t vma_prot)
{
	if (!pfn_valid(pfn))
		return pgprot_noncached(vma_prot);
	else if (file->f_flags & O_SYNC)
		return pgprot_writecombine(vma_prot);
	return vma_prot;
}
EXPORT_SYMBOL(phys_mem_access_prot);
#endif

// ARM10C 20131102
// vectors_base(): 0xffff0000
#define vectors_base()	(vectors_high() ? 0xffff0000 : 0)

// ARM10C 20131109
// ARM10C 20131116
// sz: 0x00002000, sz: 0x00002000
// ARM10C 20131123
// sz: 0x00001000, sz: 0x00001000
static void __init *early_alloc_aligned(unsigned long sz, unsigned long align)
{
	// sz: 0x00002000, align: 0x00002000
	// memblock_alloc(sz, align): 0x4F7FE000
	// ptr: __va(0x4F7FE000): 0xEF7FE000
	//
	// sz: 0x00001000, sz: 0x00001000
	// memblock_alloc(sz, align): 0x4F7FD000
	// ptr: __va(0x4F7FD000): 0xEF7FD000
	void *ptr = __va(memblock_alloc(sz, align));
	memset(ptr, 0, sz);
	return ptr;
}

// ARM10C 20131123
// PTE_HWTABLE_OFF + PTE_HWTABLE_SIZE: 4096
static void __init *early_alloc(unsigned long sz)
{
	return early_alloc_aligned(sz, sz);
}

// ARM10C 20131123
// pmd: 0xc0007FF8, addr: 0xffff0000
static pte_t * __init early_pte_alloc(pmd_t *pmd, unsigned long addr, unsigned long prot)
{
	// pmd: 0xc0007FF8, pmd_none(*pmd): 0
	if (pmd_none(*pmd)) {
		// PTE_HWTABLE_OFF: 2048, PTE_HWTABLE_SIZE: 2048
		// pte: 0xEF7FD000
		// 2차 table에서 사용할 공간 할당받음.
		pte_t *pte = early_alloc(PTE_HWTABLE_OFF + PTE_HWTABLE_SIZE);
		// pmd: 0xc0007FF8, __pa(pte): 0x4F7FD000,
		// 1차 table 내에 할당받은 2차 table 시작 주소 매핑 
		__pmd_populate(pmd, __pa(pte), prot);
	}
	// pmd_bad(*pmd): 0
	BUG_ON(pmd_bad(*pmd));

	// __pmd_populate에서 pmd 값을 바꿈
	// pmd: 0x6F7FD8XX, addr: 0xffff0000
	// pte_offset_kernel(0x4F7FD8XX, 0xffff0000): 0xEF7FD1F0
	return pte_offset_kernel(pmd, addr);
}

// ARM10C 20131123
// pmd: 0xc0007FF8, addr: 0xffff0000, next: 0xffff1000, __phys_to_pfn(phys): 0x4F7FE
static void __init alloc_init_pte(pmd_t *pmd, unsigned long addr,
				  unsigned long end, unsigned long pfn,
				  const struct mem_type *type)
{
	// pmd: 0xc0007FF8, addr: 0xffff0000
	// pte: 0xEF7FD1F0
	pte_t *pte = early_pte_alloc(pmd, addr, type->prot_l1);
	do {
		// pte: 0xEF7FD1F0, pfn: 0x4F7FE
		// pfn_pte(0x4F7FE, __pgprot(type->prot_pte)): 0x4F7FEXXX
		set_pte_ext(pte, pfn_pte(pfn, __pgprot(type->prot_pte)), 0);
		pfn++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
}

// ARM10C 20131109
// pmd: 0xc0007000, addr: 0xC0000000, next: 0xC0200000, phys: 0x20000000
static void __init __map_init_section(pmd_t *pmd, unsigned long addr,
			unsigned long end, phys_addr_t phys,
			const struct mem_type *type)
{
	// p: 0xc0007000
	pmd_t *p = pmd;

#ifndef CONFIG_ARM_LPAE // CONFIG_ARM_LPAE=n
	/*
	 * In classic MMU format, puds and pmds are folded in to
	 * the pgds. pmd_offset gives the PGD entry. PGDs refer to a
	 * group of L1 entries making up one logical pointer to
	 * an L2 table (2MB), where as PMDs refer to the individual
	 * L1 entries (1MB). Hence increment to get the correct
	 * offset for odd 1MB sections.
	 * (See arch/arm/include/asm/pgtable-2level.h)
	 */
	// addr: 0xC0000000, SECTION_SIZE: 0x00100000
	if (addr & SECTION_SIZE)
		pmd++;
#endif
	do {
		// phys: 0x20000000, type->prot_sect: 미리 넣어준 값들.
		// *pmd: 0xc0007000 <- (phys | type->prot_sect)을 넣어줌
		*pmd = __pmd(phys | type->prot_sect);

		// phys: 0x20000000
		phys += SECTION_SIZE;
	} while (pmd++, addr += SECTION_SIZE, addr != end);

	// p: 0xc0007000
	flush_pmd_entry(p);
}

// ARM10C 20131109
// pud: 0xc0007000, addr: 0xC0000000, next: 0xC0200000, phys: 0x20000000
// ARM10C 20131123
// pud: 0xc0007FF8, addr: 0xffff0000, next: 0xffff1000, phys: 0x4F7FE000
static void __init alloc_init_pmd(pud_t *pud, unsigned long addr,
				      unsigned long end, phys_addr_t phys,
				      const struct mem_type *type)
{
	// pmd: 0xc0007000
	// pmd: 0xc0007FF8
	pmd_t *pmd = pmd_offset(pud, addr);
	unsigned long next;

	do {
		/*
		 * With LPAE, we must loop over to map
		 * all the pmds for the given range.
		 */
		// next: 0xC0200000
		// next: 0xffff1000
		next = pmd_addr_end(addr, end);

		/*
		 * Try a section mapping - addr, next and phys must all be
		 * aligned to a section boundary.
		 */
		// addr: 0xC0000000, next: 0xC0200000, phys: 0x20000000
		// addr: 0xffff0000, next: 0xffff1000, phys: 0x4F7FE000
		// SECTION_MASK: 0xFFF00000, ~SECTION_MASK: 0x000FFFFF
		if (type->prot_sect &&
				((addr | next | phys) & ~SECTION_MASK) == 0) {
			// pmd: 0xc0007000, addr: 0xC0000000, next: 0xC0200000, phys: 0x20000000
			__map_init_section(pmd, addr, next, phys, type);
		} else {
			// pmd: 0xc0007FF8, addr: 0xffff0000, next: 0xffff1000, __phys_to_pfn(phys): 0x4F7FE
			alloc_init_pte(pmd, addr, next,
						__phys_to_pfn(phys), type);
		}

		// addr: 0xC0000000, next: 0xC0200000, phys: 0x20000000
		// phys: 0x20000000 + 200000
		phys += next - addr;

	} while (pmd++, addr = next, addr != end);
}

// ARM10C 20131109
// pgd: 0xc0007000, addr: 0xC0000000, next: 0xC0200000, phys: 0x20000000
// ARM10C 20131123
// pgd: 0xc0007FF8, addr: 0xffff0000, next: 0xffff1000, phys: 0x4F7FE000
static void __init alloc_init_pud(pgd_t *pgd, unsigned long addr,
				  unsigned long end, phys_addr_t phys,
				  const struct mem_type *type)
{
	// pud: 0xc0007000
	// pud: 0xc0007FF8
	pud_t *pud = pud_offset(pgd, addr);
	unsigned long next;

	do {
		// addr: 0xC0000000, end: 0xC0200000, next: 0xC0200000
		// addr: 0xffff0000, end: 0xffff1000, next: 0xffff1000
		next = pud_addr_end(addr, end);
		// pud: 0xc0007000, addr: 0xC0000000, next: 0xC0200000, phys: 0x20000000
		// pud: 0xc0007FF8, addr: 0xffff0000, next: 0xffff1000, phys: 0x4F7FE000
		alloc_init_pmd(pud, addr, next, phys, type);
		// phys: 0x20000000 + 0x200000
		// phys: 0x4F7FE000 + 0x1000
		phys += next - addr;
	} while (pud++, addr = next, addr != end);
}

#ifndef CONFIG_ARM_LPAE
static void __init create_36bit_mapping(struct map_desc *md,
					const struct mem_type *type)
{
	unsigned long addr, length, end;
	phys_addr_t phys;
	pgd_t *pgd;

	addr = md->virtual;
	phys = __pfn_to_phys(md->pfn);
	length = PAGE_ALIGN(md->length);

	if (!(cpu_architecture() >= CPU_ARCH_ARMv6 || cpu_is_xsc3())) {
		printk(KERN_ERR "MM: CPU does not support supersection "
		       "mapping for 0x%08llx at 0x%08lx\n",
		       (long long)__pfn_to_phys((u64)md->pfn), addr);
		return;
	}

	/* N.B.	ARMv6 supersections are only defined to work with domain 0.
	 *	Since domain assignments can in fact be arbitrary, the
	 *	'domain == 0' check below is required to insure that ARMv6
	 *	supersections are only allocated for domain 0 regardless
	 *	of the actual domain assignments in use.
	 */
	if (type->domain) {
		printk(KERN_ERR "MM: invalid domain in supersection "
		       "mapping for 0x%08llx at 0x%08lx\n",
		       (long long)__pfn_to_phys((u64)md->pfn), addr);
		return;
	}

	if ((addr | length | __pfn_to_phys(md->pfn)) & ~SUPERSECTION_MASK) {
		printk(KERN_ERR "MM: cannot create mapping for 0x%08llx"
		       " at 0x%08lx invalid alignment\n",
		       (long long)__pfn_to_phys((u64)md->pfn), addr);
		return;
	}

	/*
	 * Shift bits [35:32] of address into bits [23:20] of PMD
	 * (See ARMv6 spec).
	 */
	phys |= (((md->pfn >> (32 - PAGE_SHIFT)) & 0xF) << 20);

	pgd = pgd_offset_k(addr);
	end = addr + length;
	do {
		pud_t *pud = pud_offset(pgd, addr);
		pmd_t *pmd = pmd_offset(pud, addr);
		int i;

		for (i = 0; i < 16; i++)
			*pmd++ = __pmd(phys | type->prot_sect | PMD_SECT_SUPER);

		addr += SUPERSECTION_SIZE;
		phys += SUPERSECTION_SIZE;
		pgd += SUPERSECTION_SIZE >> PGDIR_SHIFT;
	} while (addr != end);
}
#endif	/* !CONFIG_ARM_LPAE */

/*
 * Create the page directory entries and any necessary
 * page tables for the mapping specified by `md'.  We
 * are able to cope here with varying sizes and address
 * offsets, and we take full advantage of sections and
 * supersections.
 */
// ARM10C 20131102
// map.pfn: 0x20000
// map.virtual: 0xC0000000
// map.length: 0x2f800000
// map.type: MT_MEMORY

// ARM10C 20131123
// map.pfn: 0x4F7FE
// map.virtual: 0xffff0000;
// map.length: 0x1000, PAGE_SIZE: 0x1000
// map.type = MT_HIGH_VECTORS;
static void __init create_mapping(struct map_desc *md)
{
	unsigned long addr, length, end;
	phys_addr_t phys;
	const struct mem_type *type;
	pgd_t *pgd;

	// md->virtual: 0xC0000000, vectors_base(): 0xffff0000, TASK_SIZE: 0xBF000000
	// md->virtual: 0xffff0000, vectors_base(): 0xffff0000, TASK_SIZE: 0xBF000000
	if (md->virtual != vectors_base() && md->virtual < TASK_SIZE) {
		printk(KERN_WARNING "BUG: not creating mapping for 0x%08llx"
		       " at 0x%08lx in user region\n",
		       (long long)__pfn_to_phys((u64)md->pfn), md->virtual);
		return;
	}

	if ((md->type == MT_DEVICE || md->type == MT_ROM) &&
	    md->virtual >= PAGE_OFFSET &&
	    (md->virtual < VMALLOC_START || md->virtual >= VMALLOC_END)) {
		printk(KERN_WARNING "BUG: mapping for 0x%08llx"
		       " at 0x%08lx out of vmalloc space\n",
		       (long long)__pfn_to_phys((u64)md->pfn), md->virtual);
	}

	type = &mem_types[md->type];

#ifndef CONFIG_ARM_LPAE // CONFIG_ARM_LPAE=n
	/*
	 * Catch 36-bit addresses
	 */
	// md->pfn: 0x20000
	// map.pfn: 0x4F7FE
	if (md->pfn >= 0x100000) {
		create_36bit_mapping(md, type);
		return;
	}
#endif

	// md.virtual: 0xC0000000, PAGE_MASK: 0xFFFFF000, addr: 0xC0000000
	// md.virtual: 0xffff0000, PAGE_MASK: 0xFFFFF000, addr: 0xffff0000
	addr = md->virtual & PAGE_MASK;
	// md->pfn: 0x20000, phys: 0x20000000
	// md->pfn: 0x4F7FE, phys: 0x4F7FE000
	phys = __pfn_to_phys(md->pfn);
	// md.length: 0x2f800000, length: 0x2f800000
	// md.length: 0x1000, length: 0x1000
	length = PAGE_ALIGN(md->length + (md->virtual & ~PAGE_MASK));

	// addr: 0xC0000000, phys: 0x20000000, length: 0x2f800000
	// addr: 0xffff0000, phys: 0x4F7FE000, length: 0x1000
	if (type->prot_l1 == 0 && ((addr | phys | length) & ~SECTION_MASK)) {
		printk(KERN_WARNING "BUG: map for 0x%08llx at 0x%08lx can not "
		       "be mapped using pages, ignoring.\n",
		       (long long)__pfn_to_phys(md->pfn), addr);
		return;
	}
	// (*8)을 하는 이유? 
	// typedef struct { pmdval_t pgd[2]; } pgd_t; 로 선언되어 pmdval_t이 4byte,
	// 그래서 주소 계산시 8byte 곱해준다.
	// addr: 0xC0000000, pgd: 0xc0004000 + 0x600 * 8
	// addr: 0xffff0000, pgd: 0xc0004000 + 0x7FF * 8
	pgd = pgd_offset_k(addr);

	// end: 0xC0000000 + 0x2f800000: 0xef800000
	// end: 0xffff0000 + 0x1000: 0xffff1000
	end = addr + length;
	do {
		// addr: 0xC0000000, end: 0xef800000, next: 0xC0200000
		// addr: 0xffff0000, end: 0xffff1000, next: 0xffff1000
		unsigned long next = pgd_addr_end(addr, end);

		// pgd: 0xc0007000, addr: 0xC0000000, next: 0xC0200000, phys: 0x20000000
		// pgd: 0xc0007FF8, addr: 0xffff0000, next: 0xffff1000, phys: 0x4F7FE000
		alloc_init_pud(pgd, addr, next, phys, type);

		// phys: 0x20000000 + 0x200000
		// phys: 0x4F7FE000 + 0x1000
		phys += next - addr;
		// addr: 0xC0200000
		// addr: 0xffff1000
		addr = next;
	} while (pgd++, addr != end);
}

/*
 * Create the architecture specific mappings
 */
// ARM10C 20131116
// iodesc.pfn: 0x10000
// iodesc.length: 0xFF
// iodesc.virtual: 0xF8000000
// iodesc.type = MT_DEVICE;
// nr: 1
//
// S3C_VA_SYS
// iodesc.pfn: __phys_to_pfn(EXYNOS5_PA_SYSCON): 0x10050
// iodesc.length: SZ_64K: 0x10000
// iodesc.virtual: S3C_VA_SYS : 0xF6100000
// iodesc.type = MT_DEVICE;
void __init iotable_init(struct map_desc *io_desc, int nr)
{
	struct map_desc *md;
	struct vm_struct *vm;
	struct static_vm *svm;

	if (!nr)
		return;

	// svm 크기만큼 가상 메모리 공간 확보
	svm = early_alloc_aligned(sizeof(*svm) * nr, __alignof__(*svm));

	for (md = io_desc; nr; md++, nr--) {
// 2013/11/23 종료
// 2013/11/30 시작
		// io 영역을 highmem에 mapping 함
		create_mapping(md);

		vm = &svm->vm;
		// md->virtual: 0xF8000000,  PAGE_MASK: 0xFFFFF000, vm->addr: 0xF8000000
		// md->virtual: 0xF6100000,  PAGE_MASK: 0xFFFFF000, vm->addr: 0xF6100000
		vm->addr = (void *)(md->virtual & PAGE_MASK);
		// md->length: 0xFF, vm->size: 0x1000
		// md->length: 0x10000, vm->size: 0x10000
		vm->size = PAGE_ALIGN(md->length + (md->virtual & ~PAGE_MASK));
		// md->pfn: 0x10000, vm->phys_addr: 0x10000000
		// md->pfn: 0x10050, vm->phys_addr: 0x10050000
		vm->phys_addr = __pfn_to_phys(md->pfn);
		// VM_IOREMAP: 0x00000001, VM_ARM_STATIC_MAPPING: 0x40000000, vm->flags: 0x40000001
		// VM_IOREMAP: 0x00000001, VM_ARM_STATIC_MAPPING: 0x40000000, vm->flags: 0x40000001
		vm->flags = VM_IOREMAP | VM_ARM_STATIC_MAPPING;
		// md->type = MT_DEVICE, VM_ARM_MTYPE(md->type): 0x0
		// md->type = MT_DEVICE, VM_ARM_MTYPE(md->type): 0x0
		vm->flags |= VM_ARM_MTYPE(md->type);
		vm->caller = iotable_init;
		// vm->addr: 0xF8000000, vm->size: 0x1000, vm->phys_addr: 0x10000000, vm->flags: 0x40000001
		// vm->addr: 0xF6100000, vm->size: 0x10000, vm->phys_addr: 0x10050000, vm->flags: 0x40000001
		add_static_vm_early(svm++);
	}
}

// ARM10C 20131130
void __init vm_reserve_area_early(unsigned long addr, unsigned long size,
				  void *caller)
{
	struct vm_struct *vm;
	struct static_vm *svm;

	svm = early_alloc_aligned(sizeof(*svm), __alignof__(*svm));

	vm = &svm->vm;
	vm->addr = (void *)addr;
	vm->size = size;
	// VM_ARM_EMPTY_MAPPING: 0x20000000
	vm->flags = VM_IOREMAP | VM_ARM_EMPTY_MAPPING;
	vm->caller = caller;
	add_static_vm_early(svm);
}

#ifndef CONFIG_ARM_LPAE // CONFIG_ARM_LPAE=n

/*
 * The Linux PMD is made of two consecutive section entries covering 2MB
 * (see definition in include/asm/pgtable-2level.h).  However a call to
 * create_mapping() may optimize static mappings by using individual
 * 1MB section mappings.  This leaves the actual PMD potentially half
 * initialized if the top or bottom section entry isn't used, leaving it
 * open to problems if a subsequent ioremap() or vmalloc() tries to use
 * the virtual space left free by that unused section entry.
 *
 * Let's avoid the issue by inserting dummy vm entries covering the unused
 * PMD halves once the static mappings are in place.
 */

// ARM10C 20131130
static void __init pmd_empty_section_gap(unsigned long addr)
{
	vm_reserve_area_early(addr, SECTION_SIZE, pmd_empty_section_gap);
}

// ARM10C 20131130
// SYSC: 0xf6100000 +  64kB   PA:0x10050000
static void __init fill_pmd_gaps(void)
{
	struct static_vm *svm;
	struct vm_struct *vm;
	unsigned long addr, next = 0;
	pmd_t *pmd;

	list_for_each_entry(svm, &static_vmlist, list) {
		vm = &svm->vm;
		// addr: 0xf6100000
		addr = (unsigned long)vm->addr;
		if (addr < next)
			continue;

		/*
		 * Check if this vm starts on an odd section boundary.
		 * If so and the first section entry for this PMD is free
		 * then we block the corresponding virtual address.
		 */
		// pmd 의 첫번째 section
		// addr: 0xf6100000, PMD_MASK: 0xFFE00000, (addr & ~PMD_MASK): 0x00100000
		// SECTION_SIZE: 0x00100000
		if ((addr & ~PMD_MASK) == SECTION_SIZE) {
			pmd = pmd_off_k(addr);
			// pmd_none(*pmd): 0
			if (pmd_none(*pmd))
				pmd_empty_section_gap(addr & PMD_MASK);
		}

		/*
		 * Then check if this vm ends on an odd section boundary.
		 * If so and the second section entry for this PMD is empty
		 * then we block the corresponding virtual address.
		 */
		// vm->size: 0x10000, addr: 0xf6110000
		addr += vm->size;

		// pmd 의 두번째 section
		// addr: 0xf6110000, PMD_MASK: 0xFFE00000, (addr & ~PMD_MASK): 0x00100000
		// SECTION_SIZE: 0x00100000
		if ((addr & ~PMD_MASK) == SECTION_SIZE) {
			pmd = pmd_off_k(addr) + 1;
			if (pmd_none(*pmd))
				pmd_empty_section_gap(addr);
		}

		/* no need to look at any vm entry until we hit the next PMD */
		// addr: 0xf6110000, PMD_SIZE: 0x00200000, PMD_MASK: 0xFFE00000
		// next: 0xf6200000
		next = (addr + PMD_SIZE - 1) & PMD_MASK;
	}
}

#else
#define fill_pmd_gaps() do { } while (0)
#endif

#if defined(CONFIG_PCI) && !defined(CONFIG_NEED_MACH_IO_H) // CONFIG_PCI=n, CONFIG_NEED_MACH_IO_H=n
static void __init pci_reserve_io(void)
{
	struct static_vm *svm;

	svm = find_static_vm_vaddr((void *)PCI_IO_VIRT_BASE);
	if (svm)
		return;

	vm_reserve_area_early(PCI_IO_VIRT_BASE, SZ_2M, pci_reserve_io);
}
#else
// ARM10C 20131130
#define pci_reserve_io() do { } while (0)
#endif

#ifdef CONFIG_DEBUG_LL
void __init debug_ll_io_init(void)
{
	struct map_desc map;

	debug_ll_addr(&map.pfn, &map.virtual);
	if (!map.pfn || !map.virtual)
		return;
	map.pfn = __phys_to_pfn(map.pfn);
	map.virtual &= PAGE_MASK;
	map.length = PAGE_SIZE;
	map.type = MT_DEVICE;
	iotable_init(&map, 1);
}
#endif

// ARM10C 20131019
// VMALLOC_END: 0xff000000, VMALLOC_OFFSET: (8*1024*1024)=0x00800000
// (240 << 20): 0x0f000000
// vmalloc_min: 0xef800000
static void * __initdata vmalloc_min =
	(void *)(VMALLOC_END - (240 << 20) - VMALLOC_OFFSET);

/*
 * vmalloc=size forces the vmalloc area to be exactly 'size'
 * bytes. This can be used to increase (or decrease) the vmalloc
 * area - the default is 240m.
 */
static int __init early_vmalloc(char *arg)
{
	unsigned long vmalloc_reserve = memparse(arg, NULL);

	if (vmalloc_reserve < SZ_16M) {
		vmalloc_reserve = SZ_16M;
		printk(KERN_WARNING
			"vmalloc area too small, limiting to %luMB\n",
			vmalloc_reserve >> 20);
	}

	if (vmalloc_reserve > VMALLOC_END - (PAGE_OFFSET + SZ_32M)) {
		vmalloc_reserve = VMALLOC_END - (PAGE_OFFSET + SZ_32M);
		printk(KERN_WARNING
			"vmalloc area is too big, limiting to %luMB\n",
			vmalloc_reserve >> 20);
	}

	vmalloc_min = (void *)(VMALLOC_END - vmalloc_reserve);
	return 0;
}
early_param("vmalloc", early_vmalloc);

// ARM10C 20131019
phys_addr_t arm_lowmem_limit __initdata = 0;

// ARM10C 20131019
void __init sanity_check_meminfo(void)
{
	phys_addr_t memblock_limit = 0;
	int i, j, highmem = 0;
	// vmalloc_limit: 0x4f800000 = __pa(0xef800000 - 1) + 1
	phys_addr_t vmalloc_limit = __pa(vmalloc_min - 1) + 1;

	// meminfo.nr_banks = 1
	for (i = 0, j = 0; i < meminfo.nr_banks; i++) {
		struct membank *bank = &meminfo.bank[j];
		phys_addr_t size_limit;

		*bank = meminfo.bank[i];
		size_limit = bank->size;

	        // vmalloc_limit: 0x4f800000
		// bank->start  : 0x20000000
		if (bank->start >= vmalloc_limit)
			highmem = 1;
		else
			// size_limit: 0x2f800000
			size_limit = vmalloc_limit - bank->start;

		// bank->highmem: 0
		bank->highmem = highmem;

#ifdef CONFIG_HIGHMEM // CONFIG_HIGHMEM=y
		/*
		 * Split those memory banks which are partially overlapping
		 * the vmalloc area greatly simplifying things later.
		 */

		// bank->size: 0x80000000
		// size_limit: 0x2f800000
		if (!highmem && bank->size > size_limit) {
			if (meminfo.nr_banks >= NR_BANKS) {
				printk(KERN_CRIT "NR_BANKS too low, "
						 "ignoring high memory\n");
			} else {
				memmove(bank + 1, bank,
					(meminfo.nr_banks - i) * sizeof(*bank));
				meminfo.nr_banks++;
				i++;

				// bank[1].size: 0x50800000, bank[1].start: 0x4f800000,
				// bank[1].highmem: 1
				bank[1].size -= size_limit;
				bank[1].start = vmalloc_limit;
				bank[1].highmem = highmem = 1;
				j++;
			}
			// bank->size: 0x2f800000:bank[0]
			bank->size = size_limit;
		}
#else
		/*
		 * Highmem banks not allowed with !CONFIG_HIGHMEM.
		 */
		if (highmem) {
			printk(KERN_NOTICE "Ignoring RAM at %.8llx-%.8llx "
			       "(!CONFIG_HIGHMEM).\n",
			       (unsigned long long)bank->start,
			       (unsigned long long)bank->start + bank->size - 1);
			continue;
		}

		/*
		 * Check whether this memory bank would partially overlap
		 * the vmalloc area.
		 */
		if (bank->size > size_limit) {
			printk(KERN_NOTICE "Truncating RAM at %.8llx-%.8llx "
			       "to -%.8llx (vmalloc region overlap).\n",
			       (unsigned long long)bank->start,
			       (unsigned long long)bank->start + bank->size - 1,
			       (unsigned long long)bank->start + size_limit - 1);
			bank->size = size_limit;
		}
#endif
		if (!bank->highmem) {
			// bank_end = 0x20000000 + 0x2f800000: 0x4f800000
			phys_addr_t bank_end = bank->start + bank->size;

			if (bank_end > arm_lowmem_limit)
				// arm_lowmem_limit: 0x4f800000
				arm_lowmem_limit = bank_end;

			/*
			 * Find the first non-section-aligned page, and point
			 * memblock_limit at it. This relies on rounding the
			 * limit down to be section-aligned, which happens at
			 * the end of this function.
			 *
			 * With this algorithm, the start or end of almost any
			 * bank can be non-section-aligned. The only exception
			 * is that the start of the bank 0 must be section-
			 * aligned, since otherwise memory would need to be
			 * allocated when mapping the start of bank 0, which
			 * occurs before any free memory is mapped.
			 */
			// memblock_limit: 0
			if (!memblock_limit) {
				// bank->start: 0x20000000, bank_end: 0x6f800000
				if (!IS_ALIGNED(bank->start, SECTION_SIZE))
					memblock_limit = bank->start;
				else if (!IS_ALIGNED(bank_end, SECTION_SIZE))
					memblock_limit = bank_end;
			}
		}
		j++;
	}
#ifdef CONFIG_HIGHMEM // CONFIG_HIGHMEM=y
	if (highmem) {
		const char *reason = NULL;

		// pipt
		if (cache_is_vipt_aliasing()) {
			/*
			 * Interactions between kmap and other mappings
			 * make highmem support with aliasing VIPT caches
			 * rather difficult.
			 */
			reason = "with VIPT aliasing cache";
		}
		if (reason) {
			printk(KERN_CRIT "HIGHMEM is not supported %s, ignoring high memory\n",
				reason);
			while (j > 0 && meminfo.bank[j - 1].highmem)
				j--;
		}
	}
#endif
	// meminfo.nr_banks: 2
	meminfo.nr_banks = j;

	// arm_lowmem_limit: 0x4f800000
	// high_memory: 0xef800000
	high_memory = __va(arm_lowmem_limit - 1) + 1;

	/*
	 * Round the memblock limit down to a section size.  This
	 * helps to ensure that we will allocate memory from the
	 * last full section, which should be mapped.
	 */
	if (memblock_limit)
		memblock_limit = round_down(memblock_limit, SECTION_SIZE);
	if (!memblock_limit)
		// memblock_limit: 0x4f800000
		memblock_limit = arm_lowmem_limit;

	memblock_set_current_limit(memblock_limit);
}

// ARM10C 20131102
static inline void prepare_page_table(void)
{
	unsigned long addr;
	phys_addr_t end;

	/*
	 * Clear out all the mappings below the kernel image.
	 */
	// 0 ~ 0xBF000000 까지 클리어 (유저 영역)
	// Virtual Address 0 ~ MODULES_VADDR까지 영역에 대한 페이지테이블 영역 Clear
	// 페이지테이블영역: 0xC0004000 ~ 0xC0006FC7
	// MODULES_VADDR: 0xBF000000, PMD_SIZE: 0x00200000
	for (addr = 0; addr < MODULES_VADDR; addr += PMD_SIZE)
		pmd_clear(pmd_off_k(addr));

#ifdef CONFIG_XIP_KERNEL // CONFIG_XIP_KERNEL=n
	/* The XIP kernel is mapped in the module area -- skip over it */
	addr = ((unsigned long)_etext + PMD_SIZE - 1) & PMD_MASK;
#endif

	// 0xBF000000 ~ 0xC0000000 까지 클리어 (모듈 영역)
	// PAGE_OFFSET: 0xC0000000, PMD_SIZE: 0x00200000
	for ( ; addr < PAGE_OFFSET; addr += PMD_SIZE)
		pmd_clear(pmd_off_k(addr));

	/*
	 * Find the end of the first block of lowmem.
	 */
	// memblock.memory.regions[0].base: 0x20000000
	// memblock.memory.regions[0].size: 0x80000000
	// end: 0xA0000000
	end = memblock.memory.regions[0].base + memblock.memory.regions[0].size;

	// arm_lowmem_limit: 0x4f800000
	if (end >= arm_lowmem_limit)
		// end: 0x4f800000
		end = arm_lowmem_limit;

	/*
	 * Clear out all the kernel space mappings, except for the first
	 * memory bank, up to the vmalloc region.
	 */
	// 0xEF800000 ~ 0xF0000000 까지 클리어
	// addr: 0xef800000, VMALLOC_START: 0xf0000000
	for (addr = __phys_to_virt(end);
	     addr < VMALLOC_START; addr += PMD_SIZE)
		pmd_clear(pmd_off_k(addr));
}

#ifdef CONFIG_ARM_LPAE // CONFIG_ARM_LPAE=n
/* the first page is reserved for pgd */
#define SWAPPER_PG_DIR_SIZE	(PAGE_SIZE + \
				 PTRS_PER_PGD * PTRS_PER_PMD * sizeof(pmd_t))
#else
// ARM10C 20131026
// PTRS_PER_PGD: 2048, sizeof(pgd_t): 8 byte
// SWAPPER_PG_DIR_SIZE: 0x4000 - 16 Kbytes
#define SWAPPER_PG_DIR_SIZE	(PTRS_PER_PGD * sizeof(pgd_t))
#endif

/*
 * Reserve the special regions of memory
 */
// ARM10C 20131026
void __init arm_mm_memblock_reserve(void)
{
	/*
	 * Reserve the page tables.  These are already in use,
	 * and can only be in node 0.
	 */
	// mmu가 사용하는 page table 있는 위치
	// swapper_pg_dir: 0xc0004000, __pa(swapper_pg_dir); 0x40004000
	memblock_reserve(__pa(swapper_pg_dir), SWAPPER_PG_DIR_SIZE);

#ifdef CONFIG_SA1111 // CONFIG_SA1111=n
	/*
	 * Because of the SA1111 DMA bug, we want to preserve our
	 * precious DMA-able memory...
	 */
	memblock_reserve(PHYS_OFFSET, __pa(swapper_pg_dir) - PHYS_OFFSET);
#endif
}

/*
 * Set up the device mappings.  Since we clear out the page tables for all
 * mappings above VMALLOC_START, we will remove any debug device mappings.
 * This means you have to be careful how you debug this function, or any
 * called function.  This means you can't use any function or debugging
 * method which may touch any device, otherwise the kernel _will_ crash.
 */
// ARM10C 20131109
static void __init devicemaps_init(const struct machine_desc *mdesc)
{
	struct map_desc map;
	unsigned long addr;
	void *vectors;

	/*
	 * Allocate the vector page early.
	 */
	// PAGE_SIZE: 0x00001000
	// early_alloc(PAGE_SIZE * 2): 0xEF7FE000
	vectors = early_alloc(PAGE_SIZE * 2);

// 2013/11/09 종료
// 2013/11/16 시작

	// 0xEF7FE000에 vector, stub, kuserhelper 설정
	early_trap_init(vectors);

	// VMALLOC_START: 0xf0000000, PMD_SIZE: 0x00200000
	// 0xF0000000 ~ 0xFFFFFFFF의 pgd를 clear함
	for (addr = VMALLOC_START; addr; addr += PMD_SIZE)
		pmd_clear(pmd_off_k(addr));

	/*
	 * Map the kernel if it is XIP.
	 * It is always first in the modulearea.
	 */
#ifdef CONFIG_XIP_KERNEL // CONFIG_XIP_KERNEL=n
	map.pfn = __phys_to_pfn(CONFIG_XIP_PHYS_ADDR & SECTION_MASK);
	map.virtual = MODULES_VADDR;
	map.length = ((unsigned long)_etext - map.virtual + ~SECTION_MASK) & SECTION_MASK;
	map.type = MT_ROM;
	create_mapping(&map);
#endif

	/*
	 * Map the cache flushing regions.
	 */
#ifdef FLUSH_BASE // undefined
	map.pfn = __phys_to_pfn(FLUSH_BASE_PHYS);
	map.virtual = FLUSH_BASE;
	map.length = SZ_1M;
	map.type = MT_CACHECLEAN;
	create_mapping(&map);
#endif
#ifdef FLUSH_BASE_MINICACHE // undefined
	map.pfn = __phys_to_pfn(FLUSH_BASE_PHYS + SZ_1M);
	map.virtual = FLUSH_BASE_MINICACHE;
	map.length = SZ_1M;
	map.type = MT_MINICLEAN;
	create_mapping(&map);
#endif

	/*
	 * Create a mapping for the machine vectors at the high-vectors
	 * location (0xffff0000).  If we aren't using high-vectors, also
	 * create a mapping at the low-vectors virtual address.
	 */
	// vectors: 0xEF7FE000, virt_to_phys(vectors): 0x4F7FE000
	// map.pfn: 0x4F7FE
	map.pfn = __phys_to_pfn(virt_to_phys(vectors));
	map.virtual = 0xffff0000;
	// map.length: 0x1000, PAGE_SIZE: 0x1000
	map.length = PAGE_SIZE;
#ifdef CONFIG_KUSER_HELPERS // CONFIG_KUSER_HELPERS=y
	map.type = MT_HIGH_VECTORS;
#else
	map.type = MT_LOW_VECTORS;
#endif
	// MT_HIGH_VECTORS 의 메모리를 mapping
	create_mapping(&map);

	if (!vectors_high()) {
		map.virtual = 0;
		map.length = PAGE_SIZE * 2;
		map.type = MT_LOW_VECTORS;
		create_mapping(&map);
	}

	/* Now create a kernel read-only mapping */
	// map.pfn: 0X4F7FF
	map.pfn += 1;
	// map.virtual: 0xffff1000
	// stub가 있는 곳 
	map.virtual = 0xffff0000 + PAGE_SIZE;
	map.length = PAGE_SIZE;
	map.type = MT_LOW_VECTORS;

	// MT_LOW_VECTORS 의 메모리를 mapping
	create_mapping(&map);

	/*
	 * Ask the machine support to map in the statically mapped devices.
	 */
// 2013/11/16 종료
// 2013/11/23 시작
	if (mdesc->map_io)
		// exynos_init_io 함수를 호출
		mdesc->map_io();
	else
		debug_ll_io_init();

	// section 단위로 pgd 할당시 사용 section이 갯수가 홀수인경우 안쓰도록 리저브함
	fill_pmd_gaps();

	/* Reserve fixed i/o space in VMALLOC region */
	pci_reserve_io();

	/*
	 * Finally flush the caches and tlb to ensure that we're in a
	 * consistent state wrt the writebuffer.  This also ensures that
	 * any write-allocated cache lines in the vector page are written
	 * back.  After this point, we can start to touch devices again.
	 */
	local_flush_tlb_all();
	flush_cache_all();
}

// ARM10C 20131130
static void __init kmap_init(void)
{
#ifdef CONFIG_HIGHMEM // CONFIG_HIGHMEM=y
	// PKMAP_BASE: 0xBFE00000,  _PAGE_KERNEL_TABLE: 0x11
	pkmap_page_table = early_pte_alloc(pmd_off_k(PKMAP_BASE),
		PKMAP_BASE, _PAGE_KERNEL_TABLE);
#endif
}

// ARM10C 20131102
// region 중 lowmem영역을 추출하여 create_mapping 수행
// create_mapping: 가상 0xC0000000~0xEF800000을 1M 단위로 물리 0x20000000 부터 매핑하면서 
// mem_type을 MT_MEMORY 값으로 설정.(cache 정책 access permission 등이 들어가 있다.
static void __init map_lowmem(void)
{
	struct memblock_region *reg;

	/* Map all the lowmem memory banks. */
	for_each_memblock(memory, reg) {
		phys_addr_t start = reg->base;
		phys_addr_t end = start + reg->size;
		struct map_desc map;

		// end: 0xA0000000, arm_lowmem_limit: 0x4f800000
		if (end > arm_lowmem_limit)
			// end: 0x4f800000
			end = arm_lowmem_limit;

		// start: 0x20000000, end: 0x4f800000
		if (start >= end)
			break;

		// map.pfn: 0x20000
		map.pfn = __phys_to_pfn(start);
		// map.virtual: 0xC0000000
		map.virtual = __phys_to_virt(start);
		// map.length: 0x2f800000
		map.length = end - start;
		map.type = MT_MEMORY;

// 2013/11/02 종료
// 2013/11/09 시작
		create_mapping(&map);
	}
}

#ifdef CONFIG_ARM_LPAE
/*
 * early_paging_init() recreates boot time page table setup, allowing machines
 * to switch over to a high (>4G) address space on LPAE systems
 */
void __init early_paging_init(const struct machine_desc *mdesc,
			      struct proc_info_list *procinfo)
{
	pmdval_t pmdprot = procinfo->__cpu_mm_mmu_flags;
	unsigned long map_start, map_end;
	pgd_t *pgd0, *pgdk;
	pud_t *pud0, *pudk, *pud_start;
	pmd_t *pmd0, *pmdk;
	phys_addr_t phys;
	int i;

	if (!(mdesc->init_meminfo))
		return;

	/* remap kernel code and data */
	map_start = init_mm.start_code;
	map_end   = init_mm.brk;

	/* get a handle on things... */
	pgd0 = pgd_offset_k(0);
	pud_start = pud0 = pud_offset(pgd0, 0);
	pmd0 = pmd_offset(pud0, 0);

	pgdk = pgd_offset_k(map_start);
	pudk = pud_offset(pgdk, map_start);
	pmdk = pmd_offset(pudk, map_start);

	mdesc->init_meminfo();

	/* Run the patch stub to update the constants */
	fixup_pv_table(&__pv_table_begin,
		(&__pv_table_end - &__pv_table_begin) << 2);

	/*
	 * Cache cleaning operations for self-modifying code
	 * We should clean the entries by MVA but running a
	 * for loop over every pv_table entry pointer would
	 * just complicate the code.
	 */
	flush_cache_louis();
	dsb();
	isb();

	/* remap level 1 table */
	for (i = 0; i < PTRS_PER_PGD; pud0++, i++) {
		set_pud(pud0,
			__pud(__pa(pmd0) | PMD_TYPE_TABLE | L_PGD_SWAPPER));
		pmd0 += PTRS_PER_PMD;
	}

	/* remap pmds for kernel mapping */
	phys = __pa(map_start) & PMD_MASK;
	do {
		*pmdk++ = __pmd(phys | pmdprot);
		phys += PMD_SIZE;
	} while (phys < map_end);

	flush_cache_all();
	cpu_switch_mm(pgd0, &init_mm);
	cpu_set_ttbr(1, __pa(pgd0) + TTBR1_OFFSET);
	local_flush_bp_all();
	local_flush_tlb_all();
}

#else

void __init early_paging_init(const struct machine_desc *mdesc,
			      struct proc_info_list *procinfo)
{
	if (mdesc->init_meminfo)
		mdesc->init_meminfo();
}

#endif

/*
 * paging_init() sets up the page tables, initialises the zone memory
 * maps, and sets up the zero page, bad page and bad page tables.
 */
// ARM10C 20131026
void __init paging_init(const struct machine_desc *mdesc)
{
	void *zero_page;

	// 아키텍처 버전에 따른 메모리 타입 설정
	build_mem_type_table();

	// page table 초기화
	// 0 ~ 0xBF000000, 0xBF000000 ~ 0xC0000000, 0xEF800000 ~ 0xF0000000
	// 영역을 2M 단위로 section table entry를 clear
	prepare_page_table();

	// low memory영역에 page table 속성값과physical memory mapping 값 갱신
	// region 중 lowmem영역을 추출하여 create_mapping 수행
	// create_mapping: 가상 0xC0000000~0xEF800000을 1M 단위로 물리 0x20000000 부터 매핑하면서 
	// mem_type을 MT_MEMORY 값으로 설정.(cache 정책 access permission 등이 들어가 있다.
	map_lowmem();

	// dma contiguous 는 사용안함
	dma_contiguous_remap();

// 2013/11/09 종료
// 2013/11/16 시작

	// vectors, io memory map 설정
	devicemaps_init(mdesc);

	// kmap을 위한 4k 공간을 0xBFE00000 에 맞는 2nd page tabel에 할당
	kmap_init();

	// tcm: tightly coupled memory.
	tcm_init();//Empty function

	// high vector가 최상위 pmd section index임
	top_pmd = pmd_off_k(0xffff0000);

	/* allocate the zero page. */
	// PAGE_SIZE: 0x1000
	// zero_page에 4k 메모리 할당
	zero_page = early_alloc(PAGE_SIZE);

// 2013/11/30 종료
// 2013/12/07 시작
	// contig_page_data 내부 값을 설정
	bootmem_init();

	// empty_zero_page : ??, low_mem에 있으므로 zone normal 영역에 존재 (0)
	empty_zero_page = virt_to_page(zero_page);

// 2014/01/18 종료
// 2014/01/25 시작

	// empty_zero_page: ??
	__flush_dcache_page(NULL, empty_zero_page);
	// empty_zero_page를 dcache flush 수행함
}
