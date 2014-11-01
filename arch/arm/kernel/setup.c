/*
 *  linux/arch/arm/kernel/setup.c
 *
 *  Copyright (C) 1995-2001 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/utsname.h>
#include <linux/initrd.h>
#include <linux/console.h>
#include <linux/bootmem.h>
#include <linux/seq_file.h>
#include <linux/screen_info.h>
#include <linux/of_platform.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/of_fdt.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#include <linux/proc_fs.h>
#include <linux/memblock.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/sort.h>

#include <asm/unified.h>
#include <asm/cp15.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/elf.h>
#include <asm/procinfo.h>
#include <asm/psci.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/smp_plat.h>
#include <asm/mach-types.h>
#include <asm/cacheflush.h>
#include <asm/cachetype.h>
#include <asm/tlbflush.h>

#include <asm/prom.h>
#include <asm/mach/arch.h>
#include <asm/mach/irq.h>
#include <asm/mach/time.h>
#include <asm/system_info.h>
#include <asm/system_misc.h>
#include <asm/traps.h>
#include <asm/unwind.h>
#include <asm/memblock.h>
#include <asm/virt.h>

#include "atags.h"


#if defined(CONFIG_FPE_NWFPE) || defined(CONFIG_FPE_FASTFPE)
char fpe_type[8];

static int __init fpe_setup(char *line)
{
	memcpy(fpe_type, line, 8);
	return 1;
}

__setup("fpe=", fpe_setup);
#endif

extern void paging_init(const struct machine_desc *desc);
extern void early_paging_init(const struct machine_desc *,
			      struct proc_info_list *);
extern void sanity_check_meminfo(void);
extern enum reboot_mode reboot_mode;
extern void setup_dma_zone(const struct machine_desc *desc);

unsigned int processor_id;
EXPORT_SYMBOL(processor_id);
unsigned int __machine_arch_type __read_mostly;
EXPORT_SYMBOL(__machine_arch_type);
// ARM10C 20141101
unsigned int cacheid __read_mostly;
EXPORT_SYMBOL(cacheid);

// ARM10C 20130928
// FIXME: __atags_pointer은 왜 EXPORT_SYMBOL 을 하지 않는지?
unsigned int __atags_pointer __initdata;

unsigned int system_rev;
EXPORT_SYMBOL(system_rev);

unsigned int system_serial_low;
EXPORT_SYMBOL(system_serial_low);

unsigned int system_serial_high;
EXPORT_SYMBOL(system_serial_high);

// ARM10C 20130914
unsigned int elf_hwcap __read_mostly;
EXPORT_SYMBOL(elf_hwcap);


#ifdef MULTI_CPU
struct processor processor __read_mostly;
#endif
#ifdef MULTI_TLB // defined
// ARM10C 20131102
// ARM10C 20131130
struct cpu_tlb_fns cpu_tlb __read_mostly;
#endif
#ifdef MULTI_USER
struct cpu_user_fns cpu_user __read_mostly;
#endif
#ifdef MULTI_CACHE // defined
// ARM10C 20131116
struct cpu_cache_fns cpu_cache __read_mostly;
#endif
#ifdef CONFIG_OUTER_CACHE
struct outer_cache_fns outer_cache __read_mostly;
EXPORT_SYMBOL(outer_cache);
#endif

/*
 * Cached cpu_architecture() result for use by assembler code.
 * C code should use the cpu_architecture() function instead of accessing this
 * variable directly.
 */
// ARM10C 20131026
int __cpu_architecture __read_mostly = CPU_ARCH_UNKNOWN;

// ARM10C 20130928
struct stack {
	u32 irq[3];
	u32 abt[3];
	u32 und[3];
} ____cacheline_aligned;

#ifndef CONFIG_CPU_V7M
// ARM10C 20130928
static struct stack stacks[NR_CPUS];
#endif

// ARM10C 20130914
char elf_platform[ELF_PLATFORM_SIZE];
EXPORT_SYMBOL(elf_platform);

static const char *cpu_name;
// ARM10C 20131012
static const char *machine_name;
static char __initdata cmd_line[COMMAND_LINE_SIZE];
// ARM10C 20131012
const struct machine_desc *machine_desc __initdata;

// ARM10C 20130914
static union { char c[4]; unsigned long l; } endian_test __initdata = { { 'l', '?', '?', 'b' } };
#define ENDIANNESS ((char)endian_test.l)

DEFINE_PER_CPU(struct cpuinfo_arm, cpu_data);

/*
 * Standard memory resources
 */
// ARM10C 20140125
static struct resource mem_res[] = {
	{
		.name = "Video RAM",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_MEM
	},
	{
		.name = "Kernel code",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_MEM
	},
	{
		.name = "Kernel data",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_MEM
	}
};

#define video_ram   mem_res[0]
// ARM10C 20140125
#define kernel_code mem_res[1]
#define kernel_data mem_res[2]

static struct resource io_res[] = {
	{
		.name = "reserved",
		.start = 0x3bc,
		.end = 0x3be,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	},
	{
		.name = "reserved",
		.start = 0x378,
		.end = 0x37f,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	},
	{
		.name = "reserved",
		.start = 0x278,
		.end = 0x27f,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	}
};

#define lp0 io_res[0]
#define lp1 io_res[1]
#define lp2 io_res[2]

static const char *proc_arch[] = {
	"undefined/unknown",
	"3",
	"4",
	"4T",
	"5",
	"5T",
	"5TE",
	"5TEJ",
	"6TEJ",
	"7",
	"7M",
	"?(12)",
	"?(13)",
	"?(14)",
	"?(15)",
	"?(16)",
	"?(17)",
};

#ifdef CONFIG_CPU_V7M
static int __get_cpu_architecture(void)
{
	return CPU_ARCH_ARMv7M;
}
#else
static int __get_cpu_architecture(void)
{
	int cpu_arch;

	// read_cpuid_id() :   0x410fc0f0
	if ((read_cpuid_id() & 0x0008f000) == 0) {
		cpu_arch = CPU_ARCH_UNKNOWN;
	} else if ((read_cpuid_id() & 0x0008f000) == 0x00007000) {
		cpu_arch = (read_cpuid_id() & (1 << 23)) ? CPU_ARCH_ARMv4T : CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x00080000) == 0x00000000) {
		cpu_arch = (read_cpuid_id() >> 16) & 7;
		if (cpu_arch)
			cpu_arch += CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x000f0000) == 0x000f0000) {
		unsigned int mmfr0;

		/* Revised CPUID format. Read the Memory Model Feature
		 * Register 0 and check for VMSAv7 or PMSAv7 */
		asm("mrc	p15, 0, %0, c0, c1, 4"
		    : "=r" (mmfr0));
		if ((mmfr0 & 0x0000000f) >= 0x00000003 ||
		    (mmfr0 & 0x000000f0) >= 0x00000030)
			cpu_arch = CPU_ARCH_ARMv7;
		else if ((mmfr0 & 0x0000000f) == 0x00000002 ||
			 (mmfr0 & 0x000000f0) == 0x00000020)
			cpu_arch = CPU_ARCH_ARMv6;
		else
			cpu_arch = CPU_ARCH_UNKNOWN;
	} else
		cpu_arch = CPU_ARCH_UNKNOWN;

	return cpu_arch;
}
#endif

// ARM10C 20130914
// ARM10C 20131026
int __pure cpu_architecture(void)
{
	BUG_ON(__cpu_architecture == CPU_ARCH_UNKNOWN);

	// __cpu_architecture: 9
	return __cpu_architecture;
}

// ARM10C 20130914
// ARM10C 20130928
static int cpu_has_aliasing_icache(unsigned int arch)
{
	int aliasing_icache;
	unsigned int id_reg, num_sets, line_size;

	/* PIPT caches never alias. */
	// icache_is_pipt() 리턴값: 0x20
	if (icache_is_pipt())
		return 0;

	/* arch specifies the register format */
	// PIPT가 아닐 경우 아래 코드 수행
	switch (arch) {
	case CPU_ARCH_ARMv7:
		asm("mcr	p15, 2, %0, c0, c0, 0 @ set CSSELR"
		    : /* No output operands */
		    : "r" (1));
		isb();
		asm("mrc	p15, 1, %0, c0, c0, 0 @ read CCSIDR"
		    : "=r" (id_reg));
		line_size = 4 << ((id_reg & 0x7) + 2);
		num_sets = ((id_reg >> 13) & 0x7fff) + 1;
		aliasing_icache = (line_size * num_sets) > PAGE_SIZE;
		break;
	case CPU_ARCH_ARMv6:
		aliasing_icache = read_cpuid_cachetype() & (1 << 11);
		break;
	default:
		/* I-cache aliases will be handled by D-cache aliasing code */
		aliasing_icache = 0;
	}

	return aliasing_icache;
}

// ARM10C 20130914
static void __init cacheid_init(void)
{
    // arch = CPU_ARCH_ARMv7
	unsigned int arch = cpu_architecture();

	if (arch == CPU_ARCH_ARMv7M) {
		cacheid = 0;
	} else if (arch >= CPU_ARCH_ARMv6) {
		// T.R.M: 4.3.2 Cache Type Register
		unsigned int cachetype = read_cpuid_cachetype();
		if ((cachetype & (7 << 29)) == 4 << 29) {
			/* ARMv7 register format */
			arch = CPU_ARCH_ARMv7;
			cacheid = CACHEID_VIPT_NONALIASING;

			// L1ip: b11, (Physical index, physical tag)
			switch (cachetype & (3 << 14)) {
			case (1 << 14):
				cacheid |= CACHEID_ASID_TAGGED;
				break;
			case (3 << 14):	// this
				cacheid |= CACHEID_PIPT;
				break;
			}
		} else {
			arch = CPU_ARCH_ARMv6;
			if (cachetype & (1 << 23))
				cacheid = CACHEID_VIPT_ALIASING;
			else
				cacheid = CACHEID_VIPT_NONALIASING;
		}
// 2013/09/14 종료
// 2013/09/28 시작
		// cpu_has_aliasing_icache(arch) 리턴값 : 0
		if (cpu_has_aliasing_icache(arch))
			cacheid |= CACHEID_VIPT_I_ALIASING;
	} else {
		cacheid = CACHEID_VIVT;
	}

	// T.R.M: 6.1 About the L1 memory system
	// prink 출력값
	// CPU: PIPT / VIPT nonaliasing data cache, PIPT instruction cache 
	printk("CPU: %s data cache, %s instruction cache\n",
		cache_is_vivt() ? "VIVT" :
		cache_is_vipt_aliasing() ? "VIPT aliasing" :
		cache_is_vipt_nonaliasing() ? "PIPT / VIPT nonaliasing" : "unknown",
		cache_is_vivt() ? "VIVT" :
		icache_is_vivt_asid_tagged() ? "VIVT ASID tagged" :
		icache_is_vipt_aliasing() ? "VIPT aliasing" :
		icache_is_pipt() ? "PIPT" :
		cache_is_vipt_nonaliasing() ? "VIPT nonaliasing" : "unknown");
}

/*
 * These functions re-use the assembly code in head.S, which
 * already provide the required functionality.
 */
extern struct proc_info_list *lookup_processor_type(unsigned int);

void __init early_print(const char *str, ...)
{
	extern void printascii(const char *);
	char buf[256];
	va_list ap;

	va_start(ap, str);
	vsnprintf(buf, sizeof(buf), str, ap);
	va_end(ap);

#ifdef CONFIG_DEBUG_LL
	printascii(buf);
#endif
	printk("%s", buf);
}

// ARM10C 20130914
static void __init cpuid_init_hwcaps(void)
{
	unsigned int divide_instrs, vmsa;

	if (cpu_architecture() < CPU_ARCH_ARMv7)
		return;

        // CPUID_EXT_ISAR0	"c2, 0"
	// A.R.M: B6.1.46 ID_ISAR0, Instruction Set Attribute Register 0, PMSA
	divide_instrs = (read_cpuid_ext(CPUID_EXT_ISAR0) & 0x0f000000) >> 24;

	// divide instruction을 지원하는지 검사하여 elf hwcap을 업데이트
	switch (divide_instrs) {
	case 2:
		elf_hwcap |= HWCAP_IDIVA;
	case 1:
		elf_hwcap |= HWCAP_IDIVT;
	}

	/* LPAE implies atomic ldrd/strd instructions */
	vmsa = (read_cpuid_ext(CPUID_EXT_MMFR0) & 0xf) >> 0;
	if (vmsa >= 5)
		elf_hwcap |= HWCAP_LPAE;
}

// ARM10C 20130914
static void __init feat_v6_fixup(void)
{
	int id = read_cpuid_id(); // id: 0x410fc0f0

	if ((id & 0xff0f0000) != 0x41070000)
		return;

	/*
	 * HWCAP_TLS is available only on 1136 r1p0 and later,
	 * see also kuser_get_tls_init.
	 */
	if ((((id >> 4) & 0xfff) == 0xb36) && (((id >> 20) & 3) == 0))
		elf_hwcap &= ~HWCAP_TLS;
}

/*
 * cpu_init - initialise one CPU.
 *
 * cpu_init sets up the per-CPU stacks.
 */
// ARM10C 20130928
void notrace cpu_init(void)
{
#ifndef CONFIG_CPU_V7M	// not defined
	unsigned int cpu = smp_processor_id();	// cpu : 0 
	struct stack *stk = &stacks[cpu];

	if (cpu >= NR_CPUS) {
		printk(KERN_CRIT "CPU%u: bad primary CPU number\n", cpu);
		BUG();
	}

	/*
	 * This only works on resume and secondary cores. For booting on the
	 * boot cpu, smp_prepare_boot_cpu is called after percpu area setup.
	 */
	set_my_cpu_offset(per_cpu_offset(cpu));

	// 특정CPU에 필요한 코드 실행, V7인 경우 아무것도 안하고 리턴
	cpu_proc_init();

	/*
	 * Define the placement constraint for the inline asm directive below.
	 * In Thumb-2, msr with an immediate value is not allowed.
	 */
#ifdef CONFIG_THUMB2_KERNEL	// not defined
#define PLC	"r"
#else
#define PLC	"I"
#endif

	/*
	 * setup stacks for re-entrant exception handlers
	 */

	// IRQ, ABT, UND 모드의 sp 값을 초기화 
	//"msr	cpsr_c, PSR_F_BIT | PSR_I_BIT | IRQ_MODE\n\t"
	//"add	r14, stk, offsetof(struct stack, irq[0])\n\t"	// r14: &(stk->irq[0])
	//"mov	sp, r14\n\t"
	//"msr	cpsr_c, PSR_F_BIT | PSR_I_BIT | ABT_MODE\n\t"
	//"add	r14, stk, offsetof(struct stack, abt[0])\n\t"	// r14: &(stk->abt[0])
	//"mov	sp, r14\n\t"
	//"msr	cpsr_c, PSR_F_BIT | PSR_I_BIT | UND_MODE\n\t"
	//"add	r14, stk, offsetof(struct stack, und[0])\n\t"	// r14: &(stk->und[0])
	//"mov	sp, r14\n\t"
	//"msr	cpsr_c, PSR_F_BIT | PSR_I_BIT | SVC_MODE"

	__asm__ (
	"msr	cpsr_c, %1\n\t"
	"add	r14, %0, %2\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %3\n\t"
	"add	r14, %0, %4\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %5\n\t"
	"add	r14, %0, %6\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %7"
	    :
	    : "r" (stk),
	      PLC (PSR_F_BIT | PSR_I_BIT | IRQ_MODE),
	      "I" (offsetof(struct stack, irq[0])),
	      PLC (PSR_F_BIT | PSR_I_BIT | ABT_MODE),
	      "I" (offsetof(struct stack, abt[0])),
	      PLC (PSR_F_BIT | PSR_I_BIT | UND_MODE),
	      "I" (offsetof(struct stack, und[0])),
	      PLC (PSR_F_BIT | PSR_I_BIT | SVC_MODE)
	    : "r14");
#endif
}

// ARM10C 20140215
u32 __cpu_logical_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };

// ARM10C 20130824
void __init smp_setup_processor_id(void)
{
	int i;
	// A.R.M B4.1.106
	// MPIDR: Multiprocessor Affinity Register
	u32 mpidr = is_smp() ? read_cpuid_mpidr() & MPIDR_HWID_BITMASK : 0;
	u32 cpu = MPIDR_AFFINITY_LEVEL(mpidr, 0);

	// if cpu=0 
	//	cpu_logical_map[0] = 0    // current
	//	cpu_logical_map[1] = 1    // others
	//	cpu_logical_map[2] = 2    // others
	//	cpu_logical_map[3] = 3    // others

	// if cpu=1 
	//	cpu_logical_map[0] = 1    // current
	//	cpu_logical_map[1] = 0    // others
	//	cpu_logical_map[2] = 2    // others
	//	cpu_logical_map[3] = 3    // others

	cpu_logical_map(0) = cpu;
	for (i = 1; i < nr_cpu_ids; ++i)
		cpu_logical_map(i) = i == cpu ? 0 : i;

	/*
	 * clear __my_cpu_offset on boot CPU to avoid hang caused by
	 * using percpu variable early, for example, lockdep will
	 * access percpu variable inside lock_release
	 */
	set_my_cpu_offset(0);

	printk(KERN_INFO "Booting Linux on physical CPU 0x%x\n", mpidr);
}

// ARM10C 20140215
struct mpidr_hash mpidr_hash;
#ifdef CONFIG_SMP // CONFIG_SMP=y
/**
 * smp_build_mpidr_hash - Pre-compute shifts required at each affinity
 *			  level in order to build a linear index from an
 *			  MPIDR value. Resulting algorithm is a collision
 *			  free hash carried out through shifting and ORing
 */
// ARM10C 20140215
static void __init smp_build_mpidr_hash(void)
{
	u32 i, affinity;
	u32 fs[3], bits[3], ls, mask = 0;
	/*
	 * Pre-scan the list of MPIDRS and filter out bits that do
	 * not contribute to affinity levels, ie they never toggle.
	 */
	for_each_possible_cpu(i)
                // [0] i: 0x0
                // cpu_logical_map(0): __cpu_logical_map[0], cpu_logical_map(0): __cpu_logical_map[0],
		mask |= (cpu_logical_map(i) ^ cpu_logical_map(0));
                // [0] mask: 0x0
                // ...
                // [3] mask: 0x3

	pr_debug("mask of set bits 0x%x\n", mask);
	/*
	 * Find and stash the last and first bit set at all affinity levels to
	 * check how many bits are required to represent them.
	 */
	for (i = 0; i < 3; i++) {
                // i: 0, mask: 0x3
                // i: 1, mask: 0x3
		affinity = MPIDR_AFFINITY_LEVEL(mask, i);
                // i: 0, affinity: 0x3
                // i: 1, affinity: 0x0

		/*
		 * Find the MSB bit and LSB bits position
		 * to determine how many bits are required
		 * to express the affinity level.
		 */
                // i: 0, affinity: 0x3
                // i: 1, affinity: 0x0
		ls = fls(affinity);
                // i: 0, ls: 2
                // i: 1, ls: 0

                // i:0 affinity: 0x3
                // i:1 affinity: 0x0
		fs[i] = affinity ? ffs(affinity) - 1 : 0;
                // i:0 ffs(0x3): 1, fs[0]: 0
                // i:1 fs[1]: 0
                // ...
                // i:2 fs[2]: 0

                // i:0 ls: 2, fs[0]: 0;
                // i:1 ls: 0, fs[1]: 0;
		bits[i] = ls - fs[i];
                // bits[0]: 2
                // bits[1]: 0
                // ...
                // bits[2]: 0
	}
	/*
	 * An index can be created from the MPIDR by isolating the
	 * significant bits at each affinity level and by shifting
	 * them in order to compress the 24 bits values space to a
	 * compressed set of values. This is equivalent to hashing
	 * the MPIDR through shifting and ORing. It is a collision free
	 * hash though not minimal since some levels might contain a number
	 * of CPUs that is not an exact power of 2 and their bit
	 * representation might contain holes, eg MPIDR[7:0] = {0x2, 0x80}.
	 */
	mpidr_hash.shift_aff[0] = fs[0];
        // mpidr_hash.shift_aff[0]: 0

        // MPIDR_LEVEL_BITS: 8, fs[1]: 0, bits[0]: 2
	mpidr_hash.shift_aff[1] = MPIDR_LEVEL_BITS + fs[1] - bits[0];
        // mpidr_hash.shift_aff[1]: 6

        // MPIDR_LEVEL_BITS: 8, fs[2]: 0, bits[1]: 0, bits[0]: 2
	mpidr_hash.shift_aff[2] = 2*MPIDR_LEVEL_BITS + fs[2] -
						(bits[1] + bits[0]);
        // mpidr_hash.shift_aff[2]: 14

	mpidr_hash.mask = mask;
        // mpidr_hash.mask: 0x3

        // bits[2]: 0, bits[1]: 0, bits[0]: 2
        mpidr_hash.bits = bits[2] + bits[1] + bits[0];
        // mpidr_hash.bits: 0x2

	pr_debug("MPIDR hash: aff0[%u] aff1[%u] aff2[%u] mask[0x%x] bits[%u]\n",
				mpidr_hash.shift_aff[0],
				mpidr_hash.shift_aff[1],
				mpidr_hash.shift_aff[2],
				mpidr_hash.mask,
				mpidr_hash.bits);
	/*
	 * 4x is an arbitrary value used to warn on a hash table much bigger
	 * than expected on most systems.
	 */
        // mpidr_hash_size(): 4, num_possible_cpus(): 4
	if (mpidr_hash_size() > 4 * num_possible_cpus())
		pr_warn("Large number of MPIDR hash buckets detected\n");
	sync_cache_w(&mpidr_hash);
        // mpidr_hash 의 cache에 있는 값을 실제 메모리에 반영
}
#endif

// ARM10C 20130914
static void __init setup_processor(void)
{
	struct proc_info_list *list;

	
	/*
	 * locate processor in the list of supported processor
	 * types.  The linker builds this table for us from the
	 * entries in arch/arm/mm/proc-*.S
	 */
	list = lookup_processor_type(read_cpuid_id());
	if (!list) {
		printk("CPU configuration botched (ID %08x), unable "
		       "to continue.\n", read_cpuid_id());
		// 못찾으면 무한루프 (여기서 중지)
		while (1);
	}

	cpu_name = list->cpu_name;  // string	cpu_v7_name, "ARMv7 Processor"
	__cpu_architecture = __get_cpu_architecture(); // CPU_ARCH_ARMv7: 9

#ifdef MULTI_CPU // undefined
	processor = *list->proc;
#endif
#ifdef MULTI_TLB // defined
	cpu_tlb = *list->tlb;
#endif
#ifdef MULTI_USER // defined
	cpu_user = *list->user;
#endif
#ifdef MULTI_CACHE // defined, 참조: #define _CACHE v7
	cpu_cache = *list->cache;
#endif

	// *proc_arch[9] = { "7" };
	// A.R.M: B4.1.130 SCTLR, System Control Register, VMSA
	// A.R.M: A3.2 Alignment support
	// cr_alignment: 1 (0xxxxxxx7f)
	printk("CPU: %s [%08x] revision %d (ARMv%s), cr=%08lx\n",
	       cpu_name, read_cpuid_id(), read_cpuid_id() & 15,
	       proc_arch[cpu_architecture()], cr_alignment);

	// init_utsname()->machine: "arm", __NEW_UTS_LEN: 64
	// list->arch_name: "armv7", ENDIANNESS: 'l'
	snprintf(init_utsname()->machine, __NEW_UTS_LEN + 1, "%s%c",
		 list->arch_name, ENDIANNESS);
	// ELF_PLATFORM_SIZE: 8, list->elf_name: v7, ENDIANNESS: 'l'
	snprintf(elf_platform, ELF_PLATFORM_SIZE, "%s%c",
		 list->elf_name, ENDIANNESS);
	
	// HWCAP_SWP | HWCAP_HALF | HWCAP_THUMB | HWCAP_FAST_MULT | HWCAP_EDSP | HWCAP_TLS
	// elf와 hwcap 이름의 관계?
	// http://blee74.tistory.com/entry/setupprocessor-archarmkernelsetupc
	elf_hwcap = list->elf_hwcap;

	// elf_hwcap |= HWCAP_IDIVA | HWCAP_IDIVT;
	cpuid_init_hwcaps();

#ifndef CONFIG_ARM_THUMB // CONFIG_ARM_THUMB = n
	elf_hwcap &= ~(HWCAP_THUMB | HWCAP_IDIVT);
#endif

	erratum_a15_798181_init();

	feat_v6_fixup();

	cacheid_init();
	cpu_init();
}

// ARM10C 20131005
void __init dump_machine_table(void)
{
	const struct machine_desc *p;

	early_print("Available machine support:\n\nID (hex)\tNAME\n");
	for_each_machine_desc(p)
		early_print("%08x\t%s\n", p->nr, p->name);

	early_print("\nPlease check your kernel config and/or bootloader.\n");

	while (true)
		/* can't use cpu_relax() here as it may require MMU setup */;
}

// ARM10C 20131012
int __init arm_add_memory(u64 start, u64 size)
{
	struct membank *bank = &meminfo.bank[meminfo.nr_banks];
	u64 aligned_start;

	if (meminfo.nr_banks >= NR_BANKS) {
		printk(KERN_CRIT "NR_BANKS too low, "
			"ignoring memory at 0x%08llx\n", (long long)start);
		return -EINVAL;
	}

	/*
	 * Ensure that start/size are aligned to a page boundary.
	 * Size is appropriately rounded down, start is rounded up.
	 */
	// start: 0x20000000, size: 0x80000000
	// PAGE_MASK=(~((1 << 12) - 1)) : 0xFFFFF000, 4k
	// size: 0x80000000 - (0x20000000 & 0x00000FFF)
	size -= start & ~PAGE_MASK;
	// size: 0x80000000

	// start: 0x20000000
	aligned_start = PAGE_ALIGN(start);
	// aligned_start: 0x20000000

#ifndef CONFIG_ARCH_PHYS_ADDR_T_64BIT // CONFIG_ARCH_PHYS_ADDR_T_64BIT=n
	// aligned_start: 0x20000000
	if (aligned_start > ULONG_MAX) {
		printk(KERN_CRIT "Ignoring memory at 0x%08llx outside "
		       "32-bit physical address space\n", (long long)start);
		return -EINVAL;
	}

	// aligned_start: 0x20000000, size: 0x80000000
	if (aligned_start + size > ULONG_MAX) {
		printk(KERN_CRIT "Truncating memory at 0x%08llx to fit in "
			"32-bit physical address space\n", (long long)start);
		/*
		 * To ensure bank->start + bank->size is representable in
		 * 32 bits, we use ULONG_MAX as the upper limit rather than 4GB.
		 * This means we lose a page after masking.
		 */
		size = ULONG_MAX - aligned_start;
	}
#endif

	// aligned_start: 0x20000000
	bank->start = aligned_start;
	// bank->start: 0x20000000

	// size: 0x80000000
	bank->size = size & ~(phys_addr_t)(PAGE_SIZE - 1);
	// bank->size: 0x80000000

	/*
	 * Check whether this memory region has non-zero size or
	 * invalid node number.
	 */
	if (bank->size == 0)
		return -EINVAL;

	meminfo.nr_banks++;
	return 0;
}

/*
 * Pick out the memory size.  We look for mem=size@start,
 * where start and size are "size[KkMm]"
 */
static int __init early_mem(char *p)
{
	static int usermem __initdata = 0;
	u64 size;
	u64 start;
	char *endp;

	/*
	 * If the user specifies memory size, we
	 * blow away any automatically generated
	 * size.
	 */
	if (usermem == 0) {
		usermem = 1;
		meminfo.nr_banks = 0;
	}

	start = PHYS_OFFSET;
	size  = memparse(p, &endp);
	if (*endp == '@')
		start = memparse(endp + 1, NULL);

	arm_add_memory(start, size);

	return 0;
}
early_param("mem", early_mem);

// ARM10C 20140125
static void __init request_standard_resources(const struct machine_desc *mdesc)
{
	struct memblock_region *region;
	struct resource *res;

	// 커널 text 영역의 시작과 끝의 주소값를 start, end에할당
	kernel_code.start   = virt_to_phys(_text);
	kernel_code.end     = virt_to_phys(_etext - 1);
	// 커널 data 영역 시작과 끝의 주소값를 start, end에할당
	kernel_data.start   = virt_to_phys(_sdata);
	kernel_data.end     = virt_to_phys(_end - 1);

	for_each_memblock(memory, region) {
		// sizeof(*res): 28 bytes
		res = alloc_bootmem_low(sizeof(*res));
		// res: 4K 메모리 할당 받은 주소

		res->name  = "System RAM";
		res->start = __pfn_to_phys(memblock_region_memory_base_pfn(region));
		res->end = __pfn_to_phys(memblock_region_memory_end_pfn(region)) - 1;

		// IORESOURCE_MEM: 0x00000200, IORESOURCE_BUSY: 0x80000000
		res->flags = IORESOURCE_MEM | IORESOURCE_BUSY;
		// res->flags: 0x80000200

		/*
		// iomem_resource, res->name  = "System RAM", res->flags: 0x80000200
		// root의 영역이 잘못되어 속하지 않거나 기존에 값이 있다면
		// 충돌이 난것이으므로 root를 반환 받는다.
		// 여기서는 충돌나지 않기 때문에 NULL을 반환 받는다.
		//
		//            res
		//     /      /          \
		// parent  child       parent
		//  /      /               \
		// kernel_code  ------->  kernel_data ------> null
		//                sibling
		*/

		request_resource(&iomem_resource, res);

		if (kernel_code.start >= res->start &&
		    kernel_code.end <= res->end)
			request_resource(res, &kernel_code);
		if (kernel_data.start >= res->start &&
		    kernel_data.end <= res->end)
			request_resource(res, &kernel_data);
	}

	// mdesc->video_start: 0
	if (mdesc->video_start) {
		video_ram.start = mdesc->video_start;
		video_ram.end   = mdesc->video_end;
		request_resource(&iomem_resource, &video_ram);
	}

	/*
	 * Some machines don't have the possibility of ever
	 * possessing lp0, lp1 or lp2
	 */
	// mdesc->reserve_lp0: 0
	if (mdesc->reserve_lp0)
		request_resource(&ioport_resource, &lp0);
	if (mdesc->reserve_lp1)
		request_resource(&ioport_resource, &lp1);
	if (mdesc->reserve_lp2)
		request_resource(&ioport_resource, &lp2);
}

#if defined(CONFIG_VGA_CONSOLE) || defined(CONFIG_DUMMY_CONSOLE)
struct screen_info screen_info = {
 .orig_video_lines	= 30,
 .orig_video_cols	= 80,
 .orig_video_mode	= 0,
 .orig_video_ega_bx	= 0,
 .orig_video_isVGA	= 1,
 .orig_video_points	= 8
};
#endif

static int __init customize_machine(void)
{
	/*
	 * customizes platform devices, or adds new ones
	 * On DT based machines, we fall back to populating the
	 * machine from the device tree, if no callback is provided,
	 * otherwise we would always need an init_machine callback.
	 */
	if (machine_desc->init_machine)
		machine_desc->init_machine();
#ifdef CONFIG_OF
	else
		of_platform_populate(NULL, of_default_bus_match_table,
					NULL, NULL);
#endif
	return 0;
}
arch_initcall(customize_machine);

static int __init init_machine_late(void)
{
	if (machine_desc->init_late)
		machine_desc->init_late();
	return 0;
}
late_initcall(init_machine_late);

#ifdef CONFIG_KEXEC // CONFIG_KEXEC=n
static inline unsigned long long get_total_mem(void)
{
	unsigned long total;

	total = max_low_pfn - min_low_pfn;
	return total << PAGE_SHIFT;
}

/**
 * reserve_crashkernel() - reserves memory are for crash kernel
 *
 * This function reserves memory area given in "crashkernel=" kernel command
 * line parameter. The memory reserved is used by a dump capture kernel when
 * primary kernel is crashing.
 */
static void __init reserve_crashkernel(void)
{
	unsigned long long crash_size, crash_base;
	unsigned long long total_mem;
	int ret;

	total_mem = get_total_mem();
	ret = parse_crashkernel(boot_command_line, total_mem,
				&crash_size, &crash_base);
	if (ret)
		return;

	ret = reserve_bootmem(crash_base, crash_size, BOOTMEM_EXCLUSIVE);
	if (ret < 0) {
		printk(KERN_WARNING "crashkernel reservation failed - "
		       "memory is in use (0x%lx)\n", (unsigned long)crash_base);
		return;
	}

	printk(KERN_INFO "Reserving %ldMB of memory at %ldMB "
	       "for crashkernel (System RAM: %ldMB)\n",
	       (unsigned long)(crash_size >> 20),
	       (unsigned long)(crash_base >> 20),
	       (unsigned long)(total_mem >> 20));

	crashk_res.start = crash_base;
	crashk_res.end = crash_base + crash_size - 1;
	insert_resource(&iomem_resource, &crashk_res);
}
#else
// ARM10C 20140215
static inline void reserve_crashkernel(void) {}
#endif /* CONFIG_KEXEC */

// ARM10C 20131019
static int __init meminfo_cmp(const void *_a, const void *_b)
{
	const struct membank *a = _a, *b = _b;
	long cmp = bank_pfn_start(a) - bank_pfn_start(b);
	return cmp < 0 ? -1 : cmp > 0 ? 1 : 0;
}

void __init hyp_mode_check(void)
{
#ifdef CONFIG_ARM_VIRT_EXT
	sync_boot_mode();

	if (is_hyp_mode_available()) {
		pr_info("CPU: All CPU(s) started in HYP mode.\n");
		pr_info("CPU: Virtualization extensions available.\n");
	} else if (is_hyp_mode_mismatched()) {
		pr_warn("CPU: WARNING: CPU(s) started in wrong/inconsistent modes (primary CPU mode 0x%x)\n",
			__boot_cpu_mode & MODE_MASK);
		pr_warn("CPU: This may indicate a broken bootloader or firmware.\n");
	} else
		pr_info("CPU: All CPU(s) started in SVC mode.\n");
#endif
}

// ARM10C 20130914
void __init setup_arch(char **cmdline_p)
{
	const struct machine_desc *mdesc;

	// setup_processor: 각 프로세서에 의존적인 초기화 함수 구조체를 할당하고,
	//                  현재 CPU에 대한 모드의 스택을 설정함.
	setup_processor();

	// setup_machine_fdt:
	// dtb에서 memory bank설정, cmd arg 설정, arch type 설정, mdesc 검색.
	mdesc = setup_machine_fdt(__atags_pointer);
	if (!mdesc)
		mdesc = setup_machine_tags(__atags_pointer, __machine_arch_type);
	machine_desc = mdesc;
	machine_name = mdesc->name;

	if (mdesc->reboot_mode != REBOOT_HARD)
		reboot_mode = mdesc->reboot_mode;

	init_mm.start_code = (unsigned long) _text;
	init_mm.end_code   = (unsigned long) _etext;
	init_mm.end_data   = (unsigned long) _edata;
	init_mm.brk	   = (unsigned long) _end;

// 2013/10/12 종료
// 2013/10/19 시작

	/* populate cmd_line too for later use, preserving boot_command_line */
	strlcpy(cmd_line, boot_command_line, COMMAND_LINE_SIZE);
	*cmdline_p = cmd_line;

	// command arg에서 각 요소들을 파싱하여 early init section으로 설정된 디바이스 초기화.
	// 우리는 serial device가 검색이 되지만 config설정은 없어서 아무것도 안함.
	parse_early_param();

	// page frame number 기준으로 정렬
	// 어드래스로 비교안하는 이유?
	sort(&meminfo.bank, meminfo.nr_banks, sizeof(meminfo.bank[0]), meminfo_cmp, NULL);

	early_paging_init(mdesc, lookup_processor_type(read_cpuid_id()));
	setup_dma_zone(mdesc);

	// memory bank에서 bank하나가  valloc limit 을 넘으면 2개로 쪼갬.bank[0]:low bank[1]:high
	sanity_check_meminfo();

// 2013/10/19 종료
// 2013/10/26 시작

	// meminfo를 참조하여 메모리 블록 구조체를 초기화
	arm_memblock_init(&meminfo, mdesc);

// 2013/10/26 종료
// 2013/11/02 시작

	// mmu용 page table (pgd, pte)을 생성
	// zone 영역 3개로 나누고 각 zone에 해당하는 page를 할당함
	paging_init(mdesc);
	request_standard_resources(mdesc);

// 2014/01/25 종료
// 2014/02/08 시작

	if (mdesc->restart)	// mdesc->restart : exynos5_restart
		arm_pm_restart = mdesc->restart;

	unflatten_device_tree();
        // device tree를 flat tree에서 실제 tree로 생성
        // of_allnodes, of_chosen, of_aliases, aliases_lookup 만들어 줌

	arm_dt_init_cpu_maps();
        // devtree에 cpu node의 reg 값을 읽어서
        // cpu_possible_bits, __cpu_logical_map의 값을 업데이트 함

	psci_init(); // null function
#ifdef CONFIG_SMP // CONFIG_SMP=y
	if (is_smp()) {
                // mdesc->smp_init: NULL
		if (!mdesc->smp_init || !mdesc->smp_init()) {
                        // psci_smp_available(): false
			if (psci_smp_available())
				smp_set_ops(&psci_smp_ops);
                        // mdesc->smp: &exynos_smp_ops
			else if (mdesc->smp)
                                // mdesc->smp: &exynos_smp_ops
				smp_set_ops(mdesc->smp);
                                // smp_ops: exynos_smp_ops 을 할당
		}
		smp_init_cpus();
		smp_build_mpidr_hash();
                // mpidr_hash 의 cache에 있는 값을 실제 메모리에 반영
	}
#endif

        // is_smp(): 1
	if (!is_smp())
		hyp_mode_check();

	reserve_crashkernel(); // null function

#ifdef CONFIG_MULTI_IRQ_HANDLER // ONFIG_MULTI_IRQ_HANDLER=y
        // mdesc->handle_irq: null
	handle_arch_irq = mdesc->handle_irq;
        // handle_arch_irq: null
#endif

#ifdef CONFIG_VT // CONFIG_VT=y
#if defined(CONFIG_VGA_CONSOLE) // CONFIG_VGA_CONSOLE=n
	conswitchp = &vga_con;
#elif defined(CONFIG_DUMMY_CONSOLE) // CONFIG_DUMMY_CONSOLE=y
	conswitchp = &dummy_con;
#endif
#endif

        // mdesc->init_early: null
	if (mdesc->init_early)
		mdesc->init_early();
}


static int __init topology_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct cpuinfo_arm *cpuinfo = &per_cpu(cpu_data, cpu);
		cpuinfo->cpu.hotpluggable = 1;
		register_cpu(&cpuinfo->cpu, cpu);
	}

	return 0;
}
subsys_initcall(topology_init);

#ifdef CONFIG_HAVE_PROC_CPU
static int __init proc_cpu_init(void)
{
	struct proc_dir_entry *res;

	res = proc_mkdir("cpu", NULL);
	if (!res)
		return -ENOMEM;
	return 0;
}
fs_initcall(proc_cpu_init);
#endif

static const char *hwcap_str[] = {
	"swp",
	"half",
	"thumb",
	"26bit",
	"fastmult",
	"fpa",
	"vfp",
	"edsp",
	"java",
	"iwmmxt",
	"crunch",
	"thumbee",
	"neon",
	"vfpv3",
	"vfpv3d16",
	"tls",
	"vfpv4",
	"idiva",
	"idivt",
	"vfpd32",
	"lpae",
	"evtstrm",
	NULL
};

static int c_show(struct seq_file *m, void *v)
{
	int i, j;
	u32 cpuid;

	for_each_online_cpu(i) {
		/*
		 * glibc reads /proc/cpuinfo to determine the number of
		 * online processors, looking for lines beginning with
		 * "processor".  Give glibc what it expects.
		 */
		seq_printf(m, "processor\t: %d\n", i);
		cpuid = is_smp() ? per_cpu(cpu_data, i).cpuid : read_cpuid_id();
		seq_printf(m, "model name\t: %s rev %d (%s)\n",
			   cpu_name, cpuid & 15, elf_platform);

		/* dump out the processor features */
		seq_puts(m, "Features\t: ");

		for (j = 0; hwcap_str[j]; j++)
			if (elf_hwcap & (1 << j))
				seq_printf(m, "%s ", hwcap_str[j]);

		seq_printf(m, "\nCPU implementer\t: 0x%02x\n", cpuid >> 24);
		seq_printf(m, "CPU architecture: %s\n",
			   proc_arch[cpu_architecture()]);

		if ((cpuid & 0x0008f000) == 0x00000000) {
			/* pre-ARM7 */
			seq_printf(m, "CPU part\t: %07x\n", cpuid >> 4);
		} else {
			if ((cpuid & 0x0008f000) == 0x00007000) {
				/* ARM7 */
				seq_printf(m, "CPU variant\t: 0x%02x\n",
					   (cpuid >> 16) & 127);
			} else {
				/* post-ARM7 */
				seq_printf(m, "CPU variant\t: 0x%x\n",
					   (cpuid >> 20) & 15);
			}
			seq_printf(m, "CPU part\t: 0x%03x\n",
				   (cpuid >> 4) & 0xfff);
		}
		seq_printf(m, "CPU revision\t: %d\n\n", cpuid & 15);
	}

	seq_printf(m, "Hardware\t: %s\n", machine_name);
	seq_printf(m, "Revision\t: %04x\n", system_rev);
	seq_printf(m, "Serial\t\t: %08x%08x\n",
		   system_serial_high, system_serial_low);

	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void c_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= c_show
};
