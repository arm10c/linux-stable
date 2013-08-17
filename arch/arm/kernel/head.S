/*
 *  linux/arch/arm/kernel/head.S
 *
 *  Copyright (C) 1994-2002 Russell King
 *  Copyright (c) 2003 ARM Limited
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  Kernel startup code for all 32-bit CPUs
 *  Kernel startup code는 32-비트 CPUs를 위한 것.
 */
#include <linux/linkage.h>
#include <linux/init.h>

#include <asm/assembler.h>
#include <asm/cp15.h>
#include <asm/domain.h>
#include <asm/ptrace.h>
#include <asm/asm-offsets.h>
#include <asm/memory.h>
#include <asm/thread_info.h>
#include <asm/pgtable.h>

#if defined(CONFIG_DEBUG_LL) && !defined(CONFIG_DEBUG_SEMIHOSTING)
#include CONFIG_DEBUG_LL_INCLUDE
#endif

/*
 * swapper_pg_dir is the virtual address of the initial page table.
 * We place the page tables 16K below KERNEL_RAM_VADDR.  Therefore, we must
 * make sure that KERNEL_RAM_VADDR is correctly set.  Currently, we expect
 * the least significant 16 bits to be 0x8000, but we could probably
 * relax this restriction to KERNEL_RAM_VADDR >= PAGE_OFFSET + 0x4000.
 * swapper_pg_dir은 초기 페이지 테이블의 가상 주소입니다.
 * KERNEL_RAM_VADDR 아래 페이지 테이블 16K을 위치 시킵니다.
 * KERNEL_RAM_VADDR가 정확히 설정되었는지 확인해야 합니다.
 * 현재, 0x8000을 시작 주소라고 생각할 수 있고
 * (KERNEL_RAM_VADDR >= PAGE_OFFSET + 0x4000) 조건에 대해 여유가 있습니다.
 */
// 2013/8/10 시작
// exynos 기준
// PAGE_OFFSET: 0xC0000000, TEXT_OFFSET: 0x8000
#define KERNEL_RAM_VADDR	(PAGE_OFFSET + TEXT_OFFSET)
#if (KERNEL_RAM_VADDR & 0xffff) != 0x8000
#error KERNEL_RAM_VADDR must start at 0xXXXX8000
#endif

// LPAE: Large physical address extensions
#ifdef CONFIG_ARM_LPAE
	/* LPAE requires an additional page for the PGD */
#define PG_DIR_SIZE	0x5000
#define PMD_ORDER	3
#else
#define PG_DIR_SIZE	0x4000
// PMD: Page Middle Directory 
#define PMD_ORDER	2
#endif

	.globl	swapper_pg_dir
	.equ	swapper_pg_dir, KERNEL_RAM_VADDR - PG_DIR_SIZE
	// 연산결과 swapper_pg_dir : 0xc0004000


	// TEXT_OFFSET = 0x8000
	// PG_DIR_SIZE = 0x4000
	.macro	pgtbl, rd, phys
	add	\rd, \phys, #TEXT_OFFSET - PG_DIR_SIZE
	.endm

/*
 * Kernel startup entry point.
 * ---------------------------
 *
 * This is normally called from the decompressor code.  The requirements
 * are: MMU = off, D-cache = off, I-cache = dont care, r0 = 0,
 * r1 = machine nr, r2 = atags or dtb pointer.
 * 이것은 압축을 푼 코드에서 정상적으로 호출된 것입니다.
 * MMU = off, D-cache = off, I-cache = dont care, r0 = 0,
 * r1 = machine nr, r2 = atags 또는 dtb pointer
 *위에 열거한 값들이 필요합니다.
 *
 * This code is mostly position independent, so if you link the kernel at
 * 0xc0008000, you call this at __pa(0xc0008000).
 * 대부분의 경우 이 코드는 위치와 관계가 없습니다.
 * 커널을 0xc0008000에 링크하려면
 *  __pa(0xc0008000)에서 호출하십시오.
 *
 * See linux/arch/arm/tools/mach-types for the complete list of machine
 * numbers for r1.
 * r1(머신 번호)에 대한 리스트는
 * linux/arch/arm/tools/mach-types에서 참조
 *
 * We're trying to keep crap to a minimum; DO NOT add any machine specific
 * crap here - that's what the boot loader (or in extreme, well justified
 * circumstances, zImage) is for.
 *  최소화를 유지하기;
 * 특정 머신의 잡다한 코드를 첨부하지 마십시오.
 * 부트로더를 위한 것입니다.
 */
	.arm

	// vmlinux.lds.s 의 아래 section에 정의 되어 있음 
        // #define __HEAD		.section	".head.text","ax"
	__HEAD
ENTRY(stext)

 THUMB(	adr	r9, BSYM(1f)	)	@ Kernel is always entered in ARM.
 THUMB(	bx	r9		)	@ If this is a Thumb-2 kernel,
 THUMB(	.thumb			)	@ switch to Thumb now.
 THUMB(1:			)

#ifdef CONFIG_ARM_VIRT_EXT
	bl	__hyp_stub_install
#endif
	@ ensure svc mode and all interrupts masked
	//  SVC 모드와 인터럽트 마크스를 확인

	safe_svcmode_maskall r9

	mrc	p15, 0, r9, c0, c0		@ get processor id
	bl	__lookup_processor_type		@ r5=procinfo r9=cpuid
	movs	r10, r5				@ invalid processor (r5=0)?
 THUMB( it	eq )		@ force fixup-able long branch encoding
	// CPU를 못찾았을 때 에러 처리 루틴으로 빠짐
	beq	__error_p			@ yes, error 'p'

#ifdef CONFIG_ARM_LPAE
	mrc	p15, 0, r3, c0, c1, 4		@ read ID_MMFR0
	and	r3, r3, #0xf			@ extract VMSA support
	cmp	r3, #5				@ long-descriptor translation table format?
 THUMB( it	lo )				@ force fixup-able long branch encoding
	blo	__error_p			@ only classic page table format
#endif

#ifndef CONFIG_XIP_KERNEL
	adr	r3, 2f
	ldmia	r3, {r4, r8}
	sub	r4, r3, r4			@ (PHYS_OFFSET - PAGE_OFFSET)
	add	r8, r8, r4			@ PHYS_OFFSET
#else
	ldr	r8, =PHYS_OFFSET		@ always constant in this case
#endif

	/*
	 * r1 = machine no, r2 = atags or dtb,
	 * r8 = phys_offset, r9 = cpuid, r10 = procinfo
	 */
	// dtb/atags 가 유효한지 확인
	bl	__vet_atags
#ifdef CONFIG_SMP_ON_UP
	// 멀티코어 인지 확인
	bl	__fixup_smp
#endif
#ifdef CONFIG_ARM_PATCH_PHYS_VIRT
	// __pv_table에 대한 주소보정
	bl	__fixup_pv_table
#endif
	// Kernel, Atag/dtb, Debug 관련 page table 생성
	bl	__create_page_tables

	/*
	 * The following calls CPU specific code in a position independent
	 * manner.  See arch/arm/mm/proc-*.S for details.  r10 = base of
	 * xxx_proc_info structure selected by __lookup_processor_type
	 * above.  On return, the CPU will be ready for the MMU to be
	 * turned on, and r0 will hold the CPU control register value.
	 *
	 * 다음은 독립적인 방법으로 한 위치에서
	 * CPU 특정 코드를 호출하는 것이다.
	 * 상세한 것은  arch/arm/mm/proc-*.S를 참조
	 * 위의  __lookup_processor_type에 의해 선택된
	 *  xxx_proc_info 구조체의 시작주소(base)가 r10에 저장됩니다.
	 * 리턴하면, CPU는 MMU를 사용할 수 있고
	 * r0에는 CPU control 레지스터 값이 저장될 것입니다.
	 */

	// r4: 0x40004000
	ldr	r13, =__mmap_switched		@ address to jump to after
						@ mmu has been enabled
	adr	lr, BSYM(1f)			@ return (PIC) address
	mov	r8, r4				@ set TTBR1 to swapper_pg_dir
 ARM(	add	pc, r10, #PROCINFO_INITFUNC	)
 THUMB(	add	r12, r10, #PROCINFO_INITFUNC	)
 THUMB(	mov	pc, r12				)
1:	b	__enable_mmu
ENDPROC(stext)
	.ltorg
#ifndef CONFIG_XIP_KERNEL
2:	.long	.
	.long	PAGE_OFFSET
#endif

/*
 * Setup the initial page tables.  We only setup the barest
 * amount which are required to get the kernel running, which
 * generally means mapping in the kernel code.
 * 초기 페이지 테이블 설정.
 * 커널 수행이 가능한 최소 크기를 설정할 것입니다.
 * 최소 크기는 커널 코드에서 맵핑을 의미합니다.
 * r8 = phys_offset, r9 = cpuid, r10 = procinfo
 *
 * Returns:
 *  r0, r3, r5-r7 corrupted
 *  r4 = physical page table address
 */
__create_page_tables:
	// r4 = 현재의 page table address
	pgtbl	r4, r8				@ page table address

	/*
	 * Clear the swapper page table
	 */
	// 0x40004000~40008000(page table저장영역)를 모두 0으로 클리어
	mov	r0, r4
	mov	r3, #0
	add	r6, r0, #PG_DIR_SIZE
1:	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	teq	r0, r6
	bne	1b

#ifdef CONFIG_ARM_LPAE
	/*
	 * Build the PGD table (first level) to point to the PMD table. A PGD
	 * entry is 64-bit wide.
	 * PMD 테이블을 포인트하는 PGD(first level) 만들기
	 *  PGD 엔트리는 64비트
	 */
	mov	r0, r4
	add	r3, r4, #0x1000			@ first PMD table address
	orr	r3, r3, #3			@ PGD block type
	mov	r6, #4				@ PTRS_PER_PGD
	mov	r7, #1 << (55 - 32)		@ L_PGD_SWAPPER
1:
#ifdef CONFIG_CPU_ENDIAN_BE8
	str	r7, [r0], #4			@ set top PGD entry bits
	str	r3, [r0], #4			@ set bottom PGD entry bits
#else
	str	r3, [r0], #4			@ set bottom PGD entry bits
	str	r7, [r0], #4			@ set top PGD entry bits
#endif
	add	r3, r3, #0x1000			@ next PMD table
	subs	r6, r6, #1
	bne	1b

	add	r4, r4, #0x1000			@ point to the PMD tables
#ifdef CONFIG_CPU_ENDIAN_BE8
	add	r4, r4, #4			@ we only write the bottom word
#endif
#endif

	// arch/arm/include/asm/procinfo.h : struct proc_info_list 의 __cpu_mm_mmu_flags 값을 읽어옴
	// mmu section ENTRY 에 들어갈 속성값 : 
	// - PMD_TYPE_SECT | PMD_SECT_AP_WRITE | PMD_SECT_AP_READ | PMD_SECT_AF | PMD_FLAGS_SMP | \mm_mmuflags = 0)
	// section ENTRY 의 base 주소를 제외한 속성값으로 사용된다. 
	ldr	r7, [r10, #PROCINFO_MM_MMUFLAGS] @ mm_mmuflags

	/*
	 * Create identity mapping to cater for __enable_mmu.
	 * This identity mapping will be removed by paging_init().
	 *  '__enable_mmu'을 위한 identity mapping 생성하기
	 * 이 identity mapping은 paging_init() 함수에 의해 제거될 것입니다.
	 */
	// SECTION_SHIFT = arch/arm/include/asm/pgtable-2level.h 의 #define SECTION_SHIFT 20
	adr	r0, __turn_mmu_on_loc
	ldmia	r0, {r3, r5, r6}
	sub	r0, r0, r3			@ virt->phys offset
	add	r5, r5, r0			@ phys __turn_mmu_on
	add	r6, r6, r0			@ phys __turn_mmu_on_end
	mov	r5, r5, lsr #SECTION_SHIFT
	mov	r6, r6, lsr #SECTION_SHIFT

	// r3 : SECTION ENTRY base address : MMU L1 table 1M단위
	// r7 : SECTION ENTRY 속성
	// __turn_mmu_on  함수는 가상과 물리 주소를 1:1로 맵핑해두고, 나머지는 해당 가상주소를 구하여 셋팅
1:	orr	r3, r7, r5, lsl #SECTION_SHIFT	@ flags + kernel base
	str	r3, [r4, r5, lsl #PMD_ORDER]	@ identity mapping
	cmp	r5, r6
	addlo	r5, r5, #1			@ next section
	blo	1b
	// 1:1 맵핑 끝

	/*
	 * Map our RAM from the start to the end of the kernel .bss section.
	 * 메모리 맵핑:  커널 .bss section의 시작에서 끝까지
	 */
	// PAGE_OFFSET = 0xc0000000
	// PMD_ORDER = 2
	// 0x40004000 + (0xC0000000 >> ( 20 - 2 ))
	// r0 = c0000000에 해당하는 페이지엔트리 base주소(가상주소)
	// r6 = vmlinux 종료 주소값 - 1
	// r8 = 0x40000000(PHYS_OFFSET)
	add	r0, r4, #PAGE_OFFSET >> (SECTION_SHIFT - PMD_ORDER)
	ldr	r6, =(_end - 1)
	orr	r3, r8, r7
	// r6 = 커널의 마지막 주소값에 해당하는 페이지 엔트리 가상 주소값
	// r3 = SECTION ENTRY base address : MMU L1 table 1M단위(가변) + 속성
	add	r6, r4, r6, lsr #(SECTION_SHIFT - PMD_ORDER)
1:	str	r3, [r0], #1 << PMD_ORDER
	add	r3, r3, #1 << SECTION_SHIFT
	cmp	r0, r6
	bls	1b
// 2013/08/10 종료
// 2013/08/17 시작

#ifdef CONFIG_XIP_KERNEL
	/*
	 * Map the kernel image separately as it is not located in RAM.
	 * 커널 이미지가 RAM에 존재하지 않을 때
	 * 커널 이미지를 분리하여 맵핑하기
	 */
#define XIP_START XIP_VIRT_ADDR(CONFIG_XIP_PHYS_ADDR)
	mov	r3, pc
	mov	r3, r3, lsr #SECTION_SHIFT
	orr	r3, r7, r3, lsl #SECTION_SHIFT
	add	r0, r4,  #(XIP_START & 0xff000000) >> (SECTION_SHIFT - PMD_ORDER)
	str	r3, [r0, #((XIP_START & 0x00f00000) >> SECTION_SHIFT) << PMD_ORDER]!
	ldr	r6, =(_edata_loc - 1)
	add	r0, r0, #1 << PMD_ORDER
	add	r6, r4, r6, lsr #(SECTION_SHIFT - PMD_ORDER)
1:	cmp	r0, r6
	add	r3, r3, #1 << SECTION_SHIFT
	strls	r3, [r0], #1 << PMD_ORDER
	bls	1b
#endif

	/*
	 * Then map boot params address in r2 if specified.
	 * We map 2 sections in case the ATAGs/DTB crosses a section boundary.
	 * 지정 되었다면, r2에 있는 부트 params 주소 맵핑.
	 * ATAGs/DTB가 section 경계를 넘어가는 경우
	 * 2 section을 맵핑하기(?)
	 */
	// r2: atags/dtb pointer 임
	// r8: 0x40000000(PHYS_OFFSET)
	// PAGE_OFFSET = 0xc0000000
	// r4: page table address=0x40004000
	// r7: SECTION ENTRY 속성
	// r3: dtb의 section entry address
	// r6: mmu의 pvtable 위치 
	mov	r0, r2, lsr #SECTION_SHIFT
	movs	r0, r0, lsl #SECTION_SHIFT
	subne	r3, r0, r8
	addne	r3, r3, #PAGE_OFFSET
	addne	r3, r4, r3, lsr #(SECTION_SHIFT - PMD_ORDER)
	orrne	r6, r7, r0
	strne	r6, [r3], #1 << PMD_ORDER
	addne	r6, r6, #1 << SECTION_SHIFT
	strne	r6, [r3]

#if defined(CONFIG_ARM_LPAE) && defined(CONFIG_CPU_ENDIAN_BE8)
	sub	r4, r4, #4			@ Fixup page table pointer
						@ for 64-bit descriptors
#endif

#ifdef CONFIG_DEBUG_LL
#if !defined(CONFIG_DEBUG_ICEDCC) && !defined(CONFIG_DEBUG_SEMIHOSTING)
	/*
	 * Map in IO space for serial debugging.
	 * This allows debug messages to be output
	 * via a serial console before paging_init.
	 * 시리얼 디버깅을 I/O 공간 맵핑
	 * paging_init 전에,
	 * 시리어 콘솔로 디버깅 메시지 전송
	 */
	addruart r7, r3, r0

	mov	r3, r3, lsr #SECTION_SHIFT
	mov	r3, r3, lsl #PMD_ORDER

	add	r0, r4, r3
	mov	r3, r7, lsr #SECTION_SHIFT
	ldr	r7, [r10, #PROCINFO_IO_MMUFLAGS] @ io_mmuflags
	orr	r3, r7, r3, lsl #SECTION_SHIFT
#ifdef CONFIG_ARM_LPAE
	mov	r7, #1 << (54 - 32)		@ XN
#ifdef CONFIG_CPU_ENDIAN_BE8
	str	r7, [r0], #4
	str	r3, [r0], #4
#else
	str	r3, [r0], #4
	str	r7, [r0], #4
#endif
#else
	orr	r3, r3, #PMD_SECT_XN
	str	r3, [r0], #4
#endif

#else /* CONFIG_DEBUG_ICEDCC || CONFIG_DEBUG_SEMIHOSTING */
	/* we don't need any serial debugging mappings */
	/* 시리얼 디버깅 맵핑이 필요하지 않음 */
	ldr	r7, [r10, #PROCINFO_IO_MMUFLAGS] @ io_mmuflags
#endif

#if defined(CONFIG_ARCH_NETWINDER) || defined(CONFIG_ARCH_CATS)
	/*
	 * If we're using the NetWinder or CATS, we also need to map
	 * in the 16550-type serial port for the debug messages
	 * NetWinder 또는 CATS를 사용하려면
	 * 디버깅 메시지를 위한
	 * 16550-type 시리얼 포트 맵핑 필요.
	 */
	add	r0, r4, #0xff000000 >> (SECTION_SHIFT - PMD_ORDER)
	orr	r3, r7, #0x7c000000
	str	r3, [r0]
#endif
#ifdef CONFIG_ARCH_RPC
	/*
	 * Map in screen at 0x02000000 & SCREEN2_BASE
	 * Similar reasons here - for debug.  This is
	 * only for Acorn RiscPC architectures.
	 */
	add	r0, r4, #0x02000000 >> (SECTION_SHIFT - PMD_ORDER)
	orr	r3, r7, #0x02000000
	str	r3, [r0]
	add	r0, r4, #0xd8000000 >> (SECTION_SHIFT - PMD_ORDER)
	str	r3, [r0]
#endif
#endif
#ifdef CONFIG_ARM_LPAE
	sub	r4, r4, #0x1000		@ point to the PGD table
#endif
	mov	pc, lr
ENDPROC(__create_page_tables)
	.ltorg
	.align
__turn_mmu_on_loc:
	.long	.
	.long	__turn_mmu_on
	.long	__turn_mmu_on_end

#if defined(CONFIG_SMP)
	__CPUINIT
ENTRY(secondary_startup)
	/*
	 * Common entry point for secondary CPUs.
	 * 두 번째 CPUs를 위한 일반적인 엔트리 포인트
	 *
	 * Ensure that we're in SVC mode, and IRQs are disabled.  Lookup
	 * the processor type - there is no need to check the machine type
	 * as it has already been validated by the primary processor.
	 * SVC 모드이고 IRQs 사용 중지인지 확인.
	 * 프로세스 타입 점검.
	 * 머신 타입 체크는 필요하지 않음(이전에 했음).
	 *
	 */
#ifdef CONFIG_ARM_VIRT_EXT
	bl	__hyp_stub_install_secondary
#endif
	safe_svcmode_maskall r9

	mrc	p15, 0, r9, c0, c0		@ get processor id
	bl	__lookup_processor_type
	movs	r10, r5				@ invalid processor?
	moveq	r0, #'p'			@ yes, error 'p'
 THUMB( it	eq )		@ force fixup-able long branch encoding
	beq	__error_p

	/*
	 * Use the page tables supplied from  __cpu_up.
	 * __cpu_up에서 제공된 페이지 테이블 사용
	 */
	adr	r4, __secondary_data
	ldmia	r4, {r5, r7, r12}		@ address to jump to after
	sub	lr, r4, r5			@ mmu has been enabled
	ldr	r4, [r7, lr]			@ get secondary_data.pgdir
	add	r7, r7, #4
	ldr	r8, [r7, lr]			@ get secondary_data.swapper_pg_dir
	adr	lr, BSYM(__enable_mmu)		@ return address
	mov	r13, r12			@ __secondary_switched address
 ARM(	add	pc, r10, #PROCINFO_INITFUNC	) @ initialise processor
						  @ (return control reg)
 THUMB(	add	r12, r10, #PROCINFO_INITFUNC	)
 THUMB(	mov	pc, r12				)
ENDPROC(secondary_startup)

	/*
	 * r6  = &secondary_data
	 */
ENTRY(__secondary_switched)
	ldr	sp, [r7, #4]			@ get secondary_data.stack
	mov	fp, #0
	b	secondary_start_kernel
ENDPROC(__secondary_switched)

	.align

	.type	__secondary_data, %object
__secondary_data:
	.long	.
	.long	secondary_data
	.long	__secondary_switched
#endif /* defined(CONFIG_SMP) */



/*
 * Setup common bits before finally enabling the MMU.  Essentially
 * this is just loading the page table pointer and domain access
 * registers.
 * 마지막으로 MMU를 사용하기 전에 common bits 설정.
 * 반드시, 페이지 테이블 포인터와 도메인 액세스 레지스터 로딩.
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags or dtb pointer
 *  r4  = page table pointer
 *  r9  = processor ID
 *  r13 = *virtual* address to jump to upon completion
 */
__enable_mmu:
#if defined(CONFIG_ALIGNMENT_TRAP) && __LINUX_ARM_ARCH__ < 6
	orr	r0, r0, #CR_A
#else
	bic	r0, r0, #CR_A
#endif
#ifdef CONFIG_CPU_DCACHE_DISABLE
	bic	r0, r0, #CR_C
#endif
#ifdef CONFIG_CPU_BPREDICT_DISABLE
	bic	r0, r0, #CR_Z
#endif
#ifdef CONFIG_CPU_ICACHE_DISABLE
	bic	r0, r0, #CR_I
#endif
#ifdef CONFIG_ARM_LPAE
	mov	r5, #0
	mcrr	p15, 0, r4, r5, c2		@ load TTBR0
#else
	mov	r5, #(domain_val(DOMAIN_USER, DOMAIN_MANAGER) | \
		      domain_val(DOMAIN_KERNEL, DOMAIN_MANAGER) | \
		      domain_val(DOMAIN_TABLE, DOMAIN_MANAGER) | \
		      domain_val(DOMAIN_IO, DOMAIN_CLIENT))
	mcr	p15, 0, r5, c3, c0, 0		@ load domain access register
	mcr	p15, 0, r4, c2, c0, 0		@ load page table pointer
#endif
	b	__turn_mmu_on
ENDPROC(__enable_mmu)

/*
 * Enable the MMU.  This completely changes the structure of the visible
 * memory space.  You will not be able to trace execution through this.
 * If you have an enquiry about this, *please* check the linux-arm-kernel
 * mailing list archives BEFORE sending another post to the list.
 * MMU 온(on) 하기.
 * 이 작업으로 메모리 공간 structure를 완벽하게 변경될 것입니다.
 * 실행되는 것(execution)을 추적할 수는 없습니다.
 * 관련된 문의 사항이 있다면
 *  linux-arm-kernel 메일 아카이브를 참조하십시오.
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags or dtb pointer
 *  r9  = processor ID
 *  r13 = *virtual* address to jump to upon completion
 *
 * other registers depend on the function called upon completion
 * 나머지 레지스터는 진행 과정 호출되는 함수가 사용할 것입니다.
 */
	.align	5
	.pushsection	.idmap.text, "ax"
ENTRY(__turn_mmu_on)
	mov	r0, r0
	instr_sync
	mcr	p15, 0, r0, c1, c0, 0		@ write control reg
	mrc	p15, 0, r3, c0, c0, 0		@ read id reg
	instr_sync
	mov	r3, r3
	mov	r3, r13
	mov	pc, r3
__turn_mmu_on_end:
ENDPROC(__turn_mmu_on)
	.popsection


#ifdef CONFIG_SMP_ON_UP
	// #define __INIT		.section	".init.text","ax"
	__INIT
__fixup_smp:
	// FIXME 멀티코어가 아닌경우, 보정작업을 한다??
	// r9: 0x410fc0f0 <- CPU ID
	// __v7_ca15mp_proc_info:
	// .long	0x410fc0f0
	// r3 = 0x410fc0f0 & 0x000f0000
	and	r3, r9, #0x000f0000	@ architecture version
	teq	r3, #0x000f0000		@ CPU ID supported?
	bne	__fixup_smp_on_up	@ no, assume UP

	// ARM 11MPCore 인지 확인후 맞으면 리턴
	bic	r3, r9, #0x00ff0000
	bic	r3, r3, #0x0000000f	@ mask 0xff00fff0
	mov	r4, #0x41000000
	orr	r4, r4, #0x0000b000
	orr	r4, r4, #0x00000020	@ val 0x4100b020
	teq	r3, r4			@ ARM 11MPCore?
	moveq	pc, lr			@ yes, assume SMP

	// A.R.M B4.1.106 MPIDR, Multiprocessor Affinity Register, VMSA
	// 해당 마스크 값이 10 경우에만 smp(멀티코어)가 되어 리턴
	mrc	p15, 0, r0, c0, c0, 5	@ read MPIDR
	and	r0, r0, #0xc0000000	@ multiprocessing extensions and
	teq	r0, #0x80000000		@ not part of a uniprocessor system?
	moveq	pc, lr			@ yes, assume SMP

__fixup_smp_on_up:
	adr	r0, 1f
	ldmia	r0, {r3 - r5}
	sub	r3, r0, r3
	add	r4, r4, r3
	add	r5, r5, r3
	b	__do_fixup_smp_on_up
ENDPROC(__fixup_smp)

	.align
1:	.word	.
	// FIXME: .alt.smp.init 의 용도? 
	.word	__smpalt_begin
	.word	__smpalt_end

	.pushsection .data
	.globl	smp_on_up
smp_on_up:
	ALT_SMP(.long	1)
	ALT_UP(.long	0)
	.popsection
#endif

	.text
__do_fixup_smp_on_up:
	cmp	r4, r5
	movhs	pc, lr
	ldmia	r4!, {r0, r6}
 ARM(	str	r6, [r0, r3]	)
 THUMB(	add	r0, r0, r3	)
#ifdef __ARMEB__
 THUMB(	mov	r6, r6, ror #16	)	@ Convert word order for big-endian.
#endif
 THUMB(	strh	r6, [r0], #2	)	@ For Thumb-2, store as two halfwords
 THUMB(	mov	r6, r6, lsr #16	)	@ to be robust against misaligned r3.
 THUMB(	strh	r6, [r0]	)
	b	__do_fixup_smp_on_up
ENDPROC(__do_fixup_smp_on_up)

ENTRY(fixup_smp)
	stmfd	sp!, {r4 - r6, lr}
	mov	r4, r0
	add	r5, r0, r1
	mov	r3, #0
	bl	__do_fixup_smp_on_up
	ldmfd	sp!, {r4 - r6, pc}
ENDPROC(fixup_smp)

#ifdef CONFIG_ARM_PATCH_PHYS_VIRT

/* __fixup_pv_table - patch the stub instructions with the delta between
 * PHYS_OFFSET and PAGE_OFFSET, which is assumed to be 16MiB aligned and
 * can be expressed by an immediate shifter operand. The stub instruction
 * has a form of '(add|sub) rd, rn, #imm'.
 *
 *  PHYS_OFFSET과 PAGE_OFFSET 사이의 델타(delta)를 이용하여
 *  __fixup_pv_table 패치인 stub instructions는 16 MiB를 차지하고 있다고 가정하고
 *  shifter operand로 구현될 수 있습니다.
 *  stub instruction는 '(add|sub) rd, rn, #imm'과 같은 형태를 취합니다.
 *
 * 참조: 메비바이트(영어: Mebibyte, MiB)  1 메가 이진 바이트 = 2^20 바이트
 */
	__HEAD
__fixup_pv_table:
	adr	r0, 1f
	ldmia	r0, {r3-r5, r7}
	sub	r3, r0, r3	@ PHYS_OFFSET - PAGE_OFFSET
	add	r4, r4, r3	@ adjust table start address
	add	r5, r5, r3	@ adjust table end address
	add	r7, r7, r3	@ adjust __pv_phys_offset address
	// 물리메모리의 주소 - 논리메모리(컴파일시결정)의 주소 = PHYS_OFFSET
	str	r8, [r7]	@ save computed PHYS_OFFSET to __pv_phys_offset
	mov	r6, r3, lsr #24	@ constant for add/sub instructions
	teq	r3, r6, lsl #24 @ must be 16MiB aligned
THUMB(	it	ne		@ cross section branch )
	bne	__error
	str	r6, [r7, #4]	@ save to __pv_offset
	b	__fixup_a_pv_table
ENDPROC(__fixup_pv_table)

	.align
1:	.long	.
	.long	__pv_table_begin
	.long	__pv_table_end
2:	.long	__pv_phys_offset

	.text
__fixup_a_pv_table:
#ifdef CONFIG_THUMB2_KERNEL
	lsls	r6, #24
	beq	2f
	clz	r7, r6
	lsr	r6, #24
	lsl	r6, r7
	bic	r6, #0x0080
	lsrs	r7, #1
	orrcs	r6, #0x0080
	orr	r6, r6, r7, lsl #12
	orr	r6, #0x4000
	b	2f
1:	add     r7, r3
	ldrh	ip, [r7, #2]
	and	ip, 0x8f00
	orr	ip, r6	@ mask in offset bits 31-24
	strh	ip, [r7, #2]
2:	cmp	r4, r5
	ldrcc	r7, [r4], #4	@ use branch for delay slot
	bcc	1b
	bx	lr
#else
	b	2f
1:	ldr	ip, [r7, r3]
	bic	ip, ip, #0x000000ff
	orr	ip, ip, r6	@ mask in offset bits 31-24
	str	ip, [r7, r3]
2:	cmp	r4, r5
	ldrcc	r7, [r4], #4	@ use branch for delay slot
	bcc	1b
	mov	pc, lr
#endif
ENDPROC(__fixup_a_pv_table)

ENTRY(fixup_pv_table)
	stmfd	sp!, {r4 - r7, lr}
	ldr	r2, 2f			@ get address of __pv_phys_offset
	mov	r3, #0			@ no offset
	mov	r4, r0			@ r0 = table start
	add	r5, r0, r1		@ r1 = table size
	ldr	r6, [r2, #4]		@ get __pv_offset
	bl	__fixup_a_pv_table
	ldmfd	sp!, {r4 - r7, pc}
ENDPROC(fixup_pv_table)

	.align
2:	.long	__pv_phys_offset

	.data
	.globl	__pv_phys_offset
	.type	__pv_phys_offset, %object
__pv_phys_offset:
	.long	0
	.size	__pv_phys_offset, . - __pv_phys_offset
__pv_offset:
	.long	0
#endif

#include "head-common.S"
