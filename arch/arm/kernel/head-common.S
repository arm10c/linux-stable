/*
 *  linux/arch/arm/kernel/head-common.S
 *
 *  Copyright (C) 1994-2002 Russell King
 *  Copyright (c) 2003 ARM Limited
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define ATAG_CORE 0x54410001
#define ATAG_CORE_SIZE ((2*4 + 3*4) >> 2)
#define ATAG_CORE_SIZE_EMPTY ((2*4) >> 2)

#ifdef CONFIG_CPU_BIG_ENDIAN
#define OF_DT_MAGIC 0xd00dfeed
#else
#define OF_DT_MAGIC 0xedfe0dd0 /* 0xd00dfeed in big-endian */
#endif

/*
 * Exception handling.  Something went wrong and we can't proceed.  We
 * ought to tell the user, but since we don't have any guarantee that
 * we're even running on the right architecture, we do virtually nothing.
 * 예외 처리.
 * 무언가 잘 못 되면 더 이상 진행하지 않음.
 * 올바른 architecture에서 수행하는지 보장할 수 없기 때문입니다.
 *
 * If CONFIG_DEBUG_LL is set we try to print out something about the error
 * and hope for the best (useful if bootloader fails to pass a proper
 * machine ID for example).
  *  CONFIG_DEBUG_LL이 설정되면
 * 에러 정보를 출력 시도
 * (부트로더가 적절한 머신 ID 전달에 실패 했을 때 유용.)
 */
	__HEAD

/* Determine validity of the r2 atags pointer.  The heuristic requires
 * that the pointer be aligned, in the first 16k of physical RAM and
 * that the ATAG_CORE marker is first and present.  If CONFIG_OF_FLATTREE
 * is selected, then it will also accept a dtb pointer.  Future revisions
 * of this function may be more lenient with the physical address and
 * may also be able to move the ATAGS block if necessary.
 *
  *  r2 atags 포인터 유효성 결정.
 * 경험(heuristic)으로는 포인터는 물리적인 RAM의 첫 번째 16k에 위치하고
 *  ATAG_CORE 마커가 첫 번째에 있음.
 * CONFIG_OF_FLATTREE를 선택했다면
 * dtb 포인터를 받음.
 * 이 함수에 대한 차 후 버전에서는
 * 물리 주소에 대해 보다 많은 융통성을 가질 것이며
 * 필요에 따라서는 ATAGS 블록 이동도 가능해 질 것임.
 *
 * Returns:
 *  r2 either valid atags pointer, valid dtb pointer, or zero
 *  r5, r6 corrupted
 * 리턴:
 * 유효한 atags 포인터 또는 dtb 포인터 아니면 0
 */
__vet_atags:
	// r2: atags or dtb 임
	tst	r2, #0x3			@ aligned?
	bne	1f

	ldr	r5, [r2, #0]
	// FLATTREE : flattened device tree -> device tree(dtb)
#ifdef CONFIG_OF_FLATTREE
	// r6: 0xd00dfeed 로드
	ldr	r6, =OF_DT_MAGIC		@ is it a DTB?
	cmp	r5, r6
	beq	2f
#endif
	cmp	r5, #ATAG_CORE_SIZE		@ is first tag ATAG_CORE?
	cmpne	r5, #ATAG_CORE_SIZE_EMPTY
	bne	1f
	ldr	r5, [r2, #4]
	ldr	r6, =ATAG_CORE
	cmp	r5, r6
	bne	1f

2:	mov	pc, lr				@ atag/dtb pointer is ok

1:	mov	r2, #0
	mov	pc, lr
ENDPROC(__vet_atags)

/*
 * The following fragment of code is executed with the MMU on in MMU mode,
 * and uses absolute addresses; this is not position independent.
  * 다음 코드는 MMU 모드에서 MMU를 이용하여 수행 되고,
 * 절대 주소를 사용합니다; position(주소) 종속
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags/dtb pointer
 *  r9  = processor ID
 */
	__INIT
__mmap_switched:
	adr	r3, __mmap_switched_data

	ldmia	r3!, {r4, r5, r6, r7}
	cmp	r4, r5				@ Copy data segment if needed
// CONFIG_XIP_KERNEL이 켜져 있으면 r4, r5는 다른 값을 가짐
// 따라서 실행되지 않음.
1:	cmpne	r5, r6
	ldrne	fp, [r4], #4			//r9(sb), r10(sl), r11(fp), r12(ip), r13(sp), r14(lr), r15(pc)
	strne	fp, [r5], #4
	bne	1b

	mov	fp, #0				@ Clear BSS (and zero fp)
1:	cmp	r6, r7
	strcc	fp, [r6],#4			//cc: carry clear (=lt)
	bcc	1b

// 2013/08/17 종료
 ARM(	ldmia	r3, {r4, r5, r6, r7, sp})	// processor id 부터 읽어옴.
 THUMB(	ldmia	r3, {r4, r5, r6, r7}	)
 THUMB(	ldr	sp, [r3, #16]		)
	str	r9, [r4]			@ Save processor ID
	str	r1, [r5]			@ Save machine type
	str	r2, [r6]			@ Save atags pointer
	cmp	r7, #0
	bicne	r4, r0, #CR_A			@ Clear 'A' bit
	stmneia	r7, {r0, r4}			@ Save control register values
	b	start_kernel
ENDPROC(__mmap_switched)

	.align	2
	.type	__mmap_switched_data, %object
__mmap_switched_data:
	.long	__data_loc			@ r4
	.long	_sdata				@ r5
	.long	__bss_start			@ r6
	.long	_end				@ r7
	.long	processor_id			@ r4
	.long	__machine_arch_type		@ r5
	.long	__atags_pointer			@ r6
#ifdef CONFIG_CPU_CP15
	.long	cr_alignment			@ r7
#else
	.long	0				@ r7
#endif
	// ARM10C 20130817
	//FIXME: THREAD_START_SP(thread_info.h) 에서 8을 빼는 이유?
	//링크: http://forum.falinux.com/zbxe/?mid=lecture_tip&comment_srl=506039&document_srl=551428
	//링크: http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.faqs/ka4127.html
	.long	init_thread_union + THREAD_START_SP @ sp
	.size	__mmap_switched_data, . - __mmap_switched_data

/*
 * This provides a C-API version of __lookup_processor_type
 */
ENTRY(lookup_processor_type)
	stmfd	sp!, {r4 - r6, r9, lr}
	mov	r9, r0
	bl	__lookup_processor_type
	mov	r0, r5
	ldmfd	sp!, {r4 - r6, r9, pc}
ENDPROC(lookup_processor_type)

/*
 * Read processor ID register (CP#15, CR0), and look up in the linker-built
 * supported processor list.  Note that we can't use the absolute addresses
 * for the __proc_info lists since we aren't running with the MMU on
 * (and therefore, we are not in the correct address space).  We have to
 * calculate the offset.
 *
 * 프로세스 ID 레지스터(CP#15, CR0) 읽어
 * linker-built에서 지원되는 프로세스 리스트를 찾아봄.
 *  __proc_info lists에 대한 절대주소를 사용할 수 없음.
 * MMU를 이용하여 실행하는 것이 아니기 때문입니다.
 * offset 값을 계산해야 합니다.

 *
 *	r9 = cpuid
 * Returns:
 *	r3, r4, r6 corrupted (변수로 사용)
 *	r5 = proc_info pointer in physical address space
 *       물리적인 주조 공간에서 proc_info 포인터
 *	r9 = cpuid (preserved)
 */
	// #define __CPUINIT        .section	".cpuinit.text", "ax"
	__CPUINIT
__lookup_processor_type:
	adr	r3, __lookup_processor_type_data
	ldmia	r3, {r4 - r6}
	sub	r3, r3, r4			@ get offset between virt&phys
	add	r5, r5, r3			@ convert virt addresses to
	add	r6, r6, r3			@ physical address space
	// arch/mm/proc-v7.S 의 아래의 값을 r3, r4에 로드함
	// __v7_ca15mp_proc_info:
	// .long	0x410fc0f0
	// .long	0xff0ffff0
1:	ldmia	r5, {r3, r4}			@ value, mask
	and	r4, r4, r9			@ mask wanted bits
	teq	r3, r4
	beq	2f
	add	r5, r5, #PROC_INFO_SZ		@ sizeof(proc_info_list)
	cmp	r5, r6
	blo	1b
	mov	r5, #0				@ unknown processor
2:	mov	pc, lr
ENDPROC(__lookup_processor_type)

/*
 * Look in <asm/procinfo.h> for information about the __proc_info structure.
 */
	.align	2
	.type	__lookup_processor_type_data, %object
__lookup_processor_type_data:
	// arch/mm/proc-v7.S 에 정의 되어 있음
	.long	.				// r4 에 로드됨
	.long	__proc_info_begin		// r5 에 로드됨
	.long	__proc_info_end			// r6 에 로드됨
	.size	__lookup_processor_type_data, . - __lookup_processor_type_data

__error_p:
#ifdef CONFIG_DEBUG_LL
	adr	r0, str_p1
	bl	printascii
	mov	r0, r9
	bl	printhex8
	adr	r0, str_p2
	bl	printascii
	b	__error
str_p1:	.asciz	"\nError: unrecognized/unsupported processor variant (0x"
str_p2:	.asciz	").\n"
	.align
#endif
ENDPROC(__error_p)

__error:
#ifdef CONFIG_ARCH_RPC
/*
 * Turn the screen red on a error - RiscPC only.
 */
	mov	r0, #0x02000000
	mov	r3, #0x11
	orr	r3, r3, r3, lsl #8
	orr	r3, r3, r3, lsl #16
	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
#endif
1:	mov	r0, r0
	b	1b
ENDPROC(__error)
