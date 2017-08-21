/*
 *  linux/arch/arm/kernel/entry-armv.S
 *
 *  Copyright (C) 1996,1997,1998 Russell King.
 *  ARM700 fix by Matthew Godbolt (linux-user@willothewisp.demon.co.uk)
 *  nommu support by Hyok S. Choi (hyok.choi@samsung.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  Low-level vector interface routines
 *
 *  Note:  there is a StrongARM bug in the STMIA rn, {regs}^ instruction
 *  that causes it to save wrong values...  Be aware!
 */

#include <asm/assembler.h>
#include <asm/memory.h>
#include <asm/glue-df.h>
#include <asm/glue-pf.h>
#include <asm/vfpmacros.h>
#ifndef CONFIG_MULTI_IRQ_HANDLER
#include <mach/entry-macro.S>
#endif
#include <asm/thread_notify.h>
#include <asm/unwind.h>
#include <asm/unistd.h>
#include <asm/tls.h>
#include <asm/system_info.h>

#include "entry-header.S"
#include <asm/entry-macro-multi.S>

/*
 * Interrupt handling.
 */
 // ARM10C 20141227
	.macro	irq_handler
#ifdef CONFIG_MULTI_IRQ_HANDLER // CONFIG_MULTI_IRQ_HANDLER=y
	// handle_arch_irq: gic_handle_irq
	ldr	r1, =handle_arch_irq
	// r1: gic_handle_irq

	// sp: sp 처음위치 - 140
	mov	r0, sp
	// r0: sp 처음위치 - 140

	adr	lr, BSYM(9997f)
	// lr: symbol 9997의 상대주소값

	// r1: gic_handle_irq
	ldr	pc, [r1]
	// pc: gic_handle_irq
	// gic_handle_irq symbol로 jump
#else
	arch_irq_handler_default
#endif
9997:
	.endm

	.macro	pabt_helper
	@ PABORT handler takes pt_regs in r2, fault address in r4 and psr in r5
#ifdef MULTI_PABORT
	ldr	ip, .LCprocfns
	mov	lr, pc
	ldr	pc, [ip, #PROCESSOR_PABT_FUNC]
#else
	bl	CPU_PABORT_HANDLER
#endif
	.endm

	.macro	dabt_helper

	@
	@ Call the processor-specific abort handler:
	@
	@  r2 - pt_regs
	@  r4 - aborted context pc
	@  r5 - aborted context psr
	@
	@ The abort handler must return the aborted address in r0, and
	@ the fault status register in r1.  r9 must be preserved.
	@
#ifdef MULTI_DABORT
	ldr	ip, .LCprocfns
	mov	lr, pc
	ldr	pc, [ip, #PROCESSOR_DABT_FUNC]
#else
	bl	CPU_DABORT_HANDLER
#endif
	.endm

#ifdef CONFIG_KPROBES
	.section	.kprobes.text,"ax",%progbits
#else
	.text
#endif

/*
 * Invalid mode handlers
 */
	.macro	inv_entry, reason
	sub	sp, sp, #S_FRAME_SIZE
 ARM(	stmib	sp, {r1 - lr}		)
 THUMB(	stmia	sp, {r0 - r12}		)
 THUMB(	str	sp, [sp, #S_SP]		)
 THUMB(	str	lr, [sp, #S_LR]		)
	mov	r1, #\reason
	.endm

__pabt_invalid:
	inv_entry BAD_PREFETCH
	b	common_invalid
ENDPROC(__pabt_invalid)

__dabt_invalid:
	inv_entry BAD_DATA
	b	common_invalid
ENDPROC(__dabt_invalid)

__irq_invalid:
	inv_entry BAD_IRQ
	b	common_invalid
ENDPROC(__irq_invalid)

__und_invalid:
	inv_entry BAD_UNDEFINSTR

	@
	@ XXX fall through to common_invalid
	@

@
@ common_invalid - generic code for failed exception (re-entrant version of handlers)
@
common_invalid:
	zero_fp

	ldmia	r0, {r4 - r6}
	add	r0, sp, #S_PC		@ here for interlock avoidance
	mov	r7, #-1			@  ""   ""    ""        ""
	str	r4, [sp]		@ save preserved r0
	stmia	r0, {r5 - r7}		@ lr_<exception>,
					@ cpsr_<exception>, "old_r0"

	mov	r0, sp
	b	bad_mode
ENDPROC(__und_invalid)

/*
 * SVC mode handlers
 */

#if defined(CONFIG_AEABI) && (__LINUX_ARM_ARCH__ >= 5) // CONFIG_AEABI=y, __LINUX_ARM_ARCH__=7
// ARM10C 20141227
#define SPFIX(code...) code
#else
#define SPFIX(code...)
#endif

// ARM10C 20141227
// r0: &(stacks[0].irq[0])
	.macro	svc_entry, stack_hole=0

// NOTE:
// G.A: The GNU Assembler manual의 약자임

// G.A: 9.3.4 ARM Machine Directives
// .fnstart: Marks the start of a function with an unwind table entry.
// .save reglist: Generate unwinder annotations to restore the registers in reglist.
// The format of reglist is the same as the corresponding store-multiple instruction.
 UNWIND(.fnstart		)
 UNWIND(.save {r0 - pc}		)
	// stack에 r0 ~ r15(pc) 까지 저장
	// sp: sp 처음위치 - 64

	// S_FRAME_SIZE: 72, stack_hole: 0
	sub	sp, sp, #(S_FRAME_SIZE + \stack_hole - 4)
	// sp: sp 처음위치 - 132

#ifdef CONFIG_THUMB2_KERNEL // CONFIG_THUMB2_KERNEL=n
 SPFIX(	str	r0, [sp]	)	@ temporarily saved
 SPFIX(	mov	r0, sp		)
 SPFIX(	tst	r0, #4		)	@ test original stack alignment
 SPFIX(	ldr	r0, [sp]	)	@ restored
#else
	// sp: sp 처음위치 - 132
 SPFIX(	tst	sp, #4		)
	// Z bit: 1
#endif
	// sp: sp 처음위치 - 132
 SPFIX(	subeq	sp, sp, #4	)
	// sp: sp 처음위치 - 136

	// sp: sp 처음위치 - 136
	stmia	sp, {r1 - r12}
	// sp: sp 처음위치 - 136 (r1 - r12 까지 순차로 저장, sp는 갱신 안함)

	// r0: &(stacks[0].irq[0])
	// stacks[0].irq[0]: r0: interrupt 발생시의 r0, stacks[0].irq[1]: lr: R14_irq: 복귀 주소
	// stacks[0].irq[2]: lr: R14_irq: interrupt 발생시 cpsr 값
	ldmia	r0, {r3 - r5}
	// r3: interrupt 발생시의 r0, r4: R14_irq: 복귀 주소, r5: interrupt 발생시 cpsr 값

	// sp: sp 처음위치 - 136, S_SP: 52
	add	r7, sp, #S_SP - 4	@ here for interlock avoidance
	// r7: sp 처음위치 - 88

	mov	r6, #-1			@  ""  ""      ""       ""
	// r6: -1

	// sp: sp 처음위치 - 136, S_FRAME_SIZE: 72, stack_hole: 0
	add	r2, sp, #(S_FRAME_SIZE + \stack_hole - 4)
	// r2: sp 처음위치 - 68

	// r2: sp 처음위치 - 68
 SPFIX(	addeq	r2, r2, #4	)
	// r2: sp 처음위치 - 64

	// r3: interrupt 발생시의 r0, sp: sp 처음위치 - 136
	str	r3, [sp, #-4]!		@ save the "real" r0 copied
					@ from the exception stack
	// sp: sp 처음위치 - 140, *(sp 처음위치 - 136): interrupt 발생시의 r0

	// lr: R14_svc
	mov	r3, lr
	// r3: R14_svc

	@
	@ We are now ready to fill in the remaining blanks on the stack:
	@
	@  r2 - sp_svc
	@  r3 - lr_svc
	@  r4 - lr_<exception>, already fixed up for correct return/restart
	@  r5 - spsr_<exception>
	@  r6 - orig_r0 (see pt_regs definition in ptrace.h)
	@
	// r7: sp 처음위치 - 88,
	// r2: sp 처음위치 - 64, r3: R14_svc, r4: R14_irq: 복귀 주소, r5: interrupt 발생시 cpsr 값, r6: -1
	stmia	r7, {r2 - r6}
	// *(sp 처음위치 - 88): sp 처음위치 - 64,
	// *(sp 처음위치 - 84): R14_svc
	// *(sp 처음위치 - 80): R14_irq: 복귀 주소
	// *(sp 처음위치 - 76): interrupt 발생시 cpsr 값
	// *(sp 처음위치 - 72): -1


#ifdef CONFIG_TRACE_IRQFLAGS // CONFIG_TRACE_IRQFLAGS=n
	bl	trace_hardirqs_off
#endif
	.endm

	.align	5
__dabt_svc:
	svc_entry
	mov	r2, sp
	dabt_helper
 THUMB(	ldr	r5, [sp, #S_PSR]	)	@ potentially updated CPSR
	svc_exit r5				@ return from exception
 UNWIND(.fnend		)
ENDPROC(__dabt_svc)

	.align	5
// ARM10C 20141227
// r0: &(stacks[0].irq[0])
__irq_svc:
	svc_entry
	/*
	//  svc_entry가 한일:
	//  irq_handler 에서 사용하기 위한 stack frame을 아래의 그림과 같이 구성함
	//
	// HIGH +--------------------------+ <-- SP 처음위치
	// ADDR |          PC (R15)        |
	//      +--------------------------+
	//      |          LR (R14)        |
	//      +--------------------------+
	//      |            ...           |
	//      +--------------------------+
	//      |            R1            |
	//      +--------------------------+
	//      |            R0            |
	//      +--------------------------+ <-- SP 처음위치 - 64
	//      |                          |
	//      +--------------------------+ <-- SP 처음위치 - 68
	//      |            -1            |
	//      +--------------------------+ <-- SP 처음위치 - 72
	//      | interrupt 발생시 cpsr 값 |
	//      +--------------------------+ <-- SP 처음위치 - 76
	//      |    R14_irq: 복귀 주소    |
	//      +--------------------------+ <-- SP 처음위치 - 80
	//      | interrupt 발생시 R14_svc |
	//      +--------------------------+ <-- SP 처음위치 - 84
	//      |      sp 처음위치 - 64    |
	//      +--------------------------+ <-- SP 처음위치 - 88
	//      |   interrupt 발생시 R12   |
	//      +--------------------------+
	//      |           ...            |
	//      +--------------------------+
	//      |   interrupt 발생시 R1    |
	//      +--------------------------+ <-- SP 처음위치 - 136
	// LOW  |   interrupt 발생시 R0    |
	// ADDR +--------------------------+ <-- SP (SP 처음위치 - 140)
	*/

	irq_handler

#ifdef CONFIG_PREEMPT
	get_thread_info tsk
	ldr	r8, [tsk, #TI_PREEMPT]		@ get preempt count
	ldr	r0, [tsk, #TI_FLAGS]		@ get flags
	teq	r8, #0				@ if preempt count != 0
	movne	r0, #0				@ force flags to 0
	tst	r0, #_TIF_NEED_RESCHED
	blne	svc_preempt
#endif

	svc_exit r5, irq = 1			@ return from exception
 UNWIND(.fnend		)
ENDPROC(__irq_svc)

	.ltorg

#ifdef CONFIG_PREEMPT
svc_preempt:
	mov	r8, lr
1:	bl	preempt_schedule_irq		@ irq en/disable is done inside
	ldr	r0, [tsk, #TI_FLAGS]		@ get new tasks TI_FLAGS
	tst	r0, #_TIF_NEED_RESCHED
	moveq	pc, r8				@ go again
	b	1b
#endif

__und_fault:
	@ Correct the PC such that it is pointing at the instruction
	@ which caused the fault.  If the faulting instruction was ARM
	@ the PC will be pointing at the next instruction, and have to
	@ subtract 4.  Otherwise, it is Thumb, and the PC will be
	@ pointing at the second half of the Thumb instruction.  We
	@ have to subtract 2.
	ldr	r2, [r0, #S_PC]
	sub	r2, r2, r1
	str	r2, [r0, #S_PC]
	b	do_undefinstr
ENDPROC(__und_fault)

	.align	5
__und_svc:
#ifdef CONFIG_KPROBES
	@ If a kprobe is about to simulate a "stmdb sp..." instruction,
	@ it obviously needs free stack space which then will belong to
	@ the saved context.
	svc_entry 64
#else
	svc_entry
#endif
	@
	@ call emulation code, which returns using r9 if it has emulated
	@ the instruction, or the more conventional lr if we are to treat
	@ this as a real undefined instruction
	@
	@  r0 - instruction
	@
#ifndef CONFIG_THUMB2_KERNEL
	ldr	r0, [r4, #-4]
#else
	mov	r1, #2
	ldrh	r0, [r4, #-2]			@ Thumb instruction at LR - 2
	cmp	r0, #0xe800			@ 32-bit instruction if xx >= 0
	blo	__und_svc_fault
	ldrh	r9, [r4]			@ bottom 16 bits
	add	r4, r4, #2
	str	r4, [sp, #S_PC]
	orr	r0, r9, r0, lsl #16
#endif
	adr	r9, BSYM(__und_svc_finish)
	mov	r2, r4
	bl	call_fpe

	mov	r1, #4				@ PC correction to apply
__und_svc_fault:
	mov	r0, sp				@ struct pt_regs *regs
	bl	__und_fault

__und_svc_finish:
	ldr	r5, [sp, #S_PSR]		@ Get SVC cpsr
	svc_exit r5				@ return from exception
 UNWIND(.fnend		)
ENDPROC(__und_svc)

	.align	5
__pabt_svc:
	svc_entry
	mov	r2, sp				@ regs
	pabt_helper
	svc_exit r5				@ return from exception
 UNWIND(.fnend		)
ENDPROC(__pabt_svc)

	.align	5
.LCcralign:
	.word	cr_alignment
#ifdef MULTI_DABORT
.LCprocfns:
	.word	processor
#endif
.LCfp:
	.word	fp_enter

/*
 * User mode handlers
 *
 * EABI note: sp_svc is always 64-bit aligned here, so should S_FRAME_SIZE
 */

#if defined(CONFIG_AEABI) && (__LINUX_ARM_ARCH__ >= 5) && (S_FRAME_SIZE & 7)
#error "sizeof(struct pt_regs) must be a multiple of 8"
#endif

	.macro	usr_entry
 UNWIND(.fnstart	)
 UNWIND(.cantunwind	)	@ don't unwind the user space
	sub	sp, sp, #S_FRAME_SIZE
 ARM(	stmib	sp, {r1 - r12}	)
 THUMB(	stmia	sp, {r0 - r12}	)

	ldmia	r0, {r3 - r5}
	add	r0, sp, #S_PC		@ here for interlock avoidance
	mov	r6, #-1			@  ""  ""     ""        ""

	str	r3, [sp]		@ save the "real" r0 copied
					@ from the exception stack

	@
	@ We are now ready to fill in the remaining blanks on the stack:
	@
	@  r4 - lr_<exception>, already fixed up for correct return/restart
	@  r5 - spsr_<exception>
	@  r6 - orig_r0 (see pt_regs definition in ptrace.h)
	@
	@ Also, separately save sp_usr and lr_usr
	@
	stmia	r0, {r4 - r6}
 ARM(	stmdb	r0, {sp, lr}^			)
 THUMB(	store_user_sp_lr r0, r1, S_SP - S_PC	)

	@
	@ Enable the alignment trap while in kernel mode
	@
	alignment_trap r0

	@
	@ Clear FP to mark the first stack frame
	@
	zero_fp

#ifdef CONFIG_IRQSOFF_TRACER
	bl	trace_hardirqs_off
#endif
	ct_user_exit save = 0
	.endm

	.macro	kuser_cmpxchg_check
#if !defined(CONFIG_CPU_32v6K) && defined(CONFIG_KUSER_HELPERS) && \
    !defined(CONFIG_NEEDS_SYSCALL_FOR_CMPXCHG)
#ifndef CONFIG_MMU
#warning "NPTL on non MMU needs fixing"
#else
	@ Make sure our user space atomic helper is restarted
	@ if it was interrupted in a critical region.  Here we
	@ perform a quick test inline since it should be false
	@ 99.9999% of the time.  The rest is done out of line.
	cmp	r4, #TASK_SIZE
	blhs	kuser_cmpxchg64_fixup
#endif
#endif
	.endm

	.align	5
__dabt_usr:
	usr_entry
	kuser_cmpxchg_check
	mov	r2, sp
	dabt_helper
	b	ret_from_exception
 UNWIND(.fnend		)
ENDPROC(__dabt_usr)

	.align	5
__irq_usr:
	usr_entry
	kuser_cmpxchg_check
	irq_handler
	get_thread_info tsk
	mov	why, #0
	b	ret_to_user_from_irq
 UNWIND(.fnend		)
ENDPROC(__irq_usr)

	.ltorg

	.align	5
__und_usr:
	usr_entry

	mov	r2, r4
	mov	r3, r5

	@ r2 = regs->ARM_pc, which is either 2 or 4 bytes ahead of the
	@      faulting instruction depending on Thumb mode.
	@ r3 = regs->ARM_cpsr
	@
	@ The emulation code returns using r9 if it has emulated the
	@ instruction, or the more conventional lr if we are to treat
	@ this as a real undefined instruction
	@
	adr	r9, BSYM(ret_from_exception)

	tst	r3, #PSR_T_BIT			@ Thumb mode?
	bne	__und_usr_thumb
	sub	r4, r2, #4			@ ARM instr at LR - 4
1:	ldrt	r0, [r4]
 ARM_BE8(rev	r0, r0)				@ little endian instruction

	@ r0 = 32-bit ARM instruction which caused the exception
	@ r2 = PC value for the following instruction (:= regs->ARM_pc)
	@ r4 = PC value for the faulting instruction
	@ lr = 32-bit undefined instruction function
	adr	lr, BSYM(__und_usr_fault_32)
	b	call_fpe

__und_usr_thumb:
	@ Thumb instruction
	sub	r4, r2, #2			@ First half of thumb instr at LR - 2
#if CONFIG_ARM_THUMB && __LINUX_ARM_ARCH__ >= 6 && CONFIG_CPU_V7
/*
 * Thumb-2 instruction handling.  Note that because pre-v6 and >= v6 platforms
 * can never be supported in a single kernel, this code is not applicable at
 * all when __LINUX_ARM_ARCH__ < 6.  This allows simplifying assumptions to be
 * made about .arch directives.
 */
#if __LINUX_ARM_ARCH__ < 7
/* If the target CPU may not be Thumb-2-capable, a run-time check is needed: */
#define NEED_CPU_ARCHITECTURE
	ldr	r5, .LCcpu_architecture
	ldr	r5, [r5]
	cmp	r5, #CPU_ARCH_ARMv7
	blo	__und_usr_fault_16		@ 16bit undefined instruction
/*
 * The following code won't get run unless the running CPU really is v7, so
 * coding round the lack of ldrht on older arches is pointless.  Temporarily
 * override the assembler target arch with the minimum required instead:
 */
	.arch	armv6t2
#endif
2:	ldrht	r5, [r4]
	cmp	r5, #0xe800			@ 32bit instruction if xx != 0
	blo	__und_usr_fault_16		@ 16bit undefined instruction
3:	ldrht	r0, [r2]
	add	r2, r2, #2			@ r2 is PC + 2, make it PC + 4
	str	r2, [sp, #S_PC]			@ it's a 2x16bit instr, update
	orr	r0, r0, r5, lsl #16
	adr	lr, BSYM(__und_usr_fault_32)
	@ r0 = the two 16-bit Thumb instructions which caused the exception
	@ r2 = PC value for the following Thumb instruction (:= regs->ARM_pc)
	@ r4 = PC value for the first 16-bit Thumb instruction
	@ lr = 32bit undefined instruction function

#if __LINUX_ARM_ARCH__ < 7
/* If the target arch was overridden, change it back: */
#ifdef CONFIG_CPU_32v6K
	.arch	armv6k
#else
	.arch	armv6
#endif
#endif /* __LINUX_ARM_ARCH__ < 7 */
#else /* !(CONFIG_ARM_THUMB && __LINUX_ARM_ARCH__ >= 6 && CONFIG_CPU_V7) */
	b	__und_usr_fault_16
#endif
 UNWIND(.fnend)
ENDPROC(__und_usr)

/*
 * The out of line fixup for the ldrt instructions above.
 */
	.pushsection .fixup, "ax"
	.align	2
4:	mov	pc, r9
	.popsection
/* ARM10C 20140329 */
	.pushsection __ex_table,"a"
	.long	1b, 4b
#if CONFIG_ARM_THUMB && __LINUX_ARM_ARCH__ >= 6 && CONFIG_CPU_V7
	.long	2b, 4b
	.long	3b, 4b
#endif
	.popsection

/*
 * Check whether the instruction is a co-processor instruction.
 * If yes, we need to call the relevant co-processor handler.
 *
 * Note that we don't do a full check here for the co-processor
 * instructions; all instructions with bit 27 set are well
 * defined.  The only instructions that should fault are the
 * co-processor instructions.  However, we have to watch out
 * for the ARM6/ARM7 SWI bug.
 *
 * NEON is a special case that has to be handled here. Not all
 * NEON instructions are co-processor instructions, so we have
 * to make a special case of checking for them. Plus, there's
 * five groups of them, so we have a table of mask/opcode pairs
 * to check against, and if any match then we branch off into the
 * NEON handler code.
 *
 * Emulators may wish to make use of the following registers:
 *  r0  = instruction opcode (32-bit ARM or two 16-bit Thumb)
 *  r2  = PC value to resume execution after successful emulation
 *  r9  = normal "successful" return address
 *  r10 = this threads thread_info structure
 *  lr  = unrecognised instruction return address
 * IRQs disabled, FIQs enabled.
 */
	@
	@ Fall-through from Thumb-2 __und_usr
	@
#ifdef CONFIG_NEON
	get_thread_info r10			@ get current thread
	adr	r6, .LCneon_thumb_opcodes
	b	2f
#endif
call_fpe:
	get_thread_info r10			@ get current thread
#ifdef CONFIG_NEON
	adr	r6, .LCneon_arm_opcodes
2:	ldr	r5, [r6], #4			@ mask value
	ldr	r7, [r6], #4			@ opcode bits matching in mask
	cmp	r5, #0				@ end mask?
	beq	1f
	and	r8, r0, r5
	cmp	r8, r7				@ NEON instruction?
	bne	2b
	mov	r7, #1
	strb	r7, [r10, #TI_USED_CP + 10]	@ mark CP#10 as used
	strb	r7, [r10, #TI_USED_CP + 11]	@ mark CP#11 as used
	b	do_vfp				@ let VFP handler handle this
1:
#endif
	tst	r0, #0x08000000			@ only CDP/CPRT/LDC/STC have bit 27
	tstne	r0, #0x04000000			@ bit 26 set on both ARM and Thumb-2
	moveq	pc, lr
	and	r8, r0, #0x00000f00		@ mask out CP number
 THUMB(	lsr	r8, r8, #8		)
	mov	r7, #1
	add	r6, r10, #TI_USED_CP
 ARM(	strb	r7, [r6, r8, lsr #8]	)	@ set appropriate used_cp[]
 THUMB(	strb	r7, [r6, r8]		)	@ set appropriate used_cp[]
#ifdef CONFIG_IWMMXT
	@ Test if we need to give access to iWMMXt coprocessors
	ldr	r5, [r10, #TI_FLAGS]
	rsbs	r7, r8, #(1 << 8)		@ CP 0 or 1 only
	movcss	r7, r5, lsr #(TIF_USING_IWMMXT + 1)
	bcs	iwmmxt_task_enable
#endif
 ARM(	add	pc, pc, r8, lsr #6	)
 THUMB(	lsl	r8, r8, #2		)
 THUMB(	add	pc, r8			)
	nop

	movw_pc	lr				@ CP#0
	W(b)	do_fpe				@ CP#1 (FPE)
	W(b)	do_fpe				@ CP#2 (FPE)
	movw_pc	lr				@ CP#3
#ifdef CONFIG_CRUNCH
	b	crunch_task_enable		@ CP#4 (MaverickCrunch)
	b	crunch_task_enable		@ CP#5 (MaverickCrunch)
	b	crunch_task_enable		@ CP#6 (MaverickCrunch)
#else
	movw_pc	lr				@ CP#4
	movw_pc	lr				@ CP#5
	movw_pc	lr				@ CP#6
#endif
	movw_pc	lr				@ CP#7
	movw_pc	lr				@ CP#8
	movw_pc	lr				@ CP#9
#ifdef CONFIG_VFP
	W(b)	do_vfp				@ CP#10 (VFP)
	W(b)	do_vfp				@ CP#11 (VFP)
#else
	movw_pc	lr				@ CP#10 (VFP)
	movw_pc	lr				@ CP#11 (VFP)
#endif
	movw_pc	lr				@ CP#12
	movw_pc	lr				@ CP#13
	movw_pc	lr				@ CP#14 (Debug)
	movw_pc	lr				@ CP#15 (Control)

#ifdef NEED_CPU_ARCHITECTURE
	.align	2
.LCcpu_architecture:
	.word	__cpu_architecture
#endif

#ifdef CONFIG_NEON
	.align	6

.LCneon_arm_opcodes:
	.word	0xfe000000			@ mask
	.word	0xf2000000			@ opcode

	.word	0xff100000			@ mask
	.word	0xf4000000			@ opcode

	.word	0x00000000			@ mask
	.word	0x00000000			@ opcode

.LCneon_thumb_opcodes:
	.word	0xef000000			@ mask
	.word	0xef000000			@ opcode

	.word	0xff100000			@ mask
	.word	0xf9000000			@ opcode

	.word	0x00000000			@ mask
	.word	0x00000000			@ opcode
#endif

do_fpe:
	enable_irq
	ldr	r4, .LCfp
	add	r10, r10, #TI_FPSTATE		@ r10 = workspace
	ldr	pc, [r4]			@ Call FP module USR entry point

/*
 * The FP module is called with these registers set:
 *  r0  = instruction
 *  r2  = PC+4
 *  r9  = normal "successful" return address
 *  r10 = FP workspace
 *  lr  = unrecognised FP instruction return address
 */

	.pushsection .data
ENTRY(fp_enter)
	.word	no_fp
	.popsection

ENTRY(no_fp)
	mov	pc, lr
ENDPROC(no_fp)

__und_usr_fault_32:
	mov	r1, #4
	b	1f
__und_usr_fault_16:
	mov	r1, #2
1:	enable_irq
	mov	r0, sp
	adr	lr, BSYM(ret_from_exception)
	b	__und_fault
ENDPROC(__und_usr_fault_32)
ENDPROC(__und_usr_fault_16)

	.align	5
__pabt_usr:
	usr_entry
	mov	r2, sp				@ regs
	pabt_helper
 UNWIND(.fnend		)
	/* fall through */
/*
 * This is the return code to user mode for abort handlers
 */
ENTRY(ret_from_exception)
 UNWIND(.fnstart	)
 UNWIND(.cantunwind	)
	get_thread_info tsk
	mov	why, #0
	b	ret_to_user
 UNWIND(.fnend		)
ENDPROC(__pabt_usr)
ENDPROC(ret_from_exception)

/*
 * Register switch for ARMv3 and ARMv4 processors
 * r0 = previous task_struct, r1 = previous thread_info, r2 = next thread_info
 * previous and next are guaranteed not to be the same.
 */
/*
 * r0-r15 및 R0-R15
 * a1-a4 (인수, 결과 또는 스크래치 레지스터, r0 ~ r3의 동의어)
 * v1-v8 (변수 레지스터, r4 ~ r11)
 * sb 및 SB (정적 기준, r9)
 * ip 및 IP (내부 프로시저 호출 스크래치 레지스터, r12)
 * sp 및 SP (스택 포인터, r13)
 * lr 및 LR (링크 레지스터, r14)
 * pc 및 PC (프로그램 카운터, r15))

 * ARM Registers
 * General-purpose registers 
 * 32 bits in size 
 * Data 나 주소를 저장 
 * 18 active registers in user mode 
 * 16 data registers : r0 to r15 
 * 2 processor status registers : cpsr, spsr 
 * 프로세서의 모드에 따라 프로그래머가 사용할 수 있는 register가 다르다.
 * r0-r3 
 * Argument, result, scratch 
 * r0-r3의 내용이 다시 필요하면 calling routine이 r0-r3의 내용을 보존하여야 함.
 * r4-r7 
 * Variable register (ARM 과 Thumb 양쪽) 
 * Called routine이 이 register를 사용하였다면, 돌아가기 전에 그 내용을 복원하여야 한다.
 * r8 
 * ARM variable register 
 * Called routine이 이 register를 사용하였다면, 돌아가기 전에 그 내용을 복원하여야 한다.
 * r9 
 * ARM variable register 
 * Read-Write Position Independence에서 static base (sb) register 
 * Called routine이 이 register를 사용하였다면, 돌아가기 전에 그 내용을 복원하여야 한다. 
 * r10 
 * ARM variable register 
 * Stack check이 일어날 때  stack limit (sl) potinter 
 * Called routine이 이 register를 사용하였다면, 돌아가기 전에 그 내용을 복원하여야 한다.
 * r11 
 * ARM variable register 
 * Called routine이 이 register를 사용하였다면, 돌아가기 전에 그 내용을 복원하여야 한다.
 * r12 
 * ARM variable register (ip, intra-procedure-call scratch register) 
 * Procedure linkage veneer (ARM-Thumb)에 사용 
 * Called routine이 이 register를 사용하였더라도, 돌아가기 전에 그 내용을 복원할 필요가 없다.
 * r13 
 * Stack pointer (sp) 
 * 현재 프로세서 모드의 stack top을 가리킨다. 
 * Called routine의 exit에서 이 register의 값은 entry에서 값과 같아야 한다.
 * r14 
 * Link register (lr) 
 * Subroutine을 부를 때 return address를 저장한다. 
 * Return 주소를 메모리에 저장하면 이 register를 자유로이 사용할 수 있다.
 * r15 
 * Program counter (pc) 
 * 프로세서에 의해 fetch될 다음 instruction 주소를 가진다. 
 * 다른 용도로 사용할 수 없다.
 * 주의 
 * r13 과 r14 는 general-purpose register로도 쓰일 수 있다. 
 * 하지만,  r13 을 general-purpose register로 쓰는 것은 위험하다. 
 * OS는 r13 가 항상 유효한 stack frame을 가리키는 것으로 가정한다.
 */
// ARM10C 20170819
// &init_task, &init_task (struct thread_info), kmem_cache#15-oX (struct thread_info) (pid: 1)
ENTRY(__switch_to)
 UNWIND(.fnstart	)
 UNWIND(.cantunwind	)
	 // r1: &init_task (struct thread_info), TI_CPU_SAVE: 28
	add	ip, r1, #TI_CPU_SAVE
	// ip: (&init_task (struct thread_info))->cpu_context

	// ip: (&init_task (struct thread_info))->cpu_context
 ARM(	stmia	ip!, {r4 - sl, fp, sp, lr} )	@ Store most regs on stack
	// (&init_task (struct thread_info))->cpu_context 의 맴버값 r4-pc 가 순차적으로 저장툄

 THUMB(	stmia	ip!, {r4 - sl, fp}	   )	@ Store most regs on stack
 THUMB(	str	sp, [ip], #4		   )
 THUMB(	str	lr, [ip], #4		   )
	 // TI_TP_VALUE: 96
	ldr	r4, [r2, #TI_TP_VALUE]
	ldr	r5, [r2, #TI_TP_VALUE + 4]
#ifdef CONFIG_CPU_USE_DOMAINS // CONFIG_CPU_USE_DOMAINS=n
	ldr	r6, [r2, #TI_CPU_DOMAIN]
#endif
	switch_tls r1, r4, r5, r3, r7
#if defined(CONFIG_CC_STACKPROTECTOR) && !defined(CONFIG_SMP) // CONFIG_CC_STACKPROTECTOR=n, CONFIG_SMP=y
	ldr	r7, [r2, #TI_TASK]
	ldr	r8, =__stack_chk_guard
	ldr	r7, [r7, #TSK_STACK_CANARY]
#endif
#ifdef CONFIG_CPU_USE_DOMAINS // CONFIG_CPU_USE_DOMAINS=n
	mcr	p15, 0, r6, c3, c0, 0		@ Set domain register
#endif
	mov	r5, r0
	add	r4, r2, #TI_CPU_SAVE
	ldr	r0, =thread_notify_head
	mov	r1, #THREAD_NOTIFY_SWITCH
	bl	atomic_notifier_call_chain
#if defined(CONFIG_CC_STACKPROTECTOR) && !defined(CONFIG_SMP) // CONFIG_CC_STACKPROTECTOR=n, CONFIG_SMP=y
	str	r7, [r8]
#endif
 THUMB(	mov	ip, r4			   )
	mov	r0, r5
 ARM(	ldmia	r4, {r4 - sl, fp, sp, pc}  )	@ Load all regs saved previously
 THUMB(	ldmia	ip!, {r4 - sl, fp}	   )	@ Load all regs saved previously
 THUMB(	ldr	sp, [ip], #4		   )
 THUMB(	ldr	pc, [ip]		   )
 UNWIND(.fnend		)
ENDPROC(__switch_to)

	__INIT

/*
 * User helpers.
 *
 * Each segment is 32-byte aligned and will be moved to the top of the high
 * vector page.  New segments (if ever needed) must be added in front of
 * existing ones.  This mechanism should be used only for things that are
 * really small and justified, and not be abused freely.
 *
 * See Documentation/arm/kernel_user_helpers.txt for formal definitions.
 */
 THUMB(	.arm	)

	.macro	usr_ret, reg
#ifdef CONFIG_ARM_THUMB
	bx	\reg
#else
	mov	pc, \reg
#endif
	.endm

	.macro	kuser_pad, sym, size
	.if	(. - \sym) & 3
	.rept	4 - (. - \sym) & 3
	.byte	0
	.endr
	.endif
	.rept	(\size - (. - \sym)) / 4
	.word	0xe7fddef1
	.endr
	.endm

#ifdef CONFIG_KUSER_HELPERS // CONFIG_KUSER_HELPERS=y
// ARM10C 20131116
	.align	5
	.globl	__kuser_helper_start
__kuser_helper_start:

/*
 * Due to the length of some sequences, __kuser_cmpxchg64 spans 2 regular
 * kuser "slots", therefore 0xffff0f80 is not used as a valid entry point.
 */

__kuser_cmpxchg64:				@ 0xffff0f60

#if defined(CONFIG_NEEDS_SYSCALL_FOR_CMPXCHG)

	/*
	 * Poor you.  No fast solution possible...
	 * The kernel itself must perform the operation.
	 * A special ghost syscall is used for that (see traps.c).
	 */
	stmfd	sp!, {r7, lr}
	ldr	r7, 1f			@ it's 20 bits
	swi	__ARM_NR_cmpxchg64
	ldmfd	sp!, {r7, pc}
1:	.word	__ARM_NR_cmpxchg64

#elif defined(CONFIG_CPU_32v6K)

	stmfd	sp!, {r4, r5, r6, r7}
	ldrd	r4, r5, [r0]			@ load old val
	ldrd	r6, r7, [r1]			@ load new val
	smp_dmb	arm
1:	ldrexd	r0, r1, [r2]			@ load current val
	eors	r3, r0, r4			@ compare with oldval (1)
	eoreqs	r3, r1, r5			@ compare with oldval (2)
	strexdeq r3, r6, r7, [r2]		@ store newval if eq
	teqeq	r3, #1				@ success?
	beq	1b				@ if no then retry
	smp_dmb	arm
	rsbs	r0, r3, #0			@ set returned val and C flag
	ldmfd	sp!, {r4, r5, r6, r7}
	usr_ret	lr

#elif !defined(CONFIG_SMP)

#ifdef CONFIG_MMU

	/*
	 * The only thing that can break atomicity in this cmpxchg64
	 * implementation is either an IRQ or a data abort exception
	 * causing another process/thread to be scheduled in the middle of
	 * the critical sequence.  The same strategy as for cmpxchg is used.
	 */
	stmfd	sp!, {r4, r5, r6, lr}
	ldmia	r0, {r4, r5}			@ load old val
	ldmia	r1, {r6, lr}			@ load new val
1:	ldmia	r2, {r0, r1}			@ load current val
	eors	r3, r0, r4			@ compare with oldval (1)
	eoreqs	r3, r1, r5			@ compare with oldval (2)
2:	stmeqia	r2, {r6, lr}			@ store newval if eq
	rsbs	r0, r3, #0			@ set return val and C flag
	ldmfd	sp!, {r4, r5, r6, pc}

	.text
kuser_cmpxchg64_fixup:
	@ Called from kuser_cmpxchg_fixup.
	@ r4 = address of interrupted insn (must be preserved).
	@ sp = saved regs. r7 and r8 are clobbered.
	@ 1b = first critical insn, 2b = last critical insn.
	@ If r4 >= 1b and r4 <= 2b then saved pc_usr is set to 1b.
	mov	r7, #0xffff0fff
	sub	r7, r7, #(0xffff0fff - (0xffff0f60 + (1b - __kuser_cmpxchg64)))
	subs	r8, r4, r7
	rsbcss	r8, r8, #(2b - 1b)
	strcs	r7, [sp, #S_PC]
#if __LINUX_ARM_ARCH__ < 6
	bcc	kuser_cmpxchg32_fixup
#endif
	mov	pc, lr
	.previous

#else
#warning "NPTL on non MMU needs fixing"
	mov	r0, #-1
	adds	r0, r0, #0
	usr_ret	lr
#endif

#else
#error "incoherent kernel configuration"
#endif

	kuser_pad __kuser_cmpxchg64, 64

__kuser_memory_barrier:				@ 0xffff0fa0
	smp_dmb	arm
	usr_ret	lr

	kuser_pad __kuser_memory_barrier, 32

__kuser_cmpxchg:				@ 0xffff0fc0

#if defined(CONFIG_NEEDS_SYSCALL_FOR_CMPXCHG)

	/*
	 * Poor you.  No fast solution possible...
	 * The kernel itself must perform the operation.
	 * A special ghost syscall is used for that (see traps.c).
	 */
	stmfd	sp!, {r7, lr}
	ldr	r7, 1f			@ it's 20 bits
	swi	__ARM_NR_cmpxchg
	ldmfd	sp!, {r7, pc}
1:	.word	__ARM_NR_cmpxchg

#elif __LINUX_ARM_ARCH__ < 6

#ifdef CONFIG_MMU

	/*
	 * The only thing that can break atomicity in this cmpxchg
	 * implementation is either an IRQ or a data abort exception
	 * causing another process/thread to be scheduled in the middle
	 * of the critical sequence.  To prevent this, code is added to
	 * the IRQ and data abort exception handlers to set the pc back
	 * to the beginning of the critical section if it is found to be
	 * within that critical section (see kuser_cmpxchg_fixup).
	 */
1:	ldr	r3, [r2]			@ load current val
	subs	r3, r3, r0			@ compare with oldval
2:	streq	r1, [r2]			@ store newval if eq
	rsbs	r0, r3, #0			@ set return val and C flag
	usr_ret	lr

	.text
kuser_cmpxchg32_fixup:
	@ Called from kuser_cmpxchg_check macro.
	@ r4 = address of interrupted insn (must be preserved).
	@ sp = saved regs. r7 and r8 are clobbered.
	@ 1b = first critical insn, 2b = last critical insn.
	@ If r4 >= 1b and r4 <= 2b then saved pc_usr is set to 1b.
	mov	r7, #0xffff0fff
	sub	r7, r7, #(0xffff0fff - (0xffff0fc0 + (1b - __kuser_cmpxchg)))
	subs	r8, r4, r7
	rsbcss	r8, r8, #(2b - 1b)
	strcs	r7, [sp, #S_PC]
	mov	pc, lr
	.previous

#else
#warning "NPTL on non MMU needs fixing"
	mov	r0, #-1
	adds	r0, r0, #0
	usr_ret	lr
#endif

#else

	smp_dmb	arm
1:	ldrex	r3, [r2]
	subs	r3, r3, r0
	strexeq	r3, r1, [r2]
	teqeq	r3, #1
	beq	1b
	rsbs	r0, r3, #0
	/* beware -- each __kuser slot must be 8 instructions max */
	ALT_SMP(b	__kuser_memory_barrier)
	ALT_UP(usr_ret	lr)

#endif

	kuser_pad __kuser_cmpxchg, 32

__kuser_get_tls:				@ 0xffff0fe0
	ldr	r0, [pc, #(16 - 8)]	@ read TLS, set in kuser_get_tls_init
	usr_ret	lr
	mrc	p15, 0, r0, c13, c0, 3	@ 0xffff0fe8 hardware TLS code
	kuser_pad __kuser_get_tls, 16
	.rep	3
	.word	0			@ 0xffff0ff0 software TLS value, then
	.endr				@ pad up to __kuser_helper_version

__kuser_helper_version:				@ 0xffff0ffc
	.word	((__kuser_helper_end - __kuser_helper_start) >> 5)

// ARM10C 20131116
	.globl	__kuser_helper_end
__kuser_helper_end:

#endif

 THUMB(	.thumb	)

/*
 * Vector stubs.
 *
 * This code is copied to 0xffff1000 so we can use branches in the
 * vectors, rather than ldr's.  Note that this code must not exceed
 * a page size.
 *
 * Common stub entry macro:
 *   Enter in IRQ mode, spsr = SVC/USR CPSR, lr = SVC/USR PC
 *
 * SP points to a minimal amount of processor-private memory, the address
 * of which is copied into r0 for the mode specific abort handler.
 */
	.macro	vector_stub, name, mode, correction=0
	.align	5

vector_\name:
	.if \correction
	sub	lr, lr, #\correction
	.endif

	@
	@ Save r0, lr_<exception> (parent PC) and spsr_<exception>
	@ (parent CPSR)
	@
	stmia	sp, {r0, lr}		@ save r0, lr
	mrs	lr, spsr
	str	lr, [sp, #8]		@ save spsr

	@
	@ Prepare for SVC32 mode.  IRQs remain disabled.
	@
	mrs	r0, cpsr
	eor	r0, r0, #(\mode ^ SVC_MODE | PSR_ISETSTATE)
	msr	spsr_cxsf, r0

	@
	@ the branch table must immediately follow this code
	@
	and	lr, lr, #0x0f
 THUMB(	adr	r0, 1f			)
 THUMB(	ldr	lr, [r0, lr, lsl #2]	)
	mov	r0, sp
 ARM(	ldr	lr, [pc, lr, lsl #2]	)
	movs	pc, lr			@ branch to handler in SVC mode
ENDPROC(vector_\name)

	.align	2
	@ handler addresses follow this label
1:
	.endm

	.section .stubs, "ax", %progbits
// ARM10C 20131109
// ARM10C 20141220
__stubs_start:
	@ This must be the first word
	.word	vector_swi

vector_rst:
 ARM(	swi	SYS_ERROR0	)
 THUMB(	svc	#0		)
 THUMB(	nop			)
	b	vector_und

/*
 * Interrupt dispatcher
 */
	// ARM10C 20141220
	// ARM10C 20141227
	vector_stub	irq, IRQ_MODE, 4
/*
	// NOTE: irq 발생시 arm processor가 자동으로 해주는 일
	// 1. PC를 R14_irq(LR) 에 저장
	// 2. CPSR를 SPSR_irq 에 저장
	// 3. CPSR의 mode bit를 irq mode로 변경
	// 4. PC값을 0xFFFF0018로 변경

	// NOTE: irq, abt, und의 stack 의 설정
	// cpu_init 에서 irq, abt, und 3개의 모드의 stack을 설정한 상태임

	// NOTE: correction 의 의미
	// interrupt가 발생한 이후에 interrupt handling 수행 후 복귀 시 실행해야할 명령어의 실행 주소를 계산
	// http://www.iamroot.org/xe/index.php?mid=Kernel_10_ARM&search_target=nick_name&search_keyword=%EB%A6%AC%EB%88%84%EC%A6%88%EB%B0%95&document_srl=158657

	vector_stub	irq, IRQ_MODE, 4 macro 확장 결과:

	.macro	vector_stub, irq, IRQ_MODE, correction=4
	.align	5

// 2014/12/20 종료
// 2014/12/27 시작
vector_irq:
	.if 4
	// lr: irq 발생시 PC 값
	sub	lr, lr, #4
	// lr: irq가 발생시 irq handler (vector_irq) 수행 후 실행 되어야할 명령어 주소
	.endif

	@
	@ Save r0, lr_<exception> (parent PC) and spsr_<exception>
	@ (parent CPSR)
	@
	// sp: R13_irq (stack pointer): &(stacks[0].irq[0]), r0: interrupt 발생시의 r0, lr: R14_irq: 복귀 주소
	stmia	sp, {r0, lr}		@ save r0, lr
	// R13_irq(sp) stack에 r0, lr 저장, r0를 저장하는 이유: 밑에서 사용하기 하기 때문
	// stacks[0].irq[0]: r0: interrupt 발생시의 r0, stacks[0].irq[1]: lr: R14_irq: 복귀 주소

	// lr: R14_irq, spsr: SPSR_irq: interrupt 발생시 cpsr 값
	mrs	lr, spsr
	// lr: R14_irq: interrupt 발생시 cpsr 값

	// lr: R14_irq: interrupt 발생시 cpsr 값, [sp, #8]: stacks[0].irq[2]
	str	lr, [sp, #8]		@ save spsr
	// stacks[0].irq[2]: lr: R14_irq: interrupt 발생시 cpsr 값

	@
	@ Prepare for SVC32 mode.  IRQs remain disabled.
	@
	// cpsr: irq 모드로 변경된 cpsr 값
	mrs	r0, cpsr
	// r0: irq 모드로 변경된 cpsr 값 (MODE BIT: 0x12)

	// r0: irq 모드로 변경된 cpsr 값 (MODE BIT: 0x12 - IRQ mode),
	// IRQ_MODE: 0x00000012, SVC_MODE: 0x00000013, PSR_ISETSTATE: 0
	eor	r0, r0, #(IRQ_MODE ^ SVC_MODE | PSR_ISETSTATE)
	// r0: irq 모드로 변경된 cpsr 값 (MODE BIT: 0x13)

	// spsr_cxsf: SPSR_irq, r0: irq 모드로 변경된 cpsr 값 (MODE BIT: 0x13)
	msr	spsr_cxsf, r0
	// spsr_cxsf: SPSR_irq: irq 모드로 변경된 cpsr 값 (MODE BIT: 0x13 - SVC mode)

	@
	@ the branch table must immediately follow this code
	@
	// lr: R14_irq: interrupt 발생시 cpsr 값
	and	lr, lr, #0x0f
	// lr: R14_irq: interrupt 발생시 cpsr 값 하위 4bit 값

	// sp: R13_irq (stack pointer): &(stacks[0].irq[0]), r0: interrupt 발생시의 r0
	mov	r0, sp
	// r0: &(stacks[0].irq[0])

	// NOTE:
	// lr: 3 (svc mode)라고 가정하고 분석

	// NOTE:
	// ARM의 PC 는 현재 실행 중인 명령어 보다 +8 한 위치를 가리킴

	// lr: R14_irq: interrupt 발생시 cpsr 값 하위 4bit 값 (usr: 0, svc: 3)
 	ldr	lr, [pc, lr, lsl #2]
	// lr: pc + 12

	// NOTE:
	// movs 명령을 pc에 사용할때 arm의 모드를 변경함 (exception return 기능)
	// SPSR_irq에 저장된 값을 cpsr 로드함

	// lr: pc + 12: __irq_svc의 주소
	movs	pc, lr			@ branch to handler in SVC mode
	// pc: __irq_svc의 주소
ENDPROC(vector_irq)
*/

	.long	__irq_usr			@  0  (USR_26 / USR_32)
	.long	__irq_invalid			@  1  (FIQ_26 / FIQ_32)
	.long	__irq_invalid			@  2  (IRQ_26 / IRQ_32)
	.long	__irq_svc			@  3  (SVC_26 / SVC_32)
	.long	__irq_invalid			@  4
	.long	__irq_invalid			@  5
	.long	__irq_invalid			@  6
	.long	__irq_invalid			@  7
	.long	__irq_invalid			@  8
	.long	__irq_invalid			@  9
	.long	__irq_invalid			@  a
	.long	__irq_invalid			@  b
	.long	__irq_invalid			@  c
	.long	__irq_invalid			@  d
	.long	__irq_invalid			@  e
	.long	__irq_invalid			@  f

/*
 * Data abort dispatcher
 * Enter in ABT mode, spsr = USR CPSR, lr = USR PC
 */
	vector_stub	dabt, ABT_MODE, 8

	.long	__dabt_usr			@  0  (USR_26 / USR_32)
	.long	__dabt_invalid			@  1  (FIQ_26 / FIQ_32)
	.long	__dabt_invalid			@  2  (IRQ_26 / IRQ_32)
	.long	__dabt_svc			@  3  (SVC_26 / SVC_32)
	.long	__dabt_invalid			@  4
	.long	__dabt_invalid			@  5
	.long	__dabt_invalid			@  6
	.long	__dabt_invalid			@  7
	.long	__dabt_invalid			@  8
	.long	__dabt_invalid			@  9
	.long	__dabt_invalid			@  a
	.long	__dabt_invalid			@  b
	.long	__dabt_invalid			@  c
	.long	__dabt_invalid			@  d
	.long	__dabt_invalid			@  e
	.long	__dabt_invalid			@  f

/*
 * Prefetch abort dispatcher
 * Enter in ABT mode, spsr = USR CPSR, lr = USR PC
 */
	vector_stub	pabt, ABT_MODE, 4

	.long	__pabt_usr			@  0 (USR_26 / USR_32)
	.long	__pabt_invalid			@  1 (FIQ_26 / FIQ_32)
	.long	__pabt_invalid			@  2 (IRQ_26 / IRQ_32)
	.long	__pabt_svc			@  3 (SVC_26 / SVC_32)
	.long	__pabt_invalid			@  4
	.long	__pabt_invalid			@  5
	.long	__pabt_invalid			@  6
	.long	__pabt_invalid			@  7
	.long	__pabt_invalid			@  8
	.long	__pabt_invalid			@  9
	.long	__pabt_invalid			@  a
	.long	__pabt_invalid			@  b
	.long	__pabt_invalid			@  c
	.long	__pabt_invalid			@  d
	.long	__pabt_invalid			@  e
	.long	__pabt_invalid			@  f

/*
 * Undef instr entry dispatcher
 * Enter in UND mode, spsr = SVC/USR CPSR, lr = SVC/USR PC
 */
	vector_stub	und, UND_MODE

	.long	__und_usr			@  0 (USR_26 / USR_32)
	.long	__und_invalid			@  1 (FIQ_26 / FIQ_32)
	.long	__und_invalid			@  2 (IRQ_26 / IRQ_32)
	.long	__und_svc			@  3 (SVC_26 / SVC_32)
	.long	__und_invalid			@  4
	.long	__und_invalid			@  5
	.long	__und_invalid			@  6
	.long	__und_invalid			@  7
	.long	__und_invalid			@  8
	.long	__und_invalid			@  9
	.long	__und_invalid			@  a
	.long	__und_invalid			@  b
	.long	__und_invalid			@  c
	.long	__und_invalid			@  d
	.long	__und_invalid			@  e
	.long	__und_invalid			@  f

	.align	5

/*=============================================================================
 * Address exception handler
 *-----------------------------------------------------------------------------
 * These aren't too critical.
 * (they're not supposed to happen, and won't happen in 32-bit data mode).
 */

vector_addrexcptn:
	b	vector_addrexcptn

/*=============================================================================
 * Undefined FIQs
 *-----------------------------------------------------------------------------
 * Enter in FIQ mode, spsr = ANY CPSR, lr = ANY PC
 * MUST PRESERVE SVC SPSR, but need to switch to SVC mode to show our msg.
 * Basically to switch modes, we *HAVE* to clobber one register...  brain
 * damage alert!  I don't think that we can execute any code in here in any
 * other mode than FIQ...  Ok you can switch to another mode, but you can't
 * get out of that mode without clobbering one register.
 */
vector_fiq:
	subs	pc, lr, #4

	.globl	vector_fiq_offset
	.equ	vector_fiq_offset, vector_fiq

	.section .vectors, "ax", %progbits
// ARM10C 20131109
// ARM10C 20141220
__vectors_start:
	W(b)	vector_rst
	W(b)	vector_und
	W(ldr)	pc, __vectors_start + 0x1000
	W(b)	vector_pabt
	W(b)	vector_dabt
	W(b)	vector_addrexcptn
	W(b)	vector_irq
	W(b)	vector_fiq

	.data

// ARM10C 20130914
	.globl	cr_alignment
	.globl	cr_no_alignment
cr_alignment:
	.space	4
cr_no_alignment:
	.space	4

#ifdef CONFIG_MULTI_IRQ_HANDLER
	.globl	handle_arch_irq
// ARM10C 20141129
// ARM10C 20141220
handle_arch_irq:
	.space	4
#endif
