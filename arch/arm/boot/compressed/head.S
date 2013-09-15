/*
 *  linux/arch/arm/boot/compressed/head.S
 *
 *  Copyright (C) 1996-2002 Russell King
 *  Copyright (C) 2004 Hyok S. Choi (MPU support)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/linkage.h>
#include <asm/assembler.h>

	.arch	armv7-a
/*
 * Debugging stuff
 *
 * Note that these macros must not contain any code which is not
 * 100% relocatable.  Any attempt to do so will result in a crash.
 * Please select one of the following when turning on debugging.
 */
#ifdef DEBUG

#if defined(CONFIG_DEBUG_ICEDCC)

// ARM 버전별로 적용
#if defined(CONFIG_CPU_V6) || defined(CONFIG_CPU_V6K) || defined(CONFIG_CPU_V7)
		.macro	loadsp, rb, tmp		// '.macro'는 매크로임을 뜻함.
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c0, c5, 0	// Debugger로 명령을 보낸다.
						// 매크로에서는 인자에 '\'를 붙인다.
						// p14: 코프로세서 (디버거,tracer)
						// 참조: 교재 663 page, TRM 257 page
		.endm
#elif defined(CONFIG_CPU_XSCALE)
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c8, c0, 0
		.endm
#else
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c1, c0, 0
		.endm
#endif

#else

#include CONFIG_DEBUG_LL_INCLUDE

		.macro	writeb,	ch, rb
		senduart \ch, \rb			//UART로 명령을 보낸다.
		.endm

#if defined(CONFIG_ARCH_SA1100)
		.macro	loadsp, rb, tmp
		mov	\rb, #0x80000000	@ physical base address
#ifdef CONFIG_DEBUG_LL_SER3
		add	\rb, \rb, #0x00050000	@ Ser3
#else
		add	\rb, \rb, #0x00010000	@ Ser1
#endif
		.endm
#elif defined(CONFIG_ARCH_S3C24XX)
		.macro loadsp, rb, tmp
		mov	\rb, #0x50000000
		add	\rb, \rb, #0x4000 * CONFIG_S3C_LOWLEVEL_UART_PORT
		.endm
#else
		.macro	loadsp,	rb, tmp
		addruart \rb, \tmp
		.endm
#endif
#endif
#endif

		.macro	kputc,val
		mov	r0, \val
		bl	putc
		.endm

		.macro	kphex,val,len
		mov	r0, \val
		mov	r1, #\len
		bl	phex
		.endm

		.macro	debug_reloc_start
#ifdef DEBUG
		kputc	#'\n'
		kphex	r6, 8		/* processor id */
		kputc	#':'
		kphex	r7, 8		/* architecture id */
#ifdef CONFIG_CPU_CP15
		kputc	#':'
		mrc	p15, 0, r0, c1, c0
		kphex	r0, 8		/* control reg */
#endif
		kputc	#'\n'
		kphex	r5, 8		/* decompressed kernel start */
		kputc	#'-'
		kphex	r9, 8		/* decompressed kernel end  */
		kputc	#'>'
		kphex	r4, 8		/* kernel execution address */
		kputc	#'\n'
#endif
		.endm

		.macro	debug_reloc_end
#ifdef DEBUG
		kphex	r5, 8		/* end of kernel */
		kputc	#'\n'
		mov	r0, r4
		bl	memdump		/* dump 256 bytes at start of kernel */
#endif
		.endm

		.section ".start", #alloc, #execinstr
/*
 * sort out different calling conventions
 */

		.align				// 4byte로 메모리를 align한다는 뜻. (default: 4)
		.arm				@ Always enter in ARM state
						// 이제부터 나오는opcode는 arm임을 어셈블러에게 알림
start:
		.type	start,#function		// .type: symbol table에 entry에 속성을 기록한다.
						// start 레이블은 함수 타입이다.


// - 이 코드가 하는 일:
//   instruction(mov r0, r0)를 8번 반복합니다.
//
// - 탄생비화:
//   옛날옛날에 어떤 거지같은 부트로더가 있었는데 그놈은 이미지 올려놓은 램주소에서
//   8 Word(32byte = 0x20)만큼의 하위 주소를 call해 버렸었고 올려놓은 주소에서
//   offset(0x24~0x30)사이에 magic number를 찾았답니다. 그래서 그런 부트로더들
//   맞춰줄려고 head.s에 의미없는 instruction(mov r0, r0)를 8번(8 Word)해서 소비합니다.
//
//   참조:
//     - http://www.iamroot.org/xe/QnA/23099
//     - http://comments.gmane.org/gmane.linux.ports.arm.kernel/26690
//
// - ARM(), THUMB() 매크로:
//   CONFIG_THUMB2_KERNEL 옵션이 켜져 있으면 ARM()매크로는 버리고  THUMB()매크로만 사용합니다.
//   반대의 경우는 ARM()매크로만 사용하고, THUMB()는 버립니다.
//
// - instruction(b  1f)에서 '1f'의 뜻:
//   '1'은 레이블 이름. 'f'는 forward방향을 뜻함. (f: forward / b: before)
//
// - BSYM()매크로:
//   #ifdef CONFIG_THUMB2_KERNEL
//     #define BSYM(sym)	sym + 1
//   #else
//     #define BSYM(sym)	sym
//   #endif

		.rept	7
		mov	r0, r0
		.endr
   ARM(		mov	r0, r0		)
   ARM(		b	1f		)
 THUMB(		adr	r12, BSYM(1f)	)
 THUMB(		bx	r12		)

// - (.word 0x016f2818)의 뜻:
//   부트로더에게 linux kernel zImage임을 알려주는 매직넘버입니다.
//   정말인지 zImage를 실제로 읽어서 확인해 VOA요.
//
//     $ hd arch/arm/boot/zImage | head -n3
//     00000000  00 00 a0 e1 00 00 a0 e1  00 00 a0 e1 00 00 a0 e1
//     *
//     00000020  02 00 00 ea 18 28 6f 01  00 00 00 00 10 3b 3d 00
//			   -----------  ----------- -----------
//			   0x016f2818   start       _edata=0x003d3b10
//
//  Thumb mode image
//  -------------------------------------------------------------------
//  00000000  00 00 a0 e1 00 00 a0 e1  00 00 a0 e1 00 00 a0 e1
//  00000010  00 00 a0 e1 00 00 a0 e1  00 00 a0 e1 0d c0 8f e2
//  00000020  1c ff 2f e1 18 28 6f 01  00 00 00 00 80 bc 39 00
//			   0x016f2818   start       _edata=0x0039bc80
//
// - (.word start)의 뜻:
//   start는 start 레이블을 뜻하며 실제로 0x00000000이 들어갑니다.
//
// - (.word _edata)의 뜻:
//   _edata는 zImage의 끝을 뜻하며, arch/arm/kernel/vmlinux.lds.S 에서 정의합니다.
//
		.word	0x016f2818		@ Magic numbers to help the loader
						// 매직 넘버(=zImage라는 뜻)
		.word	start			@ absolute load/run zImage address
						// zImage의 주소를 적재하고 실행할 절대주소
		.word	_edata			@ zImage end address
						// zImage의 끝 주소
 THUMB(		.thumb			)
1:

		mrs	r9, cpsr		// mrs란? move to register from special register

//
// CONFIG_ARM_VIRT_EXT: firmware의 실시간 지원 없이
// 하이퍼바이저를 설치하기 위한 ARM 가상화 확장 옵션
//
#ifdef CONFIG_ARM_VIRT_EXT
		bl	__hyp_stub_install	@ get into SVC mode, reversibly
						// b와 bl의 차이점: b는 단순한 이동을 뜻하고,
						//   bl은 하드웨어가 pc를 lr에 자동으로 넣은 후 이동한다.
#endif
		mov	r7, r1			@ save architecture ID
						// 부트로더가 커널에게 넘겨주는 값.
						// r7 = r1
		mov	r8, r2			@ save atags pointer
						// r8 = r2

		/*
		 * Booting from Angel - need to enter SVC mode and disable
		 * FIQs/IRQs (numeric definitions from angel arm.h source).
		 * We only do this if we were in user mode on entry.
		 */
		// Angel로 부터 부팅 - SVC모드 진입을 필요로 하며 FIQ/IRQ를
		// disable시켜야 한다.
		// (angel에 관한 수자 정의는 arm.h 소스에 있다.).
		// 처음에 user 모드로 시작한 경우에만 작업을 한다.
		mrs	r2, cpsr		@ get current mode
		tst	r2, #3			@ not user?
		bne	not_angel
		mov	r0, #0x17		@ angel_SWIreason_EnterSVC
 ARM(		swi	0x123456	)	@ angel_SWI_ARM
 THUMB(		svc	0xab		)	@ angel_SWI_THUMB
not_angel:
		safe_svcmode_maskall r0		// SVC mode로 설정한다.
		msr	spsr_cxsf, r9		@ Save the CPU boot mode in
						@ SPSR
						// SVC mode 용 SPSR에 저장
						// 접미사 cxsf 의미? PSR 필드의 접미사임
		/* ARMv2 일 경우 수행 됨*/
		/*
		 * Note that some cache flushing and other stuff may
		 * be needed here - is there an Angel SWI call for this?
		 */

		/*
		 * some architecture specific code can be inserted
		 * by the linker here, but it should preserve r7, r8, and r9.
		 */

		 //ELF format 의 text section 정의
		 //Section directive 사용/ 사용안한 코드의 차이는?
		 //vmlinux.lds.in file의 .text 가 맞는지? 
		.text

		 //exynos defconfig 기준으로 code 분석
		 //CONFIG_AUTO_ZRELADDR 는 빠져 있으므로 아래 코드는 Skip 
#ifdef CONFIG_AUTO_ZRELADDR
		@ determine final kernel image address
		mov	r4, pc
		and	r4, r4, #0xf8000000
		add	r4, r4, #TEXT_OFFSET
#else
		//= 의 의미는? : pesudo assembler 임
		//mov r4 #zreladdr 와 동일
		//arm/Makefile 의 TEXT_OFFSET 값이 적혀 있음
		//TEXT_OFFSET 값의 의미는? datasheet 찾아봐야됨
		ldr	r4, =zreladdr
#endif
		//link reg 에 pc를 저장하고 cache_on로jump
		/*
		 * Set up a page table only if it won't overwrite ourself.
		 * That means r4 < pc && r4 - 16k page directory > &_end.
		 * Given that r4 > &_end is most unfrequent, we add a rough
		 * additional 1MB of room for a possible appended DTB.
		 */
		mov	r0, pc
		cmp	r0, r4
		ldrcc	r0, LC0+32
		addcc	r0, r0, pc
		cmpcc	r4, r0
		orrcc	r4, r4, #1		@ remember we skipped cache_on
		blcs	cache_on

restart:	adr	r0, LC0			// pc에서 LC0까지의 상대 주소를 r0에 저장
						//
		ldmia	r0, {r1, r2, r3, r6, r10, r11, r12}
						// LC0 에 있는 값들을 순서대로 r1부터 r12까지 저장.
		ldr	sp, [r0, #28]
						// LC0 끝부분을 sp에 저장.
//2013/07/13 종료
//2013/07/20 시작

		/*
		 * We might be running at a different address.  We need
		 * to fix up various pointers.
		 */
		sub	r0, r0, r1		@ calculate the delta offset
						//r0 : runtime의 LC0 address, r1 : compile time의 LC0 address
		add	r6, r6, r0		@ _edata
						// r6 : runtime의 _edata
		add	r10, r10, r0		@ inflated kernel size location
						// r10 : runtime 의 inflated kernel size location

		/*
		 * The kernel build system appends the size of the
		 * decompressed kernel at the end of the compressed data
		 * in little-endian form.
		 */
		ldrb	r9, [r10, #0]		//r9 = *(input_data_end - 4)
		ldrb	lr, [r10, #1]		//lr = *(input_data_end - 3)
		orr	r9, r9, lr, lsl #8	//r9 = r9 | (lr << 8)
		ldrb	lr, [r10, #2]		//lr = *(input_data_end - 2)
		ldrb	r10, [r10, #3]		//r10 = *(input_data_end - 1)
		orr	r9, r9, lr, lsl #16	//r9 = r9 | (lr << 16)
		orr	r9, r9, r10, lsl #24	//r9 = r9 | (lr << 24)

#ifndef CONFIG_ZBOOT_ROM
		/* malloc space is above the relocated stack (64k max) */
		add	sp, sp, r0
		add	r10, sp, #0x10000
#else
		/*
		 * With ZBOOT_ROM the bss/stack is non relocatable,
		 * but someone could still run this code from RAM,
		 * in which case our reference is _edata.
		 */
		mov	r10, r6			//
#endif

		mov	r5, #0			@ init dtb size to 0
#ifdef CONFIG_ARM_APPENDED_DTB
/*
 *   r0  = delta
 *   r2  = BSS start
 *   r3  = BSS end
 *   r4  = final kernel address (possibly with LSB set)
 *   r5  = appended dtb size (still unknown)
 *   r6  = _edata
 *   r7  = architecture ID
 *   r8  = atags/device tree pointer
 *   r9  = size of decompressed image
 *   r10 = end of this image, including  bss/stack/malloc space if non XIP
 *   r11 = GOT start
 *   r12 = GOT end
 *   sp  = stack pointer
 *
 * if there are device trees (dtb) appended to zImage, advance r10 so that the
 * dtb data will get relocated along with the kernel if necessary.
 */

		ldr	lr, [r6, #0]		//lr = *(_edata) zImage의 끝의 값
#ifndef __ARMEB__
		ldr	r1, =0xedfe0dd0		@ sig is 0xd00dfeed big endian
#else
		ldr	r1, =0xd00dfeed
#endif
		//DTB를 사용하면 위 값이 zImage의 끝에 넣어져 있다.
		cmp	lr, r1
		bne	dtb_check_done		@ not found

#ifdef CONFIG_ARM_ATAG_DTB_COMPAT
		/*
		 * OK... Let's do some funky business here.
		 * If we do have a DTB appended to zImage, and we do have
		 * an ATAG list around, we want the later to be translated
		 * and folded into the former here.  To be on the safe side,
		 * let's temporarily move  the stack away into the malloc
		 * area.  No GOT fixup has occurred yet, but none of the
		 * code we're about to call uses any global variable.
		*/
		add	sp, sp, #0x10000	    //sp = sp + 64k ( sp사이즈를 + 64k한다)
		stmfd	sp!, {r0-r3, ip, lr}	    //*(sp -4) = r0, *(sp - 8) = r1, ... *(sp - 24) = lr, sp -= 24
		mov	r0, r8			    //r0 = atags/device tree pointer
		mov	r1, r6			    //r1 = _edata
		sub	r2, sp, r6		    //r2 = sp - _edata
		bl	atags_to_fdt

		/*
		 * If returned value is 1, there is no ATAG at the location
		 * pointed by r8.  Try the typical 0x100 offset from start
		 * of RAM and hope for the best.
		 */
		// start of ram + offset 0x100 보통 ATAG가 오는 주소
		// 0x100의 의미: 통상적인 ATAG의 위치 
		cmp	r0, #1
		sub	r0, r4, #TEXT_OFFSET	    // TEXT_OFFSET = 0x00008000
		bic	r0, r0, #1
		add	r0, r0, #0x100
		mov	r1, r6
		sub	r2, sp, r6
		bleq	atags_to_fdt

		ldmfd	sp!, {r0-r3, ip, lr}	    // stack에 넣은 값 복원
		sub	sp, sp, #0x10000	    // malloc 으로 잡아 놓은 값 복원
#endif

		mov	r8, r6			@ use the appended device tree
						// 위에서 fdt 설정 완료. r8 을 다른 용도로 사용 가능 
						// r8: dtb address 값

		/*
		 * Make sure that the DTB doesn't end up in the final
		 * kernel's .bss area. To do so, we adjust the decompressed
		 * kernel size to compensate if that .bss size is larger
		 * than the relocated code.
		 */
		ldr	r5, =_kernel_bss_size	// = ?: pesudo instruction.
						// mov 와 동작은 동일, 32bit 전체를 사용
						// _kernel_bss_size: 압축 풀린 kernel bss 사이즈 
		adr	r1, wont_overwrite
		sub	r1, r6, r1		// r1 = device tree 주소 -  wont_overwrite의 주소 
		subs	r1, r5, r1		// _kernel_bss_size - r1
		addhi	r9, r9, r1		// if (r5 > r1) 

		/* Get the dtb's size */
		ldr	r5, [r6, #4]
#ifndef __ARMEB__
		/* convert r5 (dtb size) to little endian */
		eor	r1, r5, r5, ror #16
		bic	r1, r1, #0x00ff0000
		mov	r5, r5, ror #8
		eor	r5, r5, r1, lsr #8
#endif

		/* preserve 64-bit alignment */
		add	r5, r5, #7
		bic	r5, r5, #7

		/* relocate some pointers past the appended dtb */
		add	r6, r6, r5	    // r6(_edata) = dtb 시작주소 + dtb size
		add	r10, r10, r5	    // r10(zimage 끝주소) = r10 + dtb size
		add	sp, sp, r5	    // sp = sp + dtb size
dtb_check_done:
#endif

/*
 * Check to see if we will overwrite ourselves.
 *   r4  = final kernel address (possibly with LSB set)
 *   r9  = size of decompressed image
 *   r10 = end of this image, including  bss/stack/malloc space if non XIP
 * We basically want:
 *   r4 - 16k page directory >= r10 -> OK
 *   r4 + image length <= address of wont_overwrite -> OK
 * Note: the possible LSB in r4 is harmless here.
 */
		add	r10, r10, #16384    // r10 = r10(zimage 끝주소)  dtb size + 16K
		cmp	r4, r10		    // r4 : final kernal address
		bhs	wont_overwrite	    // 겹치지 않는 경우
		add	r10, r4, r9
		adr	r9, wont_overwrite
		cmp	r10, r9
		bls	wont_overwrite	    
		
		
// 겹치는 경우

/*
 * Relocate ourselves past the end of the decompressed kernel.
 *   r6  = _edata
 *   r10 = end of the decompressed kernel
 * Because we always copy ahead, we need to do it from the end and go
 * backward in case the source and destination overlap.
 */
		/*
		 * Bump to the next 256-byte boundary with the size of
		 * the relocation code added. This avoids overwriting
		 * ourself when the offset is small.
		 */
		// 256 더하는 이유? 겹치지 않도록 여유공간 확보 하기위함. 
		// r10 = end of the decompressed kernel + (reloc_code_end - restart + 256) & ~255)
		add	r10, r10, #((reloc_code_end - restart + 256) & ~255)
		bic	r10, r10, #255

		/* Get start of code we want to copy and align it down. */
		adr	r5, restart
		bic	r5, r5, #31

/* Relocate the hyp vector base if necessary */
#ifdef CONFIG_ARM_VIRT_EXT
		mrs	r0, spsr
		and	r0, r0, #MODE_MASK
		cmp	r0, #HYP_MODE
		bne	1f

		bl	__hyp_get_vectors	// HVC vector call 0 을 수행
						// FIXME: Hyperviser 코드분석시 추후 검토 요망
		sub	r0, r0, r5
		add	r0, r0, r10
		bl	__hyp_set_vectors
1:
#endif

		sub	r9, r6, r5		@ size to copy
						// r6 : _edata, r5: restart 위치 
		add	r9, r9, #31		@ rounded up to a multiple
		bic	r9, r9, #31		@ ... of 32 bytes
		add	r6, r9, r5		// r6 = size + restart 위치 -> source end address 구한 결과
		add	r9, r9, r10             // destination end address 구한 결과

		
		
1:		ldmdb	r6!, {r0 - r3, r10 - r12, lr}	// decrement before
							// r0 = *(r6 - 4) ... lr = *(r6 - 32) r6 = r6 - 32
		cmp	r6, r5				// source end address 까지 왔는지 비교	
		stmdb	r9!, {r0 - r3, r10 - r12, lr}	// load한것 store 
		bhi	1b

		/* Preserve offset to relocated code. */
		sub	r6, r9, r6

#ifndef CONFIG_ZBOOT_ROM
		/* cache_clean_flush may use the stack, so relocate it */
		add	sp, sp, r6
#endif

		tst	r4, #1
		bleq	cache_clean_flush

		adr	r0, BSYM(restart)	// 복사를 했던 wont_overwrite 로 어떻게 가서 수행이 되는지?
						// - 조건에 의해서 restart에 시작해도 cache, DTB 작업을 하지않고
						// - wont_overwrite jump 하도록 되어 있음
		add	r0, r0, r6		// r6: offset to relocated code 임 
		mov	pc, r0

wont_overwrite:
/*
 * If delta is zero, we are running at the address we were linked at.
 *   r0  = delta
 *   r2  = BSS start
 *   r3  = BSS end
 *   r4  = kernel execution address (possibly with LSB set)
 *   r5  = appended dtb size (0 if not present)
 *   r7  = architecture ID
 *   r8  = atags pointer
 *   r11 = GOT start
 *   r12 = GOT end
 *   sp  = stack pointer
 */
		orrs	r1, r0, r5
		beq	not_relocated		// orr 연산결과 jump 하지 않음

		add	r11, r11, r0		// r11 : 복사한 곳의 GOT start 값임
		add	r12, r12, r0		// r12 : 복사한 곳의 GOT end 값임

#ifndef CONFIG_ZBOOT_ROM
		// FIXME: GOT, PLT를 사용하지 않을 것 같은데 이 작업이 필요한 이유??
		/*
		 * If we're running fully PIC === CONFIG_ZBOOT_ROM = n,
		 * we need to fix up pointers into the BSS region.
		 * Note that the stack pointer has already been fixed up.
		 */
		add	r2, r2, r0		// r2 : 복사한 곳의 BSS start 값임
		add	r3, r3, r0		// r3 : 복사한 곳의 BSS end 값임

		/*
		 * Relocate all entries in the GOT table.
		 * Bump bss entries to _edata + dtb size
		 */
1:		ldr	r1, [r11, #0]		@ relocate entries in the GOT
		add	r1, r1, r0		@ This fixes up C references
		cmp	r1, r2			@ if entry >= bss_start &&
		cmphs	r3, r1			@       bss_end > entry
		addhi	r1, r1, r5		@    entry += dtb size
		str	r1, [r11], #4		@ next entry
		cmp	r11, r12
		blo	1b

		/* bump our bss pointers too */
		add	r2, r2, r5		// r2 : 복사한 곳의 BSS start 값 + appended dtb size 
		add	r3, r3, r5		// r3 : 복사한 곳의 BSS end 값 + appended dtb size 

#else

		/*
		 * Relocate entries in the GOT table.  We only relocate
		 * the entries that are outside the (relocated) BSS region.
		 */
1:		ldr	r1, [r11, #0]		@ relocate entries in the GOT
		cmp	r1, r2			@ entry < bss_start ||
		cmphs	r3, r1			@ _end < entry
		addlo	r1, r1, r0		@ table.  This fixes up the
		str	r1, [r11], #4		@ C references.
		cmp	r11, r12
		blo	1b
#endif

not_relocated:	mov	r0, #0
1:		str	r0, [r2], #4		@ clear bss
		str	r0, [r2], #4
		str	r0, [r2], #4
		str	r0, [r2], #4
		cmp	r2, r3
		blo	1b

		/*
		 * Did we skip the cache setup earlier?
		 * That is indicated by the LSB in r4.
		 * Do it now if so.
		 */
		tst	r4, #1
		bic	r4, r4, #1
		blne	cache_on

/*
 * The C runtime environment should now be setup sufficiently.
 * Set up some pointers, and start decompressing.
 *   r4  = kernel execution address
 *   r7  = architecture ID
 *   r8  = atags pointer
 */
		mov	r0, r4
		mov	r1, sp			@ malloc space above stack
		add	r2, sp, #0x10000	@ 64k max
		mov	r3, r7
		bl	decompress_kernel
		bl	cache_clean_flush
		bl	cache_off
		mov	r1, r7			@ restore architecture number
		mov	r2, r8			@ restore atags pointer

#ifdef CONFIG_ARM_VIRT_EXT
		mrs	r0, spsr		@ Get saved CPU boot mode
		and	r0, r0, #MODE_MASK
		cmp	r0, #HYP_MODE		@ if not booted in HYP mode...
		bne	__enter_kernel		@ boot kernel directly

		adr	r12, .L__hyp_reentry_vectors_offset
		ldr	r0, [r12]
		add	r0, r0, r12

		bl	__hyp_set_vectors
		__HVC(0)			@ otherwise bounce to hyp mode

		b	.			@ should never be reached

		.align	2
.L__hyp_reentry_vectors_offset:	.long	__hyp_reentry_vectors - .
#else
		b	__enter_kernel
#endif

		.align	2
		.type	LC0, #object
LC0:		.word	LC0			@ r1
		.word	__bss_start		@ r2
		.word	_end			@ r3
		.word	_edata			@ r6
		.word	input_data_end - 4	@ r10 (inflated size location)
		// -4를 하는 이유는? (align 2가 없는데 무조건 -4를 해도 되는가?는 아님)
		// input_data_end의 끝에 압축을 푼 kernel의 사이즈가 들어가므로 -4를 해줌으로 실제 input_data_end가 됨 
		.word	_got_start		@ r11
		.word	_got_end		@ ip // r12
		.word	.L_user_stack_end	@ sp
		.word	_end - restart + 16384 + 1024*1024
		.size	LC0, . - LC0

#ifdef CONFIG_ARCH_RPC
		.globl	params
params:		ldr	r0, =0x10000100		@ params_phys for RPC
		mov	pc, lr
		.ltorg
		.align
#endif

/*
 * Turn on the cache.  We need to setup some page tables so that we
 * can have both the I and D caches on.
 *
 * We place the page tables 16k down from the kernel execution address,
 * and we hope that nothing else is using it.  If we're using it, we
 * will go pop!
 *
 * On entry,
 *  r4 = kernel execution address
 *  r7 = architecture number
 *  r8 = atags pointer
 * On exit,
 *  r0, r1, r2, r3, r9, r10, r12 corrupted
 * This routine must preserve:
 *  r4, r7, r8
 */
        /* memory를 2^5 (32byte) 으로 align 시킴
         * default align 은 2^4 (16byte) 임 */
		.align	5
cache_on:	mov	r3, #8			@ cache_on function
		b	call_cache_fn

/*
 * Initialize the highest priority protection region, PR7
 * to cover all 32bit address and cacheable and bufferable.
 */
__armv4_mpu_cache_on:
		mov	r0, #0x3f		@ 4G, the whole
		mcr	p15, 0, r0, c6, c7, 0	@ PR7 Area Setting
		mcr 	p15, 0, r0, c6, c7, 1

		mov	r0, #0x80		@ PR7
		mcr	p15, 0, r0, c2, c0, 0	@ D-cache on
		mcr	p15, 0, r0, c2, c0, 1	@ I-cache on
		mcr	p15, 0, r0, c3, c0, 0	@ write-buffer on

		mov	r0, #0xc000
		mcr	p15, 0, r0, c5, c0, 1	@ I-access permission
		mcr	p15, 0, r0, c5, c0, 0	@ D-access permission

		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c7, c5, 0	@ flush(inval) I-Cache
		mcr	p15, 0, r0, c7, c6, 0	@ flush(inval) D-Cache
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						@ ...I .... ..D. WC.M
		orr	r0, r0, #0x002d		@ .... .... ..1. 11.1
		orr	r0, r0, #0x1000		@ ...1 .... .... ....

		mcr	p15, 0, r0, c1, c0, 0	@ write control reg

		mov	r0, #0
		mcr	p15, 0, r0, c7, c5, 0	@ flush(inval) I-Cache
		mcr	p15, 0, r0, c7, c6, 0	@ flush(inval) D-Cache
		mov	pc, lr

__armv3_mpu_cache_on:
		mov	r0, #0x3f		@ 4G, the whole
		mcr	p15, 0, r0, c6, c7, 0	@ PR7 Area Setting

		mov	r0, #0x80		@ PR7
		mcr	p15, 0, r0, c2, c0, 0	@ cache on
		mcr	p15, 0, r0, c3, c0, 0	@ write-buffer on

		mov	r0, #0xc000
		mcr	p15, 0, r0, c5, c0, 0	@ access permission

		mov	r0, #0
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		/*
		 * ?? ARMv3 MMU does not allow reading the control register,
		 * does this really work on ARMv3 MPU?
		 */
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						@ .... .... .... WC.M
		orr	r0, r0, #0x000d		@ .... .... .... 11.1
		/* ?? this overwrites the value constructed above? */
		mov	r0, #0
		mcr	p15, 0, r0, c1, c0, 0	@ write control reg

		/* ?? invalidate for the second time? */
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

#ifdef CONFIG_CPU_DCACHE_WRITETHROUGH
#define CB_BITS 0x08
#else
#define CB_BITS 0x0c
#endif

//
// r4 : 0x40008000 - /arch/arm/mach-exynos/Makefile.boot zerladdr-y로 정의 되어있음
// bic 를 두번 하는 이유 : arm architecture manual : A5.2.4 참고 imm12 = rotation4 + imm8
//
__setup_mmu:	sub	r3, r4, #16384		@ Page directory size
						// r3 = 0x40008000 - 0x4000(16384) = 0x40004000
		bic	r3, r3, #0xff		@ Align the pointer
						// r3 = 0x40004000 & ~(0xff) = 0x40004000
		bic	r3, r3, #0x3f00		// r3 = 0x40004000 & ~(0x3f00) = 0x40004000
/*
 * Initialise the page tables, turning on the cacheable and bufferable
 * bits for the RAM area only.
 */
//
// Page Table을 초기화 한다. 오직 RAM영역만 cacheable과 bufferable 비트를 켠다.
//
		mov	r0, r3			// r0 = 0x40004000
						// lsr ,lsl #18 인 이유 : clps711x 계열의 주소가 0xc0028000 이기
						// 때문에 #18을 해야 하위 bit 클리어 할수 있다.
		mov	r9, r0, lsr #18		// r9 = 0x40004000 > 18 = 0x1000
						// FIXME: RAM시작 주소가 0x40000000인 이유는
						//  arch/arm/mach-exynos/include/mach/map.h 참고 (확인요망)
		mov	r9, r9, lsl #18		@ start of RAM
						// r9 = 0x1000 < 18 = 0x40000000
		add	r10, r9, #0x10000000	@ a reasonable RAM size
						// r10 = 0x40000000 + 0x10000000(256M) = 0x50000000
						// r1에 MMU Page table 의 Section entry 값을 만들어 준다.
		mov	r1, #0x12		@ XN(0x10)|U + section mapping(0x02)
						// FIXME: r1 = 0x12
						// XN : Excute never(0x10)(코드영역이아님),
						// U(확인요망) : manual B3.5 참고
		orr	r1, r1, #3 << 10	// AP(Access Permission)=11(Read Write가 가능하다) : B3.7.1 참고
						// r1 = 0x12 | (0x3 << 10 ) = 0xC12
		add	r2, r3, #16384		// r2 = 0x40004000 + 0x4000(16384) = 0x40008000

//
// 전체 4Gbyte 영역중 0x40000000 부터 0x50000000 까지 영역만 Writeback/executable(0xC0E)영역으로 설정한다.
// 나머지는 Noncacheable,Nonexecutable, Nonbufferable(0xC12) 로 설정
//

// r0 가 loop를 결정하는 Page table의 주소값
// r1 은 orrlo, orrhs 수행을 결정하는 Section base address 값

//-------------
// 최초 루프만 주석표시
//-------------
1:		cmp	r1, r9			@ if virt > start of RAM
						// r1 = 0xC12(가변), r9 = 0x40000000
		cmphs	r10, r1			@   && end of RAM > virt
						// r10 = 0x50000000, r1 = 0xC12(가변) // hs : unsigned로 비교해서 크거나 같다면...
		bic	r1, r1, #0x1c		@ clear XN|U + C + B
						// r1 = 0xC12 & ~(0x1c) = 0xC02 // AP와 Section mapping만 남음
		orrlo	r1, r1, #0x10		@ Set XN|U for non-RAM
						// lo(low) : 작다면 r1 = 0xc02 | 0x10 = 0xc12
		orrhs	r1, r1, r6		@ set RAM section settings
						// hs(high or same) : 크거나 같다면
		str	r1, [r0], #4		@ 1:1 mapping
						// *r0 = r1, r0 += 4 // 0x40004000 주소에 0xc12를 저장후 0x40004004
		add	r1, r1, #1048576	// r1 = 0xc12 + 0x100000(1048576) = 0x100c12
		teq	r0, r2			// r0 = 0x40004004(가변) ^ 0x40008000(고정) = //Page table의 끝을 검사한다.
		bne	1b			// 위 결과 Z=0이면 1로감


//-------------
// RAM 영역일때 루프 : 0x40000000 ~ 0x50000000 ( orrhs수행됨 )
//-------------
//
//1:		cmp	r1, r9			@ if virt > start of RAM
//						// r1 = 0x40000C12, r9 = 0x40000000
//		cmphs	r10, r1			@   && end of RAM > virt
//						// r10 = 0x50000000, r1 = 0x40000C12
//						// hs : unsigned로 비교해서 크거나 같다면...
//		bic	r1, r1, #0x1c		@ clear XN|U + C + B
//						// r1 = 0x40000C12 & ~(0x1c) = 0x40000C02 //AP와 Section mapping만 남음
//		orrlo	r1, r1, #0x10		@ Set XN|U for non-RAM
//						// lo : 작다면
//		orrhs	r1, r1, r6		@ set RAM section settings
//						// hs : 크거나 같다면 r1 = 0x40000c02 | 0xE(r6) = 0x40000C0E
//		str	r1, [r0], #4		@ 1:1 mapping
//						// *r0 = r1, r0 += 4
//						// 0x40005000 주소에 0x40000C0E를 저장후 0x40005004
//		add	r1, r1, #1048576	// r1 = 0x40000C0E + 0x100000(1048576) = 0x40100c0e
//		teq	r0, r2			// r0 = 0x40005004(가변) ^ 0x40008000(고정) =
//						//Page table의 끝을 검사한다.
//		bne	1b			// 위 결과 Z=0이면 1로감
//

//-------------
// end of loop
//-------------
//1:		cmp	r1, r9			@ if virt > start of RAM
//						// r1 = 0xfff00C12, r9 = 0x40000000
//		cmphs	r10, r1			@   && end of RAM > virt
//						// r10 = 0x50000000, r1 = 0xfff00C12
//						// hs : unsigned로 비교해서 크거나 같다면...
//		bic	r1, r1, #0x1c		@ clear XN|U + C + B
//						// r1 = 0xfff00C12 & ~(0x1c) = 0xfff00C02 //AP와 Section mapping만 남음
//		orrlo	r1, r1, #0x10		@ Set XN|U for non-RAM
//						// lo : 작다면
//		orrhs	r1, r1, r6
//		str	r1, [r0], #4		@ 1:1 mapping
//						// *r0 = r1, r0 += 4
//						// 0x40007ffc 주소에 0xfff00c12를 저장후 0x40008000
//		add	r1, r1, #1048576	// r1 = 0xfff00C12 + 0x100000(1048576) = 0x00000c12
//		teq	r0, r2			// r0 = 0x40008000(가변) ^ 0x40008000(고정) =
//						// Page table의 끝을 검사한다.
//		bne	1b			// 위 결과 Z=1, no jump-back
//

/*
 * If ever we are running from Flash, then we surely want the cache
 * to be enabled also for our execution instance...  We map 2MB of it
 * so there is no map overlap problem for up to 1 MB compressed kernel.
 * If the execution is in RAM then we would only be duplicating the above.
 */
//
//FIXME B를 여기와서 다시 0xC0E 로 셋하는 이유 : (조사요망)
//
		orr	r1, r6, #0x04		@ ensure B is set for this
						// r1 = 0xE(r6) | 0x04 = 0xE
		orr	r1, r1, #3 << 10	// r1 = 0xE(r1) | (0x3 << 10) = 0xC0E
		mov	r2, pc			// r2 = pc
		mov	r2, r2, lsr #20		// r2 = pc(r2) > 20
		orr	r1, r1, r2, lsl #20	// r1 = 0xc0E | ( pc & 0xfff00000 )
						// 현재 pc에 해당하는 Section에 대한 디스크립터
		add	r0, r3, r2, lsl #2	// r0 = 0x40004000(r3) + (( pc > 20 ) < 2)
						// 현재 pc에 해당하는 Section에 대한 Page table address
		str	r1, [r0], #4		// *r0 = 0xc0e | ( pc & 0xfff00000 ) , r0 += 4
		add	r1, r1, #1048576	// r1 = ( 0xc0e | ( pc & 0xfff00000 ) ) + 0x100000(1048576)
		str	r1, [r0]		// *r0 = ( 0xc0e | ( pc & 0xfff00000 ) ) + 0x100000(1048576)
//
// 2013/07/06 종료
//
		mov	pc, lr
ENDPROC(__setup_mmu)

@ Enable unaligned access on v6, to allow better code generation
@ for the decompressor C code:
__armv6_mmu_cache_on:
		mrc	p15, 0, r0, c1, c0, 0	@ read SCTLR
		bic	r0, r0, #2		@ A (no unaligned access fault)
		orr	r0, r0, #1 << 22	@ U (v6 unaligned access model)
		mcr	p15, 0, r0, c1, c0, 0	@ write SCTLR
		b	__armv4_mmu_cache_on

__arm926ejs_mmu_cache_on:
#ifdef CONFIG_CPU_DCACHE_WRITETHROUGH
		mov	r0, #4			@ put dcache in WT mode
		mcr	p15, 7, r0, c15, c0, 0
#endif

__armv4_mmu_cache_on:
		mov	r12, lr
#ifdef CONFIG_MMU
		mov	r6, #CB_BITS | 0x12	@ U
		bl	__setup_mmu
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		orr	r0, r0, #0x5000		@ I-cache enable, RR cache replacement
		orr	r0, r0, #0x0030
#ifdef CONFIG_CPU_ENDIAN_BE8
		orr	r0, r0, #1 << 25	@ big-endian page tables
#endif
		bl	__common_mmu_cache_on
		mov	r0, #0
		mcr	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
#endif
		mov	pc, r12

__armv7_mmu_cache_on:
		mov	r12, lr			//lr을 r12에 저장하는 이유: Stack을 쓰지 않기 위해서.
#ifdef CONFIG_MMU
		mrc	p15, 0, r11, c0, c1, 4	@ read ID_MMFR0
						// MMU에 MMFR0값을 읽어서 r11에 넣는다.
		tst	r11, #0xf		@ VMSA
						// MMFR0[3:0](VMSA)를 tst한다.
						//
						// tst에 대하여 정리:
						//    r11&0xf연산을 해서 결과가 0이면 CPSR에 Zero flag가 1이 된다.
						//
		movne	r6, #CB_BITS | 0x02	@ !XN
						// 현재 설정이 D-Cache WriteBack이므로 CB_BITS는 0xC이고
						// ne 는 Zero flag가 0이면 명령어 수행
						// r6 = 0xC | 0x02 = 0x0E 가 된다.
		blne	__setup_mmu		// VMSA를 지원하면 __setup_mmu로 이동한다.
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
						// data write buffer 용어가 변경 됨 -> data sync barrier (DSB)
						// Cache 가 아닌데도 hw적으로 data write 되지 않았을 수가 있음
						// 확실하게 write buffer 있는 data를 memory에 써주도록 함 
						// A.R.M : 152p(A3.8.3), 1484p(Table B3-42)
		tst	r11, #0xf		@ VMSA
		mcrne	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
						// invalidate entire unified TLB임, TLB에 있던 data를 무효화 함 
						// TLB는 page table의 cache임 
						// MMU를 켜기전에 TLB(cache) 남아 있는 기존 정보를 무효화 함
						// A.R.M : 1485p(Table B3-42), 1470p(B3.17.1), 1497p(B3.18.7)
#endif
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						// control register 값을 r0에 넣음
						// A.R.M : 1705p(B4.1.130 SCTLR, System Control Register, VMSA)
		bic	r0, r0, #1 << 28	@ clear SCTLR.TRE
						// TRE: TEX remap enable
						// TEX: type extension -> memory attribute를 확장함
						// TEX 값을 remap 할수 있는데 하지 않겠다는 의미임
						// remap의 의미: 다른 위치의 정보로 대채체 한다는 의미임 
						// A.R.M: 1367p(B3.8.2 Short-descriptor format memory region attributes, without TEX remap)
		orr	r0, r0, #0x5000		@ I-cache enable, RR cache replacement
						// control register의 12,14 bit를 set
						// 12bit: I-cache, 14bit: RR cache replacement - 1: round robin
		orr	r0, r0, #0x003c		@ write buffer
						// 0x3c == 0b111100
						// 5bit: CP15 Barrier enable, 4,3bit: reserved (should be set), 2bit: D-cache 
						// FIXME : 위에서 barrier enable을 했는데 여기서 다시 CP15 barrier을 enable 하는 이유?
						// mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer <-- 요기서 했었음 
						// A.R.M: 1710p
						// SCTLR[5]   - CP15BEN(CP15 barrier enable)
						// SCTLR[4:3] - Reserved, RAO/SBOP(Read-As-One, Should-Be-One-or-Preserved on writes.)
						// SCTLR[2]   - Cache Enable
		bic	r0, r0, #2		@ A (no unaligned access fault)
						// unaligned access fault 기능을 끄겠다는 뜻.
		orr	r0, r0, #1 << 22	@ U (v6 unaligned access model)
						@ (needed for ARM1176)
						// SCTLR[22]  - U bit set, arm11 지원 코드
						// arm11은 이 bit가 programmable 함
						// A.R.M: 2728p(Glossary)
#ifdef CONFIG_MMU
#ifdef CONFIG_CPU_ENDIAN_BE8			// exynos 5440의 config에는 꺼져있음.
		orr	r0, r0, #1 << 25	@ big-endian page tables
						// SCTLR[25]  - EE(Exception Endianness)
						// exception이 발생시 endian을 big endian으로 처리
						// page table 처리시 endian을 big endian으로 처리
#endif
		mrcne   p15, 0, r6, c2, c0, 2   @ read ttb control reg
						// TBL용 control register를 r6에 읽어옴
						// A.R.M: 1722p
		orrne	r0, r0, #1		@ MMU enabled
		movne	r1, #0xfffffffd		@ domain 0 = client
						// DACR (damain access control register) 에 넣을 값임 
						// page table 변경 없이 access permission의 domain 전체 값을 변경
						// page table 은 damain 0로 설정 되어 있으므로 page table AP bit로 permission 설정
						// Client내용: Accesses are checked against the permission bits 
						//             in the translation tables 
						// A.R.M: 1558p
		bic     r6, r6, #1 << 31        @ 32-bit translation system
						// A.R.M: 1722p
						// Large의 경우 40bit
						// 
		bic     r6, r6, #3 << 0         @ use only ttbr0
						// A.R.M : 1726p, 1723p, 1330p(B3.5.4)
						// 여기서는 TTBR0의 폭을 [31:14-N(0)] 으로 설정.
						// TTBR0은 User가 쓰고, TTBR1은 커널이 사용한다.
						//
						// FIXME: ttbr이 무엇인가?
						//
						// 약어
						//   - TTBR: Translation Table Base Register
						//   - TLB : Translation Lookaside Buffer
						//
						// 참조
						//  - http://wiki.kldp.org/KoreanDoc/html/EmbeddedKernel-KLDP/arm.mmu.html
						//  - http://kth3321.blogspot.kr/2013/04/arm-cortex-1.html

		mcrne	p15, 0, r3, c2, c0, 0	@ load page table pointer
						// TTBR0에 r3를 저장.
						// r3 = 0x40008000 - 0x4000(16384) = 0x40004000

		mcrne	p15, 0, r1, c3, c0, 0	@ load domain access control
						// 위에서 도메인 D0를 client로 설정한 것을 쓴다.
						// r1 = #0xfffffffd

		mcrne   p15, 0, r6, c2, c0, 2   @ load ttb control
						// TTBCR에 r6를 저장.
						// TTBCR[31, 1,0]을 clear
#endif
		mcr	p15, 0, r0, c7, c5, 4	@ ISB......<1>
						// ISB: Instruction Barrier
						// 위에서 r0를 다음과 같이 설정하였음.
						//
						// A.R.M : 389p (A8.8.53)
						//    ISB가 필요한 경우
						//       1. Address Space Identifier (ASID)
						//       2. TLB maintenance operations, 
						//       3. branch predictor maintenance operations, 
						//       4. and all changes to the CP15 registers
		mcr	p15, 0, r0, c1, c0, 0	@ load control register
						// r0에 설정했던 내용을 CP15.System Control Register에 Load
		mrc	p15, 0, r0, c1, c0, 0	@ and read it back
		mov	r0, #0
		mcr	p15, 0, r0, c7, c5, 4	@ ISB......<2>
						// FIXME: ISB<1>, <2>의 역할은 무엇?
						// 참조
						//   - http://www.iamroot.org/xe/Kernel_8_ARM/58427
		mov	pc, r12			// 'bl	cache_on'을 호출했던 곳으로 복귀

__fa526_cache_on:
		mov	r12, lr
		mov	r6, #CB_BITS | 0x12	@ U
		bl	__setup_mmu
		mov	r0, #0
		mcr	p15, 0, r0, c7, c7, 0	@ Invalidate whole cache
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c8, c7, 0	@ flush UTLB
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		orr	r0, r0, #0x1000		@ I-cache enable
		bl	__common_mmu_cache_on
		mov	r0, #0
		mcr	p15, 0, r0, c8, c7, 0	@ flush UTLB
		mov	pc, r12

__common_mmu_cache_on:
#ifndef CONFIG_THUMB2_KERNEL
#ifndef DEBUG
		orr	r0, r0, #0x000d		@ Write buffer, mmu
#endif
		mov	r1, #-1
		mcr	p15, 0, r3, c2, c0, 0	@ load page table pointer
		mcr	p15, 0, r1, c3, c0, 0	@ load domain access control
		b	1f
		.align	5			@ cache line aligned
1:		mcr	p15, 0, r0, c1, c0, 0	@ load control register
		mrc	p15, 0, r0, c1, c0, 0	@ and read it back to
		sub	pc, lr, r0, lsr #32	@ properly flush pipeline
#endif

#define PROC_ENTRY_SIZE (4*5)

/*
 * Here follow the relocatable cache support functions for the
 * various processors.  This is a generic hook for locating an
 * entry and jumping to an instruction at the specified offset
 * from the start of the block.  Please note this is all position
 * independent code.
 *
 *  r1  = corrupted      // currupted란 함수 내에서 변경한다는 뜻.
 *  r2  = corrupted
 *  r3  = block offset   // #8
 *  r9  = corrupted
 *  r12 = corrupted
 */

/* 주석의 corrupted 의 의미는? :  */
//
// adr:
// r12:
// proc_types:

call_cache_fn:	adr	r12, proc_types
#ifdef CONFIG_CPU_CP15
        /* Coprocessor 에서 processor ID를 가져옴  */
		mrc	p15, 0, r9, c0, c0	@ get processor ID
#else
        /* 코드에서 processor ID를 가져옴 */
		ldr	r9, =CONFIG_PROCESSOR_ID
#endif

// proc_types 중 일부:
//	.word	0x000f0000		@ new CPU Id
//	.word	0x000f0000

//
// 2013/06/29 시작
//

// addeq에서 eq는 CPSR에 Zero flag가 1이면 실행하라는 뜻.
1:		ldr	r1, [r12, #0]		@ get value
		ldr	r2, [r12, #4]		@ get mask
		eor	r1, r1, r9		@ (real ^ match)
		tst	r1, r2			@       & mask
 ARM(		addeq	pc, r12, r3		) @ call cache function``
 THUMB(		addeq	r12, r3			)
 THUMB(		moveq	pc, r12			) @ call cache function
		add	r12, r12, #PROC_ENTRY_SIZE	// proc_type의 다음 단위로 주소 이동
							//. PROC_ENTRY_SIZE=(4byte * 5항목수)
		b	1b

/*
 * Table for cache operations.  This is basically:
 *   - CPU ID match
 *   - CPU ID mask
 *   - 'cache on' method instruction
 *   - 'cache off' method instruction
 *   - 'cache flush' method instruction
 *
 * We match an entry using: ((real_id ^ match) & mask) == 0
 *
 * Writethrough caches generally only need 'on' and 'off'
 * methods.  Writeback caches _must_ have the flush method
 * defined.
 */
		.align	2
		.type	proc_types,#object
proc_types:
		.word	0x41000000		@ old ARM ID
		.word	0xff00f000
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41007000		@ ARM7/710
		.word	0xfff8fe00
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41807200		@ ARM720T (writethrough)
		.word	0xffffff00
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41007400		@ ARM74x
		.word	0xff00ff00
		W(b)	__armv3_mpu_cache_on
		W(b)	__armv3_mpu_cache_off
		W(b)	__armv3_mpu_cache_flush
		
		.word	0x41009400		@ ARM94x
		.word	0xff00ff00
		W(b)	__armv4_mpu_cache_on
		W(b)	__armv4_mpu_cache_off
		W(b)	__armv4_mpu_cache_flush

		.word	0x41069260		@ ARM926EJ-S (v5TEJ)
		.word	0xff0ffff0
		W(b)	__arm926ejs_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x00007000		@ ARM7 IDs
		.word	0x0000f000
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		@ Everything from here on will be the new ID system.

		.word	0x4401a100		@ sa110 / sa1100
		.word	0xffffffe0
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x6901b110		@ sa1110
		.word	0xfffffff0
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x56056900
		.word	0xffffff00		@ PXA9xx
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x56158000		@ PXA168
		.word	0xfffff000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x56050000		@ Feroceon
		.word	0xff0f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

#ifdef CONFIG_CPU_FEROCEON_OLD_ID
		/* this conflicts with the standard ARMv5TE entry */
		.long	0x41009260		@ Old Feroceon
		.long	0xff00fff0
		b	__armv4_mmu_cache_on
		b	__armv4_mmu_cache_off
		b	__armv5tej_mmu_cache_flush
#endif

		.word	0x66015261		@ FA526
		.word	0xff01fff1
		W(b)	__fa526_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__fa526_cache_flush

		@ These match on the architecture ID

		.word	0x00020000		@ ARMv4T
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x00050000		@ ARMv5TE
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x00060000		@ ARMv5TEJ
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x0007b000		@ ARMv6
		.word	0x000ff000
		W(b)	__armv6_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv6_mmu_cache_flush

		//
		// ARMv7 용 cache struct 정의
		//
		.word	0x000f0000		@ new CPU Id
		.word	0x000f0000
		W(b)	__armv7_mmu_cache_on	// W 의 의미는? include/asm/unified.h 참고
		W(b)	__armv7_mmu_cache_off
		W(b)	__armv7_mmu_cache_flush

		.word	0			@ unrecognised type
		.word	0
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.size	proc_types, . - proc_types

		/*
		 * If you get a "non-constant expression in ".if" statement"
		 * error from the assembler on this line, check that you have
		 * not accidentally written a "b" instruction where you should
		 * have written W(b).
		 */
		.if (. - proc_types) % PROC_ENTRY_SIZE != 0
		.error "The size of one or more proc_types entries is wrong."
		.endif

/*
 * Turn off the Cache and MMU.  ARMv3 does not support
 * reading the control register, but ARMv4 does.
 *
 * On exit,
 *  r0, r1, r2, r3, r9, r12 corrupted
 * This routine must preserve:
 *  r4, r7, r8
 */
		.align	5
cache_off:	mov	r3, #12			@ cache_off function
		b	call_cache_fn

__armv4_mpu_cache_off:
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0	@ turn MPU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c7, c6, 0	@ flush D-Cache
		mcr	p15, 0, r0, c7, c5, 0	@ flush I-Cache
		mov	pc, lr

__armv3_mpu_cache_off:
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0, 0	@ turn MPU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

__armv4_mmu_cache_off:
#ifdef CONFIG_MMU
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0	@ turn MMU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c7	@ invalidate whole cache v4
		mcr	p15, 0, r0, c8, c7	@ invalidate whole TLB v4
#endif
		mov	pc, lr

__armv7_mmu_cache_off:
		mrc	p15, 0, r0, c1, c0
#ifdef CONFIG_MMU
		bic	r0, r0, #0x000d
#else
		bic	r0, r0, #0x000c
#endif
		mcr	p15, 0, r0, c1, c0	@ turn MMU and cache off
		mov	r12, lr
		bl	__armv7_mmu_cache_flush
		mov	r0, #0
#ifdef CONFIG_MMU
		mcr	p15, 0, r0, c8, c7, 0	@ invalidate whole TLB
#endif
		mcr	p15, 0, r0, c7, c5, 6	@ invalidate BTC
		mcr	p15, 0, r0, c7, c10, 4	@ DSB
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mov	pc, r12

/*
 * Clean and flush the cache to maintain consistency.
 *
 * On exit,
 *  r1, r2, r3, r9, r10, r11, r12 corrupted
 * This routine must preserve:
 *  r4, r6, r7, r8
 */
		.align	5
cache_clean_flush:
		mov	r3, #16
		b	call_cache_fn

__armv4_mpu_cache_flush:
		mov	r2, #1
		mov	r3, #0
		mcr	p15, 0, ip, c7, c6, 0	@ invalidate D cache
		mov	r1, #7 << 5		@ 8 segments
1:		orr	r3, r1, #63 << 26	@ 64 entries
2:		mcr	p15, 0, r3, c7, c14, 2	@ clean & invalidate D index
		subs	r3, r3, #1 << 26
		bcs	2b			@ entries 63 to 0
		subs 	r1, r1, #1 << 5
		bcs	1b			@ segments 7 to 0

		teq	r2, #0
		mcrne	p15, 0, ip, c7, c5, 0	@ invalidate I cache
		mcr	p15, 0, ip, c7, c10, 4	@ drain WB
		mov	pc, lr
		
__fa526_cache_flush:
		mov	r1, #0
		mcr	p15, 0, r1, c7, c14, 0	@ clean and invalidate D cache
		mcr	p15, 0, r1, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv6_mmu_cache_flush:
		mov	r1, #0
		mcr	p15, 0, r1, c7, c14, 0	@ clean+invalidate D
		mcr	p15, 0, r1, c7, c5, 0	@ invalidate I+BTB
		mcr	p15, 0, r1, c7, c15, 0	@ clean+invalidate unified
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv7_mmu_cache_flush:
		mrc	p15, 0, r10, c0, c1, 5	@ read ID_MMFR1
		tst	r10, #0xf << 16		@ hierarchical cache (ARMv7)
		mov	r10, #0
		beq	hierarchical
		mcr	p15, 0, r10, c7, c14, 0	@ clean+invalidate D
		b	iflush
// 2013/07/20 종료
// 2013/07/27 시작
hierarchical:
		mcr	p15, 0, r10, c7, c10, 5	@ DMB
		stmfd	sp!, {r0-r7, r9-r11}
		mrc	p15, 1, r0, c0, c0, 1	@ read clidr
						// CACHE LEVEL ID REGISTER
						// T.R.M: 121p(4.3.22)
		ands	r3, r0, #0x7000000	@ extract loc from clidr
						// level of coherency
						// flush 하기 위한 cache level 값을 확인
		mov	r3, r3, lsr #23		@ left align loc bit field
						// 하위 0 하나를 남기고 0을 모두 없앰
						// r3 = 4, loc = 2 (cortex a15)
						// loc가 2는 memory hierarchy 가 3차란 뜻임
		beq	finished		@ if loc is 0, then no need to clean
						// 무시되고 넘어감 
		mov	r10, #0			@ start clean at cache level 0
loop1:
		add	r2, r10, r10, lsr #1	@ work out 3x current cache level
						// CLIDR의 register 의 Ctype# 의 데이터를 뽑기 위함임.
						// 3x의 의미는 계산용 숫자임
						// 순수 코드는 1.5배임, LSB에 0이 하나 추가 되어 있음
		mov	r1, r0, lsr r2		@ extract cache type bits from clidr
		and	r1, r1, #7		@ mask of the bits for current cache only
						// r1은 Ctype의 값
		cmp	r1, #2			@ see what cache we have at this level
						// Data cache 인지 확인 
						// A.R.M (B4.1.20)
		blt	skip			@ skip if no cache, or just i-cache
		mcr	p15, 2, r10, c0, c0, 0	@ select current cache level in cssr
						// Cache Size Selection Register 
						// A.R.M (B4.1.41)
		mcr	p15, 0, r10, c7, c5, 4	@ isb to sych the new cssr&csidr
		mrc	p15, 1, r1, c0, c0, 0	@ read the new csidr
						// A15 기준 : line size = 2 (의미 16 word)
						// L1 cache : Associativity = 1 (의미 2 way)
						// L2 cache : Associativity = F (의미 16 way)
						// Cache Size ID Register 
						// A.R.M (B4.1.19)
		and	r2, r1, #7		@ extract the length of the cache lines
						// r2 = cache lines
		add	r2, r2, #4		@ add 4 (line length offset)
		ldr	r4, =0x3ff
		ands	r4, r4, r1, lsr #3	@ find maximum number on the way size
						// r1 >> 3 = Associativity 값 추출
						// r4 = CSIDR의 Associativity값
						// Associativity의 의미?? N way cache, direct cache의 방법
						// cache line 의 관리 단위 : way 
		clz	r5, r4			@ find bit position of way size increment
						// clz : count leading zero 연산 
		ldr	r7, =0x7fff
		ands	r7, r7, r1, lsr #13	@ extract max number of the index size
						// r1 >> 13 = Numset 값 추출
						// r7 = CSIDR의 Numset값
loop2:
		mov	r9, r4			@ create working copy of max way size
						// r9 = CSIDR의 Associativity값
loop3:
 ARM(		orr	r11, r10, r9, lsl r5	) @ factor way and cache number into r11
 ARM(		orr	r11, r11, r7, lsl r2	) @ factor index number into r11
 THUMB(		lsl	r6, r9, r5		)
 THUMB(		orr	r11, r10, r6		) @ factor way and cache number into r11
 THUMB(		lsl	r6, r7, r2		)
 THUMB(		orr	r11, r11, r6		) @ factor index number into r11
		mcr	p15, 0, r11, c7, c14, 2	@ clean & invalidate by set/way
						// r11 : 해당 level의 cache 정보 
						// A.R.M (B4.1.45)
						// 민홍교수님 2차 세미나 자료 (p28)
		subs	r9, r9, #1		@ decrement the way
		bge	loop3
		subs	r7, r7, #1		@ decrement the index
		bge	loop2
skip:
		add	r10, r10, #2		@ increment cache number
		cmp	r3, r10			// r3 = loc * 2 값, r10 = 위에서 연산한 cache의 level
		bgt	loop1

// 모든 data cache를 flush 하였음

finished:
		ldmfd	sp!, {r0-r7, r9-r11}	// stack에 저장한 값 pop
		mov	r10, #0			@ swith back to cache level 0
		mcr	p15, 2, r10, c0, c0, 0	@ select current cache level in cssr
iflush:
		mcr	p15, 0, r10, c7, c10, 4	@ DSB
		mcr	p15, 0, r10, c7, c5, 0	@ invalidate I+BTB
						// BTB : Branch Target Buffer 
						// Branch prediction을 했다는 가정하에 기존의 history를 삭제
						// A.R.M (N3.2)
		mcr	p15, 0, r10, c7, c10, 4	@ DSB
		mcr	p15, 0, r10, c7, c5, 4	@ ISB
		mov	pc, lr

__armv5tej_mmu_cache_flush:
1:		mrc	p15, 0, r15, c7, c14, 3	@ test,clean,invalidate D cache
		bne	1b
		mcr	p15, 0, r0, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r0, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv4_mmu_cache_flush:
		mov	r2, #64*1024		@ default: 32K dcache size (*2)
		mov	r11, #32		@ default: 32 byte line size
		mrc	p15, 0, r3, c0, c0, 1	@ read cache type
		teq	r3, r9			@ cache ID register present?
		beq	no_cache_id
		mov	r1, r3, lsr #18
		and	r1, r1, #7
		mov	r2, #1024
		mov	r2, r2, lsl r1		@ base dcache size *2
		tst	r3, #1 << 14		@ test M bit
		addne	r2, r2, r2, lsr #1	@ +1/2 size if M == 1
		mov	r3, r3, lsr #12
		and	r3, r3, #3
		mov	r11, #8
		mov	r11, r11, lsl r3	@ cache line size in bytes
no_cache_id:
		mov	r1, pc
		bic	r1, r1, #63		@ align to longest cache line
		add	r2, r1, r2
1:
 ARM(		ldr	r3, [r1], r11		) @ s/w flush D cache
 THUMB(		ldr     r3, [r1]		) @ s/w flush D cache
 THUMB(		add     r1, r1, r11		)
		teq	r1, r2
		bne	1b

		mcr	p15, 0, r1, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r1, c7, c6, 0	@ flush D cache
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv3_mmu_cache_flush:
__armv3_mpu_cache_flush:
		mov	r1, #0
		mcr	p15, 0, r1, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

/*
 * Various debugging routines for printing hex characters and
 * memory, which again must be relocatable.
 */
#ifdef DEBUG
		.align	2
		.type	phexbuf,#object
phexbuf:	.space	12
		.size	phexbuf, . - phexbuf

@ phex corrupts {r0, r1, r2, r3}
phex:		adr	r3, phexbuf
		mov	r2, #0
		strb	r2, [r3, r1]
1:		subs	r1, r1, #1
		movmi	r0, r3
		bmi	puts
		and	r2, r0, #15
		mov	r0, r0, lsr #4
		cmp	r2, #10
		addge	r2, r2, #7
		add	r2, r2, #'0'
		strb	r2, [r3, r1]
		b	1b

@ puts corrupts {r0, r1, r2, r3}
puts:		loadsp	r3, r1
1:		ldrb	r2, [r0], #1
		teq	r2, #0
		moveq	pc, lr
2:		writeb	r2, r3
		mov	r1, #0x00020000
3:		subs	r1, r1, #1
		bne	3b
		teq	r2, #'\n'
		moveq	r2, #'\r'
		beq	2b
		teq	r0, #0
		bne	1b
		mov	pc, lr
@ putc corrupts {r0, r1, r2, r3}
putc:
		mov	r2, r0
		mov	r0, #0
		loadsp	r3, r1
		b	2b

@ memdump corrupts {r0, r1, r2, r3, r10, r11, r12, lr}
memdump:	mov	r12, r0
		mov	r10, lr
		mov	r11, #0
2:		mov	r0, r11, lsl #2
		add	r0, r0, r12
		mov	r1, #8
		bl	phex
		mov	r0, #':'
		bl	putc
1:		mov	r0, #' '
		bl	putc
		ldr	r0, [r12, r11, lsl #2]
		mov	r1, #8
		bl	phex
		and	r0, r11, #7
		teq	r0, #3
		moveq	r0, #' '
		bleq	putc
		and	r0, r11, #7
		add	r11, r11, #1
		teq	r0, #7
		bne	1b
		mov	r0, #'\n'
		bl	putc
		cmp	r11, #64
		blt	2b
		mov	pc, r10
#endif

		.ltorg

#ifdef CONFIG_ARM_VIRT_EXT
.align 5
__hyp_reentry_vectors:
		W(b)	.			@ reset
		W(b)	.			@ undef
		W(b)	.			@ svc
		W(b)	.			@ pabort
		W(b)	.			@ dabort
		W(b)	__enter_kernel		@ hyp
		W(b)	.			@ irq
		W(b)	.			@ fiq
#endif /* CONFIG_ARM_VIRT_EXT */

__enter_kernel:
		mov	r0, #0			@ must be 0
 ARM(		mov	pc, r4	)		@ call kernel
 THUMB(		bx	r4	)		@ entry point is always ARM

// 2013/07/27 종료

reloc_code_end:

		.align
		.section ".stack", "aw", %nobits

.L_user_stack:	.space	4096			// Stack공간을 4K만큼 잡음
.L_user_stack_end:




'

