#ifndef __ASMARM_TLS_H
#define __ASMARM_TLS_H

#ifdef __ASSEMBLY__
#include <asm/asm-offsets.h>
	.macro switch_tls_none, base, tp, tpuser, tmp1, tmp2
	.endm

	.macro switch_tls_v6k, base, tp, tpuser, tmp1, tmp2
	mrc	p15, 0, \tmp2, c13, c0, 2	@ get the user r/w register
	mcr	p15, 0, \tp, c13, c0, 3		@ set TLS register
	mcr	p15, 0, \tpuser, c13, c0, 2	@ and the user r/w register
	str	\tmp2, [\base, #TI_TP_VALUE + 4] @ save it
	.endm

	.macro switch_tls_v6, base, tp, tpuser, tmp1, tmp2
	ldr	\tmp1, =elf_hwcap
	ldr	\tmp1, [\tmp1, #0]
	mov	\tmp2, #0xffff0fff
	tst	\tmp1, #HWCAP_TLS		@ hardware TLS available?
	streq	\tp, [\tmp2, #-15]		@ set TLS value at 0xffff0ff0
	mrcne	p15, 0, \tmp2, c13, c0, 2	@ get the user r/w register
	mcrne	p15, 0, \tp, c13, c0, 3		@ yes, set TLS register
	mcrne	p15, 0, \tpuser, c13, c0, 2	@ set user r/w register
	strne	\tmp2, [\base, #TI_TP_VALUE + 4] @ save it
	.endm

	.macro switch_tls_software, base, tp, tpuser, tmp1, tmp2
	mov	\tmp1, #0xffff0fff
	str	\tp, [\tmp1, #-15]		@ set TLS value at 0xffff0ff0
	.endm
#endif

#ifdef CONFIG_TLS_REG_EMUL // CONFIG_TLS_REG_EMUL=n
#define tls_emu		1
#define has_tls_reg		1
#define switch_tls	switch_tls_none
#elif defined(CONFIG_CPU_V6) // CONFIG_CPU_V6=n
#define tls_emu		0
#define has_tls_reg		(elf_hwcap & HWCAP_TLS)
#define switch_tls	switch_tls_v6
#elif defined(CONFIG_CPU_32v6K) // CONFIG_CPU_32v6K=y
// ARM10C 20131116
// ARM10C 20161105
#define tls_emu		0
// ARM10C 20161105
#define has_tls_reg		1
#define switch_tls	switch_tls_v6k
#else
#define tls_emu		0
#define has_tls_reg		0
#define switch_tls	switch_tls_software
#endif

#ifndef __ASSEMBLY__
// ARM10C 20161105
static inline unsigned long get_tpuser(void)
{
	unsigned long reg = 0;
	// reg: 0

	// A.R.M: B6.1.92 TPIDRURW, User Read/Write Thread ID Register, PMSA
	// Provides a location where software executing at PL1 can store thread identifying information
	// that is visible to unprivileged software, for OS management purposes

	// has_tls_reg: 1, tls_emu: 0
	if (has_tls_reg && !tls_emu)
		__asm__("mrc p15, 0, %0, c13, c0, 2" : "=r" (reg));

	// reg: TPIDRURW의 읽은 값

	// reg: TPIDRURW의 읽은 값
	return reg;
	// return TPIDRURW의 읽은 값
}
#endif
#endif	/* __ASMARM_TLS_H */
