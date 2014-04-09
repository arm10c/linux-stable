/*
 * Copyright 2012 Calxeda, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _ASM_ARM_PERCPU_H_
#define _ASM_ARM_PERCPU_H_

/*
 * Same as asm-generic/percpu.h, except that we store the per cpu offset
 * in the TPIDRPRW. TPIDRPRW only exists on V6K and V7
 */
#if defined(CONFIG_SMP) && !defined(CONFIG_CPU_V6) // CONFIG_SMP=y, CONFIG_CPU_V6=n
// ARM10C 20130928
// ARM10C 20140308
// __per_cpu_offset[0]: pcpu_unit_offsets[0] + __per_cpu_start에서의 pcpu_base_addr의 옵셋
static inline void set_my_cpu_offset(unsigned long off)
{
	// A.R.M: A3.6.1 Processor privilege levels, execution privilege, and access privilege
	//        B4.1.150 TPIDRPRW, PL1 only Thread ID Register, VMSA 
	// FIXME: TPIDRPRW를 사용하여 thread id를 설정하는 이유?
	/* Set TPIDRPRW */
	// off: __per_cpu_offset[0]: pcpu_unit_offsets[0] + __per_cpu_start에서의 pcpu_base_addr의 옵셋
	asm volatile("mcr p15, 0, %0, c13, c0, 4" : : "r" (off) : "memory");
}

// ARM10C 20140405
static inline unsigned long __my_cpu_offset(void)
{
	unsigned long off;
	register unsigned long *sp asm ("sp");

	/*
	 * Read TPIDRPRW.
	 * We want to allow caching the value, so avoid using volatile and
	 * instead use a fake stack read to hazard against barrier().
	 */
	asm("mrc p15, 0, %0, c13, c0, 4" : "=r" (off) : "Q" (*sp));

	return off;
}
// ARM10C 20140405
#define __my_cpu_offset __my_cpu_offset()
#else
#define set_my_cpu_offset(x)	do {} while(0)

#endif /* CONFIG_SMP */

#include <asm-generic/percpu.h>

#endif /* _ASM_ARM_PERCPU_H_ */
