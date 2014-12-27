/* Fallback per-CPU frame pointer holder
 *
 * Copyright (C) 2006 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _ASM_GENERIC_IRQ_REGS_H
#define _ASM_GENERIC_IRQ_REGS_H

#include <linux/percpu.h>

/*
 * Per-cpu current frame pointer - the location of the last exception frame on
 * the stack
 */
// ARM10C 20141227
DECLARE_PER_CPU(struct pt_regs *, __irq_regs);

static inline struct pt_regs *get_irq_regs(void)
{
	return __this_cpu_read(__irq_regs);
}

// ARM10C 20141227
// regs: svc_entry에서 만든 struct pt_regs의 시작 주소
static inline struct pt_regs *set_irq_regs(struct pt_regs *new_regs)
{
	struct pt_regs *old_regs;

	// __this_cpu_read(__irq_regs): [pcp0] irq 발생 전의 regs 값
	old_regs = __this_cpu_read(__irq_regs);
	// old_regs: [pcp0] irq 발생 전의 regs 값

	// new_regs: svc_entry에서 만든 struct pt_regs의 시작 주소
	__this_cpu_write(__irq_regs, new_regs);
	// [pcp0] __irq_regs: svc_entry에서 만든 struct pt_regs의 시작 주소

	// old_regs: [pcp0] irq 발생 전의 regs 값
	return old_regs;
	// return [pcp0] irq 발생 전의 regs 값
}

#endif /* _ASM_GENERIC_IRQ_REGS_H */
