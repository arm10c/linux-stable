/*
 *  arch/arm/include/asm/clkdev.h
 *
 *  Copyright (C) 2008 Russell King.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Helper for the clk API to assist looking up a struct clk.
 */
#ifndef __ASM_CLKDEV_H
#define __ASM_CLKDEV_H

#include <linux/slab.h>

#ifdef CONFIG_HAVE_MACH_CLKDEV
#include <mach/clkdev.h>
#else
#define __clk_get(clk)	({ 1; })
#define __clk_put(clk)	do { } while (0)
#endif

// ARM10C 20150117
// sizeof(struct clk_lookup_alloc): 56 bytes
static inline struct clk_lookup_alloc *__clkdev_alloc(size_t size)
{
	// size: 56, GFP_KERNEL: 0xD0
	// kzalloc(56, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	return kzalloc(size, GFP_KERNEL);
	// return kmem_cache#30-oX
}

#endif
