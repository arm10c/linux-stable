/* find_last_bit.c: fallback find next bit implementation
 *
 * Copyright (C) 2008 IBM Corporation
 * Written by Rusty Russell <rusty@rustcorp.com.au>
 * (Inspired by David Howell's find_next_bit implementation)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/bitops.h>
#include <linux/export.h>
#include <asm/types.h>
#include <asm/byteorder.h>

#ifndef find_last_bit

// ARM10C 20140222
//cpumask_bits(cpu_possible_mask): cpu_possible_bits, NR_CPUS: 4
unsigned long find_last_bit(const unsigned long *addr, unsigned long size)
{
	unsigned long words;
	unsigned long tmp;

	/* Start at final word. */
	//BITS_PER_LONG: 32
	words = size / BITS_PER_LONG;
	//words: 0

	/* Partial final word? */
	if (size & (BITS_PER_LONG-1)) {
		//cpu_possible_bits[0] & (0xFFFF.. >> (32 -( 4 )))
		tmp = (addr[words] & (~0UL >> (BITS_PER_LONG
					 - (size & (BITS_PER_LONG-1)))));
		//tmp: 0xF 
		if (tmp)
			goto found;
	}

	while (words) {
		tmp = addr[--words];
		if (tmp) {
found:
			return words * BITS_PER_LONG + __fls(tmp);
			//return: 3
		}
	}

	/* Not found */
	return size;
}
EXPORT_SYMBOL(find_last_bit);

#endif
