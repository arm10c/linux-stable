/*
 * Copyright (C) 2012 Thomas Petazzoni
 *
 * Thomas Petazzoni <thomas.petazzoni@free-electrons.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/init.h>
#include <linux/of_irq.h>

#include "irqchip.h"

/*
 * This special of_device_id is the sentinel at the end of the
 * of_device_id[] array of all irqchips. It is automatically placed at
 * the end of the array by the linker, thanks to being part of a
 * special section.
 */
static const struct of_device_id
irqchip_of_match_end __used __section(__irqchip_of_end);

// ARM10C 20141004
extern struct of_device_id __irqchip_begin[];

// ARM10C 20141004
void __init irqchip_init(void)
{
	// exynos-combiner.c 에 정의된 함수를 사용하여 초기화 수행
	// __irqchip_begin: irqchip_of_match_exynos4210_combiner
	of_irq_init(__irqchip_begin);
}
