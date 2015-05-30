/*
 * linux/kernel/time/clocksource.c
 *
 * This file contains the functions which manage clocksource drivers.
 *
 * Copyright (C) 2004, 2005 IBM, John Stultz (johnstul@us.ibm.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * TODO WishList:
 *   o Allow clocksource drivers to be unregistered
 */

#include <linux/device.h>
#include <linux/clocksource.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h> /* for spin_unlock_irq() using preempt_count() m68k */
#include <linux/tick.h>
#include <linux/kthread.h>

#include "tick-internal.h"

void timecounter_init(struct timecounter *tc,
		      const struct cyclecounter *cc,
		      u64 start_tstamp)
{
	tc->cc = cc;
	tc->cycle_last = cc->read(cc);
	tc->nsec = start_tstamp;
}
EXPORT_SYMBOL_GPL(timecounter_init);

/**
 * timecounter_read_delta - get nanoseconds since last call of this function
 * @tc:         Pointer to time counter
 *
 * When the underlying cycle counter runs over, this will be handled
 * correctly as long as it does not run over more than once between
 * calls.
 *
 * The first call to this function for a new time counter initializes
 * the time tracking and returns an undefined result.
 */
static u64 timecounter_read_delta(struct timecounter *tc)
{
	cycle_t cycle_now, cycle_delta;
	u64 ns_offset;

	/* read cycle counter: */
	cycle_now = tc->cc->read(tc->cc);

	/* calculate the delta since the last timecounter_read_delta(): */
	cycle_delta = (cycle_now - tc->cycle_last) & tc->cc->mask;

	/* convert to nanoseconds: */
	ns_offset = cyclecounter_cyc2ns(tc->cc, cycle_delta);

	/* update time stamp of timecounter_read_delta() call: */
	tc->cycle_last = cycle_now;

	return ns_offset;
}

u64 timecounter_read(struct timecounter *tc)
{
	u64 nsec;

	/* increment time by nanoseconds since last call */
	nsec = timecounter_read_delta(tc);
	nsec += tc->nsec;
	tc->nsec = nsec;

	return nsec;
}
EXPORT_SYMBOL_GPL(timecounter_read);

u64 timecounter_cyc2time(struct timecounter *tc,
			 cycle_t cycle_tstamp)
{
	u64 cycle_delta = (cycle_tstamp - tc->cycle_last) & tc->cc->mask;
	u64 nsec;

	/*
	 * Instead of always treating cycle_tstamp as more recent
	 * than tc->cycle_last, detect when it is too far in the
	 * future and treat it as old time stamp instead.
	 */
	if (cycle_delta > tc->cc->mask / 2) {
		cycle_delta = (tc->cycle_last - cycle_tstamp) & tc->cc->mask;
		nsec = tc->nsec - cyclecounter_cyc2ns(tc->cc, cycle_delta);
	} else {
		nsec = cyclecounter_cyc2ns(tc->cc, cycle_delta) + tc->nsec;
	}

	return nsec;
}
EXPORT_SYMBOL_GPL(timecounter_cyc2time);

/**
 * clocks_calc_mult_shift - calculate mult/shift factors for scaled math of clocks
 * @mult:	pointer to mult variable
 * @shift:	pointer to shift variable
 * @from:	frequency to convert from
 * @to:		frequency to convert to
 * @maxsec:	guaranteed runtime conversion range in seconds
 *
 * The function evaluates the shift/mult pair for the scaled math
 * operations of clocksources and clockevents.
 *
 * @to and @from are frequency values in HZ. For clock sources @to is
 * NSEC_PER_SEC == 1GHz and @from is the counter frequency. For clock
 * event @to is the counter frequency and @from is NSEC_PER_SEC.
 *
 * The @maxsec conversion range argument controls the time frame in
 * seconds which must be covered by the runtime conversion with the
 * calculated mult and shift factors. This guarantees that no 64bit
 * overflow happens when the input value of the conversion is
 * multiplied with the calculated mult factor. Larger ranges may
 * reduce the conversion accuracy by chosing smaller mult and shift
 * factors.
 */
// ARM10C 20150411
// [1st] &ce->mult: [pcp0] &(&(&percpu_mct_tick)->evt)->mult,
// &ce->shift: [pcp0] &(&(&percpu_mct_tick)->evt)->shift,
// NSEC_PER_SEC: 1000000000L, freq: 12000000, minsec: 178
// ARM10C 20150523
// [2nd] &cs->mult: &(&mct_frc)->mult, &cs->shift: &(&mct_frc)->mult,
// freq: 24000000, 1000000000, 156
// ARM10C 20150523
// [3rd] &ce->mult: &(&mct_comp_device)->mult, &ce->shift: &(&mct_comp_device)->shift,
// NSEC_PER_SEC: 1000000000L, freq: 24000000, minsec: 178
// ARM10C 20150530
// [4th] &cd.mult, &cd.shift, rate: 100, NSEC_PER_SEC: 1000000000L, 3600
void
clocks_calc_mult_shift(u32 *mult, u32 *shift, u32 from, u32 to, u32 maxsec)
{
	u64 tmp;
	u32 sft, sftacc= 32;
	// [1st] sftacc: 32
	// [2nd] sftacc: 32
	// [3rd] sftacc: 32
	// [4th] sftacc: 32

	/*
	 * Calculate the shift factor which is limiting the conversion
	 * range:
	 */
	// [1st] maxsec: 178, from: 1000000000L
	// [2nd] maxsec: 156, from: 24000000
	// [3rd] maxsec: 178, from: 1000000000L
	// [4th] maxsec: 3600, from: 100
	tmp = ((u64)maxsec * from) >> 32;
	// [1st] tmp: 41
	// [2nd] tmp: 0
	// [3rd] tmp: 41
	// [4th] tmp: 0

	// [1st] tmp: 41, sftacc: 32
	// [2nd] tmp: 0, sftacc: 32
	// [3rd] tmp: 41, sftacc: 32
	// [4th] tmp: 0, sftacc: 32
	while (tmp) {
		tmp >>=1;
		sftacc--;
	}
	// [1st] sftacc: 26, tmp: 0
	// [2nd] sftacc: 32, tmp: 0
	// [3rd] sftacc: 26, tmp: 0
	// [4th] sftacc: 32, tmp: 0

	/*
	 * Find the conversion shift/mult pair which has the best
	 * accuracy and fits the maxsec conversion range:
	 */
	for (sft = 32; sft > 0; sft--) {
		// NOTE:
		// for 의 1st loop 수행을 [f1] 로, 2nd loop 수행을 [f2] 로 주석에 prefix 로 추가

		// [1st][f1]  sft: 32, to: 12000000
		// [2nd][f1]  sft: 32, to: 1000000000
		// [2nd][f2]  sft: 31, to: 1000000000
		// [2nd][f3]  sft: 30, to: 1000000000
		// [2nd][f4]  sft: 29, to: 1000000000
		// [2nd][f5]  sft: 28, to: 1000000000
		// [2nd][f6]  sft: 27, to: 1000000000
		// [2nd][f7]  sft: 26, to: 1000000000
		// [3rd][f1]  sft: 32, to: 24000000
		// [3rd][f2]  sft: 31, to: 24000000
		// [4th][f1]  sft: 32, to: 1000000000
		// [4th][f2]  sft: 31, to: 1000000000
		// [4th][f3]  sft: 30, to: 1000000000
		// [4th][f4]  sft: 29, to: 1000000000
		// [4th][f5]  sft: 28, to: 1000000000
		// [4th][f6]  sft: 27, to: 1000000000
		// [4th][f7]  sft: 26, to: 1000000000
		// [4th][f8]  sft: 25, to: 1000000000
		// [4th][f9]  sft: 24, to: 1000000000
		// [4th][f10] sft: 23, to: 1000000000
		// [4th][f11] sft: 22, to: 1000000000
		// [4th][f12] sft: 21, to: 1000000000
		// [4th][f13] sft: 20, to: 1000000000
		// [4th][f14] sft: 19, to: 1000000000
		// [4th][f15] sft: 18, to: 1000000000
		// [4th][f16] sft: 17, to: 1000000000
		// [4th][f17] sft: 16, to: 1000000000
		// [4th][f18] sft: 15, to: 1000000000
		// [4th][f19] sft: 14, to: 1000000000
		// [4th][f20] sft: 13, to: 1000000000
		// [4th][f21] sft: 12, to: 1000000000
		// [4th][f22] sft: 11, to: 1000000000
		// [4th][f23] sft: 10, to: 1000000000
		// [4th][f24] sft:  9, to: 1000000000
		// [4th][f25] sft:  8, to: 1000000000
		tmp = (u64) to << sft;
		// [1st][f1]  tmp: 0xb71b0000000000
		// [2nd][f1]  tmp: 0x3B9ACA0000000000
		// [2nd][f2]  tmp: 0x1DCD650000000000
		// [2nd][f3]  tmp: 0xEE6B28000000000
		// [2nd][f4]  tmp: 0x773594000000000
		// [2nd][f5]  tmp: 0x3B9ACA000000000
		// [2nd][f6]  tmp: 0x1DCD65000000000
		// [2nd][f7]  tmp: 0xEE6B2800000000
		// [3rd][f1]  tmp: 0x16E360000000000
		// [3rd][f2]  tmp: 0xB71B0000000000
		// [4th][f1]  tmp: 0x3B9ACA0000000000
		// [4th][f2]  tmp: 0x1DCD650000000000
		// [4th][f3]  tmp: 0xEE6B28000000000
		// [4th][f4]  tmp: 0x773594000000000
		// [4th][f5]  tmp: 0x3B9ACA000000000
		// [4th][f6]  tmp: 0x1DCD65000000000
		// [4th][f7]  tmp: 0xEE6B2800000000
		// [4th][f8]  tmp: 0x77359400000000
		// [4th][f9]  tmp: 0x3B9ACA00000000
		// [4th][f10] tmp: 0x1DCD6500000000
		// [4th][f11] tmp: 0xEE6B280000000
		// [4th][f12] tmp: 0x7735940000000
		// [4th][f13] tmp: 0x3B9ACA0000000
		// [4th][f14] tmp: 0x1DCD650000000
		// [4th][f15] tmp: 0xEE6B28000000
		// [4th][f16] tmp: 0x773594000000
		// [4th][f17] tmp: 0x3B9ACA000000
		// [4th][f18] tmp: 0x1DCD65000000
		// [4th][f19] tmp: 0xEE6B2800000
		// [4th][f20] tmp: 0x77359400000
		// [4th][f21] tmp: 0x3B9ACA00000
		// [4th][f22] tmp: 0x1DCD6500000
		// [4th][f23] tmp: 0xEE6B280000
		// [4th][f24] tmp: 0x7735940000
		// [4th][f25] tmp: 0x3B9ACA0000

		// [1st][f1]  tmp: 0xb71b0000000000,   from: 1000000000L
		// [2nd][f1]  tmp: 0x3B9ACA0000000000, from: 24000000
		// [2nd][f2]  tmp: 0x1DCD650000000000, from: 24000000
		// [2nd][f3]  tmp: 0xEE6B28000000000,  from: 24000000
		// [2nd][f4]  tmp: 0x773594000000000,  from: 24000000
		// [2nd][f5]  tmp: 0x3B9ACA000000000,  from: 24000000
		// [2nd][f6]  tmp: 0x1DCD65000000000,  from: 24000000
		// [2nd][f7]  tmp: 0xEE6B2800000000,   from: 24000000
		// [3rd][f1]  tmp: 0x16E360000000000,  from: 1000000000L
		// [3rd][f2]  tmp: 0xB71B0000000000,   from: 1000000000L
		// [4th][f1]  tmp: 0x3B9ACA0000000000, from: 100
		// [4th][f2]  tmp: 0x1DCD650000000000, from: 100
		// [4th][f3]  tmp: 0xEE6B28000000000,  from: 100
		// [4th][f4]  tmp: 0x773594000000000,  from: 100
		// [4th][f5]  tmp: 0x3B9ACA000000000,  from: 100
		// [4th][f6]  tmp: 0x1DCD65000000000,  from: 100
		// [4th][f7]  tmp: 0xEE6B2800000000,   from: 100
		// [4th][f8]  tmp: 0x77359400000000,   from: 100
		// [4th][f9]  tmp: 0x3B9ACA00000000,   from: 100
		// [4th][f10] tmp: 0x1DCD6500000000,   from: 100
		// [4th][f11] tmp: 0xEE6B280000000,    from: 100
		// [4th][f12] tmp: 0x7735940000000,    from: 100
		// [4th][f13] tmp: 0x3B9ACA0000000,    from: 100
		// [4th][f14] tmp: 0x1DCD650000000,    from: 100
		// [4th][f15] tmp: 0xEE6B28000000,     from: 100
		// [4th][f16] tmp: 0x773594000000,     from: 100
		// [4th][f17] tmp: 0x3B9ACA000000,     from: 100
		// [4th][f18] tmp: 0x1DCD65000000,     from: 100
		// [4th][f19] tmp: 0xEE6B2800000,      from: 100
		// [4th][f20] tmp: 0x77359400000,      from: 100
		// [4th][f21] tmp: 0x3B9ACA00000,      from: 100
		// [4th][f22] tmp: 0x1DCD6500000,      from: 100
		// [4th][f23] tmp: 0xEE6B280000,       from: 100
		// [4th][f24] tmp: 0x7735940000,       from: 100
		// [4th][f25] tmp: 0x3B9ACA0000,       from: 100
		tmp += from / 2;
		// [1st][f1]  tmp: 0xb71b001dcd6500
		// [2nd][f1]  tmp: 0x3B9ACA0000B71B00
		// [2nd][f2]  tmp: 0x1DCD650000B71B00
		// [2nd][f3]  tmp: 0xEE6B28000B71B00
		// [2nd][f4]  tmp: 0x773594000B71B00
		// [2nd][f5]  tmp: 0x3B9ACA000B71B00
		// [2nd][f6]  tmp: 0x1DCD65000B71B00
		// [2nd][f7]  tmp: 0xEE6B2800B71B00
		// [3rd][f1]  tmp: 0x16E36001DCD6500
		// [3rd][f2]  tmp: 0xB71B001DCD6500
		// [4th][f1]  tmp: 0x3B9ACA0000000032
		// [4th][f2]  tmp: 0x1DCD650000000032
		// [4th][f3]  tmp: 0xEE6B28000000032
		// [4th][f4]  tmp: 0x773594000000032
		// [4th][f5]  tmp: 0x3B9ACA000000032
		// [4th][f6]  tmp: 0x1DCD65000000032
		// [4th][f7]  tmp: 0xEE6B2800000032
		// [4th][f8]  tmp: 0x77359400000032
		// [4th][f9]  tmp: 0x3B9ACA00000032
		// [4th][f10] tmp: 0x1DCD6500000032
		// [4th][f11] tmp: 0xEE6B280000032
		// [4th][f12] tmp: 0x7735940000032
		// [4th][f13] tmp: 0x3B9ACA0000032
		// [4th][f14] tmp: 0x1DCD650000032
		// [4th][f15] tmp: 0xEE6B28000032
		// [4th][f16] tmp: 0x773594000032
		// [4th][f17] tmp: 0x3B9ACA000032
		// [4th][f18] tmp: 0x1DCD65000032
		// [4th][f19] tmp: 0xEE6B2800032
		// [4th][f20] tmp: 0x77359400032
		// [4th][f21] tmp: 0x3B9ACA00032
		// [4th][f22] tmp: 0x1DCD6500032
		// [4th][f23] tmp: 0xEE6B280032
		// [4th][f24] tmp: 0x7735940032
		// [4th][f25] tmp: 0x3B9ACA0032

		// [1st][f1]  tmp: 0xb71b001dcd6500,   from: 1000000000L
		// [2nd][f1]  tmp: 0x3B9ACA0000B71B00, from: 24000000
		// [2nd][f2]  tmp: 0x1DCD650000B71B00, from: 24000000
		// [2nd][f3]  tmp: 0xEE6B28000B71B00,  from: 24000000
		// [2nd][f4]  tmp: 0x773594000B71B00,  from: 24000000
		// [2nd][f5]  tmp: 0x3B9ACA000B71B00,  from: 24000000
		// [2nd][f6]  tmp: 0x1DCD65000B71B00,  from: 24000000
		// [2nd][f7]  tmp: 0xEE6B2800B71B00,   from: 24000000
		// [3rd][f1]  tmp: 0x16E36001DCD6500,  from: 1000000000L
		// [3rd][f2]  tmp: 0xB71B001DCD6500,   from: 1000000000L
		// [4th][f1]  tmp: 0x3B9ACA0000000032, from: 100
		// [4th][f2]  tmp: 0x1DCD650000000032, from: 100
		// [4th][f3]  tmp: 0xEE6B28000000032,  from: 100
		// [4th][f4]  tmp: 0x773594000000032,  from: 100
		// [4th][f5]  tmp: 0x3B9ACA000000032,  from: 100
		// [4th][f6]  tmp: 0x1DCD65000000032,  from: 100
		// [4th][f7]  tmp: 0xEE6B2800000032,   from: 100
		// [4th][f8]  tmp: 0x77359400000032,   from: 100
		// [4th][f9]  tmp: 0x3B9ACA00000032,   from: 100
		// [4th][f10] tmp: 0x1DCD6500000032,   from: 100
		// [4th][f11] tmp: 0xEE6B280000032,    from: 100
		// [4th][f12] tmp: 0x7735940000032,    from: 100
		// [4th][f13] tmp: 0x3B9ACA0000032,    from: 100
		// [4th][f14] tmp: 0x1DCD650000032,    from: 100
		// [4th][f15] tmp: 0xEE6B28000032,     from: 100
		// [4th][f16] tmp: 0x773594000032,     from: 100
		// [4th][f17] tmp: 0x3B9ACA000032,     from: 100
		// [4th][f18] tmp: 0x1DCD65000032,     from: 100
		// [4th][f19] tmp: 0xEE6B2800032,      from: 100
		// [4th][f20] tmp: 0x77359400032,      from: 100
		// [4th][f21] tmp: 0x3B9ACA00032,      from: 100
		// [4th][f22] tmp: 0x1DCD6500032,      from: 100
		// [4th][f23] tmp: 0xEE6B280032,       from: 100
		// [4th][f24] tmp: 0x7735940032,       from: 100
		// [4th][f25] tmp: 0x3B9ACA0032,       from: 100
		do_div(tmp, from);
		// [1st][f1]  tmp: 0x3126E98
		// [2nd][f1]  tmp: 0x29AAAAAAAB
		// [2nd][f2]  tmp: 0x14D5555555
		// [2nd][f3]  tmp: 0xA6AAAAAAB
		// [2nd][f4]  tmp: 0x535555555
		// [2nd][f5]  tmp: 0x29AAAAAAA
		// [2nd][f6]  tmp: 0x14D555555
		// [2nd][f7]  tmp: 0xA6AAAAAA
		// [3rd][f1]  tmp: 0x624DD2F
		// [3rd][f2]  tmp: 0x3126E98
		// [4th][f1]  tmp: 0x98968000000000
		// [4th][f2]  tmp: 0x4C4B4000000000
		// [4th][f3]  tmp: 0x2625A000000000
		// [4th][f4]  tmp: 0x1312D000000000
		// [4th][f5]  tmp: 0x9896800000000
		// [4th][f6]  tmp: 0x4C4B400000000
		// [4th][f7]  tmp: 0x2625A00000000
		// [4th][f8]  tmp: 0x1312D00000000
		// [4th][f9]  tmp: 0x989680000000
		// [4th][f10] tmp: 0x4C4B40000000
		// [4th][f11] tmp: 0x2625A0000000
		// [4th][f12] tmp: 0x1312D0000000
		// [4th][f13] tmp: 0x98968000000
		// [4th][f14] tmp: 0x4C4B4000000
		// [4th][f15] tmp: 0x2625A000000
		// [4th][f16] tmp: 0x1312D000000
		// [4th][f17] tmp: 0x9896800000
		// [4th][f18] tmp: 0x4C4B400000
		// [4th][f19] tmp: 0x2625A00000
		// [4th][f20] tmp: 0x1312D00000
		// [4th][f21] tmp: 0x989680000
		// [4th][f22] tmp: 0x4C4B40000
		// [4th][f23] tmp: 0x2625A0000
		// [4th][f24] tmp: 0x1312D0000
		// [4th][f25] tmp: 0x98968000

		// [1st][f1]  tmp: 0x3126E98,        sftacc: 26
		// [2nd][f1]  tmp: 0x29AAAAAAAB,     sftacc: 32
		// [2nd][f2]  tmp: 0x14D5555555,     sftacc: 32
		// [2nd][f3]  tmp: 0xA6AAAAAAB,      sftacc: 32
		// [2nd][f4]  tmp: 0x535555555,      sftacc: 32
		// [2nd][f5]  tmp: 0x29AAAAAAA,      sftacc: 32
		// [2nd][f6]  tmp: 0x14D555555,      sftacc: 32
		// [2nd][f7]  tmp: 0xA6AAAAAA,       sftacc: 32
		// [3rd][f1]  tmp: 0x624DD2F,        sftacc: 26
		// [3rd][f2]  tmp: 0x3126E98,        sftacc: 26
		// [4th][f1]  tmp: 0x98968000000000, sftacc: 32
		// [4th][f2]  tmp: 0x4C4B4000000000, sftacc: 32
		// [4th][f3]  tmp: 0x2625A000000000, sftacc: 32
		// [4th][f4]  tmp: 0x1312D000000000, sftacc: 32
		// [4th][f5]  tmp: 0x9896800000000,  sftacc: 32
		// [4th][f6]  tmp: 0x4C4B400000000,  sftacc: 32
		// [4th][f7]  tmp: 0x2625A00000000,  sftacc: 32
		// [4th][f8]  tmp: 0x1312D00000000,  sftacc: 32
		// [4th][f9]  tmp: 0x989680000000,   sftacc: 32
		// [4th][f10] tmp: 0x4C4B40000000,   sftacc: 32
		// [4th][f11] tmp: 0x2625A0000000,   sftacc: 32
		// [4th][f12] tmp: 0x1312D0000000,   sftacc: 32
		// [4th][f13] tmp: 0x98968000000,    sftacc: 32
		// [4th][f14] tmp: 0x4C4B4000000,    sftacc: 32
		// [4th][f15] tmp: 0x2625A000000,    sftacc: 32
		// [4th][f16] tmp: 0x1312D000000,    sftacc: 32
		// [4th][f17] tmp: 0x9896800000,     sftacc: 32
		// [4th][f18] tmp: 0x4C4B400000,     sftacc: 32
		// [4th][f19] tmp: 0x2625A00000,     sftacc: 32
		// [4th][f20] tmp: 0x1312D00000,     sftacc: 32
		// [4th][f21] tmp: 0x989680000,      sftacc: 32
		// [4th][f22] tmp: 0x4C4B40000,      sftacc: 32
		// [4th][f23] tmp: 0x2625A0000,      sftacc: 32
		// [4th][f24] tmp: 0x1312D0000,      sftacc: 32
		// [4th][f25] tmp: 0x98968000,       sftacc: 32
		if ((tmp >> sftacc) == 0)
			break;
			// [1st][f1]  break 수행
			// [2nd][f7]  break 수행
			// [3rd][f2]  break 수행
			// [4th][f25] break 수행
	}

	// [1st] *mult: [pcp0] (&(&percpu_mct_tick)->evt)->mult, tmp: 0x3126E98
	// [2nd] *mult: (&mct_frc)->mult, tmp: 0xA6AAAAAA
	// [3rd] *mult: (&mct_comp_device)->mult, tmp: 0x3126E98
	// [4th] *mult: (&cd)->mult, tmp: 0x98968000
	*mult = tmp;
	// [1st] *mult: [pcp0] (&(&percpu_mct_tick)->evt)->mult: 0x3126E98
	// [2nd] *mult: (&mct_frc)->mult: 0xA6AAAAAA
	// [3rd] *mult: (&mct_comp_device)->mult: 0x3126E98
	// [4th] *mult: (&cd)->mult: 0x98968000

	// [1st] *shift: [pcp0] (&(&percpu_mct_tick)->evt)->shift, sft: 32
	// [2nd] *shift: (&mct_frc)->mult, sft: 26
	// [3rd] *shift: (&mct_comp_device)->shift, sft: 31
	// [4th] *shift: (&cd)->shift, sft: 8
	*shift = sft;
	// [1st] *shift: [pcp0] (&(&percpu_mct_tick)->evt)->shift: 32
	// [2nd] *shift: (&mct_frc)->shift: 26
	// [3rd] *shift: (&mct_comp_device)->shift: 31
	// [4th] *shift: (&cd)->shift: 8
}

/*[Clocksource internal variables]---------
 * curr_clocksource:
 *	currently selected clocksource.
 * clocksource_list:
 *	linked list with the registered clocksources
 * clocksource_mutex:
 *	protects manipulations to curr_clocksource and the clocksource_list
 * override_name:
 *	Name of the user-specified clocksource.
 */
static struct clocksource *curr_clocksource;
// ARM10C 20150523
static LIST_HEAD(clocksource_list);
// ARM10C 20150523
static DEFINE_MUTEX(clocksource_mutex);
static char override_name[CS_NAME_LEN];
// ARM10C 20150523
static int finished_booting;

#ifdef CONFIG_CLOCKSOURCE_WATCHDOG // CONFIG_CLOCKSOURCE_WATCHDOG=n
static void clocksource_watchdog_work(struct work_struct *work);
static void clocksource_select(void);

static LIST_HEAD(watchdog_list);
static struct clocksource *watchdog;
static struct timer_list watchdog_timer;
static DECLARE_WORK(watchdog_work, clocksource_watchdog_work);
static DEFINE_SPINLOCK(watchdog_lock);
static int watchdog_running;
static atomic_t watchdog_reset_pending;

static int clocksource_watchdog_kthread(void *data);
static void __clocksource_change_rating(struct clocksource *cs, int rating);

/*
 * Interval: 0.5sec Threshold: 0.0625s
 */
#define WATCHDOG_INTERVAL (HZ >> 1)
#define WATCHDOG_THRESHOLD (NSEC_PER_SEC >> 4)

static void clocksource_watchdog_work(struct work_struct *work)
{
	/*
	 * If kthread_run fails the next watchdog scan over the
	 * watchdog_list will find the unstable clock again.
	 */
	kthread_run(clocksource_watchdog_kthread, NULL, "kwatchdog");
}

static void __clocksource_unstable(struct clocksource *cs)
{
	cs->flags &= ~(CLOCK_SOURCE_VALID_FOR_HRES | CLOCK_SOURCE_WATCHDOG);
	cs->flags |= CLOCK_SOURCE_UNSTABLE;
	if (finished_booting)
		schedule_work(&watchdog_work);
}

static void clocksource_unstable(struct clocksource *cs, int64_t delta)
{
	printk(KERN_WARNING "Clocksource %s unstable (delta = %Ld ns)\n",
	       cs->name, delta);
	__clocksource_unstable(cs);
}

/**
 * clocksource_mark_unstable - mark clocksource unstable via watchdog
 * @cs:		clocksource to be marked unstable
 *
 * This function is called instead of clocksource_change_rating from
 * cpu hotplug code to avoid a deadlock between the clocksource mutex
 * and the cpu hotplug mutex. It defers the update of the clocksource
 * to the watchdog thread.
 */
void clocksource_mark_unstable(struct clocksource *cs)
{
	unsigned long flags;

	spin_lock_irqsave(&watchdog_lock, flags);
	if (!(cs->flags & CLOCK_SOURCE_UNSTABLE)) {
		if (list_empty(&cs->wd_list))
			list_add(&cs->wd_list, &watchdog_list);
		__clocksource_unstable(cs);
	}
	spin_unlock_irqrestore(&watchdog_lock, flags);
}

static void clocksource_watchdog(unsigned long data)
{
	struct clocksource *cs;
	cycle_t csnow, wdnow;
	int64_t wd_nsec, cs_nsec;
	int next_cpu, reset_pending;

	spin_lock(&watchdog_lock);
	if (!watchdog_running)
		goto out;

	reset_pending = atomic_read(&watchdog_reset_pending);

	list_for_each_entry(cs, &watchdog_list, wd_list) {

		/* Clocksource already marked unstable? */
		if (cs->flags & CLOCK_SOURCE_UNSTABLE) {
			if (finished_booting)
				schedule_work(&watchdog_work);
			continue;
		}

		local_irq_disable();
		csnow = cs->read(cs);
		wdnow = watchdog->read(watchdog);
		local_irq_enable();

		/* Clocksource initialized ? */
		if (!(cs->flags & CLOCK_SOURCE_WATCHDOG) ||
		    atomic_read(&watchdog_reset_pending)) {
			cs->flags |= CLOCK_SOURCE_WATCHDOG;
			cs->wd_last = wdnow;
			cs->cs_last = csnow;
			continue;
		}

		wd_nsec = clocksource_cyc2ns((wdnow - cs->wd_last) & watchdog->mask,
					     watchdog->mult, watchdog->shift);

		cs_nsec = clocksource_cyc2ns((csnow - cs->cs_last) &
					     cs->mask, cs->mult, cs->shift);
		cs->cs_last = csnow;
		cs->wd_last = wdnow;

		if (atomic_read(&watchdog_reset_pending))
			continue;

		/* Check the deviation from the watchdog clocksource. */
		if ((abs(cs_nsec - wd_nsec) > WATCHDOG_THRESHOLD)) {
			clocksource_unstable(cs, cs_nsec - wd_nsec);
			continue;
		}

		if (!(cs->flags & CLOCK_SOURCE_VALID_FOR_HRES) &&
		    (cs->flags & CLOCK_SOURCE_IS_CONTINUOUS) &&
		    (watchdog->flags & CLOCK_SOURCE_IS_CONTINUOUS)) {
			/* Mark it valid for high-res. */
			cs->flags |= CLOCK_SOURCE_VALID_FOR_HRES;

			/*
			 * clocksource_done_booting() will sort it if
			 * finished_booting is not set yet.
			 */
			if (!finished_booting)
				continue;

			/*
			 * If this is not the current clocksource let
			 * the watchdog thread reselect it. Due to the
			 * change to high res this clocksource might
			 * be preferred now. If it is the current
			 * clocksource let the tick code know about
			 * that change.
			 */
			if (cs != curr_clocksource) {
				cs->flags |= CLOCK_SOURCE_RESELECT;
				schedule_work(&watchdog_work);
			} else {
				tick_clock_notify();
			}
		}
	}

	/*
	 * We only clear the watchdog_reset_pending, when we did a
	 * full cycle through all clocksources.
	 */
	if (reset_pending)
		atomic_dec(&watchdog_reset_pending);

	/*
	 * Cycle through CPUs to check if the CPUs stay synchronized
	 * to each other.
	 */
	next_cpu = cpumask_next(raw_smp_processor_id(), cpu_online_mask);
	if (next_cpu >= nr_cpu_ids)
		next_cpu = cpumask_first(cpu_online_mask);
	watchdog_timer.expires += WATCHDOG_INTERVAL;
	add_timer_on(&watchdog_timer, next_cpu);
out:
	spin_unlock(&watchdog_lock);
}

static inline void clocksource_start_watchdog(void)
{
	if (watchdog_running || !watchdog || list_empty(&watchdog_list))
		return;
	init_timer(&watchdog_timer);
	watchdog_timer.function = clocksource_watchdog;
	watchdog_timer.expires = jiffies + WATCHDOG_INTERVAL;
	add_timer_on(&watchdog_timer, cpumask_first(cpu_online_mask));
	watchdog_running = 1;
}

static inline void clocksource_stop_watchdog(void)
{
	if (!watchdog_running || (watchdog && !list_empty(&watchdog_list)))
		return;
	del_timer(&watchdog_timer);
	watchdog_running = 0;
}

static inline void clocksource_reset_watchdog(void)
{
	struct clocksource *cs;

	list_for_each_entry(cs, &watchdog_list, wd_list)
		cs->flags &= ~CLOCK_SOURCE_WATCHDOG;
}

static void clocksource_resume_watchdog(void)
{
	atomic_inc(&watchdog_reset_pending);
}

static void clocksource_enqueue_watchdog(struct clocksource *cs)
{
	unsigned long flags;

	spin_lock_irqsave(&watchdog_lock, flags);
	if (cs->flags & CLOCK_SOURCE_MUST_VERIFY) {
		/* cs is a clocksource to be watched. */
		list_add(&cs->wd_list, &watchdog_list);
		cs->flags &= ~CLOCK_SOURCE_WATCHDOG;
	} else {
		/* cs is a watchdog. */
		if (cs->flags & CLOCK_SOURCE_IS_CONTINUOUS)
			cs->flags |= CLOCK_SOURCE_VALID_FOR_HRES;
		/* Pick the best watchdog. */
		if (!watchdog || cs->rating > watchdog->rating) {
			watchdog = cs;
			/* Reset watchdog cycles */
			clocksource_reset_watchdog();
		}
	}
	/* Check if the watchdog timer needs to be started. */
	clocksource_start_watchdog();
	spin_unlock_irqrestore(&watchdog_lock, flags);
}

static void clocksource_dequeue_watchdog(struct clocksource *cs)
{
	unsigned long flags;

	spin_lock_irqsave(&watchdog_lock, flags);
	if (cs != watchdog) {
		if (cs->flags & CLOCK_SOURCE_MUST_VERIFY) {
			/* cs is a watched clocksource. */
			list_del_init(&cs->wd_list);
			/* Check if the watchdog timer needs to be stopped. */
			clocksource_stop_watchdog();
		}
	}
	spin_unlock_irqrestore(&watchdog_lock, flags);
}

static int __clocksource_watchdog_kthread(void)
{
	struct clocksource *cs, *tmp;
	unsigned long flags;
	LIST_HEAD(unstable);
	int select = 0;

	spin_lock_irqsave(&watchdog_lock, flags);
	list_for_each_entry_safe(cs, tmp, &watchdog_list, wd_list) {
		if (cs->flags & CLOCK_SOURCE_UNSTABLE) {
			list_del_init(&cs->wd_list);
			list_add(&cs->wd_list, &unstable);
			select = 1;
		}
		if (cs->flags & CLOCK_SOURCE_RESELECT) {
			cs->flags &= ~CLOCK_SOURCE_RESELECT;
			select = 1;
		}
	}
	/* Check if the watchdog timer needs to be stopped. */
	clocksource_stop_watchdog();
	spin_unlock_irqrestore(&watchdog_lock, flags);

	/* Needs to be done outside of watchdog lock */
	list_for_each_entry_safe(cs, tmp, &unstable, wd_list) {
		list_del_init(&cs->wd_list);
		__clocksource_change_rating(cs, 0);
	}
	return select;
}

static int clocksource_watchdog_kthread(void *data)
{
	mutex_lock(&clocksource_mutex);
	if (__clocksource_watchdog_kthread())
		clocksource_select();
	mutex_unlock(&clocksource_mutex);
	return 0;
}

static bool clocksource_is_watchdog(struct clocksource *cs)
{
	return cs == watchdog;
}

#else /* CONFIG_CLOCKSOURCE_WATCHDOG */

// ARM10C 20150523
// cs: &mct_frc
static void clocksource_enqueue_watchdog(struct clocksource *cs)
{
	// cs->flags: (&mct_frc)->flags: 0x1, CLOCK_SOURCE_IS_CONTINUOUS: 0x01
	if (cs->flags & CLOCK_SOURCE_IS_CONTINUOUS)
		// cs->flags: (&mct_frc)->flags: 0x1, CLOCK_SOURCE_VALID_FOR_HRES: 0x20
		cs->flags |= CLOCK_SOURCE_VALID_FOR_HRES;
		// cs->flags: (&mct_frc)->flags: 0x21
}

static inline void clocksource_dequeue_watchdog(struct clocksource *cs) { }
static inline void clocksource_resume_watchdog(void) { }
static inline int __clocksource_watchdog_kthread(void) { return 0; }
static bool clocksource_is_watchdog(struct clocksource *cs) { return false; }
void clocksource_mark_unstable(struct clocksource *cs) { }

#endif /* CONFIG_CLOCKSOURCE_WATCHDOG */

/**
 * clocksource_suspend - suspend the clocksource(s)
 */
void clocksource_suspend(void)
{
	struct clocksource *cs;

	list_for_each_entry_reverse(cs, &clocksource_list, list)
		if (cs->suspend)
			cs->suspend(cs);
}

/**
 * clocksource_resume - resume the clocksource(s)
 */
void clocksource_resume(void)
{
	struct clocksource *cs;

	list_for_each_entry(cs, &clocksource_list, list)
		if (cs->resume)
			cs->resume(cs);

	clocksource_resume_watchdog();
}

/**
 * clocksource_touch_watchdog - Update watchdog
 *
 * Update the watchdog after exception contexts such as kgdb so as not
 * to incorrectly trip the watchdog. This might fail when the kernel
 * was stopped in code which holds watchdog_lock.
 */
void clocksource_touch_watchdog(void)
{
	clocksource_resume_watchdog();
}

/**
 * clocksource_max_adjustment- Returns max adjustment amount
 * @cs:         Pointer to clocksource
 *
 */
// ARM10C 20150523
// cs: &mct_frc
static u32 clocksource_max_adjustment(struct clocksource *cs)
{
	u64 ret;
	/*
	 * We won't try to correct for more than 11% adjustments (110,000 ppm),
	 */
	// cs->mult: (&mct_frc)->mult: 0xA6AAAAAA
	ret = (u64)cs->mult * 11;
	// ret: 0x72955554E

	// ret: 0x72955554E
	do_div(ret,100);
	// ret: 0x12555555

	// ret: 0x12555555
	return (u32)ret;
	// return 0x12555555
}

/**
 * clocks_calc_max_nsecs - Returns maximum nanoseconds that can be converted
 * @mult:	cycle to nanosecond multiplier
 * @shift:	cycle to nanosecond divisor (power of two)
 * @maxadj:	maximum adjustment value to mult (~11%)
 * @mask:	bitmask for two's complement subtraction of non 64 bit counters
 */
// ARM10C 20150523
// cs->mult: (&mct_frc)->mult: 0xA6AAAAAA, cs->shift: (&mct_frc)->shift: 26,
// cs->maxadj: (&mct_frc)->maxadj: 0x12555555, cs->mask: (&mct_frc)->mask: 0xFFFFFFFF
u64 clocks_calc_max_nsecs(u32 mult, u32 shift, u32 maxadj, u64 mask)
{
	u64 max_nsecs, max_cycles;

	/*
	 * Calculate the maximum number of cycles that we can pass to the
	 * cyc2ns function without overflowing a 64-bit signed result. The
	 * maximum number of cycles is equal to ULLONG_MAX/(mult+maxadj)
	 * which is equivalent to the below.
	 * max_cycles < (2^63)/(mult + maxadj)
	 * max_cycles < 2^(log2((2^63)/(mult + maxadj)))
	 * max_cycles < 2^(log2(2^63) - log2(mult + maxadj))
	 * max_cycles < 2^(63 - log2(mult + maxadj))
	 * max_cycles < 1 << (63 - log2(mult + maxadj))
	 * Please note that we add 1 to the result of the log2 to account for
	 * any rounding errors, ensure the above inequality is satisfied and
	 * no overflow will occur.
	 */
	// mult: 0xA6AAAAAA, maxadj: 0x12555555, ilog2(0xb8ffffff): 31
	max_cycles = 1ULL << (63 - (ilog2(mult + maxadj) + 1));
	// max_cycles: 0x80000000

	/*
	 * The actual maximum number of cycles we can defer the clocksource is
	 * determined by the minimum of max_cycles and mask.
	 * Note: Here we subtract the maxadj to make sure we don't sleep for
	 * too long if there's a large negative adjustment.
	 */
	// max_cycles: 0x80000000, 0xFFFFFFFF
	max_cycles = min(max_cycles, mask);
	// max_cycles: 0x80000000

	// max_cycles: 0x80000000, mult: 0xA6AAAAAA, maxadj: 0x12555555, shift: 26,
	// clocksource_cyc2ns(0x80000000, 0x94555555, 26): 0x128AAAAAA0
	max_nsecs = clocksource_cyc2ns(max_cycles, mult - maxadj, shift);
	// max_nsecs: 0x128AAAAAA0

	// max_nsecs: 0x128AAAAAA0
	return max_nsecs;
	// return 0x128AAAAAA0
}

/**
 * clocksource_max_deferment - Returns max time the clocksource can be deferred
 * @cs:         Pointer to clocksource
 *
 */
// ARM10C 20150523
// cs: &mct_frc
static u64 clocksource_max_deferment(struct clocksource *cs)
{
	u64 max_nsecs;

	// cs->mult: (&mct_frc)->mult: 0xA6AAAAAA, cs->shift: (&mct_frc)->shift: 26,
	// cs->maxadj: (&mct_frc)->maxadj: 0x12555555, cs->mask: (&mct_frc)->mask: 0xFFFFFFFF
	// clocks_calc_max_nsecs(0xA6AAAAAA, 26, 0x12555555, 0xFFFFFFFF): 0x128AAAAAA0
	max_nsecs = clocks_calc_max_nsecs(cs->mult, cs->shift, cs->maxadj,
					  cs->mask);
	// max_nsecs: 0x128AAAAAA0
	/*
	 * To ensure that the clocksource does not wrap whilst we are idle,
	 * limit the time the clocksource can be deferred by 12.5%. Please
	 * note a margin of 12.5% is used because this can be computed with
	 * a shift, versus say 10% which would require division.
	 */
	// max_nsecs: 0x128AAAAAA0
	return max_nsecs - (max_nsecs >> 3);
	// return 0x103955554C
}

#ifndef CONFIG_ARCH_USES_GETTIMEOFFSET // CONFIG_ARCH_USES_GETTIMEOFFSET=n

// ARM10C 20150523
// oneshot: 0, skipcur: false
static struct clocksource *clocksource_find_best(bool oneshot, bool skipcur)
{
	struct clocksource *cs;

	// finished_booting: 0, list_empty(&clocksource_list): 0
	if (!finished_booting || list_empty(&clocksource_list))
		return NULL;
		// return NULL

	/*
	 * We pick the clocksource with the highest rating. If oneshot
	 * mode is active, we pick the highres valid clocksource with
	 * the best rating.
	 */
	list_for_each_entry(cs, &clocksource_list, list) {
		if (skipcur && cs == curr_clocksource)
			continue;
		if (oneshot && !(cs->flags & CLOCK_SOURCE_VALID_FOR_HRES))
			continue;
		return cs;
	}
	return NULL;
}

// ARM10C 20150523
// false
static void __clocksource_select(bool skipcur)
{
	// tick_oneshot_mode_active(): 0
	bool oneshot = tick_oneshot_mode_active();
	// oneshot: 0

	struct clocksource *best, *cs;

	/* Find the best suitable clocksource */
	// oneshot: 0, skipcur: false, clocksource_find_best(0, false): NULL
	best = clocksource_find_best(oneshot, skipcur);
	// best: NULL

	// best: NULL
	if (!best)
		return;
		// return 수행

	/* Check for the override clocksource. */
	list_for_each_entry(cs, &clocksource_list, list) {
		if (skipcur && cs == curr_clocksource)
			continue;
		if (strcmp(cs->name, override_name) != 0)
			continue;
		/*
		 * Check to make sure we don't switch to a non-highres
		 * capable clocksource if the tick code is in oneshot
		 * mode (highres or nohz)
		 */
		if (!(cs->flags & CLOCK_SOURCE_VALID_FOR_HRES) && oneshot) {
			/* Override clocksource cannot be used. */
			printk(KERN_WARNING "Override clocksource %s is not "
			       "HRT compatible. Cannot switch while in "
			       "HRT/NOHZ mode\n", cs->name);
			override_name[0] = 0;
		} else
			/* Override clocksource can be used. */
			best = cs;
		break;
	}

	if (curr_clocksource != best && !timekeeping_notify(best)) {
		pr_info("Switched to clocksource %s\n", best->name);
		curr_clocksource = best;
	}
}

/**
 * clocksource_select - Select the best clocksource available
 *
 * Private function. Must hold clocksource_mutex when called.
 *
 * Select the clocksource with the best rating, or the clocksource,
 * which is selected by userspace override.
 */
// ARM10C 20150523
static void clocksource_select(void)
{
	return __clocksource_select(false);
}

static void clocksource_select_fallback(void)
{
	return __clocksource_select(true);
}

#else /* !CONFIG_ARCH_USES_GETTIMEOFFSET */

static inline void clocksource_select(void) { }
static inline void clocksource_select_fallback(void) { }

#endif

/*
 * clocksource_done_booting - Called near the end of core bootup
 *
 * Hack to avoid lots of clocksource churn at boot time.
 * We use fs_initcall because we want this to start before
 * device_initcall but after subsys_initcall.
 */
static int __init clocksource_done_booting(void)
{
	mutex_lock(&clocksource_mutex);
	curr_clocksource = clocksource_default_clock();
	finished_booting = 1;
	/*
	 * Run the watchdog first to eliminate unstable clock sources
	 */
	__clocksource_watchdog_kthread();
	clocksource_select();
	mutex_unlock(&clocksource_mutex);
	return 0;
}
fs_initcall(clocksource_done_booting);

/*
 * Enqueue the clocksource sorted by rating
 */
// ARM10C 20150523
// cs: &mct_frc
static void clocksource_enqueue(struct clocksource *cs)
{
	struct list_head *entry = &clocksource_list;
	// entry: &clocksource_list

	struct clocksource *tmp;

	list_for_each_entry(tmp, &clocksource_list, list)
	// for (tmp = list_first_entry(&clocksource_list, typeof(*tmp), list);
	//     &tmp->list != (&clocksource_list); tmp = list_next_entry(tmp, list))

		/* Keep track of the place, where to insert */
		if (tmp->rating >= cs->rating)
			entry = &tmp->list;

	// &cs->list: &(&mct_frc)->list, entry: &clocksource_list
	list_add(&cs->list, entry);

	// list_add에서 한일:
	// list clocksource_list의 next에 &(&mct_frc)->list를 추가함
}

/**
 * __clocksource_updatefreq_scale - Used update clocksource with new freq
 * @cs:		clocksource to be registered
 * @scale:	Scale factor multiplied against freq to get clocksource hz
 * @freq:	clocksource frequency (cycles per second) divided by scale
 *
 * This should only be called from the clocksource->enable() method.
 *
 * This *SHOULD NOT* be called directly! Please use the
 * clocksource_updatefreq_hz() or clocksource_updatefreq_khz helper functions.
 */
// ARM10C 20150523
// cs: &mct_frc, scale: 1, freq: 24000000
void __clocksource_updatefreq_scale(struct clocksource *cs, u32 scale, u32 freq)
{
	u64 sec;
	/*
	 * Calc the maximum number of seconds which we can run before
	 * wrapping around. For clocksources which have a mask > 32bit
	 * we need to limit the max sleep time to have a good
	 * conversion precision. 10 minutes is still a reasonable
	 * amount. That results in a shift value of 24 for a
	 * clocksource with mask >= 40bit and f >= 4GHz. That maps to
	 * ~ 0.06ppm granularity for NTP. We apply the same 12.5%
	 * margin as we do in clocksource_max_deferment()
	 */
	// cs->mask: (&mct_frc)->mask: 0xFFFFFFFF
	sec = (cs->mask - (cs->mask >> 3));
	// sec: 0xE0000000

	// sec: 0xE0000000, freq: 24000000
	// do_div(0xE0000000, 24000000): 0
	do_div(sec, freq);
	// sec: 156

	// sec: 156, scale: 1
	// do_div(156, 1): 0
	do_div(sec, scale);
	// sec: 156

	// sec: 156
	if (!sec)
		sec = 1;
	else if (sec > 600 && cs->mask > UINT_MAX)
		sec = 600;

	// &cs->mult: &(&mct_frc)->mult, &cs->shift: &(&mct_frc)->mult,
	// freq: 24000000, NSEC_PER_SEC: 1000000000L, scale: 1, sec: 156
	clocks_calc_mult_shift(&cs->mult, &cs->shift, freq,
			       NSEC_PER_SEC / scale, sec * scale);

	// clocks_calc_mult_shift에서 한일:
	// (&mct_frc)->mult: 0xA6AAAAAA
	// (&mct_frc)->shift: 26

	/*
	 * for clocksources that have large mults, to avoid overflow.
	 * Since mult may be adjusted by ntp, add an safety extra margin
	 *
	 */
	// cs->maxadj: (&mct_frc)->maxadj, cs: &mct_frc, clocksource_max_adjustment(&mct_frc): 0x12555555
	cs->maxadj = clocksource_max_adjustment(cs);
	// cs->maxadj: (&mct_frc)->maxadj: 0x12555555

	// cs->mult: (&mct_frc)->mult: 0xA6AAAAAA, cs->maxadj: (&mct_frc)->maxadj: 0x12555555
	while ((cs->mult + cs->maxadj < cs->mult)
		|| (cs->mult - cs->maxadj > cs->mult)) {
		cs->mult >>= 1;
		cs->shift--;
		cs->maxadj = clocksource_max_adjustment(cs);
	}

	// cs->max_idle_ns: (&mct_frc)->max_idle_ns, cs: &mct_frc, clocksource_max_deferment(&mct_frc): 0x103955554C
	cs->max_idle_ns = clocksource_max_deferment(cs);
	// cs->max_idle_ns: (&mct_frc)->max_idle_ns: 0x103955554C

}
EXPORT_SYMBOL_GPL(__clocksource_updatefreq_scale);

/**
 * __clocksource_register_scale - Used to install new clocksources
 * @cs:		clocksource to be registered
 * @scale:	Scale factor multiplied against freq to get clocksource hz
 * @freq:	clocksource frequency (cycles per second) divided by scale
 *
 * Returns -EBUSY if registration fails, zero otherwise.
 *
 * This *SHOULD NOT* be called directly! Please use the
 * clocksource_register_hz() or clocksource_register_khz helper functions.
 */
// ARM10C 20150523
// cs: &mct_frc, 1, hz: 24000000
int __clocksource_register_scale(struct clocksource *cs, u32 scale, u32 freq)
{

	/* Initialize mult/shift and max_idle_ns */
	// cs: &mct_frc, scale: 1, freq: 24000000
	__clocksource_updatefreq_scale(cs, scale, freq);

	// __clocksource_updatefreq_scale에서 한일:
	// (&mct_frc)->mult: 0xA6AAAAAA
	// (&mct_frc)->shift: 26
	// (&mct_frc)->maxadj: 0x12555555
	// (&mct_frc)->max_idle_ns: 0x103955554C

	/* Add clocksource to the clcoksource list */
	mutex_lock(&clocksource_mutex);

	// mutex_lock에서 한일:
	// clocksource_mutex을 사용하여 mutex lock 수행

	// cs: &mct_frc
	clocksource_enqueue(cs);

	// clocksource_enqueue에서 한일:
	// list clocksource_list의 next에 &(&mct_frc)->list를 추가함

	// cs: &mct_frc
	clocksource_enqueue_watchdog(cs);

	// clocksource_enqueue_watchdog에서 한일:
	// (&mct_frc)->flags: 0x21

	clocksource_select();

	mutex_unlock(&clocksource_mutex);

	// mutex_unlock에서 한일:
	// clocksource_mutex을 사용하여 mutex unlock 수행

	return 0;
	// return 0
}
EXPORT_SYMBOL_GPL(__clocksource_register_scale);


/**
 * clocksource_register - Used to install new clocksources
 * @cs:		clocksource to be registered
 *
 * Returns -EBUSY if registration fails, zero otherwise.
 */
int clocksource_register(struct clocksource *cs)
{
	/* calculate max adjustment for given mult/shift */
	cs->maxadj = clocksource_max_adjustment(cs);
	WARN_ONCE(cs->mult + cs->maxadj < cs->mult,
		"Clocksource %s might overflow on 11%% adjustment\n",
		cs->name);

	/* calculate max idle time permitted for this clocksource */
	cs->max_idle_ns = clocksource_max_deferment(cs);

	mutex_lock(&clocksource_mutex);
	clocksource_enqueue(cs);
	clocksource_enqueue_watchdog(cs);
	clocksource_select();
	mutex_unlock(&clocksource_mutex);
	return 0;
}
EXPORT_SYMBOL(clocksource_register);

static void __clocksource_change_rating(struct clocksource *cs, int rating)
{
	list_del(&cs->list);
	cs->rating = rating;
	clocksource_enqueue(cs);
}

/**
 * clocksource_change_rating - Change the rating of a registered clocksource
 * @cs:		clocksource to be changed
 * @rating:	new rating
 */
void clocksource_change_rating(struct clocksource *cs, int rating)
{
	mutex_lock(&clocksource_mutex);
	__clocksource_change_rating(cs, rating);
	clocksource_select();
	mutex_unlock(&clocksource_mutex);
}
EXPORT_SYMBOL(clocksource_change_rating);

/*
 * Unbind clocksource @cs. Called with clocksource_mutex held
 */
static int clocksource_unbind(struct clocksource *cs)
{
	/*
	 * I really can't convince myself to support this on hardware
	 * designed by lobotomized monkeys.
	 */
	if (clocksource_is_watchdog(cs))
		return -EBUSY;

	if (cs == curr_clocksource) {
		/* Select and try to install a replacement clock source */
		clocksource_select_fallback();
		if (curr_clocksource == cs)
			return -EBUSY;
	}
	clocksource_dequeue_watchdog(cs);
	list_del_init(&cs->list);
	return 0;
}

/**
 * clocksource_unregister - remove a registered clocksource
 * @cs:	clocksource to be unregistered
 */
int clocksource_unregister(struct clocksource *cs)
{
	int ret = 0;

	mutex_lock(&clocksource_mutex);
	if (!list_empty(&cs->list))
		ret = clocksource_unbind(cs);
	mutex_unlock(&clocksource_mutex);
	return ret;
}
EXPORT_SYMBOL(clocksource_unregister);

#ifdef CONFIG_SYSFS
/**
 * sysfs_show_current_clocksources - sysfs interface for current clocksource
 * @dev:	unused
 * @attr:	unused
 * @buf:	char buffer to be filled with clocksource list
 *
 * Provides sysfs interface for listing current clocksource.
 */
static ssize_t
sysfs_show_current_clocksources(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t count = 0;

	mutex_lock(&clocksource_mutex);
	count = snprintf(buf, PAGE_SIZE, "%s\n", curr_clocksource->name);
	mutex_unlock(&clocksource_mutex);

	return count;
}

ssize_t sysfs_get_uname(const char *buf, char *dst, size_t cnt)
{
	size_t ret = cnt;

	/* strings from sysfs write are not 0 terminated! */
	if (!cnt || cnt >= CS_NAME_LEN)
		return -EINVAL;

	/* strip of \n: */
	if (buf[cnt-1] == '\n')
		cnt--;
	if (cnt > 0)
		memcpy(dst, buf, cnt);
	dst[cnt] = 0;
	return ret;
}

/**
 * sysfs_override_clocksource - interface for manually overriding clocksource
 * @dev:	unused
 * @attr:	unused
 * @buf:	name of override clocksource
 * @count:	length of buffer
 *
 * Takes input from sysfs interface for manually overriding the default
 * clocksource selection.
 */
static ssize_t sysfs_override_clocksource(struct device *dev,
					  struct device_attribute *attr,
					  const char *buf, size_t count)
{
	ssize_t ret;

	mutex_lock(&clocksource_mutex);

	ret = sysfs_get_uname(buf, override_name, count);
	if (ret >= 0)
		clocksource_select();

	mutex_unlock(&clocksource_mutex);

	return ret;
}

/**
 * sysfs_unbind_current_clocksource - interface for manually unbinding clocksource
 * @dev:	unused
 * @attr:	unused
 * @buf:	unused
 * @count:	length of buffer
 *
 * Takes input from sysfs interface for manually unbinding a clocksource.
 */
static ssize_t sysfs_unbind_clocksource(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct clocksource *cs;
	char name[CS_NAME_LEN];
	ssize_t ret;

	ret = sysfs_get_uname(buf, name, count);
	if (ret < 0)
		return ret;

	ret = -ENODEV;
	mutex_lock(&clocksource_mutex);
	list_for_each_entry(cs, &clocksource_list, list) {
		if (strcmp(cs->name, name))
			continue;
		ret = clocksource_unbind(cs);
		break;
	}
	mutex_unlock(&clocksource_mutex);

	return ret ? ret : count;
}

/**
 * sysfs_show_available_clocksources - sysfs interface for listing clocksource
 * @dev:	unused
 * @attr:	unused
 * @buf:	char buffer to be filled with clocksource list
 *
 * Provides sysfs interface for listing registered clocksources
 */
static ssize_t
sysfs_show_available_clocksources(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	struct clocksource *src;
	ssize_t count = 0;

	mutex_lock(&clocksource_mutex);
	list_for_each_entry(src, &clocksource_list, list) {
		/*
		 * Don't show non-HRES clocksource if the tick code is
		 * in one shot mode (highres=on or nohz=on)
		 */
		if (!tick_oneshot_mode_active() ||
		    (src->flags & CLOCK_SOURCE_VALID_FOR_HRES))
			count += snprintf(buf + count,
				  max((ssize_t)PAGE_SIZE - count, (ssize_t)0),
				  "%s ", src->name);
	}
	mutex_unlock(&clocksource_mutex);

	count += snprintf(buf + count,
			  max((ssize_t)PAGE_SIZE - count, (ssize_t)0), "\n");

	return count;
}

/*
 * Sysfs setup bits:
 */
static DEVICE_ATTR(current_clocksource, 0644, sysfs_show_current_clocksources,
		   sysfs_override_clocksource);

static DEVICE_ATTR(unbind_clocksource, 0200, NULL, sysfs_unbind_clocksource);

static DEVICE_ATTR(available_clocksource, 0444,
		   sysfs_show_available_clocksources, NULL);

static struct bus_type clocksource_subsys = {
	.name = "clocksource",
	.dev_name = "clocksource",
};

static struct device device_clocksource = {
	.id	= 0,
	.bus	= &clocksource_subsys,
};

static int __init init_clocksource_sysfs(void)
{
	int error = subsys_system_register(&clocksource_subsys, NULL);

	if (!error)
		error = device_register(&device_clocksource);
	if (!error)
		error = device_create_file(
				&device_clocksource,
				&dev_attr_current_clocksource);
	if (!error)
		error = device_create_file(&device_clocksource,
					   &dev_attr_unbind_clocksource);
	if (!error)
		error = device_create_file(
				&device_clocksource,
				&dev_attr_available_clocksource);
	return error;
}

device_initcall(init_clocksource_sysfs);
#endif /* CONFIG_SYSFS */

/**
 * boot_override_clocksource - boot clock override
 * @str:	override name
 *
 * Takes a clocksource= boot argument and uses it
 * as the clocksource override name.
 */
static int __init boot_override_clocksource(char* str)
{
	mutex_lock(&clocksource_mutex);
	if (str)
		strlcpy(override_name, str, sizeof(override_name));
	mutex_unlock(&clocksource_mutex);
	return 1;
}

__setup("clocksource=", boot_override_clocksource);

/**
 * boot_override_clock - Compatibility layer for deprecated boot option
 * @str:	override name
 *
 * DEPRECATED! Takes a clock= boot argument and uses it
 * as the clocksource override name
 */
static int __init boot_override_clock(char* str)
{
	if (!strcmp(str, "pmtmr")) {
		printk("Warning: clock=pmtmr is deprecated. "
			"Use clocksource=acpi_pm.\n");
		return boot_override_clocksource("acpi_pm");
	}
	printk("Warning! clock= boot option is deprecated. "
		"Use clocksource=xyz\n");
	return boot_override_clocksource(str);
}

__setup("clock=", boot_override_clock);
