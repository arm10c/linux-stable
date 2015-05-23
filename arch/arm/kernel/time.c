/*
 *  linux/arch/arm/kernel/time.c
 *
 *  Copyright (C) 1991, 1992, 1995  Linus Torvalds
 *  Modifications for ARM (C) 1994-2001 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  This file contains the ARM-specific time handling details:
 *  reading the RTC at bootup, etc...
 */
#include <linux/clk-provider.h>
#include <linux/clocksource.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/profile.h>
#include <linux/sched.h>
#include <linux/sched_clock.h>
#include <linux/smp.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/timer.h>

#include <asm/mach/arch.h>
#include <asm/mach/time.h>
#include <asm/stacktrace.h>
#include <asm/thread_info.h>

#if defined(CONFIG_RTC_DRV_CMOS) || defined(CONFIG_RTC_DRV_CMOS_MODULE) || \
    defined(CONFIG_NVRAM) || defined(CONFIG_NVRAM_MODULE)
/* this needs a better home */
DEFINE_SPINLOCK(rtc_lock);
EXPORT_SYMBOL(rtc_lock);
#endif	/* pc-style 'CMOS' RTC support */

/* change this if you have some constant time drift */
#define USECS_PER_JIFFY	(1000000/HZ)

#ifdef CONFIG_SMP
unsigned long profile_pc(struct pt_regs *regs)
{
	struct stackframe frame;

	if (!in_lock_functions(regs->ARM_pc))
		return regs->ARM_pc;

	frame.fp = regs->ARM_fp;
	frame.sp = regs->ARM_sp;
	frame.lr = regs->ARM_lr;
	frame.pc = regs->ARM_pc;
	do {
		int ret = unwind_frame(&frame);
		if (ret < 0)
			return 0;
	} while (in_lock_functions(frame.pc));

	return frame.pc;
}
EXPORT_SYMBOL(profile_pc);
#endif

#ifndef CONFIG_GENERIC_CLOCKEVENTS
/*
 * Kernel system timer support.
 */
void timer_tick(void)
{
	profile_tick(CPU_PROFILING);
	xtime_update(1);
#ifndef CONFIG_SMP
	update_process_times(user_mode(get_irq_regs()));
#endif
}
#endif

// ARM10C 20150103
// ts: &now
// ARM10C 20150103
// ts: &boot
static void dummy_clock_access(struct timespec *ts)
{
	// ts->tv_sec: (&now)->tv_sec
	ts->tv_sec = 0;
	// ts->tv_sec: (&now)->tv_sec: 0

	// ts->tv_nsec: (&now)->tv_nsec
	ts->tv_nsec = 0;
	// ts->tv_nsec: (&now)->tv_nsec: 0
}

// ARM10C 20150103
static clock_access_fn __read_persistent_clock = dummy_clock_access;
// ARM10C 20150103
static clock_access_fn __read_boot_clock = dummy_clock_access;;

// ARM10C 20150103
// &now
void read_persistent_clock(struct timespec *ts)
{
	// ts: &now
	// __read_persistent_clock: dummy_clock_access
	// dummy_clock_access(&now)
	__read_persistent_clock(ts);

	// dummy_clock_access에서 한일:
	// ts->tv_sec: (&now)->tv_sec: 0
	// ts->tv_nsec: (&now)->tv_nsec: 0
}

// ARM10C 20150103
// &boot
void read_boot_clock(struct timespec *ts)
{
	// ts: &boot
	// dummy_clock_access(&boot)
	__read_boot_clock(ts);

	// dummy_clock_access에서 한일:
	// ts->tv_sec: (&boot)->tv_sec: 0
	// ts->tv_nsec: (&boot)->tv_nsec: 0
}

int __init register_persistent_clock(clock_access_fn read_boot,
				     clock_access_fn read_persistent)
{
	/* Only allow the clockaccess functions to be registered once */
	if (__read_persistent_clock == dummy_clock_access &&
	    __read_boot_clock == dummy_clock_access) {
		if (read_boot)
			__read_boot_clock = read_boot;
		if (read_persistent)
			__read_persistent_clock = read_persistent;

		return 0;
	}

	return -EINVAL;
}

// ARM10C 20150103
void __init time_init(void)
{
	// machine_desc->init_time: __mach_desc_EXYNOS5_DT.init_time: NULL
	if (machine_desc->init_time) {
		machine_desc->init_time();
	} else {
#ifdef CONFIG_COMMON_CLK // CONFIG_COMMON_CLK=y
		of_clk_init(NULL);

		// of_clk_init에서 한일:
		//
		// devtree에서 allnext로 순회 하면서 찾은 clock node의 주소에서  match: __clk_of_table_exynos5420_clk 찾아
		// exynos5420_clk_init 함수를 수행
		//
		// exynos5420_clk_init에서 한일:
		//
		// device tree 있는 clock node에서 node의 resource 값을 가져옴
		// of_address_to_resource에서 한일(index: 0):
		// (&res)->start: 0x10010000
		// (&res)->end: 0x1003ffff
		// (&res)->flags: IORESOURCE_MEM: 0x00000200
		// (&res)->name: "/clock-controller@10010000"
		/*
		// alloc area (CLK) 를 만들고 rb tree에 alloc area 를 추가
		// 가상주소 va_start 기준으로 CLK 를 RB Tree 추가한 결과
		//
		//                                  CHID-b
		//                               (0xF8000000)
		//                              /            \
		//                         TMR-b               PMU-b
		//                    (0xF6300000)             (0xF8180000)
		//                      /      \               /           \
		//                GIC#1-r      WDT-b         CMU-b         SRAM-b
		//            (0xF0002000)   (0xF6400000)  (0xF8100000)   (0xF8400000)
		//             /       \                                          \
		//        GIC#0-b     CLK-b                                        ROMC-r
		//    (0xF0000000)   (0xF0040000)                                 (0xF84C0000)
		//                   /      \
		//               COMB-r     SYSC-r
		//          (0xF0004000)   (0xF6100000)
		//
		// vmap_area_list에 GIC#0 - GIC#1 - COMB - CLK - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
		// 순서로 리스트에 연결이 됨
		//
		// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
		// (kmem_cache#30-oX (vm_struct))->addr: 0xf0040000
		// (kmem_cache#30-oX (vm_struct))->size: 0x31000
		// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
		//
		// (kmem_cache#30-oX (vmap_area CLK))->vm: kmem_cache#30-oX (vm_struct)
		// (kmem_cache#30-oX (vmap_area CLK))->flags: 0x04
		*/
		// device tree 있는  clock node에서 node의 resource 값을 pgtable에 매핑함
		// 0xc0004780이 가리키는 pte의 시작주소에 0x10010653 값을 갱신
		// (linux pgtable과 hardware pgtable의 값 같이 갱신)
		//
		//  pgd                   pte
		// |              |
		// +--------------+
		// |              |       +--------------+ +0
		// |              |       |  0xXXXXXXXX  | ---> 0x10010653 에 매칭되는 linux pgtable 값
		// +- - - - - - - +       |  Linux pt 0  |
		// |              |       +--------------+ +1024
		// |              |       |              |
		// +--------------+ +0    |  Linux pt 1  |
		// | *(c0004780)  |-----> +--------------+ +2048
		// |              |       |  0x10010653  | ---> 2308
		// +- - - - - - - + +4    |   h/w pt 0   |
		// | *(c0004784)  |-----> +--------------+ +3072
		// |              |       +              +
		// +--------------+ +8    |   h/w pt 1   |
		// |              |       +--------------+ +4096
		//
		// cache의 값을 전부 메모리에 반영
		//
		// samsung_clk_init 에서 한일:
		// struct samsung_clk_reg_dump를 59개 만큼 메모리를 할당 받아
		// exynos5420_clk_regs의 값으로 맴버값 세팅
		// (kmem_cache#26-oX)[0...58].offset: exynos5420_clk_regs[0...58]
		//
		// syscore_ops_list의 tail에 (&samsung_clk_syscore_ops)->node 를 추가
		//
		// struct clk * 를 769개 만큼 메모리를 clk_table에 할당 받음
		// clk_table: kmem_cache#23-o0
		//
		// clk_data.clks: kmem_cache#23-o0 (clk_table)
		// clk_data.clk_num: 769
		//
		// struct of_clk_provider 의 메모리(kmem_cache#30-oX)를 할당 받고 맴버값 초기화 수행
		//
		// (kmem_cache#30-oX)->node: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소
		// (kmem_cache#30-oX)->data: &clk_data
		// (kmem_cache#30-oX)->get: of_clk_src_onecell_get
		//
		// list인 of_clk_providers의 head에 (kmem_cache#30-oX)->link를 추가
		//
		// samsung_clk_of_register_fixed_ext 에서 한일:
		//
		// devtree에서 allnext로 순회 하면서 찾은 fixed-rate-clocks node 에서
		// fixed-rate-clocks node에서 "clock-frequency" property값을 freq에 읽어옴
		// freq: 24000000
		// exynos5420_fixed_rate_ext_clks[0].fixed_rate: 24000000
		//
		// struct clk_fixed_rate 만큼 메모리를 kmem_cache#30-oX 할당 받고 struct clk_fixed_rate 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->fixed_rate: 24000000
		// (kmem_cache#30-oX)->hw.init: &init
		// (&(kmem_cache#30-oX)->hw)->clk: kmem_cache#29-oX
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX)->name: kmem_cache#30-oX ("fin_pll")
		// (kmem_cache#29-oX)->ops: &clk_fixed_rate_ops
		// (kmem_cache#29-oX)->hw: &(kmem_cache#30-oX)->hw
		// (kmem_cache#29-oX)->flags: 0x30
		// (kmem_cache#29-oX)->num_parents: 0
		// (kmem_cache#29-oX)->parent_names: ((void *)16)
		// (kmem_cache#29-oX)->parent: NULL
		// (kmem_cache#29-oX)->rate: 24000000
		//
		// (&(kmem_cache#29-oX)->child_node)->next: NULL
		// (&(kmem_cache#29-oX)->child_node)->pprev: &(&(kmem_cache#29-oX)->child_node)
		//
		// (&clk_root_list)->first: &(kmem_cache#29-oX)->child_node
		//
		// clk_table[1]: (kmem_cache#23-o0)[1]: kmem_cache#29-oX
		//
		// struct clk_lookup_alloc 의 메모리를 kmem_cache#30-oX 할당 받고
		// struct clk_lookup_alloc 맴버값 초기화 수행
		//
		// (kmem_cache#30-oX)->cl.clk: kmem_cache#29-oX
		// (kmem_cache#30-oX)->con_id: "fin_pll"
		// (kmem_cache#30-oX)->cl.con_id: (kmem_cache#30-oX)->con_id: "fin_pll"
		//
		// list clocks에 &(&(kmem_cache#30-oX)->cl)->nade를 tail로 추가
		//
		// samsung_clk_register_pll에서 한일:
		// exynos5420_plls에 정의되어 있는 PLL 값들을 초기화 수행
		//
		// [apll] 의 초기화 값 수행 결과:
		// struct clk_fixed_rate 만큼 메모리를 kmem_cache#30-oX (apll) 할당 받고 struct clk_fixed_rate 의 멤버 값을 아래와 같이 초기화 수행
		// pll: kmem_cache#30-oX (apll)
		//
		// (kmem_cache#30-oX (apll))->hw.init: &init
		// (kmem_cache#30-oX (apll))->type: pll_2550: 2
		// (kmem_cache#30-oX (apll))->lock_reg: 0xf0040000
		// (kmem_cache#30-oX (apll))->con_reg: 0xf0040100
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX (apll) 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX (apll))->name: kmem_cache#30-oX ("fout_apll")
		// (kmem_cache#29-oX (apll))->ops: &samsung_pll35xx_clk_min_ops
		// (kmem_cache#29-oX (apll))->hw: &(kmem_cache#30-oX (apll))->hw
		// (kmem_cache#29-oX (apll))->flags: 0x40
		// (kmem_cache#29-oX (apll))->num_parents: 1
		// (kmem_cache#29-oX (apll))->parent_names: kmem_cache#30-oX
		// (kmem_cache#29-oX (apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// (kmem_cache#29-oX (apll))->parent: kmem_cache#29-oX (fin_pll)
		// (kmem_cache#29-oX (apll))->rate: 1000000000 (1 Ghz)
		//
		// (&(kmem_cache#29-oX (apll))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (apll))->child_node)->pprev: &(&(kmem_cache#29-oX (apll))->child_node)
		//
		// (&(kmem_cache#29-oX (fin_pll))->children)->first: &(kmem_cache#29-oX (apll))->child_node
		//
		// (&(kmem_cache#30-oX (apll))->hw)->clk: kmem_cache#29-oX (apll)
		//
		// clk_table[2]: (kmem_cache#23-o0)[2]: kmem_cache#29-oX (apll)
		//
		// struct clk_lookup_alloc 의 메모리를 kmem_cache#30-oX (apll) 할당 받고
		// struct clk_lookup_alloc 맴버값 초기화 수행
		//
		// (kmem_cache#30-oX)->cl.clk: kmem_cache#29-oX (apll)
		// (kmem_cache#30-oX)->con_id: "fout_apll"
		// (kmem_cache#30-oX)->cl.con_id: (kmem_cache#30-oX)->con_id: "fout_apll"
		//
		// list clocks에 &(&(kmem_cache#30-oX (apll))->cl)->nade를 tail로 추가
		//
		// cpll, dpll, epll, rpll, ipll, spll, vpll, mpll, bpll, kpll 초기화 수행 결과는 생략.
		//
		// samsung_clk_register_fixed_rate에서 한일:
		// exynos5420_fixed_rate_clks에 정의되어 있는 fixed rate 값들을 초기화 수행
		//
		// sclk_hdmiphy 의 초기화 값 수행 결과
		// struct clk_fixed_rate 만큼 메모리를 kmem_cache#30-oX 할당 받고 struct clk_fixed_rate 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->fixed_rate: 24000000
		// (kmem_cache#30-oX)->hw.init: &init
		// (&(kmem_cache#30-oX)->hw)->clk: kmem_cache#29-oX
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX)->name: kmem_cache#30-oX ("sclk_hdmiphy")
		// (kmem_cache#29-oX)->ops: &clk_fixed_rate_ops
		// (kmem_cache#29-oX)->hw: &(kmem_cache#30-oX)->hw
		// (kmem_cache#29-oX)->flags: 0x30
		// (kmem_cache#29-oX)->num_parents: 0
		// (kmem_cache#29-oX)->parent_names: ((void *)16)
		// (kmem_cache#29-oX)->parent: NULL
		// (kmem_cache#29-oX)->rate: 24000000
		//
		// (&(kmem_cache#29-oX)->child_node)->next: NULL
		// (&(kmem_cache#29-oX)->child_node)->pprev: &(&(kmem_cache#29-oX)->child_node)
		//
		// (&clk_root_list)->first: &(kmem_cache#29-oX)->child_node
		//
		// clk_table[158]: (kmem_cache#23-o0)[158]: kmem_cache#29-oX
		//
		// struct clk_lookup_alloc 의 메모리를 kmem_cache#30-oX 할당 받고
		// struct clk_lookup_alloc 맴버값 초기화 수행
		//
		// (kmem_cache#30-oX)->cl.clk: kmem_cache#29-oX
		// (kmem_cache#30-oX)->con_id: "fin_pll"
		// (kmem_cache#30-oX)->cl.con_id: (kmem_cache#30-oX)->con_id: "fin_pll"
		//
		// list clocks에 &(&(kmem_cache#30-oX)->cl)->nade를 tail로 추가
		//
		// "sclk_pwi", "sclk_usbh20", "mphy_refclk_ixtal24", "sclk_usbh20_scan_clk" 초기화 수행 결과는 생략.
		//
		// samsung_clk_register_fixed_factor에서 한일:
		// struct clk_fixed_factor 만큼 메모리를 kmem_cache#30-oX 할당 받고 struct clk_fixed_factor 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->mult: 1
		// (kmem_cache#30-oX)->div: 2
		// (kmem_cache#30-oX)->hw.init: &init
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX (sclk_hsic_12m) 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX (sclk_hsic_12m))->name: kmem_cache#30-oX ("sclk_hsic_12m")
		// (kmem_cache#29-oX (sclk_hsic_12m))->ops: &clk_fixed_factor_ops
		// (kmem_cache#29-oX (sclk_hsic_12m))->hw: &(kmem_cache#30-oX (sclk_hsic_12m))->hw
		// (kmem_cache#29-oX (sclk_hsic_12m))->flags: 0x20
		// (kmem_cache#29-oX (sclk_hsic_12m))->num_parents: 1
		// (kmem_cache#29-oX (sclk_hsic_12m))->parent_names: kmem_cache#30-oX
		// (kmem_cache#29-oX (sclk_hsic_12m))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// (kmem_cache#29-oX (sclk_hsic_12m))->parent: kmem_cache#29-oX (fin_pll)
		// (kmem_cache#29-oX (sclk_hsic_12m))->rate: 12000000
		//
		// (&(kmem_cache#29-oX (sclk_hsic_12m))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_hsic_12m))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_hsic_12m))->child_node)
		//
		// (&(kmem_cache#29-oX (fin_pll))->children)->first: &(kmem_cache#29-oX (sclk_hsic_12m))->child_node
		//
		// (&(kmem_cache#30-oX (sclk_hsic_12m))->hw)->clk: kmem_cache#29-oX (sclk_hsic_12m)
		//
		// clk_table[0]: (kmem_cache#23-o0)[0]: kmem_cache#29-oX (sclk_hsic_12m)
		//
		// samsung_clk_register_mux 에서 한일:
		// exynos5420_mux_clks에 등록 되어 있는 clock mux 들의 초기화를 수행
		//
		// mout_mspll_kfc, sclk_spll를 수행한 결과:
		//
		// (mout_mspll_kfc) 에서 한일:
		// struct clk_mux 만큼 메모리를 kmem_cache#30-oX (mout_mspll_kfc) 할당 받고 struct clk_mux 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->reg: 0xf005021c
		// (kmem_cache#30-oX)->shift: 8
		// (kmem_cache#30-oX)->mask: 0x3
		// (kmem_cache#30-oX)->flags: 0
		// (kmem_cache#30-oX)->lock: &lock
		// (kmem_cache#30-oX)->table: NULL
		// (kmem_cache#30-oX)->hw.init: &init
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX (mout_mspll_kfc) 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX (mout_mspll_kfc))->name: kmem_cache#30-oX ("mout_mspll_kfc")
		// (kmem_cache#29-oX (mout_mspll_kfc))->ops: &clk_mux_ops
		// (kmem_cache#29-oX (mout_mspll_kfc))->hw: &(kmem_cache#30-oX (mout_mspll_kfc))->hw
		// (kmem_cache#29-oX (mout_mspll_kfc))->flags: 0xa0
		// (kmem_cache#29-oX (mout_mspll_kfc))->num_parents 4
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names: kmem_cache#30-oX
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "sclk_cpll"
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[1]: (kmem_cache#30-oX)[1]: kmem_cache#30-oX: "sclk_dpll"
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[2]: (kmem_cache#30-oX)[2]: kmem_cache#30-oX: "sclk_mpll"
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[3]: (kmem_cache#30-oX)[3]: kmem_cache#30-oX: "sclk_spll"
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent: NULL
		// (kmem_cache#29-oX (mout_mspll_kfc))->rate: 0
		//
		// (kmem_cache#29-oX (mout_mspll_kfc))->parents: kmem_cache#30-oX
		// (kmem_cache#29-oX (mout_mspll_kfc))->parents[0...3]: (kmem_cache#30-oX)[0...3]: NULL
		//
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
		//
		// (&clk_orphan_list)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
		//
		// (&(kmem_cache#30-oX (mout_mspll_kfc))->hw)->clk: kmem_cache#29-oX (mout_mspll_kfc)
		//
		// (sclk_spll) 에서 한일:
		// struct clk_mux 만큼 메모리를 kmem_cache#30-oX (sclk_spll) 할당 받고 struct clk_mux 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->reg: 0xf0050218
		// (kmem_cache#30-oX)->shift: 8
		// (kmem_cache#30-oX)->mask: 0x3
		// (kmem_cache#30-oX)->flags: 0
		// (kmem_cache#30-oX)->lock: &lock
		// (kmem_cache#30-oX)->table: NULL
		// (kmem_cache#30-oX)->hw.init: &init
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX (sclk_spll) 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX (sclk_spll))->name: kmem_cache#30-oX ("sclk_spll")
		// (kmem_cache#29-oX (sclk_spll))->ops: &clk_mux_ops
		// (kmem_cache#29-oX (sclk_spll))->hw: &(kmem_cache#30-oX (sclk_spll))->hw
		// (kmem_cache#29-oX (sclk_spll))->flags: 0xa0
		// (kmem_cache#29-oX (sclk_spll))->num_parents 2
		// (kmem_cache#29-oX (sclk_spll))->parent_names: kmem_cache#30-oX
		// (kmem_cache#29-oX (sclk_spll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// (kmem_cache#29-oX (sclk_spll))->parent_names[1]: (kmem_cache#30-oX)[1]: kmem_cache#30-oX: "fout_spll"
		// (kmem_cache#29-oX (sclk_spll))->parent: NULL
		// (kmem_cache#29-oX (sclk_spll))->rate: 600000000
		//
		// (kmem_cache#29-oX (sclk_spll))->parents: kmem_cache#30-oX
		// (kmem_cache#29-oX (sclk_spll))->parents[0]: (kmem_cache#30-oX)[0]: kmem_cache#29-oX (fin_pll)
		// (kmem_cache#29-oX (sclk_spll))->parents[1]: (kmem_cache#30-oX)[1]: kmem_cache#29-oX (fout_spll)
		//
		// parents 인 "fin_pll", "fout_spll" 값들 중에
		// register CLK_SRC_TOP6 의 값을 읽어서 mux 할 parent clock 을 선택함
		// return된 값이 선택된 parent clock의 index 값임
		// parent clock 중에 선택된 parent clock의 이름으로 등록된 clk struct를 반환함
		//
		// (&(kmem_cache#29-oX (sclk_spll))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_spll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_spll))->child_node)
		//
		// (&(kmem_cache#29-oX (fout_spll))->children)->first: &(kmem_cache#29-oX (sclk_spll))->child_node
		//
		// (&(kmem_cache#30-oX (sclk_spll))->hw)->clk: kmem_cache#29-oX (sclk_spll)
		//
		// orphan 으로 등록된 mout_mspll_kfc의 값을 갱신
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
		//
		// (&(kmem_cache#29-oX (sclk_spll))->children)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
		//
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent: kmem_cache#29-oX (sclk_spll)
		//
		// parent가 있는지 확인후 parent의 clock rate 값으로 clock rate 값을 세팅
		// (kmem_cache#29-oX (mout_mspll_kfc))->rate: 600000000
		//
		// samsung_clk_register_div에서 한일:
		//
		// exynos5420_div_clks의 div 들 중에 array index 1번의
		// DIV(none, "sclk_apll", "mout_apll", DIV_CPU0, 24, 3) 을 가지고 분석 진행
		//
		// struct clk_divider 만큼 메모리를 할당 받아 맴버값 초기화 수행
		// kmem_cache#30-oX (sclk_apll)
		// (kmem_cache#30-oX (sclk_apll))->reg: 0xf0040500
		// (kmem_cache#30-oX (sclk_apll))->shift: 24
		// (kmem_cache#30-oX (sclk_apll))->width: 3
		// (kmem_cache#30-oX (sclk_apll))->flags: 0
		// (kmem_cache#30-oX (sclk_apll))->lock: &lock
		// (kmem_cache#30-oX (sclk_apll))->hw.init: &init
		// (kmem_cache#30-oX (sclk_apll))->table: NULL
		//
		// struct clk 만큼 메모리를 할당 받아 맴버값 초기화 수행
		// kmem_cache#29-oX (sclk_apll)
		// (kmem_cache#29-oX (sclk_apll))->name: kmem_cache#30-oX ("sclk_apll")
		// (kmem_cache#29-oX (sclk_apll))->ops: &clk_divider_ops
		// (kmem_cache#29-oX (sclk_apll))->hw: &(kmem_cache#30-oX (sclk_apll))->hw
		// (kmem_cache#29-oX (sclk_apll))->flags: 0x0
		// (kmem_cache#29-oX (sclk_apll))->num_parents 1
		// (kmem_cache#29-oX (sclk_apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "mout_apll"
		// (kmem_cache#29-oX (sclk_apll))->parent: kmem_cache#29-oX (mout_apll)
		// (kmem_cache#29-oX (sclk_apll))->rate: 800000000
		//
		// clk 의 이름이 "mout_apll"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행
		//
		// (&(kmem_cache#29-oX (sclk_apll))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_apll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_apll))->child_node)
		//
		// (&(kmem_cache#29-oX (mout_apll))->children)->first: &(kmem_cache#29-oX (sclk_apll))->child_node
		//
		// exynos5420_div_clks의 idx 0, 2...52 까지 loop 수행
		//
		// samsung_clk_register_gate 에서 한일:
		//
		// exynos5420_gate_clks의 gate 들 중에 array index 36번의
		// GATE(sclk_fimd1, "sclk_fimd1", "dout_fimd1", GATE_TOP_SCLK_PERIC, 0, CLK_SET_RATE_PARENT, 0) 을 가지고 분석 진행
		//
		// struct clk_gate 만큼 메모리를 할당 받아 맴버값 초기화 수행
		// kmem_cache#30-oX (sclk_fimd1)
		// (kmem_cache#30-oX (sclk_fimd1))->reg: 0xf0050828
		// (kmem_cache#30-oX (sclk_fimd1))->bit_idx: 0
		// (kmem_cache#30-oX (sclk_fimd1))->flags: 0
		// (kmem_cache#30-oX (sclk_fimd1))->lock: &lock
		// (kmem_cache#30-oX (sclk_fimd1))->hw.init: &init
		// (kmem_cache#30-oX (sclk_fimd1))->table: NULL
		//
		// struct clk 만큼 메모리를 할당 받아 맴버값 초기화 수행
		// kmem_cache#29-oX (sclk_fimd1)
		// (kmem_cache#29-oX (sclk_fimd1))->name: kmem_cache#30-oX ("sclk_fimd1")
		// (kmem_cache#29-oX (sclk_fimd1))->ops: &clk_gate_ops
		// (kmem_cache#29-oX (sclk_fimd1))->hw: &(kmem_cache#30-oX (sclk_fimd1))->hw
		// (kmem_cache#29-oX (sclk_fimd1))->flags: 0x24
		// (kmem_cache#29-oX (sclk_fimd1))->num_parents 1
		// (kmem_cache#29-oX (sclk_fimd1))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "mout_apll"
		// (kmem_cache#29-oX (sclk_fimd1))->parent: kmem_cache#29-oX (dout_fimd0)
		// (kmem_cache#29-oX (sclk_fimd1))->rate: 266000000
		//
		// clk 의 이름이 "dout_fimd1"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행
		//
		// (&(kmem_cache#29-oX (sclk_fimd1))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_fimd1))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_fimd1))->child_node)
		//
		// (&(kmem_cache#29-oX (dout_fimd1))->children)->first: &(kmem_cache#29-oX (sclk_fimd1))->child_node
		//
		// clk_table[136]: (kmem_cache#23-o0)[136]: kmem_cache#29-oX (sclk_fimd1)
		//
		// exynos5420_gate_clks의 idx: 0...12...136 loop 수행
#endif
		clocksource_of_init();

		// clocksource_of_init에서 한일:
		// mct_int_type: 0
		//
		// devtree의 mct node의 interrupt의 property의 값을 dtb에  분석하여 oirq 값을 가져옴
		//
		// (&oirq)->np: combiner node의 주소
		// (&oirq)->args_count: 2
		// (&oirq)->args[0]: 23
		// (&oirq)->args[1]: 3
		//
		// oirq 값을 사용하여 combiner domain에서 virq 값을 찾음
		// virq: 347
		//
		// mct_irqs[4]: 152
		// mct_irqs[5]: 153
		// mct_irqs[6]: 154
		// mct_irqs[7]: 155
		//
		// device tree 있는  mct node에서 node의 resource 값을 가져옴
		// (&res)->start: 0x101C0000
		// (&res)->end: 0x101C07ff
		// (&res)->flags: IORESOURCE_MEM: 0x00000200
		// (&res)->name: "/mct@101C0000"
		/*
		// alloc area (MCT) 를 만들고 rb tree에 alloc area 를 추가
		// 가상주소 va_start 기준으로 MCT 를 RB Tree 추가한 결과
		//
		//                                      CHID-b
		//                                    (0xF8000000)
		//                                  /              \
		//                            CLK-b                  PMU-b
		//                         (0xF0040000)              (0xF8180000)
		//                        /          \                /        \
		//                 GIC#1-r            TMR-r        CMU-b         SRAM-b
		//             (0xF0002000)         (0xF6300000)   (0xF8100000)  (0xF8400000)
		//              /       \              /    \                         \
		//        GIC#0-b       COMB-b     SYSC-b     WDT-b                   ROMC-r
		//    (0xF0000000) (0xF0004000) (0xF6100000)  (0xF6400000)            (0xF84C0000)
		//                          \
		//                          MCT-r
		//                       (0xF0006000)
		//
		// vmap_area_list에 GIC#0 - GIC#1 - COMB - MCT - CLK - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
		// 순서로 리스트에 연결이 됨
		//
		// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
		// (kmem_cache#30-oX (vm_struct))->addr: 0xf0006000
		// (kmem_cache#30-oX (vm_struct))->size: 0x2000
		// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
		//
		// (kmem_cache#30-oX (vmap_area CLK))->vm: kmem_cache#30-oX (vm_struct)
		// (kmem_cache#30-oX (vmap_area CLK))->flags: 0x04
		*/
		// device tree 있는 mct node에서 node의 resource 값을 pgtable에 매핑함
		// 0xc0004780이 가리키는 pte의 시작주소에 0x101C0653 값을 갱신
		// (linux pgtable과 hardware pgtable의 값 같이 갱신)
		//
		//  pgd                   pte
		// |              |
		// +--------------+
		// |              |       +--------------+ +0
		// |              |       |  0xXXXXXXXX  | ---> 0x101C0653 에 매칭되는 linux pgtable 값
		// +- - - - - - - +       |  Linux pt 0  |
		// |              |       +--------------+ +1024
		// |              |       |              |
		// +--------------+ +0    |  Linux pt 1  |
		// | *(c0004780)  |-----> +--------------+ +2048
		// |              |       |  0x101C0653  | ---> 2076
		// +- - - - - - - + +4    |   h/w pt 0   |
		// | *(c0004784)  |-----> +--------------+ +3072
		// |              |       +              +
		// +--------------+ +8    |   h/w pt 1   |
		// |              |       +--------------+ +4096
		//
		// cache의 값을 전부 메모리에 반영
		//
		// mct node의 property "clock-names" 의 값을 찾아서 "fin_pll" 이 있는 위치를 찾고
		// 몇번째 값인지 index를 구함
		//
		// mct node 에서 "clocks" property의 이용하여 devtree의 값을 파싱하여 clkspec에 값을 가져옴
		// (&clkspec)->np: clock node의 주소
		// (&clkspec)->args_count: 1
		// (&clkspec)->args[0]: 1
		//
		// list of_clk_providers 에 등록된 정보들 중에 clkspec 와 매치되는 정보를 찾음
		// 이전에 만들어 놓은 clk_data의 clk_table 정보를 이용하여 clkspec에 있는 arg 값을 이용하여 clk을 찾음
		// tick_clk: kmem_cache#29-oX (fin_pll)
		//
		// mct node의 property "clock-names" 의 값을 찾아서 "mct" 이 있는 위치를 찾고
		// 몇번째 값인지 index를 구함
		//
		// mct node 에서 "clocks" property의 이용하여 devtree의 값을 파싱하여 clkspec에 값을 가져옴
		// (&clkspec)->np: clock node의 주소
		// (&clkspec)->args_count: 1
		// (&clkspec)->args[0]: 315
		//
		// list of_clk_providers 에 등록된 정보들 중에 clkspec 와 매치되는 정보를 찾음
		// 이전에 만들어 놓은 clk_data의 clk_table 정보를 이용하여 clkspec에 있는 arg 값을 이용하여 clk을 찾음
		// mct_clk: kmem_cache#29-oX (mct)
		//
		// clk_prepare_enable에서 한일:
		// mct clock의 상위 clock 들의 ops->prepare 함수들을 수행.
		// mct clock의 상위 clock 들의 ops->enable 함수들을 수행.
		// sck_cpll -- Group1_p -- mout_aclk66 -- dout_aclk66 -- mct
		// sck_ppll -|
		// sck_mpll -|
		//
		// sck_cpll, mout_aclk66, dout_aclk66 의 주석을 만들지 않았기 때문에
		// 분석내용을 skip 하도록함
		//
		// Interrupt pending register인 GICD_ITARGETSR38 값을 읽고
		// 그 값과 mask 값인 cpu_bit_bitmap[1][0] 을 or 연산한 값을 GICD_ITARGETSR38에
		// 다시 write함
		//
		// GICD_ITARGETSR38 값을 모르기 때문에 0x00000000 로
		// 읽히는 것으로 가정하고 GICD_ITARGETSR38에 0x00000001를 write 함
		// CPU interface 0에 interrupt가 발생을 나타냄
		//
		// (&(kmem_cache#28-oX (irq 152))->irq_data)->affinity->bits[0]: 1
		// (&(kmem_cache#28-oX (irq 152))->irq_data)->state_use_accessors: 0x11000
		//
		// register_cpu_notifier 에서 한일:
		// (&cpu_chain)->head: &exynos4_mct_cpu_nb 포인터 대입
		// (&exynos4_mct_cpu_nb)->next은 (&hrtimers_nb)->next로 대입
		//
		// [pcp0] (&percpu_mct_tick)->base: 0x300
		// [pcp0] (&percpu_mct_tick)->name: "mct_tick0"
		// [pcp0] (&(&percpu_mct_tick)->evt)->name: "mct_tick0"
		// [pcp0] (&(&percpu_mct_tick)->evt)->cpumask: &cpu_bit_bitmap[1][0]
		// [pcp0] (&(&percpu_mct_tick)->evt)->set_next_event: exynos4_tick_set_next_event
		// [pcp0] (&(&percpu_mct_tick)->evt)->set_mode: exynos4_tick_set_mode
		// [pcp0] (&(&percpu_mct_tick)->evt)->features: 0x3
		// [pcp0] (&(&percpu_mct_tick)->evt)->rating: 450
		// [pcp0] (&(&percpu_mct_tick)->evt)->min_delta_ticks: 0xf
		// [pcp0] (&(&percpu_mct_tick)->evt)->max_delta_ticks: 0x7fffffff
		// [pcp0] (&(&percpu_mct_tick)->evt)->mult: 0x3126E98
		// [pcp0] (&(&percpu_mct_tick)->evt)->shift: 32
		// [pcp0] (&(&percpu_mct_tick)->evt)->min_delta_ns: 0x4E2
		// [pcp0] (&(&percpu_mct_tick)->evt)->max_delta_ns: 0x29AAAAA444
		// [pcp0] (&(&percpu_mct_tick)->evt)->next_event.tv64: 0x7FFFFFFFFFFFFFFF
		// [pcp0] (&(&percpu_mct_tick)->evt)->event_handler: tick_handle_periodic
		// [pcp0] (&(&percpu_mct_tick)->evt)->mode: 2
		// [pcp0] (&(&percpu_mct_tick)->evt)->irq: 152
		//
		// [pcp0] (&tick_cpu_device)->mode: 0
		// [pcp0] (&tick_cpu_device)->evtdev: [pcp0] &(&percpu_mct_tick)->evt
		//
		// [pcp0] (&tick_cpu_sched)->check_clocks: 1
		//
		// list clockevent_devices에 [pcp0] (&(&percpu_mct_tick)->evt)->list를 추가함
		//
		// tick_do_timer_cpu: 0
		// tick_next_period.tv64: 0
		// tick_period.tv64: 10000000
		//
		// timer control register L0_TCON 값을 읽어 timer start, timer interrupt 설정을
		// 동작하지 않도록 변경함
		// L0_TCON 값이 0 으로 가정하였으므로 timer는 동작하지 않은 상태임
		//
		// register L_ICNTB 에 0x8001D4C0 write함
		// local timer 0 의 interrupt count buffer 값을 120000 (0x1D4C0) write 하고
		// interrupt manual update를 enable 시킴
		//
		// register L_INT_ENB 에 0x1 write함
		// local timer 0 의 ICNTEIE 값을 0x1을 write 하여 L0_INTCNT 값이 0 이 되었을 때
		// interrupt counter expired interrupt 가 발생하도록 함
		//
		// register L_TCON 에 0x7 write함
		// local timer 0 의 interrupt type을 interval mode로 설정하고 interrupt, timer 를 start 시킴
		//
		// register L_TCNTB 에 0x1 write함
		// local timer 0 의 tick count 값을 1로 write 함
		//
		// struct irqaction의 메모리 공간을 할당 받고 맴버값 세팅
		// (kmem_cache#30-oX)->handler: exynos4_mct_tick_isr
		// (kmem_cache#30-oX)->thread_fn: NULL
		// (kmem_cache#30-oX)->flags: 0x14A00
		// (kmem_cache#30-oX)->name: "mct_tick0"
		// (kmem_cache#30-oX)->dev_id: [pcp0] &percpu_mct_tick
		// (kmem_cache#30-oX)->irq: 152
		// (kmem_cache#30-oX)->dir: NULL
		//
		// irq_desc 152의 맴버값을 초기화
		// &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->lock을 사용한 spinlock 초기화
		// &(&(kmem_cache#28-oX (irq 152))->wait_for_threads)->task_list를 사용한 list 초기화
		// (kmem_cache#28-oX (irq 152))->istate: 0
		// (kmem_cache#28-oX (irq 152))->depth: 1
		// (kmem_cache#28-oX (irq 152))->action: kmem_cache#30-oX (irqaction)
		// (kmem_cache#28-oX (irq 152))->status_use_accessors: 0x3400
		// (kmem_cache#28-oX (irq 152))->irq_count: 0
		// (kmem_cache#28-oX (irq 152))->irqs_unhandled: 0
		// (&(kmem_cache#28-oX (irq 152))->irq_data)->state_use_accessors: 0x11400
		//
		// register G_CNT_L 에 0x0 write함
		// FRC count buffer 의 tick count 값을 0로 write 함
		//
		// register G_CNT_WSTAT 에 0x1 write함
		// G_CNT_L write status 의  값을 1로 write 함
		//
		// register G_CNT_U 에 0x0 write함
		// FRC count buffer 의 tick count 값을 0로 write 함
		//
		// register G_CNT_WSTAT 에 0x1 write함
		// G_CNT_U write status 의  값을 1로 write 함
		//
		// register G_TCON 에 0x100 write함
		// global timer enable 의 값을 1로 write 함
		//
		// (&mct_frc)->mult: 0xA6AAAAAA
		// (&mct_frc)->shift: 26
		// (&mct_frc)->maxadj: 0x12555555
		// (&mct_frc)->max_idle_ns: 0x103955554C
		// (&mct_frc)->flags: 0x21
		//
		// list clocksource_list의 next에 &(&mct_frc)->list를 추가함
		//
		// mct_comp_device.cpumask: &cpu_bit_bitmap[1][0
		//
		// (&mct_comp_device)->min_delta_ticks: 0xf
		// (&mct_comp_device)->max_delta_ticks: 0xffffffff
		// (&mct_comp_device)->mult: 0x3126E98
		// (&mct_comp_device)->shift: 31
		// (&mct_comp_device)->min_delta_ns: 0x3E8
		// (&mct_comp_device)->max_delta_ns: 0x29AAAAA46E
		// (&mct_comp_device)->mode: 1
		// (&mct_comp_device)->next_event.tv64: 0x7FFFFFFFFFFFFFFF
		//
		// list clockevent_devices에 (&mct_comp_device)->list를 추가함
		//
		// register G_TCON 에 0x100 write함
		// global timer enable 의 값을 1로 write 함
		//
		// register G_INT_ENB 에 0x0 write함
		// global timer interrupt enable 의 값을 0로 write 함
		//
		// comparator 0의 auto increment0, comp0 enable,comp0 interrupt enable 값을
		// 0으로 clear 하여 comparator 0를 동작하지 않도록 함
		//
		// tick_broadcast_device.evtdev: &mct_comp_device
		// [pcp0] &(&tick_cpu_sched)->check_clocks: 0xf
		//
		// &(&(kmem_cache#28-oX (irq 347))->wait_for_threads)->lock을 사용한 spinlock 초기화
		// &(&(kmem_cache#28-oX (irq 347))->wait_for_threads)->task_list를 사용한 list 초기화
		// &(kmem_cache#28-oX (irq 347))->istate: 0
		// (kmem_cache#28-oX (irq 347))->depth: 0
		// (kmem_cache#28-oX (irq 347))->action: &mct_comp_event_irq
		// (kmem_cache#28-oX (irq 347))->irq_count: 0
		// (kmem_cache#28-oX (irq 347))->irqs_unhandled: 0
		//
		// (&(kmem_cache#28-oX (irq 347))->irq_data)->state_use_accessors: 0x10000
		// (&(kmem_cache#28-oX (irq 347))->irq_data)->affinity->bits[0]: 1
		//
		// register IESR5의 MCT_G0 bit 를 1 로 write 하여 MCT_G0 의 interrupt 를 enable 시킴
		//
		// GICD_ITARGETSR46 값을 모르기 때문에 0x00000000 로
		// 읽히는 것으로 가정하고 GICD_ITARGETSR46에 0x1000000를 write 함
		// CPU interface 0에 interrupt가 발생을 나타냄
		//
		// struct irqaction 멤버 값 세팅
		// (&mct_comp_event_irq)->irq: 347
		// (&mct_comp_event_irq)->dir: NULL
	}
}
