/*
 * Copyright (c) 2012, NVIDIA CORPORATION.  All rights reserved.
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/init.h>
#include <linux/of.h>
#include <linux/clocksource.h>

// ARM10C 20150307
// __clksrc_of_table_armv7_arch_timer
// __clksrc_of_table_armv8_arch_timer
// __clksrc_of_table_armv7_arch_timer_mem
// __clksrc_of_table_exynos4210
// __clksrc_of_table_exynos4412
extern struct of_device_id __clksrc_of_table[];

static const struct of_device_id __clksrc_of_table_sentinel
	__used __section(__clksrc_of_table_end);

// ARM10C 20150307
void __init clocksource_of_init(void)
{
	struct device_node *np;
	const struct of_device_id *match;
	clocksource_of_init_fn init_func;

	for_each_matching_node_and_match(np, __clksrc_of_table, &match) {
	// for (np = of_find_matching_node_and_match(NULL, __clksrc_of_table, &match);
	//      np; np = of_find_matching_node_and_match(np, __clksrc_of_table, &match))

		// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소, match: __clksrc_of_table_exynos4210

		// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소
		// of_device_is_available(devtree에서 allnext로 순회 하면서 찾은 mct node의 주소): 1
		if (!of_device_is_available(np))
			continue;

		// match->data: __clksrc_of_table_exynos4210.data: mct_init_spi
		init_func = match->data;
		// init_func: mct_init_spi

		// init_func: mct_init_spi
		// np: devtree에서 allnext로 순회 하면서 찾은 mct node의 주소
		// mct_init_spi(devtree에서 allnext로 순회 하면서 찾은 mct node의 주소)
		init_func(np);

		// mct_init_spi에서 한일:
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
