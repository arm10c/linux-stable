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

	// of_irq_init에서 한일:
	//
	// device tree 있는  gic node에서 node의 resource 값을 가져옴
	// (&res)->start: 0x10481000
	// (&res)->end: 0x10481fff
	// (&res)->flags: IORESOURCE_MEM: 0x00000200
	// (&res)->name: "/interrupt-controller@10481000"
	/*
	// alloc area (GIC#0) 를 만들고 rb tree에 alloc area 를 추가
	// 가상주소 va_start 기준으로 GIC#0 를 RB Tree 추가한 결과
	//
	//                                  CHID-b
	//                               (0xF8000000)
	//                              /            \
	//                         TMR-r               PMU-r
	//                    (0xF6300000)             (0xF8180000)
	//                      /      \               /           \
	//                 SYSC-b      WDT-b         CMU-b         SRAM-b
	//            (0xF6100000)   (0xF6400000)  (0xF8100000)   (0xF8400000)
	//             /                                                 \
	//        GIC#0-r                                                 ROMC-r
	//   (0xF0000000)                                                 (0xF84C0000)
	//
	// vmap_area_list에 GIC#0 - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
	// 순서로 리스트에 연결이 됨
	//
	// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
	// (kmem_cache#30-oX (vm_struct))->addr: 0xf0000000
	// (kmem_cache#30-oX (vm_struct))->size: 0x2000
	// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
	//
	// (kmem_cache#30-oX (vmap_area GIC#0))->vm: kmem_cache#30-oX (vm_struct)
	// (kmem_cache#30-oX (vmap_area GIC#0))->flags: 0x04
	*/
	// device tree 있는  gic node에서 node의 resource 값을 pgtable에 매핑함
	// 0xc0004780이 가리키는 pte의 시작주소에 0x10481653 값을 갱신
	// (linux pgtable과 hardware pgtable의 값 같이 갱신)
	//
	//  pgd                   pte
	// |              |
	// +--------------+
	// |              |       +--------------+ +0
	// |              |       |  0xXXXXXXXX  | ---> 0x10481653 에 매칭되는 linux pgtable 값
	// +- - - - - - - +       |  Linux pt 0  |
	// |              |       +--------------+ +1024
	// |              |       |              |
	// +--------------+ +0    |  Linux pt 1  |
	// | *(c0004780)  |-----> +--------------+ +2048
	// |              |       |  0x10481653  | ---> 2052
	// +- - - - - - - + +4    |   h/w pt 0   |
	// | *(c0004784)  |-----> +--------------+ +3072
	// |              |       +              +
	// +--------------+ +8    |   h/w pt 1   |
	// |              |       +--------------+ +4096
	//
	// cache의 값을 전부 메모리에 반영
	//
	// device tree 있는  gic node에서 node의 resource 값을 가져옴
	// (&res)->start: 0x10482000
	// (&res)->end: 0x10482fff
	// (&res)->flags: IORESOURCE_MEM: 0x00000200
	// (&res)->name: "/interrupt-controller@10481000"
	/*
	// alloc area (GIC#1) 를 만들고 rb tree에 alloc area 를 추가
	// 가상주소 va_start 기준으로 GIC#1 를 RB Tree 추가한 결과
	//
	//                                  CHID-b
	//                               (0xF8000000)
	//                              /            \
	//                         TMR-r               PMU-r
	//                    (0xF6300000)             (0xF8180000)
	//                      /      \               /           \
	//                GIC#1-b      WDT-b         CMU-b         SRAM-b
	//            (0xF0002000)   (0xF6400000)  (0xF8100000)   (0xF8400000)
	//             /       \                                          \
	//        GIC#0-r     SYSC-r                                       ROMC-r
	//    (0xF0000000)   (0xF6100000)                                 (0xF84C0000)
	//
	// vmap_area_list에 GIC#0 - GIC#1 - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
	// 순서로 리스트에 연결이 됨
	//
	// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
	// (kmem_cache#30-oX (vm_struct))->addr: 0xf0002000
	// (kmem_cache#30-oX (vm_struct))->size: 0x2000
	// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
	//
	// (kmem_cache#30-oX (vmap_area GIC#1))->vm: kmem_cache#30-oX (vm_struct)
	// (kmem_cache#30-oX (vmap_area GIC#1))->flags: 0x04
	*/
	// device tree 있는  gic node에서 node의 resource 값을 pgtable에 매핑함
	// 0xc0004780이 가리키는 pte의 시작주소에 0x10482653 값을 갱신
	// (linux pgtable과 hardware pgtable의 값 같이 갱신)
	//
	//  pgd                   pte
	// |              |
	// +--------------+
	// |              |       +--------------+ +0
	// |              |       |  0xXXXXXXXX  | ---> 0x10482653 에 매칭되는 linux pgtable 값
	// +- - - - - - - +       |  Linux pt 0  |
	// |              |       +--------------+ +1024
	// |              |       |              |
	// +--------------+ +0    |  Linux pt 1  |
	// | *(c0004780)  |-----> +--------------+ +2048
	// |              |       |  0x10482653  | ---> 2060
	// +- - - - - - - + +4    |   h/w pt 0   |
	// | *(c0004784)  |-----> +--------------+ +3072
	// |              |       +              +
	// +--------------+ +8    |   h/w pt 1   |
	// |              |       +--------------+ +4096
	//
	// cache의 값을 전부 메모리에 반영
	//
	// (&gic_data[0])->dist_base.common_base: 0xf0000000
	// (&gic_data[0])->cpu_base.common_base: 0xf0002000
	// (&gic_data[0])->gic_irqs: 160
	/*
	// struct irq_desc의 자료 구조크기 만큼 160개의 메모리를 할당 받아
	// radix tree 구조로 구성
	//
	// radix tree의 root node: &irq_desc_tree 값을 변경
	// (&irq_desc_tree)->rnode: kmem_cache#20-o1 (RADIX_LSB: 1)
	// (&irq_desc_tree)->height: 2
	//
	// (kmem_cache#20-o1)->height: 2
	// (kmem_cache#20-o1)->count: 3
	// (kmem_cache#20-o1)->parent: NULL
	// (kmem_cache#20-o1)->slots[0]: kmem_cache#20-o0 (radix height 1 관리 주소)
	// (kmem_cache#20-o1)->slots[1]: kmem_cache#20-o2 (radix height 1 관리 주소)
	// (kmem_cache#20-o1)->slots[2]: kmem_cache#20-o3 (radix height 1 관리 주소)
	//
	// (kmem_cache#20-o0)->height: 1
	// (kmem_cache#20-o0)->count: 63
	// (kmem_cache#20-o0)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
	// (kmem_cache#20-o0)->slots[0...63]: kmem_cache#28-oX (irq 0...63)
	//
	// (kmem_cache#20-o2)->height: 1
	// (kmem_cache#20-o2)->count: 63
	// (kmem_cache#20-o2)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
	// (kmem_cache#20-o2)->slots[0...63]: kmem_cache#28-oX (irq 63...127)
	//
	// (kmem_cache#20-o3)->height: 1
	// (kmem_cache#20-o3)->count: 32
	// (kmem_cache#20-o3)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
	// (kmem_cache#20-o3)->slots[0...32]: kmem_cache#28-oX (irq 127...160)
	//
	// (&irq_desc_tree)->rnode --> +-----------------------+
	//                             |    radix_tree_node    |
	//                             |   (kmem_cache#20-o1)  |
	//                             +-----------------------+
	//                             | height: 2 | count: 3  |
	//                             +-----------------------+
	//                             | radix_tree_node 0 ~ 2 |
	//                             +-----------------------+
	//                            /            |             \
	//    slot: 0                /   slot: 1   |              \ slot: 2
	//    +-----------------------+  +-----------------------+  +-----------------------+
	//    |    radix_tree_node    |  |    radix_tree_node    |  |    radix_tree_node    |
	//    |   (kmem_cache#20-o0)  |  |   (kmem_cache#20-o2)  |  |   (kmem_cache#20-o3)  |
	//    +-----------------------+  +-----------------------+  +-----------------------+
	//    | height: 1 | count: 64 |  | height: 1 | count: 64 |  | height: 1 | count: 32 |
	//    +-----------------------+  +-----------------------+  +-----------------------+
	//    |    irq  0 ~ 63        |  |    irq 64 ~ 127       |  |    irq 128 ~ 160      |
	//    +-----------------------+  +-----------------------+  +-----------------------+
	*/
	// (&gic_data[0])->domain: kmem_cache#25-o0
	// (&(kmem_cache#25-o0)->revmap_tree)->height: 0
	// (&(kmem_cache#25-o0)->revmap_tree)->gfp_mask: GFP_KERNEL: 0xD0
	// (&(kmem_cache#25-o0)->revmap_tree)->rnode: NULL
	// (kmem_cache#25-o0)->ops: &gic_irq_domain_ops
	// (kmem_cache#25-o0)->host_data: &gic_data[0]
	// (kmem_cache#25-o0)->of_node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// (kmem_cache#25-o0)->hwirq_max: 160
	// (kmem_cache#25-o0)->revmap_size: 160
	// (kmem_cache#25-o0)->revmap_direct_max_irq: 0
	// (kmem_cache#25-o0)->name: "GIC"
	// (kmem_cache#25-o0)->linear_revmap[16...160]: 16...160
	//
	// irq_domain_list에 (kmem_cache#25-o0)->link를 추가
	//
	// irq 16...160까지의 struct irq_data에 값을 설정
	// (&(kmem_cache#28-oX (irq 16...160))->irq_data)->hwirq: 16...160
	// (&(kmem_cache#28-oX (irq 16...160))->irq_data)->domain: kmem_cache#25-o0
	// (&(kmem_cache#28-oX (irq 16...160))->irq_data)->state_use_accessors: 0x10800
	// (kmem_cache#28-oX (irq 16...160))->percpu_enabled: kmem_cache#30-oX
	// (kmem_cache#28-oX (irq 16...160))->status_use_accessors: 0x31600
	// (kmem_cache#28-oX (irq 16...160))->irq_data.chip: &gic_chip
	// (kmem_cache#28-oX (irq 16...160))->handle_irq: handle_percpu_devid_irq
	// (kmem_cache#28-oX (irq 16...160))->name: NULL
	// (kmem_cache#28-oX (irq 16...160))->irq_data.chip_data: &gic_data[0]
	// (kmem_cache#28-oX (irq 16...160))->status_use_accessors: 0x31600
	//
	// smp_cross_call: gic_raise_softirq
	//
	// (&cpu_chain)->head: gic_cpu_notifier 포인터 대입
	// (&gic_cpu_notifier)->next은 (&radix_tree_callback_nb)->next로 대입
	//
	// handle_arch_irq: gic_handle_irq
	//
	// gic_chip.flags: 0
	//
	// register GICD_CTLR을 0으로 초기화
	// 0 값의 의미: Disable the forwarding of pending interrupts from the Distributor to the CPU interfaces.
	// register GICD_ICFGR2 ~ GICD_ICFGR9 까지의 값을 0으로 초기화 수행
	// register GICD_ITARGETSR8 ~ GICD_ITARGETSR39 값을 0x01010101으로 세팅
	// 0x01010101의 의미: CPU targets, byte offset 0 ~ 4까지의 interrupt target을 "CPU interface 0"으로 설정
	// register GICD_IPRIORITYR8 ~ GICD_ITARGETSR39 값을 0xa0a0a0a0으로 세팅
	// 0xa0a0a0a0의 의미: Priority, byte offset 0 ~ 4까지의 interrupt priority value을 160 (0xa0)로 설정
	// register GICD_ICENABLER1 ~ GICD_ICENABLER4 값을 0xffffffff으로 세팅
	// 0xffffffff의 의미: 각각의 For SPIs and PPIs 값을 interrupt disable로 설정
	// register GICD_CTLR 값을 1로 세팅
	// 1 값의 의미: Enables the forwarding of pending interrupts from the Distributor to the CPU interfaces.
	//
	// gic_cpu_map[0]: 0x01
	// gic_cpu_map[1...7]: 0xfe
	//
	// register GICD_ICENABLER0 값을 0xffff0000으로 세팅
	// 0xffff0000 값의 의미: 0~15 bit는 SGI, 16~31 PPI를 컨트롤함, PPI를 전부 disable
	// register GICD_ISENABLER0 값을 0x0000ffff으로 세팅
	// 0x0000ffff 값의 의미: 0~15 bit는 SGI, 16~31 PPI를 컨트롤함, SGI를 전부 enable 함
	// register GICD_IPRIORITYR1 ~ GICD_ITARGETSR8 값을 0xa0a0a0a0으로 세팅
	// 0xa0a0a0a0의 의미: Priority, byte offset 0 ~ 4까지의 interrupt priority value을 160 (0xa0)로 설정
	// register GICC_PMR 값을 0xf0으로 세팅
	// 0xf0 값의 의미: interrupt priority가 240(0xf0) 이상인 interrupt만 cpu에 interrupt를 전달
	// register GICC_CTLR에 값을 1로 세팅
	// 1 값의 의미: cpu에 전달되는 interrupt를 enable 함
	//
	// (&gic_data[0])->saved_ppi_enable: kmem_cache#26-o0 에서의 4 byte 할당된 주소 (pcp)
	// (&gic_data[0])->saved_ppi_conf: kmem_cache#26-o0 에서의 8 byte 할당된 주소 (pcp)
	// (&cpu_pm_notifier_chain)->head: &gic_notifier_block
	//
	// gic_cnt: 1
	//
	//
	// device tree 있는  combiner node에서 node의 resource 값을 가져옴
	// (&res)->start: 0x10440000
	// (&res)->end: 0x10440fff
	// (&res)->flags: IORESOURCE_MEM: 0x00000200
	// (&res)->name: "/interrupt-controller@10440000"
	/*
	// alloc area (COMB) 를 만들고 rb tree에 alloc area 를 추가
	// 가상주소 va_start 기준으로 COMB 를 RB Tree 추가한 결과
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
	//        GIC#0-b     SYSC-b                                       ROMC-r
	//    (0xF0000000)   (0xF6100000)                                 (0xF84C0000)
	//                   /
	//               COMB-r
	//          (0xF0004000)
	//
	// vmap_area_list에 GIC#0 - GIC#1 - COMB - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
	// 순서로 리스트에 연결이 됨
	//
	// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
	// (kmem_cache#30-oX (vm_struct))->addr: 0xf0004000
	// (kmem_cache#30-oX (vm_struct))->size: 0x2000
	// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
	//
	// (kmem_cache#30-oX (vmap_area COMB))->vm: kmem_cache#30-oX (vm_struct)
	// (kmem_cache#30-oX (vmap_area COMB))->flags: 0x04
	*/
	// device tree 있는 combiner node에서 node의 resource 값을 pgtable에 매핑함
	// 0xc0004780이 가리키는 pte의 시작주소에 0x10440653 값을 갱신
	// (linux pgtable과 hardware pgtable의 값 같이 갱신)
	//
	//  pgd                   pte
	// |              |
	// +--------------+
	// |              |       +--------------+ +0
	// |              |       |  0xXXXXXXXX  | ---> 0x10440653 에 매칭되는 linux pgtable 값
	// +- - - - - - - +       |  Linux pt 0  |
	// |              |       +--------------+ +1024
	// |              |       |              |
	// +--------------+ +0    |  Linux pt 1  |
	// | *(c0004780)  |-----> +--------------+ +2048
	// |              |       |  0x10440653  | ---> 2068
	// +- - - - - - - + +4    |   h/w pt 0   |
	// | *(c0004784)  |-----> +--------------+ +3072
	// |              |       +              +
	// +--------------+ +8    |   h/w pt 1   |
	// |              |       +--------------+ +4096
	//
	// cache의 값을 전부 메모리에 반영
	//
	// combiner_init에서 한일:
	// struct irq_domain를 위한 메모리 할당: kmem_cache#24-o0
	// combiner_irq_domain: kmem_cache#24-o0
	//
	// (&(kmem_cache#24-o0)->revmap_tree)->height: 0
	// (&(kmem_cache#24-o0)->revmap_tree)->gfp_mask: (GFP_KERNEL: 0xD0)
	// (&(kmem_cache#24-o0)->revmap_tree)->rnode: NULL
	// (kmem_cache#24-o0)->ops: &combiner_irq_domain_ops
	// (kmem_cache#24-o0)->host_data: kmem_cache#26-oX (combiner_data)
	// (kmem_cache#24-o0)->of_node: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	// (kmem_cache#24-o0)->hwirq_max: 256
	// (kmem_cache#24-o0)->revmap_size: 256
	// (kmem_cache#24-o0)->revmap_direct_max_irq: 0
	//
	// irq_domain_list에 (kmem_cache#24-o0)->link를 추가
	/*
	// struct irq_desc의 자료 구조크기 만큼 256개의 메모리를 할당 받아
	// radix tree 구조로 구성
	//
	// radix tree의 root node: &irq_desc_tree 값을 변경
	// (&irq_desc_tree)->rnode: kmem_cache#20-o1 (RADIX_LSB: 1)
	// (&irq_desc_tree)->height: 2
	//
	// (kmem_cache#20-o1)->height: 2
	// (kmem_cache#20-o1)->count: 7
	// (kmem_cache#20-o1)->parent: NULL
	// (kmem_cache#20-o1)->slots[0]: kmem_cache#20-o0 (radix height 1 관리 주소)
	// (kmem_cache#20-o1)->slots[1]: kmem_cache#20-o2 (radix height 1 관리 주소)
	// (kmem_cache#20-o1)->slots[2]: kmem_cache#20-o3 (radix height 1 관리 주소)
	// (kmem_cache#20-o1)->slots[3]: kmem_cache#20-o4 (radix height 1 관리 주소)
	// (kmem_cache#20-o1)->slots[4]: kmem_cache#20-o5 (radix height 1 관리 주소)
	// (kmem_cache#20-o1)->slots[5]: kmem_cache#20-o6 (radix height 1 관리 주소)
	// (kmem_cache#20-o1)->slots[6]: kmem_cache#20-o7 (radix height 1 관리 주소)
	//
	// (kmem_cache#20-o0)->height: 1
	// (kmem_cache#20-o0)->count: 64
	// (kmem_cache#20-o0)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
	// (kmem_cache#20-o0)->slots[0...63]: kmem_cache#28-oX (irq 0...63)
	//
	// (kmem_cache#20-o2)->height: 1
	// (kmem_cache#20-o2)->count: 64
	// (kmem_cache#20-o2)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
	// (kmem_cache#20-o2)->slots[0...63]: kmem_cache#28-oX (irq 63...127)
	//
	// (kmem_cache#20-o3)->height: 1
	// (kmem_cache#20-o3)->count: 64
	// (kmem_cache#20-o3)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
	// (kmem_cache#20-o3)->slots[0...63]: kmem_cache#28-oX (irq 127...191)
	//
	// (kmem_cache#20-o4)->height: 1
	// (kmem_cache#20-o4)->count: 64
	// (kmem_cache#20-o4)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
	// (kmem_cache#20-o4)->slots[0...63]: kmem_cache#28-oX (irq 192...255)
	//
	// (kmem_cache#20-o5)->height: 1
	// (kmem_cache#20-o5)->count: 64
	// (kmem_cache#20-o5)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
	// (kmem_cache#20-o5)->slots[0...63]: kmem_cache#28-oX (irq 256...319)
	//
	// (kmem_cache#20-o6)->height: 1
	// (kmem_cache#20-o6)->count: 64
	// (kmem_cache#20-o6)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
	// (kmem_cache#20-o6)->slots[0...63]: kmem_cache#28-oX (irq 320...383)
	//
	// (kmem_cache#20-o7)->height: 1
	// (kmem_cache#20-o7)->count: 32
	// (kmem_cache#20-o7)->parent: kmem_cache#20-o1 (RADIX_LSB: 1)
	// (kmem_cache#20-o7)->slots[0...31]: kmem_cache#28-oX (irq 384...415)
	//
	// (&irq_desc_tree)->rnode -->  +-----------------------+
	//                              |    radix_tree_node    |
	//                              |   (kmem_cache#20-o1)  |
	//                              +-----------------------+
	//                              | height: 2 | count: 7  |
	//                              +-----------------------+
	//                              | radix_tree_node 0 ~ 6 | \
	//                            / +-----------------------+ \ \
	//                          /  /           |  |          \  \ \ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
	//  slot: 0               /   | slot: 1    |  |           |   \              slot: 2    |
	//  +-----------------------+ | +-----------------------+ | +-----------------------+   |
	//  |    radix_tree_node    | | |    radix_tree_node    | | |    radix_tree_node    |   |
	//  |   (kmem_cache#20-o0)  | | |   (kmem_cache#20-o2)  | | |   (kmem_cache#20-o3)  |   |
	//  +-----------------------+ | +-----------------------+ | +-----------------------+   |
	//  | height: 1 | count: 64 | | | height: 1 | count: 64 | | | height: 1 | count: 64 |   |
	//  +-----------------------+ | +-----------------------+ | +-----------------------+   |
	//  |    irq  0 ~ 63        | | |    irq 64 ~ 127       | | |    irq 128 ~ 191      |   |
	//  +-----------------------+ | +-----------------------+ | +-----------------------+   |
	//                           /                |            \                            |
	//  slot: 3                /    slot: 4       |              \                slot: 5    \                slot: 6
	//  +-----------------------+   +-----------------------+   +-----------------------+   +-----------------------+
	//  |    radix_tree_node    |   |    radix_tree_node    |   |    radix_tree_node    |   |    radix_tree_node    |
	//  |   (kmem_cache#20-o4)  |   |   (kmem_cache#20-o5)  |   |   (kmem_cache#20-o6)  |   |   (kmem_cache#20-o7)  |
	//  +-----------------------+   +-----------------------+   +-----------------------+   +-----------------------+
	//  | height: 1 | count: 64 |   | height: 1 | count: 64 |   | height: 1 | count: 64 |   | height: 1 | count: 32 |
	//  +-----------------------+   +-----------------------+   +-----------------------+   +-----------------------+
	//  |    irq  192 ~ 255     |   |    irq 256 ~ 319      |   |    irq 320 ~ 383      |   |    irq 384 ~ 415      |
	//  +-----------------------+   +-----------------------+   +-----------------------+   +-----------------------+
	*/
	// irq 160...415까지의 struct irq_data에 값을 설정
	//
	// (&(kmem_cache#28-oX (irq 160...415))->irq_data)->hwirq: 0...255
	// (&(kmem_cache#28-oX (irq 160...415))->irq_data)->domain: kmem_cache#24-o0
	// (&(kmem_cache#28-oX (irq 160...415))->irq_data)->state_use_accessors: 0x10800
	//
	// (kmem_cache#28-oX (irq 160...415))->irq_data.chip: &combiner_chip
	// (kmem_cache#28-oX (irq 160...415))->handle_irq: handle_level_irq
	// (kmem_cache#28-oX (irq 160...415))->name: NULL
	//
	// (kmem_cache#28-oX (irq 160...167))->irq_data.chip_data: &(kmem_cache#26-oX)[0] (combiner_data)
	// (kmem_cache#28-oX (irq 168...175))->irq_data.chip_data: &(kmem_cache#26-oX)[1] (combiner_data)
	// ......
	// (kmem_cache#28-oX (irq 408...415))->irq_data.chip_data: &(kmem_cache#26-oX)[31] (combiner_data)
	//
	// (kmem_cache#28-oX (irq 160...415))->status_use_accessors: 0x31600
	//
	// (kmem_cache#24-o0)->name: "COMBINER"
	// (kmem_cache#24-o0)->linear_revmap[0...255]: 160...415
	//
	// (&combiner_data[0])->base: 0xf0004000
	// (&combiner_data[0])->hwirq_offset: 0
	// (&combiner_data[0])->irq_mask: 0xff
	// (&combiner_data[0])->parent_irq: 32
	// group 0 의 interrupt disable 설정
	//
	// (&combiner_data[1])->base: 0xf0004000
	// (&combiner_data[1])->hwirq_offset: 0
	// (&combiner_data[1])->irq_mask: 0xff00
	// (&combiner_data[1])->parent_irq: 33
	// group 1 의 interrupt disable 설정
	//
	// (&combiner_data[2])->base: 0xf0004000
	// (&combiner_data[2])->hwirq_offset: 0
	// (&combiner_data[2])->irq_mask: 0xff0000
	// (&combiner_data[2])->parent_irq: 34
	// group 2 의 interrupt disable 설정
	//
	// (&combiner_data[3])->base: 0xf0004000
	// (&combiner_data[3])->hwirq_offset: 0
	// (&combiner_data[3])->irq_mask: 0xff000000
	// (&combiner_data[3])->parent_irq: 35
	// group 3 의 interrupt disable 설정
	//
	// (&combiner_data[4])->base: 0xf0004010
	// (&combiner_data[4])->hwirq_offset: 32
	// (&combiner_data[4])->irq_mask: 0xff
	// (&combiner_data[4])->parent_irq: 36
	// group 4 의 interrupt disable 설정
	//
	// .....
	//
	// (&combiner_data[31])->base: 0xf0004070
	// (&combiner_data[31])->hwirq_offset: 224
	// (&combiner_data[31])->irq_mask: 0xff000000
	// (&combiner_data[31])->parent_irq: 63
	// group 31 의 interrupt disable 설정
	//
	// (kmem_cache#28-oX (irq 32...63))->irq_data.handler_data: &combiner_data[0...31]
	// (kmem_cache#28-oX (irq 32...63))->handle_irq: combiner_handle_cascade_irq
	// (kmem_cache#28-oX (irq 32...63))->status_use_accessors: 0x31e00
	// (kmem_cache#28-oX (irq 32...63))->depth: 0
	// (&(kmem_cache#28-oX (irq 32...63))->irq_data)->state_use_accessors: 0x800
	//
	// register GICD_ISENABLER1 의 값을 세팅 하여 irq 32의 interrupt를 enable 시킴
}
