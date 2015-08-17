# Kernel study a10c(ARM)

##### The Linux Kernel review for ARMv7 3.13.0 (exynos 5420)
##### Community name: kernel study a10th C team
##### Target Soc    : Samsung Exynos 5420 (ARMv7 A7&A15)
##### Kernel version: Linux kernel 3.13.x
  - 1st: 3.9.6
  - 2nd: 3.10.x
  - 3th: 3.11.x
  - current : 3.13.x
  
# HISTORY
* 114th (2015/08/15) week [114차](https://github.com/hephaex/kernel_review/blob/master/a10c_114.md)
 - cgorup 초기 초기화 분석
 - cgroup_early_init()
* 113th (2015/08/08) week [113차](https://github.com/hephaex/kernel_review/blob/master/a10c_113.md)
 - cgorup 초기 초기화 분석
 - cgroup_early_init()
* 112th (2015/08/01) week [112차](https://github.com/hephaex/kernel_review/blob/master/a10c_112.md)
 - cgroup 에 대한 이야기
 - LXC와 Docker 기술
 - SS의 G6의 kernel config 를 참조하여 cgroup config를 설정.
 - config 추가: Reference/exynos7420-zerolte_kor_skc_defconfig
 - pageconsole_init()
* 111th (2015/07/25) week [111차](https://github.com/hephaex/kernel_review/blob/master/a10c_111.md)
 - console_init()
  - con_init()
* 110th (2015/07/18) week [110차](https://github.com/hephaex/kernel_review/blob/master/a10c_110.md)
 - console_init()
  - con_init()
* 109th (2015/07/11) week [109차](https://github.com/hephaex/kernel_review/blob/master/a10c_109.md)
 - console_init()
  - con_init()
* 108th (2015/07/04) week [108차](https://github.com/hephaex/kernel_review/blob/master/a10c_108.md)
 - parse_args() 복습
 - console_init()->con_init()
 - console_init()->s3c24xx_serial_console_init()
* 107th (2015/06/27) week [107차](https://github.com/hephaex/kernel_review/blob/master/a10c_107.md)
 - console_init()
* 106th (2015/06/20) week [106차](https://github.com/hephaex/kernel_review/blob/master/a10c_106.md)
 - sched_clock_postinit();
 - perf_event_init();
 - profile_init();
 - call_function_init();
 - irqs_disabled()
 - local_irq_enable();
 - kmem_cache_init_late();
* 105th (2015/06/13) week [105차](https://github.com/hephaex/kernel_review/blob/master/a10c_105.md)
 - sched_clock_postinit();
* 104th (2015/06/06) week [104차](https://github.com/hephaex/kernel_review/blob/master/a10c_104.md)
 - sched_clock_postinit();
* 103th (2015/05/30) week [103차](https://github.com/hephaex/kernel_review/blob/master/a10c_103.md)
 - sched_clock_postinit();
* 102th (2015/05/23) week [102차](https://github.com/hephaex/kernel_review/blob/master/a10c_102.md)
 - time_init()
   - timer 를 사용하기 위한 clk source, clk_table 메모리 할당 및 초기화,
   - timer event를 위한 timer irq (MCT) 초기화 수행
* 101th (2015/05/16) week [101차](https://github.com/hephaex/kernel_review/blob/master/a10c_101.md)
* 100th (2015/05/09) week [100차](https://github.com/hephaex/kernel_review/blob/master/a10c_100.md)
* Temp. (2015/04/25) week [temp](https://github.com/hephaex/kernel_review/blob/master/a10c_tmp.md)
 - NIPA 5층 대강당, 12차 Iamroot OT.
 - 개발에 대한 자유토론. (IoT, 3D/4D Printing, 라즈베리파이2, 오드로이드...)
* 99th (2015/04/19) week [99차](https://github.com/hephaex/kernel_review/blob/master/a10c_99.md)
* 98th (2015/04/11) week [98차](https://github.com/hephaex/kernel_review/blob/master/a10c_98.md)
* 97th (2015/04/04) week [97차](https://github.com/hephaex/kernel_review/blob/master/a10c_97.md)
* 96th (2015/03/28) week [96차](https://github.com/hephaex/kernel_review/blob/master/a10c_96.md)
 - start_kernel()->time_init()->clocksource_of_init()->mct_init_spi()->mct_init_dt()->irq_of_parse_and_map()
 - iamroot.org 운영자 회의
* 95th (2015/03/21) week [95차](https://github.com/hephaex/kernel_review/blob/master/a10c_95.md)
 - start_kernel()->time_init()->clocksource_of_init()->mct_init_spi()->mct_init_dt()->irq_of_parse_and_map()->of_irq_parse_one()->of_irq_parse_raw()
* 94th (2015/03/14) week [94차](https://github.com/hephaex/kernel_review/blob/master/a10c_94.md)
 - start_kernel()->time_init()->clocksource_of_init()->mct_init_spi()->mct_init_dt()->irq_of_parse_and_map()
* 93th (2015/03/07) week [93차](https://github.com/hephaex/kernel_review/blob/master/a10c_93.md)
 - start_kernel()->time_init()->of_clk_init()
 - start_kernel()->time_init()->clocksource_of_init()->mct_init_spi()->mct_init_dt()->irq_of_parse_and_map()
* 92th (2015/02/28) week [92차](https://github.com/hephaex/kernel_review/blob/master/a10c_92.md)
 - start_kernel()->time_init()->of_clk_init()
* 91th (2015/02/21) week [91차](https://github.com/hephaex/kernel_review/blob/master/a10c_91.md)
 - start_kernel()->time_init()->of_clk_init()
* 90th (2015/02/07) week [90차](https://github.com/hephaex/kernel_review/blob/master/a10c_90.md)
 - start_kernel()->time_init()->of_clk_init()
* 89th (2015/01/31) week [89차](https://github.com/hephaex/kernel_review/blob/master/a10c_89.md)
 - start_kernel()->time_init()->of_clk_init()
* 88th (2015/01/24) week [88차](https://github.com/hephaex/kernel_review/blob/master/a10c_88.md)
 - start_kernel()->time_init()->of_clk_init()
* 87th (2015/01/17) week [87차](https://github.com/hephaex/kernel_review/blob/master/a10c_87.md)
 - start_kernel()->time_init()->of_clk_init()
* 86th (2015/01/10) week [86차](https://github.com/hephaex/kernel_review/blob/master/a10c_86.md)
 - start_kernel()->time_init()->of_clk_init()
* 85th (2015/01/03) week [85차](https://github.com/hephaex/kernel_review/blob/master/a10c_85.md)
 - start_kernel()->time_init()->of_clk_init()
* 84th (2014/12/27) week [84차](https://github.com/hephaex/kernel_review/blob/master/a10c_84.md)
 - start_kernel()->time_init()->of_clk_init()
* 83th (2014/12/20) week [83차](https://github.com/hephaex/kernel_review/blob/master/a10c_83.md)
* 82th (2014/12/13) week [82차](https://github.com/hephaex/kernel_review/blob/master/a10c_82.md)
* 81th (2014/12/06) week [81차](https://github.com/hephaex/kernel_review/blob/master/a10c_81.md)
 - init_IRQ()->...->kfree()
- 80th (2014/11/29) week: [80차](https://github.com/hephaex/kernel_review/blob/master/a10c_80.md)
 - init_IRQ()->...->gic_of_init()->gic_of_bases()
 - irqchip_init()
- 79th (2014/11/22) week: [79차](https://github.com/hephaex/kernel_review/blob/master/a10c_79.md)
 - init_IRQ()->...->gic_of_init()->gic_of_bases()
- 78th (2014/11/15) week: [78차](https://github.com/hephaex/kernel_review/blob/master/a10c_78.md)
 - init_IRQ()->...->gic_of_init()
 - Radix-tree
- 77th (2014/11/08) week: [77차](https://github.com/hephaex/kernel_review/blob/master/a10c_77.md)
 - init_IRQ()->...->gic_of_init()
- 76th (2014/11/01) week: [76차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_76.md)
 - init_IRQ()
- 75th (2014/10/25) week: [75차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_75.md)
 - init_IRQ()
 - RBTree 알고리즘
- 74th (2014/10/18) week: [74차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_74.md)
 - init_IRQ()
- 73th (2014/10/11) week: [73차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_73.md)
 - init_IRQ()
- 72th (2014/10/04) week: [72차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_72.md)
 - tick_nohz_init()
 - context_tracking_init()
 - radix_tree_init()
 - early_irq_init()
 - init_IRQ()
- 71th (2014/09/27) week: [71차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_71.md)
 - rcu_init()
- 70th (2014/09/20) week: [70차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_70.md)
 - rcu_init()
- 69th (2014/09/13) week: [69차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_69.md)
 - sched_init()를 계속 분석
 - sched_init()::for_each_possible_cpu(i) { ... }
 - sched_init()->set_load_weight()
 - sched_init()->plist_head_init()
 - sched_init()->init_idle()
 - sched_init()->zalloc_cpumask_var()
* 68th (2014/08/30) week: [68차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_68.md)
 - sched_init()
 - rq 설정 (for_each_possible_cpu(i))
* 67th (2014/08/23) week: [67차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_67.md)
 - mm_init() 복습
 - slub() 복습 (kmem_cache_init(), percpu_init_late(), vmalloc_init())
* 66th (2014/08/16) week: [66차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_66.md)
 - mm_init() 복습;
 - buddy 까지 복습 (mem_init())
* 65th (2014/08/09) week: [65차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_65.md)
 - start_kernel()-> mm_init()-> vmalloc_init();
 - vmlist에 등록된 vm struct 들을 slab으로 이관하고 RB Tree로 구성
* 64th (2014/07/26) week: [64차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_64.md)
 - start_kernel()-> mm_init()-> kmem_cache_init()
 - start_kernel()-> mm_init()-> percpu_init_late()
 - start_kernel()-> mm_init()-> pgtable_cache_init()
* 63th (2014/07/19) week: [63차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_63.md)
 - mm_init()->kmem_cache_init()->bootstrab(&boot_kmem_cache_node) 
* 62th (2014/07/12) week: [62차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_62.md)
 - mm_init()->kmem_cache_init()->bootstrab(&boot_kmem_cache) 
* 61th (2014/07/05) week: [61차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_61.md)
* 60th (2014/06/28) week: [60차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_60.md)
* 59th (2014/06/21) week: [59차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_59.md)
* 58th (2014/06/14) week: [58차](https://github.com/arm10c/linux-stable/blob/master/Reference/88_Review/a10c_58.md)
 
...

* 12th (2012-07-13) week: [12차](http://www.iamroot.org/xe/index.php?_filter=search&mid=Kernel_10_ARM&search_keyword=13&search_target=title&page=3&document_srl=176125) 15명
 - arch/arm/boot/compressed/head.S
 - restart 진입 후 LC0값 로드
* 11th (2012-07-06) week: [11차](http://www.iamroot.org/xe/index.php?mid=Kernel_10_ARM&category=172676&page=6&document_srl=174738) 18+2명
 - arch/arm/boot/compressed/head.S 분석
 - _setup_mmu 종료
* 10th (2012-06-29) week: [10차](http://www.iamroot.org/xe/index.php?mid=Kernel_10_ARM&category=172676&page=6&document_srl=174738) 22명
 - arch/arm/boot/compressed/head.S 분석
 - _setup_mmu 진입직전
* 09th (2012-06-22) week: [09차](http://www.iamroot.org/xe/index.php?mid=Kernel_10_ARM&category=172676&page=6&document_srl=171562) 25명
 - arch/arm/boot/compressed/head.S 분석
 - call_cache_fn 진입직전
 - Arm System Developer's Guide (Ch.14 ~ 끝)
* 08th (2012-06-15) week: [08차] 21명
 - Arm System Developer's Guide (Ch.09 ~ Ch.14.4 페이지 테이블)
* 07th (2012-06-08) week: [07차] 20명
 - Arm System Developer's Guide (시작 ~ Ch.09 인터럽트 처리방법)
* 06th (2012-06-01) week: [06차]
 - ARM v7 아키텍쳐 세미나
* 05th (2012-05-25) week: [05차]
 - ARM v7 아키텍쳐 세미나
* 04th (2012-05-18) week: [04차] 28명+1 (백창우님)
 - Arm System Developer's Guide (pt자료)
* 03th (2012-05-11) week: [03차] 22명
 - 리눅스 커널 내부구조 (p.150 ~ 끝)
* 02th (2012-05-04) week: [02차] 27명
 - 리눅스 커널 내부구조 (p. 88~ p.150)
* 01th (2012-04-28) week: [01차] 34명
 - 리눅스 커널 내부구조 (처음  ~ p. 88)
=======


