/*
 *  linux/arch/arm/kernel/devtree.c
 *
 *  Copyright (C) 2009 Canonical Ltd. <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>

#include <asm/cputype.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <asm/smp_plat.h>
#include <asm/mach/arch.h>
#include <asm/mach-types.h>

// ARM10C 20131012
void __init early_init_dt_add_memory_arch(u64 base, u64 size)
{
	arm_add_memory(base, size);
}

// ARM10C 20140208
// size + 4 : ?, __alignof__(struct device_node) : 4
void * __init early_init_dt_alloc_memory_arch(u64 size, u64 align)
{
	return alloc_bootmem_align(size, align);
}

// ARM10C 20131026
void __init arm_dt_memblock_reserve(void)
{
	u64 *reserve_map, base, size;

	// initial_boot_params: atag 의 위치 값
	if (!initial_boot_params)
		return;

	/* Reserve the dtb region */
	memblock_reserve(virt_to_phys(initial_boot_params),
			 be32_to_cpu(initial_boot_params->totalsize));

	/*
	 * Process the reserve map.  This will probably overlap the initrd
	 * and dtb locations which are already reserved, but overlaping
	 * doesn't hurt anything
	 */
	// offset to memory reserve map
	reserve_map = ((void*)initial_boot_params) +
			be32_to_cpu(initial_boot_params->off_mem_rsvmap);
	while (1) {
		// detree 값이 big endian이므로 little로 변환
		base = be64_to_cpup(reserve_map++);
		size = be64_to_cpup(reserve_map++);
		if (!size)
			break;
		memblock_reserve(base, size);
	}
}

/*
 * arm_dt_init_cpu_maps - Function retrieves cpu nodes from the device tree
 * and builds the cpu logical map array containing MPIDR values related to
 * logical cpus
 *
 * Updates the cpu possible mask with the number of parsed cpu nodes
 */
// ARM10C 20140215
void __init arm_dt_init_cpu_maps(void)
{
	/*
	 * Temp logical map is initialized with UINT_MAX values that are
	 * considered invalid logical map entries since the logical map must
	 * contain a list of MPIDR[23:0] values where MPIDR[31:24] must
	 * read as 0.
	 */
	struct device_node *cpu, *cpus;
	u32 i, j, cpuidx = 1;
        // A.R.M: B4.1.106 MPIDR, Multiprocessor Affinity Register, VMSA
	// T.R.M: 4.3.5 Multiprocessor Affinity Register
        // MPIDR_HWID_BITMASK: 0xFFFFFF
	// mpidr: CPU ID를 가리킴
	u32 mpidr = is_smp() ? read_cpuid_mpidr() & MPIDR_HWID_BITMASK : 0;
	// mpidr 값은 0

        // NR_CPUS: 4, MPIDR_INVALID: 0xFF000000
	u32 tmp_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };
	bool bootcpu_valid = false;
	cpus = of_find_node_by_path("/cpus");
        // cpus: cpus의tree의주소값

	if (!cpus)
		return;

        // for_each_child_of_node(cpus, cpu) 
        //   for (cpu = of_get_next_child(cpus, NULL); cpu != NULL; \
        //      cpu = of_get_next_child(cpus, cpu))
	for_each_child_of_node(cpus, cpu) {
		// [0] cpu: cpu0의 node의 주소값
		u32 hwid;

                // cpu->type: "cpu", "cpu"
		if (of_node_cmp(cpu->type, "cpu"))
			continue;

		// cpu->full_name: "/cpus/cpu@0"
		pr_debug(" * %s...\n", cpu->full_name);
		/*
		 * A device tree containing CPU nodes with missing "reg"
		 * properties is considered invalid to build the
		 * cpu_logical_map.
		 */
		// [0] cpu: cpu0의 node의 주소값, "reg", &hwid
		if (of_property_read_u32(cpu, "reg", &hwid)) {
			pr_debug(" * %s missing reg property\n",
				     cpu->full_name);
			return;
		}
		// hwid: 0

		/*
		 * 8 MSBs must be set to 0 in the DT since the reg property
		 * defines the MPIDR[23:0].
		 */
		// ~MPIDR_HWID_BITMASK: 0xFF000000
		if (hwid & ~MPIDR_HWID_BITMASK)
			return;

		/*
		 * Duplicate MPIDRs are a recipe for disaster.
		 * Scan all initialized entries and check for
		 * duplicates. If any is found just bail out.
		 * temp values were initialized to UINT_MAX
		 * to avoid matching valid MPIDR[23:0] values.
		 */
		// cpuidx: 1
		for (j = 0; j < cpuidx; j++)
			// tmp_map[0]: 0xFF000000, hwid: 0
			if (WARN(tmp_map[j] == hwid, "Duplicate /cpu reg "
						     "properties in the DT\n"))
				return;

		/*
		 * Build a stashed array of MPIDR values. Numbering scheme
		 * requires that if detected the boot CPU must be assigned
		 * logical id 0. Other CPUs get sequential indexes starting
		 * from 1. If a CPU node with a reg property matching the
		 * boot CPU MPIDR is detected, this is recorded so that the
		 * logical map built from DT is validated and can be used
		 * to override the map created in smp_setup_processor_id().
		 */
		// hwid: 0, mpidr: 0
		if (hwid == mpidr) {
			i = 0;
			bootcpu_valid = true;
		} else {
			i = cpuidx++;
		}

		// cpuidx: 1,  nr_cpu_ids: 4
		if (WARN(cpuidx > nr_cpu_ids, "DT /cpu %u nodes greater than "
					       "max cores %u, capping them\n",
					       cpuidx, nr_cpu_ids)) {
			cpuidx = nr_cpu_ids;
			break;
		}

		// i:0  hwid: 0
		tmp_map[i] = hwid;
		// tmp_map[0]: 0 
	}

	// bootcpu_valid: true
	if (!bootcpu_valid) {
		pr_warn("DT missing boot CPU MPIDR[23:0], fall back to default cpu_logical_map\n");
		return;
	}

	/*
	 * Since the boot CPU node contains proper data, and all nodes have
	 * a reg property, the DT CPU list can be considered valid and the
	 * logical map created in smp_setup_processor_id() can be overridden
	 */
	// cpuidx: 4
	for (i = 0; i < cpuidx; i++) {
		// i: 0, true
		set_cpu_possible(i, true);
		cpu_logical_map(i) = tmp_map[i];
		// __cpu_logical_map[0]: tmp_map[0]: 0

		pr_debug("cpu logical map 0x%x\n", cpu_logical_map(i));
	}
}

/**
 * setup_machine_fdt - Machine setup when an dtb was passed to the kernel
 * @dt_phys: physical address of dt blob
 *
 * If a dtb was passed to the kernel in r2, then use it to choose the
 * correct machine_desc and to setup the system.
 */
// ARM10C 20130928
struct machine_desc * __init setup_machine_fdt(unsigned int dt_phys)
{
	struct boot_param_header *devtree;
	struct machine_desc *mdesc, *mdesc_best = NULL;
	unsigned int score, mdesc_score = ~1;
	unsigned long dt_root;
	const char *model;

#ifdef CONFIG_ARCH_MULTIPLATFORM // not defined
	DT_MACHINE_START(GENERIC_DT, "Generic DT based system")
	MACHINE_END

	mdesc_best = (struct machine_desc *)&__mach_desc_GENERIC_DT;
#endif

	if (!dt_phys)
		return NULL;

// 2013/09/28 종료
// 2013/10/05 시작
	devtree = phys_to_virt(dt_phys);

	/* check device tree validity */

	// little endian으로 swap 한 결과
	// devtree->magic: 0xd00dfeed
	if (be32_to_cpu(devtree->magic) != OF_DT_HEADER)
		return NULL;

	/* Search the mdescs for the 'best' compatible value match */
	initial_boot_params = devtree;
	dt_root = of_get_flat_dt_root();
	for_each_machine_desc(mdesc) {
		// 아래 경로의 dtcompat 값 비교
		// arch/arm/mach-exynos/mach-exynos5-dt.c
		score = of_flat_dt_match(dt_root, mdesc->dt_compat);
		if (score > 0 && score < mdesc_score) {
			mdesc_best = mdesc;
			mdesc_score = score;
		}
	}

	// 해당하는 compatible 이 없을 경우 에러 메시지 처리
	if (!mdesc_best) {
		const char *prop;
		long size;

		early_print("\nError: unrecognized/unsupported "
			    "device tree compatible list:\n[ ");

		prop = of_get_flat_dt_prop(dt_root, "compatible", &size);
		while (size > 0) {
			early_print("'%s' ", prop);
			size -= strlen(prop) + 1;
			prop += strlen(prop) + 1;
		}
		early_print("]\n\n");

		dump_machine_table(); /* does not return */
	}

	model = of_get_flat_dt_prop(dt_root, "model", NULL);

	// model 명이 없으면 compatible 의 문자열을 가져옴 
	if (!model)
		model = of_get_flat_dt_prop(dt_root, "compatible", NULL);
	if (!model)
		model = "<unknown>";
	pr_info("Machine: %s, model: %s\n", mdesc_best->name, model);

// 2013/10/05 종료
// 2013/10/12 시작
	/* Retrieve various information from the /chosen node */
	// dt에서 chosen 노드를 찾고 정보를 저장 
	of_scan_flat_dt(early_init_dt_scan_chosen, boot_command_line);

	/* Initialize {size,address}-cells info */
	// dt에서 root 노드에 있는 정보를 저장
	of_scan_flat_dt(early_init_dt_scan_root, NULL);

	/* Setup memory, calling early_init_dt_add_memory_arch */
	// dt에서 memory 노드에 있는 정보를 저장
	of_scan_flat_dt(early_init_dt_scan_memory, NULL);

	/* Change machine number to match the mdesc we're using */
	// FIXME: machine_arch_type값이 0xFFFFFFFF 가 맞는지?
	// __machine_arch_type = 0xFFFFFFFF 
	__machine_arch_type = mdesc_best->nr;

	return mdesc_best;
}
