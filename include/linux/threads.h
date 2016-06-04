#ifndef _LINUX_THREADS_H
#define _LINUX_THREADS_H


/*
 * The default limit for the nr of threads is now in
 * /proc/sys/kernel/threads-max.
 */

/*
 * Maximum supported processors.  Setting this smaller saves quite a
 * bit of memory.  Use nr_cpu_ids instead of this except for static bitmaps.
 */
#ifndef CONFIG_NR_CPUS
/* FIXME: This should be fixed in the arch's Kconfig */
#define CONFIG_NR_CPUS	1
#endif

/* Places which use this should consider cpumask_var_t. */
// ARM10C 20140215
// ARM10C 20140830
// ARM10C 20140920
// ARM10C 20150103
// ARM10C 20150808
// ARM10C 20160604
// CONFIG_NR_CPUS: 4
// NR_CPUS: 4
#define NR_CPUS		CONFIG_NR_CPUS

#define MIN_THREADS_LEFT_FOR_ROOT 4

/*
 * This controls the default maximum pid allocated to a process
 */
// ARM10C 20150912
// CONFIG_BASE_SMALL: 0
// PID_MAX_DEFAULT: 0x8000
#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)

/*
 * A maximum of 4 million PIDs should be enough for a while.
 * [NOTE: PID/TIDs are limited to 2^29 ~= 500+ million, see futex.h.]
 */
// ARM10C 20150912
// CONFIG_BASE_SMALL: 0
// PID_MAX_DEFAULT: 0x8000
// PID_MAX_LIMIT: 0x8000
#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
	(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))

/*
 * Define a minimum number of pids per cpu.  Heuristically based
 * on original pid max of 32k for 32 cpus.  Also, increase the
 * minimum settable value for pid_max on the running system based
 * on similar defaults.  See kernel/pid.c:pidmap_init() for details.
 */
// ARM10C 20150912
// PIDS_PER_CPU_DEFAULT: 1024
#define PIDS_PER_CPU_DEFAULT	1024
// ARM10C 20150912
// PIDS_PER_CPU_MIN: 8
#define PIDS_PER_CPU_MIN	8

#endif
