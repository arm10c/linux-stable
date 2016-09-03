#ifndef _UAPI_ASM_GENERIC_RESOURCE_H
#define _UAPI_ASM_GENERIC_RESOURCE_H

/*
 * Resource limit IDs
 *
 * ( Compatibility detail: there are architectures that have
 *   a different rlimit ID order in the 5-9 range and want
 *   to keep that order for binary compatibility. The reasons
 *   are historic and all new rlimits are identical across all
 *   arches. If an arch has such special order for some rlimits
 *   then it defines them prior including asm-generic/resource.h. )
 */

// ARM10C 20160903
// RLIMIT_CPU: 0
#define RLIMIT_CPU		0	/* CPU time in sec */
// ARM10C 20160903
// RLIMIT_FSIZE: 1
#define RLIMIT_FSIZE		1	/* Maximum filesize */
// ARM10C 20160903
// RLIMIT_DATA: 2
#define RLIMIT_DATA		2	/* max data size */
// ARM10C 20160903
// RLIMIT_STACK: 3
#define RLIMIT_STACK		3	/* max stack size */
// ARM10C 20160903
// RLIMIT_CORE: 4
#define RLIMIT_CORE		4	/* max core file size */

#ifndef RLIMIT_RSS
// ARM10C 20160903
// RLIMIT_RSS: 5
# define RLIMIT_RSS		5	/* max resident set size */
#endif

#ifndef RLIMIT_NPROC
// ARM10C 20150919
// ARM10C 20160903
// RLIMIT_NPROC: 6
# define RLIMIT_NPROC		6	/* max number of processes */
#endif

#ifndef RLIMIT_NOFILE
// ARM10C 20160903
// RLIMIT_NOFILE: 7
# define RLIMIT_NOFILE		7	/* max number of open files */
#endif

#ifndef RLIMIT_MEMLOCK
// ARM10C 20160903
// RLIMIT_MEMLOCK: 8
# define RLIMIT_MEMLOCK		8	/* max locked-in-memory address space */
#endif

#ifndef RLIMIT_AS
// ARM10C 20160903
// RLIMIT_AS: 9
# define RLIMIT_AS		9	/* address space limit */
#endif

// ARM10C 20160903
// RLIMIT_LOCKS: 10
#define RLIMIT_LOCKS		10	/* maximum file locks held */
// ARM10C 20150919
// ARM10C 20160903
// RLIMIT_SIGPENDING: 11
#define RLIMIT_SIGPENDING	11	/* max number of pending signals */
// ARM10C 20160903
// RLIMIT_MSGQUEUE: 12
#define RLIMIT_MSGQUEUE		12	/* maximum bytes in POSIX mqueues */
// ARM10C 20160903
// RLIMIT_NICE: 13
#define RLIMIT_NICE		13	/* max nice prio allowed to raise to
					   0-39 for nice level 19 .. -20 */
// ARM10C 20160903
// RLIMIT_RTPRIO: 14
#define RLIMIT_RTPRIO		14	/* maximum realtime priority */
// ARM10C 20160903
// RLIMIT_RTTIME: 15
#define RLIMIT_RTTIME		15	/* timeout for RT tasks in us */
// ARM10C 20150919
// RLIM_NLIMITS: 16
#define RLIM_NLIMITS		16

/*
 * SuS says limits have to be unsigned.
 * Which makes a ton more sense anyway.
 *
 * Some architectures override this (for compatibility reasons):
 */
#ifndef RLIM_INFINITY
// ARM10C 20160903
// RLIM_INFINITY: 0xFFFFFFFF
# define RLIM_INFINITY		(~0UL)
#endif

/*
 * RLIMIT_STACK default maximum - some architectures override it:
 */
#ifndef _STK_LIM_MAX
// ARM10C 20160903
// RLIM_INFINITY: 0xFFFFFFFF
// _STK_LIM_MAX: 0xFFFFFFFF
# define _STK_LIM_MAX		RLIM_INFINITY
#endif


#endif /* _UAPI_ASM_GENERIC_RESOURCE_H */
