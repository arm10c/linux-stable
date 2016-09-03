#ifndef _LINUX__INIT_TASK_H
#define _LINUX__INIT_TASK_H

#include <linux/rcupdate.h>
#include <linux/irqflags.h>
#include <linux/utsname.h>
#include <linux/lockdep.h>
#include <linux/ftrace.h>
#include <linux/ipc.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/securebits.h>
#include <linux/seqlock.h>
#include <net/net_namespace.h>
#include <linux/sched/rt.h>

#ifdef CONFIG_SMP // CONFIG_SMP=y
// ARM10C 20150808
// MAX_PRIO: 140
// PLIST_NODE_INIT(init_task.pushable_tasks, 140):
// {
// 	.prio  = (140),
// 	.prio_list = { &((init_task.pushable_tasks).prio_list), &((init_task.pushable_tasks).prio_list) },
// 	.node_list = { &((init_task.pushable_tasks).node_list), &((init_task.pushable_tasks).node_list) },
// }
//
// #define INIT_PUSHABLE_TASKS(init_task):
//	.pushable_tasks =
//	{
//		.prio  = (140),
//		.prio_list = { &((init_task.pushable_tasks).prio_list), &((init_task.pushable_tasks).prio_list) },
//		.node_list = { &((init_task.pushable_tasks).node_list), &((init_task.pushable_tasks).node_list) },
//	},
# define INIT_PUSHABLE_TASKS(tsk)					\
	.pushable_tasks = PLIST_NODE_INIT(tsk.pushable_tasks, MAX_PRIO),
#else
# define INIT_PUSHABLE_TASKS(tsk)
#endif

extern struct files_struct init_files;
extern struct fs_struct init_fs;

#ifdef CONFIG_CGROUPS // CONFIG_CGROUPS=y
// ARM10C 20160903
// __RWSEM_INITIALIZER(init_signals.group_rwsem):
// {
//     0x00000000L,
//     (raw_spinlock_t)
//     {
//        .raw_lock = { { 0 } },
//        .magic = 0xdead4ead,
//        .owner_cpu = -1,
//        .owner = 0xffffffff,
//     },
//     { &((init_signals.group_rwsem).wait_list), &((init_signals.group_rwsem).wait_list) }
//  }
//
// #define INIT_GROUP_RWSEM(init_signals):
// .group_rwsem =
// {
//     0x00000000L,
//     (raw_spinlock_t)
//     {
//        .raw_lock = { { 0 } },
//        .magic = 0xdead4ead,
//        .owner_cpu = -1,
//        .owner = 0xffffffff,
//     },
//     { &((init_signals.group_rwsem).wait_list), &((init_signals.group_rwsem).wait_list) }
//  }
#define INIT_GROUP_RWSEM(sig)						\
	.group_rwsem = __RWSEM_INITIALIZER(sig.group_rwsem),
#else
#define INIT_GROUP_RWSEM(sig)
#endif

#ifdef CONFIG_CPUSETS // CONFIG_CPUSETS=n
#define INIT_CPUSET_SEQ(tsk)							\
	.mems_allowed_seq = SEQCNT_ZERO(tsk.mems_allowed_seq),
#else
// ARM10C 20150808
#define INIT_CPUSET_SEQ(tsk)
#endif

// ARM10C 20160827
// ARM10C 20160903
// __WAIT_QUEUE_HEAD_INITIALIZER(init_signals.wait_chldexit):
// {
//     .lock            = (spinlock_t )
//                        { { .rlock =
//                            {
//                              .raw_lock = { { 0 } },
//                              .magic = 0xdead4ead,
//                              .owner_cpu = -1,
//                              .owner = 0xffffffff,
//                            }
//                        } }
//     .task_list       = { &(init_signals.wait_chldexit).task_list, &(init_signals.wait_chldexit).task_list }
// }
// LIST_HEAD_INIT(init_signals.shared_pending.list):
// { &(init_signals.shared_pending.list), &(init_signals.shared_pending.list) }
// LIST_HEAD_INIT(init_signals.posix_timers):
// { &(init_signals.posix_timers), &(init_signals.posix_timers) }
// INIT_CPU_TIMERS(init_signals.cpu_timers):
// {
//     { &(init_signals.cpu_timers[0]), &(init_signals.cpu_timers[0]) },
//     { &(init_signals.cpu_timers[1]), &(init_signals.cpu_timers[1]) },
//     { &(init_signals.cpu_timers[2]), &(init_signals.cpu_timers[2]) },
// }
// INIT_RLIMITS:
// {
//     [0]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//     [1]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//     [2]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//     [3]    = {    0x800000,  0xFFFFFFFF },
//     [4]    = {           0,  0xFFFFFFFF },
//     [5]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//     [6]    = {           0,           0 },
//     [7]    = {       0x400,      0x1000 },
//     [8]    = {     0x10000,     0x10000 },
//     [9]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//     [10]   = {  0xFFFFFFFF,  0xFFFFFFFF },
//     [11]   = {           0,           0 },
//     [12]   = {     0xC8000,     0xC8000 },
//     [13]   = {           0,           0 },
//     [14]   = {           0,           0 },
//     [15]   = {  0xFFFFFFFF,  0xFFFFFFFF },
// }
// INIT_CPUTIME:
// (struct task_cputime) {
//     .utime = 0,
//     .stime = 0,
//     .sum_exec_runtime = 0,
// }
// __RAW_SPIN_LOCK_UNLOCKED(init_signals.cputimer.lock):
// (raw_spinlock_t)
// {
//    .raw_lock = { { 0 } },
//    .magic = 0xdead4ead,
//    .owner_cpu = -1,
//    .owner = 0xffffffff,
// }
// __MUTEX_INITIALIZER(init_signals.cred_guard_mutex):
// { .count = { (1) }
//    , .wait_lock =
//    (spinlock_t )
//    { { .rlock =
//          {
//              .raw_lock = { { 0 } },
//              .magic = 0xdead4ead,
//              .owner_cpu = -1,
//              .owner = 0xffffffff,
//          }
//    } }
//    , .wait_list =
//    { &(init_signals.cred_guard_mutex.wait_list), &(init_signals.cred_guard_mutex.wait_list) }
//    , .magic = &init_signals.cred_guard_mutex
// }
// INIT_GROUP_RWSEM(init_signals):
// .group_rwsem =
// {
//     0x00000000L,
//     (raw_spinlock_t)
//     {
//        .raw_lock = { { 0 } },
//        .magic = 0xdead4ead,
//        .owner_cpu = -1,
//        .owner = 0xffffffff,
//     },
//     { &((init_signals.group_rwsem).wait_list), &((init_signals.group_rwsem).wait_list) }
//  }
//
// #define INIT_SIGNALS(init_signals):
// {
//     .nr_threads = 1,
//     .wait_chldexit =
//     {
//         .lock = (spinlock_t )
//         { { .rlock =
//               {
//                    .raw_lock = { { 0 } },
//                    .magic = 0xdead4ead,
//                    .owner_cpu = -1,
//                    .owner = 0xffffffff,
//                }
//         } }
//         .task_list = { &(init_signals.wait_chldexit).task_list, &(init_signals.wait_chldexit).task_list }
//     },
//     .shared_pending = {
//                           .list = { &(init_signals.shared_pending.list), &(init_signals.shared_pending.list) },
//                           .signal =  {{0}}
//                        },
//     .posix_timers = { &(init_signals.posix_timers), &(init_signals.posix_timers) },
//     .cpu_timers =
//     {
//         { &(init_signals.cpu_timers[0]), &(init_signals.cpu_timers[0]) },
//         { &(init_signals.cpu_timers[1]), &(init_signals.cpu_timers[1]) },
//         { &(init_signals.cpu_timers[2]), &(init_signals.cpu_timers[2]) },
//     }
//     .rlim =
//     {
//         [0]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//         [1]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//         [2]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//         [3]    = {    0x800000,  0xFFFFFFFF },
//         [4]    = {           0,  0xFFFFFFFF },
//         [5]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//         [6]    = {           0,           0 },
//         [7]    = {       0x400,      0x1000 },
//         [8]    = {     0x10000,     0x10000 },
//         [9]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//         [10]   = {  0xFFFFFFFF,  0xFFFFFFFF },
//         [11]   = {           0,           0 },
//         [12]   = {     0xC8000,     0xC8000 },
//         [13]   = {           0,           0 },
//         [14]   = {           0,           0 },
//         [15]   = {  0xFFFFFFFF,  0xFFFFFFFF },
//     },
//     .cputimer        = {
//         .cputime =
//         (struct task_cputime) {
//             .utime = 0,
//             .stime = 0,
//             .sum_exec_runtime = 0,
//         },
//
//         .running = 0,
//         .lock =
//         (raw_spinlock_t)
//         {
//            .raw_lock = { { 0 } },
//            .magic = 0xdead4ead,
//            .owner_cpu = -1,
//            .owner = 0xffffffff,
//         },
//     },
//     .cred_guard_mutex =
//     { .count = { (1) }
//        , .wait_lock =
//        (spinlock_t )
//        { { .rlock =
//              {
//                  .raw_lock = { { 0 } },
//                  .magic = 0xdead4ead,
//                  .owner_cpu = -1,
//                  .owner = 0xffffffff,
//              }
//        } }
//        , .wait_list =
//        { &(init_signals.cred_guard_mutex.wait_list), &(init_signals.cred_guard_mutex.wait_list) }
//        , .magic = &init_signals.cred_guard_mutex
//     },
//     .group_rwsem =
//     {
//         0x00000000L,
//         (raw_spinlock_t)
//         {
//            .raw_lock = { { 0 } },
//            .magic = 0xdead4ead,
//            .owner_cpu = -1,
//            .owner = 0xffffffff,
//         },
//         { &((init_signals.group_rwsem).wait_list), &((init_signals.group_rwsem).wait_list) }
//     }
// }
#define INIT_SIGNALS(sig) {						\
	.nr_threads	= 1,						\
	.wait_chldexit	= __WAIT_QUEUE_HEAD_INITIALIZER(sig.wait_chldexit),\
	.shared_pending	= { 						\
		.list = LIST_HEAD_INIT(sig.shared_pending.list),	\
		.signal =  {{0}}},					\
	.posix_timers	 = LIST_HEAD_INIT(sig.posix_timers),		\
	.cpu_timers	= INIT_CPU_TIMERS(sig.cpu_timers),		\
	.rlim		= INIT_RLIMITS,					\
	.cputimer	= { 						\
		.cputime = INIT_CPUTIME,				\
		.running = 0,						\
		.lock = __RAW_SPIN_LOCK_UNLOCKED(sig.cputimer.lock),	\
	},								\
	.cred_guard_mutex =						\
		 __MUTEX_INITIALIZER(sig.cred_guard_mutex),		\
	INIT_GROUP_RWSEM(sig)						\
}

extern struct nsproxy init_nsproxy;

// ARM10C 20160903
// ATOMIC_INIT(1): { (1) }
// __SPIN_LOCK_UNLOCKED(init_sighand.siglock):
// (spinlock_t )
// { { .rlock =
//     {
//         .raw_lock = { { 0 } },
//         .magic = 0xdead4ead,
//         .owner_cpu = -1,
//         .owner = 0xffffffff,
//     }
// } }
// __WAIT_QUEUE_HEAD_INITIALIZER(init_sighand.signalfd_wqh):
// {
//     .lock            = (spinlock_t )
//                        { { .rlock =
//                            {
//                              .raw_lock = { { 0 } },
//                              .magic = 0xdead4ead,
//                              .owner_cpu = -1,
//                              .owner = 0xffffffff,
//                            }
//                        } }
//     .task_list       = { &(init_sighand.signalfd_wqh).task_list, &(init_sighand.signalfd_wqh).task_list }
// }
//
// #define INIT_SIGHAND(init_sighand):
// {
//     .count        = { (1) },
//     .action       = { { { .sa_handler = SIG_DFL, } }, },
//     .siglock      =
//     (spinlock_t )
//     { { .rlock =
//         {
//             .raw_lock = { { 0 } },
//             .magic = 0xdead4ead,
//             .owner_cpu = -1,
//             .owner = 0xffffffff,
//         }
//     } },
//     .signalfd_wqh =
//     {
//         .lock = (spinlock_t )
//         { { .rlock =
//             {
//                 .raw_lock = { { 0 } },
//                 .magic = 0xdead4ead,
//                 .owner_cpu = -1,
//                 .owner = 0xffffffff,
//             }
//         } }
//         .task_list = { &(init_sighand.signalfd_wqh).task_list, &(init_sighand.signalfd_wqh).task_list }
//     },
// }
#define INIT_SIGHAND(sighand) {						\
	.count		= ATOMIC_INIT(1), 				\
	.action		= { { { .sa_handler = SIG_DFL, } }, },		\
	.siglock	= __SPIN_LOCK_UNLOCKED(sighand.siglock),	\
	.signalfd_wqh	= __WAIT_QUEUE_HEAD_INITIALIZER(sighand.signalfd_wqh),	\
}

extern struct group_info init_groups;

// ARM10C 20160903
// ATOMIC_INIT(1): { (1) }
//
// #define INIT_STRUCT_PID:
// {
//     .count        = { (1) },
//     .tasks        = {
//         { .first = NULL },
//         { .first = NULL },
//         { .first = NULL },
//     },
//     .level        = 0,
//     .numbers      = { {
//         .nr        = 0,
//         .ns        = &init_pid_ns,
//         .pid_chain    = { .next = NULL, .pprev = NULL },
//     }, }
// }
#define INIT_STRUCT_PID {						\
	.count 		= ATOMIC_INIT(1),				\
	.tasks		= {						\
		{ .first = NULL },					\
		{ .first = NULL },					\
		{ .first = NULL },					\
	},								\
	.level		= 0,						\
	.numbers	= { {						\
		.nr		= 0,					\
		.ns		= &init_pid_ns,				\
		.pid_chain	= { .next = NULL, .pprev = NULL },	\
	}, }								\
}

// ARM10C 20150808
// #define INIT_PID_LINK(PIDTYPE_PID):
// {
// 	.node = {
// 		.next = NULL,
// 		.pprev = NULL,
// 	},
// 	.pid = &init_struct_pid,
// }
// ARM10C 20150808
// #define INIT_PID_LINK(PIDTYPE_PGID):
// {
// 	.node = {
// 		.next = NULL,
// 		.pprev = NULL,
// 	},
// 	.pid = &init_struct_pid,
// }
// ARM10C 20150808
// #define INIT_PID_LINK(PIDTYPE_SID):
// {
// 	.node = {
// 		.next = NULL,
// 		.pprev = NULL,
// 	},
// 	.pid = &init_struct_pid,
// }
#define INIT_PID_LINK(type) 					\
{								\
	.node = {						\
		.next = NULL,					\
		.pprev = NULL,					\
	},							\
	.pid = &init_struct_pid,				\
}

#ifdef CONFIG_AUDITSYSCALL // CONFIG_AUDITSYSCALL=n
#define INIT_IDS \
	.loginuid = INVALID_UID, \
	.sessionid = -1,
#else
// ARM10C 20150808
#define INIT_IDS
#endif

#ifdef CONFIG_RCU_BOOST // CONFIG_RCU_BOOST=n
#define INIT_TASK_RCU_BOOST()						\
	.rcu_boost_mutex = NULL,
#else
// ARM10C 20150808
#define INIT_TASK_RCU_BOOST()
#endif
#ifdef CONFIG_TREE_PREEMPT_RCU // CONFIG_TREE_PREEMPT_RCU=y
// ARM10C 20150808
// #define INIT_TASK_RCU_TREE_PREEMPT():
//	.rcu_blocked_node = NULL,
#define INIT_TASK_RCU_TREE_PREEMPT()					\
	.rcu_blocked_node = NULL,
#else
#define INIT_TASK_RCU_TREE_PREEMPT(tsk)
#endif
#ifdef CONFIG_PREEMPT_RCU // CONFIG_PREEMPT_RCU=y
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.rcu_node_entry):
// { &(init_task.rcu_node_entry), &(init_task.rcu_node_entry) }
// INIT_TASK_RCU_TREE_PREEMPT():
// .rcu_blocked_node = NULL,
//
// #define INIT_TASK_RCU_PREEMPT(init_task):
// 	.rcu_read_lock_nesting = 0,
// 	.rcu_read_unlock_special = 0,
// 	.rcu_node_entry = { &(init_task.rcu_node_entry), &(init_task.rcu_node_entry) },
// 	.rcu_blocked_node = NULL,
#define INIT_TASK_RCU_PREEMPT(tsk)					\
	.rcu_read_lock_nesting = 0,					\
	.rcu_read_unlock_special = 0,					\
	.rcu_node_entry = LIST_HEAD_INIT(tsk.rcu_node_entry),		\
	INIT_TASK_RCU_TREE_PREEMPT()					\
	INIT_TASK_RCU_BOOST()
#else
#define INIT_TASK_RCU_PREEMPT(tsk)
#endif

extern struct cred init_cred;

extern struct task_group root_task_group;

#ifdef CONFIG_CGROUP_SCHED // CONFIG_CGROUP_SCHED=y
// ARM10C 20150808
// #define INIT_CGROUP_SCHED(init_task):
// 	.sched_task_group = &root_task_group,
# define INIT_CGROUP_SCHED(tsk)						\
	.sched_task_group = &root_task_group,
#else
# define INIT_CGROUP_SCHED(tsk)
#endif

#ifdef CONFIG_PERF_EVENTS // CONFIG_PERF_EVENTS=n
# define INIT_PERF_EVENTS(tsk)						\
	.perf_event_mutex = 						\
		 __MUTEX_INITIALIZER(tsk.perf_event_mutex),		\
	.perf_event_list = LIST_HEAD_INIT(tsk.perf_event_list),
#else
// ARM10C 20150808
# define INIT_PERF_EVENTS(tsk)
#endif

#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN // CONFIG_VIRT_CPU_ACCOUNTING_GEN=n
# define INIT_VTIME(tsk)						\
	.vtime_seqlock = __SEQLOCK_UNLOCKED(tsk.vtime_seqlock),	\
	.vtime_snap = 0,				\
	.vtime_snap_whence = VTIME_SYS,
#else
// ARM10C 20150808
# define INIT_VTIME(tsk)
#endif

// ARM10C 20140913
// ARM10C 20150808
// INIT_TASK_COMM: "swapper"
#define INIT_TASK_COMM "swapper"

/*
 *  INIT_TASK is used to set up the first task table, touch at
 * your own risk!. Base=0, limit=0x1fffff (=2MB)
 */
// ARM10C 20130831
// .cpus_allowed : 3
// ARM10C 20140315
// ARM10C 20140510
// PF_KTHREAD: 0x00200000
// MAX_PRIO: 140
// SCHED_NORMAL: 0
// ARM10C 20150808
// ATOMIC_INIT(2): { (2) }
// PF_KTHREAD: 0x00200000
// MAX_PRIO: 140
// SCHED_NORMAL: 0
// CPU_MASK_ALL: (cpumask_t) { { [0] = 0xf } }
// NR_CPUS: 4
// LIST_HEAD_INIT(init_task.se.group_node):
// { &(init_task.se.group_node), &(init_task.se.group_node) }
// LIST_HEAD_INIT(init_task.rt.run_list):
// { &(init_task.rt.run_list), &(init_task.rt.run_list) }
// RR_TIMESLICE: 10
// LIST_HEAD_INIT(init_task.tasks):
// { &(init_task.tasks), &(init_task.tasks) }
// INIT_PUSHABLE_TASKS(init_task):
// .pushable_tasks =
// {
//     .prio  = (140),
//     .prio_list = { &((init_task.pushable_tasks).prio_list), &((init_task.pushable_tasks).prio_list) },
//     .node_list = { &((init_task.pushable_tasks).node_list), &((init_task.pushable_tasks).node_list) },
// },
// INIT_CGROUP_SCHED(init_task):
// .sched_task_group = &root_task_group,
// LIST_HEAD_INIT(init_task.ptraced):
// { &(init_task.ptraced), &(init_task.ptraced) }
// LIST_HEAD_INIT(init_task.ptrace_entry):
// { &(init_task.ptrace_entry), &(init_task.ptrace_entry) }
// LIST_HEAD_INIT(init_task.children):
// { &(init_task.children), &(init_task.children) }
// LIST_HEAD_INIT(init_task.sibling):
// { &(init_task.sibling), &(init_task.sibling) }
// RCU_POINTER_INITIALIZER(real_cred, &init_cred):
// .real_cred = (typeof(*&init_cred) __force __rcu *)(&init_cred)
// RCU_POINTER_INITIALIZER(cred, &init_cred):
// .cred = (typeof(*&init_cred) __force __rcu *)(&init_cred)
// INIT_TASK_COMM: "swapper"
// INIT_THREAD: {}
// LIST_HEAD_INIT(init_task.pending.list):
// { &(init_task.pending.list), &(init_task.pending.list) }
// __SPIN_LOCK_UNLOCKED(init_task.alloc_lock):
// (spinlock_t )
// { { .rlock =
//     {
//       .raw_lock = { { 0 } },
//       .magic = 0xdead4ead,
//       .owner_cpu = -1,
//       .owner = 0xffffffff,
//     }
// } }
// INIT_CPU_TIMERS(init_task.cpu_timers):
// {
//     { &(init_task.cpu_timers[0]), &(init_task.cpu_timers[0]) },
//     { &(init_task.cpu_timers[1]), &(init_task.cpu_timers[1]) },
//     { &(init_task.cpu_timers[2]), &(init_task.cpu_timers[2]) },
// }
// __RAW_SPIN_LOCK_UNLOCKED(init_task.pi_lock):
// (raw_spinlock_t)
// {
//    .raw_lock = { { 0 } },
//    .magic = 0xdead4ead,
//    .owner_cpu = -1,
//    .owner = 0xffffffff,
// }
// PIDTYPE_PID: 0
// PIDTYPE_PGID: 1
// PIDTYPE_SID: 2
// INIT_PID_LINK(PIDTYPE_PID):
// {
//     .node = {
//         .next = NULL,
//         .pprev = NULL,
//     },
//     .pid = &init_struct_pid,
// }
// INIT_PID_LINK(PIDTYPE_PGID):
// {
//     .node = {
//         .next = NULL,
//         .pprev = NULL,
//     },
//     .pid = &init_struct_pid,
// }
// INIT_PID_LINK(PIDTYPE_SID):
// {
//     .node = {
//         .next = NULL,
//         .pprev = NULL,
//     },
//     .pid = &init_struct_pid,
// }
// LIST_HEAD_INIT(init_task.thread_group):
// { &(init_task.thread_group), &(init_task.thread_group) }
// INIT_TRACE_RECURSION: .trace_recursion = 0,
// INIT_TASK_RCU_PREEMPT(init_task):
// .rcu_read_lock_nesting = 0,
// .rcu_read_unlock_special = 0,
// .rcu_node_entry = { &(init_task.rcu_node_entry), &(init_task.rcu_node_entry) },
// .rcu_blocked_node = NULL,
//
// #define INIT_TASK(init_task):
// {
//    .state            = 0,
//    .stack            = &init_thread_info,
//    .usage            = { (2) },
//    .flags            = 0x00200000,
//    .prio             = 120,
//    .static_prio      = 120,
//    .normal_prio      = 120,
//    .policy           = 0,
//    .cpus_allowed     = (cpumask_t) { { [0] = 0xf } },
//    .nr_cpus_allowed  = 4,
//    .mm               = NULL,
//    .active_mm        = &init_mm,
//    .se               = {
//        .group_node = { &(init_task.se.group_node), &(init_task.se.group_node) }
//    },
//    .rt               = {
//        .run_list     = { &(init_task.rt.run_list), &(init_task.rt.run_list) },
//        .time_slice   = 10,
//    },
//    .tasks            = { &(init_task.tasks), &(init_task.tasks) },
//    .pushable_tasks   =
//    {
//        .prio  = (140),
//        .prio_list = { &((init_task.pushable_tasks).prio_list), &((init_task.pushable_tasks).prio_list) },
//        .node_list = { &((init_task.pushable_tasks).node_list), &((init_task.pushable_tasks).node_list) },
//    },
//    .sched_task_group = &root_task_group,
//    .ptraced          = { &(init_task.ptraced), &(init_task.ptraced) },
//    .ptrace_entry     = { &(init_task.ptrace_entry), &(init_task.ptrace_entry) },
//    .real_parent      = &init_task,
//    .parent           = &init_task,
//    .children         = { &(init_task.children), &(init_task.children) },
//    .sibling          = { &(init_task.sibling), &(init_task.sibling) },
//    .group_leader     = &init_task,
//    .real_cred        = (typeof(*&init_cred) __force __rcu *)(&init_cred),
//    .cred             = (typeof(*&init_cred) __force __rcu *)(&init_cred),
//    .comm             = "swapper",
//    .thread           = {},
//    .fs               = &init_fs,
//    .files            = &init_files,
//    .signal           = &init_signals,
//    .sighand          = &init_sighand,
//    .nsproxy          = &init_nsproxy,
//    .pending          = {
//        .list = { &(init_task.pending.list), &(init_task.pending.list) },
//        .signal = {{0}}
//    },
//    .blocked          = {{0}},
//    .alloc_lock       =
//    (spinlock_t )
//    { { .rlock =
//        {
//          .raw_lock = { { 0 } },
//          .magic = 0xdead4ead,
//          .owner_cpu = -1,
//          .owner = 0xffffffff,
//        }
//    } },
//    .journal_info     = NULL,
//    .cpu_timers       =
//    {
//        { &(init_task.cpu_timers[0]), &(init_task.cpu_timers[0]) },
//        { &(init_task.cpu_timers[1]), &(init_task.cpu_timers[1]) },
//        { &(init_task.cpu_timers[2]), &(init_task.cpu_timers[2]) },
//    },
//    .pi_lock          =
//    (raw_spinlock_t)
//    {
//       .raw_lock = { { 0 } },
//       .magic = 0xdead4ead,
//       .owner_cpu = -1,
//       .owner = 0xffffffff,
//    },
//    .timer_slack_ns   = 50000,
//    .pids             = {
//        [0]  =
//        {
//            .node = {
//                .next = NULL,
//                .pprev = NULL,
//            },
//            .pid = &init_struct_pid,
//        },
//        [1]  =
//        {
//            .node = {
//                .next = NULL,
//                .pprev = NULL,
//            },
//            .pid = &init_struct_pid,
//        },
//        [2]  =
//        {
//            .node = {
//                .next = NULL,
//                .pprev = NULL,
//            },
//            .pid = &init_struct_pid,
//        },
//    },
//    .thread_group     = { &(init_task.thread_group), &(init_task.thread_group) },
//    .trace_recursion  = 0,
//    .rcu_read_lock_nesting = 0,
//    .rcu_read_unlock_special = 0,
//    .rcu_node_entry   = { &(init_task.rcu_node_entry), &(init_task.rcu_node_entry) },
//    .rcu_blocked_node = NULL,
// }
#define INIT_TASK(tsk)							\
{									\
	.state		= 0,						\
	.stack		= &init_thread_info,				\
	.usage		= ATOMIC_INIT(2),				\
	.flags		= PF_KTHREAD,					\
	.prio		= MAX_PRIO-20,					\
	.static_prio	= MAX_PRIO-20,					\
	.normal_prio	= MAX_PRIO-20,					\
	.policy		= SCHED_NORMAL,					\
	.cpus_allowed	= CPU_MASK_ALL,					\
	.nr_cpus_allowed= NR_CPUS,					\
	.mm		= NULL,						\
	.active_mm	= &init_mm,					\
	.se		= {						\
		.group_node 	= LIST_HEAD_INIT(tsk.se.group_node),	\
	},								\
	.rt		= {						\
		.run_list	= LIST_HEAD_INIT(tsk.rt.run_list),	\
		.time_slice	= RR_TIMESLICE,				\
	},								\
	.tasks		= LIST_HEAD_INIT(tsk.tasks),			\
	INIT_PUSHABLE_TASKS(tsk)					\
	INIT_CGROUP_SCHED(tsk)						\
	.ptraced	= LIST_HEAD_INIT(tsk.ptraced),			\
	.ptrace_entry	= LIST_HEAD_INIT(tsk.ptrace_entry),		\
	.real_parent	= &tsk,						\
	.parent		= &tsk,						\
	.children	= LIST_HEAD_INIT(tsk.children),			\
	.sibling	= LIST_HEAD_INIT(tsk.sibling),			\
	.group_leader	= &tsk,						\
	RCU_POINTER_INITIALIZER(real_cred, &init_cred),			\
	RCU_POINTER_INITIALIZER(cred, &init_cred),			\
	.comm		= INIT_TASK_COMM,				\
	.thread		= INIT_THREAD,					\
	.fs		= &init_fs,					\
	.files		= &init_files,					\
	.signal		= &init_signals,				\
	.sighand	= &init_sighand,				\
	.nsproxy	= &init_nsproxy,				\
	.pending	= {						\
		.list = LIST_HEAD_INIT(tsk.pending.list),		\
		.signal = {{0}}},					\
	.blocked	= {{0}},					\
	.alloc_lock	= __SPIN_LOCK_UNLOCKED(tsk.alloc_lock),		\
	.journal_info	= NULL,						\
	.cpu_timers	= INIT_CPU_TIMERS(tsk.cpu_timers),		\
	.pi_lock	= __RAW_SPIN_LOCK_UNLOCKED(tsk.pi_lock),	\
	.timer_slack_ns = 50000, /* 50 usec default slack */		\
	.pids = {							\
		[PIDTYPE_PID]  = INIT_PID_LINK(PIDTYPE_PID),		\
		[PIDTYPE_PGID] = INIT_PID_LINK(PIDTYPE_PGID),		\
		[PIDTYPE_SID]  = INIT_PID_LINK(PIDTYPE_SID),		\
	},								\
	.thread_group	= LIST_HEAD_INIT(tsk.thread_group),		\
	INIT_IDS							\
	INIT_PERF_EVENTS(tsk)						\
	INIT_TRACE_IRQFLAGS						\
	INIT_LOCKDEP							\
	INIT_FTRACE_GRAPH						\
	INIT_TRACE_RECURSION						\
	INIT_TASK_RCU_PREEMPT(tsk)					\
	INIT_CPUSET_SEQ(tsk)						\
	INIT_VTIME(tsk)							\
}


// ARM10C 20150808
// LIST_HEAD_INIT(init_task.cpu_timers[0]):
// { &(init_task.cpu_timers[0]), &(init_task.cpu_timers[0]) }
// LIST_HEAD_INIT(init_task.cpu_timers[1]):
// { &(init_task.cpu_timers[1]), &(init_task.cpu_timers[1]) }
// LIST_HEAD_INIT(init_task.cpu_timers[2]):
// { &(init_task.cpu_timers[2]), &(init_task.cpu_timers[2]) }
//
// #define INIT_CPU_TIMERS(init_task.cpu_timers):
// {
// 	{ &(init_task.cpu_timers[0]), &(init_task.cpu_timers[0]) },
// 	{ &(init_task.cpu_timers[1]), &(init_task.cpu_timers[1]) },
// 	{ &(init_task.cpu_timers[2]), &(init_task.cpu_timers[2]) },
// }
//
// ARM10C 20160903
// INIT_CPU_TIMERS(init_signals.cpu_timers):
// {
// 	{ &(init_signals.cpu_timers[0]), &(init_signals.cpu_timers[0]) },
// 	{ &(init_signals.cpu_timers[1]), &(init_signals.cpu_timers[1]) },
// 	{ &(init_signals.cpu_timers[2]), &(init_signals.cpu_timers[2]) },
// }
#define INIT_CPU_TIMERS(cpu_timers)					\
{									\
	LIST_HEAD_INIT(cpu_timers[0]),					\
	LIST_HEAD_INIT(cpu_timers[1]),					\
	LIST_HEAD_INIT(cpu_timers[2]),					\
}

/* Attach to the init_task data structure for proper alignment */
// ARM10C 20140315
#define __init_task_data __attribute__((__section__(".data..init_task")))


#endif
