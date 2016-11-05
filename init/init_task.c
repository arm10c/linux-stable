#include <linux/init_task.h>
#include <linux/export.h>
#include <linux/mqueue.h>
#include <linux/sched.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/rt.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>

#include <asm/pgtable.h>
#include <asm/uaccess.h>

// ARM10C 20150808
// ARM10C 20160827
// ARM10C 20160903
// INIT_SIGNALS(init_signals):
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
static struct signal_struct init_signals = INIT_SIGNALS(init_signals);
// ARM10C 20150808
// ARM10C 20160903
// ARM10C 20161105
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
static struct sighand_struct init_sighand = INIT_SIGHAND(init_sighand);

/* Initial task structure */
// ARM10C 20140315
// ARM10C 20140913
// ARM10C 20150808
// ARM10C 20160521
// ARM10C 20160827
// INIT_TASK(init_task):
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
struct task_struct init_task = INIT_TASK(init_task);
EXPORT_SYMBOL(init_task);

/*
 * Initial thread structure. Alignment of this is handled by a special
 * linker map entry.
 */
// ARM10C 20130824
// ARM10C 20140315
// ARM10C 20160402
// __init_task_data: __attribute__((__section__(".data..init_task")))
// INIT_THREAD_INFO(init_task):
// {
// 	.task		= &init_task,
// 	.exec_domain	= &default_exec_domain,
// 	.flags		= 0,
// 	.preempt_count	= 0x40000001,
// 	.addr_limit	= KERNEL_DS,
// 	.cpu_domain	= domain_val(DOMAIN_USER, DOMAIN_MANAGER) |
// 			  domain_val(DOMAIN_KERNEL, DOMAIN_MANAGER) |
// 			  domain_val(DOMAIN_IO, DOMAIN_CLIENT),
// 	.restart_block	= {
// 		.fn	= do_no_restart_syscall,
// 	},
// }
//
// union thread_union init_thread_union __attribute__((__section__(".data..init_task"))) =
// {
// 	.task		= &init_task,
// 	.exec_domain	= &default_exec_domain,
// 	.flags		= 0,
// 	.preempt_count	= 0x40000001,
// 	.addr_limit	= KERNEL_DS,
// 	.cpu_domain	= domain_val(DOMAIN_USER, DOMAIN_MANAGER) |
// 			  domain_val(DOMAIN_KERNEL, DOMAIN_MANAGER) |
// 			  domain_val(DOMAIN_IO, DOMAIN_CLIENT),
// 	.restart_block	= {
// 		.fn	= do_no_restart_syscall,
// 	},
// }
union thread_union init_thread_union __init_task_data =
	{ INIT_THREAD_INFO(init_task) };
