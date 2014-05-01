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

static struct signal_struct init_signals = INIT_SIGNALS(init_signals);
static struct sighand_struct init_sighand = INIT_SIGHAND(init_sighand);

/* Initial task structure */
// ARM10C 20140315
struct task_struct init_task = INIT_TASK(init_task);
EXPORT_SYMBOL(init_task);

/*
 * Initial thread structure. Alignment of this is handled by a special
 * linker map entry.
 */
// ARM10C 20130824
// ARM10C 20140315
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
