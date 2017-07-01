/*
 *  linux/init/main.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  GK 2/5/95  -  Changed to support mounting root fs via NFS
 *  Added initrd & change_root: Werner Almesberger & Hans Lermen, Feb '96
 *  Moan early if gcc is old, avoiding bogus kernels - Paul Gortmaker, May '96
 *  Simplified starting of init:  Michael A. Griffith <grif@acm.org> 
 */

#define DEBUG		/* Enable initcall_debug */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/stackprotector.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/bootmem.h>
#include <linux/acpi.h>
#include <linux/tty.h>
#include <linux/percpu.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/kernel_stat.h>
#include <linux/start_kernel.h>
#include <linux/security.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/rcupdate.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/writeback.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/cgroup.h>
#include <linux/efi.h>
#include <linux/tick.h>
#include <linux/interrupt.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/unistd.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <linux/key.h>
#include <linux/buffer_head.h>
#include <linux/page_cgroup.h>
#include <linux/debug_locks.h>
#include <linux/debugobjects.h>
#include <linux/lockdep.h>
#include <linux/kmemleak.h>
#include <linux/pid_namespace.h>
#include <linux/device.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/idr.h>
#include <linux/kgdb.h>
#include <linux/ftrace.h>
#include <linux/async.h>
#include <linux/kmemcheck.h>
#include <linux/sfi.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/file.h>
#include <linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/sched_clock.h>
#include <linux/context_tracking.h>
#include <linux/random.h>

#include <asm/io.h>
#include <asm/bugs.h>
#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/cacheflush.h>

#ifdef CONFIG_X86_LOCAL_APIC
#include <asm/smp.h>
#endif

static int kernel_init(void *);

extern void init_IRQ(void);
extern void fork_init(unsigned long);
extern void mca_init(void);
extern void sbus_init(void);
extern void radix_tree_init(void);
#ifndef CONFIG_DEBUG_RODATA
static inline void mark_rodata_ro(void) { }
#endif

#ifdef CONFIG_TC
extern void tc_init(void);
#endif

/*
 * Debug helper: via this flag we know that we are in 'early bootup code'
 * where only the boot processor is running with IRQ disabled.  This means
 * two things - IRQ must not be enabled before the flag is cleared and some
 * operations which are not allowed with IRQ disabled are allowed while the
 * flag is set.
 */
// ARM10C 20150620
bool early_boot_irqs_disabled __read_mostly;

// ARM10C 20140308
// ARM10C 20140927
enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

extern void time_init(void);
/* Default late time init is NULL. archs can override this later. */
// ARM10C 20150912
void (*__initdata late_time_init)(void);

/* Untouched command line saved by arch-specific code. */
// ARM10C 20140222
char __initdata boot_command_line[COMMAND_LINE_SIZE];

/* Untouched saved command line (eg. for /proc) */
// ARM10C 20140222
char *saved_command_line;

/* Command line for parameter parsing */
// ARM10C 20140222
static char *static_command_line;
/* Command line for per-initcall parameter parsing */
static char *initcall_command_line;

static char *execute_command;
static char *ramdisk_execute_command;

/*
 * Used to generate warnings if static_key manipulation functions are used
 * before jump_label_init is called.
 */
bool static_key_initialized __read_mostly = false;
EXPORT_SYMBOL_GPL(static_key_initialized);

/*
 * If set, this is an indication to the drivers that reset the underlying
 * device before going ahead with the initialization otherwise driver might
 * rely on the BIOS and skip the reset operation.
 *
 * This is useful if kernel is booting in an unreliable environment.
 * For ex. kdump situaiton where previous kernel has crashed, BIOS has been
 * skipped and devices will be in unknown state.
 */
unsigned int reset_devices;
EXPORT_SYMBOL(reset_devices);

static int __init set_reset_devices(char *str)
{
	reset_devices = 1;
	return 1;
}

__setup("reset_devices", set_reset_devices);

static const char * argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char * envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
// ARM10C 20150801
static const char *panic_later, *panic_param;

// ARM10C 20131019
extern const struct obs_kernel_param __setup_start[], __setup_end[];

// ARM10C 20150627
// param: "console=ttySAC2,115200"
static int __init obsolete_checksetup(char *line)
{
	const struct obs_kernel_param *p;
	int had_early_param = 0;
	// had_early_param: 0

	p = __setup_start;
	do {
		// NOTE:
		// __setup_console_setup의 경우의 코드를 분석

		// p->str: __setup_console_setup.str: "console=", strlen("console="): 8
		int n = strlen(p->str);
		// n: 8

		// line: "console=ttySAC2,115200", p->str: __setup_console_setup.str: "console=", n: 8
		// parameqn("console=ttySAC2,115200", "console=", 8): true
		if (parameqn(line, p->str, n)) {
			// p->early: __setup_console_setup.early: 0,
			// p->setup_func: __setup_console_setup.setup_func: console_setup
			// line: "console=ttySAC2,115200", n: 8
			// console_setup("ttySAC2,115200"): 1
			if (p->early) {
				/* Already done in parse_early_param?
				 * (Needs exact match on param part).
				 * Keep iterating, as we can have early
				 * params and __setups of same names 8( */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = 1;
			} else if (!p->setup_func) {
				pr_warn("Parameter %s is obsolete, ignored\n",
					p->str);
				return 1;
			} else if (p->setup_func(line + n))
				return 1;
				// return 1

				// console_setup에서 한일:
				// selected_console: 0
				// console_cmdline[0].name: "ttySAC"
				// console_cmdline[0].options: "115200"
				// console_cmdline[0].index: 2
				// console_set_on_cmdline: 1
		}
		p++;
	} while (p < __setup_end);

	return had_early_param;
}

/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
// ARM10C 20150516
// loops_per_jiffy: 4096
unsigned long loops_per_jiffy = (1<<12);

EXPORT_SYMBOL(loops_per_jiffy);

static int __init debug_kernel(char *str)
{
	console_loglevel = 10;
	return 0;
}

static int __init quiet_kernel(char *str)
{
	console_loglevel = 4;
	return 0;
}

early_param("debug", debug_kernel);
early_param("quiet", quiet_kernel);

static int __init loglevel(char *str)
{
	int newlevel;

	/*
	 * Only update loglevel value when a correct setting was passed,
	 * to prevent blind crashes (when loglevel being set to 0) that
	 * are quite hard to debug
	 */
	if (get_option(&str, &newlevel)) {
		console_loglevel = newlevel;
		return 0;
	}

	return -EINVAL;
}

early_param("loglevel", loglevel);

/* Change NUL term back to "=", to make "param" the whole string. */
// ARM10C 20150627
// param: "console", val: "ttySAC2,115200", unused: "Booting kernel"
static int __init repair_env_string(char *param, char *val, const char *unused)
{
	// val: "ttySAC2,115200"
	if (val) {
		/* param=val or param="val"? */
		// val: "ttySAC2,115200", param: "console", strlen("console"): 7
		if (val == param+strlen(param)+1)
			val[-1] = '=';
			// param: "console=ttySAC2,115200"
		else if (val == param+strlen(param)+2) {
			val[-2] = '=';
			memmove(val-1, val, strlen(val)+1);
			val--;
		} else
			BUG();
	}
	return 0;
	// return 0
}

/*
 * Unknown boot options get handed to init, unless they look like
 * unused parameters (modprobe will find them in /proc/cmdline).
 */
// ARM10C 20140322
// ARM10C 20150627
// param: "console", val: "ttySAC2,115200", doing: "Booting kernel"
static int __init unknown_bootoption(char *param, char *val, const char *unused)
{
	// param: "console", val: "ttySAC2,115200", unused: "Booting kernel"
	repair_env_string(param, val, unused);

	// repair_env_string에서 한일:
	// param: "console=ttySAC2,115200"

	/* Handle obsolete-style parameters */
	// param: "console=ttySAC2,115200"
	// obsolete_checksetup("console=ttySAC2,115200"): 1
	if (obsolete_checksetup(param))
		return 0;
		// return 0

	// obsolete_checksetup에서 한일:
	// selected_console: 0
	// console_cmdline[0].name: "ttySAC"
	// console_cmdline[0].options: "115200"
	// console_cmdline[0].index: 2
	// console_set_on_cmdline: 1

	/* Unused module parameter. */
	if (strchr(param, '.') && (!val || strchr(param, '.') < val))
		return 0;

	if (panic_later)
		return 0;

	if (val) {
		/* Environment option */
		unsigned int i;
		for (i = 0; envp_init[i]; i++) {
			if (i == MAX_INIT_ENVS) {
				panic_later = "Too many boot env vars at `%s'";
				panic_param = param;
			}
			if (!strncmp(param, envp_init[i], val - param))
				break;
		}
		envp_init[i] = param;
	} else {
		/* Command line option */
		unsigned int i;
		for (i = 0; argv_init[i]; i++) {
			if (i == MAX_INIT_ARGS) {
				panic_later = "Too many boot init vars at `%s'";
				panic_param = param;
			}
		}
		argv_init[i] = param;
	}
	return 0;
}

static int __init init_setup(char *str)
{
	unsigned int i;

	execute_command = str;
	/*
	 * In case LILO is going to boot us with default command line,
	 * it prepends "auto" before the whole cmdline which makes
	 * the shell think it should execute a script with such name.
	 * So we ignore all arguments entered _before_ init=... [MJ]
	 */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("init=", init_setup);

static int __init rdinit_setup(char *str)
{
	unsigned int i;

	ramdisk_execute_command = str;
	/* See "auto" comment in init_setup */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("rdinit=", rdinit_setup);

#ifndef CONFIG_SMP
static const unsigned int setup_max_cpus = NR_CPUS;
#ifdef CONFIG_X86_LOCAL_APIC
static void __init smp_init(void)
{
	APIC_init_uniprocessor();
}
#else
#define smp_init()	do { } while (0)
#endif

static inline void setup_nr_cpu_ids(void) { }
static inline void smp_prepare_cpus(unsigned int maxcpus) { }
#endif

/*
 * We need to store the untouched command line for future reference.
 * We also need to store the touched command line since the parameter
 * parsing is performed in place, and we should allow a component to
 * store reference of name/value for future reference.
 */
// ARM10C 20140222
// command_line: "console=ttySAC2,115200 init=/linuxrc"
static void __init setup_command_line(char *command_line)
{
	saved_command_line = alloc_bootmem(strlen (boot_command_line)+1);
	initcall_command_line = alloc_bootmem(strlen (boot_command_line)+1);
	static_command_line = alloc_bootmem(strlen (command_line)+1);
	// 현재 boot_command_line 과 command_line 은 같은 문자열.
	// saved_command_line 은 고정값 static_command_line 은 수정용.

	strcpy (saved_command_line, boot_command_line);
	strcpy (static_command_line, command_line);
	// saved_command_line 및 static_command_line 할당
}

/*
 * We need to finalize in a non-__init function or else race conditions
 * between the root thread and the init thread may cause start_kernel to
 * be reaped by free_initmem before the root thread has proceeded to
 * cpu_idle.
 *
 * gcc-3.4 accidentally inlines this function, so use noinline.
 */

// ARM10C 20170701
// DECLARE_COMPLETION(kthreadd_done):
// struct completion kthreadd_done =
// { 0,
//   {
//     .lock            = (spinlock_t )
//                        { { .rlock =
//                            {
//                              .raw_lock = { { 0 } },
//                              .magic = 0xdead4ead,
//                              .owner_cpu = -1,
//                              .owner = 0xffffffff,
//                            }
//                        } }
//     .task_list       = { &(kthreadd_done).task_list, &(kthreadd_done).task_list }
//   }.wait
// }
static __initdata DECLARE_COMPLETION(kthreadd_done);

// ARM10C 20160827
static noinline void __init_refok rest_init(void)
{
	int pid;

	rcu_scheduler_starting(); // null function
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	// CLONE_FS: 0x00000200, CLONE_SIGHAND: 0x00000800
	//kernel_thread(kernel_init, NULL, 0x00000A00): 1
	kernel_thread(kernel_init, NULL, CLONE_FS | CLONE_SIGHAND);

	// kernel_thread 에서 한일:
	// struct task_struct 만큼의 메모리를 할당 받음
	// kmem_cache#15-oX (struct task_struct)
	//
	// struct thread_info 를 구성 하기 위한 메모리를 할당 받음 (8K)
	// 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 메모리에 init_task 값을 전부 할당함
	//
	// (kmem_cache#15-oX (struct task_struct))->stack: 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 의 stack의 값을 init_task 의 stack 값에서 전부 복사함
	// 복사된 struct thread_info 의 task 주소값을 할당 받은 kmem_cache#15-oX (struct task_struct)로 변경함
	// *(할당 받은 page 2개의 메로리의 가상 주소): init_thread_info
	// ((struct thread_info *) 할당 받은 page 2개의 메로리의 가상 주소)->task: kmem_cache#15-oX (struct task_struct)
	//
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 1 bit 값을 clear 수행
	//
	// *((unsigned long *)(할당 받은 page 2개의 메로리의 가상 주소 + 1)): 0x57AC6E9D
	//
	// (&(kmem_cache#15-oX (struct task_struct))->usage)->counter: 2
	// (kmem_cache#15-oX (struct task_struct))->splice_pipe: NULL
	// (kmem_cache#15-oX (struct task_struct))->task_frag.page: NULL
	//
	// (&contig_page_data)->node_zones[0].vm_stat[16]: 1 을 더함
	// vmstat.c의 vm_stat[16] 전역 변수에도 1을 더함
	//
	// &(kmem_cache#15-oX (struct task_struct))->pi_lock을 사용한 spinlock 초기화
	// &(kmem_cache#15-oX (struct task_struct))->pi_waiters 리스트 초기화
	// (kmem_cache#15-oX (struct task_struct))->pi_blocked_on: NULL
	//
	// (&init_task)->flags: 0x00200100
	// (&init_task)->flags: 0x00200100
	//
	// struct cred 만큼의 메모리를 할당 받음
	// kmem_cache#16-oX (struct cred)
	//
	// kmem_cache#16-oX (struct cred) 에 init_cred 에 있는 맴버값 전부를 복사함
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 1
	// (&(&init_groups)->usage)->counter: 3
	// (&(&root_user)->__count)->counter: 2
	// (&(&root_user)->processes)->counter: 2
	//
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 2
	//
	// (kmem_cache#15-oX (struct task_struct))->cred: kmem_cache#16-oX (struct cred)
	// (kmem_cache#15-oX (struct task_struct))->real_cred: kmem_cache#16-oX (struct cred)
	// (kmem_cache#15-oX (struct task_struct))->did_exec: 0
	// (kmem_cache#15-oX (struct task_struct))->flags: 0x00200040
	//
	// (&(kmem_cache#15-oX (struct task_struct))->children)->next: &(kmem_cache#15-oX (struct task_struct))->children
	// (&(kmem_cache#15-oX (struct task_struct))->children)->prev: &(kmem_cache#15-oX (struct task_struct))->children
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->next: &(kmem_cache#15-oX (struct task_struct))->sibling
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->prev: &(kmem_cache#15-oX (struct task_struct))->sibling
	//
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_lock_nesting: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_unlock_special: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_blocked_node: NULL
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->next: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry
	//
	// (kmem_cache#15-oX (struct task_struct))->vfork_done: NULL
	//
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->magic: 0xdead4ead
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner: 0xffffffff
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner_cpu: 0xffffffff
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list
	//
	// (kmem_cache#15-oX (struct task_struct))->utime: 0
	// (kmem_cache#15-oX (struct task_struct))->stime: 0
	// (kmem_cache#15-oX (struct task_struct))->gtime: 0
	// (kmem_cache#15-oX (struct task_struct))->utimescaled: 0
	// (kmem_cache#15-oX (struct task_struct))->stimescaled: 0
	//
	// &(kmem_cache#15-oX (struct task_struct))->rss_stat 값을 0 으로 초기화 수행
	//
	// (kmem_cache#15-oX (struct task_struct))->default_timer_slack_ns: 50000
	//
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.prof_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.virt_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.sched_exp: 0
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	//
	// (kmem_cache#15-oX (struct task_struct))->start_time 에 현재 시간 값을 가져옴
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_sec: normalized 된 sec 값
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_nsec: normalized 된 nsec 값
	//
	// (kmem_cache#15-oX (struct task_struct))->io_context: NULL
	// (kmem_cache#15-oX (struct task_struct))->audit_context: NULL
	//
	// rcu reference의 값 (&init_task)->cgroups 이 유요한지 체크하고 그 값을 리턴함
	// ((&init_task)->cgroups)->refcount: 1
	// (kmem_cache#15-oX (struct task_struct))->cgroups: (&init_task)->cgroups
	//
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->next: &(kmem_cache#15-oX (struct task_struct))->cg_list
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->prev: &(kmem_cache#15-oX (struct task_struct))->cg_list
	//
	// (kmem_cache#15-oX (struct task_struct))->blocked_on: NULL
	//
	// (&kmem_cache#15-oX (struct task_struct))->on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.exec_start: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.prev_sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.nr_migrations: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.vruntime: 0
	// &(&kmem_cache#15-oX (struct task_struct))->se.group_node의 리스트 초기화
	// &(&kmem_cache#15-oX (struct task_struct))->rt.run_list의 리스트 초기화
	//
	// (kmem_cache#15-oX (struct task_struct))->state: 0
	// (kmem_cache#15-oX (struct task_struct))->prio: 120
	// (kmem_cache#15-oX (struct task_struct))->sched_class: &fair_sched_class
	//
	// 현재의 schedule 시간값과 기존의 (&runqueues)->clock 의 값의 차이값을
	// [pcp0] (&runqueues)->clock, [pcp0] (&runqueues)->clock_task 의 값에 더해 갱신함
	//
	// [pcp0] (&runqueues)->clock: schedule 시간 차이값
	// [pcp0] (&runqueues)->clock_task: schedule 시간 차이값
	//
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (&(kmem_cache#15-oX (struct task_struct))->se)->vruntime: 0x5B8D7E
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->on_cpu: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->preempt_count: 1
	// (&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio: 140
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list
	//
	// (kmem_cache#15-oX (struct task_struct))->sysvsem.undo_list: NULL
	//
	// files_cachep: kmem_cache#12 을 사용하여 struct files_struct 을 위한 메모리를 할당함
	// kmem_cache#12-oX (struct files_struct)
	//
	// (kmem_cache#12-oX (struct files_struct))->count: 1
	//
	// &(kmem_cache#12-oX (struct files_struct))->file_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->owner_cpu: 0xffffffff
	//
	// (kmem_cache#12-oX (struct files_struct))->next_fd: 0
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->max_fds: 32
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->close_on_exec: (kmem_cache#12-oX (struct files_struct))->close_on_exec_init
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->open_fds: (kmem_cache#12-oX (struct files_struct))->open_fds_init
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->fd: &(kmem_cache#12-oX (struct files_struct))->fd_array[0]
	//
	// &(&init_files)->file_lock 을 사용하여 spin lock 수행
	//
	// (kmem_cache#12-oX (struct files_struct))->open_fds_init 에 init_files.open_fds_init 값을 복사
	// (kmem_cache#12-oX (struct files_struct))->open_fds_init: NULL
	// (kmem_cache#12-oX (struct files_struct))->close_on_exec_init 에 init_files.close_on_exec_init 값을 복사
	// (kmem_cache#12-oX (struct files_struct))->close_on_exec_init: NULL
	//
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->open_fds 의 0~31 bit 를 clear 함
	// (kmem_cache#12-oX (struct files_struct))->fd_array[0...31]: NULL
	// &(kmem_cache#12-oX (struct files_struct))->fd_array[0] 에 값을 size 0 만큼 0 으로 set 함
	//
	// (kmem_cache#12-oX (struct files_struct))->fdt: &(kmem_cache#12-oX (struct files_struct))->fdtab
	//
	// (kmem_cache#15-oX (struct task_struct))->files: kmem_cache#12-oX (struct files_struct)
	//
	// (&init_fs)->users: 2
	//
	// (&init_sighand)->count: { (2) }
	//
	// struct signal_struct 크기 만큼의 메모리를 할당함
	// kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#15-oX (struct task_struct))->signal: kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#13-oX (struct signal_struct))->nr_threads: 1
	// (kmem_cache#13-oX (struct signal_struct))->live: { (1) }
	// (kmem_cache#13-oX (struct signal_struct))->sigcnt: { (1) }
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->task_list를 사용한 list 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->curr_target: kmem_cache#15-oX (struct task_struct)
	//
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->next: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->prev: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer의 값을 0으로 초기화
	// (&(kmem_cache#13-oX (struct signal_struct))->real_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// RB Tree의 &(&(kmem_cache#13-oX (struct signal_struct))->real_timer)->node 를 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer.function: it_real_fn
	// (kmem_cache#13-oX (struct signal_struct))->rlim 에 (&init_signals)->rlim 값을 전부 복사함
	// &(kmem_cache#13-oX (struct signal_struct))->cputimer.lock 을 사용한 spinlock 초기화 수행
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->activity: 0
	// &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_lock을 사용한 spinlock 초기화
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj: 0
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj_min: 0
	// (kmem_cache#13-oX (struct signal_struct))->has_child_subreaper: 0
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->count: 1
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->onwer: NULL
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->magic: &(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex
	//
	// (kmem_cache#15-oX (struct task_struct))->min_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->maj_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->nvcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->nivcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->last_switch_count: 0
	// (kmem_cache#15-oX (struct task_struct))->mm: NULL
	//
	// (&init_nsproxy)->count: { (2) }
	//
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context 의 값을 0으로 초기화 함
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183) 의 값을 0으로 초기화 함
	//
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r4: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r5: kernel_init
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)->uregs[16]: 0x00000013
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.pc: ret_from_fork
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.sp: ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->tp_value[1]: TPIDRURW의 읽은 값
	//
	// struct pid 만큼의 메모리를 할당 받음
	// kmem_cache#19-oX (struct pid)
	//
	// (kmem_cache#19-oX (struct pid))->level: 0
	//
	// page 사이즈 만큼의 메모리를 할당 받음: kmem_cache#25-oX
	//
	// (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX
	// kmem_cache#25-oX 의 1 bit 의 값을 1 으로 set
	// (&(&init_pid_ns)->pidmap[0])->nr_free: { (0x7FFF) }
	// &(&init_pid_ns)->last_pid 을 1 로 변경함
	//
	// (kmem_cache#19-oX (struct pid))->numbers[0].nr: 1
	// (kmem_cache#19-oX (struct pid))->numbers[0].ns: &init_pid_ns
	//
	// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 3번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 4         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 4)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 4 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 5
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 4
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 4) 의 memory 공간을 반환함
	//
	// mnt_id_start: 5
	//
	// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "proc"
	// (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count: 1
	//
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->next: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->pprev: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->next: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->prev: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->next: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->prev: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->next: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->next: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->prev: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->next: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->prev: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->next: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->next: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks)->first: NULL
	//
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_flags: 0x4000
	//
	// struct super_block 만큼의 메모리를 할당 받음 kmem_cache#25-oX (struct super_block)
	//
	// (&(&(&(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->list)->next: &(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->list
	// (&(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->list)->prev: &(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->list
	// (&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->count: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->list를 연결함
	//
	// &(&(kmem_cache#25-oX (struct super_block))->s_writers.wait)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#25-oX (struct super_block))->s_writers.wait)->task_list를 사용한 list 초기화
	// &(&(kmem_cache#25-oX (struct super_block))->s_writers.wait_unfrozen)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#25-oX (struct super_block))->s_writers.wait_unfrozen)->task_list를 사용한 list 초기화
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->next: NULL
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->pprev: NULL
	// (&(kmem_cache#25-oX (struct super_block))->s_anon)->first: NULL
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_inodes)->next: &(kmem_cache#25-oX (struct super_block))->s_inodes
	// (&(kmem_cache#25-oX (struct super_block))->s_inodes)->prev: &(kmem_cache#25-oX (struct super_block))->s_inodes
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node: kmem_cache#30-oX
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->active_nodes)->bits[0]: 0
	// ((&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].lock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].lock)->magic: 0xdead4ead
	// ((&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].lock)->owner: 0xffffffff
	// ((&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].lock)->owner_cpu: 0xffffffff
	// ((&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].list)->next: (&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].list
	// ((&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].list)->prev: (&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].list
	// (&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].nr_items: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node: kmem_cache#30-oX
	// (&(&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->active_nodes)->bits[0]: 0
	// ((&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].lock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].lock)->magic: 0xdead4ead
	// ((&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].lock)->owner: 0xffffffff
	// ((&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].lock)->owner_cpu: 0xffffffff
	// ((&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].list)->next: (&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].list
	// ((&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].list)->prev: (&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].list
	// (&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].nr_items: 0
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_mounts)->next: &(kmem_cache#25-oX (struct super_block))->s_mounts
	// (&(kmem_cache#25-oX (struct super_block))->s_mounts)->prev: &(kmem_cache#25-oX (struct super_block))->s_mounts
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0
	// &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_lock을 사용한 spinlock 초기화
	// (&(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list)->next: &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list
	// (&(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list)->prev: &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: -1
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->count: 1
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_list)->next: &(&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_list
	// (&(&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_list)->prev: &(&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_list
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->onwer: NULL
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->magic: &(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->count: 1
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_list)->next: &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_list
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_list)->prev: &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_list
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->onwer: NULL
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->magic: &(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->count: 1
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_list)->next: &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_list
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_list)->prev: &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_list
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->onwer: NULL
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->magic: &(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqptr_sem)->activity: 0
	// &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqptr_sem)->wait_lock을 사용한 spinlock 초기화
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqptr_sem)->wait_list)->next: &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqptr_sem)->wait_list
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqptr_sem)->wait_list)->prev: &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqptr_sem)->wait_list
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x400000
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &default_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_count: 1
	// ((kmem_cache#25-oX (struct super_block))->s_active)->counter: 1
	// (kmem_cache#25-oX (struct super_block))->s_maxbytes: 0x7fffffff
	// (kmem_cache#25-oX (struct super_block))->s_op: &default_op
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1000000000
	// (kmem_cache#25-oX (struct super_block))->cleancache_poolid: -1
	// (kmem_cache#25-oX (struct super_block))->s_shrink.seeks: 2
	// (kmem_cache#25-oX (struct super_block))->s_shrink.scan_objects: super_cache_scan
	// (kmem_cache#25-oX (struct super_block))->s_shrink.count_objects: super_cache_count
	// (kmem_cache#25-oX (struct super_block))->s_shrink.batch: 1024
	// (kmem_cache#25-oX (struct super_block))->s_shrink.flags: 1
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 4번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 4         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 4)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	//
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// (&(&unnamed_dev_ida)->idr)->id_free: (idr object new 0)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 4 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 5
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 4) 의 memory 공간을 반환함
	//
	// unnamed_dev_start: 5
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 4
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_fs_info: &init_pid_ns
	// (kmem_cache#25-oX (struct super_block))->s_type: &proc_fs_type
	// (kmem_cache#25-oX (struct super_block))->s_id: "proc"
	//
	// list head인 &super_blocks 에 (kmem_cache#25-oX (struct super_block))->s_list을 tail에 추가
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->next: NULL
	// (&(&proc_fs_type)->fs_supers)->first: &(kmem_cache#25-oX (struct super_block))->s_instances
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->pprev: &(&(&proc_fs_type)->fs_supers)->first
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->flags: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->nr_deferred: kmem_cache#30-oX
	// head list인 &shrinker_list에 &(&(kmem_cache#25-oX (struct super_block))->s_shrink)->list를 tail로 추가함
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x40080a
	// (kmem_cache#25-oX (struct super_block))->s_blocksize: 1024
	// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 10
	// (kmem_cache#25-oX (struct super_block))->s_magic: 0x9fa0
	// (kmem_cache#25-oX (struct super_block))->s_op: &proc_sops
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1
	//
	// (&proc_root)->count: { (2) }
	//
	// struct inode 만큼의 메모리를 할당 받음 kmem_cache#4-oX (struct inode)
	//
	// (kmem_cache#4-oX (struct inode))->i_sb: kmem_cache#25-oX (struct super_block)
	// (kmem_cache#4-oX (struct inode))->i_blkbits: 12
	// (kmem_cache#4-oX (struct inode))->i_flags: 0
	// (kmem_cache#4-oX (struct inode))->i_count: 1
	// (kmem_cache#4-oX (struct inode))->i_op: &empty_iops
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 1
	// (kmem_cache#4-oX (struct inode))->i_opflags: 0
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#4-oX (struct inode))->i_count: 0
	// (kmem_cache#4-oX (struct inode))->i_size: 0
	// (kmem_cache#4-oX (struct inode))->i_blocks: 0
	// (kmem_cache#4-oX (struct inode))->i_bytes: 0
	// (kmem_cache#4-oX (struct inode))->i_generation: 0
	// (kmem_cache#4-oX (struct inode))->i_pipe: NULL
	// (kmem_cache#4-oX (struct inode))->i_bdev: NULL
	// (kmem_cache#4-oX (struct inode))->i_cdev: NULL
	// (kmem_cache#4-oX (struct inode))->i_rdev: 0
	// (kmem_cache#4-oX (struct inode))->dirtied_when: 0
	//
	// &(kmem_cache#4-oX (struct inode))->i_lock을 이용한 spin lock 초기화 수행
	//
	// ((&(kmem_cache#4-oX (struct inode))->i_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#4-oX (struct inode))->i_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#4-oX (struct inode))->i_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#4-oX (struct inode))->i_lock)->rlock)->owner_cpu: 0xffffffff
	//
	// (&(kmem_cache#4-oX (struct inode))->i_mutex)->count: 1
	// (&(&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_list)->next: &(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_list
	// (&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_list)->prev: &(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_list
	// (&(kmem_cache#4-oX (struct inode))->i_mutex)->onwer: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_mutex)->magic: &(kmem_cache#4-oX (struct inode))->i_mutex
	//
	// (kmem_cache#4-oX (struct inode))->i_dio_count: 0
	//
	// (&(kmem_cache#4-oX (struct inode))->i_data)->a_ops: &empty_aops
	// (&(kmem_cache#4-oX (struct inode))->i_data)->host: kmem_cache#4-oX (struct inode)
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0x200DA
	// (&(kmem_cache#4-oX (struct inode))->i_data)->private_data: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_data)->backing_dev_info: &default_backing_dev_info
	// (&(kmem_cache#4-oX (struct inode))->i_data)->writeback_index: 0
	//
	// (kmem_cache#4-oX (struct inode))->i_private: NULL
	// (kmem_cache#4-oX (struct inode))->i_mapping: &(kmem_cache#4-oX (struct inode))->i_data
	// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: NULL
	// (kmem_cache#4-oX (struct inode))->i_acl: (void *)(0xFFFFFFFF),
	// (kmem_cache#4-oX (struct inode))->i_default_acl: (void *)(0xFFFFFFFF)
	// (kmem_cache#4-oX (struct inode))->i_fsnotify_mask: 0
	//
	// [pcp0] nr_inodes: 2
	//
	// (kmem_cache#4-oX (struct inode))->i_state: 0
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
	//
	// (kmem_cache#4-oX (struct inode))->i_ino: 1
	// (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->pde: &proc_root
	// (kmem_cache#4-oX (struct inode))->i_mode: 0040555
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
	// (kmem_cache#4-oX (struct inode))->i_op: &proc_root_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_fop: &proc_root_operations
	//
	// dentry_cache인 kmem_cache#5을 사용하여 dentry로 사용할 메모리 kmem_cache#5-oX (struct dentry)을 할당받음
	//
	// (kmem_cache#5-oX (struct dentry))->d_iname[35]: 0
	// (kmem_cache#5-oX (struct dentry))->d_name.len: 1
	// (kmem_cache#5-oX (struct dentry))->d_name.hash: (&name)->hash: 0
	// (kmem_cache#5-oX (struct dentry))->d_iname: "/"
	//
	// 공유자원을 다른 cpu core가 사용할수 있게 함
	//
	// (kmem_cache#5-oX (struct dentry))->d_name.name: "/"
	// (kmem_cache#5-oX (struct dentry))->d_lockref.count: 1
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->magic: 0xdead4ead
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->owner: 0xffffffff
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->owner_cpu: 0xffffffff
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_seq)->sequence: 0
	//
	// (kmem_cache#5-oX (struct dentry))->d_inode: NULL
	//
	// (kmem_cache#5-oX (struct dentry))->d_parent: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#5-oX (struct dentry))->d_sb: kmem_cache#25-oX (struct super_block)
	// (kmem_cache#5-oX (struct dentry))->d_op: NULL
	// (kmem_cache#5-oX (struct dentry))->d_fsdata: NULL
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->pprev: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_lru)->next: &(kmem_cache#5-oX (struct dentry))->d_lru
	// (&(kmem_cache#5-oX (struct dentry))->d_lru)->prev: &(kmem_cache#5-oX (struct dentry))->d_lru
	// (&(kmem_cache#5-oX (struct dentry))->d_subdirs)->next: &(kmem_cache#5-oX (struct dentry))->d_subdirs
	// (&(kmem_cache#5-oX (struct dentry))->d_subdirs)->prev: &(kmem_cache#5-oX (struct dentry))->d_subdirs
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->pprev: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_u.d_child)->next: &(kmem_cache#5-oX (struct dentry))->d_u.d_child
	// (&(kmem_cache#5-oX (struct dentry))->d_u.d_child)->prev: &(kmem_cache#5-oX (struct dentry))->d_u.d_child
	//
	// (kmem_cache#5-oX (struct dentry))->d_op: NULL
	//
	// [pcp0] nr_dentry: 3
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->next: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: &(kmem_cache#5-oX (struct dentry))->d_alias
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->pprev: &(&(kmem_cache#5-oX (struct dentry))->d_alias)
	//
	// (kmem_cache#5-oX (struct dentry))->d_inode: kmem_cache#4-oX (struct inode)
	//
	// 공유자원을 다른 cpu core가 사용할수 있게 함
	// (&(kmem_cache#5-oX (struct dentry))->d_seq)->sequence: 2
	//
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100000
	//
	// (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
	//
	// dentry_cache인 kmem_cache#5을 사용하여 dentry로 사용할 메모리 kmem_cache#5-oX (struct dentry)을 할당받음
	//
	// (kmem_cache#5-oX (struct dentry))->d_iname[35]: 0
	// (kmem_cache#5-oX (struct dentry))->d_name.len: 4
	// (kmem_cache#5-oX (struct dentry))->d_name.hash: (&q)->hash: 0xXXXXXXXX
	// (kmem_cache#5-oX (struct dentry))->d_iname: "self"
	//
	// 공유자원을 다른 cpu core가 사용할수 있게 함
	//
	// (kmem_cache#5-oX (struct dentry))->d_name.name: "self"
	// (kmem_cache#5-oX (struct dentry))->d_lockref.count: 1
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->magic: 0xdead4ead
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->owner: 0xffffffff
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->owner_cpu: 0xffffffff
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_seq)->sequence: 0
	//
	// (kmem_cache#5-oX (struct dentry))->d_inode: NULL
	//
	// (kmem_cache#5-oX (struct dentry))->d_parent: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#5-oX (struct dentry))->d_sb: kmem_cache#25-oX (struct super_block)
	// (kmem_cache#5-oX (struct dentry))->d_op: NULL
	// (kmem_cache#5-oX (struct dentry))->d_fsdata: NULL
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->pprev: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_lru)->next: &(kmem_cache#5-oX (struct dentry))->d_lru
	// (&(kmem_cache#5-oX (struct dentry))->d_lru)->prev: &(kmem_cache#5-oX (struct dentry))->d_lru
	// (&(kmem_cache#5-oX (struct dentry))->d_subdirs)->next: &(kmem_cache#5-oX (struct dentry))->d_subdirs
	// (&(kmem_cache#5-oX (struct dentry))->d_subdirs)->prev: &(kmem_cache#5-oX (struct dentry))->d_subdirs
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->pprev: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_u.d_child)->next: &(kmem_cache#5-oX (struct dentry))->d_u.d_child
	// (&(kmem_cache#5-oX (struct dentry))->d_u.d_child)->prev: &(kmem_cache#5-oX (struct dentry))->d_u.d_child
	//
	// (kmem_cache#5-oX (struct dentry))->d_op: NULL
	//
	// [pcp0] nr_dentry: 4
	//
	// (kmem_cache#5-oX (struct dentry))->d_lockref.count: 1
	// (kmem_cache#5-oX (struct dentry))->d_parent: kmem_cache#5-oX (struct dentry)
	//
	// head list 인 &(kmem_cache#5-oX (struct dentry))->d_subdirs 에
	// list &(kmem_cache#5-oX (struct dentry))->d_u.d_child 를 추가함
	//
	// struct inode 만큼의 메모리를 할당 받음 kmem_cache#4-oX (struct inode)
	//
	// (kmem_cache#4-oX (struct inode))->i_sb: kmem_cache#25-oX (struct super_block)
	// (kmem_cache#4-oX (struct inode))->i_blkbits: 12
	// (kmem_cache#4-oX (struct inode))->i_flags: 0
	// (kmem_cache#4-oX (struct inode))->i_count: 1
	// (kmem_cache#4-oX (struct inode))->i_op: &empty_iops
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 1
	// (kmem_cache#4-oX (struct inode))->i_opflags: 0
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#4-oX (struct inode))->i_count: 0
	// (kmem_cache#4-oX (struct inode))->i_size: 0
	// (kmem_cache#4-oX (struct inode))->i_blocks: 0
	// (kmem_cache#4-oX (struct inode))->i_bytes: 0
	// (kmem_cache#4-oX (struct inode))->i_generation: 0
	// (kmem_cache#4-oX (struct inode))->i_pipe: NULL
	// (kmem_cache#4-oX (struct inode))->i_bdev: NULL
	// (kmem_cache#4-oX (struct inode))->i_cdev: NULL
	// (kmem_cache#4-oX (struct inode))->i_rdev: 0
	// (kmem_cache#4-oX (struct inode))->dirtied_when: 0
	//
	// &(kmem_cache#4-oX (struct inode))->i_lock을 이용한 spin lock 초기화 수행
	//
	// ((&(kmem_cache#4-oX (struct inode))->i_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#4-oX (struct inode))->i_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#4-oX (struct inode))->i_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#4-oX (struct inode))->i_lock)->rlock)->owner_cpu: 0xffffffff
	//
	// (&(kmem_cache#4-oX (struct inode))->i_mutex)->count: 1
	// (&(&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_list)->next: &(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_list
	// (&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_list)->prev: &(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_list
	// (&(kmem_cache#4-oX (struct inode))->i_mutex)->onwer: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_mutex)->magic: &(kmem_cache#4-oX (struct inode))->i_mutex
	//
	// (kmem_cache#4-oX (struct inode))->i_dio_count: 0
	//
	// (&(kmem_cache#4-oX (struct inode))->i_data)->a_ops: &empty_aops
	// (&(kmem_cache#4-oX (struct inode))->i_data)->host: kmem_cache#4-oX (struct inode)
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0x200DA
	// (&(kmem_cache#4-oX (struct inode))->i_data)->private_data: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_data)->backing_dev_info: &default_backing_dev_info
	// (&(kmem_cache#4-oX (struct inode))->i_data)->writeback_index: 0
	//
	// (kmem_cache#4-oX (struct inode))->i_private: NULL
	// (kmem_cache#4-oX (struct inode))->i_mapping: &(kmem_cache#4-oX (struct inode))->i_data
	// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: NULL
	// (kmem_cache#4-oX (struct inode))->i_acl: (void *)(0xFFFFFFFF),
	// (kmem_cache#4-oX (struct inode))->i_default_acl: (void *)(0xFFFFFFFF)
	// (kmem_cache#4-oX (struct inode))->i_fsnotify_mask: 0
	//
	// [pcp0] nr_inodes: 3
	//
	// (kmem_cache#4-oX (struct inode))->i_state: 0
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// (kmem_cache#4-oX (struct inode))->i_ino: 0xF0000001
	// (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_mode: 0120777
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#4-oX (struct inode))->i_op: &proc_self_inode_operations
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->next: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: &(kmem_cache#5-oX (struct dentry))->d_alias
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->pprev: &(&(kmem_cache#5-oX (struct dentry))->d_alias)
	//
	// (kmem_cache#5-oX (struct dentry))->d_inode: kmem_cache#4-oX (struct inode)
	//
	// 공유자원을 다른 cpu core가 사용할수 있게 함
	// (&(kmem_cache#5-oX (struct dentry))->d_seq)->sequence: 2
	//
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100080
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->pprev: &(hash 0xXXXXXXXX 에 맞는 list table 주소값)->first
	//
	// ((hash 0xXXXXXXXX 에 맞는 list table 주소값)->first): ((&(kmem_cache#5-oX (struct dentry))->d_hash) | 1)
	//
	// (&init_pid_ns)->proc_self: kmem_cache#5-oX (struct dentry)
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_lockref)->count: 1
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x6040080a
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0
	//
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_root: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_sb: kmem_cache#25-oX (struct super_block)
	// (kmem_cache#2-oX (struct mount))->mnt_mountpoint: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt_parent: kmem_cache#2-oX (struct mount)
	//
	// list head인 &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts에
	// &(kmem_cache#2-oX (struct mount))->mnt_instance를 tail로 연결
	//
	// (kmem_cache#2-oX (struct mount))->mnt_ns: 0xffffffea
	//
	// (&init_pid_ns)->proc_mnt: &(kmem_cache#2-oX (struct mount))->mnt
	//
	// (&(kmem_cache#19-oX (struct pid))->count)->counter: 1
	// (&(kmem_cache#19-oX (struct pid))->tasks[0...2])->first: NULL
	//
	// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->next: NULL
	// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->pprev: &(&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first
	// ((&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first): &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain
	//
	// (&init_pid_ns)->nr_hashed: 0x80000001
	//
	// (kmem_cache#15-oX (struct task_struct))->set_child_tid: NULL
	// (kmem_cache#15-oX (struct task_struct))->clear_child_tid: NULL
	// (kmem_cache#15-oX (struct task_struct))->plug: NULL
	// (kmem_cache#15-oX (struct task_struct))->robust_list: NULL
	//
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->next: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->prev: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	//
	// (kmem_cache#15-oX (struct task_struct))->pi_state_cache: NULL
	//
	// (kmem_cache#15-oX (struct task_struct))->sas_ss_sp: 0
	// (kmem_cache#15-oX (struct task_struct))->sas_ss_size: 0
	//
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 8 bit 값을 clear 수행
	//
	// (kmem_cache#15-oX (struct task_struct))->pid: 1
	// (kmem_cache#15-oX (struct task_struct))->exit_signal: 0
	// (kmem_cache#15-oX (struct task_struct))->group_leader: kmem_cache#15-oX (struct task_struct)
	// (kmem_cache#15-oX (struct task_struct))->tgid: 1
	//
	// (kmem_cache#15-oX (struct task_struct))->pdeath_signal: 0
	// (kmem_cache#15-oX (struct task_struct))->exit_state: 0
	// (kmem_cache#15-oX (struct task_struct))->nr_dirtied: 0
	// (kmem_cache#15-oX (struct task_struct))->nr_dirtied_pause: 32
	// (kmem_cache#15-oX (struct task_struct))->dirty_paused_when: 0
	//
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->next: &(kmem_cache#15-oX (struct task_struct))->thread_group
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->prev: &(kmem_cache#15-oX (struct task_struct))->thread_group
	//
	// (kmem_cache#15-oX (struct task_struct))->task_works: NULL
	//
	// (kmem_cache#15-oX (struct task_struct))->real_parent: &init_task
	// (kmem_cache#15-oX (struct task_struct))->parent_exec_id: 0
	//
	// (init_task의 struct thread_info 주소값)->flags 의 0 bit 값을 clear 수행
	//
	// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->next: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
	// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
	// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->next: &(kmem_cache#15-oX (struct task_struct))->ptraced
	// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->prev: &(kmem_cache#15-oX (struct task_struct))->ptraced
	// (kmem_cache#15-oX (struct task_struct))->jobctl: 0
	// (kmem_cache#15-oX (struct task_struct))->ptrace: 0
	// (kmem_cache#15-oX (struct task_struct))->parent: &init_task
	//
	// (kmem_cache#15-oX (struct task_struct))->pids[0].pid: kmem_cache#19-oX (struct pid)
	//
	// (kmem_cache#15-oX (struct task_struct))->pids[1].pid: &init_struct_pid
	// (kmem_cache#15-oX (struct task_struct))->pids[2].pid: &init_struct_pid
	//
	// (kmem_cache#13-oX (struct signal_struct))->flags: 0x00000040
	// (kmem_cache#13-oX (struct signal_struct))->leader_pid: kmem_cache#19-oX (struct pid)
	// (kmem_cache#13-oX (struct signal_struct))->tty: NULL
	//
	// list head 인 &(&init_task)->children 에 &(kmem_cache#15-oX (struct task_struct))->sibling 을 tail에 연결
	//
	// (&(kmem_cache#15-oX (struct task_struct))->tasks)->next: &init_task.tasks
	// (&(kmem_cache#15-oX (struct task_struct))->tasks)->prev: (&init_task.tasks)->prev
	//
	// core간 write memory barrier 수행
	// ((*((struct list_head __rcu **) (&((&init_task.tasks)->prev)->next)))):
	// (typeof(*&(kmem_cache#15-oX (struct task_struct))->tasks) __force __rcu *)(&(kmem_cache#15-oX (struct task_struct))->tasks);
	//
	// (&init_task.tasks)->prev: &(kmem_cache#15-oX (struct task_struct))->tasks
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->pprev: &(&(&init_struct_pid)->tasks[1])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[1])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->pprev: &(&(&init_struct_pid)->tasks[2])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[2])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node
	//
	// [pcp0] process_counts: 1 로 증가시킴
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->pprev: &(&(kmem_cache#19-oX (struct pid))->tasks[0])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(kmem_cache#19-oX (struct pid))->tasks[0])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node
	//
	// nr_threads: 1
	//
	// total_forks: 1
	//
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	//
	// (kmem_cache#15-oX (struct task_struct))->se.avg.decay_count: 0
	// (kmem_cache#15-oX (struct task_struct))->se.avg.runnable_avg_sum: 현재 task의 남아 있는 수행 시간량 / 1024
	// (kmem_cache#15-oX (struct task_struct))->se.avg.runnable_avg_period: 현재 task의 남아 있는 수행 시간량 / 1024
	// (&(kmem_cache#15-oX (struct task_struct))->se)->avg.load_avg_contrib:
	// 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
	//
	// [pcp0] (&runqueues)->clock: 현재의 schedule 시간값
	// [pcp0] (&runqueues)->clock_task: 현재의 schedule 시간값
	//
	// (&(kmem_cache#15-oX (struct task_struct))->se)->vruntime: 0x4B8D7E
	//
	// (&(kmem_cache#15-oX (struct task_struct))->se)->avg.last_runnable_update: 현재의 schedule 시간값
	// [pcp0] (&(&runqueues)->cfs)->runnable_load_avg: 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
	//
	// decays: 현재의 schedule 시간값>> 20 값이 0이 아닌 상수 값이라 가정하고 분석 진행
	//
	// [pcp0] (&(&runqueues)->cfs)->blocked_load_avg: 0
	// [pcp0] (&(&(&runqueues)->cfs)->decay_counter)->counter: 2
	// [pcp0] (&(&runqueues)->cfs)->last_decay: 현재의 schedule 시간값>> 20
	//
	// (&(&root_task_group)->load_avg)->counter: 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
	// [pcp0] (&(&runqueues)->cfs)->tg_load_contrib: 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
	//
	// [pcp0] (&(&(&runqueues)->cfs)->load)->weight: 2048
	// [pcp0] (&(&(&runqueues)->cfs)->load)->inv_weight: 0
	// [pcp0] (&(&runqueues)->load)->weight: 1024
	// [pcp0] (&(&runqueues)->load)->inv_weight: 0
	// [pcp0] &(&runqueues)->cfs_tasks 란 list head에 &(&(kmem_cache#15-oX (struct task_struct))->se)->group_node 를 추가함
	// [pcp0] (&(&runqueues)->cfs)->nr_running: 1
	//
	// [pcp0] (&(&runqueues)->cfs)->rb_leftmost: &(&(kmem_cache#15-oX (struct task_struct))->se)->run_node
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->run_node)->__rb_parent_color: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->run_node)->rb_left: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->run_node)->rb_right: NULL
	// [pcp0] (&(&runqueues)->cfs)->tasks_timeline.rb_node: &(&(kmem_cache#15-oX (struct task_struct))->se)->run_node
	//
	/*
	// rb tree 의 root인 [pcp0] &(&(&runqueues)->cfs)->tasks_timeline 에
	// rb node인 &(&(kmem_cache#15-oX (struct task_struct))->se)->run_node 가 추가되어 rb tree 구성
	//
	//                            task ID: 1-b
	//                            /           \
	*/
	// (&(kmem_cache#15-oX (struct task_struct))->se)->on_rq: 1
	//
	// list head인 [pcp0] &(&runqueues)->leaf_cfs_rq_list에 [pcp0] &(&(&runqueues)->cfs)->leaf_cfs_rq_list 을 tail에 추가함
	//
	// [pcp0] (&(&(&runqueues)->cfs)->leaf_cfs_rq_list)->next: [pcp0] &(&runqueues)->leaf_cfs_rq_list
	// [pcp0] (&(&(&runqueues)->cfs)->leaf_cfs_rq_list)->prev: [pcp0] (&(&runqueues)->leaf_cfs_rq_list)->prev
	//
	// core간 write memory barrier 수행
	// ((*((struct list_head __rcu **) (&(([pcp0] &(&runqueues)->leaf_cfs_rq_list)->prev)->next)))):
	// (typeof(*[pcp0] &(&(&runqueues)->cfs)->leaf_cfs_rq_list) __force __rcu *)([pcp0] &(&(&runqueues)->cfs)->leaf_cfs_rq_list);
	//
	// [pcp0] (&(&runqueues)->leaf_cfs_rq_list)->prev: [pcp0] &(&(&runqueues)->cfs)->leaf_cfs_rq_list
	//
	// [pcp0] (&(&runqueues)->cfs)->on_list: 1
	//
	// [pcp0] (&(&runqueues)->cfs)->blocked_load_avg: 0
	// (&(&(&runqueues)->cfs)->decay_counter)->counter: 현재의 schedule 시간값>> 20 + 1 + 시간값x
	// [pcp0] (&(&runqueues)->cfs)->last_decay: 현재의 schedule 시간값 + 시간값x >> 20
	//
	// [pcp0] (&(&runqueues)->cfs)->h_nr_running: 2
	//
	// delta: 현재의 schedule 시간 변화값은 signed 로 변경시 0 보다 큰 값으로 가정하고 코드 분석 진행
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->avg)->last_runnable_update: 현재의 schedule 시간값
	//
	// delta + delta_w 값이 1024 보다 작은 값이라고 가정하고 코드 분석 진행
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->avg)->runnable_avg_sum:
	// 현재 task의 남아 있는 수행 시간량 / 1024 + 현재의 schedule 시간 변화값
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->avg)->runnable_avg_period:
	// 현재 task의 남아 있는 수행 시간량 / 1024 + 현재의 schedule 시간 변화값
	//
	// (kmem_cache#15-oX (struct task_struct))->on_rq: 1

	numa_default_policy(); // null function

	// CLONE_FS: 0x00000200, CLONE_FILES: 0x00000400
	// kernel_thread(kthreadd, NULL, 0x00000600): 2
	pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
	// pid: 2

	// kernel_thread 에서 한일:
	// struct task_struct 만큼의 메모리를 할당 받음
	// kmem_cache#15-oX (struct task_struct)
	//
	// struct thread_info 를 구성 하기 위한 메모리를 할당 받음 (8K)
	// 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 메모리에 init_task 값을 전부 할당함
	//
	// (kmem_cache#15-oX (struct task_struct))->stack: 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 의 stack의 값을 init_task 의 stack 값에서 전부 복사함
	// 복사된 struct thread_info 의 task 주소값을 할당 받은 kmem_cache#15-oX (struct task_struct)로 변경함
	// *(할당 받은 page 2개의 메로리의 가상 주소): init_thread_info
	// ((struct thread_info *) 할당 받은 page 2개의 메로리의 가상 주소)->task: kmem_cache#15-oX (struct task_struct)
	//
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 1 bit 값을 clear 수행
	//
	// *((unsigned long *)(할당 받은 page 2개의 메로리의 가상 주소 + 1)): 0x57AC6E9D
	//
	// (&(kmem_cache#15-oX (struct task_struct))->usage)->counter: 2
	// (kmem_cache#15-oX (struct task_struct))->splice_pipe: NULL
	// (kmem_cache#15-oX (struct task_struct))->task_frag.page: NULL
	//
	// (&contig_page_data)->node_zones[0].vm_stat[16]: 1 을 더함
	// vmstat.c의 vm_stat[16] 전역 변수에도 1을 더함
	//
	// &(kmem_cache#15-oX (struct task_struct))->pi_lock을 사용한 spinlock 초기화
	// &(kmem_cache#15-oX (struct task_struct))->pi_waiters 리스트 초기화
	// (kmem_cache#15-oX (struct task_struct))->pi_blocked_on: NULL
	//
	// (&init_task)->flags: 0x00200100
	//
	// struct cred 만큼의 메모리를 할당 받음
	// kmem_cache#16-oX (struct cred)
	//
	// kmem_cache#16-oX (struct cred) 에 init_cred 에 있는 맴버값 전부를 복사함
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 1
	// (&(&init_groups)->usage)->counter: 4
	// (&(&root_user)->__count)->counter: 3
	//
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 2
	//
	// (kmem_cache#15-oX (struct task_struct))->cred: kmem_cache#16-oX (struct cred)
	// (kmem_cache#15-oX (struct task_struct))->real_cred: kmem_cache#16-oX (struct cred)
	// (kmem_cache#15-oX (struct task_struct))->did_exec: 0
	// (kmem_cache#15-oX (struct task_struct))->flags: 0x00200040
	//
	// (&(kmem_cache#15-oX (struct task_struct))->children)->next: &(kmem_cache#15-oX (struct task_struct))->children
	// (&(kmem_cache#15-oX (struct task_struct))->children)->prev: &(kmem_cache#15-oX (struct task_struct))->children
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->next: &(kmem_cache#15-oX (struct task_struct))->sibling
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->prev: &(kmem_cache#15-oX (struct task_struct))->sibling
	//
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_lock_nesting: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_unlock_special: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_blocked_node: NULL
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->next: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry
	//
	// (kmem_cache#15-oX (struct task_struct))->vfork_done: NULL
	//
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->magic: 0xdead4ead
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner: 0xffffffff
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner_cpu: 0xffffffff
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list
	//
	// (kmem_cache#15-oX (struct task_struct))->utime: 0
	// (kmem_cache#15-oX (struct task_struct))->stime: 0
	// (kmem_cache#15-oX (struct task_struct))->gtime: 0
	// (kmem_cache#15-oX (struct task_struct))->utimescaled: 0
	// (kmem_cache#15-oX (struct task_struct))->stimescaled: 0
	//
	// &(kmem_cache#15-oX (struct task_struct))->rss_stat 값을 0 으로 초기화 수행
	//
	// (kmem_cache#15-oX (struct task_struct))->default_timer_slack_ns: 50000
	//
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.prof_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.virt_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.sched_exp: 0
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	//
	// (kmem_cache#15-oX (struct task_struct))->start_time 에 현재 시간 값을 가져옴
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_sec: normalized 된 sec 값
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_nsec: normalized 된 nsec 값
	//
	// (kmem_cache#15-oX (struct task_struct))->io_context: NULL
	// (kmem_cache#15-oX (struct task_struct))->audit_context: NULL
	//
	// rcu reference의 값 (&init_task)->cgroups 이 유요한지 체크하고 그 값을 리턴함
	// ((&init_task)->cgroups)->refcount: 1
	// (kmem_cache#15-oX (struct task_struct))->cgroups: (&init_task)->cgroups
	//
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->next: &(kmem_cache#15-oX (struct task_struct))->cg_list
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->prev: &(kmem_cache#15-oX (struct task_struct))->cg_list
	//
	// (kmem_cache#15-oX (struct task_struct))->blocked_on: NULL
	//
	// (&kmem_cache#15-oX (struct task_struct))->on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.exec_start: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.prev_sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.nr_migrations: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.vruntime: 0
	// &(&kmem_cache#15-oX (struct task_struct))->se.group_node의 리스트 초기화
	// &(&kmem_cache#15-oX (struct task_struct))->rt.run_list의 리스트 초기화
	//
	// (kmem_cache#15-oX (struct task_struct))->state: 0
	// (kmem_cache#15-oX (struct task_struct))->prio: 120
	// (kmem_cache#15-oX (struct task_struct))->sched_class: &fair_sched_class
	//
	// 현재의 schedule 시간값과 기존의 (&runqueues)->clock 의 값의 차이값을
	// [pcp0] (&runqueues)->clock, [pcp0] (&runqueues)->clock_task 의 값에 더해 갱신함
	//
	// [pcp0] (&runqueues)->clock: schedule 시간 차이값
	// [pcp0] (&runqueues)->clock_task: schedule 시간 차이값
	//
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (&(kmem_cache#15-oX (struct task_struct))->se)->vruntime: 0x5B8D7E
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->on_cpu: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->preempt_count: 1
	// (&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio: 140
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list
	//
	// (kmem_cache#15-oX (struct task_struct))->sysvsem.undo_list: NULL
	//
	// files_cachep: kmem_cache#12 을 사용하여 struct files_struct 을 위한 메모리를 할당함
	// kmem_cache#12-oX (struct files_struct)
	//
	// (kmem_cache#12-oX (struct files_struct))->count: 1
	//
	// &(kmem_cache#12-oX (struct files_struct))->file_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->owner_cpu: 0xffffffff
	//
	// (kmem_cache#12-oX (struct files_struct))->next_fd: 0
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->max_fds: 32
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->close_on_exec: (kmem_cache#12-oX (struct files_struct))->close_on_exec_init
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->open_fds: (kmem_cache#12-oX (struct files_struct))->open_fds_init
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->fd: &(kmem_cache#12-oX (struct files_struct))->fd_array[0]
	//
	// &(&init_files)->file_lock 을 사용하여 spin lock 수행
	//
	// (kmem_cache#12-oX (struct files_struct))->open_fds_init 에 init_files.open_fds_init 값을 복사
	// (kmem_cache#12-oX (struct files_struct))->open_fds_init: NULL
	// (kmem_cache#12-oX (struct files_struct))->close_on_exec_init 에 init_files.close_on_exec_init 값을 복사
	// (kmem_cache#12-oX (struct files_struct))->close_on_exec_init: NULL
	//
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->open_fds 의 0~31 bit 를 clear 함
	// (kmem_cache#12-oX (struct files_struct))->fd_array[0...31]: NULL
	// &(kmem_cache#12-oX (struct files_struct))->fd_array[0] 에 값을 size 0 만큼 0 으로 set 함
	//
	// (kmem_cache#12-oX (struct files_struct))->fdt: &(kmem_cache#12-oX (struct files_struct))->fdtab
	//
	// (kmem_cache#15-oX (struct task_struct))->files: kmem_cache#12-oX (struct files_struct)
	//
	// (&init_fs)->users: 2
	//
	// (&init_sighand)->count: { (2) }
	//
	// struct signal_struct 크기 만큼의 메모리를 할당함
	// kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#15-oX (struct task_struct))->signal: kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#13-oX (struct signal_struct))->nr_threads: 1
	// (kmem_cache#13-oX (struct signal_struct))->live: { (1) }
	// (kmem_cache#13-oX (struct signal_struct))->sigcnt: { (1) }
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->task_list를 사용한 list 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->curr_target: kmem_cache#15-oX (struct task_struct)
	//
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->next: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->prev: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer의 값을 0으로 초기화
	// (&(kmem_cache#13-oX (struct signal_struct))->real_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// RB Tree의 &(&(kmem_cache#13-oX (struct signal_struct))->real_timer)->node 를 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer.function: it_real_fn
	// (kmem_cache#13-oX (struct signal_struct))->rlim 에 (&init_signals)->rlim 값을 전부 복사함
	// &(kmem_cache#13-oX (struct signal_struct))->cputimer.lock 을 사용한 spinlock 초기화 수행
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->activity: 0
	// &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_lock을 사용한 spinlock 초기화
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj: 0
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj_min: 0
	// (kmem_cache#13-oX (struct signal_struct))->has_child_subreaper: 0
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->count: 1
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->onwer: NULL
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->magic: &(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex
	//
	// (kmem_cache#15-oX (struct task_struct))->min_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->maj_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->nvcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->nivcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->last_switch_count: 0
	// (kmem_cache#15-oX (struct task_struct))->mm: NULL
	//
	// (&init_nsproxy)->count: { (2) }
	//
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context 의 값을 0으로 초기화 함
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183) 의 값을 0으로 초기화 함
	//
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r4: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r5: kernel_init
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)->uregs[16]: 0x00000013
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.pc: ret_from_fork
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.sp: ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->tp_value[1]: TPIDRURW의 읽은 값
	//
	// struct pid 만큼의 메모리를 할당 받음
	// kmem_cache#19-oX (struct pid)
	//
	// (kmem_cache#19-oX (struct pid))->level: 0
	//
	// 기존에 할당받은 pidmap의 메모리 값
	// (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX
	// kmem_cache#25-oX 의 2 bit 의 값을 1 으로 set
	// (&(&init_pid_ns)->pidmap[0])->nr_free: { (0x7FFE) }
	// &(&init_pid_ns)->last_pid 을 2 로 변경함
	//
	// (kmem_cache#19-oX (struct pid))->numbers[0].nr: 2
	// (kmem_cache#19-oX (struct pid))->numbers[0].ns: &init_pid_ns
	//
	// (&(kmem_cache#19-oX (struct pid))->count)->counter: 1
	//
	// (&(kmem_cache#19-oX (struct pid))->tasks[0...2])->first: NULL
	//
	// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->next: NULL
	// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->pprev: &(&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first
	// ((&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first): &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain
	//
	// (&init_pid_ns)->nr_hashed: 0x80000002
	//
	// (kmem_cache#15-oX (struct task_struct))->set_child_tid: NULL
	// (kmem_cache#15-oX (struct task_struct))->clear_child_tid: NULL
	// (kmem_cache#15-oX (struct task_struct))->plug: NULL
	// (kmem_cache#15-oX (struct task_struct))->robust_list: NULL
	//
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->next: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->prev: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	//
	// (kmem_cache#15-oX (struct task_struct))->pi_state_cache: NULL
	//
	// (kmem_cache#15-oX (struct task_struct))->sas_ss_sp: 0
	// (kmem_cache#15-oX (struct task_struct))->sas_ss_size: 0
	//
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 8 bit 값을 clear 수행
	//
	// (kmem_cache#15-oX (struct task_struct))->pid: 2
	// (kmem_cache#15-oX (struct task_struct))->exit_signal: 0
	// (kmem_cache#15-oX (struct task_struct))->group_leader: kmem_cache#15-oX (struct task_struct)
	// (kmem_cache#15-oX (struct task_struct))->tgid: 2
	//
	// (kmem_cache#15-oX (struct task_struct))->pdeath_signal: 0
	// (kmem_cache#15-oX (struct task_struct))->exit_state: 0
	// (kmem_cache#15-oX (struct task_struct))->nr_dirtied: 0
	// (kmem_cache#15-oX (struct task_struct))->nr_dirtied_pause: 32
	// (kmem_cache#15-oX (struct task_struct))->dirty_paused_when: 0
	//
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->next: &(kmem_cache#15-oX (struct task_struct))->thread_group
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->prev: &(kmem_cache#15-oX (struct task_struct))->thread_group
	//
	// (kmem_cache#15-oX (struct task_struct))->task_works: NULL
	//
	// (kmem_cache#15-oX (struct task_struct))->real_parent: &init_task
	// (kmem_cache#15-oX (struct task_struct))->parent_exec_id: 0
	//
	// (init_task의 struct thread_info 주소값)->flags 의 0 bit 값을 clear 수행
	//
	// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->next: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
	// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
	// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->next: &(kmem_cache#15-oX (struct task_struct))->ptraced
	// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->prev: &(kmem_cache#15-oX (struct task_struct))->ptraced
	// (kmem_cache#15-oX (struct task_struct))->jobctl: 0
	// (kmem_cache#15-oX (struct task_struct))->ptrace: 0
	// (kmem_cache#15-oX (struct task_struct))->parent: &init_task
	//
	// (kmem_cache#15-oX (struct task_struct))->pids[0].pid: kmem_cache#19-oX (struct pid)
	//
	// (kmem_cache#15-oX (struct task_struct))->pids[1].pid: &init_struct_pid
	// (kmem_cache#15-oX (struct task_struct))->pids[2].pid: &init_struct_pid
	//
	// (kmem_cache#13-oX (struct signal_struct))->flags: 0x00000040
	// (kmem_cache#13-oX (struct signal_struct))->leader_pid: kmem_cache#19-oX (struct pid)
	// (kmem_cache#13-oX (struct signal_struct))->tty: NULL
	//
	// list head 인 &(&init_task)->children 에 &(kmem_cache#15-oX (struct task_struct))->sibling 을 tail에 연결
	//
	// (&(kmem_cache#15-oX (struct task_struct))->tasks)->next: &init_task.tasks
	// (&(kmem_cache#15-oX (struct task_struct))->tasks)->prev: (&init_task.tasks)->prev
	//
	// core간 write memory barrier 수행
	// ((*((struct list_head __rcu **) (&((&init_task.tasks)->prev)->next)))):
	// (typeof(*&(kmem_cache#15-oX (struct task_struct))->tasks) __force __rcu *)(&(kmem_cache#15-oX (struct task_struct))->tasks);
	//
	// (&init_task.tasks)->prev: &(kmem_cache#15-oX (struct task_struct))->tasks
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->pprev: &(&(&init_struct_pid)->tasks[1])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[1])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->pprev: &(&(&init_struct_pid)->tasks[2])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[2])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node
	//
	// [pcp0] process_counts: 1 로 증가시킴
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->pprev: &(&(kmem_cache#19-oX (struct pid))->tasks[0])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(kmem_cache#19-oX (struct pid))->tasks[0])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node
	//
	// nr_threads: 2
	//
	// total_forks: 2
	//
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	//
	// (kmem_cache#15-oX (struct task_struct))->se.avg.decay_count: 0
	// (kmem_cache#15-oX (struct task_struct))->se.avg.runnable_avg_sum: 현재 task의 남아 있는 수행 시간량 / 1024
	// (kmem_cache#15-oX (struct task_struct))->se.avg.runnable_avg_period: 현재 task의 남아 있는 수행 시간량 / 1024
	// (&(kmem_cache#15-oX (struct task_struct))->se)->avg.load_avg_contrib:
	// 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
	//
	// [pcp0] (&runqueues)->clock: 현재의 schedule 시간값
	// [pcp0] (&runqueues)->clock_task: 현재의 schedule 시간값
	//
	// (&(kmem_cache#15-oX (struct task_struct))->se)->vruntime: 0x4B8D7E
	//
	// (&(kmem_cache#15-oX (struct task_struct))->se)->avg.last_runnable_update: 현재의 schedule 시간값
	// [pcp0] (&(&runqueues)->cfs)->runnable_load_avg: 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
	//
	// decays: 현재의 schedule 시간값>> 20 값이 0이 아닌 상수 값이라 가정하고 분석 진행
	//
	// [pcp0] (&(&runqueues)->cfs)->blocked_load_avg: 0
	// [pcp0] (&(&(&runqueues)->cfs)->decay_counter)->counter: 2
	// [pcp0] (&(&runqueues)->cfs)->last_decay: 현재의 schedule 시간값>> 20
	//
	// (&(&root_task_group)->load_avg)->counter: 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
	// [pcp0] (&(&runqueues)->cfs)->tg_load_contrib: 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
	//
	// [pcp0] (&(&(&runqueues)->cfs)->load)->weight: 2048
	// [pcp0] (&(&(&runqueues)->cfs)->load)->inv_weight: 0
	// [pcp0] (&(&runqueues)->load)->weight: 1024
	// [pcp0] (&(&runqueues)->load)->inv_weight: 0
	// [pcp0] &(&runqueues)->cfs_tasks 란 list head에 &(&(kmem_cache#15-oX (struct task_struct))->se)->group_node 를 추가함 (pid 2)
	// [pcp0] (&(&runqueues)->cfs)->nr_running: 2
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->run_node (pid 2))->__rb_parent_color: &(&(kmem_cache#15-oX (struct task_struct))->se)->run_node (pid 1)
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->run_node (pid 2))->rb_left: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->run_node (pid 2))->rb_right: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->run_node (pid 1))->rb_right: &(&(kmem_cache#15-oX (struct task_struct))->se)->run_node (pid 2)
	/*
	// rb tree 의 root인 [pcp0] &(&(&runqueues)->cfs)->tasks_timeline 에
	// rb node인 &se->run_node: &(&(kmem_cache#15-oX (struct task_struct))->se)->run_node (pid 2) 가 추가되어 rb tree 구성
	//
	//                            task ID: 1-b
	//                            /           \
	//                                   task ID: 2-r
	*/
	// (&(kmem_cache#15-oX (struct task_struct))->se)->on_rq: 1
	//
	// [pcp0] (&(&runqueues)->cfs)->h_nr_running: 4
	//
	// delta: 현재의 schedule 시간 변화값은 signed 로 변경시 0 보다 큰 값으로 가정하고 코드 분석 진행
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->avg)->last_runnable_update: 현재의 schedule 시간값
	//
	// delta + delta_w 값이 1024 보다 작은 값이라고 가정하고 코드 분석 진행
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->avg)->runnable_avg_sum:
	// 현재 task의 남아 있는 수행 시간량 / 1024 + 현재의 schedule 시간 변화값
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->avg)->runnable_avg_period:
	// 현재 task의 남아 있는 수행 시간량 / 1024 + 현재의 schedule 시간 변화값
	//
	// (kmem_cache#15-oX (struct task_struct))->on_rq: 1

	rcu_read_lock();

	// rcu_read_lock 에서 한일:
	// (&init_task)->rcu_read_lock_nesting: 1

	// pid: 2, find_task_by_pid_ns(2, &init_pid_ns): kmem_cache#15-oX (struct task_struct) (pid 2)
	kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
	// kthreadd_task: kmem_cache#15-oX (struct task_struct) (pid 2)

	// find_task_by_pid_ns 에서 한일:
	// pid 값을 이용하여 pid 를 사용하는 task의 메모리 주소를 가져옴

	rcu_read_unlock();

	// rcu_read_unlock에서 한일:
	// (&init_task)->rcu_read_lock_nesting: 0

	complete(&kthreadd_done);

	// complete 에서 한일:
	// (&kthreadd_done)->done: 1

	/*
	 * The boot idle thread must execute schedule()
	 * at least once to get things moving:
	 */
	// current: &init_task
	init_idle_bootup_task(current);

	// init_idle_bootup_task 에 한일:
	// (&init_task)->sched_class: &idle_sched_class

// 2017/07/01 종료

	schedule_preempt_disabled();
	/* Call into cpu_idle with preempt disabled */
	cpu_startup_entry(CPUHP_ONLINE);
}

/* Check for early params. */
// ARM10C 20131019
// param: "console", val: "ttySAC2,115200", doing: "early options"
static int __init do_early_param(char *param, char *val, const char *unused)
{
	const struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		// param: "console"
		if ((p->early && parameq(param, p->str)) ||
		    (strcmp(param, "console") == 0 &&
		     strcmp(p->str, "earlycon") == 0)
		) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	// 위 loop 수행 결과 만족하는 조건이 없음

	/* We accept everything at this stage. */
	return 0;
	// return 0
}

// ARM10C 20131019
// ARM10C 20140322
// tmp_cmdline: "console=ttySAC2,115200 init=/linuxrc"
void __init parse_early_options(char *cmdline)
{
	// cmdline: "console=ttySAC2,115200 init=/linuxrc"
	parse_args("early options", cmdline, NULL, 0, 0, 0, do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
// ARM10C 20131019
// ARM10C 20140322
void __init parse_early_param(void)
{
	static __initdata int done = 0;
	static __initdata char tmp_cmdline[COMMAND_LINE_SIZE];

	// done: 0
	if (done)
		return;

	/* All fall through to do_early_param. */
	// boot_command_line: "console=ttySAC2,115200 init=/linuxrc", COMMAND_LINE_SIZE: 1024
	strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	// tmp_cmdline: "console=ttySAC2,115200 init=/linuxrc"

	parse_early_options(tmp_cmdline);

	// done: 0
	done = 1;
	// done: 1
}

/*
 *	Activate the first processor.
 */

// ARM10C 20130907
// 현재 cpu(core id)를 얻어서 cpu_XXX_bits[] 의 cpu를 셋한다.
//
// 참조 : http://cafe.daum.net/lksas/8HoZ/42?docid=1K80b8HoZ4220110218025952
// 시스템 상에 존재하는 CPU의 상태 정보는 다음과 같은 4개의 비트맵 (cpumask_t)으로 관리한다.
// cpu_possible_mask - 해당 비트에 대한 CPU가 존재할 수 있다.
// cpu_present_mask - 해당 비트에 대한 CPU가 존재한다.
// cpu_online_mask - 해당 비트에 대한 CPU가 존재하며 스케줄러가 이를 관리한다.
// cpu_active_mask - 해당 비트에 대한 CPU가 존재하며 task migration 시 이를 이용할 수 있다.
static void __init boot_cpu_init(void)
{
	int cpu = smp_processor_id();	// ARM10C FIXME cpu = 0 일 가능성이 큼 
	/* Mark the boot cpu "present", "online" etc for SMP and UP case */
	set_cpu_online(cpu, true);
	set_cpu_active(cpu, true);
	set_cpu_present(cpu, true);
	set_cpu_possible(cpu, true);
}

// ARM10C 20130824
// weak 정의: gcc 메뉴얼 일부 참조
// weak
// The weak attribute causes the declaration to be emitted as a weak symbol rather than a global. 
// This is primarily useful in defining library functions which can be overridden in user code, 
// though it can also be used with non-function declarations. 
// Weak symbols are supported for ELF targets, 
// and also for a.out targets when using the GNU assembler and linker. 
void __init __weak smp_setup_processor_id(void)
{
}

# if THREAD_SIZE >= PAGE_SIZE // THREAD_SIZE: 8192, PAGE_SIZE: 0x1000
// ARM10C 20150919
void __init __weak thread_info_cache_init(void)
{
}
#endif

/*
 * Set up kernel memory allocators
 */
// ARM10C 20140329
static void __init mm_init(void)
{
	/*
	 * page_cgroup requires contiguous pages,
	 * bigger than MAX_ORDER unless SPARSEMEM.
	 */
	page_cgroup_init_flatmem(); // null function
	mem_init();
	// bootmem으로 관리하던 메모리를 buddy로 이관.
	// 각 section 메모리 크기를 출력.
	
	// mm/Makefile 에서 CONFIG_SLUB 설정으로 slub.c 로 jump
	kmem_cache_init();
	// slub 을 활성화 시킴
	
	percpu_init_late();
	// dchunk로 할당 받은 pcpu 메모리 값들을 slab으로 카피하여 이관

	pgtable_cache_init(); // null function

// 2014/07/26 종료
// 2014/08/09 시작

	vmalloc_init();
	// vmlist에 등록된 vm struct 들을 slab으로 이관하고 RB Tree로 구성
	/*
	// 가상주소 va_start 기준으로 RB Tree 구성한 결과
	//
	//                          CHID-b
	//                       (0xF8000000)
	//                      /            \
	//                 TMR-r               PMU-r
	//            (0xF6300000)             (0xF8180000)
	//              /      \               /           \
	//         SYSC-b      WDT-b         CMU-b         SRAM-b
	//    (0xF6100000)   (0xF6400000)  (0xF8100000)   (0xF8400000)
	//                                                       \
	//                                                        ROMC-r
	//                                                        (0xF84C0000)
	*/
}

// ARM10C 20130824
// asmlinkage의 의미
// http://www.spinics.net/lists/arm-kernel/msg87677.html
asmlinkage void __init start_kernel(void)
{
	char * command_line;
	extern const struct kernel_param __start___param[], __stop___param[];
	// ATAG,DTB 정보로 사용

	/*
	 * Need to run as early as possible, to initialize the
	 * lockdep hash:
	 */
	lockdep_init();
	smp_setup_processor_id();
	debug_objects_early_init();

	/*
	 * Set up the the initial canary ASAP:
	 */
	boot_init_stack_canary();

	cgroup_init_early();
	// cgroup 를 사용하기 위한 cgroup_dummy_root, cgroup_subsys 의 구조체 초기화 수행

	local_irq_disable();
	// IRQ를 disable 함

	early_boot_irqs_disabled = true;
	// early_boot_irqs_disabled: true

/*
 * Interrupts are still disabled. Do necessary setups, then
 * enable them
 */
	boot_cpu_init();
	// 현재 cpu(core id)를 얻어서 cpu_XXX_bits[] 의 cpu를 셋한다.

// 2013/09/07 종료
// 2013/09/14 시작
	
	page_address_init();
	// 128개의 page_address_htable 배열을 초기화

	pr_notice("%s", linux_banner);
	// 배너:
	//	Linux version 2.6.37_DM385_IPNC_3.50.00
	// 	(a0875405@bangvideoapps01) (gcc version 4.5.3 20110311
	// 	(prerelease) (GCC) ) #1 Fri Dec 21 17:27:08 IST 2012

	setup_arch(&command_line);

// 2014/02/15 종료
// 2014/02/22 시작

	mm_init_owner(&init_mm, &init_task); // null function
	mm_init_cpumask(&init_mm); // null function

	// command_line: exynos5420-smdk5420.dts 파일의 chosen node 의 bootarg 값
	// "console=ttySAC2,115200 init=/linuxrc"
	setup_command_line(command_line);
	// saved_command_line 및 static_command_line 할당

	setup_nr_cpu_ids();
	setup_per_cpu_areas();
	// pcpu 구조체를 만들어 줌 (mm/percpu.c)

	smp_prepare_boot_cpu();	/* arch-specific boot-cpu hooks */
	// boot cpu 0의 pcpu 영역의 base주소를 core register에 설정해줌

	build_all_zonelists(NULL, NULL);

// 2014/03/08 종료
// 2014/03/15 시작

	page_alloc_init();
	// cpu_chain에 page_alloc_cpu_notify를 연결함 (mutex lock/unlock 사용)

	// boot_command_line: "console=ttySAC2,115200 init=/linuxrc"
	pr_notice("Kernel command line: %s\n", boot_command_line);
	// "Kernel command line: console=ttySAC2,115200 init=/linuxrc"

	parse_early_param();
	// setup_arch에서 수행했던 작업 다시 수행
	// command arg에서 각 요소들을 파싱하여 early init section으로 설정된 디바이스 초기화.
	// 우리는 serial device가 검색이 되지만 config설정은 없어서 아무것도 안함.

	// static_command_line: "console=ttySAC2,115200 init=/linuxrc"
	parse_args("Booting kernel", static_command_line, __start___param,
		   __stop___param - __start___param,
		   -1, -1, &unknown_bootoption);
	// DTB에서 넘어온 bootargs를 파싱하여 param, val을 뽑아내고 그에 대응되는
	// kernel_param 구조체에 값을 등록함.

	jump_label_init();
	// HAVE_JUMP_LABEL 이 undefined 이므로 NULL 함수

	/*
	 * These use large bootmem allocations and must precede
	 * kmem_cache_init()
	 */
	setup_log_buf(0);
	// defalut log_buf의 크기는 __LOG_BUF_LEN: 0x20000 (128KB) 임
	// early_param 에서 호출했던 log_buf_len 값이 있다면 log_buf의 크기를 넘어온 크기로 만듬

	pidhash_init();
	// pidhash의 크기를 16kB만큼 할당 받고 4096개의 hash list를 만듬

	vfs_caches_init_early();
	// Dentry cache, Inode-cache용 hash를 위한 메모리 공간을 각각 512kB, 256kB만큼 할당 받고,
	// 131072, 65536개 만큼 hash table을 각각 만듬

// 2014/03/22 종료
// 2014/03/29 시작

	sort_main_extable();
	// extable 을 cmp_ex를 이용하여 sort수행

	trap_init(); // null function

	mm_init();
	// buddy와 slab 을 활성화 하고 기존 할당 받은 bootmem 은 buddy,
	// pcpu 메모리, vmlist 는 slab으로 이관

// 2014/08/09 종료
// 2014/08/30 시작

	/*
	 * Set up the scheduler prior starting any interrupts (such as the
	 * timer interrupt). Full topology setup happens at smp_init()
	 * time - but meanwhile we still have a functioning scheduler.
	 */
	sched_init();
	// scheduler가 사용하는 자료 구조 초기화, idle_threads를 init_task로 세팅

	/*
	 * Disable preemption - early bootup scheduling is extremely
	 * fragile until we cpu_idle() for the first time.
	 */
	preempt_disable();
	// preempt count를 증가시켜 preemption 못하도록 막음

	// irqs_disabled(): 1
	if (WARN(!irqs_disabled(), "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();

	idr_init_cache();
	// integer ID management로 사용하는 idr_layer_cache에 kmem_cache#21 을 생성 및 초기화 후 할당

	rcu_init();
	// rcu 자료구조 bh, sched, preempt 를 각각 초기화 수행함

	tick_nohz_init(); // null function
	context_tracking_init(); // null function

	radix_tree_init();
	// radix tree로 사용하는 radix_tree_node_cachep에 kmem_cache#20을 생성 및 초기화 후 할당하고
	// height_to_maxindex을 초기화 수행

	/* init some links before init_ISA_irqs() */
	early_irq_init();
	// irq_desc 0 ~ 15 까지의 object을 할당 받고 초기화를 수행
	// allocated_irqs에 bit를 1로 세팅하고 radix tree에 각 irq_desc를 노트로 추가

	init_IRQ();
	// gic, combiner이 사용할 메모리 할당과 자료 구조 설정,
	// gic irq (0~15), combiner irq (32~63) interrupt 를 enable 시킴

	tick_init();
	// tick 관련 mask 변수를 0으로 초기화 수행

	init_timers();
	// boot_tvec_bases의 맴버 값을 초기화하고 timers_nb를 cpu_notifier 에 등록,
	// softirq_vec[1] 에 run_timer_softirq 등록하여 초기화 수행

	hrtimers_init();
	// hrtimer_bases의 맴버 값을 초기화하고 hrtimers_nb를 cpu_notifier 에 등록,
	// softirq_vec[8] 에 run_hrtimer_softirq 등록하여 초기화 수행

	softirq_init();
	// tasklet_vec, tasklet_hi_vec 맴버 값을 초기화하고,
	// softirq_vec[6]에 tasklet_action, softirq_vec[0]에 tasklet_hi_action 등록하여 초기화 수행

	timekeeping_init();
	// ntp 관련 전역변수 초기화, timekeeper, shadow_timekeeper의 맴버값 초기화 수행

	time_init();
	// timer 를 사용하기 위한 clk source, clk_table 메모리 할당 및 초기화,
	// timer event를 위한 timer irq (MCT) 초기화 수행

// 2015/05/23 종료
// 2015/05/30 시작

	sched_clock_postinit();
	// sched_clock_timer을 초기화 수행

	perf_event_init(); // null function
	profile_init(); // null function
	call_function_init();
	// 각 cpu core에서 사용할 call_single_queue를 맴버값 초기화
	// cfd_data 맴버값을 초기화하고 pcp에서 사용할 메모리 공간 할당
	// cpu_chain에 hotplug_cfd_notifier 를 등록함

	// irqs_disabled(): 1
	WARN(!irqs_disabled(), "Interrupts were enabled early\n");

	// early_boot_irqs_disabled: true
	early_boot_irqs_disabled = false;
	// early_boot_irqs_disabled: false

	local_irq_enable();
	// IRQ를 enable 함

	kmem_cache_init_late(); // null function

// 2015/06/20 종료
// 2015/06/27 시작

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	console_init();

// 2015/07/25 종료
// 2015/08/01 시작

	// panic_later: NULL
	if (panic_later)
		panic(panic_later, panic_param);

	lockdep_info(); // null function

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
	locking_selftest(); // null function

#ifdef CONFIG_BLK_DEV_INITRD // CONFIG_BLK_DEV_INITRD=y
	// initrd_start: NULL, initrd_below_start_ok: 0
	if (initrd_start && !initrd_below_start_ok &&
	    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
		pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
		    page_to_pfn(virt_to_page((void *)initrd_start)),
		    min_low_pfn);
		initrd_start = 0;
	}
#endif

// 2015/08/01 종료
// 2015/08/08 시작

	page_cgroup_init(); // null function
	debug_objects_mem_init(); // null function
	kmemleak_init(); // null function

// 2015/08/22 종료
// 2015/09/12 시작

	setup_per_cpu_pageset();
	// per cpu가 사용하는 pageset의 각각의 zone 맴버값 초기화 수행

	numa_policy_init(); // null function

	// late_time_init: NULL
	if (late_time_init)
		late_time_init();

	sched_clock_init();
	// sched_clock_running 값을 1 로 초기화 수행

	calibrate_delay();
	// BogoMIPS값을 결정하기위한 계산을 수행하고 결과를 출력함

	pidmap_init();
	// pidmap 을 사용하기 위한 초기화 수행

// 2015/09/12 종료
// 2015/09/19 시작

	anon_vma_init();
	// anon vma 를 사용하기 위한 kmem_cache 할당자 초기화 수행

#ifdef CONFIG_X86 // CONFIG_X86=n
	if (efi_enabled(EFI_RUNTIME_SERVICES))
		efi_enter_virtual_mode();
#endif
	thread_info_cache_init(); // null function
	cred_init();
	// credentials 를 사용하기 위한 kmem_cache 할당자 초기화 수행

	// totalram_pages: 총 free된 page 수
	fork_init(totalram_pages);
	// task_struct 를 사용하기 위한 kmem_cache 할당자 초기화 수행
	// max_threads값을 계산하여 init_task에 threads값의 limit 값 설정함

	proc_caches_init();
	// sighand_struct, signal_struct, files_struct, fs_struct, mm_struct, vm_area_struct, nsproxy
	// 를 사용하기 위한 kmem_cache 할당자 및 percpu list 초기화 수행

	buffer_init();
	// buffer_head 를 사용하기 위한 kmem_cache 할당자 및 max_buffer_heads 값 초기화 수행

	key_init(); // null funtion
	security_init(); // null funtion
	dbg_late_init(); // null funtion

	// totalram_pages: 총 free된 page 수
	vfs_caches_init(totalram_pages);
	// virtual file system을 위한 names, dentry, inode, filp, mount cache 생성 후
	// file system 을 위한 초기화 수행 및 mount 수행, block, char dev 사용을 위한 초기화 수행

	signals_init();
	// signal을 사용하기 위한 kmem_cache 를 생성

	/* rootfs populating might need page-writeback */
	page_writeback_init();
	// page writeback을 위한 global_dirty_limit, ratelimit_pages 값을 초기화 수행

#ifdef CONFIG_PROC_FS // CONFIG_PROC_FS=y
	proc_root_init();
	// proc filesystem을 등록 하고 proc을 사용하기 위한 dentry, inode 생성 후
	// sysctl_base_table 에 등록된 kernel, vm, fs, debug, dev의 dir, files 를 recursive 하게 RB Tree 를 구성함
#endif
	cgroup_init();
	// cgroup에서 사용하는 sub system 인 debug_subsys, cpu_cgroup_subsys, cpuacct_subsys, freezer_subsys 를 등록 하고
	// init_css_set.subsys 를 이용하여 hash key 값 생성, cgroup 을 위한 kobject 를 생성, cgroup용 fils system type을 추가 하여
	// filesystem 에 등록함, cgroup 을 위한 proc 생성.

	cpuset_init(); // null function
	taskstats_init_early(); // null function
	delayacct_init(); // null function

	check_bugs();
	// page 2개를 할당 받고 할당 받은 메모리에 값을 쓰고 비교하여
	// 메모리 동작을 테스트 수행한 이후 다시 메모리를 반환함

	acpi_early_init(); /* before LAPIC and SMP init */  // null function
	sfi_init_late(); // null function

	// efi_enabled(EFI_RUNTIME_SERVICES): 1
	if (efi_enabled(EFI_RUNTIME_SERVICES)) {
		efi_late_init(); // null function
		efi_free_boot_services(); // null function
	}

	ftrace_init(); // null function

	/* Do the rest non-__init'ed, we're now alive */
	rest_init();

	// TODO:
	// kmem_cache 를 사용했던 xxx_init() 함수들 기능이 나오지 않는 부분은
	// Remind해서 다시 공부 하는 것으로 진행
}

/* Call all constructor functions linked into the kernel. */
static void __init do_ctors(void)
{
#ifdef CONFIG_CONSTRUCTORS
	ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

	for (; fn < (ctor_fn_t *) __ctors_end; fn++)
		(*fn)();
#endif
}

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

static int __init_or_module do_one_initcall_debug(initcall_t fn)
{
	ktime_t calltime, delta, rettime;
	unsigned long long duration;
	int ret;

	pr_debug("calling  %pF @ %i\n", fn, task_pid_nr(current));
	calltime = ktime_get();
	ret = fn();
	rettime = ktime_get();
	delta = ktime_sub(rettime, calltime);
	duration = (unsigned long long) ktime_to_ns(delta) >> 10;
	pr_debug("initcall %pF returned %d after %lld usecs\n",
		 fn, ret, duration);

	return ret;
}

int __init_or_module do_one_initcall(initcall_t fn)
{
	int count = preempt_count();
	int ret;
	char msgbuf[64];

	if (initcall_debug)
		ret = do_one_initcall_debug(fn);
	else
		ret = fn();

	msgbuf[0] = 0;

	if (preempt_count() != count) {
		sprintf(msgbuf, "preemption imbalance ");
		preempt_count_set(count);
	}
	if (irqs_disabled()) {
		strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
		local_irq_enable();
	}
	WARN(msgbuf[0], "initcall %pF returned with %s\n", fn, msgbuf);

	return ret;
}


extern initcall_t __initcall_start[];
extern initcall_t __initcall0_start[];
extern initcall_t __initcall1_start[];
extern initcall_t __initcall2_start[];
extern initcall_t __initcall3_start[];
extern initcall_t __initcall4_start[];
extern initcall_t __initcall5_start[];
extern initcall_t __initcall6_start[];
extern initcall_t __initcall7_start[];
extern initcall_t __initcall_end[];

static initcall_t *initcall_levels[] __initdata = {
	__initcall0_start,
	__initcall1_start,
	__initcall2_start,
	__initcall3_start,
	__initcall4_start,
	__initcall5_start,
	__initcall6_start,
	__initcall7_start,
	__initcall_end,
};

/* Keep these in sync with initcalls in include/linux/init.h */
static char *initcall_level_names[] __initdata = {
	"early",
	"core",
	"postcore",
	"arch",
	"subsys",
	"fs",
	"device",
	"late",
};

static void __init do_initcall_level(int level)
{
	extern const struct kernel_param __start___param[], __stop___param[];
	initcall_t *fn;

	strcpy(initcall_command_line, saved_command_line);
	parse_args(initcall_level_names[level],
		   initcall_command_line, __start___param,
		   __stop___param - __start___param,
		   level, level,
		   &repair_env_string);

	for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
		do_one_initcall(*fn);
}

static void __init do_initcalls(void)
{
	int level;

	for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++)
		do_initcall_level(level);
}

/*
 * Ok, the machine is now initialized. None of the devices
 * have been touched yet, but the CPU subsystem is up and
 * running, and memory and process management works.
 *
 * Now we can finally start doing some real work..
 */
static void __init do_basic_setup(void)
{
	cpuset_init_smp();
	usermodehelper_init();
	shmem_init();
	driver_init();
	init_irq_proc();
	do_ctors();
	usermodehelper_enable();
	do_initcalls();
	random_int_secret_init();
}

static void __init do_pre_smp_initcalls(void)
{
	initcall_t *fn;

	for (fn = __initcall_start; fn < __initcall0_start; fn++)
		do_one_initcall(*fn);
}

/*
 * This function requests modules which should be loaded by default and is
 * called twice right after initrd is mounted and right before init is
 * exec'd.  If such modules are on either initrd or rootfs, they will be
 * loaded before control is passed to userland.
 */
void __init load_default_modules(void)
{
	load_default_elevator_module();
}

static int run_init_process(const char *init_filename)
{
	argv_init[0] = init_filename;
	return do_execve(init_filename,
		(const char __user *const __user *)argv_init,
		(const char __user *const __user *)envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
	int ret;

	ret = run_init_process(init_filename);

	if (ret && ret != -ENOENT) {
		pr_err("Starting init: %s exists but couldn't execute it (error %d)\n",
		       init_filename, ret);
	}

	return ret;
}

static noinline void __init kernel_init_freeable(void);

// ARM10C 20160827
static int __ref kernel_init(void *unused)
{
	int ret;

	kernel_init_freeable();
	/* need to finish all async __init code before freeing the memory */
	async_synchronize_full();
	free_initmem();
	mark_rodata_ro();
	system_state = SYSTEM_RUNNING;
	numa_default_policy();

	flush_delayed_fput();

	if (ramdisk_execute_command) {
		ret = run_init_process(ramdisk_execute_command);
		if (!ret)
			return 0;
		pr_err("Failed to execute %s (error %d)\n",
		       ramdisk_execute_command, ret);
	}

	/*
	 * We try each of these until one succeeds.
	 *
	 * The Bourne shell can be used instead of init if we are
	 * trying to recover a really broken machine.
	 */
	if (execute_command) {
		ret = run_init_process(execute_command);
		if (!ret)
			return 0;
		pr_err("Failed to execute %s (error %d).  Attempting defaults...\n",
			execute_command, ret);
	}
	if (!try_to_run_init_process("/sbin/init") ||
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;

	panic("No working init found.  Try passing init= option to kernel. "
	      "See Linux Documentation/init.txt for guidance.");
}

static noinline void __init kernel_init_freeable(void)
{
	/*
	 * Wait until kthreadd is all set-up.
	 */
	wait_for_completion(&kthreadd_done);

	/* Now the scheduler is fully set up and can do blocking allocations */
	gfp_allowed_mask = __GFP_BITS_MASK;

	/*
	 * init can allocate pages on any node
	 */
	set_mems_allowed(node_states[N_MEMORY]);
	/*
	 * init can run on any cpu.
	 */
	set_cpus_allowed_ptr(current, cpu_all_mask);

	cad_pid = task_pid(current);

	smp_prepare_cpus(setup_max_cpus);

	do_pre_smp_initcalls();
	lockup_detector_init();

	smp_init();
	sched_init_smp();

	do_basic_setup();

	/* Open the /dev/console on the rootfs, this should never fail */
	if (sys_open((const char __user *) "/dev/console", O_RDWR, 0) < 0)
		pr_err("Warning: unable to open an initial console.\n");

	(void) sys_dup(0);
	(void) sys_dup(0);
	/*
	 * check if there is an early userspace init.  If yes, let it do all
	 * the work
	 */

	if (!ramdisk_execute_command)
		ramdisk_execute_command = "/init";

	if (sys_access((const char __user *) ramdisk_execute_command, 0) != 0) {
		ramdisk_execute_command = NULL;
		prepare_namespace();
	}

	/*
	 * Ok, we have completed the initial bootup, and
	 * we're essentially up and running. Get rid of the
	 * initmem segments and start the user-mode stuff..
	 */

	/* rootfs is available now, try loading default modules */
	load_default_modules();
}
