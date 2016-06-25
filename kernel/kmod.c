/*
	kmod, the new module loader (replaces kerneld)
	Kirk Petersen

	Reorganized not to be a daemon by Adam Richter, with guidance
	from Greg Zornetzer.

	Modified to avoid chroot and file sharing problems.
	Mikael Pettersson

	Limit the concurrent number of kmod modprobes to catch loops from
	"modprobe needs a service that is in a module".
	Keith Owens <kaos@ocs.com.au> December 1999

	Unblock all signals when we exec a usermode process.
	Shuu Yamaguchi <shuu@wondernetworkresources.com> December 2000

	call_usermodehelper wait flag, and remove exec_usermodehelper.
	Rusty Russell <rusty@rustcorp.com.au>  Jan 2003
*/
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/resource.h>
#include <linux/notifier.h>
#include <linux/suspend.h>
#include <linux/rwsem.h>
#include <linux/ptrace.h>
#include <linux/async.h>
#include <asm/uaccess.h>

#include <trace/events/module.h>

extern int max_threads;

// ARM10C 20160409
static struct workqueue_struct *khelper_wq;

/*
 * kmod_thread_locker is used for deadlock avoidance.  There is no explicit
 * locking to protect this global - it is private to the singleton khelper
 * thread and should only ever be modified by that thread.
 */
static const struct task_struct *kmod_thread_locker;

#define CAP_BSET	(void *)1
#define CAP_PI		(void *)2

static kernel_cap_t usermodehelper_bset = CAP_FULL_SET;
static kernel_cap_t usermodehelper_inheritable = CAP_FULL_SET;
static DEFINE_SPINLOCK(umh_sysctl_lock);
static DECLARE_RWSEM(umhelper_sem);

#ifdef CONFIG_MODULES // CONFIG_MODULES=y

/*
	modprobe_path is set via /proc/sys.
*/
// ARM10C 20160402
// KMOD_PATH_LEN: 256
char modprobe_path[KMOD_PATH_LEN] = "/sbin/modprobe";

static void free_modprobe_argv(struct subprocess_info *info)
{
	kfree(info->argv[3]); /* check call_modprobe() */
	kfree(info->argv);
}

// ARM10C 20160402
// module_name: "fs-rootfs", 2
static int call_modprobe(char *module_name, int wait)
{
	struct subprocess_info *info;
	static char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
		NULL
	};
	// envp[0]: "HOME=/"
	// envp[1]: "TERM=linux"
	// envp[2]: "PATH=/sbin:/usr/sbin:/bin:/usr/bin"

	// sizeof(char *[5]): 20 bytes, GFP_KERNEL: 0xD0
	// kmalloc(20, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	char **argv = kmalloc(sizeof(char *[5]), GFP_KERNEL);
	// argv: kmem_cache#30-oX

	// argv: kmem_cache#30-oX
	if (!argv)
		goto out;

	// module_name: "fs-rootfs", GFP_KERNEL: 0xD0
	// kstrdup("fs-rootfs", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "fs-rootfs"
	module_name = kstrdup(module_name, GFP_KERNEL);
	// module_name: kmem_cache#30-oX: "fs-rootfs"

	// module_name: kmem_cache#30-oX: "fs-rootfs"
	if (!module_name)
		goto free_argv;

	// argv[0]: (kmem_cache#30-oX)[0], modprobe_path: "/sbin/modprobe"
	argv[0] = modprobe_path;
	// argv[0]: (kmem_cache#30-oX)[0]: "/sbin/modprobe"

	// argv[1]: (kmem_cache#30-oX)[1]
	argv[1] = "-q";
	// argv[1]: (kmem_cache#30-oX)[1]: "-q"

	// argv[2]: (kmem_cache#30-oX)[2]
	argv[2] = "--";
	// argv[2]: (kmem_cache#30-oX)[2]: "--"

	// argv[3]: (kmem_cache#30-oX)[3], module_name: kmem_cache#30-oX: "fs-rootfs"
	argv[3] = module_name;	/* check free_modprobe_argv() */
	// argv[3]: (kmem_cache#30-oX)[3]: kmem_cache#30-oX: "fs-rootfs"

	// argv[4]: (kmem_cache#30-oX)[4]
	argv[4] = NULL;
	// argv[4]: (kmem_cache#30-oX)[4]: NULL

	// modprobe_path: "/sbin/modprobe", argv: kmem_cache#30-oX
	// envp[0]: "HOME=/"
	// envp[1]: "TERM=linux"
	// envp[2]: "PATH=/sbin:/usr/sbin:/bin:/usr/bin", GFP_KERNEL: 0xD0
	// call_usermodehelper_setup("/sbin/modprobe", kmem_cache#30-oX, envp, GFP_KERNEL: 0xD0, NULL, free_modprobe_argv, NULL):
	// kmem_cache#30-oX (struct subprocess_info)
	info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
					 NULL, free_modprobe_argv, NULL);
	// info: kmem_cache#30-oX (struct subprocess_info)

	// call_usermodehelper_setup 에서 한일:
	// struct subprocess_info 만큼의 메모리를 할당받음 kmem_cache#30-oX (struct subprocess_info)
	// (&(kmem_cache#30-oX (struct subprocess_info))->work)->data: { 0xFFFFFFE0 }
	// (&(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry)->next: &(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry
	// (&(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry)->prev: &(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry
	// (&(kmem_cache#30-oX (struct subprocess_info))->work)->func: __call_usermodehelper
	// (kmem_cache#30-oX (struct subprocess_info))->path: "/sbin/modprobe"
	// (kmem_cache#30-oX (struct subprocess_info))->argv: kmem_cache#30-oX
	// (kmem_cache#30-oX (struct subprocess_info))->envp: envp
	// (kmem_cache#30-oX (struct subprocess_info))->cleanup: NULL
	// (kmem_cache#30-oX (struct subprocess_info))->init: free_modprobe_argv
	// (kmem_cache#30-oX (struct subprocess_info))->data: NULL

// 2016/04/02 종료
// 2016/04/09 시작

	// info: kmem_cache#30-oX (struct subprocess_info)
	if (!info)
		goto free_module_name;

	// info: kmem_cache#30-oX (struct subprocess_info), wait: 2, UMH_KILLABLE: 4
	// call_usermodehelper_exec(kmem_cache#30-oX (struct subprocess_info), 6): -16
	return call_usermodehelper_exec(info, wait | UMH_KILLABLE);

	// call_usermodehelper_exec 에서 한일:
	// struct subprocess_info 만큼 할당 받은 메모리를 반환함
	// &running_helpers_waitq의 tasklist에 등록된 task가 없어서 수행한 일이 없음

free_module_name:
	kfree(module_name);
free_argv:
	kfree(argv);
out:
	return -ENOMEM;
}

/**
 * __request_module - try to load a kernel module
 * @wait: wait (or not) for the operation to complete
 * @fmt: printf style format string for the name of the module
 * @...: arguments as specified in the format string
 *
 * Load a module using the user mode module loader. The function returns
 * zero on success or a negative errno code on failure. Note that a
 * successful module load does not mean the module did not then unload
 * and exit on an error of its own. Callers must check that the service
 * they requested is now available not blindly invoke it.
 *
 * If module auto-loading support is disabled then this function
 * becomes a no-operation.
 */
// ARM10C 20160402
// true, "fs-%.*s", len: 6, name: "rootfs"
int __request_module(bool wait, const char *fmt, ...)
{
	va_list args;

	// MODULE_NAME_LEN: 60
	char module_name[MODULE_NAME_LEN];
	unsigned int max_modprobes;
	int ret;

	// ATOMIC_INIT(0): { (0) }
	static atomic_t kmod_concurrent = ATOMIC_INIT(0);
	// kmod_concurrent.counter: 0

// ARM10C 20160402
// MAX_KMOD_CONCURRENT: 50
#define MAX_KMOD_CONCURRENT 50	/* Completely arbitrary value - KAO */
	static int kmod_loop_msg;

	/*
	 * We don't allow synchronous module loading from async.  Module
	 * init may invoke async_synchronize_full() which will end up
	 * waiting for this task which already is waiting for the module
	 * loading to complete, leading to a deadlock.
	 */
	// wait: true, current_is_async(): NULL
	WARN_ON_ONCE(wait && current_is_async());

	// modprobe_path[0]: '/'
	if (!modprobe_path[0])
		return 0;

	// fmt: "fs-%.*s",
	va_start(args, fmt);

	// va_start에서 한일:
	// args: (((char *) &("fs-%.*s")) + 4)

	// MODULE_NAME_LEN: 60, fmt: "fs-%.*s", args: (((char *) &("fs-%.*s")) + 4)
	// vsnprintf(module_name, 60, "fs-%.*s", (((char *) &("fs-%.*s")) + 4)): 9
	ret = vsnprintf(module_name, MODULE_NAME_LEN, fmt, args);
	// ret: 9

	// vsnprintf 에서 한일:
	// module_name: "fs-rootfs"

	// args: (((char *) &("fs-%.*s")) + 4)
	va_end(args);

	// va_end에서 한일:
	// args: NULL

	// ret: 9, MODULE_NAME_LEN: 60
	if (ret >= MODULE_NAME_LEN)
		return -ENAMETOOLONG;

	// module_name: "fs-rootfs"
	// security_kernel_module_request("fs-rootfs"): 0
	ret = security_kernel_module_request(module_name); // null function
	// ret: 0

	// ret: 0
	if (ret)
		return ret;

	/* If modprobe needs a service that is in a module, we get a recursive
	 * loop.  Limit the number of running kmod threads to max_threads/2 or
	 * MAX_KMOD_CONCURRENT, whichever is the smaller.  A cleaner method
	 * would be to run the parents of this process, counting how many times
	 * kmod was invoked.  That would mean accessing the internals of the
	 * process tables to get the command line, proc_pid_cmdline is static
	 * and it is not worth changing the proc code just to handle this case. 
	 * KAO.
	 *
	 * "trace the ppid" is simple, but will fail if someone's
	 * parent exits.  I think this is as good as it gets. --RR
	 */
	// max_threads: 총 free된 page 수 / 16, MAX_KMOD_CONCURRENT: 50
	// min(총 free된 page 수 / 16, 50): 50
	max_modprobes = min(max_threads/2, MAX_KMOD_CONCURRENT);
	// max_modprobes: 50

	// kmod_concurrent.counter: 0
	atomic_inc(&kmod_concurrent);

	// atomic_inc 에서 한일:
	// kmod_concurrent.counter: 1

	// atomic_read(&kmod_concurrent): 1, max_modprobes: 50
	if (atomic_read(&kmod_concurrent) > max_modprobes) {
		/* We may be blaming an innocent here, but unlikely */
		if (kmod_loop_msg < 5) {
			printk(KERN_ERR
			       "request_module: runaway loop modprobe %s\n",
			       module_name);
			kmod_loop_msg++;
		}
		atomic_dec(&kmod_concurrent);
		return -ENOMEM;
	}

	// module_name: "fs-rootfs", wait: true
	trace_module_request(module_name, wait, _RET_IP_);

	// module_name: "fs-rootfs", wait: true, UMH_WAIT_PROC: 2, UMH_WAIT_EXEC: 1
	// call_modprobe("fs-rootfs", UMH_WAIT_PROC: 2): -16
	ret = call_modprobe(module_name, wait ? UMH_WAIT_PROC : UMH_WAIT_EXEC);
	// ret: -16

	// call_modprobe에서 한일:
	// struct subprocess_info 만큼의 메모리를 할당받음 kmem_cache#30-oX (struct subprocess_info)
	// (&(kmem_cache#30-oX (struct subprocess_info))->work)->data: { 0xFFFFFFE0 }
	// (&(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry)->next: &(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry
	// (&(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry)->prev: &(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry
	// (&(kmem_cache#30-oX (struct subprocess_info))->work)->func: __call_usermodehelper
	// (kmem_cache#30-oX (struct subprocess_info))->path: "/sbin/modprobe"
	// (kmem_cache#30-oX (struct subprocess_info))->argv: kmem_cache#30-oX
	// (kmem_cache#30-oX (struct subprocess_info))->envp: envp
	// (kmem_cache#30-oX (struct subprocess_info))->cleanup: NULL
	// (kmem_cache#30-oX (struct subprocess_info))->init: free_modprobe_argv
	// (kmem_cache#30-oX (struct subprocess_info))->data: NULL
	//
	// struct subprocess_info 만큼 할당 받은 메모리를 반환함
	// &running_helpers_waitq의 tasklist에 등록된 task가 없어서 수행한 일이 없음

	// kmod_concurrent.counter: 1
	atomic_dec(&kmod_concurrent);

	// atomic_dec에서 한일:
	// kmod_concurrent.counter: 0

	// ret: -16
	return ret;
	// return -16
}
EXPORT_SYMBOL(__request_module);
#endif /* CONFIG_MODULES */

/*
 * This is the task which runs the usermode application
 */
static int ____call_usermodehelper(void *data)
{
	struct subprocess_info *sub_info = data;
	struct cred *new;
	int retval;

	spin_lock_irq(&current->sighand->siglock);
	flush_signal_handlers(current, 1);
	spin_unlock_irq(&current->sighand->siglock);

	/* We can run anywhere, unlike our parent keventd(). */
	set_cpus_allowed_ptr(current, cpu_all_mask);

	/*
	 * Our parent is keventd, which runs with elevated scheduling priority.
	 * Avoid propagating that into the userspace child.
	 */
	set_user_nice(current, 0);

	retval = -ENOMEM;
	new = prepare_kernel_cred(current);
	if (!new)
		goto fail;

	spin_lock(&umh_sysctl_lock);
	new->cap_bset = cap_intersect(usermodehelper_bset, new->cap_bset);
	new->cap_inheritable = cap_intersect(usermodehelper_inheritable,
					     new->cap_inheritable);
	spin_unlock(&umh_sysctl_lock);

	if (sub_info->init) {
		retval = sub_info->init(sub_info, new);
		if (retval) {
			abort_creds(new);
			goto fail;
		}
	}

	commit_creds(new);

	retval = do_execve(sub_info->path,
			   (const char __user *const __user *)sub_info->argv,
			   (const char __user *const __user *)sub_info->envp);
	if (!retval)
		return 0;

	/* Exec failed? */
fail:
	sub_info->retval = retval;
	do_exit(0);
}

static int call_helper(void *data)
{
	/* Worker thread started blocking khelper thread. */
	kmod_thread_locker = current;
	return ____call_usermodehelper(data);
}

// ARM10C 20160409
// sub_info: kmem_cache#30-oX (struct subprocess_info)
static void call_usermodehelper_freeinfo(struct subprocess_info *info)
{
	// info->cleanup: (kmem_cache#30-oX (struct subprocess_info))->cleanup: NULL
	if (info->cleanup)
		(*info->cleanup)(info);

	// info: kmem_cache#30-oX (struct subprocess_info)
	kfree(info);

	// kfree에서 한일:
	// struct subprocess_info 만큼 할당 받은 메모리를 반환함
}

static void umh_complete(struct subprocess_info *sub_info)
{
	struct completion *comp = xchg(&sub_info->complete, NULL);
	/*
	 * See call_usermodehelper_exec(). If xchg() returns NULL
	 * we own sub_info, the UMH_KILLABLE caller has gone away.
	 */
	if (comp)
		complete(comp);
	else
		call_usermodehelper_freeinfo(sub_info);
}

/* Keventd can't block, but this (a child) can. */
static int wait_for_helper(void *data)
{
	struct subprocess_info *sub_info = data;
	pid_t pid;

	/* If SIGCLD is ignored sys_wait4 won't populate the status. */
	spin_lock_irq(&current->sighand->siglock);
	current->sighand->action[SIGCHLD-1].sa.sa_handler = SIG_DFL;
	spin_unlock_irq(&current->sighand->siglock);

	pid = kernel_thread(____call_usermodehelper, sub_info, SIGCHLD);
	if (pid < 0) {
		sub_info->retval = pid;
	} else {
		int ret = -ECHILD;
		/*
		 * Normally it is bogus to call wait4() from in-kernel because
		 * wait4() wants to write the exit code to a userspace address.
		 * But wait_for_helper() always runs as keventd, and put_user()
		 * to a kernel address works OK for kernel threads, due to their
		 * having an mm_segment_t which spans the entire address space.
		 *
		 * Thus the __user pointer cast is valid here.
		 */
		sys_wait4(pid, (int __user *)&ret, 0, NULL);

		/*
		 * If ret is 0, either ____call_usermodehelper failed and the
		 * real error code is already in sub_info->retval or
		 * sub_info->retval is 0 anyway, so don't mess with it then.
		 */
		if (ret)
			sub_info->retval = ret;
	}

	umh_complete(sub_info);
	do_exit(0);
}

/* This is run by khelper thread  */
static void __call_usermodehelper(struct work_struct *work)
{
	struct subprocess_info *sub_info =
		container_of(work, struct subprocess_info, work);
	int wait = sub_info->wait & ~UMH_KILLABLE;
	pid_t pid;

	/* CLONE_VFORK: wait until the usermode helper has execve'd
	 * successfully We need the data structures to stay around
	 * until that is done.  */
	if (wait == UMH_WAIT_PROC)
		pid = kernel_thread(wait_for_helper, sub_info,
				    CLONE_FS | CLONE_FILES | SIGCHLD);
	else {
		pid = kernel_thread(call_helper, sub_info,
				    CLONE_VFORK | SIGCHLD);
		/* Worker thread stopped blocking khelper thread. */
		kmod_thread_locker = NULL;
	}

	switch (wait) {
	case UMH_NO_WAIT:
		call_usermodehelper_freeinfo(sub_info);
		break;

	case UMH_WAIT_PROC:
		if (pid > 0)
			break;
		/* FALLTHROUGH */
	case UMH_WAIT_EXEC:
		if (pid < 0)
			sub_info->retval = pid;
		umh_complete(sub_info);
	}
}

/*
 * If set, call_usermodehelper_exec() will exit immediately returning -EBUSY
 * (used for preventing user land processes from being created after the user
 * land has been frozen during a system-wide hibernation or suspend operation).
 * Should always be manipulated under umhelper_sem acquired for write.
 */
// ARM10C 20160409
// UMH_DISABLED: 2
static enum umh_disable_depth usermodehelper_disabled = UMH_DISABLED;

/* Number of helpers running */
// ARM10C 20160409
// ATOMIC_INIT(0): { (0) }
static atomic_t running_helpers = ATOMIC_INIT(0);

/*
 * Wait queue head used by usermodehelper_disable() to wait for all running
 * helpers to finish.
 */
// ARM10C 20160409
// DECLARE_WAIT_QUEUE_HEAD(running_helpers_waitq):
// wait_queue_head_t running_helpers_waitq =
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
//     .task_list       = { &(running_helpers_waitq).task_list, &(running_helpers_waitq).task_list }
// }
static DECLARE_WAIT_QUEUE_HEAD(running_helpers_waitq);

/*
 * Used by usermodehelper_read_lock_wait() to wait for usermodehelper_disabled
 * to become 'false'.
 */
static DECLARE_WAIT_QUEUE_HEAD(usermodehelper_disabled_waitq);

/*
 * Time to wait for running_helpers to become zero before the setting of
 * usermodehelper_disabled in usermodehelper_disable() fails
 */
#define RUNNING_HELPERS_TIMEOUT	(5 * HZ)

int usermodehelper_read_trylock(void)
{
	DEFINE_WAIT(wait);
	int ret = 0;

	down_read(&umhelper_sem);
	for (;;) {
		prepare_to_wait(&usermodehelper_disabled_waitq, &wait,
				TASK_INTERRUPTIBLE);
		if (!usermodehelper_disabled)
			break;

		if (usermodehelper_disabled == UMH_DISABLED)
			ret = -EAGAIN;

		up_read(&umhelper_sem);

		if (ret)
			break;

		schedule();
		try_to_freeze();

		down_read(&umhelper_sem);
	}
	finish_wait(&usermodehelper_disabled_waitq, &wait);
	return ret;
}
EXPORT_SYMBOL_GPL(usermodehelper_read_trylock);

long usermodehelper_read_lock_wait(long timeout)
{
	DEFINE_WAIT(wait);

	if (timeout < 0)
		return -EINVAL;

	down_read(&umhelper_sem);
	for (;;) {
		prepare_to_wait(&usermodehelper_disabled_waitq, &wait,
				TASK_UNINTERRUPTIBLE);
		if (!usermodehelper_disabled)
			break;

		up_read(&umhelper_sem);

		timeout = schedule_timeout(timeout);
		if (!timeout)
			break;

		down_read(&umhelper_sem);
	}
	finish_wait(&usermodehelper_disabled_waitq, &wait);
	return timeout;
}
EXPORT_SYMBOL_GPL(usermodehelper_read_lock_wait);

void usermodehelper_read_unlock(void)
{
	up_read(&umhelper_sem);
}
EXPORT_SYMBOL_GPL(usermodehelper_read_unlock);

/**
 * __usermodehelper_set_disable_depth - Modify usermodehelper_disabled.
 * @depth: New value to assign to usermodehelper_disabled.
 *
 * Change the value of usermodehelper_disabled (under umhelper_sem locked for
 * writing) and wakeup tasks waiting for it to change.
 */
void __usermodehelper_set_disable_depth(enum umh_disable_depth depth)
{
	down_write(&umhelper_sem);
	usermodehelper_disabled = depth;
	wake_up(&usermodehelper_disabled_waitq);
	up_write(&umhelper_sem);
}

/**
 * __usermodehelper_disable - Prevent new helpers from being started.
 * @depth: New value to assign to usermodehelper_disabled.
 *
 * Set usermodehelper_disabled to @depth and wait for running helpers to exit.
 */
int __usermodehelper_disable(enum umh_disable_depth depth)
{
	long retval;

	if (!depth)
		return -EINVAL;

	down_write(&umhelper_sem);
	usermodehelper_disabled = depth;
	up_write(&umhelper_sem);

	/*
	 * From now on call_usermodehelper_exec() won't start any new
	 * helpers, so it is sufficient if running_helpers turns out to
	 * be zero at one point (it may be increased later, but that
	 * doesn't matter).
	 */
	retval = wait_event_timeout(running_helpers_waitq,
					atomic_read(&running_helpers) == 0,
					RUNNING_HELPERS_TIMEOUT);
	if (retval)
		return 0;

	__usermodehelper_set_disable_depth(UMH_ENABLED);
	return -EAGAIN;
}

// ARM10C 20160409
static void helper_lock(void)
{
	atomic_inc(&running_helpers);

	// atomic_inc에서 한일:
	// running_helpers.counter 1

	smp_mb__after_atomic_inc();

	// smp_mb__after_atomic_inc 에서 한일:
	// 공유자원을 다른 cpu core가 사용할수 있게 해주는 옵션
}

// ARM10C 20160409
static void helper_unlock(void)
{
	// atomic_dec_and_test(&running_helpers): 1
	if (atomic_dec_and_test(&running_helpers))
		wake_up(&running_helpers_waitq);

		// wake_up 에서 한일:
		// &running_helpers_waitq의 tasklist에 등록된 task가 없어서 수행한 일이 없음
	
	// atomic_dec_and_test 에서 한일:
	// running_helpers.counter 0
}

/**
 * call_usermodehelper_setup - prepare to call a usermode helper
 * @path: path to usermode executable
 * @argv: arg vector for process
 * @envp: environment for process
 * @gfp_mask: gfp mask for memory allocation
 * @cleanup: a cleanup function
 * @init: an init function
 * @data: arbitrary context sensitive data
 *
 * Returns either %NULL on allocation failure, or a subprocess_info
 * structure.  This should be passed to call_usermodehelper_exec to
 * exec the process and free the structure.
 *
 * The init function is used to customize the helper process prior to
 * exec.  A non-zero return code causes the process to error out, exit,
 * and return the failure to the calling process
 *
 * The cleanup function is just before ethe subprocess_info is about to
 * be freed.  This can be used for freeing the argv and envp.  The
 * Function must be runnable in either a process context or the
 * context in which call_usermodehelper_exec is called.
 */
// ARM10C 20160402
// modprobe_path: "/sbin/modprobe", argv: kmem_cache#30-oX
// envp[0]: "HOME=/", envp[1]: "TERM=linux", envp[2]: "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
// GFP_KERNEL: 0xD0, NULL, free_modprobe_argv, NULL
struct subprocess_info *call_usermodehelper_setup(char *path, char **argv,
		char **envp, gfp_t gfp_mask,
		int (*init)(struct subprocess_info *info, struct cred *new),
		void (*cleanup)(struct subprocess_info *info),
		void *data)
{
	struct subprocess_info *sub_info;

	// sizeof(struct subprocess_info): 52 bytes, gfp_mask: GFP_KERNEL: 0xD0
	// kzalloc(52, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	sub_info = kzalloc(sizeof(struct subprocess_info), gfp_mask);
	// sub_info: kmem_cache#30-oX (struct subprocess_info)

	// sub_info: kmem_cache#30-oX (struct subprocess_info)
	if (!sub_info)
		goto out;

	// &sub_info->work: &(kmem_cache#30-oX (struct subprocess_info))->work
	INIT_WORK(&sub_info->work, __call_usermodehelper);

	// INIT_WORK 에서 한일:
	// (&(kmem_cache#30-oX (struct subprocess_info))->work)->data: { 0xFFFFFFE0 }
	// (&(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry)->next: &(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry
	// (&(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry)->prev: &(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry
	// (&(kmem_cache#30-oX (struct subprocess_info))->work)->func: __call_usermodehelper

	// sub_info->path: (kmem_cache#30-oX (struct subprocess_info))->path, path: "/sbin/modprobe"
	sub_info->path = path;
	// sub_info->path: (kmem_cache#30-oX (struct subprocess_info))->path: "/sbin/modprobe"

	// sub_info->argv: (kmem_cache#30-oX (struct subprocess_info))->argv, argv: kmem_cache#30-oX
	sub_info->argv = argv;
	// sub_info->argv: (kmem_cache#30-oX (struct subprocess_info))->argv: kmem_cache#30-oX

	// sub_info->envp: (kmem_cache#30-oX (struct subprocess_info))->envp, envp: envp
	sub_info->envp = envp;
	// sub_info->envp: (kmem_cache#30-oX (struct subprocess_info))->envp: envp

	// sub_info->cleanup: (kmem_cache#30-oX (struct subprocess_info))->cleanup, cleanup: NULL
	sub_info->cleanup = cleanup;
	// sub_info->cleanup: (kmem_cache#30-oX (struct subprocess_info))->cleanup: NULL

	// sub_info->init: (kmem_cache#30-oX (struct subprocess_info))->init, init: free_modprobe_argv
	sub_info->init = init;
	// sub_info->init: (kmem_cache#30-oX (struct subprocess_info))->init: free_modprobe_argv

	// sub_info->data: (kmem_cache#30-oX (struct subprocess_info))->data, data: NULL
	sub_info->data = data;
	// sub_info->data: (kmem_cache#30-oX (struct subprocess_info))->data: NULL
  out:

	// sub_info: kmem_cache#30-oX (struct subprocess_info)
	return sub_info;
	// return kmem_cache#30-oX (struct subprocess_info)
}
EXPORT_SYMBOL(call_usermodehelper_setup);

/**
 * call_usermodehelper_exec - start a usermode application
 * @sub_info: information about the subprocessa
 * @wait: wait for the application to finish and return status.
 *        when UMH_NO_WAIT don't wait at all, but you get no useful error back
 *        when the program couldn't be exec'ed. This makes it safe to call
 *        from interrupt context.
 *
 * Runs a user-space application.  The application is started
 * asynchronously if wait is not set, and runs as a child of keventd.
 * (ie. it runs with full root capabilities).
 */
// ARM10C 20160409
// info: kmem_cache#30-oX (struct subprocess_info), 6
int call_usermodehelper_exec(struct subprocess_info *sub_info, int wait)
{
	// DECLARE_COMPLETION_ONSTACK(done):
	// struct completion done =
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
	//     .task_list       = { &(done).task_list, &(done).task_list }
	//   }.wait
	// }
	DECLARE_COMPLETION_ONSTACK(done);
	int retval = 0;
	// retval: 0

	// sub_info->path: (kmem_cache#30-oX (struct subprocess_info))->path: "/sbin/modprobe"
	if (!sub_info->path) {
		call_usermodehelper_freeinfo(sub_info);
		return -EINVAL;
	}
	helper_lock();

	// helper_lock 에서 한일:
	// running_helpers.counter 1
	// 공유자원을 다른 cpu core가 사용할수 있게 해주는 옵션

	// khelper_wq: NULL, usermodehelper_disabled: 2
	if (!khelper_wq || usermodehelper_disabled) {
		// EBUSY: 16
		retval = -EBUSY;
		// retval: -16

		goto out;
		// goto out으로 이동
	}
	/*
	 * Worker thread must not wait for khelper thread at below
	 * wait_for_completion() if the thread was created with CLONE_VFORK
	 * flag, for khelper thread is already waiting for the thread at
	 * wait_for_completion() in do_fork().
	 */
	if (wait != UMH_NO_WAIT && current == kmod_thread_locker) {
		retval = -EBUSY;
		goto out;
	}

	sub_info->complete = &done;
	sub_info->wait = wait;

	queue_work(khelper_wq, &sub_info->work);
	if (wait == UMH_NO_WAIT)	/* task has freed sub_info */
		goto unlock;

	if (wait & UMH_KILLABLE) {
		retval = wait_for_completion_killable(&done);
		if (!retval)
			goto wait_done;

		/* umh_complete() will see NULL and free sub_info */
		if (xchg(&sub_info->complete, NULL))
			goto unlock;
		/* fallthrough, umh_complete() was already called */
	}

	wait_for_completion(&done);
wait_done:
	retval = sub_info->retval;
out:
	// sub_info: kmem_cache#30-oX (struct subprocess_info)
	call_usermodehelper_freeinfo(sub_info);

	// call_usermodehelper_freeinfo 에서 한일:
	// struct subprocess_info 만큼 할당 받은 메모리를 반환함
unlock:
	helper_unlock();

	// helper_unlock에서 한일:
	// &running_helpers_waitq의 tasklist에 등록된 task가 없어서 수행한 일이 없음
	// running_helpers.counter 0

	// retval: -16
	return retval;
	// return -16
}
EXPORT_SYMBOL(call_usermodehelper_exec);

/**
 * call_usermodehelper() - prepare and start a usermode application
 * @path: path to usermode executable
 * @argv: arg vector for process
 * @envp: environment for process
 * @wait: wait for the application to finish and return status.
 *        when UMH_NO_WAIT don't wait at all, but you get no useful error back
 *        when the program couldn't be exec'ed. This makes it safe to call
 *        from interrupt context.
 *
 * This function is the equivalent to use call_usermodehelper_setup() and
 * call_usermodehelper_exec().
 */
int call_usermodehelper(char *path, char **argv, char **envp, int wait)
{
	struct subprocess_info *info;
	gfp_t gfp_mask = (wait == UMH_NO_WAIT) ? GFP_ATOMIC : GFP_KERNEL;

	info = call_usermodehelper_setup(path, argv, envp, gfp_mask,
					 NULL, NULL, NULL);
	if (info == NULL)
		return -ENOMEM;

	return call_usermodehelper_exec(info, wait);
}
EXPORT_SYMBOL(call_usermodehelper);

static int proc_cap_handler(struct ctl_table *table, int write,
			 void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	unsigned long cap_array[_KERNEL_CAPABILITY_U32S];
	kernel_cap_t new_cap;
	int err, i;

	if (write && (!capable(CAP_SETPCAP) ||
		      !capable(CAP_SYS_MODULE)))
		return -EPERM;

	/*
	 * convert from the global kernel_cap_t to the ulong array to print to
	 * userspace if this is a read.
	 */
	spin_lock(&umh_sysctl_lock);
	for (i = 0; i < _KERNEL_CAPABILITY_U32S; i++)  {
		if (table->data == CAP_BSET)
			cap_array[i] = usermodehelper_bset.cap[i];
		else if (table->data == CAP_PI)
			cap_array[i] = usermodehelper_inheritable.cap[i];
		else
			BUG();
	}
	spin_unlock(&umh_sysctl_lock);

	t = *table;
	t.data = &cap_array;

	/*
	 * actually read or write and array of ulongs from userspace.  Remember
	 * these are least significant 32 bits first
	 */
	err = proc_doulongvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;

	/*
	 * convert from the sysctl array of ulongs to the kernel_cap_t
	 * internal representation
	 */
	for (i = 0; i < _KERNEL_CAPABILITY_U32S; i++)
		new_cap.cap[i] = cap_array[i];

	/*
	 * Drop everything not in the new_cap (but don't add things)
	 */
	spin_lock(&umh_sysctl_lock);
	if (write) {
		if (table->data == CAP_BSET)
			usermodehelper_bset = cap_intersect(usermodehelper_bset, new_cap);
		if (table->data == CAP_PI)
			usermodehelper_inheritable = cap_intersect(usermodehelper_inheritable, new_cap);
	}
	spin_unlock(&umh_sysctl_lock);

	return 0;
}

// ARM10C 20160625
struct ctl_table usermodehelper_table[] = {
	{
		.procname	= "bset",
		.data		= CAP_BSET,
		.maxlen		= _KERNEL_CAPABILITY_U32S * sizeof(unsigned long),
		.mode		= 0600,
		.proc_handler	= proc_cap_handler,
	},
	{
		.procname	= "inheritable",
		.data		= CAP_PI,
		.maxlen		= _KERNEL_CAPABILITY_U32S * sizeof(unsigned long),
		.mode		= 0600,
		.proc_handler	= proc_cap_handler,
	},
	{ }
};

void __init usermodehelper_init(void)
{
	khelper_wq = create_singlethread_workqueue("khelper");
	BUG_ON(!khelper_wq);
}
