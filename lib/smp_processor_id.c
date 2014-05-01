/*
 * lib/smp_processor_id.c
 *
 * DEBUG_PREEMPT variant of smp_processor_id().
 */
#include <linux/export.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>

// ARM10C 20130824
// FIXME: notrace와 관련하여 프로파일링-함수가 무엇인가?
// ARM10C 20140308
notrace unsigned int debug_smp_processor_id(void)
{
	// FIXME: this_cpu 값은?
	// ARM10C this_cpu = 0이 가장 유력함
	int this_cpu = raw_smp_processor_id();

	// likely는 true일 가능성이 높은 코드라고 컴파일러에게 알려준다.
	// preempt_count(): 0x4000_0001
	// 최초만 0x40000001
	// Reset by start_kernel()->sched_init()->init_idle().
	if (likely(preempt_count()))
		goto out;

// 2013/08/24 종료
// 2013/08/31 시작

	if (irqs_disabled())
		goto out;

	/*
	 * Kernel threads bound to a single CPU can safely use
	 * smp_processor_id():
	 */
	if (cpumask_equal(tsk_cpus_allowed(current), cpumask_of(this_cpu)))
		goto out;

	/*
	 * It is valid to assume CPU-locality during early bootup:
	 */
	if (system_state != SYSTEM_RUNNING)
		goto out;

	/*
	 * Avoid recursion:
	 */
	preempt_disable_notrace();

// 2013/08/31 종료 (spin lock 분석중)
// 2013/09/07 시작
	if (!printk_ratelimit())
		goto out_enable;

	printk(KERN_ERR "BUG: using smp_processor_id() in preemptible [%08x] "
			"code: %s/%d\n",
			preempt_count() - 1, current->comm, current->pid);
	print_symbol("caller is %s\n", (long)__builtin_return_address(0));
	dump_stack();

out_enable:
	preempt_enable_no_resched_notrace();
out:
	return this_cpu;
}

EXPORT_SYMBOL(debug_smp_processor_id);

