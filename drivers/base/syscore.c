/*
 *  syscore.c - Execution of system core operations.
 *
 *  Copyright (C) 2011 Rafael J. Wysocki <rjw@sisk.pl>, Novell Inc.
 *
 *  This file is released under the GPLv2.
 */

#include <linux/syscore_ops.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/interrupt.h>

// ARM10C 20150110
static LIST_HEAD(syscore_ops_list);
// ARM10C 20150110
static DEFINE_MUTEX(syscore_ops_lock);

/**
 * register_syscore_ops - Register a set of system core operations.
 * @ops: System core operations to register.
 */
// ARM10C 20150110
// &samsung_clk_syscore_ops
void register_syscore_ops(struct syscore_ops *ops)
{
	mutex_lock(&syscore_ops_lock);
	// syscore_ops_lock을 사용하여 mutex lock 수행

	// &ops->node: &(&samsung_clk_syscore_ops)->node
	list_add_tail(&ops->node, &syscore_ops_list);

	// list_add_tail에서 한일
	// syscore_ops_list의 tail에 (&samsung_clk_syscore_ops)->node 를 추가

	mutex_unlock(&syscore_ops_lock);
	// syscore_ops_lock을 사용하여 mutex unlock 수행
}
EXPORT_SYMBOL_GPL(register_syscore_ops);

/**
 * unregister_syscore_ops - Unregister a set of system core operations.
 * @ops: System core operations to unregister.
 */
void unregister_syscore_ops(struct syscore_ops *ops)
{
	mutex_lock(&syscore_ops_lock);
	list_del(&ops->node);
	mutex_unlock(&syscore_ops_lock);
}
EXPORT_SYMBOL_GPL(unregister_syscore_ops);

#ifdef CONFIG_PM_SLEEP
/**
 * syscore_suspend - Execute all the registered system core suspend callbacks.
 *
 * This function is executed with one CPU on-line and disabled interrupts.
 */
int syscore_suspend(void)
{
	struct syscore_ops *ops;
	int ret = 0;

	pr_debug("Checking wakeup interrupts\n");

	/* Return error code if there are any wakeup interrupts pending. */
	ret = check_wakeup_irqs();
	if (ret)
		return ret;

	WARN_ONCE(!irqs_disabled(),
		"Interrupts enabled before system core suspend.\n");

	list_for_each_entry_reverse(ops, &syscore_ops_list, node)
		if (ops->suspend) {
			if (initcall_debug)
				pr_info("PM: Calling %pF\n", ops->suspend);
			ret = ops->suspend();
			if (ret)
				goto err_out;
			WARN_ONCE(!irqs_disabled(),
				"Interrupts enabled after %pF\n", ops->suspend);
		}

	return 0;

 err_out:
	pr_err("PM: System core suspend callback %pF failed.\n", ops->suspend);

	list_for_each_entry_continue(ops, &syscore_ops_list, node)
		if (ops->resume)
			ops->resume();

	return ret;
}
EXPORT_SYMBOL_GPL(syscore_suspend);

/**
 * syscore_resume - Execute all the registered system core resume callbacks.
 *
 * This function is executed with one CPU on-line and disabled interrupts.
 */
void syscore_resume(void)
{
	struct syscore_ops *ops;

	WARN_ONCE(!irqs_disabled(),
		"Interrupts enabled before system core resume.\n");

	list_for_each_entry(ops, &syscore_ops_list, node)
		if (ops->resume) {
			if (initcall_debug)
				pr_info("PM: Calling %pF\n", ops->resume);
			ops->resume();
			WARN_ONCE(!irqs_disabled(),
				"Interrupts enabled after %pF\n", ops->resume);
		}
}
EXPORT_SYMBOL_GPL(syscore_resume);
#endif /* CONFIG_PM_SLEEP */

/**
 * syscore_shutdown - Execute all the registered system core shutdown callbacks.
 */
void syscore_shutdown(void)
{
	struct syscore_ops *ops;

	mutex_lock(&syscore_ops_lock);

	list_for_each_entry_reverse(ops, &syscore_ops_list, node)
		if (ops->shutdown) {
			if (initcall_debug)
				pr_info("PM: Calling %pF\n", ops->shutdown);
			ops->shutdown();
		}

	mutex_unlock(&syscore_ops_lock);
}
