/*
 * Copyright (C) 2010-2011 Canonical Ltd <jeremy.kerr@canonical.com>
 * Copyright (C) 2011-2012 Linaro Ltd <mturquette@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Standard functionality for the common clock API.  See Documentation/clk.txt
 */

#include <linux/clk-private.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/sched.h>

static DEFINE_SPINLOCK(enable_lock);
// ARM10C 20150117
static DEFINE_MUTEX(prepare_lock);

// ARM10C 20150117
static struct task_struct *prepare_owner;
static struct task_struct *enable_owner;

// ARM10C 20150117
static int prepare_refcnt;
static int enable_refcnt;

// ARM10C 20150117
static HLIST_HEAD(clk_root_list);
// ARM10C 20150117
// ARM10C 20150131
static HLIST_HEAD(clk_orphan_list);
static LIST_HEAD(clk_notifier_list);

/***           locking             ***/
// ARM10C 20150117
static void clk_prepare_lock(void)
{
	// mutex_trylock(&prepare_lock): 1
	if (!mutex_trylock(&prepare_lock)) {
		if (prepare_owner == current) {
			prepare_refcnt++;
			return;
		}
		mutex_lock(&prepare_lock);
	}

	// mutex_trylock에서 한일:
	// &prepare_lock을 이용한 mutex lock 수행

	// prepare_owner: NULL
	WARN_ON_ONCE(prepare_owner != NULL);

	// prepare_refcnt: 0
	WARN_ON_ONCE(prepare_refcnt != 0);

	// prepare_owner: NULL, current: &init_task
	prepare_owner = current;
	// prepare_owner: &init_task

	// prepare_refcnt: 0
	prepare_refcnt = 1;
	// prepare_refcnt: 1
}

// ARM10C 20150117
static void clk_prepare_unlock(void)
{
	// prepare_owner: &init_task, current: &init_task
	WARN_ON_ONCE(prepare_owner != current);

	// prepare_refcnt: 1
	WARN_ON_ONCE(prepare_refcnt == 0);

	// prepare_refcnt: 1
	if (--prepare_refcnt)
		return;
	// prepare_refcnt: 0

	// prepare_owner: &init_task
	prepare_owner = NULL;
	// prepare_owner: NULL

	mutex_unlock(&prepare_lock);

	// mutex_unlock에서 한일:
	// &prepare_lock을 이용한 mutex unlock 수행
}

static unsigned long clk_enable_lock(void)
{
	unsigned long flags;

	if (!spin_trylock_irqsave(&enable_lock, flags)) {
		if (enable_owner == current) {
			enable_refcnt++;
			return flags;
		}
		spin_lock_irqsave(&enable_lock, flags);
	}
	WARN_ON_ONCE(enable_owner != NULL);
	WARN_ON_ONCE(enable_refcnt != 0);
	enable_owner = current;
	enable_refcnt = 1;
	return flags;
}

static void clk_enable_unlock(unsigned long flags)
{
	WARN_ON_ONCE(enable_owner != current);
	WARN_ON_ONCE(enable_refcnt == 0);

	if (--enable_refcnt)
		return;
	enable_owner = NULL;
	spin_unlock_irqrestore(&enable_lock, flags);
}

/***        debugfs support        ***/

#ifdef CONFIG_COMMON_CLK_DEBUG // CONFIG_COMMON_CLK_DEBUG=n
#include <linux/debugfs.h>

static struct dentry *rootdir;
static struct dentry *orphandir;
static int inited = 0;

static void clk_summary_show_one(struct seq_file *s, struct clk *c, int level)
{
	if (!c)
		return;

	seq_printf(s, "%*s%-*s %-11d %-12d %-10lu",
		   level * 3 + 1, "",
		   30 - level * 3, c->name,
		   c->enable_count, c->prepare_count, clk_get_rate(c));
	seq_printf(s, "\n");
}

static void clk_summary_show_subtree(struct seq_file *s, struct clk *c,
				     int level)
{
	struct clk *child;

	if (!c)
		return;

	clk_summary_show_one(s, c, level);

	hlist_for_each_entry(child, &c->children, child_node)
		clk_summary_show_subtree(s, child, level + 1);
}

static int clk_summary_show(struct seq_file *s, void *data)
{
	struct clk *c;

	seq_printf(s, "   clock                        enable_cnt  prepare_cnt  rate\n");
	seq_printf(s, "---------------------------------------------------------------------\n");

	clk_prepare_lock();

	hlist_for_each_entry(c, &clk_root_list, child_node)
		clk_summary_show_subtree(s, c, 0);

	hlist_for_each_entry(c, &clk_orphan_list, child_node)
		clk_summary_show_subtree(s, c, 0);

	clk_prepare_unlock();

	return 0;
}


static int clk_summary_open(struct inode *inode, struct file *file)
{
	return single_open(file, clk_summary_show, inode->i_private);
}

static const struct file_operations clk_summary_fops = {
	.open		= clk_summary_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static void clk_dump_one(struct seq_file *s, struct clk *c, int level)
{
	if (!c)
		return;

	seq_printf(s, "\"%s\": { ", c->name);
	seq_printf(s, "\"enable_count\": %d,", c->enable_count);
	seq_printf(s, "\"prepare_count\": %d,", c->prepare_count);
	seq_printf(s, "\"rate\": %lu", clk_get_rate(c));
}

static void clk_dump_subtree(struct seq_file *s, struct clk *c, int level)
{
	struct clk *child;

	if (!c)
		return;

	clk_dump_one(s, c, level);

	hlist_for_each_entry(child, &c->children, child_node) {
		seq_printf(s, ",");
		clk_dump_subtree(s, child, level + 1);
	}

	seq_printf(s, "}");
}

static int clk_dump(struct seq_file *s, void *data)
{
	struct clk *c;
	bool first_node = true;

	seq_printf(s, "{");

	clk_prepare_lock();

	hlist_for_each_entry(c, &clk_root_list, child_node) {
		if (!first_node)
			seq_printf(s, ",");
		first_node = false;
		clk_dump_subtree(s, c, 0);
	}

	hlist_for_each_entry(c, &clk_orphan_list, child_node) {
		seq_printf(s, ",");
		clk_dump_subtree(s, c, 0);
	}

	clk_prepare_unlock();

	seq_printf(s, "}");
	return 0;
}


static int clk_dump_open(struct inode *inode, struct file *file)
{
	return single_open(file, clk_dump, inode->i_private);
}

static const struct file_operations clk_dump_fops = {
	.open		= clk_dump_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* caller must hold prepare_lock */
static int clk_debug_create_one(struct clk *clk, struct dentry *pdentry)
{
	struct dentry *d;
	int ret = -ENOMEM;

	if (!clk || !pdentry) {
		ret = -EINVAL;
		goto out;
	}

	d = debugfs_create_dir(clk->name, pdentry);
	if (!d)
		goto out;

	clk->dentry = d;

	d = debugfs_create_u32("clk_rate", S_IRUGO, clk->dentry,
			(u32 *)&clk->rate);
	if (!d)
		goto err_out;

	d = debugfs_create_x32("clk_flags", S_IRUGO, clk->dentry,
			(u32 *)&clk->flags);
	if (!d)
		goto err_out;

	d = debugfs_create_u32("clk_prepare_count", S_IRUGO, clk->dentry,
			(u32 *)&clk->prepare_count);
	if (!d)
		goto err_out;

	d = debugfs_create_u32("clk_enable_count", S_IRUGO, clk->dentry,
			(u32 *)&clk->enable_count);
	if (!d)
		goto err_out;

	d = debugfs_create_u32("clk_notifier_count", S_IRUGO, clk->dentry,
			(u32 *)&clk->notifier_count);
	if (!d)
		goto err_out;

	ret = 0;
	goto out;

err_out:
	debugfs_remove(clk->dentry);
out:
	return ret;
}

/* caller must hold prepare_lock */
static int clk_debug_create_subtree(struct clk *clk, struct dentry *pdentry)
{
	struct clk *child;
	int ret = -EINVAL;;

	if (!clk || !pdentry)
		goto out;

	ret = clk_debug_create_one(clk, pdentry);

	if (ret)
		goto out;

	hlist_for_each_entry(child, &clk->children, child_node)
		clk_debug_create_subtree(child, clk->dentry);

	ret = 0;
out:
	return ret;
}

/**
 * clk_debug_register - add a clk node to the debugfs clk tree
 * @clk: the clk being added to the debugfs clk tree
 *
 * Dynamically adds a clk to the debugfs clk tree if debugfs has been
 * initialized.  Otherwise it bails out early since the debugfs clk tree
 * will be created lazily by clk_debug_init as part of a late_initcall.
 *
 * Caller must hold prepare_lock.  Only clk_init calls this function (so
 * far) so this is taken care.
 */
static int clk_debug_register(struct clk *clk)
{
	struct clk *parent;
	struct dentry *pdentry;
	int ret = 0;

	if (!inited)
		goto out;

	parent = clk->parent;

	/*
	 * Check to see if a clk is a root clk.  Also check that it is
	 * safe to add this clk to debugfs
	 */
	if (!parent)
		if (clk->flags & CLK_IS_ROOT)
			pdentry = rootdir;
		else
			pdentry = orphandir;
	else
		if (parent->dentry)
			pdentry = parent->dentry;
		else
			goto out;

	ret = clk_debug_create_subtree(clk, pdentry);

out:
	return ret;
}

/**
 * clk_debug_reparent - reparent clk node in the debugfs clk tree
 * @clk: the clk being reparented
 * @new_parent: the new clk parent, may be NULL
 *
 * Rename clk entry in the debugfs clk tree if debugfs has been
 * initialized.  Otherwise it bails out early since the debugfs clk tree
 * will be created lazily by clk_debug_init as part of a late_initcall.
 *
 * Caller must hold prepare_lock.
 */
static void clk_debug_reparent(struct clk *clk, struct clk *new_parent)
{
	struct dentry *d;
	struct dentry *new_parent_d;

	if (!inited)
		return;

	if (new_parent)
		new_parent_d = new_parent->dentry;
	else
		new_parent_d = orphandir;

	d = debugfs_rename(clk->dentry->d_parent, clk->dentry,
			new_parent_d, clk->name);
	if (d)
		clk->dentry = d;
	else
		pr_debug("%s: failed to rename debugfs entry for %s\n",
				__func__, clk->name);
}

/**
 * clk_debug_init - lazily create the debugfs clk tree visualization
 *
 * clks are often initialized very early during boot before memory can
 * be dynamically allocated and well before debugfs is setup.
 * clk_debug_init walks the clk tree hierarchy while holding
 * prepare_lock and creates the topology as part of a late_initcall,
 * thus insuring that clks initialized very early will still be
 * represented in the debugfs clk tree.  This function should only be
 * called once at boot-time, and all other clks added dynamically will
 * be done so with clk_debug_register.
 */
static int __init clk_debug_init(void)
{
	struct clk *clk;
	struct dentry *d;

	rootdir = debugfs_create_dir("clk", NULL);

	if (!rootdir)
		return -ENOMEM;

	d = debugfs_create_file("clk_summary", S_IRUGO, rootdir, NULL,
				&clk_summary_fops);
	if (!d)
		return -ENOMEM;

	d = debugfs_create_file("clk_dump", S_IRUGO, rootdir, NULL,
				&clk_dump_fops);
	if (!d)
		return -ENOMEM;

	orphandir = debugfs_create_dir("orphans", rootdir);

	if (!orphandir)
		return -ENOMEM;

	clk_prepare_lock();

	hlist_for_each_entry(clk, &clk_root_list, child_node)
		clk_debug_create_subtree(clk, rootdir);

	hlist_for_each_entry(clk, &clk_orphan_list, child_node)
		clk_debug_create_subtree(clk, orphandir);

	inited = 1;

	clk_prepare_unlock();

	return 0;
}
late_initcall(clk_debug_init);
#else
// ARM10C 20150117
static inline int clk_debug_register(struct clk *clk) { return 0; }
// ARM10C 20150131
static inline void clk_debug_reparent(struct clk *clk, struct clk *new_parent)
{
}
#endif

/* caller must hold prepare_lock */
static void clk_unprepare_unused_subtree(struct clk *clk)
{
	struct clk *child;

	if (!clk)
		return;

	hlist_for_each_entry(child, &clk->children, child_node)
		clk_unprepare_unused_subtree(child);

	if (clk->prepare_count)
		return;

	if (clk->flags & CLK_IGNORE_UNUSED)
		return;

	if (__clk_is_prepared(clk)) {
		if (clk->ops->unprepare_unused)
			clk->ops->unprepare_unused(clk->hw);
		else if (clk->ops->unprepare)
			clk->ops->unprepare(clk->hw);
	}
}

/* caller must hold prepare_lock */
static void clk_disable_unused_subtree(struct clk *clk)
{
	struct clk *child;
	unsigned long flags;

	if (!clk)
		goto out;

	hlist_for_each_entry(child, &clk->children, child_node)
		clk_disable_unused_subtree(child);

	flags = clk_enable_lock();

	if (clk->enable_count)
		goto unlock_out;

	if (clk->flags & CLK_IGNORE_UNUSED)
		goto unlock_out;

	/*
	 * some gate clocks have special needs during the disable-unused
	 * sequence.  call .disable_unused if available, otherwise fall
	 * back to .disable
	 */
	if (__clk_is_enabled(clk)) {
		if (clk->ops->disable_unused)
			clk->ops->disable_unused(clk->hw);
		else if (clk->ops->disable)
			clk->ops->disable(clk->hw);
	}

unlock_out:
	clk_enable_unlock(flags);

out:
	return;
}

static bool clk_ignore_unused;
static int __init clk_ignore_unused_setup(char *__unused)
{
	clk_ignore_unused = true;
	return 1;
}
__setup("clk_ignore_unused", clk_ignore_unused_setup);

static int clk_disable_unused(void)
{
	struct clk *clk;

	if (clk_ignore_unused) {
		pr_warn("clk: Not disabling unused clocks\n");
		return 0;
	}

	clk_prepare_lock();

	hlist_for_each_entry(clk, &clk_root_list, child_node)
		clk_disable_unused_subtree(clk);

	hlist_for_each_entry(clk, &clk_orphan_list, child_node)
		clk_disable_unused_subtree(clk);

	hlist_for_each_entry(clk, &clk_root_list, child_node)
		clk_unprepare_unused_subtree(clk);

	hlist_for_each_entry(clk, &clk_orphan_list, child_node)
		clk_unprepare_unused_subtree(clk);

	clk_prepare_unlock();

	return 0;
}
late_initcall_sync(clk_disable_unused);

/***    helper functions   ***/

const char *__clk_get_name(struct clk *clk)
{
	return !clk ? NULL : clk->name;
}
EXPORT_SYMBOL_GPL(__clk_get_name);

struct clk_hw *__clk_get_hw(struct clk *clk)
{
	return !clk ? NULL : clk->hw;
}

// ARM10C 20150131
// hw->clk: ((kmem_cache#29-oX (mout_mspll_kfc))->hw)->clk
// ARM10C 20150131
// hw->clk: ((kmem_cache#29-oX (sclk_dpll))->hw)->clk
u8 __clk_get_num_parents(struct clk *clk)
{
	// clk: ((kmem_cache#29-oX (mout_mspll_kfc))->hw)->clk: kmem_cache#29-oX (mout_mspll_kfc)
	// clk->num_parents: (((kmem_cache#29-oX (mout_mspll_kfc))->hw)->clk)->num_parents: 4
	return !clk ? 0 : clk->num_parents;
	// return 4
}

struct clk *__clk_get_parent(struct clk *clk)
{
	return !clk ? NULL : clk->parent;
}

// ARM10C 20150131
// clk: kmem_cache#29-oX (mout_mspll_kfc), index: 0
// ARM10C 20150131
// clk: kmem_cache#29-oX (sclk_dpll), index: 1
struct clk *clk_get_parent_by_index(struct clk *clk, u8 index)
{
	// clk: kmem_cache#29-oX (mout_mspll_kfc), index: 0,
	// clk->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents: 4,
	// clk->parents: (kmem_cache#29-oX (mout_mspll_kfc))->parents: kmem_cache#30-oX
	// clk->parents[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parents[0]: (kmem_cache#30-oX)[0]: NULL
	// clk: kmem_cache#29-oX (sclk_dpll), index: 1,
	// clk->num_parents: (kmem_cache#29-oX (sclk_dpll))->num_parents: 2,
	// clk->parents: (kmem_cache#29-oX (sclk_dpll))->parents: kmem_cache#30-oX
	// clk->parents[1]: (kmem_cache#29-oX (sclk_dpll))->parents[1]: (kmem_cache#30-oX)[1]: kmem_cache#29-oX (fout_dpll)
	if (!clk || index >= clk->num_parents)
		return NULL;
	else if (!clk->parents)
		return __clk_lookup(clk->parent_names[index]);
	else if (!clk->parents[index])
		// clk->parents[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parents[0]: (kmem_cache#30-oX)[0],
		// clk->parent_names[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: "sclk_cpll"
		// __clk_lookup("sclk_cpll"): NULL
		return clk->parents[index] =
			__clk_lookup(clk->parent_names[index]);
		// clk->parents[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parents[0]: (kmem_cache#30-oX)[0]: NULL
		// return NULL
	else
		// clk->parents[1]: (kmem_cache#29-oX (sclk_dpll))->parents[1]: (kmem_cache#30-oX)[1]: kmem_cache#29-oX (fout_dpll)
		return clk->parents[index];
		// return kmem_cache#29-oX (fout_dpll)
}

unsigned int __clk_get_enable_count(struct clk *clk)
{
	return !clk ? 0 : clk->enable_count;
}

unsigned int __clk_get_prepare_count(struct clk *clk)
{
	return !clk ? 0 : clk->prepare_count;
}

// ARM10C 20150117
// clk->parent: (kmem_cache#29-oX)->parent: NULL
// ARM10C 20150117
// clk->parent: (kmem_cache#29-oX (apll))->parent: kmem_cache#29-oX (fin_pll),
// ARM10C 20150228
// clk->parent: (kmem_cache#29-oX (sclk_apll))->parent: kmem_cache#29-oX (mout_apll),
unsigned long __clk_get_rate(struct clk *clk)
{
	unsigned long ret;

	// clk: NULL
	// clk: kmem_cache#29-oX (fin_pll)
	// clk: kmem_cache#29-oX (mout_apll)
	if (!clk) {
		ret = 0;
		// ret: 0

		goto out;
		// goto out
	}

	// NOTE:
	// mout_apll의 rate 값은 arndale 보드의 부팅로그에서
	// 800000000을 가져온 것으로 가정하고 분석

	// clk->rate: (kmem_cache#29-oX (fin_pll))->rate: 24000000
	// clk->rate: (kmem_cache#29-oX (mout_apll))->rate: 800000000
	ret = clk->rate;
	// ret: 24000000
	// ret: 800000000

	// clk->flags: (kmem_cache#29-oX (fin_pll))->flags: 0x30, CLK_IS_ROOT: 0x10
	// clk->flags: (kmem_cache#29-oX (mout_apll))->flags: 0x80, CLK_IS_ROOT: 0x10
	if (clk->flags & CLK_IS_ROOT)
		goto out;
		// goto out

	// clk->parent: (kmem_cache#29-oX (mout_apll))->parent: kmem_cache#29-oX (fout_apll)
	if (!clk->parent)
		ret = 0;

out:
	// ret: 0
	// ret: 24000000
	// ret: 800000000
	return ret;
	// return 0
	// return 24000000
	// ret: 800000000
}

unsigned long __clk_get_flags(struct clk *clk)
{
	return !clk ? 0 : clk->flags;
}
EXPORT_SYMBOL_GPL(__clk_get_flags);

bool __clk_is_prepared(struct clk *clk)
{
	int ret;

	if (!clk)
		return false;

	/*
	 * .is_prepared is optional for clocks that can prepare
	 * fall back to software usage counter if it is missing
	 */
	if (!clk->ops->is_prepared) {
		ret = clk->prepare_count ? 1 : 0;
		goto out;
	}

	ret = clk->ops->is_prepared(clk->hw);
out:
	return !!ret;
}

bool __clk_is_enabled(struct clk *clk)
{
	int ret;

	if (!clk)
		return false;

	/*
	 * .is_enabled is only mandatory for clocks that gate
	 * fall back to software usage counter if .is_enabled is missing
	 */
	if (!clk->ops->is_enabled) {
		ret = clk->enable_count ? 1 : 0;
		goto out;
	}

	ret = clk->ops->is_enabled(clk->hw);
out:
	return !!ret;
}

// ARM10C 20150117
// [2] name: kmem_cache#30-oX ("fout_apll"), root_clk: kmem_cache#29-oX (fin_pll)
// ARM10C 20150117
// [3] name: kmem_cache#30-oX ("fin_pll"), root_clk: kmem_cache#29-oX (fin_pll)
static struct clk *__clk_lookup_subtree(const char *name, struct clk *clk)
{
	struct clk *child;
	struct clk *ret;

	// clk->name: (kmem_cache#29-oX)->name: "fin_pll", name: "fout_apll"
	// strcmp("fin_pll", "fout_apll"): -1
	// clk->name: (kmem_cache#29-oX)->name: "fin_pll", name: "fin_pll"
	// strcmp("fin_pll", "fin_pll"): 0
	if (!strcmp(clk->name, name))
		// clk: kmem_cache#29-oX (fin_pll)
		return clk;
		// return kmem_cache#29-oX (fin_pll)

	// &clk->children: &(kmem_cache#29-oX (fin_pll))->children
	hlist_for_each_entry(child, &clk->children, child_node) {
	// for (child = hlist_entry_safe((&clk->children)->first, typeof(*(child)), child_node);
	//      child; child = hlist_entry_safe((child)->child_node.next, typeof(*(child)), child_node))

		// hlist_entry_safe((&(kmem_cache#29-oX (fin_pll))->children)->first, typeof(*(child)), child_node): NULL
		// child: NULL

		ret = __clk_lookup_subtree(name, child);
		if (ret)
			return ret;
	}

	return NULL;
	// return NULL
}

// ARM10C 20150117
// [1] clk->name: (kmem_cache#29-oX)->name: kmem_cache#30-oX ("fin_pll")
// ARM10C 20150117
// [2] clk->name: (kmem_cache#29-oX (apll))->name: kmem_cache#30-oX ("fout_apll")
// ARM10C 20150117
// [3] clk->parent_names[0]: (kmem_cache#29-oX (apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
// ARM10C 20150124
// clk->name: (kmem_cache#29-oX (epll))->name: kmem_cache#30-oX ("fout_epll")
// ARM10C 20150131
// clk->name: (kmem_cache#29-oX (mout_mspll_kfc))->name: kmem_cache#30-oX ("mout_mspll_kfc")
// ARM10C 20150131
// clk->parent_names[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "sclk_spll"
// ARM10C 20150131
// clk->parent_names[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: "sclk_spll"
// ARM10C 20150228
// clk->name: (kmem_cache#29-oX (sclk_apll))->name: kmem_cache#30-oX ("sclk_apll")
// ARM10C 20150228
// clk->parent_names[0]: (kmem_cache#29-oX (sclk_apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "mout_apll"
// ARM10C 20150307
// clk->parent_names[0]: (kmem_cache#29-oX (sclk_uart0))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "dout_uart0"
struct clk *__clk_lookup(const char *name)
{
	struct clk *root_clk;
	struct clk *ret;

	// [1] name: kmem_cache#30-oX ("fin_pll")
	// [2] name: kmem_cache#30-oX ("fout_apll")
	// [3] name: kmem_cache#30-oX ("fin_pll")
	if (!name)
		return NULL;

	/* search the 'proper' clk tree first */
	hlist_for_each_entry(root_clk, &clk_root_list, child_node) {
	// for (root_clk = hlist_entry_safe((&clk_root_list)->first, typeof(*(root_clk)), child_node);
	//      root_clk; root_clk = hlist_entry_safe((root_clk)->child_node.next, typeof(*(root_clk)), child_node))

		// [1] hlist_entry_safe((&clk_root_list)->first, typeof(*(root_clk)), child_node): NULL
		// [1] root_clk: NULL

		// [2] hlist_entry_safe((&clk_root_list)->first, typeof(*(root_clk)), child_node): kmem_cache#29-oX (fin_pll)
		// [2] root_clk: kmem_cache#29-oX (fin_pll)

		// [3] hlist_entry_safe((&clk_root_list)->first, typeof(*(root_clk)), child_node): kmem_cache#29-oX (fin_pll)
		// [3] root_clk: kmem_cache#29-oX (fin_pll)

		// [2] name: kmem_cache#30-oX ("fout_apll"), root_clk: kmem_cache#29-oX (fin_pll)
		// [2] __clk_lookup_subtree("fout_apll", kmem_cache#29-oX (fin_pll)): NULL
		// [3] name: kmem_cache#30-oX ("fin_pll"), root_clk: kmem_cache#29-oX (fin_pll)
		// [3] __clk_lookup_subtree("fin_pll", kmem_cache#29-oX (fin_pll)): kmem_cache#29-oX (fin_pll)
		ret = __clk_lookup_subtree(name, root_clk);
		// [2] ret: NULL
		// [3] ret: kmem_cache#29-oX (fin_pll)

		// [2] ret: NULL
		// [3] ret: kmem_cache#29-oX (fin_pll)
		if (ret)
			// [3] ret: kmem_cache#29-oX (fin_pll)
			return ret;
			// [3] return kmem_cache#29-oX (fin_pll)
	}

	/* if not found, then search the orphan tree */
	hlist_for_each_entry(root_clk, &clk_orphan_list, child_node) {
	// for (root_clk = hlist_entry_safe((&clk_orphan_list)->first, typeof(*(root_clk)), child_node);
	//      root_clk; root_clk = hlist_entry_safe((root_clk)->child_node.next, typeof(*(root_clk)), child_node))

		// [1] hlist_entry_safe((&clk_orphan_list)->first, typeof(*(root_clk)), child_node): NULL
		// [1] root_clk: NULL

		// [2] hlist_entry_safe((&clk_orphan_list)->first, typeof(*(root_clk)), child_node): NULL
		// [2] root_clk: NULL

		ret = __clk_lookup_subtree(name, root_clk);
		if (ret)
			return ret;
	}

	return NULL;
	// return NULL
	// return NULL
}

/*
 * Helper for finding best parent to provide a given frequency. This can be used
 * directly as a determine_rate callback (e.g. for a mux), or from a more
 * complex clock that may combine a mux with other operations.
 */
long __clk_mux_determine_rate(struct clk_hw *hw, unsigned long rate,
			      unsigned long *best_parent_rate,
			      struct clk **best_parent_p)
{
	struct clk *clk = hw->clk, *parent, *best_parent = NULL;
	int i, num_parents;
	unsigned long parent_rate, best = 0;

	/* if NO_REPARENT flag set, pass through to current parent */
	if (clk->flags & CLK_SET_RATE_NO_REPARENT) {
		parent = clk->parent;
		if (clk->flags & CLK_SET_RATE_PARENT)
			best = __clk_round_rate(parent, rate);
		else if (parent)
			best = __clk_get_rate(parent);
		else
			best = __clk_get_rate(clk);
		goto out;
	}

	/* find the parent that can provide the fastest rate <= rate */
	num_parents = clk->num_parents;
	for (i = 0; i < num_parents; i++) {
		parent = clk_get_parent_by_index(clk, i);
		if (!parent)
			continue;
		if (clk->flags & CLK_SET_RATE_PARENT)
			parent_rate = __clk_round_rate(parent, rate);
		else
			parent_rate = __clk_get_rate(parent);
		if (parent_rate <= rate && parent_rate > best) {
			best_parent = parent;
			best = parent_rate;
		}
	}

out:
	if (best_parent)
		*best_parent_p = best_parent;
	*best_parent_rate = best;

	return best;
}

/***        clk api        ***/

void __clk_unprepare(struct clk *clk)
{
	if (!clk)
		return;

	if (WARN_ON(clk->prepare_count == 0))
		return;

	if (--clk->prepare_count > 0)
		return;

	WARN_ON(clk->enable_count > 0);

	if (clk->ops->unprepare)
		clk->ops->unprepare(clk->hw);

	__clk_unprepare(clk->parent);
}

/**
 * clk_unprepare - undo preparation of a clock source
 * @clk: the clk being unprepared
 *
 * clk_unprepare may sleep, which differentiates it from clk_disable.  In a
 * simple case, clk_unprepare can be used instead of clk_disable to gate a clk
 * if the operation may sleep.  One example is a clk which is accessed over
 * I2c.  In the complex case a clk gate operation may require a fast and a slow
 * part.  It is this reason that clk_unprepare and clk_disable are not mutually
 * exclusive.  In fact clk_disable must be called before clk_unprepare.
 */
void clk_unprepare(struct clk *clk)
{
	clk_prepare_lock();
	__clk_unprepare(clk);
	clk_prepare_unlock();
}
EXPORT_SYMBOL_GPL(clk_unprepare);

int __clk_prepare(struct clk *clk)
{
	int ret = 0;

	if (!clk)
		return 0;

	if (clk->prepare_count == 0) {
		ret = __clk_prepare(clk->parent);
		if (ret)
			return ret;

		if (clk->ops->prepare) {
			ret = clk->ops->prepare(clk->hw);
			if (ret) {
				__clk_unprepare(clk->parent);
				return ret;
			}
		}
	}

	clk->prepare_count++;

	return 0;
}

/**
 * clk_prepare - prepare a clock source
 * @clk: the clk being prepared
 *
 * clk_prepare may sleep, which differentiates it from clk_enable.  In a simple
 * case, clk_prepare can be used instead of clk_enable to ungate a clk if the
 * operation may sleep.  One example is a clk which is accessed over I2c.  In
 * the complex case a clk ungate operation may require a fast and a slow part.
 * It is this reason that clk_prepare and clk_enable are not mutually
 * exclusive.  In fact clk_prepare must be called before clk_enable.
 * Returns 0 on success, -EERROR otherwise.
 */
int clk_prepare(struct clk *clk)
{
	int ret;

	clk_prepare_lock();
	ret = __clk_prepare(clk);
	clk_prepare_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(clk_prepare);

static void __clk_disable(struct clk *clk)
{
	if (!clk)
		return;

	if (WARN_ON(IS_ERR(clk)))
		return;

	if (WARN_ON(clk->enable_count == 0))
		return;

	if (--clk->enable_count > 0)
		return;

	if (clk->ops->disable)
		clk->ops->disable(clk->hw);

	__clk_disable(clk->parent);
}

/**
 * clk_disable - gate a clock
 * @clk: the clk being gated
 *
 * clk_disable must not sleep, which differentiates it from clk_unprepare.  In
 * a simple case, clk_disable can be used instead of clk_unprepare to gate a
 * clk if the operation is fast and will never sleep.  One example is a
 * SoC-internal clk which is controlled via simple register writes.  In the
 * complex case a clk gate operation may require a fast and a slow part.  It is
 * this reason that clk_unprepare and clk_disable are not mutually exclusive.
 * In fact clk_disable must be called before clk_unprepare.
 */
void clk_disable(struct clk *clk)
{
	unsigned long flags;

	flags = clk_enable_lock();
	__clk_disable(clk);
	clk_enable_unlock(flags);
}
EXPORT_SYMBOL_GPL(clk_disable);

static int __clk_enable(struct clk *clk)
{
	int ret = 0;

	if (!clk)
		return 0;

	if (WARN_ON(clk->prepare_count == 0))
		return -ESHUTDOWN;

	if (clk->enable_count == 0) {
		ret = __clk_enable(clk->parent);

		if (ret)
			return ret;

		if (clk->ops->enable) {
			ret = clk->ops->enable(clk->hw);
			if (ret) {
				__clk_disable(clk->parent);
				return ret;
			}
		}
	}

	clk->enable_count++;
	return 0;
}

/**
 * clk_enable - ungate a clock
 * @clk: the clk being ungated
 *
 * clk_enable must not sleep, which differentiates it from clk_prepare.  In a
 * simple case, clk_enable can be used instead of clk_prepare to ungate a clk
 * if the operation will never sleep.  One example is a SoC-internal clk which
 * is controlled via simple register writes.  In the complex case a clk ungate
 * operation may require a fast and a slow part.  It is this reason that
 * clk_enable and clk_prepare are not mutually exclusive.  In fact clk_prepare
 * must be called before clk_enable.  Returns 0 on success, -EERROR
 * otherwise.
 */
int clk_enable(struct clk *clk)
{
	unsigned long flags;
	int ret;

	flags = clk_enable_lock();
	ret = __clk_enable(clk);
	clk_enable_unlock(flags);

	return ret;
}
EXPORT_SYMBOL_GPL(clk_enable);

/**
 * __clk_round_rate - round the given rate for a clk
 * @clk: round the rate of this clock
 * @rate: the rate which is to be rounded
 *
 * Caller must hold prepare_lock.  Useful for clk_ops such as .set_rate
 */
unsigned long __clk_round_rate(struct clk *clk, unsigned long rate)
{
	unsigned long parent_rate = 0;
	struct clk *parent;

	if (!clk)
		return 0;

	parent = clk->parent;
	if (parent)
		parent_rate = parent->rate;

	if (clk->ops->determine_rate)
		return clk->ops->determine_rate(clk->hw, rate, &parent_rate,
						&parent);
	else if (clk->ops->round_rate)
		return clk->ops->round_rate(clk->hw, rate, &parent_rate);
	else if (clk->flags & CLK_SET_RATE_PARENT)
		return __clk_round_rate(clk->parent, rate);
	else
		return clk->rate;
}

/**
 * clk_round_rate - round the given rate for a clk
 * @clk: the clk for which we are rounding a rate
 * @rate: the rate which is to be rounded
 *
 * Takes in a rate as input and rounds it to a rate that the clk can actually
 * use which is then returned.  If clk doesn't support round_rate operation
 * then the parent rate is returned.
 */
long clk_round_rate(struct clk *clk, unsigned long rate)
{
	unsigned long ret;

	clk_prepare_lock();
	ret = __clk_round_rate(clk, rate);
	clk_prepare_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(clk_round_rate);

/**
 * __clk_notify - call clk notifier chain
 * @clk: struct clk * that is changing rate
 * @msg: clk notifier type (see include/linux/clk.h)
 * @old_rate: old clk rate
 * @new_rate: new clk rate
 *
 * Triggers a notifier call chain on the clk rate-change notification
 * for 'clk'.  Passes a pointer to the struct clk and the previous
 * and current rates to the notifier callback.  Intended to be called by
 * internal clock code only.  Returns NOTIFY_DONE from the last driver
 * called if all went well, or NOTIFY_STOP or NOTIFY_BAD immediately if
 * a driver returns that.
 */
static int __clk_notify(struct clk *clk, unsigned long msg,
		unsigned long old_rate, unsigned long new_rate)
{
	struct clk_notifier *cn;
	struct clk_notifier_data cnd;
	int ret = NOTIFY_DONE;

	cnd.clk = clk;
	cnd.old_rate = old_rate;
	cnd.new_rate = new_rate;

	list_for_each_entry(cn, &clk_notifier_list, node) {
		if (cn->clk == clk) {
			ret = srcu_notifier_call_chain(&cn->notifier_head, msg,
					&cnd);
			break;
		}
	}

	return ret;
}

/**
 * __clk_recalc_rates
 * @clk: first clk in the subtree
 * @msg: notification type (see include/linux/clk.h)
 *
 * Walks the subtree of clks starting with clk and recalculates rates as it
 * goes.  Note that if a clk does not implement the .recalc_rate callback then
 * it is assumed that the clock will take on the rate of its parent.
 *
 * clk_recalc_rates also propagates the POST_RATE_CHANGE notification,
 * if necessary.
 *
 * Caller must hold prepare_lock.
 */
// ARM10C 20150228
// clk: kmem_cache#29-oX (mout_mspll_kfc), POST_RATE_CHANGE: 0x2
static void __clk_recalc_rates(struct clk *clk, unsigned long msg)
{
	unsigned long old_rate;
	unsigned long parent_rate = 0;
	// parent_rate: 0

	struct clk *child;

	// clk->rate: (kmem_cache#29-oX (mout_mspll_kfc))->rate: 0
	old_rate = clk->rate;
	// old_rate: 0

	// clk->parent: (kmem_cache#29-oX (mout_mspll_kfc))->parent: kmem_cache#29-oX (sclk_dpll)
	if (clk->parent)
		// parent_rate: 0, clk->parent->rate: (kmem_cache#29-oX (sclk_dpll))->rate: 600000000
		parent_rate = clk->parent->rate;
		// parent_rate: 600000000

	// clk->ops->recalc_rate: (kmem_cache#29-oX (mout_mspll_kfc))->ops->recalc_rate: NULL
	if (clk->ops->recalc_rate)
		clk->rate = clk->ops->recalc_rate(clk->hw, parent_rate);
	else
		// clk->rate: (kmem_cache#29-oX (mout_mspll_kfc))->rate: 0, parent_rate: 600000000
		clk->rate = parent_rate;
		// clk->rate: (kmem_cache#29-oX (mout_mspll_kfc))->rate: 600000000

	/*
	 * ignore NOTIFY_STOP and NOTIFY_BAD return values for POST_RATE_CHANGE
	 * & ABORT_RATE_CHANGE notifiers
	 */
	// clk->notifier_count: (kmem_cache#29-oX (mout_mspll_kfc))->notifier_count: 0, msg: 0x2
	if (clk->notifier_count && msg)
		__clk_notify(clk, msg, old_rate, clk->rate);

	// clk->children: (kmem_cache#29-oX (mout_mspll_kfc))->children
	hlist_for_each_entry(child, &clk->children, child_node)
	// for (child = hlist_entry_safe((&clk->children)->first, typeof(*(child)), child_node);
	//      child; child = hlist_entry_safe((child)->child_node.next, typeof(*(child)), child_node))

		// NOTE:
		// mout_mspll_kfc 에 등록된 children이 없을 것이라 가정하고 분석

		// hlist_entry_safe((&(kmem_cache#29-oX (mout_mspll_kfc))->children)->first, typeof(*(child)), child_node): NULL
		// child: NULL

		__clk_recalc_rates(child, msg);
}

/**
 * clk_get_rate - return the rate of clk
 * @clk: the clk whose rate is being returned
 *
 * Simply returns the cached rate of the clk, unless CLK_GET_RATE_NOCACHE flag
 * is set, which means a recalc_rate will be issued.
 * If clk is NULL then returns 0.
 */
unsigned long clk_get_rate(struct clk *clk)
{
	unsigned long rate;

	clk_prepare_lock();

	if (clk && (clk->flags & CLK_GET_RATE_NOCACHE))
		__clk_recalc_rates(clk, 0);

	rate = __clk_get_rate(clk);
	clk_prepare_unlock();

	return rate;
}
EXPORT_SYMBOL_GPL(clk_get_rate);

static int clk_fetch_parent_index(struct clk *clk, struct clk *parent)
{
	int i;

	if (!clk->parents) {
		clk->parents = kcalloc(clk->num_parents,
					sizeof(struct clk *), GFP_KERNEL);
		if (!clk->parents)
			return -ENOMEM;
	}

	/*
	 * find index of new parent clock using cached parent ptrs,
	 * or if not yet cached, use string name comparison and cache
	 * them now to avoid future calls to __clk_lookup.
	 */
	for (i = 0; i < clk->num_parents; i++) {
		if (clk->parents[i] == parent)
			return i;

		if (clk->parents[i])
			continue;

		if (!strcmp(clk->parent_names[i], parent->name)) {
			clk->parents[i] = __clk_lookup(parent->name);
			return i;
		}
	}

	return -EINVAL;
}

// ARM10C 20150131
// clk: kmem_cache#29-oX (mout_mspll_kfc), new_parent: kmem_cache#29-oX (sclk_dpll)
static void clk_reparent(struct clk *clk, struct clk *new_parent)
{
	// &clk->child_node: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
	hlist_del(&clk->child_node);

	// hlist_del에서 한일:
	// &(kmem_cache#29-oX (mout_mspll_kfc))->child_node의 next list에 pprev의 값을 연결함
	// &(kmem_cache#29-oX (mout_mspll_kfc))->child_node를 제거

	// new_parent: kmem_cache#29-oX (sclk_dpll)
	if (new_parent) {
		/* avoid duplicate POST_RATE_CHANGE notifications */
		// new_parent->new_child: (kmem_cache#29-oX (sclk_dpll))->new_child,
		// clk: kmem_cache#29-oX (mout_mspll_kfc)
		if (new_parent->new_child == clk)
			new_parent->new_child = NULL;

		// clk->child_node: (kmem_cache#29-oX (mout_mspll_kfc))->child_node,
		// new_parent->children: (kmem_cache#29-oX (sclk_dpll))->children
		hlist_add_head(&clk->child_node, &new_parent->children);

		// hlist_add_head에서 한일:
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
		//
		// (&(kmem_cache#29-oX (sclk_dpll))->children)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
	} else {
		hlist_add_head(&clk->child_node, &clk_orphan_list);
	}

	// clk->parent: (kmem_cache#29-oX (mout_mspll_kfc))->parent, new_parent: kmem_cache#29-oX (sclk_dpll)
	clk->parent = new_parent;
	// clk->parent: (kmem_cache#29-oX (mout_mspll_kfc))->parent: kmem_cache#29-oX (sclk_dpll)
}

static int __clk_set_parent(struct clk *clk, struct clk *parent, u8 p_index)
{
	unsigned long flags;
	int ret = 0;
	struct clk *old_parent = clk->parent;

	/*
	 * Migrate prepare state between parents and prevent race with
	 * clk_enable().
	 *
	 * If the clock is not prepared, then a race with
	 * clk_enable/disable() is impossible since we already have the
	 * prepare lock (future calls to clk_enable() need to be preceded by
	 * a clk_prepare()).
	 *
	 * If the clock is prepared, migrate the prepared state to the new
	 * parent and also protect against a race with clk_enable() by
	 * forcing the clock and the new parent on.  This ensures that all
	 * future calls to clk_enable() are practically NOPs with respect to
	 * hardware and software states.
	 *
	 * See also: Comment for clk_set_parent() below.
	 */
	if (clk->prepare_count) {
		__clk_prepare(parent);
		clk_enable(parent);
		clk_enable(clk);
	}

	/* update the clk tree topology */
	flags = clk_enable_lock();
	clk_reparent(clk, parent);
	clk_enable_unlock(flags);

	/* change clock input source */
	if (parent && clk->ops->set_parent)
		ret = clk->ops->set_parent(clk->hw, p_index);

	if (ret) {
		flags = clk_enable_lock();
		clk_reparent(clk, old_parent);
		clk_enable_unlock(flags);

		if (clk->prepare_count) {
			clk_disable(clk);
			clk_disable(parent);
			__clk_unprepare(parent);
		}
		return ret;
	}

	/*
	 * Finish the migration of prepare state and undo the changes done
	 * for preventing a race with clk_enable().
	 */
	if (clk->prepare_count) {
		clk_disable(clk);
		clk_disable(old_parent);
		__clk_unprepare(old_parent);
	}

	/* update debugfs with new clk tree topology */
	clk_debug_reparent(clk, parent);
	return 0;
}

/**
 * __clk_speculate_rates
 * @clk: first clk in the subtree
 * @parent_rate: the "future" rate of clk's parent
 *
 * Walks the subtree of clks starting with clk, speculating rates as it
 * goes and firing off PRE_RATE_CHANGE notifications as necessary.
 *
 * Unlike clk_recalc_rates, clk_speculate_rates exists only for sending
 * pre-rate change notifications and returns early if no clks in the
 * subtree have subscribed to the notifications.  Note that if a clk does not
 * implement the .recalc_rate callback then it is assumed that the clock will
 * take on the rate of its parent.
 *
 * Caller must hold prepare_lock.
 */
static int __clk_speculate_rates(struct clk *clk, unsigned long parent_rate)
{
	struct clk *child;
	unsigned long new_rate;
	int ret = NOTIFY_DONE;

	if (clk->ops->recalc_rate)
		new_rate = clk->ops->recalc_rate(clk->hw, parent_rate);
	else
		new_rate = parent_rate;

	/* abort rate change if a driver returns NOTIFY_BAD or NOTIFY_STOP */
	if (clk->notifier_count)
		ret = __clk_notify(clk, PRE_RATE_CHANGE, clk->rate, new_rate);

	if (ret & NOTIFY_STOP_MASK)
		goto out;

	hlist_for_each_entry(child, &clk->children, child_node) {
		ret = __clk_speculate_rates(child, new_rate);
		if (ret & NOTIFY_STOP_MASK)
			break;
	}

out:
	return ret;
}

static void clk_calc_subtree(struct clk *clk, unsigned long new_rate,
			     struct clk *new_parent, u8 p_index)
{
	struct clk *child;

	clk->new_rate = new_rate;
	clk->new_parent = new_parent;
	clk->new_parent_index = p_index;
	/* include clk in new parent's PRE_RATE_CHANGE notifications */
	clk->new_child = NULL;
	if (new_parent && new_parent != clk->parent)
		new_parent->new_child = clk;

	hlist_for_each_entry(child, &clk->children, child_node) {
		if (child->ops->recalc_rate)
			child->new_rate = child->ops->recalc_rate(child->hw, new_rate);
		else
			child->new_rate = new_rate;
		clk_calc_subtree(child, child->new_rate, NULL, 0);
	}
}

/*
 * calculate the new rates returning the topmost clock that has to be
 * changed.
 */
static struct clk *clk_calc_new_rates(struct clk *clk, unsigned long rate)
{
	struct clk *top = clk;
	struct clk *old_parent, *parent;
	unsigned long best_parent_rate = 0;
	unsigned long new_rate;
	int p_index = 0;

	/* sanity */
	if (IS_ERR_OR_NULL(clk))
		return NULL;

	/* save parent rate, if it exists */
	parent = old_parent = clk->parent;
	if (parent)
		best_parent_rate = parent->rate;

	/* find the closest rate and parent clk/rate */
	if (clk->ops->determine_rate) {
		new_rate = clk->ops->determine_rate(clk->hw, rate,
						    &best_parent_rate,
						    &parent);
	} else if (clk->ops->round_rate) {
		new_rate = clk->ops->round_rate(clk->hw, rate,
						&best_parent_rate);
	} else if (!parent || !(clk->flags & CLK_SET_RATE_PARENT)) {
		/* pass-through clock without adjustable parent */
		clk->new_rate = clk->rate;
		return NULL;
	} else {
		/* pass-through clock with adjustable parent */
		top = clk_calc_new_rates(parent, rate);
		new_rate = parent->new_rate;
		goto out;
	}

	/* some clocks must be gated to change parent */
	if (parent != old_parent &&
	    (clk->flags & CLK_SET_PARENT_GATE) && clk->prepare_count) {
		pr_debug("%s: %s not gated but wants to reparent\n",
			 __func__, clk->name);
		return NULL;
	}

	/* try finding the new parent index */
	if (parent) {
		p_index = clk_fetch_parent_index(clk, parent);
		if (p_index < 0) {
			pr_debug("%s: clk %s can not be parent of clk %s\n",
				 __func__, parent->name, clk->name);
			return NULL;
		}
	}

	if ((clk->flags & CLK_SET_RATE_PARENT) && parent &&
	    best_parent_rate != parent->rate)
		top = clk_calc_new_rates(parent, best_parent_rate);

out:
	clk_calc_subtree(clk, new_rate, parent, p_index);

	return top;
}

/*
 * Notify about rate changes in a subtree. Always walk down the whole tree
 * so that in case of an error we can walk down the whole tree again and
 * abort the change.
 */
static struct clk *clk_propagate_rate_change(struct clk *clk, unsigned long event)
{
	struct clk *child, *tmp_clk, *fail_clk = NULL;
	int ret = NOTIFY_DONE;

	if (clk->rate == clk->new_rate)
		return NULL;

	if (clk->notifier_count) {
		ret = __clk_notify(clk, event, clk->rate, clk->new_rate);
		if (ret & NOTIFY_STOP_MASK)
			fail_clk = clk;
	}

	hlist_for_each_entry(child, &clk->children, child_node) {
		/* Skip children who will be reparented to another clock */
		if (child->new_parent && child->new_parent != clk)
			continue;
		tmp_clk = clk_propagate_rate_change(child, event);
		if (tmp_clk)
			fail_clk = tmp_clk;
	}

	/* handle the new child who might not be in clk->children yet */
	if (clk->new_child) {
		tmp_clk = clk_propagate_rate_change(clk->new_child, event);
		if (tmp_clk)
			fail_clk = tmp_clk;
	}

	return fail_clk;
}

/*
 * walk down a subtree and set the new rates notifying the rate
 * change on the way
 */
static void clk_change_rate(struct clk *clk)
{
	struct clk *child;
	unsigned long old_rate;
	unsigned long best_parent_rate = 0;

	old_rate = clk->rate;

	/* set parent */
	if (clk->new_parent && clk->new_parent != clk->parent)
		__clk_set_parent(clk, clk->new_parent, clk->new_parent_index);

	if (clk->parent)
		best_parent_rate = clk->parent->rate;

	if (clk->ops->set_rate)
		clk->ops->set_rate(clk->hw, clk->new_rate, best_parent_rate);

	if (clk->ops->recalc_rate)
		clk->rate = clk->ops->recalc_rate(clk->hw, best_parent_rate);
	else
		clk->rate = best_parent_rate;

	if (clk->notifier_count && old_rate != clk->rate)
		__clk_notify(clk, POST_RATE_CHANGE, old_rate, clk->rate);

	hlist_for_each_entry(child, &clk->children, child_node) {
		/* Skip children who will be reparented to another clock */
		if (child->new_parent && child->new_parent != clk)
			continue;
		clk_change_rate(child);
	}

	/* handle the new child who might not be in clk->children yet */
	if (clk->new_child)
		clk_change_rate(clk->new_child);
}

/**
 * clk_set_rate - specify a new rate for clk
 * @clk: the clk whose rate is being changed
 * @rate: the new rate for clk
 *
 * In the simplest case clk_set_rate will only adjust the rate of clk.
 *
 * Setting the CLK_SET_RATE_PARENT flag allows the rate change operation to
 * propagate up to clk's parent; whether or not this happens depends on the
 * outcome of clk's .round_rate implementation.  If *parent_rate is unchanged
 * after calling .round_rate then upstream parent propagation is ignored.  If
 * *parent_rate comes back with a new rate for clk's parent then we propagate
 * up to clk's parent and set its rate.  Upward propagation will continue
 * until either a clk does not support the CLK_SET_RATE_PARENT flag or
 * .round_rate stops requesting changes to clk's parent_rate.
 *
 * Rate changes are accomplished via tree traversal that also recalculates the
 * rates for the clocks and fires off POST_RATE_CHANGE notifiers.
 *
 * Returns 0 on success, -EERROR otherwise.
 */
int clk_set_rate(struct clk *clk, unsigned long rate)
{
	struct clk *top, *fail_clk;
	int ret = 0;

	if (!clk)
		return 0;

	/* prevent racing with updates to the clock topology */
	clk_prepare_lock();

	/* bail early if nothing to do */
	if (rate == clk_get_rate(clk))
		goto out;

	if ((clk->flags & CLK_SET_RATE_GATE) && clk->prepare_count) {
		ret = -EBUSY;
		goto out;
	}

	/* calculate new rates and get the topmost changed clock */
	top = clk_calc_new_rates(clk, rate);
	if (!top) {
		ret = -EINVAL;
		goto out;
	}

	/* notify that we are about to change rates */
	fail_clk = clk_propagate_rate_change(top, PRE_RATE_CHANGE);
	if (fail_clk) {
		pr_warn("%s: failed to set %s rate\n", __func__,
				fail_clk->name);
		clk_propagate_rate_change(top, ABORT_RATE_CHANGE);
		ret = -EBUSY;
		goto out;
	}

	/* change the rates */
	clk_change_rate(top);

out:
	clk_prepare_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(clk_set_rate);

/**
 * clk_get_parent - return the parent of a clk
 * @clk: the clk whose parent gets returned
 *
 * Simply returns clk->parent.  Returns NULL if clk is NULL.
 */
struct clk *clk_get_parent(struct clk *clk)
{
	struct clk *parent;

	clk_prepare_lock();
	parent = __clk_get_parent(clk);
	clk_prepare_unlock();

	return parent;
}
EXPORT_SYMBOL_GPL(clk_get_parent);

/*
 * .get_parent is mandatory for clocks with multiple possible parents.  It is
 * optional for single-parent clocks.  Always call .get_parent if it is
 * available and WARN if it is missing for multi-parent clocks.
 *
 * For single-parent clocks without .get_parent, first check to see if the
 * .parents array exists, and if so use it to avoid an expensive tree
 * traversal.  If .parents does not exist then walk the tree with __clk_lookup.
 */
// ARM10C 20150117
// clk: kmem_cache#29-oX (fin)
// ARM10C 20150117
// clk: kmem_cache#29-oX (apll)
// ARM10C 20150124
// clk: kmem_cache#29-oX (epll)
// ARM10C 20150131
// clk: kmem_cache#29-oX (mout_mspll_kfc)
// ARM10C 20150131
// clk: kmem_cache#29-oX (sclk_dpll)
// ARM10C 20150228
// clk: kmem_cache#29-oX (sclk_apll)
// ARM10C 20150307
// clk: kmem_cache#29-oX (sclk_uart0)
static struct clk *__clk_init_parent(struct clk *clk)
{
	struct clk *ret = NULL;
	// ret: NULL
	// ret: NULL
	// ret: NULL
	// ret: NULL
	// ret: NULL
	// ret: NULL

	u8 index;

	/* handle the trivial cases */

	// clk->num_parents: (kmem_cache#29-oX)->num_parents: 0
	// clk->num_parents: (kmem_cache#29-oX (apll))->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents: 4
	// clk->num_parents: (kmem_cache#29-oX (sclk_dpll))->num_parents: 2
	// clk->num_parents: (kmem_cache#29-oX (sclk_apll))->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (sclk_uart0))->num_parents: 1
	if (!clk->num_parents)
		goto out;
		// goto out

	// clk->num_parents: (kmem_cache#29-oX (apll))->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents: 4
	// clk->num_parents: (kmem_cache#29-oX (sclk_dpll))->num_parents: 2
	// clk->num_parents: (kmem_cache#29-oX (sclk_apll))->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (sclk_uart0))->num_parents: 1
	if (clk->num_parents == 1) {
		// clk->parent: (kmem_cache#29-oX (apll))->parent: NULL
		// IS_ERR_OR_NULL((kmem_cache#29-oX (apll))->parent): 1
		// clk->parent: (kmem_cache#29-oX (sclk_apll))->parent: NULL
		// IS_ERR_OR_NULL((kmem_cache#29-oX (sclk_apll))->parent): 1
		// clk->parent: (kmem_cache#29-oX (sclk_uart0))->parent: NULL
		// IS_ERR_OR_NULL((kmem_cache#29-oX (sclk_uart0))->parent): 1
		if (IS_ERR_OR_NULL(clk->parent))
			// clk->parent: (kmem_cache#29-oX (apll))->parent: NULL,
			// clk->parent_names[0]: (kmem_cache#29-oX (apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
			// __clk_lookup("fin_pll"): kmem_cache#29-oX (fin_pll)
			// clk->parent: (kmem_cache#29-oX (sclk_apll))->parent: NULL,
			// clk->parent_names[0]: (kmem_cache#29-oX (sclk_apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "mout_apll"
			// __clk_lookup("mout_apll"): kmem_cache#29-oX (mout_apll)
			// clk->parent: (kmem_cache#29-oX (sclk_uart0))->parent: NULL,
			// clk->parent_names[0]: (kmem_cache#29-oX (sclk_uart0))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "dout_uart0"
			// __clk_lookup("dout_uart0"): kmem_cache#29-oX (dout_uart0)
			ret = clk->parent = __clk_lookup(clk->parent_names[0]);
			// clk->parent: (kmem_cache#29-oX (apll))->parent: kmem_cache#29-oX (fin_pll)
			// clk->parent: (kmem_cache#29-oX (sclk_apll))->parent: kmem_cache#29-oX (mout_apll)
			// clk->parent: (kmem_cache#29-oX (sclk_uart0))->parent: kmem_cache#29-oX (dout_uart0)

			// __clk_lookup에서 한일:
			// clk 의 이름이 "fin_pll"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행

			// __clk_lookup에서 한일:
			// clk 의 이름이 "mout_apll"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행

			// __clk_lookup에서 한일:
			// clk 의 이름이 "dout_uart0"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행
		
		// clk->parent: (kmem_cache#29-oX (apll))->parent: kmem_cache#29-oX (fin_pll)
		// clk->parent: (kmem_cache#29-oX (sclk_apll))->parent: kmem_cache#29-oX (mout_apll)
		// clk->parent: (kmem_cache#29-oX (sclk_uart0))->parent: kmem_cache#29-oX (dout_uart0)
		ret = clk->parent;
		// ret: kmem_cache#29-oX (fin_pll)
		// ret: kmem_cache#29-oX (mout_apll)
		// ret: kmem_cache#29-oX (dout_uart0)

		goto out;
		// goto out
		// goto out
		// goto out
	}

	// clk->ops->get_parent: (kmem_cache#29-oX (mout_mspll_kfc))->ops->get_parent: clk_mux_get_parent
	// clk->ops->get_parent: (kmem_cache#29-oX (sclk_dpll))->ops->get_parent: clk_mux_get_parent
	if (!clk->ops->get_parent) {
		WARN(!clk->ops->get_parent,
			"%s: multi-parent clocks must implement .get_parent\n",
			__func__);
		goto out;
	};

	/*
	 * Do our best to cache parent clocks in clk->parents.  This prevents
	 * unnecessary and expensive calls to __clk_lookup.  We don't set
	 * clk->parent here; that is done by the calling function
	 */

	// clk->ops->get_parent: (kmem_cache#29-oX (mout_mspll_kfc))->ops->get_parent: clk_mux_get_parent,
	// clk->hw: (kmem_cache#29-oX (mout_mspll_kfc))->hw
	// clk_mux_get_parent((kmem_cache#29-oX (mout_mspll_kfc))->hw): 0
	// clk->ops->get_parent: (kmem_cache#29-oX (sclk_dpll))->ops->get_parent: clk_mux_get_parent,
	// clk->hw: (kmem_cache#29-oX (sclk_dpll))->hw
	// clk_mux_get_parent((kmem_cache#29-oX (sclk_dpll))->hw): 1
	index = clk->ops->get_parent(clk->hw);
	// index: 0
	// index: 1

	// clk_mux_get_parent(mout_mspll_kfc) 에서 한일:
	// parents 인 "sclk_cpll", "sclk_dpll", "sclk_mpll", "sclk_spll" 값들 중에
	// register CLK_SRC_TOP7 의 값을 읽어서 mux 할 parent clock 을 선택함
	// return된 값이 선택된 parent clock의 index 값임

	// clk_mux_get_parent(sclk_dpll) 에서 한일:
	// parents 인 "fin_pll", "fout_dpll" 값들 중에
	// register CLK_SRC_TOP6 의 값을 읽어서 mux 할 parent clock 을 선택함
	// return된 값이 선택된 parent clock의 index 값임

	// clk->parents: (kmem_cache#29-oX (mout_mspll_kfc))->parents: kmem_cache#30-oX
	// clk->parents: (kmem_cache#29-oX (sclk_dpll))->parents: kmem_cache#30-oX
	if (!clk->parents)
		clk->parents =
			kcalloc(clk->num_parents, sizeof(struct clk *),
					GFP_KERNEL);

	// clk: kmem_cache#29-oX (mout_mspll_kfc), index: 0
	// clk_get_parent_by_index(kmem_cache#29-oX (mout_mspll_kfc), 0): NULL
	// clk: kmem_cache#29-oX (sclk_dpll), index: 1
	// clk_get_parent_by_index(kmem_cache#29-oX (sclk_dpll), 1): kmem_cache#29-oX (fout_dpll)
	ret = clk_get_parent_by_index(clk, index);
	// ret: NULL
	// ret: kmem_cache#29-oX (fout_dpll)

	// clk_get_parent_by_index(mout_mspll_kfc) 에서 한일:
	// parent clock 중에 선택된 parent clock의 이름으로 등록된 clk struct를 반환함

	// clk_get_parent_by_index(sclk_dpll) 에서 한일:
	// parent clock 중에 선택된 parent clock의 이름으로 등록된 clk struct를 반환함
out:
	// ret: NULL
	// ret: kmem_cache#29-oX (fin_pll)
	// ret: NULL
	// ret: kmem_cache#29-oX (fout_dpll)
	// ret: kmem_cache#29-oX (mout_apll)
	// ret: kmem_cache#29-oX (dout_uart0)
	return ret;
	// return NULL
	// return kmem_cache#29-oX (fin_pll)
	// return NULL
	// return kmem_cache#29-oX (fout_dpll)
	// return kmem_cache#29-oX (mout_apll)
	// return kmem_cache#29-oX (dout_uart0)
}

// ARM10C 20150131
// orphan: kmem_cache#29-oX (mout_mspll_kfc), clk: kmem_cache#29-oX (sclk_dpll)
void __clk_reparent(struct clk *clk, struct clk *new_parent)
{
	// clk: kmem_cache#29-oX (mout_mspll_kfc), new_parent: kmem_cache#29-oX (sclk_dpll)
	clk_reparent(clk, new_parent);

	// clk_reparent 에서 한일:
	// &(kmem_cache#29-oX (mout_mspll_kfc))->child_node의 next list에 pprev의 값을 연결함
	// &(kmem_cache#29-oX (mout_mspll_kfc))->child_node를 제거
	//
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
	//
	// (&(kmem_cache#29-oX (sclk_dpll))->children)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
	//
	// (kmem_cache#29-oX (mout_mspll_kfc))->parent: kmem_cache#29-oX (sclk_dpll)

	clk_debug_reparent(clk, new_parent); // null function

// 2015/01/31 종료
// 2015/02/28 시작

	// clk: kmem_cache#29-oX (mout_mspll_kfc), POST_RATE_CHANGE: 0x2
	__clk_recalc_rates(clk, POST_RATE_CHANGE);

	// __clk_recalc_rates에서 한일:
	// parent가 있는지 확인후 parent의 clock rate 값으로 clock rate 값을 세팅
	// clk->rate: (kmem_cache#29-oX (mout_mspll_kfc))->rate: 600000000
}

/**
 * clk_set_parent - switch the parent of a mux clk
 * @clk: the mux clk whose input we are switching
 * @parent: the new input to clk
 *
 * Re-parent clk to use parent as its new input source.  If clk is in
 * prepared state, the clk will get enabled for the duration of this call. If
 * that's not acceptable for a specific clk (Eg: the consumer can't handle
 * that, the reparenting is glitchy in hardware, etc), use the
 * CLK_SET_PARENT_GATE flag to allow reparenting only when clk is unprepared.
 *
 * After successfully changing clk's parent clk_set_parent will update the
 * clk topology, sysfs topology and propagate rate recalculation via
 * __clk_recalc_rates.
 *
 * Returns 0 on success, -EERROR otherwise.
 */
int clk_set_parent(struct clk *clk, struct clk *parent)
{
	int ret = 0;
	int p_index = 0;
	unsigned long p_rate = 0;

	if (!clk)
		return 0;

	if (!clk->ops)
		return -EINVAL;

	/* verify ops for for multi-parent clks */
	if ((clk->num_parents > 1) && (!clk->ops->set_parent))
		return -ENOSYS;

	/* prevent racing with updates to the clock topology */
	clk_prepare_lock();

	if (clk->parent == parent)
		goto out;

	/* check that we are allowed to re-parent if the clock is in use */
	if ((clk->flags & CLK_SET_PARENT_GATE) && clk->prepare_count) {
		ret = -EBUSY;
		goto out;
	}

	/* try finding the new parent index */
	if (parent) {
		p_index = clk_fetch_parent_index(clk, parent);
		p_rate = parent->rate;
		if (p_index < 0) {
			pr_debug("%s: clk %s can not be parent of clk %s\n",
					__func__, parent->name, clk->name);
			ret = p_index;
			goto out;
		}
	}

	/* propagate PRE_RATE_CHANGE notifications */
	ret = __clk_speculate_rates(clk, p_rate);

	/* abort if a driver objects */
	if (ret & NOTIFY_STOP_MASK)
		goto out;

	/* do the re-parent */
	ret = __clk_set_parent(clk, parent, p_index);

	/* propagate rate recalculation accordingly */
	if (ret)
		__clk_recalc_rates(clk, ABORT_RATE_CHANGE);
	else
		__clk_recalc_rates(clk, POST_RATE_CHANGE);

out:
	clk_prepare_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(clk_set_parent);

/**
 * __clk_init - initialize the data structures in a struct clk
 * @dev:	device initializing this clk, placeholder for now
 * @clk:	clk being initialized
 *
 * Initializes the lists in struct clk, queries the hardware for the
 * parent and rate and sets them both.
 */
// ARM10C 20150117
// dev: NULL, clk: kmem_cache#29-oX (fin)
// ARM10C 20150117
// dev: NULL, clk: kmem_cache#29-oX (apll)
// ARM10C 20150124
// dev: NULL, clk: kmem_cache#29-oX (epll)
// ARM10C 20150131
// dev: NULL, clk: kmem_cache#29-oX (mout_mspll_kfc)
// ARM10C 20150131
// dev: NULL, clk: kmem_cache#29-oX (sclk_spll)
// ARM10C 20150228
// dev: NULL, clk: kmem_cache#29-oX (sclk_apll)
// ARM10C 20150307
// dev: NULL, clk: kmem_cache#29-oX (sclk_uart0)
int __clk_init(struct device *dev, struct clk *clk)
{
	int i, ret = 0;
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0

	struct clk *orphan;
	struct hlist_node *tmp2;

	// clk: kmem_cache#29-oX (fin)
	// clk: kmem_cache#29-oX (apll)
	// clk: kmem_cache#29-oX (epll)
	// clk: kmem_cache#29-oX (mout_mspll_kfc)
	// clk: kmem_cache#29-oX (sclk_spll)
	// clk: kmem_cache#29-oX (sclk_apll)
	// clk: kmem_cache#29-oX (sclk_uart0)
	if (!clk)
		return -EINVAL;

	clk_prepare_lock();

	// clk_prepare_lock 에서 한일:
	// &prepare_lock을 이용한 mutex lock 수행
	// prepare_owner: &init_task
	// prepare_refcnt: 1

	// clk_prepare_lock 에서 한일:
	// &prepare_lock을 이용한 mutex lock 수행
	// prepare_owner: &init_task
	// prepare_refcnt: 1

	// clk_prepare_lock 에서 한일:
	// &prepare_lock을 이용한 mutex lock 수행
	// prepare_owner: &init_task
	// prepare_refcnt: 1

	// clk_prepare_lock 에서 한일:
	// &prepare_lock을 이용한 mutex lock 수행
	// prepare_owner: &init_task
	// prepare_refcnt: 1

	// clk_prepare_lock 에서 한일:
	// &prepare_lock을 이용한 mutex lock 수행
	// prepare_owner: &init_task
	// prepare_refcnt: 1

	// clk_prepare_lock 에서 한일:
	// &prepare_lock을 이용한 mutex lock 수행
	// prepare_owner: &init_task
	// prepare_refcnt: 1

	// clk_prepare_lock 에서 한일:
	// &prepare_lock을 이용한 mutex lock 수행
	// prepare_owner: &init_task
	// prepare_refcnt: 1

	/* check to see if a clock with this name is already registered */
	// clk->name: (kmem_cache#29-oX (fin))->name: kmem_cache#30-oX ("fin_pll")
	// __clk_lookup(kmem_cache#30-oX (fin)): NULL
	// clk->name: (kmem_cache#29-oX (apll))->name: kmem_cache#30-oX ("fout_apll")
	// __clk_lookup(kmem_cache#30-oX (apll)): NULL
	// clk->name: (kmem_cache#29-oX (epll))->name: kmem_cache#30-oX ("fout_epll")
	// __clk_lookup(kmem_cache#30-oX (epll)): NULL
	// clk->name: (kmem_cache#29-oX (mout_mspll_kfc))->name: kmem_cache#30-oX ("mout_mspll_kfc")
	// __clk_lookup(kmem_cache#30-oX (mout_mspll_kfc)): NULL
	// clk->name: (kmem_cache#29-oX (sclk_spll))->name: kmem_cache#30-oX ("sclk_spll")
	// __clk_lookup(kmem_cache#30-oX (sclk_spll)): NULL
	// clk->name: (kmem_cache#29-oX (sclk_apll))->name: kmem_cache#30-oX ("sclk_apll")
	// __clk_lookup(kmem_cache#30-oX (sclk_apll)): NULL
	// clk->name: (kmem_cache#29-oX (sclk_uart0))->name: kmem_cache#30-oX ("sclk_uart0")
	// __clk_lookup(kmem_cache#30-oX (sclk_uart0)): NULL
	if (__clk_lookup(clk->name)) {
		pr_debug("%s: clk %s already initialized\n",
				__func__, clk->name);
		ret = -EEXIST;
		goto out;
	}

	/* check that clk_ops are sane.  See Documentation/clk.txt */
	// clk->ops->set_rate: (kmem_cache#29-oX (fin))->ops->set_rate: NULL,
	// clk->ops->round_rate: (kmem_cache#29-oX (fin))->ops->round_rate: NULL,
	// clk->ops->determine_rate: (kmem_cache#29-oX (fin))->ops->determine_rate: NULL,
	// clk->ops->recalc_rate: (kmem_cache#29-oX (fin))->ops->recalc_rate: clk_fixed_rate_recalc_rate
	// clk->ops->set_rate: (kmem_cache#29-oX (apll))->ops->set_rate: NULL,
	// clk->ops->round_rate: (kmem_cache#29-oX (apll))->ops->round_rate: NULL,
	// clk->ops->determine_rate: (kmem_cache#29-oX (apll))->ops->determine_rate: NULL,
	// clk->ops->recalc_rate: (kmem_cache#29-oX (apll))->ops->recalc_rate: samsung_pll35xx_recalc_rate
	// clk->ops->set_rate: (kmem_cache#29-oX (epll))->ops->set_rate: NULL,
	// clk->ops->round_rate: (kmem_cache#29-oX (epll))->ops->round_rate: NULL,
	// clk->ops->determine_rate: (kmem_cache#29-oX (epll))->ops->determine_rate: NULL,
	// clk->ops->recalc_rate: (kmem_cache#29-oX (epll))->ops->recalc_rate: samsung_pll36xx_recalc_rate
	// clk->ops->set_rate: (kmem_cache#29-oX (mout_mspll_kfc))->ops->set_rate: NULL,
	// clk->ops->round_rate: (kmem_cache#29-oX (mout_mspll_kfc))->ops->round_rate: NULL,
	// clk->ops->determine_rate: (kmem_cache#29-oX (mout_mspll_kfc))->ops->determine_rate: __clk_mux_determine_rate,
	// clk->ops->recalc_rate: (kmem_cache#29-oX (mout_mspll_kfc))->ops->recalc_rate: NULL
	// clk->ops->set_rate: (kmem_cache#29-oX (sclk_spll))->ops->set_rate: NULL,
	// clk->ops->round_rate: (kmem_cache#29-oX (sclk_spll))->ops->round_rate: NULL,
	// clk->ops->determine_rate: (kmem_cache#29-oX (sclk_spll))->ops->determine_rate: __clk_mux_determine_rate,
	// clk->ops->recalc_rate: (kmem_cache#29-oX (sclk_spll))->ops->recalc_rate: NULL
	// clk->ops->set_rate: (kmem_cache#29-oX (sclk_apll))->ops->set_rate: clk_divider_set_rate,
	// clk->ops->round_rate: (kmem_cache#29-oX (sclk_apll))->ops->round_rate: clk_divider_round_rate,
	// clk->ops->determine_rate: (kmem_cache#29-oX (sclk_apll))->ops->determine_rate: NULL,
	// clk->ops->recalc_rate: (kmem_cache#29-oX (sclk_apll))->ops->recalc_rate: clk_divider_recalc_rate
	// clk->ops->set_rate: (kmem_cache#29-oX (sclk_uart0))->ops->set_rate: NULL,
	// clk->ops->round_rate: (kmem_cache#29-oX (sclk_uart0))->ops->round_rate: NULL,
	// clk->ops->determine_rate: (kmem_cache#29-oX (sclk_uart0))->ops->determine_rate: NULL,
	// clk->ops->recalc_rate: (kmem_cache#29-oX (sclk_uart0))->ops->recalc_rate:NULL 
	if (clk->ops->set_rate &&
	    !((clk->ops->round_rate || clk->ops->determine_rate) &&
	      clk->ops->recalc_rate)) {
		pr_warning("%s: %s must implement .round_rate or .determine_rate in addition to .recalc_rate\n",
				__func__, clk->name);
		ret = -EINVAL;
		goto out;
	}

	// clk->ops->set_parent: (kmem_cache#29-oX (fin))->ops->set_parent: NULL,
	// clk->ops->get_parent: (kmem_cache#29-oX (fin))->ops->get_parent: NULL
	// clk->ops->set_parent: (kmem_cache#29-oX (apll))->ops->set_parent: NULL,
	// clk->ops->get_parent: (kmem_cache#29-oX (apll))->ops->get_parent: NULL
	// clk->ops->set_parent: (kmem_cache#29-oX (epll))->ops->set_parent: NULL,
	// clk->ops->get_parent: (kmem_cache#29-oX (epll))->ops->get_parent: NULL
	// clk->ops->set_parent: (kmem_cache#29-oX (mout_mspll_kfc))->ops->set_parent: clk_mux_set_parent,
	// clk->ops->get_parent: (kmem_cache#29-oX (mout_mspll_kfc))->ops->get_parent: clk_mux_get_parent
	// clk->ops->set_parent: (kmem_cache#29-oX (sclk_spll))->ops->set_parent: clk_mux_set_parent,
	// clk->ops->get_parent: (kmem_cache#29-oX (sclk_spll))->ops->get_parent: clk_mux_get_parent
	// clk->ops->set_parent: (kmem_cache#29-oX (sclk_apll))->ops->set_parent: NULL,
	// clk->ops->get_parent: (kmem_cache#29-oX (sclk_apll))->ops->get_parent: NULL
	// clk->ops->set_parent: (kmem_cache#29-oX (sclk_uart0))->ops->set_parent: NULL,
	// clk->ops->get_parent: (kmem_cache#29-oX (sclk_uart0))->ops->get_parent: NULL
	if (clk->ops->set_parent && !clk->ops->get_parent) {
		pr_warning("%s: %s must implement .get_parent & .set_parent\n",
				__func__, clk->name);
		ret = -EINVAL;
		goto out;
	}

	/* throw a WARN if any entries in parent_names are NULL */
	// clk->num_parents: (kmem_cache#29-oX (fin))->num_parents: 0
	// clk->num_parents: (kmem_cache#29-oX (apll))->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (epll))->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents: 4
	// clk->num_parents: (kmem_cache#29-oX (sclk_spll))->num_parents: 2
	// clk->num_parents: (kmem_cache#29-oX (sclk_apll))->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (sclk_uart0))->num_parents: 1
	for (i = 0; i < clk->num_parents; i++)
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (epll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "sclk_cpll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (sclk_spll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (sclk_apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "mout_apll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (sclk_uart0))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "dout_uart0"
		WARN(!clk->parent_names[i],
				"%s: invalid NULL in %s's .parent_names\n",
				__func__, clk->name);

		// mout_mspll_kfc 의 경우 i: 1...3 루프 수행
		// sclk_spll의 경우 i: 1 루프 수행
		// sclk_apll의 경우 루프 종료
		// sclk_uart0의 경우 루프 종료

	/*
	 * Allocate an array of struct clk *'s to avoid unnecessary string
	 * look-ups of clk's possible parents.  This can fail for clocks passed
	 * in to clk_init during early boot; thus any access to clk->parents[]
	 * must always check for a NULL pointer and try to populate it if
	 * necessary.
	 *
	 * If clk->parents is not NULL we skip this entire block.  This allows
	 * for clock drivers to statically initialize clk->parents.
	 */
	// clk->num_parents: (kmem_cache#29-oX (fin))->num_parents: 0,
	// clk->parents: (kmem_cache#29-oX (fin))->parents: NULL
	// clk->num_parents: (kmem_cache#29-oX (apll))->num_parents: 1,
	// clk->parents: (kmem_cache#29-oX (apll))->parents: NULL
	// clk->num_parents: (kmem_cache#29-oX (epll))->num_parents: 1,
	// clk->parents: (kmem_cache#29-oX (epll))->parents: NULL
	// clk->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents: 4,
	// clk->parents: (kmem_cache#29-oX (mout_mspll_kfc))->parents: NULL
	// clk->num_parents: (kmem_cache#29-oX (sclk_spll))->num_parents: 2,
	// clk->parents: (kmem_cache#29-oX (sclk_spll))->parents: NULL
	// clk->num_parents: (kmem_cache#29-oX (sclk_apll))->num_parents: 1,
	// clk->parents: (kmem_cache#29-oX (sclk_apll))->parents: NULL
	// clk->num_parents: (kmem_cache#29-oX (sclk_uart0))->num_parents: 1,
	// clk->parents: (kmem_cache#29-oX (sclk_uart0))->parents: NULL
	if (clk->num_parents > 1 && !clk->parents) {
		// clk->parents: (kmem_cache#29-oX (mout_mspll_kfc))->parents
		// clk->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents: 4,
		// sizeof(struct clk *): 4, GFP_KERNEL: 0xD0
		// kcalloc(4, 4, GFP_KERNEL: 0xD0): kmem_cache#30-oX
		// clk->parents: (kmem_cache#29-oX (sclk_spll))->parents
		// clk->num_parents: (kmem_cache#29-oX (sclk_spll))->num_parents: 2,
		// sizeof(struct clk *): 4, GFP_KERNEL: 0xD0
		// kcalloc(4, 4, GFP_KERNEL: 0xD0): kmem_cache#30-oX
		clk->parents = kcalloc(clk->num_parents, sizeof(struct clk *),
					GFP_KERNEL);
		// clk->parents: (kmem_cache#29-oX (mout_mspll_kfc))->parents: kmem_cache#30-oX
		// clk->parents: (kmem_cache#29-oX (sclk_spll))->parents: kmem_cache#30-oX

		/*
		 * __clk_lookup returns NULL for parents that have not been
		 * clk_init'd; thus any access to clk->parents[] must check
		 * for a NULL pointer.  We can always perform lazy lookups for
		 * missing parents later on.
		 */
		// clk->parents: (kmem_cache#29-oX (mout_mspll_kfc))->parents: kmem_cache#30-oX
		// clk->parents: (kmem_cache#29-oX (sclk_spll))->parents: kmem_cache#30-oX
		if (clk->parents)
			// clk->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents: 4
			// clk->num_parents: (kmem_cache#29-oX (sclk_spll))->num_parents: 2
			for (i = 0; i < clk->num_parents; i++)
				// i: 0, clk->parents[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parents[0]: (kmem_cache#30-oX)[0]
				// clk->parent_names[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "sclk_cpll"
				// __clk_lookup("sclk_cpll"): NULL
				// i: 0, clk->parents[0]: (kmem_cache#29-oX (sclk_spll))->parents[0]: (kmem_cache#30-oX)[0]
				// clk->parent_names[0]: (kmem_cache#29-oX (sclk_spll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
				// __clk_lookup("fin_pll"): kmem_cache#29-oX (fin_pll)
				clk->parents[i] =
					__clk_lookup(clk->parent_names[i]);
				// clk->parents[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parents[0]: (kmem_cache#30-oX)[0]: NULL
				// clk->parents[0]: (kmem_cache#29-oX (sclk_spll))->parents[0]: (kmem_cache#30-oX)[0]: kmem_cache#29-oX (fin_pll)

				// mout_mspll_kfc 경우 i: 1...3 루프 수행
				// sclk_spll 경우 i: 1 루프 수행

			// clk->parents[0...3]: (kmem_cache#29-oX (mout_mspll_kfc))->parents[0...3]: (kmem_cache#30-oX)[0...3]: NULL
			// clk->parents[0]: (kmem_cache#29-oX (sclk_spll))->parents[0]: (kmem_cache#30-oX)[0]: kmem_cache#29-oX (fin_pll)
			// clk->parents[1]: (kmem_cache#29-oX (sclk_spll))->parents[1]: (kmem_cache#30-oX)[1]: kmem_cache#29-oX (fout_spll)
	}

	// clk->parent: (kmem_cache#29-oX (fin))->parent, clk: kmem_cache#29-oX (fin)
	// __clk_init_parent(kmem_cache#29-oX (fin)): NULL
	// clk->parent: (kmem_cache#29-oX (apll))->parent, clk: kmem_cache#29-oX (apll)
	// __clk_init_parent(kmem_cache#29-oX (apll)): kmem_cache#29-oX (fin_pll)
	// clk->parent: (kmem_cache#29-oX (epll))->parent, clk: kmem_cache#29-oX (epll)
	// __clk_init_parent(kmem_cache#29-oX (epll)): kmem_cache#29-oX (fin_pll)
	// clk->parent: (kmem_cache#29-oX (mout_mspll_kfc))->parent, clk: kmem_cache#29-oX (mout_mspll_kfc)
	// __clk_init_parent(kmem_cache#29-oX (mout_mspll_kfc)): NULL
	// clk->parent: (kmem_cache#29-oX (sclk_spll))->parent, clk: kmem_cache#29-oX (sclk_spll)
	// __clk_init_parent(kmem_cache#29-oX (sclk_spll)): kmem_cache#29-oX (fout_spll)
	// clk->parent: (kmem_cache#29-oX (sclk_apll))->parent, clk: kmem_cache#29-oX (sclk_apll)
	// __clk_init_parent(kmem_cache#29-oX (sclk_apll)): kmem_cache#29-oX (mout_apll)
	// clk->parent: (kmem_cache#29-oX (sclk_uart0))->parent, clk: kmem_cache#29-oX (sclk_uart0)
	// __clk_init_parent(kmem_cache#29-oX (sclk_uart0)): kmem_cache#29-oX (dout_uart0)
	clk->parent = __clk_init_parent(clk);
	// clk->parent: (kmem_cache#29-oX (fin))->parent: NULL
	// clk->parent: (kmem_cache#29-oX (apll))->parent: kmem_cache#29-oX (fin_pll)
	// clk->parent: (kmem_cache#29-oX (epll))->parent: kmem_cache#29-oX (fin_pll)
	// clk->parent: (kmem_cache#29-oX (mout_mspll_kfc))->parent: NULL
	// clk->parent: (kmem_cache#29-oX (sclk_spll))->parent: kmem_cache#29-oX (fout_spll)
	// clk->parent: (kmem_cache#29-oX (sclk_apll))->parent: kmem_cache#29-oX (mout_apll)
	// clk->parent: (kmem_cache#29-oX (sclk_uart0))->parent: kmem_cache#29-oX (dout_uart0)

	// __clk_init_parent(mout_mspll_kfc) 에서 한일:
	// parents 인 "sclk_cpll", "sclk_dpll", "sclk_mpll", "sclk_spll" 값들 중에
	// register CLK_SRC_TOP7 의 값을 읽어서 mux 할 parent clock 을 선택함
	// return된 값이 선택된 parent clock의 index 값임
	// parent clock 중에 선택된 parent clock의 이름으로 등록된 clk struct를 반환함

	// __clk_init_parent(sclk_dpll) 에서 한일:
	// parents 인 "fin_pll", "fout_spll" 값들 중에
	// register CLK_SRC_TOP6 의 값을 읽어서 mux 할 parent clock 을 선택함
	// return된 값이 선택된 parent clock의 index 값임
	// parent clock 중에 선택된 parent clock의 이름으로 등록된 clk struct를 반환함

	// __clk_init_parent(sclk_apll) 에서 한일:
	// clk 의 이름이 "mout_apll"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행

	// __clk_init_parent(sclk_uart0) 에서 한일:
	// clk 의 이름이 "dout_uart0"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행

	/*
	 * Populate clk->parent if parent has already been __clk_init'd.  If
	 * parent has not yet been __clk_init'd then place clk in the orphan
	 * list.  If clk has set the CLK_IS_ROOT flag then place it in the root
	 * clk list.
	 *
	 * Every time a new clk is clk_init'd then we walk the list of orphan
	 * clocks and re-parent any that are children of the clock currently
	 * being clk_init'd.
	 */
	// clk->parent: (kmem_cache#29-oX (fin))->parent: NULL,
	// clk->flags: (kmem_cache#29-oX (fin))->flags: 0x30
	// clk->parent: (kmem_cache#29-oX (apll))->parent: kmem_cache#29-oX (fin_pll)
	// clk->flags: (kmem_cache#29-oX (apll))->flags: 0x40
	// clk->parent: (kmem_cache#29-oX (epll))->parent: kmem_cache#29-oX (fin_pll)
	// clk->flags: (kmem_cache#29-oX (epll))->flags: 0x40
	// clk->parent: (kmem_cache#29-oX (mout_mspll_kfc))->parent: NULL
	// clk->flags: (kmem_cache#29-oX (mout_mspll_kfc))->flags: 0xa0
	// clk->parent: (kmem_cache#29-oX (sclk_spll))->parent: kmem_cache#29-oX (fout_spll)
	// clk->flags: (kmem_cache#29-oX (sclk_spll))->flags: 0xa0
	// clk->parent: (kmem_cache#29-oX (sclk_apll))->parent: kmem_cache#29-oX (mout_apll)
	// clk->flags: (kmem_cache#29-oX (sclk_apll))->flags: 0x0
	// clk->parent: (kmem_cache#29-oX (sclk_uart0))->parent: kmem_cache#29-oX (dout_uart0)
	// clk->flags: (kmem_cache#29-oX (sclk_uart0))->flags: 0x24
	if (clk->parent)
		// &clk->child_node: &(kmem_cache#29-oX (apll))->child_node,
		// &clk->parent->children: (&kmem_cache#29-oX (fin_pll))->children
		// &clk->child_node: &(kmem_cache#29-oX (epll))->child_node,
		// &clk->parent->children: (&kmem_cache#29-oX (fin_pll))->children
		// &clk->child_node: &(kmem_cache#29-oX (sclk_spll))->child_node,
		// &clk->parent->children: (&kmem_cache#29-oX (fout_spll))->children
		// &clk->child_node: &(kmem_cache#29-oX (sclk_apll))->child_node,
		// &clk->parent->children: (&kmem_cache#29-oX (mout_apll))->children
		// &clk->child_node: &(kmem_cache#29-oX (sclk_uart0))->child_node,
		// &clk->parent->children: (&kmem_cache#29-oX (dout_uart0))->children
		hlist_add_head(&clk->child_node,
				&clk->parent->children);

		// hlist_add_head에서 한일:
		// (&(kmem_cache#29-oX (apll))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (apll))->child_node)->pprev: &(&(kmem_cache#29-oX (apll))->child_node)
		//
		// (&(kmem_cache#29-oX (fin_pll))->children)->first: &(kmem_cache#29-oX (apll))->child_node

		// hlist_add_head에서 한일:
		// (&(kmem_cache#29-oX (epll))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (epll))->child_node)->pprev: &(&(kmem_cache#29-oX (epll))->child_node)
		//
		// (&(kmem_cache#29-oX (fin_pll))->children)->first: &(kmem_cache#29-oX (epll))->child_node

		// hlist_add_head에서 한일:
		// (&(kmem_cache#29-oX (sclk_spll))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_spll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_spll))->child_node)
		//
		// (&(kmem_cache#29-oX (fout_spll))->children)->first: &(kmem_cache#29-oX (sclk_spll))->child_node

		// hlist_add_head에서 한일:
		// (&(kmem_cache#29-oX (sclk_apll))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_apll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_apll))->child_node)
		//
		// (&(kmem_cache#29-oX (mout_apll))->children)->first: &(kmem_cache#29-oX (sclk_apll))->child_node

		// hlist_add_head에서 한일:
		// (&(kmem_cache#29-oX (sclk_uart0))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_uart0))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_uart0))->child_node)
		//
		// (&(kmem_cache#29-oX (dout_uart0))->children)->first: &(kmem_cache#29-oX (sclk_uart0))->child_node
	else if (clk->flags & CLK_IS_ROOT)
		// &clk->child_node: &(kmem_cache#29-oX (fin))->child_node
		hlist_add_head(&clk->child_node, &clk_root_list);

		// hlist_add_head에서 한일:
		// (&(kmem_cache#29-oX (fin))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (fin))->child_node)->pprev: &(&(kmem_cache#29-oX (fin))->child_node)
		//
		// (&clk_root_list)->first: &(kmem_cache#29-oX (fin))->child_node
	else
		// &clk->child_node: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
		hlist_add_head(&clk->child_node, &clk_orphan_list);

		// hlist_add_head에서 한일:
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
		//
		// (&clk_orphan_list)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node

	/*
	 * Set clk's rate.  The preferred method is to use .recalc_rate.  For
	 * simple clocks and lazy developers the default fallback is to use the
	 * parent's rate.  If a clock doesn't have a parent (or is orphaned)
	 * then rate is set to zero.
	 */
// 2015/01/17 종료
// 2015/01/24 시작

	// clk->ops->recalc_rate: (kmem_cache#29-oX (fin))->ops->recalc_rate: clk_fixed_rate_recalc_rate
	// clk->ops->recalc_rate: (kmem_cache#29-oX (apll))->ops->recalc_rate: samsung_pll35xx_recalc_rate
	// clk->ops->recalc_rate: (kmem_cache#29-oX (epll))->ops->recalc_rate: samsung_pll36xx_recalc_rate
	// clk->ops->recalc_rate: (kmem_cache#29-oX (mout_mspll_kfc))->ops->recalc_rate: NULL
	// clk->parent: (kmem_cache#29-oX (mout_mspll_kfc))->parent: NULL
	// clk->ops->recalc_rate: (kmem_cache#29-oX (sclk_spll))->ops->recalc_rate: NULL
	// clk->parent: (kmem_cache#29-oX (sclk_spll))->parent: kmem_cache#29-oX (fout_spll)
	// clk->ops->recalc_rate: (kmem_cache#29-oX (sclk_apll))->ops->recalc_rate: clk_divider_recalc_rate
	// clk->ops->recalc_rate: (kmem_cache#29-oX (sclk_uart0))->ops->recalc_rate: NULL
	// clk->parent: (kmem_cache#29-oX (sclk_uart0))->parent: kmem_cache#29-oX (dout_uart0)
	if (clk->ops->recalc_rate)
		// clk->rate: (kmem_cache#29-oX)->rate,
		// clk->ops->recalc_rate: (kmem_cache#29-oX)->ops->recalc_rate: clk_fixed_rate_recalc_rate
		// clk->hw: (kmem_cache#29-oX)->hw: &(kmem_cache#30-oX)->hw,
		// clk->parent: (kmem_cache#29-oX)->parent: NULL, __clk_get_rate(NULL): 0
		// clk_fixed_rate_recalc_rate(&(kmem_cache#30-oX)->hw, 0): 24000000
		// clk->rate: (kmem_cache#29-oX (apll))->rate,
		// clk->ops->recalc_rate: (kmem_cache#29-oX (apll))->ops->recalc_rate: samsung_pll35xx_recalc_rate
		// clk->hw: (kmem_cache#29-oX (apll))->hw: &(kmem_cache#30-oX (apll))->hw,
		// clk->parent: (kmem_cache#29-oX (apll))->parent: kmem_cache#29-oX (fin_pll),
		// __clk_get_rate(kmem_cache#29-oX (fin_pll)): 24000000
		// samsung_pll35xx_recalc_rate(&(kmem_cache#30-oX (apll))->hw, 24000000): 1000000000
		// clk->rate: (kmem_cache#29-oX (epll))->rate,
		// clk->ops->recalc_rate: (kmem_cache#29-oX (epll))->ops->recalc_rate: samsung_pll36xx_recalc_rate
		// clk->hw: (kmem_cache#29-oX (epll))->hw: &(kmem_cache#30-oX (epll))->hw,
		// clk->parent: (kmem_cache#29-oX (epll))->parent: kmem_cache#29-oX (fin_pll),
		// __clk_get_rate(kmem_cache#29-oX (fin_pll)): 24000000
		// samsung_pll36xx_recalc_rate(&(kmem_cache#30-oX (epll))->hw, 24000000): 191999389
		// clk->hw: (kmem_cache#29-oX (sclk_apll))->hw: &(kmem_cache#30-oX (sclk_apll))->hw,
		// clk->parent: (kmem_cache#29-oX (sclk_apll))->parent: kmem_cache#29-oX (mout_apll),
		// __clk_get_rate(kmem_cache#29-oX (mout_apll)): 800000000
		// clk_divider_recalc_rate(&(kmem_cache#30-oX (sclk_apll))->hw, 800000000): 800000000
		clk->rate = clk->ops->recalc_rate(clk->hw,
				__clk_get_rate(clk->parent));
		// clk->rate: (kmem_cache#29-oX (fin))->rate: 24000000
		// clk->rate: (kmem_cache#29-oX (apll))->rate: 1000000000
		// clk->rate: (kmem_cache#29-oX (epll))->rate: 191999389
		// clk->rate: (kmem_cache#29-oX (sclk_apll))->rate: 800000000

		// clk_divider_recalc_rate에서 한일:
		// register CLK_DIV_CPU0 의 값을 읽어 APLL_RATIO[26:24]: CLKDIV_APLL clock divider ratio을 구함.
		// SCLK_APLL = MOUT_APLL/(APLL_RATIO + 1) 공식으로 clock div가 수행됨
	else if (clk->parent)
		// NOTE:
		// fout_dpll의 값을 600 Mhz 가정하고 분석 (5420 arndale board 로그 참고)

		// NOTE:
		// sclk_uart0의 값을 266 Mhz 가정하고 분석 (5420 arndale board 로그 참고)

		// clk->rate: (kmem_cache#29-oX (sclk_dpll))->rate,
		// clk->parent->rate: ((kmem_cache#29-oX (sclk_dpll))->parent)->rate: (kmem_cache#29-oX (fout_dpll))->rate: 1000000000
		// clk->rate: (kmem_cache#29-oX (sclk_uart0))->rate,
		// clk->parent->rate: ((kmem_cache#29-oX (sclk_uart0))->parent)->rate: (kmem_cache#29-oX (dout_uart0))->rate: 266000000
		clk->rate = clk->parent->rate;
		// clk->rate: (kmem_cache#29-oX (sclk_dpll))->rate: 600000000
		// clk->rate: (kmem_cache#29-oX (sclk_uart0))->rate: 266000000
	else
		// clk->rate: (kmem_cache#29-oX (mout_mspll_kfc))->rate
		clk->rate = 0;
		// clk->rate: (kmem_cache#29-oX (mout_mspll_kfc))->rate: 0

	/*
	 * walk the list of orphan clocks and reparent any that are children of
	 * this clock
	 */
	hlist_for_each_entry_safe(orphan, tmp2, &clk_orphan_list, child_node) {
	// for (orphan = hlist_entry_safe((&clk_orphan_list)->first, typeof(*orphan), child_node);
	//      orphan && ({ tmp2 = orphan->child_node.next; 1; }); orphan = hlist_entry_safe(tmp2, typeof(*orphan), child_node))

		// hlist_entry_safe((&clk_orphan_list)->first, typeof(*orphan), child_node): NULL
		// orphan: NULL

		// hlist_entry_safe(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node, typeof(*orphan), child_node): kmem_cache#29-oX (mout_mspll_kfc)
		// orphan: kmem_cache#29-oX (mout_mspll_kfc)

		// hlist_entry_safe(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node, typeof(*orphan), child_node): kmem_cache#29-oX (mout_mspll_kfc)
		// orphan: kmem_cache#29-oX (mout_mspll_kfc)

		// orphan->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents: 4,
		// orphan->ops->get_parent: clk_mux_get_parent
		// orphan->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents: 4,
		// orphan->ops->get_parent: clk_mux_get_parent
		if (orphan->num_parents && orphan->ops->get_parent) {
			// orphan->ops->get_parent: clk_mux_get_parent
			// orphan->hw: (kmem_cache#29-oX (mout_mspll_kfc))->hw
			// clk_mux_get_parent((kmem_cache#29-oX (mout_mspll_kfc))->hw): 0
			// orphan->ops->get_parent: clk_mux_get_parent
			// orphan->hw: (kmem_cache#29-oX (mout_mspll_kfc))->hw
			// clk_mux_get_parent((kmem_cache#29-oX (mout_mspll_kfc))->hw): 0
			i = orphan->ops->get_parent(orphan->hw);
			// i: 0
			// i: 0

			// clk->name: (kmem_cache#29-oX (mout_mspll_kfc))->name: kmem_cache#30-oX ("mout_mspll_kfc")
			// i: 0, orphan->parent_names[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "sclk_cpll"
			// clk->name: (kmem_cache#29-oX (mout_mspll_kfc))->name: kmem_cache#30-oX ("mout_mspll_kfc")
			// i: 0, orphan->parent_names[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "sclk_cpll"
			if (!strcmp(clk->name, orphan->parent_names[i]))
				__clk_reparent(orphan, clk);
			continue;
		}

		// orphan->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents: 4
		// orphan->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents: 4
		for (i = 0; i < orphan->num_parents; i++)
			// i: 0, clk->name: (kmem_cache#29-oX (mout_mspll_kfc))->name: kmem_cache#30-oX ("mout_mspll_kfc")
			// orphan->parent_names[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "sclk_cpll"
			// strcmp("mout_mspll_kfc", "sclk_cpll"): -1
			// i: 1, clk->name: (kmem_cache#29-oX (sclk_spll))->name: kmem_cache#30-oX ("sclk_spll")
			// orphan->parent_names[1]: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[1]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "sclk_spll"
			// strcmp("sclk_dpll", "sclk_spll"): 0
			if (!strcmp(clk->name, orphan->parent_names[i])) {
				// orphan: kmem_cache#29-oX (mout_mspll_kfc), clk: kmem_cache#29-oX (sclk_dpll)
				__clk_reparent(orphan, clk);

				// __clk_reparent 에서 한일:
				// &(kmem_cache#29-oX (mout_mspll_kfc))->child_node의 next list에 pprev의 값을 연결함
				// &(kmem_cache#29-oX (mout_mspll_kfc))->child_node를 제거
				//
				// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
				// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
				//
				// (&(kmem_cache#29-oX (sclk_spll))->children)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
				//
				// (kmem_cache#29-oX (mout_mspll_kfc))->parent: kmem_cache#29-oX (sclk_spll)
				//
				// parent가 있는지 확인후 parent의 clock rate 값으로 clock rate 값을 세팅
				// clk->rate: (kmem_cache#29-oX (mout_mspll_kfc))->rate: 600000000

				break;
				// break 수행
			}
			// i: 1...3 루프 수행
	 }

	/*
	 * optional platform-specific magic
	 *
	 * The .init callback is not used by any of the basic clock types, but
	 * exists for weird hardware that must perform initialization magic.
	 * Please consider other ways of solving initialization problems before
	 * using this callback, as its use is discouraged.
	 */
	// clk->ops->init: (kmem_cache#29-oX (fin))->ops->init: NULL
	// clk->ops->init: (kmem_cache#29-oX (apll))->ops->init: NULL
	// clk->ops->init: (kmem_cache#29-oX (epll))->ops->init: NULL
	// clk->ops->init: (kmem_cache#29-oX (mout_mspll_kfc))->ops->init: NULL
	// clk->ops->init: (kmem_cache#29-oX (sclk_spll))->ops->init: NULL
	// clk->ops->init: (kmem_cache#29-oX (sclk_apll))->ops->init: NULL
	// clk->ops->init: (kmem_cache#29-oX (sclk_uart0))->ops->init: NULL
	if (clk->ops->init)
		clk->ops->init(clk->hw);

	// clk: kmem_cache#29-oX (fin)
	// clk: kmem_cache#29-oX (apll)
	// clk: kmem_cache#29-oX (epll)
	// clk: kmem_cache#29-oX (mout_mspll_kfc)
	// clk: kmem_cache#29-oX (sclk_spll)
	// clk: kmem_cache#29-oX (sclk_apll)
	// clk: kmem_cache#29-oX (sclk_uart0)
	clk_debug_register(clk); // null function

out:
	clk_prepare_unlock();

	// clk_prepare_unlock에서 한일:
	// prepare_refcnt: 0
	// prepare_owner: NULL
	// &prepare_lock을 이용한 mutex unlock 수행

	// clk_prepare_unlock에서 한일:
	// prepare_refcnt: 0
	// prepare_owner: NULL
	// &prepare_lock을 이용한 mutex unlock 수행

	// clk_prepare_unlock에서 한일:
	// prepare_refcnt: 0
	// prepare_owner: NULL
	// &prepare_lock을 이용한 mutex unlock 수행

	// clk_prepare_unlock에서 한일:
	// prepare_refcnt: 0
	// prepare_owner: NULL
	// &prepare_lock을 이용한 mutex unlock 수행

	// clk_prepare_unlock에서 한일:
	// prepare_refcnt: 0
	// prepare_owner: NULL
	// &prepare_lock을 이용한 mutex unlock 수행

	// clk_prepare_unlock에서 한일:
	// prepare_refcnt: 0
	// prepare_owner: NULL
	// &prepare_lock을 이용한 mutex unlock 수행

	// clk_prepare_unlock에서 한일:
	// prepare_refcnt: 0
	// prepare_owner: NULL
	// &prepare_lock을 이용한 mutex unlock 수행

	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	return ret;
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
	// return 0
}

/**
 * __clk_register - register a clock and return a cookie.
 *
 * Same as clk_register, except that the .clk field inside hw shall point to a
 * preallocated (generally statically allocated) struct clk. None of the fields
 * of the struct clk need to be initialized.
 *
 * The data pointed to by .init and .clk field shall NOT be marked as init
 * data.
 *
 * __clk_register is only exposed via clk-private.h and is intended for use with
 * very large numbers of clocks that need to be statically initialized.  It is
 * a layering violation to include clk-private.h from any code which implements
 * a clock's .ops; as such any statically initialized clock data MUST be in a
 * separate C file from the logic that implements its operations.  Returns 0
 * on success, otherwise an error code.
 */
struct clk *__clk_register(struct device *dev, struct clk_hw *hw)
{
	int ret;
	struct clk *clk;

	clk = hw->clk;
	clk->name = hw->init->name;
	clk->ops = hw->init->ops;
	clk->hw = hw;
	clk->flags = hw->init->flags;
	clk->parent_names = hw->init->parent_names;
	clk->num_parents = hw->init->num_parents;

	ret = __clk_init(dev, clk);
	if (ret)
		return ERR_PTR(ret);

	return clk;
}
EXPORT_SYMBOL_GPL(__clk_register);

// ARM10C 20150117
// dev: NULL, hw: &(kmem_cache#30-oX (fin))->hw, clk: kmem_cache#29-oX (fin)
// ARM10C 20150117
// dev: NULL, hw: &(kmem_cache#30-oX (apll))->hw, clk: kmem_cache#29-oX (apll)
// ARM10C 20150124
// dev: NULL, hw: &(kmem_cache#30-oX (epll))->hw, clk: kmem_cache#29-oX (epll)
// ARM10C 20150131
// dev: NULL, hw: &(kmem_cache#30-oX (mout_mspll_kfc))->hw, clk: kmem_cache#29-oX (mout_mspll_kfc)
// ARM10C 20150131
// dev: NULL, hw: &(kmem_cache#30-oX (sclk_spll))->hw, clk: kmem_cache#29-oX (sclk_spll)
// ARM10C 20150228
// dev: NULL, hw: &(kmem_cache#30-oX (sclk_apll))->hw, clk: kmem_cache#29-oX (sclk_apll)
// ARM10C 20150307
// dev: NULL, hw: &(kmem_cache#30-oX (sclk_uart0))->hw, clk: kmem_cache#29-oX (sclk_uart0)
static int _clk_register(struct device *dev, struct clk_hw *hw, struct clk *clk)
{
	int i, ret;

	// clk->name: (kmem_cache#29-oX (fin))->name,
	// hw->init->name: (&(kmem_cache#30-oX (fin))->hw)->init->name: "fin_pll", GFP_KERNEL: 0xD0
	// kstrdup("fin_pll", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "fin_pll"
	// clk->name: (kmem_cache#29-oX (apll))->name,
	// hw->init->name: (&(kmem_cache#30-oX (apll))->hw)->init->name: "fout_apll", GFP_KERNEL: 0xD0
	// kstrdup("fout_apll", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "fout_apll"
	// clk->name: (kmem_cache#29-oX (epll))->name,
	// hw->init->name: (&(kmem_cache#30-oX (epll))->hw)->init->name: "fout_epll", GFP_KERNEL: 0xD0
	// kstrdup("fout_epll", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "fout_epll"
	// clk->name: (kmem_cache#29-oX (mout_mspll_kfc))->name,
	// hw->init->name: (&(kmem_cache#30-oX (mout_mspll_kfc))->hw)->init->name: "mout_mspll_kfc", GFP_KERNEL: 0xD0
	// kstrdup("mout_mspll_kfc", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "mout_mspll_kfc"
	// clk->name: (kmem_cache#29-oX (sclk_spll))->name,
	// hw->init->name: (&(kmem_cache#30-oX (sclk_spll))->hw)->init->name: "sclk_spll", GFP_KERNEL: 0xD0
	// kstrdup("sclk_dpll", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "sclk_spll"
	// clk->name: (kmem_cache#29-oX (sclk_apll))->name,
	// hw->init->name: (&(kmem_cache#30-oX (sclk_apll))->hw)->init->name: "sclk_apll", GFP_KERNEL: 0xD0
	// kstrdup("sclk_apll", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "sclk_apll"
	// clk->name: (kmem_cache#29-oX (sclk_uart0))->name,
	// hw->init->name: (&(kmem_cache#30-oX (sclk_uart0))->hw)->init->name: "sclk_uart0", GFP_KERNEL: 0xD0
	// kstrdup("sclk_uart0", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "sclk_uart0"
	clk->name = kstrdup(hw->init->name, GFP_KERNEL);
	// clk->name: (kmem_cache#29-oX (fin))->name: kmem_cache#30-oX ("fin_pll")
	// clk->name: (kmem_cache#29-oX (apll))->name: kmem_cache#30-oX ("fout_apll")
	// clk->name: (kmem_cache#29-oX (epll))->name: kmem_cache#30-oX ("fout_epll")
	// clk->name: (kmem_cache#29-oX (mout_mspll_kfc))->name: kmem_cache#30-oX ("mout_mspll_kfc")
	// clk->name: (kmem_cache#29-oX (sclk_spll))->name: kmem_cache#30-oX ("sclk_spll")
	// clk->name: (kmem_cache#29-oX (sclk_apll))->name: kmem_cache#30-oX ("sclk_apll")
	// clk->name: (kmem_cache#29-oX (sclk_uart0))->name: kmem_cache#30-oX ("sclk_uart0")

	// clk->name: (kmem_cache#29-oX (fin))->name: kmem_cache#30-oX ("fin_pll")
	// clk->name: (kmem_cache#29-oX (apll))->name: kmem_cache#30-oX ("fout_apll")
	// clk->name: (kmem_cache#29-oX (epll))->name: kmem_cache#30-oX ("fout_epll")
	// clk->name: (kmem_cache#29-oX (mout_mspll_kfc))->name: kmem_cache#30-oX ("mout_mspll_kfc")
	// clk->name: (kmem_cache#29-oX (sclk_spll))->name: kmem_cache#30-oX ("sclk_spll")
	// clk->name: (kmem_cache#29-oX (sclk_apll))->name: kmem_cache#30-oX ("sclk_apll")
	// clk->name: (kmem_cache#29-oX (sclk_uart0))->name: kmem_cache#30-oX ("sclk_uart0")
	if (!clk->name) {
		pr_err("%s: could not allocate clk->name\n", __func__);
		ret = -ENOMEM;
		goto fail_name;
	}

	// clk->ops: (kmem_cache#29-oX (fin))->ops, hw->init->ops: (&(kmem_cache#30-oX (fin))->hw)->init->ops: &clk_fixed_rate_ops
	// clk->ops: (kmem_cache#29-oX (apll))->ops, hw->init->ops: (&(kmem_cache#30-oX (apll))->hw)->init->ops: &samsung_pll35xx_clk_min_ops
	// clk->ops: (kmem_cache#29-oX (epll))->ops, hw->init->ops: (&(kmem_cache#30-oX (epll))->hw)->init->ops: &samsung_pll36xx_clk_min_ops
	// clk->ops: (kmem_cache#29-oX (mout_mspll_kfc))->ops, hw->init->ops: (&(kmem_cache#30-oX (mout_mspll_kfc))->hw)->init->ops: &clk_mux_ops
	// clk->ops: (kmem_cache#29-oX (sclk_spll))->ops, hw->init->ops: (&(kmem_cache#30-oX (sclk_spll))->hw)->init->ops: &clk_mux_ops
	// clk->ops: (kmem_cache#29-oX (sclk_apll))->ops, hw->init->ops: (&(kmem_cache#30-oX (sclk_apll))->hw)->init->ops: &clk_divider_ops
	// clk->ops: (kmem_cache#29-oX (sclk_uart0))->ops, hw->init->ops: (&(kmem_cache#30-oX (sclk_uart0))->hw)->init->ops: &clk_gate_ops
	clk->ops = hw->init->ops;
	// clk->ops: (kmem_cache#29-oX (fin))->ops: &clk_fixed_rate_ops
	// clk->ops: (kmem_cache#29-oX (apll))->ops: &samsung_pll35xx_clk_min_ops
	// clk->ops: (kmem_cache#29-oX (epll))->ops: &samsung_pll36xx_clk_min_ops
	// clk->ops: (kmem_cache#29-oX (mout_mspll_kfc))->ops: &clk_mux_ops
	// clk->ops: (kmem_cache#29-oX (sclk_spll))->ops: &clk_mux_ops
	// clk->ops: (kmem_cache#29-oX (sclk_apll))->ops: &clk_divider_ops
	// clk->ops: (kmem_cache#29-oX (sclk_uart0))->ops: &clk_gate_ops

	// clk->hw: (kmem_cache#29-oX (fin))->hw, hw: &(kmem_cache#30-oX (fin))->hw
	// clk->hw: (kmem_cache#29-oX (apll))->hw, hw: &(kmem_cache#30-oX (apll))->hw
	// clk->hw: (kmem_cache#29-oX (epll))->hw, hw: &(kmem_cache#30-oX (epll))->hw
	// clk->hw: (kmem_cache#29-oX (mout_mspll_kfc))->hw, hw: &(kmem_cache#30-oX (mout_mspll_kfc))->hw
	// clk->hw: (kmem_cache#29-oX (sclk_spll))->hw, hw: &(kmem_cache#30-oX (sclk_spll))->hw
	// clk->hw: (kmem_cache#29-oX (sclk_apll))->hw, hw: &(kmem_cache#30-oX (sclk_apll))->hw
	// clk->hw: (kmem_cache#29-oX (sclk_uart0))->hw, hw: &(kmem_cache#30-oX (sclk_uart0))->hw
	clk->hw = hw;
	// clk->hw: (kmem_cache#29-oX (fin))->hw: &(kmem_cache#30-oX (fin))->hw
	// clk->hw: (kmem_cache#29-oX (apll))->hw: &(kmem_cache#30-oX (apll))->hw
	// clk->hw: (kmem_cache#29-oX (epll))->hw: &(kmem_cache#30-oX (epll))->hw
	// clk->hw: (kmem_cache#29-oX (mout_mspll_kfc))->hw: &(kmem_cache#30-oX (mout_mspll_kfc))->hw
	// clk->hw: (kmem_cache#29-oX (sclk_spll))->hw: &(kmem_cache#30-oX (sclk_spll))->hw
	// clk->hw: (kmem_cache#29-oX (sclk_apll))->hw: &(kmem_cache#30-oX (sclk_apll))->hw
	// clk->hw: (kmem_cache#29-oX (sclk_uart0))->hw: &(kmem_cache#30-oX (sclk_uart0))->hw

	// clk->flags: (kmem_cache#29-oX (fin))->flags, hw->init->flags: (&(kmem_cache#30-oX (fin))->hw)->init->flags: 0x30
	// clk->flags: (kmem_cache#29-oX (apll))->flags, hw->init->flags: (&(kmem_cache#30-oX (apll))->hw)->init->flags: 0x40
	// clk->flags: (kmem_cache#29-oX (epll))->flags, hw->init->flags: (&(kmem_cache#30-oX (epll))->hw)->init->flags: 0x40
	// clk->flags: (kmem_cache#29-oX (mout_mspll_kfc))->flags, hw->init->flags: (&(kmem_cache#30-oX (mout_mspll_kfc))->hw)->init->flags: 0xa0
	// clk->flags: (kmem_cache#29-oX (sclk_spll))->flags, hw->init->flags: (&(kmem_cache#30-oX (sclk_spll))->hw)->init->flags: 0xa0
	// clk->flags: (kmem_cache#29-oX (sclk_apll))->flags, hw->init->flags: (&(kmem_cache#30-oX (sclk_apll))->hw)->init->flags: 0x0
	// clk->flags: (kmem_cache#29-oX (sclk_uart0))->flags, hw->init->flags: (&(kmem_cache#30-oX (sclk_uart0))->hw)->init->flags: 0x0
	clk->flags = hw->init->flags;
	// clk->flags: (kmem_cache#29-oX (fin))->flags: 0x30
	// clk->flags: (kmem_cache#29-oX (apll))->flags: 0x40
	// clk->flags: (kmem_cache#29-oX (epll))->flags: 0x40
	// clk->flags: (kmem_cache#29-oX (mout_mspll_kfc))->flags: 0xa0
	// clk->flags: (kmem_cache#29-oX (sclk_spll))->flags: 0xa0
	// clk->flags: (kmem_cache#29-oX (sclk_apll))->flags: 0x0
	// clk->flags: (kmem_cache#29-oX (sclk_uart0))->flags: 0x24

	// clk->num_parents: (kmem_cache#29-oX (fin))->num_parents, hw->init->flags: (&(kmem_cache#30-oX (fin))->hw)->init->num_parents: 0
	// clk->num_parents: (kmem_cache#29-oX (apll))->num_parents, hw->init->flags: (&(kmem_cache#30-oX (apll))->hw)->init->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (epll))->num_parents, hw->init->flags: (&(kmem_cache#30-oX (epll))->hw)->init->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents, hw->init->flags: (&(kmem_cache#30-oX (mout_mspll_kfc))->hw)->init->num_parents: 4
	// clk->num_parents: (kmem_cache#29-oX (sclk_spll))->num_parents, hw->init->flags: (&(kmem_cache#30-oX (sclk_spll))->hw)->init->num_parents: 2
	// clk->num_parents: (kmem_cache#29-oX (sclk_apll))->num_parents, hw->init->flags: (&(kmem_cache#30-oX (sclk_apll))->hw)->init->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (sclk_uart0))->num_parents, hw->init->flags: (&(kmem_cache#30-oX (sclk_uart0))->hw)->init->num_parents: 1
	clk->num_parents = hw->init->num_parents;
	// clk->num_parents: (kmem_cache#29-oX (fin))->num_parents: 0
	// clk->num_parents: (kmem_cache#29-oX (apll))->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (epll))->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents 4
	// clk->num_parents: (kmem_cache#29-oX (sclk_spll))->num_parents 2
	// clk->num_parents: (kmem_cache#29-oX (sclk_apll))->num_parents 1
	// clk->num_parents: (kmem_cache#29-oX (sclk_uart0))->num_parents 1

	// hw->clk: (&(kmem_cache#30-oX (fin))->hw)->clk, clk: kmem_cache#29-oX (fin)
	// hw->clk: (&(kmem_cache#30-oX (apll))->hw)->clk, clk: kmem_cache#29-oX (apll)
	// hw->clk: (&(kmem_cache#30-oX (epll))->hw)->clk, clk: kmem_cache#29-oX (epll)
	// hw->clk: (&(kmem_cache#30-oX (mout_mspll_kfc))->hw)->clk, clk: kmem_cache#29-oX (mout_mspll_kfc)
	// hw->clk: (&(kmem_cache#30-oX (sclk_spll))->hw)->clk, clk: kmem_cache#29-oX (sclk_spll)
	// hw->clk: (&(kmem_cache#30-oX (sclk_apll))->hw)->clk, clk: kmem_cache#29-oX (sclk_apll)
	// hw->clk: (&(kmem_cache#30-oX (sclk_uart0))->hw)->clk, clk: kmem_cache#29-oX (sclk_uart0)
	hw->clk = clk;
	// hw->clk: (&(kmem_cache#30-oX (fin))->hw)->clk: kmem_cache#29-oX (fin)
	// hw->clk: (&(kmem_cache#30-oX (apll))->hw)->clk: kmem_cache#29-oX (apll)
	// hw->clk: (&(kmem_cache#30-oX (epll))->hw)->clk: kmem_cache#29-oX (epll)
	// hw->clk: (&(kmem_cache#30-oX (mout_mspll_kfc))->hw)->clk: kmem_cache#29-oX (mout_mspll_kfc)
	// hw->clk: (&(kmem_cache#30-oX (sclk_spll))->hw)->clk: kmem_cache#29-oX (sclk_spll)
	// hw->clk: (&(kmem_cache#30-oX (sclk_apll))->hw)->clk: kmem_cache#29-oX (sclk_apll)
	// hw->clk: (&(kmem_cache#30-oX (sclk_uart0))->hw)->clk: kmem_cache#29-oX (sclk_uart0)

	/* allocate local copy in case parent_names is __initdata */
	// clk->parent_names: (kmem_cache#29-oX (fin))->parent_names
	// clk->num_parents: (kmem_cache#29-oX (fin))->num_parents: 0, sizeof(char *): 4, GFP_KERNEL: 0xD0
	// kcalloc(0, 4, GFP_KERNEL: 0xD0): ((void *)16)
	// clk->parent_names: (kmem_cache#29-oX (apll))->parent_names
	// clk->num_parents: (kmem_cache#29-oX (apll))->num_parents: 1, sizeof(char *): 4, GFP_KERNEL: 0xD0
	// kcalloc(0, 4, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (epll))->parent_names
	// clk->num_parents: (kmem_cache#29-oX (epll))->num_parents: 1, sizeof(char *): 4, GFP_KERNEL: 0xD0
	// kcalloc(0, 4, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names
	// clk->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents: 4, sizeof(char *): 4, GFP_KERNEL: 0xD0
	// kcalloc(4, 4, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (sclk_spll))->parent_names
	// clk->num_parents: (kmem_cache#29-oX (sclk_spll))->num_parents: 2, sizeof(char *): 4, GFP_KERNEL: 0xD0
	// kcalloc(2, 4, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (sclk_apll))->parent_names
	// clk->num_parents: (kmem_cache#29-oX (sclk_apll))->num_parents: 1, sizeof(char *): 4, GFP_KERNEL: 0xD0
	// kcalloc(1, 4, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (sclk_uart0))->parent_names
	// clk->num_parents: (kmem_cache#29-oX (sclk_uart0))->num_parents: 1, sizeof(char *): 4, GFP_KERNEL: 0xD0
	// kcalloc(1, 4, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	clk->parent_names = kcalloc(clk->num_parents, sizeof(char *),
					GFP_KERNEL);
	// clk->parent_names: (kmem_cache#29-oX (fin))->parent_names: ((void *)16)
	// clk->parent_names: (kmem_cache#29-oX (apll))->parent_names: kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (epll))->parent_names: kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names: kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (sclk_spll))->parent_names: kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (sclk_apll))->parent_names: kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (sclk_uart0))->parent_names: kmem_cache#30-oX

	// clk->parent_names: (kmem_cache#29-oX (fin))->parent_names: ((void *)16)
	// clk->parent_names: (kmem_cache#29-oX (apll))->parent_names: kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (epll))->parent_names: kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names: kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (sclk_spll))->parent_names: kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (sclk_apll))->parent_names: kmem_cache#30-oX
	// clk->parent_names: (kmem_cache#29-oX (sclk_uart0))->parent_names: kmem_cache#30-oX
	if (!clk->parent_names) {
		pr_err("%s: could not allocate clk->parent_names\n", __func__);
		ret = -ENOMEM;
		goto fail_parent_names;
	}


	/* copy each string name in case parent_names is __initdata */
	// clk->num_parents: (kmem_cache#29-oX (fin))->num_parents: 0
	// clk->num_parents: (kmem_cache#29-oX (apll))->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (epll))->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (mout_mspll_kfc))->num_parents: 4
	// clk->num_parents: (kmem_cache#29-oX (sclk_spll))->num_parents: 2
	// clk->num_parents: (kmem_cache#29-oX (sclk_apll))->num_parents: 1
	// clk->num_parents: (kmem_cache#29-oX (sclk_uart0))->num_parents: 1
	for (i = 0; i < clk->num_parents; i++) {
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (apll))->parent_names[0]: (kmem_cache#30-oX)[0]
		// hw->init->parent_names[0]: (&(kmem_cache#30-oX (apll))->hw)->init->parent_names[0]: "fin_pll", GFP_KERNEL: 0xD0
		// kstrdup("fin_pll", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "fin_pll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (epll))->parent_names[0]: (kmem_cache#30-oX)[0]
		// hw->init->parent_names[0]: (&(kmem_cache#30-oX (epll))->hw)->init->parent_names[0]: "fin_pll", GFP_KERNEL: 0xD0
		// kstrdup("fin_pll", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "fin_pll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: (kmem_cache#30-oX)[0]
		// hw->init->parent_names[0]: (&(kmem_cache#30-oX (mout_mspll_kfc))->hw)->init->parent_names[0]: "sclk_cpll", GFP_KERNEL: 0xD0
		// kstrdup("sclk_spll", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "sclk_spll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (sclk_spll))->parent_names[0]: (kmem_cache#30-oX)[0]
		// hw->init->parent_names[0]: (&(kmem_cache#30-oX (sclk_spll))->hw)->init->parent_names[0]: "fin_pll", GFP_KERNEL: 0xD0
		// kstrdup("fin_pll", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "fin_pll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (sclk_apll))->parent_names[0]: (kmem_cache#30-oX)[0]
		// hw->init->parent_names[0]: (&(kmem_cache#30-oX (sclk_apll))->hw)->init->parent_names[0]: "mout_apll", GFP_KERNEL: 0xD0
		// kstrdup("mout_apll", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "mout_apll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (sclk_uart0))->parent_names[0]: (kmem_cache#30-oX)[0]
		// hw->init->parent_names[0]: (&(kmem_cache#30-oX (sclk_uart0))->hw)->init->parent_names[0]: "dout_uart0", GFP_KERNEL: 0xD0
		// kstrdup("dout_uart0", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "dout_uart0"
		clk->parent_names[i] = kstrdup(hw->init->parent_names[i],
						GFP_KERNEL);
		// clk->parent_names[0]: (kmem_cache#29-oX (apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// clk->parent_names[0]: (kmem_cache#29-oX (epll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// clk->parent_names[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "sclk_cpll"
		// clk->parent_names[0]: (kmem_cache#29-oX (sclk_spll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// clk->parent_names[0]: (kmem_cache#29-oX (sclk_apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "mout_apll"
		// clk->parent_names[0]: (kmem_cache#29-oX (sclk_uart0))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "dout_uart0"

		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (epll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "sclk_cpll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (sclk_spll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (sclk_apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "mout_apll"
		// i: 0, clk->parent_names[0]: (kmem_cache#29-oX (sclk_uart0))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "dout_uart0"
		if (!clk->parent_names[i]) {
			pr_err("%s: could not copy parent_names\n", __func__);
			ret = -ENOMEM;
			goto fail_parent_names_copy;
		}

		// mout_mspll_kfc 의 경우 i: 1...3 루프 수행
		// sclk_spll의 경우 i: 1 루프 수행
		// sclk_apll의 경우 루프 수행 끝
		// sclk_uart0의 경우 루프 수행 끝
	}

	// dev: NULL, clk: kmem_cache#29-oX (fin)
	// __clk_init(NULL, kmem_cache#29-oX): NULL
	// dev: NULL, clk: kmem_cache#29-oX (apll)
	// __clk_init(NULL, kmem_cache#29-oX (apll)): NULL
	// dev: NULL, clk: kmem_cache#29-oX (epll)
	// __clk_init(NULL, kmem_cache#29-oX (epll)): NULL
	// dev: NULL, clk: kmem_cache#29-oX (mout_mspll_kfc)
	// __clk_init(NULL, kmem_cache#29-oX (mout_mspll_kfc)): NULL
	// dev: NULL, clk: kmem_cache#29-oX (sclk_spll)
	// __clk_init(NULL, kmem_cache#29-oX (sclk_spll)): NULL
	// dev: NULL, clk: kmem_cache#29-oX (sclk_apll)
	// __clk_init(NULL, kmem_cache#29-oX (sclk_apll)): NULL
	// dev: NULL, clk: kmem_cache#29-oX (sclk_uart0)
	// __clk_init(NULL, kmem_cache#29-oX (sclk_uart0)): NULL
	ret = __clk_init(dev, clk);
	// ret: NULL
	// ret: NULL
	// ret: NULL
	// ret: NULL
	// ret: NULL
	// ret: NULL
	// ret: NULL

	// __clk_init에서 한일:
	// (kmem_cache#29-oX)->parent: NULL
	// (kmem_cache#29-oX)->rate: 24000000
	//
	// (&(kmem_cache#29-oX)->child_node)->next: NULL
	// (&(kmem_cache#29-oX)->child_node)->pprev: &(&(kmem_cache#29-oX)->child_node)
	//
	// (&clk_root_list)->first: &(kmem_cache#29-oX)->child_node

	// __clk_init(apll)에서 한일:
	// clk->parent: (kmem_cache#29-oX (apll))->parent: kmem_cache#29-oX (fin_pll)
	// clk->rate: (kmem_cache#29-oX (apll))->rate: 1000000000 (1 Ghz)
	//
	// (&(kmem_cache#29-oX (apll))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (apll))->child_node)->pprev: &(&(kmem_cache#29-oX (apll))->child_node)
	//
	// (&(kmem_cache#29-oX (fin_pll))->children)->first: &(kmem_cache#29-oX (apll))->child_node

	// __clk_init(epll)에서 한일:
	// clk->parent: (kmem_cache#29-oX (epll))->parent: kmem_cache#29-oX (fin_pll)
	// clk->rate: (kmem_cache#29-oX (epll))->rate: 191999389
	//
	// (&(kmem_cache#29-oX (epll))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (epll))->child_node)->pprev: &(&(kmem_cache#29-oX (epll))->child_node)
	//
	// (&(kmem_cache#29-oX (fin_pll))->children)->first: &(kmem_cache#29-oX (epll))->child_node

	// __clk_init(mout_mspll_kfc)에서 한일:
	// (kmem_cache#29-oX (mout_mspll_kfc))->parent: NULL
	// (kmem_cache#29-oX (mout_mspll_kfc))->rate: 0
	//
	// (kmem_cache#29-oX (mout_mspll_kfc))->parents: kmem_cache#30-oX
	// (kmem_cache#29-oX (mout_mspll_kfc))->parents[0...3]: (kmem_cache#30-oX)[0...3]: NULL
	//
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
	//
	// (&clk_orphan_list)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
	//
	// parents 인 "sclk_cpll", "sclk_dpll", "sclk_mpll", "sclk_spll" 값들 중에
	// register CLK_SRC_TOP7 의 값을 읽어서 mux 할 parent clock 을 선택함
	// return된 값이 선택된 parent clock의 index 값임
	// parent clock 중에 선택된 parent clock의 이름으로 등록된 clk struct를 반환함

	// __clk_init(sclk_dpll)에서 한일:
	// (kmem_cache#29-oX (sclk_dpll))->parent: NULL
	// (kmem_cache#29-oX (sclk_dpll))->rate: 600000000
	//
	// (kmem_cache#29-oX (sclk_dpll))->parents: kmem_cache#30-oX
	// (kmem_cache#29-oX (sclk_dpll))->parents[0]: (kmem_cache#30-oX)[0]: kmem_cache#29-oX (fin_pll)
	// (kmem_cache#29-oX (sclk_dpll))->parents[1]: (kmem_cache#30-oX)[1]: kmem_cache#29-oX (fout_dpll)
	//
	// parents 인 "fin_pll", "fout_spll" 값들 중에
	// register CLK_SRC_TOP6 의 값을 읽어서 mux 할 parent clock 을 선택함
	// return된 값이 선택된 parent clock의 index 값임
	// parent clock 중에 선택된 parent clock의 이름으로 등록된 clk struct를 반환함
	//
	// (&(kmem_cache#29-oX (sclk_spll))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (sclk_spll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_spll))->child_node)
	//
	// (&(kmem_cache#29-oX (fout_spll))->children)->first: &(kmem_cache#29-oX (sclk_spll))->child_node
	//
	// orphan 으로 등록된 mout_mspll_kfc의 값을 갱신
	// &(kmem_cache#29-oX (mout_mspll_kfc))->child_node의 next list에 pprev의 값을 연결함
	// &(kmem_cache#29-oX (mout_mspll_kfc))->child_node를 제거
	//
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
	//
	// (&(kmem_cache#29-oX (sclk_spll))->children)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
	//
	// (kmem_cache#29-oX (mout_mspll_kfc))->parent: kmem_cache#29-oX (sclk_spll)
	//
	// parent가 있는지 확인후 parent의 clock rate 값으로 clock rate 값을 세팅
	// (kmem_cache#29-oX (mout_mspll_kfc))->rate: 600000000

	// __clk_init(sclk_apll)에서 한일:
	// (kmem_cache#29-oX (sclk_apll))->parent: kmem_cache#29-oX (mout_apll)
	// (kmem_cache#29-oX (sclk_apll))->rate: 800000000
	//
	// clk 의 이름이 "mout_apll"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행
	//
	// (&(kmem_cache#29-oX (sclk_apll))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (sclk_apll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_apll))->child_node)
	//
	// (&(kmem_cache#29-oX (mout_apll))->children)->first: &(kmem_cache#29-oX (sclk_apll))->child_node

	// __clk_init(sclk_uart0)에서 한일:
	// (kmem_cache#29-oX (sclk_uart0))->parent: kmem_cache#29-oX (dout_uart0)
	// (kmem_cache#29-oX (sclk_uart0))->rate: 266000000
	//
	// clk 의 이름이 "dout_uart0"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행
	//
	// (&(kmem_cache#29-oX (sclk_uart0))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (sclk_uart0))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_uart0))->child_node)
	//
	// (&(kmem_cache#29-oX (dout_uart0))->children)->first: &(kmem_cache#29-oX (sclk_uart0))->child_node

	// ret: NULL
	// ret: NULL
	// ret: NULL
	// ret: NULL
	// ret: NULL
	// ret: NULL
	// ret: NULL
	if (!ret)
		return 0;
		// return 0
		// return 0
		// return 0
		// return 0
		// return 0
		// return 0
		// return 0

fail_parent_names_copy:
	while (--i >= 0)
		kfree(clk->parent_names[i]);
	kfree(clk->parent_names);
fail_parent_names:
	kfree(clk->name);
fail_name:
	return ret;
}

/**
 * clk_register - allocate a new clock, register it and return an opaque cookie
 * @dev: device that is registering this clock
 * @hw: link to hardware-specific clock data
 *
 * clk_register is the primary interface for populating the clock tree with new
 * clock nodes.  It returns a pointer to the newly allocated struct clk which
 * cannot be dereferenced by driver code but may be used in conjuction with the
 * rest of the clock API.  In the event of an error clk_register will return an
 * error code; drivers must test for an error code after calling clk_register.
 */
// ARM10C 20150117
// dev: NULL, &fixed->hw: &(kmem_cache#30-oX)->hw
// ARM10C 20150117
// dev: NULL, &pll->hw: &(kmem_cache#30-oX (apll))->hw
// ARM10C 20150124
// dev: NULL, &pll->hw: &(kmem_cache#30-oX (epll))->hw
// ARM10C 20150124
// dev: NULL, &fix->hw: &(kmem_cache#30-oX (sclk_hsic_12m))->hw
// ARM10C 20150131
// dev: NULL, &mux->hw: &(kmem_cache#30-oX (mout_mspll_kfc))->hw
// ARM10C 20150131
// dev: NULL, &mux->hw: &(kmem_cache#30-oX (sclk_spll))->hw
// ARM10C 20150228
// dev: NULL, &div->hw: &(kmem_cache#30-oX (sclk_apll))->hw
// ARM10C 20150307
// dev: NULL, &gate->hw: &(kmem_cache#30-oX (sclk_fimd1))->hw
struct clk *clk_register(struct device *dev, struct clk_hw *hw)
{
	int ret;
	struct clk *clk;

	// sizeof(struct clk): 66 bytes, GFP_KERNEL: 0xD0
	// kzalloc(66, GFP_KERNEL: 0xD0): kmem_cache#29-oX (128 bytes)
	// sizeof(struct clk): 66 bytes, GFP_KERNEL: 0xD0
	// kzalloc(66, GFP_KERNEL: 0xD0): kmem_cache#29-oX (128 bytes)
	// sizeof(struct clk): 66 bytes, GFP_KERNEL: 0xD0
	// kzalloc(66, GFP_KERNEL: 0xD0): kmem_cache#29-oX (128 bytes)
	// sizeof(struct clk): 66 bytes, GFP_KERNEL: 0xD0
	// kzalloc(66, GFP_KERNEL: 0xD0): kmem_cache#29-oX (128 bytes)
	// sizeof(struct clk): 66 bytes, GFP_KERNEL: 0xD0
	// kzalloc(66, GFP_KERNEL: 0xD0): kmem_cache#29-oX (128 bytes)
	// sizeof(struct clk): 66 bytes, GFP_KERNEL: 0xD0
	// kzalloc(66, GFP_KERNEL: 0xD0): kmem_cache#29-oX (128 bytes)
	// sizeof(struct clk): 66 bytes, GFP_KERNEL: 0xD0
	// kzalloc(66, GFP_KERNEL: 0xD0): kmem_cache#29-oX (128 bytes)
	clk = kzalloc(sizeof(*clk), GFP_KERNEL);
	// clk: kmem_cache#29-oX (fin)
	// clk: kmem_cache#29-oX (apll)
	// clk: kmem_cache#29-oX (epll)
	// clk: kmem_cache#29-oX (mout_mspll_kfc)
	// clk: kmem_cache#29-oX (sclk_spll)
	// clk: kmem_cache#29-oX (sclk_apll)
	// clk: kmem_cache#29-oX (sclk_fimd1)

	// clk: kmem_cache#29-oX (fin)
	// clk: kmem_cache#29-oX (apll)
	// clk: kmem_cache#29-oX (epll)
	// clk: kmem_cache#29-oX (mout_mspll_kfc)
	// clk: kmem_cache#29-oX (sclk_spll)
	// clk: kmem_cache#29-oX (sclk_apll)
	// clk: kmem_cache#29-oX (sclk_fimd1)
	if (!clk) {
		pr_err("%s: could not allocate clk\n", __func__);
		ret = -ENOMEM;
		goto fail_out;
	}

	// dev: NULL, hw: &(kmem_cache#30-oX (fin))->hw, clk: kmem_cache#29-oX (fin)
	// _clk_register(NULL, &(kmem_cache#30-oX (fin))->hw, kmem_cache#29-oX (fin)): 0
	// dev: NULL, hw: &(kmem_cache#30-oX (apll))->hw, clk: kmem_cache#29-oX (apll)
	// _clk_register(NULL, &(kmem_cache#30-oX (apll))->hw, kmem_cache#29-oX (apll)): 0
	// dev: NULL, hw: &(kmem_cache#30-oX (epll))->hw, clk: kmem_cache#29-oX (epll)
	// _clk_register(NULL, &(kmem_cache#30-oX (epll))->hw, kmem_cache#29-oX (epll)): 0
	// dev: NULL, hw: &(kmem_cache#30-oX (mout_mspll_kfc))->hw, clk: kmem_cache#29-oX (mout_mspll_kfc)
	// _clk_register(NULL, &(kmem_cache#30-oX (mout_mspll_kfc))->hw, kmem_cache#29-oX (mout_mspll_kfc)): 0
	// dev: NULL, hw: &(kmem_cache#30-oX (sclk_spll))->hw, clk: kmem_cache#29-oX (sclk_spll)
	// _clk_register(NULL, &(kmem_cache#30-oX (sclk_spll))->hw, kmem_cache#29-oX (sclk_spll)): 0
	// dev: NULL, hw: &(kmem_cache#30-oX (sclk_apll))->hw, clk: kmem_cache#29-oX (sclk_apll)
	// _clk_register(NULL, &(kmem_cache#30-oX (sclk_apll))->hw, kmem_cache#29-oX (sclk_apll)): 0
	// dev: NULL, hw: &(kmem_cache#30-oX (sclk_fimd1))->hw, clk: kmem_cache#29-oX (sclk_uart0)
	// _clk_register(NULL, &(kmem_cache#30-oX (sclk_uart0))->hw, kmem_cache#29-oX (sclk_uart0)): 0
	ret = _clk_register(dev, hw, clk);
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0

	// _clk_register 에서 한일:
	// (kmem_cache#29-oX)->name: kmem_cache#30-oX ("fin_pll")
	// (kmem_cache#29-oX)->ops: &clk_fixed_rate_ops
	// (kmem_cache#29-oX)->hw: &(kmem_cache#30-oX)->hw
	// (kmem_cache#29-oX)->flags: 0x30
	// (kmem_cache#29-oX)->num_parents: 0
	// (kmem_cache#29-oX)->parent_names: ((void *)16)
	// (kmem_cache#29-oX)->parent: NULL
	// (kmem_cache#29-oX)->rate: 24000000
	//
	// (&(kmem_cache#29-oX)->child_node)->next: NULL
	// (&(kmem_cache#29-oX)->child_node)->pprev: &(&(kmem_cache#29-oX)->child_node)
	//
	// (&clk_root_list)->first: &(kmem_cache#29-oX)->child_node
	//
	// (&(kmem_cache#30-oX)->hw)->clk: kmem_cache#29-oX

	// _clk_register(apll) 에서 한일:
	// (kmem_cache#29-oX (apll))->name: kmem_cache#30-oX ("fout_apll")
	// (kmem_cache#29-oX (apll))->ops: &samsung_pll35xx_clk_min_ops
	// (kmem_cache#29-oX (apll))->hw: &(kmem_cache#30-oX (apll))->hw
	// (kmem_cache#29-oX (apll))->flags: 0x40
	// (kmem_cache#29-oX (apll))->num_parents: 1
	// (kmem_cache#29-oX (apll))->parent_names: kmem_cache#30-oX
	// (kmem_cache#29-oX (apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
	// (kmem_cache#29-oX (apll))->parent: kmem_cache#29-oX (fin_pll)
	// (kmem_cache#29-oX (apll))->rate: 1000000000 (1 Ghz)
	//
	// (&(kmem_cache#29-oX (apll))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (apll))->child_node)->pprev: &(&(kmem_cache#29-oX (apll))->child_node)
	//
	// (&(kmem_cache#29-oX (fin_pll))->children)->first: &(kmem_cache#29-oX (apll))->child_node
	//
	// (&(kmem_cache#30-oX (apll))->hw)->clk: kmem_cache#29-oX (apll)

	// _clk_register(epll) 에서 한일:
	// (kmem_cache#29-oX (epll))->name: kmem_cache#30-oX ("fout_epll")
	// (kmem_cache#29-oX (epll))->ops: &samsung_pll36xx_clk_min_ops
	// (kmem_cache#29-oX (epll))->hw: &(kmem_cache#30-oX (epll))->hw
	// (kmem_cache#29-oX (epll))->flags: 0x40
	// (kmem_cache#29-oX (epll))->num_parents: 1
	// (kmem_cache#29-oX (epll))->parent_names: kmem_cache#30-oX
	// (kmem_cache#29-oX (epll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
	// (kmem_cache#29-oX (epll))->parent: kmem_cache#29-oX (fin_pll)
	// (kmem_cache#29-oX (epll))->rate: 191999389
	//
	// (&(kmem_cache#29-oX (epll))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (epll))->child_node)->pprev: &(&(kmem_cache#29-oX (epll))->child_node)
	//
	// (&(kmem_cache#29-oX (fin_pll))->children)->first: &(kmem_cache#29-oX (epll))->child_node
	//
	// (&(kmem_cache#30-oX (epll))->hw)->clk: kmem_cache#29-oX (epll)

	// _clk_register(mout_mspll_kfc) 에서 한일:
	// (kmem_cache#29-oX (mout_mspll_kfc))->name: kmem_cache#30-oX ("mout_mspll_kfc")
	// (kmem_cache#29-oX (mout_mspll_kfc))->ops: &clk_mux_ops
	// (kmem_cache#29-oX (mout_mspll_kfc))->hw: &(kmem_cache#30-oX (mout_mspll_kfc))->hw
	// (kmem_cache#29-oX (mout_mspll_kfc))->flags: 0xa0
	// (kmem_cache#29-oX (mout_mspll_kfc))->num_parents 4
	// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names: kmem_cache#30-oX
	// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "sclk_cpll"
	// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[1]: (kmem_cache#30-oX)[1]: kmem_cache#30-oX: "sclk_dpll"
	// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[2]: (kmem_cache#30-oX)[2]: kmem_cache#30-oX: "sclk_mpll"
	// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[3]: (kmem_cache#30-oX)[3]: kmem_cache#30-oX: "sclk_spll"
	// (kmem_cache#29-oX (mout_mspll_kfc))->parent: NULL
	// (kmem_cache#29-oX (mout_mspll_kfc))->rate: 0
	//
	// (kmem_cache#29-oX (mout_mspll_kfc))->parents: kmem_cache#30-oX
	// (kmem_cache#29-oX (mout_mspll_kfc))->parents[0...3]: (kmem_cache#30-oX)[0...3]: NULL
	//
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
	//
	// (&clk_orphan_list)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
	//
	// (&(kmem_cache#30-oX (mout_mspll_kfc))->hw)->clk: kmem_cache#29-oX (mout_mspll_kfc)
	
	// _clk_register(sclk_spll) 에서 한일:
	// (kmem_cache#29-oX (sclk_spll))->name: kmem_cache#30-oX ("sclk_spll")
	// (kmem_cache#29-oX (sclk_spll))->ops: &clk_mux_ops
	// (kmem_cache#29-oX (sclk_spll))->hw: &(kmem_cache#30-oX (sclk_spll))->hw
	// (kmem_cache#29-oX (sclk_spll))->flags: 0xa0
	// (kmem_cache#29-oX (sclk_spll))->num_parents 2
	// (kmem_cache#29-oX (sclk_spll))->parent_names: kmem_cache#30-oX
	// (kmem_cache#29-oX (sclk_spll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
	// (kmem_cache#29-oX (sclk_spll))->parent_names[1]: (kmem_cache#30-oX)[1]: kmem_cache#30-oX: "fout_spll"
	// (kmem_cache#29-oX (sclk_spll))->parent: NULL
	// (kmem_cache#29-oX (sclk_spll))->rate: 600000000
	//
	// (kmem_cache#29-oX (sclk_spll))->parents: kmem_cache#30-oX
	// (kmem_cache#29-oX (sclk_spll))->parents[0]: (kmem_cache#30-oX)[0]: kmem_cache#29-oX (fin_pll)
	// (kmem_cache#29-oX (sclk_spll))->parents[1]: (kmem_cache#30-oX)[1]: kmem_cache#29-oX (fout_spll)
	//
	// parents 인 "fin_pll", "fout_spll" 값들 중에
	// register CLK_SRC_TOP6 의 값을 읽어서 mux 할 parent clock 을 선택함
	// return된 값이 선택된 parent clock의 index 값임
	// parent clock 중에 선택된 parent clock의 이름으로 등록된 clk struct를 반환함
	//
	// (&(kmem_cache#29-oX (sclk_spll))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (sclk_spll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_spll))->child_node)
	//
	// (&(kmem_cache#29-oX (fout_spll))->children)->first: &(kmem_cache#29-oX (sclk_spll))->child_node
	//
	// (&(kmem_cache#30-oX (sclk_spll))->hw)->clk: kmem_cache#29-oX (sclk_spll)
	//
	// orphan 으로 등록된 mout_mspll_kfc의 값을 갱신
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
	//
	// (&(kmem_cache#29-oX (sclk_dpll))->children)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
	//
	// (kmem_cache#29-oX (mout_mspll_kfc))->parent: kmem_cache#29-oX (sclk_spll)
	//
	// parent가 있는지 확인후 parent의 clock rate 값으로 clock rate 값을 세팅
	// (kmem_cache#29-oX (mout_mspll_kfc))->rate: 600000000

	// _clk_register(sclk_apll) 에서 한일:
	// (kmem_cache#29-oX (sclk_apll))->name: kmem_cache#30-oX ("sclk_apll")
	// (kmem_cache#29-oX (sclk_apll))->ops: &clk_divider_ops
	// (kmem_cache#29-oX (sclk_apll))->hw: &(kmem_cache#30-oX (sclk_apll))->hw
	// (kmem_cache#29-oX (sclk_apll))->flags: 0x0
	// (kmem_cache#29-oX (sclk_apll))->num_parents 1
	// (kmem_cache#29-oX (sclk_apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "mout_apll"
	// (kmem_cache#29-oX (sclk_apll))->parent: kmem_cache#29-oX (mout_apll)
	// (kmem_cache#29-oX (sclk_apll))->rate: 800000000
	//
	// clk 의 이름이 "mout_apll"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행
	//
	// (&(kmem_cache#29-oX (sclk_apll))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (sclk_apll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_apll))->child_node)
	//
	// (&(kmem_cache#29-oX (mout_apll))->children)->first: &(kmem_cache#29-oX (sclk_apll))->child_node

	// _clk_register(sclk_uart0) 에서 한일:
	// (kmem_cache#29-oX (sclk_uart0))->name: kmem_cache#30-oX ("sclk_uart0")
	// (kmem_cache#29-oX (sclk_uart0))->ops: &clk_gate_ops
	// (kmem_cache#29-oX (sclk_uart0))->hw: &(kmem_cache#30-oX (sclk_uart0))->hw
	// (kmem_cache#29-oX (sclk_uart0))->flags: 0x24
	// (kmem_cache#29-oX (sclk_uart0))->num_parents 1
	// (kmem_cache#29-oX (sclk_uart0))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "mout_apll"
	// (kmem_cache#29-oX (sclk_uart0))->parent: kmem_cache#29-oX (dout_uart0)
	// (kmem_cache#29-oX (sclk_uart0))->rate: 266000000
	//
	// clk 의 이름이 "dout_uart0"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행
	//
	// (&(kmem_cache#29-oX (sclk_uart0))->child_node)->next: NULL
	// (&(kmem_cache#29-oX (sclk_uart0))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_uart0))->child_node)
	//
	// (&(kmem_cache#29-oX (dout_uart0))->children)->first: &(kmem_cache#29-oX (sclk_uart0))->child_node

// 2015/02/28 종료
// 2015/03/07 시작

	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	// ret: 0
	if (!ret)
		// clk: kmem_cache#29-oX (fin)
		// clk: kmem_cache#29-oX (apll)
		// clk: kmem_cache#29-oX (epll)
		// clk: kmem_cache#29-oX (mout_mspll_kfc)
		// clk: kmem_cache#29-oX (sclk_spll)
		// clk: kmem_cache#29-oX (sclk_apll)
		// clk: kmem_cache#29-oX (sclk_uart0)
		return clk;
		// return kmem_cache#29-oX (fin)
		// return kmem_cache#29-oX (apll)
		// return kmem_cache#29-oX (epll)
		// return kmem_cache#29-oX (mout_mspll_kfc)
		// return kmem_cache#29-oX (sclk_spll)
		// return kmem_cache#29-oX (sclk_apll)
		// return kmem_cache#29-oX (sclk_uart0)

	kfree(clk);
fail_out:
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(clk_register);

/**
 * clk_unregister - unregister a currently registered clock
 * @clk: clock to unregister
 *
 * Currently unimplemented.
 */
void clk_unregister(struct clk *clk) {}
EXPORT_SYMBOL_GPL(clk_unregister);

static void devm_clk_release(struct device *dev, void *res)
{
	clk_unregister(res);
}

/**
 * devm_clk_register - resource managed clk_register()
 * @dev: device that is registering this clock
 * @hw: link to hardware-specific clock data
 *
 * Managed clk_register(). Clocks returned from this function are
 * automatically clk_unregister()ed on driver detach. See clk_register() for
 * more information.
 */
struct clk *devm_clk_register(struct device *dev, struct clk_hw *hw)
{
	struct clk *clk;
	int ret;

	clk = devres_alloc(devm_clk_release, sizeof(*clk), GFP_KERNEL);
	if (!clk)
		return ERR_PTR(-ENOMEM);

	ret = _clk_register(dev, hw, clk);
	if (!ret) {
		devres_add(dev, clk);
	} else {
		devres_free(clk);
		clk = ERR_PTR(ret);
	}

	return clk;
}
EXPORT_SYMBOL_GPL(devm_clk_register);

static int devm_clk_match(struct device *dev, void *res, void *data)
{
	struct clk *c = res;
	if (WARN_ON(!c))
		return 0;
	return c == data;
}

/**
 * devm_clk_unregister - resource managed clk_unregister()
 * @clk: clock to unregister
 *
 * Deallocate a clock allocated with devm_clk_register(). Normally
 * this function will not need to be called and the resource management
 * code will ensure that the resource is freed.
 */
void devm_clk_unregister(struct device *dev, struct clk *clk)
{
	WARN_ON(devres_release(dev, devm_clk_release, devm_clk_match, clk));
}
EXPORT_SYMBOL_GPL(devm_clk_unregister);

/***        clk rate change notifiers        ***/

/**
 * clk_notifier_register - add a clk rate change notifier
 * @clk: struct clk * to watch
 * @nb: struct notifier_block * with callback info
 *
 * Request notification when clk's rate changes.  This uses an SRCU
 * notifier because we want it to block and notifier unregistrations are
 * uncommon.  The callbacks associated with the notifier must not
 * re-enter into the clk framework by calling any top-level clk APIs;
 * this will cause a nested prepare_lock mutex.
 *
 * Pre-change notifier callbacks will be passed the current, pre-change
 * rate of the clk via struct clk_notifier_data.old_rate.  The new,
 * post-change rate of the clk is passed via struct
 * clk_notifier_data.new_rate.
 *
 * Post-change notifiers will pass the now-current, post-change rate of
 * the clk in both struct clk_notifier_data.old_rate and struct
 * clk_notifier_data.new_rate.
 *
 * Abort-change notifiers are effectively the opposite of pre-change
 * notifiers: the original pre-change clk rate is passed in via struct
 * clk_notifier_data.new_rate and the failed post-change rate is passed
 * in via struct clk_notifier_data.old_rate.
 *
 * clk_notifier_register() must be called from non-atomic context.
 * Returns -EINVAL if called with null arguments, -ENOMEM upon
 * allocation failure; otherwise, passes along the return value of
 * srcu_notifier_chain_register().
 */
int clk_notifier_register(struct clk *clk, struct notifier_block *nb)
{
	struct clk_notifier *cn;
	int ret = -ENOMEM;

	if (!clk || !nb)
		return -EINVAL;

	clk_prepare_lock();

	/* search the list of notifiers for this clk */
	list_for_each_entry(cn, &clk_notifier_list, node)
		if (cn->clk == clk)
			break;

	/* if clk wasn't in the notifier list, allocate new clk_notifier */
	if (cn->clk != clk) {
		cn = kzalloc(sizeof(struct clk_notifier), GFP_KERNEL);
		if (!cn)
			goto out;

		cn->clk = clk;
		srcu_init_notifier_head(&cn->notifier_head);

		list_add(&cn->node, &clk_notifier_list);
	}

	ret = srcu_notifier_chain_register(&cn->notifier_head, nb);

	clk->notifier_count++;

out:
	clk_prepare_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(clk_notifier_register);

/**
 * clk_notifier_unregister - remove a clk rate change notifier
 * @clk: struct clk *
 * @nb: struct notifier_block * with callback info
 *
 * Request no further notification for changes to 'clk' and frees memory
 * allocated in clk_notifier_register.
 *
 * Returns -EINVAL if called with null arguments; otherwise, passes
 * along the return value of srcu_notifier_chain_unregister().
 */
int clk_notifier_unregister(struct clk *clk, struct notifier_block *nb)
{
	struct clk_notifier *cn = NULL;
	int ret = -EINVAL;

	if (!clk || !nb)
		return -EINVAL;

	clk_prepare_lock();

	list_for_each_entry(cn, &clk_notifier_list, node)
		if (cn->clk == clk)
			break;

	if (cn->clk == clk) {
		ret = srcu_notifier_chain_unregister(&cn->notifier_head, nb);

		clk->notifier_count--;

		/* XXX the notifier code should handle this better */
		if (!cn->notifier_head.head) {
			srcu_cleanup_notifier_head(&cn->notifier_head);
			list_del(&cn->node);
			kfree(cn);
		}

	} else {
		ret = -ENOENT;
	}

	clk_prepare_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(clk_notifier_unregister);

#ifdef CONFIG_OF // CONFIG_OF=y
/**
 * struct of_clk_provider - Clock provider registration structure
 * @link: Entry in global list of clock providers
 * @node: Pointer to device tree node of clock provider
 * @get: Get clock callback.  Returns NULL or a struct clk for the
 *       given clock specifier
 * @data: context pointer to be passed into @get callback
 */
// ARM10C 20150110
// sizeof(struct of_clk_provider): 20 bytes
struct of_clk_provider {
	struct list_head link;

	struct device_node *node;
	struct clk *(*get)(struct of_phandle_args *clkspec, void *data);
	void *data;
};

// ARM10C 20150103
// __clk_of_table:
// __clk_of_table_fixed_factor_clk
// __clk_of_table_fixed_clk
// __clk_of_table_exynos4210_audss_clk
// __clk_of_table_exynos5250_audss_clk
// __clk_of_table_exynos5420_clk
extern struct of_device_id __clk_of_table[];

static const struct of_device_id __clk_of_table_sentinel
	__used __section(__clk_of_table_end);

// ARM10C 20150110
static LIST_HEAD(of_clk_providers);
// ARM10C 20150110
static DEFINE_MUTEX(of_clk_lock);

struct clk *of_clk_src_simple_get(struct of_phandle_args *clkspec,
				     void *data)
{
	return data;
}
EXPORT_SYMBOL_GPL(of_clk_src_simple_get);

// ARM10C 20150110
struct clk *of_clk_src_onecell_get(struct of_phandle_args *clkspec, void *data)
{
	struct clk_onecell_data *clk_data = data;
	unsigned int idx = clkspec->args[0];

	if (idx >= clk_data->clk_num) {
		pr_err("%s: invalid clock index %d\n", __func__, idx);
		return ERR_PTR(-EINVAL);
	}

	return clk_data->clks[idx];
}
EXPORT_SYMBOL_GPL(of_clk_src_onecell_get);

/**
 * of_clk_add_provider() - Register a clock provider for a node
 * @np: Device node pointer associated with clock provider
 * @clk_src_get: callback for decoding clock
 * @data: context pointer for @clk_src_get callback.
 */
// ARM10C 20150110
// np: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소, of_clk_src_onecell_get, &clk_data
int of_clk_add_provider(struct device_node *np,
			struct clk *(*clk_src_get)(struct of_phandle_args *clkspec,
						   void *data),
			void *data)
{
	struct of_clk_provider *cp;

	// sizeof(struct of_clk_provider): 20 bytes, GFP_KERNEL: 0xD0
	// kzalloc(20, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	cp = kzalloc(sizeof(struct of_clk_provider), GFP_KERNEL);
	// cp: kmem_cache#30-oX

	// cp: kmem_cache#30-oX
	if (!cp)
		return -ENOMEM;

	// cp->node: (kmem_cache#30-oX)->node,
	// np: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소
	// of_node_get(devtree에서 allnext로 순회 하면서 찾은 clock node의 주소):
	// devtree에서 allnext로 순회 하면서 찾은 clock node의 주소
	cp->node = of_node_get(np);
	// cp->node: (kmem_cache#30-oX)->node: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소

	// cp->data: (kmem_cache#30-oX)->data, data: &clk_data
	cp->data = data;
	// cp->data: (kmem_cache#30-oX)->data: &clk_data

	// cp->get: (kmem_cache#30-oX)->get, clk_src_get: of_clk_src_onecell_get
	cp->get = clk_src_get;
	// cp->get: (kmem_cache#30-oX)->get: of_clk_src_onecell_get

	mutex_lock(&of_clk_lock);
	// of_clk_lock을 사용하여 mutex lock 수행

	// &cp->link: (kmem_cache#30-oX)->link
	list_add(&cp->link, &of_clk_providers);
	// list인 of_clk_providers의 head에 (kmem_cache#30-oX)->link를 추가

	mutex_unlock(&of_clk_lock);
	// of_clk_lock을 사용하여 mutex unlock 수행

	// np->full_name: (devtree에서 allnext로 순회 하면서 찾은 clock node의 주소)->full_name:
	// "/clock-controller@10010000"
	pr_debug("Added clock from %s\n", np->full_name);
	// "Added clock from /clock-controller@10010000\n"

	return 0;
}
EXPORT_SYMBOL_GPL(of_clk_add_provider);

/**
 * of_clk_del_provider() - Remove a previously registered clock provider
 * @np: Device node pointer associated with clock provider
 */
void of_clk_del_provider(struct device_node *np)
{
	struct of_clk_provider *cp;

	mutex_lock(&of_clk_lock);
	list_for_each_entry(cp, &of_clk_providers, link) {
		if (cp->node == np) {
			list_del(&cp->link);
			of_node_put(cp->node);
			kfree(cp);
			break;
		}
	}
	mutex_unlock(&of_clk_lock);
}
EXPORT_SYMBOL_GPL(of_clk_del_provider);

struct clk *of_clk_get_from_provider(struct of_phandle_args *clkspec)
{
	struct of_clk_provider *provider;
	struct clk *clk = ERR_PTR(-ENOENT);

	/* Check if we have such a provider in our array */
	mutex_lock(&of_clk_lock);
	list_for_each_entry(provider, &of_clk_providers, link) {
		if (provider->node == clkspec->np)
			clk = provider->get(clkspec, provider->data);
		if (!IS_ERR(clk))
			break;
	}
	mutex_unlock(&of_clk_lock);

	return clk;
}

int of_clk_get_parent_count(struct device_node *np)
{
	return of_count_phandle_with_args(np, "clocks", "#clock-cells");
}
EXPORT_SYMBOL_GPL(of_clk_get_parent_count);

const char *of_clk_get_parent_name(struct device_node *np, int index)
{
	struct of_phandle_args clkspec;
	const char *clk_name;
	int rc;

	if (index < 0)
		return NULL;

	rc = of_parse_phandle_with_args(np, "clocks", "#clock-cells", index,
					&clkspec);
	if (rc)
		return NULL;

	if (of_property_read_string_index(clkspec.np, "clock-output-names",
					  clkspec.args_count ? clkspec.args[0] : 0,
					  &clk_name) < 0)
		clk_name = clkspec.np->name;

	of_node_put(clkspec.np);
	return clk_name;
}
EXPORT_SYMBOL_GPL(of_clk_get_parent_name);

/**
 * of_clk_init() - Scan and init clock providers from the DT
 * @matches: array of compatible values and init functions for providers.
 *
 * This function scans the device tree for matching clock providers and
 * calls their initialization functions
 */
// ARM10C 20150103
// NULL
void __init of_clk_init(const struct of_device_id *matches)
{
	const struct of_device_id *match;
	struct device_node *np;

	// matches: NULL
	if (!matches)
		// __clk_of_table:
		// __clk_of_table_fixed_factor_clk
		// __clk_of_table_fixed_clk
		// __clk_of_table_exynos4210_audss_clk
		// __clk_of_table_exynos5250_audss_clk
		// __clk_of_table_exynos5420_clk
		matches = __clk_of_table;
		// matches:
		// __clk_of_table_fixed_factor_clk
		// __clk_of_table_fixed_clk
		// __clk_of_table_exynos4210_audss_clk
		// __clk_of_table_exynos5250_audss_clk
		// __clk_of_table_exynos5420_clk

	for_each_matching_node_and_match(np, matches, &match) {
	// for (np = of_find_matching_node_and_match(NULL, matches, &match);
	//      np; np = of_find_matching_node_and_match(np, matches, &match))

		// np: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소, match: __clk_of_table_exynos5420_clk

		// match->data: __clk_of_table_exynos5420_clk.data: exynos5420_clk_init
		of_clk_init_cb_t clk_init_cb = match->data;
		// clk_init_cb: exynos5420_clk_init

		// clk_init_cb: exynos5420_clk_init,
		// np: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소
		// exynos5420_clk_init(devtree에서 allnext로 순회 하면서 찾은 clock node의 주소)
		clk_init_cb(np);

		// exynos5420_clk_init에서 한일:
		//
		// device tree 있는 clock node에서 node의 resource 값을 가져옴
		// of_address_to_resource에서 한일(index: 0):
		// (&res)->start: 0x10010000
		// (&res)->end: 0x1003ffff
		// (&res)->flags: IORESOURCE_MEM: 0x00000200
		// (&res)->name: "/clock-controller@10010000"
		/*
		// alloc area (CLK) 를 만들고 rb tree에 alloc area 를 추가
		// 가상주소 va_start 기준으로 CLK 를 RB Tree 추가한 결과
		//
		//                                  CHID-b
		//                               (0xF8000000)
		//                              /            \
		//                         TMR-b               PMU-b
		//                    (0xF6300000)             (0xF8180000)
		//                      /      \               /           \
		//                GIC#1-r      WDT-b         CMU-b         SRAM-b
		//            (0xF0002000)   (0xF6400000)  (0xF8100000)   (0xF8400000)
		//             /       \                                          \
		//        GIC#0-b     CLK-b                                        ROMC-r
		//    (0xF0000000)   (0xF0040000)                                 (0xF84C0000)
		//                   /      \
		//               COMB-r     SYSC-r
		//          (0xF0004000)   (0xF6100000)
		//
		// vmap_area_list에 GIC#0 - GIC#1 - COMB - CLK - SYSC -TMR - WDT - CHID - CMU - PMU - SRAM - ROMC
		// 순서로 리스트에 연결이 됨
		//
		// (kmem_cache#30-oX (vm_struct))->flags: GFP_KERNEL: 0xD0
		// (kmem_cache#30-oX (vm_struct))->addr: 0xf0040000
		// (kmem_cache#30-oX (vm_struct))->size: 0x31000
		// (kmem_cache#30-oX (vm_struct))->caller: __builtin_return_address(0)
		//
		// (kmem_cache#30-oX (vmap_area CLK))->vm: kmem_cache#30-oX (vm_struct)
		// (kmem_cache#30-oX (vmap_area CLK))->flags: 0x04
		*/
		// device tree 있는  clock node에서 node의 resource 값을 pgtable에 매핑함
		// 0xc0004780이 가리키는 pte의 시작주소에 0x10010653 값을 갱신
		// (linux pgtable과 hardware pgtable의 값 같이 갱신)
		//
		//  pgd                   pte
		// |              |
		// +--------------+
		// |              |       +--------------+ +0
		// |              |       |  0xXXXXXXXX  | ---> 0x10010653 에 매칭되는 linux pgtable 값
		// +- - - - - - - +       |  Linux pt 0  |
		// |              |       +--------------+ +1024
		// |              |       |              |
		// +--------------+ +0    |  Linux pt 1  |
		// | *(c0004780)  |-----> +--------------+ +2048
		// |              |       |  0x10010653  | ---> 2308
		// +- - - - - - - + +4    |   h/w pt 0   |
		// | *(c0004784)  |-----> +--------------+ +3072
		// |              |       +              +
		// +--------------+ +8    |   h/w pt 1   |
		// |              |       +--------------+ +4096
		//
		// cache의 값을 전부 메모리에 반영
		//
		// samsung_clk_init 에서 한일:
		// struct samsung_clk_reg_dump를 59개 만큼 메모리를 할당 받아
		// exynos5420_clk_regs의 값으로 맴버값 세팅
		// (kmem_cache#26-oX)[0...58].offset: exynos5420_clk_regs[0...58]
		//
		// syscore_ops_list의 tail에 (&samsung_clk_syscore_ops)->node 를 추가
		//
		// struct clk * 를 769개 만큼 메모리를 clk_table에 할당 받음
		// clk_table: kmem_cache#23-o0
		//
		// clk_data.clks: kmem_cache#23-o0 (clk_table)
		// clk_data.clk_num: 769
		//
		// struct of_clk_provider 의 메모리(kmem_cache#30-oX)를 할당 받고 맴버값 초기화 수행
		//
		// (kmem_cache#30-oX)->node: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소
		// (kmem_cache#30-oX)->data: &clk_data
		// (kmem_cache#30-oX)->get: of_clk_src_onecell_get
		//
		// list인 of_clk_providers의 head에 (kmem_cache#30-oX)->link를 추가
		//
		// samsung_clk_of_register_fixed_ext 에서 한일:
		//
		// devtree에서 allnext로 순회 하면서 찾은 fixed-rate-clocks node 에서
		// fixed-rate-clocks node에서 "clock-frequency" property값을 freq에 읽어옴
		// freq: 24000000
		// exynos5420_fixed_rate_ext_clks[0].fixed_rate: 24000000
		//
		// struct clk_fixed_rate 만큼 메모리를 kmem_cache#30-oX 할당 받고 struct clk_fixed_rate 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->fixed_rate: 24000000
		// (kmem_cache#30-oX)->hw.init: &init
		// (&(kmem_cache#30-oX)->hw)->clk: kmem_cache#29-oX
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX)->name: kmem_cache#30-oX ("fin_pll")
		// (kmem_cache#29-oX)->ops: &clk_fixed_rate_ops
		// (kmem_cache#29-oX)->hw: &(kmem_cache#30-oX)->hw
		// (kmem_cache#29-oX)->flags: 0x30
		// (kmem_cache#29-oX)->num_parents: 0
		// (kmem_cache#29-oX)->parent_names: ((void *)16)
		// (kmem_cache#29-oX)->parent: NULL
		// (kmem_cache#29-oX)->rate: 24000000
		//
		// (&(kmem_cache#29-oX)->child_node)->next: NULL
		// (&(kmem_cache#29-oX)->child_node)->pprev: &(&(kmem_cache#29-oX)->child_node)
		//
		// (&clk_root_list)->first: &(kmem_cache#29-oX)->child_node
		//
		// clk_table[1]: (kmem_cache#23-o0)[1]: kmem_cache#29-oX
		//
		// struct clk_lookup_alloc 의 메모리를 kmem_cache#30-oX 할당 받고
		// struct clk_lookup_alloc 맴버값 초기화 수행
		//
		// (kmem_cache#30-oX)->cl.clk: kmem_cache#29-oX
		// (kmem_cache#30-oX)->con_id: "fin_pll"
		// (kmem_cache#30-oX)->cl.con_id: (kmem_cache#30-oX)->con_id: "fin_pll"
		//
		// list clocks에 &(&(kmem_cache#30-oX)->cl)->nade를 tail로 추가
		//
		// samsung_clk_register_pll에서 한일:
		// exynos5420_plls에 정의되어 있는 PLL 값들을 초기화 수행
		//
		// [apll] 의 초기화 값 수행 결과:
		// struct clk_fixed_rate 만큼 메모리를 kmem_cache#30-oX (apll) 할당 받고 struct clk_fixed_rate 의 멤버 값을 아래와 같이 초기화 수행
		// pll: kmem_cache#30-oX (apll)
		//
		// (kmem_cache#30-oX (apll))->hw.init: &init
		// (kmem_cache#30-oX (apll))->type: pll_2550: 2
		// (kmem_cache#30-oX (apll))->lock_reg: 0xf0040000
		// (kmem_cache#30-oX (apll))->con_reg: 0xf0040100
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX (apll) 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX (apll))->name: kmem_cache#30-oX ("fout_apll")
		// (kmem_cache#29-oX (apll))->ops: &samsung_pll35xx_clk_min_ops
		// (kmem_cache#29-oX (apll))->hw: &(kmem_cache#30-oX (apll))->hw
		// (kmem_cache#29-oX (apll))->flags: 0x40
		// (kmem_cache#29-oX (apll))->num_parents: 1
		// (kmem_cache#29-oX (apll))->parent_names: kmem_cache#30-oX
		// (kmem_cache#29-oX (apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// (kmem_cache#29-oX (apll))->parent: kmem_cache#29-oX (fin_pll)
		// (kmem_cache#29-oX (apll))->rate: 1000000000 (1 Ghz)
		//
		// (&(kmem_cache#29-oX (apll))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (apll))->child_node)->pprev: &(&(kmem_cache#29-oX (apll))->child_node)
		//
		// (&(kmem_cache#29-oX (fin_pll))->children)->first: &(kmem_cache#29-oX (apll))->child_node
		//
		// (&(kmem_cache#30-oX (apll))->hw)->clk: kmem_cache#29-oX (apll)
		//
		// clk_table[2]: (kmem_cache#23-o0)[2]: kmem_cache#29-oX (apll)
		//
		// struct clk_lookup_alloc 의 메모리를 kmem_cache#30-oX (apll) 할당 받고
		// struct clk_lookup_alloc 맴버값 초기화 수행
		//
		// (kmem_cache#30-oX)->cl.clk: kmem_cache#29-oX (apll)
		// (kmem_cache#30-oX)->con_id: "fout_apll"
		// (kmem_cache#30-oX)->cl.con_id: (kmem_cache#30-oX)->con_id: "fout_apll"
		//
		// list clocks에 &(&(kmem_cache#30-oX (apll))->cl)->nade를 tail로 추가
		//
		// cpll, dpll, epll, rpll, ipll, spll, vpll, mpll, bpll, kpll 초기화 수행 결과는 생략.
		//
		// samsung_clk_register_fixed_rate에서 한일:
		// exynos5420_fixed_rate_clks에 정의되어 있는 fixed rate 값들을 초기화 수행
		//
		// sclk_hdmiphy 의 초기화 값 수행 결과
		// struct clk_fixed_rate 만큼 메모리를 kmem_cache#30-oX 할당 받고 struct clk_fixed_rate 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->fixed_rate: 24000000
		// (kmem_cache#30-oX)->hw.init: &init
		// (&(kmem_cache#30-oX)->hw)->clk: kmem_cache#29-oX
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX)->name: kmem_cache#30-oX ("sclk_hdmiphy")
		// (kmem_cache#29-oX)->ops: &clk_fixed_rate_ops
		// (kmem_cache#29-oX)->hw: &(kmem_cache#30-oX)->hw
		// (kmem_cache#29-oX)->flags: 0x30
		// (kmem_cache#29-oX)->num_parents: 0
		// (kmem_cache#29-oX)->parent_names: ((void *)16)
		// (kmem_cache#29-oX)->parent: NULL
		// (kmem_cache#29-oX)->rate: 24000000
		//
		// (&(kmem_cache#29-oX)->child_node)->next: NULL
		// (&(kmem_cache#29-oX)->child_node)->pprev: &(&(kmem_cache#29-oX)->child_node)
		//
		// (&clk_root_list)->first: &(kmem_cache#29-oX)->child_node
		//
		// clk_table[158]: (kmem_cache#23-o0)[158]: kmem_cache#29-oX
		//
		// struct clk_lookup_alloc 의 메모리를 kmem_cache#30-oX 할당 받고
		// struct clk_lookup_alloc 맴버값 초기화 수행
		//
		// (kmem_cache#30-oX)->cl.clk: kmem_cache#29-oX
		// (kmem_cache#30-oX)->con_id: "fin_pll"
		// (kmem_cache#30-oX)->cl.con_id: (kmem_cache#30-oX)->con_id: "fin_pll"
		//
		// list clocks에 &(&(kmem_cache#30-oX)->cl)->nade를 tail로 추가
		//
		// "sclk_pwi", "sclk_usbh20", "mphy_refclk_ixtal24", "sclk_usbh20_scan_clk" 초기화 수행 결과는 생략.
		//
		// samsung_clk_register_fixed_factor에서 한일:
		// struct clk_fixed_factor 만큼 메모리를 kmem_cache#30-oX 할당 받고 struct clk_fixed_factor 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->mult: 1
		// (kmem_cache#30-oX)->div: 2
		// (kmem_cache#30-oX)->hw.init: &init
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX (sclk_hsic_12m) 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX (sclk_hsic_12m))->name: kmem_cache#30-oX ("sclk_hsic_12m")
		// (kmem_cache#29-oX (sclk_hsic_12m))->ops: &clk_fixed_factor_ops
		// (kmem_cache#29-oX (sclk_hsic_12m))->hw: &(kmem_cache#30-oX (sclk_hsic_12m))->hw
		// (kmem_cache#29-oX (sclk_hsic_12m))->flags: 0x20
		// (kmem_cache#29-oX (sclk_hsic_12m))->num_parents: 1
		// (kmem_cache#29-oX (sclk_hsic_12m))->parent_names: kmem_cache#30-oX
		// (kmem_cache#29-oX (sclk_hsic_12m))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// (kmem_cache#29-oX (sclk_hsic_12m))->parent: kmem_cache#29-oX (fin_pll)
		// (kmem_cache#29-oX (sclk_hsic_12m))->rate: 12000000
		//
		// (&(kmem_cache#29-oX (sclk_hsic_12m))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_hsic_12m))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_hsic_12m))->child_node)
		//
		// (&(kmem_cache#29-oX (fin_pll))->children)->first: &(kmem_cache#29-oX (sclk_hsic_12m))->child_node
		//
		// (&(kmem_cache#30-oX (sclk_hsic_12m))->hw)->clk: kmem_cache#29-oX (sclk_hsic_12m)
		//
		// clk_table[0]: (kmem_cache#23-o0)[0]: kmem_cache#29-oX (sclk_hsic_12m)
		//
		// samsung_clk_register_mux 에서 한일:
		// exynos5420_mux_clks에 등록 되어 있는 clock mux 들의 초기화를 수행
		//
		// mout_mspll_kfc, sclk_dpll를 수행한 결과:
		//
		// (mout_mspll_kfc) 에서 한일:
		// struct clk_mux 만큼 메모리를 kmem_cache#30-oX (mout_mspll_kfc) 할당 받고 struct clk_mux 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->reg: 0xf005021c
		// (kmem_cache#30-oX)->shift: 8
		// (kmem_cache#30-oX)->mask: 0x3
		// (kmem_cache#30-oX)->flags: 0
		// (kmem_cache#30-oX)->lock: &lock
		// (kmem_cache#30-oX)->table: NULL
		// (kmem_cache#30-oX)->hw.init: &init
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX (mout_mspll_kfc) 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX (mout_mspll_kfc))->name: kmem_cache#30-oX ("mout_mspll_kfc")
		// (kmem_cache#29-oX (mout_mspll_kfc))->ops: &clk_mux_ops
		// (kmem_cache#29-oX (mout_mspll_kfc))->hw: &(kmem_cache#30-oX (mout_mspll_kfc))->hw
		// (kmem_cache#29-oX (mout_mspll_kfc))->flags: 0xa0
		// (kmem_cache#29-oX (mout_mspll_kfc))->num_parents 4
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names: kmem_cache#30-oX
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "sclk_cpll"
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[1]: (kmem_cache#30-oX)[1]: kmem_cache#30-oX: "sclk_dpll"
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[2]: (kmem_cache#30-oX)[2]: kmem_cache#30-oX: "sclk_mpll"
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent_names[3]: (kmem_cache#30-oX)[3]: kmem_cache#30-oX: "sclk_spll"
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent: NULL
		// (kmem_cache#29-oX (mout_mspll_kfc))->rate: 0
		//
		// (kmem_cache#29-oX (mout_mspll_kfc))->parents: kmem_cache#30-oX
		// (kmem_cache#29-oX (mout_mspll_kfc))->parents[0...3]: (kmem_cache#30-oX)[0...3]: NULL
		//
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
		//
		// (&clk_orphan_list)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
		//
		// (&(kmem_cache#30-oX (mout_mspll_kfc))->hw)->clk: kmem_cache#29-oX (mout_mspll_kfc)
		//
		// (sclk_spll) 에서 한일:
		// struct clk_mux 만큼 메모리를 kmem_cache#30-oX (sclk_spll) 할당 받고 struct clk_mux 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#30-oX)->reg: 0xf0050218
		// (kmem_cache#30-oX)->shift: 8
		// (kmem_cache#30-oX)->mask: 0x3
		// (kmem_cache#30-oX)->flags: 0
		// (kmem_cache#30-oX)->lock: &lock
		// (kmem_cache#30-oX)->table: NULL
		// (kmem_cache#30-oX)->hw.init: &init
		//
		// struct clk 만큼 메모리를 kmem_cache#29-oX (sclk_spll) 할당 받고 struct clk 의 멤버 값을 아래와 같이 초기화 수행
		//
		// (kmem_cache#29-oX (sclk_spll))->name: kmem_cache#30-oX ("sclk_spll")
		// (kmem_cache#29-oX (sclk_spll))->ops: &clk_mux_ops
		// (kmem_cache#29-oX (sclk_spll))->hw: &(kmem_cache#30-oX (sclk_spll))->hw
		// (kmem_cache#29-oX (sclk_spll))->flags: 0xa0
		// (kmem_cache#29-oX (sclk_spll))->num_parents 2
		// (kmem_cache#29-oX (sclk_spll))->parent_names: kmem_cache#30-oX
		// (kmem_cache#29-oX (sclk_spll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "fin_pll"
		// (kmem_cache#29-oX (sclk_spll))->parent_names[1]: (kmem_cache#30-oX)[1]: kmem_cache#30-oX: "fout_spll"
		// (kmem_cache#29-oX (sclk_spll))->parent: NULL
		// (kmem_cache#29-oX (sclk_spll))->rate: 600000000
		//
		// (kmem_cache#29-oX (sclk_spll))->parents: kmem_cache#30-oX
		// (kmem_cache#29-oX (sclk_spll))->parents[0]: (kmem_cache#30-oX)[0]: kmem_cache#29-oX (fin_pll)
		// (kmem_cache#29-oX (sclk_spll))->parents[1]: (kmem_cache#30-oX)[1]: kmem_cache#29-oX (fout_spll)
		//
		// parents 인 "fin_pll", "fout_spll" 값들 중에
		// register CLK_SRC_TOP6 의 값을 읽어서 mux 할 parent clock 을 선택함
		// return된 값이 선택된 parent clock의 index 값임
		// parent clock 중에 선택된 parent clock의 이름으로 등록된 clk struct를 반환함
		//
		// (&(kmem_cache#29-oX (sclk_spll))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_spll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_spll))->child_node)
		//
		// (&(kmem_cache#29-oX (fout_spll))->children)->first: &(kmem_cache#29-oX (sclk_spll))->child_node
		//
		// (&(kmem_cache#30-oX (sclk_spll))->hw)->clk: kmem_cache#29-oX (sclk_spll)
		//
		// orphan 으로 등록된 mout_mspll_kfc의 값을 갱신
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
		//
		// (&(kmem_cache#29-oX (sclk_spll))->children)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
		//
		// (kmem_cache#29-oX (mout_mspll_kfc))->parent: kmem_cache#29-oX (sclk_spll)
		//
		// parent가 있는지 확인후 parent의 clock rate 값으로 clock rate 값을 세팅
		// (kmem_cache#29-oX (mout_mspll_kfc))->rate: 600000000
		//
		// samsung_clk_register_div에서 한일:
		//
		// exynos5420_div_clks의 div 들 중에 array index 1번의
		// DIV(none, "sclk_apll", "mout_apll", DIV_CPU0, 24, 3) 을 가지고 분석 진행
		//
		// struct clk_divider 만큼 메모리를 할당 받아 맴버값 초기화 수행
		// kmem_cache#30-oX (sclk_apll)
		// (kmem_cache#30-oX (sclk_apll))->reg: 0xf0040500
		// (kmem_cache#30-oX (sclk_apll))->shift: 24
		// (kmem_cache#30-oX (sclk_apll))->width: 3
		// (kmem_cache#30-oX (sclk_apll))->flags: 0
		// (kmem_cache#30-oX (sclk_apll))->lock: &lock
		// (kmem_cache#30-oX (sclk_apll))->hw.init: &init
		// (kmem_cache#30-oX (sclk_apll))->table: NULL
		//
		// struct clk 만큼 메모리를 할당 받아 맴버값 초기화 수행
		// kmem_cache#29-oX (sclk_apll)
		// (kmem_cache#29-oX (sclk_apll))->name: kmem_cache#30-oX ("sclk_apll")
		// (kmem_cache#29-oX (sclk_apll))->ops: &clk_divider_ops
		// (kmem_cache#29-oX (sclk_apll))->hw: &(kmem_cache#30-oX (sclk_apll))->hw
		// (kmem_cache#29-oX (sclk_apll))->flags: 0x0
		// (kmem_cache#29-oX (sclk_apll))->num_parents 1
		// (kmem_cache#29-oX (sclk_apll))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "mout_apll"
		// (kmem_cache#29-oX (sclk_apll))->parent: kmem_cache#29-oX (mout_apll)
		// (kmem_cache#29-oX (sclk_apll))->rate: 800000000
		//
		// clk 의 이름이 "mout_apll"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행
		//
		// (&(kmem_cache#29-oX (sclk_apll))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_apll))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_apll))->child_node)
		//
		// (&(kmem_cache#29-oX (fout_dpll))->children)->first: &(kmem_cache#29-oX (sclk_apll))->child_node
		//
		// exynos5420_div_clks의 idx 0, 2...52 까지 loop 수행
		//
		// samsung_clk_register_gate 에서 한일:
		//
		// exynos5420_gate_clks의 gate 들 중에 array index 13번의
		// GATE(sclk_fimd1, "sclk_fimd1", "dout_fimd1", GATE_TOP_SCLK_PERIC, 0, CLK_SET_RATE_PARENT, 0) 을 가지고 분석 진행
		//
		// struct clk_gate 만큼 메모리를 할당 받아 맴버값 초기화 수행
		// kmem_cache#30-oX (sclk_fimd1)
		// (kmem_cache#30-oX (sclk_fimd1))->reg: 0xf0050850
		// (kmem_cache#30-oX (sclk_fimd1))->bit_idx: 0
		// (kmem_cache#30-oX (sclk_fimd1))->flags: 0
		// (kmem_cache#30-oX (sclk_fimd1))->lock: &lock
		// (kmem_cache#30-oX (sclk_fimd1))->hw.init: &init
		// (kmem_cache#30-oX (sclk_fimd1))->table: NULL
		//
		// struct clk 만큼 메모리를 할당 받아 맴버값 초기화 수행
		// kmem_cache#29-oX (sclk_fimd1)
		// (kmem_cache#29-oX (sclk_fimd1))->name: kmem_cache#30-oX ("sclk_fimd1")
		// (kmem_cache#29-oX (sclk_fimd1))->ops: &clk_gate_ops
		// (kmem_cache#29-oX (sclk_fimd1))->hw: &(kmem_cache#30-oX (sclk_fimd1))->hw
		// (kmem_cache#29-oX (sclk_fimd1))->flags: 0x24
		// (kmem_cache#29-oX (sclk_fimd1))->num_parents 1
		// (kmem_cache#29-oX (sclk_fimd1))->parent_names[0]: (kmem_cache#30-oX)[0]: kmem_cache#30-oX: "mout_apll"
		// (kmem_cache#29-oX (sclk_fimd1))->parent: kmem_cache#29-oX (dout_fimd1)
		// (kmem_cache#29-oX (sclk_fimd1))->rate: 266000000
		//
		// clk 의 이름이 "dout_fimd1"인 메모리 값을 clk_root_list 에서 찾아 리턴 수행
		//
		// (&(kmem_cache#29-oX (sclk_fimd1))->child_node)->next: NULL
		// (&(kmem_cache#29-oX (sclk_fimd1))->child_node)->pprev: &(&(kmem_cache#29-oX (sclk_fimd1))->child_node)
		//
		// (&(kmem_cache#29-oX (dout_fimd1))->children)->first: &(kmem_cache#29-oX (sclk_fimd1))->child_node
		//
		// clk_table[128]: (kmem_cache#23-o0)[128]: kmem_cache#29-oX (sclk_fimd1)
		//
		// exynos5420_gate_clks의 idx: 0...12...136 loop 수행
	}
}
#endif
