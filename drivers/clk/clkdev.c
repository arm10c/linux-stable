/*
 * drivers/clk/clkdev.c
 *
 *  Copyright (C) 2008 Russell King.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Helper for the clk API to assist looking up a struct clk.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/clk.h>
#include <linux/clkdev.h>
#include <linux/of.h>

// ARM10C 20150117
static LIST_HEAD(clocks);
// ARM10C 20150117
static DEFINE_MUTEX(clocks_mutex);

#if defined(CONFIG_OF) && defined(CONFIG_COMMON_CLK)
struct clk *of_clk_get(struct device_node *np, int index)
{
	struct of_phandle_args clkspec;
	struct clk *clk;
	int rc;

	if (index < 0)
		return ERR_PTR(-EINVAL);

	rc = of_parse_phandle_with_args(np, "clocks", "#clock-cells", index,
					&clkspec);
	if (rc)
		return ERR_PTR(rc);

	clk = of_clk_get_from_provider(&clkspec);
	of_node_put(clkspec.np);
	return clk;
}
EXPORT_SYMBOL(of_clk_get);

/**
 * of_clk_get_by_name() - Parse and lookup a clock referenced by a device node
 * @np: pointer to clock consumer node
 * @name: name of consumer's clock input, or NULL for the first clock reference
 *
 * This function parses the clocks and clock-names properties,
 * and uses them to look up the struct clk from the registered list of clock
 * providers.
 */
struct clk *of_clk_get_by_name(struct device_node *np, const char *name)
{
	struct clk *clk = ERR_PTR(-ENOENT);

	/* Walk up the tree of devices looking for a clock that matches */
	while (np) {
		int index = 0;

		/*
		 * For named clocks, first look up the name in the
		 * "clock-names" property.  If it cannot be found, then
		 * index will be an error code, and of_clk_get() will fail.
		 */
		if (name)
			index = of_property_match_string(np, "clock-names", name);
		clk = of_clk_get(np, index);
		if (!IS_ERR(clk))
			break;
		else if (name && index >= 0) {
			pr_err("ERROR: could not get clock %s:%s(%i)\n",
				np->full_name, name ? name : "", index);
			return clk;
		}

		/*
		 * No matching clock found on this node.  If the parent node
		 * has a "clock-ranges" property, then we can try one of its
		 * clocks.
		 */
		np = np->parent;
		if (np && !of_get_property(np, "clock-ranges", NULL))
			break;
	}

	return clk;
}
EXPORT_SYMBOL(of_clk_get_by_name);
#endif

/*
 * Find the correct struct clk for the device and connection ID.
 * We do slightly fuzzy matching here:
 *  An entry with a NULL ID is assumed to be a wildcard.
 *  If an entry has a device ID, it must match
 *  If an entry has a connection ID, it must match
 * Then we take the most specific entry - with the following
 * order of precedence: dev+con > dev only > con only.
 */
static struct clk_lookup *clk_find(const char *dev_id, const char *con_id)
{
	struct clk_lookup *p, *cl = NULL;
	int match, best_found = 0, best_possible = 0;

	if (dev_id)
		best_possible += 2;
	if (con_id)
		best_possible += 1;

	list_for_each_entry(p, &clocks, node) {
		match = 0;
		if (p->dev_id) {
			if (!dev_id || strcmp(p->dev_id, dev_id))
				continue;
			match += 2;
		}
		if (p->con_id) {
			if (!con_id || strcmp(p->con_id, con_id))
				continue;
			match += 1;
		}

		if (match > best_found) {
			cl = p;
			if (match != best_possible)
				best_found = match;
			else
				break;
		}
	}
	return cl;
}

struct clk *clk_get_sys(const char *dev_id, const char *con_id)
{
	struct clk_lookup *cl;

	mutex_lock(&clocks_mutex);
	cl = clk_find(dev_id, con_id);
	if (cl && !__clk_get(cl->clk))
		cl = NULL;
	mutex_unlock(&clocks_mutex);

	return cl ? cl->clk : ERR_PTR(-ENOENT);
}
EXPORT_SYMBOL(clk_get_sys);

struct clk *clk_get(struct device *dev, const char *con_id)
{
	const char *dev_id = dev ? dev_name(dev) : NULL;
	struct clk *clk;

	if (dev) {
		clk = of_clk_get_by_name(dev->of_node, con_id);
		if (!IS_ERR(clk) && __clk_get(clk))
			return clk;
	}

	return clk_get_sys(dev_id, con_id);
}
EXPORT_SYMBOL(clk_get);

void clk_put(struct clk *clk)
{
	__clk_put(clk);
}
EXPORT_SYMBOL(clk_put);

// ARM10C 20150117
// cl: &(kmem_cache#30-oX)->cl
// ARM10C 20150124
// cl: &(kmem_cache#30-oX (apll))->cl
void clkdev_add(struct clk_lookup *cl)
{
	mutex_lock(&clocks_mutex);
	// clocks_mutex를 이용한 mutex lock 수행

	// &cl->node: &(&(kmem_cache#30-oX)->cl)->nade
	list_add_tail(&cl->node, &clocks);

	// list_add_tail 에서 한일:
	// list clocks에 &(&(kmem_cache#30-oX)->cl)->nade를 tail로 추가

	mutex_unlock(&clocks_mutex);
	// clocks_mutex를 이용한 mutex unlock 수행
}
EXPORT_SYMBOL(clkdev_add);

void __init clkdev_add_table(struct clk_lookup *cl, size_t num)
{
	mutex_lock(&clocks_mutex);
	while (num--) {
		list_add_tail(&cl->node, &clocks);
		cl++;
	}
	mutex_unlock(&clocks_mutex);
}

// ARM10C 20150117
// MAX_DEV_ID: 20
#define MAX_DEV_ID	20
// ARM10C 20150117
// MAX_CON_ID: 16
#define MAX_CON_ID	16

// ARM10C 20150117
// sizeof(struct clk_lookup_alloc): 56 bytes
struct clk_lookup_alloc {
	struct clk_lookup cl;
	// MAX_DEV_ID: 20
	char	dev_id[MAX_DEV_ID];
	// MAX_CON_ID: 16
	char	con_id[MAX_CON_ID];
};

// ARM10C 20150117
// clk: kmem_cache#29-oX, con_id: "fin_pll", dev_fmt: NULL, ap
// ARM10C 20150124
// clk: kmem_cache#29-oX (apll), con_id: "fout_apll", dev_fmt: NULL, ap
static struct clk_lookup * __init_refok
vclkdev_alloc(struct clk *clk, const char *con_id, const char *dev_fmt,
	va_list ap)
{
	struct clk_lookup_alloc *cla;

	// sizeof(struct clk_lookup_alloc): 56 bytes
	// __clkdev_alloc(56): kmem_cache#30-oX
	// sizeof(struct clk_lookup_alloc): 56 bytes
	// __clkdev_alloc(56): kmem_cache#30-oX (apll)
	cla = __clkdev_alloc(sizeof(*cla));
	// cla: kmem_cache#30-oX
	// cla: kmem_cache#30-oX (apll)

	// cla: kmem_cache#30-oX
	// cla: kmem_cache#30-oX (apll)
	if (!cla)
		return NULL;

	// cla->cl.clk: (kmem_cache#30-oX)->cl.clk, clk: kmem_cache#29-oX
	// cla->cl.clk: (kmem_cache#30-oX (apll))->cl.clk, clk: kmem_cache#29-oX (apll)
	cla->cl.clk = clk;
	// cla->cl.clk: (kmem_cache#30-oX)->cl.clk: kmem_cache#29-oX
	// cla->cl.clk: (kmem_cache#30-oX (apll))->cl.clk: kmem_cache#29-oX (apll)

	// con_id: "fin_pll"
	// con_id: "fout_apll"
	if (con_id) {
		// cla->con_id: (kmem_cache#30-oX)->con_id, con_id: "fin_pll",
		// sizeof((kmem_cache#30-oX)->con_id): 16
		// cla->con_id: (kmem_cache#30-oX (apll))->con_id, con_id: "fout_apll",
		// sizeof((kmem_cache#30-oX (apll))->con_id): 16
		strlcpy(cla->con_id, con_id, sizeof(cla->con_id));
		// cla->con_id: (kmem_cache#30-oX)->con_id: "fin_pll"
		// cla->con_id: (kmem_cache#30-oX (apll))->con_id: "fout_apll"

		// cla->cl.con_id: (kmem_cache#30-oX)->cl.con_id,
		// cla->con_id: (kmem_cache#30-oX)->con_id: "fin_pll"
		// cla->cl.con_id: (kmem_cache#30-oX (apll))->cl.con_id,
		// cla->con_id: (kmem_cache#30-oX (apll))->con_id: "fout_apll"
		cla->cl.con_id = cla->con_id;
		// cla->cl.con_id: (kmem_cache#30-oX)->cl.con_id: (kmem_cache#30-oX)->con_id: "fin_pll"
		// cla->cl.con_id: (kmem_cache#30-oX (apll))->cl.con_id: (kmem_cache#30-oX (apll))->con_id: "fin_pll"
	}

	// dev_fmt: NULL
	// dev_fmt: NULL
	if (dev_fmt) {
		vscnprintf(cla->dev_id, sizeof(cla->dev_id), dev_fmt, ap);
		cla->cl.dev_id = cla->dev_id;
	}

	// cla: &(kmem_cache#30-oX)->cl
	// cla: &(kmem_cache#30-oX (apll))->cl
	return &cla->cl;
	// return &(kmem_cache#30-oX)->cl
	// return &(kmem_cache#30-oX (apll))->cl
}

struct clk_lookup * __init_refok
clkdev_alloc(struct clk *clk, const char *con_id, const char *dev_fmt, ...)
{
	struct clk_lookup *cl;
	va_list ap;

	va_start(ap, dev_fmt);
	cl = vclkdev_alloc(clk, con_id, dev_fmt, ap);
	va_end(ap);

	return cl;
}
EXPORT_SYMBOL(clkdev_alloc);

int clk_add_alias(const char *alias, const char *alias_dev_name, char *id,
	struct device *dev)
{
	struct clk *r = clk_get(dev, id);
	struct clk_lookup *l;

	if (IS_ERR(r))
		return PTR_ERR(r);

	l = clkdev_alloc(r, alias, alias_dev_name);
	clk_put(r);
	if (!l)
		return -ENODEV;
	clkdev_add(l);
	return 0;
}
EXPORT_SYMBOL(clk_add_alias);

/*
 * clkdev_drop - remove a clock dynamically allocated
 */
void clkdev_drop(struct clk_lookup *cl)
{
	mutex_lock(&clocks_mutex);
	list_del(&cl->node);
	mutex_unlock(&clocks_mutex);
	kfree(cl);
}
EXPORT_SYMBOL(clkdev_drop);

/**
 * clk_register_clkdev - register one clock lookup for a struct clk
 * @clk: struct clk to associate with all clk_lookups
 * @con_id: connection ID string on device
 * @dev_id: format string describing device name
 *
 * con_id or dev_id may be NULL as a wildcard, just as in the rest of
 * clkdev.
 *
 * To make things easier for mass registration, we detect error clks
 * from a previous clk_register() call, and return the error code for
 * those.  This is to permit this function to be called immediately
 * after clk_register().
 */
// ARM10C 20150117
// clk: kmem_cache#29-oX, list->name: exynos5420_fixed_rate_ext_clks.name: "fin_pll", NULL
// ARM10C 20150124
// clk: kmem_cache#29-oX (apll),
// pll_clk->alias: (&exynos5420_plls[0])->alias: "fout_apll"
// pll_clk->dev_name: (&exynos5420_plls[0])->dev_name: NULL
int clk_register_clkdev(struct clk *clk, const char *con_id,
	const char *dev_fmt, ...)
{
	struct clk_lookup *cl;
	va_list ap;

	// clk: kmem_cache#29-oX, IS_ERR(kmem_cache#29-oX): 0
	// clk: kmem_cache#29-oX (apll), IS_ERR(kmem_cache#29-oX (apll)): 0
	if (IS_ERR(clk))
		return PTR_ERR(clk);

	// dev_fmt: NULL
	// dev_fmt: NULL
	va_start(ap, dev_fmt);

	// clk: kmem_cache#29-oX, con_id: "fin_pll", dev_fmt: NULL
	// vclkdev_alloc(kmem_cache#29-oX, "fin_pll", NULL, ap): &(kmem_cache#30-oX)->cl
	// clk: kmem_cache#29-oX (apll), con_id: "fout_apll", dev_fmt: NULL
	// vclkdev_alloc(kmem_cache#29-oX (apll), "fout_apll", NULL, ap): &(kmem_cache#30-oX (apll))->cl
	cl = vclkdev_alloc(clk, con_id, dev_fmt, ap);
	// cl: &(kmem_cache#30-oX)->cl
	// cl: &(kmem_cache#30-oX (apll))->cl

	// vclkdev_alloc에서 한일:
	// struct clk_lookup_alloc 의 메모리를 kmem_cache#30-oX 할당 받고
	// struct clk_lookup_alloc 맴버값 초기화 수행
	//
	// (kmem_cache#30-oX)->cl.clk: kmem_cache#29-oX
	// (kmem_cache#30-oX)->con_id: "fin_pll"
	// (kmem_cache#30-oX)->cl.con_id: (kmem_cache#30-oX)->con_id: "fin_pll"

	// vclkdev_alloc (apll) 에서 한일:
	// struct clk_lookup_alloc 의 메모리를 kmem_cache#30-oX (apll) 할당 받고
	// struct clk_lookup_alloc 맴버값 초기화 수행
	//
	// (kmem_cache#30-oX)->cl.clk: kmem_cache#29-oX (apll)
	// (kmem_cache#30-oX)->con_id: "fout_apll"
	// (kmem_cache#30-oX)->cl.con_id: (kmem_cache#30-oX)->con_id: "fout_apll"

	va_end(ap);

	// cl: &(kmem_cache#30-oX)->cl
	// cl: &(kmem_cache#30-oX (apll))->cl
	if (!cl)
		return -ENOMEM;

	// cl: &(kmem_cache#30-oX)->cl
	// cl: &(kmem_cache#30-oX (apll))->cl
	clkdev_add(cl);

	// clkdev_add 에서 한일:
	// list clocks에 &(&(kmem_cache#30-oX)->cl)->nade를 tail로 추가

	// clkdev_add (apll) 에서 한일:
	// list clocks에 &(&(kmem_cache#30-oX (apll))->cl)->nade를 tail로 추가

	return 0;
	// return 0
	// return 0
}

/**
 * clk_register_clkdevs - register a set of clk_lookup for a struct clk
 * @clk: struct clk to associate with all clk_lookups
 * @cl: array of clk_lookup structures with con_id and dev_id pre-initialized
 * @num: number of clk_lookup structures to register
 *
 * To make things easier for mass registration, we detect error clks
 * from a previous clk_register() call, and return the error code for
 * those.  This is to permit this function to be called immediately
 * after clk_register().
 */
int clk_register_clkdevs(struct clk *clk, struct clk_lookup *cl, size_t num)
{
	unsigned i;

	if (IS_ERR(clk))
		return PTR_ERR(clk);

	for (i = 0; i < num; i++, cl++) {
		cl->clk = clk;
		clkdev_add(cl);
	}

	return 0;
}
EXPORT_SYMBOL(clk_register_clkdevs);
