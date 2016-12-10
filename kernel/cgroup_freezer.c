/*
 * cgroup_freezer.c -  control group freezer subsystem
 *
 * Copyright IBM Corporation, 2007
 *
 * Author : Cedric Le Goater <clg@fr.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <linux/export.h>
#include <linux/slab.h>
#include <linux/cgroup.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/freezer.h>
#include <linux/seq_file.h>

/*
 * A cgroup is freezing if any FREEZING flags are set.  FREEZING_SELF is
 * set if "FROZEN" is written to freezer.state cgroupfs file, and cleared
 * for "THAWED".  FREEZING_PARENT is set if the parent freezer is FREEZING
 * for whatever reason.  IOW, a cgroup has FREEZING_PARENT set if one of
 * its ancestors has FREEZING_SELF set.
 */
// ARM10C 20160723
enum freezer_state_flags {
	// CGROUP_FREEZER_ONLINE: 1
	CGROUP_FREEZER_ONLINE	= (1 << 0), /* freezer is fully online */
	// CGROUP_FREEZING_SELF: 2
	CGROUP_FREEZING_SELF	= (1 << 1), /* this freezer is freezing */
	// CGROUP_FREEZING_PARENT: 4
	CGROUP_FREEZING_PARENT	= (1 << 2), /* the parent freezer is freezing */
	// CGROUP_FROZEN: 8
	CGROUP_FROZEN		= (1 << 3), /* this and its descendants frozen */

	/* mask for all FREEZING flags */
	// CGROUP_FREEZING_SELF: 2
	// CGROUP_FREEZING_PARENT: 4
	// CGROUP_FREEZING: 6
	CGROUP_FREEZING		= CGROUP_FREEZING_SELF | CGROUP_FREEZING_PARENT,
};

// ARM10C 20160716
// ARM10C 20160723
// ARM10C 20161210
// sizeof(struct freezer): 84 bytes
struct freezer {
	struct cgroup_subsys_state	css;
	unsigned int			state;
	spinlock_t			lock;
};

// ARM10C 20160723
// css: &(kmem_cache#29-oX (struct freezer))->css
// ARM10C 20160723
// NULL
// ARM10C 20161210
// &(kmem_cache#29-oX (struct freezer))->css
static inline struct freezer *css_freezer(struct cgroup_subsys_state *css)
{
	// css: &(kmem_cache#29-oX (struct freezer))->css
	// container_of(&(kmem_cache#29-oX (struct freezer))->css, struct freezer, css): kmem_cache#29-oX (struct freezer)
	// css: &(kmem_cache#29-oX (struct freezer))->css
	// container_of(&(kmem_cache#29-oX (struct freezer))->css, struct freezer, css): kmem_cache#29-oX (struct freezer)
	return css ? container_of(css, struct freezer, css) : NULL;
	// return kmem_cache#29-oX (struct freezer)
	// return kmem_cache#29-oX (struct freezer)
}

// ARM10C 20161210
// task: kmem_cache#15-oX (struct task_struct)
static inline struct freezer *task_freezer(struct task_struct *task)
{
	// task: kmem_cache#15-oX (struct task_struct), freezer_subsys_id: 3
	// task_css(kmem_cache#15-oX (struct task_struct), 3): &(kmem_cache#29-oX (struct freezer))->css
	// css_freezer(&(kmem_cache#29-oX (struct freezer))->css): kmem_cache#29-oX (struct freezer)
	return css_freezer(task_css(task, freezer_subsys_id));
	// return kmem_cache#29-oX (struct freezer)
}

// ARM10C 20160723
// freezer: kmem_cache#29-oX (struct freezer)
static struct freezer *parent_freezer(struct freezer *freezer)
{
	// &freezer->css: &(kmem_cache#29-oX (struct freezer))->css,
	// css_parent(&(kmem_cache#29-oX (struct freezer))->css): NULL, css_freezer(NULL): NULL
	return css_freezer(css_parent(&freezer->css));
	// return NULL
}

bool cgroup_freezing(struct task_struct *task)
{
	bool ret;

	rcu_read_lock();
	ret = task_freezer(task)->state & CGROUP_FREEZING;
	rcu_read_unlock();

	return ret;
}

/*
 * cgroups_write_string() limits the size of freezer state strings to
 * CGROUP_LOCAL_BUFFER_SIZE
 */
static const char *freezer_state_strs(unsigned int state)
{
	if (state & CGROUP_FROZEN)
		return "FROZEN";
	if (state & CGROUP_FREEZING)
		return "FREEZING";
	return "THAWED";
};

struct cgroup_subsys freezer_subsys;

// ARM10C 20160716
// (&cgroup_dummy_root.top_cgroup)->subsys[3]: NULL
static struct cgroup_subsys_state *
freezer_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct freezer *freezer;

	// sizeof(struct freezer): 84 bytes, GFP_KERNEL: 0xD0
	// kzalloc(84, GFP_KERNEL: 0xD0): kmem_cache#29-o0 (struct freezer)
	freezer = kzalloc(sizeof(struct freezer), GFP_KERNEL);
	// freezer: kmem_cache#29-o0 (struct freezer)

	// freezer: kmem_cache#29-o0 (struct freezer)
	if (!freezer)
		return ERR_PTR(-ENOMEM);

	// &freezer->lock: &(kmem_cache#29-o0 (struct freezer))->lock
	spin_lock_init(&freezer->lock);

	// spin_lock_init에서 한일:
	// (&(kmem_cache#29-o0 (struct freezer))->lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#29-o0 (struct freezer))->lock)->magic: 0xdead4ead
	// (&(kmem_cache#29-o0 (struct freezer))->lock)->owner: 0xffffffff
	// (&(kmem_cache#29-o0 (struct freezer))->lock)->owner_cpu: 0xffffffff

	// &freezer->css: &(kmem_cache#29-o0 (struct freezer))->css
	return &freezer->css;
	// return &(kmem_cache#29-o0 (struct freezer))->css
}

/**
 * freezer_css_online - commit creation of a freezer css
 * @css: css being created
 *
 * We're committing to creation of @css.  Mark it online and inherit
 * parent's freezing state while holding both parent's and our
 * freezer->lock.
 */
// ARM10C 20160716
// css: &(kmem_cache#29-oX (struct freezer))->css
static int freezer_css_online(struct cgroup_subsys_state *css)
{
	// css: &(kmem_cache#29-oX (struct freezer))->css
	// css_freezer(&(kmem_cache#29-oX (struct freezer))->css): kmem_cache#29-oX (struct freezer)
	struct freezer *freezer = css_freezer(css);
	// freezer: kmem_cache#29-oX (struct freezer)

	// freezer: kmem_cache#29-oX (struct freezer)
	// parent_freezer(kmem_cache#29-oX (struct freezer)): NULL
	struct freezer *parent = parent_freezer(freezer);
	// parent: NULL

	/*
	 * The following double locking and freezing state inheritance
	 * guarantee that @cgroup can never escape ancestors' freezing
	 * states.  See css_for_each_descendant_pre() for details.
	 */
	// parent: NULL
	if (parent)
		spin_lock_irq(&parent->lock);

	// &freezer->lock: &(kmem_cache#29-oX (struct freezer))->lock, SINGLE_DEPTH_NESTING: 1
	spin_lock_nested(&freezer->lock, SINGLE_DEPTH_NESTING);

	// spin_lock_nested 에서 한일:
	// &(kmem_cache#29-oX (struct freezer))->lock 을 이용한 spin lock 수행

	// freezer->state: (kmem_cache#29-oX (struct freezer))->state: 0, CGROUP_FREEZER_ONLINE: 1
	freezer->state |= CGROUP_FREEZER_ONLINE;
	// freezer->state: (kmem_cache#29-oX (struct freezer))->state: 1

	// parent: NULL, CGROUP_FREEZING: 6
	if (parent && (parent->state & CGROUP_FREEZING)) {
		freezer->state |= CGROUP_FREEZING_PARENT | CGROUP_FROZEN;
		atomic_inc(&system_freezing_cnt);
	}

	// &freezer->lock: &(kmem_cache#29-oX (struct freezer))->lock
	spin_unlock(&freezer->lock);

	// spin_unlock 에서 한일:
	// &(kmem_cache#29-oX (struct freezer))->lock 을 이용한 spin unlock 수행

	// parent: NULL
	if (parent)
		spin_unlock_irq(&parent->lock);

	return 0;
	// return 0
}

/**
 * freezer_css_offline - initiate destruction of a freezer css
 * @css: css being destroyed
 *
 * @css is going away.  Mark it dead and decrement system_freezing_count if
 * it was holding one.
 */
static void freezer_css_offline(struct cgroup_subsys_state *css)
{
	struct freezer *freezer = css_freezer(css);

	spin_lock_irq(&freezer->lock);

	if (freezer->state & CGROUP_FREEZING)
		atomic_dec(&system_freezing_cnt);

	freezer->state = 0;

	spin_unlock_irq(&freezer->lock);
}

static void freezer_css_free(struct cgroup_subsys_state *css)
{
	kfree(css_freezer(css));
}

/*
 * Tasks can be migrated into a different freezer anytime regardless of its
 * current state.  freezer_attach() is responsible for making new tasks
 * conform to the current state.
 *
 * Freezer state changes and task migration are synchronized via
 * @freezer->lock.  freezer_attach() makes the new tasks conform to the
 * current state and all following state changes can see the new tasks.
 */
static void freezer_attach(struct cgroup_subsys_state *new_css,
			   struct cgroup_taskset *tset)
{
	struct freezer *freezer = css_freezer(new_css);
	struct task_struct *task;
	bool clear_frozen = false;

	spin_lock_irq(&freezer->lock);

	/*
	 * Make the new tasks conform to the current state of @new_css.
	 * For simplicity, when migrating any task to a FROZEN cgroup, we
	 * revert it to FREEZING and let update_if_frozen() determine the
	 * correct state later.
	 *
	 * Tasks in @tset are on @new_css but may not conform to its
	 * current state before executing the following - !frozen tasks may
	 * be visible in a FROZEN cgroup and frozen tasks in a THAWED one.
	 */
	cgroup_taskset_for_each(task, new_css, tset) {
		if (!(freezer->state & CGROUP_FREEZING)) {
			__thaw_task(task);
		} else {
			freeze_task(task);
			freezer->state &= ~CGROUP_FROZEN;
			clear_frozen = true;
		}
	}

	spin_unlock_irq(&freezer->lock);

	/*
	 * Propagate FROZEN clearing upwards.  We may race with
	 * update_if_frozen(), but as long as both work bottom-up, either
	 * update_if_frozen() sees child's FROZEN cleared or we clear the
	 * parent's FROZEN later.  No parent w/ !FROZEN children can be
	 * left FROZEN.
	 */
	while (clear_frozen && (freezer = parent_freezer(freezer))) {
		spin_lock_irq(&freezer->lock);
		freezer->state &= ~CGROUP_FROZEN;
		clear_frozen = freezer->state & CGROUP_FREEZING;
		spin_unlock_irq(&freezer->lock);
	}
}

// ARM10C 20161210
// kmem_cache#15-oX (struct task_struct)
static void freezer_fork(struct task_struct *task)
{
	struct freezer *freezer;

	rcu_read_lock();

	// rcu_read_lock 에서 한일:
	// (&init_task)->rcu_read_lock_nesting: 1

	// task: kmem_cache#15-oX (struct task_struct)
	// task_freezer(kmem_cache#15-oX (struct task_struct)): kmem_cache#29-oX (struct freezer)
	freezer = task_freezer(task);
	// freezer: kmem_cache#29-oX (struct freezer)

// 2016/12/10 종료

	/*
	 * The root cgroup is non-freezable, so we can skip the
	 * following check.
	 */
	if (!parent_freezer(freezer))
		goto out;

	spin_lock_irq(&freezer->lock);
	if (freezer->state & CGROUP_FREEZING)
		freeze_task(task);
	spin_unlock_irq(&freezer->lock);
out:
	rcu_read_unlock();
}

/**
 * update_if_frozen - update whether a cgroup finished freezing
 * @css: css of interest
 *
 * Once FREEZING is initiated, transition to FROZEN is lazily updated by
 * calling this function.  If the current state is FREEZING but not FROZEN,
 * this function checks whether all tasks of this cgroup and the descendant
 * cgroups finished freezing and, if so, sets FROZEN.
 *
 * The caller is responsible for grabbing RCU read lock and calling
 * update_if_frozen() on all descendants prior to invoking this function.
 *
 * Task states and freezer state might disagree while tasks are being
 * migrated into or out of @css, so we can't verify task states against
 * @freezer state here.  See freezer_attach() for details.
 */
static void update_if_frozen(struct cgroup_subsys_state *css)
{
	struct freezer *freezer = css_freezer(css);
	struct cgroup_subsys_state *pos;
	struct css_task_iter it;
	struct task_struct *task;

	WARN_ON_ONCE(!rcu_read_lock_held());

	spin_lock_irq(&freezer->lock);

	if (!(freezer->state & CGROUP_FREEZING) ||
	    (freezer->state & CGROUP_FROZEN))
		goto out_unlock;

	/* are all (live) children frozen? */
	css_for_each_child(pos, css) {
		struct freezer *child = css_freezer(pos);

		if ((child->state & CGROUP_FREEZER_ONLINE) &&
		    !(child->state & CGROUP_FROZEN))
			goto out_unlock;
	}

	/* are all tasks frozen? */
	css_task_iter_start(css, &it);

	while ((task = css_task_iter_next(&it))) {
		if (freezing(task)) {
			/*
			 * freezer_should_skip() indicates that the task
			 * should be skipped when determining freezing
			 * completion.  Consider it frozen in addition to
			 * the usual frozen condition.
			 */
			if (!frozen(task) && !freezer_should_skip(task))
				goto out_iter_end;
		}
	}

	freezer->state |= CGROUP_FROZEN;
out_iter_end:
	css_task_iter_end(&it);
out_unlock:
	spin_unlock_irq(&freezer->lock);
}

static int freezer_read(struct cgroup_subsys_state *css, struct cftype *cft,
			struct seq_file *m)
{
	struct cgroup_subsys_state *pos;

	rcu_read_lock();

	/* update states bottom-up */
	css_for_each_descendant_post(pos, css)
		update_if_frozen(pos);

	rcu_read_unlock();

	seq_puts(m, freezer_state_strs(css_freezer(css)->state));
	seq_putc(m, '\n');
	return 0;
}

static void freeze_cgroup(struct freezer *freezer)
{
	struct css_task_iter it;
	struct task_struct *task;

	css_task_iter_start(&freezer->css, &it);
	while ((task = css_task_iter_next(&it)))
		freeze_task(task);
	css_task_iter_end(&it);
}

static void unfreeze_cgroup(struct freezer *freezer)
{
	struct css_task_iter it;
	struct task_struct *task;

	css_task_iter_start(&freezer->css, &it);
	while ((task = css_task_iter_next(&it)))
		__thaw_task(task);
	css_task_iter_end(&it);
}

/**
 * freezer_apply_state - apply state change to a single cgroup_freezer
 * @freezer: freezer to apply state change to
 * @freeze: whether to freeze or unfreeze
 * @state: CGROUP_FREEZING_* flag to set or clear
 *
 * Set or clear @state on @cgroup according to @freeze, and perform
 * freezing or thawing as necessary.
 */
static void freezer_apply_state(struct freezer *freezer, bool freeze,
				unsigned int state)
{
	/* also synchronizes against task migration, see freezer_attach() */
	lockdep_assert_held(&freezer->lock);

	if (!(freezer->state & CGROUP_FREEZER_ONLINE))
		return;

	if (freeze) {
		if (!(freezer->state & CGROUP_FREEZING))
			atomic_inc(&system_freezing_cnt);
		freezer->state |= state;
		freeze_cgroup(freezer);
	} else {
		bool was_freezing = freezer->state & CGROUP_FREEZING;

		freezer->state &= ~state;

		if (!(freezer->state & CGROUP_FREEZING)) {
			if (was_freezing)
				atomic_dec(&system_freezing_cnt);
			freezer->state &= ~CGROUP_FROZEN;
			unfreeze_cgroup(freezer);
		}
	}
}

/**
 * freezer_change_state - change the freezing state of a cgroup_freezer
 * @freezer: freezer of interest
 * @freeze: whether to freeze or thaw
 *
 * Freeze or thaw @freezer according to @freeze.  The operations are
 * recursive - all descendants of @freezer will be affected.
 */
static void freezer_change_state(struct freezer *freezer, bool freeze)
{
	struct cgroup_subsys_state *pos;

	/*
	 * Update all its descendants in pre-order traversal.  Each
	 * descendant will try to inherit its parent's FREEZING state as
	 * CGROUP_FREEZING_PARENT.
	 */
	rcu_read_lock();
	css_for_each_descendant_pre(pos, &freezer->css) {
		struct freezer *pos_f = css_freezer(pos);
		struct freezer *parent = parent_freezer(pos_f);

		spin_lock_irq(&pos_f->lock);

		if (pos_f == freezer) {
			freezer_apply_state(pos_f, freeze,
					    CGROUP_FREEZING_SELF);
		} else {
			/*
			 * Our update to @parent->state is already visible
			 * which is all we need.  No need to lock @parent.
			 * For more info on synchronization, see
			 * freezer_post_create().
			 */
			freezer_apply_state(pos_f,
					    parent->state & CGROUP_FREEZING,
					    CGROUP_FREEZING_PARENT);
		}

		spin_unlock_irq(&pos_f->lock);
	}
	rcu_read_unlock();
}

static int freezer_write(struct cgroup_subsys_state *css, struct cftype *cft,
			 const char *buffer)
{
	bool freeze;

	if (strcmp(buffer, freezer_state_strs(0)) == 0)
		freeze = false;
	else if (strcmp(buffer, freezer_state_strs(CGROUP_FROZEN)) == 0)
		freeze = true;
	else
		return -EINVAL;

	freezer_change_state(css_freezer(css), freeze);
	return 0;
}

static u64 freezer_self_freezing_read(struct cgroup_subsys_state *css,
				      struct cftype *cft)
{
	struct freezer *freezer = css_freezer(css);

	return (bool)(freezer->state & CGROUP_FREEZING_SELF);
}

static u64 freezer_parent_freezing_read(struct cgroup_subsys_state *css,
					struct cftype *cft)
{
	struct freezer *freezer = css_freezer(css);

	return (bool)(freezer->state & CGROUP_FREEZING_PARENT);
}

static struct cftype files[] = {
	{
		.name = "state",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_seq_string = freezer_read,
		.write_string = freezer_write,
	},
	{
		.name = "self_freezing",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_u64 = freezer_self_freezing_read,
	},
	{
		.name = "parent_freezing",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_u64 = freezer_parent_freezing_read,
	},
	{ }	/* terminate */
};

// ARM10C 20150822
// ARM10C 20160716
// ARM10C 20161210
struct cgroup_subsys freezer_subsys = {
	.name		= "freezer",
	.css_alloc	= freezer_css_alloc,
	.css_online	= freezer_css_online,
	.css_offline	= freezer_css_offline,
	.css_free	= freezer_css_free,
	.subsys_id	= freezer_subsys_id,
	.attach		= freezer_attach,
	.fork		= freezer_fork,
	.base_cftypes	= files,
};
