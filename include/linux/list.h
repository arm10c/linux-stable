#ifndef _LINUX_LIST_H
#define _LINUX_LIST_H

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/poison.h>
#include <linux/const.h>

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

// ARM10C 20131012
// ARM10C 20131116
// ARM10C 20131130
// ARM10C 20140315
// ARM10C 20150704
// LIST_HEAD_INIT(cpu_add_remove_lock.wait_list):
// { &(cpu_add_remove_lock.wait_list), &(cpu_add_remove_lock.wait_list) }
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.rcu_node_entry):
// { &(init_task.rcu_node_entry), &(init_task.rcu_node_entry) }
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.se.group_node):
// { &(init_task.se.group_node), &(init_task.se.group_node) }
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.rt.run_list):
// { &(init_task.rt.run_list), &(init_task.rt.run_list) }
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.tasks):
// { &(init_task.tasks), &(init_task.tasks) }
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.ptraced):
// { &(init_task.ptraced), &(init_task.ptraced) }
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.ptrace_entry):
// { &(init_task.ptrace_entry), &(init_task.ptrace_entry) }
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.children):
// { &(init_task.children), &(init_task.children) }
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.sibling):
// { &(init_task.sibling), &(init_task.sibling) }
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.pending.list):
// { &(init_task.pending.list), &(init_task.pending.list) }
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.thread_group):
// { &(init_task.thread_group), &(init_task.thread_group) }
// ARM10C 20150808
// LIST_HEAD_INIT((init_task.pushable_tasks).prio_list):
// { &((init_task.pushable_tasks).prio_list), &((init_task.pushable_tasks).prio_list) }
// ARM10C 20150808
// LIST_HEAD_INIT((init_task.pushable_tasks).node_list):
// { &((init_task.pushable_tasks).node_list), &((init_task.pushable_tasks).node_list) }
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.cpu_timers[0]):
// { &(init_task.cpu_timers[0]), &(init_task.cpu_timers[0]) }
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.cpu_timers[1]):
// { &(init_task.cpu_timers[1]), &(init_task.cpu_timers[1]) }
// ARM10C 20150808
// LIST_HEAD_INIT(init_task.cpu_timers[2]):
// { &(init_task.cpu_timers[2]), &(init_task.cpu_timers[2]) }
// ARM10C 20151121
// LIST_HEAD_INIT((shrinker_rwsem).wait_list):
// { &((shrinker_rwsem).wait_list), &((shrinker_rwsem).wait_list) }
// ARM10C 20151121
// LIST_HEAD_INIT(shrinker_list):
// { &(shrinker_list), &(shrinker_list) }
// ARM10C 20160903
// LIST_HEAD_INIT(init_signals.shared_pending.list):
// { &(init_signals.shared_pending.list), &(init_signals.shared_pending.list) }
// ARM10C 20160903
// LIST_HEAD_INIT(init_signals.posix_timers):
// { &(init_signals.posix_timers), &(init_signals.posix_timers) }
#define LIST_HEAD_INIT(name) { &(name), &(name) }

// ARM10C 20131116
// ARM10C 20131130
// ARM10C 20141108
// ARM10C 20140830
// ARM10C 20150919
// ARM10C 20151114
// ARM10C 20151121
// ARM10C 20160611
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

// ARM10C 20130824
// ARM10C 20140301
// ARM10C 20140315
// &waiter->list->next: list, &waiter->list->prev: list
// ARM10C 20140809
// ARM10C 20140830
// &root_task_group.children
// ARM10C 20140830
// &root_task_group.siblings
// ARM10C 20140830
// [pcp0] &rq->leaf_cfs_rq_list: &(&runqueues)->leaf_cfs_rq_list
// ARM10C 20140830
// ARM10C 20141004
// ARM10C 20150103
// ARM10C 20150620
// &q->list: [pcp0] &(&call_single_queue)->list
// ARM10C 20150718
// &(&vc_cons[0].SAK_work)->entry
// ARM10C 20150718
// &lock->wait_list: &(&(&(&(kmem_cache#25-oX)->port)->buf)->lock)->wait_list
// ARM10C 20150808
// &init_css_set.cgrp_links
// ARM10C 20150808
// &init_css_set.tasks
// ARM10C 20150808
// &root->subsys_list: &(&cgroup_dummy_root)->subsys_list
// ARM10C 20150808
// &root->root_list: &(&cgroup_dummy_root)->root_list
// ARM10C 20150808
// &cgrp->sibling: &(&(&cgroup_dummy_root)->top_cgroup)->sibling
// ARM10C 20150808
// &cgrp->children: &(&(&cgroup_dummy_root)->top_cgroup)->children
// ARM10C 20150808
// &cgrp->files: &(&(&cgroup_dummy_root)->top_cgroup)->files
// ARM10C 20150808
// &cgrp->release_list: &(&(&cgroup_dummy_root)->top_cgroup)->release_list
// ARM10C 20150808
// &cgrp->event_list: &(&(&cgroup_dummy_root)->top_cgroup)->event_list
// ARM10C 20150808
// &xattrs->head: (&(&(&cgroup_dummy_root)->top_cgroup)->xattrs)->head
// ARM10C 20150822
// &ss->cftsets: &(&cpu_cgroup_subsys)->cftsets
// ARM10C 20150822
// &ss->cftsets: &(&cpuacct_subsys)->cftsets
// ARM10C 20150919
// &fbc->list: &(&vm_committed_as)->list
// ARM10C 20151031
// &bdi->bdi_list: &(&sysfs_backing_dev_info)->bdi_list
// ARM10C 20151031
// &wb->b_dirty: &(&(&sysfs_backing_dev_info)->wb)->b_dirty
// ARM10C 20151107
// mnt->mnt_child: (kmem_cache#2-oX (struct mount))->mnt_child
// ARM10C 20151107
// mnt->mnt_mounts: (kmem_cache#2-oX (struct mount))->mnt_mounts
// ARM10C 20151107
// mnt->mnt_list: (kmem_cache#2-oX (struct mount))->mnt_list
// ARM10C 20151107
// mnt->mnt_expire: (kmem_cache#2-oX (struct mount))->mnt_expire
// ARM10C 20151107
// mnt->mnt_share: (kmem_cache#2-oX (struct mount))->mnt_share
// ARM10C 20151107
// mnt->mnt_slave_list: (kmem_cache#2-oX (struct mount))->mnt_slave_list
// ARM10C 20151107
// mnt->mnt_slave: (kmem_cache#2-oX (struct mount))->mnt_slave
// ARM10C 20151114
// &s->s_inodes: &(kmem_cache#25-oX (struct super_block))->s_inodes
// ARM10C 20151114
// &lru->node[0].list: (&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].list
// ARM10C 20151114
// &s->s_mounts: &(kmem_cache#25-oX (struct super_block))->s_mounts
// ARM10C 20151219
// &dentry->d_lru: &(kmem_cache#5-oX)->d_lru
// ARM10C 20151219
// &dentry->d_subdirs: &(kmem_cache#5-oX)->d_subdirs
// ARM10C 20160109
// &kobj->entry: &(kmem_cache#30-oX (struct kobject))->entry
// ARM10C 20160319
// mnt->mnt_child: (kmem_cache#2-oX (struct mount))->mnt_child
// ARM10C 20160319
// mnt->mnt_mounts: (kmem_cache#2-oX (struct mount))->mnt_mounts
// ARM10C 20160319
// mnt->mnt_list: (kmem_cache#2-oX (struct mount))->mnt_list
// ARM10C 20160319
// mnt->mnt_expire: (kmem_cache#2-oX (struct mount))->mnt_expire
// ARM10C 20160319
// mnt->mnt_share: (kmem_cache#2-oX (struct mount))->mnt_share
// ARM10C 20160319
// mnt->mnt_slave_list: (kmem_cache#2-oX (struct mount))->mnt_slave_list
// ARM10C 20160319
// mnt->mnt_slave: (kmem_cache#2-oX (struct mount))->mnt_slave
// ARM10C 20160319
// &s->s_inodes: &(kmem_cache#25-oX (struct super_block))->s_inodes
// ARM10C 20160319
// &s->s_mounts: &(kmem_cache#25-oX (struct super_block))->s_mounts
// ARM10C 20160319
// &inode->i_sb_list: &(kmem_cache#4-oX (struct inode))->i_sb_list
// ARM10C 20160319
// &info->swaplist: &(kmem_cache#4-oX (struct shmem_inode_info))->swaplist
// ARM10C 20160514
// &new_ns->list: (kmem_cache#30-oX (struct mnt_namespace))->list
// ARM10C 20160611
// &ent->pde_openers: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers
// ARM10C 20160910
// &p->children: &(kmem_cache#15-oX (struct task_struct))->children
// ARM10C 20161008
// &child->cg_list: &(kmem_cache#15-oX (struct task_struct))->cg_list
// ARM10C 20161029
// &node->prio_list: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
// ARM10C 20161029
// &node->node_list: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list
// ARM10C 20161105
// &sig->posix_timers: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
// ARM10C 20161105
// &sig->cpu_timers[0]): &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
// ARM10C 20161105
// &sig->cpu_timers[1]): &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
// ARM10C 20161105
// &sig->cpu_timers[2]): &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
// ARM10C 20161203
// &p->thread_group: &(kmem_cache#15-oX (struct task_struct))->thread_group
// ARM10C 20161203
// &child->ptrace_entry: (kmem_cache#15-oX (struct task_struct))->ptrace_entry
// ARM10C 20161203
// &child->ptraced: (kmem_cache#15-oX (struct task_struct))->ptraced
static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
#ifndef CONFIG_DEBUG_LIST // CONFIG_DEBUG_LIST=n
// ARM10C 20131130
// __list_add(new, head->prev, head);
// ARM10C 20140301
// new: &dchunk->list, prev: &pcpu_slot[11], next: &pcpu_slot[11]->next(&pcpu_slot[11])
// ARM10C 20140315
// __list_add(&waiter.list, (&(&cpu_add_remove_lock)->wait_list)->prev, &(&cpu_add_remove_lock)->wait_list)
// ARM10C 20150815
// &init_cgrp_cset_link.cset_link, &cgroup_dummy_top->cset_links, &cgroup_dummy_top->cset_links
// ARM10C 20150815
// &init_cgrp_cset_link.cgrp_link, &init_css_set.cgrp_links, &cgroup_dummy_top->cset_links
static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	//&pcpu_slot[11]->prev = &dchunk->list;
	new->next = next;
	//&dchunk->list->next = &pcpu_slot[11];
	new->prev = prev;
	//&dchunk->list->prev = &pcpu_slot[11];
	prev->next = new;
	//&pcpu_slot[11]->next = &dchunk->list;
}
#else
extern void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next);
#endif

/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
// ARM10C 20140301
// new: &dchunk->list, head: &pcpu_slot[11]
// ARM10C 20140830
// &root_task_group.list, &task_groups
// ARM10C 20150411
// &dev->list: [pcp0] (&(&percpu_mct_tick)->evt)->list, &clockevent_devices
// ARM10C 20150523
// &cs->list: &(&mct_frc)->list, entry: &clocksource_list
// ARM10C 20150523
// &dev->list: (&mct_comp_device)->list, &clockevent_devices
// ARM10C 20150815
// &init_cgrp_cset_link.cset_link, &cgroup_dummy_top->cset_links
// ARM10C 20150815
// &init_cgrp_cset_link.cgrp_link, &init_css_set.cgrp_links
// ARM10C 20150822
// &ss->sibling: &(&cpu_cgroup_subsys)->sibling, &cgroup_dummy_root.subsys_list
// ARM10C 20150822
// &ss->sibling: &(&cpuacct_subsys)->sibling, &cgroup_dummy_root.subsys_list
// ARM10C 20150919
// &fbc->list: &(&vm_committed_as)->list
// ARM10C 20151205
// &inode->i_sb_list: &(kmem_cache#4-oX)->i_sb_list,
// &inode->i_sb->s_inodes: &(kmem_cache#4-oX)->i_sb->s_inodes
// ARM10C 20160521
// &mnt->mnt_list: &(kmem_cache#2-oX (struct mount))->mnt_list, &new_ns->list: &(kmem_cache#30-oX (struct mnt_namespace))->list
// ARM10C 20160716
// &ss->sibling: &(&debug_subsys)->sibling
// ARM10C 20161126
// &dentry->d_u.d_child: &(kmem_cache#5-oX (struct dentry))->d_u.d_child,
// &parent->d_subdirs: &(kmem_cache#5-oX (struct dentry))->d_subdirs
// ARM10C 20170419
// &se->group_node: &(&(kmem_cache#15-oX (struct task_struct))->se)->group_node,
// &rq->cfs_tasks: [pcp0] &(&runqueues)->cfs_tasks
static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}


/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
// ARM10C 20131130
// list_add_tail(&svm->list, &curr_svm->list);
// ARM10C 20140315
// list_add_tail(&waiter.list, &(&cpu_add_remove_lock)->wait_list);
// ARM10C 20150711
// &timer->entry: &(&console_timer)->entry, vec: &(&boot_tvec_bases)->tv3.vec[3]
// ARM10C 20150822
// &ss->base_cftset.node: &(&cpu_cgroup_subsys)->base_cftset.node, &ss->cftsets: &(&cpu_cgroup_subsys)->cftsets
// ARM10C 20150822
// &ss->base_cftset.node: &(&cpuacct_subsys)->base_cftset.node, &ss->cftsets: &(&cpuacct_subsys)->cftsets
// ARM10C 20151114
// [re] s->s_list: (kmem_cache#25-oX (struct super_block))->s_list, &super_blocks
// ARM10C 20151121
// &waiter.list, &sem->wait_list: &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list
// ARM10C 20151121
// &shrinker->list: &(&(kmem_cache#25-oX (struct super_block))->s_shrink)->list, &shrinker_list
// ARM10C 20160109
// &mnt->mnt_instance: &(kmem_cache#2-oX (struct mount))->mnt_instance, &root->d_sb->s_mounts: &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts
// ARM10C 20160326
// &mnt->mnt_instance: &(kmem_cache#2-oX (struct mount))->mnt_instance, &root->d_sb->s_mounts: &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts
// ARM10C 20160521
// [re] s->s_list: (kmem_cache#25-oX (struct super_block))->s_list,
// ARM10C 20160611
// &ops->list: &(&proc_net_ns_ops)->list, list: &pernet_list
// ARM10C 20161112
// [re] s->s_list: (kmem_cache#25-oX (struct super_block))->s_list,
// ARM10C 20161203
// &p->sibling: &(kmem_cache#15-oX (struct task_struct))->sibling
// &p->real_parent->children: &(&init_task)->children
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	// new: &waiter.list, head->prev: (&(&cpu_add_remove_lock)->wait_list)->prev
	// head: &(&cpu_add_remove_lock)->wait_list
	__list_add(new, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
// ARM10C 20140315
// *entry : &waiter->list
// &waiter->list->prev: prev, &waiter->list->next: next
// ARM10C 20140412
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
#ifndef CONFIG_DEBUG_LIST
// ARM10C 20140301
// ARM10C 20140315
// *entry: &waiter->list
static inline void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

// ARM10C 20140412
// ARM10C 20140517
// ARM10C 20151121
static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);

	// LIST_POISON1: ((void *) 0x00100100)
	entry->next = LIST_POISON1;

	// LIST_POISON2: ((void *) 0x00200200)
	entry->prev = LIST_POISON2;
}
#else
extern void __list_del_entry(struct list_head *entry);
extern void list_del(struct list_head *entry);
#endif

/**
 * list_replace - replace old entry by new one
 * @old : the element to be replaced
 * @new : the new element to insert
 *
 * If @old was empty, it will be overwritten.
 */
static inline void list_replace(struct list_head *old,
				struct list_head *new)
{
	new->next = old->next;
	new->next->prev = new;
	new->prev = old->prev;
	new->prev->next = new;
}

static inline void list_replace_init(struct list_head *old,
					struct list_head *new)
{
	list_replace(old, new);
	INIT_LIST_HEAD(old);
}

/**
 * list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
// ARM10C 20140315
// *entry : &waiter->list
static inline void list_del_init(struct list_head *entry)
{
	// entry: waiter->list
	__list_del_entry(entry);
	// &waiter->list->prev: prev, &waiter->list->next: next

	INIT_LIST_HEAD(entry);
	// &waiter->list->next: &waiter->list, &waiter->list->prev: &waiter->list
}

/**
 * list_move - delete from one list and add as another's head
 * @list: the entry to move
 * @head: the head that will precede our entry
 */
// ARM10C 20140301
// list: &dchunk->list, head: &pcpu_slot[11]
static inline void list_move(struct list_head *list, struct list_head *head)
{
	// list: &dchunk->list
	__list_del_entry(list);
	// &dchunk->list->next: &dchunk->list
	// &dchunk->list->prev: &dchunk->list

	// head: &pcpu_slot[11]
	list_add(list, head);
	// &pcpu_slot[11](list)에 &dchunk->list 추가
}

/**
 * list_move_tail - delete from one list and add as another's tail
 * @list: the entry to move
 * @head: the head that will follow our entry
 */
static inline void list_move_tail(struct list_head *list,
				  struct list_head *head)
{
	__list_del_entry(list);

	list_add_tail(list, head);
}

/**
 * list_is_last - tests whether @list is the last entry in list @head
 * @list: the entry to test
 * @head: the head of the list
 */
// ARM10C 20141108
// &first->list: &(GIC#0)->list, &vmap_area_list
// ARM10C 20141206
// &first->list: &(GIC#1)->list, &vmap_area_list
// ARM10C 20150110
// &first->list: &(COMB)->list, &vmap_area_list
// ARM10C 20150321
// &first->list: &(CLK)->list, &vmap_area_list
static inline int list_is_last(const struct list_head *list,
				const struct list_head *head)
{
	// list->next: (&(GIC#0)->list)->next: &(SYSC)->list
	// head: &vmap_area_list
	// list->next: (&(GIC#1)->list)->next: &(SYSC)->list
	// head: &vmap_area_list
	// list->next: (&(COMB)->list)->next: &(SYSC)->list
	// head: &vmap_area_list
	// list->next: (&(CLK)->list)->next: &(SYSC)->list
	// head: &vmap_area_list
	return list->next == head;
	// return 0
	// return 0
	// return 0
	// return 0
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
// ARM10C 20140315
// &waiter->list
// ARM10C 20130322
// ARM10C 20140322
// ARM10C 20140517
// list: (&boot_pageset + (__per_cpu_offset[0]))->pcp.lists[0]
// ARM10C 20150117
// ARM10C 20150509
// ARM10C 20150523
// ARM10C 20150725
// ARM10C 20150822
// ARM10C 20151121
// ARM10C 20151212
// &q->task_list: &(&(&(kmem_cache#4-oX)->i_state의 zone의 주소)->wait_table[계산된 hash index 값])->task_list
static inline int list_empty(const struct list_head *head)
{
	// head->next: waiter->list->next, head: waiter->list
	return head->next == head;
	// return 0
}

/**
 * list_empty_careful - tests whether a list is empty and not being modified
 * @head: the list to test
 *
 * Description:
 * tests whether a list is empty _and_ checks that no other CPU might be
 * in the process of modifying either member (next or prev)
 *
 * NOTE: using list_empty_careful() without synchronization
 * can only be safe if the only activity that can happen
 * to the list entry is list_del_init(). Eg. it cannot be used
 * if another CPU could re-list_add() it.
 */
static inline int list_empty_careful(const struct list_head *head)
{
	struct list_head *next = head->next;
	return (next == head) && (next == head->prev);
}

/**
 * list_rotate_left - rotate the list to the left
 * @head: the head of the list
 */
static inline void list_rotate_left(struct list_head *head)
{
	struct list_head *first;

	if (!list_empty(head)) {
		first = head->next;
		list_move_tail(first, head);
	}
}

/**
 * list_is_singular - tests whether a list has just one entry.
 * @head: the list to test.
 */
static inline int list_is_singular(const struct list_head *head)
{
	return !list_empty(head) && (head->next == head->prev);
}

static inline void __list_cut_position(struct list_head *list,
		struct list_head *head, struct list_head *entry)
{
	struct list_head *new_first = entry->next;
	list->next = head->next;
	list->next->prev = list;
	list->prev = entry;
	entry->next = list;
	head->next = new_first;
	new_first->prev = head;
}

/**
 * list_cut_position - cut a list into two
 * @list: a new list to add all removed entries
 * @head: a list with entries
 * @entry: an entry within head, could be the head itself
 *	and if so we won't cut the list
 *
 * This helper moves the initial part of @head, up to and
 * including @entry, from @head to @list. You should
 * pass on @entry an element you know is on @head. @list
 * should be an empty list or a list you do not care about
 * losing its data.
 *
 */
static inline void list_cut_position(struct list_head *list,
		struct list_head *head, struct list_head *entry)
{
	if (list_empty(head))
		return;
	if (list_is_singular(head) &&
		(head->next != entry && head != entry))
		return;
	if (entry == head)
		INIT_LIST_HEAD(list);
	else
		__list_cut_position(list, head, entry);
}

static inline void __list_splice(const struct list_head *list,
				 struct list_head *prev,
				 struct list_head *next)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

/**
 * list_splice - join two lists, this is designed for stacks
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void list_splice(const struct list_head *list,
				struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head, head->next);
}

/**
 * list_splice_tail - join two lists, each list being a queue
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void list_splice_tail(struct list_head *list,
				struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head->prev, head);
}

/**
 * list_splice_init - join two lists and reinitialise the emptied list.
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * The list at @list is reinitialised
 */
static inline void list_splice_init(struct list_head *list,
				    struct list_head *head)
{
	if (!list_empty(list)) {
		__list_splice(list, head, head->next);
		INIT_LIST_HEAD(list);
	}
}

/**
 * list_splice_tail_init - join two lists and reinitialise the emptied list
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * Each of the lists is a queue.
 * The list at @list is reinitialised
 */
static inline void list_splice_tail_init(struct list_head *list,
					 struct list_head *head)
{
	if (!list_empty(list)) {
		__list_splice(list, head->prev, head);
		INIT_LIST_HEAD(list);
	}
}

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
// ARM10C 20131130
// ARM10C 20140322
// ARM10C 20140329
// ARM10C 20140412
// ARM10C 20140531
// #define list_entry((&pcpu_slot[1])->next, typeof(*chunk), list):
// container_of((&pcpu_slot[1])->next, typeof(*chunk), list)
// ARM10C 20140705
// ARM10C 20141108
// ARM10C 20150523
// list_entry((&clocksource_list)->next, struct clocksource, list)
// ARM10C 20160409
// list_entry((&(&running_helpers_waitq)->task_list)->next, typeof(*curr), task_list)
// ARM10C 20160409
// list_entry((&running_helpers_waitq)->task_list.next, typeof(*(&running_helpers_waitq)), task_list)
// ARM10C 20160611
// list_entry((&net_namespace_list)->next, typeof(*net), list)
#define list_entry(ptr, type, member)		\
	container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
// ARM10C 20140531
// #define list_first_entry(&pcpu_slot[1], typeof(*chunk), list):
// list_entry((&pcpu_slot[1])->next, typeof(*chunk), list)
// ARM10C 20140614
// ARM10C 20140705
// ARM10C 20141011
// ARM10C 20150523
// list_first_entry(&clocksource_list, typeof(*tmp), list)
// ARM10C 20160409
// list_first_entry(&(&running_helpers_waitq)->task_list, typeof(*curr), task_list)
// ARM10C 20160611
// list_first_entry(&net_namespace_list, typeof(*net), list)
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

/**
 * list_last_entry - get the last element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

/**
 * list_first_entry_or_null - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 */
// ARM10C 20141129
// #define list_first_entry_or_null(&intc_parent_list, struct intc_desc, list):
// (!list_empty(&intc_parent_list) ? list_first_entry(&intc_parent_list, struct intc_desc, list) : NULL)
#define list_first_entry_or_null(ptr, type, member) \
	(!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)

/**
 * list_next_entry - get the next element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_struct within the struct.
 */
// ARM10C 20140614
// ARM10C 20160409
// list_next_entry(&running_helpers_waitq, task_list)
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

/**
 * list_prev_entry - get the prev element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_struct within the struct.
 */
#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)

/**
 * list_for_each	-	iterate over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * list_for_each_prev	-	iterate over a list backwards
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)

/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:	the &struct list_head to use as a loop cursor.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/**
 * list_for_each_prev_safe - iterate over a list backwards safe against removal of list entry
 * @pos:	the &struct list_head to use as a loop cursor.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define list_for_each_prev_safe(pos, n, head) \
	for (pos = (head)->prev, n = pos->prev; \
	     pos != (head); \
	     pos = n, n = pos->prev)

/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
// ARM10C 20131130
// ARM10C 20140329
// ARM10C 20140531
// #define list_for_each_entry(chunk, &pcpu_slot[slot], list):
// for (chunk = list_first_entry(&pcpu_slot[1], typeof(*chunk), list);
//      &chunk->list != (&pcpu_slot[1]); chunk = list_next_entry(chunk, list))
// ARM10C 20140705
// #define list_for_each_entry(p, &n->partial, lru):
// for (p = list_first_entry(&n->partial, typeof(*p), lru);
//      &p->lru != (&n->partial); p = list_next_entry(p, lru))
//
// ARM10C 20140920
// #define: list_for_each_entry(s, &slab_caches, list):
// for (s = list_first_entry(&slab_caches, typeof(*s), list);
//      &s->list != (&slab_caches); s = list_next_entry(s, list))
//
// ARM10C 20140927
// list_for_each_entry((rsp), &rcu_struct_flavors, flavors):
// for (rsp = list_first_entry(&rcu_struct_flavors, typeof(*rsp), flavors);
//     &rsp->flavors != (&rcu_struct_flavors); rsp = list_next_entry(rsp, flavors))
//
// ARM10C 20141018
// #define list_for_each_entry(svm, &static_vmlist, list):
// for (svm = list_first_entry(&static_vmlist, typeof(*svm), list);
//     &svm->list != (&static_vmlist); svm = list_next_entry(svm, list))
//
// ARM10C 20141213
// #define list_for_each_entry(h, &irq_domain_list, link):
// for (h = list_first_entry(&irq_domain_list, typeof(*h), link);
//     &h->link != (&irq_domain_list); h = list_next_entry(h, link))
//
// ARM10C 20150328
// #define list_for_each_entry(provider, &of_clk_providers, link):
// for (provider = list_first_entry(&of_clk_providers, typeof(*provider), link);
//     &provider->link != (&of_clk_providers); provider = list_next_entry(provider, link))
//
// ARM10C 20150523
// #define list_for_each_entry(tmp, &clocksource_list, list):
// for (tmp = list_first_entry(&clocksource_list, typeof(*tmp), list);
//     &tmp->list != (&clocksource_list); tmp = list_next_entry(tmp, list))
// ARM10C 20160611
// #define list_for_each_entry(net, &net_namespace_list, list):
// for (net = list_first_entry(&net_namespace_list, typeof(*net), list);
//     &net->list != (&net_namespace_list); net = list_next_entry(net, list))
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_last_entry(head, typeof(*pos), member);		\
	     &pos->member != (head); 					\
	     pos = list_prev_entry(pos, member))

/**
 * list_prepare_entry - prepare a pos entry for use in list_for_each_entry_continue()
 * @pos:	the type * to use as a start point
 * @head:	the head of the list
 * @member:	the name of the list_struct within the struct.
 *
 * Prepares a pos entry for use as a start point in list_for_each_entry_continue().
 */
#define list_prepare_entry(pos, head, member) \
	((pos) ? : list_entry(head, typeof(*pos), member))

/**
 * list_for_each_entry_continue - continue iteration over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Continue to iterate over list of given type, continuing after
 * the current position.
 */
#define list_for_each_entry_continue(pos, head, member) 		\
	for (pos = list_next_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_continue_reverse - iterate backwards from the given point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Start to iterate over list of given type backwards, continuing after
 * the current position.
 */
#define list_for_each_entry_continue_reverse(pos, head, member)		\
	for (pos = list_prev_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = list_prev_entry(pos, member))

/**
 * list_for_each_entry_from - iterate over list of given type from the current point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate over list of given type, continuing from current position.
 */
#define list_for_each_entry_from(pos, head, member) 			\
	for (; &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
// ARM10C 20140614
// #define list_for_each_entry_safe(page, page2, &n->partial, lru):
// for (page = list_first_entry(&n->partial, typeof(*page), lru),
// 	page2 = list_next_entry(page, lru);
// 	&page->lru != (&n->partial);
// 	page = page2, page2 = list_next_entry(page2, lru))
// ARM10C 20141011
// #define list_for_each_entry_safe(desc, temp_desc, &intc_desc_list, list)
// for (desc = list_first_entry(&intc_desc_list, typeof(*desc), list),
// 	temp_desc = list_next_entry(desc, list);
//      &desc->list != (&intc_desc_list);
//      desc = temp_desc, temp_desc = list_next_entry(temp_desc, list))
// ARM10C 20160409
// #define list_for_each_entry_safe(curr, next, &(&running_helpers_waitq)->task_list, task_list):
// for (curr = list_first_entry(&(&running_helpers_waitq)->task_list, typeof(*curr), task_list),
//      next = list_next_entry(curr, task_list); &curr->task_list != (&(&running_helpers_waitq)->task_list);
//      curr = next, next = list_next_entry(next, task_list))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = list_next_entry(n, member))

/**
 * list_for_each_entry_safe_continue - continue list iteration safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate over list of given type, continuing after current point,
 * safe against removal of list entry.
 */
#define list_for_each_entry_safe_continue(pos, n, head, member) 		\
	for (pos = list_next_entry(pos, member), 				\
		n = list_next_entry(pos, member);				\
	     &pos->member != (head);						\
	     pos = n, n = list_next_entry(n, member))

/**
 * list_for_each_entry_safe_from - iterate over list from current point safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate over list of given type from current point, safe against
 * removal of list entry.
 */
#define list_for_each_entry_safe_from(pos, n, head, member) 			\
	for (n = list_next_entry(pos, member);					\
	     &pos->member != (head);						\
	     pos = n, n = list_next_entry(n, member))

/**
 * list_for_each_entry_safe_reverse - iterate backwards over list safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate backwards over list of given type, safe against removal
 * of list entry.
 */
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_last_entry(head, typeof(*pos), member),		\
		n = list_prev_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = list_prev_entry(n, member))

/**
 * list_safe_reset_next - reset a stale list_for_each_entry_safe loop
 * @pos:	the loop cursor used in the list_for_each_entry_safe loop
 * @n:		temporary storage used in list_for_each_entry_safe
 * @member:	the name of the list_struct within the struct.
 *
 * list_safe_reset_next is not safe to use in general if the list may be
 * modified concurrently (eg. the lock is dropped in the loop body). An
 * exception to this is if the cursor element (pos) is pinned in the list,
 * and list_safe_reset_next is called after re-taking the lock and before
 * completing the current iteration of the loop body.
 */
#define list_safe_reset_next(pos, n, member)				\
	n = list_next_entry(pos, member)

/*
 * Double linked lists with a single pointer list head.
 * Mostly useful for hash tables where the two pointer list head is
 * too wasteful.
 * You lose the ability to access the tail in O(1).
 */

// ARM10C 20160730
#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
// ARM10C 20151031
// #define INIT_HLIST_HEAD(&mount_hashtable[0]):
// ((&mount_hashtable[0])->first = NULL)
// ARM10C 20151031
// #define INIT_HLIST_HEAD(&mountpoint_hashtable[0]):
// ((&mountpoint_hashtable[0])->first = NULL)
// ARM10C 20151107
// mnt->mnt_fsnotify_marks: (kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks
// ARM10C 20151205
// &inode->i_dentry: &(kmem_cache#4-oX)->i_dentry
// ARM10C 20160319
// mnt->mnt_fsnotify_marks: (kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks
// ARM10C 20161203
// &pid->tasks[0]: &(kmem_cache#19-oX (struct pid))->tasks[0]
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)

// ARM10C 20150808
// &init_css_set.hlist
// ARM10C 20151107
// mnt->mnt_hash: (kmem_cache#2-oX (struct mount))->mnt_hash
// ARM10C 20151114
// &s->s_instances: &(kmem_cache#25-oX (struct super_block))->s_instances
// ARM10C 20151219
// &dentry->d_alias: &(kmem_cache#5-oX)->d_alias
// ARM10C 20160319
// mnt->mnt_hash: (kmem_cache#2-oX (struct mount))->mnt_hash
// ARM10C 20160319
// &s->s_instances: &(kmem_cache#25-oX (struct super_block))->s_instances
static inline void INIT_HLIST_NODE(struct hlist_node *h)
{

	// h->next: (&init_css_set.hlist)->next
	h->next = NULL;
	// h->next: (&init_css_set.hlist)->next: NULL

	// h->pprev: (&init_css_set.hlist)->pprev
	h->pprev = NULL;
	// h->pprev: (&init_css_set.hlist)->pprev: NULL
}

// ARM10C 20151219
// &entry->d_alias: &(kmem_cache#5-oX)->d_alias
static inline int hlist_unhashed(const struct hlist_node *h)
{
	// h->pprev: (&(kmem_cache#5-oX)->d_alias)->pprev: NULL
	return !h->pprev;
	// return 1
}

static inline int hlist_empty(const struct hlist_head *h)
{
	return !h->first;
}

// ARM10C 20150131
// n: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
static inline void __hlist_del(struct hlist_node *n)
{
	// n->next: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next
	struct hlist_node *next = n->next;
	// next: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next

	// n->pprev: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev
	struct hlist_node **pprev = n->pprev;
	// pprev: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev

	// *pprev: *((&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev),
	// next: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next
	*pprev = next;
	// *pprev: *((&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev): (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next

	// next: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next
	if (next)
		next->pprev = pprev;
}

// ARM10C 20150131
// &clk->child_node: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
static inline void hlist_del(struct hlist_node *n)
{
	// n: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
	__hlist_del(n);

	// __hlist_del 에서 한일:
	// next list에 pprev의 값을 연결함

	// n->next: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next, LIST_POISON1: ((void *) 0x00100100)
	n->next = LIST_POISON1;
	// n->next: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: ((void *) 0x00100100)

	// n->pprev: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev, LIST_POISON2: ((void *) 0x00200200)
	n->pprev = LIST_POISON2;
	// n->pprev: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: ((void *) 0x00200200)
}

static inline void hlist_del_init(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}

// ARM10C 20150117
// &clk->child_node: &(kmem_cache#29-oX)->child_node, &clk_root_list
// ARM10C 20150117
// &clk->child_node: &(kmem_cache#29-oX (apll))->child_node, &clk->parent->children: (&kmem_cache#29-oX (fin_pll))->children
// ARM10C 20150131
// &clk->child_node: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node, &clk_orphan_list
// ARM10C 20150131
// &clk->child_node: &(kmem_cache#29-oX (sclk_spll))->child_node, &clk->parent->children: (&kmem_cache#29-oX (fout_spll))->children
// ARM10C 20150131
// clk->child_node: (kmem_cache#29-oX (mout_mspll_kfc))->child_node, new_parent->children: (kmem_cache#29-oX (sclk_spll))->children
// ARM10C 20150228
// &clk->child_node: &(kmem_cache#29-oX (sclk_apll))->child_node, &clk->parent->children: (&kmem_cache#29-oX (mout_apll))->children
// ARM10C 20151114
// [re] &s->s_instances: &(kmem_cache#25-oX (struct super_block))->s_instances, &type->fs_supers: &(&sysfs_fs_type)->fs_supers
// ARM10C 20151205
// &inode->i_hash: &(kmem_cache#4-oX)->i_hash, head: 256KB의 메모리 공간 + 계산된 hash index 값
// ARM10C 20151219
// &dentry->d_alias: (kmem_cache#5-oX)->d_alias, &inode->i_dentry: &(kmem_cache#4-oX)->i_dentry
// ARM10C 20160730
// &init_css_set.hlist, &css_set_table[계산된 hash index 값]
// ARM10C 20161112
// [re] &s->s_instances: &(kmem_cache#25-oX (struct super_block))->s_instances, &type->fs_supers: &(&proc_fs_type)->fs_supers
static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	// h->first: (&clk_root_list)->first: NULL
	// h->first: (&(kmem_cache#29-oX (fin_pll))->children)->first: NULL
	// h->first: (&clk_orphan_list)->first: NULL
	struct hlist_node *first = h->first;
	// first: NULL
	// first: NULL
	// first: NULL

	// n->next: (&(kmem_cache#29-oX)->child_node)->next, first: NULL
	// n->next: (&(kmem_cache#29-oX (apll))->child_node)->next, first: NULL
	// n->next: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next, first: NULL
	n->next = first;
	// n->next: (&(kmem_cache#29-oX)->child_node)->next: NULL
	// n->next: (&(kmem_cache#29-oX (apll))->child_node)->next: NULL
	// n->next: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->next: NULL

	// first: NULL
	// first: NULL
	// first: NULL
	if (first)
		first->pprev = &n->next;

	// h->first: (&clk_root_list)->first: NULL, n: &(kmem_cache#29-oX)->child_node
	// h->first: (&(kmem_cache#29-oX (fin_pll))->children)->first: NULL, n: &(kmem_cache#29-oX (apll))->child_node
	// h->first: (&clk_orphan_list)->first: NULL, n: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node
	h->first = n;
	// h->first: (&clk_root_list)->first: &(kmem_cache#29-oX)->child_node
	// h->first: (&(kmem_cache#29-oX (fin_pll))->children)->first: &(kmem_cache#29-oX (apll))->child_node
	// h->first: (&clk_orphan_list)->first: &(kmem_cache#29-oX (mout_mspll_kfc))->child_node

	// n->pprev: (&(kmem_cache#29-oX)->child_node)->pprev,
	// &h->first: &(&clk_root_list)->first: &(&(kmem_cache#29-oX)->child_node)
	// n->pprev: (&(kmem_cache#29-oX (apll))->child_node)->pprev,
	// &h->first: &(&(kmem_cache#29-oX (fin_pll))->children)->first: &(&(kmem_cache#29-oX (apll))->child_node)
	// n->pprev: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev,
	// &h->first: (&clk_orphan_list)->first: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
	n->pprev = &h->first;
	// n->pprev: (&(kmem_cache#29-oX)->child_node)->pprev: &(&(kmem_cache#29-oX)->child_node)
	// n->pprev: (&(kmem_cache#29-oX (apll))->child_node)->pprev: &(&(kmem_cache#29-oX (apll))->child_node)
	// n->pprev: (&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)->pprev: &(&(kmem_cache#29-oX (mout_mspll_kfc))->child_node)
}

/* next must be != NULL */
static inline void hlist_add_before(struct hlist_node *n,
					struct hlist_node *next)
{
	n->pprev = next->pprev;
	n->next = next;
	next->pprev = &n->next;
	*(n->pprev) = n;
}

static inline void hlist_add_after(struct hlist_node *n,
					struct hlist_node *next)
{
	next->next = n->next;
	n->next = next;
	next->pprev = &n->next;

	if(next->next)
		next->next->pprev  = &next->next;
}

/* after that we'll appear to be on some hlist and hlist_del will work */
static inline void hlist_add_fake(struct hlist_node *n)
{
	n->pprev = &n->next;
}

/*
 * Move a list from one list head to another. Fixup the pprev
 * reference of the first entry if it exists.
 */
static inline void hlist_move_list(struct hlist_head *old,
				   struct hlist_head *new)
{
	new->first = old->first;
	if (new->first)
		new->first->pprev = &new->first;
	old->first = NULL;
}

// ARM10C 20150117
#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos ; pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)

// ARM10C 20150117
// hlist_entry_safe((&clk_root_list)->first, typeof(*(root_clk)), child_node)
// ARM10C 20150117
// hlist_entry_safe((&clk_orphan_list)->first, typeof(*orphan), child_node)
// ARM10C 20150228
// clk->children: (kmem_cache#29-oX (mout_mspll_kfc))->children
// ARM10C 20151114
// (&(&sysfs_fs_type)->fs_supers)->first, typeof(*(old)), s_instances
// ARM10C 20151128
// (256KB의 메모리 공간 + 계산된 hash index 값)->first, typeof(*(inode)), i_hash
#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})

/**
 * hlist_for_each_entry	- iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
// ARM10C 20150117
// #define hlist_for_each_entry(root_clk, &clk_root_list, child_node):
// for (root_clk = hlist_entry_safe((&clk_root_list)->first, typeof(*(root_clk)), child_node);
//      root_clk; root_clk = hlist_entry_safe((root_clk)->child_node.next, typeof(*(root_clk)), child_node))
// ARM10C 20150117
// #define hlist_for_each_entry(root_clk, &clk_orphan_list, child_node):
// for (root_clk = hlist_entry_safe((&clk_orphan_list)->first, typeof(*(root_clk)), child_node);
//      root_clk; root_clk = hlist_entry_safe((root_clk)->child_node.next, typeof(*(root_clk)), child_node))
// ARM10C 20150117
// #define hlist_for_each_entry(child, &clk->children, child_node):
// for (child = hlist_entry_safe((&clk->children)->first, typeof(*(child)), child_node);
//      child; child = hlist_entry_safe((child)->child_node.next, typeof(*(child)), child_node))
// ARM10C 20150228
// #define hlist_for_each_entry(child, &clk->children, child_node):
// for (child = hlist_entry_safe((&clk->children)->first, typeof(*(child)), child_node);
//      child; child = hlist_entry_safe((child)->child_node.next, typeof(*(child)), child_node))
// ARM10C 20151114
// #define hlist_for_each_entry(old, &type->fs_supers, s_instances):
// for (old = hlist_entry_safe((&type->fs_supers)->first, typeof(*(old)), s_instances);
//      old; old = hlist_entry_safe((old)->s_instances.next, typeof(*(old)), s_instances))
// ARM10C 20151128
// #define hlist_for_each_entry(inode, head, i_hash):
// for (inode = hlist_entry_safe((head)->first, typeof(*(inode)), i_hash);
//     inode; inode = hlist_entry_safe((inode)->i_hash.next, typeof(*(inode)), i_hash))
#define hlist_for_each_entry(pos, head, member)				\
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

/**
 * hlist_for_each_entry_continue - iterate over a hlist continuing after current point
 * @pos:	the type * to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue(pos, member)			\
	for (pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

/**
 * hlist_for_each_entry_from - iterate over a hlist continuing from current point
 * @pos:	the type * to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_from(pos, member)				\
	for (; pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

/**
 * hlist_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another &struct hlist_node to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
// ARM10C 20150117
// #define hlist_for_each_entry_safe(orphan, tmp2, &clk_orphan_list, child_node):
// for (orphan = hlist_entry_safe((&clk_orphan_list)->first, typeof(*orphan), child_node);
//      orphan && ({ tmp2 = orphan->child_node.next; 1; }); orphan = hlist_entry_safe(tmp2, typeof(*orphan), child_node))
#define hlist_for_each_entry_safe(pos, n, head, member) 		\
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member);\
	     pos && ({ n = pos->member.next; 1; });			\
	     pos = hlist_entry_safe(n, typeof(*pos), member))

#endif
