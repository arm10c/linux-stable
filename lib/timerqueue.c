/*
 *  Generic Timer-queue
 *
 *  Manages a simple queue of timers, ordered by expiration time.
 *  Uses rbtrees for quick list adds and expiration.
 *
 *  NOTE: All of the following functions need to be serialized
 *  to avoid races. No locking is done by this library code.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/bug.h>
#include <linux/timerqueue.h>
#include <linux/rbtree.h>
#include <linux/export.h>

/**
 * timerqueue_add - Adds timer to timerqueue.
 *
 * @head: head of timerqueue
 * @node: timer node to be added
 *
 * Adds the timer node to the timerqueue, sorted by the
 * node's expires value.
 */
// ARM10C 20150606
// &base->active: [pcp0] &(&(&hrtimer_bases)->clock_base[0])->active,
// &timer->node: &(&sched_clock_timer)->node
void timerqueue_add(struct timerqueue_head *head, struct timerqueue_node *node)
{
	// &head->head.rb_node: [pcp0] &(&(&(&hrtimer_bases)->clock_base[0])->active)->head.rb_node
	struct rb_node **p = &head->head.rb_node;
	// p: [pcp0] &(&(&(&hrtimer_bases)->clock_base[0])->active)->head.rb_node

	struct rb_node *parent = NULL;
	// parent: NULL

	struct timerqueue_node  *ptr;

	/* Make sure we don't add nodes that are already added */
	// &node->node: &(&(&sched_clock_timer)->node)->node,
	// RB_EMPTY_NODE(&(&(&sched_clock_timer)->node)->node): 1
	WARN_ON_ONCE(!RB_EMPTY_NODE(&node->node));

	// *p: [pcp0] (&(&(&hrtimer_bases)->clock_base[0])->active)->head.rb_node: NULL
	while (*p) {
		parent = *p;
		ptr = rb_entry(parent, struct timerqueue_node, node);
		if (node->expires.tv64 < ptr->expires.tv64)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

// 2015/06/06 종료
// 2015/06/13 시작

	// &node->node: &(&(&sched_clock_timer)->node)->node, parent: NULL,
	// p: [pcp0] &(&(&(&hrtimer_bases)->clock_base[0])->active)->head.rb_node
	rb_link_node(&node->node, parent, p);

	// rb_link_node 에서 한일:
	// (&(&(&sched_clock_timer)->node)->node)->__rb_parent_color: NULL
	// (&(&(&sched_clock_timer)->node)->node)->rb_left: NULL
	// (&(&(&sched_clock_timer)->node)->node)->rb_right: NULL
	// [pcp0] (&(&(&hrtimer_bases)->clock_base[0])->active)->head.rb_node: &(&(&sched_clock_timer)->node)->node

	// &node->node: &(&(&sched_clock_timer)->node)->node,
	// &head->head: [pcp0] &(&(&(&hrtimer_bases)->clock_base[0])->active)->head
	rb_insert_color(&node->node, &head->head);

	// rb_insert_color에서 한일:
	// [pcp0] &(&(&(&hrtimer_bases)->clock_base[0])->active)->head 에 RB Tree 형태로
	// &(&(&sched_clock_timer)->node)->node 를 추가함

	// head->next: [pcp0] &(&(&(&hrtimer_bases)->clock_base[0])->active)->next: NULL,
	// node->expires.tv64: &(&(&sched_clock_timer)->node)->expires.tv64: 0x42C1D83B9ACA00,
	// head->next->expires.tv64: [pcp0] &(&(&(&hrtimer_bases)->clock_base[0])->active)->next->expires.tv64
	if (!head->next || node->expires.tv64 < head->next->expires.tv64)
		// head->next: [pcp0] &(&(&(&hrtimer_bases)->clock_base[0])->active)->next: NULL,
		// node: &(&sched_clock_timer)->node
		head->next = node;
		// head->next: [pcp0] &(&(&(&hrtimer_bases)->clock_base[0])->active)->next: &(&sched_clock_timer)->node
}
EXPORT_SYMBOL_GPL(timerqueue_add);

/**
 * timerqueue_del - Removes a timer from the timerqueue.
 *
 * @head: head of timerqueue
 * @node: timer node to be removed
 *
 * Removes the timer node from the timerqueue.
 */
void timerqueue_del(struct timerqueue_head *head, struct timerqueue_node *node)
{
	WARN_ON_ONCE(RB_EMPTY_NODE(&node->node));

	/* update next pointer */
	if (head->next == node) {
		struct rb_node *rbn = rb_next(&node->node);

		head->next = rbn ?
			rb_entry(rbn, struct timerqueue_node, node) : NULL;
	}
	rb_erase(&node->node, &head->head);
	RB_CLEAR_NODE(&node->node);
}
EXPORT_SYMBOL_GPL(timerqueue_del);

/**
 * timerqueue_iterate_next - Returns the timer after the provided timer
 *
 * @node: Pointer to a timer.
 *
 * Provides the timer that is after the given node. This is used, when
 * necessary, to iterate through the list of timers in a timer list
 * without modifying the list.
 */
struct timerqueue_node *timerqueue_iterate_next(struct timerqueue_node *node)
{
	struct rb_node *next;

	if (!node)
		return NULL;
	next = rb_next(&node->node);
	if (!next)
		return NULL;
	return container_of(next, struct timerqueue_node, node);
}
EXPORT_SYMBOL_GPL(timerqueue_iterate_next);
