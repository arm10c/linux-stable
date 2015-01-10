/*
  Red Black Trees
  (C) 1999  Andrea Arcangeli <andrea@suse.de>
  
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  linux/include/linux/rbtree.h

  To use rbtrees you'll have to implement your own insert and search cores.
  This will avoid us to use callbacks and to drop drammatically performances.
  I know it's not the cleaner way,  but in C (not in C++) to get
  performances and genericity...

  See Documentation/rbtree.txt for documentation and samples.
*/

#ifndef	_LINUX_RBTREE_H
#define	_LINUX_RBTREE_H

#include <linux/kernel.h>
#include <linux/stddef.h>

// ARM10C 20140809
// ARM10C 20141025
// sizeof(struct rb_node): 12 bytes
struct rb_node {
	unsigned long  __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
    /* The alignment might seem pointless, but allegedly CRIS needs it */

// ARM10C 20140809
// ARM10C 20141025
// ARM10C 20150103
struct rb_root {
	struct rb_node *rb_node;
};


// ARM10C 20141025
// node: (kmem_cache#30-oX (GIC))->rb_node
#define rb_parent(r)   ((struct rb_node *)((r)->__rb_parent_color & ~3))

// ARM10C 20140809
// ARM10C 20140830
// ARM10C 20150103
// RB_ROOT: (struct rb_root) { NULL, }
#define RB_ROOT	(struct rb_root) { NULL, }

// ARM10C 20141025
// ARM10C 20141206
#define	rb_entry(ptr, type, member) container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root)  ((root)->rb_node == NULL)

/* 'empty' nodes are nodes that are known not to be inserted in an rbree */
// ARM10C 20141025
// node: (kmem_cache#30-oX (GIC#0))->rb_node
// ARM10C 20141108
// node: (kmem_cache#30-oX (GIC#1))->rb_node
#define RB_EMPTY_NODE(node)  \
	((node)->__rb_parent_color == (unsigned long)(node))
// ARM10C 20140830
// &node->node: (&(&(&def_rt_bandwidth)->rt_period_timer)->node)->node
//
// #define RB_CLEAR_NODE((&(&(&def_rt_bandwidth)->rt_period_timer)->node)->node)
// 	(((&(&(&def_rt_bandwidth)->rt_period_timer)->node)->node)->__rb_parent_color =
// 	(unsigned long)((&(&(&def_rt_bandwidth)->rt_period_timer)->node)->node))
#define RB_CLEAR_NODE(node)  \
	((node)->__rb_parent_color = (unsigned long)(node))


extern void rb_insert_color(struct rb_node *, struct rb_root *);
extern void rb_erase(struct rb_node *, struct rb_root *);


/* Find logical next and previous nodes in a tree */
extern struct rb_node *rb_next(const struct rb_node *);
extern struct rb_node *rb_prev(const struct rb_node *);
extern struct rb_node *rb_first(const struct rb_root *);
extern struct rb_node *rb_last(const struct rb_root *);

/* Postorder iteration - always visit the parent after its children */
extern struct rb_node *rb_first_postorder(const struct rb_root *);
extern struct rb_node *rb_next_postorder(const struct rb_node *);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
extern void rb_replace_node(struct rb_node *victim, struct rb_node *new, 
			    struct rb_root *root);

// ARM10C 20140809
// &va->rb_node: &(kmem_cache#30-o9)->rb_node, parent: NULL, p: &vmap_area_root.rb_node
// ARM10C 20141025
// va->rb_node: (kmem_cache#30-oX (GIC#0))->rb_node, parent: SYSC node, p: (SYSC node)->rb_left
// ARM10C 20141206
// va->rb_node: (kmem_cache#30-oX (COMB))->rb_node, parent: SYSC node, p: (SYSC node)->rb_left
// ARM10C 20150110
// va->rb_node: (kmem_cache#30-oX (CLK))->rb_node, parent: COMB node, p: (COMB node)->rb_right
static inline void rb_link_node(struct rb_node * node, struct rb_node * parent,
				struct rb_node ** rb_link)
{
	// node->__rb_parent_color: (kmem_cache#30-o9)->rb_node.__rb_parent_color, parent: NULL
	// ((GIC#0)->rb_node)->__rb_parent_color, parent: (SYSC)->rb_node
	node->__rb_parent_color = (unsigned long)parent;
	// node->__rb_parent_color: (kmem_cache#30-o9)->rb_node.__rb_parent_color: NULL
	// ((GIC#0)->rb_node)->__rb_parent_color: (SYSC)->rb_node

	node->rb_left = node->rb_right = NULL;
	// node->rb_left: (kmem_cache#30-o9)->rb_node.rb_left: NULL
	// node->rb_right: (kmem_cache#30-o9)->rb_node.rb_right: NULL
	// ((GIC#0)->rb_node)->rb_left: ((GIC#0)->rb_node).rb_left: NULL
	// ((GIC#0)->rb_node)->rb_right: ((GIC#0)->rb_node).rb_right: NULL

	// *rb_link: vmap_area_root.rb_node, node: &(kmem_cache#30-o9)->rb_node
	// *rb_link: (SYSC node)->rb_left, node: &(GIC#0)->rb_node
	*rb_link = node;
	// vmap_area_root.rb_node: &(kmem_cache#30-o9)->rb_node
	// (SYSC node)->rb_left: &(GIC#0)->rb_node
}

#define rb_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? rb_entry(____ptr, type, member) : NULL; \
	})

/**
 * rbtree_postorder_for_each_entry_safe - iterate over rb_root in post order of
 * given type safe against removal of rb_node entry
 *
 * @pos:	the 'type *' to use as a loop cursor.
 * @n:		another 'type *' to use as temporary storage
 * @root:	'rb_root *' of the rbtree.
 * @field:	the name of the rb_node field within 'type'.
 */
#define rbtree_postorder_for_each_entry_safe(pos, n, root, field) \
	for (pos = rb_entry_safe(rb_first_postorder(root), typeof(*pos), field); \
	     pos && ({ n = rb_entry_safe(rb_next_postorder(&pos->field), \
			typeof(*pos), field); 1; }); \
	     pos = n)

#endif	/* _LINUX_RBTREE_H */
