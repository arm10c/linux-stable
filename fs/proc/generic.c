/*
 * proc/fs/generic.c --- generic routines for the proc-fs
 *
 * This file contains generic proc-fs routines for handling
 * directories and files.
 * 
 * Copyright (C) 1991, 1992 Linus Torvalds.
 * Copyright (C) 1997 Theodore Ts'o
 */

#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/mount.h>
#include <linux/init.h>
#include <linux/idr.h>
#include <linux/namei.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <asm/uaccess.h>

#include "internal.h"

// ARM10C 20160604
// ARM10C 20160611
// DEFINE_SPINLOCK(proc_subdir_lock):
// spinlock_t proc_subdir_lock =
// (spinlock_t )
// { { .rlock =
//     {
//       .raw_lock = { { 0 } },
//       .magic = 0xdead4ead,
//       .owner_cpu = -1,
//       .owner = 0xffffffff,
//     }
// } }
DEFINE_SPINLOCK(proc_subdir_lock);

static int proc_match(unsigned int len, const char *name, struct proc_dir_entry *de)
{
	if (de->namelen != len)
		return 0;
	return !memcmp(name, de->name, len);
}

static int proc_notify_change(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	struct proc_dir_entry *de = PDE(inode);
	int error;

	error = inode_change_ok(inode, iattr);
	if (error)
		return error;

	setattr_copy(inode, iattr);
	mark_inode_dirty(inode);

	de->uid = inode->i_uid;
	de->gid = inode->i_gid;
	de->mode = inode->i_mode;
	return 0;
}

static int proc_getattr(struct vfsmount *mnt, struct dentry *dentry,
			struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	struct proc_dir_entry *de = PROC_I(inode)->pde;
	if (de && de->nlink)
		set_nlink(inode, de->nlink);

	generic_fillattr(inode, stat);
	return 0;
}

static const struct inode_operations proc_file_inode_operations = {
	.setattr	= proc_notify_change,
};

/*
 * This function parses a name such as "tty/driver/serial", and
 * returns the struct proc_dir_entry for "/proc/tty/driver", and
 * returns "serial" in residual.
 */
// ARM10C 20160604
// name: "mounts", ret: &parent, residual: &"mounts"
static int __xlate_proc_name(const char *name, struct proc_dir_entry **ret,
			     const char **residual)
{
	const char     		*cp = name, *next;
	// cp: &"mounts",

	struct proc_dir_entry	*de;
	unsigned int		len;

	// ret: &parent, *ret: parent: NULL
	de = *ret;
	// de: NULL

	// de: NULL
	if (!de)
		// de: NULL
		de = &proc_root;
		// de: &proc_root

	while (1) {
		// cp: &"mounts", strchr("mounts", '/'): NULL
		next = strchr(cp, '/');
		// next: NULL

		// next: NULL
		if (!next)
			break;
			// break 수행

		len = next - cp;
		for (de = de->subdir; de ; de = de->next) {
			if (proc_match(len, cp, de))
				break;
		}
		if (!de) {
			WARN(1, "name '%s'\n", name);
			return -ENOENT;
		}
		cp += len + 1;
	}

	// *residual: "mounts", cp: &"mounts",
	*residual = cp;
	// *residual: "mounts"

	// *ret: parent: NULL, de: &proc_root
	*ret = de;
	// *ret: parent: &proc_root

	return 0;
	// return 0
}

// ARM10C 20160604
// name: "mounts", parent: &parent, &fn: &"mounts"
static int xlate_proc_name(const char *name, struct proc_dir_entry **ret,
			   const char **residual)
{
	int rv;

	spin_lock(&proc_subdir_lock);

	// spin_lock 에서 한일:
	// &proc_subdir_lock 을 이용하여 spin lock 을 수행

	// name: "mounts", ret: &parent, residual: &"mounts"
	// __xlate_proc_name("mounts", &parent, "mounts"): 0
	rv = __xlate_proc_name(name, ret, residual);
	// rv: 0

	// __xlate_proc_name 에서 한일:
	// residual: "mounts" ret: &proc_root

	spin_unlock(&proc_subdir_lock);

	// spin_unlock 에서 한일:
	// &proc_subdir_lock 을 이용하여 spin unlock 을 수행

	// rv: 0
	return rv;
	// return 0
}

// ARM10C 20160514
// DEFINE_IDA(proc_inum_ida):
// struct ida proc_inum_ida =
// {
//     .idr =
//     {
//         .lock =
//         (spinlock_t )
//         { { .rlock =
//              {
//                .raw_lock = { { 0 } },
//                .magic = 0xdead4ead,
//                .owner_cpu = -1,
//                .owner = 0xffffffff,
//              }
//          } },
//      }
//      .free_bitmap = NULL,
// }
static DEFINE_IDA(proc_inum_ida);
// ARM10C 20160514
// DEFINE_SPINLOCK(proc_inum_lock):
// spinlock_t proc_inum_lock =
// (spinlock_t )
// { { .rlock =
//     {
//       .raw_lock = { { 0 } },
//       .magic = 0xdead4ead,
//       .owner_cpu = -1,
//       .owner = 0xffffffff,
//     }
// } }
static DEFINE_SPINLOCK(proc_inum_lock); /* protects the above */

// ARM10C 20160514
// PROC_DYNAMIC_FIRST: 0xF0000000U
#define PROC_DYNAMIC_FIRST 0xF0000000U

/*
 * Return an inode number between PROC_DYNAMIC_FIRST and
 * 0xffffffff, or zero on failure.
 */
// ARM10C 20160514
// &new_ns->proc_inum: &(kmem_cache#30-oX (struct mnt_namespace))->proc_inum
// ARM10C 20160604
// &self_inum
// ARM10C 20160611
// &dp->low_ino: &(kmem_cache#29-oX (struct proc_dir_entry))->low_ino
int proc_alloc_inum(unsigned int *inum)
{
	unsigned int i;
	int error;

retry:
	// GFP_KERNEL: 0xD0, ida_pre_get(&proc_inum_ida, 0xD0): 1
	// GFP_KERNEL: 0xD0, ida_pre_get(&proc_inum_ida, 0xD0): 1
	// GFP_KERNEL: 0xD0, ida_pre_get(&proc_inum_ida, 0xD0): 1
	if (!ida_pre_get(&proc_inum_ida, GFP_KERNEL))
		return -ENOMEM;

	// ida_pre_get 에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&proc_inum_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&proc_inum_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 8

	// __idr_pre_get에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 2 개를 할당 받음
	//
	// (&(&proc_inum_ida)->idr)->id_free 이 idr object new 1번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&proc_inum_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 8

	// __idr_pre_get에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&proc_inum_ida)->idr)->id_free 이 idr object new 2번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&proc_inum_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 8

	spin_lock_irq(&proc_inum_lock);

	// spin_lock_irq 에서 한일:
	// &proc_inum_lock 을 사용하여 spin lock을 수행

	// spin_lock_irq 에서 한일:
	// &proc_inum_lock 을 사용하여 spin lock을 수행

	// spin_lock_irq 에서 한일:
	// &proc_inum_lock 을 사용하여 spin lock을 수행

	// ida_get_new(&proc_inum_ida, &i): 0
	// ida_get_new(&proc_inum_ida, &i): 0
	// ida_get_new(&proc_inum_ida, &i): 0
	error = ida_get_new(&proc_inum_ida, &i);
	// error: 0
	// error: 0
	// error: 0

	// ida_get_new 에서 한일:
	// (&(&proc_inum_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 6
	// (&(&proc_inum_ida)->idr)->layers: 1
	// ((&(&proc_inum_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&proc_inum_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 1
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행
	//
	// i: 0
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함

	// ida_get_new 에서 한일:
	// (&(&proc_inum_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&proc_inum_ida)->idr)->layers: 1
	// (&(&proc_inum_ida)->idr)->id_free: (idr object new 0)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// i: 1
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함

	// ida_get_new 에서 한일:
	// (&(&proc_inum_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&proc_inum_ida)->idr)->layers: 1
	// (&(&proc_inum_ida)->idr)->id_free: (idr object new 0)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 3
	//
	// i: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 2) 의 memory 공간을 반환함

	spin_unlock_irq(&proc_inum_lock);

	// spin_unlock_irq 에서 한일:
	// &proc_inum_lock 을 사용하여 spin lock을 수행

	// spin_unlock_irq 에서 한일:
	// &proc_inum_lock 을 사용하여 spin lock을 수행

	// spin_unlock_irq 에서 한일:
	// &proc_inum_lock 을 사용하여 spin lock을 수행

	// error: 0
	// error: 0
	// error: 0
	if (error == -EAGAIN)
		goto retry;
	else if (error)
		return error;

	// i: 0, UINT_MAX: 0xFFFFFFFF, PROC_DYNAMIC_FIRST: 0xF0000000
	// i: 1, UINT_MAX: 0xFFFFFFFF, PROC_DYNAMIC_FIRST: 0xF0000000
	// i: 2, UINT_MAX: 0xFFFFFFFF, PROC_DYNAMIC_FIRST: 0xF0000000
	if (i > UINT_MAX - PROC_DYNAMIC_FIRST) {
		spin_lock_irq(&proc_inum_lock);
		ida_remove(&proc_inum_ida, i);
		spin_unlock_irq(&proc_inum_lock);
		return -ENOSPC;
	}

	// *inum: (kmem_cache#30-oX (struct mnt_namespace))->proc_inum, PROC_DYNAMIC_FIRST: 0xF0000000, i: 0
	// *inum: self_inum, PROC_DYNAMIC_FIRST: 0xF0000000, i: 1
	// *inum: (kmem_cache#29-oX (struct proc_dir_entry))->low_ino, PROC_DYNAMIC_FIRST: 0xF0000000, i: 2
	*inum = PROC_DYNAMIC_FIRST + i;
	// *inum: (kmem_cache#30-oX (struct mnt_namespace))->proc_inum: 0xF0000000
	// *inum: self_inum: 0xF0000001
	// *inum: (kmem_cache#29-oX (struct proc_dir_entry))->low_ino: 0xF0000002

	return 0;
	// return 0
	// return 0
	// return 0
}

void proc_free_inum(unsigned int inum)
{
	unsigned long flags;
	spin_lock_irqsave(&proc_inum_lock, flags);
	ida_remove(&proc_inum_ida, inum - PROC_DYNAMIC_FIRST);
	spin_unlock_irqrestore(&proc_inum_lock, flags);
}

static void *proc_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	nd_set_link(nd, __PDE_DATA(dentry->d_inode));
	return NULL;
}

// ARM10C 20160611
static const struct inode_operations proc_link_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= proc_follow_link,
};

/*
 * Don't create negative dentries here, return -ENOENT by hand
 * instead.
 */
struct dentry *proc_lookup_de(struct proc_dir_entry *de, struct inode *dir,
		struct dentry *dentry)
{
	struct inode *inode;

	spin_lock(&proc_subdir_lock);
	for (de = de->subdir; de ; de = de->next) {
		if (de->namelen != dentry->d_name.len)
			continue;
		if (!memcmp(dentry->d_name.name, de->name, de->namelen)) {
			pde_get(de);
			spin_unlock(&proc_subdir_lock);
			inode = proc_get_inode(dir->i_sb, de);
			if (!inode)
				return ERR_PTR(-ENOMEM);
			d_set_d_op(dentry, &simple_dentry_operations);
			d_add(dentry, inode);
			return NULL;
		}
	}
	spin_unlock(&proc_subdir_lock);
	return ERR_PTR(-ENOENT);
}

struct dentry *proc_lookup(struct inode *dir, struct dentry *dentry,
		unsigned int flags)
{
	return proc_lookup_de(PDE(dir), dir, dentry);
}

/*
 * This returns non-zero if at EOF, so that the /proc
 * root directory can use this and check if it should
 * continue with the <pid> entries..
 *
 * Note that the VFS-layer doesn't care about the return
 * value of the readdir() call, as long as it's non-negative
 * for success..
 */
int proc_readdir_de(struct proc_dir_entry *de, struct file *file,
		    struct dir_context *ctx)
{
	int i;

	if (!dir_emit_dots(file, ctx))
		return 0;

	spin_lock(&proc_subdir_lock);
	de = de->subdir;
	i = ctx->pos - 2;
	for (;;) {
		if (!de) {
			spin_unlock(&proc_subdir_lock);
			return 0;
		}
		if (!i)
			break;
		de = de->next;
		i--;
	}

	do {
		struct proc_dir_entry *next;
		pde_get(de);
		spin_unlock(&proc_subdir_lock);
		if (!dir_emit(ctx, de->name, de->namelen,
			    de->low_ino, de->mode >> 12)) {
			pde_put(de);
			return 0;
		}
		spin_lock(&proc_subdir_lock);
		ctx->pos++;
		next = de->next;
		pde_put(de);
		de = next;
	} while (de);
	spin_unlock(&proc_subdir_lock);
	return 1;
}

int proc_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);

	return proc_readdir_de(PDE(inode), file, ctx);
}

/*
 * These are the generic /proc directory operations. They
 * use the in-memory "struct proc_dir_entry" tree to parse
 * the /proc directory.
 */
static const struct file_operations proc_dir_operations = {
	.llseek			= generic_file_llseek,
	.read			= generic_read_dir,
	.iterate		= proc_readdir,
};

/*
 * proc directories can do almost nothing..
 */
static const struct inode_operations proc_dir_inode_operations = {
	.lookup		= proc_lookup,
	.getattr	= proc_getattr,
	.setattr	= proc_notify_change,
};

// ARM10C 20160611
// parent: &proc_root, ent: kmem_cache#29-oX (struct proc_dir_entry)
static int proc_register(struct proc_dir_entry * dir, struct proc_dir_entry * dp)
{
	struct proc_dir_entry *tmp;
	int ret;
	
	// &dp->low_ino: &(kmem_cache#29-oX (struct proc_dir_entry))->low_ino
	// proc_alloc_inum(&(kmem_cache#29-oX (struct proc_dir_entry))->low_ino): 0
	ret = proc_alloc_inum(&dp->low_ino);
	// ret: 0

	// proc_alloc_inum 에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&proc_inum_ida)->idr)->id_free 이 idr object new 2번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&proc_inum_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 8
	//
	// (&(&proc_inum_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&proc_inum_ida)->idr)->layers: 1
	// (&(&proc_inum_ida)->idr)->id_free: (idr object new 0)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 3
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 2) 의 memory 공간을 반환함
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->low_ino: 0xF0000002

	// ret: 0
	if (ret)
		return ret;

	// dp->mode: (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0120777,
	// S_ISDIR(0120777): 0, S_ISLNK(0120777): 1
	if (S_ISDIR(dp->mode)) {
		dp->proc_fops = &proc_dir_operations;
		dp->proc_iops = &proc_dir_inode_operations;
		dir->nlink++;
	} else if (S_ISLNK(dp->mode)) {
		// dp->proc_iops: (kmem_cache#29-oX (struct proc_dir_entry))->proc_iops
		dp->proc_iops = &proc_link_inode_operations;
		// dp->proc_iops: (kmem_cache#29-oX (struct proc_dir_entry))->proc_iops: &proc_link_inode_operations
	} else if (S_ISREG(dp->mode)) {
		BUG_ON(dp->proc_fops == NULL);
		dp->proc_iops = &proc_file_inode_operations;
	} else {
		WARN_ON(1);
		return -EINVAL;
	}

	spin_lock(&proc_subdir_lock);

	// spin_lock 에서 한일:
	// &proc_subdir_lock 을 이용하여 spin lock 을 수행

	// dir: &proc_root, dir->subdir: (&proc_root)->subdir: NULL
	for (tmp = dir->subdir; tmp; tmp = tmp->next)
		if (strcmp(tmp->name, dp->name) == 0) {
			WARN(1, "proc_dir_entry '%s/%s' already registered\n",
				dir->name, dp->name);
			break;
		}

	// dp->next: (kmem_cache#29-oX (struct proc_dir_entry))->next, dir->subdir: (&proc_root)->subdir: NULL
	dp->next = dir->subdir;
	// dp->next: (kmem_cache#29-oX (struct proc_dir_entry))->next: NULL

	// dp->parent: (kmem_cache#29-oX (struct proc_dir_entry))->parent, dir: &proc_root
	dp->parent = dir;
	// dp->parent: (kmem_cache#29-oX (struct proc_dir_entry))->parent: &proc_root

	// dir->subdir: (&proc_root)->subdir, dp: kmem_cache#29-oX (struct proc_dir_entry)
	dir->subdir = dp;
	// dir->subdir: (&proc_root)->subdir: kmem_cache#29-oX (struct proc_dir_entry)

	spin_unlock(&proc_subdir_lock);

	// spin_unlock 에서 한일:
	// &proc_subdir_lock 을 이용하여 spin unlock 을 수행

	return 0;
	// return 0
}

// ARM10C 20160604
// &parent, name: "mounts", 0120777, 1
static struct proc_dir_entry *__proc_create(struct proc_dir_entry **parent,
					  const char *name,
					  umode_t mode,
					  nlink_t nlink)
{
	struct proc_dir_entry *ent = NULL;
	// ent: NULL

	const char *fn = name;
	// fn: "mounts"

	unsigned int len;

	/* make sure name is valid */
	// name: "mounts", strlen("mounts"): 6
	if (!name || !strlen(name))
		goto out;

	// name: "mounts", parent: &parent, &fn: &"mounts"
	// xlate_proc_name("mounts", &parent, "mounts"): 0
	if (xlate_proc_name(name, parent, &fn) != 0)
		goto out;

	// xlate_proc_name 에서 한일:
	// parent: &proc_root

	/* At this point there must not be any '/' characters beyond *fn */
	// fn: "mounts", strchr("mounts", '/'): NULL
	if (strchr(fn, '/'))
		goto out;

	// fn: "mounts", strlen("mounts"): 6
	len = strlen(fn);
	// len: 6

	// ent: NULL, sizeof(struct proc_dir_entry): 91 bytes, len: 6, GFP_KERNEL: 0xD0
	// kzalloc(98, GFP_KERNEL: 0xD0): kmem_cache#29-oX
	ent = kzalloc(sizeof(struct proc_dir_entry) + len + 1, GFP_KERNEL);
	// ent: kmem_cache#29-oX (struct proc_dir_entry)

	// ent: kmem_cache#29-oX (struct proc_dir_entry)
	if (!ent)
		goto out;

	// ent->name: (kmem_cache#29-oX (struct proc_dir_entry))->name, fn: "mounts", len: 6
	memcpy(ent->name, fn, len + 1);
	// ent->name: (kmem_cache#29-oX (struct proc_dir_entry))->name: "mounts"

	// ent->namelen: (kmem_cache#29-oX (struct proc_dir_entry))->namelen, len: 6
	ent->namelen = len;
	// ent->namelen: (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 6

	// ent->mode: (kmem_cache#29-oX (struct proc_dir_entry))->mode, mode: 0120777
	ent->mode = mode;
	// ent->mode: (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0120777

	// ent->nlink: (kmem_cache#29-oX (struct proc_dir_entry))->nlink, nlink: 1
	ent->nlink = nlink;
	// ent->nlink: (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 1

	// &ent->count: &(kmem_cache#29-oX (struct proc_dir_entry))->count
	atomic_set(&ent->count, 1);

	// atomic_set 에서 한일:
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1

// 2016/06/04 종료
// 2016/06/11 시작

	// &ent->pde_unload_lock: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock
	spin_lock_init(&ent->pde_unload_lock);

	// spin_lock_init에서 한일:
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	//
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff

	// &ent->pde_openers: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers
	INIT_LIST_HEAD(&ent->pde_openers);

	// INIT_LIST_HEAD 에서 한일:
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
out:
	// ent: kmem_cache#29-oX (struct proc_dir_entry)
	return ent;
	// return kmem_cache#29-oX (struct proc_dir_entry)
}

// ARM10C 20160604
// "mounts", NULL, "self/mounts"
struct proc_dir_entry *proc_symlink(const char *name,
		struct proc_dir_entry *parent, const char *dest)
{
	struct proc_dir_entry *ent;

	// &parent, name: "mounts"
	// S_IFLNK: 0120000, S_IRUGO: 00444, S_IWUGO: 00222, S_IXUGO: 00111
	// __proc_create(NULL, "mounts", 0120777, 1): kmem_cache#29-oX (struct proc_dir_entry)
	ent = __proc_create(&parent, name,
			  (S_IFLNK | S_IRUGO | S_IWUGO | S_IXUGO),1);
	// ent: kmem_cache#29-oX (struct proc_dir_entry)

	// __proc_create 에서 한일:
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "mounts"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 6
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0120777
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 1
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root

	// ent: kmem_cache#29-oX (struct proc_dir_entry)
	if (ent) {
		// ent->data: (kmem_cache#29-oX (struct proc_dir_entry))->data, dest: "self/mounts", strlen("self/mounts"): 11
		// ent->size: (kmem_cache#29-oX (struct proc_dir_entry))->size: 11, GFP_KERNEL: 0xD0,
		// kmalloc(12, GFP_KERNEL: 0xD0): kmem_cache#30-oX
		ent->data = kmalloc((ent->size=strlen(dest))+1, GFP_KERNEL);
		// ent->data: (kmem_cache#29-oX (struct proc_dir_entry))->data: kmem_cache#30-oX

		// ent->data: (kmem_cache#29-oX (struct proc_dir_entry))->data: kmem_cache#30-oX
		if (ent->data) {
			// ent->data: (kmem_cache#29-oX (struct proc_dir_entry))->data: kmem_cache#30-oX, dest: "self/mounts"
			// strcpy(kmem_cache#30-oX, "self/mounts"): kmem_cache#30-oX: "self/mounts"
			strcpy((char*)ent->data,dest);
			// ent->data: (kmem_cache#29-oX (struct proc_dir_entry))->data: kmem_cache#30-oX: "self/mounts"

			// parent: NULL, ent: kmem_cache#29-oX (struct proc_dir_entry),
			// proc_register(NULL, kmem_cache#29-oX (struct proc_dir_entry)): 0
			if (proc_register(parent, ent) < 0) {
				kfree(ent->data);
				kfree(ent);
				ent = NULL;
			}

			// proc_register 에서 한일:
			// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
			//
			// (&(&proc_inum_ida)->idr)->id_free 이 idr object new 2번을 가르킴
			// |
			// |-> ---------------------------------------------------------------------------------------------------------------------------
			//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
			//     ---------------------------------------------------------------------------------------------------------------------------
			//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
			//     ---------------------------------------------------------------------------------------------------------------------------
			//
			// (&(&proc_inum_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
			// (&(&proc_inum_ida)->idr)->id_free_cnt: 8
			//
			// (&(&proc_inum_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
			// (&(&proc_inum_ida)->idr)->layers: 1
			// (&(&proc_inum_ida)->idr)->id_free: (idr object new 0)
			// (&(&proc_inum_ida)->idr)->id_free_cnt: 7
			//
			// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
			// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 3
			//
			// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 2) 의 memory 공간을 반환함
			//
			// (kmem_cache#29-oX (struct proc_dir_entry))->low_ino: 0xF0000002
			// (kmem_cache#29-oX (struct proc_dir_entry))->proc_iops: &proc_link_inode_operations
			// (kmem_cache#29-oX (struct proc_dir_entry))->next: NULL
			// (kmem_cache#29-oX (struct proc_dir_entry))->parent: &proc_root
			//
			// (&proc_root)->subdir: kmem_cache#29-oX (struct proc_dir_entry)
		} else {
			kfree(ent);
			ent = NULL;
		}
	}

	// ent: kmem_cache#29-oX (struct proc_dir_entry)
	return ent;
	// return kmem_cache#29-oX (struct proc_dir_entry)
}
EXPORT_SYMBOL(proc_symlink);

struct proc_dir_entry *proc_mkdir_data(const char *name, umode_t mode,
		struct proc_dir_entry *parent, void *data)
{
	struct proc_dir_entry *ent;

	if (mode == 0)
		mode = S_IRUGO | S_IXUGO;

	ent = __proc_create(&parent, name, S_IFDIR | mode, 2);
	if (ent) {
		ent->data = data;
		if (proc_register(parent, ent) < 0) {
			kfree(ent);
			ent = NULL;
		}
	}
	return ent;
}
EXPORT_SYMBOL_GPL(proc_mkdir_data);

struct proc_dir_entry *proc_mkdir_mode(const char *name, umode_t mode,
				       struct proc_dir_entry *parent)
{
	return proc_mkdir_data(name, mode, parent, NULL);
}
EXPORT_SYMBOL(proc_mkdir_mode);

struct proc_dir_entry *proc_mkdir(const char *name,
		struct proc_dir_entry *parent)
{
	return proc_mkdir_data(name, 0, parent, NULL);
}
EXPORT_SYMBOL(proc_mkdir);

struct proc_dir_entry *proc_create_data(const char *name, umode_t mode,
					struct proc_dir_entry *parent,
					const struct file_operations *proc_fops,
					void *data)
{
	struct proc_dir_entry *pde;
	if ((mode & S_IFMT) == 0)
		mode |= S_IFREG;

	if (!S_ISREG(mode)) {
		WARN_ON(1);	/* use proc_mkdir() */
		return NULL;
	}

	if ((mode & S_IALLUGO) == 0)
		mode |= S_IRUGO;
	pde = __proc_create(&parent, name, mode, 1);
	if (!pde)
		goto out;
	pde->proc_fops = proc_fops;
	pde->data = data;
	if (proc_register(parent, pde) < 0)
		goto out_free;
	return pde;
out_free:
	kfree(pde);
out:
	return NULL;
}
EXPORT_SYMBOL(proc_create_data);
 
void proc_set_size(struct proc_dir_entry *de, loff_t size)
{
	de->size = size;
}
EXPORT_SYMBOL(proc_set_size);

void proc_set_user(struct proc_dir_entry *de, kuid_t uid, kgid_t gid)
{
	de->uid = uid;
	de->gid = gid;
}
EXPORT_SYMBOL(proc_set_user);

static void free_proc_entry(struct proc_dir_entry *de)
{
	proc_free_inum(de->low_ino);

	if (S_ISLNK(de->mode))
		kfree(de->data);
	kfree(de);
}

void pde_put(struct proc_dir_entry *pde)
{
	if (atomic_dec_and_test(&pde->count))
		free_proc_entry(pde);
}

/*
 * Remove a /proc entry and free it if it's not currently in use.
 */
void remove_proc_entry(const char *name, struct proc_dir_entry *parent)
{
	struct proc_dir_entry **p;
	struct proc_dir_entry *de = NULL;
	const char *fn = name;
	unsigned int len;

	spin_lock(&proc_subdir_lock);
	if (__xlate_proc_name(name, &parent, &fn) != 0) {
		spin_unlock(&proc_subdir_lock);
		return;
	}
	len = strlen(fn);

	for (p = &parent->subdir; *p; p=&(*p)->next ) {
		if (proc_match(len, fn, *p)) {
			de = *p;
			*p = de->next;
			de->next = NULL;
			break;
		}
	}
	spin_unlock(&proc_subdir_lock);
	if (!de) {
		WARN(1, "name '%s'\n", name);
		return;
	}

	proc_entry_rundown(de);

	if (S_ISDIR(de->mode))
		parent->nlink--;
	de->nlink = 0;
	WARN(de->subdir, "%s: removing non-empty directory "
			 "'%s/%s', leaking at least '%s'\n", __func__,
			 de->parent->name, de->name, de->subdir->name);
	pde_put(de);
}
EXPORT_SYMBOL(remove_proc_entry);

int remove_proc_subtree(const char *name, struct proc_dir_entry *parent)
{
	struct proc_dir_entry **p;
	struct proc_dir_entry *root = NULL, *de, *next;
	const char *fn = name;
	unsigned int len;

	spin_lock(&proc_subdir_lock);
	if (__xlate_proc_name(name, &parent, &fn) != 0) {
		spin_unlock(&proc_subdir_lock);
		return -ENOENT;
	}
	len = strlen(fn);

	for (p = &parent->subdir; *p; p=&(*p)->next ) {
		if (proc_match(len, fn, *p)) {
			root = *p;
			*p = root->next;
			root->next = NULL;
			break;
		}
	}
	if (!root) {
		spin_unlock(&proc_subdir_lock);
		return -ENOENT;
	}
	de = root;
	while (1) {
		next = de->subdir;
		if (next) {
			de->subdir = next->next;
			next->next = NULL;
			de = next;
			continue;
		}
		spin_unlock(&proc_subdir_lock);

		proc_entry_rundown(de);
		next = de->parent;
		if (S_ISDIR(de->mode))
			next->nlink--;
		de->nlink = 0;
		if (de == root)
			break;
		pde_put(de);

		spin_lock(&proc_subdir_lock);
		de = next;
	}
	pde_put(root);
	return 0;
}
EXPORT_SYMBOL(remove_proc_subtree);

void *proc_get_parent_data(const struct inode *inode)
{
	struct proc_dir_entry *de = PDE(inode);
	return de->parent->data;
}
EXPORT_SYMBOL_GPL(proc_get_parent_data);

void proc_remove(struct proc_dir_entry *de)
{
	if (de)
		remove_proc_subtree(de->name, de->parent);
}
EXPORT_SYMBOL(proc_remove);

void *PDE_DATA(const struct inode *inode)
{
	return __PDE_DATA(inode);
}
EXPORT_SYMBOL(PDE_DATA);
