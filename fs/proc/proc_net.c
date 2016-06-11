/*
 *  linux/fs/proc/net.c
 *
 *  Copyright (C) 2007
 *
 *  Author: Eric Biederman <ebiederm@xmission.com>
 *
 *  proc net directory handling functions
 */

#include <asm/uaccess.h>

#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <linux/seq_file.h>

#include "internal.h"

static inline struct net *PDE_NET(struct proc_dir_entry *pde)
{
	return pde->parent->data;
}

static struct net *get_proc_net(const struct inode *inode)
{
	return maybe_get_net(PDE_NET(PDE(inode)));
}

int seq_open_net(struct inode *ino, struct file *f,
		 const struct seq_operations *ops, int size)
{
	struct net *net;
	struct seq_net_private *p;

	BUG_ON(size < sizeof(*p));

	net = get_proc_net(ino);
	if (net == NULL)
		return -ENXIO;

	p = __seq_open_private(f, ops, size);
	if (p == NULL) {
		put_net(net);
		return -ENOMEM;
	}
#ifdef CONFIG_NET_NS
	p->net = net;
#endif
	return 0;
}
EXPORT_SYMBOL_GPL(seq_open_net);

int single_open_net(struct inode *inode, struct file *file,
		int (*show)(struct seq_file *, void *))
{
	int err;
	struct net *net;

	err = -ENXIO;
	net = get_proc_net(inode);
	if (net == NULL)
		goto err_net;

	err = single_open(file, show, net);
	if (err < 0)
		goto err_open;

	return 0;

err_open:
	put_net(net);
err_net:
	return err;
}
EXPORT_SYMBOL_GPL(single_open_net);

int seq_release_net(struct inode *ino, struct file *f)
{
	struct seq_file *seq;

	seq = f->private_data;

	put_net(seq_file_net(seq));
	seq_release_private(ino, f);
	return 0;
}
EXPORT_SYMBOL_GPL(seq_release_net);

int single_release_net(struct inode *ino, struct file *f)
{
	struct seq_file *seq = f->private_data;
	put_net(seq->private);
	return single_release(ino, f);
}
EXPORT_SYMBOL_GPL(single_release_net);

static struct net *get_proc_task_net(struct inode *dir)
{
	struct task_struct *task;
	struct nsproxy *ns;
	struct net *net = NULL;

	rcu_read_lock();
	task = pid_task(proc_pid(dir), PIDTYPE_PID);
	if (task != NULL) {
		ns = task_nsproxy(task);
		if (ns != NULL)
			net = get_net(ns->net_ns);
	}
	rcu_read_unlock();

	return net;
}

static struct dentry *proc_tgid_net_lookup(struct inode *dir,
		struct dentry *dentry, unsigned int flags)
{
	struct dentry *de;
	struct net *net;

	de = ERR_PTR(-ENOENT);
	net = get_proc_task_net(dir);
	if (net != NULL) {
		de = proc_lookup_de(net->proc_net, dir, dentry);
		put_net(net);
	}
	return de;
}

static int proc_tgid_net_getattr(struct vfsmount *mnt, struct dentry *dentry,
		struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	struct net *net;

	net = get_proc_task_net(inode);

	generic_fillattr(inode, stat);

	if (net != NULL) {
		stat->nlink = net->proc_net->nlink;
		put_net(net);
	}

	return 0;
}

const struct inode_operations proc_net_inode_operations = {
	.lookup		= proc_tgid_net_lookup,
	.getattr	= proc_tgid_net_getattr,
};

static int proc_tgid_net_readdir(struct file *file, struct dir_context *ctx)
{
	int ret;
	struct net *net;

	ret = -EINVAL;
	net = get_proc_task_net(file_inode(file));
	if (net != NULL) {
		ret = proc_readdir_de(net->proc_net, file, ctx);
		put_net(net);
	}
	return ret;
}

const struct file_operations proc_net_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= proc_tgid_net_readdir,
};

// ARM10C 20160611
static __net_init int proc_net_ns_init(struct net *net)
{
	struct proc_dir_entry *netd, *net_statd;
	int err;

	err = -ENOMEM;
	netd = kzalloc(sizeof(*netd) + 4, GFP_KERNEL);
	if (!netd)
		goto out;

	netd->data = net;
	netd->nlink = 2;
	netd->namelen = 3;
	netd->parent = &proc_root;
	memcpy(netd->name, "net", 4);

	err = -EEXIST;
	net_statd = proc_net_mkdir(net, "stat", netd);
	if (!net_statd)
		goto free_net;

	net->proc_net = netd;
	net->proc_net_stat = net_statd;
	return 0;

free_net:
	kfree(netd);
out:
	return err;
}

static __net_exit void proc_net_ns_exit(struct net *net)
{
	remove_proc_entry("stat", net->proc_net);
	kfree(net->proc_net);
}

// ARM10C 20160611
static struct pernet_operations __net_initdata proc_net_ns_ops = {
	.init = proc_net_ns_init,
	.exit = proc_net_ns_exit,
};

// ARM10C 20160611
int __init proc_net_init(void)
{
	// proc_symlink("net", NULL, "self/net"): kmem_cache#29-oX (struct proc_dir_entry)
	proc_symlink("net", NULL, "self/net");

	// proc_symlink 에서 한일:
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "net"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 3
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
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->data: kmem_cache#30-oX: "self/net"
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&proc_inum_ida)->idr)->id_free 이 idr object new 3번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 3         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&proc_inum_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 3)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 8
	//
	// (&(&proc_inum_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&proc_inum_ida)->idr)->layers: 1
	// (&(&proc_inum_ida)->idr)->id_free: (idr object new 0)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 3 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 4
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 3) 의 memory 공간을 반환함
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->low_ino: 0xF0000003
	// (kmem_cache#29-oX (struct proc_dir_entry))->proc_iops: &proc_link_inode_operations
	// (kmem_cache#29-oX (struct proc_dir_entry))->next: NULL
	// (kmem_cache#29-oX (struct proc_dir_entry))->parent: &proc_root
	//
	// (&proc_root)->subdir: kmem_cache#29-oX (struct proc_dir_entry)

	// register_pernet_subsys(&proc_net_ns_ops): 0
	return register_pernet_subsys(&proc_net_ns_ops);
	// return 0

	// register_pernet_subsys 에서 한일:
	// list head 인 &pernet_list 에 &(&proc_net_ns_ops)->list 을 tail로 추가함
}
