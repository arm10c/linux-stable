#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/pid_namespace.h>
#include "internal.h"

/*
 * /proc/self:
 */
static int proc_self_readlink(struct dentry *dentry, char __user *buffer,
			      int buflen)
{
	struct pid_namespace *ns = dentry->d_sb->s_fs_info;
	pid_t tgid = task_tgid_nr_ns(current, ns);
	char tmp[PROC_NUMBUF];
	if (!tgid)
		return -ENOENT;
	sprintf(tmp, "%d", tgid);
	return vfs_readlink(dentry,buffer,buflen,tmp);
}

static void *proc_self_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct pid_namespace *ns = dentry->d_sb->s_fs_info;
	pid_t tgid = task_tgid_nr_ns(current, ns);
	char *name = ERR_PTR(-ENOENT);
	if (tgid) {
		/* 11 for max length of signed int in decimal + NULL term */
		name = kmalloc(12, GFP_KERNEL);
		if (!name)
			name = ERR_PTR(-ENOMEM);
		else
			sprintf(name, "%d", tgid);
	}
	nd_set_link(nd, name);
	return NULL;
}

static const struct inode_operations proc_self_inode_operations = {
	.readlink	= proc_self_readlink,
	.follow_link	= proc_self_follow_link,
	.put_link	= kfree_put_link,
};

// ARM10C 20160604
static unsigned self_inum;

int proc_setup_self(struct super_block *s)
{
	struct inode *root_inode = s->s_root->d_inode;
	struct pid_namespace *ns = s->s_fs_info;
	struct dentry *self;
	
	mutex_lock(&root_inode->i_mutex);
	self = d_alloc_name(s->s_root, "self");
	if (self) {
		struct inode *inode = new_inode_pseudo(s);
		if (inode) {
			inode->i_ino = self_inum;
			inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
			inode->i_mode = S_IFLNK | S_IRWXUGO;
			inode->i_uid = GLOBAL_ROOT_UID;
			inode->i_gid = GLOBAL_ROOT_GID;
			inode->i_op = &proc_self_inode_operations;
			d_add(self, inode);
		} else {
			dput(self);
			self = ERR_PTR(-ENOMEM);
		}
	} else {
		self = ERR_PTR(-ENOMEM);
	}
	mutex_unlock(&root_inode->i_mutex);
	if (IS_ERR(self)) {
		pr_err("proc_fill_super: can't allocate /proc/self\n");
		return PTR_ERR(self);
	}
	ns->proc_self = self;
	return 0;
}

// ARM10C 20160604
void __init proc_self_init(void)
{
	proc_alloc_inum(&self_inum);

	// proc_alloc_inum 에서 한일:
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
	//
	// (&(&proc_inum_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&proc_inum_ida)->idr)->layers: 1
	// (&(&proc_inum_ida)->idr)->id_free: (idr object new 0)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함
	//
	// self_inum: 0xF0000001
}
