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

// ARM10C 20161126
static const struct inode_operations proc_self_inode_operations = {
	.readlink	= proc_self_readlink,
	.follow_link	= proc_self_follow_link,
	.put_link	= kfree_put_link,
};

// ARM10C 20160604
// ARM10C 20161126
static unsigned self_inum;

// ARM10C 20161126
// s: kmem_cache#25-oX (struct super_block)
int proc_setup_self(struct super_block *s)
{
	// s->s_root: (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
	// s->s_root->d_inode: (kmem_cache#5-oX (struct dentry))->d_inode: kmem_cache#4-oX (struct inode)
	struct inode *root_inode = s->s_root->d_inode;
	// root_inode: kmem_cache#4-oX (struct inode)

	// s->s_fs_info: (kmem_cache#25-oX (struct super_block))->s_fs_info: &init_pid_ns
	struct pid_namespace *ns = s->s_fs_info;
	// ns: &init_pid_ns

	struct dentry *self;
	
	// &root_inode->i_mutex: &(kmem_cache#4-oX (struct inode))->i_mutex
	mutex_lock(&root_inode->i_mutex);

	// mutex_lock 에서 한일:
	// &(kmem_cache#4-oX (struct inode))->i_mutex 을 사용하여 mutex lock 수행

	// s->s_root: (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
	// d_alloc_name(kmem_cache#5-oX (struct dentry)): kmem_cache#5-oX (struct dentry)
	self = d_alloc_name(s->s_root, "self");
	// self: kmem_cache#5-oX (struct dentry)

	// d_alloc_name 에서 한일:
	// dentry_cache인 kmem_cache#5을 사용하여 dentry로 사용할 메모리 kmem_cache#5-oX (struct dentry)을 할당받음
	//
	// (kmem_cache#5-oX (struct dentry))->d_iname[35]: 0
	// (kmem_cache#5-oX (struct dentry))->d_name.len: 4
	// (kmem_cache#5-oX (struct dentry))->d_name.hash: (&q)->hash: 0xXXXXXXXX
	// (kmem_cache#5-oX (struct dentry))->d_iname: "self"
	//
	// 공유자원을 다른 cpu core가 사용할수 있게 함
	//
	// (kmem_cache#5-oX (struct dentry))->d_name.name: "self"
	// (kmem_cache#5-oX (struct dentry))->d_lockref.count: 1
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->magic: 0xdead4ead
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->owner: 0xffffffff
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->owner_cpu: 0xffffffff
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_seq)->sequence: 0
	//
	// (kmem_cache#5-oX (struct dentry))->d_inode: NULL
	//
	// (kmem_cache#5-oX (struct dentry))->d_parent: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#5-oX (struct dentry))->d_sb: kmem_cache#25-oX (struct super_block)
	// (kmem_cache#5-oX (struct dentry))->d_op: NULL
	// (kmem_cache#5-oX (struct dentry))->d_fsdata: NULL
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->pprev: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_lru)->next: &(kmem_cache#5-oX (struct dentry))->d_lru
	// (&(kmem_cache#5-oX (struct dentry))->d_lru)->prev: &(kmem_cache#5-oX (struct dentry))->d_lru
	// (&(kmem_cache#5-oX (struct dentry))->d_subdirs)->next: &(kmem_cache#5-oX (struct dentry))->d_subdirs
	// (&(kmem_cache#5-oX (struct dentry))->d_subdirs)->prev: &(kmem_cache#5-oX (struct dentry))->d_subdirs
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->pprev: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_u.d_child)->next: &(kmem_cache#5-oX (struct dentry))->d_u.d_child
	// (&(kmem_cache#5-oX (struct dentry))->d_u.d_child)->prev: &(kmem_cache#5-oX (struct dentry))->d_u.d_child
	//
	// (kmem_cache#5-oX (struct dentry))->d_op: NULL
	//
	// [pcp0] nr_dentry: 4
	//
	// (kmem_cache#5-oX (struct dentry))->d_lockref.count: 1
	// (kmem_cache#5-oX (struct dentry))->d_parent: kmem_cache#5-oX (struct dentry)
	//
	// head list 인 &(kmem_cache#5-oX (struct dentry))->d_subdirs 에
	// list &(kmem_cache#5-oX (struct dentry))->d_u.d_child 를 추가함

	// self: kmem_cache#5-oX (struct dentry)
	if (self) {
		// s: kmem_cache#25-oX (struct super_block),
		// new_inode_pseudo(kmem_cache#25-oX (struct super_block)): kmem_cache#4-oX (struct inode)
		struct inode *inode = new_inode_pseudo(s);
		// inode: kmem_cache#4-oX (struct inode)

		// new_inode_pseudo 에서 한일:
		// struct inode 만큼의 메모리를 할당 받음 kmem_cache#4-oX (struct inode)
		//
		// (kmem_cache#4-oX (struct inode))->i_sb: kmem_cache#25-oX (struct super_block)
		// (kmem_cache#4-oX (struct inode))->i_blkbits: 12
		// (kmem_cache#4-oX (struct inode))->i_flags: 0
		// (kmem_cache#4-oX (struct inode))->i_count: 1
		// (kmem_cache#4-oX (struct inode))->i_op: &empty_iops
		// (kmem_cache#4-oX (struct inode))->__i_nlink: 1
		// (kmem_cache#4-oX (struct inode))->i_opflags: 0
		// (kmem_cache#4-oX (struct inode))->i_uid: 0
		// (kmem_cache#4-oX (struct inode))->i_gid: 0
		// (kmem_cache#4-oX (struct inode))->i_count: 0
		// (kmem_cache#4-oX (struct inode))->i_size: 0
		// (kmem_cache#4-oX (struct inode))->i_blocks: 0
		// (kmem_cache#4-oX (struct inode))->i_bytes: 0
		// (kmem_cache#4-oX (struct inode))->i_generation: 0
		// (kmem_cache#4-oX (struct inode))->i_pipe: NULL
		// (kmem_cache#4-oX (struct inode))->i_bdev: NULL
		// (kmem_cache#4-oX (struct inode))->i_cdev: NULL
		// (kmem_cache#4-oX (struct inode))->i_rdev: 0
		// (kmem_cache#4-oX (struct inode))->dirtied_when: 0
		//
		// &(kmem_cache#4-oX (struct inode))->i_lock을 이용한 spin lock 초기화 수행
		//
		// ((&(kmem_cache#4-oX (struct inode))->i_lock)->rlock)->raw_lock: { { 0 } }
		// ((&(kmem_cache#4-oX (struct inode))->i_lock)->rlock)->magic: 0xdead4ead
		// ((&(kmem_cache#4-oX (struct inode))->i_lock)->rlock)->owner: 0xffffffff
		// ((&(kmem_cache#4-oX (struct inode))->i_lock)->rlock)->owner_cpu: 0xffffffff
		//
		// (&(kmem_cache#4-oX (struct inode))->i_mutex)->count: 1
		// (&(&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
		// (&(&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
		// (&(&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_lock)->rlock)->owner: 0xffffffff
		// (&(&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
		// (&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_list)->next: &(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_list
		// (&(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_list)->prev: &(&(kmem_cache#4-oX (struct inode))->i_mutex)->wait_list
		// (&(kmem_cache#4-oX (struct inode))->i_mutex)->onwer: NULL
		// (&(kmem_cache#4-oX (struct inode))->i_mutex)->magic: &(kmem_cache#4-oX (struct inode))->i_mutex
		//
		// (kmem_cache#4-oX (struct inode))->i_dio_count: 0
		//
		// (&(kmem_cache#4-oX (struct inode))->i_data)->a_ops: &empty_aops
		// (&(kmem_cache#4-oX (struct inode))->i_data)->host: kmem_cache#4-oX (struct inode)
		// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0
		// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0x200DA
		// (&(kmem_cache#4-oX (struct inode))->i_data)->private_data: NULL
		// (&(kmem_cache#4-oX (struct inode))->i_data)->backing_dev_info: &default_backing_dev_info
		// (&(kmem_cache#4-oX (struct inode))->i_data)->writeback_index: 0
		//
		// (kmem_cache#4-oX (struct inode))->i_private: NULL
		// (kmem_cache#4-oX (struct inode))->i_mapping: &(kmem_cache#4-oX (struct inode))->i_data
		// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: NULL
		// (kmem_cache#4-oX (struct inode))->i_acl: (void *)(0xFFFFFFFF),
		// (kmem_cache#4-oX (struct inode))->i_default_acl: (void *)(0xFFFFFFFF)
		// (kmem_cache#4-oX (struct inode))->i_fsnotify_mask: 0
		//
		// [pcp0] nr_inodes: 3
		//
		// (kmem_cache#4-oX (struct inode))->i_state: 0
		// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
		// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list

		// inode: kmem_cache#4-oX (struct inode)
		if (inode) {
			// inode->i_ino: (kmem_cache#4-oX (struct inode))->i_ino, self_inum: 0xF0000001
			inode->i_ino = self_inum;
			// inode->i_ino: (kmem_cache#4-oX (struct inode))->i_ino: 0xF0000001

			// inode->i_mtime: (kmem_cache#4-oX (struct inode))->i_mtime,
			// inode->i_atime: (kmem_cache#4-oX (struct inode))->i_atime,
			// inode->i_ctime: (kmem_cache#4-oX (struct inode))->i_ctime, CURRENT_TIME: 현재시간값
			inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
			// inode->i_mtime: (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값,
			// inode->i_atime: (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값,
			// inode->i_ctime: (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값

			// inode->i_mode: (kmem_cache#4-oX (struct inode))->i_mode, S_IFLNK: 0120000, S_IRWXUGO: 00777
			inode->i_mode = S_IFLNK | S_IRWXUGO;
			// inode->i_mode: (kmem_cache#4-oX (struct inode))->i_mode: 0120777

			// inode->i_uid: (kmem_cache#4-oX (struct inode))->i_uid, GLOBAL_ROOT_UID: 0
			inode->i_uid = GLOBAL_ROOT_UID;
			// inode->i_uid: (kmem_cache#4-oX (struct inode))->i_uid: 0

			// inode->i_gid: (kmem_cache#4-oX (struct inode))->i_gid, GLOBAL_ROOT_GID: 0
			inode->i_gid = GLOBAL_ROOT_GID;
			// inode->i_gid: (kmem_cache#4-oX (struct inode))->i_gid: 0

			// inode->i_op: (kmem_cache#4-oX (struct inode))->i_op
			inode->i_op = &proc_self_inode_operations;
			// inode->i_op: (kmem_cache#4-oX (struct inode))->i_op: &proc_self_inode_operations

			// self: kmem_cache#5-oX (struct dentry), inode: kmem_cache#4-oX (struct inode)
			d_add(self, inode);

			// d_add 에서 한일:
			// (&(kmem_cache#5-oX (struct dentry))->d_alias)->next: NULL
			// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: &(kmem_cache#5-oX (struct dentry))->d_alias
			// (&(kmem_cache#5-oX (struct dentry))->d_alias)->pprev: &(&(kmem_cache#5-oX (struct dentry))->d_alias)
			//
			// (kmem_cache#5-oX (struct dentry))->d_inode: kmem_cache#4-oX (struct inode)
			//
			// 공유자원을 다른 cpu core가 사용할수 있게 함
			// (&(kmem_cache#5-oX (struct dentry))->d_seq)->sequence: 2
			//
			// (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100080
			//
			// (&(kmem_cache#5-oX (struct dentry))->d_hash)->next: NULL
			// (&(kmem_cache#5-oX (struct dentry))->d_hash)->pprev: &(hash 0xXXXXXXXX 에 맞는 list table 주소값)->first
			//
			// ((hash 0xXXXXXXXX 에 맞는 list table 주소값)->first): ((&(kmem_cache#5-oX (struct dentry))->d_hash) | 1)
		} else {
			dput(self);
			self = ERR_PTR(-ENOMEM);
		}
	} else {
		self = ERR_PTR(-ENOMEM);
	}

	// &root_inode->i_mutex: &(kmem_cache#4-oX (struct inode))->i_mutex
	mutex_unlock(&root_inode->i_mutex);

	// mutex_unlock 에서 한일:
	// &(kmem_cache#4-oX (struct inode))->i_mutex 을 사용하여 mutex unlock 수행

	// self: kmem_cache#5-oX (struct dentry), IS_ERR(kmem_cache#5-oX (struct dentry)): 0
	if (IS_ERR(self)) {
		pr_err("proc_fill_super: can't allocate /proc/self\n");
		return PTR_ERR(self);
	}

	// ns->proc_self: (&init_pid_ns)->proc_self, self: kmem_cache#5-oX (struct dentry)
	ns->proc_self = self;
	// ns->proc_self: (&init_pid_ns)->proc_self: kmem_cache#5-oX (struct dentry)

	return 0;
	// return 0
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
