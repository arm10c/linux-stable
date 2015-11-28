/*
 * fs/sysfs/symlink.c - operations for initializing and mounting sysfs
 *
 * Copyright (c) 2001-3 Patrick Mochel
 * Copyright (c) 2007 SUSE Linux Products GmbH
 * Copyright (c) 2007 Tejun Heo <teheo@suse.de>
 *
 * This file is released under the GPLv2.
 *
 * Please see Documentation/filesystems/sysfs.txt for more information.
 */

#define DEBUG

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>

#include "sysfs.h"


// ARM10C 20151031
static struct vfsmount *sysfs_mnt;
// ARM10C 20151031
struct kmem_cache *sysfs_dir_cachep;

// ARM10C 20151121
// ARM10C 20151128
static const struct super_operations sysfs_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
	.evict_inode	= sysfs_evict_inode,
};

// ARM10C 20151121
struct sysfs_dirent sysfs_root = {
	.s_name		= "",
	.s_count	= ATOMIC_INIT(1),
	.s_flags	= SYSFS_DIR | (KOBJ_NS_TYPE_NONE << SYSFS_NS_TYPE_SHIFT),
	.s_mode		= S_IFDIR | S_IRUGO | S_IXUGO,
	.s_ino		= 1,
};

// ARM10C 20151121
// sb: kmem_cache#25-oX (struct super_block), data: NULL, 0
static int sysfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *inode;
	struct dentry *root;

	// sb->s_blocksize: (kmem_cache#25-oX (struct super_block))->s_blocksize, PAGE_CACHE_SIZE: 0x1000
	sb->s_blocksize = PAGE_CACHE_SIZE;
	// sb->s_blocksize: (kmem_cache#25-oX (struct super_block))->s_blocksize: 0x1000

	// sb->s_blocksize_bits: (kmem_cache#25-oX (struct super_block))->s_blocksize_bits, PAGE_CACHE_SHIFT: 12
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	// sb->s_blocksize_bits: (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 12

	// sb->s_magic: (kmem_cache#25-oX (struct super_block))->s_magic, SYSFS_MAGIC: 0x62656572
	sb->s_magic = SYSFS_MAGIC;
	// sb->s_magic: (kmem_cache#25-oX (struct super_block))->s_magic: 0x62656572

	// sb->s_op: (kmem_cache#25-oX (struct super_block))->s_op
	sb->s_op = &sysfs_ops;
	// sb->s_op: (kmem_cache#25-oX (struct super_block))->s_op: &sysfs_ops

	// sb->s_time_gran: (kmem_cache#25-oX (struct super_block))->s_time_gran
	sb->s_time_gran = 1;
	// sb->s_time_gran: (kmem_cache#25-oX (struct super_block))->s_time_gran: 1

	/* get root inode, initialize and unlock it */
	mutex_lock(&sysfs_mutex);

	// mutex_lock에서 한일:
	// &sysfs_mutex을 사용하여 mutex lock을 수행함

	// sb: kmem_cache#25-oX (struct super_block),
	inode = sysfs_get_inode(sb, &sysfs_root);
	mutex_unlock(&sysfs_mutex);
	if (!inode) {
		pr_debug("sysfs: could not get root inode\n");
		return -ENOMEM;
	}

	/* instantiate and link root dentry */
	root = d_make_root(inode);
	if (!root) {
		pr_debug("%s: could not get root dentry!\n", __func__);
		return -ENOMEM;
	}
	root->d_fsdata = &sysfs_root;
	sb->s_root = root;
	sb->s_d_op = &sysfs_dentry_ops;
	return 0;
}

// ARM10C 20151114
static int sysfs_test_super(struct super_block *sb, void *data)
{
	struct sysfs_super_info *sb_info = sysfs_info(sb);
	struct sysfs_super_info *info = data;
	enum kobj_ns_type type;
	int found = 1;

	for (type = KOBJ_NS_TYPE_NONE; type < KOBJ_NS_TYPES; type++) {
		if (sb_info->ns[type] != info->ns[type])
			found = 0;
	}
	return found;
}

// ARM10C 20151114
// s: kmem_cache#25-oX (struct super_block), data: kmem_cache#30-oX (struct sysfs_super_info)
static int sysfs_set_super(struct super_block *sb, void *data)
{
	int error;

	// sb: kmem_cache#25-oX (struct super_block), data: kmem_cache#30-oX (struct sysfs_super_info)
	// set_anon_super(kmem_cache#25-oX (struct super_block), kmem_cache#30-oX (struct sysfs_super_info)): 0
	error = set_anon_super(sb, data);
	// error: 0

	// set_anon_super에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	// (kmem_cache#21-o0...7)->ary[0]: NULL
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-o7
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: NULL
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 6
	// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-o7 (struct idr_layer)
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// (&unnamed_dev_ida)->free_bitmap: NULL
	//
	// (kmem_cache#21-o7 (struct idr_layer))->ary[0]: NULL
	// (kmem_cache#21-o7 (struct idr_layer))->layer: 0
	// (kmem_cache#21-o7 (struct idr_layer))->ary[0]: kmem_cache#27-oX (struct ida_bitmap)
	// (kmem_cache#21-o7 (struct idr_layer))->count: 1
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행
	//
	// unnamed_dev_start: 1
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 0
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info

	// error: 0
	if (!error)
		// s->s_fs_info: (kmem_cache#25-oX (struct super_block))->s_fs_info, data: kmem_cache#30-oX (struct sysfs_super_info)
		sb->s_fs_info = data;
		// s->s_fs_info: (kmem_cache#25-oX (struct super_block))->s_fs_info: kmem_cache#30-oX (struct sysfs_super_info)

	// error: 0
	return error;
	// return 0
}

static void free_sysfs_super_info(struct sysfs_super_info *info)
{
	int type;
	for (type = KOBJ_NS_TYPE_NONE; type < KOBJ_NS_TYPES; type++)
		kobj_ns_drop(type, info->ns[type]);
	kfree(info);
}

// ARM10C 20151114
// type: &sysfs_fs_type, flags: 0x400000, name: "sysfs", data: NULL
static struct dentry *sysfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	struct sysfs_super_info *info;
	enum kobj_ns_type type;
	struct super_block *sb;
	int error;

	// flags: 0x400000, MS_KERNMOUNT: 0x400000
	if (!(flags & MS_KERNMOUNT)) {
		if (!capable(CAP_SYS_ADMIN) && !fs_fully_visible(fs_type))
			return ERR_PTR(-EPERM);

		for (type = KOBJ_NS_TYPE_NONE; type < KOBJ_NS_TYPES; type++) {
			if (!kobj_ns_current_may_mount(type))
				return ERR_PTR(-EPERM);
		}
	}

	// sizeof(struct sysfs_super_info): 8 bytes, GFP_KERNEL: 0xD0
	// kzalloc(8, GFP_KERNEL: 0xD0): kmem_cache#30-oX
	info = kzalloc(sizeof(*info), GFP_KERNEL);
	// info: kmem_cache#30-oX (struct sysfs_super_info)

	// info: kmem_cache#30-oX (struct sysfs_super_info)
	if (!info)
		return ERR_PTR(-ENOMEM);

	// KOBJ_NS_TYPE_NONE: 0, KOBJ_NS_TYPES: 2
	for (type = KOBJ_NS_TYPE_NONE; type < KOBJ_NS_TYPES; type++)
		// type: 0, info->ns[0]: (kmem_cache#30-oX (struct sysfs_super_info))->ns[0],
		// kobj_ns_grab_current(0): NULL
		info->ns[type] = kobj_ns_grab_current(type);
		// info->ns[0]: (kmem_cache#30-oX (struct sysfs_super_info))->ns[0]: NULL

	// fs_type: &sysfs_fs_type, flags: 0x400000, info: kmem_cache#30-oX (struct sysfs_super_info)
	// sget(&sysfs_fs_type, sysfs_test_super, sysfs_set_super, 0x400000, kmem_cache#30-oX (struct sysfs_super_info)): kmem_cache#25-oX (struct super_block)
	sb = sget(fs_type, sysfs_test_super, sysfs_set_super, flags, info);
	// sb: kmem_cache#25-oX (struct super_block)

	// sget에서 한일:
	// struct super_block 만큼의 메모리를 할당 받음 kmem_cache#25-oX (struct super_block)
	//
	// (&(&(&(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->list)->next: &(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->list
	// (&(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->list)->prev: &(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->list
	// (&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->count: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&(kmem_cache#25-oX (struct super_block))->s_writers.counter[0...2])->list를 연결함
	//
	// &(&(kmem_cache#25-oX (struct super_block))->s_writers.wait)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#25-oX (struct super_block))->s_writers.wait)->task_list를 사용한 list 초기화
	// &(&(kmem_cache#25-oX (struct super_block))->s_writers.wait_unfrozen)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#25-oX (struct super_block))->s_writers.wait_unfrozen)->task_list를 사용한 list 초기화
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->next: NULL
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->pprev: NULL
	// (&(kmem_cache#25-oX (struct super_block))->s_anon)->first: NULL
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_inodes)->next: &(kmem_cache#25-oX (struct super_block))->s_inodes
	// (&(kmem_cache#25-oX (struct super_block))->s_inodes)->prev: &(kmem_cache#25-oX (struct super_block))->s_inodes
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node: kmem_cache#30-oX
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->active_nodes)->bits[0]: 0
	// ((&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].lock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].lock)->magic: 0xdead4ead
	// ((&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].lock)->owner: 0xffffffff
	// ((&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].lock)->owner_cpu: 0xffffffff
	// ((&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].list)->next: (&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].list
	// ((&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].list)->prev: (&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].list
	// (&(kmem_cache#25-oX (struct super_block))->s_dentry_lru)->node[0].nr_items: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node: kmem_cache#30-oX
	// (&(&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->active_nodes)->bits[0]: 0
	// ((&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].lock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].lock)->magic: 0xdead4ead
	// ((&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].lock)->owner: 0xffffffff
	// ((&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].lock)->owner_cpu: 0xffffffff
	// ((&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].list)->next: (&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].list
	// ((&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].list)->prev: (&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].list
	// (&(kmem_cache#25-oX (struct super_block))->s_inode_lru)->node[0].nr_items: 0
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_mounts)->next: &(kmem_cache#25-oX (struct super_block))->s_mounts
	// (&(kmem_cache#25-oX (struct super_block))->s_mounts)->prev: &(kmem_cache#25-oX (struct super_block))->s_mounts
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0
	// &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_lock을 사용한 spinlock 초기화
	// (&(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list)->next: &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list
	// (&(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list)->prev: &(&(kmem_cache#25-oX (struct super_block))->s_umount)->wait_list
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: -1
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->count: 1
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_list)->next: &(&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_list
	// (&(&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_list)->prev: &(&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->wait_list
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->onwer: NULL
	// (&(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex)->magic: &(kmem_cache#25-oX (struct super_block))->s_vfs_rename_mutex
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->count: 1
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_list)->next: &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_list
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_list)->prev: &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->wait_list
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->onwer: NULL
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex)->magic: &(kmem_cache#25-oX (struct super_block))->s_dquot.dqio_mutex
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->count: 1
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_list)->next: &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_list
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_list)->prev: &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->wait_list
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->onwer: NULL
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex)->magic: &(kmem_cache#25-oX (struct super_block))->s_dquot.dqonoff_mutex
	// (&(kmem_cache#25-oX (struct super_block))->s_dquot.dqptr_sem)->activity: 0
	// &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqptr_sem)->wait_lock을 사용한 spinlock 초기화
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqptr_sem)->wait_list)->next: &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqptr_sem)->wait_list
	// (&(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqptr_sem)->wait_list)->prev: &(&(kmem_cache#25-oX (struct super_block))->s_dquot.dqptr_sem)->wait_list
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x400000
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &default_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_count: 1
	// ((kmem_cache#25-oX (struct super_block))->s_active)->counter: 1
	// (kmem_cache#25-oX (struct super_block))->s_maxbytes: 0x7fffffff
	// (kmem_cache#25-oX (struct super_block))->s_op: &default_op
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1000000000
	// (kmem_cache#25-oX (struct super_block))->cleancache_poolid: -1
	// (kmem_cache#25-oX (struct super_block))->s_shrink.seeks: 2
	// (kmem_cache#25-oX (struct super_block))->s_shrink.scan_objects: super_cache_scan
	// (kmem_cache#25-oX (struct super_block))->s_shrink.count_objects: super_cache_count
	// (kmem_cache#25-oX (struct super_block))->s_shrink.batch: 1024
	// (kmem_cache#25-oX (struct super_block))->s_shrink.flags: 1
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	// (kmem_cache#21-o0...7)->ary[0]: NULL
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-o7
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: NULL
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 6
	// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-o7 (struct idr_layer)
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// (&unnamed_dev_ida)->free_bitmap: NULL
	//
	// (kmem_cache#21-o7 (struct idr_layer))->ary[0]: NULL
	// (kmem_cache#21-o7 (struct idr_layer))->layer: 0
	// (kmem_cache#21-o7 (struct idr_layer))->ary[0]: kmem_cache#27-oX (struct ida_bitmap)
	// (kmem_cache#21-o7 (struct idr_layer))->count: 1
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행
	//
	// unnamed_dev_start: 1
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 0
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_fs_info: kmem_cache#30-oX (struct sysfs_super_info)
	//
	// (kmem_cache#25-oX (struct super_block))->s_type: &sysfs_fs_type
	// (kmem_cache#25-oX (struct super_block))->s_id: "sysfs"
	//
	// list head인 &super_blocks 에 (kmem_cache#25-oX (struct super_block))->s_list을 tail에 추가
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->next: NULL
	// (&(&sysfs_fs_type)->fs_supers)->first: &(kmem_cache#25-oX (struct super_block))->s_instances
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->pprev: &(&(&sysfs_fs_type)->fs_supers)->first
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->flags: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->nr_deferred: kmem_cache#30-oX
	// head list인 &shrinker_list에 &(&(kmem_cache#25-oX (struct super_block))->s_shrink)->list를 tail로 추가함

	// sb: kmem_cache#25-oX (struct super_block)
	// IS_ERR(kmem_cache#25-oX (struct super_block)): 0,
	// sb->s_fs_info: (kmem_cache#25-oX (struct super_block))->s_fs_info: kmem_cache#30-oX (struct sysfs_super_info),
	// info: kmem_cache#30-oX (struct sysfs_super_info)
	if (IS_ERR(sb) || sb->s_fs_info != info)
		free_sysfs_super_info(info);

	// sb: kmem_cache#25-oX (struct super_block)
	// IS_ERR(kmem_cache#25-oX (struct super_block)): 0,
	if (IS_ERR(sb))
		return ERR_CAST(sb);

	// sb->s_root: (kmem_cache#25-oX (struct super_block))->s_root: NULL
	if (!sb->s_root) {
		// sb: kmem_cache#25-oX (struct super_block), data: NULL, flags: 0x400000, MS_SILENT: 0x8000
		error = sysfs_fill_super(sb, data, flags & MS_SILENT ? 1 : 0);
		if (error) {
			deactivate_locked_super(sb);
			return ERR_PTR(error);
		}
		sb->s_flags |= MS_ACTIVE;
	}

	return dget(sb->s_root);
}

static void sysfs_kill_sb(struct super_block *sb)
{
	struct sysfs_super_info *info = sysfs_info(sb);
	/* Remove the superblock from fs_supers/s_instances
	 * so we can't find it, before freeing sysfs_super_info.
	 */
	kill_anon_super(sb);
	free_sysfs_super_info(info);
}

// ARM10C 20151031
// ARM10C 20151114
static struct file_system_type sysfs_fs_type = {
	.name		= "sysfs",
	.mount		= sysfs_mount,
	.kill_sb	= sysfs_kill_sb,
	.fs_flags	= FS_USERNS_MOUNT,
};

// ARM10C 20151031
int __init sysfs_init(void)
{
	// ENOMEM: 12
	int err = -ENOMEM;
	// err: -12

	// sizeof(struct sysfs_dirent): 64 bytes
	// kmem_cache_create("sysfs_dir_cache", 64, 0, 0, NULL): kmem_cache#1
	sysfs_dir_cachep = kmem_cache_create("sysfs_dir_cache",
					      sizeof(struct sysfs_dirent),
					      0, 0, NULL);
	// sysfs_dir_cachep: kmem_cache#1

	// sysfs_dir_cachep: kmem_cache#1
	if (!sysfs_dir_cachep)
		goto out;

	// sysfs_inode_init(): 0
	err = sysfs_inode_init();
	// err: 0

	// sysfs_inode_init에서 한일:
	// (&sysfs_backing_dev_info)->dev: NULL
	// (&sysfs_backing_dev_info)->min_ratio: 0
	// (&sysfs_backing_dev_info)->max_ratio: 100
	// (&sysfs_backing_dev_info)->max_prop_frac: 0x400
	// &(&sysfs_backing_dev_info)->wb_lock 을 이용한 spinlock 초기화 수행
	// (&(&sysfs_backing_dev_info)->bdi_list)->next: &(&sysfs_backing_dev_info)->bdi_list
	// (&(&sysfs_backing_dev_info)->bdi_list)->prev: &(&sysfs_backing_dev_info)->bdi_list
	// (&(&sysfs_backing_dev_info)->work_list)->next: &(&sysfs_backing_dev_info)->work_list
	// (&(&sysfs_backing_dev_info)->work_list)->prev: &(&sysfs_backing_dev_info)->work_list
	//
	// (&sysfs_backing_dev_info)->wb 의 맴버값을 0으로 초기화함
	// (&(&sysfs_backing_dev_info)->wb)->bdi: &sysfs_backing_dev_info
	// (&(&sysfs_backing_dev_info)->wb)->last_old_flush: XXX
	// (&(&(&sysfs_backing_dev_info)->wb)->b_dirty)->next: &(&(&sysfs_backing_dev_info)->wb)->b_dirty
	// (&(&(&sysfs_backing_dev_info)->wb)->b_dirty)->prev: &(&(&sysfs_backing_dev_info)->wb)->b_dirty
	// (&(&(&sysfs_backing_dev_info)->wb)->b_io)->next: &(&(&sysfs_backing_dev_info)->wb)->b_io
	// (&(&(&sysfs_backing_dev_info)->wb)->b_io)->prev: &(&(&sysfs_backing_dev_info)->wb)->b_io
	// (&(&(&sysfs_backing_dev_info)->wb)->b_more_io)->next: &(&(&sysfs_backing_dev_info)->wb)->b_more_io
	// (&(&(&sysfs_backing_dev_info)->wb)->b_more_io)->prev: &(&(&sysfs_backing_dev_info)->wb)->b_more_io
	// &(&(&sysfs_backing_dev_info)->wb)->list_lock 을 이용한 spinlock 초기화 수행
	// (&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->work)->data: { 0xFFFFFFE0 }
	// (&(&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->work)->entry)->next: &(&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->work)->entry
	// (&(&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->work)->entry)->prev: &(&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->work)->entry
	// (&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->work)->func: bdi_writeback_workfn
	// (&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->timer)->entry.next: NULL
	// (&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->timer)->base: [pcp0] tvec_bases | 0x2
	// (&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->timer)->slack: -1
	// (&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->timer)->function = (delayed_work_timer_fn);
	// (&(&(&(&sysfs_backing_dev_info)->wb)->dwork)->timer)->data = ((unsigned long)(&(&(&sysfs_backing_dev_info)->wb)->dwork));
	//
	// (&(&(&(&(&sysfs_backing_dev_info)->bdi_stat[0...3])->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&(&sysfs_backing_dev_info)->bdi_stat[0...3])->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&(&sysfs_backing_dev_info)->bdi_stat[0...3])->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&(&sysfs_backing_dev_info)->bdi_stat[0...3])->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(&sysfs_backing_dev_info)->bdi_stat[0...3])->list)->next: &(&(&sysfs_backing_dev_info)->bdi_stat[0...3])->list
	// (&(&(&sysfs_backing_dev_info)->bdi_stat[0...3])->list)->prev: &(&(&sysfs_backing_dev_info)->bdi_stat[0...3])->list
	// (&(&sysfs_backing_dev_info)->bdi_stat[0...3])->count: 0
	// (&(&sysfs_backing_dev_info)->bdi_stat[0...3])->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&(&sysfs_backing_dev_info)->bdi_stat[0...3])->list를 연결함
	//
	// (&sysfs_backing_dev_info)->dirty_exceeded: 0
	// (&sysfs_backing_dev_info)->bw_time_stamp: XXX
	// (&sysfs_backing_dev_info)->written_stamp: 0
	// (&sysfs_backing_dev_info)->balanced_dirty_ratelimit: 0x6400
	// (&sysfs_backing_dev_info)->dirty_ratelimit: 0x6400
	// (&sysfs_backing_dev_info)->write_bandwidth: 0x6400
	// (&sysfs_backing_dev_info)->avg_write_bandwidth: 0x6400
	//
	// (&(&(&(&(&(&sysfs_backing_dev_info)->completions)->events)->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&(&(&sysfs_backing_dev_info)->completions)->events)->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&(&(&sysfs_backing_dev_info)->completions)->events)->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&(&(&sysfs_backing_dev_info)->completions)->events)->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(&(&sysfs_backing_dev_info)->completions)->events)->list)->next: &(&(&(&sysfs_backing_dev_info)->completions)->events)->list
	// (&(&(&(&sysfs_backing_dev_info)->completions)->events)->list)->prev: &(&(&(&sysfs_backing_dev_info)->completions)->events)->list
	// (&(&(&sysfs_backing_dev_info)->completions)->events)->count: 0
	// (&(&(&sysfs_backing_dev_info)->completions)->events)->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&(&(&sysfs_backing_dev_info)->completions)->events)->list를 연결함
	// (&(&sysfs_backing_dev_info)->completions)->period: 0
	// &(&(&sysfs_backing_dev_info)->completions)->lock을 이용한 spinlock 초기화 수행

	// err: 0
	if (err)
		goto out_err;

	// register_filesystem(&sysfs_fs_type): 0
	err = register_filesystem(&sysfs_fs_type);
	// err: 0

	// register_filesystem에서 한일:
	// file_systems: &sysfs_fs_type

	// err: 0
	if (!err) {
		sysfs_mnt = kern_mount(&sysfs_fs_type);
		if (IS_ERR(sysfs_mnt)) {
			printk(KERN_ERR "sysfs: could not mount!\n");
			err = PTR_ERR(sysfs_mnt);
			sysfs_mnt = NULL;
			unregister_filesystem(&sysfs_fs_type);
			goto out_err;
		}
	} else
		goto out_err;
out:
	return err;
out_err:
	kmem_cache_destroy(sysfs_dir_cachep);
	sysfs_dir_cachep = NULL;
	goto out;
}

#undef sysfs_get
struct sysfs_dirent *sysfs_get(struct sysfs_dirent *sd)
{
	return __sysfs_get(sd);
}
EXPORT_SYMBOL_GPL(sysfs_get);

#undef sysfs_put
void sysfs_put(struct sysfs_dirent *sd)
{
	__sysfs_put(sd);
}
EXPORT_SYMBOL_GPL(sysfs_put);
