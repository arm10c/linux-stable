/*
 *  inode.c - securityfs
 *
 *  Copyright (C) 2005 Greg Kroah-Hartman <gregkh@suse.de>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License version
 *	2 as published by the Free Software Foundation.
 *
 *  Based on fs/debugfs/inode.c which had the following copyright notice:
 *    Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
 *    Copyright (C) 2004 IBM Inc.
 */

/* #define DEBUG */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/magic.h>

static struct vfsmount *mount;
static int mount_count;

static inline int positive(struct dentry *dentry)
{
	return dentry->d_inode && !d_unhashed(dentry);
}

// ARM10C 20160319
// s: kmem_cache#25-oX (struct super_block), data: NULL, 0
static int fill_super(struct super_block *sb, void *data, int silent)
{
	static struct tree_descr files[] = {{""}};
	// files[0].name: "", files[0].ops: NULL, files[0].mode: 0

	// sb: kmem_cache#25-oX (struct super_block), SECURITYFS_MAGIC: 0x73636673
	// simple_fill_super(kmem_cache#25-oX (struct super_block), 0x73636673, files): 0
	return simple_fill_super(sb, SECURITYFS_MAGIC, files);
	// return 0

	// simple_fill_super 에서 한일:
	// (kmem_cache#25-oX (struct super_block))->s_blocksize: 0x1000
	// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 12
	// (kmem_cache#25-oX (struct super_block))->s_magic: 0x73636673
	// (kmem_cache#25-oX (struct super_block))->s_op: &simple_super_operations
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1
	//
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
	// [pcp0] nr_inodes: 1
	//
	// (kmem_cache#4-oX (struct inode))->i_state: 0
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
	//
	// head list인 &(kmem_cache#4-oX (struct inode))->i_sb->s_inodes에 &(kmem_cache#4-oX (struct inode))->i_sb_list를 추가함
	//
	// (kmem_cache#4-oX (struct inode)))->i_ino: 1
	// (kmem_cache#4-oX (struct inode)))->i_mode: 0x41ed
	// (kmem_cache#4-oX (struct inode)))->i_atime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode)))->i_mtime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode)))->i_ctime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode)))->i_op: &simple_dir_inode_operations
	// (kmem_cache#4-oX (struct inode)))->i_fop: &simple_dir_operations
	//
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
	//
	// dentry_cache인 kmem_cache#5을 사용하여 dentry로 사용할 메모리 kmem_cache#5-oX (struct dentry)을 할당받음
	//
	// (kmem_cache#5-oX (struct dentry))->d_iname[35]: 0
	// (kmem_cache#5-oX (struct dentry))->d_name.len: 1
	// (kmem_cache#5-oX (struct dentry))->d_name.hash: (&name)->hash: 0
	// (kmem_cache#5-oX (struct dentry))->d_iname: "/"
	//
	// 공유자원을 다른 cpu core가 사용할수 있게 함
	//
	// (kmem_cache#5-oX (struct dentry))->d_name.name: "/"
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
	// [pcp0] nr_dentry: 1
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->next: NULL
	// (&(kmem_cache#4-oX)->i_dentry)->first: &(kmem_cache#5-oX (struct dentry))->d_alias
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->pprev: &(&(kmem_cache#5-oX (struct dentry))->d_alias)
	//
	// (kmem_cache#5-oX (struct dentry))->d_inode: kmem_cache#4-oX
	//
	// 공유자원을 다른 cpu core가 사용할수 있게 함
	// (&(kmem_cache#5-oX (struct dentry))->d_seq)->sequence: 2
	//
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100000
	//
	// (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
}

static struct dentry *get_sb(struct file_system_type *fs_type,
		  int flags, const char *dev_name,
		  void *data)
{
	return mount_single(fs_type, flags, data, fill_super);
}

static struct file_system_type fs_type = {
	.owner =	THIS_MODULE,
	.name =		"securityfs",
	.mount =	get_sb,
	.kill_sb =	kill_litter_super,
};

/**
 * securityfs_create_file - create a file in the securityfs filesystem
 *
 * @name: a pointer to a string containing the name of the file to create.
 * @mode: the permission that the file should have
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this parameter is %NULL, then the
 *          file will be created in the root of the securityfs filesystem.
 * @data: a pointer to something that the caller will want to get to later
 *        on.  The inode.i_private pointer will point to this value on
 *        the open() call.
 * @fops: a pointer to a struct file_operations that should be used for
 *        this file.
 *
 * This is the basic "create a file" function for securityfs.  It allows for a
 * wide range of flexibility in creating a file, or a directory (if you
 * want to create a directory, the securityfs_create_dir() function is
 * recommended to be used instead).
 *
 * This function returns a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the securityfs_remove() function when the file is
 * to be removed (no automatic cleanup happens if your module is unloaded,
 * you are responsible here).  If an error occurs, the function will return
 * the erorr value (via ERR_PTR).
 *
 * If securityfs is not enabled in the kernel, the value %-ENODEV is
 * returned.
 */
struct dentry *securityfs_create_file(const char *name, umode_t mode,
				   struct dentry *parent, void *data,
				   const struct file_operations *fops)
{
	struct dentry *dentry;
	int is_dir = S_ISDIR(mode);
	struct inode *dir, *inode;
	int error;

	if (!is_dir) {
		BUG_ON(!fops);
		mode = (mode & S_IALLUGO) | S_IFREG;
	}

	pr_debug("securityfs: creating file '%s'\n",name);

	error = simple_pin_fs(&fs_type, &mount, &mount_count);
	if (error)
		return ERR_PTR(error);

	if (!parent)
		parent = mount->mnt_root;

	dir = parent->d_inode;

	mutex_lock(&dir->i_mutex);
	dentry = lookup_one_len(name, parent, strlen(name));
	if (IS_ERR(dentry))
		goto out;

	if (dentry->d_inode) {
		error = -EEXIST;
		goto out1;
	}

	inode = new_inode(dir->i_sb);
	if (!inode) {
		error = -ENOMEM;
		goto out1;
	}

	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	inode->i_private = data;
	if (is_dir) {
		inode->i_op = &simple_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
		inc_nlink(inode);
		inc_nlink(dir);
	} else {
		inode->i_fop = fops;
	}
	d_instantiate(dentry, inode);
	dget(dentry);
	mutex_unlock(&dir->i_mutex);
	return dentry;

out1:
	dput(dentry);
	dentry = ERR_PTR(error);
out:
	mutex_unlock(&dir->i_mutex);
	simple_release_fs(&mount, &mount_count);
	return dentry;
}
EXPORT_SYMBOL_GPL(securityfs_create_file);

/**
 * securityfs_create_dir - create a directory in the securityfs filesystem
 *
 * @name: a pointer to a string containing the name of the directory to
 *        create.
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this parameter is %NULL, then the
 *          directory will be created in the root of the securityfs filesystem.
 *
 * This function creates a directory in securityfs with the given @name.
 *
 * This function returns a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the securityfs_remove() function when the file is
 * to be removed (no automatic cleanup happens if your module is unloaded,
 * you are responsible here).  If an error occurs, %NULL will be returned.
 *
 * If securityfs is not enabled in the kernel, the value %-ENODEV is
 * returned.  It is not wise to check for this value, but rather, check for
 * %NULL or !%NULL instead as to eliminate the need for #ifdef in the calling
 * code.
 */
struct dentry *securityfs_create_dir(const char *name, struct dentry *parent)
{
	return securityfs_create_file(name,
				      S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO,
				      parent, NULL, NULL);
}
EXPORT_SYMBOL_GPL(securityfs_create_dir);

/**
 * securityfs_remove - removes a file or directory from the securityfs filesystem
 *
 * @dentry: a pointer to a the dentry of the file or directory to be removed.
 *
 * This function removes a file or directory in securityfs that was previously
 * created with a call to another securityfs function (like
 * securityfs_create_file() or variants thereof.)
 *
 * This function is required to be called in order for the file to be
 * removed. No automatic cleanup of files will happen when a module is
 * removed; you are responsible here.
 */
void securityfs_remove(struct dentry *dentry)
{
	struct dentry *parent;

	if (!dentry || IS_ERR(dentry))
		return;

	parent = dentry->d_parent;
	if (!parent || !parent->d_inode)
		return;

	mutex_lock(&parent->d_inode->i_mutex);
	if (positive(dentry)) {
		if (dentry->d_inode) {
			if (S_ISDIR(dentry->d_inode->i_mode))
				simple_rmdir(parent->d_inode, dentry);
			else
				simple_unlink(parent->d_inode, dentry);
			dput(dentry);
		}
	}
	mutex_unlock(&parent->d_inode->i_mutex);
	simple_release_fs(&mount, &mount_count);
}
EXPORT_SYMBOL_GPL(securityfs_remove);

static struct kobject *security_kobj;

static int __init securityfs_init(void)
{
	int retval;

	security_kobj = kobject_create_and_add("security", kernel_kobj);
	if (!security_kobj)
		return -EINVAL;

	retval = register_filesystem(&fs_type);
	if (retval)
		kobject_put(security_kobj);
	return retval;
}

core_initcall(securityfs_init);
MODULE_LICENSE("GPL");

