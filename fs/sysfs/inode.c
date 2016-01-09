/*
 * fs/sysfs/inode.c - basic sysfs inode and dentry operations
 *
 * Copyright (c) 2001-3 Patrick Mochel
 * Copyright (c) 2007 SUSE Linux Products GmbH
 * Copyright (c) 2007 Tejun Heo <teheo@suse.de>
 *
 * This file is released under the GPLv2.
 *
 * Please see Documentation/filesystems/sysfs.txt for more information.
 */

#undef DEBUG

#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include "sysfs.h"

// ARM10C 20151205
static const struct address_space_operations sysfs_aops = {
	.readpage	= simple_readpage,
	.write_begin	= simple_write_begin,
	.write_end	= simple_write_end,
};

// ARM10C 20151031
// ARM10C 20151205
static struct backing_dev_info sysfs_backing_dev_info = {
	.name		= "sysfs",
	.ra_pages	= 0,	/* No readahead */
	.capabilities	= BDI_CAP_NO_ACCT_AND_WRITEBACK,
};

// ARM10C 20151205
static const struct inode_operations sysfs_inode_operations = {
	.permission	= sysfs_permission,
	.setattr	= sysfs_setattr,
	.getattr	= sysfs_getattr,
	.setxattr	= sysfs_setxattr,
};

// ARM10C 20151031
int __init sysfs_inode_init(void)
{
	// bdi_init(&sysfs_backing_dev_info): 0
	return bdi_init(&sysfs_backing_dev_info);
	// return 0

	// bdi_init에서 한일:
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
}

static struct sysfs_inode_attrs *sysfs_init_inode_attrs(struct sysfs_dirent *sd)
{
	struct sysfs_inode_attrs *attrs;
	struct iattr *iattrs;

	attrs = kzalloc(sizeof(struct sysfs_inode_attrs), GFP_KERNEL);
	if (!attrs)
		return NULL;
	iattrs = &attrs->ia_iattr;

	/* assign default attributes */
	iattrs->ia_mode = sd->s_mode;
	iattrs->ia_uid = GLOBAL_ROOT_UID;
	iattrs->ia_gid = GLOBAL_ROOT_GID;
	iattrs->ia_atime = iattrs->ia_mtime = iattrs->ia_ctime = CURRENT_TIME;

	return attrs;
}

int sysfs_sd_setattr(struct sysfs_dirent *sd, struct iattr *iattr)
{
	struct sysfs_inode_attrs *sd_attrs;
	struct iattr *iattrs;
	unsigned int ia_valid = iattr->ia_valid;

	sd_attrs = sd->s_iattr;

	if (!sd_attrs) {
		/* setting attributes for the first time, allocate now */
		sd_attrs = sysfs_init_inode_attrs(sd);
		if (!sd_attrs)
			return -ENOMEM;
		sd->s_iattr = sd_attrs;
	}
	/* attributes were changed at least once in past */
	iattrs = &sd_attrs->ia_iattr;

	if (ia_valid & ATTR_UID)
		iattrs->ia_uid = iattr->ia_uid;
	if (ia_valid & ATTR_GID)
		iattrs->ia_gid = iattr->ia_gid;
	if (ia_valid & ATTR_ATIME)
		iattrs->ia_atime = iattr->ia_atime;
	if (ia_valid & ATTR_MTIME)
		iattrs->ia_mtime = iattr->ia_mtime;
	if (ia_valid & ATTR_CTIME)
		iattrs->ia_ctime = iattr->ia_ctime;
	if (ia_valid & ATTR_MODE) {
		umode_t mode = iattr->ia_mode;
		iattrs->ia_mode = sd->s_mode = mode;
	}
	return 0;
}

int sysfs_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	struct sysfs_dirent *sd = dentry->d_fsdata;
	int error;

	if (!sd)
		return -EINVAL;

	mutex_lock(&sysfs_mutex);
	error = inode_change_ok(inode, iattr);
	if (error)
		goto out;

	error = sysfs_sd_setattr(sd, iattr);
	if (error)
		goto out;

	/* this ignores size changes */
	setattr_copy(inode, iattr);

out:
	mutex_unlock(&sysfs_mutex);
	return error;
}

static int sysfs_sd_setsecdata(struct sysfs_dirent *sd, void **secdata,
			       u32 *secdata_len)
{
	struct sysfs_inode_attrs *iattrs;
	void *old_secdata;
	size_t old_secdata_len;

	if (!sd->s_iattr) {
		sd->s_iattr = sysfs_init_inode_attrs(sd);
		if (!sd->s_iattr)
			return -ENOMEM;
	}

	iattrs = sd->s_iattr;
	old_secdata = iattrs->ia_secdata;
	old_secdata_len = iattrs->ia_secdata_len;

	iattrs->ia_secdata = *secdata;
	iattrs->ia_secdata_len = *secdata_len;

	*secdata = old_secdata;
	*secdata_len = old_secdata_len;
	return 0;
}

int sysfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	struct sysfs_dirent *sd = dentry->d_fsdata;
	void *secdata;
	int error;
	u32 secdata_len = 0;

	if (!sd)
		return -EINVAL;

	if (!strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN)) {
		const char *suffix = name + XATTR_SECURITY_PREFIX_LEN;
		error = security_inode_setsecurity(dentry->d_inode, suffix,
						value, size, flags);
		if (error)
			goto out;
		error = security_inode_getsecctx(dentry->d_inode,
						&secdata, &secdata_len);
		if (error)
			goto out;

		mutex_lock(&sysfs_mutex);
		error = sysfs_sd_setsecdata(sd, &secdata, &secdata_len);
		mutex_unlock(&sysfs_mutex);

		if (secdata)
			security_release_secctx(secdata, secdata_len);
	} else
		return -EINVAL;
out:
	return error;
}

// ARM10C 20151205
// inode: kmem_cache#4-oX (struct inode), sd->s_mode: (&sysfs_root)->s_mode
static inline void set_default_inode_attr(struct inode *inode, umode_t mode)
{
	// inode->i_mode: (kmem_cache#4-oX (struct inode))->i_mode, mode: (&sysfs_root)->s_mode: 40447
	inode->i_mode = mode;
	// inode->i_mode: (kmem_cache#4-oX (struct inode))->i_mode: 40447

	// inode->i_atime: (kmem_cache#4-oX (struct inode))->i_atime,
	// inode->i_mtime: (kmem_cache#4-oX (struct inode))->i_mtime,
	// inode->i_ctime: (kmem_cache#4-oX (struct inode))->i_ctime, CURRENT_TIME: 현재시간값
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	// inode->i_atime: (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값,
	// inode->i_mtime: (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값,
	// inode->i_ctime: (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값
}

static inline void set_inode_attr(struct inode *inode, struct iattr *iattr)
{
	inode->i_uid = iattr->ia_uid;
	inode->i_gid = iattr->ia_gid;
	inode->i_atime = iattr->ia_atime;
	inode->i_mtime = iattr->ia_mtime;
	inode->i_ctime = iattr->ia_ctime;
}

// ARM10C 20151205
// sd: &sysfs_root, inode: kmem_cache#4-oX (struct inode)
static void sysfs_refresh_inode(struct sysfs_dirent *sd, struct inode *inode)
{
	// sd->s_iattr: (&sysfs_root)->s_iattr
	struct sysfs_inode_attrs *iattrs = sd->s_iattr;
	// iattrs: (&sysfs_root)->s_iattr

	// inode->i_mode: (kmem_cache#4-oX (struct inode))->i_mode: 40447,
	// sd->s_mode: (&sysfs_root)->s_mode: 40447
	inode->i_mode = sd->s_mode;
	// inode->i_mode: (kmem_cache#4-oX (struct inode))->i_mode: 40447

	// iattrs: (&sysfs_root)->s_iattr: NULL
	if (iattrs) {
		/* sysfs_dirent has non-default attributes
		 * get them from persistent copy in sysfs_dirent
		 */
		set_inode_attr(inode, &iattrs->ia_iattr);
		security_inode_notifysecctx(inode,
					    iattrs->ia_secdata,
					    iattrs->ia_secdata_len);
	}

// 2015/12/05 종료
// 2015/12/12 시작

	// sd: &sysfs_root, sysfs_type(&sysfs_root): 0x1, SYSFS_DIR: 0x0001
	if (sysfs_type(sd) == SYSFS_DIR)
		// inode: kmem_cache#4-oX (struct inode), sd->s_dir.subdirs: (&sysfs_root)->s_dir.subdirs: 0
		set_nlink(inode, sd->s_dir.subdirs + 2);

		// set_nlink에서 한일:
		// inode->__i_nlink: (kmem_cache#4-oX (struct inode))->__i_nlink: 2
}

int sysfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		  struct kstat *stat)
{
	struct sysfs_dirent *sd = dentry->d_fsdata;
	struct inode *inode = dentry->d_inode;

	mutex_lock(&sysfs_mutex);
	sysfs_refresh_inode(sd, inode);
	mutex_unlock(&sysfs_mutex);

	generic_fillattr(inode, stat);
	return 0;
}

// ARM10C 20151205
// sd: &sysfs_root, inode: kmem_cache#4-oX (struct inode)
static void sysfs_init_inode(struct sysfs_dirent *sd, struct inode *inode)
{
	struct bin_attribute *bin_attr;

	// inode->i_private: (kmem_cache#4-oX (struct inode))->i_private,
	// sd: &sysfs_root, sysfs_get(&sysfs_root): 2
	inode->i_private = sysfs_get(sd);
	// inode->i_private: (kmem_cache#4-oX (struct inode))->i_private: 2

	// sysfs_get에서 한일:
	// (&sysfs_root)->s_count: 2

	// inode->i_mapping: (kmem_cache#4-oX (struct inode))->i_mapping: &(kmem_cache#4-oX (struct inode))->i_data
	// inode->i_mapping->a_ops: (kmem_cache#4-oX (struct inode))->i_mapping->a_ops: &empty_aops
	inode->i_mapping->a_ops = &sysfs_aops;
	// inode->i_mapping->a_ops: (kmem_cache#4-oX (struct inode))->i_mapping->a_ops: &sysfs_aops

	// inode->i_mapping->backing_dev_info: (kmem_cache#4-oX (struct inode))->i_mapping->backing_dev_info: &default_backing_dev_info
	inode->i_mapping->backing_dev_info = &sysfs_backing_dev_info;
	// inode->i_mapping->backing_dev_info: (kmem_cache#4-oX (struct inode))->i_mapping->backing_dev_info: &sysfs_backing_dev_info

	// inode->i_op: (kmem_cache#4-oX (struct inode))->i_op: &empty_iops
	inode->i_op = &sysfs_inode_operations;
	// inode->i_op: (kmem_cache#4-oX (struct inode))->i_op: &sysfs_inode_operations

	// inode: kmem_cache#4-oX (struct inode), sd->s_mode: (&sysfs_root)->s_mode
	set_default_inode_attr(inode, sd->s_mode);

	// set_default_inode_attr에서 한일:
	// (kmem_cache#4-oX (struct inode))->i_mode: 40447
	// (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값,
	// (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값,
	// (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값

	// sd: &sysfs_root, inode: kmem_cache#4-oX (struct inode)
	sysfs_refresh_inode(sd, inode);

	// sysfs_refresh_inode에서 한일:
	// (kmem_cache#4-oX (struct inode))->i_mode: 40447
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 2

	/* initialize inode according to type */
	// sd: &sysfs_root, sysfs_type(&sysfs_root): 0x1
	switch (sysfs_type(sd)) {
	case SYSFS_DIR: // SYSFS_DIR: 0x0001
		// inode->i_op: (kmem_cache#4-oX (struct inode))->i_op
		inode->i_op = &sysfs_dir_inode_operations;
		// inode->i_op: (kmem_cache#4-oX (struct inode))->i_op: &sysfs_dir_inode_operations

		// inode->i_fop: (kmem_cache#4-oX (struct inode))->i_fop
		inode->i_fop = &sysfs_dir_operations;
		// inode->i_fop: (kmem_cache#4-oX (struct inode))->i_fop: &sysfs_dir_operations
		break;
	case SYSFS_KOBJ_ATTR: // SYSFS_KOBJ_ATTR: 0x0002
		inode->i_size = PAGE_SIZE;
		inode->i_fop = &sysfs_file_operations;
		break;
	case SYSFS_KOBJ_BIN_ATTR: // SYSFS_KOBJ_BIN_ATTR: 0x0004
		bin_attr = sd->s_attr.bin_attr;
		inode->i_size = bin_attr->size;
		inode->i_fop = &sysfs_bin_operations;
		break;
	case SYSFS_KOBJ_LINK: // SYSFS_KOBJ_LINK: 0x0008
		inode->i_op = &sysfs_symlink_inode_operations;
		break;
	default:
		BUG();
	}

	// inode: kmem_cache#4-oX (struct inode)
	unlock_new_inode(inode);

	// unlock_new_inode에서 한일
	// (kmem_cache#4-oX (struct inode))->i_state: 0x0
	// memory barrier 수행 (공유자원을 다른 cpu core가 사용할 수 있게 해줌)
}

/**
 *	sysfs_get_inode - get inode for sysfs_dirent
 *	@sb: super block
 *	@sd: sysfs_dirent to allocate inode for
 *
 *	Get inode for @sd.  If such inode doesn't exist, a new inode
 *	is allocated and basics are initialized.  New inode is
 *	returned locked.
 *
 *	LOCKING:
 *	Kernel thread context (may sleep).
 *
 *	RETURNS:
 *	Pointer to allocated inode on success, NULL on failure.
 */
// ARM10C 20151121
// sb: kmem_cache#25-oX (struct super_block), &sysfs_root
struct inode *sysfs_get_inode(struct super_block *sb, struct sysfs_dirent *sd)
{
	struct inode *inode;

// 2015/11/21 종료
// 2015/11/28 시작

	// sb: kmem_cache#25-oX (struct super_block), sd->s_ino: (&sysfs_root)->s_ino: 1
	// iget_locked(kmem_cache#25-oX (struct super_block), 1): kmem_cache#4-oX (struct inode)
	inode = iget_locked(sb, sd->s_ino);
	// inode: kmem_cache#4-oX (struct inode)

	// iget_locked에서 한일:
	// inode용 kmem_cache인 inode_cachep: kmem_cache#4 를 사용하여 inode를 위한 메모리 kmem_cache#4-oX (struct inode) 할당 받음
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
	// (kmem_cache#4-oX (struct inode))->i_ino: 1
	// (kmem_cache#4-oX (struct inode))->i_state: 0x8
	//
	// (&(kmem_cache#4-oX (struct inode))->i_hash)->next: NULL
	// (256KB의 메모리 공간 + 계산된 hash index 값)->first: &(kmem_cache#4-oX (struct inode))->i_hash
	// (&(kmem_cache#4-oX (struct inode))->i_hash)->pprev: &(&(kmem_cache#4-oX (struct inode))->i_hash)
	//
	// head list인 &(kmem_cache#4-oX (struct inode))->i_sb->s_inodes에 &(kmem_cache#4-oX (struct inode))->i_sb_list를 추가함

	// inode: kmem_cache#4-oX (struct inode), inode->i_state: (kmem_cache#4-oX (struct inode))->i_state: 0x8, I_NEW: 0x8
	if (inode && (inode->i_state & I_NEW))
		// sd: &sysfs_root, inode: kmem_cache#4-oX (struct inode)
		sysfs_init_inode(sd, inode);

		// sysfs_init_inode에서 한일:
		// (&sysfs_root)->s_count: 2
		//
		// (kmem_cache#4-oX (struct inode))->i_private: 2
		// (kmem_cache#4-oX (struct inode))->i_mapping->a_ops: &sysfs_aops
		// (kmem_cache#4-oX (struct inode))->i_mapping->backing_dev_info: &sysfs_backing_dev_info
		// (kmem_cache#4-oX (struct inode))->i_op: &sysfs_inode_operations
		// (kmem_cache#4-oX (struct inode))->i_mode: 40447
		// (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값,
		// (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값,
		// (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값
		// (kmem_cache#4-oX (struct inode))->i_mode: 40447
		// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
		// (kmem_cache#4-oX (struct inode))->i_op: &sysfs_dir_inode_operations
		// (kmem_cache#4-oX (struct inode))->i_fop: &sysfs_dir_operations
		// (kmem_cache#4-oX (struct inode))->i_state: 0x0
		// memory barrier 수행 (공유자원을 다른 cpu core가 사용할 수 있게 해줌)

	// inode: kmem_cache#4-oX (struct inode)
	return inode;
	// return kmem_cache#4-oX (struct inode)
}

/*
 * The sysfs_dirent serves as both an inode and a directory entry for sysfs.
 * To prevent the sysfs inode numbers from being freed prematurely we take a
 * reference to sysfs_dirent from the sysfs inode.  A
 * super_operations.evict_inode() implementation is needed to drop that
 * reference upon inode destruction.
 */
void sysfs_evict_inode(struct inode *inode)
{
	struct sysfs_dirent *sd  = inode->i_private;

	truncate_inode_pages(&inode->i_data, 0);
	clear_inode(inode);
	sysfs_put(sd);
}

int sysfs_permission(struct inode *inode, int mask)
{
	struct sysfs_dirent *sd;

	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	sd = inode->i_private;

	mutex_lock(&sysfs_mutex);
	sysfs_refresh_inode(sd, inode);
	mutex_unlock(&sysfs_mutex);

	return generic_permission(inode, mask);
}
