/*
 * fs/sysfs/dir.c - sysfs core and dir operation implementation
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

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/namei.h>
#include <linux/idr.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/hash.h>
#include "sysfs.h"

// ARM10C 20151121
// ARM10C 20160116
// DEFINE_MUTEX(sysfs_mutex):
// struct mutex sysfs_mutex =
// { .count = { (1) }
//    , .wait_lock =
//    (spinlock_t )
//    { { .rlock =
//	  {
//	  .raw_lock = { { 0 } },
//	  .magic = 0xdead4ead,
//	  .owner_cpu = -1,
//	  .owner = 0xffffffff,
//	  }
//    } }
//    , .wait_list =
//    { &(sysfs_mutex.wait_list), &(sysfs_mutex.wait_list) }
//    , .magic = &sysfs_mutex
// }
DEFINE_MUTEX(sysfs_mutex);
DEFINE_SPINLOCK(sysfs_symlink_target_lock);

#define to_sysfs_dirent(X) rb_entry((X), struct sysfs_dirent, s_rb)

// ARM10C 20160116
// DEFINE_SPINLOCK(sysfs_ino_lock):
// spinlock_t sysfs_ino_lock =
// (spinlock_t )
// { { .rlock =
//     {
//       .raw_lock = { { 0 } },
//       .magic = 0xdead4ead,
//       .owner_cpu = -1,
//       .owner = 0xffffffff,
//     }
// } }
static DEFINE_SPINLOCK(sysfs_ino_lock);
// ARM10C 20160116
// DEFINE_IDA(sysfs_ino_ida):
// struct ida sysfs_ino_ida =
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
static DEFINE_IDA(sysfs_ino_ida);

/**
 *	sysfs_name_hash
 *	@name: Null terminated string to hash
 *	@ns:   Namespace tag to hash
 *
 *	Returns 31 bit hash of ns + name (so it fits in an off_t )
 */
// ARM10C 20160116
// sd->s_name: (kmem_cache#1-oX (struct sysfs_dirent))->s_name: "fs",
// sd->s_ns: (kmem_cache#1-oX (struct sysfs_dirent))->s_ns: NULL
static unsigned int sysfs_name_hash(const char *name, const void *ns)
{
	// init_name_hash(): 0
	unsigned long hash = init_name_hash();
	// hash: 0

	// name: "fs", strlen("fs"): 2
	unsigned int len = strlen(name);
	// len: 2

	// len: 2
	while (len--)
		// [loop 1] len: 1, name: "fs", hash: 0, partial_name_hash('f', 0): 0x4662
		// [loop 2] len: 0, name: "fs", hash: 0x4662, partial_name_hash('s', 0x4662): 0x35593
		hash = partial_name_hash(*name++, hash);
		// [loop 1] len: 1, hash: 0x4662
		// [loop 1] len: 0, hash: 0x35593

	// hash: 0x35593, end_name_hash(0x35593): 0x35593, ns: NULL, hash_ptr(NULL, 31): 계산된 hash index 값
	hash = (end_name_hash(hash) ^ hash_ptr((void *)ns, 31));
	// hash: 계산된 hash index 값

	// hash: 계산된 hash index 값
	hash &= 0x7fffffffU;
	// hash: 계산된 hash index 값

	/* Reserve hash numbers 0, 1 and INT_MAX for magic directory entries */
	// hash: 계산된 hash index 값
	if (hash < 1)
		hash += 2;
	if (hash >= INT_MAX)
		hash = INT_MAX - 1;

	// hash: 계산된 hash index 값
	return hash;
	// return 계산된 hash index 값
}

static int sysfs_name_compare(unsigned int hash, const char *name,
			      const void *ns, const struct sysfs_dirent *sd)
{
	if (hash != sd->s_hash)
		return hash - sd->s_hash;
	if (ns != sd->s_ns)
		return ns - sd->s_ns;
	return strcmp(name, sd->s_name);
}

static int sysfs_sd_compare(const struct sysfs_dirent *left,
			    const struct sysfs_dirent *right)
{
	return sysfs_name_compare(left->s_hash, left->s_name, left->s_ns,
				  right);
}

/**
 *	sysfs_link_sibling - link sysfs_dirent into sibling rbtree
 *	@sd: sysfs_dirent of interest
 *
 *	Link @sd into its sibling rbtree which starts from
 *	sd->s_parent->s_dir.children.
 *
 *	Locking:
 *	mutex_lock(sysfs_mutex)
 *
 *	RETURNS:
 *	0 on susccess -EEXIST on failure.
 */
// ARM10C 20160116
// sd: kmem_cache#1-oX (struct sysfs_dirent)
static int sysfs_link_sibling(struct sysfs_dirent *sd)
{
	// &sd->s_parent: &(kmem_cache#1-oX (struct sysfs_dirent))->s_parent: &sysfs_root
	// &sd->s_parent->s_dir.children.rb_node: &(&sysfs_root)->s_dir.children.rb_node
	struct rb_node **node = &sd->s_parent->s_dir.children.rb_node;
	// node: &(&sysfs_root)->s_dir.children.rb_node

	struct rb_node *parent = NULL;
	// parent: NULL

	// sd: kmem_cache#1-oX (struct sysfs_dirent),
	// sysfs_type(kmem_cache#1-oX (struct sysfs_dirent)): 0x1, SYSFS_DIR: 0x0001
	if (sysfs_type(sd) == SYSFS_DIR)
		// sd->s_parent: (kmem_cache#1-oX (struct sysfs_dirent))->s_parent: &sysfs_root
		// sd->s_parent->s_dir.subdirs: (&sysfs_root)->s_dir.subdirs: 0
		sd->s_parent->s_dir.subdirs++;
		// sd->s_parent->s_dir.subdirs: (&sysfs_root)->s_dir.subdirs: 1

	// *node: (&sysfs_root)->s_dir.children.rb_node: NULL
	while (*node) {
		struct sysfs_dirent *pos;
		int result;

		pos = to_sysfs_dirent(*node);
		parent = *node;
		result = sysfs_sd_compare(sd, pos);
		if (result < 0)
			node = &pos->s_rb.rb_left;
		else if (result > 0)
			node = &pos->s_rb.rb_right;
		else
			return -EEXIST;
	}
	/* add new node and rebalance the tree */
	// &sd->s_rb: &(kmem_cache#1-oX (struct sysfs_dirent))->s_rb, parent: NULL, node: &(&sysfs_root)->s_dir.children.rb_node
	rb_link_node(&sd->s_rb, parent, node);

	// rb_link_node에서 한일:
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_right: NULL
	// (&sysfs_root)->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent))->s_rb

	// &sd->s_rb: &(kmem_cache#1-oX (struct sysfs_dirent))->s_rb,
	// &sd->s_parent: &(kmem_cache#1-oX (struct sysfs_dirent))->s_parent: &sysfs_root,
	// &sd->s_parent->s_dir.children: &(&sysfs_root)->s_dir.children
	rb_insert_color(&sd->s_rb, &sd->s_parent->s_dir.children);

	// NOTE:
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2 값을 이용하여
	// rb_node를 INODE(2) 주석을 달기로 함

	// rb_insert_color에서 한일:
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(2)-b
	//              /            \
	*/

	return 0;
	// return 0
}

/**
 *	sysfs_unlink_sibling - unlink sysfs_dirent from sibling rbtree
 *	@sd: sysfs_dirent of interest
 *
 *	Unlink @sd from its sibling rbtree which starts from
 *	sd->s_parent->s_dir.children.
 *
 *	Locking:
 *	mutex_lock(sysfs_mutex)
 */
static void sysfs_unlink_sibling(struct sysfs_dirent *sd)
{
	if (sysfs_type(sd) == SYSFS_DIR)
		sd->s_parent->s_dir.subdirs--;

	rb_erase(&sd->s_rb, &sd->s_parent->s_dir.children);
}

/**
 *	sysfs_get_active - get an active reference to sysfs_dirent
 *	@sd: sysfs_dirent to get an active reference to
 *
 *	Get an active reference of @sd.  This function is noop if @sd
 *	is NULL.
 *
 *	RETURNS:
 *	Pointer to @sd on success, NULL on failure.
 */
struct sysfs_dirent *sysfs_get_active(struct sysfs_dirent *sd)
{
	if (unlikely(!sd))
		return NULL;

	if (!atomic_inc_unless_negative(&sd->s_active))
		return NULL;

	if (likely(!sysfs_ignore_lockdep(sd)))
		rwsem_acquire_read(&sd->dep_map, 0, 1, _RET_IP_);
	return sd;
}

/**
 *	sysfs_put_active - put an active reference to sysfs_dirent
 *	@sd: sysfs_dirent to put an active reference to
 *
 *	Put an active reference to @sd.  This function is noop if @sd
 *	is NULL.
 */
void sysfs_put_active(struct sysfs_dirent *sd)
{
	int v;

	if (unlikely(!sd))
		return;

	if (likely(!sysfs_ignore_lockdep(sd)))
		rwsem_release(&sd->dep_map, 1, _RET_IP_);
	v = atomic_dec_return(&sd->s_active);
	if (likely(v != SD_DEACTIVATED_BIAS))
		return;

	/* atomic_dec_return() is a mb(), we'll always see the updated
	 * sd->u.completion.
	 */
	complete(sd->u.completion);
}

/**
 *	sysfs_deactivate - deactivate sysfs_dirent
 *	@sd: sysfs_dirent to deactivate
 *
 *	Deny new active references and drain existing ones.
 */
static void sysfs_deactivate(struct sysfs_dirent *sd)
{
	DECLARE_COMPLETION_ONSTACK(wait);
	int v;

	BUG_ON(!(sd->s_flags & SYSFS_FLAG_REMOVED));

	if (!(sysfs_type(sd) & SYSFS_ACTIVE_REF))
		return;

	sd->u.completion = (void *)&wait;

	rwsem_acquire(&sd->dep_map, 0, 0, _RET_IP_);
	/* atomic_add_return() is a mb(), put_active() will always see
	 * the updated sd->u.completion.
	 */
	v = atomic_add_return(SD_DEACTIVATED_BIAS, &sd->s_active);

	if (v != SD_DEACTIVATED_BIAS) {
		lock_contended(&sd->dep_map, _RET_IP_);
		wait_for_completion(&wait);
	}

	lock_acquired(&sd->dep_map, _RET_IP_);
	rwsem_release(&sd->dep_map, 1, _RET_IP_);
}

// ARM10C 20160116
// &sd->s_ino: &(kmem_cache#1-oX (struct sysfs_dirent))->s_ino
// ARM10C 20160730
// &sd->s_ino: &(kmem_cache#1-oX (struct sysfs_dirent))->s_ino
static int sysfs_alloc_ino(unsigned int *pino)
{
	int ino, rc;

 retry:
	spin_lock(&sysfs_ino_lock);

	// spin_lock에서 한일:
	// &sysfs_ino_lock을 사용하여 spin lock을 수행

	// [re] spin_lock에서 한일:
	// &sysfs_ino_lock을 사용하여 spin lock을 수행

	// spin_lock에서 한일:
	// &sysfs_ino_lock을 사용하여 spin lock을 수행

	// ida_get_new_above(&sysfs_ino_ida, 2, &ino): -11
	// [re] ida_get_new_above(&sysfs_ino_ida, 2, &ino): 0
	// ida_get_new_above(&sysfs_ino_ida, 2, &ino): 0
	rc = ida_get_new_above(&sysfs_ino_ida, 2, &ino);
	// rc: -11
	// [re] rc: 0
	// rc: 0

	// ida_get_new_above에서 한일:
	// (&(&sysfs_ino_ida)->idr)->id_free: NULL 이므로 -11 을 리턴함

	// [re] ida_get_new_above에서 한일:
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 6
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// ((&(&sysfs_ino_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&sysfs_ino_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 1
	//
	// ino: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함

	// ida_get_new_above에서 한일:
	// (&(&sysfs_ino_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// (&(&sysfs_ino_ida)->idr)->id_free: (idr object new 0)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 3 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// ino: 3
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함

	spin_unlock(&sysfs_ino_lock);

	// spin_unlock에서 한일:
	// &sysfs_ino_lock을 사용하여 spin unlock을 수행

	// [re] spin_unlock에서 한일:
	// &sysfs_ino_lock을 사용하여 spin unlock을 수행

	// spin_unlock에서 한일:
	// &sysfs_ino_lock을 사용하여 spin unlock을 수행

	// rc: -11, EAGAIN: 11
	// [re] rc: 0, EAGAIN: 11
	// rc: 0, EAGAIN: 11
	if (rc == -EAGAIN) {
		// GFP_KERNEL: 0xD0
		// ida_pre_get(&sysfs_ino_ida, 0xD0): 1
		if (ida_pre_get(&sysfs_ino_ida, GFP_KERNEL))
			goto retry;
			// goto retry 수행

		// ida_pre_get에서 한일:
		// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
		//
		// (&(&sysfs_ino_ida)->idr)->id_free 이 idr object 8 번을 가르킴
		// |
		// |-> ---------------------------------------------------------------------------------------------------------------------------
		//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//
		// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
		// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 8
		//
		// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
		// (&sysfs_ino_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)

		rc = -ENOMEM;
	}


	// [re] *pino: *(&(kmem_cache#1-oX (struct sysfs_dirent))->s_ino), ino: 2
	// *pino: *(&(kmem_cache#1-oX (struct sysfs_dirent))->s_ino), ino: 3
	*pino = ino;
	// [re] *pino: *(&(kmem_cache#1-oX (struct sysfs_dirent))->s_ino): 2
	// *pino: *(&(kmem_cache#1-oX (struct sysfs_dirent))->s_ino): 3

	// [re] rc: 0
	// rc: 0
	return rc;
	// [re] return 0
	// return 0
}

static void sysfs_free_ino(unsigned int ino)
{
	spin_lock(&sysfs_ino_lock);
	ida_remove(&sysfs_ino_ida, ino);
	spin_unlock(&sysfs_ino_lock);
}

void release_sysfs_dirent(struct sysfs_dirent *sd)
{
	struct sysfs_dirent *parent_sd;

 repeat:
	/* Moving/renaming is always done while holding reference.
	 * sd->s_parent won't change beneath us.
	 */
	parent_sd = sd->s_parent;

	WARN(!(sd->s_flags & SYSFS_FLAG_REMOVED),
		"sysfs: free using entry: %s/%s\n",
		parent_sd ? parent_sd->s_name : "", sd->s_name);

	if (sysfs_type(sd) == SYSFS_KOBJ_LINK)
		sysfs_put(sd->s_symlink.target_sd);
	if (sysfs_type(sd) & SYSFS_COPY_NAME)
		kfree(sd->s_name);
	if (sd->s_iattr && sd->s_iattr->ia_secdata)
		security_release_secctx(sd->s_iattr->ia_secdata,
					sd->s_iattr->ia_secdata_len);
	kfree(sd->s_iattr);
	sysfs_free_ino(sd->s_ino);
	kmem_cache_free(sysfs_dir_cachep, sd);

	sd = parent_sd;
	if (sd && atomic_dec_and_test(&sd->s_count))
		goto repeat;
}

static int sysfs_dentry_delete(const struct dentry *dentry)
{
	struct sysfs_dirent *sd = dentry->d_fsdata;
	return !(sd && !(sd->s_flags & SYSFS_FLAG_REMOVED));
}

static int sysfs_dentry_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct sysfs_dirent *sd;
	int type;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	sd = dentry->d_fsdata;
	mutex_lock(&sysfs_mutex);

	/* The sysfs dirent has been deleted */
	if (sd->s_flags & SYSFS_FLAG_REMOVED)
		goto out_bad;

	/* The sysfs dirent has been moved? */
	if (dentry->d_parent->d_fsdata != sd->s_parent)
		goto out_bad;

	/* The sysfs dirent has been renamed */
	if (strcmp(dentry->d_name.name, sd->s_name) != 0)
		goto out_bad;

	/* The sysfs dirent has been moved to a different namespace */
	type = KOBJ_NS_TYPE_NONE;
	if (sd->s_parent) {
		type = sysfs_ns_type(sd->s_parent);
		if (type != KOBJ_NS_TYPE_NONE &&
				sysfs_info(dentry->d_sb)->ns[type] != sd->s_ns)
			goto out_bad;
	}

	mutex_unlock(&sysfs_mutex);
out_valid:
	return 1;
out_bad:
	/* Remove the dentry from the dcache hashes.
	 * If this is a deleted dentry we use d_drop instead of d_delete
	 * so sysfs doesn't need to cope with negative dentries.
	 *
	 * If this is a dentry that has simply been renamed we
	 * use d_drop to remove it from the dcache lookup on its
	 * old parent.  If this dentry persists later when a lookup
	 * is performed at its new name the dentry will be readded
	 * to the dcache hashes.
	 */
	mutex_unlock(&sysfs_mutex);

	/* If we have submounts we must allow the vfs caches
	 * to lie about the state of the filesystem to prevent
	 * leaks and other nasty things.
	 */
	if (check_submounts_and_drop(dentry) != 0)
		goto out_valid;

	return 0;
}

static void sysfs_dentry_release(struct dentry *dentry)
{
	sysfs_put(dentry->d_fsdata);
}

// ARM10C 20151219
const struct dentry_operations sysfs_dentry_ops = {
	.d_revalidate	= sysfs_dentry_revalidate,
	.d_delete	= sysfs_dentry_delete,
	.d_release	= sysfs_dentry_release,
};

// ARM10C 20160116
// name: "fs", mode: 0x41ED, SYSFS_DIR: 0x0001
// ARM10C 20160730
// name: "cgroup", mode: 0x41ED, SYSFS_DIR: 0x0001
struct sysfs_dirent *sysfs_new_dirent(const char *name, umode_t mode, int type)
{
	char *dup_name = NULL;
	// dup_name: NULL
	// dup_name: NULL

	struct sysfs_dirent *sd;

	// type: 0x0001, SYSFS_COPY_NAME: 0x9
	// type: 0x0001, SYSFS_COPY_NAME: 0x9
	if (type & SYSFS_COPY_NAME) {
		name = dup_name = kstrdup(name, GFP_KERNEL);
		if (!name)
			return NULL;
	}

	// sysfs_dir_cachep: kmem_cache#1, GFP_KERNEL: 0xD0
	// kmem_cache_zalloc(kmem_cache#1, GFP_KERNEL: 0xD0): kmem_cache#1-oX (struct sysfs_dirent)
	// sysfs_dir_cachep: kmem_cache#1, GFP_KERNEL: 0xD0
	// kmem_cache_zalloc(kmem_cache#1, GFP_KERNEL: 0xD0): kmem_cache#1-oX (struct sysfs_dirent)
	sd = kmem_cache_zalloc(sysfs_dir_cachep, GFP_KERNEL);
	// sd: kmem_cache#1-oX (struct sysfs_dirent)
	// sd: kmem_cache#1-oX (struct sysfs_dirent)

	// sd: kmem_cache#1-oX (struct sysfs_dirent)
	// sd: kmem_cache#1-oX (struct sysfs_dirent)
	if (!sd)
		goto err_out1;

// 2016/02/27 종료
// 2016/03/05 시작

	// &sd->s_ino: &(kmem_cache#1-oX (struct sysfs_dirent))->s_ino
	// sysfs_alloc_ino(&(kmem_cache#1-oX (struct sysfs_dirent))->s_ino): 0
	// &sd->s_ino: &(kmem_cache#1-oX (struct sysfs_dirent))->s_ino
	// sysfs_alloc_ino(&(kmem_cache#1-oX (struct sysfs_dirent))->s_ino): 0
	if (sysfs_alloc_ino(&sd->s_ino))
		goto err_out2;

	// sysfs_alloc_ino에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&sysfs_ino_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&sysfs_ino_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 6
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// ((&(&sysfs_ino_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&sysfs_ino_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2

	// sysfs_alloc_ino에서 한일:
	// (&(&sysfs_ino_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// (&(&sysfs_ino_ida)->idr)->id_free: (idr object new 0)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 3 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// *(&(kmem_cache#1-oX (struct sysfs_dirent))->s_ino): 3

	// &sd->s_count,: &(kmem_cache#1-oX (struct sysfs_dirent))->s_count
	// &sd->s_count,: &(kmem_cache#1-oX (struct sysfs_dirent))->s_count
	atomic_set(&sd->s_count, 1);

	// atomic_set에서 한일:
	// &sd->s_count,: (&(kmem_cache#1-oX (struct sysfs_dirent))->s_count)->counter: 1

	// atomic_set에서 한일:
	// &sd->s_count,: (&(kmem_cache#1-oX (struct sysfs_dirent))->s_count)->counter: 1

	// &sd->s_active,: &(kmem_cache#1-oX (struct sysfs_dirent))->s_active
	// &sd->s_active,: &(kmem_cache#1-oX (struct sysfs_dirent))->s_active
	atomic_set(&sd->s_active, 0);

	// atomic_set에서 한일:
	// &sd->s_active: (&(kmem_cache#1-oX (struct sysfs_dirent))->s_active)->counter: 0

	// atomic_set에서 한일:
	// &sd->s_active: (&(kmem_cache#1-oX (struct sysfs_dirent))->s_active)->counter: 0

	// sd->s_name,: (kmem_cache#1-oX (struct sysfs_dirent))->s_name, name: "fs"
	// sd->s_name,: (kmem_cache#1-oX (struct sysfs_dirent))->s_name, name: "fs"
	sd->s_name = name;
	// sd->s_name: (kmem_cache#1-oX (struct sysfs_dirent))->s_name: "fs"
	// sd->s_name: (kmem_cache#1-oX (struct sysfs_dirent))->s_name: "cgroup"

	// sd->s_mode: (kmem_cache#1-oX (struct sysfs_dirent))->s_mode, mode: 0x41ED
	// sd->s_mode: (kmem_cache#1-oX (struct sysfs_dirent))->s_mode, mode: 0x41ED
	sd->s_mode = mode;
	// sd->s_mode: (kmem_cache#1-oX (struct sysfs_dirent))->s_mode: 0x41ED
	// sd->s_mode: (kmem_cache#1-oX (struct sysfs_dirent))->s_mode: 0x41ED

	// sd->s_flags,: (kmem_cache#1-oX (struct sysfs_dirent))->s_flags, type: 0x1, SYSFS_FLAG_REMOVED: 0x02000
	// sd->s_flags,: (kmem_cache#1-oX (struct sysfs_dirent))->s_flags, type: 0x1, SYSFS_FLAG_REMOVED: 0x02000
	sd->s_flags = type | SYSFS_FLAG_REMOVED;
	// sd->s_flags: (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x2001
	// sd->s_flags: (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x2001

	// sd: kmem_cache#1-oX (struct sysfs_dirent)
	// sd: kmem_cache#1-oX (struct sysfs_dirent)
	return sd;
	// return kmem_cache#1-oX (struct sysfs_dirent)
	// return kmem_cache#1-oX (struct sysfs_dirent)

 err_out2:
	kmem_cache_free(sysfs_dir_cachep, sd);
 err_out1:
	kfree(dup_name);
	return NULL;
}

/**
 *	sysfs_addrm_start - prepare for sysfs_dirent add/remove
 *	@acxt: pointer to sysfs_addrm_cxt to be used
 *
 *	This function is called when the caller is about to add or remove
 *	sysfs_dirent.  This function acquires sysfs_mutex.  @acxt is used
 *	to keep and pass context to other addrm functions.
 *
 *	LOCKING:
 *	Kernel thread context (may sleep).  sysfs_mutex is locked on
 *	return.
 */
// ARM10C 20160116
// &acxt
void sysfs_addrm_start(struct sysfs_addrm_cxt *acxt)
	__acquires(sysfs_mutex)
{
	// sizeof(struct sysfs_addrm_cxt): 4 bytes
	memset(acxt, 0, sizeof(*acxt));

	// memset에서 한일:
	// struct sysfs_addrm_cxt의 acxt 맴버값을 0으로 초기화 함

	mutex_lock(&sysfs_mutex);

	// mutex_lock에서 한일:
	// &sysfs_mutex을 이용하여 mutex lock을 수행
}

/**
 *	__sysfs_add_one - add sysfs_dirent to parent without warning
 *	@acxt: addrm context to use
 *	@sd: sysfs_dirent to be added
 *	@parent_sd: the parent sysfs_dirent to add @sd to
 *
 *	Get @parent_sd and set @sd->s_parent to it and increment nlink of
 *	the parent inode if @sd is a directory and link into the children
 *	list of the parent.
 *
 *	This function should be called between calls to
 *	sysfs_addrm_start() and sysfs_addrm_finish() and should be
 *	passed the same @acxt as passed to sysfs_addrm_start().
 *
 *	LOCKING:
 *	Determined by sysfs_addrm_start().
 *
 *	RETURNS:
 *	0 on success, -EEXIST if entry with the given name already
 *	exists.
 */
// ARM10C 20160116
// acxt: &acxt, sd: kmem_cache#1-oX (struct sysfs_dirent), parent_sd: &sysfs_root
int __sysfs_add_one(struct sysfs_addrm_cxt *acxt, struct sysfs_dirent *sd,
		    struct sysfs_dirent *parent_sd)
{
	struct sysfs_inode_attrs *ps_iattr;
	int ret;

	// parent_sd: &sysfs_root, sysfs_ns_type(&sysfs_root): 0,
	// sd->s_ns: (kmem_cache#1-oX (struct sysfs_dirent))->s_ns: NULL
	if (!!sysfs_ns_type(parent_sd) != !!sd->s_ns) {
		WARN(1, KERN_WARNING "sysfs: ns %s in '%s' for '%s'\n",
			sysfs_ns_type(parent_sd) ? "required" : "invalid",
			parent_sd->s_name, sd->s_name);
		return -EINVAL;
	}

	// sd->s_hash: (kmem_cache#1-oX (struct sysfs_dirent))->s_hash,
	// sd->s_name: (kmem_cache#1-oX (struct sysfs_dirent))->s_name: "fs"
	// sd->s_ns: (kmem_cache#1-oX (struct sysfs_dirent))->s_ns: NULL
	// sysfs_name_hash("fs", NULL): 계산된 hash index 값
	sd->s_hash = sysfs_name_hash(sd->s_name, sd->s_ns);
	// sd->s_hash: (kmem_cache#1-oX (struct sysfs_dirent))->s_hash: 계산된 hash index 값

	// sd->s_parent: (kmem_cache#1-oX (struct sysfs_dirent))->s_parent,
	// parent_sd: &sysfs_root, sysfs_get(&sysfs_root): &sysfs_root
	sd->s_parent = sysfs_get(parent_sd);
	// sd->s_parent: (kmem_cache#1-oX (struct sysfs_dirent))->s_parent: &sysfs_root

	// sd: kmem_cache#1-oX (struct sysfs_dirent)
	// sysfs_link_sibling(kmem_cache#1-oX (struct sysfs_dirent)): 0
	ret = sysfs_link_sibling(sd);
	// ret: 0

	// sysfs_link_sibling에서 한일:
	// (&sysfs_root)->s_dir.subdirs: 1
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_right: NULL
	// (&sysfs_root)->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent))->s_rb
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2 값을 이용하여
	// rb_node를 INODE(2) 주석을 달기로 함
	//
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(2)-b
	//              /            \
	*/

	// ret: 0
	if (ret)
		return ret;

// 2016/01/16 종료
// 2016/01/23 시작

	/* Update timestamps on the parent */
	// parent_sd->s_iattr: (&sysfs_root)->s_iattr: NULL
	ps_iattr = parent_sd->s_iattr;
	// ps_iattr: NULL

	// ps_iattr: NULL
	if (ps_iattr) {
		struct iattr *ps_iattrs = &ps_iattr->ia_iattr;
		ps_iattrs->ia_ctime = ps_iattrs->ia_mtime = CURRENT_TIME;
	}

	/* Mark the entry added into directory tree */
	// sd->s_flags: (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x2001, SYSFS_FLAG_REMOVED: 0x02000
	sd->s_flags &= ~SYSFS_FLAG_REMOVED;
	// sd->s_flags: (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x1

	return 0;
	// return 0
}

/**
 *	sysfs_pathname - return full path to sysfs dirent
 *	@sd: sysfs_dirent whose path we want
 *	@path: caller allocated buffer of size PATH_MAX
 *
 *	Gives the name "/" to the sysfs_root entry; any path returned
 *	is relative to wherever sysfs is mounted.
 */
static char *sysfs_pathname(struct sysfs_dirent *sd, char *path)
{
	if (sd->s_parent) {
		sysfs_pathname(sd->s_parent, path);
		strlcat(path, "/", PATH_MAX);
	}
	strlcat(path, sd->s_name, PATH_MAX);
	return path;
}

void sysfs_warn_dup(struct sysfs_dirent *parent, const char *name)
{
	char *path;

	path = kzalloc(PATH_MAX, GFP_KERNEL);
	if (path) {
		sysfs_pathname(parent, path);
		strlcat(path, "/", PATH_MAX);
		strlcat(path, name, PATH_MAX);
	}

	WARN(1, KERN_WARNING "sysfs: cannot create duplicate filename '%s'\n",
	     path ? path : name);

	kfree(path);
}

/**
 *	sysfs_add_one - add sysfs_dirent to parent
 *	@acxt: addrm context to use
 *	@sd: sysfs_dirent to be added
 *	@parent_sd: the parent sysfs_dirent to add @sd to
 *
 *	Get @parent_sd and set @sd->s_parent to it and increment nlink of
 *	the parent inode if @sd is a directory and link into the children
 *	list of the parent.
 *
 *	This function should be called between calls to
 *	sysfs_addrm_start() and sysfs_addrm_finish() and should be
 *	passed the same @acxt as passed to sysfs_addrm_start().
 *
 *	LOCKING:
 *	Determined by sysfs_addrm_start().
 *
 *	RETURNS:
 *	0 on success, -EEXIST if entry with the given name already
 *	exists.
 */
// ARM10C 20160116
// &acxt, sd: kmem_cache#1-oX (struct sysfs_dirent), parent_sd: &sysfs_root
int sysfs_add_one(struct sysfs_addrm_cxt *acxt, struct sysfs_dirent *sd,
		  struct sysfs_dirent *parent_sd)
{
	int ret;

	// acxt: &acxt, sd: kmem_cache#1-oX (struct sysfs_dirent), parent_sd: &sysfs_root
	// __sysfs_add_one(&acxt, kmem_cache#1-oX (struct sysfs_dirent), &sysfs_root): 0
	ret = __sysfs_add_one(acxt, sd, parent_sd);
	// ret: 0

	// __sysfs_add_one에서 한일:
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_hash: 계산된 hash index 값
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_parent: &sysfs_root
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x1
	//
	// (&sysfs_root)->s_dir.subdirs: 1
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_right: NULL
	// (&sysfs_root)->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent))->s_rb
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2 값을 이용하여
	// rb_node를 INODE(2) 주석을 달기로 함
	//
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(2)-b
	//              /            \
	*/

	// ret: 0, EEXIST: 17
	if (ret == -EEXIST)
		sysfs_warn_dup(parent_sd, sd->s_name);

	// ret: 0
	return ret;
	// return 0
}

/**
 *	sysfs_remove_one - remove sysfs_dirent from parent
 *	@acxt: addrm context to use
 *	@sd: sysfs_dirent to be removed
 *
 *	Mark @sd removed and drop nlink of parent inode if @sd is a
 *	directory.  @sd is unlinked from the children list.
 *
 *	This function should be called between calls to
 *	sysfs_addrm_start() and sysfs_addrm_finish() and should be
 *	passed the same @acxt as passed to sysfs_addrm_start().
 *
 *	LOCKING:
 *	Determined by sysfs_addrm_start().
 */
static void sysfs_remove_one(struct sysfs_addrm_cxt *acxt,
			     struct sysfs_dirent *sd)
{
	struct sysfs_inode_attrs *ps_iattr;

	/*
	 * Removal can be called multiple times on the same node.  Only the
	 * first invocation is effective and puts the base ref.
	 */
	if (sd->s_flags & SYSFS_FLAG_REMOVED)
		return;

	sysfs_unlink_sibling(sd);

	/* Update timestamps on the parent */
	ps_iattr = sd->s_parent->s_iattr;
	if (ps_iattr) {
		struct iattr *ps_iattrs = &ps_iattr->ia_iattr;
		ps_iattrs->ia_ctime = ps_iattrs->ia_mtime = CURRENT_TIME;
	}

	sd->s_flags |= SYSFS_FLAG_REMOVED;
	sd->u.removed_list = acxt->removed;
	acxt->removed = sd;
}

/**
 *	sysfs_addrm_finish - finish up sysfs_dirent add/remove
 *	@acxt: addrm context to finish up
 *
 *	Finish up sysfs_dirent add/remove.  Resources acquired by
 *	sysfs_addrm_start() are released and removed sysfs_dirents are
 *	cleaned up.
 *
 *	LOCKING:
 *	sysfs_mutex is released.
 */
// ARM10C 20160123
// &acxt
void sysfs_addrm_finish(struct sysfs_addrm_cxt *acxt)
	__releases(sysfs_mutex)
{
	/* release resources acquired by sysfs_addrm_start() */
	mutex_unlock(&sysfs_mutex);

	// mutex_unlock에서 한일:
	// &sysfs_mutex을 이용하여 mutex unlock을 수행

	/* kill removed sysfs_dirents */
	// acxt->removed: (&acxt)->removed: NULL
	while (acxt->removed) {
		struct sysfs_dirent *sd = acxt->removed;

		acxt->removed = sd->u.removed_list;

		sysfs_deactivate(sd);
		sysfs_unmap_bin_file(sd);
		sysfs_put(sd);
	}
}

/**
 *	sysfs_find_dirent - find sysfs_dirent with the given name
 *	@parent_sd: sysfs_dirent to search under
 *	@name: name to look for
 *	@ns: the namespace tag to use
 *
 *	Look for sysfs_dirent with name @name under @parent_sd.
 *
 *	LOCKING:
 *	mutex_lock(sysfs_mutex)
 *
 *	RETURNS:
 *	Pointer to sysfs_dirent if found, NULL if not.
 */
struct sysfs_dirent *sysfs_find_dirent(struct sysfs_dirent *parent_sd,
				       const unsigned char *name,
				       const void *ns)
{
	struct rb_node *node = parent_sd->s_dir.children.rb_node;
	unsigned int hash;

	if (!!sysfs_ns_type(parent_sd) != !!ns) {
		WARN(1, KERN_WARNING "sysfs: ns %s in '%s' for '%s'\n",
			sysfs_ns_type(parent_sd) ? "required" : "invalid",
			parent_sd->s_name, name);
		return NULL;
	}

	hash = sysfs_name_hash(name, ns);
	while (node) {
		struct sysfs_dirent *sd;
		int result;

		sd = to_sysfs_dirent(node);
		result = sysfs_name_compare(hash, name, ns, sd);
		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return sd;
	}
	return NULL;
}

/**
 *	sysfs_get_dirent_ns - find and get sysfs_dirent with the given name
 *	@parent_sd: sysfs_dirent to search under
 *	@name: name to look for
 *	@ns: the namespace tag to use
 *
 *	Look for sysfs_dirent with name @name under @parent_sd and get
 *	it if found.
 *
 *	LOCKING:
 *	Kernel thread context (may sleep).  Grabs sysfs_mutex.
 *
 *	RETURNS:
 *	Pointer to sysfs_dirent if found, NULL if not.
 */
struct sysfs_dirent *sysfs_get_dirent_ns(struct sysfs_dirent *parent_sd,
					 const unsigned char *name,
					 const void *ns)
{
	struct sysfs_dirent *sd;

	mutex_lock(&sysfs_mutex);
	sd = sysfs_find_dirent(parent_sd, name, ns);
	sysfs_get(sd);
	mutex_unlock(&sysfs_mutex);

	return sd;
}
EXPORT_SYMBOL_GPL(sysfs_get_dirent_ns);

// ARM10C 20160116
// kobj: kmem_cache#30-oX (struct kobject), parent_sd: &sysfs_root, type: 0,
// kobject_name(kmem_cache#30-oX (struct kobject)): "fs", ns: NULL, &sd
// ARM10C 20160730
// kobj: kmem_cache#30-oX (struct kobject) (cgroup), parent_sd: kmem_cache#1-oX (struct sysfs_dirent) (fs), type: 0
// kobject_name(kmem_cache#30-oX (struct kobject) (cgroup)): "cgroup", ns: NULL, &sd
static int create_dir(struct kobject *kobj, struct sysfs_dirent *parent_sd,
		      enum kobj_ns_type type,
		      const char *name, const void *ns,
		      struct sysfs_dirent **p_sd)
{
	// S_IFDIR: 0040000, S_IRWXU: 00700, S_IRUGO: 00444, S_IXUGO: 00111
	// S_IFDIR: 0040000, S_IRWXU: 00700, S_IRUGO: 00444, S_IXUGO: 00111
	umode_t mode = S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO;
	// mode: 0x41ED
	// mode: 0x41ED

	struct sysfs_addrm_cxt acxt;
	struct sysfs_dirent *sd;
	int rc;

	/* allocate */
	// name: "fs", mode: 0x41ED, SYSFS_DIR: 0x0001
	// sysfs_new_dirent("fs", 0x41ED, 0x0001): kmem_cache#1-oX (struct sysfs_dirent)
	// name: "cgroup", mode: 0x41ED, SYSFS_DIR: 0x0001
	// sysfs_new_dirent("cgroup", 0x41ED, 0x0001): kmem_cache#1-oX (struct sysfs_dirent)
	sd = sysfs_new_dirent(name, mode, SYSFS_DIR);
	// sd: kmem_cache#1-oX (struct sysfs_dirent) (fs)
	// sd: kmem_cache#1-oX (struct sysfs_dirent) (cgroup)

	// sysfs_new_dirent에서 한일:
	// sysfs_dir_cachep: kmem_cache#1을 이용하여 struct sysfs_dirent 메모리를 할당받음
	// kmem_cache#1-oX (struct sysfs_dirent)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&sysfs_ino_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&sysfs_ino_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 6
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// ((&(&sysfs_ino_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&sysfs_ino_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_count)->counter: 1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_active)->counter: 0
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_name: "fs"
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_mode: 0x41ED
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x2001

	// sysfs_new_dirent에서 한일:
	// sysfs_dir_cachep: kmem_cache#1을 이용하여 struct sysfs_dirent 메모리를 할당받음
	// kmem_cache#1-oX (struct sysfs_dirent)
	//
	// (&(&sysfs_ino_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// (&(&sysfs_ino_ida)->idr)->id_free: (idr object new 0)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 3 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// *(&(kmem_cache#1-oX (struct sysfs_dirent))->s_ino): 3
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_count)->counter: 1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_active)->counter: 0
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_name: "cgroup"
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_mode: 0x41ED
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x2001

	// sd: kmem_cache#1-oX (struct sysfs_dirent)
	// sd: kmem_cache#1-oX (struct sysfs_dirent) (cgroup)
	if (!sd)
		return -ENOMEM;

	// sd->s_flags: (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x2001, type: 0, SYSFS_NS_TYPE_SHIFT: 8
	// sd->s_flags: (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x2001, type: 0, SYSFS_NS_TYPE_SHIFT: 8
	sd->s_flags |= (type << SYSFS_NS_TYPE_SHIFT);
	// sd->s_flags: (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x2001
	// sd->s_flags: (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x2001

	// sd->s_ns: (kmem_cache#1-oX (struct sysfs_dirent))->s_ns, ns: NULL
	// sd->s_ns: (kmem_cache#1-oX (struct sysfs_dirent))->s_ns, ns: NULL
	sd->s_ns = ns;
	// sd->s_ns: (kmem_cache#1-oX (struct sysfs_dirent))->s_ns: NULL
	// sd->s_ns: (kmem_cache#1-oX (struct sysfs_dirent))->s_ns: NULL

	// sd->s_dir.kobj: (kmem_cache#1-oX (struct sysfs_dirent))->s_dir.kobj, kobj: kmem_cache#30-oX (struct kobject)
	// sd->s_dir.kobj: (kmem_cache#1-oX (struct sysfs_dirent))->s_dir.kobj, kobj: kmem_cache#30-oX (struct kobject)
	sd->s_dir.kobj = kobj;
	// sd->s_dir.kobj: (kmem_cache#1-oX (struct sysfs_dirent))->s_dir.kobj: kmem_cache#30-oX (struct kobject)
	// sd->s_dir.kobj: (kmem_cache#1-oX (struct sysfs_dirent))->s_dir.kobj: kmem_cache#30-oX (struct kobject)

// 2016/07/30 종료

	/* link in */
	sysfs_addrm_start(&acxt);

	// sysfs_addrm_start에서 한일:
	// struct sysfs_addrm_cxt의 acxt 맴버값을 0으로 초기화 함
	// &sysfs_mutex을 이용하여 mutex lock을 수행

	// sd: kmem_cache#1-oX (struct sysfs_dirent), parent_sd: &sysfs_root
	// sysfs_add_one(&acxt, kmem_cache#1-oX (struct sysfs_dirent), &sysfs_root): 0
	rc = sysfs_add_one(&acxt, sd, parent_sd);
	// rc: 0

	// sysfs_add_one에서 한일:
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_hash: 계산된 hash index 값
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_parent: &sysfs_root
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x1
	//
	// (&sysfs_root)->s_dir.subdirs: 1
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_right: NULL
	// (&sysfs_root)->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent))->s_rb
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2 값을 이용하여
	// rb_node를 INODE(2) 주석을 달기로 함
	//
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(2)-b
	//              /            \
	*/

	sysfs_addrm_finish(&acxt);

	// sysfs_addrm_finish에서 한일:
	// &sysfs_mutex을 이용하여 mutex unlock을 수행

	// rc: 0
	if (rc == 0)
		// *p_sd: sd, sd: kmem_cache#1-oX (struct sysfs_dirent)
		*p_sd = sd;
		// *p_sd: sd: kmem_cache#1-oX (struct sysfs_dirent)
	else
		sysfs_put(sd);

	// rc: 0
	return rc;
	// return 0
}

int sysfs_create_subdir(struct kobject *kobj, const char *name,
			struct sysfs_dirent **p_sd)
{
	return create_dir(kobj, kobj->sd,
			  KOBJ_NS_TYPE_NONE, name, NULL, p_sd);
}

/**
 *	sysfs_read_ns_type: return associated ns_type
 *	@kobj: the kobject being queried
 *
 *	Each kobject can be tagged with exactly one namespace type
 *	(i.e. network or user).  Return the ns_type associated with
 *	this object if any
 */
// ARM10C 20160116
// kobj: kmem_cache#30-oX (struct kobject)
// ARM10C 20160730
// kobj: kmem_cache#30-oX (struct kobject)
static enum kobj_ns_type sysfs_read_ns_type(struct kobject *kobj)
{
	const struct kobj_ns_type_operations *ops;
	enum kobj_ns_type type;

	// kobj: kmem_cache#30-oX (struct kobject) (fs), kobj_child_ns_ops(kmem_cache#30-oX (struct kobject) (fs)): NULL
	// kobj: kmem_cache#30-oX (struct kobject) (cgroup), kobj_child_ns_ops(kmem_cache#30-oX (struct kobject) (cgroup)): NULL
	ops = kobj_child_ns_ops(kobj);
	// ops: NULL
	// ops: NULL

	// ops: NULL
	// ops: NULL
	if (!ops)
		// KOBJ_NS_TYPE_NONE: 0
		// KOBJ_NS_TYPE_NONE: 0
		return KOBJ_NS_TYPE_NONE;
		// return 0
		// return 0

	type = ops->type;
	BUG_ON(type <= KOBJ_NS_TYPE_NONE);
	BUG_ON(type >= KOBJ_NS_TYPES);
	BUG_ON(!kobj_ns_type_registered(type));

	return type;
}

/**
 * sysfs_create_dir_ns - create a directory for an object with a namespace tag
 * @kobj: object we're creating directory for
 * @ns: the namespace tag to use
 */
// ARM10C 20160116
// kobj: kmem_cache#30-oX (struct kobject), kobject_namespace(kmem_cache#30-oX (struct kobject)): NULL
// ARM10C 20160730
// kobj: kmem_cache#30-oX (struct kobject), kobject_namespace(kmem_cache#30-oX (struct kobject)): NULL
int sysfs_create_dir_ns(struct kobject *kobj, const void *ns)
{
	enum kobj_ns_type type;
	struct sysfs_dirent *parent_sd, *sd;
	int error = 0;
	// error: 0
	// error: 0

	// kobj: kmem_cache#30-oX (struct kobject)
	// kobj: kmem_cache#30-oX (struct kobject)
	BUG_ON(!kobj);

	// kobj->parent: (kmem_cache#30-oX (struct kobject))->parent: NULL
	// kobj->parent: (kmem_cache#30-oX (struct kobject))->parent: kmem_cache#30-oX (struct kobject) (fs)
	if (kobj->parent)
		// kobj->parent->sd: ((kmem_cache#30-oX (struct kobject))->parent: kmem_cache#30-oX (struct kobject) (fs))->sd:
		// kmem_cache#1-oX (struct sysfs_dirent) (fs)
		parent_sd = kobj->parent->sd;
		// parent_sd: kmem_cache#1-oX (struct sysfs_dirent) (fs)
	else
		parent_sd = &sysfs_root;
		// parent_sd: &sysfs_root

	// parent_sd: &sysfs_root
	// parent_sd: kmem_cache#1-oX (struct sysfs_dirent) (fs)
	if (!parent_sd)
		return -ENOENT;

	// kobj: kmem_cache#30-oX (struct kobject) (fs),
	// sysfs_read_ns_type(kmem_cache#30-oX (struct kobject)): 0
	// kobj: kmem_cache#30-oX (struct kobject) (cgroup),
	// sysfs_read_ns_type(kmem_cache#30-oX (struct kobject)): 0
	type = sysfs_read_ns_type(kobj);
	// type: 0
	// type: 0

	// kobj: kmem_cache#30-oX (struct kobject), parent_sd: &sysfs_root, type: 0
	// kobject_name(kmem_cache#30-oX (struct kobject)): "fs", ns: NULL
	// create_dir(kmem_cache#30-oX (struct kobject), &sysfs_root, 0, "fs", NULL, &sd): 0
	//
	// kobj: kmem_cache#30-oX (struct kobject) (cgroup), parent_sd: kmem_cache#1-oX (struct sysfs_dirent) (fs), type: 0
	// kobject_name(kmem_cache#30-oX (struct kobject) (cgroup)): "cgroup", ns: NULL
	// create_dir(kmem_cache#30-oX (struct kobject) (cgroup), kmem_cache#1-oX (struct sysfs_dirent) (fs), 0, "cgroup", NULL, &sd): 0
	error = create_dir(kobj, parent_sd, type, kobject_name(kobj), ns, &sd);
	// error: 0

	// create_dir에서 한일:
	// sysfs_dir_cachep: kmem_cache#1을 이용하여 struct sysfs_dirent 메모리를 할당받음
	// kmem_cache#1-oX (struct sysfs_dirent)
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: NULL
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 6
	// (&(&sysfs_ino_ida)->idr)->top: kmem_cache#21-o7 (struct idr_layer)
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// (&sysfs_ino_ida)->free_bitmap: NULL
	//
	// (kmem_cache#21-o7 (struct idr_layer))->ary[0]: NULL
	// (kmem_cache#21-o7 (struct idr_layer))->layer: 0
	// (kmem_cache#21-o7 (struct idr_layer))->ary[0]: kmem_cache#27-oX (struct ida_bitmap)
	// (kmem_cache#21-o7 (struct idr_layer))->count: 1
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행
	//
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_count)->counter: 1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_active)->counter: 0
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_name: "fs"
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_mode: 0x41ED
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ns: NULL
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_dir.kobj: kmem_cache#30-oX (struct kobject)
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_hash: 계산된 hash index 값
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_parent: &sysfs_root
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_right: NULL
	//
	// (&sysfs_root)->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent))->s_rb
	// (&sysfs_root)->s_dir.subdirs: 1
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2 값을 이용하여
	// rb_node를 INODE(2) 주석을 달기로 함
	//
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(2)-b
	//              /            \
	*/
	// sd: kmem_cache#1-oX (struct sysfs_dirent)

	// error: 0
	if (!error)
		// kobj->sd: (kmem_cache#30-oX (struct kobject))->sd, sd: kmem_cache#1-oX (struct sysfs_dirent)
		kobj->sd = sd;
		// kobj->sd: (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent)

	// error: 0
	return error;
	// return 0
}

static struct dentry *sysfs_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct dentry *ret = NULL;
	struct dentry *parent = dentry->d_parent;
	struct sysfs_dirent *parent_sd = parent->d_fsdata;
	struct sysfs_dirent *sd;
	struct inode *inode;
	enum kobj_ns_type type;
	const void *ns;

	mutex_lock(&sysfs_mutex);

	type = sysfs_ns_type(parent_sd);
	ns = sysfs_info(dir->i_sb)->ns[type];

	sd = sysfs_find_dirent(parent_sd, dentry->d_name.name, ns);

	/* no such entry */
	if (!sd) {
		ret = ERR_PTR(-ENOENT);
		goto out_unlock;
	}
	dentry->d_fsdata = sysfs_get(sd);

	/* attach dentry and inode */
	inode = sysfs_get_inode(dir->i_sb, sd);
	if (!inode) {
		ret = ERR_PTR(-ENOMEM);
		goto out_unlock;
	}

	/* instantiate and hash dentry */
	ret = d_materialise_unique(dentry, inode);
 out_unlock:
	mutex_unlock(&sysfs_mutex);
	return ret;
}

// ARM10C 20151212
// ARM10C 20151219
const struct inode_operations sysfs_dir_inode_operations = {
	.lookup		= sysfs_lookup,
	.permission	= sysfs_permission,
	.setattr	= sysfs_setattr,
	.getattr	= sysfs_getattr,
	.setxattr	= sysfs_setxattr,
};

static struct sysfs_dirent *sysfs_leftmost_descendant(struct sysfs_dirent *pos)
{
	struct sysfs_dirent *last;

	while (true) {
		struct rb_node *rbn;

		last = pos;

		if (sysfs_type(pos) != SYSFS_DIR)
			break;

		rbn = rb_first(&pos->s_dir.children);
		if (!rbn)
			break;

		pos = to_sysfs_dirent(rbn);
	}

	return last;
}

/**
 * sysfs_next_descendant_post - find the next descendant for post-order walk
 * @pos: the current position (%NULL to initiate traversal)
 * @root: sysfs_dirent whose descendants to walk
 *
 * Find the next descendant to visit for post-order traversal of @root's
 * descendants.  @root is included in the iteration and the last node to be
 * visited.
 */
static struct sysfs_dirent *sysfs_next_descendant_post(struct sysfs_dirent *pos,
						       struct sysfs_dirent *root)
{
	struct rb_node *rbn;

	lockdep_assert_held(&sysfs_mutex);

	/* if first iteration, visit leftmost descendant which may be root */
	if (!pos)
		return sysfs_leftmost_descendant(root);

	/* if we visited @root, we're done */
	if (pos == root)
		return NULL;

	/* if there's an unvisited sibling, visit its leftmost descendant */
	rbn = rb_next(&pos->s_rb);
	if (rbn)
		return sysfs_leftmost_descendant(to_sysfs_dirent(rbn));

	/* no sibling left, visit parent */
	return pos->s_parent;
}

static void __sysfs_remove(struct sysfs_addrm_cxt *acxt,
			   struct sysfs_dirent *sd)
{
	struct sysfs_dirent *pos, *next;

	if (!sd)
		return;

	pr_debug("sysfs %s: removing\n", sd->s_name);

	next = NULL;
	do {
		pos = next;
		next = sysfs_next_descendant_post(pos, sd);
		if (pos)
			sysfs_remove_one(acxt, pos);
	} while (next);
}

/**
 * sysfs_remove - remove a sysfs_dirent recursively
 * @sd: the sysfs_dirent to remove
 *
 * Remove @sd along with all its subdirectories and files.
 */
void sysfs_remove(struct sysfs_dirent *sd)
{
	struct sysfs_addrm_cxt acxt;

	sysfs_addrm_start(&acxt);
	__sysfs_remove(&acxt, sd);
	sysfs_addrm_finish(&acxt);
}

/**
 * sysfs_hash_and_remove - find a sysfs_dirent by name and remove it
 * @dir_sd: parent of the target
 * @name: name of the sysfs_dirent to remove
 * @ns: namespace tag of the sysfs_dirent to remove
 *
 * Look for the sysfs_dirent with @name and @ns under @dir_sd and remove
 * it.  Returns 0 on success, -ENOENT if such entry doesn't exist.
 */
int sysfs_hash_and_remove(struct sysfs_dirent *dir_sd, const char *name,
			  const void *ns)
{
	struct sysfs_addrm_cxt acxt;
	struct sysfs_dirent *sd;

	if (!dir_sd) {
		WARN(1, KERN_WARNING "sysfs: can not remove '%s', no directory\n",
			name);
		return -ENOENT;
	}

	sysfs_addrm_start(&acxt);

	sd = sysfs_find_dirent(dir_sd, name, ns);
	if (sd)
		__sysfs_remove(&acxt, sd);

	sysfs_addrm_finish(&acxt);

	if (sd)
		return 0;
	else
		return -ENOENT;
}

/**
 *	sysfs_remove_dir - remove an object's directory.
 *	@kobj:	object.
 *
 *	The only thing special about this is that we remove any files in
 *	the directory before we remove the directory, and we've inlined
 *	what used to be sysfs_rmdir() below, instead of calling separately.
 */
void sysfs_remove_dir(struct kobject *kobj)
{
	struct sysfs_dirent *sd = kobj->sd;

	/*
	 * In general, kboject owner is responsible for ensuring removal
	 * doesn't race with other operations and sysfs doesn't provide any
	 * protection; however, when @kobj is used as a symlink target, the
	 * symlinking entity usually doesn't own @kobj and thus has no
	 * control over removal.  @kobj->sd may be removed anytime and
	 * symlink code may end up dereferencing an already freed sd.
	 *
	 * sysfs_symlink_target_lock synchronizes @kobj->sd disassociation
	 * against symlink operations so that symlink code can safely
	 * dereference @kobj->sd.
	 */
	spin_lock(&sysfs_symlink_target_lock);
	kobj->sd = NULL;
	spin_unlock(&sysfs_symlink_target_lock);

	if (sd) {
		WARN_ON_ONCE(sysfs_type(sd) != SYSFS_DIR);
		sysfs_remove(sd);
	}
}

int sysfs_rename(struct sysfs_dirent *sd, struct sysfs_dirent *new_parent_sd,
		 const char *new_name, const void *new_ns)
{
	int error;

	mutex_lock(&sysfs_mutex);

	error = 0;
	if ((sd->s_parent == new_parent_sd) && (sd->s_ns == new_ns) &&
	    (strcmp(sd->s_name, new_name) == 0))
		goto out;	/* nothing to rename */

	error = -EEXIST;
	if (sysfs_find_dirent(new_parent_sd, new_name, new_ns))
		goto out;

	/* rename sysfs_dirent */
	if (strcmp(sd->s_name, new_name) != 0) {
		error = -ENOMEM;
		new_name = kstrdup(new_name, GFP_KERNEL);
		if (!new_name)
			goto out;

		kfree(sd->s_name);
		sd->s_name = new_name;
	}

	/*
	 * Move to the appropriate place in the appropriate directories rbtree.
	 */
	sysfs_unlink_sibling(sd);
	sysfs_get(new_parent_sd);
	sysfs_put(sd->s_parent);
	sd->s_ns = new_ns;
	sd->s_hash = sysfs_name_hash(sd->s_name, sd->s_ns);
	sd->s_parent = new_parent_sd;
	sysfs_link_sibling(sd);

	error = 0;
 out:
	mutex_unlock(&sysfs_mutex);
	return error;
}

int sysfs_rename_dir_ns(struct kobject *kobj, const char *new_name,
			const void *new_ns)
{
	struct sysfs_dirent *parent_sd = kobj->sd->s_parent;

	return sysfs_rename(kobj->sd, parent_sd, new_name, new_ns);
}

int sysfs_move_dir_ns(struct kobject *kobj, struct kobject *new_parent_kobj,
		      const void *new_ns)
{
	struct sysfs_dirent *sd = kobj->sd;
	struct sysfs_dirent *new_parent_sd;

	BUG_ON(!sd->s_parent);
	new_parent_sd = new_parent_kobj && new_parent_kobj->sd ?
		new_parent_kobj->sd : &sysfs_root;

	return sysfs_rename(sd, new_parent_sd, sd->s_name, new_ns);
}

/* Relationship between s_mode and the DT_xxx types */
static inline unsigned char dt_type(struct sysfs_dirent *sd)
{
	return (sd->s_mode >> 12) & 15;
}

static int sysfs_dir_release(struct inode *inode, struct file *filp)
{
	sysfs_put(filp->private_data);
	return 0;
}

static struct sysfs_dirent *sysfs_dir_pos(const void *ns,
	struct sysfs_dirent *parent_sd,	loff_t hash, struct sysfs_dirent *pos)
{
	if (pos) {
		int valid = !(pos->s_flags & SYSFS_FLAG_REMOVED) &&
			pos->s_parent == parent_sd &&
			hash == pos->s_hash;
		sysfs_put(pos);
		if (!valid)
			pos = NULL;
	}
	if (!pos && (hash > 1) && (hash < INT_MAX)) {
		struct rb_node *node = parent_sd->s_dir.children.rb_node;
		while (node) {
			pos = to_sysfs_dirent(node);

			if (hash < pos->s_hash)
				node = node->rb_left;
			else if (hash > pos->s_hash)
				node = node->rb_right;
			else
				break;
		}
	}
	/* Skip over entries in the wrong namespace */
	while (pos && pos->s_ns != ns) {
		struct rb_node *node = rb_next(&pos->s_rb);
		if (!node)
			pos = NULL;
		else
			pos = to_sysfs_dirent(node);
	}
	return pos;
}

static struct sysfs_dirent *sysfs_dir_next_pos(const void *ns,
	struct sysfs_dirent *parent_sd,	ino_t ino, struct sysfs_dirent *pos)
{
	pos = sysfs_dir_pos(ns, parent_sd, ino, pos);
	if (pos)
		do {
			struct rb_node *node = rb_next(&pos->s_rb);
			if (!node)
				pos = NULL;
			else
				pos = to_sysfs_dirent(node);
		} while (pos && pos->s_ns != ns);
	return pos;
}

static int sysfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct dentry *dentry = file->f_path.dentry;
	struct sysfs_dirent *parent_sd = dentry->d_fsdata;
	struct sysfs_dirent *pos = file->private_data;
	enum kobj_ns_type type;
	const void *ns;

	type = sysfs_ns_type(parent_sd);
	ns = sysfs_info(dentry->d_sb)->ns[type];

	if (!dir_emit_dots(file, ctx))
		return 0;
	mutex_lock(&sysfs_mutex);
	for (pos = sysfs_dir_pos(ns, parent_sd, ctx->pos, pos);
	     pos;
	     pos = sysfs_dir_next_pos(ns, parent_sd, ctx->pos, pos)) {
		const char *name = pos->s_name;
		unsigned int type = dt_type(pos);
		int len = strlen(name);
		ino_t ino = pos->s_ino;
		ctx->pos = pos->s_hash;
		file->private_data = sysfs_get(pos);

		mutex_unlock(&sysfs_mutex);
		if (!dir_emit(ctx, name, len, ino, type))
			return 0;
		mutex_lock(&sysfs_mutex);
	}
	mutex_unlock(&sysfs_mutex);
	file->private_data = NULL;
	ctx->pos = INT_MAX;
	return 0;
}

static loff_t sysfs_dir_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	loff_t ret;

	mutex_lock(&inode->i_mutex);
	ret = generic_file_llseek(file, offset, whence);
	mutex_unlock(&inode->i_mutex);

	return ret;
}

// ARM10C 20151212
const struct file_operations sysfs_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= sysfs_readdir,
	.release	= sysfs_dir_release,
	.llseek		= sysfs_dir_llseek,
};
