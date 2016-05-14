/*
 *  linux/fs/namespace.c
 *
 * (C) Copyright Al Viro 2000, 2001
 *	Released under GPL v2.
 *
 * Based on code from fs/super.c, copyright Linus Torvalds and others.
 * Heavily rewritten.
 */

#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/capability.h>
#include <linux/mnt_namespace.h>
#include <linux/user_namespace.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/idr.h>
#include <linux/acct.h>		/* acct_auto_close_mnt */
#include <linux/init.h>		/* init_rootfs */
#include <linux/fs_struct.h>	/* get_fs_root et.al. */
#include <linux/fsnotify.h>	/* fsnotify_vfsmount_delete */
#include <linux/uaccess.h>
#include <linux/proc_ns.h>
#include <linux/magic.h>
#include <linux/bootmem.h>
#include "pnode.h"
#include "internal.h"

// ARM10C 20151024
static unsigned int m_hash_mask __read_mostly;
// ARM10C 20151024
static unsigned int m_hash_shift __read_mostly;
static unsigned int mp_hash_mask __read_mostly;
static unsigned int mp_hash_shift __read_mostly;

// ARM10C 20151024
static __initdata unsigned long mhash_entries;
static int __init set_mhash_entries(char *str)
{
	if (!str)
		return 0;
	mhash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("mhash_entries=", set_mhash_entries);

// ARM10C 20151024
static __initdata unsigned long mphash_entries;
static int __init set_mphash_entries(char *str)
{
	if (!str)
		return 0;
	mphash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("mphash_entries=", set_mphash_entries);

static int event;
// ARM10C 20151031
// ARM10C 20160213
// DEFINE_IDA(mnt_id_ida):
// struct ida mnt_id_ida =
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
static DEFINE_IDA(mnt_id_ida);
static DEFINE_IDA(mnt_group_ida);
// ARM10C 20151031
// DEFINE_SPINLOCK(mnt_id_lock):
// spinlock_t mnt_id_lock =
// (spinlock_t )
// { { .rlock =
//     {
//       .raw_lock = { { 0 } },
//       .magic = 0xdead4ead,
//       .owner_cpu = -1,
//       .owner = 0xffffffff,
//     }
// } }
static DEFINE_SPINLOCK(mnt_id_lock);
// ARM10C 20151031
static int mnt_id_start = 0;
static int mnt_group_start = 1;

// ARM10C 20151024
// ARM10C 20151031
static struct hlist_head *mount_hashtable __read_mostly;
// ARM10C 20151024
// ARM10C 20151031
static struct hlist_head *mountpoint_hashtable __read_mostly;
// ARM10C 20151024
// ARM10C 20151031
static struct kmem_cache *mnt_cache __read_mostly;
static DECLARE_RWSEM(namespace_sem);

/* /sys/fs */
// ARM10C 20160109
struct kobject *fs_kobj;
EXPORT_SYMBOL_GPL(fs_kobj);

/*
 * vfsmount lock may be taken for read to prevent changes to the
 * vfsmount hash, ie. during mountpoint lookups or walking back
 * up the tree.
 *
 * It should be taken for write in all cases where the vfsmount
 * tree or hash is modified or when a vfsmount structure is modified.
 */
// ARM10C 20160109
// DEFINE_SEQLOCK(mount_lock):
// seqlock_t mount_lock =
// {
//     .seqcount = { .sequence = 0, },
//     .lock =
//     (spinlock_t )
//     { { .rlock =
//         {
//           .raw_lock = { { 0 } },
//           .magic = 0xdead4ead,
//           .owner_cpu = -1,
//           .owner = 0xffffffff,
//         }
//     } }
// }
__cacheline_aligned_in_smp DEFINE_SEQLOCK(mount_lock);

static inline struct hlist_head *m_hash(struct vfsmount *mnt, struct dentry *dentry)
{
	unsigned long tmp = ((unsigned long)mnt / L1_CACHE_BYTES);
	tmp += ((unsigned long)dentry / L1_CACHE_BYTES);
	tmp = tmp + (tmp >> m_hash_shift);
	return &mount_hashtable[tmp & m_hash_mask];
}

static inline struct hlist_head *mp_hash(struct dentry *dentry)
{
	unsigned long tmp = ((unsigned long)dentry / L1_CACHE_BYTES);
	tmp = tmp + (tmp >> mp_hash_shift);
	return &mountpoint_hashtable[tmp & mp_hash_mask];
}

/*
 * allocation is serialized by namespace_sem, but we need the spinlock to
 * serialize with freeing.
 */
// ARM10C 20151031
// mnt: kmem_cache#2-oX
// ARM10C 20160213
// mnt: kmem_cache#2-oX
// ARM10C 20160416
// mnt: kmem_cache#2-oX (struct mount)
static int mnt_alloc_id(struct mount *mnt)
{
	int res;

retry:
	// GFP_KERNEL: 0xD0
	// GFP_KERNEL: 0xD0
	// GFP_KERNEL: 0xD0
	ida_pre_get(&mnt_id_ida, GFP_KERNEL);

	// ida_pre_get에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)

	// ida_pre_get에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 2 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 1번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)

	// ida_pre_get에서 한일:
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 2번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)

	spin_lock(&mnt_id_lock);

	// spin_lock에서 한일:
	// &mnt_id_lock을 이용한 spin lock 수행

	// spin_lock에서 한일:
	// &mnt_id_lock을 이용한 spin lock 수행

	// spin_lock에서 한일:
	// &mnt_id_lock을 이용한 spin lock 수행


// 2016/02/13 종료
// 2016/02/20 시작

	// mnt_id_start: 0, &mnt->mnt_id: &(kmem_cache#2-oX (struct mount))->mnt_id
	// ida_get_new_above(&mnt_id_ida, 0, &(kmem_cache#2-oX)->mnt_id): 0
	// mnt_id_start: 1, &mnt->mnt_id: &(kmem_cache#2-oX)->mnt_id
	// ida_get_new_above(&mnt_id_ida, 1, &(kmem_cache#2-oX)->mnt_id): 0
	// mnt_id_start: 2, &mnt->mnt_id: &(kmem_cache#2-oX)->mnt_id
	// ida_get_new_above(&mnt_id_ida, 1, &(kmem_cache#2-oX)->mnt_id): 0
	res = ida_get_new_above(&mnt_id_ida, mnt_id_start, &mnt->mnt_id);
	// res: 0
	// res: 0
	// res: 0

	// ida_get_new_above에서 한일:
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 6
	// (&(&mnt_id_ida)->idr)->layers: 1
	// ((&(&mnt_id_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&mnt_id_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 1
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 0
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함

	// ida_get_new_above에서 한일:
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 1
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함

	// ida_get_new_above에서 한일:
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 3
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 2) 의 memory 공간을 반환함

	// res: 0
	// res: 0
	// res: 0
	if (!res)
		// mnt_id_start: 0, mnt->mnt_id: (kmem_cache#2-oX (struct mount))->mnt_id: 0
		// mnt_id_start: 1, mnt->mnt_id: (kmem_cache#2-oX (struct mount))->mnt_id: 1
		// mnt_id_start: 2, mnt->mnt_id: (kmem_cache#2-oX (struct mount))->mnt_id: 2
		mnt_id_start = mnt->mnt_id + 1;
		// mnt_id_start: 1
		// mnt_id_start: 2
		// mnt_id_start: 3

	spin_unlock(&mnt_id_lock);

	// spin_unlock에서 한일:
	// &mnt_id_lock을 이용한 spin unlock 수행

	// spin_unlock에서 한일:
	// &mnt_id_lock을 이용한 spin unlock 수행

	// spin_unlock에서 한일:
	// &mnt_id_lock을 이용한 spin unlock 수행

	// res: 0, EAGAIN: 11
	// res: 0, EAGAIN: 11
	// res: 0, EAGAIN: 11
	if (res == -EAGAIN)
		goto retry;

	// res: 0
	// res: 0
	// res: 0
	return res;
	// return 0
	// return 0
	// return 0
}

static void mnt_free_id(struct mount *mnt)
{
	int id = mnt->mnt_id;
	spin_lock(&mnt_id_lock);
	ida_remove(&mnt_id_ida, id);
	if (mnt_id_start > id)
		mnt_id_start = id;
	spin_unlock(&mnt_id_lock);
}

/*
 * Allocate a new peer group ID
 *
 * mnt_group_ida is protected by namespace_sem
 */
static int mnt_alloc_group_id(struct mount *mnt)
{
	int res;

	if (!ida_pre_get(&mnt_group_ida, GFP_KERNEL))
		return -ENOMEM;

	res = ida_get_new_above(&mnt_group_ida,
				mnt_group_start,
				&mnt->mnt_group_id);
	if (!res)
		mnt_group_start = mnt->mnt_group_id + 1;

	return res;
}

/*
 * Release a peer group ID
 */
void mnt_release_group_id(struct mount *mnt)
{
	int id = mnt->mnt_group_id;
	ida_remove(&mnt_group_ida, id);
	if (mnt_group_start > id)
		mnt_group_start = id;
	mnt->mnt_group_id = 0;
}

/*
 * vfsmount lock must be held for read
 */
static inline void mnt_add_count(struct mount *mnt, int n)
{
#ifdef CONFIG_SMP
	this_cpu_add(mnt->mnt_pcp->mnt_count, n);
#else
	preempt_disable();
	mnt->mnt_count += n;
	preempt_enable();
#endif
}

/*
 * vfsmount lock must be held for write
 */
unsigned int mnt_get_count(struct mount *mnt)
{
#ifdef CONFIG_SMP
	unsigned int count = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		count += per_cpu_ptr(mnt->mnt_pcp, cpu)->mnt_count;
	}

	return count;
#else
	return mnt->mnt_count;
#endif
}

// ARM10C 20151031
// name: "sysfs"
// ARM10C 20160213
// name: "tmpfs"
// ARM10C 20160416
// name: "rootfs"
static struct mount *alloc_vfsmnt(const char *name)
{
	// mnt_cache: kmem_cache#2, GFP_KERNEL: 0xD0
	// kmem_cache_zalloc(kmem_cache#2, 0xD0): kmem_cache#2-oX (struct mount)
	// mnt_cache: kmem_cache#2, GFP_KERNEL: 0xD0
	// kmem_cache_zalloc(kmem_cache#2, 0xD0): kmem_cache#2-oX (struct mount)
	// mnt_cache: kmem_cache#2, GFP_KERNEL: 0xD0
	// kmem_cache_zalloc(kmem_cache#2, 0xD0): kmem_cache#2-oX (struct mount)
	struct mount *mnt = kmem_cache_zalloc(mnt_cache, GFP_KERNEL);
	// mnt: kmem_cache#2-oX (struct mount)
	// mnt: kmem_cache#2-oX (struct mount)
	// mnt: kmem_cache#2-oX (struct mount)

	// mnt: kmem_cache#2-oX (struct mount)
	// mnt: kmem_cache#2-oX (struct mount)
	// mnt: kmem_cache#2-oX (struct mount)
	if (mnt) {
		int err;

		// mnt: kmem_cache#2-oX (struct mount)
		// mnt_alloc_id(kmem_cache#2-oX (struct mount)): 0
		// mnt: kmem_cache#2-oX (struct mount)
		// mnt_alloc_id(kmem_cache#2-oX (struct mount)): 0
		// mnt: kmem_cache#2-oX (struct mount)
		// mnt_alloc_id(kmem_cache#2-oX (struct mount)): 0
		err = mnt_alloc_id(mnt);
		// err: 0
		// err: 0
		// err: 0

		// mnt_alloc_id에서 한일:
		// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
		//
		// (&(&mnt_id_ida)->idr)->id_free 이 idr object 8 번을 가르킴
		// |
		// |-> ---------------------------------------------------------------------------------------------------------------------------
		//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
		//
		// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
		// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
		//
		// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
		//
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 6
		// (&(&mnt_id_ida)->idr)->layers: 1
		// ((&(&mnt_id_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
		//
		// (kmem_cache#21-oX (idr object 8))->layer: 0
		// kmem_cache#21-oX (struct idr_layer) (idr object 8)
		// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
		// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
		//
		// (&mnt_id_ida)->free_bitmap: NULL
		// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
		// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행
		// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 1
		//
		// (kmem_cache#2-oX (struct mount))->mnt_id: 0
		//
		// mnt_id_start: 1

		// mnt_alloc_id에서 한일:
		// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 2 개를 할당 받음
		//
		// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 1번을 가르킴
		// |
		// |-> ---------------------------------------------------------------------------------------------------------------------------
		//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
		//
		// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
		// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
		//
		// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
		// (&(&mnt_id_ida)->idr)->layers: 1
		// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
		//
		// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행
		// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
		//
		// (kmem_cache#2-oX (struct mount))->mnt_id: 1
		//
		// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함
		//
		// mnt_id_start: 2

		// mnt_alloc_id에서 한일:
		// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
		//
		// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 2번을 가르킴
		// |
		// |-> ---------------------------------------------------------------------------------------------------------------------------
		//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
		//
		// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
		//
		// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
		// (&(&mnt_id_ida)->idr)->layers: 1
		// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
		//
		// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
		// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 3
		//
		// (kmem_cache#2-oX (struct mount))->mnt_id: 2
		//
		// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 2) 의 memory 공간을 반환함
		//
		// mnt_id_start: 3

		// err: 0
		// err: 0
		// err: 0
		if (err)
			goto out_free_cache;

// 2016/03/05 종료
// 2016/03/19 시작

		// name: "sysfs"
		// name: "tmpfs"
		// name: "rootfs"
		if (name) {
			// mnt->mnt_devname: (kmem_cache#2-oX (struct mount))->mnt_devname, name: "sysfs", GFP_KERNEL: 0xD0
			// kstrdup("sysfs", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "sysfs"
			// mnt->mnt_devname: (kmem_cache#2-oX (struct mount))->mnt_devname, name: "tmpfs", GFP_KERNEL: 0xD0
			// kstrdup("tmpfs", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "tmpfs"
			// mnt->mnt_devname: (kmem_cache#2-oX (struct mount))->mnt_devname, name: "rootfs", GFP_KERNEL: 0xD0
			// kstrdup("rootfs", GFP_KERNEL: 0xD0): kmem_cache#30-oX: "rootfs"
			mnt->mnt_devname = kstrdup(name, GFP_KERNEL);
			// mnt->mnt_devname: (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "sysfs"
			// mnt->mnt_devname: (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "tmpfs"
			// mnt->mnt_devname: (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "rootfs"

			// mnt->mnt_devname: (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "sysfs"
			// mnt->mnt_devname: (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "tmpfs"
			// mnt->mnt_devname: (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "rootfs"
			if (!mnt->mnt_devname)
				goto out_free_id;
		}

#ifdef CONFIG_SMP // CONFIG_SMP=y
		// mnt->mnt_pcp: (kmem_cache#2-oX (struct mount))->mnt_pcp, sizeof(struct mnt_pcp): 8 bytes
		// alloc_percpu(struct mnt_pcp): kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
		// mnt->mnt_pcp: (kmem_cache#2-oX (struct mount))->mnt_pcp, sizeof(struct mnt_pcp): 8 bytes
		// alloc_percpu(struct mnt_pcp): kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
		// mnt->mnt_pcp: (kmem_cache#2-oX (struct mount))->mnt_pcp, sizeof(struct mnt_pcp): 8 bytes
		// alloc_percpu(struct mnt_pcp): kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
		mnt->mnt_pcp = alloc_percpu(struct mnt_pcp);
		// mnt->mnt_pcp: (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
		// mnt->mnt_pcp: (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
		// mnt->mnt_pcp: (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소

		// mnt->mnt_pcp: (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
		// mnt->mnt_pcp: (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
		// mnt->mnt_pcp: (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
		if (!mnt->mnt_pcp)
			goto out_free_devname;

		// mnt->mnt_pcp->mnt_count: (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count
		// mnt->mnt_pcp->mnt_count: (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count
		// mnt->mnt_pcp->mnt_count: (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count
		this_cpu_add(mnt->mnt_pcp->mnt_count, 1);
		// [pcp0] mnt->mnt_pcp->mnt_count: (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count: 1
		// [pcp0] mnt->mnt_pcp->mnt_count: (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count: 1
		// [pcp0] mnt->mnt_pcp->mnt_count: (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count: 1
#else
		mnt->mnt_count = 1;
		mnt->mnt_writers = 0;
#endif

		// mnt->mnt_hash: (kmem_cache#2-oX (struct mount))->mnt_hash
		// mnt->mnt_hash: (kmem_cache#2-oX (struct mount))->mnt_hash
		// mnt->mnt_hash: (kmem_cache#2-oX (struct mount))->mnt_hash
		INIT_HLIST_NODE(&mnt->mnt_hash);

		// INIT_HLIST_NODE에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_hash)->next: NULL
		// ((kmem_cache#2-oX (struct mount))->mnt_hash)->pprev: NULL

		// INIT_HLIST_NODE에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_hash)->next: NULL
		// ((kmem_cache#2-oX (struct mount))->mnt_hash)->pprev: NULL

		// INIT_HLIST_NODE에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_hash)->next: NULL
		// ((kmem_cache#2-oX (struct mount))->mnt_hash)->pprev: NULL

		// mnt->mnt_child: (kmem_cache#2-oX (struct mount))->mnt_child
		// mnt->mnt_child: (kmem_cache#2-oX (struct mount))->mnt_child
		// mnt->mnt_child: (kmem_cache#2-oX (struct mount))->mnt_child
		INIT_LIST_HEAD(&mnt->mnt_child);

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_child)->next: (kmem_cache#2-oX (struct mount))->mnt_child
		// ((kmem_cache#2-oX (struct mount))->mnt_child)->prev: (kmem_cache#2-oX (struct mount))->mnt_child

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_child)->next: (kmem_cache#2-oX (struct mount))->mnt_child
		// ((kmem_cache#2-oX (struct mount))->mnt_child)->prev: (kmem_cache#2-oX (struct mount))->mnt_child

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_child)->next: (kmem_cache#2-oX (struct mount))->mnt_child
		// ((kmem_cache#2-oX (struct mount))->mnt_child)->prev: (kmem_cache#2-oX (struct mount))->mnt_child

		// mnt->mnt_mounts: (kmem_cache#2-oX (struct mount))->mnt_mounts
		// mnt->mnt_mounts: (kmem_cache#2-oX (struct mount))->mnt_mounts
		// mnt->mnt_mounts: (kmem_cache#2-oX (struct mount))->mnt_mounts
		INIT_LIST_HEAD(&mnt->mnt_mounts);

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->next: (kmem_cache#2-oX (struct mount))->mnt_mounts
		// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->prev: (kmem_cache#2-oX (struct mount))->mnt_mounts

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->next: (kmem_cache#2-oX (struct mount))->mnt_mounts
		// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->prev: (kmem_cache#2-oX (struct mount))->mnt_mounts

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->next: (kmem_cache#2-oX (struct mount))->mnt_mounts
		// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->prev: (kmem_cache#2-oX (struct mount))->mnt_mounts
		
		// mnt->mnt_list: (kmem_cache#2-oX (struct mount))->mnt_list
		// mnt->mnt_list: (kmem_cache#2-oX (struct mount))->mnt_list
		// mnt->mnt_list: (kmem_cache#2-oX (struct mount))->mnt_list
		INIT_LIST_HEAD(&mnt->mnt_list);

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_list)->next: (kmem_cache#2-oX (struct mount))->mnt_list
		// ((kmem_cache#2-oX (struct mount))->mnt_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_list

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_list)->next: (kmem_cache#2-oX (struct mount))->mnt_list
		// ((kmem_cache#2-oX (struct mount))->mnt_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_list

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_list)->next: (kmem_cache#2-oX (struct mount))->mnt_list
		// ((kmem_cache#2-oX (struct mount))->mnt_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_list

		// mnt->mnt_expire: (kmem_cache#2-oX (struct mount))->mnt_expire
		// mnt->mnt_expire: (kmem_cache#2-oX (struct mount))->mnt_expire
		// mnt->mnt_expire: (kmem_cache#2-oX (struct mount))->mnt_expire
		INIT_LIST_HEAD(&mnt->mnt_expire);

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_expire)->next: (kmem_cache#2-oX (struct mount))->mnt_expire
		// ((kmem_cache#2-oX (struct mount))->mnt_expire)->prev: (kmem_cache#2-oX (struct mount))->mnt_expire

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_expire)->next: (kmem_cache#2-oX (struct mount))->mnt_expire
		// ((kmem_cache#2-oX (struct mount))->mnt_expire)->prev: (kmem_cache#2-oX (struct mount))->mnt_expire

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_expire)->next: (kmem_cache#2-oX (struct mount))->mnt_expire
		// ((kmem_cache#2-oX (struct mount))->mnt_expire)->prev: (kmem_cache#2-oX (struct mount))->mnt_expire

		// mnt->mnt_share: (kmem_cache#2-oX (struct mount))->mnt_share
		// mnt->mnt_share: (kmem_cache#2-oX (struct mount))->mnt_share
		// mnt->mnt_share: (kmem_cache#2-oX (struct mount))->mnt_share
		INIT_LIST_HEAD(&mnt->mnt_share);

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_share)->next: (kmem_cache#2-oX (struct mount))->mnt_share
		// ((kmem_cache#2-oX (struct mount))->mnt_share)->prev: (kmem_cache#2-oX (struct mount))->mnt_share

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_share)->next: (kmem_cache#2-oX (struct mount))->mnt_share
		// ((kmem_cache#2-oX (struct mount))->mnt_share)->prev: (kmem_cache#2-oX (struct mount))->mnt_share

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_share)->next: (kmem_cache#2-oX (struct mount))->mnt_share
		// ((kmem_cache#2-oX (struct mount))->mnt_share)->prev: (kmem_cache#2-oX (struct mount))->mnt_share

		// mnt->mnt_slave_list: (kmem_cache#2-oX (struct mount))->mnt_slave_list
		// mnt->mnt_slave_list: (kmem_cache#2-oX (struct mount))->mnt_slave_list
		// mnt->mnt_slave_list: (kmem_cache#2-oX (struct mount))->mnt_slave_list
		INIT_LIST_HEAD(&mnt->mnt_slave_list);

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->next: (kmem_cache#2-oX (struct mount))->mnt_slave_list
		// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave_list

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->next: (kmem_cache#2-oX (struct mount))->mnt_slave_list
		// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave_list

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->next: (kmem_cache#2-oX (struct mount))->mnt_slave_list
		// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave_list

		// mnt->mnt_slave: (kmem_cache#2-oX (struct mount))->mnt_slave
		// mnt->mnt_slave: (kmem_cache#2-oX (struct mount))->mnt_slave
		// mnt->mnt_slave: (kmem_cache#2-oX (struct mount))->mnt_slave
		INIT_LIST_HEAD(&mnt->mnt_slave);

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_slave)->next: (kmem_cache#2-oX (struct mount))->mnt_slave
		// ((kmem_cache#2-oX (struct mount))->mnt_slave)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_slave)->next: (kmem_cache#2-oX (struct mount))->mnt_slave
		// ((kmem_cache#2-oX (struct mount))->mnt_slave)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave

		// INIT_LIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_slave)->next: (kmem_cache#2-oX (struct mount))->mnt_slave
		// ((kmem_cache#2-oX (struct mount))->mnt_slave)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave

#ifdef CONFIG_FSNOTIFY // CONFIG_FSNOTIFY=y
		// mnt->mnt_fsnotify_marks: (kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks
		// mnt->mnt_fsnotify_marks: (kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks
		// mnt->mnt_fsnotify_marks: (kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks
		INIT_HLIST_HEAD(&mnt->mnt_fsnotify_marks);

		// INIT_HLIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks)->first: NULL

		// INIT_HLIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks)->first: NULL

		// INIT_HLIST_HEAD에서 한일:
		// ((kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks)->first: NULL
#endif
	}

	// mnt: kmem_cache#2-oX (struct mount)
	// mnt: kmem_cache#2-oX (struct mount)
	// mnt: kmem_cache#2-oX (struct mount)
	return mnt;
	// return kmem_cache#2-oX (struct mount)
	// return kmem_cache#2-oX (struct mount)
	// return kmem_cache#2-oX (struct mount)

#ifdef CONFIG_SMP
out_free_devname:
	kfree(mnt->mnt_devname);
#endif
out_free_id:
	mnt_free_id(mnt);
out_free_cache:
	kmem_cache_free(mnt_cache, mnt);
	return NULL;
}

/*
 * Most r/o checks on a fs are for operations that take
 * discrete amounts of time, like a write() or unlink().
 * We must keep track of when those operations start
 * (for permission checks) and when they end, so that
 * we can determine when writes are able to occur to
 * a filesystem.
 */
/*
 * __mnt_is_readonly: check whether a mount is read-only
 * @mnt: the mount to check for its write status
 *
 * This shouldn't be used directly ouside of the VFS.
 * It does not guarantee that the filesystem will stay
 * r/w, just that it is right *now*.  This can not and
 * should not be used in place of IS_RDONLY(inode).
 * mnt_want/drop_write() will _keep_ the filesystem
 * r/w.
 */
int __mnt_is_readonly(struct vfsmount *mnt)
{
	if (mnt->mnt_flags & MNT_READONLY)
		return 1;
	if (mnt->mnt_sb->s_flags & MS_RDONLY)
		return 1;
	return 0;
}
EXPORT_SYMBOL_GPL(__mnt_is_readonly);

static inline void mnt_inc_writers(struct mount *mnt)
{
#ifdef CONFIG_SMP
	this_cpu_inc(mnt->mnt_pcp->mnt_writers);
#else
	mnt->mnt_writers++;
#endif
}

static inline void mnt_dec_writers(struct mount *mnt)
{
#ifdef CONFIG_SMP
	this_cpu_dec(mnt->mnt_pcp->mnt_writers);
#else
	mnt->mnt_writers--;
#endif
}

static unsigned int mnt_get_writers(struct mount *mnt)
{
#ifdef CONFIG_SMP
	unsigned int count = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		count += per_cpu_ptr(mnt->mnt_pcp, cpu)->mnt_writers;
	}

	return count;
#else
	return mnt->mnt_writers;
#endif
}

static int mnt_is_readonly(struct vfsmount *mnt)
{
	if (mnt->mnt_sb->s_readonly_remount)
		return 1;
	/* Order wrt setting s_flags/s_readonly_remount in do_remount() */
	smp_rmb();
	return __mnt_is_readonly(mnt);
}

/*
 * Most r/o & frozen checks on a fs are for operations that take discrete
 * amounts of time, like a write() or unlink().  We must keep track of when
 * those operations start (for permission checks) and when they end, so that we
 * can determine when writes are able to occur to a filesystem.
 */
/**
 * __mnt_want_write - get write access to a mount without freeze protection
 * @m: the mount on which to take a write
 *
 * This tells the low-level filesystem that a write is about to be performed to
 * it, and makes sure that writes are allowed (mnt it read-write) before
 * returning success. This operation does not protect against filesystem being
 * frozen. When the write operation is finished, __mnt_drop_write() must be
 * called. This is effectively a refcount.
 */
int __mnt_want_write(struct vfsmount *m)
{
	struct mount *mnt = real_mount(m);
	int ret = 0;

	preempt_disable();
	mnt_inc_writers(mnt);
	/*
	 * The store to mnt_inc_writers must be visible before we pass
	 * MNT_WRITE_HOLD loop below, so that the slowpath can see our
	 * incremented count after it has set MNT_WRITE_HOLD.
	 */
	smp_mb();
	while (ACCESS_ONCE(mnt->mnt.mnt_flags) & MNT_WRITE_HOLD)
		cpu_relax();
	/*
	 * After the slowpath clears MNT_WRITE_HOLD, mnt_is_readonly will
	 * be set to match its requirements. So we must not load that until
	 * MNT_WRITE_HOLD is cleared.
	 */
	smp_rmb();
	if (mnt_is_readonly(m)) {
		mnt_dec_writers(mnt);
		ret = -EROFS;
	}
	preempt_enable();

	return ret;
}

/**
 * mnt_want_write - get write access to a mount
 * @m: the mount on which to take a write
 *
 * This tells the low-level filesystem that a write is about to be performed to
 * it, and makes sure that writes are allowed (mount is read-write, filesystem
 * is not frozen) before returning success.  When the write operation is
 * finished, mnt_drop_write() must be called.  This is effectively a refcount.
 */
int mnt_want_write(struct vfsmount *m)
{
	int ret;

	sb_start_write(m->mnt_sb);
	ret = __mnt_want_write(m);
	if (ret)
		sb_end_write(m->mnt_sb);
	return ret;
}
EXPORT_SYMBOL_GPL(mnt_want_write);

/**
 * mnt_clone_write - get write access to a mount
 * @mnt: the mount on which to take a write
 *
 * This is effectively like mnt_want_write, except
 * it must only be used to take an extra write reference
 * on a mountpoint that we already know has a write reference
 * on it. This allows some optimisation.
 *
 * After finished, mnt_drop_write must be called as usual to
 * drop the reference.
 */
int mnt_clone_write(struct vfsmount *mnt)
{
	/* superblock may be r/o */
	if (__mnt_is_readonly(mnt))
		return -EROFS;
	preempt_disable();
	mnt_inc_writers(real_mount(mnt));
	preempt_enable();
	return 0;
}
EXPORT_SYMBOL_GPL(mnt_clone_write);

/**
 * __mnt_want_write_file - get write access to a file's mount
 * @file: the file who's mount on which to take a write
 *
 * This is like __mnt_want_write, but it takes a file and can
 * do some optimisations if the file is open for write already
 */
int __mnt_want_write_file(struct file *file)
{
	struct inode *inode = file_inode(file);

	if (!(file->f_mode & FMODE_WRITE) || special_file(inode->i_mode))
		return __mnt_want_write(file->f_path.mnt);
	else
		return mnt_clone_write(file->f_path.mnt);
}

/**
 * mnt_want_write_file - get write access to a file's mount
 * @file: the file who's mount on which to take a write
 *
 * This is like mnt_want_write, but it takes a file and can
 * do some optimisations if the file is open for write already
 */
int mnt_want_write_file(struct file *file)
{
	int ret;

	sb_start_write(file->f_path.mnt->mnt_sb);
	ret = __mnt_want_write_file(file);
	if (ret)
		sb_end_write(file->f_path.mnt->mnt_sb);
	return ret;
}
EXPORT_SYMBOL_GPL(mnt_want_write_file);

/**
 * __mnt_drop_write - give up write access to a mount
 * @mnt: the mount on which to give up write access
 *
 * Tells the low-level filesystem that we are done
 * performing writes to it.  Must be matched with
 * __mnt_want_write() call above.
 */
void __mnt_drop_write(struct vfsmount *mnt)
{
	preempt_disable();
	mnt_dec_writers(real_mount(mnt));
	preempt_enable();
}

/**
 * mnt_drop_write - give up write access to a mount
 * @mnt: the mount on which to give up write access
 *
 * Tells the low-level filesystem that we are done performing writes to it and
 * also allows filesystem to be frozen again.  Must be matched with
 * mnt_want_write() call above.
 */
void mnt_drop_write(struct vfsmount *mnt)
{
	__mnt_drop_write(mnt);
	sb_end_write(mnt->mnt_sb);
}
EXPORT_SYMBOL_GPL(mnt_drop_write);

void __mnt_drop_write_file(struct file *file)
{
	__mnt_drop_write(file->f_path.mnt);
}

void mnt_drop_write_file(struct file *file)
{
	mnt_drop_write(file->f_path.mnt);
}
EXPORT_SYMBOL(mnt_drop_write_file);

static int mnt_make_readonly(struct mount *mnt)
{
	int ret = 0;

	lock_mount_hash();
	mnt->mnt.mnt_flags |= MNT_WRITE_HOLD;
	/*
	 * After storing MNT_WRITE_HOLD, we'll read the counters. This store
	 * should be visible before we do.
	 */
	smp_mb();

	/*
	 * With writers on hold, if this value is zero, then there are
	 * definitely no active writers (although held writers may subsequently
	 * increment the count, they'll have to wait, and decrement it after
	 * seeing MNT_READONLY).
	 *
	 * It is OK to have counter incremented on one CPU and decremented on
	 * another: the sum will add up correctly. The danger would be when we
	 * sum up each counter, if we read a counter before it is incremented,
	 * but then read another CPU's count which it has been subsequently
	 * decremented from -- we would see more decrements than we should.
	 * MNT_WRITE_HOLD protects against this scenario, because
	 * mnt_want_write first increments count, then smp_mb, then spins on
	 * MNT_WRITE_HOLD, so it can't be decremented by another CPU while
	 * we're counting up here.
	 */
	if (mnt_get_writers(mnt) > 0)
		ret = -EBUSY;
	else
		mnt->mnt.mnt_flags |= MNT_READONLY;
	/*
	 * MNT_READONLY must become visible before ~MNT_WRITE_HOLD, so writers
	 * that become unheld will see MNT_READONLY.
	 */
	smp_wmb();
	mnt->mnt.mnt_flags &= ~MNT_WRITE_HOLD;
	unlock_mount_hash();
	return ret;
}

static void __mnt_unmake_readonly(struct mount *mnt)
{
	lock_mount_hash();
	mnt->mnt.mnt_flags &= ~MNT_READONLY;
	unlock_mount_hash();
}

int sb_prepare_remount_readonly(struct super_block *sb)
{
	struct mount *mnt;
	int err = 0;

	/* Racy optimization.  Recheck the counter under MNT_WRITE_HOLD */
	if (atomic_long_read(&sb->s_remove_count))
		return -EBUSY;

	lock_mount_hash();
	list_for_each_entry(mnt, &sb->s_mounts, mnt_instance) {
		if (!(mnt->mnt.mnt_flags & MNT_READONLY)) {
			mnt->mnt.mnt_flags |= MNT_WRITE_HOLD;
			smp_mb();
			if (mnt_get_writers(mnt) > 0) {
				err = -EBUSY;
				break;
			}
		}
	}
	if (!err && atomic_long_read(&sb->s_remove_count))
		err = -EBUSY;

	if (!err) {
		sb->s_readonly_remount = 1;
		smp_wmb();
	}
	list_for_each_entry(mnt, &sb->s_mounts, mnt_instance) {
		if (mnt->mnt.mnt_flags & MNT_WRITE_HOLD)
			mnt->mnt.mnt_flags &= ~MNT_WRITE_HOLD;
	}
	unlock_mount_hash();

	return err;
}

static void free_vfsmnt(struct mount *mnt)
{
	kfree(mnt->mnt_devname);
	mnt_free_id(mnt);
#ifdef CONFIG_SMP
	free_percpu(mnt->mnt_pcp);
#endif
	kmem_cache_free(mnt_cache, mnt);
}

/* call under rcu_read_lock */
bool legitimize_mnt(struct vfsmount *bastard, unsigned seq)
{
	struct mount *mnt;
	if (read_seqretry(&mount_lock, seq))
		return false;
	if (bastard == NULL)
		return true;
	mnt = real_mount(bastard);
	mnt_add_count(mnt, 1);
	if (likely(!read_seqretry(&mount_lock, seq)))
		return true;
	if (bastard->mnt_flags & MNT_SYNC_UMOUNT) {
		mnt_add_count(mnt, -1);
		return false;
	}
	rcu_read_unlock();
	mntput(bastard);
	rcu_read_lock();
	return false;
}

/*
 * find the first mount at @dentry on vfsmount @mnt.
 * call under rcu_read_lock()
 */
struct mount *__lookup_mnt(struct vfsmount *mnt, struct dentry *dentry)
{
	struct hlist_head *head = m_hash(mnt, dentry);
	struct mount *p;

	hlist_for_each_entry_rcu(p, head, mnt_hash)
		if (&p->mnt_parent->mnt == mnt && p->mnt_mountpoint == dentry)
			return p;
	return NULL;
}

/*
 * find the last mount at @dentry on vfsmount @mnt.
 * mount_lock must be held.
 */
struct mount *__lookup_mnt_last(struct vfsmount *mnt, struct dentry *dentry)
{
	struct mount *p, *res;
	res = p = __lookup_mnt(mnt, dentry);
	if (!p)
		goto out;
	hlist_for_each_entry_continue(p, mnt_hash) {
		if (&p->mnt_parent->mnt != mnt || p->mnt_mountpoint != dentry)
			break;
		res = p;
	}
out:
	return res;
}

/*
 * lookup_mnt - Return the first child mount mounted at path
 *
 * "First" means first mounted chronologically.  If you create the
 * following mounts:
 *
 * mount /dev/sda1 /mnt
 * mount /dev/sda2 /mnt
 * mount /dev/sda3 /mnt
 *
 * Then lookup_mnt() on the base /mnt dentry in the root mount will
 * return successively the root dentry and vfsmount of /dev/sda1, then
 * /dev/sda2, then /dev/sda3, then NULL.
 *
 * lookup_mnt takes a reference to the found vfsmount.
 */
struct vfsmount *lookup_mnt(struct path *path)
{
	struct mount *child_mnt;
	struct vfsmount *m;
	unsigned seq;

	rcu_read_lock();
	do {
		seq = read_seqbegin(&mount_lock);
		child_mnt = __lookup_mnt(path->mnt, path->dentry);
		m = child_mnt ? &child_mnt->mnt : NULL;
	} while (!legitimize_mnt(m, seq));
	rcu_read_unlock();
	return m;
}

static struct mountpoint *new_mountpoint(struct dentry *dentry)
{
	struct hlist_head *chain = mp_hash(dentry);
	struct mountpoint *mp;
	int ret;

	hlist_for_each_entry(mp, chain, m_hash) {
		if (mp->m_dentry == dentry) {
			/* might be worth a WARN_ON() */
			if (d_unlinked(dentry))
				return ERR_PTR(-ENOENT);
			mp->m_count++;
			return mp;
		}
	}

	mp = kmalloc(sizeof(struct mountpoint), GFP_KERNEL);
	if (!mp)
		return ERR_PTR(-ENOMEM);

	ret = d_set_mounted(dentry);
	if (ret) {
		kfree(mp);
		return ERR_PTR(ret);
	}

	mp->m_dentry = dentry;
	mp->m_count = 1;
	hlist_add_head(&mp->m_hash, chain);
	return mp;
}

static void put_mountpoint(struct mountpoint *mp)
{
	if (!--mp->m_count) {
		struct dentry *dentry = mp->m_dentry;
		spin_lock(&dentry->d_lock);
		dentry->d_flags &= ~DCACHE_MOUNTED;
		spin_unlock(&dentry->d_lock);
		hlist_del(&mp->m_hash);
		kfree(mp);
	}
}

static inline int check_mnt(struct mount *mnt)
{
	return mnt->mnt_ns == current->nsproxy->mnt_ns;
}

/*
 * vfsmount lock must be held for write
 */
static void touch_mnt_namespace(struct mnt_namespace *ns)
{
	if (ns) {
		ns->event = ++event;
		wake_up_interruptible(&ns->poll);
	}
}

/*
 * vfsmount lock must be held for write
 */
static void __touch_mnt_namespace(struct mnt_namespace *ns)
{
	if (ns && ns->event != event) {
		ns->event = event;
		wake_up_interruptible(&ns->poll);
	}
}

/*
 * vfsmount lock must be held for write
 */
static void detach_mnt(struct mount *mnt, struct path *old_path)
{
	old_path->dentry = mnt->mnt_mountpoint;
	old_path->mnt = &mnt->mnt_parent->mnt;
	mnt->mnt_parent = mnt;
	mnt->mnt_mountpoint = mnt->mnt.mnt_root;
	list_del_init(&mnt->mnt_child);
	hlist_del_init_rcu(&mnt->mnt_hash);
	put_mountpoint(mnt->mnt_mp);
	mnt->mnt_mp = NULL;
}

/*
 * vfsmount lock must be held for write
 */
void mnt_set_mountpoint(struct mount *mnt,
			struct mountpoint *mp,
			struct mount *child_mnt)
{
	mp->m_count++;
	mnt_add_count(mnt, 1);	/* essentially, that's mntget */
	child_mnt->mnt_mountpoint = dget(mp->m_dentry);
	child_mnt->mnt_parent = mnt;
	child_mnt->mnt_mp = mp;
}

/*
 * vfsmount lock must be held for write
 */
static void attach_mnt(struct mount *mnt,
			struct mount *parent,
			struct mountpoint *mp)
{
	mnt_set_mountpoint(parent, mp, mnt);
	hlist_add_head_rcu(&mnt->mnt_hash, m_hash(&parent->mnt, mp->m_dentry));
	list_add_tail(&mnt->mnt_child, &parent->mnt_mounts);
}

/*
 * vfsmount lock must be held for write
 */
static void commit_tree(struct mount *mnt, struct mount *shadows)
{
	struct mount *parent = mnt->mnt_parent;
	struct mount *m;
	LIST_HEAD(head);
	struct mnt_namespace *n = parent->mnt_ns;

	BUG_ON(parent == mnt);

	list_add_tail(&head, &mnt->mnt_list);
	list_for_each_entry(m, &head, mnt_list)
		m->mnt_ns = n;

	list_splice(&head, n->list.prev);

	if (shadows)
		hlist_add_after_rcu(&shadows->mnt_hash, &mnt->mnt_hash);
	else
		hlist_add_head_rcu(&mnt->mnt_hash,
				m_hash(&parent->mnt, mnt->mnt_mountpoint));
	list_add_tail(&mnt->mnt_child, &parent->mnt_mounts);
	touch_mnt_namespace(n);
}

static struct mount *next_mnt(struct mount *p, struct mount *root)
{
	struct list_head *next = p->mnt_mounts.next;
	if (next == &p->mnt_mounts) {
		while (1) {
			if (p == root)
				return NULL;
			next = p->mnt_child.next;
			if (next != &p->mnt_parent->mnt_mounts)
				break;
			p = p->mnt_parent;
		}
	}
	return list_entry(next, struct mount, mnt_child);
}

static struct mount *skip_mnt_tree(struct mount *p)
{
	struct list_head *prev = p->mnt_mounts.prev;
	while (prev != &p->mnt_mounts) {
		p = list_entry(prev, struct mount, mnt_child);
		prev = p->mnt_mounts.prev;
	}
	return p;
}

// ARM10C 20151031
// type: &sysfs_fs_type, MS_KERNMOUNT: 0x400000, type->name: (&sysfs_fs_type)->name: "sysfs", data: NULL
// ARM10C 20160213
// type: &shmem_fs_type, MS_KERNMOUNT: 0x400000, type->name: (&shmem_fs_type)->name: "tmpfs", data: NULL
// ARM10C 20160409
// type: &rootfs_fs_type, 0, "rootfs", NULL
struct vfsmount *
vfs_kern_mount(struct file_system_type *type, int flags, const char *name, void *data)
{
	struct mount *mnt;
	struct dentry *root;

// 2016/04/09 종료
// 2016/04/16 시작

	// type: &sysfs_fs_type
	// type: &shmem_fs_type
	// type: &rootfs_fs_type
	if (!type)
		return ERR_PTR(-ENODEV);

	// name: "sysfs", alloc_vfsmnt("sysfs"): kmem_cache#2-oX (struct mount)
	// name: "tmpfs", alloc_vfsmnt("tmpfs"): kmem_cache#2-oX (struct mount)
	// name: "rootfs", alloc_vfsmnt("rootfs"): kmem_cache#2-oX (struct mount)
	mnt = alloc_vfsmnt(name);
	// mnt: kmem_cache#2-oX (struct mount)
	// mnt: kmem_cache#2-oX (struct mount)
	// mnt: kmem_cache#2-oX (struct mount)

	// alloc_vfsmnt에서 한일:
	// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 6
	// (&(&mnt_id_ida)->idr)->layers: 1
	// ((&(&mnt_id_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&mnt_id_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행 // // (kmem_cache#2-oX (struct mount))->mnt_id: 0
	//
	// mnt_id_start: 1
	//
	// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "sysfs"
	// (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count: 1
	//
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->next: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->pprev: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->next: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->prev: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->next: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->prev: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->next: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->next: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->prev: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->next: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->prev: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->next: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->next: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks)->first: NULL

	// alloc_vfsmnt에서 한일:
	// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 2 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 1번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 1
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함
	//
	// mnt_id_start: 2
	//
	// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "tmpfs"
	// (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count: 1
	//
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->next: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->pprev: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->next: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->prev: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->next: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->prev: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->next: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->next: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->prev: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->next: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->prev: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->next: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->next: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks)->first: NULL

	// alloc_vfsmnt에서 한일:
	// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 2번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 3
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 2) 의 memory 공간을 반환함
	//
	// mnt_id_start: 3
	//
	// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "rootfs"
	// (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count: 1
	//
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->next: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->pprev: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->next: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->prev: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->next: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->prev: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->next: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->next: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->prev: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->next: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->prev: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->next: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->next: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks)->first: NULL

	// mnt: kmem_cache#2-oX (struct mount)
	// mnt: kmem_cache#2-oX (struct mount)
	// mnt: kmem_cache#2-oX (struct mount)
	if (!mnt)
		return ERR_PTR(-ENOMEM);

// 2015/11/07 종료
// 2015/11/14 시작

	// flags: 0x400000, MS_KERNMOUNT: 0x400000
	// flags: 0x400000, MS_KERNMOUNT: 0x400000
	// flags: 0, MS_KERNMOUNT: 0x400000
	if (flags & MS_KERNMOUNT)
		// mnt->mnt.mnt_flags: (kmem_cache#2-oX (struct mount))->mnt.mnt_flags, MNT_INTERNAL: 0x4000
		// mnt->mnt.mnt_flags: (kmem_cache#2-oX (struct mount))->mnt.mnt_flags, MNT_INTERNAL: 0x4000
		mnt->mnt.mnt_flags = MNT_INTERNAL;
		// mnt->mnt.mnt_flags: (kmem_cache#2-oX (struct mount))->mnt.mnt_flags: 0x4000
		// mnt->mnt.mnt_flags: (kmem_cache#2-oX (struct mount))->mnt.mnt_flags: 0x4000

	// type: &sysfs_fs_type, flags: 0x400000, name: "sysfs", data: NULL
	// mount_fs(&sysfs_fs_type, 0x400000, "sysfs", NULL): kmem_cache#5-oX (struct dentry)
	// type: &shmem_fs_type, flags: 0x400000, name: "tmpfs", data: NULL
	// mount_fs(&shmem_fs_type, 0x400000, "tmpfs", NULL): kmem_cache#5-oX (struct dentry)
	// type: &rootfs_fs_type, flags: 0, name: "rootfs", data: NULL
	// mount_fs(&rootfs_fs_type, 0, "rootfs", NULL): kmem_cache#5-oX (struct dentry)
	root = mount_fs(type, flags, name, data);
	// root: kmem_cache#5-oX (struct dentry)
	// root: kmem_cache#5-oX (struct dentry)
	// root: kmem_cache#5-oX (struct dentry)

	// mount_fs에서 한일:
	// struct sysfs_super_info의 메모리 kmem_cache#30-oX (struct sysfs_super_info)를 할당받음
	//
	// (kmem_cache#30-oX (struct sysfs_super_info))->ns[0]: NULL
	//
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
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 6
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// ((&(&unnamed_dev_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&unnamed_dev_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 0
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// unnamed_dev_start: 1
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 0
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_fs_info: kmem_cache#30-oX (struct sysfs_super_info)
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
	//
	// (kmem_cache#25-oX (struct super_block))->s_blocksize: 0x1000
	// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 12
	// (kmem_cache#25-oX (struct super_block))->s_magic: 0x62656572
	// (kmem_cache#25-oX (struct super_block))->s_op: &sysfs_ops
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1
	//
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
	//
	// (&sysfs_root)->s_count: 2
	//
	// (kmem_cache#4-oX (struct inode))->i_private: 2
	// (kmem_cache#4-oX (struct inode))->i_mapping->a_ops: &sysfs_aops
	// (kmem_cache#4-oX (struct inode))->i_mapping->backing_dev_info: &sysfs_backing_dev_info
	// (kmem_cache#4-oX (struct inode))->i_op: &sysfs_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값,
	// (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값,
	// (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_mode: 40447
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
	// (kmem_cache#4-oX (struct inode))->i_op: &sysfs_dir_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_fop: &sysfs_dir_operations
	// (kmem_cache#4-oX (struct inode))->i_state: 0x0
	// memory barrier 수행 (공유자원을 다른 cpu core가 사용할 수 있게 해줌)
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
	// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: &(kmem_cache#5-oX (struct dentry))->d_alias
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->pprev: &(&(kmem_cache#5-oX (struct dentry))->d_alias)
	//
	// (kmem_cache#5-oX (struct dentry))->d_inode: kmem_cache#4-oX (struct inode)
	//
	// 공유자원을 다른 cpu core가 사용할수 있게 함
	// (&(kmem_cache#5-oX (struct dentry))->d_seq)->sequence: 2
	//
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100000
	//
	// (kmem_cache#5-oX (struct dentry))->d_fsdata: &sysfs_root
	// (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#25-oX (struct super_block))->s_d_op: &sysfs_dentry_ops
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x40400000
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_lockref)->count: 1
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x60400000
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0

	// mount_fs에서 한일:
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
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 2 개를 할당 받음
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 1번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// (&(&unnamed_dev_ida)->idr)->id_free: (idr object new 0)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함
	//
	// unnamed_dev_start: 2
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 1
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_type: &shmem_fs_type
	// (kmem_cache#25-oX (struct super_block))->s_id: "tmpfs"
	//
	// list head인 &super_blocks 에 (kmem_cache#25-oX (struct super_block))->s_list을 tail에 추가
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->next: NULL
	// (&(&shmem_fs_type)->fs_supers)->first: &(kmem_cache#25-oX (struct super_block))->s_instances
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->pprev: &(&(&shmem_fs_type)->fs_supers)->first
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->flags: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->nr_deferred: kmem_cache#30-oX
	// head list인 &shrinker_list에 &(&(kmem_cache#25-oX (struct super_block))->s_shrink)->list를 tail로 추가함
	//
	// struct shmem_sb_info 사이즈 만큼의 메모리를 할당 받음 kmem_cache#29-oX (struct shmem_sb_info)
	//
	// (kmem_cache#29-oX (struct shmem_sb_info))->mode: 01777
	// (kmem_cache#29-oX (struct shmem_sb_info))->uid: 0
	// (kmem_cache#29-oX (struct shmem_sb_info))->gid: 0
	// (kmem_cache#25-oX (struct super_block))->s_fs_info: kmem_cache#29-oX (struct shmem_sb_info)
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x80400000
	// (kmem_cache#25-oX (struct super_block))->s_export_op: &shmem_export_ops
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x90400000
	//
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->magic: 0xdead4ead
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->owner: 0xffffffff
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->owner_cpu: 0xffffffff
	//
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list)->next: &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list
	// (&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list)->prev: &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->count: 0
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list를 연결함
	//
	// (kmem_cache#29-oX (struct shmem_sb_info))->free_inodes: 0
	// (kmem_cache#25-oX (struct super_block))->s_maxbytes: 0x7ffffffffff
	// (kmem_cache#25-oX (struct super_block))->s_blocksize: 0x1000
	// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 12
	// (kmem_cache#25-oX (struct super_block))->s_magic: 0x01021994
	// (kmem_cache#25-oX (struct super_block))->s_op: &shmem_ops
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1
	// (kmem_cache#25-oX (struct super_block))->s_xattr: shmem_xattr_handlers
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x90410000
	//
	// struct shmem_sb_info 만큼의 메모리를 할당 받음 kmem_cache#29-oX (struct shmem_sb_info)
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
	// (kmem_cache#4-oX (struct inode))->i_dio_count: 0
	// (&(kmem_cache#4-oX (struct inode))->i_data)->a_ops: &empty_aops
	// (&(kmem_cache#4-oX (struct inode))->i_data)->host: kmem_cache#4-oX (struct inode)
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0x200DA
	// (&(kmem_cache#4-oX (struct inode))->i_data)->private_data: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_data)->backing_dev_info: &default_backing_dev_info
	// (&(kmem_cache#4-oX (struct inode))->i_data)->writeback_index: 0
	// (kmem_cache#4-oX (struct inode))->i_private: NULL
	// (kmem_cache#4-oX (struct inode))->i_mapping: &(kmem_cache#4-oX (struct inode))->i_data
	// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: NULL
	// (kmem_cache#4-oX (struct inode))->i_acl: (void *)(0xFFFFFFFF),
	// (kmem_cache#4-oX (struct inode))->i_default_acl: (void *)(0xFFFFFFFF)
	// (kmem_cache#4-oX (struct inode))->i_fsnotify_mask: 0
	// (kmem_cache#4-oX (struct inode))->i_ino: 1
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#4-oX (struct inode))->i_mode: 0041777
	// (kmem_cache#4-oX (struct inode))->i_blocks: 0
	// (kmem_cache#4-oX (struct inode))->i_mapping->backing_dev_info: &shmem_backing_dev_info
	// (kmem_cache#4-oX (struct inode))->i_atime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_mtime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_ctime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_generation: 현재시간의 sec 값
	// (kmem_cache#4-oX (struct inode))->i_acl: NULL
	// (kmem_cache#4-oX (struct inode))->i_default_acl: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_sb->s_remove_count)->counter: -1
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
	// (kmem_cache#4-oX (struct inode))->i_size: 40
	// (kmem_cache#4-oX (struct inode))->i_op: &shmem_dir_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_fop: &simple_dir_operations
	//
	// (kmem_cache#4-oX (struct inode))->i_state: 0
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
	//
	// head list인 &(kmem_cache#4-oX (struct inode))->i_sb->s_inodes에 &(kmem_cache#4-oX (struct inode))->i_sb_list를 추가함
	//
	// [pcp0] nr_inodes: 1
	//
	// (&shared_last_ino)->counter: 1024
	// [pcp0] last_ino: 1
	//
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->magic: 0xdead4ead
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->owner: 0xffffffff
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->owner_cpu: 0xffffffff
	// (kmem_cache#4-oX (struct shmem_inode_info))->flags: 0x00200000
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->swaplist)->next: &(kmem_cache#4-oX (struct shmem_inode_info))->swaplist
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->swaplist)->prev: &(kmem_cache#4-oX (struct shmem_inode_info))->swaplist
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head)->next: &(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head)->prev: &(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->raw_lock: { { 0 } }
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->magic: 0xdead4ead
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->owner: 0xffffffff
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->owner_cpu: 0xffffffff
	//
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
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
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0xf0410000
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0

	// mount_fs에서 한일:
	// once: 1
	//
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
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0
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
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 2번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	//
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// (&(&unnamed_dev_ida)->idr)->id_free: (idr object new 0)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 3
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 2) 의 memory 공간을 반환함
	//
	// unnamed_dev_start: 3
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 2
	//
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 1
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_type: &rootfs_fs_type
	// (kmem_cache#25-oX (struct super_block))->s_id: "rootfs"
	//
	// list head인 &super_blocks 에 (kmem_cache#25-oX (struct super_block))->s_list을 tail에 추가
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->next: NULL
	// (&(&rootfs_fs_type)->fs_supers)->first: &(kmem_cache#25-oX (struct super_block))->s_instances
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->pprev: &(&(&rootfs_fs_type)->fs_supers)->first
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->flags: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->nr_deferred: kmem_cache#30-oX
	// head list인 &shrinker_list에 &(&(kmem_cache#25-oX (struct super_block))->s_shrink)->list를 tail로 추가함
	//
	// struct shmem_sb_info 사이즈 만큼의 메모리를 할당 받음 kmem_cache#29-oX (struct shmem_sb_info)
	//
	// (kmem_cache#29-oX (struct shmem_sb_info))->mode: 01777
	// (kmem_cache#29-oX (struct shmem_sb_info))->uid: 0
	// (kmem_cache#29-oX (struct shmem_sb_info))->gid: 0
	// (kmem_cache#25-oX (struct super_block))->s_fs_info: kmem_cache#29-oX (struct shmem_sb_info)
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x80400000
	// (kmem_cache#25-oX (struct super_block))->s_export_op: &shmem_export_ops
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x90400000
	//
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->magic: 0xdead4ead
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->owner: 0xffffffff
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->owner_cpu: 0xffffffff
	//
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list)->next: &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list
	// (&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list)->prev: &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->count: 0
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list를 연결함
	//
	// (kmem_cache#29-oX (struct shmem_sb_info))->free_inodes: 0
	// (kmem_cache#25-oX (struct super_block))->s_maxbytes: 0x7ffffffffff
	// (kmem_cache#25-oX (struct super_block))->s_blocksize: 0x1000
	// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 12
	// (kmem_cache#25-oX (struct super_block))->s_magic: 0x01021994
	// (kmem_cache#25-oX (struct super_block))->s_op: &shmem_ops
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1
	// (kmem_cache#25-oX (struct super_block))->s_xattr: shmem_xattr_handlers
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x90410000
	//
	// struct shmem_sb_info 만큼의 메모리를 할당 받음 kmem_cache#29-oX (struct shmem_sb_info)
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
	// (kmem_cache#4-oX (struct inode))->i_dio_count: 0
	// (&(kmem_cache#4-oX (struct inode))->i_data)->a_ops: &empty_aops
	// (&(kmem_cache#4-oX (struct inode))->i_data)->host: kmem_cache#4-oX (struct inode)
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0x200DA
	// (&(kmem_cache#4-oX (struct inode))->i_data)->private_data: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_data)->backing_dev_info: &default_backing_dev_info
	// (&(kmem_cache#4-oX (struct inode))->i_data)->writeback_index: 0
	// (kmem_cache#4-oX (struct inode))->i_private: NULL
	// (kmem_cache#4-oX (struct inode))->i_mapping: &(kmem_cache#4-oX (struct inode))->i_data
	// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: NULL
	// (kmem_cache#4-oX (struct inode))->i_acl: (void *)(0xFFFFFFFF),
	// (kmem_cache#4-oX (struct inode))->i_default_acl: (void *)(0xFFFFFFFF)
	// (kmem_cache#4-oX (struct inode))->i_fsnotify_mask: 0
	// (kmem_cache#4-oX (struct inode))->i_ino: 1
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#4-oX (struct inode))->i_mode: 0041777
	// (kmem_cache#4-oX (struct inode))->i_blocks: 0
	// (kmem_cache#4-oX (struct inode))->i_mapping->backing_dev_info: &shmem_backing_dev_info
	// (kmem_cache#4-oX (struct inode))->i_atime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_mtime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_ctime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_generation: 현재시간의 sec 값
	// (kmem_cache#4-oX (struct inode))->i_acl: NULL
	// (kmem_cache#4-oX (struct inode))->i_default_acl: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_sb->s_remove_count)->counter: -1
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
	// (kmem_cache#4-oX (struct inode))->i_size: 40
	// (kmem_cache#4-oX (struct inode))->i_op: &shmem_dir_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_fop: &simple_dir_operations
	//
	// (kmem_cache#4-oX (struct inode))->i_state: 0
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
	//
	// head list인 &(kmem_cache#4-oX (struct inode))->i_sb->s_inodes에 &(kmem_cache#4-oX (struct inode))->i_sb_list를 추가함
	//
	// [pcp0] nr_inodes: 1
	//
	// (&shared_last_ino)->counter: 1024
	// [pcp0] last_ino: 1
	//
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->magic: 0xdead4ead
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->owner: 0xffffffff
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->owner_cpu: 0xffffffff
	// (kmem_cache#4-oX (struct shmem_inode_info))->flags: 0x00200000
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->swaplist)->next: &(kmem_cache#4-oX (struct shmem_inode_info))->swaplist
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->swaplist)->prev: &(kmem_cache#4-oX (struct shmem_inode_info))->swaplist
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head)->next: &(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head)->prev: &(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->raw_lock: { { 0 } }
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->magic: 0xdead4ead
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->owner: 0xffffffff
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->owner_cpu: 0xffffffff
	//
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
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
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0xf0410000
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0

	// root: kmem_cache#5-oX (struct dentry), IS_ERR(kmem_cache#5-oX (struct dentry)): 0
	// root: kmem_cache#5-oX (struct dentry), IS_ERR(kmem_cache#5-oX (struct dentry)): 0
	// root: kmem_cache#5-oX (struct dentry), IS_ERR(kmem_cache#5-oX (struct dentry)): 0
	if (IS_ERR(root)) {
		free_vfsmnt(mnt);
		return ERR_CAST(root);
	}

	// mnt->mnt.mnt_root: (kmem_cache#2-oX (struct mount))->mnt.mnt_root, root: kmem_cache#5-oX (struct dentry)
	// mnt->mnt.mnt_root: (kmem_cache#2-oX (struct mount))->mnt.mnt_root, root: kmem_cache#5-oX (struct dentry)
	// mnt->mnt.mnt_root: (kmem_cache#2-oX (struct mount))->mnt.mnt_root, root: kmem_cache#5-oX (struct dentry)
	mnt->mnt.mnt_root = root;
	// mnt->mnt.mnt_root: (kmem_cache#2-oX (struct mount))->mnt.mnt_root: kmem_cache#5-oX (struct dentry)
	// mnt->mnt.mnt_root: (kmem_cache#2-oX (struct mount))->mnt.mnt_root: kmem_cache#5-oX (struct dentry)
	// mnt->mnt.mnt_root: (kmem_cache#2-oX (struct mount))->mnt.mnt_root: kmem_cache#5-oX (struct dentry)

	// mnt->mnt.mnt_sb: (kmem_cache#2-oX (struct mount))->mnt.mnt_sb,
	// root->d_sb: (kmem_cache#5-oX (struct dentry))->d_sb: kmem_cache#25-oX (struct super_block)
	// mnt->mnt.mnt_sb: (kmem_cache#2-oX (struct mount))->mnt.mnt_sb,
	// root->d_sb: (kmem_cache#5-oX (struct dentry))->d_sb: kmem_cache#25-oX (struct super_block)
	// mnt->mnt.mnt_sb: (kmem_cache#2-oX (struct mount))->mnt.mnt_sb,
	// root->d_sb: (kmem_cache#5-oX (struct dentry))->d_sb: kmem_cache#25-oX (struct super_block)
	mnt->mnt.mnt_sb = root->d_sb;
	// mnt->mnt.mnt_sb: (kmem_cache#2-oX (struct mount))->mnt.mnt_sb: kmem_cache#25-oX (struct super_block)
	// mnt->mnt.mnt_sb: (kmem_cache#2-oX (struct mount))->mnt.mnt_sb: kmem_cache#25-oX (struct super_block)
	// mnt->mnt.mnt_sb: (kmem_cache#2-oX (struct mount))->mnt.mnt_sb: kmem_cache#25-oX (struct super_block)

	// mnt->mnt_mountpoint: (kmem_cache#2-oX (struct mount))->mnt_mountpoint,
	// mnt->mnt.mnt_root: (kmem_cache#2-oX (struct mount))->mnt.mnt_root: kmem_cache#5-oX (struct dentry)
	// mnt->mnt_mountpoint: (kmem_cache#2-oX (struct mount))->mnt_mountpoint,
	// mnt->mnt.mnt_root: (kmem_cache#2-oX (struct mount))->mnt.mnt_root: kmem_cache#5-oX (struct dentry)
	// mnt->mnt_mountpoint: (kmem_cache#2-oX (struct mount))->mnt_mountpoint,
	// mnt->mnt.mnt_root: (kmem_cache#2-oX (struct mount))->mnt.mnt_root: kmem_cache#5-oX (struct dentry)
	mnt->mnt_mountpoint = mnt->mnt.mnt_root;
	// mnt->mnt_mountpoint: (kmem_cache#2-oX (struct mount))->mnt_mountpoint: kmem_cache#5-oX (struct dentry)
	// mnt->mnt_mountpoint: (kmem_cache#2-oX (struct mount))->mnt_mountpoint: kmem_cache#5-oX (struct dentry)
	// mnt->mnt_mountpoint: (kmem_cache#2-oX (struct mount))->mnt_mountpoint: kmem_cache#5-oX (struct dentry)

	// mnt->mnt_parent: (kmem_cache#2-oX (struct mount))->mnt_parent, mnt: kmem_cache#2-oX (struct mount)
	// mnt->mnt_parent: (kmem_cache#2-oX (struct mount))->mnt_parent, mnt: kmem_cache#2-oX (struct mount)
	// mnt->mnt_parent: (kmem_cache#2-oX (struct mount))->mnt_parent, mnt: kmem_cache#2-oX (struct mount)
	mnt->mnt_parent = mnt;
	// mnt->mnt_parent: (kmem_cache#2-oX (struct mount))->mnt_parent: kmem_cache#2-oX (struct mount)
	// mnt->mnt_parent: (kmem_cache#2-oX (struct mount))->mnt_parent: kmem_cache#2-oX (struct mount)
	// mnt->mnt_parent: (kmem_cache#2-oX (struct mount))->mnt_parent: kmem_cache#2-oX (struct mount)

// 2015/12/19 종료
// 2016/01/09 시작

	lock_mount_hash();

	// lock_mount_hash에서 한일:
	// &(&mount_lock)->lock 을 사용하여 spin lock 수행
	// (&(&mount_lock)->seqcount)->sequence: 1
	// 공유자원을 다른 cpu core가 사용할수 있게 메모리 적용

	// lock_mount_hash에서 한일:
	// &(&mount_lock)->lock 을 사용하여 spin lock 수행
	// (&(&mount_lock)->seqcount)->sequence: 1
	// 공유자원을 다른 cpu core가 사용할수 있게 메모리 적용

	// lock_mount_hash에서 한일:
	// &(&mount_lock)->lock 을 사용하여 spin lock 수행
	// (&(&mount_lock)->seqcount)->sequence: 1
	// 공유자원을 다른 cpu core가 사용할수 있게 메모리 적용

	// &mnt->mnt_instance: &(kmem_cache#2-oX (struct mount))->mnt_instance,
	// root->d_sb: (kmem_cache#5-oX (struct dentry))->d_sb: kmem_cache#25-oX (struct super_block),
	// &root->d_sb->s_mounts: &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts
	// &mnt->mnt_instance: &(kmem_cache#2-oX (struct mount))->mnt_instance,
	// root->d_sb: (kmem_cache#5-oX (struct dentry))->d_sb: kmem_cache#25-oX (struct super_block),
	// &root->d_sb->s_mounts: &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts
	// &mnt->mnt_instance: &(kmem_cache#2-oX (struct mount))->mnt_instance,
	// root->d_sb: (kmem_cache#5-oX (struct dentry))->d_sb: kmem_cache#25-oX (struct super_block),
	// &root->d_sb->s_mounts: &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts
	list_add_tail(&mnt->mnt_instance, &root->d_sb->s_mounts);

	// list_add_tail에서 한일:
	// list head인 &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts에
	// &(kmem_cache#2-oX (struct mount))->mnt_instance를 tail로 연결

	// list_add_tail에서 한일:
	// list head인 &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts에
	// &(kmem_cache#2-oX (struct mount))->mnt_instance를 tail로 연결

	// list_add_tail에서 한일:
	// list head인 &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts에
	// &(kmem_cache#2-oX (struct mount))->mnt_instance를 tail로 연결

	unlock_mount_hash();

	// unlock_mount_hash에서 한일:
	// 공유자원을 다른 cpu core가 사용할수 있게 메모리 적용
	// (&(&mount_lock)->seqcount)->sequence: 2
	// &(&mount_lock)->lock을 사용하여 spin unlock 수행

	// unlock_mount_hash에서 한일:
	// 공유자원을 다른 cpu core가 사용할수 있게 메모리 적용
	// (&(&mount_lock)->seqcount)->sequence: 2
	// &(&mount_lock)->lock을 사용하여 spin unlock 수행

	// unlock_mount_hash에서 한일:
	// 공유자원을 다른 cpu core가 사용할수 있게 메모리 적용
	// (&(&mount_lock)->seqcount)->sequence: 2
	// &(&mount_lock)->lock을 사용하여 spin unlock 수행

	// &mnt->mnt: &(kmem_cache#2-oX (struct mount))->mnt
	// &mnt->mnt: &(kmem_cache#2-oX (struct mount))->mnt
	// &mnt->mnt: &(kmem_cache#2-oX (struct mount))->mnt
	return &mnt->mnt;
	// return &(kmem_cache#2-oX (struct mount))->mnt
	// return &(kmem_cache#2-oX (struct mount))->mnt
	// return &(kmem_cache#2-oX (struct mount))->mnt
}
EXPORT_SYMBOL_GPL(vfs_kern_mount);

static struct mount *clone_mnt(struct mount *old, struct dentry *root,
					int flag)
{
	struct super_block *sb = old->mnt.mnt_sb;
	struct mount *mnt;
	int err;

	mnt = alloc_vfsmnt(old->mnt_devname);
	if (!mnt)
		return ERR_PTR(-ENOMEM);

	if (flag & (CL_SLAVE | CL_PRIVATE | CL_SHARED_TO_SLAVE))
		mnt->mnt_group_id = 0; /* not a peer of original */
	else
		mnt->mnt_group_id = old->mnt_group_id;

	if ((flag & CL_MAKE_SHARED) && !mnt->mnt_group_id) {
		err = mnt_alloc_group_id(mnt);
		if (err)
			goto out_free;
	}

	mnt->mnt.mnt_flags = old->mnt.mnt_flags & ~MNT_WRITE_HOLD;
	/* Don't allow unprivileged users to change mount flags */
	if ((flag & CL_UNPRIVILEGED) && (mnt->mnt.mnt_flags & MNT_READONLY))
		mnt->mnt.mnt_flags |= MNT_LOCK_READONLY;

	/* Don't allow unprivileged users to reveal what is under a mount */
	if ((flag & CL_UNPRIVILEGED) && list_empty(&old->mnt_expire))
		mnt->mnt.mnt_flags |= MNT_LOCKED;

	atomic_inc(&sb->s_active);
	mnt->mnt.mnt_sb = sb;
	mnt->mnt.mnt_root = dget(root);
	mnt->mnt_mountpoint = mnt->mnt.mnt_root;
	mnt->mnt_parent = mnt;
	lock_mount_hash();
	list_add_tail(&mnt->mnt_instance, &sb->s_mounts);
	unlock_mount_hash();

	if ((flag & CL_SLAVE) ||
	    ((flag & CL_SHARED_TO_SLAVE) && IS_MNT_SHARED(old))) {
		list_add(&mnt->mnt_slave, &old->mnt_slave_list);
		mnt->mnt_master = old;
		CLEAR_MNT_SHARED(mnt);
	} else if (!(flag & CL_PRIVATE)) {
		if ((flag & CL_MAKE_SHARED) || IS_MNT_SHARED(old))
			list_add(&mnt->mnt_share, &old->mnt_share);
		if (IS_MNT_SLAVE(old))
			list_add(&mnt->mnt_slave, &old->mnt_slave);
		mnt->mnt_master = old->mnt_master;
	}
	if (flag & CL_MAKE_SHARED)
		set_mnt_shared(mnt);

	/* stick the duplicate mount on the same expiry list
	 * as the original if that was on one */
	if (flag & CL_EXPIRE) {
		if (!list_empty(&old->mnt_expire))
			list_add(&mnt->mnt_expire, &old->mnt_expire);
	}

	return mnt;

 out_free:
	free_vfsmnt(mnt);
	return ERR_PTR(err);
}

static void delayed_free(struct rcu_head *head)
{
	struct mount *mnt = container_of(head, struct mount, mnt_rcu);
	kfree(mnt->mnt_devname);
#ifdef CONFIG_SMP
	free_percpu(mnt->mnt_pcp);
#endif
	kmem_cache_free(mnt_cache, mnt);
}

static void mntput_no_expire(struct mount *mnt)
{
put_again:
	rcu_read_lock();
	mnt_add_count(mnt, -1);
	if (likely(mnt->mnt_ns)) { /* shouldn't be the last one */
		rcu_read_unlock();
		return;
	}
	lock_mount_hash();
	if (mnt_get_count(mnt)) {
		rcu_read_unlock();
		unlock_mount_hash();
		return;
	}
	if (unlikely(mnt->mnt_pinned)) {
		mnt_add_count(mnt, mnt->mnt_pinned + 1);
		mnt->mnt_pinned = 0;
		rcu_read_unlock();
		unlock_mount_hash();
		acct_auto_close_mnt(&mnt->mnt);
		goto put_again;
	}
	if (unlikely(mnt->mnt.mnt_flags & MNT_DOOMED)) {
		rcu_read_unlock();
		unlock_mount_hash();
		return;
	}
	mnt->mnt.mnt_flags |= MNT_DOOMED;
	rcu_read_unlock();

	list_del(&mnt->mnt_instance);
	unlock_mount_hash();

	/*
	 * This probably indicates that somebody messed
	 * up a mnt_want/drop_write() pair.  If this
	 * happens, the filesystem was probably unable
	 * to make r/w->r/o transitions.
	 */
	/*
	 * The locking used to deal with mnt_count decrement provides barriers,
	 * so mnt_get_writers() below is safe.
	 */
	WARN_ON(mnt_get_writers(mnt));
	fsnotify_vfsmount_delete(&mnt->mnt);
	dput(mnt->mnt.mnt_root);
	deactivate_super(mnt->mnt.mnt_sb);
	mnt_free_id(mnt);
	call_rcu(&mnt->mnt_rcu, delayed_free);
}

void mntput(struct vfsmount *mnt)
{
	if (mnt) {
		struct mount *m = real_mount(mnt);
		/* avoid cacheline pingpong, hope gcc doesn't get "smart" */
		if (unlikely(m->mnt_expiry_mark))
			m->mnt_expiry_mark = 0;
		mntput_no_expire(m);
	}
}
EXPORT_SYMBOL(mntput);

struct vfsmount *mntget(struct vfsmount *mnt)
{
	if (mnt)
		mnt_add_count(real_mount(mnt), 1);
	return mnt;
}
EXPORT_SYMBOL(mntget);

void mnt_pin(struct vfsmount *mnt)
{
	lock_mount_hash();
	real_mount(mnt)->mnt_pinned++;
	unlock_mount_hash();
}
EXPORT_SYMBOL(mnt_pin);

void mnt_unpin(struct vfsmount *m)
{
	struct mount *mnt = real_mount(m);
	lock_mount_hash();
	if (mnt->mnt_pinned) {
		mnt_add_count(mnt, 1);
		mnt->mnt_pinned--;
	}
	unlock_mount_hash();
}
EXPORT_SYMBOL(mnt_unpin);

static inline void mangle(struct seq_file *m, const char *s)
{
	seq_escape(m, s, " \t\n\\");
}

/*
 * Simple .show_options callback for filesystems which don't want to
 * implement more complex mount option showing.
 *
 * See also save_mount_options().
 */
int generic_show_options(struct seq_file *m, struct dentry *root)
{
	const char *options;

	rcu_read_lock();
	options = rcu_dereference(root->d_sb->s_options);

	if (options != NULL && options[0]) {
		seq_putc(m, ',');
		mangle(m, options);
	}
	rcu_read_unlock();

	return 0;
}
EXPORT_SYMBOL(generic_show_options);

/*
 * If filesystem uses generic_show_options(), this function should be
 * called from the fill_super() callback.
 *
 * The .remount_fs callback usually needs to be handled in a special
 * way, to make sure, that previous options are not overwritten if the
 * remount fails.
 *
 * Also note, that if the filesystem's .remount_fs function doesn't
 * reset all options to their default value, but changes only newly
 * given options, then the displayed options will not reflect reality
 * any more.
 */
void save_mount_options(struct super_block *sb, char *options)
{
	BUG_ON(sb->s_options);
	rcu_assign_pointer(sb->s_options, kstrdup(options, GFP_KERNEL));
}
EXPORT_SYMBOL(save_mount_options);

void replace_mount_options(struct super_block *sb, char *options)
{
	char *old = sb->s_options;
	rcu_assign_pointer(sb->s_options, options);
	if (old) {
		synchronize_rcu();
		kfree(old);
	}
}
EXPORT_SYMBOL(replace_mount_options);

#ifdef CONFIG_PROC_FS
/* iterator; we want it to have access to namespace_sem, thus here... */
static void *m_start(struct seq_file *m, loff_t *pos)
{
	struct proc_mounts *p = proc_mounts(m);

	down_read(&namespace_sem);
	return seq_list_start(&p->ns->list, *pos);
}

static void *m_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct proc_mounts *p = proc_mounts(m);

	return seq_list_next(v, &p->ns->list, pos);
}

static void m_stop(struct seq_file *m, void *v)
{
	up_read(&namespace_sem);
}

static int m_show(struct seq_file *m, void *v)
{
	struct proc_mounts *p = proc_mounts(m);
	struct mount *r = list_entry(v, struct mount, mnt_list);
	return p->show(m, &r->mnt);
}

const struct seq_operations mounts_op = {
	.start	= m_start,
	.next	= m_next,
	.stop	= m_stop,
	.show	= m_show,
};
#endif  /* CONFIG_PROC_FS */

/**
 * may_umount_tree - check if a mount tree is busy
 * @mnt: root of mount tree
 *
 * This is called to check if a tree of mounts has any
 * open files, pwds, chroots or sub mounts that are
 * busy.
 */
int may_umount_tree(struct vfsmount *m)
{
	struct mount *mnt = real_mount(m);
	int actual_refs = 0;
	int minimum_refs = 0;
	struct mount *p;
	BUG_ON(!m);

	/* write lock needed for mnt_get_count */
	lock_mount_hash();
	for (p = mnt; p; p = next_mnt(p, mnt)) {
		actual_refs += mnt_get_count(p);
		minimum_refs += 2;
	}
	unlock_mount_hash();

	if (actual_refs > minimum_refs)
		return 0;

	return 1;
}

EXPORT_SYMBOL(may_umount_tree);

/**
 * may_umount - check if a mount point is busy
 * @mnt: root of mount
 *
 * This is called to check if a mount point has any
 * open files, pwds, chroots or sub mounts. If the
 * mount has sub mounts this will return busy
 * regardless of whether the sub mounts are busy.
 *
 * Doesn't take quota and stuff into account. IOW, in some cases it will
 * give false negatives. The main reason why it's here is that we need
 * a non-destructive way to look for easily umountable filesystems.
 */
int may_umount(struct vfsmount *mnt)
{
	int ret = 1;
	down_read(&namespace_sem);
	lock_mount_hash();
	if (propagate_mount_busy(real_mount(mnt), 2))
		ret = 0;
	unlock_mount_hash();
	up_read(&namespace_sem);
	return ret;
}

EXPORT_SYMBOL(may_umount);

static HLIST_HEAD(unmounted);	/* protected by namespace_sem */

static void namespace_unlock(void)
{
	struct mount *mnt;
	struct hlist_head head = unmounted;

	if (likely(hlist_empty(&head))) {
		up_write(&namespace_sem);
		return;
	}

	head.first->pprev = &head.first;
	INIT_HLIST_HEAD(&unmounted);

	up_write(&namespace_sem);

	synchronize_rcu();

	while (!hlist_empty(&head)) {
		mnt = hlist_entry(head.first, struct mount, mnt_hash);
		hlist_del_init(&mnt->mnt_hash);
		if (mnt->mnt_ex_mountpoint.mnt)
			path_put(&mnt->mnt_ex_mountpoint);
		mntput(&mnt->mnt);
	}
}

static inline void namespace_lock(void)
{
	down_write(&namespace_sem);
}

/*
 * mount_lock must be held
 * namespace_sem must be held for write
 * how = 0 => just this tree, don't propagate
 * how = 1 => propagate; we know that nobody else has reference to any victims
 * how = 2 => lazy umount
 */
void umount_tree(struct mount *mnt, int how)
{
	HLIST_HEAD(tmp_list);
	struct mount *p;
	struct mount *last = NULL;

	for (p = mnt; p; p = next_mnt(p, mnt)) {
		hlist_del_init_rcu(&p->mnt_hash);
		hlist_add_head(&p->mnt_hash, &tmp_list);
	}

	if (how)
		propagate_umount(&tmp_list);

	hlist_for_each_entry(p, &tmp_list, mnt_hash) {
		list_del_init(&p->mnt_expire);
		list_del_init(&p->mnt_list);
		__touch_mnt_namespace(p->mnt_ns);
		p->mnt_ns = NULL;
		if (how < 2)
			p->mnt.mnt_flags |= MNT_SYNC_UMOUNT;
		list_del_init(&p->mnt_child);
		if (mnt_has_parent(p)) {
			put_mountpoint(p->mnt_mp);
			/* move the reference to mountpoint into ->mnt_ex_mountpoint */
			p->mnt_ex_mountpoint.dentry = p->mnt_mountpoint;
			p->mnt_ex_mountpoint.mnt = &p->mnt_parent->mnt;
			p->mnt_mountpoint = p->mnt.mnt_root;
			p->mnt_parent = p;
			p->mnt_mp = NULL;
		}
		change_mnt_propagation(p, MS_PRIVATE);
		last = p;
	}
	if (last) {
		last->mnt_hash.next = unmounted.first;
		unmounted.first = tmp_list.first;
		unmounted.first->pprev = &unmounted.first;
	}
}

static void shrink_submounts(struct mount *mnt);

static int do_umount(struct mount *mnt, int flags)
{
	struct super_block *sb = mnt->mnt.mnt_sb;
	int retval;

	retval = security_sb_umount(&mnt->mnt, flags);
	if (retval)
		return retval;

	/*
	 * Allow userspace to request a mountpoint be expired rather than
	 * unmounting unconditionally. Unmount only happens if:
	 *  (1) the mark is already set (the mark is cleared by mntput())
	 *  (2) the usage count == 1 [parent vfsmount] + 1 [sys_umount]
	 */
	if (flags & MNT_EXPIRE) {
		if (&mnt->mnt == current->fs->root.mnt ||
		    flags & (MNT_FORCE | MNT_DETACH))
			return -EINVAL;

		/*
		 * probably don't strictly need the lock here if we examined
		 * all race cases, but it's a slowpath.
		 */
		lock_mount_hash();
		if (mnt_get_count(mnt) != 2) {
			unlock_mount_hash();
			return -EBUSY;
		}
		unlock_mount_hash();

		if (!xchg(&mnt->mnt_expiry_mark, 1))
			return -EAGAIN;
	}

	/*
	 * If we may have to abort operations to get out of this
	 * mount, and they will themselves hold resources we must
	 * allow the fs to do things. In the Unix tradition of
	 * 'Gee thats tricky lets do it in userspace' the umount_begin
	 * might fail to complete on the first run through as other tasks
	 * must return, and the like. Thats for the mount program to worry
	 * about for the moment.
	 */

	if (flags & MNT_FORCE && sb->s_op->umount_begin) {
		sb->s_op->umount_begin(sb);
	}

	/*
	 * No sense to grab the lock for this test, but test itself looks
	 * somewhat bogus. Suggestions for better replacement?
	 * Ho-hum... In principle, we might treat that as umount + switch
	 * to rootfs. GC would eventually take care of the old vfsmount.
	 * Actually it makes sense, especially if rootfs would contain a
	 * /reboot - static binary that would close all descriptors and
	 * call reboot(9). Then init(8) could umount root and exec /reboot.
	 */
	if (&mnt->mnt == current->fs->root.mnt && !(flags & MNT_DETACH)) {
		/*
		 * Special case for "unmounting" root ...
		 * we just try to remount it readonly.
		 */
		down_write(&sb->s_umount);
		if (!(sb->s_flags & MS_RDONLY))
			retval = do_remount_sb(sb, MS_RDONLY, NULL, 0);
		up_write(&sb->s_umount);
		return retval;
	}

	namespace_lock();
	lock_mount_hash();
	event++;

	if (flags & MNT_DETACH) {
		if (!list_empty(&mnt->mnt_list))
			umount_tree(mnt, 2);
		retval = 0;
	} else {
		shrink_submounts(mnt);
		retval = -EBUSY;
		if (!propagate_mount_busy(mnt, 2)) {
			if (!list_empty(&mnt->mnt_list))
				umount_tree(mnt, 1);
			retval = 0;
		}
	}
	unlock_mount_hash();
	namespace_unlock();
	return retval;
}

/* 
 * Is the caller allowed to modify his namespace?
 */
static inline bool may_mount(void)
{
	return ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN);
}

/*
 * Now umount can handle mount points as well as block devices.
 * This is important for filesystems which use unnamed block devices.
 *
 * We now support a flag for forced unmount like the other 'big iron'
 * unixes. Our API is identical to OSF/1 to avoid making a mess of AMD
 */

SYSCALL_DEFINE2(umount, char __user *, name, int, flags)
{
	struct path path;
	struct mount *mnt;
	int retval;
	int lookup_flags = 0;

	if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
		return -EINVAL;

	if (!may_mount())
		return -EPERM;

	if (!(flags & UMOUNT_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;

	retval = user_path_mountpoint_at(AT_FDCWD, name, lookup_flags, &path);
	if (retval)
		goto out;
	mnt = real_mount(path.mnt);
	retval = -EINVAL;
	if (path.dentry != path.mnt->mnt_root)
		goto dput_and_out;
	if (!check_mnt(mnt))
		goto dput_and_out;
	if (mnt->mnt.mnt_flags & MNT_LOCKED)
		goto dput_and_out;

	retval = do_umount(mnt, flags);
dput_and_out:
	/* we mustn't call path_put() as that would clear mnt_expiry_mark */
	dput(path.dentry);
	mntput_no_expire(mnt);
out:
	return retval;
}

#ifdef __ARCH_WANT_SYS_OLDUMOUNT

/*
 *	The 2.0 compatible umount. No flags.
 */
SYSCALL_DEFINE1(oldumount, char __user *, name)
{
	return sys_umount(name, 0);
}

#endif

static bool is_mnt_ns_file(struct dentry *dentry)
{
	/* Is this a proxy for a mount namespace? */
	struct inode *inode = dentry->d_inode;
	struct proc_ns *ei;

	if (!proc_ns_inode(inode))
		return false;

	ei = get_proc_ns(inode);
	if (ei->ns_ops != &mntns_operations)
		return false;

	return true;
}

static bool mnt_ns_loop(struct dentry *dentry)
{
	/* Could bind mounting the mount namespace inode cause a
	 * mount namespace loop?
	 */
	struct mnt_namespace *mnt_ns;
	if (!is_mnt_ns_file(dentry))
		return false;

	mnt_ns = get_proc_ns(dentry->d_inode)->ns;
	return current->nsproxy->mnt_ns->seq >= mnt_ns->seq;
}

struct mount *copy_tree(struct mount *mnt, struct dentry *dentry,
					int flag)
{
	struct mount *res, *p, *q, *r, *parent;

	if (!(flag & CL_COPY_UNBINDABLE) && IS_MNT_UNBINDABLE(mnt))
		return ERR_PTR(-EINVAL);

	if (!(flag & CL_COPY_MNT_NS_FILE) && is_mnt_ns_file(dentry))
		return ERR_PTR(-EINVAL);

	res = q = clone_mnt(mnt, dentry, flag);
	if (IS_ERR(q))
		return q;

	q->mnt.mnt_flags &= ~MNT_LOCKED;
	q->mnt_mountpoint = mnt->mnt_mountpoint;

	p = mnt;
	list_for_each_entry(r, &mnt->mnt_mounts, mnt_child) {
		struct mount *s;
		if (!is_subdir(r->mnt_mountpoint, dentry))
			continue;

		for (s = r; s; s = next_mnt(s, r)) {
			if (!(flag & CL_COPY_UNBINDABLE) &&
			    IS_MNT_UNBINDABLE(s)) {
				s = skip_mnt_tree(s);
				continue;
			}
			if (!(flag & CL_COPY_MNT_NS_FILE) &&
			    is_mnt_ns_file(s->mnt.mnt_root)) {
				s = skip_mnt_tree(s);
				continue;
			}
			while (p != s->mnt_parent) {
				p = p->mnt_parent;
				q = q->mnt_parent;
			}
			p = s;
			parent = q;
			q = clone_mnt(p, p->mnt.mnt_root, flag);
			if (IS_ERR(q))
				goto out;
			lock_mount_hash();
			list_add_tail(&q->mnt_list, &res->mnt_list);
			attach_mnt(q, parent, p->mnt_mp);
			unlock_mount_hash();
		}
	}
	return res;
out:
	if (res) {
		lock_mount_hash();
		umount_tree(res, 0);
		unlock_mount_hash();
	}
	return q;
}

/* Caller should check returned pointer for errors */

struct vfsmount *collect_mounts(struct path *path)
{
	struct mount *tree;
	namespace_lock();
	tree = copy_tree(real_mount(path->mnt), path->dentry,
			 CL_COPY_ALL | CL_PRIVATE);
	namespace_unlock();
	if (IS_ERR(tree))
		return ERR_CAST(tree);
	return &tree->mnt;
}

void drop_collected_mounts(struct vfsmount *mnt)
{
	namespace_lock();
	lock_mount_hash();
	umount_tree(real_mount(mnt), 0);
	unlock_mount_hash();
	namespace_unlock();
}

int iterate_mounts(int (*f)(struct vfsmount *, void *), void *arg,
		   struct vfsmount *root)
{
	struct mount *mnt;
	int res = f(root, arg);
	if (res)
		return res;
	list_for_each_entry(mnt, &real_mount(root)->mnt_list, mnt_list) {
		res = f(&mnt->mnt, arg);
		if (res)
			return res;
	}
	return 0;
}

static void cleanup_group_ids(struct mount *mnt, struct mount *end)
{
	struct mount *p;

	for (p = mnt; p != end; p = next_mnt(p, mnt)) {
		if (p->mnt_group_id && !IS_MNT_SHARED(p))
			mnt_release_group_id(p);
	}
}

static int invent_group_ids(struct mount *mnt, bool recurse)
{
	struct mount *p;

	for (p = mnt; p; p = recurse ? next_mnt(p, mnt) : NULL) {
		if (!p->mnt_group_id && !IS_MNT_SHARED(p)) {
			int err = mnt_alloc_group_id(p);
			if (err) {
				cleanup_group_ids(mnt, p);
				return err;
			}
		}
	}

	return 0;
}

/*
 *  @source_mnt : mount tree to be attached
 *  @nd         : place the mount tree @source_mnt is attached
 *  @parent_nd  : if non-null, detach the source_mnt from its parent and
 *  		   store the parent mount and mountpoint dentry.
 *  		   (done when source_mnt is moved)
 *
 *  NOTE: in the table below explains the semantics when a source mount
 *  of a given type is attached to a destination mount of a given type.
 * ---------------------------------------------------------------------------
 * |         BIND MOUNT OPERATION                                            |
 * |**************************************************************************
 * | source-->| shared        |       private  |       slave    | unbindable |
 * | dest     |               |                |                |            |
 * |   |      |               |                |                |            |
 * |   v      |               |                |                |            |
 * |**************************************************************************
 * |  shared  | shared (++)   |     shared (+) |     shared(+++)|  invalid   |
 * |          |               |                |                |            |
 * |non-shared| shared (+)    |      private   |      slave (*) |  invalid   |
 * ***************************************************************************
 * A bind operation clones the source mount and mounts the clone on the
 * destination mount.
 *
 * (++)  the cloned mount is propagated to all the mounts in the propagation
 * 	 tree of the destination mount and the cloned mount is added to
 * 	 the peer group of the source mount.
 * (+)   the cloned mount is created under the destination mount and is marked
 *       as shared. The cloned mount is added to the peer group of the source
 *       mount.
 * (+++) the mount is propagated to all the mounts in the propagation tree
 *       of the destination mount and the cloned mount is made slave
 *       of the same master as that of the source mount. The cloned mount
 *       is marked as 'shared and slave'.
 * (*)   the cloned mount is made a slave of the same master as that of the
 * 	 source mount.
 *
 * ---------------------------------------------------------------------------
 * |         		MOVE MOUNT OPERATION                                 |
 * |**************************************************************************
 * | source-->| shared        |       private  |       slave    | unbindable |
 * | dest     |               |                |                |            |
 * |   |      |               |                |                |            |
 * |   v      |               |                |                |            |
 * |**************************************************************************
 * |  shared  | shared (+)    |     shared (+) |    shared(+++) |  invalid   |
 * |          |               |                |                |            |
 * |non-shared| shared (+*)   |      private   |    slave (*)   | unbindable |
 * ***************************************************************************
 *
 * (+)  the mount is moved to the destination. And is then propagated to
 * 	all the mounts in the propagation tree of the destination mount.
 * (+*)  the mount is moved to the destination.
 * (+++)  the mount is moved to the destination and is then propagated to
 * 	all the mounts belonging to the destination mount's propagation tree.
 * 	the mount is marked as 'shared and slave'.
 * (*)	the mount continues to be a slave at the new location.
 *
 * if the source mount is a tree, the operations explained above is
 * applied to each mount in the tree.
 * Must be called without spinlocks held, since this function can sleep
 * in allocations.
 */
static int attach_recursive_mnt(struct mount *source_mnt,
			struct mount *dest_mnt,
			struct mountpoint *dest_mp,
			struct path *parent_path)
{
	HLIST_HEAD(tree_list);
	struct mount *child, *p;
	struct hlist_node *n;
	int err;

	if (IS_MNT_SHARED(dest_mnt)) {
		err = invent_group_ids(source_mnt, true);
		if (err)
			goto out;
		err = propagate_mnt(dest_mnt, dest_mp, source_mnt, &tree_list);
		if (err)
			goto out_cleanup_ids;
		lock_mount_hash();
		for (p = source_mnt; p; p = next_mnt(p, source_mnt))
			set_mnt_shared(p);
	} else {
		lock_mount_hash();
	}
	if (parent_path) {
		detach_mnt(source_mnt, parent_path);
		attach_mnt(source_mnt, dest_mnt, dest_mp);
		touch_mnt_namespace(source_mnt->mnt_ns);
	} else {
		mnt_set_mountpoint(dest_mnt, dest_mp, source_mnt);
		commit_tree(source_mnt, NULL);
	}

	hlist_for_each_entry_safe(child, n, &tree_list, mnt_hash) {
		struct mount *q;
		hlist_del_init(&child->mnt_hash);
		q = __lookup_mnt_last(&child->mnt_parent->mnt,
				      child->mnt_mountpoint);
		commit_tree(child, q);
	}
	unlock_mount_hash();

	return 0;

 out_cleanup_ids:
	cleanup_group_ids(source_mnt, NULL);
 out:
	return err;
}

static struct mountpoint *lock_mount(struct path *path)
{
	struct vfsmount *mnt;
	struct dentry *dentry = path->dentry;
retry:
	mutex_lock(&dentry->d_inode->i_mutex);
	if (unlikely(cant_mount(dentry))) {
		mutex_unlock(&dentry->d_inode->i_mutex);
		return ERR_PTR(-ENOENT);
	}
	namespace_lock();
	mnt = lookup_mnt(path);
	if (likely(!mnt)) {
		struct mountpoint *mp = new_mountpoint(dentry);
		if (IS_ERR(mp)) {
			namespace_unlock();
			mutex_unlock(&dentry->d_inode->i_mutex);
			return mp;
		}
		return mp;
	}
	namespace_unlock();
	mutex_unlock(&path->dentry->d_inode->i_mutex);
	path_put(path);
	path->mnt = mnt;
	dentry = path->dentry = dget(mnt->mnt_root);
	goto retry;
}

static void unlock_mount(struct mountpoint *where)
{
	struct dentry *dentry = where->m_dentry;
	put_mountpoint(where);
	namespace_unlock();
	mutex_unlock(&dentry->d_inode->i_mutex);
}

static int graft_tree(struct mount *mnt, struct mount *p, struct mountpoint *mp)
{
	if (mnt->mnt.mnt_sb->s_flags & MS_NOUSER)
		return -EINVAL;

	if (S_ISDIR(mp->m_dentry->d_inode->i_mode) !=
	      S_ISDIR(mnt->mnt.mnt_root->d_inode->i_mode))
		return -ENOTDIR;

	return attach_recursive_mnt(mnt, p, mp, NULL);
}

/*
 * Sanity check the flags to change_mnt_propagation.
 */

static int flags_to_propagation_type(int flags)
{
	int type = flags & ~(MS_REC | MS_SILENT);

	/* Fail if any non-propagation flags are set */
	if (type & ~(MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
		return 0;
	/* Only one propagation flag should be set */
	if (!is_power_of_2(type))
		return 0;
	return type;
}

/*
 * recursively change the type of the mountpoint.
 */
static int do_change_type(struct path *path, int flag)
{
	struct mount *m;
	struct mount *mnt = real_mount(path->mnt);
	int recurse = flag & MS_REC;
	int type;
	int err = 0;

	if (path->dentry != path->mnt->mnt_root)
		return -EINVAL;

	type = flags_to_propagation_type(flag);
	if (!type)
		return -EINVAL;

	namespace_lock();
	if (type == MS_SHARED) {
		err = invent_group_ids(mnt, recurse);
		if (err)
			goto out_unlock;
	}

	lock_mount_hash();
	for (m = mnt; m; m = (recurse ? next_mnt(m, mnt) : NULL))
		change_mnt_propagation(m, type);
	unlock_mount_hash();

 out_unlock:
	namespace_unlock();
	return err;
}

static bool has_locked_children(struct mount *mnt, struct dentry *dentry)
{
	struct mount *child;
	list_for_each_entry(child, &mnt->mnt_mounts, mnt_child) {
		if (!is_subdir(child->mnt_mountpoint, dentry))
			continue;

		if (child->mnt.mnt_flags & MNT_LOCKED)
			return true;
	}
	return false;
}

/*
 * do loopback mount.
 */
static int do_loopback(struct path *path, const char *old_name,
				int recurse)
{
	struct path old_path;
	struct mount *mnt = NULL, *old, *parent;
	struct mountpoint *mp;
	int err;
	if (!old_name || !*old_name)
		return -EINVAL;
	err = kern_path(old_name, LOOKUP_FOLLOW|LOOKUP_AUTOMOUNT, &old_path);
	if (err)
		return err;

	err = -EINVAL;
	if (mnt_ns_loop(old_path.dentry))
		goto out; 

	mp = lock_mount(path);
	err = PTR_ERR(mp);
	if (IS_ERR(mp))
		goto out;

	old = real_mount(old_path.mnt);
	parent = real_mount(path->mnt);

	err = -EINVAL;
	if (IS_MNT_UNBINDABLE(old))
		goto out2;

	if (!check_mnt(parent) || !check_mnt(old))
		goto out2;

	if (!recurse && has_locked_children(old, old_path.dentry))
		goto out2;

	if (recurse)
		mnt = copy_tree(old, old_path.dentry, CL_COPY_MNT_NS_FILE);
	else
		mnt = clone_mnt(old, old_path.dentry, 0);

	if (IS_ERR(mnt)) {
		err = PTR_ERR(mnt);
		goto out2;
	}

	mnt->mnt.mnt_flags &= ~MNT_LOCKED;

	err = graft_tree(mnt, parent, mp);
	if (err) {
		lock_mount_hash();
		umount_tree(mnt, 0);
		unlock_mount_hash();
	}
out2:
	unlock_mount(mp);
out:
	path_put(&old_path);
	return err;
}

static int change_mount_flags(struct vfsmount *mnt, int ms_flags)
{
	int error = 0;
	int readonly_request = 0;

	if (ms_flags & MS_RDONLY)
		readonly_request = 1;
	if (readonly_request == __mnt_is_readonly(mnt))
		return 0;

	if (mnt->mnt_flags & MNT_LOCK_READONLY)
		return -EPERM;

	if (readonly_request)
		error = mnt_make_readonly(real_mount(mnt));
	else
		__mnt_unmake_readonly(real_mount(mnt));
	return error;
}

/*
 * change filesystem flags. dir should be a physical root of filesystem.
 * If you've mounted a non-root directory somewhere and want to do remount
 * on it - tough luck.
 */
static int do_remount(struct path *path, int flags, int mnt_flags,
		      void *data)
{
	int err;
	struct super_block *sb = path->mnt->mnt_sb;
	struct mount *mnt = real_mount(path->mnt);

	if (!check_mnt(mnt))
		return -EINVAL;

	if (path->dentry != path->mnt->mnt_root)
		return -EINVAL;

	err = security_sb_remount(sb, data);
	if (err)
		return err;

	down_write(&sb->s_umount);
	if (flags & MS_BIND)
		err = change_mount_flags(path->mnt, flags);
	else if (!capable(CAP_SYS_ADMIN))
		err = -EPERM;
	else
		err = do_remount_sb(sb, flags, data, 0);
	if (!err) {
		lock_mount_hash();
		mnt_flags |= mnt->mnt.mnt_flags & MNT_PROPAGATION_MASK;
		mnt->mnt.mnt_flags = mnt_flags;
		touch_mnt_namespace(mnt->mnt_ns);
		unlock_mount_hash();
	}
	up_write(&sb->s_umount);
	return err;
}

static inline int tree_contains_unbindable(struct mount *mnt)
{
	struct mount *p;
	for (p = mnt; p; p = next_mnt(p, mnt)) {
		if (IS_MNT_UNBINDABLE(p))
			return 1;
	}
	return 0;
}

static int do_move_mount(struct path *path, const char *old_name)
{
	struct path old_path, parent_path;
	struct mount *p;
	struct mount *old;
	struct mountpoint *mp;
	int err;
	if (!old_name || !*old_name)
		return -EINVAL;
	err = kern_path(old_name, LOOKUP_FOLLOW, &old_path);
	if (err)
		return err;

	mp = lock_mount(path);
	err = PTR_ERR(mp);
	if (IS_ERR(mp))
		goto out;

	old = real_mount(old_path.mnt);
	p = real_mount(path->mnt);

	err = -EINVAL;
	if (!check_mnt(p) || !check_mnt(old))
		goto out1;

	if (old->mnt.mnt_flags & MNT_LOCKED)
		goto out1;

	err = -EINVAL;
	if (old_path.dentry != old_path.mnt->mnt_root)
		goto out1;

	if (!mnt_has_parent(old))
		goto out1;

	if (S_ISDIR(path->dentry->d_inode->i_mode) !=
	      S_ISDIR(old_path.dentry->d_inode->i_mode))
		goto out1;
	/*
	 * Don't move a mount residing in a shared parent.
	 */
	if (IS_MNT_SHARED(old->mnt_parent))
		goto out1;
	/*
	 * Don't move a mount tree containing unbindable mounts to a destination
	 * mount which is shared.
	 */
	if (IS_MNT_SHARED(p) && tree_contains_unbindable(old))
		goto out1;
	err = -ELOOP;
	for (; mnt_has_parent(p); p = p->mnt_parent)
		if (p == old)
			goto out1;

	err = attach_recursive_mnt(old, real_mount(path->mnt), mp, &parent_path);
	if (err)
		goto out1;

	/* if the mount is moved, it should no longer be expire
	 * automatically */
	list_del_init(&old->mnt_expire);
out1:
	unlock_mount(mp);
out:
	if (!err)
		path_put(&parent_path);
	path_put(&old_path);
	return err;
}

static struct vfsmount *fs_set_subtype(struct vfsmount *mnt, const char *fstype)
{
	int err;
	const char *subtype = strchr(fstype, '.');
	if (subtype) {
		subtype++;
		err = -EINVAL;
		if (!subtype[0])
			goto err;
	} else
		subtype = "";

	mnt->mnt_sb->s_subtype = kstrdup(subtype, GFP_KERNEL);
	err = -ENOMEM;
	if (!mnt->mnt_sb->s_subtype)
		goto err;
	return mnt;

 err:
	mntput(mnt);
	return ERR_PTR(err);
}

/*
 * add a mount into a namespace's mount tree
 */
static int do_add_mount(struct mount *newmnt, struct path *path, int mnt_flags)
{
	struct mountpoint *mp;
	struct mount *parent;
	int err;

	mnt_flags &= ~(MNT_SHARED | MNT_WRITE_HOLD | MNT_INTERNAL | MNT_DOOMED | MNT_SYNC_UMOUNT);

	mp = lock_mount(path);
	if (IS_ERR(mp))
		return PTR_ERR(mp);

	parent = real_mount(path->mnt);
	err = -EINVAL;
	if (unlikely(!check_mnt(parent))) {
		/* that's acceptable only for automounts done in private ns */
		if (!(mnt_flags & MNT_SHRINKABLE))
			goto unlock;
		/* ... and for those we'd better have mountpoint still alive */
		if (!parent->mnt_ns)
			goto unlock;
	}

	/* Refuse the same filesystem on the same mount point */
	err = -EBUSY;
	if (path->mnt->mnt_sb == newmnt->mnt.mnt_sb &&
	    path->mnt->mnt_root == path->dentry)
		goto unlock;

	err = -EINVAL;
	if (S_ISLNK(newmnt->mnt.mnt_root->d_inode->i_mode))
		goto unlock;

	newmnt->mnt.mnt_flags = mnt_flags;
	err = graft_tree(newmnt, parent, mp);

unlock:
	unlock_mount(mp);
	return err;
}

/*
 * create a new mount for userspace and request it to be added into the
 * namespace's tree
 */
static int do_new_mount(struct path *path, const char *fstype, int flags,
			int mnt_flags, const char *name, void *data)
{
	struct file_system_type *type;
	struct user_namespace *user_ns = current->nsproxy->mnt_ns->user_ns;
	struct vfsmount *mnt;
	int err;

	if (!fstype)
		return -EINVAL;

	type = get_fs_type(fstype);
	if (!type)
		return -ENODEV;

	if (user_ns != &init_user_ns) {
		if (!(type->fs_flags & FS_USERNS_MOUNT)) {
			put_filesystem(type);
			return -EPERM;
		}
		/* Only in special cases allow devices from mounts
		 * created outside the initial user namespace.
		 */
		if (!(type->fs_flags & FS_USERNS_DEV_MOUNT)) {
			flags |= MS_NODEV;
			mnt_flags |= MNT_NODEV;
		}
	}

	mnt = vfs_kern_mount(type, flags, name, data);
	if (!IS_ERR(mnt) && (type->fs_flags & FS_HAS_SUBTYPE) &&
	    !mnt->mnt_sb->s_subtype)
		mnt = fs_set_subtype(mnt, fstype);

	put_filesystem(type);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	err = do_add_mount(real_mount(mnt), path, mnt_flags);
	if (err)
		mntput(mnt);
	return err;
}

int finish_automount(struct vfsmount *m, struct path *path)
{
	struct mount *mnt = real_mount(m);
	int err;
	/* The new mount record should have at least 2 refs to prevent it being
	 * expired before we get a chance to add it
	 */
	BUG_ON(mnt_get_count(mnt) < 2);

	if (m->mnt_sb == path->mnt->mnt_sb &&
	    m->mnt_root == path->dentry) {
		err = -ELOOP;
		goto fail;
	}

	err = do_add_mount(mnt, path, path->mnt->mnt_flags | MNT_SHRINKABLE);
	if (!err)
		return 0;
fail:
	/* remove m from any expiration list it may be on */
	if (!list_empty(&mnt->mnt_expire)) {
		namespace_lock();
		list_del_init(&mnt->mnt_expire);
		namespace_unlock();
	}
	mntput(m);
	mntput(m);
	return err;
}

/**
 * mnt_set_expiry - Put a mount on an expiration list
 * @mnt: The mount to list.
 * @expiry_list: The list to add the mount to.
 */
void mnt_set_expiry(struct vfsmount *mnt, struct list_head *expiry_list)
{
	namespace_lock();

	list_add_tail(&real_mount(mnt)->mnt_expire, expiry_list);

	namespace_unlock();
}
EXPORT_SYMBOL(mnt_set_expiry);

/*
 * process a list of expirable mountpoints with the intent of discarding any
 * mountpoints that aren't in use and haven't been touched since last we came
 * here
 */
void mark_mounts_for_expiry(struct list_head *mounts)
{
	struct mount *mnt, *next;
	LIST_HEAD(graveyard);

	if (list_empty(mounts))
		return;

	namespace_lock();
	lock_mount_hash();

	/* extract from the expiration list every vfsmount that matches the
	 * following criteria:
	 * - only referenced by its parent vfsmount
	 * - still marked for expiry (marked on the last call here; marks are
	 *   cleared by mntput())
	 */
	list_for_each_entry_safe(mnt, next, mounts, mnt_expire) {
		if (!xchg(&mnt->mnt_expiry_mark, 1) ||
			propagate_mount_busy(mnt, 1))
			continue;
		list_move(&mnt->mnt_expire, &graveyard);
	}
	while (!list_empty(&graveyard)) {
		mnt = list_first_entry(&graveyard, struct mount, mnt_expire);
		touch_mnt_namespace(mnt->mnt_ns);
		umount_tree(mnt, 1);
	}
	unlock_mount_hash();
	namespace_unlock();
}

EXPORT_SYMBOL_GPL(mark_mounts_for_expiry);

/*
 * Ripoff of 'select_parent()'
 *
 * search the list of submounts for a given mountpoint, and move any
 * shrinkable submounts to the 'graveyard' list.
 */
static int select_submounts(struct mount *parent, struct list_head *graveyard)
{
	struct mount *this_parent = parent;
	struct list_head *next;
	int found = 0;

repeat:
	next = this_parent->mnt_mounts.next;
resume:
	while (next != &this_parent->mnt_mounts) {
		struct list_head *tmp = next;
		struct mount *mnt = list_entry(tmp, struct mount, mnt_child);

		next = tmp->next;
		if (!(mnt->mnt.mnt_flags & MNT_SHRINKABLE))
			continue;
		/*
		 * Descend a level if the d_mounts list is non-empty.
		 */
		if (!list_empty(&mnt->mnt_mounts)) {
			this_parent = mnt;
			goto repeat;
		}

		if (!propagate_mount_busy(mnt, 1)) {
			list_move_tail(&mnt->mnt_expire, graveyard);
			found++;
		}
	}
	/*
	 * All done at this level ... ascend and resume the search
	 */
	if (this_parent != parent) {
		next = this_parent->mnt_child.next;
		this_parent = this_parent->mnt_parent;
		goto resume;
	}
	return found;
}

/*
 * process a list of expirable mountpoints with the intent of discarding any
 * submounts of a specific parent mountpoint
 *
 * mount_lock must be held for write
 */
static void shrink_submounts(struct mount *mnt)
{
	LIST_HEAD(graveyard);
	struct mount *m;

	/* extract submounts of 'mountpoint' from the expiration list */
	while (select_submounts(mnt, &graveyard)) {
		while (!list_empty(&graveyard)) {
			m = list_first_entry(&graveyard, struct mount,
						mnt_expire);
			touch_mnt_namespace(m->mnt_ns);
			umount_tree(m, 1);
		}
	}
}

/*
 * Some copy_from_user() implementations do not return the exact number of
 * bytes remaining to copy on a fault.  But copy_mount_options() requires that.
 * Note that this function differs from copy_from_user() in that it will oops
 * on bad values of `to', rather than returning a short copy.
 */
static long exact_copy_from_user(void *to, const void __user * from,
				 unsigned long n)
{
	char *t = to;
	const char __user *f = from;
	char c;

	if (!access_ok(VERIFY_READ, from, n))
		return n;

	while (n) {
		if (__get_user(c, f)) {
			memset(t, 0, n);
			break;
		}
		*t++ = c;
		f++;
		n--;
	}
	return n;
}

int copy_mount_options(const void __user * data, unsigned long *where)
{
	int i;
	unsigned long page;
	unsigned long size;

	*where = 0;
	if (!data)
		return 0;

	if (!(page = __get_free_page(GFP_KERNEL)))
		return -ENOMEM;

	/* We only care that *some* data at the address the user
	 * gave us is valid.  Just in case, we'll zero
	 * the remainder of the page.
	 */
	/* copy_from_user cannot cross TASK_SIZE ! */
	size = TASK_SIZE - (unsigned long)data;
	if (size > PAGE_SIZE)
		size = PAGE_SIZE;

	i = size - exact_copy_from_user((void *)page, data, size);
	if (!i) {
		free_page(page);
		return -EFAULT;
	}
	if (i != PAGE_SIZE)
		memset((char *)page + i, 0, PAGE_SIZE - i);
	*where = page;
	return 0;
}

int copy_mount_string(const void __user *data, char **where)
{
	char *tmp;

	if (!data) {
		*where = NULL;
		return 0;
	}

	tmp = strndup_user(data, PAGE_SIZE);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	*where = tmp;
	return 0;
}

/*
 * Flags is a 32-bit value that allows up to 31 non-fs dependent flags to
 * be given to the mount() call (ie: read-only, no-dev, no-suid etc).
 *
 * data is a (void *) that can point to any structure up to
 * PAGE_SIZE-1 bytes, which can contain arbitrary fs-dependent
 * information (or be NULL).
 *
 * Pre-0.97 versions of mount() didn't have a flags word.
 * When the flags word was introduced its top half was required
 * to have the magic value 0xC0ED, and this remained so until 2.4.0-test9.
 * Therefore, if this magic number is present, it carries no information
 * and must be discarded.
 */
long do_mount(const char *dev_name, const char *dir_name,
		const char *type_page, unsigned long flags, void *data_page)
{
	struct path path;
	int retval = 0;
	int mnt_flags = 0;

	/* Discard magic */
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;

	/* Basic sanity checks */

	if (!dir_name || !*dir_name || !memchr(dir_name, 0, PAGE_SIZE))
		return -EINVAL;

	if (data_page)
		((char *)data_page)[PAGE_SIZE - 1] = 0;

	/* ... and get the mountpoint */
	retval = kern_path(dir_name, LOOKUP_FOLLOW, &path);
	if (retval)
		return retval;

	retval = security_sb_mount(dev_name, &path,
				   type_page, flags, data_page);
	if (!retval && !may_mount())
		retval = -EPERM;
	if (retval)
		goto dput_out;

	/* Default to relatime unless overriden */
	if (!(flags & MS_NOATIME))
		mnt_flags |= MNT_RELATIME;

	/* Separate the per-mountpoint flags */
	if (flags & MS_NOSUID)
		mnt_flags |= MNT_NOSUID;
	if (flags & MS_NODEV)
		mnt_flags |= MNT_NODEV;
	if (flags & MS_NOEXEC)
		mnt_flags |= MNT_NOEXEC;
	if (flags & MS_NOATIME)
		mnt_flags |= MNT_NOATIME;
	if (flags & MS_NODIRATIME)
		mnt_flags |= MNT_NODIRATIME;
	if (flags & MS_STRICTATIME)
		mnt_flags &= ~(MNT_RELATIME | MNT_NOATIME);
	if (flags & MS_RDONLY)
		mnt_flags |= MNT_READONLY;

	flags &= ~(MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_ACTIVE | MS_BORN |
		   MS_NOATIME | MS_NODIRATIME | MS_RELATIME| MS_KERNMOUNT |
		   MS_STRICTATIME);

	if (flags & MS_REMOUNT)
		retval = do_remount(&path, flags & ~MS_REMOUNT, mnt_flags,
				    data_page);
	else if (flags & MS_BIND)
		retval = do_loopback(&path, dev_name, flags & MS_REC);
	else if (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
		retval = do_change_type(&path, flags);
	else if (flags & MS_MOVE)
		retval = do_move_mount(&path, dev_name);
	else
		retval = do_new_mount(&path, type_page, flags, mnt_flags,
				      dev_name, data_page);
dput_out:
	path_put(&path);
	return retval;
}

static void free_mnt_ns(struct mnt_namespace *ns)
{
	proc_free_inum(ns->proc_inum);
	put_user_ns(ns->user_ns);
	kfree(ns);
}

/*
 * Assign a sequence number so we can detect when we attempt to bind
 * mount a reference to an older mount namespace into the current
 * mount namespace, preventing reference counting loops.  A 64bit
 * number incrementing at 10Ghz will take 12,427 years to wrap which
 * is effectively never, so we can ignore the possibility.
 */
// ARM10C 20160514
// ATOMIC64_INIT(1): { (1) }
// mnt_ns_seq.counter: 1
static atomic64_t mnt_ns_seq = ATOMIC64_INIT(1);

// ARM10C 20160514
// &init_user_ns
static struct mnt_namespace *alloc_mnt_ns(struct user_namespace *user_ns)
{
	struct mnt_namespace *new_ns;
	int ret;

	// sizeof(struct mnt_namespace): 60 bytes, GFP_KERNEL: 0xD0
	// kmalloc(60,  GFP_KERNEL: 0xD0): kmem_cache#30-oX
	new_ns = kmalloc(sizeof(struct mnt_namespace), GFP_KERNEL);
	// new_ns: kmem_cache#30-oX (struct mnt_namespace)

	// new_ns: kmem_cache#30-oX (struct mnt_namespace)
	if (!new_ns)
		return ERR_PTR(-ENOMEM);

	// &new_ns->proc_inum: &(kmem_cache#30-oX (struct mnt_namespace))->proc_inum
	// proc_alloc_inum(&(kmem_cache#30-oX (struct mnt_namespace))->proc_inum): 0
	ret = proc_alloc_inum(&new_ns->proc_inum);
	// ret: 0

	// proc_alloc_inum에서 한일:
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
	//
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
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// (kmem_cache#30-oX (struct mnt_namespace))->proc_inum: 0xF0000000

	// ret: 0
	if (ret) {
		kfree(new_ns);
		return ERR_PTR(ret);
	}
	// new_ns->seq: (kmem_cache#30-oX (struct mnt_namespace))->seq,
	// atomic64_add_return(1, &mnt_ns_seq): 2
	new_ns->seq = atomic64_add_return(1, &mnt_ns_seq);
	// new_ns->seq: (kmem_cache#30-oX (struct mnt_namespace))->seq: 2

	// atomic64_add_return 에서 한일:
	// mnt_ns_seq.counter: 2

	// &new_ns->count: (kmem_cache#30-oX (struct mnt_namespace))->count
	atomic_set(&new_ns->count, 1);

	// atomic_set 에서 한일:
	// (kmem_cache#30-oX (struct mnt_namespace))->count: 1

	// &new_ns->root: (kmem_cache#30-oX (struct mnt_namespace))->root
	new_ns->root = NULL;
	// &new_ns->root: (kmem_cache#30-oX (struct mnt_namespace))->root: NULL

	// &new_ns->list: &(kmem_cache#30-oX (struct mnt_namespace))->list
	INIT_LIST_HEAD(&new_ns->list);

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#30-oX (struct mnt_namespace))->list)->next: &(kmem_cache#30-oX (struct mnt_namespace))->list
	// (&(kmem_cache#30-oX (struct mnt_namespace))->list)->prev: &(kmem_cache#30-oX (struct mnt_namespace))->list

	// &new_ns->poll: &(kmem_cache#30-oX (struct mnt_namespace))->poll
	init_waitqueue_head(&new_ns->poll);

	// init_waitqueue_head에서 한일:
	// &(&(&(kmem_cache#30-oX (struct mnt_namespace))->poll)->open_wait)->lock을 사용한 spinlock 초기화
	// &(&(&(kmem_cache#30-oX (struct mnt_namespace))->poll)->open_wait)->task_list를 사용한 list 초기화

	// new_ns->event: (kmem_cache#30-oX (struct mnt_namespace))->event
	new_ns->event = 0;
	// new_ns->event: (kmem_cache#30-oX (struct mnt_namespace))->event: 0

	// new_ns->user_ns: (kmem_cache#30-oX (struct mnt_namespace))->user_ns,
	// user_ns: &init_user_ns, get_user_ns(&init_user_ns): &init_user_ns
	new_ns->user_ns = get_user_ns(user_ns);
	// new_ns->user_ns: (kmem_cache#30-oX (struct mnt_namespace))->user_ns: &init_user_ns

	// new_ns: kmem_cache#30-oX (struct mnt_namespace)
	return new_ns;
	// return kmem_cache#30-oX (struct mnt_namespace)
}

struct mnt_namespace *copy_mnt_ns(unsigned long flags, struct mnt_namespace *ns,
		struct user_namespace *user_ns, struct fs_struct *new_fs)
{
	struct mnt_namespace *new_ns;
	struct vfsmount *rootmnt = NULL, *pwdmnt = NULL;
	struct mount *p, *q;
	struct mount *old;
	struct mount *new;
	int copy_flags;

	BUG_ON(!ns);

	if (likely(!(flags & CLONE_NEWNS))) {
		get_mnt_ns(ns);
		return ns;
	}

	old = ns->root;

	new_ns = alloc_mnt_ns(user_ns);
	if (IS_ERR(new_ns))
		return new_ns;

	namespace_lock();
	/* First pass: copy the tree topology */
	copy_flags = CL_COPY_UNBINDABLE | CL_EXPIRE;
	if (user_ns != ns->user_ns)
		copy_flags |= CL_SHARED_TO_SLAVE | CL_UNPRIVILEGED;
	new = copy_tree(old, old->mnt.mnt_root, copy_flags);
	if (IS_ERR(new)) {
		namespace_unlock();
		free_mnt_ns(new_ns);
		return ERR_CAST(new);
	}
	new_ns->root = new;
	list_add_tail(&new_ns->list, &new->mnt_list);

	/*
	 * Second pass: switch the tsk->fs->* elements and mark new vfsmounts
	 * as belonging to new namespace.  We have already acquired a private
	 * fs_struct, so tsk->fs->lock is not needed.
	 */
	p = old;
	q = new;
	while (p) {
		q->mnt_ns = new_ns;
		if (new_fs) {
			if (&p->mnt == new_fs->root.mnt) {
				new_fs->root.mnt = mntget(&q->mnt);
				rootmnt = &p->mnt;
			}
			if (&p->mnt == new_fs->pwd.mnt) {
				new_fs->pwd.mnt = mntget(&q->mnt);
				pwdmnt = &p->mnt;
			}
		}
		p = next_mnt(p, old);
		q = next_mnt(q, new);
		if (!q)
			break;
		while (p->mnt.mnt_root != q->mnt.mnt_root)
			p = next_mnt(p, old);
	}
	namespace_unlock();

	if (rootmnt)
		mntput(rootmnt);
	if (pwdmnt)
		mntput(pwdmnt);

	return new_ns;
}

/**
 * create_mnt_ns - creates a private namespace and adds a root filesystem
 * @mnt: pointer to the new root filesystem mountpoint
 */
// ARM10C 20160514
// mnt: &(kmem_cache#2-oX (struct mount))->mnt
static struct mnt_namespace *create_mnt_ns(struct vfsmount *m)
{
	// alloc_mnt_ns(&init_user_ns): kmem_cache#30-oX (struct mnt_namespace)
	struct mnt_namespace *new_ns = alloc_mnt_ns(&init_user_ns);
	// new_ns: kmem_cache#30-oX (struct mnt_namespace)

	// alloc_mnt_ns에서 한일:
	// struct mnt_namespace 만큼의 메모리를 할당 받음 kmem_cache#30-oX (struct mnt_namespace)
	//
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
	//
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
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// mnt_ns_seq.counter: 2
	//
	// (kmem_cache#30-oX (struct mnt_namespace))->proc_inum: 0xF0000000
	// (kmem_cache#30-oX (struct mnt_namespace))->seq: 2
	// (kmem_cache#30-oX (struct mnt_namespace))->count: 1
	// (kmem_cache#30-oX (struct mnt_namespace))->root: NULL
	// (&(kmem_cache#30-oX (struct mnt_namespace))->list)->next: &(kmem_cache#30-oX (struct mnt_namespace))->list
	// (&(kmem_cache#30-oX (struct mnt_namespace))->list)->prev: &(kmem_cache#30-oX (struct mnt_namespace))->list
	// &(&(&(kmem_cache#30-oX (struct mnt_namespace))->poll)->open_wait)->lock을 사용한 spinlock 초기화
	// &(&(&(kmem_cache#30-oX (struct mnt_namespace))->poll)->open_wait)->task_list를 사용한 list 초기화
	// (kmem_cache#30-oX (struct mnt_namespace))->event: 0
	// (kmem_cache#30-oX (struct mnt_namespace))->user_ns: &init_user_ns

// 2016/05/14 종료

	// new_ns: kmem_cache#30-oX (struct mnt_namespace), IS_ERR(kmem_cache#30-oX (struct mnt_namespace)): 0
	if (!IS_ERR(new_ns)) {
		struct mount *mnt = real_mount(m);
		mnt->mnt_ns = new_ns;
		new_ns->root = mnt;
		list_add(&mnt->mnt_list, &new_ns->list);
	} else {
		mntput(m);
	}
	return new_ns;
}

struct dentry *mount_subtree(struct vfsmount *mnt, const char *name)
{
	struct mnt_namespace *ns;
	struct super_block *s;
	struct path path;
	int err;

	ns = create_mnt_ns(mnt);
	if (IS_ERR(ns))
		return ERR_CAST(ns);

	err = vfs_path_lookup(mnt->mnt_root, mnt,
			name, LOOKUP_FOLLOW|LOOKUP_AUTOMOUNT, &path);

	put_mnt_ns(ns);

	if (err)
		return ERR_PTR(err);

	/* trade a vfsmount reference for active sb one */
	s = path.mnt->mnt_sb;
	atomic_inc(&s->s_active);
	mntput(path.mnt);
	/* lock the sucker */
	down_write(&s->s_umount);
	/* ... and return the root of (sub)tree on it */
	return path.dentry;
}
EXPORT_SYMBOL(mount_subtree);

SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
		char __user *, type, unsigned long, flags, void __user *, data)
{
	int ret;
	char *kernel_type;
	struct filename *kernel_dir;
	char *kernel_dev;
	unsigned long data_page;

	ret = copy_mount_string(type, &kernel_type);
	if (ret < 0)
		goto out_type;

	kernel_dir = getname(dir_name);
	if (IS_ERR(kernel_dir)) {
		ret = PTR_ERR(kernel_dir);
		goto out_dir;
	}

	ret = copy_mount_string(dev_name, &kernel_dev);
	if (ret < 0)
		goto out_dev;

	ret = copy_mount_options(data, &data_page);
	if (ret < 0)
		goto out_data;

	ret = do_mount(kernel_dev, kernel_dir->name, kernel_type, flags,
		(void *) data_page);

	free_page(data_page);
out_data:
	kfree(kernel_dev);
out_dev:
	putname(kernel_dir);
out_dir:
	kfree(kernel_type);
out_type:
	return ret;
}

/*
 * Return true if path is reachable from root
 *
 * namespace_sem or mount_lock is held
 */
bool is_path_reachable(struct mount *mnt, struct dentry *dentry,
			 const struct path *root)
{
	while (&mnt->mnt != root->mnt && mnt_has_parent(mnt)) {
		dentry = mnt->mnt_mountpoint;
		mnt = mnt->mnt_parent;
	}
	return &mnt->mnt == root->mnt && is_subdir(dentry, root->dentry);
}

int path_is_under(struct path *path1, struct path *path2)
{
	int res;
	read_seqlock_excl(&mount_lock);
	res = is_path_reachable(real_mount(path1->mnt), path1->dentry, path2);
	read_sequnlock_excl(&mount_lock);
	return res;
}
EXPORT_SYMBOL(path_is_under);

/*
 * pivot_root Semantics:
 * Moves the root file system of the current process to the directory put_old,
 * makes new_root as the new root file system of the current process, and sets
 * root/cwd of all processes which had them on the current root to new_root.
 *
 * Restrictions:
 * The new_root and put_old must be directories, and  must not be on the
 * same file  system as the current process root. The put_old  must  be
 * underneath new_root,  i.e. adding a non-zero number of /.. to the string
 * pointed to by put_old must yield the same directory as new_root. No other
 * file system may be mounted on put_old. After all, new_root is a mountpoint.
 *
 * Also, the current root cannot be on the 'rootfs' (initial ramfs) filesystem.
 * See Documentation/filesystems/ramfs-rootfs-initramfs.txt for alternatives
 * in this situation.
 *
 * Notes:
 *  - we don't move root/cwd if they are not at the root (reason: if something
 *    cared enough to change them, it's probably wrong to force them elsewhere)
 *  - it's okay to pick a root that isn't the root of a file system, e.g.
 *    /nfs/my_root where /nfs is the mount point. It must be a mountpoint,
 *    though, so you may need to say mount --bind /nfs/my_root /nfs/my_root
 *    first.
 */
SYSCALL_DEFINE2(pivot_root, const char __user *, new_root,
		const char __user *, put_old)
{
	struct path new, old, parent_path, root_parent, root;
	struct mount *new_mnt, *root_mnt, *old_mnt;
	struct mountpoint *old_mp, *root_mp;
	int error;

	if (!may_mount())
		return -EPERM;

	error = user_path_dir(new_root, &new);
	if (error)
		goto out0;

	error = user_path_dir(put_old, &old);
	if (error)
		goto out1;

	error = security_sb_pivotroot(&old, &new);
	if (error)
		goto out2;

	get_fs_root(current->fs, &root);
	old_mp = lock_mount(&old);
	error = PTR_ERR(old_mp);
	if (IS_ERR(old_mp))
		goto out3;

	error = -EINVAL;
	new_mnt = real_mount(new.mnt);
	root_mnt = real_mount(root.mnt);
	old_mnt = real_mount(old.mnt);
	if (IS_MNT_SHARED(old_mnt) ||
		IS_MNT_SHARED(new_mnt->mnt_parent) ||
		IS_MNT_SHARED(root_mnt->mnt_parent))
		goto out4;
	if (!check_mnt(root_mnt) || !check_mnt(new_mnt))
		goto out4;
	if (new_mnt->mnt.mnt_flags & MNT_LOCKED)
		goto out4;
	error = -ENOENT;
	if (d_unlinked(new.dentry))
		goto out4;
	error = -EBUSY;
	if (new_mnt == root_mnt || old_mnt == root_mnt)
		goto out4; /* loop, on the same file system  */
	error = -EINVAL;
	if (root.mnt->mnt_root != root.dentry)
		goto out4; /* not a mountpoint */
	if (!mnt_has_parent(root_mnt))
		goto out4; /* not attached */
	root_mp = root_mnt->mnt_mp;
	if (new.mnt->mnt_root != new.dentry)
		goto out4; /* not a mountpoint */
	if (!mnt_has_parent(new_mnt))
		goto out4; /* not attached */
	/* make sure we can reach put_old from new_root */
	if (!is_path_reachable(old_mnt, old.dentry, &new))
		goto out4;
	root_mp->m_count++; /* pin it so it won't go away */
	lock_mount_hash();
	detach_mnt(new_mnt, &parent_path);
	detach_mnt(root_mnt, &root_parent);
	if (root_mnt->mnt.mnt_flags & MNT_LOCKED) {
		new_mnt->mnt.mnt_flags |= MNT_LOCKED;
		root_mnt->mnt.mnt_flags &= ~MNT_LOCKED;
	}
	/* mount old root on put_old */
	attach_mnt(root_mnt, old_mnt, old_mp);
	/* mount new_root on / */
	attach_mnt(new_mnt, real_mount(root_parent.mnt), root_mp);
	touch_mnt_namespace(current->nsproxy->mnt_ns);
	unlock_mount_hash();
	chroot_fs_refs(&root, &new);
	put_mountpoint(root_mp);
	error = 0;
out4:
	unlock_mount(old_mp);
	if (!error) {
		path_put(&root_parent);
		path_put(&parent_path);
	}
out3:
	path_put(&root);
out2:
	path_put(&old);
out1:
	path_put(&new);
out0:
	return error;
}

// ARM10C 20160326
static void __init init_mount_tree(void)
{
	struct vfsmount *mnt;
	struct mnt_namespace *ns;
	struct path root;
	struct file_system_type *type;

	// get_fs_type("rootfs"): &rootfs_fs_type
	type = get_fs_type("rootfs");
	// type: &rootfs_fs_type

	// get_fs_type 에서 한일:
	// "rootfs" 으로 등록된 &rootfs_fs_type 을 찾음

	// type: &rootfs_fs_type
	if (!type)
		panic("Can't find rootfs type");

	// type: &rootfs_fs_type
	// vfs_kern_mount(&rootfs_fs_type, 0, "rootfs", NULL): &(kmem_cache#2-oX (struct mount))->mnt
	mnt = vfs_kern_mount(type, 0, "rootfs", NULL);
	// mnt: &(kmem_cache#2-oX (struct mount))->mnt

	// vfs_kern_mount 에서 한일:
	// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 2번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 3
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 2) 의 memory 공간을 반환함
	//
	// mnt_id_start: 3
	//
	// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "rootfs"
	// (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count: 1
	//
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->next: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->pprev: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->next: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->prev: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->next: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->prev: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->next: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->next: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->prev: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->next: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->prev: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->next: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->next: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks)->first: NULL
	//
	// once: 1
	//
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
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0
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
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 2번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	//
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// (&(&unnamed_dev_ida)->idr)->id_free: (idr object new 0)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 3
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 2) 의 memory 공간을 반환함
	//
	// unnamed_dev_start: 3
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 2
	//
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 1
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_type: &rootfs_fs_type
	// (kmem_cache#25-oX (struct super_block))->s_id: "rootfs"
	//
	// list head인 &super_blocks 에 (kmem_cache#25-oX (struct super_block))->s_list을 tail에 추가
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->next: NULL
	// (&(&rootfs_fs_type)->fs_supers)->first: &(kmem_cache#25-oX (struct super_block))->s_instances
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->pprev: &(&(&rootfs_fs_type)->fs_supers)->first
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->flags: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->nr_deferred: kmem_cache#30-oX
	// head list인 &shrinker_list에 &(&(kmem_cache#25-oX (struct super_block))->s_shrink)->list를 tail로 추가함
	//
	// struct shmem_sb_info 사이즈 만큼의 메모리를 할당 받음 kmem_cache#29-oX (struct shmem_sb_info)
	//
	// (kmem_cache#29-oX (struct shmem_sb_info))->mode: 01777
	// (kmem_cache#29-oX (struct shmem_sb_info))->uid: 0
	// (kmem_cache#29-oX (struct shmem_sb_info))->gid: 0
	// (kmem_cache#25-oX (struct super_block))->s_fs_info: kmem_cache#29-oX (struct shmem_sb_info)
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x80400000
	// (kmem_cache#25-oX (struct super_block))->s_export_op: &shmem_export_ops
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x90400000
	//
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->magic: 0xdead4ead
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->owner: 0xffffffff
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->owner_cpu: 0xffffffff
	//
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list)->next: &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list
	// (&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list)->prev: &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->count: 0
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list를 연결함
	//
	// (kmem_cache#29-oX (struct shmem_sb_info))->free_inodes: 0
	// (kmem_cache#25-oX (struct super_block))->s_maxbytes: 0x7ffffffffff
	// (kmem_cache#25-oX (struct super_block))->s_blocksize: 0x1000
	// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 12
	// (kmem_cache#25-oX (struct super_block))->s_magic: 0x01021994
	// (kmem_cache#25-oX (struct super_block))->s_op: &shmem_ops
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1
	// (kmem_cache#25-oX (struct super_block))->s_xattr: shmem_xattr_handlers
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x90410000
	//
	// struct shmem_sb_info 만큼의 메모리를 할당 받음 kmem_cache#29-oX (struct shmem_sb_info)
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
	// (kmem_cache#4-oX (struct inode))->i_dio_count: 0
	// (&(kmem_cache#4-oX (struct inode))->i_data)->a_ops: &empty_aops
	// (&(kmem_cache#4-oX (struct inode))->i_data)->host: kmem_cache#4-oX (struct inode)
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0x200DA
	// (&(kmem_cache#4-oX (struct inode))->i_data)->private_data: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_data)->backing_dev_info: &default_backing_dev_info
	// (&(kmem_cache#4-oX (struct inode))->i_data)->writeback_index: 0
	// (kmem_cache#4-oX (struct inode))->i_private: NULL
	// (kmem_cache#4-oX (struct inode))->i_mapping: &(kmem_cache#4-oX (struct inode))->i_data
	// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: NULL
	// (kmem_cache#4-oX (struct inode))->i_acl: (void *)(0xFFFFFFFF),
	// (kmem_cache#4-oX (struct inode))->i_default_acl: (void *)(0xFFFFFFFF)
	// (kmem_cache#4-oX (struct inode))->i_fsnotify_mask: 0
	// (kmem_cache#4-oX (struct inode))->i_ino: 1
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#4-oX (struct inode))->i_mode: 0041777
	// (kmem_cache#4-oX (struct inode))->i_blocks: 0
	// (kmem_cache#4-oX (struct inode))->i_mapping->backing_dev_info: &shmem_backing_dev_info
	// (kmem_cache#4-oX (struct inode))->i_atime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_mtime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_ctime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_generation: 현재시간의 sec 값
	// (kmem_cache#4-oX (struct inode))->i_acl: NULL
	// (kmem_cache#4-oX (struct inode))->i_default_acl: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_sb->s_remove_count)->counter: -1
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
	// (kmem_cache#4-oX (struct inode))->i_size: 40
	// (kmem_cache#4-oX (struct inode))->i_op: &shmem_dir_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_fop: &simple_dir_operations
	//
	// (kmem_cache#4-oX (struct inode))->i_state: 0
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
	//
	// head list인 &(kmem_cache#4-oX (struct inode))->i_sb->s_inodes에 &(kmem_cache#4-oX (struct inode))->i_sb_list를 추가함
	//
	// [pcp0] nr_inodes: 1
	//
	// (&shared_last_ino)->counter: 1024
	// [pcp0] last_ino: 1
	//
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->magic: 0xdead4ead
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->owner: 0xffffffff
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->owner_cpu: 0xffffffff
	// (kmem_cache#4-oX (struct shmem_inode_info))->flags: 0x00200000
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->swaplist)->next: &(kmem_cache#4-oX (struct shmem_inode_info))->swaplist
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->swaplist)->prev: &(kmem_cache#4-oX (struct shmem_inode_info))->swaplist
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head)->next: &(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head)->prev: &(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->raw_lock: { { 0 } }
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->magic: 0xdead4ead
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->owner: 0xffffffff
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->owner_cpu: 0xffffffff
	//
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
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
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0xf0410000
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0
	//
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_root: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_sb: kmem_cache#25-oX (struct super_block)
	// (kmem_cache#2-oX (struct mount))->mnt_mountpoint: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt_parent: kmem_cache#2-oX (struct mount)
	//
	// list head인 &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts에
	// &(kmem_cache#2-oX (struct mount))->mnt_instance를 tail로 연결

	// type: &rootfs_fs_type
	put_filesystem(type);

	// mnt: &(kmem_cache#2-oX (struct mount))->mnt, IS_ERR(&(kmem_cache#2-oX (struct mount))->mnt): 0
	if (IS_ERR(mnt))
		panic("Can't create rootfs");

	// mnt: &(kmem_cache#2-oX (struct mount))->mnt
	ns = create_mnt_ns(mnt);
	if (IS_ERR(ns))
		panic("Can't allocate initial namespace");

	init_task.nsproxy->mnt_ns = ns;
	get_mnt_ns(ns);

	root.mnt = mnt;
	root.dentry = mnt->mnt_root;

	set_fs_pwd(current->fs, &root);
	set_fs_root(current->fs, &root);
}

// ARM10C 20151024
void __init mnt_init(void)
{
	unsigned u;
	int err;

	// sizeof(struct mount): 152 bytes, SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_PANIC: 0x00040000UL
	// kmem_cache_create("mnt_cache", 152, 0, 0x42000, NULL): kmem_cache#2
	mnt_cache = kmem_cache_create("mnt_cache", sizeof(struct mount),
			0, SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);
	// mnt_cache: kmem_cache#2

	// sizeof(struct hlist_head): 4 bytes, mhash_entries: 0
	// alloc_large_system_hash("Mount-cache", 4, 0, 19, 0, &m_hash_shift, &m_hash_mask, 0, 0): 16kB만큼 할당받은 메모리 주소
	mount_hashtable = alloc_large_system_hash("Mount-cache",
				sizeof(struct hlist_head),
				mhash_entries, 19,
				0,
				&m_hash_shift, &m_hash_mask, 0, 0);
	// mount_hashtable: 16kB만큼 할당받은 메모리 주소


	// sizeof(struct hlist_head): 4 bytes, mphash_entries: 0
	// alloc_large_system_hash("Mountpoint-cache", 4, 0, 19, 0, &m_hash_shift, &m_hash_mask, 0, 0): 16kB만큼 할당받은 메모리 주소
	mountpoint_hashtable = alloc_large_system_hash("Mountpoint-cache",
				sizeof(struct hlist_head),
				mphash_entries, 19,
				0,
				&mp_hash_shift, &mp_hash_mask, 0, 0);
	// mountpoint_hashtable: 16kB만큼 할당받은 메모리 주소

// 2015/10/24 종료
// 2015/10/31 시작

	// mount_hashtable: 16kB만큼 할당받은 메모리 주소, mountpoint_hashtable: 16kB만큼 할당받은 메모리 주소
	if (!mount_hashtable || !mountpoint_hashtable)
		panic("Failed to allocate mount hash table\n");

	// m_hash_mask: 0xFFF
	for (u = 0; u <= m_hash_mask; u++)
		// u: 0
		INIT_HLIST_HEAD(&mount_hashtable[u]);

		// INIT_HLIST_HEAD 에서 한일:
		// ((&mount_hashtable[0])->first = NULL)

		// u: 1...4095 까지 loop 수행

	// mp_hash_mask: 0xFFF
	for (u = 0; u <= mp_hash_mask; u++)
		// u: 0
		INIT_HLIST_HEAD(&mountpoint_hashtable[u]);

		// INIT_HLIST_HEAD 에서 한일:
		// ((&mountpoint_hashtable[0])->first = NULL)

		// u: 1...4095 까지 loop 수행

	// sysfs_init(): 0
	err = sysfs_init();
	// err: 0

	// sysfs_init에서 한일:
	//
	// struct sysfs_dirent를 위한 kmem_cache 를 생성
	// sysfs_dir_cachep: kmem_cache#1
	//
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
	//
	// file system 을 sysfs_fs_type로 등록
	// file_systems: &sysfs_fs_type
	//
	// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 6
	// (&(&mnt_id_ida)->idr)->layers: 1
	// ((&(&mnt_id_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&mnt_id_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 0
	//
	// mnt_id_start: 1
	//
	// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "sysfs"
	// (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count: 1
	//
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->next: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->pprev: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->next: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->prev: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->next: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->prev: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->next: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->next: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->prev: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->next: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->prev: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->next: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->next: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks)->first: NULL
	//
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_flags: 0x4000
	//
	// struct sysfs_super_info의 메모리 kmem_cache#30-oX (struct sysfs_super_info)를 할당받음
	//
	// (kmem_cache#30-oX (struct sysfs_super_info))->ns[0]: NULL
	//
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
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 6
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// ((&(&unnamed_dev_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&unnamed_dev_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 0
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// unnamed_dev_start: 1
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 0
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_fs_info: kmem_cache#30-oX (struct sysfs_super_info)
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
	//
	// (kmem_cache#25-oX (struct super_block))->s_blocksize: 0x1000
	// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 12
	// (kmem_cache#25-oX (struct super_block))->s_magic: 0x62656572
	// (kmem_cache#25-oX (struct super_block))->s_op: &sysfs_ops
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1
	//
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
	//
	// (&sysfs_root)->s_count: 2
	//
	// (kmem_cache#4-oX (struct inode))->i_private: 2
	// (kmem_cache#4-oX (struct inode))->i_mapping->a_ops: &sysfs_aops
	// (kmem_cache#4-oX (struct inode))->i_mapping->backing_dev_info: &sysfs_backing_dev_info
	// (kmem_cache#4-oX (struct inode))->i_op: &sysfs_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값,
	// (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값,
	// (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_mode: 40447
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
	// (kmem_cache#4-oX (struct inode))->i_op: &sysfs_dir_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_fop: &sysfs_dir_operations
	// (kmem_cache#4-oX (struct inode))->i_state: 0x0
	// memory barrier 수행 (공유자원을 다른 cpu core가 사용할 수 있게 해줌)
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
	// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: &(kmem_cache#5-oX (struct dentry))->d_alias
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->pprev: &(&(kmem_cache#5-oX (struct dentry))->d_alias)
	//
	// (kmem_cache#5-oX (struct dentry))->d_inode: kmem_cache#4-oX (struct inode)
	//
	// 공유자원을 다른 cpu core가 사용할수 있게 함
	// (&(kmem_cache#5-oX (struct dentry))->d_seq)->sequence: 2
	//
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100000
	//
	// (kmem_cache#5-oX (struct dentry))->d_fsdata: &sysfs_root
	// (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#25-oX (struct super_block))->s_d_op: &sysfs_dentry_ops
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x40400000
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_lockref)->count: 1
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x60400000
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0
	//
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_flags: 0x4000
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_root: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_sb: kmem_cache#25-oX (struct super_block)
	// (kmem_cache#2-oX (struct mount))->mnt_mountpoint: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt_parent: kmem_cache#2-oX (struct mount)
	//
	// list head인 &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts에
	// &(kmem_cache#2-oX (struct mount))->mnt_instance를 tail로 연결
	//
	// (kmem_cache#2-oX (struct mount))->mnt_ns: 0xffffffea

	// err: 0
	if (err)
		printk(KERN_WARNING "%s: sysfs_init error: %d\n",
			__func__, err);

	// kobject_create_and_add("fs", NULL): kmem_cache#30-oX (struct kobject)
	fs_kobj = kobject_create_and_add("fs", NULL);
	// fs_kobj: kmem_cache#30-oX (struct kobject)

	// kobject_create_and_add에서 한일:
	// struct kobject의 메모리를 할당받음 kmem_cache#30-oX (struct kobject)
	//
	// (&(kmem_cache#30-oX (struct kobject))->kref)->refcount: 1
	// (&(kmem_cache#30-oX (struct kobject))->entry)->next: &(kmem_cache#30-oX (struct kobject))->entry
	// (&(kmem_cache#30-oX (struct kobject))->entry)->prev: &(kmem_cache#30-oX (struct kobject))->entry
	// (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 0
	// (kmem_cache#30-oX (struct kobject))->state_add_uevent_sent: 0
	// (kmem_cache#30-oX (struct kobject))->state_remove_uevent_sent: 0
	// (kmem_cache#30-oX (struct kobject))->state_initialized: 1
	// (kmem_cache#30-oX (struct kobject))->ktype: &dynamic_kobj_ktype
	//
	// struct kobject의 멤버 name에 메모리를 할당하고 string 값을 만듬
	//
	// (kmem_cache#30-oX (struct kobject))->name: kmem_cache#30-oX: "fs"
	// (kmem_cache#30-oX (struct kobject))->parent: NULL
	//
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
	//
	// (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent)
	//
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_count: 2
	//
	// (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 1

	// fs_kobj: kmem_cache#30-oX (struct kobject)
	if (!fs_kobj)
		printk(KERN_WARNING "%s: kobj create error\n", __func__);

	init_rootfs();

	// init_rootfs 에서 한일:
	// (&sysfs_fs_type)->next: &rootfs_fs_type
	//
	// (&shmem_backing_dev_info)->dev: NULL
	// (&shmem_backing_dev_info)->min_ratio: 0
	// (&shmem_backing_dev_info)->max_ratio: 100
	// (&shmem_backing_dev_info)->max_prop_frac: 0x400
	// &(&shmem_backing_dev_info)->wb_lock 을 이용한 spinlock 초기화 수행
	// (&(&shmem_backing_dev_info)->bdi_list)->next: &(&shmem_backing_dev_info)->bdi_list
	// (&(&shmem_backing_dev_info)->bdi_list)->prev: &(&shmem_backing_dev_info)->bdi_list
	// (&(&shmem_backing_dev_info)->work_list)->next: &(&shmem_backing_dev_info)->work_list
	// (&(&shmem_backing_dev_info)->work_list)->prev: &(&shmem_backing_dev_info)->work_list
	//
	// (&shmem_backing_dev_info)->wb 의 맴버값을 0으로 초기화함
	// (&(&shmem_backing_dev_info)->wb)->bdi: &shmem_backing_dev_info
	// (&(&shmem_backing_dev_info)->wb)->last_old_flush: XXX
	// (&(&(&shmem_backing_dev_info)->wb)->b_dirty)->next: &(&(&shmem_backing_dev_info)->wb)->b_dirty
	// (&(&(&shmem_backing_dev_info)->wb)->b_dirty)->prev: &(&(&shmem_backing_dev_info)->wb)->b_dirty
	// (&(&(&shmem_backing_dev_info)->wb)->b_io)->next: &(&(&shmem_backing_dev_info)->wb)->b_io
	// (&(&(&shmem_backing_dev_info)->wb)->b_io)->prev: &(&(&shmem_backing_dev_info)->wb)->b_io
	// (&(&(&shmem_backing_dev_info)->wb)->b_more_io)->next: &(&(&shmem_backing_dev_info)->wb)->b_more_io
	// (&(&(&shmem_backing_dev_info)->wb)->b_more_io)->prev: &(&(&shmem_backing_dev_info)->wb)->b_more_io
	// &(&(&shmem_backing_dev_info)->wb)->list_lock 을 이용한 spinlock 초기화 수행
	// (&(&(&(&shmem_backing_dev_info)->wb)->dwork)->work)->data: { 0xFFFFFFE0 }
	// (&(&(&(&(&shmem_backing_dev_info)->wb)->dwork)->work)->entry)->next: &(&(&(&(&shmem_backing_dev_info)->wb)->dwork)->work)->entry
	// (&(&(&(&(&shmem_backing_dev_info)->wb)->dwork)->work)->entry)->prev: &(&(&(&(&shmem_backing_dev_info)->wb)->dwork)->work)->entry
	// (&(&(&(&shmem_backing_dev_info)->wb)->dwork)->work)->func: bdi_writeback_workfn
	// (&(&(&(&shmem_backing_dev_info)->wb)->dwork)->timer)->entry.next: NULL
	// (&(&(&(&shmem_backing_dev_info)->wb)->dwork)->timer)->base: [pcp0] tvec_bases | 0x2
	// (&(&(&(&shmem_backing_dev_info)->wb)->dwork)->timer)->slack: -1
	// (&(&(&(&shmem_backing_dev_info)->wb)->dwork)->timer)->function = (delayed_work_timer_fn);
	// (&(&(&(&shmem_backing_dev_info)->wb)->dwork)->timer)->data = ((unsigned long)(&(&(&shmem_backing_dev_info)->wb)->dwork));
	//
	// (&(&(&(&(&shmem_backing_dev_info)->bdi_stat[0...3])->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&(&shmem_backing_dev_info)->bdi_stat[0...3])->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&(&shmem_backing_dev_info)->bdi_stat[0...3])->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&(&shmem_backing_dev_info)->bdi_stat[0...3])->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(&shmem_backing_dev_info)->bdi_stat[0...3])->list)->next: &(&(&shmem_backing_dev_info)->bdi_stat[0...3])->list
	// (&(&(&shmem_backing_dev_info)->bdi_stat[0...3])->list)->prev: &(&(&shmem_backing_dev_info)->bdi_stat[0...3])->list
	// (&(&shmem_backing_dev_info)->bdi_stat[0...3])->count: 0
	// (&(&shmem_backing_dev_info)->bdi_stat[0...3])->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&(&shmem_backing_dev_info)->bdi_stat[0...3])->list를 연결함
	//
	// (&shmem_backing_dev_info)->dirty_exceeded: 0
	// (&shmem_backing_dev_info)->bw_time_stamp: XXX
	// (&shmem_backing_dev_info)->written_stamp: 0
	// (&shmem_backing_dev_info)->balanced_dirty_ratelimit: 0x6400
	// (&shmem_backing_dev_info)->dirty_ratelimit: 0x6400
	// (&shmem_backing_dev_info)->write_bandwidth: 0x6400
	// (&shmem_backing_dev_info)->avg_write_bandwidth: 0x6400
	//
	// (&(&(&(&(&(&shmem_backing_dev_info)->completions)->events)->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&(&(&shmem_backing_dev_info)->completions)->events)->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&(&(&shmem_backing_dev_info)->completions)->events)->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&(&(&shmem_backing_dev_info)->completions)->events)->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(&(&shmem_backing_dev_info)->completions)->events)->list)->next: &(&(&(&shmem_backing_dev_info)->completions)->events)->list
	// (&(&(&(&shmem_backing_dev_info)->completions)->events)->list)->prev: &(&(&(&shmem_backing_dev_info)->completions)->events)->list
	// (&(&(&shmem_backing_dev_info)->completions)->events)->count: 0
	// (&(&(&shmem_backing_dev_info)->completions)->events)->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&(&(&shmem_backing_dev_info)->completions)->events)->list를 연결함
	// (&(&shmem_backing_dev_info)->completions)->period: 0
	// &(&(&shmem_backing_dev_info)->completions)->lock을 이용한 spinlock 초기화 수행
	//
	// struct shmem_inode_info 의 type의 메모리 할당하는 kmem_cache를 생성함
	// shmem_inode_cachep: kmem_cache#0
	//
	// (&rootfs_fs_type)->next: &shmem_fs_type
	//
	// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 2 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 1번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 1
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함
	//
	// mnt_id_start: 2
	//
	// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "tmpfs"
	// (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count: 1
	//
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->next: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->pprev: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->next: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->prev: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->next: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->prev: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->next: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->next: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->prev: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->next: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->prev: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->next: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->next: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks)->first: NULL
	//
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_flags: 0x4000
	//
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
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 2 개를 할당 받음
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 1번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// (&(&unnamed_dev_ida)->idr)->id_free: (idr object new 0)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함
	//
	// unnamed_dev_start: 2
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 1
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_type: &shmem_fs_type
	// (kmem_cache#25-oX (struct super_block))->s_id: "tmpfs"
	//
	// list head인 &super_blocks 에 (kmem_cache#25-oX (struct super_block))->s_list을 tail에 추가
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->next: NULL
	// (&(&shmem_fs_type)->fs_supers)->first: &(kmem_cache#25-oX (struct super_block))->s_instances
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->pprev: &(&(&shmem_fs_type)->fs_supers)->first
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->flags: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->nr_deferred: kmem_cache#30-oX
	// head list인 &shrinker_list에 &(&(kmem_cache#25-oX (struct super_block))->s_shrink)->list를 tail로 추가함
	//
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
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x40400000
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x60400000
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0
	//
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_root: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_sb: kmem_cache#25-oX (struct super_block)
	// (kmem_cache#2-oX (struct mount))->mnt_mountpoint: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt_parent: kmem_cache#2-oX (struct mount)
	//
	// list head인 &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts에
	// &(kmem_cache#2-oX (struct mount))->mnt_instance를 tail로 연결
	//
	// (kmem_cache#2-oX (struct mount))->mnt_ns: 0xffffffea
	// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 2 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 1번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 1
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함
	//
	// mnt_id_start: 2
	//
	// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "tmpfs"
	// (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count: 1
	//
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->next: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->pprev: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->next: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->prev: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->next: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->prev: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->next: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->next: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->prev: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->next: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->prev: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->next: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->next: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks)->first: NULL
	//
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
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 2 개를 할당 받음
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 1번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// (&(&unnamed_dev_ida)->idr)->id_free: (idr object new 0)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함
	//
	// unnamed_dev_start: 2
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 1
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_type: &shmem_fs_type
	// (kmem_cache#25-oX (struct super_block))->s_id: "tmpfs"
	//
	// list head인 &super_blocks 에 (kmem_cache#25-oX (struct super_block))->s_list을 tail에 추가
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->next: NULL
	// (&(&shmem_fs_type)->fs_supers)->first: &(kmem_cache#25-oX (struct super_block))->s_instances
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->pprev: &(&(&shmem_fs_type)->fs_supers)->first
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->flags: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->nr_deferred: kmem_cache#30-oX
	// head list인 &shrinker_list에 &(&(kmem_cache#25-oX (struct super_block))->s_shrink)->list를 tail로 추가함
	//
	// struct shmem_sb_info 사이즈 만큼의 메모리를 할당 받음 kmem_cache#29-oX (struct shmem_sb_info)
	//
	// (kmem_cache#29-oX (struct shmem_sb_info))->mode: 01777
	// (kmem_cache#29-oX (struct shmem_sb_info))->uid: 0
	// (kmem_cache#29-oX (struct shmem_sb_info))->gid: 0
	// (kmem_cache#25-oX (struct super_block))->s_fs_info: kmem_cache#29-oX (struct shmem_sb_info)
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x80400000
	// (kmem_cache#25-oX (struct super_block))->s_export_op: &shmem_export_ops
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x90400000
	//
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->magic: 0xdead4ead
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->owner: 0xffffffff
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->owner_cpu: 0xffffffff
	//
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list)->next: &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list
	// (&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list)->prev: &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->count: 0
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list를 연결함
	//
	// (kmem_cache#29-oX (struct shmem_sb_info))->free_inodes: 0
	// (kmem_cache#25-oX (struct super_block))->s_maxbytes: 0x7ffffffffff
	// (kmem_cache#25-oX (struct super_block))->s_blocksize: 0x1000
	// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 12
	// (kmem_cache#25-oX (struct super_block))->s_magic: 0x01021994
	// (kmem_cache#25-oX (struct super_block))->s_op: &shmem_ops
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1
	// (kmem_cache#25-oX (struct super_block))->s_xattr: shmem_xattr_handlers
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x90410000
	//
	// struct shmem_sb_info 만큼의 메모리를 할당 받음 kmem_cache#29-oX (struct shmem_sb_info)
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
	// (kmem_cache#4-oX (struct inode))->i_dio_count: 0
	// (&(kmem_cache#4-oX (struct inode))->i_data)->a_ops: &empty_aops
	// (&(kmem_cache#4-oX (struct inode))->i_data)->host: kmem_cache#4-oX (struct inode)
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0x200DA
	// (&(kmem_cache#4-oX (struct inode))->i_data)->private_data: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_data)->backing_dev_info: &default_backing_dev_info
	// (&(kmem_cache#4-oX (struct inode))->i_data)->writeback_index: 0
	// (kmem_cache#4-oX (struct inode))->i_private: NULL
	// (kmem_cache#4-oX (struct inode))->i_mapping: &(kmem_cache#4-oX (struct inode))->i_data
	// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: NULL
	// (kmem_cache#4-oX (struct inode))->i_acl: (void *)(0xFFFFFFFF),
	// (kmem_cache#4-oX (struct inode))->i_default_acl: (void *)(0xFFFFFFFF)
	// (kmem_cache#4-oX (struct inode))->i_fsnotify_mask: 0
	// (kmem_cache#4-oX (struct inode))->i_ino: 1
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#4-oX (struct inode))->i_mode: 0041777
	// (kmem_cache#4-oX (struct inode))->i_blocks: 0
	// (kmem_cache#4-oX (struct inode))->i_mapping->backing_dev_info: &shmem_backing_dev_info
	// (kmem_cache#4-oX (struct inode))->i_atime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_mtime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_ctime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_generation: 현재시간의 sec 값
	// (kmem_cache#4-oX (struct inode))->i_acl: NULL
	// (kmem_cache#4-oX (struct inode))->i_default_acl: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_sb->s_remove_count)->counter: -1
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
	// (kmem_cache#4-oX (struct inode))->i_size: 40
	// (kmem_cache#4-oX (struct inode))->i_op: &shmem_dir_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_fop: &simple_dir_operations
	//
	// (kmem_cache#4-oX (struct inode))->i_state: 0
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
	//
	// head list인 &(kmem_cache#4-oX (struct inode))->i_sb->s_inodes에 &(kmem_cache#4-oX (struct inode))->i_sb_list를 추가함
	//
	// [pcp0] nr_inodes: 1
	//
	// (&shared_last_ino)->counter: 1024
	// [pcp0] last_ino: 1
	//
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->magic: 0xdead4ead
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->owner: 0xffffffff
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->owner_cpu: 0xffffffff
	// (kmem_cache#4-oX (struct shmem_inode_info))->flags: 0x00200000
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->swaplist)->next: &(kmem_cache#4-oX (struct shmem_inode_info))->swaplist
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->swaplist)->prev: &(kmem_cache#4-oX (struct shmem_inode_info))->swaplist
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head)->next: &(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head)->prev: &(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->raw_lock: { { 0 } }
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->magic: 0xdead4ead
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->owner: 0xffffffff
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->owner_cpu: 0xffffffff
	//
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
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
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0xf0410000
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0
	//
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_root: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_sb: kmem_cache#25-oX (struct super_block)
	// (kmem_cache#2-oX (struct mount))->mnt_mountpoint: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt_parent: kmem_cache#2-oX (struct mount)
	//
	// list head인 &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts에
	// &(kmem_cache#2-oX (struct mount))->mnt_instance를 tail로 연결
	//
	// (kmem_cache#2-oX (struct mount))->mnt_ns: 0xffffffea
	//
	// is_tmpfs: 1

	init_mount_tree();
}

void put_mnt_ns(struct mnt_namespace *ns)
{
	if (!atomic_dec_and_test(&ns->count))
		return;
	drop_collected_mounts(&ns->root->mnt);
	free_mnt_ns(ns);
}

// ARM10C 20151031
// &sysfs_fs_type, NULL
// ARM10C 20160213
// &shmem_fs_type, NULL
struct vfsmount *kern_mount_data(struct file_system_type *type, void *data)
{
	struct vfsmount *mnt;

	// type: &sysfs_fs_type, MS_KERNMOUNT: 0x400000, type->name: (&sysfs_fs_type)->name: "sysfs", data: NULL
	// vfs_kern_mount(&sysfs_fs_type, 0x400000, "sysfs", NULL): &(kmem_cache#2-oX (struct mount))->mnt
	// type: &shmem_fs_type, MS_KERNMOUNT: 0x400000, type->name: (&shmem_fs_type)->name: "tmpfs", data: NULL
	// vfs_kern_mount(&shmem_fs_type, 0x400000, "tmpfs", NULL): &(kmem_cache#2-oX (struct mount))->mnt
	mnt = vfs_kern_mount(type, MS_KERNMOUNT, type->name, data);
	// mnt: &(kmem_cache#2-oX (struct mount))->mnt
	// mnt: &(kmem_cache#2-oX (struct mount))->mnt

	// vfs_kern_mount에서 한일:
	// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 6
	// (&(&mnt_id_ida)->idr)->layers: 1
	// ((&(&mnt_id_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&mnt_id_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 0
	//
	// mnt_id_start: 1
	//
	// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "sysfs"
	// (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count: 1
	//
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->next: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->pprev: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->next: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->prev: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->next: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->prev: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->next: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->next: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->prev: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->next: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->prev: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->next: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->next: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks)->first: NULL
	//
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_flags: 0x4000
	//
	// struct sysfs_super_info의 메모리 kmem_cache#30-oX (struct sysfs_super_info)를 할당받음
	//
	// (kmem_cache#30-oX (struct sysfs_super_info))->ns[0]: NULL
	//
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
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 6
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// ((&(&unnamed_dev_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&unnamed_dev_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 0
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// unnamed_dev_start: 1
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 0
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_fs_info: kmem_cache#30-oX (struct sysfs_super_info)
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
	//
	// (kmem_cache#25-oX (struct super_block))->s_blocksize: 0x1000
	// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 12
	// (kmem_cache#25-oX (struct super_block))->s_magic: 0x62656572
	// (kmem_cache#25-oX (struct super_block))->s_op: &sysfs_ops
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1
	//
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
	//
	// (&sysfs_root)->s_count: 2
	//
	// (kmem_cache#4-oX (struct inode))->i_private: 2
	// (kmem_cache#4-oX (struct inode))->i_mapping->a_ops: &sysfs_aops
	// (kmem_cache#4-oX (struct inode))->i_mapping->backing_dev_info: &sysfs_backing_dev_info
	// (kmem_cache#4-oX (struct inode))->i_op: &sysfs_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값,
	// (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값,
	// (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_mode: 40447
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
	// (kmem_cache#4-oX (struct inode))->i_op: &sysfs_dir_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_fop: &sysfs_dir_operations
	// (kmem_cache#4-oX (struct inode))->i_state: 0x0
	// memory barrier 수행 (공유자원을 다른 cpu core가 사용할 수 있게 해줌)
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
	// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: &(kmem_cache#5-oX (struct dentry))->d_alias
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->pprev: &(&(kmem_cache#5-oX (struct dentry))->d_alias)
	//
	// (kmem_cache#5-oX (struct dentry))->d_inode: kmem_cache#4-oX (struct inode)
	//
	// 공유자원을 다른 cpu core가 사용할수 있게 함
	// (&(kmem_cache#5-oX (struct dentry))->d_seq)->sequence: 2
	//
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100000
	//
	// (kmem_cache#5-oX (struct dentry))->d_fsdata: &sysfs_root
	// (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#25-oX (struct super_block))->s_d_op: &sysfs_dentry_ops
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x40400000
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_lockref)->count: 1
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x60400000
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0
	//
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_flags: 0x4000
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_root: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_sb: kmem_cache#25-oX (struct super_block)
	// (kmem_cache#2-oX (struct mount))->mnt_mountpoint: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt_parent: kmem_cache#2-oX (struct mount)
	//
	// list head인 &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts에
	// &(kmem_cache#2-oX (struct mount))->mnt_instance를 tail로 연결

	// vfs_kern_mount에서 한일:
	// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 2 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 1번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 1
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함
	//
	// mnt_id_start: 2
	//
	// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "tmpfs"
	// (kmem_cache#2-oX (struct mount))->mnt_pcp: kmem_cache#26-o0 에서 할당된 8 bytes 메모리 주소
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count: 1
	//
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->next: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_hash)->pprev: NULL
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->next: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_child)->prev: (kmem_cache#2-oX (struct mount))->mnt_child
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->next: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_mounts)->prev: (kmem_cache#2-oX (struct mount))->mnt_mounts
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->next: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_list
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->next: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_expire)->prev: (kmem_cache#2-oX (struct mount))->mnt_expire
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->next: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_share)->prev: (kmem_cache#2-oX (struct mount))->mnt_share
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->next: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave_list)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave_list
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->next: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_slave)->prev: (kmem_cache#2-oX (struct mount))->mnt_slave
	// ((kmem_cache#2-oX (struct mount))->mnt_fsnotify_marks)->first: NULL
	//
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
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 2 개를 할당 받음
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 1번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 1         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 1)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// (&(&unnamed_dev_ida)->idr)->id_free: (idr object new 0)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 1 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 1) 의 memory 공간을 반환함
	//
	// unnamed_dev_start: 2
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 1
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_type: &shmem_fs_type
	// (kmem_cache#25-oX (struct super_block))->s_id: "tmpfs"
	//
	// list head인 &super_blocks 에 (kmem_cache#25-oX (struct super_block))->s_list을 tail에 추가
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->next: NULL
	// (&(&shmem_fs_type)->fs_supers)->first: &(kmem_cache#25-oX (struct super_block))->s_instances
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->pprev: &(&(&shmem_fs_type)->fs_supers)->first
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->flags: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->nr_deferred: kmem_cache#30-oX
	// head list인 &shrinker_list에 &(&(kmem_cache#25-oX (struct super_block))->s_shrink)->list를 tail로 추가함
	//
	// struct shmem_sb_info 사이즈 만큼의 메모리를 할당 받음 kmem_cache#29-oX (struct shmem_sb_info)
	//
	// (kmem_cache#29-oX (struct shmem_sb_info))->mode: 01777
	// (kmem_cache#29-oX (struct shmem_sb_info))->uid: 0
	// (kmem_cache#29-oX (struct shmem_sb_info))->gid: 0
	// (kmem_cache#25-oX (struct super_block))->s_fs_info: kmem_cache#29-oX (struct shmem_sb_info)
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x80400000
	// (kmem_cache#25-oX (struct super_block))->s_export_op: &shmem_export_ops
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x90400000
	//
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->magic: 0xdead4ead
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->owner: 0xffffffff
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->stat_lock)->owner_cpu: 0xffffffff
	//
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list)->next: &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list
	// (&(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list)->prev: &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->count: 0
	// (&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&(kmem_cache#29-oX (struct shmem_sb_info))->used_blocks)->list를 연결함
	//
	// (kmem_cache#29-oX (struct shmem_sb_info))->free_inodes: 0
	// (kmem_cache#25-oX (struct super_block))->s_maxbytes: 0x7ffffffffff
	// (kmem_cache#25-oX (struct super_block))->s_blocksize: 0x1000
	// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 12
	// (kmem_cache#25-oX (struct super_block))->s_magic: 0x01021994
	// (kmem_cache#25-oX (struct super_block))->s_op: &shmem_ops
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1
	// (kmem_cache#25-oX (struct super_block))->s_xattr: shmem_xattr_handlers
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x90410000
	//
	// struct shmem_sb_info 만큼의 메모리를 할당 받음 kmem_cache#29-oX (struct shmem_sb_info)
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
	// (kmem_cache#4-oX (struct inode))->i_dio_count: 0
	// (&(kmem_cache#4-oX (struct inode))->i_data)->a_ops: &empty_aops
	// (&(kmem_cache#4-oX (struct inode))->i_data)->host: kmem_cache#4-oX (struct inode)
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0
	// (&(kmem_cache#4-oX (struct inode))->i_data)->flags: 0x200DA
	// (&(kmem_cache#4-oX (struct inode))->i_data)->private_data: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_data)->backing_dev_info: &default_backing_dev_info
	// (&(kmem_cache#4-oX (struct inode))->i_data)->writeback_index: 0
	// (kmem_cache#4-oX (struct inode))->i_private: NULL
	// (kmem_cache#4-oX (struct inode))->i_mapping: &(kmem_cache#4-oX (struct inode))->i_data
	// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: NULL
	// (kmem_cache#4-oX (struct inode))->i_acl: (void *)(0xFFFFFFFF),
	// (kmem_cache#4-oX (struct inode))->i_default_acl: (void *)(0xFFFFFFFF)
	// (kmem_cache#4-oX (struct inode))->i_fsnotify_mask: 0
	// (kmem_cache#4-oX (struct inode))->i_ino: 1
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#4-oX (struct inode))->i_mode: 0041777
	// (kmem_cache#4-oX (struct inode))->i_blocks: 0
	// (kmem_cache#4-oX (struct inode))->i_mapping->backing_dev_info: &shmem_backing_dev_info
	// (kmem_cache#4-oX (struct inode))->i_atime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_mtime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_ctime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_generation: 현재시간의 sec 값
	// (kmem_cache#4-oX (struct inode))->i_acl: NULL
	// (kmem_cache#4-oX (struct inode))->i_default_acl: NULL
	// (&(kmem_cache#4-oX (struct inode))->i_sb->s_remove_count)->counter: -1
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
	// (kmem_cache#4-oX (struct inode))->i_size: 40
	// (kmem_cache#4-oX (struct inode))->i_op: &shmem_dir_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_fop: &simple_dir_operations
	//
	// (kmem_cache#4-oX (struct inode))->i_state: 0
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
	//
	// head list인 &(kmem_cache#4-oX (struct inode))->i_sb->s_inodes에 &(kmem_cache#4-oX (struct inode))->i_sb_list를 추가함
	//
	// [pcp0] nr_inodes: 1
	//
	// (&shared_last_ino)->counter: 1024
	// [pcp0] last_ino: 1
	//
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->magic: 0xdead4ead
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->owner: 0xffffffff
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->lock)->owner_cpu: 0xffffffff
	// (kmem_cache#4-oX (struct shmem_inode_info))->flags: 0x00200000
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->swaplist)->next: &(kmem_cache#4-oX (struct shmem_inode_info))->swaplist
	// (&(kmem_cache#4-oX (struct shmem_inode_info))->swaplist)->prev: &(kmem_cache#4-oX (struct shmem_inode_info))->swaplist
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head)->next: &(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head)->prev: &(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->head
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->raw_lock: { { 0 } }
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->magic: 0xdead4ead
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->owner: 0xffffffff
	// (&(&(kmem_cache#4-oX (struct shmem_inode_info))->xattrs)->lock)->owner_cpu: 0xffffffff
	//
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
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
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0xf0410000
	//
	// (&(kmem_cache#25-oX (struct super_block))->s_umount)->activity: 0
	//
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_root: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt.mnt_sb: kmem_cache#25-oX (struct super_block)
	// (kmem_cache#2-oX (struct mount))->mnt_mountpoint: kmem_cache#5-oX (struct dentry)
	// (kmem_cache#2-oX (struct mount))->mnt_parent: kmem_cache#2-oX (struct mount)
	//
	// list head인 &(kmem_cache#5-oX (struct dentry))->d_sb->s_mounts에
	// &(kmem_cache#2-oX (struct mount))->mnt_instance를 tail로 연결

	// mnt: &(kmem_cache#2-oX (struct mount))->mnt, IS_ERR(&(kmem_cache#2-oX (struct mount))->mnt): 0
	// mnt: &(kmem_cache#2-oX (struct mount))->mnt, IS_ERR(&(kmem_cache#2-oX (struct mount))->mnt): 0
	if (!IS_ERR(mnt)) {
		/*
		 * it is a longterm mount, don't release mnt until
		 * we unmount before file sys is unregistered
		*/
		// mnt: &(kmem_cache#2-oX (struct mount))->mnt, MNT_NS_INTERNAL: 0xffffffea
		// real_mount(&(kmem_cache#2-oX (struct mount))->mn): kmem_cache#2-oX (struct mount)
		// real_mount(&(kmem_cache#2-oX (struct mount))->mn)->mnt_ns: (kmem_cache#2-oX (struct mount))->mnt_ns
		// mnt: &(kmem_cache#2-oX (struct mount))->mnt, MNT_NS_INTERNAL: 0xffffffea
		// real_mount(&(kmem_cache#2-oX (struct mount))->mn): kmem_cache#2-oX (struct mount)
		// real_mount(&(kmem_cache#2-oX (struct mount))->mn)->mnt_ns: (kmem_cache#2-oX (struct mount))->mnt_ns
		real_mount(mnt)->mnt_ns = MNT_NS_INTERNAL;
		// real_mount(&(kmem_cache#2-oX (struct mount))->mn)->mnt_ns: (kmem_cache#2-oX (struct mount))->mnt_ns: 0xffffffea
		// real_mount(&(kmem_cache#2-oX (struct mount))->mn)->mnt_ns: (kmem_cache#2-oX (struct mount))->mnt_ns: 0xffffffea
	}

	// mnt: &(kmem_cache#2-oX (struct mount))->mnt
	// mnt: &(kmem_cache#2-oX (struct mount))->mnt
	return mnt;
	// return &(kmem_cache#2-oX (struct mount))->mnt
	// return &(kmem_cache#2-oX (struct mount))->mnt
}
EXPORT_SYMBOL_GPL(kern_mount_data);

void kern_unmount(struct vfsmount *mnt)
{
	/* release long term mount so mount point can be released */
	if (!IS_ERR_OR_NULL(mnt)) {
		real_mount(mnt)->mnt_ns = NULL;
		synchronize_rcu();	/* yecchhh... */
		mntput(mnt);
	}
}
EXPORT_SYMBOL(kern_unmount);

bool our_mnt(struct vfsmount *mnt)
{
	return check_mnt(real_mount(mnt));
}

bool current_chrooted(void)
{
	/* Does the current process have a non-standard root */
	struct path ns_root;
	struct path fs_root;
	bool chrooted;

	/* Find the namespace root */
	ns_root.mnt = &current->nsproxy->mnt_ns->root->mnt;
	ns_root.dentry = ns_root.mnt->mnt_root;
	path_get(&ns_root);
	while (d_mountpoint(ns_root.dentry) && follow_down_one(&ns_root))
		;

	get_fs_root(current->fs, &fs_root);

	chrooted = !path_equal(&fs_root, &ns_root);

	path_put(&fs_root);
	path_put(&ns_root);

	return chrooted;
}

bool fs_fully_visible(struct file_system_type *type)
{
	struct mnt_namespace *ns = current->nsproxy->mnt_ns;
	struct mount *mnt;
	bool visible = false;

	if (unlikely(!ns))
		return false;

	down_read(&namespace_sem);
	list_for_each_entry(mnt, &ns->list, mnt_list) {
		struct mount *child;
		if (mnt->mnt.mnt_sb->s_type != type)
			continue;

		/* This mount is not fully visible if there are any child mounts
		 * that cover anything except for empty directories.
		 */
		list_for_each_entry(child, &mnt->mnt_mounts, mnt_child) {
			struct inode *inode = child->mnt_mountpoint->d_inode;
			if (!S_ISDIR(inode->i_mode))
				goto next;
			if (inode->i_nlink > 2)
				goto next;
		}
		visible = true;
		goto found;
	next:	;
	}
found:
	up_read(&namespace_sem);
	return visible;
}

static void *mntns_get(struct task_struct *task)
{
	struct mnt_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	rcu_read_lock();
	nsproxy = task_nsproxy(task);
	if (nsproxy) {
		ns = nsproxy->mnt_ns;
		get_mnt_ns(ns);
	}
	rcu_read_unlock();

	return ns;
}

static void mntns_put(void *ns)
{
	put_mnt_ns(ns);
}

static int mntns_install(struct nsproxy *nsproxy, void *ns)
{
	struct fs_struct *fs = current->fs;
	struct mnt_namespace *mnt_ns = ns;
	struct path root;

	if (!ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(current_user_ns(), CAP_SYS_CHROOT) ||
	    !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
		return -EPERM;

	if (fs->users != 1)
		return -EINVAL;

	get_mnt_ns(mnt_ns);
	put_mnt_ns(nsproxy->mnt_ns);
	nsproxy->mnt_ns = mnt_ns;

	/* Find the root */
	root.mnt    = &mnt_ns->root->mnt;
	root.dentry = mnt_ns->root->mnt.mnt_root;
	path_get(&root);
	while(d_mountpoint(root.dentry) && follow_down_one(&root))
		;

	/* Update the pwd and root */
	set_fs_pwd(fs, &root);
	set_fs_root(fs, &root);

	path_put(&root);
	return 0;
}

static unsigned int mntns_inum(void *ns)
{
	struct mnt_namespace *mnt_ns = ns;
	return mnt_ns->proc_inum;
}

const struct proc_ns_operations mntns_operations = {
	.name		= "mnt",
	.type		= CLONE_NEWNS,
	.get		= mntns_get,
	.put		= mntns_put,
	.install	= mntns_install,
	.inum		= mntns_inum,
};
