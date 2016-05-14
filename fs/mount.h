#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/poll.h>

// ARM10C 20160326
// ARM10C 20160514
// sizeof(struct mnt_namespace): 60 bytes
struct mnt_namespace {
	atomic_t		count;
	unsigned int		proc_inum;
	struct mount *	root;
	struct list_head	list;
	struct user_namespace	*user_ns;
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t poll;
	int event;
};

// ARM10C 20151024
// ARM10C 20151107
// sizeof(struct mnt_pcp): 8 bytes
struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mountpoint {
	struct hlist_node m_hash;
	struct dentry *m_dentry;
	int m_count;
};

// ARM10C 20151024
// ARM10C 20151031
// ARM10C 20160109
// ARM10C 20160213
// sizeof(struct mount): 152 bytes
struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	struct rcu_head mnt_rcu;
#ifdef CONFIG_SMP // CONFIG_SMP=y
	struct mnt_pcp __percpu *mnt_pcp;
#else
	int mnt_count;
	int mnt_writers;
#endif
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	struct mountpoint *mnt_mp;	/* where is it mounted */
#ifdef CONFIG_FSNOTIFY // CONFIG_FSNOTIFY=y
	struct hlist_head mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	int mnt_id;			/* mount identifier */
	int mnt_group_id;		/* peer group identifier */
	int mnt_expiry_mark;		/* true if marked for expiry */
	int mnt_pinned;
	struct path mnt_ex_mountpoint;
};

// ARM10C 20160109
// EINVAL: 22
// ERR_PTR(-22): 0xffffffea
// MNT_NS_INTERNAL: 0xffffffea
#define MNT_NS_INTERNAL ERR_PTR(-EINVAL) /* distinct from any mnt_namespace */

// ARM10C 20160109
// mnt: &(kmem_cache#2-oX (struct mount))->mnt
// ARM10C 20160326
// mnt: &(kmem_cache#2-oX (struct mount))->mnt
static inline struct mount *real_mount(struct vfsmount *mnt)
{
	// mnt: &(kmem_cache#2-oX (struct mount))->mnt
	// container_of(&(kmem_cache#2-oX (struct mount))->mnt, struct mount, &(kmem_cache#2-oX (struct mount))->mnt):
	// kmem_cache#2-oX (struct mount)
	return container_of(mnt, struct mount, mnt);
	// return kmem_cache#2-oX (struct mount)
}

static inline int mnt_has_parent(struct mount *mnt)
{
	return mnt != mnt->mnt_parent;
}

static inline int is_mounted(struct vfsmount *mnt)
{
	/* neither detached nor internal? */
	return !IS_ERR_OR_NULL(real_mount(mnt)->mnt_ns);
}

extern struct mount *__lookup_mnt(struct vfsmount *, struct dentry *);
extern struct mount *__lookup_mnt_last(struct vfsmount *, struct dentry *);

extern bool legitimize_mnt(struct vfsmount *, unsigned);

static inline void get_mnt_ns(struct mnt_namespace *ns)
{
	atomic_inc(&ns->count);
}

extern seqlock_t mount_lock;

// ARM10C 20160109
// ARM10C 20160326
// ARM10C 20160514
static inline void lock_mount_hash(void)
{
	write_seqlock(&mount_lock);

	// write_seqlock에서 한일:
	// &(&mount_lock)->lock 을 사용하여 spin lock 수행
	// (&(&mount_lock)->seqcount)->sequence: 1
	// 공유자원을 다른 cpu core가 사용할수 있게 메모리 적용

}

// ARM10C 20160109
// ARM10C 20160326
// ARM10C 20160514
static inline void unlock_mount_hash(void)
{
	write_sequnlock(&mount_lock);

	// write_sequnlock에서 한일:
	// 공유자원을 다른 cpu core가 사용할수 있게 메모리 적용
	// (&(&mount_lock)->seqcount)->sequence: 2
	// &(&mount_lock)->lock을 사용하여 spin unlock 수행
}

struct proc_mounts {
	struct seq_file m;
	struct mnt_namespace *ns;
	struct path root;
	int (*show)(struct seq_file *, struct vfsmount *);
};

#define proc_mounts(p) (container_of((p), struct proc_mounts, m))

extern const struct seq_operations mounts_op;
