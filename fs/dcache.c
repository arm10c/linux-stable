/*
 * fs/dcache.c
 *
 * Complete reimplementation
 * (C) 1997 Thomas Schoebel-Theuer,
 * with heavy changes by Linus Torvalds
 */

/*
 * Notes on the allocation strategy:
 *
 * The dcache is a master of the icache - whenever a dcache entry
 * exists, the inode will always exist. "iput()" is done either when
 * the dcache entry is deleted or garbage collected.
 */

#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/export.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <linux/security.h>
#include <linux/seqlock.h>
#include <linux/swap.h>
#include <linux/bootmem.h>
#include <linux/fs_struct.h>
#include <linux/hardirq.h>
#include <linux/bit_spinlock.h>
#include <linux/rculist_bl.h>
#include <linux/prefetch.h>
#include <linux/ratelimit.h>
#include <linux/list_lru.h>
#include "internal.h"
#include "mount.h"

/*
 * Usage:
 * dcache->d_inode->i_lock protects:
 *   - i_dentry, d_alias, d_inode of aliases
 * dcache_hash_bucket lock protects:
 *   - the dcache hash table
 * s_anon bl list spinlock protects:
 *   - the s_anon list (see __d_drop)
 * dentry->d_sb->s_dentry_lru_lock protects:
 *   - the dcache lru lists and counters
 * d_lock protects:
 *   - d_flags
 *   - d_name
 *   - d_lru
 *   - d_count
 *   - d_unhashed()
 *   - d_parent and d_subdirs
 *   - childrens' d_child and d_parent
 *   - d_alias, d_inode
 *
 * Ordering:
 * dentry->d_inode->i_lock
 *   dentry->d_lock
 *     dentry->d_sb->s_dentry_lru_lock
 *     dcache_hash_bucket lock
 *     s_anon lock
 *
 * If there is an ancestor relationship:
 * dentry->d_parent->...->d_parent->d_lock
 *   ...
 *     dentry->d_parent->d_lock
 *       dentry->d_lock
 *
 * If no ancestor relationship:
 * if (dentry1 < dentry2)
 *   dentry1->d_lock
 *     dentry2->d_lock
 */
int sysctl_vfs_cache_pressure __read_mostly = 100;
EXPORT_SYMBOL_GPL(sysctl_vfs_cache_pressure);

__cacheline_aligned_in_smp DEFINE_SEQLOCK(rename_lock);

EXPORT_SYMBOL(rename_lock);

// ARM10C 20151003
// ARM10C 20151212
static struct kmem_cache *dentry_cache __read_mostly;

/*
 * This is the single most critical data structure when it comes
 * to the dcache: the hashtable for lookups. Somebody should try
 * to make this good - I've just made it work.
 *
 * This hash-function tries to avoid losing too many bits of hash
 * information, yet avoid using a prime hash-size or similar.
 */

// ARM10C 20140322
// ARM10C 20161126
static unsigned int d_hash_mask __read_mostly;
// ARM10C 20140322
// ARM10C 20161126
static unsigned int d_hash_shift __read_mostly;
// ARM10C 20140322
// ARM10C 20161126
static struct hlist_bl_head *dentry_hashtable __read_mostly;

// ARM10C 20161126
// entry->d_parent: (kmem_cache#5-oX (struct dentry))->d_parent: kmem_cache#5-oX (struct dentry),
// entry->d_name.hash: (kmem_cache#5-oX (struct dentry))->d_name.hash: 0xXXXXXXXX
static inline struct hlist_bl_head *d_hash(const struct dentry *parent,
					unsigned int hash)
{
	// hash: 0xXXXXXXXX, parent: kmem_cache#5-oX (struct dentry), L1_CACHE_BYTES: 64
	hash += (unsigned long) parent / L1_CACHE_BYTES;
	// hash: 0xXXXXXXXX

	// hash: 0xXXXXXXXX, d_hash_shift: 17
	hash = hash + (hash >> d_hash_shift);
	// hash: 0xXXXXXXXX

	// dentry_hashtable: dentry hash를 위한 메모리 공간 512kB, hash: 0xXXXXXXXX, d_hash_mask: 0x1FFFF
	return dentry_hashtable + (hash & d_hash_mask);
	// return hash 0xXXXXXXXX 에 맞는 list table 주소값
}

/* Statistics gathering. */
struct dentry_stat_t dentry_stat = {
	.age_limit = 45,
};

// ARM10C 20151219
// DEFINE_PER_CPU(long, nr_dentry):
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(unsigned long) nr_dentry
static DEFINE_PER_CPU(long, nr_dentry);
static DEFINE_PER_CPU(long, nr_dentry_unused);

#if defined(CONFIG_SYSCTL) && defined(CONFIG_PROC_FS)

/*
 * Here we resort to our own counters instead of using generic per-cpu counters
 * for consistency with what the vfs inode code does. We are expected to harvest
 * better code and performance by having our own specialized counters.
 *
 * Please note that the loop is done over all possible CPUs, not over all online
 * CPUs. The reason for this is that we don't want to play games with CPUs going
 * on and off. If one of them goes off, we will just keep their counters.
 *
 * glommer: See cffbc8a for details, and if you ever intend to change this,
 * please update all vfs counters to match.
 */
static long get_nr_dentry(void)
{
	int i;
	long sum = 0;
	for_each_possible_cpu(i)
		sum += per_cpu(nr_dentry, i);
	return sum < 0 ? 0 : sum;
}

static long get_nr_dentry_unused(void)
{
	int i;
	long sum = 0;
	for_each_possible_cpu(i)
		sum += per_cpu(nr_dentry_unused, i);
	return sum < 0 ? 0 : sum;
}

int proc_nr_dentry(ctl_table *table, int write, void __user *buffer,
		   size_t *lenp, loff_t *ppos)
{
	dentry_stat.nr_dentry = get_nr_dentry();
	dentry_stat.nr_unused = get_nr_dentry_unused();
	return proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
}
#endif

/*
 * Compare 2 name strings, return 0 if they match, otherwise non-zero.
 * The strings are both count bytes long, and count is non-zero.
 */
#ifdef CONFIG_DCACHE_WORD_ACCESS

#include <asm/word-at-a-time.h>
/*
 * NOTE! 'cs' and 'scount' come from a dentry, so it has a
 * aligned allocation for this particular component. We don't
 * strictly need the load_unaligned_zeropad() safety, but it
 * doesn't hurt either.
 *
 * In contrast, 'ct' and 'tcount' can be from a pathname, and do
 * need the careful unaligned handling.
 */
static inline int dentry_string_cmp(const unsigned char *cs, const unsigned char *ct, unsigned tcount)
{
	unsigned long a,b,mask;

	for (;;) {
		a = *(unsigned long *)cs;
		b = load_unaligned_zeropad(ct);
		if (tcount < sizeof(unsigned long))
			break;
		if (unlikely(a != b))
			return 1;
		cs += sizeof(unsigned long);
		ct += sizeof(unsigned long);
		tcount -= sizeof(unsigned long);
		if (!tcount)
			return 0;
	}
	mask = bytemask_from_count(tcount);
	return unlikely(!!((a ^ b) & mask));
}

#else

static inline int dentry_string_cmp(const unsigned char *cs, const unsigned char *ct, unsigned tcount)
{
	do {
		if (*cs != *ct)
			return 1;
		cs++;
		ct++;
		tcount--;
	} while (tcount);
	return 0;
}

#endif

static inline int dentry_cmp(const struct dentry *dentry, const unsigned char *ct, unsigned tcount)
{
	const unsigned char *cs;
	/*
	 * Be careful about RCU walk racing with rename:
	 * use ACCESS_ONCE to fetch the name pointer.
	 *
	 * NOTE! Even if a rename will mean that the length
	 * was not loaded atomically, we don't care. The
	 * RCU walk will check the sequence count eventually,
	 * and catch it. And we won't overrun the buffer,
	 * because we're reading the name pointer atomically,
	 * and a dentry name is guaranteed to be properly
	 * terminated with a NUL byte.
	 *
	 * End result: even if 'len' is wrong, we'll exit
	 * early because the data cannot match (there can
	 * be no NUL in the ct/tcount data)
	 */
	cs = ACCESS_ONCE(dentry->d_name.name);
	smp_read_barrier_depends();
	return dentry_string_cmp(cs, ct, tcount);
}

static void __d_free(struct rcu_head *head)
{
	struct dentry *dentry = container_of(head, struct dentry, d_u.d_rcu);

	WARN_ON(!hlist_unhashed(&dentry->d_alias));
	if (dname_external(dentry))
		kfree(dentry->d_name.name);
	kmem_cache_free(dentry_cache, dentry); 
}

/*
 * no locks, please.
 */
static void d_free(struct dentry *dentry)
{
	BUG_ON((int)dentry->d_lockref.count > 0);
	this_cpu_dec(nr_dentry);
	if (dentry->d_op && dentry->d_op->d_release)
		dentry->d_op->d_release(dentry);

	/* if dentry was never visible to RCU, immediate free is OK */
	if (!(dentry->d_flags & DCACHE_RCUACCESS))
		__d_free(&dentry->d_u.d_rcu);
	else
		call_rcu(&dentry->d_u.d_rcu, __d_free);
}

/**
 * dentry_rcuwalk_barrier - invalidate in-progress rcu-walk lookups
 * @dentry: the target dentry
 * After this call, in-progress rcu-walk path lookup will fail. This
 * should be called after unhashing, and after changing d_inode (if
 * the dentry has not already been unhashed).
 */
// ARM10C 20151219
// dentry: kmem_cache#5-oX (struct dentry)
static inline void dentry_rcuwalk_barrier(struct dentry *dentry)
{
	// &dentry->d_lock: &(kmem_cache#5-oX (struct dentry))->d_lock
	assert_spin_locked(&dentry->d_lock);
	
	/* Go through a barrier */
	// &dentry->d_seq: &(kmem_cache#5-oX (struct dentry))->d_seq
	write_seqcount_barrier(&dentry->d_seq);

	// write_seqcount_barrier에서 한일:
	// 공유자원을 다른 cpu core가 사용할수 있게 함
	// (&(kmem_cache#5-oX (struct dentry))->d_seq)->sequence: 2
}

/*
 * Release the dentry's inode, using the filesystem
 * d_iput() operation if defined. Dentry has no refcount
 * and is unhashed.
 */
static void dentry_iput(struct dentry * dentry)
	__releases(dentry->d_lock)
	__releases(dentry->d_inode->i_lock)
{
	struct inode *inode = dentry->d_inode;
	if (inode) {
		dentry->d_inode = NULL;
		hlist_del_init(&dentry->d_alias);
		spin_unlock(&dentry->d_lock);
		spin_unlock(&inode->i_lock);
		if (!inode->i_nlink)
			fsnotify_inoderemove(inode);
		if (dentry->d_op && dentry->d_op->d_iput)
			dentry->d_op->d_iput(dentry, inode);
		else
			iput(inode);
	} else {
		spin_unlock(&dentry->d_lock);
	}
}

/*
 * Release the dentry's inode, using the filesystem
 * d_iput() operation if defined. dentry remains in-use.
 */
static void dentry_unlink_inode(struct dentry * dentry)
	__releases(dentry->d_lock)
	__releases(dentry->d_inode->i_lock)
{
	struct inode *inode = dentry->d_inode;
	__d_clear_type(dentry);
	dentry->d_inode = NULL;
	hlist_del_init(&dentry->d_alias);
	dentry_rcuwalk_barrier(dentry);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&inode->i_lock);
	if (!inode->i_nlink)
		fsnotify_inoderemove(inode);
	if (dentry->d_op && dentry->d_op->d_iput)
		dentry->d_op->d_iput(dentry, inode);
	else
		iput(inode);
}

/*
 * The DCACHE_LRU_LIST bit is set whenever the 'd_lru' entry
 * is in use - which includes both the "real" per-superblock
 * LRU list _and_ the DCACHE_SHRINK_LIST use.
 *
 * The DCACHE_SHRINK_LIST bit is set whenever the dentry is
 * on the shrink list (ie not on the superblock LRU list).
 *
 * The per-cpu "nr_dentry_unused" counters are updated with
 * the DCACHE_LRU_LIST bit.
 *
 * These helper functions make sure we always follow the
 * rules. d_lock must be held by the caller.
 */
#define D_FLAG_VERIFY(dentry,x) WARN_ON_ONCE(((dentry)->d_flags & (DCACHE_LRU_LIST | DCACHE_SHRINK_LIST)) != (x))
static void d_lru_add(struct dentry *dentry)
{
	D_FLAG_VERIFY(dentry, 0);
	dentry->d_flags |= DCACHE_LRU_LIST;
	this_cpu_inc(nr_dentry_unused);
	WARN_ON_ONCE(!list_lru_add(&dentry->d_sb->s_dentry_lru, &dentry->d_lru));
}

static void d_lru_del(struct dentry *dentry)
{
	D_FLAG_VERIFY(dentry, DCACHE_LRU_LIST);
	dentry->d_flags &= ~DCACHE_LRU_LIST;
	this_cpu_dec(nr_dentry_unused);
	WARN_ON_ONCE(!list_lru_del(&dentry->d_sb->s_dentry_lru, &dentry->d_lru));
}

static void d_shrink_del(struct dentry *dentry)
{
	D_FLAG_VERIFY(dentry, DCACHE_SHRINK_LIST | DCACHE_LRU_LIST);
	list_del_init(&dentry->d_lru);
	dentry->d_flags &= ~(DCACHE_SHRINK_LIST | DCACHE_LRU_LIST);
	this_cpu_dec(nr_dentry_unused);
}

static void d_shrink_add(struct dentry *dentry, struct list_head *list)
{
	D_FLAG_VERIFY(dentry, 0);
	list_add(&dentry->d_lru, list);
	dentry->d_flags |= DCACHE_SHRINK_LIST | DCACHE_LRU_LIST;
	this_cpu_inc(nr_dentry_unused);
}

/*
 * These can only be called under the global LRU lock, ie during the
 * callback for freeing the LRU list. "isolate" removes it from the
 * LRU lists entirely, while shrink_move moves it to the indicated
 * private list.
 */
static void d_lru_isolate(struct dentry *dentry)
{
	D_FLAG_VERIFY(dentry, DCACHE_LRU_LIST);
	dentry->d_flags &= ~DCACHE_LRU_LIST;
	this_cpu_dec(nr_dentry_unused);
	list_del_init(&dentry->d_lru);
}

static void d_lru_shrink_move(struct dentry *dentry, struct list_head *list)
{
	D_FLAG_VERIFY(dentry, DCACHE_LRU_LIST);
	dentry->d_flags |= DCACHE_SHRINK_LIST;
	list_move_tail(&dentry->d_lru, list);
}

/*
 * dentry_lru_(add|del)_list) must be called with d_lock held.
 */
static void dentry_lru_add(struct dentry *dentry)
{
	if (unlikely(!(dentry->d_flags & DCACHE_LRU_LIST)))
		d_lru_add(dentry);
}

/*
 * Remove a dentry with references from the LRU.
 *
 * If we are on the shrink list, then we can get to try_prune_one_dentry() and
 * lose our last reference through the parent walk. In this case, we need to
 * remove ourselves from the shrink list, not the LRU.
 */
static void dentry_lru_del(struct dentry *dentry)
{
	if (dentry->d_flags & DCACHE_LRU_LIST) {
		if (dentry->d_flags & DCACHE_SHRINK_LIST)
			return d_shrink_del(dentry);
		d_lru_del(dentry);
	}
}

/**
 * d_kill - kill dentry and return parent
 * @dentry: dentry to kill
 * @parent: parent dentry
 *
 * The dentry must already be unhashed and removed from the LRU.
 *
 * If this is the root of the dentry tree, return NULL.
 *
 * dentry->d_lock and parent->d_lock must be held by caller, and are dropped by
 * d_kill.
 */
static struct dentry *d_kill(struct dentry *dentry, struct dentry *parent)
	__releases(dentry->d_lock)
	__releases(parent->d_lock)
	__releases(dentry->d_inode->i_lock)
{
	list_del(&dentry->d_u.d_child);
	/*
	 * Inform d_walk() that we are no longer attached to the
	 * dentry tree
	 */
	dentry->d_flags |= DCACHE_DENTRY_KILLED;
	if (parent)
		spin_unlock(&parent->d_lock);
	dentry_iput(dentry);
	/*
	 * dentry_iput drops the locks, at which point nobody (except
	 * transient RCU lookups) can reach this dentry.
	 */
	d_free(dentry);
	return parent;
}

/**
 * d_drop - drop a dentry
 * @dentry: dentry to drop
 *
 * d_drop() unhashes the entry from the parent dentry hashes, so that it won't
 * be found through a VFS lookup any more. Note that this is different from
 * deleting the dentry - d_delete will try to mark the dentry negative if
 * possible, giving a successful _negative_ lookup, while d_drop will
 * just make the cache lookup fail.
 *
 * d_drop() is used mainly for stuff that wants to invalidate a dentry for some
 * reason (NFS timeouts or autofs deletes).
 *
 * __d_drop requires dentry->d_lock.
 */
void __d_drop(struct dentry *dentry)
{
	if (!d_unhashed(dentry)) {
		struct hlist_bl_head *b;
		/*
		 * Hashed dentries are normally on the dentry hashtable,
		 * with the exception of those newly allocated by
		 * d_obtain_alias, which are always IS_ROOT:
		 */
		if (unlikely(IS_ROOT(dentry)))
			b = &dentry->d_sb->s_anon;
		else
			b = d_hash(dentry->d_parent, dentry->d_name.hash);

		hlist_bl_lock(b);
		__hlist_bl_del(&dentry->d_hash);
		dentry->d_hash.pprev = NULL;
		hlist_bl_unlock(b);
		dentry_rcuwalk_barrier(dentry);
	}
}
EXPORT_SYMBOL(__d_drop);

void d_drop(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	__d_drop(dentry);
	spin_unlock(&dentry->d_lock);
}
EXPORT_SYMBOL(d_drop);

/*
 * Finish off a dentry we've decided to kill.
 * dentry->d_lock must be held, returns with it unlocked.
 * If ref is non-zero, then decrement the refcount too.
 * Returns dentry requiring refcount drop, or NULL if we're done.
 */
static struct dentry *
dentry_kill(struct dentry *dentry, int unlock_on_failure)
	__releases(dentry->d_lock)
{
	struct inode *inode;
	struct dentry *parent;

	inode = dentry->d_inode;
	if (inode && !spin_trylock(&inode->i_lock)) {
relock:
		if (unlock_on_failure) {
			spin_unlock(&dentry->d_lock);
			cpu_relax();
		}
		return dentry; /* try again with same dentry */
	}
	if (IS_ROOT(dentry))
		parent = NULL;
	else
		parent = dentry->d_parent;
	if (parent && !spin_trylock(&parent->d_lock)) {
		if (inode)
			spin_unlock(&inode->i_lock);
		goto relock;
	}

	/*
	 * The dentry is now unrecoverably dead to the world.
	 */
	lockref_mark_dead(&dentry->d_lockref);

	/*
	 * inform the fs via d_prune that this dentry is about to be
	 * unhashed and destroyed.
	 */
	if ((dentry->d_flags & DCACHE_OP_PRUNE) && !d_unhashed(dentry))
		dentry->d_op->d_prune(dentry);

	dentry_lru_del(dentry);
	/* if it was on the hash then remove it */
	__d_drop(dentry);
	return d_kill(dentry, parent);
}

/* 
 * This is dput
 *
 * This is complicated by the fact that we do not want to put
 * dentries that are no longer on any hash chain on the unused
 * list: we'd much rather just get rid of them immediately.
 *
 * However, that implies that we have to traverse the dentry
 * tree upwards to the parents which might _also_ now be
 * scheduled for deletion (it may have been only waiting for
 * its last child to go away).
 *
 * This tail recursion is done by hand as we don't want to depend
 * on the compiler to always get this right (gcc generally doesn't).
 * Real recursion would eat up our stack space.
 */

/*
 * dput - release a dentry
 * @dentry: dentry to release 
 *
 * Release a dentry. This will drop the usage count and if appropriate
 * call the dentry unlink method as well as removing it from the queues and
 * releasing its resources. If the parent dentries were scheduled for release
 * they too may now get deleted.
 */
void dput(struct dentry *dentry)
{
	if (unlikely(!dentry))
		return;

repeat:
	if (lockref_put_or_lock(&dentry->d_lockref))
		return;

	/* Unreachable? Get rid of it */
	if (unlikely(d_unhashed(dentry)))
		goto kill_it;

	if (unlikely(dentry->d_flags & DCACHE_OP_DELETE)) {
		if (dentry->d_op->d_delete(dentry))
			goto kill_it;
	}

	if (!(dentry->d_flags & DCACHE_REFERENCED))
		dentry->d_flags |= DCACHE_REFERENCED;
	dentry_lru_add(dentry);

	dentry->d_lockref.count--;
	spin_unlock(&dentry->d_lock);
	return;

kill_it:
	dentry = dentry_kill(dentry, 1);
	if (dentry)
		goto repeat;
}
EXPORT_SYMBOL(dput);

/**
 * d_invalidate - invalidate a dentry
 * @dentry: dentry to invalidate
 *
 * Try to invalidate the dentry if it turns out to be
 * possible. If there are other dentries that can be
 * reached through this one we can't delete it and we
 * return -EBUSY. On success we return 0.
 *
 * no dcache lock.
 */
 
int d_invalidate(struct dentry * dentry)
{
	/*
	 * If it's already been dropped, return OK.
	 */
	spin_lock(&dentry->d_lock);
	if (d_unhashed(dentry)) {
		spin_unlock(&dentry->d_lock);
		return 0;
	}
	/*
	 * Check whether to do a partial shrink_dcache
	 * to get rid of unused child entries.
	 */
	if (!list_empty(&dentry->d_subdirs)) {
		spin_unlock(&dentry->d_lock);
		shrink_dcache_parent(dentry);
		spin_lock(&dentry->d_lock);
	}

	/*
	 * Somebody else still using it?
	 *
	 * If it's a directory, we can't drop it
	 * for fear of somebody re-populating it
	 * with children (even though dropping it
	 * would make it unreachable from the root,
	 * we might still populate it if it was a
	 * working directory or similar).
	 * We also need to leave mountpoints alone,
	 * directory or not.
	 */
	if (dentry->d_lockref.count > 1 && dentry->d_inode) {
		if (S_ISDIR(dentry->d_inode->i_mode) || d_mountpoint(dentry)) {
			spin_unlock(&dentry->d_lock);
			return -EBUSY;
		}
	}

	__d_drop(dentry);
	spin_unlock(&dentry->d_lock);
	return 0;
}
EXPORT_SYMBOL(d_invalidate);

/* This must be called with d_lock held */
// ARM10C 20161126
// parent: kmem_cache#5-oX (struct dentry)
static inline void __dget_dlock(struct dentry *dentry)
{
	// dentry->d_lockref.count: (kmem_cache#5-oX (struct dentry))->d_lockref.count: 0
	dentry->d_lockref.count++;
	// dentry->d_lockref.count: (kmem_cache#5-oX (struct dentry))->d_lockref.count: 1
}

static inline void __dget(struct dentry *dentry)
{
	lockref_get(&dentry->d_lockref);
}

struct dentry *dget_parent(struct dentry *dentry)
{
	int gotref;
	struct dentry *ret;

	/*
	 * Do optimistic parent lookup without any
	 * locking.
	 */
	rcu_read_lock();
	ret = ACCESS_ONCE(dentry->d_parent);
	gotref = lockref_get_not_zero(&ret->d_lockref);
	rcu_read_unlock();
	if (likely(gotref)) {
		if (likely(ret == ACCESS_ONCE(dentry->d_parent)))
			return ret;
		dput(ret);
	}

repeat:
	/*
	 * Don't need rcu_dereference because we re-check it was correct under
	 * the lock.
	 */
	rcu_read_lock();
	ret = dentry->d_parent;
	spin_lock(&ret->d_lock);
	if (unlikely(ret != dentry->d_parent)) {
		spin_unlock(&ret->d_lock);
		rcu_read_unlock();
		goto repeat;
	}
	rcu_read_unlock();
	BUG_ON(!ret->d_lockref.count);
	ret->d_lockref.count++;
	spin_unlock(&ret->d_lock);
	return ret;
}
EXPORT_SYMBOL(dget_parent);

/**
 * d_find_alias - grab a hashed alias of inode
 * @inode: inode in question
 * @want_discon:  flag, used by d_splice_alias, to request
 *          that only a DISCONNECTED alias be returned.
 *
 * If inode has a hashed alias, or is a directory and has any alias,
 * acquire the reference to alias and return it. Otherwise return NULL.
 * Notice that if inode is a directory there can be only one alias and
 * it can be unhashed only if it has no children, or if it is the root
 * of a filesystem.
 *
 * If the inode has an IS_ROOT, DCACHE_DISCONNECTED alias, then prefer
 * any other hashed alias over that one unless @want_discon is set,
 * in which case only return an IS_ROOT, DCACHE_DISCONNECTED alias.
 */
static struct dentry *__d_find_alias(struct inode *inode, int want_discon)
{
	struct dentry *alias, *discon_alias;

again:
	discon_alias = NULL;
	hlist_for_each_entry(alias, &inode->i_dentry, d_alias) {
		spin_lock(&alias->d_lock);
 		if (S_ISDIR(inode->i_mode) || !d_unhashed(alias)) {
			if (IS_ROOT(alias) &&
			    (alias->d_flags & DCACHE_DISCONNECTED)) {
				discon_alias = alias;
			} else if (!want_discon) {
				__dget_dlock(alias);
				spin_unlock(&alias->d_lock);
				return alias;
			}
		}
		spin_unlock(&alias->d_lock);
	}
	if (discon_alias) {
		alias = discon_alias;
		spin_lock(&alias->d_lock);
		if (S_ISDIR(inode->i_mode) || !d_unhashed(alias)) {
			if (IS_ROOT(alias) &&
			    (alias->d_flags & DCACHE_DISCONNECTED)) {
				__dget_dlock(alias);
				spin_unlock(&alias->d_lock);
				return alias;
			}
		}
		spin_unlock(&alias->d_lock);
		goto again;
	}
	return NULL;
}

struct dentry *d_find_alias(struct inode *inode)
{
	struct dentry *de = NULL;

	if (!hlist_empty(&inode->i_dentry)) {
		spin_lock(&inode->i_lock);
		de = __d_find_alias(inode, 0);
		spin_unlock(&inode->i_lock);
	}
	return de;
}
EXPORT_SYMBOL(d_find_alias);

/*
 *	Try to kill dentries associated with this inode.
 * WARNING: you must own a reference to inode.
 */
void d_prune_aliases(struct inode *inode)
{
	struct dentry *dentry;
restart:
	spin_lock(&inode->i_lock);
	hlist_for_each_entry(dentry, &inode->i_dentry, d_alias) {
		spin_lock(&dentry->d_lock);
		if (!dentry->d_lockref.count) {
			/*
			 * inform the fs via d_prune that this dentry
			 * is about to be unhashed and destroyed.
			 */
			if ((dentry->d_flags & DCACHE_OP_PRUNE) &&
			    !d_unhashed(dentry))
				dentry->d_op->d_prune(dentry);

			__dget_dlock(dentry);
			__d_drop(dentry);
			spin_unlock(&dentry->d_lock);
			spin_unlock(&inode->i_lock);
			dput(dentry);
			goto restart;
		}
		spin_unlock(&dentry->d_lock);
	}
	spin_unlock(&inode->i_lock);
}
EXPORT_SYMBOL(d_prune_aliases);

/*
 * Try to throw away a dentry - free the inode, dput the parent.
 * Requires dentry->d_lock is held, and dentry->d_count == 0.
 * Releases dentry->d_lock.
 *
 * This may fail if locks cannot be acquired no problem, just try again.
 */
static struct dentry * try_prune_one_dentry(struct dentry *dentry)
	__releases(dentry->d_lock)
{
	struct dentry *parent;

	parent = dentry_kill(dentry, 0);
	/*
	 * If dentry_kill returns NULL, we have nothing more to do.
	 * if it returns the same dentry, trylocks failed. In either
	 * case, just loop again.
	 *
	 * Otherwise, we need to prune ancestors too. This is necessary
	 * to prevent quadratic behavior of shrink_dcache_parent(), but
	 * is also expected to be beneficial in reducing dentry cache
	 * fragmentation.
	 */
	if (!parent)
		return NULL;
	if (parent == dentry)
		return dentry;

	/* Prune ancestors. */
	dentry = parent;
	while (dentry) {
		if (lockref_put_or_lock(&dentry->d_lockref))
			return NULL;
		dentry = dentry_kill(dentry, 1);
	}
	return NULL;
}

static void shrink_dentry_list(struct list_head *list)
{
	struct dentry *dentry;

	rcu_read_lock();
	for (;;) {
		dentry = list_entry_rcu(list->prev, struct dentry, d_lru);
		if (&dentry->d_lru == list)
			break; /* empty */

		/*
		 * Get the dentry lock, and re-verify that the dentry is
		 * this on the shrinking list. If it is, we know that
		 * DCACHE_SHRINK_LIST and DCACHE_LRU_LIST are set.
		 */
		spin_lock(&dentry->d_lock);
		if (dentry != list_entry(list->prev, struct dentry, d_lru)) {
			spin_unlock(&dentry->d_lock);
			continue;
		}

		/*
		 * The dispose list is isolated and dentries are not accounted
		 * to the LRU here, so we can simply remove it from the list
		 * here regardless of whether it is referenced or not.
		 */
		d_shrink_del(dentry);

		/*
		 * We found an inuse dentry which was not removed from
		 * the LRU because of laziness during lookup. Do not free it.
		 */
		if (dentry->d_lockref.count) {
			spin_unlock(&dentry->d_lock);
			continue;
		}
		rcu_read_unlock();

		/*
		 * If 'try_to_prune()' returns a dentry, it will
		 * be the same one we passed in, and d_lock will
		 * have been held the whole time, so it will not
		 * have been added to any other lists. We failed
		 * to get the inode lock.
		 *
		 * We just add it back to the shrink list.
		 */
		dentry = try_prune_one_dentry(dentry);

		rcu_read_lock();
		if (dentry) {
			d_shrink_add(dentry, list);
			spin_unlock(&dentry->d_lock);
		}
	}
	rcu_read_unlock();
}

static enum lru_status
dentry_lru_isolate(struct list_head *item, spinlock_t *lru_lock, void *arg)
{
	struct list_head *freeable = arg;
	struct dentry	*dentry = container_of(item, struct dentry, d_lru);


	/*
	 * we are inverting the lru lock/dentry->d_lock here,
	 * so use a trylock. If we fail to get the lock, just skip
	 * it
	 */
	if (!spin_trylock(&dentry->d_lock))
		return LRU_SKIP;

	/*
	 * Referenced dentries are still in use. If they have active
	 * counts, just remove them from the LRU. Otherwise give them
	 * another pass through the LRU.
	 */
	if (dentry->d_lockref.count) {
		d_lru_isolate(dentry);
		spin_unlock(&dentry->d_lock);
		return LRU_REMOVED;
	}

	if (dentry->d_flags & DCACHE_REFERENCED) {
		dentry->d_flags &= ~DCACHE_REFERENCED;
		spin_unlock(&dentry->d_lock);

		/*
		 * The list move itself will be made by the common LRU code. At
		 * this point, we've dropped the dentry->d_lock but keep the
		 * lru lock. This is safe to do, since every list movement is
		 * protected by the lru lock even if both locks are held.
		 *
		 * This is guaranteed by the fact that all LRU management
		 * functions are intermediated by the LRU API calls like
		 * list_lru_add and list_lru_del. List movement in this file
		 * only ever occur through this functions or through callbacks
		 * like this one, that are called from the LRU API.
		 *
		 * The only exceptions to this are functions like
		 * shrink_dentry_list, and code that first checks for the
		 * DCACHE_SHRINK_LIST flag.  Those are guaranteed to be
		 * operating only with stack provided lists after they are
		 * properly isolated from the main list.  It is thus, always a
		 * local access.
		 */
		return LRU_ROTATE;
	}

	d_lru_shrink_move(dentry, freeable);
	spin_unlock(&dentry->d_lock);

	return LRU_REMOVED;
}

/**
 * prune_dcache_sb - shrink the dcache
 * @sb: superblock
 * @nr_to_scan : number of entries to try to free
 * @nid: which node to scan for freeable entities
 *
 * Attempt to shrink the superblock dcache LRU by @nr_to_scan entries. This is
 * done when we need more memory an called from the superblock shrinker
 * function.
 *
 * This function may fail to free any resources if all the dentries are in
 * use.
 */
long prune_dcache_sb(struct super_block *sb, unsigned long nr_to_scan,
		     int nid)
{
	LIST_HEAD(dispose);
	long freed;

	freed = list_lru_walk_node(&sb->s_dentry_lru, nid, dentry_lru_isolate,
				       &dispose, &nr_to_scan);
	shrink_dentry_list(&dispose);
	return freed;
}

static enum lru_status dentry_lru_isolate_shrink(struct list_head *item,
						spinlock_t *lru_lock, void *arg)
{
	struct list_head *freeable = arg;
	struct dentry	*dentry = container_of(item, struct dentry, d_lru);

	/*
	 * we are inverting the lru lock/dentry->d_lock here,
	 * so use a trylock. If we fail to get the lock, just skip
	 * it
	 */
	if (!spin_trylock(&dentry->d_lock))
		return LRU_SKIP;

	d_lru_shrink_move(dentry, freeable);
	spin_unlock(&dentry->d_lock);

	return LRU_REMOVED;
}


/**
 * shrink_dcache_sb - shrink dcache for a superblock
 * @sb: superblock
 *
 * Shrink the dcache for the specified super block. This is used to free
 * the dcache before unmounting a file system.
 */
void shrink_dcache_sb(struct super_block *sb)
{
	long freed;

	do {
		LIST_HEAD(dispose);

		freed = list_lru_walk(&sb->s_dentry_lru,
			dentry_lru_isolate_shrink, &dispose, UINT_MAX);

		this_cpu_sub(nr_dentry_unused, freed);
		shrink_dentry_list(&dispose);
	} while (freed > 0);
}
EXPORT_SYMBOL(shrink_dcache_sb);

/**
 * enum d_walk_ret - action to talke during tree walk
 * @D_WALK_CONTINUE:	contrinue walk
 * @D_WALK_QUIT:	quit walk
 * @D_WALK_NORETRY:	quit when retry is needed
 * @D_WALK_SKIP:	skip this dentry and its children
 */
enum d_walk_ret {
	D_WALK_CONTINUE,
	D_WALK_QUIT,
	D_WALK_NORETRY,
	D_WALK_SKIP,
};

/**
 * d_walk - walk the dentry tree
 * @parent:	start of walk
 * @data:	data passed to @enter() and @finish()
 * @enter:	callback when first entering the dentry
 * @finish:	callback when successfully finished the walk
 *
 * The @enter() and @finish() callbacks are called with d_lock held.
 */
static void d_walk(struct dentry *parent, void *data,
		   enum d_walk_ret (*enter)(void *, struct dentry *),
		   void (*finish)(void *))
{
	struct dentry *this_parent;
	struct list_head *next;
	unsigned seq = 0;
	enum d_walk_ret ret;
	bool retry = true;

again:
	read_seqbegin_or_lock(&rename_lock, &seq);
	this_parent = parent;
	spin_lock(&this_parent->d_lock);

	ret = enter(data, this_parent);
	switch (ret) {
	case D_WALK_CONTINUE:
		break;
	case D_WALK_QUIT:
	case D_WALK_SKIP:
		goto out_unlock;
	case D_WALK_NORETRY:
		retry = false;
		break;
	}
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry = list_entry(tmp, struct dentry, d_u.d_child);
		next = tmp->next;

		spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);

		ret = enter(data, dentry);
		switch (ret) {
		case D_WALK_CONTINUE:
			break;
		case D_WALK_QUIT:
			spin_unlock(&dentry->d_lock);
			goto out_unlock;
		case D_WALK_NORETRY:
			retry = false;
			break;
		case D_WALK_SKIP:
			spin_unlock(&dentry->d_lock);
			continue;
		}

		if (!list_empty(&dentry->d_subdirs)) {
			spin_unlock(&this_parent->d_lock);
			spin_release(&dentry->d_lock.dep_map, 1, _RET_IP_);
			this_parent = dentry;
			spin_acquire(&this_parent->d_lock.dep_map, 0, 1, _RET_IP_);
			goto repeat;
		}
		spin_unlock(&dentry->d_lock);
	}
	/*
	 * All done at this level ... ascend and resume the search.
	 */
	if (this_parent != parent) {
		struct dentry *child = this_parent;
		this_parent = child->d_parent;

		rcu_read_lock();
		spin_unlock(&child->d_lock);
		spin_lock(&this_parent->d_lock);

		/*
		 * might go back up the wrong parent if we have had a rename
		 * or deletion
		 */
		if (this_parent != child->d_parent ||
			 (child->d_flags & DCACHE_DENTRY_KILLED) ||
			 need_seqretry(&rename_lock, seq)) {
			spin_unlock(&this_parent->d_lock);
			rcu_read_unlock();
			goto rename_retry;
		}
		rcu_read_unlock();
		next = child->d_u.d_child.next;
		goto resume;
	}
	if (need_seqretry(&rename_lock, seq)) {
		spin_unlock(&this_parent->d_lock);
		goto rename_retry;
	}
	if (finish)
		finish(data);

out_unlock:
	spin_unlock(&this_parent->d_lock);
	done_seqretry(&rename_lock, seq);
	return;

rename_retry:
	if (!retry)
		return;
	seq = 1;
	goto again;
}

/*
 * Search for at least 1 mount point in the dentry's subdirs.
 * We descend to the next level whenever the d_subdirs
 * list is non-empty and continue searching.
 */

static enum d_walk_ret check_mount(void *data, struct dentry *dentry)
{
	int *ret = data;
	if (d_mountpoint(dentry)) {
		*ret = 1;
		return D_WALK_QUIT;
	}
	return D_WALK_CONTINUE;
}

/**
 * have_submounts - check for mounts over a dentry
 * @parent: dentry to check.
 *
 * Return true if the parent or its subdirectories contain
 * a mount point
 */
int have_submounts(struct dentry *parent)
{
	int ret = 0;

	d_walk(parent, &ret, check_mount, NULL);

	return ret;
}
EXPORT_SYMBOL(have_submounts);

/*
 * Called by mount code to set a mountpoint and check if the mountpoint is
 * reachable (e.g. NFS can unhash a directory dentry and then the complete
 * subtree can become unreachable).
 *
 * Only one of check_submounts_and_drop() and d_set_mounted() must succeed.  For
 * this reason take rename_lock and d_lock on dentry and ancestors.
 */
int d_set_mounted(struct dentry *dentry)
{
	struct dentry *p;
	int ret = -ENOENT;
	write_seqlock(&rename_lock);
	for (p = dentry->d_parent; !IS_ROOT(p); p = p->d_parent) {
		/* Need exclusion wrt. check_submounts_and_drop() */
		spin_lock(&p->d_lock);
		if (unlikely(d_unhashed(p))) {
			spin_unlock(&p->d_lock);
			goto out;
		}
		spin_unlock(&p->d_lock);
	}
	spin_lock(&dentry->d_lock);
	if (!d_unlinked(dentry)) {
		dentry->d_flags |= DCACHE_MOUNTED;
		ret = 0;
	}
 	spin_unlock(&dentry->d_lock);
out:
	write_sequnlock(&rename_lock);
	return ret;
}

/*
 * Search the dentry child list of the specified parent,
 * and move any unused dentries to the end of the unused
 * list for prune_dcache(). We descend to the next level
 * whenever the d_subdirs list is non-empty and continue
 * searching.
 *
 * It returns zero iff there are no unused children,
 * otherwise  it returns the number of children moved to
 * the end of the unused list. This may not be the total
 * number of unused children, because select_parent can
 * drop the lock and return early due to latency
 * constraints.
 */

struct select_data {
	struct dentry *start;
	struct list_head dispose;
	int found;
};

static enum d_walk_ret select_collect(void *_data, struct dentry *dentry)
{
	struct select_data *data = _data;
	enum d_walk_ret ret = D_WALK_CONTINUE;

	if (data->start == dentry)
		goto out;

	/*
	 * move only zero ref count dentries to the dispose list.
	 *
	 * Those which are presently on the shrink list, being processed
	 * by shrink_dentry_list(), shouldn't be moved.  Otherwise the
	 * loop in shrink_dcache_parent() might not make any progress
	 * and loop forever.
	 */
	if (dentry->d_lockref.count) {
		dentry_lru_del(dentry);
	} else if (!(dentry->d_flags & DCACHE_SHRINK_LIST)) {
		/*
		 * We can't use d_lru_shrink_move() because we
		 * need to get the global LRU lock and do the
		 * LRU accounting.
		 */
		d_lru_del(dentry);
		d_shrink_add(dentry, &data->dispose);
		data->found++;
		ret = D_WALK_NORETRY;
	}
	/*
	 * We can return to the caller if we have found some (this
	 * ensures forward progress). We'll be coming back to find
	 * the rest.
	 */
	if (data->found && need_resched())
		ret = D_WALK_QUIT;
out:
	return ret;
}

/**
 * shrink_dcache_parent - prune dcache
 * @parent: parent of entries to prune
 *
 * Prune the dcache to remove unused children of the parent dentry.
 */
void shrink_dcache_parent(struct dentry *parent)
{
	for (;;) {
		struct select_data data;

		INIT_LIST_HEAD(&data.dispose);
		data.start = parent;
		data.found = 0;

		d_walk(parent, &data, select_collect, NULL);
		if (!data.found)
			break;

		shrink_dentry_list(&data.dispose);
		cond_resched();
	}
}
EXPORT_SYMBOL(shrink_dcache_parent);

static enum d_walk_ret umount_collect(void *_data, struct dentry *dentry)
{
	struct select_data *data = _data;
	enum d_walk_ret ret = D_WALK_CONTINUE;

	if (dentry->d_lockref.count) {
		dentry_lru_del(dentry);
		if (likely(!list_empty(&dentry->d_subdirs)))
			goto out;
		if (dentry == data->start && dentry->d_lockref.count == 1)
			goto out;
		printk(KERN_ERR
		       "BUG: Dentry %p{i=%lx,n=%s}"
		       " still in use (%d)"
		       " [unmount of %s %s]\n",
		       dentry,
		       dentry->d_inode ?
		       dentry->d_inode->i_ino : 0UL,
		       dentry->d_name.name,
		       dentry->d_lockref.count,
		       dentry->d_sb->s_type->name,
		       dentry->d_sb->s_id);
		BUG();
	} else if (!(dentry->d_flags & DCACHE_SHRINK_LIST)) {
		/*
		 * We can't use d_lru_shrink_move() because we
		 * need to get the global LRU lock and do the
		 * LRU accounting.
		 */
		if (dentry->d_flags & DCACHE_LRU_LIST)
			d_lru_del(dentry);
		d_shrink_add(dentry, &data->dispose);
		data->found++;
		ret = D_WALK_NORETRY;
	}
out:
	if (data->found && need_resched())
		ret = D_WALK_QUIT;
	return ret;
}

/*
 * destroy the dentries attached to a superblock on unmounting
 */
void shrink_dcache_for_umount(struct super_block *sb)
{
	struct dentry *dentry;

	if (down_read_trylock(&sb->s_umount))
		BUG();

	dentry = sb->s_root;
	sb->s_root = NULL;
	for (;;) {
		struct select_data data;

		INIT_LIST_HEAD(&data.dispose);
		data.start = dentry;
		data.found = 0;

		d_walk(dentry, &data, umount_collect, NULL);
		if (!data.found)
			break;

		shrink_dentry_list(&data.dispose);
		cond_resched();
	}
	d_drop(dentry);
	dput(dentry);

	while (!hlist_bl_empty(&sb->s_anon)) {
		struct select_data data;
		dentry = hlist_bl_entry(hlist_bl_first(&sb->s_anon), struct dentry, d_hash);

		INIT_LIST_HEAD(&data.dispose);
		data.start = NULL;
		data.found = 0;

		d_walk(dentry, &data, umount_collect, NULL);
		if (data.found)
			shrink_dentry_list(&data.dispose);
		cond_resched();
	}
}

static enum d_walk_ret check_and_collect(void *_data, struct dentry *dentry)
{
	struct select_data *data = _data;

	if (d_mountpoint(dentry)) {
		data->found = -EBUSY;
		return D_WALK_QUIT;
	}

	return select_collect(_data, dentry);
}

static void check_and_drop(void *_data)
{
	struct select_data *data = _data;

	if (d_mountpoint(data->start))
		data->found = -EBUSY;
	if (!data->found)
		__d_drop(data->start);
}

/**
 * check_submounts_and_drop - prune dcache, check for submounts and drop
 *
 * All done as a single atomic operation relative to has_unlinked_ancestor().
 * Returns 0 if successfully unhashed @parent.  If there were submounts then
 * return -EBUSY.
 *
 * @dentry: dentry to prune and drop
 */
int check_submounts_and_drop(struct dentry *dentry)
{
	int ret = 0;

	/* Negative dentries can be dropped without further checks */
	if (!dentry->d_inode) {
		d_drop(dentry);
		goto out;
	}

	for (;;) {
		struct select_data data;

		INIT_LIST_HEAD(&data.dispose);
		data.start = dentry;
		data.found = 0;

		d_walk(dentry, &data, check_and_collect, check_and_drop);
		ret = data.found;

		if (!list_empty(&data.dispose))
			shrink_dentry_list(&data.dispose);

		if (ret <= 0)
			break;

		cond_resched();
	}

out:
	return ret;
}
EXPORT_SYMBOL(check_submounts_and_drop);

/**
 * __d_alloc	-	allocate a dcache entry
 * @sb: filesystem it will belong to
 * @name: qstr of the name
 *
 * Allocates a dentry. It returns %NULL if there is insufficient memory
 * available. On a success the dentry is returned. The name passed in is
 * copied and the copy passed in may be reused after this call.
 */
// ARM10C 20151212
// root_inode->i_sb: (kmem_cache#4-oX)->i_sb: kmem_cache#25-oX (struct super_block), &name
// ARM10C 20160521
// s: kmem_cache#25-oX (struct super_block), &d_name
// ARM10C 20161126
// parent->d_sb: (kmem_cache#5-oX (struct dentry))->d_sb: kmem_cache#25-oX (struct super_block), name: &q
struct dentry *__d_alloc(struct super_block *sb, const struct qstr *name)
{
	struct dentry *dentry;
	char *dname;

	// dentry_cache: kmem_cache#5, GFP_KERNEL: 0xD0
	// kmem_cache_alloc(kmem_cache#5, GFP_KERNEL: 0xD0): kmem_cache#5-oX (struct dentry)
	dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL);
	// dentry: kmem_cache#5-oX (struct dentry)

	// dentry: kmem_cache#5-oX (struct dentry)
	if (!dentry)
		return NULL;

	/*
	 * We guarantee that the inline name is always NUL-terminated.
	 * This way the memcpy() done by the name switching in rename
	 * will still always have a NUL at the end, even if we might
	 * be overwriting an internal NUL character
	 */
	// DNAME_INLINE_LEN: 36, dentry->d_iname: (kmem_cache#5-oX (struct dentry))->d_iname[35]
	dentry->d_iname[DNAME_INLINE_LEN-1] = 0;
	// dentry->d_iname: (kmem_cache#5-oX (struct dentry))->d_iname[35]: 0

	// name->len: (&name)->len: 1, DNAME_INLINE_LEN: 36
	if (name->len > DNAME_INLINE_LEN-1) {
		dname = kmalloc(name->len + 1, GFP_KERNEL);
		if (!dname) {
			kmem_cache_free(dentry_cache, dentry); 
			return NULL;
		}
	} else  {
		// dentry->d_iname: (kmem_cache#5-oX (struct dentry))->d_iname
		dname = dentry->d_iname;
		// dname: (kmem_cache#5-oX (struct dentry))->d_iname
	}	

	// dentry->d_name.len: (kmem_cache#5-oX (struct dentry))->d_name.len, name->len: (&name)->len: 1
	dentry->d_name.len = name->len;
	// dentry->d_name.len: (kmem_cache#5-oX (struct dentry))->d_name.len: 1

	// dentry->d_name.hash: (kmem_cache#5-oX (struct dentry))->d_name.hash, name->hash: (&name)->hash: 0
	dentry->d_name.hash = name->hash;
	// dentry->d_name.hash: (kmem_cache#5-oX (struct dentry))->d_name.hash: (&name)->hash: 0

	// dname: (kmem_cache#5-oX (struct dentry))->d_iname, name->name: (&name)->name: "/", name->len: (&name)->len: 1
	memcpy(dname, name->name, name->len);

	// memcpy에서 한일:
	// dname: (kmem_cache#5-oX (struct dentry))->d_iname: "/"

	// name->len: (&name)->len: 1, dname[1]: (kmem_cache#5-oX (struct dentry))->d_iname[1]
	dname[name->len] = 0;
	// dname[1]: (kmem_cache#5-oX (struct dentry))->d_iname[1]: 0

// 2015/12/12 종료
// 2015/12/19 시작

	/* Make sure we always see the terminating NUL character */
	smp_wmb();

	// smp_wmb에서 한일:
	// 공유자원을 다른 cpu core가 사용할수 있게 함

	// dentry->d_name.name: (kmem_cache#5-oX (struct dentry))->d_name.name, dname: "/"
	dentry->d_name.name = dname;
	// dentry->d_name.name: (kmem_cache#5-oX (struct dentry))->d_name.name: "/"

	// dentry->d_lockref.count: (kmem_cache#5-oX (struct dentry))->d_lockref.count
	dentry->d_lockref.count = 1;
	// dentry->d_lockref.count: (kmem_cache#5-oX (struct dentry))->d_lockref.count: 1

	// dentry->d_flags: (kmem_cache#5-oX (struct dentry))->d_flags
	dentry->d_flags = 0;
	// dentry->d_flags: (kmem_cache#5-oX (struct dentry))->d_flags: 0

	// &dentry->d_lock: &(kmem_cache#5-oX (struct dentry))->d_lock
	spin_lock_init(&dentry->d_lock);

	// spin_lock_init에서 한일:
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->magic: 0xdead4ead
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->owner: 0xffffffff
	// (&(kmem_cache#5-oX (struct dentry))->d_lock)->owner_cpu: 0xffffffff

	// TODO:
	// seqcount lock 을 어떨때 사용하는지, 사용하는 부분 분석 및 확인 필요함

	// &dentry->d_seq: &(kmem_cache#5-oX (struct dentry))->d_seq
	seqcount_init(&dentry->d_seq);

	// seqcount_init에서 한일:
	// (&(kmem_cache#5-oX (struct dentry))->d_seq)->sequence: 0

	// dentry->d_inode: (kmem_cache#5-oX (struct dentry))->d_inode
	dentry->d_inode = NULL;
	// dentry->d_inode: (kmem_cache#5-oX (struct dentry))->d_inode: NULL

	// dentry->d_parent: (kmem_cache#5-oX (struct dentry))->d_parent, dentry: kmem_cache#5-oX (struct dentry)
	dentry->d_parent = dentry;
	// dentry->d_parent: (kmem_cache#5-oX (struct dentry))->d_parent: kmem_cache#5-oX (struct dentry)

	// dentry->d_sb: (kmem_cache#5-oX (struct dentry))->d_sb, sb: kmem_cache#25-oX (struct super_block)
	dentry->d_sb = sb;
	// dentry->d_sb: (kmem_cache#5-oX (struct dentry))->d_sb: kmem_cache#25-oX (struct super_block)

	// dentry->d_op: (kmem_cache#5-oX (struct dentry))->d_op
	dentry->d_op = NULL;
	// dentry->d_op: (kmem_cache#5-oX (struct dentry))->d_op: NULL

	// dentry->d_fsdata: (kmem_cache#5-oX (struct dentry))->d_fsdata
	dentry->d_fsdata = NULL;
	// dentry->d_fsdata: (kmem_cache#5-oX (struct dentry))->d_fsdata: NULL

	// &dentry->d_hash: &(kmem_cache#5-oX (struct dentry))->d_hash
	INIT_HLIST_BL_NODE(&dentry->d_hash);

	// INIT_HLIST_BL_NODE에서 한일:
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->pprev: NULL

	// &dentry->d_lru: &(kmem_cache#5-oX (struct dentry))->d_lru
	INIT_LIST_HEAD(&dentry->d_lru);

	// INIT_LIST_HEAD에서 한일:
	// (&(kmem_cache#5-oX (struct dentry))->d_lru)->next: &(kmem_cache#5-oX (struct dentry))->d_lru
	// (&(kmem_cache#5-oX (struct dentry))->d_lru)->prev: &(kmem_cache#5-oX (struct dentry))->d_lru

	// &dentry->d_subdirs: &(kmem_cache#5-oX (struct dentry))->d_subdirs
	INIT_LIST_HEAD(&dentry->d_subdirs);

	// INIT_LIST_HEAD에서 한일:
	// (&(kmem_cache#5-oX (struct dentry))->d_subdirs)->next: &(kmem_cache#5-oX (struct dentry))->d_subdirs
	// (&(kmem_cache#5-oX (struct dentry))->d_subdirs)->prev: &(kmem_cache#5-oX (struct dentry))->d_subdirs

	// &dentry->d_alias: &(kmem_cache#5-oX (struct dentry))->d_alias
	INIT_HLIST_NODE(&dentry->d_alias);

	// INIT_HLIST_NODE에서 한일:
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_alias)->pprev: NULL

	// &dentry->d_u.d_child: &(kmem_cache#5-oX (struct dentry))->d_u.d_child
	INIT_LIST_HEAD(&dentry->d_u.d_child);

	// INIT_LIST_HEAD에서 한일:
	// (&(kmem_cache#5-oX (struct dentry))->d_u.d_child)->next: &(kmem_cache#5-oX (struct dentry))->d_u.d_child
	// (&(kmem_cache#5-oX (struct dentry))->d_u.d_child)->prev: &(kmem_cache#5-oX (struct dentry))->d_u.d_child

	// dentry: kmem_cache#5-oX (struct dentry), dentry->d_sb: (kmem_cache#5-oX (struct dentry))->d_sb: kmem_cache#25-oX (struct super_block)
	// dentry->d_sb->s_d_op: (kmem_cache#5-oX (struct dentry))->d_sb->s_d_op: NULL
	d_set_d_op(dentry, dentry->d_sb->s_d_op);

	// d_set_d_op에서 한일:
	// (kmem_cache#5-oX (struct dentry))->d_op: NULL

	this_cpu_inc(nr_dentry);

	// this_cpu_inc에서 한일:
	// [pcp0] nr_dentry: 1

	// dentry: kmem_cache#5-oX (struct dentry)
	return dentry;
	// return kmem_cache#5-oX (struct dentry)
}

/**
 * d_alloc	-	allocate a dcache entry
 * @parent: parent of entry to allocate
 * @name: qstr of the name
 *
 * Allocates a dentry. It returns %NULL if there is insufficient memory
 * available. On a success the dentry is returned. The name passed in is
 * copied and the copy passed in may be reused after this call.
 */
// ARM10C 20161126
// parent: kmem_cache#5-oX (struct dentry), &q
struct dentry *d_alloc(struct dentry * parent, const struct qstr *name)
{
	// parent->d_sb: (kmem_cache#5-oX (struct dentry))->d_sb: kmem_cache#25-oX (struct super_block), name: &q
	// __d_alloc(kmem_cache#25-oX (struct super_block), &q): kmem_cache#5-oX (struct dentry)
	struct dentry *dentry = __d_alloc(parent->d_sb, name);
	// dentry: kmem_cache#5-oX (struct dentry)

	// __d_alloc에서 한일:
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

	// dentry: kmem_cache#5-oX (struct dentry)
	if (!dentry)
		return NULL;

	// &parent->d_lock: &(kmem_cache#5-oX (struct dentry))->d_lock
	spin_lock(&parent->d_lock);

	// spin_lock 에서 한일:
	// &(kmem_cache#5-oX (struct dentry))->d_lock 을 사용하여 spin lock 수행

	/*
	 * don't need child lock because it is not subject
	 * to concurrency here
	 */
	// parent: kmem_cache#5-oX (struct dentry)
	__dget_dlock(parent);

	// __dget_dlock 에서 한일:
	// (kmem_cache#5-oX (struct dentry))->d_lockref.count: 1

	// dentry->d_parent: (kmem_cache#5-oX (struct dentry))->d_parent, parent: kmem_cache#5-oX (struct dentry)
	dentry->d_parent = parent;
	// dentry->d_parent: (kmem_cache#5-oX (struct dentry))->d_parent: kmem_cache#5-oX (struct dentry)

	// &dentry->d_u.d_child: &(kmem_cache#5-oX (struct dentry))->d_u.d_child,
	// &parent->d_subdirs: &(kmem_cache#5-oX (struct dentry))->d_subdirs
	list_add(&dentry->d_u.d_child, &parent->d_subdirs);

	// list_add 에서 한일:
	// head list 인 &(kmem_cache#5-oX (struct dentry))->d_subdirs 에
	// list &(kmem_cache#5-oX (struct dentry))->d_u.d_child 를 추가함

	// &parent->d_lock: &(kmem_cache#5-oX (struct dentry))->d_lock
	spin_unlock(&parent->d_lock);

	// spin_lock 에서 한일:
	// &(kmem_cache#5-oX (struct dentry))->d_lock 을 사용하여 spin unlock 수행

	// dentry: kmem_cache#5-oX (struct dentry)
	return dentry;
	// return kmem_cache#5-oX (struct dentry)
}
EXPORT_SYMBOL(d_alloc);

/**
 * d_alloc_pseudo - allocate a dentry (for lookup-less filesystems)
 * @sb: the superblock
 * @name: qstr of the name
 *
 * For a filesystem that just pins its dentries in memory and never
 * performs lookups at all, return an unhashed IS_ROOT dentry.
 */
struct dentry *d_alloc_pseudo(struct super_block *sb, const struct qstr *name)
{
	return __d_alloc(sb, name);
}
EXPORT_SYMBOL(d_alloc_pseudo);

// ARM10C 20161126
// s->s_root: (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry), "self"
struct dentry *d_alloc_name(struct dentry *parent, const char *name)
{
	struct qstr q;

	// name: "self"
	q.name = name;
	// q.name: "self"

	// name: "self", strlen("self"): 4
	q.len = strlen(name);
	// q.len: 4

	// q.name: "self", q.len: 4, full_name_hash("self", 4): 0xXXXXXXXX
	q.hash = full_name_hash(q.name, q.len);
	// q.hash: 0xXXXXXXXX

	// parent: kmem_cache#5-oX (struct dentry)
	// d_alloc(kmem_cache#5-oX (struct dentry)): kmem_cache#5-oX (struct dentry)
	return d_alloc(parent, &q);
	// return kmem_cache#5-oX (struct dentry)

	// d_alloc 에서 한일:
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
}
EXPORT_SYMBOL(d_alloc_name);

// ARM10C 20151219
// dentry: kmem_cache#5-oX (struct dentry), dentry->d_sb->s_d_op: (kmem_cache#5-oX (struct dentry))->d_sb->s_d_op: NULL
void d_set_d_op(struct dentry *dentry, const struct dentry_operations *op)
{
	// dentry->d_op: (kmem_cache#5-oX (struct dentry))->d_op: NULL
	WARN_ON_ONCE(dentry->d_op);

	// dentry->d_flags: (kmem_cache#5-oX (struct dentry))->d_flags: 0
	// DCACHE_OP_HASH: 0x00000001, DCACHE_OP_COMPARE: 0x00000002, DCACHE_OP_REVALIDATE: 0x00000004
	// DCACHE_OP_WEAK_REVALIDATE: 0x00000800, DCACHE_OP_DELETE: 0x00000008
	WARN_ON_ONCE(dentry->d_flags & (DCACHE_OP_HASH	|
				DCACHE_OP_COMPARE	|
				DCACHE_OP_REVALIDATE	|
				DCACHE_OP_WEAK_REVALIDATE	|
				DCACHE_OP_DELETE ));

	// dentry->d_op: (kmem_cache#5-oX (struct dentry))->d_op: NULL, op: (kmem_cache#5-oX (struct dentry))->d_sb->s_d_op: NULL
	dentry->d_op = op;
	// dentry->d_op: (kmem_cache#5-oX (struct dentry))->d_op: NULL

	// dentry->d_op: (kmem_cache#5-oX (struct dentry))->d_op: NULL
	if (!op)
		return;
		// return 수행

	if (op->d_hash)
		dentry->d_flags |= DCACHE_OP_HASH;
	if (op->d_compare)
		dentry->d_flags |= DCACHE_OP_COMPARE;
	if (op->d_revalidate)
		dentry->d_flags |= DCACHE_OP_REVALIDATE;
	if (op->d_weak_revalidate)
		dentry->d_flags |= DCACHE_OP_WEAK_REVALIDATE;
	if (op->d_delete)
		dentry->d_flags |= DCACHE_OP_DELETE;
	if (op->d_prune)
		dentry->d_flags |= DCACHE_OP_PRUNE;

}
EXPORT_SYMBOL(d_set_d_op);

// ARM10C 20151219
// inode: kmem_cache#4-oX
static unsigned d_flags_for_inode(struct inode *inode)
{
	// DCACHE_FILE_TYPE: 0x00400000
	unsigned add_flags = DCACHE_FILE_TYPE;
	// add_flags: 0x00400000

	// inode: kmem_cache#4-oX
	if (!inode)
		return DCACHE_MISS_TYPE;

	// inode->i_mode: (kmem_cache#4-oX)->i_mode: 40447, S_ISDIR(40447): 1
	if (S_ISDIR(inode->i_mode)) {
		// DCACHE_DIRECTORY_TYPE: 0x00100000
		add_flags = DCACHE_DIRECTORY_TYPE;
		// add_flags: 0x00100000

		// inode->i_opflags: (kmem_cache#4-oX)->i_opflags: 0, IOP_LOOKUP: 0x0002
		if (unlikely(!(inode->i_opflags & IOP_LOOKUP))) {
			// inode->i_op: (kmem_cache#4-oX)->i_op: &sysfs_dir_inode_operations
			// inode->i_op->lookup: (kmem_cache#4-oX)->i_op->lookup: sysfs_lookup
			if (unlikely(!inode->i_op->lookup))
				add_flags = DCACHE_AUTODIR_TYPE;
			else
				// inode->i_opflags: (kmem_cache#4-oX)->i_opflags: 0, IOP_LOOKUP: 0x0002
				inode->i_opflags |= IOP_LOOKUP;
				// inode->i_opflags: (kmem_cache#4-oX)->i_opflags: 0x0002
		}
	} else if (unlikely(!(inode->i_opflags & IOP_NOFOLLOW))) {
		if (unlikely(inode->i_op->follow_link))
			add_flags = DCACHE_SYMLINK_TYPE;
		else
			inode->i_opflags |= IOP_NOFOLLOW;
	}

	// inode: kmem_cache#4-oX, IS_AUTOMOUNT(kmem_cache#4-oX): 0
	if (unlikely(IS_AUTOMOUNT(inode)))
		add_flags |= DCACHE_NEED_AUTOMOUNT;

	// add_flags: 0x00100000
	return add_flags;
	// return 0x00100000
}

// ARM10C 20151219
// entry: kmem_cache#5-oX (struct dentry), inode: kmem_cache#4-oX (struct inode)
static void __d_instantiate(struct dentry *dentry, struct inode *inode)
{
	// inode: kmem_cache#4-oX (struct inode), i d_flags_for_inode(kmem_cache#4-oX (struct inode)): 0x00100000
	unsigned add_flags = d_flags_for_inode(inode);
	// add_flags: 0x00100000

	// &dentry->d_lock: &(kmem_cache#5-oX (struct dentry))->d_lock
	spin_lock(&dentry->d_lock);

	// spin_lock에서 한일:
	// &(kmem_cache#5-oX (struct dentry))->d_lock을 이용하여 spin lock 수행

	// dentry->d_flags: (kmem_cache#5-oX (struct dentry))->d_flags: 0, DCACHE_ENTRY_TYPE: 0x00700000
	dentry->d_flags &= ~DCACHE_ENTRY_TYPE;
	// dentry->d_flags: (kmem_cache#5-oX (struct dentry))->d_flags: 0

	// dentry->d_flags: (kmem_cache#5-oX (struct dentry))->d_flags: 0, add_flags: 0x00100000
	dentry->d_flags |= add_flags;
	// dentry->d_flags: (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100000

	// inode: kmem_cache#4-oX (struct inode)
	if (inode)
		// &dentry->d_alias: &(kmem_cache#5-oX (struct dentry))->d_alias, &inode->i_dentry: &(kmem_cache#4-oX (struct inode))->i_dentry
		hlist_add_head(&dentry->d_alias, &inode->i_dentry);

		// hlist_add_head에서 한일:
		// (&(kmem_cache#5-oX (struct dentry))->d_alias)->next: NULL
		// (&(kmem_cache#4-oX (struct inode))->i_dentry)->first: &(kmem_cache#5-oX (struct dentry))->d_alias
		// (&(kmem_cache#5-oX (struct dentry))->d_alias)->pprev: &(&(kmem_cache#5-oX (struct dentry))->d_alias)

	// dentry->d_inode: (kmem_cache#5-oX (struct dentry))->d_inode, inode: kmem_cache#4-oX (struct inode)
	dentry->d_inode = inode;
	// dentry->d_inode: (kmem_cache#5-oX (struct dentry))->d_inode: kmem_cache#4-oX (struct inode)

	// dentry: kmem_cache#5-oX (struct dentry)
	dentry_rcuwalk_barrier(dentry);

	// dentry_rcuwalk_barrier에서 한일:
	// 공유자원을 다른 cpu core가 사용할수 있게 함
	// (&(kmem_cache#5-oX (struct dentry))->d_seq)->sequence: 2

	// &dentry->d_lock: &(kmem_cache#5-oX (struct dentry))->d_lock
	spin_unlock(&dentry->d_lock);

	// spin_unlock에서 한일:
	// &(kmem_cache#5-oX (struct dentry))->d_lock을 이용하여 spin unlock 수행

	// dentry: kmem_cache#5-oX (struct dentry), inode: kmem_cache#4-oX (struct inode)
	fsnotify_d_instantiate(dentry, inode);

	// fsnotify_d_instantiate에서 한일
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100000
}

/**
 * d_instantiate - fill in inode information for a dentry
 * @entry: dentry to complete
 * @inode: inode to attach to this dentry
 *
 * Fill in inode information in the entry.
 *
 * This turns negative dentries into productive full members
 * of society.
 *
 * NOTE! This assumes that the inode count has been incremented
 * (or otherwise set) by the caller to indicate that it is now
 * in use by the dcache.
 */
 
// ARM10C 20151219
// res: kmem_cache#5-oX (struct dentry), root_inode: kmem_cache#4-oX
// ARM10C 20160521
// dentry: kmem_cache#5-oX (struct dentry), root: kmem_cache#4-oX (struct inode)
// ARM10C 20161126
// entry: kmem_cache#5-oX (struct dentry), inode: kmem_cache#4-oX (struct inode)
void d_instantiate(struct dentry *entry, struct inode * inode)
{
	// &entry->d_alias: &(kmem_cache#5-oX (struct dentry))->d_alias, hlist_unhashed(&(kmem_cache#5-oX (struct dentry))->d_alias): 1
	BUG_ON(!hlist_unhashed(&entry->d_alias));

	// inode: kmem_cache#4-oX
	if (inode)
		// &inode->i_lock: &(kmem_cache#4-oX)->i_lock
		spin_lock(&inode->i_lock);

		// spin_lock에서 한일:
		// &(kmem_cache#4-oX)->i_lock을 이용하여 spin lock을 수행

	// entry: kmem_cache#5-oX (struct dentry), inode: kmem_cache#4-oX
	__d_instantiate(entry, inode);

	// __d_instantiate에서 한일:
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

	// inode: kmem_cache#4-oX
	if (inode)
		// &inode->i_lock: &(kmem_cache#4-oX)->i_lock
		spin_unlock(&inode->i_lock);

		// spin_unlock에서 한일:
		// &(kmem_cache#4-oX)->i_lock을 이용하여 spin unlock을 수행

	// entry: kmem_cache#5-oX (struct dentry), inode: kmem_cache#4-oX
	security_d_instantiate(entry, inode); // null function
}
EXPORT_SYMBOL(d_instantiate);

/**
 * d_instantiate_unique - instantiate a non-aliased dentry
 * @entry: dentry to instantiate
 * @inode: inode to attach to this dentry
 *
 * Fill in inode information in the entry. On success, it returns NULL.
 * If an unhashed alias of "entry" already exists, then we return the
 * aliased dentry instead and drop one reference to inode.
 *
 * Note that in order to avoid conflicts with rename() etc, the caller
 * had better be holding the parent directory semaphore.
 *
 * This also assumes that the inode count has been incremented
 * (or otherwise set) by the caller to indicate that it is now
 * in use by the dcache.
 */
static struct dentry *__d_instantiate_unique(struct dentry *entry,
					     struct inode *inode)
{
	struct dentry *alias;
	int len = entry->d_name.len;
	const char *name = entry->d_name.name;
	unsigned int hash = entry->d_name.hash;

	if (!inode) {
		__d_instantiate(entry, NULL);
		return NULL;
	}

	hlist_for_each_entry(alias, &inode->i_dentry, d_alias) {
		/*
		 * Don't need alias->d_lock here, because aliases with
		 * d_parent == entry->d_parent are not subject to name or
		 * parent changes, because the parent inode i_mutex is held.
		 */
		if (alias->d_name.hash != hash)
			continue;
		if (alias->d_parent != entry->d_parent)
			continue;
		if (alias->d_name.len != len)
			continue;
		if (dentry_cmp(alias, name, len))
			continue;
		__dget(alias);
		return alias;
	}

	__d_instantiate(entry, inode);
	return NULL;
}

struct dentry *d_instantiate_unique(struct dentry *entry, struct inode *inode)
{
	struct dentry *result;

	BUG_ON(!hlist_unhashed(&entry->d_alias));

	if (inode)
		spin_lock(&inode->i_lock);
	result = __d_instantiate_unique(entry, inode);
	if (inode)
		spin_unlock(&inode->i_lock);

	if (!result) {
		security_d_instantiate(entry, inode);
		return NULL;
	}

	BUG_ON(!d_unhashed(result));
	iput(inode);
	return result;
}

EXPORT_SYMBOL(d_instantiate_unique);

/**
 * d_instantiate_no_diralias - instantiate a non-aliased dentry
 * @entry: dentry to complete
 * @inode: inode to attach to this dentry
 *
 * Fill in inode information in the entry.  If a directory alias is found, then
 * return an error (and drop inode).  Together with d_materialise_unique() this
 * guarantees that a directory inode may never have more than one alias.
 */
int d_instantiate_no_diralias(struct dentry *entry, struct inode *inode)
{
	BUG_ON(!hlist_unhashed(&entry->d_alias));

	spin_lock(&inode->i_lock);
	if (S_ISDIR(inode->i_mode) && !hlist_empty(&inode->i_dentry)) {
		spin_unlock(&inode->i_lock);
		iput(inode);
		return -EBUSY;
	}
	__d_instantiate(entry, inode);
	spin_unlock(&inode->i_lock);
	security_d_instantiate(entry, inode);

	return 0;
}
EXPORT_SYMBOL(d_instantiate_no_diralias);

// ARM10C 20151212
// inode: kmem_cache#4-oX
// ARM10C 20160319
// inode: kmem_cache#4-oX (struct inode)
// ARM10C 20161126
// root_inode: kmem_cache#4-oX (struct inode)
struct dentry *d_make_root(struct inode *root_inode)
{
	struct dentry *res = NULL;
	// res: NULL

	// root_inode: kmem_cache#4-oX
	if (root_inode) {
		// QSTR_INIT("/", 1): { { { .len = 1 } }, .name = "/" }
		static const struct qstr name = QSTR_INIT("/", 1);

		// QSTR_INIT에서 한일:
		// name.name: "/"
		// name.len: 1

		// root_inode->i_sb: (kmem_cache#4-oX)->i_sb: kmem_cache#25-oX (struct super_block)
		// __d_alloc(kmem_cache#25-oX (struct super_block), &name): kmem_cache#5-oX (struct dentry)
		res = __d_alloc(root_inode->i_sb, &name);
		// res: kmem_cache#5-oX (struct dentry)

		// __d_alloc에서 한일:
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

		// res: kmem_cache#5-oX (struct dentry)
		if (res)
			// res: kmem_cache#5-oX (struct dentry), root_inode: kmem_cache#4-oX
			d_instantiate(res, root_inode);

			// d_instantiate에서 한일:
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
		else
			iput(root_inode);
	}

	// res: kmem_cache#5-oX (struct dentry)
	return res;
	// return kmem_cache#5-oX (struct dentry)
}
EXPORT_SYMBOL(d_make_root);

static struct dentry * __d_find_any_alias(struct inode *inode)
{
	struct dentry *alias;

	if (hlist_empty(&inode->i_dentry))
		return NULL;
	alias = hlist_entry(inode->i_dentry.first, struct dentry, d_alias);
	__dget(alias);
	return alias;
}

/**
 * d_find_any_alias - find any alias for a given inode
 * @inode: inode to find an alias for
 *
 * If any aliases exist for the given inode, take and return a
 * reference for one of them.  If no aliases exist, return %NULL.
 */
struct dentry *d_find_any_alias(struct inode *inode)
{
	struct dentry *de;

	spin_lock(&inode->i_lock);
	de = __d_find_any_alias(inode);
	spin_unlock(&inode->i_lock);
	return de;
}
EXPORT_SYMBOL(d_find_any_alias);

/**
 * d_obtain_alias - find or allocate a dentry for a given inode
 * @inode: inode to allocate the dentry for
 *
 * Obtain a dentry for an inode resulting from NFS filehandle conversion or
 * similar open by handle operations.  The returned dentry may be anonymous,
 * or may have a full name (if the inode was already in the cache).
 *
 * When called on a directory inode, we must ensure that the inode only ever
 * has one dentry.  If a dentry is found, that is returned instead of
 * allocating a new one.
 *
 * On successful return, the reference to the inode has been transferred
 * to the dentry.  In case of an error the reference on the inode is released.
 * To make it easier to use in export operations a %NULL or IS_ERR inode may
 * be passed in and will be the error will be propagate to the return value,
 * with a %NULL @inode replaced by ERR_PTR(-ESTALE).
 */
struct dentry *d_obtain_alias(struct inode *inode)
{
	static const struct qstr anonstring = QSTR_INIT("/", 1);
	struct dentry *tmp;
	struct dentry *res;
	unsigned add_flags;

	if (!inode)
		return ERR_PTR(-ESTALE);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	res = d_find_any_alias(inode);
	if (res)
		goto out_iput;

	tmp = __d_alloc(inode->i_sb, &anonstring);
	if (!tmp) {
		res = ERR_PTR(-ENOMEM);
		goto out_iput;
	}

	spin_lock(&inode->i_lock);
	res = __d_find_any_alias(inode);
	if (res) {
		spin_unlock(&inode->i_lock);
		dput(tmp);
		goto out_iput;
	}

	/* attach a disconnected dentry */
	add_flags = d_flags_for_inode(inode) | DCACHE_DISCONNECTED;

	spin_lock(&tmp->d_lock);
	tmp->d_inode = inode;
	tmp->d_flags |= add_flags;
	hlist_add_head(&tmp->d_alias, &inode->i_dentry);
	hlist_bl_lock(&tmp->d_sb->s_anon);
	hlist_bl_add_head(&tmp->d_hash, &tmp->d_sb->s_anon);
	hlist_bl_unlock(&tmp->d_sb->s_anon);
	spin_unlock(&tmp->d_lock);
	spin_unlock(&inode->i_lock);
	security_d_instantiate(tmp, inode);

	return tmp;

 out_iput:
	if (res && !IS_ERR(res))
		security_d_instantiate(res, inode);
	iput(inode);
	return res;
}
EXPORT_SYMBOL(d_obtain_alias);

/**
 * d_splice_alias - splice a disconnected dentry into the tree if one exists
 * @inode:  the inode which may have a disconnected dentry
 * @dentry: a negative dentry which we want to point to the inode.
 *
 * If inode is a directory and has a 'disconnected' dentry (i.e. IS_ROOT and
 * DCACHE_DISCONNECTED), then d_move that in place of the given dentry
 * and return it, else simply d_add the inode to the dentry and return NULL.
 *
 * This is needed in the lookup routine of any filesystem that is exportable
 * (via knfsd) so that we can build dcache paths to directories effectively.
 *
 * If a dentry was found and moved, then it is returned.  Otherwise NULL
 * is returned.  This matches the expected return value of ->lookup.
 *
 * Cluster filesystems may call this function with a negative, hashed dentry.
 * In that case, we know that the inode will be a regular file, and also this
 * will only occur during atomic_open. So we need to check for the dentry
 * being already hashed only in the final case.
 */
struct dentry *d_splice_alias(struct inode *inode, struct dentry *dentry)
{
	struct dentry *new = NULL;

	if (IS_ERR(inode))
		return ERR_CAST(inode);

	if (inode && S_ISDIR(inode->i_mode)) {
		spin_lock(&inode->i_lock);
		new = __d_find_alias(inode, 1);
		if (new) {
			BUG_ON(!(new->d_flags & DCACHE_DISCONNECTED));
			spin_unlock(&inode->i_lock);
			security_d_instantiate(new, inode);
			d_move(new, dentry);
			iput(inode);
		} else {
			/* already taking inode->i_lock, so d_add() by hand */
			__d_instantiate(dentry, inode);
			spin_unlock(&inode->i_lock);
			security_d_instantiate(dentry, inode);
			d_rehash(dentry);
		}
	} else {
		d_instantiate(dentry, inode);
		if (d_unhashed(dentry))
			d_rehash(dentry);
	}
	return new;
}
EXPORT_SYMBOL(d_splice_alias);

/**
 * d_add_ci - lookup or allocate new dentry with case-exact name
 * @inode:  the inode case-insensitive lookup has found
 * @dentry: the negative dentry that was passed to the parent's lookup func
 * @name:   the case-exact name to be associated with the returned dentry
 *
 * This is to avoid filling the dcache with case-insensitive names to the
 * same inode, only the actual correct case is stored in the dcache for
 * case-insensitive filesystems.
 *
 * For a case-insensitive lookup match and if the the case-exact dentry
 * already exists in in the dcache, use it and return it.
 *
 * If no entry exists with the exact case name, allocate new dentry with
 * the exact case, and return the spliced entry.
 */
struct dentry *d_add_ci(struct dentry *dentry, struct inode *inode,
			struct qstr *name)
{
	struct dentry *found;
	struct dentry *new;

	/*
	 * First check if a dentry matching the name already exists,
	 * if not go ahead and create it now.
	 */
	found = d_hash_and_lookup(dentry->d_parent, name);
	if (unlikely(IS_ERR(found)))
		goto err_out;
	if (!found) {
		new = d_alloc(dentry->d_parent, name);
		if (!new) {
			found = ERR_PTR(-ENOMEM);
			goto err_out;
		}

		found = d_splice_alias(inode, new);
		if (found) {
			dput(new);
			return found;
		}
		return new;
	}

	/*
	 * If a matching dentry exists, and it's not negative use it.
	 *
	 * Decrement the reference count to balance the iget() done
	 * earlier on.
	 */
	if (found->d_inode) {
		if (unlikely(found->d_inode != inode)) {
			/* This can't happen because bad inodes are unhashed. */
			BUG_ON(!is_bad_inode(inode));
			BUG_ON(!is_bad_inode(found->d_inode));
		}
		iput(inode);
		return found;
	}

	/*
	 * Negative dentry: instantiate it unless the inode is a directory and
	 * already has a dentry.
	 */
	new = d_splice_alias(inode, found);
	if (new) {
		dput(found);
		found = new;
	}
	return found;

err_out:
	iput(inode);
	return found;
}
EXPORT_SYMBOL(d_add_ci);

/*
 * Do the slow-case of the dentry name compare.
 *
 * Unlike the dentry_cmp() function, we need to atomically
 * load the name and length information, so that the
 * filesystem can rely on them, and can use the 'name' and
 * 'len' information without worrying about walking off the
 * end of memory etc.
 *
 * Thus the read_seqcount_retry() and the "duplicate" info
 * in arguments (the low-level filesystem should not look
 * at the dentry inode or name contents directly, since
 * rename can change them while we're in RCU mode).
 */
enum slow_d_compare {
	D_COMP_OK,
	D_COMP_NOMATCH,
	D_COMP_SEQRETRY,
};

static noinline enum slow_d_compare slow_dentry_cmp(
		const struct dentry *parent,
		struct dentry *dentry,
		unsigned int seq,
		const struct qstr *name)
{
	int tlen = dentry->d_name.len;
	const char *tname = dentry->d_name.name;

	if (read_seqcount_retry(&dentry->d_seq, seq)) {
		cpu_relax();
		return D_COMP_SEQRETRY;
	}
	if (parent->d_op->d_compare(parent, dentry, tlen, tname, name))
		return D_COMP_NOMATCH;
	return D_COMP_OK;
}

/**
 * __d_lookup_rcu - search for a dentry (racy, store-free)
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 * @seqp: returns d_seq value at the point where the dentry was found
 * Returns: dentry, or NULL
 *
 * __d_lookup_rcu is the dcache lookup function for rcu-walk name
 * resolution (store-free path walking) design described in
 * Documentation/filesystems/path-lookup.txt.
 *
 * This is not to be used outside core vfs.
 *
 * __d_lookup_rcu must only be used in rcu-walk mode, ie. with vfsmount lock
 * held, and rcu_read_lock held. The returned dentry must not be stored into
 * without taking d_lock and checking d_seq sequence count against @seq
 * returned here.
 *
 * A refcount may be taken on the found dentry with the d_rcu_to_refcount
 * function.
 *
 * Alternatively, __d_lookup_rcu may be called again to look up the child of
 * the returned dentry, so long as its parent's seqlock is checked after the
 * child is looked up. Thus, an interlocking stepping of sequence lock checks
 * is formed, giving integrity down the path walk.
 *
 * NOTE! The caller *has* to check the resulting dentry against the sequence
 * number we've returned before using any of the resulting dentry state!
 */
struct dentry *__d_lookup_rcu(const struct dentry *parent,
				const struct qstr *name,
				unsigned *seqp)
{
	u64 hashlen = name->hash_len;
	const unsigned char *str = name->name;
	struct hlist_bl_head *b = d_hash(parent, hashlen_hash(hashlen));
	struct hlist_bl_node *node;
	struct dentry *dentry;

	/*
	 * Note: There is significant duplication with __d_lookup_rcu which is
	 * required to prevent single threaded performance regressions
	 * especially on architectures where smp_rmb (in seqcounts) are costly.
	 * Keep the two functions in sync.
	 */

	/*
	 * The hash list is protected using RCU.
	 *
	 * Carefully use d_seq when comparing a candidate dentry, to avoid
	 * races with d_move().
	 *
	 * It is possible that concurrent renames can mess up our list
	 * walk here and result in missing our dentry, resulting in the
	 * false-negative result. d_lookup() protects against concurrent
	 * renames using rename_lock seqlock.
	 *
	 * See Documentation/filesystems/path-lookup.txt for more details.
	 */
	hlist_bl_for_each_entry_rcu(dentry, node, b, d_hash) {
		unsigned seq;

seqretry:
		/*
		 * The dentry sequence count protects us from concurrent
		 * renames, and thus protects parent and name fields.
		 *
		 * The caller must perform a seqcount check in order
		 * to do anything useful with the returned dentry.
		 *
		 * NOTE! We do a "raw" seqcount_begin here. That means that
		 * we don't wait for the sequence count to stabilize if it
		 * is in the middle of a sequence change. If we do the slow
		 * dentry compare, we will do seqretries until it is stable,
		 * and if we end up with a successful lookup, we actually
		 * want to exit RCU lookup anyway.
		 */
		seq = raw_seqcount_begin(&dentry->d_seq);
		if (dentry->d_parent != parent)
			continue;
		if (d_unhashed(dentry))
			continue;

		if (unlikely(parent->d_flags & DCACHE_OP_COMPARE)) {
			if (dentry->d_name.hash != hashlen_hash(hashlen))
				continue;
			*seqp = seq;
			switch (slow_dentry_cmp(parent, dentry, seq, name)) {
			case D_COMP_OK:
				return dentry;
			case D_COMP_NOMATCH:
				continue;
			default:
				goto seqretry;
			}
		}

		if (dentry->d_name.hash_len != hashlen)
			continue;
		*seqp = seq;
		if (!dentry_cmp(dentry, str, hashlen_len(hashlen)))
			return dentry;
	}
	return NULL;
}

/**
 * d_lookup - search for a dentry
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 * Returns: dentry, or NULL
 *
 * d_lookup searches the children of the parent dentry for the name in
 * question. If the dentry is found its reference count is incremented and the
 * dentry is returned. The caller must use dput to free the entry when it has
 * finished using it. %NULL is returned if the dentry does not exist.
 */
struct dentry *d_lookup(const struct dentry *parent, const struct qstr *name)
{
	struct dentry *dentry;
	unsigned seq;

        do {
                seq = read_seqbegin(&rename_lock);
                dentry = __d_lookup(parent, name);
                if (dentry)
			break;
	} while (read_seqretry(&rename_lock, seq));
	return dentry;
}
EXPORT_SYMBOL(d_lookup);

/**
 * __d_lookup - search for a dentry (racy)
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 * Returns: dentry, or NULL
 *
 * __d_lookup is like d_lookup, however it may (rarely) return a
 * false-negative result due to unrelated rename activity.
 *
 * __d_lookup is slightly faster by avoiding rename_lock read seqlock,
 * however it must be used carefully, eg. with a following d_lookup in
 * the case of failure.
 *
 * __d_lookup callers must be commented.
 */
struct dentry *__d_lookup(const struct dentry *parent, const struct qstr *name)
{
	unsigned int len = name->len;
	unsigned int hash = name->hash;
	const unsigned char *str = name->name;
	struct hlist_bl_head *b = d_hash(parent, hash);
	struct hlist_bl_node *node;
	struct dentry *found = NULL;
	struct dentry *dentry;

	/*
	 * Note: There is significant duplication with __d_lookup_rcu which is
	 * required to prevent single threaded performance regressions
	 * especially on architectures where smp_rmb (in seqcounts) are costly.
	 * Keep the two functions in sync.
	 */

	/*
	 * The hash list is protected using RCU.
	 *
	 * Take d_lock when comparing a candidate dentry, to avoid races
	 * with d_move().
	 *
	 * It is possible that concurrent renames can mess up our list
	 * walk here and result in missing our dentry, resulting in the
	 * false-negative result. d_lookup() protects against concurrent
	 * renames using rename_lock seqlock.
	 *
	 * See Documentation/filesystems/path-lookup.txt for more details.
	 */
	rcu_read_lock();
	
	hlist_bl_for_each_entry_rcu(dentry, node, b, d_hash) {

		if (dentry->d_name.hash != hash)
			continue;

		spin_lock(&dentry->d_lock);
		if (dentry->d_parent != parent)
			goto next;
		if (d_unhashed(dentry))
			goto next;

		/*
		 * It is safe to compare names since d_move() cannot
		 * change the qstr (protected by d_lock).
		 */
		if (parent->d_flags & DCACHE_OP_COMPARE) {
			int tlen = dentry->d_name.len;
			const char *tname = dentry->d_name.name;
			if (parent->d_op->d_compare(parent, dentry, tlen, tname, name))
				goto next;
		} else {
			if (dentry->d_name.len != len)
				goto next;
			if (dentry_cmp(dentry, str, len))
				goto next;
		}

		dentry->d_lockref.count++;
		found = dentry;
		spin_unlock(&dentry->d_lock);
		break;
next:
		spin_unlock(&dentry->d_lock);
 	}
 	rcu_read_unlock();

 	return found;
}

/**
 * d_hash_and_lookup - hash the qstr then search for a dentry
 * @dir: Directory to search in
 * @name: qstr of name we wish to find
 *
 * On lookup failure NULL is returned; on bad name - ERR_PTR(-error)
 */
struct dentry *d_hash_and_lookup(struct dentry *dir, struct qstr *name)
{
	/*
	 * Check for a fs-specific hash function. Note that we must
	 * calculate the standard hash first, as the d_op->d_hash()
	 * routine may choose to leave the hash value unchanged.
	 */
	name->hash = full_name_hash(name->name, name->len);
	if (dir->d_flags & DCACHE_OP_HASH) {
		int err = dir->d_op->d_hash(dir, name);
		if (unlikely(err < 0))
			return ERR_PTR(err);
	}
	return d_lookup(dir, name);
}
EXPORT_SYMBOL(d_hash_and_lookup);

/**
 * d_validate - verify dentry provided from insecure source (deprecated)
 * @dentry: The dentry alleged to be valid child of @dparent
 * @dparent: The parent dentry (known to be valid)
 *
 * An insecure source has sent us a dentry, here we verify it and dget() it.
 * This is used by ncpfs in its readdir implementation.
 * Zero is returned in the dentry is invalid.
 *
 * This function is slow for big directories, and deprecated, do not use it.
 */
int d_validate(struct dentry *dentry, struct dentry *dparent)
{
	struct dentry *child;

	spin_lock(&dparent->d_lock);
	list_for_each_entry(child, &dparent->d_subdirs, d_u.d_child) {
		if (dentry == child) {
			spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);
			__dget_dlock(dentry);
			spin_unlock(&dentry->d_lock);
			spin_unlock(&dparent->d_lock);
			return 1;
		}
	}
	spin_unlock(&dparent->d_lock);

	return 0;
}
EXPORT_SYMBOL(d_validate);

/*
 * When a file is deleted, we have two options:
 * - turn this dentry into a negative dentry
 * - unhash this dentry and free it.
 *
 * Usually, we want to just turn this into
 * a negative dentry, but if anybody else is
 * currently using the dentry or the inode
 * we can't do that and we fall back on removing
 * it from the hash queues and waiting for
 * it to be deleted later when it has no users
 */
 
/**
 * d_delete - delete a dentry
 * @dentry: The dentry to delete
 *
 * Turn the dentry into a negative dentry if possible, otherwise
 * remove it from the hash queues so it can be deleted later
 */
 
void d_delete(struct dentry * dentry)
{
	struct inode *inode;
	int isdir = 0;
	/*
	 * Are we the only user?
	 */
again:
	spin_lock(&dentry->d_lock);
	inode = dentry->d_inode;
	isdir = S_ISDIR(inode->i_mode);
	if (dentry->d_lockref.count == 1) {
		if (!spin_trylock(&inode->i_lock)) {
			spin_unlock(&dentry->d_lock);
			cpu_relax();
			goto again;
		}
		dentry->d_flags &= ~DCACHE_CANT_MOUNT;
		dentry_unlink_inode(dentry);
		fsnotify_nameremove(dentry, isdir);
		return;
	}

	if (!d_unhashed(dentry))
		__d_drop(dentry);

	spin_unlock(&dentry->d_lock);

	fsnotify_nameremove(dentry, isdir);
}
EXPORT_SYMBOL(d_delete);

// ARM10C 20161126
// entry: kmem_cache#5-oX (struct dentry), hash 0xXXXXXXXX 에 맞는 list table 주소값
static void __d_rehash(struct dentry * entry, struct hlist_bl_head *b)
{
	// entry: kmem_cache#5-oX (struct dentry), d_unhashed(kmem_cache#5-oX (struct dentry)): 1
	BUG_ON(!d_unhashed(entry));

	// b: hash 0xXXXXXXXX 에 맞는 list table 주소값
	hlist_bl_lock(b);

	// hlist_bl_lock 에서 한일:
	// hash 0xXXXXXXXX 에 맞는 list table 주소값의 0 bit 를 1로 set

	// entry->d_flags: (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100000, DCACHE_RCUACCESS: 0x00000080
	entry->d_flags |= DCACHE_RCUACCESS;
	// entry->d_flags: (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100080

	// &entry->d_hash: &(kmem_cache#5-oX (struct dentry))->d_hash, b: hash 0xXXXXXXXX 에 맞는 list table 주소값
	hlist_bl_add_head_rcu(&entry->d_hash, b);

	// hlist_bl_add_head_rcu 에서 한일:
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->pprev: &(hash 0xXXXXXXXX 에 맞는 list table 주소값)->first
	//
	// ((hash 0xXXXXXXXX 에 맞는 list table 주소값)->first): ((&(kmem_cache#5-oX (struct dentry))->d_hash) | 1)

	// b: hash 0xXXXXXXXX 에 맞는 list table 주소값
	hlist_bl_unlock(b);

	// hlist_bl_unlock 에서 한일:
	// hash 0xXXXXXXXX 에 맞는 list table 주소값 의 bit 0을 클리어함
	// dmb(ish)를 사용하여 공유 자원 hash 0xXXXXXXXX 에 맞는 list table 주소값 값을 갱신
}

// ARM10C 20161126
// entry: kmem_cache#5-oX (struct dentry)
static void _d_rehash(struct dentry * entry)
{
	// entry: kmem_cache#5-oX (struct dentry),
	// entry->d_parent: (kmem_cache#5-oX (struct dentry))->d_parent: kmem_cache#5-oX (struct dentry),
	// entry->d_name.hash: (kmem_cache#5-oX (struct dentry))->d_name.hash: 0xXXXXXXXX
	// d_hash(kmem_cache#5-oX (struct dentry), 0xXXXXXXXX): hash 0xXXXXXXXX 에 맞는 list table 주소값
	__d_rehash(entry, d_hash(entry->d_parent, entry->d_name.hash));

	// __d_rehash 에서 한일:
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100080
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->pprev: &(hash 0xXXXXXXXX 에 맞는 list table 주소값)->first
	//
	// ((hash 0xXXXXXXXX 에 맞는 list table 주소값)->first): ((&(kmem_cache#5-oX (struct dentry))->d_hash) | 1)
}

/**
 * d_rehash	- add an entry back to the hash
 * @entry: dentry to add to the hash
 *
 * Adds a dentry to the hash according to its name.
 */
 
// ARM10C 20161126
// entry: kmem_cache#5-oX (struct dentry)
void d_rehash(struct dentry * entry)
{
	// &entry->d_lock: &(kmem_cache#5-oX (struct dentry))->d_lock
	spin_lock(&entry->d_lock);

	// spin_lock 에서 한일:
	// &(kmem_cache#5-oX (struct dentry))->d_lock 을 사용하여 spin lock 을 수행

	// entry: kmem_cache#5-oX (struct dentry)
	_d_rehash(entry);

	// _d_rehash 에서 한일:
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100080
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->pprev: &(hash 0xXXXXXXXX 에 맞는 list table 주소값)->first
	//
	// ((hash 0xXXXXXXXX 에 맞는 list table 주소값)->first): ((&(kmem_cache#5-oX (struct dentry))->d_hash) | 1)

	// &entry->d_lock: &(kmem_cache#5-oX (struct dentry))->d_lock
	spin_unlock(&entry->d_lock);

	// spin_unlock 에서 한일:
	// &(kmem_cache#5-oX (struct dentry))->d_lock 을 사용하여 spin unlock 을 수행
}
EXPORT_SYMBOL(d_rehash);

/**
 * dentry_update_name_case - update case insensitive dentry with a new name
 * @dentry: dentry to be updated
 * @name: new name
 *
 * Update a case insensitive dentry with new case of name.
 *
 * dentry must have been returned by d_lookup with name @name. Old and new
 * name lengths must match (ie. no d_compare which allows mismatched name
 * lengths).
 *
 * Parent inode i_mutex must be held over d_lookup and into this call (to
 * keep renames and concurrent inserts, and readdir(2) away).
 */
void dentry_update_name_case(struct dentry *dentry, struct qstr *name)
{
	BUG_ON(!mutex_is_locked(&dentry->d_parent->d_inode->i_mutex));
	BUG_ON(dentry->d_name.len != name->len); /* d_lookup gives this */

	spin_lock(&dentry->d_lock);
	write_seqcount_begin(&dentry->d_seq);
	memcpy((unsigned char *)dentry->d_name.name, name->name, name->len);
	write_seqcount_end(&dentry->d_seq);
	spin_unlock(&dentry->d_lock);
}
EXPORT_SYMBOL(dentry_update_name_case);

static void switch_names(struct dentry *dentry, struct dentry *target)
{
	if (dname_external(target)) {
		if (dname_external(dentry)) {
			/*
			 * Both external: swap the pointers
			 */
			swap(target->d_name.name, dentry->d_name.name);
		} else {
			/*
			 * dentry:internal, target:external.  Steal target's
			 * storage and make target internal.
			 */
			memcpy(target->d_iname, dentry->d_name.name,
					dentry->d_name.len + 1);
			dentry->d_name.name = target->d_name.name;
			target->d_name.name = target->d_iname;
		}
	} else {
		if (dname_external(dentry)) {
			/*
			 * dentry:external, target:internal.  Give dentry's
			 * storage to target and make dentry internal
			 */
			memcpy(dentry->d_iname, target->d_name.name,
					target->d_name.len + 1);
			target->d_name.name = dentry->d_name.name;
			dentry->d_name.name = dentry->d_iname;
		} else {
			/*
			 * Both are internal.  Just copy target to dentry
			 */
			memcpy(dentry->d_iname, target->d_name.name,
					target->d_name.len + 1);
			dentry->d_name.len = target->d_name.len;
			return;
		}
	}
	swap(dentry->d_name.len, target->d_name.len);
}

static void dentry_lock_for_move(struct dentry *dentry, struct dentry *target)
{
	/*
	 * XXXX: do we really need to take target->d_lock?
	 */
	if (IS_ROOT(dentry) || dentry->d_parent == target->d_parent)
		spin_lock(&target->d_parent->d_lock);
	else {
		if (d_ancestor(dentry->d_parent, target->d_parent)) {
			spin_lock(&dentry->d_parent->d_lock);
			spin_lock_nested(&target->d_parent->d_lock,
						DENTRY_D_LOCK_NESTED);
		} else {
			spin_lock(&target->d_parent->d_lock);
			spin_lock_nested(&dentry->d_parent->d_lock,
						DENTRY_D_LOCK_NESTED);
		}
	}
	if (target < dentry) {
		spin_lock_nested(&target->d_lock, 2);
		spin_lock_nested(&dentry->d_lock, 3);
	} else {
		spin_lock_nested(&dentry->d_lock, 2);
		spin_lock_nested(&target->d_lock, 3);
	}
}

static void dentry_unlock_parents_for_move(struct dentry *dentry,
					struct dentry *target)
{
	if (target->d_parent != dentry->d_parent)
		spin_unlock(&dentry->d_parent->d_lock);
	if (target->d_parent != target)
		spin_unlock(&target->d_parent->d_lock);
}

/*
 * When switching names, the actual string doesn't strictly have to
 * be preserved in the target - because we're dropping the target
 * anyway. As such, we can just do a simple memcpy() to copy over
 * the new name before we switch.
 *
 * Note that we have to be a lot more careful about getting the hash
 * switched - we have to switch the hash value properly even if it
 * then no longer matches the actual (corrupted) string of the target.
 * The hash value has to match the hash queue that the dentry is on..
 */
/*
 * __d_move - move a dentry
 * @dentry: entry to move
 * @target: new dentry
 *
 * Update the dcache to reflect the move of a file name. Negative
 * dcache entries should not be moved in this way. Caller must hold
 * rename_lock, the i_mutex of the source and target directories,
 * and the sb->s_vfs_rename_mutex if they differ. See lock_rename().
 */
static void __d_move(struct dentry * dentry, struct dentry * target)
{
	if (!dentry->d_inode)
		printk(KERN_WARNING "VFS: moving negative dcache entry\n");

	BUG_ON(d_ancestor(dentry, target));
	BUG_ON(d_ancestor(target, dentry));

	dentry_lock_for_move(dentry, target);

	write_seqcount_begin(&dentry->d_seq);
	write_seqcount_begin_nested(&target->d_seq, DENTRY_D_LOCK_NESTED);

	/* __d_drop does write_seqcount_barrier, but they're OK to nest. */

	/*
	 * Move the dentry to the target hash queue. Don't bother checking
	 * for the same hash queue because of how unlikely it is.
	 */
	__d_drop(dentry);
	__d_rehash(dentry, d_hash(target->d_parent, target->d_name.hash));

	/* Unhash the target: dput() will then get rid of it */
	__d_drop(target);

	list_del(&dentry->d_u.d_child);
	list_del(&target->d_u.d_child);

	/* Switch the names.. */
	switch_names(dentry, target);
	swap(dentry->d_name.hash, target->d_name.hash);

	/* ... and switch the parents */
	if (IS_ROOT(dentry)) {
		dentry->d_parent = target->d_parent;
		target->d_parent = target;
		INIT_LIST_HEAD(&target->d_u.d_child);
	} else {
		swap(dentry->d_parent, target->d_parent);

		/* And add them back to the (new) parent lists */
		list_add(&target->d_u.d_child, &target->d_parent->d_subdirs);
	}

	list_add(&dentry->d_u.d_child, &dentry->d_parent->d_subdirs);

	write_seqcount_end(&target->d_seq);
	write_seqcount_end(&dentry->d_seq);

	dentry_unlock_parents_for_move(dentry, target);
	spin_unlock(&target->d_lock);
	fsnotify_d_move(dentry);
	spin_unlock(&dentry->d_lock);
}

/*
 * d_move - move a dentry
 * @dentry: entry to move
 * @target: new dentry
 *
 * Update the dcache to reflect the move of a file name. Negative
 * dcache entries should not be moved in this way. See the locking
 * requirements for __d_move.
 */
void d_move(struct dentry *dentry, struct dentry *target)
{
	write_seqlock(&rename_lock);
	__d_move(dentry, target);
	write_sequnlock(&rename_lock);
}
EXPORT_SYMBOL(d_move);

/**
 * d_ancestor - search for an ancestor
 * @p1: ancestor dentry
 * @p2: child dentry
 *
 * Returns the ancestor dentry of p2 which is a child of p1, if p1 is
 * an ancestor of p2, else NULL.
 */
struct dentry *d_ancestor(struct dentry *p1, struct dentry *p2)
{
	struct dentry *p;

	for (p = p2; !IS_ROOT(p); p = p->d_parent) {
		if (p->d_parent == p1)
			return p;
	}
	return NULL;
}

/*
 * This helper attempts to cope with remotely renamed directories
 *
 * It assumes that the caller is already holding
 * dentry->d_parent->d_inode->i_mutex, inode->i_lock and rename_lock
 *
 * Note: If ever the locking in lock_rename() changes, then please
 * remember to update this too...
 */
static struct dentry *__d_unalias(struct inode *inode,
		struct dentry *dentry, struct dentry *alias)
{
	struct mutex *m1 = NULL, *m2 = NULL;
	struct dentry *ret = ERR_PTR(-EBUSY);

	/* If alias and dentry share a parent, then no extra locks required */
	if (alias->d_parent == dentry->d_parent)
		goto out_unalias;

	/* See lock_rename() */
	if (!mutex_trylock(&dentry->d_sb->s_vfs_rename_mutex))
		goto out_err;
	m1 = &dentry->d_sb->s_vfs_rename_mutex;
	if (!mutex_trylock(&alias->d_parent->d_inode->i_mutex))
		goto out_err;
	m2 = &alias->d_parent->d_inode->i_mutex;
out_unalias:
	if (likely(!d_mountpoint(alias))) {
		__d_move(alias, dentry);
		ret = alias;
	}
out_err:
	spin_unlock(&inode->i_lock);
	if (m2)
		mutex_unlock(m2);
	if (m1)
		mutex_unlock(m1);
	return ret;
}

/*
 * Prepare an anonymous dentry for life in the superblock's dentry tree as a
 * named dentry in place of the dentry to be replaced.
 * returns with anon->d_lock held!
 */
static void __d_materialise_dentry(struct dentry *dentry, struct dentry *anon)
{
	struct dentry *dparent;

	dentry_lock_for_move(anon, dentry);

	write_seqcount_begin(&dentry->d_seq);
	write_seqcount_begin_nested(&anon->d_seq, DENTRY_D_LOCK_NESTED);

	dparent = dentry->d_parent;

	switch_names(dentry, anon);
	swap(dentry->d_name.hash, anon->d_name.hash);

	dentry->d_parent = dentry;
	list_del_init(&dentry->d_u.d_child);
	anon->d_parent = dparent;
	list_move(&anon->d_u.d_child, &dparent->d_subdirs);

	write_seqcount_end(&dentry->d_seq);
	write_seqcount_end(&anon->d_seq);

	dentry_unlock_parents_for_move(anon, dentry);
	spin_unlock(&dentry->d_lock);

	/* anon->d_lock still locked, returns locked */
}

/**
 * d_materialise_unique - introduce an inode into the tree
 * @dentry: candidate dentry
 * @inode: inode to bind to the dentry, to which aliases may be attached
 *
 * Introduces an dentry into the tree, substituting an extant disconnected
 * root directory alias in its place if there is one. Caller must hold the
 * i_mutex of the parent directory.
 */
struct dentry *d_materialise_unique(struct dentry *dentry, struct inode *inode)
{
	struct dentry *actual;

	BUG_ON(!d_unhashed(dentry));

	if (!inode) {
		actual = dentry;
		__d_instantiate(dentry, NULL);
		d_rehash(actual);
		goto out_nolock;
	}

	spin_lock(&inode->i_lock);

	if (S_ISDIR(inode->i_mode)) {
		struct dentry *alias;

		/* Does an aliased dentry already exist? */
		alias = __d_find_alias(inode, 0);
		if (alias) {
			actual = alias;
			write_seqlock(&rename_lock);

			if (d_ancestor(alias, dentry)) {
				/* Check for loops */
				actual = ERR_PTR(-ELOOP);
				spin_unlock(&inode->i_lock);
			} else if (IS_ROOT(alias)) {
				/* Is this an anonymous mountpoint that we
				 * could splice into our tree? */
				__d_materialise_dentry(dentry, alias);
				write_sequnlock(&rename_lock);
				__d_drop(alias);
				goto found;
			} else {
				/* Nope, but we must(!) avoid directory
				 * aliasing. This drops inode->i_lock */
				actual = __d_unalias(inode, dentry, alias);
			}
			write_sequnlock(&rename_lock);
			if (IS_ERR(actual)) {
				if (PTR_ERR(actual) == -ELOOP)
					pr_warn_ratelimited(
						"VFS: Lookup of '%s' in %s %s"
						" would have caused loop\n",
						dentry->d_name.name,
						inode->i_sb->s_type->name,
						inode->i_sb->s_id);
				dput(alias);
			}
			goto out_nolock;
		}
	}

	/* Add a unique reference */
	actual = __d_instantiate_unique(dentry, inode);
	if (!actual)
		actual = dentry;
	else
		BUG_ON(!d_unhashed(actual));

	spin_lock(&actual->d_lock);
found:
	_d_rehash(actual);
	spin_unlock(&actual->d_lock);
	spin_unlock(&inode->i_lock);
out_nolock:
	if (actual == dentry) {
		security_d_instantiate(dentry, inode);
		return NULL;
	}

	iput(inode);
	return actual;
}
EXPORT_SYMBOL_GPL(d_materialise_unique);

static int prepend(char **buffer, int *buflen, const char *str, int namelen)
{
	*buflen -= namelen;
	if (*buflen < 0)
		return -ENAMETOOLONG;
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

/**
 * prepend_name - prepend a pathname in front of current buffer pointer
 * @buffer: buffer pointer
 * @buflen: allocated length of the buffer
 * @name:   name string and length qstr structure
 *
 * With RCU path tracing, it may race with d_move(). Use ACCESS_ONCE() to
 * make sure that either the old or the new name pointer and length are
 * fetched. However, there may be mismatch between length and pointer.
 * The length cannot be trusted, we need to copy it byte-by-byte until
 * the length is reached or a null byte is found. It also prepends "/" at
 * the beginning of the name. The sequence number check at the caller will
 * retry it again when a d_move() does happen. So any garbage in the buffer
 * due to mismatched pointer and length will be discarded.
 */
static int prepend_name(char **buffer, int *buflen, struct qstr *name)
{
	const char *dname = ACCESS_ONCE(name->name);
	u32 dlen = ACCESS_ONCE(name->len);
	char *p;

	*buflen -= dlen + 1;
	if (*buflen < 0)
		return -ENAMETOOLONG;
	p = *buffer -= dlen + 1;
	*p++ = '/';
	while (dlen--) {
		char c = *dname++;
		if (!c)
			break;
		*p++ = c;
	}
	return 0;
}

/**
 * prepend_path - Prepend path string to a buffer
 * @path: the dentry/vfsmount to report
 * @root: root vfsmnt/dentry
 * @buffer: pointer to the end of the buffer
 * @buflen: pointer to buffer length
 *
 * The function will first try to write out the pathname without taking any
 * lock other than the RCU read lock to make sure that dentries won't go away.
 * It only checks the sequence number of the global rename_lock as any change
 * in the dentry's d_seq will be preceded by changes in the rename_lock
 * sequence number. If the sequence number had been changed, it will restart
 * the whole pathname back-tracing sequence again by taking the rename_lock.
 * In this case, there is no need to take the RCU read lock as the recursive
 * parent pointer references will keep the dentry chain alive as long as no
 * rename operation is performed.
 */
static int prepend_path(const struct path *path,
			const struct path *root,
			char **buffer, int *buflen)
{
	struct dentry *dentry;
	struct vfsmount *vfsmnt;
	struct mount *mnt;
	int error = 0;
	unsigned seq, m_seq = 0;
	char *bptr;
	int blen;

	rcu_read_lock();
restart_mnt:
	read_seqbegin_or_lock(&mount_lock, &m_seq);
	seq = 0;
	rcu_read_lock();
restart:
	bptr = *buffer;
	blen = *buflen;
	error = 0;
	dentry = path->dentry;
	vfsmnt = path->mnt;
	mnt = real_mount(vfsmnt);
	read_seqbegin_or_lock(&rename_lock, &seq);
	while (dentry != root->dentry || vfsmnt != root->mnt) {
		struct dentry * parent;

		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			struct mount *parent = ACCESS_ONCE(mnt->mnt_parent);
			/* Global root? */
			if (mnt != parent) {
				dentry = ACCESS_ONCE(mnt->mnt_mountpoint);
				mnt = parent;
				vfsmnt = &mnt->mnt;
				continue;
			}
			/*
			 * Filesystems needing to implement special "root names"
			 * should do so with ->d_dname()
			 */
			if (IS_ROOT(dentry) &&
			   (dentry->d_name.len != 1 ||
			    dentry->d_name.name[0] != '/')) {
				WARN(1, "Root dentry has weird name <%.*s>\n",
				     (int) dentry->d_name.len,
				     dentry->d_name.name);
			}
			if (!error)
				error = is_mounted(vfsmnt) ? 1 : 2;
			break;
		}
		parent = dentry->d_parent;
		prefetch(parent);
		error = prepend_name(&bptr, &blen, &dentry->d_name);
		if (error)
			break;

		dentry = parent;
	}
	if (!(seq & 1))
		rcu_read_unlock();
	if (need_seqretry(&rename_lock, seq)) {
		seq = 1;
		goto restart;
	}
	done_seqretry(&rename_lock, seq);

	if (!(m_seq & 1))
		rcu_read_unlock();
	if (need_seqretry(&mount_lock, m_seq)) {
		m_seq = 1;
		goto restart_mnt;
	}
	done_seqretry(&mount_lock, m_seq);

	if (error >= 0 && bptr == *buffer) {
		if (--blen < 0)
			error = -ENAMETOOLONG;
		else
			*--bptr = '/';
	}
	*buffer = bptr;
	*buflen = blen;
	return error;
}

/**
 * __d_path - return the path of a dentry
 * @path: the dentry/vfsmount to report
 * @root: root vfsmnt/dentry
 * @buf: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name.
 *
 * Returns a pointer into the buffer or an error code if the
 * path was too long.
 *
 * "buflen" should be positive.
 *
 * If the path is not reachable from the supplied root, return %NULL.
 */
char *__d_path(const struct path *path,
	       const struct path *root,
	       char *buf, int buflen)
{
	char *res = buf + buflen;
	int error;

	prepend(&res, &buflen, "\0", 1);
	error = prepend_path(path, root, &res, &buflen);

	if (error < 0)
		return ERR_PTR(error);
	if (error > 0)
		return NULL;
	return res;
}

char *d_absolute_path(const struct path *path,
	       char *buf, int buflen)
{
	struct path root = {};
	char *res = buf + buflen;
	int error;

	prepend(&res, &buflen, "\0", 1);
	error = prepend_path(path, &root, &res, &buflen);

	if (error > 1)
		error = -EINVAL;
	if (error < 0)
		return ERR_PTR(error);
	return res;
}

/*
 * same as __d_path but appends "(deleted)" for unlinked files.
 */
static int path_with_deleted(const struct path *path,
			     const struct path *root,
			     char **buf, int *buflen)
{
	prepend(buf, buflen, "\0", 1);
	if (d_unlinked(path->dentry)) {
		int error = prepend(buf, buflen, " (deleted)", 10);
		if (error)
			return error;
	}

	return prepend_path(path, root, buf, buflen);
}

static int prepend_unreachable(char **buffer, int *buflen)
{
	return prepend(buffer, buflen, "(unreachable)", 13);
}

static void get_fs_root_rcu(struct fs_struct *fs, struct path *root)
{
	unsigned seq;

	do {
		seq = read_seqcount_begin(&fs->seq);
		*root = fs->root;
	} while (read_seqcount_retry(&fs->seq, seq));
}

/**
 * d_path - return the path of a dentry
 * @path: path to report
 * @buf: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name. If the entry has been deleted
 * the string " (deleted)" is appended. Note that this is ambiguous.
 *
 * Returns a pointer into the buffer or an error code if the path was
 * too long. Note: Callers should use the returned pointer, not the passed
 * in buffer, to use the name! The implementation often starts at an offset
 * into the buffer, and may leave 0 bytes at the start.
 *
 * "buflen" should be positive.
 */
char *d_path(const struct path *path, char *buf, int buflen)
{
	char *res = buf + buflen;
	struct path root;
	int error;

	/*
	 * We have various synthetic filesystems that never get mounted.  On
	 * these filesystems dentries are never used for lookup purposes, and
	 * thus don't need to be hashed.  They also don't need a name until a
	 * user wants to identify the object in /proc/pid/fd/.  The little hack
	 * below allows us to generate a name for these objects on demand:
	 *
	 * Some pseudo inodes are mountable.  When they are mounted
	 * path->dentry == path->mnt->mnt_root.  In that case don't call d_dname
	 * and instead have d_path return the mounted path.
	 */
	if (path->dentry->d_op && path->dentry->d_op->d_dname &&
	    (!IS_ROOT(path->dentry) || path->dentry != path->mnt->mnt_root))
		return path->dentry->d_op->d_dname(path->dentry, buf, buflen);

	rcu_read_lock();
	get_fs_root_rcu(current->fs, &root);
	error = path_with_deleted(path, &root, &res, &buflen);
	rcu_read_unlock();

	if (error < 0)
		res = ERR_PTR(error);
	return res;
}
EXPORT_SYMBOL(d_path);

/*
 * Helper function for dentry_operations.d_dname() members
 */
char *dynamic_dname(struct dentry *dentry, char *buffer, int buflen,
			const char *fmt, ...)
{
	va_list args;
	char temp[64];
	int sz;

	va_start(args, fmt);
	sz = vsnprintf(temp, sizeof(temp), fmt, args) + 1;
	va_end(args);

	if (sz > sizeof(temp) || sz > buflen)
		return ERR_PTR(-ENAMETOOLONG);

	buffer += buflen - sz;
	return memcpy(buffer, temp, sz);
}

char *simple_dname(struct dentry *dentry, char *buffer, int buflen)
{
	char *end = buffer + buflen;
	/* these dentries are never renamed, so d_lock is not needed */
	if (prepend(&end, &buflen, " (deleted)", 11) ||
	    prepend(&end, &buflen, dentry->d_name.name, dentry->d_name.len) ||
	    prepend(&end, &buflen, "/", 1))  
		end = ERR_PTR(-ENAMETOOLONG);
	return end;
}

/*
 * Write full pathname from the root of the filesystem into the buffer.
 */
static char *__dentry_path(struct dentry *dentry, char *buf, int buflen)
{
	char *end, *retval;
	int len, seq = 0;
	int error = 0;

	rcu_read_lock();
restart:
	end = buf + buflen;
	len = buflen;
	prepend(&end, &len, "\0", 1);
	if (buflen < 1)
		goto Elong;
	/* Get '/' right */
	retval = end-1;
	*retval = '/';
	read_seqbegin_or_lock(&rename_lock, &seq);
	while (!IS_ROOT(dentry)) {
		struct dentry *parent = dentry->d_parent;

		prefetch(parent);
		error = prepend_name(&end, &len, &dentry->d_name);
		if (error)
			break;

		retval = end;
		dentry = parent;
	}
	if (!(seq & 1))
		rcu_read_unlock();
	if (need_seqretry(&rename_lock, seq)) {
		seq = 1;
		goto restart;
	}
	done_seqretry(&rename_lock, seq);
	if (error)
		goto Elong;
	return retval;
Elong:
	return ERR_PTR(-ENAMETOOLONG);
}

char *dentry_path_raw(struct dentry *dentry, char *buf, int buflen)
{
	return __dentry_path(dentry, buf, buflen);
}
EXPORT_SYMBOL(dentry_path_raw);

char *dentry_path(struct dentry *dentry, char *buf, int buflen)
{
	char *p = NULL;
	char *retval;

	if (d_unlinked(dentry)) {
		p = buf + buflen;
		if (prepend(&p, &buflen, "//deleted", 10) != 0)
			goto Elong;
		buflen++;
	}
	retval = __dentry_path(dentry, buf, buflen);
	if (!IS_ERR(retval) && p)
		*p = '/';	/* restore '/' overriden with '\0' */
	return retval;
Elong:
	return ERR_PTR(-ENAMETOOLONG);
}

static void get_fs_root_and_pwd_rcu(struct fs_struct *fs, struct path *root,
				    struct path *pwd)
{
	unsigned seq;

	do {
		seq = read_seqcount_begin(&fs->seq);
		*root = fs->root;
		*pwd = fs->pwd;
	} while (read_seqcount_retry(&fs->seq, seq));
}

/*
 * NOTE! The user-level library version returns a
 * character pointer. The kernel system call just
 * returns the length of the buffer filled (which
 * includes the ending '\0' character), or a negative
 * error value. So libc would do something like
 *
 *	char *getcwd(char * buf, size_t size)
 *	{
 *		int retval;
 *
 *		retval = sys_getcwd(buf, size);
 *		if (retval >= 0)
 *			return buf;
 *		errno = -retval;
 *		return NULL;
 *	}
 */
SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
{
	int error;
	struct path pwd, root;
	char *page = __getname();

	if (!page)
		return -ENOMEM;

	rcu_read_lock();
	get_fs_root_and_pwd_rcu(current->fs, &root, &pwd);

	error = -ENOENT;
	if (!d_unlinked(pwd.dentry)) {
		unsigned long len;
		char *cwd = page + PATH_MAX;
		int buflen = PATH_MAX;

		prepend(&cwd, &buflen, "\0", 1);
		error = prepend_path(&pwd, &root, &cwd, &buflen);
		rcu_read_unlock();

		if (error < 0)
			goto out;

		/* Unreachable from current root */
		if (error > 0) {
			error = prepend_unreachable(&cwd, &buflen);
			if (error)
				goto out;
		}

		error = -ERANGE;
		len = PATH_MAX + page - cwd;
		if (len <= size) {
			error = len;
			if (copy_to_user(buf, cwd, len))
				error = -EFAULT;
		}
	} else {
		rcu_read_unlock();
	}

out:
	__putname(page);
	return error;
}

/*
 * Test whether new_dentry is a subdirectory of old_dentry.
 *
 * Trivially implemented using the dcache structure
 */

/**
 * is_subdir - is new dentry a subdirectory of old_dentry
 * @new_dentry: new dentry
 * @old_dentry: old dentry
 *
 * Returns 1 if new_dentry is a subdirectory of the parent (at any depth).
 * Returns 0 otherwise.
 * Caller must ensure that "new_dentry" is pinned before calling is_subdir()
 */
  
int is_subdir(struct dentry *new_dentry, struct dentry *old_dentry)
{
	int result;
	unsigned seq;

	if (new_dentry == old_dentry)
		return 1;

	do {
		/* for restarting inner loop in case of seq retry */
		seq = read_seqbegin(&rename_lock);
		/*
		 * Need rcu_readlock to protect against the d_parent trashing
		 * due to d_move
		 */
		rcu_read_lock();
		if (d_ancestor(old_dentry, new_dentry))
			result = 1;
		else
			result = 0;
		rcu_read_unlock();
	} while (read_seqretry(&rename_lock, seq));

	return result;
}

static enum d_walk_ret d_genocide_kill(void *data, struct dentry *dentry)
{
	struct dentry *root = data;
	if (dentry != root) {
		if (d_unhashed(dentry) || !dentry->d_inode)
			return D_WALK_SKIP;

		if (!(dentry->d_flags & DCACHE_GENOCIDE)) {
			dentry->d_flags |= DCACHE_GENOCIDE;
			dentry->d_lockref.count--;
		}
	}
	return D_WALK_CONTINUE;
}

void d_genocide(struct dentry *parent)
{
	d_walk(parent, parent, d_genocide_kill, NULL);
}

void d_tmpfile(struct dentry *dentry, struct inode *inode)
{
	inode_dec_link_count(inode);
	BUG_ON(dentry->d_name.name != dentry->d_iname ||
		!hlist_unhashed(&dentry->d_alias) ||
		!d_unlinked(dentry));
	spin_lock(&dentry->d_parent->d_lock);
	spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);
	dentry->d_name.len = sprintf(dentry->d_iname, "#%llu",
				(unsigned long long)inode->i_ino);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&dentry->d_parent->d_lock);
	d_instantiate(dentry, inode);
}
EXPORT_SYMBOL(d_tmpfile);

static __initdata unsigned long dhash_entries;
static int __init set_dhash_entries(char *str)
{
	if (!str)
		return 0;
	dhash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("dhash_entries=", set_dhash_entries);

// ARM10C 20140322
static void __init dcache_init_early(void)
{
	unsigned int loop;

	/* If hashes are distributed across NUMA nodes, defer
	 * hash allocation until vmalloc space is available.
	 */
	// hashdist: 0
	if (hashdist)
		return;
	
	dentry_hashtable =
		alloc_large_system_hash("Dentry cache",
					sizeof(struct hlist_bl_head),
					dhash_entries,
					13,
					HASH_EARLY,
					&d_hash_shift,
					&d_hash_mask,
					0,
					0);
	// Dentry cache용 dentry hash를 위한 메모리 공간을 512kB만큼 할당 받고,
	// d_hash_shift: 17, d_hash_mask: 0x1FFFF로 변경됨

	// d_hash_shift: 17
	for (loop = 0; loop < (1U << d_hash_shift); loop++)
		INIT_HLIST_BL_HEAD(dentry_hashtable + loop);
	// 131072개 만큼 hash를 만들었다. 총 hash크기는 512kB이다.
}

// ARM10C 20151003
static void __init dcache_init(void)
{
	unsigned int loop;

	/* 
	 * A constructor could be added for stable state like the lists,
	 * but it is probably not worth it because of the cache nature
	 * of the dcache. 
	 */
	// sizeof(struct dentry): 140 bytes
	// SLAB_RECLAIM_ACCOUNT: 0x00020000UL, SLAB_PANIC: 0x00040000UL, SLAB_MEM_SPREAD: 0x00100000UL
	// KMEM_CACHE(dentry, 0x160000):
	// kmem_cache_create("dentry", sizeof(struct dentry), __alignof__(struct dentry), (0x160000), NULL): kmem_cache#5
	dentry_cache = KMEM_CACHE(dentry,
		SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|SLAB_MEM_SPREAD);
	// dentry_cache: kmem_cache#5

	/* Hash may have been set up in dcache_init_early */
	// hashdist: 0
	if (!hashdist)
		return;
		// return 수행

	dentry_hashtable =
		alloc_large_system_hash("Dentry cache",
					sizeof(struct hlist_bl_head),
					dhash_entries,
					13,
					0,
					&d_hash_shift,
					&d_hash_mask,
					0,
					0);

	for (loop = 0; loop < (1U << d_hash_shift); loop++)
		INIT_HLIST_BL_HEAD(dentry_hashtable + loop);
}

/* SLAB cache for __getname() consumers */
// ARM10C 20151003
struct kmem_cache *names_cachep __read_mostly;
EXPORT_SYMBOL(names_cachep);

EXPORT_SYMBOL(d_genocide);

// ARM10C 20140322
void __init vfs_caches_init_early(void)
{
	dcache_init_early();
	// 131072개 만큼 hash를 만들었다. 총 hash크기는 512kB이다.

	inode_init_early();
	// 65536개 만큼 hash를 만들었다. 총 hash크기는 256kB이다.
}

// ARM10C 20151003
// totalram_pages: 총 free된 page 수
void __init vfs_caches_init(unsigned long mempages)
{
	unsigned long reserve;

	/* Base hash sizes on available memory, with a reserve equal to
           150% of current kernel size */

	// NOTE:
	// mempages 값과 nr_free_pages() 의 값을 정확히 알 수 없음
	// 계산된 reserve의 값을 XXX 로 함

	// mempages: 총 free된 page 수, nr_free_pages(): 현재의 free pages 수
	reserve = min((mempages - nr_free_pages()) * 3/2, mempages - 1);
	// reserve: XXX

	// mempages: 총 free된 page 수, reserve: XXX
	mempages -= reserve;
	// mempages: 총 free된 page 수 - XXX

	// PATH_MAX: 4096
	// SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_PANIC: 0x00040000UL
	// kmem_cache_create("names_cache", 4096, 0, 0x42000, NULL): kmem_cache#6
	names_cachep = kmem_cache_create("names_cache", PATH_MAX, 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
	// names_cachep: kmem_cache#6

	dcache_init();

	// dcache_init에서 한일:
	//
	// struct dentry를 위한 kmem_cache 생성
	// dentry_cache: kmem_cache#5

	inode_init();

	// inode_init에서 한일:
	//
	// struct inode를 위한 kmem_cache 생성
	// inode_cachep: kmem_cache#4

	// mempages: 총 free된 page 수 - XXX
	files_init(mempages);

	// files_init에서 한일:
	//
	// filp_cachep: kmem_cache#3
	// files_stat.max_files: (총 free된 page 수 - XXX) * 4 / 10
	// sysctl_nr_open_max: 0x3FFFFFE0
	//
	// (&(&(&(&nr_files)->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&nr_files)->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&nr_files)->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&nr_files)->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&nr_files)->list)->next: &(&nr_files)->list
	// (&(&nr_files)->list)->prev: &(&nr_files)->list
	// (&nr_files)->count: 0
	// (&nr_files)->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&nr_files)->list를 연결함

	mnt_init();

	// mnt_init 에서 한일:
	// struct mount 를 위한 mnt_cache 용 kmem_cache 를 생성함 mnt_cache: kmem_cache#2
	// mount cache 를 위해 사용할 hashtable을 위한 메모리를 할당 받음 mount_hashtable: 16kB만큼 할당받은 메모리 주소
	// mountpoint cache 를 위해 사용할 hashtable 위한 메모리를 할당 받음 mountpoint_hashtable: 16kB만큼 할당받은 메모리 주소
	//
	// mount cache 용 hash table을 초기화
	// (&mount_hashtable[0...4095])->first = NULL
	// mountpoint cache 용 hash table을 초기화
	// (&mountpoint_hashtable[0...4095])->first = NULL
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
	//
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
	//
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
	//
	// "rootfs" 으로 등록된 &rootfs_fs_type 을 찾음
	//
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
	//
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
	//
	// (kmem_cache#2-oX (struct mount))->mnt_ns: kmem_cache#30-oX (struct mnt_namespace)
	// (kmem_cache#30-oX (struct mnt_namespace))->root: kmem_cache#2-oX (struct mount)
	//
	// list head 인 &(kmem_cache#30-oX (struct mnt_namespace))->list 에 &(kmem_cache#2-oX (struct mount))->mnt_list 를 추가함
	//
	// init_task.nsproxy->mnt_ns: (&init_nsproxy)->mnt_ns: kmem_cache#30-oX (struct mnt_namespace)
	//
	// (&(kmem_cache#30-oX (struct mnt_namespace))->count)->counter 을 1 증가 시킴
	//
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count 을 1만큼 증가 시킴
	// (&(kmem_cache#5-oX (struct dentry))->d_lockref)->count: 1
	//
	// ((&init_task)->fs)->pwd.mnt: &(kmem_cache#2-oX (struct mount))->mnt
	// ((&init_task)->fs)->pwd.dentry: kmem_cache#5-oX (struct dentry)
	//
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count 을 1만큼 증가 시킴
	// (&(kmem_cache#5-oX (struct dentry))->d_lockref)->count: 1 만큼 증가 시킴
	//
	// ((&init_task)->fs)->root.mnt: &(kmem_cache#2-oX (struct mount))->mnt
	// ((&init_task)->fs)->root.dentry: kmem_cache#5-oX (struct dentry)

	bdev_cache_init();

	// bdev_cache_init 에서 한일:
	// struct bdev_inode를 위한 bdev_cache 용 kmem_cache 를 생성함 bdev_cachep: kmem_cache#n#30
	//
	// NOTE:
	// 기존에 생성해 만들어 놓은 kmem_cache 용 object를 전부 사용하여
	// 새로 kmem_cache를 위한 object를 만들었다고 가정하고 주석을 아래와 같이
	// 달기로 함.(30 -> 0 순으로 사용)
	// kmem_cache#n#30
	//
	// (&shmem_fs_type)->next: &bd_type
	//
	// file system 연결 결과
	// file_systems: sysfs_fs_type -> rootfs_fs_type -> shmem_fs_type -> bd_type
	//
	// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 3번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 3         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 3)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 3 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 4
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 3
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 3) 의 memory 공간을 반환함
	//
	// mnt_id_start: 4
	//
	// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "bdev"
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
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x80000000
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
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 3번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 3         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 3)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	//
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// (&(&unnamed_dev_ida)->idr)->id_free: (idr object new 0)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 3 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 4
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 3) 의 memory 공간을 반환함
	//
	// unnamed_dev_start: 4
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 3
	//
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	//
	// (kmem_cache#25-oX (struct super_block))->s_type: &bd_type
	// (kmem_cache#25-oX (struct super_block))->s_id: "bdev"
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
	// (kmem_cache#25-oX (struct super_block))->s_maxbytes: 0x7ffffffffff
	// (kmem_cache#25-oX (struct super_block))->s_blocksize: 0x1000
	// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 12
	// (kmem_cache#25-oX (struct super_block))->s_magic: 0x62646576
	// (kmem_cache#25-oX (struct super_block))->s_op: &bdev_sops
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
	// (kmem_cache#4-oX (struct inode))->i_ino: 1
	// (kmem_cache#4-oX (struct inode))->i_mode: 0040400
	// (kmem_cache#4-oX (struct inode))->i_atime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_mtime: CURRENT_TIME: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_ctime: CURRENT_TIME: 현재시간값
	//
	// dentry_cache인 kmem_cache#5을 사용하여 dentry로 사용할 메모리 kmem_cache#5-oX (struct dentry)을 할당받음
	//
	// (kmem_cache#5-oX (struct dentry))->d_iname[35]: 0
	// (kmem_cache#5-oX (struct dentry))->d_name.len: 5
	// (kmem_cache#5-oX (struct dentry))->d_name.hash: (&name)->hash: 0
	// (kmem_cache#5-oX (struct dentry))->d_iname: "bdev"
	//
	// 공유자원을 다른 cpu core가 사용할수 있게 함
	//
	// (kmem_cache#5-oX (struct dentry))->d_name.name: "bdev"
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
	// (kmem_cache#25-oX (struct super_block))->s_d_op: NULL
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0xc0000000
	// (&(kmem_cache#5-oX (struct dentry))->d_lockref)->count: 1
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0xe0000000
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
	// blockdev_superblock: kmem_cache#25-oX (struct super_block)

	chrdev_init();

	// chrdev_init에서 한일:
	// struct kobj_map 만큼의 메로리를 할당 받음 kmem_cache#26-oX (struct kobj_map)
	// struct probe 만큼의 메로리를 할당 받음 kmem_cache#30-oX (struct probe)
	//
	// (kmem_cache#30-oX (struct probe))->dev: 1
	// (kmem_cache#30-oX (struct probe))->range: 0xFFFFFFFF
	// (kmem_cache#30-oX (struct probe))->get: base_probe
	//
	// (kmem_cache#26-oX (struct kobj_map))->probes[0...255]: kmem_cache#30-oX (struct probe)
	// (kmem_cache#26-oX (struct kobj_map))->lock: &chrdevs_lock
	//
	// (&directly_mappable_cdev_bdi)->dev: NULL
	// (&directly_mappable_cdev_bdi)->min_ratio: 0
	// (&directly_mappable_cdev_bdi)->max_ratio: 100
	// (&directly_mappable_cdev_bdi)->max_prop_frac: 0x400
	// &(&directly_mappable_cdev_bdi)->wb_lock 을 이용한 spinlock 초기화 수행
	// (&(&directly_mappable_cdev_bdi)->bdi_list)->next: &(&directly_mappable_cdev_bdi)->bdi_list
	// (&(&directly_mappable_cdev_bdi)->bdi_list)->prev: &(&directly_mappable_cdev_bdi)->bdi_list
	// (&(&directly_mappable_cdev_bdi)->work_list)->next: &(&directly_mappable_cdev_bdi)->work_list
	// (&(&directly_mappable_cdev_bdi)->work_list)->prev: &(&directly_mappable_cdev_bdi)->work_list
	//
	// (&directly_mappable_cdev_bdi)->wb 의 맴버값을 0으로 초기화함
	// (&(&directly_mappable_cdev_bdi)->wb)->bdi: &directly_mappable_cdev_bdi
	// (&(&directly_mappable_cdev_bdi)->wb)->last_old_flush: XXX
	// (&(&(&directly_mappable_cdev_bdi)->wb)->b_dirty)->next: &(&(&directly_mappable_cdev_bdi)->wb)->b_dirty
	// (&(&(&directly_mappable_cdev_bdi)->wb)->b_dirty)->prev: &(&(&directly_mappable_cdev_bdi)->wb)->b_dirty
	// (&(&(&directly_mappable_cdev_bdi)->wb)->b_io)->next: &(&(&directly_mappable_cdev_bdi)->wb)->b_io
	// (&(&(&directly_mappable_cdev_bdi)->wb)->b_io)->prev: &(&(&directly_mappable_cdev_bdi)->wb)->b_io
	// (&(&(&directly_mappable_cdev_bdi)->wb)->b_more_io)->next: &(&(&directly_mappable_cdev_bdi)->wb)->b_more_io
	// (&(&(&directly_mappable_cdev_bdi)->wb)->b_more_io)->prev: &(&(&directly_mappable_cdev_bdi)->wb)->b_more_io
	// &(&(&directly_mappable_cdev_bdi)->wb)->list_lock 을 이용한 spinlock 초기화 수행
	// (&(&(&(&directly_mappable_cdev_bdi)->wb)->dwork)->work)->data: { 0xFFFFFFE0 }
	// (&(&(&(&(&directly_mappable_cdev_bdi)->wb)->dwork)->work)->entry)->next: &(&(&(&(&directly_mappable_cdev_bdi)->wb)->dwork)->work)->entry
	// (&(&(&(&(&directly_mappable_cdev_bdi)->wb)->dwork)->work)->entry)->prev: &(&(&(&(&directly_mappable_cdev_bdi)->wb)->dwork)->work)->entry
	// (&(&(&(&directly_mappable_cdev_bdi)->wb)->dwork)->work)->func: bdi_writeback_workfn
	// (&(&(&(&directly_mappable_cdev_bdi)->wb)->dwork)->timer)->entry.next: NULL
	// (&(&(&(&directly_mappable_cdev_bdi)->wb)->dwork)->timer)->base: [pcp0] tvec_bases | 0x2
	// (&(&(&(&directly_mappable_cdev_bdi)->wb)->dwork)->timer)->slack: -1
	// (&(&(&(&directly_mappable_cdev_bdi)->wb)->dwork)->timer)->function = (delayed_work_timer_fn);
	// (&(&(&(&directly_mappable_cdev_bdi)->wb)->dwork)->timer)->data = ((unsigned long)(&(&(&directly_mappable_cdev_bdi)->wb)->dwork));
	//
	// (&(&(&(&(&directly_mappable_cdev_bdi)->bdi_stat[0...3])->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&(&directly_mappable_cdev_bdi)->bdi_stat[0...3])->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&(&directly_mappable_cdev_bdi)->bdi_stat[0...3])->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&(&directly_mappable_cdev_bdi)->bdi_stat[0...3])->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(&directly_mappable_cdev_bdi)->bdi_stat[0...3])->list)->next: &(&(&directly_mappable_cdev_bdi)->bdi_stat[0...3])->list
	// (&(&(&directly_mappable_cdev_bdi)->bdi_stat[0...3])->list)->prev: &(&(&directly_mappable_cdev_bdi)->bdi_stat[0...3])->list
	// (&(&directly_mappable_cdev_bdi)->bdi_stat[0...3])->count: 0
	// (&(&directly_mappable_cdev_bdi)->bdi_stat[0...3])->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&(&directly_mappable_cdev_bdi)->bdi_stat[0...3])->list를 연결함
	//
	// (&directly_mappable_cdev_bdi)->dirty_exceeded: 0
	// (&directly_mappable_cdev_bdi)->bw_time_stamp: XXX
	// (&directly_mappable_cdev_bdi)->written_stamp: 0
	// (&directly_mappable_cdev_bdi)->balanced_dirty_ratelimit: 0x6400
	// (&directly_mappable_cdev_bdi)->dirty_ratelimit: 0x6400
	// (&directly_mappable_cdev_bdi)->write_bandwidth: 0x6400
	// (&directly_mappable_cdev_bdi)->avg_write_bandwidth: 0x6400
	//
	// (&(&(&(&(&(&directly_mappable_cdev_bdi)->completions)->events)->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&(&(&directly_mappable_cdev_bdi)->completions)->events)->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&(&(&directly_mappable_cdev_bdi)->completions)->events)->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&(&(&directly_mappable_cdev_bdi)->completions)->events)->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(&(&directly_mappable_cdev_bdi)->completions)->events)->list)->next: &(&(&(&directly_mappable_cdev_bdi)->completions)->events)->list
	// (&(&(&(&directly_mappable_cdev_bdi)->completions)->events)->list)->prev: &(&(&(&directly_mappable_cdev_bdi)->completions)->events)->list
	// (&(&(&directly_mappable_cdev_bdi)->completions)->events)->count: 0
	// (&(&(&directly_mappable_cdev_bdi)->completions)->events)->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&(&(&directly_mappable_cdev_bdi)->completions)->events)->list를 연결함
	// (&(&directly_mappable_cdev_bdi)->completions)->period: 0
	// &(&(&directly_mappable_cdev_bdi)->completions)->lock을 이용한 spinlock 초기화 수행
}
