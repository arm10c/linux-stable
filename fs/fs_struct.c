#include <linux/export.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>
#include "internal.h"

/*
 * Replace the fs->{rootmnt,root} with {mnt,dentry}. Put the old values.
 * It can block.
 */
// ARM10C 20160521
// current->fs: (&init_task)->fs, &root
void set_fs_root(struct fs_struct *fs, const struct path *path)
{
	struct path old_root;

	// path: &root
	path_get(path);

	// path_get에서 한일:
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count 을 1만큼 증가 시킴
	// (&(kmem_cache#5-oX (struct dentry))->d_lockref)->count: 1 만큼 증가 시킴

	// &fs->lock: &((&init_task)->fs)->lock
	spin_lock(&fs->lock);

	// spin_lock 에서 한일:
	// &((&init_task)->fs)->lock 을 사용하여 spin lock 을 수행

	// &fs->seq: &((&init_task)->fs)->seq
	write_seqcount_begin(&fs->seq);

	// write_seqcount_begin에서 한일:
	// (&((&init_task)->fs)->seq)->sequence: 1
	// 공유자원을 다른 cpu core가 사용할수 있게 메모리 적용

	// fs->root: ((&init_task)->fs)->root: (&init_fs)->root: 맴버가 0 으로 초기화된 값
	old_root = fs->root;
	// old_root: 맴버가 0 으로 초기화된 값

	// root.mnt: &(kmem_cache#2-oX (struct mount))->mnt
	// root.dentry: kmem_cache#5-oX (struct dentry)

	// fs->root: ((&init_task)->fs)->root: (&init_fs)->root: 맴버가 0 으로 초기화된 값, *path: root
	fs->root = *path;
	// fs->root: ((&init_task)->fs)->root.mnt: &(kmem_cache#2-oX (struct mount))->mnt
	// fs->root: ((&init_task)->fs)->root.dentry: kmem_cache#5-oX (struct dentry)

	// &fs->seq: &((&init_task)->fs)->seq
	write_seqcount_end(&fs->seq);

	// write_seqcount_end에서 한일:
	// 공유자원을 다른 cpu core가 사용할수 있게 메모리 적용
	// (&((&init_task)->fs)->seq)->sequence: 2

	// &fs->lock: &((&init_task)->fs)->lock
	spin_unlock(&fs->lock);

	// spin_unlock 에서 한일:
	// &((&init_task)->fs)->lock 을 사용하여 spin unlock 을 수행

	// old_root.dentry: NULL
	if (old_root.dentry)
		path_put(&old_root);
}

/*
 * Replace the fs->{pwdmnt,pwd} with {mnt,dentry}. Put the old values.
 * It can block.
 */
// ARM10C 20160521
// current->fs: (&init_task)->fs, &root
void set_fs_pwd(struct fs_struct *fs, const struct path *path)
{
	struct path old_pwd;

	// path: &root
	path_get(path);

	// path_get에서 한일:
	// [pcp0] (kmem_cache#2-oX (struct mount))->mnt_pcp->mnt_count 을 1만큼 증가 시킴
	// (&(kmem_cache#5-oX (struct dentry))->d_lockref)->count: 1 만큼 증가 시킴

	// &fs->lock: &((&init_task)->fs)->lock
	spin_lock(&fs->lock);

	// spin_lock 에서 한일:
	// &((&init_task)->fs)->lock 을 사용하여 spin lock 을 수행

	// &fs->seq: &((&init_task)->fs)->seq
	write_seqcount_begin(&fs->seq);

	// write_seqcount_begin에서 한일:
	// (&((&init_task)->fs)->seq)->sequence: 1
	// 공유자원을 다른 cpu core가 사용할수 있게 메모리 적용

	// fs->pwd: ((&init_task)->fs)->pwd: (&init_fs)->pwd: 맴버가 0 으로 초기화된 값
	old_pwd = fs->pwd;
	// old_pwd: 맴버가 0 으로 초기화된 값

	// root.mnt: &(kmem_cache#2-oX (struct mount))->mnt
	// root.dentry: kmem_cache#5-oX (struct dentry)

	// fs->pwd: ((&init_task)->fs)->pwd: (&init_fs)->pwd: 맴버가 0 으로 초기화된 값, *path: root
	fs->pwd = *path;
	// fs->pwd: ((&init_task)->fs)->pwd.mnt: &(kmem_cache#2-oX (struct mount))->mnt
	// fs->pwd: ((&init_task)->fs)->pwd.dentry: kmem_cache#5-oX (struct dentry)

	// &fs->seq: &((&init_task)->fs)->seq
	write_seqcount_end(&fs->seq);

	// write_seqcount_end에서 한일:
	// 공유자원을 다른 cpu core가 사용할수 있게 메모리 적용
	// (&((&init_task)->fs)->seq)->sequence: 2

	// &fs->lock: &((&init_task)->fs)->lock
	spin_unlock(&fs->lock);

	// spin_unlock 에서 한일:
	// &((&init_task)->fs)->lock 을 사용하여 spin unlock 을 수행

	// old_pwd.dentry: NULL
	if (old_pwd.dentry)
		path_put(&old_pwd);
}

static inline int replace_path(struct path *p, const struct path *old, const struct path *new)
{
	if (likely(p->dentry != old->dentry || p->mnt != old->mnt))
		return 0;
	*p = *new;
	return 1;
}

void chroot_fs_refs(const struct path *old_root, const struct path *new_root)
{
	struct task_struct *g, *p;
	struct fs_struct *fs;
	int count = 0;

	read_lock(&tasklist_lock);
	do_each_thread(g, p) {
		task_lock(p);
		fs = p->fs;
		if (fs) {
			int hits = 0;
			spin_lock(&fs->lock);
			write_seqcount_begin(&fs->seq);
			hits += replace_path(&fs->root, old_root, new_root);
			hits += replace_path(&fs->pwd, old_root, new_root);
			write_seqcount_end(&fs->seq);
			while (hits--) {
				count++;
				path_get(new_root);
			}
			spin_unlock(&fs->lock);
		}
		task_unlock(p);
	} while_each_thread(g, p);
	read_unlock(&tasklist_lock);
	while (count--)
		path_put(old_root);
}

void free_fs_struct(struct fs_struct *fs)
{
	path_put(&fs->root);
	path_put(&fs->pwd);
	kmem_cache_free(fs_cachep, fs);
}

void exit_fs(struct task_struct *tsk)
{
	struct fs_struct *fs = tsk->fs;

	if (fs) {
		int kill;
		task_lock(tsk);
		spin_lock(&fs->lock);
		tsk->fs = NULL;
		kill = !--fs->users;
		spin_unlock(&fs->lock);
		task_unlock(tsk);
		if (kill)
			free_fs_struct(fs);
	}
}

struct fs_struct *copy_fs_struct(struct fs_struct *old)
{
	struct fs_struct *fs = kmem_cache_alloc(fs_cachep, GFP_KERNEL);
	/* We don't need to lock fs - think why ;-) */
	if (fs) {
		fs->users = 1;
		fs->in_exec = 0;
		spin_lock_init(&fs->lock);
		seqcount_init(&fs->seq);
		fs->umask = old->umask;

		spin_lock(&old->lock);
		fs->root = old->root;
		path_get(&fs->root);
		fs->pwd = old->pwd;
		path_get(&fs->pwd);
		spin_unlock(&old->lock);
	}
	return fs;
}

int unshare_fs_struct(void)
{
	struct fs_struct *fs = current->fs;
	struct fs_struct *new_fs = copy_fs_struct(fs);
	int kill;

	if (!new_fs)
		return -ENOMEM;

	task_lock(current);
	spin_lock(&fs->lock);
	kill = !--fs->users;
	current->fs = new_fs;
	spin_unlock(&fs->lock);
	task_unlock(current);

	if (kill)
		free_fs_struct(fs);

	return 0;
}
EXPORT_SYMBOL_GPL(unshare_fs_struct);

int current_umask(void)
{
	return current->fs->umask;
}
EXPORT_SYMBOL(current_umask);

/* to be mentioned only in INIT_TASK */
// ARM10C 20150808
// ARM10C 20160521
struct fs_struct init_fs = {
	.users		= 1,
	.lock		= __SPIN_LOCK_UNLOCKED(init_fs.lock),
	.seq		= SEQCNT_ZERO(init_fs.seq),
	.umask		= 0022,
};
