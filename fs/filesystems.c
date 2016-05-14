/*
 *  linux/fs/filesystems.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  table of configured filesystems
 */

#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

/*
 * Handling of filesystem drivers list.
 * Rules:
 *	Inclusion to/removals from/scanning of list are protected by spinlock.
 *	During the unload module must call unregister_filesystem().
 *	We can access the fields of list element if:
 *		1) spinlock is held or
 *		2) we hold the reference to the module.
 *	The latter can be guaranteed by call of try_module_get(); if it
 *	returned 0 we must skip the element, otherwise we got the reference.
 *	Once the reference is obtained we can drop the spinlock.
 */

// ARM10C 20151031
// ARM10C 20160123
// ARM10C 20160402
static struct file_system_type *file_systems;
// ARM10C 20151031
// ARM10C 20160123
// ARM10C 20160326
// DEFINE_RWLOCK(file_systems_lock):
// rwlock_t file_systems_lock =
// (rwlock_t)
// {
//      .raw_lock = { 0 },
//      .magic = 0xdeaf1eed,
//      .owner = 0xffffffff,
//      .owner_cpu = -1,
// }
static DEFINE_RWLOCK(file_systems_lock);

/* WARNING: This can be used only if we _already_ own a reference */
// ARM10C 20151114
// type: &sysfs_fs_type
// ARM10C 20160319
// [re] type: &shmem_fs_type
// ARM10C 20160416
// [re] type: &rootfs_fs_type
void get_filesystem(struct file_system_type *fs)
{
	// fs->owner: (&sysfs_fs_type)->owner
	// fs->owner: (&shmem_fs_type)->owner
	// fs->owner: (&rootfs_fs_type)->owner
	__module_get(fs->owner);
}

// ARM10C 20160514
// type: &rootfs_fs_type
void put_filesystem(struct file_system_type *fs)
{
	// fs->owner: (&rootfs_fs_type)->owner: NULL
	module_put(fs->owner);
}

// ARM10C 20151031
// [1st] fs->name: (&sysfs_fs_type)->name: "sysfs", strlen("sysfs"): 5
// ARM10C 20160123
// [2nd] fs->name: (&rootfs_fs_type)->name: "rootfs", strlen("rootfs"): 6
// ARM10C 20160123
// [3rd] fs->name: (&shmem_fs_type)->name: "tmpfs", strlen("tmpfs"): 5
// ARM10C 20160402
// [4th] name: "rootfs", len: 6
static struct file_system_type **find_filesystem(const char *name, unsigned len)
{
	struct file_system_type **p;

	// [1st][f1] p: &file_systems, *p: file_systems: NULL
	// [2nd][f1] p: &file_systems, *p: file_systems: &sysfs_fs_type
	// [3rd][f1] p: &file_systems, *p: file_systems: &sysfs_fs_type
	for (p=&file_systems; *p; p=&(*p)->next)
		// [2nd][f2] p: &(&sysfs_fs_type)->next, *p: (&sysfs_fs_type)->next: NULL
		// [3nd][f2] p: &(&sysfs_fs_type)->next, *p: (&sysfs_fs_type)->next: &rootfs_fs_type
		// [3nd][f2] p: &(&rootfs_fs_type)->next, *p: (&rootfs_fs_type)->next: NULL

		// [2nd][f1] (*p)->name: (&sysfs_fs_type)->name: "sysfs",
		// [2nd][f1] strlen("sysfs"): 5, len: 6, name: "rootfs", strncmp("sysfs", "rootfs", 6): 1
		// [3rd][f1] (*p)->name: (&sysfs_fs_type)->name: "sysfs",
		// [3rd][f1] strlen("sysfs"): 5, len: 5, name: "rootfs", strncmp("sysfs", "rootfs", 5): 1
		//
		// [3rd][f2] (*p)->name: (&rootfs_fs_type)->name: "rootfs",
		// [3rd][f2] strlen("rootfs"): 6, len: 5, name: "tmpfs", strncmp("rootfs", "tmpfs", 5): -1
		if (strlen((*p)->name) == len &&
		    strncmp((*p)->name, name, len) == 0)
			break;

		// [2nd][f1] &(*p)->next: &(&sysfs_fs_type)->next
		// [3nd][f1] &(*p)->next: &(&sysfs_fs_type)->next
		// [3nd][f2] &(*p)->next: &(&rootfs_fs_type)->next
	
	// file_systems 의 list 연결 상태
	// sysfs_fs_type: "sysfs"  -> rootfs_fs_type: "rootfs" -> shmem_fs_type: "tmpfs"

	// [1st] p: &file_systems
	// [2nd] p: &(&sysfs_fs_type)->next
	// [3rd] p: &(&rootfs_fs_type)->next
	return p;
	// [1st] return &file_systems
	// [2nd] return &(&sysfs_fs_type)->next
	// [3rd] return &(&rootfs_fs_type)->next
}

/**
 *	register_filesystem - register a new filesystem
 *	@fs: the file system structure
 *
 *	Adds the file system passed to the list of file systems the kernel
 *	is aware of for mount and other syscalls. Returns 0 on success,
 *	or a negative errno code on an error.
 *
 *	The &struct file_system_type that is passed is linked into the kernel 
 *	structures and must not be freed until the file system has been
 *	unregistered.
 */
 
// ARM10C 20151031
// &sysfs_fs_type
// ARM10C 20160123
// &rootfs_fs_type
// ARM10C 20160123
// &shmem_fs_type
int register_filesystem(struct file_system_type * fs)
{
	int res = 0;
	// res: 0
	// res: 0
	// res: 0

	struct file_system_type ** p;

	// fs->name: (&sysfs_fs_type)->name: "sysfs", strchr("sysfs", '.'): NULL
	// fs->name: (&rootfs_fs_type)->name: "rootfs", strchr("rootfs", '.'): NULL
	// fs->name: (&shmem_fs_type)->name: "tmpfs", strchr("tmpfs", '.'): NULL
	BUG_ON(strchr(fs->name, '.'));

	// fs->next: (&sysfs_fs_type)->next: NULL
	// fs->next: (&rootfs_fs_type)->next: NULL
	// fs->next: (&shmem_fs_type)->next: NULL
	if (fs->next)
		return -EBUSY;

	write_lock(&file_systems_lock);

	// write_lock에서 한일:
	// &file_systems_lock 을 사용한 write lock 수행

	// write_lock에서 한일:
	// &file_systems_lock 을 사용한 write lock 수행

	// write_lock에서 한일:
	// &file_systems_lock 을 사용한 write lock 수행

	// fs->name: (&sysfs_fs_type)->name: "sysfs", strlen("sysfs"): 5
	// find_filesystem("sysfs", 5): &file_systems
	// fs->name: (&rootfs_fs_type)->name: "rootfs", strlen("rootfs"): 6
	// find_filesystem("rootfs", 6): &(&sysfs_fs_type)->next
	// fs->name: (&shmem_fs_type)->name: "tmpfs", strlen("tmpfs"): 5
	// find_filesystem("tmpfs", 5): &(&rootfs_fs_type)->next
	p = find_filesystem(fs->name, strlen(fs->name));
	// p: &file_systems
	// p: &(&sysfs_fs_type)->next
	// p: &(&rootfs_fs_type)->next

	// *p: file_systems: NULL
	// *p: (&sysfs_fs_type)->next: NULL
	// *p: (&rootfs_fs_type)->next: NULL
	if (*p)
		res = -EBUSY;
	else
		// *p: file_systems: NULL, fs: &sysfs_fs_type
		// *p: (&sysfs_fs_type)->next: NULL, fs: &rootfs_fs_type
		// *p: (&rootfs_fs_type)->next: NULL, fs: &shmem_fs_type
		*p = fs;
		// *p: file_systems: &sysfs_fs_type
		// *p: (&sysfs_fs_type)->next: &rootfs_fs_type
		// *p: (&rootfs_fs_type)->next: &shmem_fs_type

	write_unlock(&file_systems_lock);

	// write_unlock에서 한일:
	// &file_systems_lock 을 사용한 write lock 수행

	// write_unlock에서 한일:
	// &file_systems_lock 을 사용한 write lock 수행

	// write_unlock에서 한일:
	// &file_systems_lock 을 사용한 write lock 수행

	// res: 0
	// res: 0
	// res: 0
	return res;
	// return 0
	// return 0
	// return 0
}

EXPORT_SYMBOL(register_filesystem);

/**
 *	unregister_filesystem - unregister a file system
 *	@fs: filesystem to unregister
 *
 *	Remove a file system that was previously successfully registered
 *	with the kernel. An error is returned if the file system is not found.
 *	Zero is returned on a success.
 *	
 *	Once this function has returned the &struct file_system_type structure
 *	may be freed or reused.
 */
 
int unregister_filesystem(struct file_system_type * fs)
{
	struct file_system_type ** tmp;

	write_lock(&file_systems_lock);
	tmp = &file_systems;
	while (*tmp) {
		if (fs == *tmp) {
			*tmp = fs->next;
			fs->next = NULL;
			write_unlock(&file_systems_lock);
			synchronize_rcu();
			return 0;
		}
		tmp = &(*tmp)->next;
	}
	write_unlock(&file_systems_lock);

	return -EINVAL;
}

EXPORT_SYMBOL(unregister_filesystem);

static int fs_index(const char __user * __name)
{
	struct file_system_type * tmp;
	struct filename *name;
	int err, index;

	name = getname(__name);
	err = PTR_ERR(name);
	if (IS_ERR(name))
		return err;

	err = -EINVAL;
	read_lock(&file_systems_lock);
	for (tmp=file_systems, index=0 ; tmp ; tmp=tmp->next, index++) {
		if (strcmp(tmp->name, name->name) == 0) {
			err = index;
			break;
		}
	}
	read_unlock(&file_systems_lock);
	putname(name);
	return err;
}

static int fs_name(unsigned int index, char __user * buf)
{
	struct file_system_type * tmp;
	int len, res;

	read_lock(&file_systems_lock);
	for (tmp = file_systems; tmp; tmp = tmp->next, index--)
		if (index <= 0 && try_module_get(tmp->owner))
			break;
	read_unlock(&file_systems_lock);
	if (!tmp)
		return -EINVAL;

	/* OK, we got the reference, so we can safely block */
	len = strlen(tmp->name) + 1;
	res = copy_to_user(buf, tmp->name, len) ? -EFAULT : 0;
	put_filesystem(tmp);
	return res;
}

static int fs_maxindex(void)
{
	struct file_system_type * tmp;
	int index;

	read_lock(&file_systems_lock);
	for (tmp = file_systems, index = 0 ; tmp ; tmp = tmp->next, index++)
		;
	read_unlock(&file_systems_lock);
	return index;
}

/*
 * Whee.. Weird sysv syscall. 
 */
SYSCALL_DEFINE3(sysfs, int, option, unsigned long, arg1, unsigned long, arg2)
{
	int retval = -EINVAL;

	switch (option) {
		case 1:
			retval = fs_index((const char __user *) arg1);
			break;

		case 2:
			retval = fs_name(arg1, (char __user *) arg2);
			break;

		case 3:
			retval = fs_maxindex();
			break;
	}
	return retval;
}

int __init get_filesystem_list(char *buf)
{
	int len = 0;
	struct file_system_type * tmp;

	read_lock(&file_systems_lock);
	tmp = file_systems;
	while (tmp && len < PAGE_SIZE - 80) {
		len += sprintf(buf+len, "%s\t%s\n",
			(tmp->fs_flags & FS_REQUIRES_DEV) ? "" : "nodev",
			tmp->name);
		tmp = tmp->next;
	}
	read_unlock(&file_systems_lock);
	return len;
}

#ifdef CONFIG_PROC_FS
static int filesystems_proc_show(struct seq_file *m, void *v)
{
	struct file_system_type * tmp;

	read_lock(&file_systems_lock);
	tmp = file_systems;
	while (tmp) {
		seq_printf(m, "%s\t%s\n",
			(tmp->fs_flags & FS_REQUIRES_DEV) ? "" : "nodev",
			tmp->name);
		tmp = tmp->next;
	}
	read_unlock(&file_systems_lock);
	return 0;
}

static int filesystems_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, filesystems_proc_show, NULL);
}

static const struct file_operations filesystems_proc_fops = {
	.open		= filesystems_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_filesystems_init(void)
{
	proc_create("filesystems", 0, NULL, &filesystems_proc_fops);
	return 0;
}
module_init(proc_filesystems_init);
#endif

// ARM10C 20160326
// name: "rootfs", len: 6
static struct file_system_type *__get_fs_type(const char *name, int len)
{
	struct file_system_type *fs;

	read_lock(&file_systems_lock);

	// read_lock에서 한일:
	// &(&(&file_systems_lock)->raw_lock)->lock 의 값을 미리 cache에 가져옴
	// &(&(&file_systems_lock)->raw_lock)->lock 의 값을 1을 더해줌
	// 공유자원을 다른 cpu core가 사용할수 있게 해주는 옵션

	// name: "rootfs", len: 6
	// find_filesystem("rootfs", 6): &&rootfs_fs_type
	fs = *(find_filesystem(name, len));
	// fs: &rootfs_fs_type

	// find_filesystem 에서 한일:
	// "rootfs" 이름을 가지고 file_systems 의 list로 연결된 file_system_type 값을 찾음

	// fs: &rootfs_fs_type, fs->owner: (&rootfs_fs_type)->owner,
	// try_module_get((&rootfs_fs_type)->owner): true
	if (fs && !try_module_get(fs->owner))
		fs = NULL;

	read_unlock(&file_systems_lock);

	//  read_unlock 에서 한일:
	// &(&(&file_systems_lock)->raw_lock)->lock 의 값을 미리 cache에 가져옴
	// &(&(&file_systems_lock)->raw_lock)->lock 의 값을 1 만큼 값을 감소 시킴
	// Inner Shareable domain에 포함되어 있는 core 들의 instruction이 완료 될때 까지 기다리 겠다는 뜻.
	// 다중 프로세서 시스템 내의 모든 코어에 신호를 보낼 이벤트를 발생시킴
	// current_thread_info()->preempt_count: 0x40000001

	// fs: &rootfs_fs_type
	return fs;
	// return &rootfs_fs_type
}

// ARM10C 20160326
// "rootfs"
struct file_system_type *get_fs_type(const char *name)
{
	struct file_system_type *fs;

	// name: "rootfs", strchr("rootfs". '.'): NULL
	const char *dot = strchr(name, '.');
	// dot: NULL

	// dot: NULL, name: "rootfs", strlen("rootfs"): 6
	int len = dot ? dot - name : strlen(name);
	// len: 6

	// name: "rootfs", len: 6, __get_fs_type("rootfs", 6): NULL
	fs = __get_fs_type(name, len);
	// fs: &rootfs_fs_type
 
	// __get_fs_type 에서 한일:
	// fs: &rootfs_fs_type

	// fs: &rootfs_fs_type, len: 6, name: "rootfs", request_module("fs-%.*s", 6, "rootfs"): -16
	if (!fs && (request_module("fs-%.*s", len, name) == 0))
		fs = __get_fs_type(name, len);

	// request_module 에서 한일: (불리지 않음)
	// struct subprocess_info 만큼의 메모리를 할당받음 kmem_cache#30-oX (struct subprocess_info)
	// (&(kmem_cache#30-oX (struct subprocess_info))->work)->data: { 0xFFFFFFE0 }
	// (&(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry)->next: &(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry
	// (&(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry)->prev: &(&(kmem_cache#30-oX (struct subprocess_info))->work)->entry
	// (&(kmem_cache#30-oX (struct subprocess_info))->work)->func: __call_usermodehelper
	// (kmem_cache#30-oX (struct subprocess_info))->path: "/sbin/modprobe"
	// (kmem_cache#30-oX (struct subprocess_info))->argv: kmem_cache#30-oX
	// (kmem_cache#30-oX (struct subprocess_info))->envp: envp
	// (kmem_cache#30-oX (struct subprocess_info))->cleanup: NULL
	// (kmem_cache#30-oX (struct subprocess_info))->init: free_modprobe_argv
	// (kmem_cache#30-oX (struct subprocess_info))->data: NULL
	//
	// struct subprocess_info 만큼 할당 받은 메모리를 반환함
	// &running_helpers_waitq의 tasklist에 등록된 task가 없어서 수행한 일이 없음

	// dot: NULL, fs: &rootfs_fs_type, fs->fs_flags: (&rootfs_fs_type)->fs_flags: 0
	if (dot && fs && !(fs->fs_flags & FS_HAS_SUBTYPE)) {
		put_filesystem(fs);
		fs = NULL;
	}

	// fs: &rootfs_fs_type
	return fs;
	// return &rootfs_fs_type
}

EXPORT_SYMBOL(get_fs_type);
