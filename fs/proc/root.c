/*
 *  linux/fs/proc/root.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  proc root directory handling functions
 */

#include <asm/uaccess.h>

#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/user_namespace.h>
#include <linux/mount.h>
#include <linux/pid_namespace.h>
#include <linux/parser.h>

#include "internal.h"

static int proc_test_super(struct super_block *sb, void *data)
{
	return sb->s_fs_info == data;
}

static int proc_set_super(struct super_block *sb, void *data)
{
	int err = set_anon_super(sb, NULL);
	if (!err) {
		struct pid_namespace *ns = (struct pid_namespace *)data;
		sb->s_fs_info = get_pid_ns(ns);
	}
	return err;
}

enum {
	Opt_gid, Opt_hidepid, Opt_err,
};

static const match_table_t tokens = {
	{Opt_hidepid, "hidepid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_err, NULL},
};

static int proc_parse_options(char *options, struct pid_namespace *pid)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		args[0].to = args[0].from = NULL;
		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_gid:
			if (match_int(&args[0], &option))
				return 0;
			pid->pid_gid = make_kgid(current_user_ns(), option);
			break;
		case Opt_hidepid:
			if (match_int(&args[0], &option))
				return 0;
			if (option < 0 || option > 2) {
				pr_err("proc: hidepid value must be between 0 and 2.\n");
				return 0;
			}
			pid->hide_pid = option;
			break;
		default:
			pr_err("proc: unrecognized mount option \"%s\" "
			       "or missing value\n", p);
			return 0;
		}
	}

	return 1;
}

int proc_remount(struct super_block *sb, int *flags, char *data)
{
	struct pid_namespace *pid = sb->s_fs_info;
	return !proc_parse_options(data, pid);
}

static struct dentry *proc_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	int err;
	struct super_block *sb;
	struct pid_namespace *ns;
	char *options;

	if (flags & MS_KERNMOUNT) {
		ns = (struct pid_namespace *)data;
		options = NULL;
	} else {
		ns = task_active_pid_ns(current);
		options = data;

		if (!capable(CAP_SYS_ADMIN) && !fs_fully_visible(fs_type))
			return ERR_PTR(-EPERM);

		/* Does the mounter have privilege over the pid namespace? */
		if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN))
			return ERR_PTR(-EPERM);
	}

	sb = sget(fs_type, proc_test_super, proc_set_super, flags, ns);
	if (IS_ERR(sb))
		return ERR_CAST(sb);

	if (!proc_parse_options(options, ns)) {
		deactivate_locked_super(sb);
		return ERR_PTR(-EINVAL);
	}

	if (!sb->s_root) {
		err = proc_fill_super(sb);
		if (err) {
			deactivate_locked_super(sb);
			return ERR_PTR(err);
		}

		sb->s_flags |= MS_ACTIVE;
	}

	return dget(sb->s_root);
}

static void proc_kill_sb(struct super_block *sb)
{
	struct pid_namespace *ns;

	ns = (struct pid_namespace *)sb->s_fs_info;
	if (ns->proc_self)
		dput(ns->proc_self);
	kill_anon_super(sb);
	put_pid_ns(ns);
}

// ARM10C 20160604
static struct file_system_type proc_fs_type = {
	.name		= "proc",
	.mount		= proc_mount,
	.kill_sb	= proc_kill_sb,
	.fs_flags	= FS_USERNS_MOUNT,
};

// ARM10C 20160604
void __init proc_root_init(void)
{
	int err;

	proc_init_inodecache();

	// proc_init_inodecache 에서 한일:
	// struct proc_inode 크기 만큼의 메모리를 할당항는 kmem_cache 할당자를 생성함
	// proc_inode_cachep: kmem_cache#n#28 (struct proc_inode)

	// register_filesystem(&proc_fs_type): 0
	err = register_filesystem(&proc_fs_type);
	// err: 0

	// register_filesystem에서 한일:
	// (&bd_type)->next: &proc_fs_type
	//
	// file system 연결 결과
	// file_systems: sysfs_fs_type -> rootfs_fs_type -> shmem_fs_type -> bd_type -> proc_fs_type

	// err: 0
	if (err)
		return;

	proc_self_init();

	// proc_self_init 에서 한일:
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

	// proc_symlink("mounts", NULL, "self/mounts"): kmem_cache#29-oX (struct proc_dir_entry)
	proc_symlink("mounts", NULL, "self/mounts");

	// proc_symlink 에서 한일:
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "mounts"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 6
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0120777
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 1
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->data: kmem_cache#30-oX: "self/mounts"
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&proc_inum_ida)->idr)->id_free 이 idr object new 2번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 2         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&proc_inum_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 2)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 8
	//
	// (&(&proc_inum_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&proc_inum_ida)->idr)->layers: 1
	// (&(&proc_inum_ida)->idr)->id_free: (idr object new 0)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 3
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 2) 의 memory 공간을 반환함
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->low_ino: 0xF0000002
	// (kmem_cache#29-oX (struct proc_dir_entry))->proc_iops: &proc_link_inode_operations
	// (kmem_cache#29-oX (struct proc_dir_entry))->next: NULL
	// (kmem_cache#29-oX (struct proc_dir_entry))->parent: &proc_root
	//
	// (&proc_root)->subdir: kmem_cache#29-oX (struct proc_dir_entry)

	// proc_net_init(): 0
	proc_net_init();

	// proc_net_init 에서 한일:
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "net"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 3
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0120777
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 1
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->data: kmem_cache#30-oX: "self/net"
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&proc_inum_ida)->idr)->id_free 이 idr object new 3번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 3         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&proc_inum_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 3)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 8
	//
	// (&(&proc_inum_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&proc_inum_ida)->idr)->layers: 1
	// (&(&proc_inum_ida)->idr)->id_free: (idr object new 0)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 3 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 4
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 3) 의 memory 공간을 반환함
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->low_ino: 0xF0000003
	// (kmem_cache#29-oX (struct proc_dir_entry))->proc_iops: &proc_link_inode_operations
	// (kmem_cache#29-oX (struct proc_dir_entry))->next: NULL
	// (kmem_cache#29-oX (struct proc_dir_entry))->parent: &proc_root
	//
	// (&proc_root)->subdir: kmem_cache#29-oX (struct proc_dir_entry)
	//
	// list head 인 &pernet_list 에 &(&proc_net_ns_ops)->list 을 tail로 추가함

#ifdef CONFIG_SYSVIPC // CONFIG_SYSVIPC=y
	// proc_mkdir("sysvipc", NULL): kmem_cache#29-oX (struct proc_dir_entry)
	proc_mkdir("sysvipc", NULL);

	// proc_mkdir 에서 한일:
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "sysvipc"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 7
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0040555
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 2
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root
#endif
	// proc_mkdir("fs", NULL): kmem_cache#29-oX (struct proc_dir_entry)
	proc_mkdir("fs", NULL);

	// proc_mkdir 에서 한일:
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "fs"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 2
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0040555
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 2
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root

	// proc_mkdir("driver", NULL): kmem_cache#29-oX (struct proc_dir_entry)
	proc_mkdir("driver", NULL);

	// proc_mkdir 에서 한일:
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "driver"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 6
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0040555
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 2
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root

	// proc_mkdir("fs/nfsd", NULL): kmem_cache#29-oX (struct proc_dir_entry)
	proc_mkdir("fs/nfsd", NULL); /* somewhere for the nfsd filesystem to be mounted */

	// proc_mkdir 에서 한일:
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "fs/nfsd"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 7
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0040555
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 2
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root

#if defined(CONFIG_SUN_OPENPROMFS) || defined(CONFIG_SUN_OPENPROMFS_MODULE) // CONFIG_SUN_OPENPROMFS=n, CONFIG_SUN_OPENPROMFS_MODULE=n
	/* just give it a mountpoint */
	proc_mkdir("openprom", NULL);
#endif
	proc_tty_init();

	// proc_tty_init 에서 한일:
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "tty"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 3
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0040555
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 2
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root
	//
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "tty/ldisc"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 9
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0040555
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 2
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root
	//
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "tty/driver"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 10
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 00500
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 2
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root
	//
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "tty/ldiscs"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 10
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0100444
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 1
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->proc_fops: &tty_ldiscs_proc_fops
	// (kmem_cache#29-oX (struct proc_dir_entry))->data: NULL
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&proc_inum_ida)->idr)->id_free 이 idr object new 4번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 4         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&proc_inum_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 4)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 8
	//
	// (&(&proc_inum_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&proc_inum_ida)->idr)->layers: 1
	// (&(&proc_inum_ida)->idr)->id_free: (idr object new 0)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 4 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 5
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 4) 의 memory 공간을 반환함
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->low_ino: 0xF0000004
	// (kmem_cache#29-oX (struct proc_dir_entry))->proc_iops: &proc_file_inode_operations
	// (kmem_cache#29-oX (struct proc_dir_entry))->next: NULL
	// (kmem_cache#29-oX (struct proc_dir_entry))->parent: &proc_root
	//
	// (&proc_root)->subdir: kmem_cache#29-oX (struct proc_dir_entry)
	//
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "tty/drivers"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 11
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0100444
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 1
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->proc_fops: &proc_tty_drivers_operations
	// (kmem_cache#29-oX (struct proc_dir_entry))->data: NULL
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&proc_inum_ida)->idr)->id_free 이 idr object new 5번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 5         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&proc_inum_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 5)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 8
	//
	// (&(&proc_inum_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&proc_inum_ida)->idr)->layers: 1
	// (&(&proc_inum_ida)->idr)->id_free: (idr object new 0)
	// (&(&proc_inum_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 5 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 6
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 5) 의 memory 공간을 반환함
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->low_ino: 0xF0000005
	// (kmem_cache#29-oX (struct proc_dir_entry))->proc_iops: &proc_file_inode_operations
	// (kmem_cache#29-oX (struct proc_dir_entry))->next: NULL
	// (kmem_cache#29-oX (struct proc_dir_entry))->parent: &proc_root
	//
	// (&proc_root)->subdir: kmem_cache#29-oX (struct proc_dir_entry)

#ifdef CONFIG_PROC_DEVICETREE // CONFIG_PROC_DEVICETREE=y
	proc_device_tree_init();

	// proc_device_tree_init 에서 한일:
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "device-tree"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 11
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0040555
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 2
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root
	//
	// unflatten_device_tree 에서 만든 tree의 root node 의 값을 사용하여proc device tree를 만드는 작업을 수행
#endif
	proc_mkdir("bus", NULL);

	// proc_mkdir 에서 한일:
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "bus"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 3
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0040555
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 2
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root

	// proc_sys_init(): 0
	proc_sys_init();

	// proc_sys_init 에서 한일:
	// struct proc_dir_entry 만큼 메모리를 할당 받음 kmem_cache#29-oX (struct proc_dir_entry)
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->name: "sys"
	// (kmem_cache#29-oX (struct proc_dir_entry))->namelen: 3
	// (kmem_cache#29-oX (struct proc_dir_entry))->mode: 0040555
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 2
	// (&(kmem_cache#29-oX (struct proc_dir_entry))->count)->counter: 1
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#29-oX (struct proc_dir_entry))->pde_unload_lock)->rlock)->owner_cpu: 0xffffffff
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->next: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	// &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list->prev: &(kmem_cache#29-oX (struct proc_dir_entry))->pde_openers->i_sb_list
	//
	// parent: &proc_root
	//
	// (kmem_cache#29-oX (struct proc_dir_entry))->proc_iops: &proc_sys_dir_operations
	// (kmem_cache#29-oX (struct proc_dir_entry))->proc_fops: &proc_sys_dir_file_operations
	// (kmem_cache#29-oX (struct proc_dir_entry))->nlink: 0
	//
	// struct ctl_table_header 의 메모리 +  struct ctl_table_header 의 포인터 메모리 * 2 를 할당 받음 kmem_cache#27-oX
	//
	// struct ctl_table_header 의 메모리 + struct ctl_node 의 메모리 46 개를 할당 받음 kmem_cache#25-oX
	//
	// (kmem_cache#25-oX)->ctl_table: kmem_cache#24-oX
	// (kmem_cache#25-oX)->ctl_table_arg: kmem_cache#24-oX
	// (kmem_cache#25-oX)->used: 0
	// (kmem_cache#25-oX)->count: 1
	// (kmem_cache#25-oX)->nreg: 1
	// (kmem_cache#25-oX)->unregistering: NULL
	// (kmem_cache#25-oX)->root: &sysctl_table_root
	// (kmem_cache#25-oX)->set: &sysctl_table_root.default_set
	// (kmem_cache#25-oX)->parent: NULL
	// (kmem_cache#25-oX)->node: &(kmem_cache#25-oX)[1] (struct ctl_node)
	// (&(kmem_cache#25-oX)[1...46] (struct ctl_node))->header: kmem_cache#25-oX
	//
	// (&(&sysctl_table_root.default_set)->dir)->header.nreg: 2
	//
	// struct ctl_dir: 36, struct ctl_node: 16, struct ctl_table: 34 * 2, char: 7
	// 만큼의 메모리 kmem_cache#29-oX 를 할당 받음
	//
	// (kmem_cache#29-oX + 120): "kernel"
	// ((kmem_cache#29-oX + 52)[0] (struct ctl_table)).procname: (kmem_cache#29-oX + 120): "kernel"
	// ((kmem_cache#29-oX + 52)[0] (struct ctl_table)).mode: 0040555
	// (&(kmem_cache#29-oX)->header)->ctl_table: (kmem_cache#29-oX + 52) (struct ctl_table)
	// (&(kmem_cache#29-oX)->header)->ctl_table_arg: (kmem_cache#29-oX + 52) (struct ctl_table)
	// (&(kmem_cache#29-oX)->header)->used: 0
	// (&(kmem_cache#29-oX)->header)->count: 1
	// (&(kmem_cache#29-oX)->header)->nreg: 1
	// (&(kmem_cache#29-oX)->header)->unregistering: NULL
	// (&(kmem_cache#29-oX)->header)->root: (&sysctl_table_root.default_set)->dir.header.root
	// (&(kmem_cache#29-oX)->header)->set: &sysctl_table_root.default_set
	// (&(kmem_cache#29-oX)->header)->parent: NULL
	// (&(kmem_cache#29-oX)->header)->node: (kmem_cache#29-oX + 36) (struct ctl_node)
	// ((kmem_cache#29-oX + 36) (struct ctl_node))->header: &(kmem_cache#29-oX)->header
	//
	// (&(&sysctl_table_root.default_set)->dir)->header.nreg: 3
	// (&(kmem_cache#29-oX)->header)->parent: &(&sysctl_table_root.default_set)->dir
	//
	// (&((kmem_cache#29-oX + 36) (struct ctl_node)).node).__rb_parent_color: NULL
	// (&((kmem_cache#29-oX + 36) (struct ctl_node)).node)->rb_left: NULL
	// (&((kmem_cache#29-oX + 36) (struct ctl_node)).node)->rb_right: NULL
	// (&(&sysctl_table_root.default_set)->dir)->root.rb_node: &((kmem_cache#29-oX + 36) (struct ctl_node)).node
	//
	// RB Tree &((kmem_cache#29-oX + 36) (struct ctl_node)).node 을 black node 로 추가
	/*
	//                          proc-b
	//                         (kernel)
	*/
	// (&(&(&sysctl_table_root.default_set)->dir)->header)->nreg: 2
	// (&(kmem_cache#29-oX)->header)->nreg: 1
	//
	// (kmem_cache#29-oX)->header.nreg: 2
	// (kmem_cache#25-oX)->parent: kmem_cache#29-oX
	//
	// (&(&(kmem_cache#25-oX)[1] (struct ctl_node)).node).__rb_parent_color: NULL
	// (&(&(kmem_cache#25-oX)[1] (struct ctl_node)).node)->rb_left: NULL
	// (&(&(kmem_cache#25-oX)[1] (struct ctl_node)).node)->rb_right: NULL
	// &(kmem_cache#29-oX)->root.rb_node: &(&(kmem_cache#25-oX)[1] (struct ctl_node)).node
	// (&(&(kmem_cache#25-oX)[1] (struct ctl_node) + 1).node).__rb_parent_color: &(&(kmem_cache#25-oX)[1] (struct ctl_node)).node
	// (&(&(kmem_cache#25-oX)[1] (struct ctl_node) + 1).node)->rb_left: NULL
	// (&(&(kmem_cache#25-oX)[1] (struct ctl_node) + 1).node)->rb_right: NULL
	// (&(&(kmem_cache#25-oX)[1] (struct ctl_node)).node)->rb_right: &(&(kmem_cache#25-oX)[1] (struct ctl_node) + 1).node
	//
	// &(&(kmem_cache#25-oX)[1] (struct ctl_node) + 1).node 을 node 로 추가 후 rbtree 로 구성
	// (kern_table 의 2 번째 index의 값)
	/*
	//                       kern_table-b
	//                 (sched_child_runs_first)
	//                                      \
	//                                        kern_table-r
	//                                  (sched_min_granularity_ns)
	//
	// ..... kern_table 의 index 수만큼 RB Tree를 구성
	// 아래 링크의 RB Tree 그림 참고
	// http://neuromancer.kr/t/150-2016-07-09-proc-root-init/313
	//
	// TODO: kern_table 의 rbtree 그림을 그려야함
	*/
	// (kmem_cache#25-oX)->ctl_table_arg: kmem_cache#24-oX
	// (kmem_cache#27-oX)[1] (struct ctl_table_header): kmem_cache#25-oX
	//
	// kern_table index 만큼 kern_table[...].child 맴버값을 보고 dir, files 의 RB Tree 를 구성함
	//
	// sysctl_base_table index 만큼 sysctl_base_table[...].child 맴버값을 보고 recursive 하게 dir, files 의 RB Tree 를 구성함
}

static int proc_root_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat
)
{
	generic_fillattr(dentry->d_inode, stat);
	stat->nlink = proc_root.nlink + nr_processes();
	return 0;
}

static struct dentry *proc_root_lookup(struct inode * dir, struct dentry * dentry, unsigned int flags)
{
	if (!proc_lookup(dir, dentry, flags))
		return NULL;
	
	return proc_pid_lookup(dir, dentry, flags);
}

static int proc_root_readdir(struct file *file, struct dir_context *ctx)
{
	if (ctx->pos < FIRST_PROCESS_ENTRY) {
		int error = proc_readdir(file, ctx);
		if (unlikely(error <= 0))
			return error;
		ctx->pos = FIRST_PROCESS_ENTRY;
	}

	return proc_pid_readdir(file, ctx);
}

/*
 * The root /proc directory is special, as it has the
 * <pid> directories. Thus we don't use the generic
 * directory handling functions for that..
 */
static const struct file_operations proc_root_operations = {
	.read		 = generic_read_dir,
	.iterate	 = proc_root_readdir,
	.llseek		= default_llseek,
};

/*
 * proc root can do almost nothing..
 */
static const struct inode_operations proc_root_inode_operations = {
	.lookup		= proc_root_lookup,
	.getattr	= proc_root_getattr,
};

/*
 * This is the root "inode" in the /proc tree..
 */
// ARM10C 20160604
// ARM10C 20160611
struct proc_dir_entry proc_root = {
	.low_ino	= PROC_ROOT_INO, 
	.namelen	= 5, 
	.mode		= S_IFDIR | S_IRUGO | S_IXUGO, 
	.nlink		= 2, 
	.count		= ATOMIC_INIT(1),
	.proc_iops	= &proc_root_inode_operations, 
	.proc_fops	= &proc_root_operations,
	.parent		= &proc_root,
	.name		= "/proc",
};

int pid_ns_prepare_proc(struct pid_namespace *ns)
{
	struct vfsmount *mnt;

	mnt = kern_mount_data(&proc_fs_type, ns);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	ns->proc_mnt = mnt;
	return 0;
}

void pid_ns_release_proc(struct pid_namespace *ns)
{
	kern_unmount(ns->proc_mnt);
}
