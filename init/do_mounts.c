/*
 * Many of the syscalls used in this file expect some of the arguments
 * to be __user pointers not __kernel pointers.  To limit the sparse
 * noise, turn off sparse checking for this file.
 */
#ifdef __CHECKER__
#undef __CHECKER__
#warning "Sparse checking disabled for this file"
#endif

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#include <linux/fd.h>
#include <linux/tty.h>
#include <linux/suspend.h>
#include <linux/root_dev.h>
#include <linux/security.h>
#include <linux/delay.h>
#include <linux/genhd.h>
#include <linux/mount.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/initrd.h>
#include <linux/async.h>
#include <linux/fs_struct.h>
#include <linux/slab.h>
#include <linux/ramfs.h>
#include <linux/shmem_fs.h>

#include <linux/nfs_fs.h>
#include <linux/nfs_fs_sb.h>
#include <linux/nfs_mount.h>

#include "do_mounts.h"

int __initdata rd_doload;	/* 1 = load RAM disk, 0 = don't load */

int root_mountflags = MS_RDONLY | MS_SILENT;
static char * __initdata root_device_name;
// ARM10C 20160123
static char __initdata saved_root_name[64];
static int root_wait;

dev_t ROOT_DEV;

static int __init load_ramdisk(char *str)
{
	rd_doload = simple_strtol(str,NULL,0) & 3;
	return 1;
}
__setup("load_ramdisk=", load_ramdisk);

static int __init readonly(char *str)
{
	if (*str)
		return 0;
	root_mountflags |= MS_RDONLY;
	return 1;
}

static int __init readwrite(char *str)
{
	if (*str)
		return 0;
	root_mountflags &= ~MS_RDONLY;
	return 1;
}

__setup("ro", readonly);
__setup("rw", readwrite);

#ifdef CONFIG_BLOCK
struct uuidcmp {
	const char *uuid;
	int len;
};

/**
 * match_dev_by_uuid - callback for finding a partition using its uuid
 * @dev:	device passed in by the caller
 * @data:	opaque pointer to the desired struct uuidcmp to match
 *
 * Returns 1 if the device matches, and 0 otherwise.
 */
static int match_dev_by_uuid(struct device *dev, const void *data)
{
	const struct uuidcmp *cmp = data;
	struct hd_struct *part = dev_to_part(dev);

	if (!part->info)
		goto no_match;

	if (strncasecmp(cmp->uuid, part->info->uuid, cmp->len))
		goto no_match;

	return 1;
no_match:
	return 0;
}


/**
 * devt_from_partuuid - looks up the dev_t of a partition by its UUID
 * @uuid:	char array containing ascii UUID
 *
 * The function will return the first partition which contains a matching
 * UUID value in its partition_meta_info struct.  This does not search
 * by filesystem UUIDs.
 *
 * If @uuid is followed by a "/PARTNROFF=%d", then the number will be
 * extracted and used as an offset from the partition identified by the UUID.
 *
 * Returns the matching dev_t on success or 0 on failure.
 */
static dev_t devt_from_partuuid(const char *uuid_str)
{
	dev_t res = 0;
	struct uuidcmp cmp;
	struct device *dev = NULL;
	struct gendisk *disk;
	struct hd_struct *part;
	int offset = 0;
	bool clear_root_wait = false;
	char *slash;

	cmp.uuid = uuid_str;

	slash = strchr(uuid_str, '/');
	/* Check for optional partition number offset attributes. */
	if (slash) {
		char c = 0;
		/* Explicitly fail on poor PARTUUID syntax. */
		if (sscanf(slash + 1,
			   "PARTNROFF=%d%c", &offset, &c) != 1) {
			clear_root_wait = true;
			goto done;
		}
		cmp.len = slash - uuid_str;
	} else {
		cmp.len = strlen(uuid_str);
	}

	if (!cmp.len) {
		clear_root_wait = true;
		goto done;
	}

	dev = class_find_device(&block_class, NULL, &cmp,
				&match_dev_by_uuid);
	if (!dev)
		goto done;

	res = dev->devt;

	/* Attempt to find the partition by offset. */
	if (!offset)
		goto no_offset;

	res = 0;
	disk = part_to_disk(dev_to_part(dev));
	part = disk_get_part(disk, dev_to_part(dev)->partno + offset);
	if (part) {
		res = part_devt(part);
		put_device(part_to_dev(part));
	}

no_offset:
	put_device(dev);
done:
	if (clear_root_wait) {
		pr_err("VFS: PARTUUID= is invalid.\n"
		       "Expected PARTUUID=<valid-uuid-id>[/PARTNROFF=%%d]\n");
		if (root_wait)
			pr_err("Disabling rootwait; root= is invalid.\n");
		root_wait = 0;
	}
	return res;
}
#endif

/*
 *	Convert a name into device number.  We accept the following variants:
 *
 *	1) device number in hexadecimal	represents itself
 *	2) /dev/nfs represents Root_NFS (0xff)
 *	3) /dev/<disk_name> represents the device number of disk
 *	4) /dev/<disk_name><decimal> represents the device number
 *         of partition - device number of disk plus the partition number
 *	5) /dev/<disk_name>p<decimal> - same as the above, that form is
 *	   used when disk name of partitioned disk ends on a digit.
 *	6) PARTUUID=00112233-4455-6677-8899-AABBCCDDEEFF representing the
 *	   unique id of a partition if the partition table provides it.
 *	   The UUID may be either an EFI/GPT UUID, or refer to an MSDOS
 *	   partition using the format SSSSSSSS-PP, where SSSSSSSS is a zero-
 *	   filled hex representation of the 32-bit "NT disk signature", and PP
 *	   is a zero-filled hex representation of the 1-based partition number.
 *	7) PARTUUID=<UUID>/PARTNROFF=<int> to select a partition in relation to
 *	   a partition with a known unique id.
 *	8) <major>:<minor> major and minor number of the device separated by
 *	   a colon.
 *
 *	If name doesn't have fall into the categories above, we return (0,0).
 *	block_class is used to check if something is a disk name. If the disk
 *	name contains slashes, the device name has them replaced with
 *	bangs.
 */

dev_t name_to_dev_t(char *name)
{
	char s[32];
	char *p;
	dev_t res = 0;
	int part;

#ifdef CONFIG_BLOCK
	if (strncmp(name, "PARTUUID=", 9) == 0) {
		name += 9;
		res = devt_from_partuuid(name);
		if (!res)
			goto fail;
		goto done;
	}
#endif

	if (strncmp(name, "/dev/", 5) != 0) {
		unsigned maj, min;

		if (sscanf(name, "%u:%u", &maj, &min) == 2) {
			res = MKDEV(maj, min);
			if (maj != MAJOR(res) || min != MINOR(res))
				goto fail;
		} else {
			res = new_decode_dev(simple_strtoul(name, &p, 16));
			if (*p)
				goto fail;
		}
		goto done;
	}

	name += 5;
	res = Root_NFS;
	if (strcmp(name, "nfs") == 0)
		goto done;
	res = Root_RAM0;
	if (strcmp(name, "ram") == 0)
		goto done;

	if (strlen(name) > 31)
		goto fail;
	strcpy(s, name);
	for (p = s; *p; p++)
		if (*p == '/')
			*p = '!';
	res = blk_lookup_devt(s, 0);
	if (res)
		goto done;

	/*
	 * try non-existent, but valid partition, which may only exist
	 * after revalidating the disk, like partitioned md devices
	 */
	while (p > s && isdigit(p[-1]))
		p--;
	if (p == s || !*p || *p == '0')
		goto fail;

	/* try disk name without <part number> */
	part = simple_strtoul(p, NULL, 10);
	*p = '\0';
	res = blk_lookup_devt(s, part);
	if (res)
		goto done;

	/* try disk name without p<part number> */
	if (p < s + 2 || !isdigit(p[-2]) || p[-1] != 'p')
		goto fail;
	p[-1] = '\0';
	res = blk_lookup_devt(s, part);
	if (res)
		goto done;

fail:
	return 0;
done:
	return res;
}

static int __init root_dev_setup(char *line)
{
	strlcpy(saved_root_name, line, sizeof(saved_root_name));
	return 1;
}

__setup("root=", root_dev_setup);

static int __init rootwait_setup(char *str)
{
	if (*str)
		return 0;
	root_wait = 1;
	return 1;
}

__setup("rootwait", rootwait_setup);

static char * __initdata root_mount_data;
static int __init root_data_setup(char *str)
{
	root_mount_data = str;
	return 1;
}

// ARM10C 20160123
static char * __initdata root_fs_names;
static int __init fs_names_setup(char *str)
{
	root_fs_names = str;
	return 1;
}

static unsigned int __initdata root_delay;
static int __init root_delay_setup(char *str)
{
	root_delay = simple_strtoul(str, NULL, 0);
	return 1;
}

__setup("rootflags=", root_data_setup);
__setup("rootfstype=", fs_names_setup);
__setup("rootdelay=", root_delay_setup);

static void __init get_fs_names(char *page)
{
	char *s = page;

	if (root_fs_names) {
		strcpy(page, root_fs_names);
		while (*s++) {
			if (s[-1] == ',')
				s[-1] = '\0';
		}
	} else {
		int len = get_filesystem_list(page);
		char *p, *next;

		page[len] = '\0';
		for (p = page-1; p; p = next) {
			next = strchr(++p, '\n');
			if (*p++ != '\t')
				continue;
			while ((*s++ = *p++) != '\n')
				;
			s[-1] = '\0';
		}
	}
	*s = '\0';
}

static int __init do_mount_root(char *name, char *fs, int flags, void *data)
{
	struct super_block *s;
	int err = sys_mount(name, "/root", fs, flags, data);
	if (err)
		return err;

	sys_chdir("/root");
	s = current->fs->pwd.dentry->d_sb;
	ROOT_DEV = s->s_dev;
	printk(KERN_INFO
	       "VFS: Mounted root (%s filesystem)%s on device %u:%u.\n",
	       s->s_type->name,
	       s->s_flags & MS_RDONLY ?  " readonly" : "",
	       MAJOR(ROOT_DEV), MINOR(ROOT_DEV));
	return 0;
}

void __init mount_block_root(char *name, int flags)
{
	struct page *page = alloc_page(GFP_KERNEL |
					__GFP_NOTRACK_FALSE_POSITIVE);
	char *fs_names = page_address(page);
	char *p;
#ifdef CONFIG_BLOCK
	char b[BDEVNAME_SIZE];
#else
	const char *b = name;
#endif

	get_fs_names(fs_names);
retry:
	for (p = fs_names; *p; p += strlen(p)+1) {
		int err = do_mount_root(name, p, flags, root_mount_data);
		switch (err) {
			case 0:
				goto out;
			case -EACCES:
				flags |= MS_RDONLY;
				goto retry;
			case -EINVAL:
				continue;
		}
	        /*
		 * Allow the user to distinguish between failed sys_open
		 * and bad superblock on root device.
		 * and give them a list of the available devices
		 */
#ifdef CONFIG_BLOCK
		__bdevname(ROOT_DEV, b);
#endif
		printk("VFS: Cannot open root device \"%s\" or %s: error %d\n",
				root_device_name, b, err);
		printk("Please append a correct \"root=\" boot option; here are the available partitions:\n");

		printk_all_partitions();
#ifdef CONFIG_DEBUG_BLOCK_EXT_DEVT
		printk("DEBUG_BLOCK_EXT_DEVT is enabled, you need to specify "
		       "explicit textual name for \"root=\" boot option.\n");
#endif
		panic("VFS: Unable to mount root fs on %s", b);
	}

	printk("List of all partitions:\n");
	printk_all_partitions();
	printk("No filesystem could mount root, tried: ");
	for (p = fs_names; *p; p += strlen(p)+1)
		printk(" %s", p);
	printk("\n");
#ifdef CONFIG_BLOCK
	__bdevname(ROOT_DEV, b);
#endif
	panic("VFS: Unable to mount root fs on %s", b);
out:
	put_page(page);
}
 
#ifdef CONFIG_ROOT_NFS

#define NFSROOT_TIMEOUT_MIN	5
#define NFSROOT_TIMEOUT_MAX	30
#define NFSROOT_RETRY_MAX	5

static int __init mount_nfs_root(void)
{
	char *root_dev, *root_data;
	unsigned int timeout;
	int try, err;

	err = nfs_root_data(&root_dev, &root_data);
	if (err != 0)
		return 0;

	/*
	 * The server or network may not be ready, so try several
	 * times.  Stop after a few tries in case the client wants
	 * to fall back to other boot methods.
	 */
	timeout = NFSROOT_TIMEOUT_MIN;
	for (try = 1; ; try++) {
		err = do_mount_root(root_dev, "nfs",
					root_mountflags, root_data);
		if (err == 0)
			return 1;
		if (try > NFSROOT_RETRY_MAX)
			break;

		/* Wait, in case the server refused us immediately */
		ssleep(timeout);
		timeout <<= 1;
		if (timeout > NFSROOT_TIMEOUT_MAX)
			timeout = NFSROOT_TIMEOUT_MAX;
	}
	return 0;
}
#endif

#if defined(CONFIG_BLK_DEV_RAM) || defined(CONFIG_BLK_DEV_FD)
void __init change_floppy(char *fmt, ...)
{
	struct termios termios;
	char buf[80];
	char c;
	int fd;
	va_list args;
	va_start(args, fmt);
	vsprintf(buf, fmt, args);
	va_end(args);
	fd = sys_open("/dev/root", O_RDWR | O_NDELAY, 0);
	if (fd >= 0) {
		sys_ioctl(fd, FDEJECT, 0);
		sys_close(fd);
	}
	printk(KERN_NOTICE "VFS: Insert %s and press ENTER\n", buf);
	fd = sys_open("/dev/console", O_RDWR, 0);
	if (fd >= 0) {
		sys_ioctl(fd, TCGETS, (long)&termios);
		termios.c_lflag &= ~ICANON;
		sys_ioctl(fd, TCSETSF, (long)&termios);
		sys_read(fd, &c, 1);
		termios.c_lflag |= ICANON;
		sys_ioctl(fd, TCSETSF, (long)&termios);
		sys_close(fd);
	}
}
#endif

void __init mount_root(void)
{
#ifdef CONFIG_ROOT_NFS
	if (ROOT_DEV == Root_NFS) {
		if (mount_nfs_root())
			return;

		printk(KERN_ERR "VFS: Unable to mount root fs via NFS, trying floppy.\n");
		ROOT_DEV = Root_FD0;
	}
#endif
#ifdef CONFIG_BLK_DEV_FD
	if (MAJOR(ROOT_DEV) == FLOPPY_MAJOR) {
		/* rd_doload is 2 for a dual initrd/ramload setup */
		if (rd_doload==2) {
			if (rd_load_disk(1)) {
				ROOT_DEV = Root_RAM1;
				root_device_name = NULL;
			}
		} else
			change_floppy("root floppy");
	}
#endif
#ifdef CONFIG_BLOCK
	create_dev("/dev/root", ROOT_DEV);
	mount_block_root("/dev/root", root_mountflags);
#endif
}

/*
 * Prepare the namespace - decide what/where to mount, load ramdisks, etc.
 */
void __init prepare_namespace(void)
{
	int is_floppy;

	if (root_delay) {
		printk(KERN_INFO "Waiting %d sec before mounting root device...\n",
		       root_delay);
		ssleep(root_delay);
	}

	/*
	 * wait for the known devices to complete their probing
	 *
	 * Note: this is a potential source of long boot delays.
	 * For example, it is not atypical to wait 5 seconds here
	 * for the touchpad of a laptop to initialize.
	 */
	wait_for_device_probe();

	md_run_setup();

	if (saved_root_name[0]) {
		root_device_name = saved_root_name;
		if (!strncmp(root_device_name, "mtd", 3) ||
		    !strncmp(root_device_name, "ubi", 3)) {
			mount_block_root(root_device_name, root_mountflags);
			goto out;
		}
		ROOT_DEV = name_to_dev_t(root_device_name);
		if (strncmp(root_device_name, "/dev/", 5) == 0)
			root_device_name += 5;
	}

	if (initrd_load())
		goto out;

	/* wait for any asynchronous scanning to complete */
	if ((ROOT_DEV == 0) && root_wait) {
		printk(KERN_INFO "Waiting for root device %s...\n",
			saved_root_name);
		while (driver_probe_done() != 0 ||
			(ROOT_DEV = name_to_dev_t(saved_root_name)) == 0)
			msleep(100);
		async_synchronize_full();
	}

	is_floppy = MAJOR(ROOT_DEV) == FLOPPY_MAJOR;

	if (is_floppy && rd_doload && rd_load_disk(0))
		ROOT_DEV = Root_RAM0;

	mount_root();
out:
	devtmpfs_mount("dev");
	sys_mount(".", "/", NULL, MS_MOVE, NULL);
	sys_chroot(".");
}

// ARM10C 20160326
// ARM10C 20160416
static bool is_tmpfs;

// ARM10C 20160416
// type: &rootfs_fs_type, flags: 0, name: "rootfs", data: NULL
static struct dentry *rootfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	static unsigned long once;
	void *fill = ramfs_fill_super;
	// fill: ramfs_fill_super

	// once: 0, test_and_set_bit(0, &once): 0
	if (test_and_set_bit(0, &once))
		return ERR_PTR(-ENODEV);

	// test_and_set_bit 에서 한일:
	// once: 1

	// CONFIG_TMPFS=y, IS_ENABLED(CONFIG_TMPFS): 1, is_tmpfs: 1
	if (IS_ENABLED(CONFIG_TMPFS) && is_tmpfs)
		// fill: ramfs_fill_super
		fill = shmem_fill_super;
		// fill: shmem_fill_super

	// fs_type: &rootfs_fs_type, flags: 0, data: NULL, fill: shmem_fill_super
	// mount_nodev(&rootfs_fs_type, 0, NULL, shmem_fill_super): kmem_cache#5-oX (struct dentry)
	return mount_nodev(fs_type, flags, data, fill);
	// return kmem_cache#5-oX (struct dentry)

	// mount_nodev 에서 한일:
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
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0xd0410000
}

// ARM10C 20160123
// ARM10C 20160402
static struct file_system_type rootfs_fs_type = {
	.name		= "rootfs",
	.mount		= rootfs_mount,
	.kill_sb	= kill_litter_super,
};

// ARM10C 20160123
int __init init_rootfs(void)
{
	// register_filesystem(&rootfs_fs_type): 0
	int err = register_filesystem(&rootfs_fs_type);
	// err: 0

	// register_filesystem에서 한일:
	// (&sysfs_fs_type)->next: &rootfs_fs_type

	// err: 0
	if (err)
		return err;

	// CONFIG_TMPFS: y, IS_ENABLED(CONFIG_TMPFS): 1, saved_root_name[0]: 0,
	// root_fs_names: NULL, strstr(NULL, "tmpfs"): NULL
	if (IS_ENABLED(CONFIG_TMPFS) && !saved_root_name[0] &&
		(!root_fs_names || strstr(root_fs_names, "tmpfs"))) {
		// shmem_init(): 0
		err = shmem_init();
		// err: 0

		// shmem_init에서 한일:
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

		is_tmpfs = true;
		// is_tmpfs: 1
	} else {
		err = init_ramfs_fs();
	}

	// err: 0
	if (err)
		unregister_filesystem(&rootfs_fs_type);

	// err: 0
	return err;
	// return 0
}
