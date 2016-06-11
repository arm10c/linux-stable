/*
 * proc_tty.c -- handles /proc/tty
 *
 * Copyright 1997, Theodore Ts'o
 */

#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/tty.h>
#include <linux/seq_file.h>
#include <linux/bitops.h>

/*
 * The /proc/tty directory inodes...
 */
// ARM10C 20160611
static struct proc_dir_entry *proc_tty_ldisc, *proc_tty_driver;

/*
 * This is the handler for /proc/tty/drivers
 */
static void show_tty_range(struct seq_file *m, struct tty_driver *p,
	dev_t from, int num)
{
	seq_printf(m, "%-20s ", p->driver_name ? p->driver_name : "unknown");
	seq_printf(m, "/dev/%-8s ", p->name);
	if (p->num > 1) {
		seq_printf(m, "%3d %d-%d ", MAJOR(from), MINOR(from),
			MINOR(from) + num - 1);
	} else {
		seq_printf(m, "%3d %7d ", MAJOR(from), MINOR(from));
	}
	switch (p->type) {
	case TTY_DRIVER_TYPE_SYSTEM:
		seq_puts(m, "system");
		if (p->subtype == SYSTEM_TYPE_TTY)
			seq_puts(m, ":/dev/tty");
		else if (p->subtype == SYSTEM_TYPE_SYSCONS)
			seq_puts(m, ":console");
		else if (p->subtype == SYSTEM_TYPE_CONSOLE)
			seq_puts(m, ":vtmaster");
		break;
	case TTY_DRIVER_TYPE_CONSOLE:
		seq_puts(m, "console");
		break;
	case TTY_DRIVER_TYPE_SERIAL:
		seq_puts(m, "serial");
		break;
	case TTY_DRIVER_TYPE_PTY:
		if (p->subtype == PTY_TYPE_MASTER)
			seq_puts(m, "pty:master");
		else if (p->subtype == PTY_TYPE_SLAVE)
			seq_puts(m, "pty:slave");
		else
			seq_puts(m, "pty");
		break;
	default:
		seq_printf(m, "type:%d.%d", p->type, p->subtype);
	}
	seq_putc(m, '\n');
}

static int show_tty_driver(struct seq_file *m, void *v)
{
	struct tty_driver *p = list_entry(v, struct tty_driver, tty_drivers);
	dev_t from = MKDEV(p->major, p->minor_start);
	dev_t to = from + p->num;

	if (&p->tty_drivers == tty_drivers.next) {
		/* pseudo-drivers first */
		seq_printf(m, "%-20s /dev/%-8s ", "/dev/tty", "tty");
		seq_printf(m, "%3d %7d ", TTYAUX_MAJOR, 0);
		seq_puts(m, "system:/dev/tty\n");
		seq_printf(m, "%-20s /dev/%-8s ", "/dev/console", "console");
		seq_printf(m, "%3d %7d ", TTYAUX_MAJOR, 1);
		seq_puts(m, "system:console\n");
#ifdef CONFIG_UNIX98_PTYS
		seq_printf(m, "%-20s /dev/%-8s ", "/dev/ptmx", "ptmx");
		seq_printf(m, "%3d %7d ", TTYAUX_MAJOR, 2);
		seq_puts(m, "system\n");
#endif
#ifdef CONFIG_VT
		seq_printf(m, "%-20s /dev/%-8s ", "/dev/vc/0", "vc/0");
		seq_printf(m, "%3d %7d ", TTY_MAJOR, 0);
		seq_puts(m, "system:vtmaster\n");
#endif
	}

	while (MAJOR(from) < MAJOR(to)) {
		dev_t next = MKDEV(MAJOR(from)+1, 0);
		show_tty_range(m, p, from, next - from);
		from = next;
	}
	if (from != to)
		show_tty_range(m, p, from, to - from);
	return 0;
}

/* iterator */
static void *t_start(struct seq_file *m, loff_t *pos)
{
	mutex_lock(&tty_mutex);
	return seq_list_start(&tty_drivers, *pos);
}

static void *t_next(struct seq_file *m, void *v, loff_t *pos)
{
	return seq_list_next(v, &tty_drivers, pos);
}

static void t_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&tty_mutex);
}

static const struct seq_operations tty_drivers_op = {
	.start	= t_start,
	.next	= t_next,
	.stop	= t_stop,
	.show	= show_tty_driver
};

static int tty_drivers_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &tty_drivers_op);
}

static const struct file_operations proc_tty_drivers_operations = {
	.open		= tty_drivers_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/*
 * This function is called by tty_register_driver() to handle
 * registering the driver's /proc handler into /proc/tty/driver/<foo>
 */
void proc_tty_register_driver(struct tty_driver *driver)
{
	struct proc_dir_entry *ent;
		
	if (!driver->driver_name || driver->proc_entry ||
	    !driver->ops->proc_fops)
		return;

	ent = proc_create_data(driver->driver_name, 0, proc_tty_driver,
			       driver->ops->proc_fops, driver);
	driver->proc_entry = ent;
}

/*
 * This function is called by tty_unregister_driver()
 */
void proc_tty_unregister_driver(struct tty_driver *driver)
{
	struct proc_dir_entry *ent;

	ent = driver->proc_entry;
	if (!ent)
		return;
		
	remove_proc_entry(driver->driver_name, proc_tty_driver);
	
	driver->proc_entry = NULL;
}

/*
 * Called by proc_root_init() to initialize the /proc/tty subtree
 */
// ARM10C 20160611
void __init proc_tty_init(void)
{
	// proc_mkdir("tty", NULL): kmem_cache#29-oX (struct proc_dir_entry)
	if (!proc_mkdir("tty", NULL))
		return;

	// proc_mkdir 에서 한일:
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

	// proc_mkdir("tty/ldisc", NULL: kmem_cache#29-oX (struct proc_dir_entry)
	proc_tty_ldisc = proc_mkdir("tty/ldisc", NULL);
	// proc_tty_ldisc: kmem_cache#29-oX (struct proc_dir_entry)

	// proc_mkdir 에서 한일:
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

	/*
	 * /proc/tty/driver/serial reveals the exact character counts for
	 * serial links which is just too easy to abuse for inferring
	 * password lengths and inter-keystroke timings during password
	 * entry.
	 */
	// S_IRUSR: 00400, S_IXUSR: 00100
	// proc_mkdir_mode("tty/driver", 00500, NULL): kmem_cache#29-oX (struct proc_dir_entry)
	proc_tty_driver = proc_mkdir_mode("tty/driver", S_IRUSR|S_IXUSR, NULL);
	// proc_tty_driver: kmem_cache#29-oX (struct proc_dir_entry)

	// proc_mkdir_mode 에서 한일:
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

	// proc_create("tty/ldiscs", 0, NULL, &tty_ldiscs_proc_fops): kmem_cache#29-oX (struct proc_dir_entry)
	proc_create("tty/ldiscs", 0, NULL, &tty_ldiscs_proc_fops);

	// proc_create 에서 한일:
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

	// proc_create("tty/drivers", 0, NULL, &proc_tty_drivers_operations): kmem_cache#29-oX (struct proc_dir_entry)
	proc_create("tty/drivers", 0, NULL, &proc_tty_drivers_operations);

	// proc_create 에서 한일:
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
}
