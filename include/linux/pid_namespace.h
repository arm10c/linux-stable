#ifndef _LINUX_PID_NS_H
#define _LINUX_PID_NS_H

#include <linux/sched.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <linux/workqueue.h>
#include <linux/threads.h>
#include <linux/nsproxy.h>
#include <linux/kref.h>

// ARM10C 20161105
struct pidmap {
       atomic_t nr_free;
       void *page;
};

// ARM10C 20150912
// ARM10C 20161105
// PAGE_SIZE: 0x1000
// BITS_PER_PAGE: 0x8000
#define BITS_PER_PAGE		(PAGE_SIZE * 8)
// ARM10C 20161105
// BITS_PER_PAGE: 0x8000
// BITS_PER_PAGE_MASK: 0x7FFF
#define BITS_PER_PAGE_MASK	(BITS_PER_PAGE-1)
// ARM10C 20161105
// PID_MAX_LIMIT: 0x8000
// BITS_PER_PAGE: 0x8000
// PIDMAP_ENTRIES: 1
#define PIDMAP_ENTRIES		((PID_MAX_LIMIT+BITS_PER_PAGE-1)/BITS_PER_PAGE)

struct bsd_acct_struct;

// ARM10C 20150718
// ARM10C 20150912
// ARM10C 20160903
// ARM10C 20161105
// ARM10C 20161112
// ARM10C 20161126
struct pid_namespace {
	struct kref kref;
	struct pidmap pidmap[PIDMAP_ENTRIES];
	struct rcu_head rcu;
	int last_pid;
	unsigned int nr_hashed;
	struct task_struct *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace *parent;
#ifdef CONFIG_PROC_FS // CONFIG_PROC_FS=y
	struct vfsmount *proc_mnt;
	struct dentry *proc_self;
#endif
#ifdef CONFIG_BSD_PROCESS_ACCT // CONFIG_BSD_PROCESS_ACCT=n
	struct bsd_acct_struct *bacct;
#endif
	struct user_namespace *user_ns;
	struct work_struct proc_work;
	kgid_t pid_gid;
	int hide_pid;
	int reboot;	/* group exit code if this pidns was rebooted */
	unsigned int proc_inum;
};

extern struct pid_namespace init_pid_ns;

// ARM10C 20150912
// ARM10C 20161203
// PIDNS_HASH_ADDING: 0x80000000
#define PIDNS_HASH_ADDING (1U << 31)

#ifdef CONFIG_PID_NS // CONFIG_PID_NS=y
// ARM10C 20161112
// ns: &init_pid_ns
// ARM10C 20161203
// ns: &init_pid_ns
static inline struct pid_namespace *get_pid_ns(struct pid_namespace *ns)
{
	// ns: &init_pid_ns
	if (ns != &init_pid_ns)
		kref_get(&ns->kref);
	// ns: &init_pid_ns
	return ns;
	// return &init_pid_ns
}

extern struct pid_namespace *copy_pid_ns(unsigned long flags,
	struct user_namespace *user_ns, struct pid_namespace *ns);
extern void zap_pid_ns_processes(struct pid_namespace *pid_ns);
extern int reboot_pid_ns(struct pid_namespace *pid_ns, int cmd);
extern void put_pid_ns(struct pid_namespace *ns);

#else /* !CONFIG_PID_NS */
#include <linux/err.h>

static inline struct pid_namespace *get_pid_ns(struct pid_namespace *ns)
{
	return ns;
}

static inline struct pid_namespace *copy_pid_ns(unsigned long flags,
	struct user_namespace *user_ns, struct pid_namespace *ns)
{
	if (flags & CLONE_NEWPID)
		ns = ERR_PTR(-EINVAL);
	return ns;
}

static inline void put_pid_ns(struct pid_namespace *ns)
{
}

static inline void zap_pid_ns_processes(struct pid_namespace *ns)
{
	BUG();
}

static inline int reboot_pid_ns(struct pid_namespace *pid_ns, int cmd)
{
	return 0;
}
#endif /* CONFIG_PID_NS */

extern struct pid_namespace *task_active_pid_ns(struct task_struct *tsk);
void pidhash_init(void);
void pidmap_init(void);

#endif /* _LINUX_PID_NS_H */
