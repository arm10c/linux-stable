/*
 *  linux/kernel/fork.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 *  'fork.c' contains the help-routines for the 'fork' system call
 * (see also entry.S and others).
 * Fork is rather simple, once you get the hang of it, but the memory
 * management can be a bitch. See 'mm/memory.c': 'copy_page_range()'
 */

#include <linux/slab.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/mempolicy.h>
#include <linux/sem.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/iocontext.h>
#include <linux/key.h>
#include <linux/binfmts.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/cgroup.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/seccomp.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/jiffies.h>
#include <linux/futex.h>
#include <linux/compat.h>
#include <linux/kthread.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/rcupdate.h>
#include <linux/ptrace.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/memcontrol.h>
#include <linux/ftrace.h>
#include <linux/proc_fs.h>
#include <linux/profile.h>
#include <linux/rmap.h>
#include <linux/ksm.h>
#include <linux/acct.h>
#include <linux/tsacct_kern.h>
#include <linux/cn_proc.h>
#include <linux/freezer.h>
#include <linux/delayacct.h>
#include <linux/taskstats_kern.h>
#include <linux/random.h>
#include <linux/tty.h>
#include <linux/blkdev.h>
#include <linux/fs_struct.h>
#include <linux/magic.h>
#include <linux/perf_event.h>
#include <linux/posix-timers.h>
#include <linux/user-return-notifier.h>
#include <linux/oom.h>
#include <linux/khugepaged.h>
#include <linux/signalfd.h>
#include <linux/uprobes.h>
#include <linux/aio.h>

#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#include <trace/events/sched.h>

#define CREATE_TRACE_POINTS
#include <trace/events/task.h>

/*
 * Protected counters by write_lock_irq(&tasklist_lock)
 */
// ARM10C 20161210
// ARM10C 20170610
unsigned long total_forks;	/* Handle normal Linux uptimes. */

// ARM10C 20160910
// ARM10C 20161210
// ARM10C 20170610
int nr_threads;			/* The idle threads do not count.. */

// ARM10C 20150919
// ARM10C 20160402
int max_threads;		/* tunable limit on nr_threads */

// ARM10C 20161210
// DEFINE_PER_CPU(unsigned long, process_counts):
//	__attribute__((section(".data..percpu" "")))
//	__typeof__(unsigned long) process_counts
DEFINE_PER_CPU(unsigned long, process_counts) = 0;

// ARM10C 20161203
// DEFINE_RWLOCK(tasklist_lock):
// rwlock_t tasklist_lock =
// (rwlock_t)
// {
//      .raw_lock = { 0 },
//      .magic = 0xdeaf1eed,
//      .owner = 0xffffffff,
//      .owner_cpu = -1,
// }
__cacheline_aligned DEFINE_RWLOCK(tasklist_lock);  /* outer */

#ifdef CONFIG_PROVE_RCU
int lockdep_tasklist_lock_is_held(void)
{
	return lockdep_is_held(&tasklist_lock);
}
EXPORT_SYMBOL_GPL(lockdep_tasklist_lock_is_held);
#endif /* #ifdef CONFIG_PROVE_RCU */

int nr_processes(void)
{
	int cpu;
	int total = 0;

	for_each_possible_cpu(cpu)
		total += per_cpu(process_counts, cpu);

	return total;
}

void __weak arch_release_task_struct(struct task_struct *tsk)
{
}

#ifndef CONFIG_ARCH_TASK_STRUCT_ALLOCATOR // CONFIG_ARCH_TASK_STRUCT_ALLOCATOR=n
// ARM10C 20150919
// ARM10C 20160903
static struct kmem_cache *task_struct_cachep;

// ARM10C 20160903
// node: 0
static inline struct task_struct *alloc_task_struct_node(int node)
{
	// task_struct_cachep: kmem_cache#15, GFP_KERNEL: 0xD0, node: 0
	// kmem_cache_alloc_node(kmem_cache#15, GFP_KERNEL: 0xD0, 0): kmem_cache#15-oX (struct task_struct)
	return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node);
	// return kmem_cache#15-oX (struct task_struct)
}

static inline void free_task_struct(struct task_struct *tsk)
{
	kmem_cache_free(task_struct_cachep, tsk);
}
#endif

void __weak arch_release_thread_info(struct thread_info *ti)
{
}

#ifndef CONFIG_ARCH_THREAD_INFO_ALLOCATOR // CONFIG_ARCH_THREAD_INFO_ALLOCATOR=n

/*
 * Allocate pages if THREAD_SIZE is >= PAGE_SIZE, otherwise use a
 * kmemcache based allocator.
 */
# if THREAD_SIZE >= PAGE_SIZE // THREAD_SIZE: 8192, PAGE_SIZE: 0x1000
// ARM10C 20160903
// tsk: kmem_cache#15-oX (struct task_struct), node: 0
static struct thread_info *alloc_thread_info_node(struct task_struct *tsk,
						  int node)
{
	// node: 0, THREADINFO_GFP_ACCOUNTED: 0x3000D0, THREAD_SIZE_ORDER: 1
	// alloc_pages_node(0, 0x3000D0, 1): 할당 받은 page 2개의 메로리 주소
	struct page *page = alloc_pages_node(node, THREADINFO_GFP_ACCOUNTED,
					     THREAD_SIZE_ORDER);
	// page: 할당 받은 page 2개의 메로리 주소

	// page: 할당 받은 page 2개의 메로리 주소
	// page_address(할당 받은 page 2개의 메로리 주소): 할당 받은 page 2개의 메로리의 가상 주소
	return page ? page_address(page) : NULL;
	// return 할당 받은 page 2개의 메로리의 가상 주소
}

static inline void free_thread_info(struct thread_info *ti)
{
	free_memcg_kmem_pages((unsigned long)ti, THREAD_SIZE_ORDER);
}
# else
static struct kmem_cache *thread_info_cache;

static struct thread_info *alloc_thread_info_node(struct task_struct *tsk,
						  int node)
{
	return kmem_cache_alloc_node(thread_info_cache, THREADINFO_GFP, node);
}

static void free_thread_info(struct thread_info *ti)
{
	kmem_cache_free(thread_info_cache, ti);
}

void thread_info_cache_init(void)
{
	thread_info_cache = kmem_cache_create("thread_info", THREAD_SIZE,
					      THREAD_SIZE, 0, NULL);
	BUG_ON(thread_info_cache == NULL);
}
# endif
#endif

/* SLAB cache for signal_struct structures (tsk->signal) */
// ARM10C 20150919
// ARM10C 20161105
static struct kmem_cache *signal_cachep;

/* SLAB cache for sighand_struct structures (tsk->sighand) */
// ARM10C 20150919
// ARM10C 20170524
struct kmem_cache *sighand_cachep;

/* SLAB cache for files_struct structures (tsk->files) */
// ARM10C 20150919
struct kmem_cache *files_cachep;

/* SLAB cache for fs_struct structures (tsk->fs) */
// ARM10C 20150919
struct kmem_cache *fs_cachep;

/* SLAB cache for vm_area_struct structures */
// ARM10C 20150919
struct kmem_cache *vm_area_cachep;

/* SLAB cache for mm_struct structures (tsk->mm) */
// ARM10C 20150919
static struct kmem_cache *mm_cachep;

// ARM10C 20160903
// ti: 할당 받은 page 2개의 메로리의 가상 주소, 1
static void account_kernel_stack(struct thread_info *ti, int account)
{
	// ti: 할당 받은 page 2개의 메로리의 가상 주소
	// virt_to_page(할당 받은 page 2개의 메로리의 가상 주소): 할당 받은 page 2개의 메로리의 가상 주소
	// page_zone(할당 받은 page 2개의 메로리의 가상 주소): &(&contig_page_data)->node_zones[0]
	struct zone *zone = page_zone(virt_to_page(ti));
	// zone: &(&contig_page_data)->node_zones[0]

	// zone: &(&contig_page_data)->node_zones[0], NR_KERNEL_STACK: 16, account: 1
	mod_zone_page_state(zone, NR_KERNEL_STACK, account);

	// mod_zone_page_state 에서 한일:
	// (&contig_page_data)->node_zones[0].vm_stat[16]: 1 을 더함
	// vmstat.c의 vm_stat[16] 전역 변수에도 1을 더함
}

void free_task(struct task_struct *tsk)
{
	account_kernel_stack(tsk->stack, -1);
	arch_release_thread_info(tsk->stack);
	free_thread_info(tsk->stack);
	rt_mutex_debug_task_free(tsk);
	ftrace_graph_exit_task(tsk);
	put_seccomp_filter(tsk);
	arch_release_task_struct(tsk);
	free_task_struct(tsk);
}
EXPORT_SYMBOL(free_task);

static inline void free_signal_struct(struct signal_struct *sig)
{
	taskstats_tgid_free(sig);
	sched_autogroup_exit(sig);
	kmem_cache_free(signal_cachep, sig);
}

static inline void put_signal_struct(struct signal_struct *sig)
{
	if (atomic_dec_and_test(&sig->sigcnt))
		free_signal_struct(sig);
}

void __put_task_struct(struct task_struct *tsk)
{
	WARN_ON(!tsk->exit_state);
	WARN_ON(atomic_read(&tsk->usage));
	WARN_ON(tsk == current);

	security_task_free(tsk);
	exit_creds(tsk);
	delayacct_tsk_free(tsk);
	put_signal_struct(tsk->signal);

	if (!profile_handoff_task(tsk))
		free_task(tsk);
}
EXPORT_SYMBOL_GPL(__put_task_struct);

// ARM10C 20150919
void __init __weak arch_task_cache_init(void) { }

// ARM10C 20150919
// totalram_pages: 총 free된 page 수
void __init fork_init(unsigned long mempages)
{
#ifndef CONFIG_ARCH_TASK_STRUCT_ALLOCATOR // CONFIG_ARCH_TASK_STRUCT_ALLOCATOR=n
#ifndef ARCH_MIN_TASKALIGN
	// L1_CACHE_BYTES: 64
	// ARCH_MIN_TASKALIGN: 64
#define ARCH_MIN_TASKALIGN	L1_CACHE_BYTES
#endif
	/* create a slab on which task_structs can be allocated */

	// ARCH_MIN_TASKALIGN: 64, SLAB_PANIC: 0x00040000UL, SLAB_NOTRACK: 0x00000000UL, sizeof(struct task_struct): 815 bytes
	// kmem_cache_create("task_struct", 815, 64, 0x00040000, NULL): kmem_cache#15
	task_struct_cachep =
		kmem_cache_create("task_struct", sizeof(struct task_struct),
				ARCH_MIN_TASKALIGN, SLAB_PANIC | SLAB_NOTRACK, NULL);
	// task_struct_cachep: kmem_cache#15
#endif

	/* do the arch specific task caches init */
	arch_task_cache_init(); // null function

	/*
	 * The default maximum number of threads is set to a safe
	 * value: the thread structures can take up at most half
	 * of memory.
	 */
	// mempages: 총 free된 page 수, THREAD_SIZE: 0x2000, PAGE_SIZE: 0x1000
	max_threads = mempages / (8 * THREAD_SIZE / PAGE_SIZE);
	// max_threads: 총 free된 page 수 / 16

	/*
	 * we need to allow at least 20 threads to boot a system
	 */
	// max_threads: 총 free된 page 수 / 16
	if (max_threads < 20)
		max_threads = 20;

	// max_threads: 총 free된 page 수 / 16, RLIMIT_NPROC: 6
	init_task.signal->rlim[RLIMIT_NPROC].rlim_cur = max_threads/2;
	// init_task.signal->rlim[6].rlim_cur: 총 free된 page 수 / 32

	// max_threads: 총 free된 page 수 / 16, RLIMIT_NPROC: 6
	init_task.signal->rlim[RLIMIT_NPROC].rlim_max = max_threads/2;
	// init_task.signal->rlim[6].rlim_max: 총 free된 page 수 / 32

	// RLIMIT_SIGPENDING: 11
	init_task.signal->rlim[RLIMIT_SIGPENDING] =
		init_task.signal->rlim[RLIMIT_NPROC];
	// init_task.signal->rlim[11].rlim_cur: 총 free된 page 수 / 32
	// init_task.signal->rlim[11].rlim_max: 총 free된 page 수 / 32
}

// ARM10C 20160903
// tsk: kmem_cache#15-oX (struct task_struct), current: &init_task
int __attribute__((weak)) arch_dup_task_struct(struct task_struct *dst,
		struct task_struct *src)
{
	// *dst: *(kmem_cache#15-oX (struct task_struct)), *src: init_task
	*dst = *src;
	// *dst: *(kmem_cache#15-oX (struct task_struct)): init_task 를 복사한 값

	return 0;
	// return 0
}

// ARM10C 20160903
// current: &init_task
// ARM10C 20170524
// current: &init_task
static struct task_struct *dup_task_struct(struct task_struct *orig)
{
	struct task_struct *tsk;
	struct thread_info *ti;
	unsigned long *stackend;

	// orig: &init_task, tsk_fork_get_node(&init_task): 0
	int node = tsk_fork_get_node(orig);
	// node: 0

	int err;

	// node: 0, alloc_task_struct_node(0): kmem_cache#15-oX (struct task_struct)
	tsk = alloc_task_struct_node(node);
	// tsk: kmem_cache#15-oX (struct task_struct)

	// tsk: kmem_cache#15-oX (struct task_struct)
	if (!tsk)
		return NULL;

	// tsk: kmem_cache#15-oX (struct task_struct), node: 0
	// alloc_thread_info_node(kmem_cache#15-oX (struct task_struct), 0): 할당 받은 page 2개의 메로리의 가상 주소
	ti = alloc_thread_info_node(tsk, node);
	// ti: 할당 받은 page 2개의 메로리의 가상 주소

	// ti: 할당 받은 page 2개의 메로리의 가상 주소
	if (!ti)
		goto free_tsk;

	// tsk: kmem_cache#15-oX (struct task_struct), orig: &init_task
	// arch_dup_task_struct(kmem_cache#15-oX (struct task_struct), &init_task): 0
	err = arch_dup_task_struct(tsk, orig);
	// err: 0

	// arch_dup_task_struct 에서 한일:
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 메모리에 init_task 값을 전부 할당함

	// err: 0
	if (err)
		goto free_ti;

	// tsk->stack: (kmem_cache#15-oX (struct task_struct))->stack,
	// ti: 할당 받은 page 2개의 메로리의 가상 주소
	tsk->stack = ti;
	// tsk->stack: (kmem_cache#15-oX (struct task_struct))->stack: 할당 받은 page 2개의 메로리의 가상 주소

	// tsk: kmem_cache#15-oX (struct task_struct), orig: &init_task
	setup_thread_stack(tsk, orig);

	// setup_thread_stack 에서 한일:
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 의 stack의 값을 init_task 의 stack 값에서 전부 복사함
	// 복사된 struct thread_info 의 task 주소값을 할당 받은 kmem_cache#15-oX (struct task_struct)로 변경함
	//
	// *(할당 받은 page 2개의 메로리의 가상 주소): init_thread_info
	// ((struct thread_info *) 할당 받은 page 2개의 메로리의 가상 주소)->task: kmem_cache#15-oX (struct task_struct),

	// tsk: kmem_cache#15-oX (struct task_struct)
	clear_user_return_notifier(tsk); // null function

	// tsk: kmem_cache#15-oX (struct task_struct)
	clear_tsk_need_resched(tsk);

	// clear_tsk_need_resched 에서 한일:
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 1 bit 값을 clear 수행

	// tsk: kmem_cache#15-oX (struct task_struct)
	// end_of_stack(kmem_cache#15-oX (struct task_struct)): (unsigned long *)(할당 받은 page 2개의 메로리의 가상 주소 + 1)
	stackend = end_of_stack(tsk);
	// stackend: (unsigned long *)(할당 받은 page 2개의 메로리의 가상 주소 + 1)

	// *stackend: *((unsigned long *)(할당 받은 page 2개의 메로리의 가상 주소 + 1)), STACK_END_MAGIC: 0x57AC6E9D
	*stackend = STACK_END_MAGIC;	/* for overflow detection */
	// *stackend: *((unsigned long *)(할당 받은 page 2개의 메로리의 가상 주소 + 1)): 0x57AC6E9D

#ifdef CONFIG_CC_STACKPROTECTOR // CONFIG_CC_STACKPROTECTOR=n
	tsk->stack_canary = get_random_int();
#endif

	/*
	 * One for us, one for whoever does the "release_task()" (usually
	 * parent)
	 */
	// &tsk->usage: &(kmem_cache#15-oX (struct task_struct))->usage
	atomic_set(&tsk->usage, 2);

	// atomic_set 에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->usage)->counter: 2

#ifdef CONFIG_BLK_DEV_IO_TRACE // CONFIG_BLK_DEV_IO_TRACE=n
	tsk->btrace_seq = 0;
#endif
	// tsk->splice_pipe: (kmem_cache#15-oX (struct task_struct))->splice_pipe
	tsk->splice_pipe = NULL;
	// tsk->splice_pipe: (kmem_cache#15-oX (struct task_struct))->splice_pipe: NULL

	// tsk->task_frag.page: (kmem_cache#15-oX (struct task_struct))->task_frag.page
	tsk->task_frag.page = NULL;
	// tsk->task_frag.page: (kmem_cache#15-oX (struct task_struct))->task_frag.page: NULL

	// ti: 할당 받은 page 2개의 메로리의 가상 주소
	account_kernel_stack(ti, 1);

	// account_kernel_stack 에서 한일:
	// (&contig_page_data)->node_zones[0].vm_stat[16]: 1 을 더함
	// vmstat.c의 vm_stat[16] 전역 변수에도 1을 더함

	// tsk: kmem_cache#15-oX (struct task_struct)
	return tsk;
	// return kmem_cache#15-oX (struct task_struct)

free_ti:
	free_thread_info(ti);
free_tsk:
	free_task_struct(tsk);
	return NULL;
}

#ifdef CONFIG_MMU
static int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm)
{
	struct vm_area_struct *mpnt, *tmp, *prev, **pprev;
	struct rb_node **rb_link, *rb_parent;
	int retval;
	unsigned long charge;

	uprobe_start_dup_mmap();
	down_write(&oldmm->mmap_sem);
	flush_cache_dup_mm(oldmm);
	uprobe_dup_mmap(oldmm, mm);
	/*
	 * Not linked in yet - no deadlock potential:
	 */
	down_write_nested(&mm->mmap_sem, SINGLE_DEPTH_NESTING);

	mm->locked_vm = 0;
	mm->mmap = NULL;
	mm->mmap_cache = NULL;
	mm->map_count = 0;
	cpumask_clear(mm_cpumask(mm));
	mm->mm_rb = RB_ROOT;
	rb_link = &mm->mm_rb.rb_node;
	rb_parent = NULL;
	pprev = &mm->mmap;
	retval = ksm_fork(mm, oldmm);
	if (retval)
		goto out;
	retval = khugepaged_fork(mm, oldmm);
	if (retval)
		goto out;

	prev = NULL;
	for (mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) {
		struct file *file;

		if (mpnt->vm_flags & VM_DONTCOPY) {
			vm_stat_account(mm, mpnt->vm_flags, mpnt->vm_file,
					-vma_pages(mpnt));
			continue;
		}
		charge = 0;
		if (mpnt->vm_flags & VM_ACCOUNT) {
			unsigned long len = vma_pages(mpnt);

			if (security_vm_enough_memory_mm(oldmm, len)) /* sic */
				goto fail_nomem;
			charge = len;
		}
		tmp = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);
		if (!tmp)
			goto fail_nomem;
		*tmp = *mpnt;
		INIT_LIST_HEAD(&tmp->anon_vma_chain);
		retval = vma_dup_policy(mpnt, tmp);
		if (retval)
			goto fail_nomem_policy;
		tmp->vm_mm = mm;
		if (anon_vma_fork(tmp, mpnt))
			goto fail_nomem_anon_vma_fork;
		tmp->vm_flags &= ~VM_LOCKED;
		tmp->vm_next = tmp->vm_prev = NULL;
		file = tmp->vm_file;
		if (file) {
			struct inode *inode = file_inode(file);
			struct address_space *mapping = file->f_mapping;

			get_file(file);
			if (tmp->vm_flags & VM_DENYWRITE)
				atomic_dec(&inode->i_writecount);
			mutex_lock(&mapping->i_mmap_mutex);
			if (tmp->vm_flags & VM_SHARED)
				mapping->i_mmap_writable++;
			flush_dcache_mmap_lock(mapping);
			/* insert tmp into the share list, just after mpnt */
			if (unlikely(tmp->vm_flags & VM_NONLINEAR))
				vma_nonlinear_insert(tmp,
						&mapping->i_mmap_nonlinear);
			else
				vma_interval_tree_insert_after(tmp, mpnt,
						&mapping->i_mmap);
			flush_dcache_mmap_unlock(mapping);
			mutex_unlock(&mapping->i_mmap_mutex);
		}

		/*
		 * Clear hugetlb-related page reserves for children. This only
		 * affects MAP_PRIVATE mappings. Faults generated by the child
		 * are not guaranteed to succeed, even if read-only
		 */
		if (is_vm_hugetlb_page(tmp))
			reset_vma_resv_huge_pages(tmp);

		/*
		 * Link in the new vma and copy the page table entries.
		 */
		*pprev = tmp;
		pprev = &tmp->vm_next;
		tmp->vm_prev = prev;
		prev = tmp;

		__vma_link_rb(mm, tmp, rb_link, rb_parent);
		rb_link = &tmp->vm_rb.rb_right;
		rb_parent = &tmp->vm_rb;

		mm->map_count++;
		retval = copy_page_range(mm, oldmm, mpnt);

		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);

		if (retval)
			goto out;
	}
	/* a new mm has just been created */
	arch_dup_mmap(oldmm, mm);
	retval = 0;
out:
	up_write(&mm->mmap_sem);
	flush_tlb_mm(oldmm);
	up_write(&oldmm->mmap_sem);
	uprobe_end_dup_mmap();
	return retval;
fail_nomem_anon_vma_fork:
	mpol_put(vma_policy(tmp));
fail_nomem_policy:
	kmem_cache_free(vm_area_cachep, tmp);
fail_nomem:
	retval = -ENOMEM;
	vm_unacct_memory(charge);
	goto out;
}

static inline int mm_alloc_pgd(struct mm_struct *mm)
{
	mm->pgd = pgd_alloc(mm);
	if (unlikely(!mm->pgd))
		return -ENOMEM;
	return 0;
}

static inline void mm_free_pgd(struct mm_struct *mm)
{
	pgd_free(mm, mm->pgd);
}
#else
#define dup_mmap(mm, oldmm)	(0)
#define mm_alloc_pgd(mm)	(0)
#define mm_free_pgd(mm)
#endif /* CONFIG_MMU */

__cacheline_aligned_in_smp DEFINE_SPINLOCK(mmlist_lock);

#define allocate_mm()	(kmem_cache_alloc(mm_cachep, GFP_KERNEL))
#define free_mm(mm)	(kmem_cache_free(mm_cachep, (mm)))

static unsigned long default_dump_filter = MMF_DUMP_FILTER_DEFAULT;

static int __init coredump_filter_setup(char *s)
{
	default_dump_filter =
		(simple_strtoul(s, NULL, 0) << MMF_DUMP_FILTER_SHIFT) &
		MMF_DUMP_FILTER_MASK;
	return 1;
}

__setup("coredump_filter=", coredump_filter_setup);

#include <linux/init_task.h>

static void mm_init_aio(struct mm_struct *mm)
{
#ifdef CONFIG_AIO
	spin_lock_init(&mm->ioctx_lock);
	mm->ioctx_table = NULL;
#endif
}

static struct mm_struct *mm_init(struct mm_struct *mm, struct task_struct *p)
{
	atomic_set(&mm->mm_users, 1);
	atomic_set(&mm->mm_count, 1);
	init_rwsem(&mm->mmap_sem);
	INIT_LIST_HEAD(&mm->mmlist);
	mm->flags = (current->mm) ?
		(current->mm->flags & MMF_INIT_MASK) : default_dump_filter;
	mm->core_state = NULL;
	atomic_long_set(&mm->nr_ptes, 0);
	memset(&mm->rss_stat, 0, sizeof(mm->rss_stat));
	spin_lock_init(&mm->page_table_lock);
	mm_init_aio(mm);
	mm_init_owner(mm, p);
	clear_tlb_flush_pending(mm);

	if (likely(!mm_alloc_pgd(mm))) {
		mm->def_flags = 0;
		mmu_notifier_mm_init(mm);
		return mm;
	}

	free_mm(mm);
	return NULL;
}

static void check_mm(struct mm_struct *mm)
{
	int i;

	for (i = 0; i < NR_MM_COUNTERS; i++) {
		long x = atomic_long_read(&mm->rss_stat.count[i]);

		if (unlikely(x))
			printk(KERN_ALERT "BUG: Bad rss-counter state "
					"mm:%p idx:%d val:%ld\n", mm, i, x);
	}

#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS
	VM_BUG_ON(mm->pmd_huge_pte);
#endif
}

/*
 * Allocate and initialize an mm_struct.
 */
struct mm_struct *mm_alloc(void)
{
	struct mm_struct *mm;

	mm = allocate_mm();
	if (!mm)
		return NULL;

	memset(mm, 0, sizeof(*mm));
	mm_init_cpumask(mm);
	return mm_init(mm, current);
}

/*
 * Called when the last reference to the mm
 * is dropped: either by a lazy thread or by
 * mmput. Free the page directory and the mm.
 */
void __mmdrop(struct mm_struct *mm)
{
	BUG_ON(mm == &init_mm);
	mm_free_pgd(mm);
	destroy_context(mm);
	mmu_notifier_mm_destroy(mm);
	check_mm(mm);
	free_mm(mm);
}
EXPORT_SYMBOL_GPL(__mmdrop);

/*
 * Decrement the use count and release all resources for an mm.
 */
void mmput(struct mm_struct *mm)
{
	might_sleep();

	if (atomic_dec_and_test(&mm->mm_users)) {
		uprobe_clear_state(mm);
		exit_aio(mm);
		ksm_exit(mm);
		khugepaged_exit(mm); /* must run before exit_mmap */
		exit_mmap(mm);
		set_mm_exe_file(mm, NULL);
		if (!list_empty(&mm->mmlist)) {
			spin_lock(&mmlist_lock);
			list_del(&mm->mmlist);
			spin_unlock(&mmlist_lock);
		}
		if (mm->binfmt)
			module_put(mm->binfmt->module);
		mmdrop(mm);
	}
}
EXPORT_SYMBOL_GPL(mmput);

void set_mm_exe_file(struct mm_struct *mm, struct file *new_exe_file)
{
	if (new_exe_file)
		get_file(new_exe_file);
	if (mm->exe_file)
		fput(mm->exe_file);
	mm->exe_file = new_exe_file;
}

struct file *get_mm_exe_file(struct mm_struct *mm)
{
	struct file *exe_file;

	/* We need mmap_sem to protect against races with removal of exe_file */
	down_read(&mm->mmap_sem);
	exe_file = mm->exe_file;
	if (exe_file)
		get_file(exe_file);
	up_read(&mm->mmap_sem);
	return exe_file;
}

static void dup_mm_exe_file(struct mm_struct *oldmm, struct mm_struct *newmm)
{
	/* It's safe to write the exe_file pointer without exe_file_lock because
	 * this is called during fork when the task is not yet in /proc */
	newmm->exe_file = get_mm_exe_file(oldmm);
}

/**
 * get_task_mm - acquire a reference to the task's mm
 *
 * Returns %NULL if the task has no mm.  Checks PF_KTHREAD (meaning
 * this kernel workthread has transiently adopted a user mm with use_mm,
 * to do its AIO) is not set and if so returns a reference to it, after
 * bumping up the use count.  User must release the mm via mmput()
 * after use.  Typically used by /proc and ptrace.
 */
struct mm_struct *get_task_mm(struct task_struct *task)
{
	struct mm_struct *mm;

	task_lock(task);
	mm = task->mm;
	if (mm) {
		if (task->flags & PF_KTHREAD)
			mm = NULL;
		else
			atomic_inc(&mm->mm_users);
	}
	task_unlock(task);
	return mm;
}
EXPORT_SYMBOL_GPL(get_task_mm);

struct mm_struct *mm_access(struct task_struct *task, unsigned int mode)
{
	struct mm_struct *mm;
	int err;

	err =  mutex_lock_killable(&task->signal->cred_guard_mutex);
	if (err)
		return ERR_PTR(err);

	mm = get_task_mm(task);
	if (mm && mm != current->mm &&
			!ptrace_may_access(task, mode)) {
		mmput(mm);
		mm = ERR_PTR(-EACCES);
	}
	mutex_unlock(&task->signal->cred_guard_mutex);

	return mm;
}

static void complete_vfork_done(struct task_struct *tsk)
{
	struct completion *vfork;

	task_lock(tsk);
	vfork = tsk->vfork_done;
	if (likely(vfork)) {
		tsk->vfork_done = NULL;
		complete(vfork);
	}
	task_unlock(tsk);
}

static int wait_for_vfork_done(struct task_struct *child,
		struct completion *vfork)
{
	int killed;

	freezer_do_not_count();
	killed = wait_for_completion_killable(vfork);
	freezer_count();

	if (killed) {
		task_lock(child);
		child->vfork_done = NULL;
		task_unlock(child);
	}

	put_task_struct(child);
	return killed;
}

/* Please note the differences between mmput and mm_release.
 * mmput is called whenever we stop holding onto a mm_struct,
 * error success whatever.
 *
 * mm_release is called after a mm_struct has been removed
 * from the current process.
 *
 * This difference is important for error handling, when we
 * only half set up a mm_struct for a new process and need to restore
 * the old one.  Because we mmput the new mm_struct before
 * restoring the old one. . .
 * Eric Biederman 10 January 1998
 */
void mm_release(struct task_struct *tsk, struct mm_struct *mm)
{
	/* Get rid of any futexes when releasing the mm */
#ifdef CONFIG_FUTEX
	if (unlikely(tsk->robust_list)) {
		exit_robust_list(tsk);
		tsk->robust_list = NULL;
	}
#ifdef CONFIG_COMPAT
	if (unlikely(tsk->compat_robust_list)) {
		compat_exit_robust_list(tsk);
		tsk->compat_robust_list = NULL;
	}
#endif
	if (unlikely(!list_empty(&tsk->pi_state_list)))
		exit_pi_state_list(tsk);
#endif

	uprobe_free_utask(tsk);

	/* Get rid of any cached register state */
	deactivate_mm(tsk, mm);

	/*
	 * If we're exiting normally, clear a user-space tid field if
	 * requested.  We leave this alone when dying by signal, to leave
	 * the value intact in a core dump, and to save the unnecessary
	 * trouble, say, a killed vfork parent shouldn't touch this mm.
	 * Userland only wants this done for a sys_exit.
	 */
	if (tsk->clear_child_tid) {
		if (!(tsk->flags & PF_SIGNALED) &&
				atomic_read(&mm->mm_users) > 1) {
			/*
			 * We don't check the error code - if userspace has
			 * not set up a proper pointer then tough luck.
			 */
			put_user(0, tsk->clear_child_tid);
			sys_futex(tsk->clear_child_tid, FUTEX_WAKE,
					1, NULL, NULL, 0);
		}
		tsk->clear_child_tid = NULL;
	}

	/*
	 * All done, finally we can wake up parent and return this mm to him.
	 * Also kthread_stop() uses this completion for synchronization.
	 */
	if (tsk->vfork_done)
		complete_vfork_done(tsk);
}

/*
 * Allocate a new mm structure and copy contents from the
 * mm structure of the passed in task structure.
 */
struct mm_struct *dup_mm(struct task_struct *tsk)
{
	struct mm_struct *mm, *oldmm = current->mm;
	int err;

	if (!oldmm)
		return NULL;

	mm = allocate_mm();
	if (!mm)
		goto fail_nomem;

	memcpy(mm, oldmm, sizeof(*mm));
	mm_init_cpumask(mm);

#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS
	mm->pmd_huge_pte = NULL;
#endif
	if (!mm_init(mm, tsk))
		goto fail_nomem;

	if (init_new_context(tsk, mm))
		goto fail_nocontext;

	dup_mm_exe_file(oldmm, mm);

	err = dup_mmap(mm, oldmm);
	if (err)
		goto free_pt;

	mm->hiwater_rss = get_mm_rss(mm);
	mm->hiwater_vm = mm->total_vm;

	if (mm->binfmt && !try_module_get(mm->binfmt->module))
		goto free_pt;

	return mm;

free_pt:
	/* don't put binfmt in mmput, we haven't got module yet */
	mm->binfmt = NULL;
	mmput(mm);

fail_nomem:
	return NULL;

fail_nocontext:
	/*
	 * If init_new_context() failed, we cannot use mmput() to free the mm
	 * because it calls destroy_context()
	 */
	mm_free_pgd(mm);
	free_mm(mm);
	return NULL;
}

// ARM10C 20161105
// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
// ARM10C 20170610
// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
static int copy_mm(unsigned long clone_flags, struct task_struct *tsk)
{
	struct mm_struct *mm, *oldmm;
	int retval;

	// tsk->min_flt: (kmem_cache#15-oX (struct task_struct))->min_flt
	// tsk->maj_flt: (kmem_cache#15-oX (struct task_struct))->maj_flt
	tsk->min_flt = tsk->maj_flt = 0;
	// tsk->min_flt: (kmem_cache#15-oX (struct task_struct))->min_flt: 0
	// tsk->maj_flt: (kmem_cache#15-oX (struct task_struct))->maj_flt: 0

	// tsk->nvcsw: (kmem_cache#15-oX (struct task_struct))->nvcsw
	// tsk->nivcsw: (kmem_cache#15-oX (struct task_struct))->nivcsw
	tsk->nvcsw = tsk->nivcsw = 0;
	// tsk->nvcsw: (kmem_cache#15-oX (struct task_struct))->nvcsw: 0
	// tsk->nivcsw: (kmem_cache#15-oX (struct task_struct))->nivcsw: 0

#ifdef CONFIG_DETECT_HUNG_TASK // CONFIG_DETECT_HUNG_TASK=y
	// tsk->nvcsw: (kmem_cache#15-oX (struct task_struct))->nvcsw: 0
	// tsk->nivcsw: (kmem_cache#15-oX (struct task_struct))->nivcsw: 0
	tsk->last_switch_count = tsk->nvcsw + tsk->nivcsw;
	// tsk->last_switch_count: (kmem_cache#15-oX (struct task_struct))->last_switch_count: 0
#endif

	// tsk->mm: (kmem_cache#15-oX (struct task_struct))->mm
	tsk->mm = NULL;
	// tsk->mm: (kmem_cache#15-oX (struct task_struct))->mm: NULL

	// tsk->active_mm: (kmem_cache#15-oX (struct task_struct))->active_mm
	tsk->active_mm = NULL;
	// tsk->active_mm: (kmem_cache#15-oX (struct task_struct))->active_mm: NULL

	/*
	 * Are we cloning a kernel thread?
	 *
	 * We need to steal a active VM for that..
	 */
	// current->mm: (&init_task)->mm: NULL
	oldmm = current->mm;
	// oldmm: NULL

	// oldmm: NULL
	if (!oldmm)
		return 0;
		// return 0

	if (clone_flags & CLONE_VM) {
		atomic_inc(&oldmm->mm_users);
		mm = oldmm;
		goto good_mm;
	}

	retval = -ENOMEM;
	mm = dup_mm(tsk);
	if (!mm)
		goto fail_nomem;

good_mm:
	tsk->mm = mm;
	tsk->active_mm = mm;
	return 0;

fail_nomem:
	return retval;
}

// ARM10C 20161105
// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
// ARM10C 20170524
// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
static int copy_fs(unsigned long clone_flags, struct task_struct *tsk)
{
	// current->fs: (&init_task)->fs: &init_fs
	// current->fs: (&init_task)->fs: &init_fs
	struct fs_struct *fs = current->fs;
	// fs: &init_fs
	// fs: &init_fs

	// clone_flags: 0x00800B00, CLONE_FS: 0x00000200
	// clone_flags: 0x00800700, CLONE_FS: 0x00000200
	if (clone_flags & CLONE_FS) {
		/* tsk->fs is already what we want */
		// &fs->lock: &(&init_fs)->lock
		// &fs->lock: &(&init_fs)->lock
		spin_lock(&fs->lock);

		// spin_lock 에서 한일:
		// &(&init_fs)->lock 을 사용하여 spin lock 을 수행

		// spin_lock 에서 한일:
		// &(&init_fs)->lock 을 사용하여 spin lock 을 수행

		// fs->in_exec: (&init_fs)->in_exec: 0
		// fs->in_exec: (&init_fs)->in_exec: 0
		if (fs->in_exec) {
			spin_unlock(&fs->lock);
			return -EAGAIN;
		}
		// fs->users: (&init_fs)->users: 1
		// fs->users: (&init_fs)->users: 2
		fs->users++;
		// fs->users: (&init_fs)->users: 2
		// fs->users: (&init_fs)->users: 3

		// &fs->lock: &(&init_fs)->lock
		// &fs->lock: &(&init_fs)->lock
		spin_unlock(&fs->lock);

		// spin_unlock 에서 한일:
		// &(&init_fs)->lock 을 사용하여 spin unlock 을 수행

		// spin_unlock 에서 한일:
		// &(&init_fs)->lock 을 사용하여 spin unlock 을 수행

		return 0;
		// return 0
		// return 0
	}
	tsk->fs = copy_fs_struct(fs);
	if (!tsk->fs)
		return -ENOMEM;
	return 0;
}

// ARM10C 20161029
// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
// ARM10C 20170524
// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
static int copy_files(unsigned long clone_flags, struct task_struct *tsk)
{
	struct files_struct *oldf, *newf;
	int error = 0;
	// error: 0
	// error: 0

	/*
	 * A background process may not have any files ...
	 */
	// current->files: (&init_task)->files: &init_files
	// current->files: (&init_task)->files: &init_files
	oldf = current->files;
	// oldf: &init_files
	// oldf: &init_files

	// oldf: &init_files
	// oldf: &init_files
	if (!oldf)
		goto out;

	// clone_flags: 0x00800B00, CLONE_FILES: 0x00000400
	// clone_flags: 0x00800700, CLONE_FILES: 0x00000400
	if (clone_flags & CLONE_FILES) {
		// &oldf->count: &(&init_files)->count
		atomic_inc(&oldf->count);

		// atomic_inc 에서 한일:
		// (&(&init_files)->count)->counter: 2

		goto out;
		// goto out
	}

	// oldf: &init_files, dup_fd(&init_files, &error): kmem_cache#12-oX (struct files_struct)
	newf = dup_fd(oldf, &error);
	// newf: kmem_cache#12-oX (struct files_struct)

	// dup_fd 에서 한일:
	// error: -12
	//
	// files_cachep: kmem_cache#12 을 사용하여 struct files_struct 을 위한 메모리를 할당함
	// kmem_cache#12-oX (struct files_struct)
	//
	// (kmem_cache#12-oX (struct files_struct))->count: 1
	//
	// &(kmem_cache#12-oX (struct files_struct))->file_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->owner_cpu: 0xffffffff
	//
	// (kmem_cache#12-oX (struct files_struct))->next_fd: 0
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->max_fds: 32
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->close_on_exec: (kmem_cache#12-oX (struct files_struct))->close_on_exec_init
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->open_fds: (kmem_cache#12-oX (struct files_struct))->open_fds_init
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->fd: &(kmem_cache#12-oX (struct files_struct))->fd_array[0]
	//
	// &(&init_files)->file_lock 을 사용하여 spin lock 수행
	//
	// (kmem_cache#12-oX (struct files_struct))->open_fds_init 에 init_files.open_fds_init 값을 복사
	// (kmem_cache#12-oX (struct files_struct))->open_fds_init: NULL
	// (kmem_cache#12-oX (struct files_struct))->close_on_exec_init 에 init_files.close_on_exec_init 값을 복사
	// (kmem_cache#12-oX (struct files_struct))->close_on_exec_init: NULL
	//
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->open_fds 의 0~31 bit 를 clear 함
	// (kmem_cache#12-oX (struct files_struct))->fd_array[0...31]: NULL
	// &(kmem_cache#12-oX (struct files_struct))->fd_array[0] 에 값을 size 0 만큼 0 으로 set 함
	//
	// (kmem_cache#12-oX (struct files_struct))->fdt: &(kmem_cache#12-oX (struct files_struct))->fdtab

	// newf: kmem_cache#12-oX (struct files_struct)
	if (!newf)
		goto out;

	// tsk->files: (kmem_cache#15-oX (struct task_struct))->files, newf: kmem_cache#12-oX (struct files_struct)
	tsk->files = newf;
	// tsk->files: (kmem_cache#15-oX (struct task_struct))->files: kmem_cache#12-oX (struct files_struct)

	error = 0;
	// error: 0
out:
	// error: 0
	// error: 0
	return error;
	// return 0
	// return 0
}

// ARM10C 20161105
// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
// ARM10C 20170610
// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
static int copy_io(unsigned long clone_flags, struct task_struct *tsk)
{
#ifdef CONFIG_BLOCK // CONFIG_BLOCK=y
	// current->io_context: (&init_task)->io_context: NULL
	struct io_context *ioc = current->io_context;
	// ioc: NULL

	struct io_context *new_ioc;

	// ioc: NULL
	if (!ioc)
		return 0;
		// return 0
	/*
	 * Share io context with parent, if CLONE_IO is set
	 */
	if (clone_flags & CLONE_IO) {
		ioc_task_link(ioc);
		tsk->io_context = ioc;
	} else if (ioprio_valid(ioc->ioprio)) {
		new_ioc = get_task_io_context(tsk, GFP_KERNEL, NUMA_NO_NODE);
		if (unlikely(!new_ioc))
			return -ENOMEM;

		new_ioc->ioprio = ioc->ioprio;
		put_io_context(new_ioc);
	}
#endif
	return 0;
}

// ARM10C 20161105
// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
// ARM10C 20170524
// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
static int copy_sighand(unsigned long clone_flags, struct task_struct *tsk)
{
	struct sighand_struct *sig;

	// clone_flags: 0x00800B00, CLONE_SIGHAND: 0x00000800
	// clone_flags: 0x00800700, CLONE_SIGHAND: 0x00000800
	if (clone_flags & CLONE_SIGHAND) {
		// current->sighand: (&init_task)->sighand: &init_sighand,
		// &current->sighand->count: &(&init_sighand)->count
		atomic_inc(&current->sighand->count);

		// atomic_inc 에서 한일:
		// (&init_sighand)->count: { (2) }

		return 0;
		// return 0
	}

	// sighand_cachep: kmem_cache#14, GFP_KERNEL: 0xD0
	// kmem_cache_alloc(kmem_cache#14, 0xD0): kmem_cache#14-oX (struct sighand_struct)
	sig = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);
	// sig: kmem_cache#14-oX (struct sighand_struct)

	// tsk->sighand: (kmem_cache#15-oX (struct task_struct))->sighand,
	// sig: kmem_cache#14-oX (struct sighand_struct)
	rcu_assign_pointer(tsk->sighand, sig);

	// rcu_assign_pointer 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->sighand: kmem_cache#14-oX (struct sighand_struct)

	// sig: kmem_cache#14-oX (struct sighand_struct)
	if (!sig)
		return -ENOMEM;

	// &sig->count: &(kmem_cache#14-oX (struct sighand_struct))->count
	atomic_set(&sig->count, 1);

	// atomic_set에서 한일:
	// (&(kmem_cache#14-oX (struct sighand_struct))->count)->counter: 1

	// sig->action: (kmem_cache#14-oX (struct sighand_struct))->action,
	// current->sighand: (&init_task)->sighand: &init_sighand
	// current->sighand->action: (&init_sighand)->action,
	// sizeof((&init_sighand)->action): 1280 bytes
	memcpy(sig->action, current->sighand->action, sizeof(sig->action));

	// memcpy 에서 한일:
	// (&init_sighand)->action 의 값을 (kmem_cache#14-oX (struct sighand_struct))->action 에 복사함

	return 0;
	// return 0
}

void __cleanup_sighand(struct sighand_struct *sighand)
{
	if (atomic_dec_and_test(&sighand->count)) {
		signalfd_cleanup(sighand);
		kmem_cache_free(sighand_cachep, sighand);
	}
}


/*
 * Initialize POSIX timer handling for a thread group.
 */
// ARM10C 20161105
// sig: kmem_cache#13-oX (struct signal_struct)
static void posix_cpu_timers_init_group(struct signal_struct *sig)
{
	unsigned long cpu_limit;

	/* Thread group counters. */
	// sig: kmem_cache#13-oX (struct signal_struct)
	thread_group_cputime_init(sig);

	// thread_group_cputime_init 에서 한일:
	// &(kmem_cache#13-oX (struct signal_struct))->cputimer.lock 을 사용한 spinlock 초기화 수행

	// RLIMIT_CPU: 0
	// sig->rlim[0].rlim_cur: (kmem_cache#13-oX (struct signal_struct))->rlim[0].rlim_cur,
	// ACCESS_ONCE((kmem_cache#13-oX (struct signal_struct))->rlim[0].rlim_cur): 0xFFFFFFFF
	cpu_limit = ACCESS_ONCE(sig->rlim[RLIMIT_CPU].rlim_cur);
	// cpu_limit: 0xFFFFFFFF

	// cpu_limit: 0xFFFFFFFF, RLIM_INFINITY: 0xFFFFFFFF
	if (cpu_limit != RLIM_INFINITY) {
		sig->cputime_expires.prof_exp = secs_to_cputime(cpu_limit);
		sig->cputimer.running = 1;
	}

	/* The timer lists. */
	// &sig->cpu_timers[0]): &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	INIT_LIST_HEAD(&sig->cpu_timers[0]);

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]

	// &sig->cpu_timers[1]): &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	INIT_LIST_HEAD(&sig->cpu_timers[1]);

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]

	// &sig->cpu_timers[2]): &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	INIT_LIST_HEAD(&sig->cpu_timers[2]);

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
}

// ARM10C 20161105
// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
// ARM10C 20170610
// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
static int copy_signal(unsigned long clone_flags, struct task_struct *tsk)
{
	struct signal_struct *sig;

	// clone_flags: 0x00800B00, CLONE_THREAD: 0x00010000
	if (clone_flags & CLONE_THREAD)
		return 0;

	// signal_cachep: kmem_cache#13, GFP_KERNEL: 0xD0
	// kmem_cache_zalloc(kmem_cache#13, 0xD0): kmem_cache#13-oX (struct signal_struct)
	sig = kmem_cache_zalloc(signal_cachep, GFP_KERNEL);
	// sig: kmem_cache#13-oX (struct signal_struct)

	// tsk->signal: (kmem_cache#15-oX (struct task_struct))->signal,
	// sig: kmem_cache#13-oX (struct signal_struct)
	tsk->signal = sig;
	// tsk->signal: (kmem_cache#15-oX (struct task_struct))->signal: kmem_cache#13-oX (struct signal_struct)

	// sig: kmem_cache#13-oX (struct signal_struct)
	if (!sig)
		return -ENOMEM;

	// sig->nr_threads: (kmem_cache#13-oX (struct signal_struct))->nr_threads
	sig->nr_threads = 1;
	// sig->nr_threads: (kmem_cache#13-oX (struct signal_struct))->nr_threads: 1

	// &sig->live: &(kmem_cache#13-oX (struct signal_struct))->live
	atomic_set(&sig->live, 1);

	// atomic_set 에서 한일:
	// (kmem_cache#13-oX (struct signal_struct))->live: { (1) }

	// &sig->sigcnt: &(kmem_cache#13-oX (struct signal_struct))->sigcnt
	atomic_set(&sig->sigcnt, 1);

	// atomic_set 에서 한일:
	// (kmem_cache#13-oX (struct signal_struct))->sigcnt: { (1) }

	// &sig->wait_chldexit: &(kmem_cache#13-oX (struct signal_struct))->wait_chldexit
	init_waitqueue_head(&sig->wait_chldexit);

	// init_waitqueue_head에서 한일:
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->task_list를 사용한 list 초기화

	// sig->curr_target: (kmem_cache#13-oX (struct signal_struct))->curr_target, tsk: kmem_cache#15-oX (struct task_struct)
	sig->curr_target = tsk;
	// sig->curr_target: (kmem_cache#13-oX (struct signal_struct))->curr_target: kmem_cache#15-oX (struct task_struct)

	// &sig->shared_pending: &(kmem_cache#13-oX (struct signal_struct))->shared_pending
	init_sigpending(&sig->shared_pending);

	// init_sigpending 에서 한일:
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list

	// &sig->posix_timers: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	INIT_LIST_HEAD(&sig->posix_timers);

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->next: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->prev: &(kmem_cache#13-oX (struct signal_struct))->posix_timers

	// &sig->real_timer: &(kmem_cache#13-oX (struct signal_struct))->real_timer, CLOCK_MONOTONIC: 1, HRTIMER_MODE_REL: 1
	hrtimer_init(&sig->real_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);

	// hrtimer_init에서 한일:
	// (kmem_cache#13-oX (struct signal_struct))->real_timer의 값을 0으로 초기화
	// (&(kmem_cache#13-oX (struct signal_struct))->real_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// RB Tree의 &(&(kmem_cache#13-oX (struct signal_struct))->real_timer)->node 를 초기화

	// sig->real_timer.function: (kmem_cache#13-oX (struct signal_struct))->real_timer.function
	sig->real_timer.function = it_real_fn;
	// sig->real_timer.function: (kmem_cache#13-oX (struct signal_struct))->real_timer.function: it_real_fn

	// current->group_leader: (&init_task)->group_leader: &init_task
	task_lock(current->group_leader);

	// task_lock 에서 한일:
	// &(&init_task)->alloc_lock 을 사용하여 spin lock 수행

	// sig->rlim: (kmem_cache#13-oX (struct signal_struct))->rlim
	// current->signal: (&init_task)->signal: &init_signals,
	// current->signal->rlim: (&init_signals)->rlim,
	// sizeof((struct rlimit) * 16): 128 bytes
	memcpy(sig->rlim, current->signal->rlim, sizeof sig->rlim);

	// memcpy 에서 한일:
	// (kmem_cache#13-oX (struct signal_struct))->rlim 에 (&init_signals)->rlim 값을 전부 복사함

	// current->group_leader: (&init_task)->group_leader: &init_task
	task_unlock(current->group_leader);

	// task_unlock 에서 한일:
	// &(&init_task)->alloc_lock 을 사용하여 spin unlock 수행

	// sig: kmem_cache#13-oX (struct signal_struct)
	posix_cpu_timers_init_group(sig);

	// posix_cpu_timers_init_group 에서 한일:
	// &(kmem_cache#13-oX (struct signal_struct))->cputimer.lock 을 사용한 spinlock 초기화 수행
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]

	// sig: kmem_cache#13-oX (struct signal_struct)
	tty_audit_fork(sig); // null function

	// sig: kmem_cache#13-oX (struct signal_struct)
	sched_autogroup_fork(sig); // null function

#ifdef CONFIG_CGROUPS // CONFIG_CGROUPS=y
	// &sig->group_rwsem: &(kmem_cache#13-oX (struct signal_struct))->group_rwsem
	init_rwsem(&sig->group_rwsem);

	// init_rwsem에서 한일:
	// (&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->activity: 0
	// &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_lock을 사용한 spinlock 초기화
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
#endif

	// sig->oom_score_adj: (kmem_cache#13-oX (struct signal_struct))->oom_score_adj,
	// current->signal: (&init_task)->signal: &init_signals,
	// current->signal->oom_score_adj: (&init_signals)->oom_score_adj: 0
	sig->oom_score_adj = current->signal->oom_score_adj;
	// sig->oom_score_adj: (kmem_cache#13-oX (struct signal_struct))->oom_score_adj: 0

	// sig->oom_score_adj_min: (kmem_cache#13-oX (struct signal_struct))->oom_score_adj_min,
	// current->signal: (&init_task)->signal: &init_signals,
	// current->signal->oom_score_adj_min: (&init_signals)->oom_score_adj_min: 0
	sig->oom_score_adj_min = current->signal->oom_score_adj_min;
	// sig->oom_score_adj_min: (kmem_cache#13-oX (struct signal_struct))->oom_score_adj_min: 0

	// sig->has_child_subreaper: (kmem_cache#13-oX (struct signal_struct))->has_child_subreaper,
	// current->signal: (&init_task)->signal: &init_signals,
	// current->signal->has_child_subreaper: (&init_signals)->has_child_subreaper: 0,
	// current->signal->is_child_subreaper: (&init_signals)->is_child_subreaper: 0
	sig->has_child_subreaper = current->signal->has_child_subreaper ||
		current->signal->is_child_subreaper;
	// sig->has_child_subreaper: (kmem_cache#13-oX (struct signal_struct))->has_child_subreaper: 0

	// &sig->cred_guard_mutex: &(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex
	mutex_init(&sig->cred_guard_mutex);

	// mutex_init에서 한일:
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->count: 1
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->onwer: NULL
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->magic: &(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex

	return 0;
	// return 0
}

// ARM10C 20160910
// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
// ARM10C 20170524
// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
static void copy_flags(unsigned long clone_flags, struct task_struct *p)
{
	// p->flags: (kmem_cache#15-oX (struct task_struct))->flags: 0x00200000
	unsigned long new_flags = p->flags;
	// new_flags: 0x00200000

	// new_flags: 0x00200000, PF_SUPERPRIV: 0x00000100, PF_WQ_WORKER: 0x00000020
	new_flags &= ~(PF_SUPERPRIV | PF_WQ_WORKER);
	// new_flags: 0x00200000

	// new_flags: 0x00200000, PF_FORKNOEXEC: 0x00000040
	new_flags |= PF_FORKNOEXEC;
	// new_flags: 0x00200040

	// p->flags: (kmem_cache#15-oX (struct task_struct))->flags: 0x00200000, new_flags: 0x00200040
	p->flags = new_flags;
	// p->flags: (kmem_cache#15-oX (struct task_struct))->flags: 0x00200040
}

SYSCALL_DEFINE1(set_tid_address, int __user *, tidptr)
{
	current->clear_child_tid = tidptr;

	return task_pid_vnr(current);
}

// ARM10C 20160903
// p: kmem_cache#15-oX (struct task_struct)
// ARM10C 20170524
// p: kmem_cache#15-oX (struct task_struct)
static void rt_mutex_init_task(struct task_struct *p)
{
	// &p->pi_lock: &(kmem_cache#15-oX (struct task_struct))->pi_lock
	raw_spin_lock_init(&p->pi_lock);

	// raw_spin_lock_init에서 한일:
	// &(kmem_cache#15-oX (struct task_struct))->pi_lock을 사용한 spinlock 초기화

#ifdef CONFIG_RT_MUTEXES // CONFIG_RT_MUTEXES=y
	// &p->pi_waiters: &(kmem_cache#15-oX (struct task_struct))->pi_waiters
	plist_head_init(&p->pi_waiters);

	// plist_head_init 에서 한일:
	// &(kmem_cache#15-oX (struct task_struct))->pi_waiters 리스트 초기화

	// p->pi_blocked_on: (kmem_cache#15-oX (struct task_struct))->pi_blocked_on
	p->pi_blocked_on = NULL;
	// p->pi_blocked_on: (kmem_cache#15-oX (struct task_struct))->pi_blocked_on: NULL
#endif
}

#ifdef CONFIG_MM_OWNER
void mm_init_owner(struct mm_struct *mm, struct task_struct *p)
{
	mm->owner = p;
}
#endif /* CONFIG_MM_OWNER */

/*
 * Initialize POSIX timer handling for a single task.
 */
// ARM10C 20160910
// p: kmem_cache#15-oX (struct task_struct)
// ARM10C 20170524
// p: kmem_cache#15-oX (struct task_struct)
static void posix_cpu_timers_init(struct task_struct *tsk)
{
	// tsk->cputime_expires.prof_exp: (kmem_cache#15-oX (struct task_struct))->cputime_expires.prof_exp
	tsk->cputime_expires.prof_exp = 0;
	// tsk->cputime_expires.prof_exp: (kmem_cache#15-oX (struct task_struct))->cputime_expires.prof_exp: 0

	// tsk->cputime_expires.virt_exp: (kmem_cache#15-oX (struct task_struct))->cputime_expires.virt_exp
	tsk->cputime_expires.virt_exp = 0;
	// tsk->cputime_expires.virt_exp: (kmem_cache#15-oX (struct task_struct))->cputime_expires.virt_exp: 0

	// tsk->cputime_expires.sched_exp: (kmem_cache#15-oX (struct task_struct))->cputime_expires.sched_exp
	tsk->cputime_expires.sched_exp = 0;
	// tsk->cputime_expires.sched_exp: (kmem_cache#15-oX (struct task_struct))->cputime_expires.sched_exp: 0

	// &tsk->cpu_timers[0]: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	INIT_LIST_HEAD(&tsk->cpu_timers[0]);

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]

	// &tsk->cpu_timers[1]: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	INIT_LIST_HEAD(&tsk->cpu_timers[1]);

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]

	// &tsk->cpu_timers[2]: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	INIT_LIST_HEAD(&tsk->cpu_timers[2]);

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
}

// ARM10C 20161203
// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PID: 0, pid: kmem_cache#19-oX (struct pid)
// ARM10C 20161203
// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PGID: 1, task_pgrp(&init_task): &init_struct_pid
// ARM10C 20161203
// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_SID: 2, task_session(&init_task): &init_struct_pid
// ARM10C 20170610
// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PGID: 1, task_pgrp(&init_task): &init_struct_pid
static inline void
init_task_pid(struct task_struct *task, enum pid_type type, struct pid *pid)
{
	// type: 0, task->pids[0].pid: (kmem_cache#15-oX (struct task_struct))->pids[0].pid
	// pid: kmem_cache#19-oX (struct pid)
	// type: 1, task->pids[1].pid: (kmem_cache#15-oX (struct task_struct))->pids[1].pid
	// pid: &init_struct_pid
	// type: 2, task->pids[1].pid: (kmem_cache#15-oX (struct task_struct))->pids[2].pid
	// pid: &init_struct_pid
	task->pids[type].pid = pid;
	// task->pids[0].pid: (kmem_cache#15-oX (struct task_struct))->pids[0].pid: kmem_cache#19-oX (struct pid)
	// task->pids[1].pid: (kmem_cache#15-oX (struct task_struct))->pids[1].pid: &init_struct_pid
	// task->pids[2].pid: (kmem_cache#15-oX (struct task_struct))->pids[1].pid: &init_struct_pid
}

/*
 * This creates a new process as a copy of the old one,
 * but does not actually start it yet.
 *
 * It copies the registers, and all the appropriate
 * parts of the process environment (as per the clone
 * flags). The actual kick-off is left to the caller.
 */
// ARM10C 20160827
// clone_flags: 0x00800B00, stack_start: kernel_init, stack_size: 0, child_tidptr: 0, NULL, trace: 0
// ARM10C 20170524
// clone_flags: 0x00800700, stack_start: kthreadd, stack_size: 0, child_tidptr: 0, trace: 0
static struct task_struct *copy_process(unsigned long clone_flags,
		unsigned long stack_start,
		unsigned long stack_size,
		int __user *child_tidptr,
		struct pid *pid,
		int trace)
{
	int retval;
	struct task_struct *p;

	// clone_flags: 0x00800B00, CLONE_NEWNS: 0x00020000, CLONE_FS: 0x00000200
	// clone_flags: 0x00800700, CLONE_NEWNS: 0x00020000, CLONE_FS: 0x00000200
	if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))
		return ERR_PTR(-EINVAL);

	// clone_flags: 0x00800B00, CLONE_NEWUSER: 0x10000000, CLONE_FS: 0x00000200
	// clone_flags: 0x00800700, CLONE_NEWUSER: 0x10000000, CLONE_FS: 0x00000200
	if ((clone_flags & (CLONE_NEWUSER|CLONE_FS)) == (CLONE_NEWUSER|CLONE_FS))
		return ERR_PTR(-EINVAL);

	/*
	 * Thread groups must share signals as well, and detached threads
	 * can only be started up within the thread group.
	 */
	// clone_flags: 0x00800B00, CLONE_THREAD: 0x00010000, CLONE_SIGHAND: 0x00000800
	// clone_flags: 0x00800700, CLONE_THREAD: 0x00010000, CLONE_SIGHAND: 0x00000800
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
		return ERR_PTR(-EINVAL);

	/*
	 * Shared signal handlers imply shared VM. By way of the above,
	 * thread groups also imply shared VM. Blocking this case allows
	 * for various simplifications in other code.
	 */
	// clone_flags: 0x00800B00, CLONE_SIGHAND: 0x00000800, CLONE_VM: 0x00000100
	// clone_flags: 0x00800700, CLONE_SIGHAND: 0x00000800, CLONE_VM: 0x00000100
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
		return ERR_PTR(-EINVAL);

// 2016/08/27 종료
// 2016/09/03 시작

	/*
	 * Siblings of global init remain as zombies on exit since they are
	 * not reaped by their parent (swapper). To solve this and to avoid
	 * multi-rooted process trees, prevent global and container-inits
	 * from creating siblings.
	 */
	// clone_flags: 0x00800B00, CLONE_PARENT: 0x00008000, SIGNAL_UNKILLABLE: 0x00000040
	// current: &init_task, current->signal: &init_signals
	// current->signal->flags: (&init_signals)->flags: 0
	// clone_flags: 0x00800700, CLONE_PARENT: 0x00008000, SIGNAL_UNKILLABLE: 0x00000040
	// current: &init_task, current->signal: &init_signals
	// current->signal->flags: (&init_signals)->flags: 0
	if ((clone_flags & CLONE_PARENT) &&
			current->signal->flags & SIGNAL_UNKILLABLE)
		return ERR_PTR(-EINVAL);

	/*
	 * If the new process will be in a different pid or user namespace
	 * do not allow it to share a thread group or signal handlers or
	 * parent with the forking task.
	 */
	// clone_flags: 0x00800B00, CLONE_SIGHAND: 0x00000800
	// clone_flags: 0x00800700, CLONE_SIGHAND: 0x00000800
	if (clone_flags & CLONE_SIGHAND) {
		// clone_flags: 0x00800B00, CLONE_NEWUSER: 0x10000000, CLONE_NEWPID: 0x20000000
		// current: &init_task, task_active_pid_ns(&init_task): &init_pid_ns,
		// current->nsproxy: (&init_task)->nsproxy: &init_nsproxy,
		// current->nsproxy->pid_ns_for_children: (&init_nsproxy)->pid_ns_for_children: &init_pid_ns
		if ((clone_flags & (CLONE_NEWUSER | CLONE_NEWPID)) ||
				(task_active_pid_ns(current) !=
				 current->nsproxy->pid_ns_for_children))
			return ERR_PTR(-EINVAL);
	}

	// clone_flags: 0x00800B00, security_task_create(0x00800B00): 0
	// clone_flags: 0x00800700, security_task_create(0x00800700): 0
	retval = security_task_create(clone_flags);
	// retval: 0
	// retval: 0

	// retval: 0
	// retval: 0
	if (retval)
		goto fork_out;

	// ENOMEM: 12
	// ENOMEM: 12
	retval = -ENOMEM;
	// retval: -12
	// retval: -12

	// current: &init_task
	// dup_task_struct(&init_task): kmem_cache#15-oX (struct task_struct)
	// current: &init_task
	// dup_task_struct(&init_task): kmem_cache#15-oX (struct task_struct)
	p = dup_task_struct(current);
	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)

	// dup_task_struct 에서 한일:
	// struct task_struct 만큼의 메모리를 할당 받음
	// kmem_cache#15-oX (struct task_struct)
	//
	// struct thread_info 를 구성 하기 위한 메모리를 할당 받음 (8K)
	// 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 메모리에 init_task 값을 전부 할당함
	//
	// (kmem_cache#15-oX (struct task_struct))->stack: 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 의 stack의 값을 init_task 의 stack 값에서 전부 복사함
	// 복사된 struct thread_info 의 task 주소값을 할당 받은 kmem_cache#15-oX (struct task_struct)로 변경함
	// *(할당 받은 page 2개의 메로리의 가상 주소): init_thread_info
	// ((struct thread_info *) 할당 받은 page 2개의 메로리의 가상 주소)->task: kmem_cache#15-oX (struct task_struct)
	//
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 1 bit 값을 clear 수행
	//
	// *((unsigned long *)(할당 받은 page 2개의 메로리의 가상 주소 + 1)): 0x57AC6E9D
	//
	// (&(kmem_cache#15-oX (struct task_struct))->usage)->counter: 2
	// (kmem_cache#15-oX (struct task_struct))->splice_pipe: NULL
	// (kmem_cache#15-oX (struct task_struct))->task_frag.page: NULL
	//
	// (&contig_page_data)->node_zones[0].vm_stat[16]: 1 을 더함
	// vmstat.c의 vm_stat[16] 전역 변수에도 1을 더함

	// dup_task_struct 에서 한일:
	// struct task_struct 만큼의 메모리를 할당 받음
	// kmem_cache#15-oX (struct task_struct)
	//
	// struct thread_info 를 구성 하기 위한 메모리를 할당 받음 (8K)
	// 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 메모리에 init_task 값을 전부 할당함
	//
	// (kmem_cache#15-oX (struct task_struct))->stack: 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 의 stack의 값을 init_task 의 stack 값에서 전부 복사함
	// 복사된 struct thread_info 의 task 주소값을 할당 받은 kmem_cache#15-oX (struct task_struct)로 변경함
	// *(할당 받은 page 2개의 메로리의 가상 주소): init_thread_info
	// ((struct thread_info *) 할당 받은 page 2개의 메로리의 가상 주소)->task: kmem_cache#15-oX (struct task_struct)
	//
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 1 bit 값을 clear 수행
	//
	// *((unsigned long *)(할당 받은 page 2개의 메로리의 가상 주소 + 1)): 0x57AC6E9D
	//
	// (&(kmem_cache#15-oX (struct task_struct))->usage)->counter: 2
	// (kmem_cache#15-oX (struct task_struct))->splice_pipe: NULL
	// (kmem_cache#15-oX (struct task_struct))->task_frag.page: NULL
	//
	// (&contig_page_data)->node_zones[0].vm_stat[16]: 1 을 더함
	// vmstat.c의 vm_stat[16] 전역 변수에도 1을 더함

	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	if (!p)
		goto fork_out;

	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	ftrace_graph_init_task(p); // null function

	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	get_seccomp_filter(p); // null function

	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	rt_mutex_init_task(p);

	// rt_mutex_init_task 한일:
	// &(kmem_cache#15-oX (struct task_struct))->pi_lock을 사용한 spinlock 초기화
	// &(kmem_cache#15-oX (struct task_struct))->pi_waiters 리스트 초기화
	// (kmem_cache#15-oX (struct task_struct))->pi_blocked_on: NULL

	// rt_mutex_init_task 한일:
	// &(kmem_cache#15-oX (struct task_struct))->pi_lock을 사용한 spinlock 초기화
	// &(kmem_cache#15-oX (struct task_struct))->pi_waiters 리스트 초기화
	// (kmem_cache#15-oX (struct task_struct))->pi_blocked_on: NULL

#ifdef CONFIG_PROVE_LOCKING // CONFIG_PROVE_LOCKING=n
	DEBUG_LOCKS_WARN_ON(!p->hardirqs_enabled);
	DEBUG_LOCKS_WARN_ON(!p->softirqs_enabled);
#endif
	// EAGAIN: 11
	// EAGAIN: 11
	retval = -EAGAIN;
	// retval: -11
	// retval: -11

	// p: kmem_cache#15-oX (struct task_struct)
	// p->real_cred: (kmem_cache#15-oX (struct task_struct))->real_cred: &init_cred,
	// p->real_cred->user: (&init_cred)->user: &root_user,
	// &p->real_cred->user->processes: &(&root_user)->processes, atomic_read(&(&root_user)->processes): 1
	// RLIMIT_NPROC: 6, task_rlimit(kmem_cache#15-oX (struct task_struct), 6): 0
	// p: kmem_cache#15-oX (struct task_struct)
	// p->real_cred: (kmem_cache#15-oX (struct task_struct))->real_cred: &init_cred,
	// p->real_cred->user: (&init_cred)->user: &root_user,
	// &p->real_cred->user->processes: &(&root_user)->processes, atomic_read(&(&root_user)->processes): 1
	// RLIMIT_NPROC: 6, task_rlimit(kmem_cache#15-oX (struct task_struct), 6): 0
	if (atomic_read(&p->real_cred->user->processes) >=
			task_rlimit(p, RLIMIT_NPROC)) {
		// p->real_cred->user: (&init_cred)->user: &root_user, INIT_USER: (&root_user)
		// CAP_SYS_RESOURCE: 24, capable(24): true, CAP_SYS_ADMIN: 21, capable(21): true
		// p->real_cred->user: (&init_cred)->user: &root_user, INIT_USER: (&root_user)
		// CAP_SYS_RESOURCE: 24, capable(24): true, CAP_SYS_ADMIN: 21, capable(21): true
		if (p->real_cred->user != INIT_USER &&
		    !capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN))
			goto bad_fork_free;

		// capable 에서 한일:
		// (&init_task)->flags: 0x00200100

		// capable 에서 한일:
		// (&init_task)->flags: 0x00200100
	}

	// current->flags: (&init_task)->flags: 0x00200100, PF_NPROC_EXCEEDED: 0x00001000
	// current->flags: (&init_task)->flags: 0x00200100, PF_NPROC_EXCEEDED: 0x00001000
	current->flags &= ~PF_NPROC_EXCEEDED;
	// current->flags: (&init_task)->flags: 0x00200100
	// current->flags: (&init_task)->flags: 0x00200100

	// retval: -11, p: kmem_cache#15-oX (struct task_struct), clone_flags: 0x00800B00
	// copy_creds(kmem_cache#15-oX (struct task_struct), 0x00800B00): 0
	// retval: -11, p: kmem_cache#15-oX (struct task_struct), clone_flags: 0x00800700
	// copy_creds(kmem_cache#15-oX (struct task_struct), 0x00800700): 0
	retval = copy_creds(p, clone_flags);
	// retval: 0
	// retval: 0

	// copy_creds 에서 한일:
	// struct cred 만큼의 메모리를 할당 받음
	// kmem_cache#16-oX (struct cred)
	//
	// kmem_cache#16-oX (struct cred) 에 init_cred 에 있는 맴버값 전부를 복사함
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 1
	// (&(&init_groups)->usage)->counter: 3
	// (&(&root_user)->__count)->counter: 2
	// (&(&root_user)->processes)->counter: 2
	//
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 2
	//
	// (kmem_cache#15-oX (struct task_struct))->cred: kmem_cache#16-oX (struct cred)
	// (kmem_cache#15-oX (struct task_struct))->real_cred: kmem_cache#16-oX (struct cred)

	// copy_creds 에서 한일:
	// struct cred 만큼의 메모리를 할당 받음
	// kmem_cache#16-oX (struct cred)
	//
	// kmem_cache#16-oX (struct cred) 에 init_cred 에 있는 맴버값 전부를 복사함
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 1
	// (&(&init_groups)->usage)->counter: 4
	// (&(&root_user)->__count)->counter: 3
	// (&(&root_user)->processes)->counter: 3
	//
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 2
	//
	// (kmem_cache#15-oX (struct task_struct))->cred: kmem_cache#16-oX (struct cred)
	// (kmem_cache#15-oX (struct task_struct))->real_cred: kmem_cache#16-oX (struct cred)

	// retval: 0
	// retval: 0
	if (retval < 0)
		goto bad_fork_free;

	/*
	 * If multiple threads are within copy_process(), then this check
	 * triggers too late. This doesn't hurt, the check is only there
	 * to stop root fork bombs.
	 */
	// EAGAIN: 11
	// EAGAIN: 11
	retval = -EAGAIN;
	// retval: -11
	// retval: -11

	// nr_threads: 0, max_threads: 총 free된 page 수 / 16
	// nr_threads: 0, max_threads: 총 free된 page 수 / 16
	if (nr_threads >= max_threads)
		goto bad_fork_cleanup_count;

	// p: kmem_cache#15-oX (struct task_struct),
	// task_thread_info(kmem_cache#15-oX (struct task_struct)):
	// (kmem_cache#15-oX (struct task_struct))->stack: 할당 받은 page 2개의 메모리의 가상 주소,
	// task_thread_info(kmem_cache#15-oX (struct task_struct)->exec_domain:
	// ((struct thread_info *) 할당 받은 page 2개의 메로리의 가상 주소)->exec_domain: &default_exec_domain,
	// task_thread_info(kmem_cache#15-oX (struct task_struct)->exec_domain->module:
	// (&default_exec_domain)->module: NULL,
	// try_module_get(NULL): true
	// p: kmem_cache#15-oX (struct task_struct),
	// task_thread_info(kmem_cache#15-oX (struct task_struct)):
	// (kmem_cache#15-oX (struct task_struct))->stack: 할당 받은 page 2개의 메모리의 가상 주소,
	// task_thread_info(kmem_cache#15-oX (struct task_struct)->exec_domain:
	// ((struct thread_info *) 할당 받은 page 2개의 메로리의 가상 주소)->exec_domain: &default_exec_domain,
	// task_thread_info(kmem_cache#15-oX (struct task_struct)->exec_domain->module:
	// (&default_exec_domain)->module: NULL,
	// try_module_get(NULL): true
	if (!try_module_get(task_thread_info(p)->exec_domain->module))
		goto bad_fork_cleanup_count;

	// p->did_exec: (kmem_cache#15-oX (struct task_struct))->did_exec
	// p->did_exec: (kmem_cache#15-oX (struct task_struct))->did_exec
	p->did_exec = 0;
	// p->did_exec: (kmem_cache#15-oX (struct task_struct))->did_exec: 0
	// p->did_exec: (kmem_cache#15-oX (struct task_struct))->did_exec: 0

	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	delayacct_tsk_init(p);	/* Must remain after dup_task_struct() */ // null function

	// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
	// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
	copy_flags(clone_flags, p);

	// copy_flags 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->flags: 0x00200040

	// copy_flags 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->flags: 0x00200040

	// &p->children: &(kmem_cache#15-oX (struct task_struct))->children
	// &p->children: &(kmem_cache#15-oX (struct task_struct))->children
	INIT_LIST_HEAD(&p->children);

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->children)->next: &(kmem_cache#15-oX (struct task_struct))->children
	// (&(kmem_cache#15-oX (struct task_struct))->children)->prev: &(kmem_cache#15-oX (struct task_struct))->children

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->children)->next: &(kmem_cache#15-oX (struct task_struct))->children
	// (&(kmem_cache#15-oX (struct task_struct))->children)->prev: &(kmem_cache#15-oX (struct task_struct))->children

	// &p->sibling: &(kmem_cache#15-oX (struct task_struct))->sibling
	// &p->sibling: &(kmem_cache#15-oX (struct task_struct))->sibling
	INIT_LIST_HEAD(&p->sibling);

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->next: &(kmem_cache#15-oX (struct task_struct))->sibling
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->prev: &(kmem_cache#15-oX (struct task_struct))->sibling

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->next: &(kmem_cache#15-oX (struct task_struct))->sibling
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->prev: &(kmem_cache#15-oX (struct task_struct))->sibling

	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	rcu_copy_process(p);

	// rcu_copy_process 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_lock_nesting: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_unlock_special: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_blocked_node: NULL
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->next: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry

	// rcu_copy_process 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_lock_nesting: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_unlock_special: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_blocked_node: NULL
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->next: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry

	// p->vfork_done: (kmem_cache#15-oX (struct task_struct))->vfork_done
	// p->vfork_done: (kmem_cache#15-oX (struct task_struct))->vfork_done
	p->vfork_done = NULL;
	// p->vfork_done: (kmem_cache#15-oX (struct task_struct))->vfork_done: NULL
	// p->vfork_done: (kmem_cache#15-oX (struct task_struct))->vfork_done: NULL

	// &p->alloc_lock: &(kmem_cache#15-oX (struct task_struct))->alloc_lock
	// &p->alloc_lock: &(kmem_cache#15-oX (struct task_struct))->alloc_lock
	spin_lock_init(&p->alloc_lock);

	// spin_lock_init에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->magic: 0xdead4ead
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner: 0xffffffff
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner_cpu: 0xffffffff

	// spin_lock_init에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->magic: 0xdead4ead
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner: 0xffffffff
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner_cpu: 0xffffffff

	// &p->pending: &(kmem_cache#15-oX (struct task_struct))->pending
	// &p->pending: &(kmem_cache#15-oX (struct task_struct))->pending
	init_sigpending(&p->pending);

	// init_sigpending 에서 한일:
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list

	// init_sigpending 에서 한일:
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list

	// p->utime: (kmem_cache#15-oX (struct task_struct))->utime,
	// p->stime: (kmem_cache#15-oX (struct task_struct))->stime,
	// p->gtime: (kmem_cache#15-oX (struct task_struct))->gtime
	// p->utime: (kmem_cache#15-oX (struct task_struct))->utime,
	// p->stime: (kmem_cache#15-oX (struct task_struct))->stime,
	// p->gtime: (kmem_cache#15-oX (struct task_struct))->gtime
	p->utime = p->stime = p->gtime = 0;
	// p->utime: (kmem_cache#15-oX (struct task_struct))->utime: 0
	// p->stime: (kmem_cache#15-oX (struct task_struct))->stime: 0
	// p->gtime: (kmem_cache#15-oX (struct task_struct))->gtime: 0
	// p->utime: (kmem_cache#15-oX (struct task_struct))->utime: 0
	// p->stime: (kmem_cache#15-oX (struct task_struct))->stime: 0
	// p->gtime: (kmem_cache#15-oX (struct task_struct))->gtime: 0

	// p->utimescaled: (kmem_cache#15-oX (struct task_struct))->utimescaled,
	// p->stimescaled: (kmem_cache#15-oX (struct task_struct))->stimescaled
	// p->utimescaled: (kmem_cache#15-oX (struct task_struct))->utimescaled,
	// p->stimescaled: (kmem_cache#15-oX (struct task_struct))->stimescaled
	p->utimescaled = p->stimescaled = 0;
	// p->utimescaled: (kmem_cache#15-oX (struct task_struct))->utimescaled: 0
	// p->stimescaled: (kmem_cache#15-oX (struct task_struct))->stimescaled: 0
	// p->utimescaled: (kmem_cache#15-oX (struct task_struct))->utimescaled: 0
	// p->stimescaled: (kmem_cache#15-oX (struct task_struct))->stimescaled: 0

#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE // CONFIG_VIRT_CPU_ACCOUNTING_NATIVE=n
	p->prev_cputime.utime = p->prev_cputime.stime = 0;
#endif
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN // CONFIG_VIRT_CPU_ACCOUNTING_GEN=n
	seqlock_init(&p->vtime_seqlock);
	p->vtime_snap = 0;
	p->vtime_snap_whence = VTIME_SLEEPING;
#endif

#if defined(SPLIT_RSS_COUNTING)
	// &p->rss_stat: &(kmem_cache#15-oX (struct task_struct))->rss_stat
	// &p->rss_stat: &(kmem_cache#15-oX (struct task_struct))->rss_stat
	memset(&p->rss_stat, 0, sizeof(p->rss_stat));

	// memset 에서 한일:
	// &(kmem_cache#15-oX (struct task_struct))->rss_stat 값을 0 으로 초기화 수행

	// memset 에서 한일:
	// &(kmem_cache#15-oX (struct task_struct))->rss_stat 값을 0 으로 초기화 수행
#endif

	// p->default_timer_slack_ns: (kmem_cache#15-oX (struct task_struct))->default_timer_slack_ns,
	// current->timer_slack_ns: (&init_task)->timer_slack_ns: 50000
	// p->default_timer_slack_ns: (kmem_cache#15-oX (struct task_struct))->default_timer_slack_ns,
	// current->timer_slack_ns: (&init_task)->timer_slack_ns: 50000
	p->default_timer_slack_ns = current->timer_slack_ns;
	// p->default_timer_slack_ns: (kmem_cache#15-oX (struct task_struct))->default_timer_slack_ns: 50000
	// p->default_timer_slack_ns: (kmem_cache#15-oX (struct task_struct))->default_timer_slack_ns: 50000

	// p->ioac: (kmem_cache#15-oX (struct task_struct))->ioac
	// p->ioac: (kmem_cache#15-oX (struct task_struct))->ioac
	task_io_accounting_init(&p->ioac); // null function

	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	acct_clear_integrals(p); // null function

	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	posix_cpu_timers_init(p);

	// posix_cpu_timers_init 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.prof_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.virt_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.sched_exp: 0
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]

	// posix_cpu_timers_init 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.prof_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.virt_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.sched_exp: 0
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]

	// &p->start_time: &(kmem_cache#15-oX (struct task_struct))->start_time
	// &p->start_time: &(kmem_cache#15-oX (struct task_struct))->start_time
	do_posix_clock_monotonic_gettime(&p->start_time);

	// do_posix_clock_monotonic_gettime 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->start_time 에 현재 시간 값을 가져옴
	//
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L

	// do_posix_clock_monotonic_gettime 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->start_time 에 현재 시간 값을 가져옴
	//
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L

	// p->real_start_time: (kmem_cache#15-oX (struct task_struct))->real_start_time,
	// p->start_time: (kmem_cache#15-oX (struct task_struct))->start_time
	// p->real_start_time: (kmem_cache#15-oX (struct task_struct))->real_start_time,
	// p->start_time: (kmem_cache#15-oX (struct task_struct))->start_time
	p->real_start_time = p->start_time;
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L

	// &p->real_start_time: &(kmem_cache#15-oX (struct task_struct))->real_start_time
	// &p->real_start_time: &(kmem_cache#15-oX (struct task_struct))->real_start_time
	monotonic_to_bootbased(&p->real_start_time);

	// monotonic_to_bootbased 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_sec: normalized 된 sec 값
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_nsec: normalized 된 nsec 값

	// monotonic_to_bootbased 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_sec: normalized 된 sec 값
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_nsec: normalized 된 nsec 값

	// p->io_context: (kmem_cache#15-oX (struct task_struct))->io_context
	// p->io_context: (kmem_cache#15-oX (struct task_struct))->io_context
	p->io_context = NULL;
	// p->io_context: (kmem_cache#15-oX (struct task_struct))->io_context: NULL
	// p->io_context: (kmem_cache#15-oX (struct task_struct))->io_context: NULL

	// p->audit_context: (kmem_cache#15-oX (struct task_struct))->audit_context
	// p->audit_context: (kmem_cache#15-oX (struct task_struct))->audit_context
	p->audit_context = NULL;
	// p->audit_context: (kmem_cache#15-oX (struct task_struct))->audit_context: NULL
	// p->audit_context: (kmem_cache#15-oX (struct task_struct))->audit_context: NULL

// 2016/09/10 종료
// 2016/10/08 시작

	// clone_flags: 0x00800B00, CLONE_THREAD: 0x00010000
	// clone_flags: 0x00800700, CLONE_THREAD: 0x00010000
	if (clone_flags & CLONE_THREAD)
		threadgroup_change_begin(current);

	// p: kmem_cache#15-oX (struct task_struct)
	cgroup_fork(p);

	// cgroup_fork 에서 한일:
	// rcu reference의 값 (&init_task)->cgroups 이 유요한지 체크하고 그 값을 리턴함
	// ((&init_task)->cgroups)->refcount: 1
	// (kmem_cache#15-oX (struct task_struct))->cgroups: (&init_task)->cgroups
	//
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->next: &(kmem_cache#15-oX (struct task_struct))->cg_list
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->prev: &(kmem_cache#15-oX (struct task_struct))->cg_list

	// cgroup_fork 에서 한일:
	// rcu reference의 값 (&init_task)->cgroups 이 유요한지 체크하고 그 값을 리턴함
	// ((&init_task)->cgroups)->refcount: 1
	// (kmem_cache#15-oX (struct task_struct))->cgroups: (&init_task)->cgroups
	//
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->next: &(kmem_cache#15-oX (struct task_struct))->cg_list
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->prev: &(kmem_cache#15-oX (struct task_struct))->cg_list

#ifdef CONFIG_NUMA // CONFIG_NUMA=n
	p->mempolicy = mpol_dup(p->mempolicy);
	if (IS_ERR(p->mempolicy)) {
		retval = PTR_ERR(p->mempolicy);
		p->mempolicy = NULL;
		goto bad_fork_cleanup_cgroup;
	}
	mpol_fix_fork_child_flag(p);
#endif
#ifdef CONFIG_CPUSETS // CONFIG_CPUSETS=n
	p->cpuset_mem_spread_rotor = NUMA_NO_NODE;
	p->cpuset_slab_spread_rotor = NUMA_NO_NODE;
	seqcount_init(&p->mems_allowed_seq);
#endif
#ifdef CONFIG_TRACE_IRQFLAGS // CONFIG_TRACE_IRQFLAGS=n
	p->irq_events = 0;
	p->hardirqs_enabled = 0;
	p->hardirq_enable_ip = 0;
	p->hardirq_enable_event = 0;
	p->hardirq_disable_ip = _THIS_IP_;
	p->hardirq_disable_event = 0;
	p->softirqs_enabled = 1;
	p->softirq_enable_ip = _THIS_IP_;
	p->softirq_enable_event = 0;
	p->softirq_disable_ip = 0;
	p->softirq_disable_event = 0;
	p->hardirq_context = 0;
	p->softirq_context = 0;
#endif
#ifdef CONFIG_LOCKDEP // CONFIG_LOCKDEP=n
	p->lockdep_depth = 0; /* no locks held yet */
	p->curr_chain_key = 0;
	p->lockdep_recursion = 0;
#endif

#ifdef CONFIG_DEBUG_MUTEXES // CONFIG_DEBUG_MUTEXES=y
	// p->blocked_on: (kmem_cache#15-oX (struct task_struct))->blocked_on
	// p->blocked_on: (kmem_cache#15-oX (struct task_struct))->blocked_on
	p->blocked_on = NULL; /* not blocked yet */
	// p->blocked_on: (kmem_cache#15-oX (struct task_struct))->blocked_on: NULL
	// p->blocked_on: (kmem_cache#15-oX (struct task_struct))->blocked_on: NULL
#endif
#ifdef CONFIG_MEMCG // CONFIG_MEMCG=n
	p->memcg_batch.do_batch = 0;
	p->memcg_batch.memcg = NULL;
#endif
#ifdef CONFIG_BCACHE // CONFIG_BCACHE=n
	p->sequential_io	= 0;
	p->sequential_io_avg	= 0;
#endif

	/* Perform scheduler related setup. Assign this task to a CPU. */
	// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
	// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
	sched_fork(clone_flags, p);

	// sched_fork 에서 한일:
	// (&kmem_cache#15-oX (struct task_struct))->on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.exec_start: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.prev_sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.nr_migrations: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.vruntime: 0
	// &(&kmem_cache#15-oX (struct task_struct))->se.group_node의 리스트 초기화
	// &(&kmem_cache#15-oX (struct task_struct))->rt.run_list의 리스트 초기화
	//
	// (kmem_cache#15-oX (struct task_struct))->state: 0
	// (kmem_cache#15-oX (struct task_struct))->prio: 120
	// (kmem_cache#15-oX (struct task_struct))->sched_class: &fair_sched_class
	//
	// 현재의 schedule 시간값과 기존의 (&runqueues)->clock 의 값의 차이값을
	// [pcp0] (&runqueues)->clock, [pcp0] (&runqueues)->clock_task 의 값에 더해 갱신함
	//
	// [pcp0] (&runqueues)->clock: schedule 시간 차이값
	// [pcp0] (&runqueues)->clock_task: schedule 시간 차이값
	//
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (&(kmem_cache#15-oX (struct task_struct))->se)->vruntime: 0x5B8D7E
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->on_cpu: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->preempt_count: 1
	// (&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio: 140
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list

	// sched_fork 에서 한일:
	// (&kmem_cache#15-oX (struct task_struct))->on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.exec_start: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.prev_sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.nr_migrations: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.vruntime: 0
	// &(&kmem_cache#15-oX (struct task_struct))->se.group_node의 리스트 초기화
	// &(&kmem_cache#15-oX (struct task_struct))->rt.run_list의 리스트 초기화
	//
	// (kmem_cache#15-oX (struct task_struct))->state: 0
	// (kmem_cache#15-oX (struct task_struct))->prio: 120
	// (kmem_cache#15-oX (struct task_struct))->sched_class: &fair_sched_class
	//
	// 현재의 schedule 시간값과 기존의 (&runqueues)->clock 의 값의 차이값을
	// [pcp0] (&runqueues)->clock, [pcp0] (&runqueues)->clock_task 의 값에 더해 갱신함
	//
	// [pcp0] (&runqueues)->clock: schedule 시간 차이값
	// [pcp0] (&runqueues)->clock_task: schedule 시간 차이값
	//
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (&(kmem_cache#15-oX (struct task_struct))->se)->vruntime: 0x5B8D7E
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->on_cpu: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->preempt_count: 1
	// (&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio: 140
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list

	// p: kmem_cache#15-oX (struct task_struct)
	// perf_event_init_task(kmem_cache#15-oX (struct task_struct)): 0
	// p: kmem_cache#15-oX (struct task_struct)
	// perf_event_init_task(kmem_cache#15-oX (struct task_struct)): 0
	retval = perf_event_init_task(p); // null function
	// retval: 0
	// retval: 0

	// retval: 0
	// retval: 0
	if (retval)
		goto bad_fork_cleanup_policy;

	// p: kmem_cache#15-oX (struct task_struct)
	// audit_alloc(kmem_cache#15-oX (struct task_struct)): 0
	// p: kmem_cache#15-oX (struct task_struct)
	// audit_alloc(kmem_cache#15-oX (struct task_struct)): 0
	retval = audit_alloc(p); // null function
	// retval: 0
	// retval: 0

	// retval: 0
	// retval: 0
	if (retval)
		goto bad_fork_cleanup_policy;

	/* copy all the process information */
	// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
	// copy_semundo(kmem_cache#15-oX (struct task_struct)): 0
	// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
	// copy_semundo(kmem_cache#15-oX (struct task_struct)): 0
	retval = copy_semundo(clone_flags, p);
	// retval: 0
	// retval: 0

	// copy_semundo 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->sysvsem.undo_list: NULL

	// copy_semundo 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->sysvsem.undo_list: NULL

	// retval: 0
	// retval: 0
	if (retval)
		goto bad_fork_cleanup_audit;

	// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
	// copy_files(0x00800B00, kmem_cache#15-oX (struct task_struct)): 0
	// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
	// copy_files(0x00800700, kmem_cache#15-oX (struct task_struct)): 0
	retval = copy_files(clone_flags, p);
	// retval: 0
	// retval: 0

	// copy_files 에서 한일:
	// files_cachep: kmem_cache#12 을 사용하여 struct files_struct 을 위한 메모리를 할당함
	// kmem_cache#12-oX (struct files_struct)
	//
	// (kmem_cache#12-oX (struct files_struct))->count: 1
	//
	// &(kmem_cache#12-oX (struct files_struct))->file_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->owner_cpu: 0xffffffff
	//
	// (kmem_cache#12-oX (struct files_struct))->next_fd: 0
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->max_fds: 32
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->close_on_exec: (kmem_cache#12-oX (struct files_struct))->close_on_exec_init
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->open_fds: (kmem_cache#12-oX (struct files_struct))->open_fds_init
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->fd: &(kmem_cache#12-oX (struct files_struct))->fd_array[0]
	//
	// &(&init_files)->file_lock 을 사용하여 spin lock 수행
	//
	// (kmem_cache#12-oX (struct files_struct))->open_fds_init 에 init_files.open_fds_init 값을 복사
	// (kmem_cache#12-oX (struct files_struct))->open_fds_init: NULL
	// (kmem_cache#12-oX (struct files_struct))->close_on_exec_init 에 init_files.close_on_exec_init 값을 복사
	// (kmem_cache#12-oX (struct files_struct))->close_on_exec_init: NULL
	//
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->open_fds 의 0~31 bit 를 clear 함
	// (kmem_cache#12-oX (struct files_struct))->fd_array[0...31]: NULL
	// &(kmem_cache#12-oX (struct files_struct))->fd_array[0] 에 값을 size 0 만큼 0 으로 set 함
	//
	// (kmem_cache#12-oX (struct files_struct))->fdt: &(kmem_cache#12-oX (struct files_struct))->fdtab
	//
	// (kmem_cache#15-oX (struct task_struct))->files: kmem_cache#12-oX (struct files_struct)

	// copy_files 에서 한일:
	// (&(&init_files)->count)->counter: 2

	// retval: 0
	// retval: 0
	if (retval)
		goto bad_fork_cleanup_semundo;

// 2016/10/29 종료
// 2016/11/05 시작

	// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
	// copy_fs(0x00800B00, kmem_cache#15-oX (struct task_struct)): 0
	// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
	// copy_fs(0x00800700, kmem_cache#15-oX (struct task_struct)): 0
	retval = copy_fs(clone_flags, p);
	// retval: 0
	// retval: 0

	// copy_fs 에서 한일:
	// (&init_fs)->users: 2

	// copy_fs 에서 한일:
	// (&init_fs)->users: 3

	// retval: 0
	// retval: 0
	if (retval)
		goto bad_fork_cleanup_files;

	// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
	// copy_sighand(0x00800B00, kmem_cache#15-oX (struct task_struct)): 0
	// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
	// copy_sighand(0x00800700, kmem_cache#15-oX (struct task_struct)): 0
	retval = copy_sighand(clone_flags, p);
	// retval: 0
	// retval: 0

	// copy_sighand 에서 한일:
	// (&init_sighand)->count: { (2) }

	// copy_sighand 에서 한일:
	// struct sighand_struct 만큼의 메모리를 할당 받음
	// kmem_cache#14-oX (struct sighand_struct)
	//
	// (kmem_cache#15-oX (struct task_struct))->sighand: kmem_cache#14-oX (struct sighand_struct)
	// (&(kmem_cache#14-oX (struct sighand_struct))->count)->counter: 1
	// (&init_sighand)->action 의 값을 (kmem_cache#14-oX (struct sighand_struct))->action 에 복사함

	// retval: 0
	// retval: 0
	if (retval)
		goto bad_fork_cleanup_fs;

// 2017/05/24 종료
// 2017/06/10 시작

	// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
	// copy_signal(0x00800B00, kmem_cache#15-oX (struct task_struct)): 0
	// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
	// copy_signal(0x00800700, kmem_cache#15-oX (struct task_struct)): 0
	retval = copy_signal(clone_flags, p);
	// retval: 0
	// retval: 0

	// copy_signal 에서 한일:
	// struct signal_struct 크기 만큼의 메모리를 할당함
	// kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#15-oX (struct task_struct))->signal: kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#13-oX (struct signal_struct))->nr_threads: 1
	// (kmem_cache#13-oX (struct signal_struct))->live: { (1) }
	// (kmem_cache#13-oX (struct signal_struct))->sigcnt: { (1) }
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->task_list를 사용한 list 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->curr_target: kmem_cache#15-oX (struct task_struct)
	//
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->next: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->prev: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer의 값을 0으로 초기화
	// (&(kmem_cache#13-oX (struct signal_struct))->real_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// RB Tree의 &(&(kmem_cache#13-oX (struct signal_struct))->real_timer)->node 를 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer.function: it_real_fn
	// (kmem_cache#13-oX (struct signal_struct))->rlim 에 (&init_signals)->rlim 값을 전부 복사함
	// &(kmem_cache#13-oX (struct signal_struct))->cputimer.lock 을 사용한 spinlock 초기화 수행
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->activity: 0
	// &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_lock을 사용한 spinlock 초기화
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj: 0
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj_min: 0
	// (kmem_cache#13-oX (struct signal_struct))->has_child_subreaper: 0
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->count: 1
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->onwer: NULL
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->magic: &(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex

	// copy_signal 에서 한일:
	// struct signal_struct 크기 만큼의 메모리를 할당함
	// kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#15-oX (struct task_struct))->signal: kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#13-oX (struct signal_struct))->nr_threads: 1
	// (kmem_cache#13-oX (struct signal_struct))->live: { (1) }
	// (kmem_cache#13-oX (struct signal_struct))->sigcnt: { (1) }
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->task_list를 사용한 list 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->curr_target: kmem_cache#15-oX (struct task_struct)
	//
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->next: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->prev: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer의 값을 0으로 초기화
	// (&(kmem_cache#13-oX (struct signal_struct))->real_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// RB Tree의 &(&(kmem_cache#13-oX (struct signal_struct))->real_timer)->node 를 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer.function: it_real_fn
	// (kmem_cache#13-oX (struct signal_struct))->rlim 에 (&init_signals)->rlim 값을 전부 복사함
	// &(kmem_cache#13-oX (struct signal_struct))->cputimer.lock 을 사용한 spinlock 초기화 수행
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->activity: 0
	// &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_lock을 사용한 spinlock 초기화
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj: 0
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj_min: 0
	// (kmem_cache#13-oX (struct signal_struct))->has_child_subreaper: 0
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->count: 1
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->onwer: NULL
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->magic: &(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex

	// retval: 0
	// retval: 0
	if (retval)
		goto bad_fork_cleanup_sighand;

	// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
	// copy_mm(0x00800B00, kmem_cache#15-oX (struct task_struct)): 0
	// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
	// copy_mm(0x00800700, kmem_cache#15-oX (struct task_struct)): 0
	retval = copy_mm(clone_flags, p);
	// retval: 0
	// retval: 0

	// copy_mm 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->min_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->maj_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->nvcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->nivcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->last_switch_count: 0
	// (kmem_cache#15-oX (struct task_struct))->mm: NULL
	// (kmem_cache#15-oX (struct task_struct))->active_mm: NULL

	// copy_mm 에서 한일:
	// (kmem_cache#15-oX (struct task_struct))->min_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->maj_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->nvcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->nivcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->last_switch_count: 0
	// (kmem_cache#15-oX (struct task_struct))->mm: NULL
	// (kmem_cache#15-oX (struct task_struct))->active_mm: NULL

	// retval: 0
	// retval: 0
	if (retval)
		goto bad_fork_cleanup_signal;

	// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
	// copy_namespaces(0x00800B00, kmem_cache#15-oX (struct task_struct)): 0
	// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
	// copy_namespaces(0x00800700, kmem_cache#15-oX (struct task_struct)): 0
	retval = copy_namespaces(clone_flags, p);
	// retval: 0

	// copy_namespaces 에서 한일:
	// (&init_nsproxy)->count: { (2) }

	// copy_namespaces 에서 한일:
	// (&init_nsproxy)->count: { (3) }

	// retval: 0
	// retval: 0
	if (retval)
		goto bad_fork_cleanup_mm;

	// clone_flags: 0x00800B00, p: kmem_cache#15-oX (struct task_struct)
	// copy_io(0x00800B00, kmem_cache#15-oX (struct task_struct)): 0
	// clone_flags: 0x00800700, p: kmem_cache#15-oX (struct task_struct)
	// copy_io(0x00800700, kmem_cache#15-oX (struct task_struct)): 0
	retval = copy_io(clone_flags, p);
	// retval: 0
	// retval: 0

	// retval: 0
	// retval: 0
	if (retval)
		goto bad_fork_cleanup_namespaces;

	// clone_flags: 0x00800B00, stack_start: kernel_init, stack_size: 0, p: kmem_cache#15-oX (struct task_struct)
	// copy_thread(0x00800B00, kernel_init, 0, kmem_cache#15-oX (struct task_struct)): 0
	// clone_flags: 0x00800700, stack_start: kernel_init, stack_size: 0, p: kmem_cache#15-oX (struct task_struct)
	// copy_thread(0x00800700, kernel_init, 0, kmem_cache#15-oX (struct task_struct)): 0
	retval = copy_thread(clone_flags, stack_start, stack_size, p);
	// retval: 0
	// retval: 0

	// copy_thread 에서 한일:
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context 의 값을 0으로 초기화 함
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183) 의 값을 0으로 초기화 함
	//
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r4: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r5: kernel_init
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)->uregs[16]: 0x00000013
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.pc: ret_from_fork
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.sp: ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->tp_value[1]: TPIDRURW의 읽은 값

	// copy_thread 에서 한일:
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context 의 값을 0으로 초기화 함
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183) 의 값을 0으로 초기화 함
	//
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r4: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r5: kernel_init
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)->uregs[16]: 0x00000013
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.pc: ret_from_fork
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.sp: ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->tp_value[1]: TPIDRURW의 읽은 값

	// retval: 0
	// retval: 0
	if (retval)
		goto bad_fork_cleanup_io;

	// pid: NULL
	// pid: NULL
	if (pid != &init_struct_pid) {
		// ENOMEM: 12
		// ENOMEM: 12
		retval = -ENOMEM;
		// retval: -12
		// retval: -12

		// p->nsproxy: (kmem_cache#15-oX (struct task_struct))->nsproxy: &init_nsproxy
		// p->nsproxy->pid_ns_for_children: (&init_nsproxy)->pid_ns_for_children: &init_pid_ns
		// alloc_pid(&init_pid_ns): kmem_cache#19-oX (struct pid)
		// p->nsproxy: (kmem_cache#15-oX (struct task_struct))->nsproxy: &init_nsproxy
		// p->nsproxy->pid_ns_for_children: (&init_nsproxy)->pid_ns_for_children: &init_pid_ns
		// alloc_pid(&init_pid_ns): kmem_cache#19-oX (struct pid)
		pid = alloc_pid(p->nsproxy->pid_ns_for_children);
		// pid: kmem_cache#19-oX (struct pid)
		// pid: kmem_cache#19-oX (struct pid)

		// alloc_pid 에서 한일:
		// struct pid 만큼의 메모리를 할당 받음
		// kmem_cache#19-oX (struct pid)
		//
		// (kmem_cache#19-oX (struct pid))->level: 0
		//
		// page 사이즈 만큼의 메모리를 할당 받음: kmem_cache#25-oX
		//
		// (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX
		// kmem_cache#25-oX 의 1 bit 의 값을 1 으로 set
		// (&(&init_pid_ns)->pidmap[0])->nr_free: { (0x7FFF) }
		// &(&init_pid_ns)->last_pid 을 1 로 변경함
		//
		// (kmem_cache#19-oX (struct pid))->numbers[0].nr: 1
		// (kmem_cache#19-oX (struct pid))->numbers[0].ns: &init_pid_ns
		//
		// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
		//
		// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
		//
		// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 3번을 가르킴
		// |
		// |-> ---------------------------------------------------------------------------------------------------------------------------
		//     | idr object new 4         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//
		// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 4)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
		//
		// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
		//
		// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
		// (&(&mnt_id_ida)->idr)->layers: 1
		// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
		// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
		//
		// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 4 bit를 1로 set 수행
		// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 5
		//
		// (kmem_cache#2-oX (struct mount))->mnt_id: 4
		//
		// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 4) 의 memory 공간을 반환함
		//
		// mnt_id_start: 5
		//
		// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "proc"
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
		// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
		//
		// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 4번을 가르킴
		// |
		// |-> ---------------------------------------------------------------------------------------------------------------------------
		//     | idr object new 4         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
		//     ---------------------------------------------------------------------------------------------------------------------------
		//
		// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 4)
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
		//
		// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
		//
		// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
		// (&(&unnamed_dev_ida)->idr)->layers: 1
		// (&(&unnamed_dev_ida)->idr)->id_free: (idr object new 0)
		// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
		//
		// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 4 bit를 1로 set 수행
		// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 5
		//
		// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 4) 의 memory 공간을 반환함
		//
		// unnamed_dev_start: 5
		//
		// (kmem_cache#25-oX (struct super_block))->s_dev: 4
		// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
		// (kmem_cache#25-oX (struct super_block))->s_fs_info: &init_pid_ns
		// (kmem_cache#25-oX (struct super_block))->s_type: &proc_fs_type
		// (kmem_cache#25-oX (struct super_block))->s_id: "proc"
		//
		// list head인 &super_blocks 에 (kmem_cache#25-oX (struct super_block))->s_list을 tail에 추가
		// (&(kmem_cache#25-oX (struct super_block))->s_instances)->next: NULL
		// (&(&proc_fs_type)->fs_supers)->first: &(kmem_cache#25-oX (struct super_block))->s_instances
		// (&(kmem_cache#25-oX (struct super_block))->s_instances)->pprev: &(&(&proc_fs_type)->fs_supers)->first
		// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->flags: 0
		// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->nr_deferred: kmem_cache#30-oX
		// head list인 &shrinker_list에 &(&(kmem_cache#25-oX (struct super_block))->s_shrink)->list를 tail로 추가함
		//
		// (kmem_cache#25-oX (struct super_block))->s_flags: 0x40080a
		// (kmem_cache#25-oX (struct super_block))->s_blocksize: 1024
		// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 10
		// (kmem_cache#25-oX (struct super_block))->s_magic: 0x9fa0
		// (kmem_cache#25-oX (struct super_block))->s_op: &proc_sops
		// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1
		//
		// (&proc_root)->count: { (2) }
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
		// [pcp0] nr_inodes: 2
		//
		// (kmem_cache#4-oX (struct inode))->i_state: 0
		// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
		// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
		//
		// (kmem_cache#4-oX (struct inode))->i_ino: 1
		// (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값
		// (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값
		// (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값
		// (kmem_cache#4-oX (struct inode))->pde: &proc_root
		// (kmem_cache#4-oX (struct inode))->i_mode: 0040555
		// (kmem_cache#4-oX (struct inode))->i_uid: 0
		// (kmem_cache#4-oX (struct inode))->i_gid: 0
		// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
		// (kmem_cache#4-oX (struct inode))->i_op: &proc_root_inode_operations
		// (kmem_cache#4-oX (struct inode))->i_fop: &proc_root_operations
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
		// [pcp0] nr_dentry: 3
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
		// (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
		//
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
		// [pcp0] nr_inodes: 3
		//
		// (kmem_cache#4-oX (struct inode))->i_state: 0
		// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
		// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
		// (kmem_cache#4-oX (struct inode))->i_ino: 0xF0000001
		// (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값
		// (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값
		// (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값
		// (kmem_cache#4-oX (struct inode))->i_mode: 0120777
		// (kmem_cache#4-oX (struct inode))->i_uid: 0
		// (kmem_cache#4-oX (struct inode))->i_gid: 0
		// (kmem_cache#4-oX (struct inode))->i_op: &proc_self_inode_operations
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
		// (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100080
		//
		// (&(kmem_cache#5-oX (struct dentry))->d_hash)->next: NULL
		// (&(kmem_cache#5-oX (struct dentry))->d_hash)->pprev: &(hash 0xXXXXXXXX 에 맞는 list table 주소값)->first
		//
		// ((hash 0xXXXXXXXX 에 맞는 list table 주소값)->first): ((&(kmem_cache#5-oX (struct dentry))->d_hash) | 1)
		//
		// (&init_pid_ns)->proc_self: kmem_cache#5-oX (struct dentry)
		//
		// (&(kmem_cache#5-oX (struct dentry))->d_lockref)->count: 1
		//
		// (kmem_cache#25-oX (struct super_block))->s_flags: 0x6040080a
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
		// (&init_pid_ns)->proc_mnt: &(kmem_cache#2-oX (struct mount))->mnt
		//
		// (&(kmem_cache#19-oX (struct pid))->count)->counter: 1
		// (&(kmem_cache#19-oX (struct pid))->tasks[0...2])->first: NULL
		//
		// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->next: NULL
		// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->pprev: &(&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first
		// ((&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first): &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain
		//
		// (&init_pid_ns)->nr_hashed: 0x80000001

		// alloc_pid 에서 한일:
		// struct pid 만큼의 메모리를 할당 받음
		// kmem_cache#19-oX (struct pid)
		//
		// (kmem_cache#19-oX (struct pid))->level: 0
		//
		// 기존에 할당받은 pidmap의 메모리 값
		// (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX
		// kmem_cache#25-oX 의 2 bit 의 값을 1 으로 set
		// (&(&init_pid_ns)->pidmap[0])->nr_free: { (0x7FFE) }
		// &(&init_pid_ns)->last_pid 을 2 로 변경함
		//
		// (kmem_cache#19-oX (struct pid))->numbers[0].nr: 2
		// (kmem_cache#19-oX (struct pid))->numbers[0].ns: &init_pid_ns
		//
		// (&(kmem_cache#19-oX (struct pid))->count)->counter: 1
		//
		// (&(kmem_cache#19-oX (struct pid))->tasks[0...2])->first: NULL
		//
		// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->next: NULL
		// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->pprev: &(&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first
		// ((&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first): &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain
		//
		// (&init_pid_ns)->nr_hashed: 0x80000002

		// pid: kmem_cache#19-oX (struct pid)
		// pid: kmem_cache#19-oX (struct pid)
		if (!pid)
			goto bad_fork_cleanup_io;
	}

	// p->set_child_tid: (kmem_cache#15-oX (struct task_struct))->set_child_tid,
	// clone_flags: 0x00800B00, CLONE_CHILD_SETTID: 0x01000000
	// p->set_child_tid: (kmem_cache#15-oX (struct task_struct))->set_child_tid,
	// clone_flags: 0x00800700, CLONE_CHILD_SETTID: 0x01000000
	p->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? child_tidptr : NULL;
	// p->set_child_tid: (kmem_cache#15-oX (struct task_struct))->set_child_tid: NULL
	// p->set_child_tid: (kmem_cache#15-oX (struct task_struct))->set_child_tid: NULL

	/*
	 * Clear TID on mm_release()?
	 */
	// p->clear_child_tid: (kmem_cache#15-oX (struct task_struct))->clear_child_tid,
	// clone_flags: 0x00800B00, CLONE_CHILD_CLEARTID: 0x00200000
	// p->clear_child_tid: (kmem_cache#15-oX (struct task_struct))->clear_child_tid,
	// clone_flags: 0x00800700, CLONE_CHILD_CLEARTID: 0x00200000
	p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? child_tidptr : NULL;
	// p->clear_child_tid: (kmem_cache#15-oX (struct task_struct))->clear_child_tid: NULL
	// p->clear_child_tid: (kmem_cache#15-oX (struct task_struct))->clear_child_tid: NULL

#ifdef CONFIG_BLOCK // CONFIG_BLOCK=y
	// p->plug: (kmem_cache#15-oX (struct task_struct))->plug
	// p->plug: (kmem_cache#15-oX (struct task_struct))->plug
	p->plug = NULL;
	// p->plug: (kmem_cache#15-oX (struct task_struct))->plug: NULL
	// p->plug: (kmem_cache#15-oX (struct task_struct))->plug: NULL
#endif
#ifdef CONFIG_FUTEX // CONFIG_FUTEX=y
	// p->robust_list: (kmem_cache#15-oX (struct task_struct))->robust_list
	// p->robust_list: (kmem_cache#15-oX (struct task_struct))->robust_list
	p->robust_list = NULL;
	// p->robust_list: (kmem_cache#15-oX (struct task_struct))->robust_list: NULL
	// p->robust_list: (kmem_cache#15-oX (struct task_struct))->robust_list: NULL
#ifdef CONFIG_COMPAT // CONFIG_COMPAT=n
	p->compat_robust_list = NULL;
#endif
	// &p->pi_state_list: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	// &p->pi_state_list: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	INIT_LIST_HEAD(&p->pi_state_list);

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->next: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->prev: &(kmem_cache#15-oX (struct task_struct))->pi_state_list

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->next: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->prev: &(kmem_cache#15-oX (struct task_struct))->pi_state_list

	// p->pi_state_cache: (kmem_cache#15-oX (struct task_struct))->pi_state_cache
	// p->pi_state_cache: (kmem_cache#15-oX (struct task_struct))->pi_state_cache
	p->pi_state_cache = NULL;
	// p->pi_state_cache: (kmem_cache#15-oX (struct task_struct))->pi_state_cache: NULL
	// p->pi_state_cache: (kmem_cache#15-oX (struct task_struct))->pi_state_cache: NULL
#endif
	/*
	 * sigaltstack should be cleared when sharing the same VM
	 */
	// clone_flags: 0x00800B00, CLONE_VM: 0x00000100, CLONE_VFORK: 0x00004000
	// clone_flags: 0x00800700, CLONE_VM: 0x00000100, CLONE_VFORK: 0x00004000
	if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)
		// p->sas_ss_sp: (kmem_cache#15-oX (struct task_struct))->sas_ss_sp,
		// p->sas_ss_size: (kmem_cache#15-oX (struct task_struct))->sas_ss_size
		// p->sas_ss_sp: (kmem_cache#15-oX (struct task_struct))->sas_ss_sp,
		// p->sas_ss_size: (kmem_cache#15-oX (struct task_struct))->sas_ss_size
		p->sas_ss_sp = p->sas_ss_size = 0;
		// p->sas_ss_sp: (kmem_cache#15-oX (struct task_struct))->sas_ss_sp: 0
		// p->sas_ss_size: (kmem_cache#15-oX (struct task_struct))->sas_ss_size: 0
		// p->sas_ss_sp: (kmem_cache#15-oX (struct task_struct))->sas_ss_sp: 0
		// p->sas_ss_size: (kmem_cache#15-oX (struct task_struct))->sas_ss_size: 0

	/*
	 * Syscall tracing and stepping should be turned off in the
	 * child regardless of CLONE_PTRACE.
	 */
	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	user_disable_single_step(p); // null function

	// p: kmem_cache#15-oX (struct task_struct), TIF_SYSCALL_TRACE: 8
	// p: kmem_cache#15-oX (struct task_struct), TIF_SYSCALL_TRACE: 8
	clear_tsk_thread_flag(p, TIF_SYSCALL_TRACE);

	// clear_tsk_thread_flag 에서 한일:
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 8 bit 값을 clear 수행

	// clear_tsk_thread_flag 에서 한일:
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 8 bit 값을 clear 수행

#ifdef TIF_SYSCALL_EMU // undefined
	clear_tsk_thread_flag(p, TIF_SYSCALL_EMU);
#endif
	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	clear_all_latency_tracing(p); // null function

	/* ok, now we should be set up.. */
	// p->pid: (kmem_cache#15-oX (struct task_struct))->pid,
	// pid: kmem_cache#19-oX (struct pid), pid_nr(kmem_cache#19-oX (struct pid)): 1
	// p->pid: (kmem_cache#15-oX (struct task_struct))->pid,
	// pid: kmem_cache#19-oX (struct pid), pid_nr(kmem_cache#19-oX (struct pid)): 2
	p->pid = pid_nr(pid);
	// p->pid: (kmem_cache#15-oX (struct task_struct))->pid: 1
	// p->pid: (kmem_cache#15-oX (struct task_struct))->pid: 2

	// clone_flags: 0x00800B00, CLONE_THREAD: 0x00010000
	// clone_flags: 0x00800700, CLONE_THREAD: 0x00010000
	if (clone_flags & CLONE_THREAD) {
		p->exit_signal = -1;
		p->group_leader = current->group_leader;
		p->tgid = current->tgid;
	} else {
		// clone_flags: 0x00800B00, CLONE_PARENT: 0x00008000
		// clone_flags: 0x00800700, CLONE_PARENT: 0x00008000
		if (clone_flags & CLONE_PARENT)
			p->exit_signal = current->group_leader->exit_signal;
		else
			// p->exit_signal: (kmem_cache#15-oX (struct task_struct))->exit_signal,
			// clone_flags: 0x00800B00, CSIGNAL: 0x000000ff
			// p->exit_signal: (kmem_cache#15-oX (struct task_struct))->exit_signal,
			// clone_flags: 0x00800700, CSIGNAL: 0x000000ff
			p->exit_signal = (clone_flags & CSIGNAL);
			// p->exit_signal: (kmem_cache#15-oX (struct task_struct))->exit_signal: 0
			// p->exit_signal: (kmem_cache#15-oX (struct task_struct))->exit_signal: 0

		// p->group_leader: (kmem_cache#15-oX (struct task_struct))->group_leader, p: kmem_cache#15-oX (struct task_struct)
		// p->group_leader: (kmem_cache#15-oX (struct task_struct))->group_leader, p: kmem_cache#15-oX (struct task_struct)
		p->group_leader = p;
		// p->group_leader: (kmem_cache#15-oX (struct task_struct))->group_leader: kmem_cache#15-oX (struct task_struct)
		// p->group_leader: (kmem_cache#15-oX (struct task_struct))->group_leader: kmem_cache#15-oX (struct task_struct)

		// p->tgid: (kmem_cache#15-oX (struct task_struct))->tgid, p->pid: (kmem_cache#15-oX (struct task_struct))->pid: 1
		// p->tgid: (kmem_cache#15-oX (struct task_struct))->tgid, p->pid: (kmem_cache#15-oX (struct task_struct))->pid: 2
		p->tgid = p->pid;
		// p->tgid: (kmem_cache#15-oX (struct task_struct))->tgid: 1
		// p->tgid: (kmem_cache#15-oX (struct task_struct))->tgid: 2
	}

	// p->pdeath_signal: (kmem_cache#15-oX (struct task_struct))->pdeath_signal
	// p->pdeath_signal: (kmem_cache#15-oX (struct task_struct))->pdeath_signal
	p->pdeath_signal = 0;
	// p->pdeath_signal: (kmem_cache#15-oX (struct task_struct))->pdeath_signal: 0
	// p->pdeath_signal: (kmem_cache#15-oX (struct task_struct))->pdeath_signal: 0

	// p->exit_state: (kmem_cache#15-oX (struct task_struct))->exit_state
	// p->exit_state: (kmem_cache#15-oX (struct task_struct))->exit_state
	p->exit_state = 0;
	// p->exit_state: (kmem_cache#15-oX (struct task_struct))->exit_state: 0
	// p->exit_state: (kmem_cache#15-oX (struct task_struct))->exit_state: 0

	// p->nr_dirtied: (kmem_cache#15-oX (struct task_struct))->nr_dirtied
	// p->nr_dirtied: (kmem_cache#15-oX (struct task_struct))->nr_dirtied
	p->nr_dirtied = 0;
	// p->nr_dirtied: (kmem_cache#15-oX (struct task_struct))->nr_dirtied: 0
	// p->nr_dirtied: (kmem_cache#15-oX (struct task_struct))->nr_dirtied: 0

	// p->nr_dirtied_pause: (kmem_cache#15-oX (struct task_struct))->nr_dirtied_pause, PAGE_SHIFT: 12
	// p->nr_dirtied_pause: (kmem_cache#15-oX (struct task_struct))->nr_dirtied_pause, PAGE_SHIFT: 12
	p->nr_dirtied_pause = 128 >> (PAGE_SHIFT - 10);
	// p->nr_dirtied_pause: (kmem_cache#15-oX (struct task_struct))->nr_dirtied_pause: 32
	// p->nr_dirtied_pause: (kmem_cache#15-oX (struct task_struct))->nr_dirtied_pause: 32

	// p->dirty_paused_when: (kmem_cache#15-oX (struct task_struct))->dirty_paused_when
	// p->dirty_paused_when: (kmem_cache#15-oX (struct task_struct))->dirty_paused_when
	p->dirty_paused_when = 0;
	// p->dirty_paused_when: (kmem_cache#15-oX (struct task_struct))->dirty_paused_when: 0
	// p->dirty_paused_when: (kmem_cache#15-oX (struct task_struct))->dirty_paused_when: 0

	// &p->thread_group: &(kmem_cache#15-oX (struct task_struct))->thread_group
	// &p->thread_group: &(kmem_cache#15-oX (struct task_struct))->thread_group
	INIT_LIST_HEAD(&p->thread_group);

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->next: &(kmem_cache#15-oX (struct task_struct))->thread_group
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->prev: &(kmem_cache#15-oX (struct task_struct))->thread_group

	// INIT_LIST_HEAD 에서 한일:
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->next: &(kmem_cache#15-oX (struct task_struct))->thread_group
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->prev: &(kmem_cache#15-oX (struct task_struct))->thread_group

	// p->task_works: (kmem_cache#15-oX (struct task_struct))->task_works
	// p->task_works: (kmem_cache#15-oX (struct task_struct))->task_works
	p->task_works = NULL;
	// p->task_works: (kmem_cache#15-oX (struct task_struct))->task_works: NULL
	// p->task_works: (kmem_cache#15-oX (struct task_struct))->task_works: NULL

	/*
	 * Make it visible to the rest of the system, but dont wake it up yet.
	 * Need tasklist lock for parent etc handling!
	 */
	write_lock_irq(&tasklist_lock);

	// write_lock_irq 에서 한일:
	// &tasklist_lock 을 사용하여 rw lock 수행

	// write_lock_irq 에서 한일:
	// &tasklist_lock 을 사용하여 rw lock 수행

	/* CLONE_PARENT re-uses the old parent */
	// clone_flags: 0x00800B00, CLONE_PARENT: 0x00008000, CLONE_THREAD: 0x00010000
	// clone_flags: 0x00800700, CLONE_PARENT: 0x00008000, CLONE_THREAD: 0x00010000
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) {
		p->real_parent = current->real_parent;
		p->parent_exec_id = current->parent_exec_id;
	} else {
		// p->real_parent: (kmem_cache#15-oX (struct task_struct))->real_parent, current: &init_task
		// p->real_parent: (kmem_cache#15-oX (struct task_struct))->real_parent, current: &init_task
		p->real_parent = current;
		// p->real_parent: (kmem_cache#15-oX (struct task_struct))->real_parent: &init_task
		// p->real_parent: (kmem_cache#15-oX (struct task_struct))->real_parent: &init_task

		// p->parent_exec_id: (kmem_cache#15-oX (struct task_struct))->parent_exec_id,
		// current->self_exec_id: (&init_task)->self_exec_id: 0
		// p->parent_exec_id: (kmem_cache#15-oX (struct task_struct))->parent_exec_id,
		// current->self_exec_id: (&init_task)->self_exec_id: 0
		p->parent_exec_id = current->self_exec_id;
		// p->parent_exec_id: (kmem_cache#15-oX (struct task_struct))->parent_exec_id: 0
		// p->parent_exec_id: (kmem_cache#15-oX (struct task_struct))->parent_exec_id: 0
	}

	// current: &init_task
	// current->sighand: (&init_task)->sighand: &init_sighand
	// &current->sighand->siglock: &(&init_sighand)->siglock
	// current: &init_task
	// current->sighand: (&init_task)->sighand: &init_sighand
	// &current->sighand->siglock: &(&init_sighand)->siglock
	spin_lock(&current->sighand->siglock);

	// spin_lock 에서 한일:
	// &(&init_sighand)->siglock 을 사용하여 spin lock 수행

	// spin_lock 에서 한일:
	// &(&init_sighand)->siglock 을 사용하여 spin lock 수행

	/*
	 * Process group and session signals need to be delivered to just the
	 * parent before the fork or both the parent and the child after the
	 * fork. Restart if a signal comes in before we add the new process to
	 * it's process group.
	 * A fatal signal pending means that current will exit, so the new
	 * thread can't slip out of an OOM kill (or normal SIGKILL).
	*/
	recalc_sigpending();

	// recalc_sigpending 에서 한일:
	// (init_task의 struct thread_info 주소값)->flags 의 0 bit 값을 clear 수행

	// recalc_sigpending 에서 한일:
	// (init_task의 struct thread_info 주소값)->flags 의 0 bit 값을 clear 수행

	// current: &init_task, signal_pending(&init_task): 0
	// current: &init_task, signal_pending(&init_task): 0
	if (signal_pending(current)) {
		spin_unlock(&current->sighand->siglock);
		write_unlock_irq(&tasklist_lock);
		retval = -ERESTARTNOINTR;
		goto bad_fork_free_pid;
	}

	// p->pid: (kmem_cache#15-oX (struct task_struct))->pid: 1
	// p->pid: (kmem_cache#15-oX (struct task_struct))->pid: 2
	if (likely(p->pid)) {
		// p: kmem_cache#15-oX (struct task_struct)
		// clone_flags: 0x00800B00, CLONE_PTRACE: 0x00002000, trace: 0
		// p: kmem_cache#15-oX (struct task_struct)
		// clone_flags: 0x00800700, CLONE_PTRACE: 0x00002000, trace: 0
		ptrace_init_task(p, (clone_flags & CLONE_PTRACE) || trace);

		// ptrace_init_task 에서 한일:
		// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->next: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
		// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
		// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->next: &(kmem_cache#15-oX (struct task_struct))->ptraced
		// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->prev: &(kmem_cache#15-oX (struct task_struct))->ptraced
		// (kmem_cache#15-oX (struct task_struct))->jobctl: 0
		// (kmem_cache#15-oX (struct task_struct))->ptrace: 0
		// (kmem_cache#15-oX (struct task_struct))->parent: &init_task

		// ptrace_init_task 에서 한일:
		// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->next: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
		// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
		// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->next: &(kmem_cache#15-oX (struct task_struct))->ptraced
		// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->prev: &(kmem_cache#15-oX (struct task_struct))->ptraced
		// (kmem_cache#15-oX (struct task_struct))->jobctl: 0
		// (kmem_cache#15-oX (struct task_struct))->ptrace: 0
		// (kmem_cache#15-oX (struct task_struct))->parent: &init_task

		// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PID: 0, pid: kmem_cache#19-oX (struct pid)
		// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PID: 0, pid: kmem_cache#19-oX (struct pid)
		init_task_pid(p, PIDTYPE_PID, pid);

		// init_task_pid 에서 한일:
		// (kmem_cache#15-oX (struct task_struct))->pids[0].pid: kmem_cache#19-oX (struct pid)

		// init_task_pid 에서 한일:
		// (kmem_cache#15-oX (struct task_struct))->pids[0].pid: kmem_cache#19-oX (struct pid)

		// p: kmem_cache#15-oX (struct task_struct), thread_group_leader(kmem_cache#15-oX (struct task_struct)): 1
		// p: kmem_cache#15-oX (struct task_struct), thread_group_leader(kmem_cache#15-oX (struct task_struct)): 1
		if (thread_group_leader(p)) {
			// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PGID: 1,
			// current: &init_task, task_pgrp(&init_task): &init_struct_pid
			// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PGID: 1,
			// current: &init_task, task_pgrp(&init_task): &init_struct_pid
			init_task_pid(p, PIDTYPE_PGID, task_pgrp(current));

			// init_task_pid 에서 한일:
			// (kmem_cache#15-oX (struct task_struct))->pids[1].pid: &init_struct_pid

			// init_task_pid 에서 한일:
			// (kmem_cache#15-oX (struct task_struct))->pids[1].pid: &init_struct_pid

			// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_SID: 2,
			// current: &init_task, task_session(&init_task): &init_struct_pid
			// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_SID: 2,
			// current: &init_task, task_session(&init_task): &init_struct_pid
			init_task_pid(p, PIDTYPE_SID, task_session(current));

			// init_task_pid 에서 한일:
			// (kmem_cache#15-oX (struct task_struct))->pids[2].pid: &init_struct_pid

			// init_task_pid 에서 한일:
			// (kmem_cache#15-oX (struct task_struct))->pids[2].pid: &init_struct_pid

			// pid: kmem_cache#19-oX (struct pid), is_child_reaper(kmem_cache#19-oX (struct pid)): 1
			// pid: kmem_cache#19-oX (struct pid), is_child_reaper(kmem_cache#19-oX (struct pid)): 0
			if (is_child_reaper(pid)) {
				// pid: kmem_cache#19-oX (struct pid), ns_of_pid(kmem_cache#19-oX (struct pid)): &init_pid_ns
				// ns_of_pid(kmem_cache#19-oX (struct pid))->child_reaper: (&init_pid_ns)->child_reaper,
				// p: kmem_cache#15-oX (struct task_struct)
				ns_of_pid(pid)->child_reaper = p;
				// ns_of_pid(kmem_cache#19-oX (struct pid))->child_reaper: (&init_pid_ns)->child_reaper: kmem_cache#15-oX (struct task_struct)

				// p->signal: (kmem_cache#15-oX (struct task_struct))->signal: kmem_cache#13-oX (struct signal_struct)
				// p->signal->flags: (kmem_cache#13-oX (struct signal_struct))->flags: 0, SIGNAL_UNKILLABLE: 0x00000040
				p->signal->flags |= SIGNAL_UNKILLABLE;
				// p->signal->flags: (kmem_cache#13-oX (struct signal_struct))->flags: 0x00000040
			}

			// p->signal->leader_pid: (kmem_cache#13-oX (struct signal_struct))->leader_pid, pid: kmem_cache#19-oX (struct pid)
			// p->signal->leader_pid: (kmem_cache#13-oX (struct signal_struct))->leader_pid, pid: kmem_cache#19-oX (struct pid)
			p->signal->leader_pid = pid;
			// p->signal->leader_pid: (kmem_cache#13-oX (struct signal_struct))->leader_pid: kmem_cache#19-oX (struct pid)
			// p->signal->leader_pid: (kmem_cache#13-oX (struct signal_struct))->leader_pid: kmem_cache#19-oX (struct pid)

			// p->signal->tty: (kmem_cache#13-oX (struct signal_struct))->tty,
			// current->signal: (&init_task)->signal: &init_signals,
			// current->signal->tty: (&init_signals)->tty: NULL, tty_kref_get(NULL): NULL
			// p->signal->tty: (kmem_cache#13-oX (struct signal_struct))->tty,
			// current->signal: (&init_task)->signal: &init_signals,
			// current->signal->tty: (&init_signals)->tty: NULL, tty_kref_get(NULL): NULL
			p->signal->tty = tty_kref_get(current->signal->tty);
			// p->signal->tty: (kmem_cache#13-oX (struct signal_struct))->tty: NULL
			// p->signal->tty: (kmem_cache#13-oX (struct signal_struct))->tty: NULL

			// &p->sibling: &(kmem_cache#15-oX (struct task_struct))->sibling
			// p->real_parent: (kmem_cache#15-oX (struct task_struct))->real_parent: &init_task
			// &p->real_parent->children: &(&init_task)->children
			// &p->sibling: &(kmem_cache#15-oX (struct task_struct))->sibling
			// p->real_parent: (kmem_cache#15-oX (struct task_struct))->real_parent: &init_task
			// &p->real_parent->children: &(&init_task)->children
			list_add_tail(&p->sibling, &p->real_parent->children);

			// list_add_tail 에서 한일:
			// list head 인 &(&init_task)->children 에 &(kmem_cache#15-oX (struct task_struct))->sibling 을 tail에 연결

			// list_add_tail 에서 한일:
			// list head 인 &(&init_task)->children 에 &(kmem_cache#15-oX (struct task_struct))->sibling 을 tail에 연결

			// &p->tasks: &(kmem_cache#15-oX (struct task_struct))->tasks
			// &p->tasks: &(kmem_cache#15-oX (struct task_struct))->tasks
			list_add_tail_rcu(&p->tasks, &init_task.tasks);

			// list_add_tail_rcu 에서 한일:
			// (&(kmem_cache#15-oX (struct task_struct))->tasks)->next: &init_task.tasks
			// (&(kmem_cache#15-oX (struct task_struct))->tasks)->prev: (&init_task.tasks)->prev
			//
			// core간 write memory barrier 수행
			// ((*((struct list_head __rcu **) (&((&init_task.tasks)->prev)->next)))):
			// (typeof(*&(kmem_cache#15-oX (struct task_struct))->tasks) __force __rcu *)(&(kmem_cache#15-oX (struct task_struct))->tasks);
			//
			// (&init_task.tasks)->prev: &(kmem_cache#15-oX (struct task_struct))->tasks

			// list_add_tail_rcu 에서 한일:
			// (&(kmem_cache#15-oX (struct task_struct))->tasks)->next: &init_task.tasks
			// (&(kmem_cache#15-oX (struct task_struct))->tasks)->prev: (&init_task.tasks)->prev
			//
			// core간 write memory barrier 수행
			// ((*((struct list_head __rcu **) (&((&init_task.tasks)->prev)->next)))):
			// (typeof(*&(kmem_cache#15-oX (struct task_struct))->tasks) __force __rcu *)(&(kmem_cache#15-oX (struct task_struct))->tasks);
			//
			// (&init_task.tasks)->prev: &(kmem_cache#15-oX (struct task_struct))->tasks

// 2016/12/03 종료
// 2016/12/10 시작

			// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PGID: 1
			// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PGID: 1
			attach_pid(p, PIDTYPE_PGID);

			// attach_pid 에서 한일:
			// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->next: NULL
			// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->pprev: &(&(&init_struct_pid)->tasks[1])->first
			//
			// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[1])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node

			// attach_pid 에서 한일:
			// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->next: NULL
			// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->pprev: &(&(&init_struct_pid)->tasks[1])->first
			//
			// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[1])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node

			// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_SID: 2
			attach_pid(p, PIDTYPE_SID);

			// attach_pid 에서 한일:
			// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->next: NULL
			// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->pprev: &(&(&init_struct_pid)->tasks[2])->first
			//
			// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[2])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node

			// attach_pid 에서 한일:
			// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->next: NULL
			// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->pprev: &(&(&init_struct_pid)->tasks[2])->first
			//
			// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[2])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node

			__this_cpu_inc(process_counts);

			// __this_cpu_inc 에서 한일:
			// [pcp0] process_counts: 1 로 증가시킴

			// __this_cpu_inc 에서 한일:
			// [pcp0] process_counts: 1 로 증가시킴
		} else {
			current->signal->nr_threads++;
			atomic_inc(&current->signal->live);
			atomic_inc(&current->signal->sigcnt);
			list_add_tail_rcu(&p->thread_group,
					  &p->group_leader->thread_group);
		}

		// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PID: 0
		// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PID: 0
		attach_pid(p, PIDTYPE_PID);

		// attach_pid 에서 한일:
		// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->next: NULL
		// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->pprev: &(&(kmem_cache#19-oX (struct pid))->tasks[0])->first
		//
		// ((*((struct hlist_node __rcu **)(&(&(kmem_cache#19-oX (struct pid))->tasks[0])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node

		// attach_pid 에서 한일:
		// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->next: NULL
		// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->pprev: &(&(kmem_cache#19-oX (struct pid))->tasks[0])->first
		//
		// ((*((struct hlist_node __rcu **)(&(&(kmem_cache#19-oX (struct pid))->tasks[0])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node

		// nr_threads: 0
		// nr_threads: 1
		nr_threads++;
		// nr_threads: 1
		// nr_threads: 2
	}

	// total_forks: 0
	// total_forks: 1
	total_forks++;
	// total_forks: 1
	// total_forks: 2

	// current: &init_task
	// current->sighand: (&init_task)->sighand: &init_sighand
	// &current->sighand->siglock: &(&init_sighand)->siglock
	// current: &init_task
	// current->sighand: (&init_task)->sighand: &init_sighand
	// &current->sighand->siglock: &(&init_sighand)->siglock
	spin_unlock(&current->sighand->siglock);

	// spin_unlock 에서 한일:
	// &(&init_sighand)->siglock 을 사용하여 spin unlock 수행

	// spin_unlock 에서 한일:
	// &(&init_sighand)->siglock 을 사용하여 spin unlock 수행

	write_unlock_irq(&tasklist_lock);

	// write_unlock_irq 에서 한일:
	// &tasklist_lock 을 사용하여 rw unlock 수행

	// write_unlock_irq 에서 한일:
	// &tasklist_lock 을 사용하여 rw unlock 수행

	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	proc_fork_connector(p); // null function

	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	cgroup_post_fork(p);

	// clone_flags: 0x00800B00, CLONE_THREAD: 0x00010000
	// clone_flags: 0x00800700, CLONE_THREAD: 0x00010000
	if (clone_flags & CLONE_THREAD)
		threadgroup_change_end(current);

	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	perf_event_fork(p); // null function

	// p: kmem_cache#15-oX (struct task_struct), clone_flags: 0x00800B00
	// p: kmem_cache#15-oX (struct task_struct), clone_flags: 0x00800700
	trace_task_newtask(p, clone_flags);

	// p: kmem_cache#15-oX (struct task_struct), clone_flags: 0x00800B00
	// p: kmem_cache#15-oX (struct task_struct), clone_flags: 0x00800700
	uprobe_copy_process(p, clone_flags); // null function

	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)
	return p;
	// return kmem_cache#15-oX (struct task_struct)
	// return kmem_cache#15-oX (struct task_struct)

bad_fork_free_pid:
	if (pid != &init_struct_pid)
		free_pid(pid);
bad_fork_cleanup_io:
	if (p->io_context)
		exit_io_context(p);
bad_fork_cleanup_namespaces:
	exit_task_namespaces(p);
bad_fork_cleanup_mm:
	if (p->mm)
		mmput(p->mm);
bad_fork_cleanup_signal:
	if (!(clone_flags & CLONE_THREAD))
		free_signal_struct(p->signal);
bad_fork_cleanup_sighand:
	__cleanup_sighand(p->sighand);
bad_fork_cleanup_fs:
	exit_fs(p); /* blocking */
bad_fork_cleanup_files:
	exit_files(p); /* blocking */
bad_fork_cleanup_semundo:
	exit_sem(p);
bad_fork_cleanup_audit:
	audit_free(p);
bad_fork_cleanup_policy:
	perf_event_free_task(p);
#ifdef CONFIG_NUMA
	mpol_put(p->mempolicy);
bad_fork_cleanup_cgroup:
#endif
	if (clone_flags & CLONE_THREAD)
		threadgroup_change_end(current);
	cgroup_exit(p, 0);
	delayacct_tsk_free(p);
	module_put(task_thread_info(p)->exec_domain->module);
bad_fork_cleanup_count:
	atomic_dec(&p->cred->user->processes);
	exit_creds(p);
bad_fork_free:
	free_task(p);
fork_out:
	return ERR_PTR(retval);
}

static inline void init_idle_pids(struct pid_link *links)
{
	enum pid_type type;

	for (type = PIDTYPE_PID; type < PIDTYPE_MAX; ++type) {
		INIT_HLIST_NODE(&links[type].node); /* not really needed */
		links[type].pid = &init_struct_pid;
	}
}

struct task_struct *fork_idle(int cpu)
{
	struct task_struct *task;
	task = copy_process(CLONE_VM, 0, 0, NULL, &init_struct_pid, 0);
	if (!IS_ERR(task)) {
		init_idle_pids(task->pids);
		init_idle(task, cpu);
	}

	return task;
}

/*
 *  Ok, this is the main fork-routine.
 *
 * It copies the process, and if successful kick-starts
 * it and waits for it to finish using the VM if required.
 */
// ARM10C 20160827
// flags: 0x00800B00, fn: kernel_init, arg: NULL, NULL, NULL
// ARM10C 20170524
// flags: 0x00800700, fn: kthreadd, arg: NULL, NULL, NULL
long do_fork(unsigned long clone_flags,
	      unsigned long stack_start,
	      unsigned long stack_size,
	      int __user *parent_tidptr,
	      int __user *child_tidptr)
{
	struct task_struct *p;
	int trace = 0;
	// trace: 0
	// trace: 0

	long nr;

	/*
	 * Determine whether and which event to report to ptracer.  When
	 * called from kernel_thread or CLONE_UNTRACED is explicitly
	 * requested, no event is reported; otherwise, report if the event
	 * for the type of forking is enabled.
	 */
	// clone_flags: 0x00800B00, CLONE_UNTRACED: 0x00800000
	// clone_flags: 0x00800700, CLONE_UNTRACED: 0x00800000
	if (!(clone_flags & CLONE_UNTRACED)) {
		if (clone_flags & CLONE_VFORK)
			trace = PTRACE_EVENT_VFORK;
		else if ((clone_flags & CSIGNAL) != SIGCHLD)
			trace = PTRACE_EVENT_CLONE;
		else
			trace = PTRACE_EVENT_FORK;

		if (likely(!ptrace_event_enabled(current, trace)))
			trace = 0;
	}

	// clone_flags: 0x00800B00, stack_start: kernel_init, stack_size: 0, child_tidptr: 0, trace: 0
	// copy_process(0x00800B00, kernel_init, 0, 0, NULL, 0): kmem_cache#15-oX (struct task_struct)
	// clone_flags: 0x00800700, stack_start: kthreadd, stack_size: 0, child_tidptr: 0, trace: 0
	// copy_process(0x00800700, kthreadd, 0, 0, NULL, 0): kmem_cache#15-oX (struct task_struct)
	p = copy_process(clone_flags, stack_start, stack_size,
			 child_tidptr, NULL, trace);
	// p: kmem_cache#15-oX (struct task_struct)
	// p: kmem_cache#15-oX (struct task_struct)

	// copy_process 에서 한일:
	// struct task_struct 만큼의 메모리를 할당 받음
	// kmem_cache#15-oX (struct task_struct)
	//
	// struct thread_info 를 구성 하기 위한 메모리를 할당 받음 (8K)
	// 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 메모리에 init_task 값을 전부 할당함
	//
	// (kmem_cache#15-oX (struct task_struct))->stack: 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 의 stack의 값을 init_task 의 stack 값에서 전부 복사함
	// 복사된 struct thread_info 의 task 주소값을 할당 받은 kmem_cache#15-oX (struct task_struct)로 변경함
	// *(할당 받은 page 2개의 메로리의 가상 주소): init_thread_info
	// ((struct thread_info *) 할당 받은 page 2개의 메로리의 가상 주소)->task: kmem_cache#15-oX (struct task_struct)
	//
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 1 bit 값을 clear 수행
	//
	// *((unsigned long *)(할당 받은 page 2개의 메로리의 가상 주소 + 1)): 0x57AC6E9D
	//
	// (&(kmem_cache#15-oX (struct task_struct))->usage)->counter: 2
	// (kmem_cache#15-oX (struct task_struct))->splice_pipe: NULL
	// (kmem_cache#15-oX (struct task_struct))->task_frag.page: NULL
	//
	// (&contig_page_data)->node_zones[0].vm_stat[16]: 1 을 더함
	// vmstat.c의 vm_stat[16] 전역 변수에도 1을 더함
	//
	// &(kmem_cache#15-oX (struct task_struct))->pi_lock을 사용한 spinlock 초기화
	// &(kmem_cache#15-oX (struct task_struct))->pi_waiters 리스트 초기화
	// (kmem_cache#15-oX (struct task_struct))->pi_blocked_on: NULL
	//
	// (&init_task)->flags: 0x00200100
	// (&init_task)->flags: 0x00200100
	//
	// struct cred 만큼의 메모리를 할당 받음
	// kmem_cache#16-oX (struct cred)
	//
	// kmem_cache#16-oX (struct cred) 에 init_cred 에 있는 맴버값 전부를 복사함
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 1
	// (&(&init_groups)->usage)->counter: 3
	// (&(&root_user)->__count)->counter: 2
	// (&(&root_user)->processes)->counter: 2
	//
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 2
	//
	// (kmem_cache#15-oX (struct task_struct))->cred: kmem_cache#16-oX (struct cred)
	// (kmem_cache#15-oX (struct task_struct))->real_cred: kmem_cache#16-oX (struct cred)
	// (kmem_cache#15-oX (struct task_struct))->did_exec: 0
	// (kmem_cache#15-oX (struct task_struct))->flags: 0x00200040
	//
	// (&(kmem_cache#15-oX (struct task_struct))->children)->next: &(kmem_cache#15-oX (struct task_struct))->children
	// (&(kmem_cache#15-oX (struct task_struct))->children)->prev: &(kmem_cache#15-oX (struct task_struct))->children
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->next: &(kmem_cache#15-oX (struct task_struct))->sibling
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->prev: &(kmem_cache#15-oX (struct task_struct))->sibling
	//
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_lock_nesting: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_unlock_special: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_blocked_node: NULL
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->next: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry
	//
	// (kmem_cache#15-oX (struct task_struct))->vfork_done: NULL
	//
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->magic: 0xdead4ead
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner: 0xffffffff
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner_cpu: 0xffffffff
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list
	//
	// (kmem_cache#15-oX (struct task_struct))->utime: 0
	// (kmem_cache#15-oX (struct task_struct))->stime: 0
	// (kmem_cache#15-oX (struct task_struct))->gtime: 0
	// (kmem_cache#15-oX (struct task_struct))->utimescaled: 0
	// (kmem_cache#15-oX (struct task_struct))->stimescaled: 0
	//
	// &(kmem_cache#15-oX (struct task_struct))->rss_stat 값을 0 으로 초기화 수행
	//
	// (kmem_cache#15-oX (struct task_struct))->default_timer_slack_ns: 50000
	//
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.prof_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.virt_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.sched_exp: 0
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	//
	// (kmem_cache#15-oX (struct task_struct))->start_time 에 현재 시간 값을 가져옴
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_sec: normalized 된 sec 값
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_nsec: normalized 된 nsec 값
	//
	// (kmem_cache#15-oX (struct task_struct))->io_context: NULL
	// (kmem_cache#15-oX (struct task_struct))->audit_context: NULL
	//
	// rcu reference의 값 (&init_task)->cgroups 이 유요한지 체크하고 그 값을 리턴함
	// ((&init_task)->cgroups)->refcount: 1
	// (kmem_cache#15-oX (struct task_struct))->cgroups: (&init_task)->cgroups
	//
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->next: &(kmem_cache#15-oX (struct task_struct))->cg_list
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->prev: &(kmem_cache#15-oX (struct task_struct))->cg_list
	//
	// (kmem_cache#15-oX (struct task_struct))->blocked_on: NULL
	//
	// (&kmem_cache#15-oX (struct task_struct))->on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.exec_start: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.prev_sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.nr_migrations: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.vruntime: 0
	// &(&kmem_cache#15-oX (struct task_struct))->se.group_node의 리스트 초기화
	// &(&kmem_cache#15-oX (struct task_struct))->rt.run_list의 리스트 초기화
	//
	// (kmem_cache#15-oX (struct task_struct))->state: 0
	// (kmem_cache#15-oX (struct task_struct))->prio: 120
	// (kmem_cache#15-oX (struct task_struct))->sched_class: &fair_sched_class
	//
	// 현재의 schedule 시간값과 기존의 (&runqueues)->clock 의 값의 차이값을
	// [pcp0] (&runqueues)->clock, [pcp0] (&runqueues)->clock_task 의 값에 더해 갱신함
	//
	// [pcp0] (&runqueues)->clock: schedule 시간 차이값
	// [pcp0] (&runqueues)->clock_task: schedule 시간 차이값
	//
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (&(kmem_cache#15-oX (struct task_struct))->se)->vruntime: 0x5B8D7E
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->on_cpu: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->preempt_count: 1
	// (&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio: 140
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list
	//
	// (kmem_cache#15-oX (struct task_struct))->sysvsem.undo_list: NULL
	//
	// files_cachep: kmem_cache#12 을 사용하여 struct files_struct 을 위한 메모리를 할당함
	// kmem_cache#12-oX (struct files_struct)
	//
	// (kmem_cache#12-oX (struct files_struct))->count: 1
	//
	// &(kmem_cache#12-oX (struct files_struct))->file_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->owner_cpu: 0xffffffff
	//
	// (kmem_cache#12-oX (struct files_struct))->next_fd: 0
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->max_fds: 32
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->close_on_exec: (kmem_cache#12-oX (struct files_struct))->close_on_exec_init
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->open_fds: (kmem_cache#12-oX (struct files_struct))->open_fds_init
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->fd: &(kmem_cache#12-oX (struct files_struct))->fd_array[0]
	//
	// &(&init_files)->file_lock 을 사용하여 spin lock 수행
	//
	// (kmem_cache#12-oX (struct files_struct))->open_fds_init 에 init_files.open_fds_init 값을 복사
	// (kmem_cache#12-oX (struct files_struct))->open_fds_init: NULL
	// (kmem_cache#12-oX (struct files_struct))->close_on_exec_init 에 init_files.close_on_exec_init 값을 복사
	// (kmem_cache#12-oX (struct files_struct))->close_on_exec_init: NULL
	//
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->open_fds 의 0~31 bit 를 clear 함
	// (kmem_cache#12-oX (struct files_struct))->fd_array[0...31]: NULL
	// &(kmem_cache#12-oX (struct files_struct))->fd_array[0] 에 값을 size 0 만큼 0 으로 set 함
	//
	// (kmem_cache#12-oX (struct files_struct))->fdt: &(kmem_cache#12-oX (struct files_struct))->fdtab
	//
	// (kmem_cache#15-oX (struct task_struct))->files: kmem_cache#12-oX (struct files_struct)
	//
	// (&init_fs)->users: 2
	//
	// (&init_sighand)->count: { (2) }
	//
	// struct signal_struct 크기 만큼의 메모리를 할당함
	// kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#15-oX (struct task_struct))->signal: kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#13-oX (struct signal_struct))->nr_threads: 1
	// (kmem_cache#13-oX (struct signal_struct))->live: { (1) }
	// (kmem_cache#13-oX (struct signal_struct))->sigcnt: { (1) }
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->task_list를 사용한 list 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->curr_target: kmem_cache#15-oX (struct task_struct)
	//
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->next: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->prev: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer의 값을 0으로 초기화
	// (&(kmem_cache#13-oX (struct signal_struct))->real_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// RB Tree의 &(&(kmem_cache#13-oX (struct signal_struct))->real_timer)->node 를 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer.function: it_real_fn
	// (kmem_cache#13-oX (struct signal_struct))->rlim 에 (&init_signals)->rlim 값을 전부 복사함
	// &(kmem_cache#13-oX (struct signal_struct))->cputimer.lock 을 사용한 spinlock 초기화 수행
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->activity: 0
	// &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_lock을 사용한 spinlock 초기화
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj: 0
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj_min: 0
	// (kmem_cache#13-oX (struct signal_struct))->has_child_subreaper: 0
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->count: 1
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->onwer: NULL
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->magic: &(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex
	//
	// (kmem_cache#15-oX (struct task_struct))->min_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->maj_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->nvcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->nivcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->last_switch_count: 0
	// (kmem_cache#15-oX (struct task_struct))->mm: NULL
	//
	// (&init_nsproxy)->count: { (2) }
	//
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context 의 값을 0으로 초기화 함
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183) 의 값을 0으로 초기화 함
	//
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r4: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r5: kernel_init
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)->uregs[16]: 0x00000013
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.pc: ret_from_fork
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.sp: ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->tp_value[1]: TPIDRURW의 읽은 값
	//
	// struct pid 만큼의 메모리를 할당 받음
	// kmem_cache#19-oX (struct pid)
	//
	// (kmem_cache#19-oX (struct pid))->level: 0
	//
	// page 사이즈 만큼의 메모리를 할당 받음: kmem_cache#25-oX
	//
	// (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX
	// kmem_cache#25-oX 의 1 bit 의 값을 1 으로 set
	// (&(&init_pid_ns)->pidmap[0])->nr_free: { (0x7FFF) }
	// &(&init_pid_ns)->last_pid 을 1 로 변경함
	//
	// (kmem_cache#19-oX (struct pid))->numbers[0].nr: 1
	// (kmem_cache#19-oX (struct pid))->numbers[0].ns: &init_pid_ns
	//
	// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 3번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 4         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 4)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 4 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 5
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 4
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 4) 의 memory 공간을 반환함
	//
	// mnt_id_start: 5
	//
	// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "proc"
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
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 4번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 4         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 4)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	//
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// (&(&unnamed_dev_ida)->idr)->id_free: (idr object new 0)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 4 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 5
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 4) 의 memory 공간을 반환함
	//
	// unnamed_dev_start: 5
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 4
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_fs_info: &init_pid_ns
	// (kmem_cache#25-oX (struct super_block))->s_type: &proc_fs_type
	// (kmem_cache#25-oX (struct super_block))->s_id: "proc"
	//
	// list head인 &super_blocks 에 (kmem_cache#25-oX (struct super_block))->s_list을 tail에 추가
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->next: NULL
	// (&(&proc_fs_type)->fs_supers)->first: &(kmem_cache#25-oX (struct super_block))->s_instances
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->pprev: &(&(&proc_fs_type)->fs_supers)->first
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->flags: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->nr_deferred: kmem_cache#30-oX
	// head list인 &shrinker_list에 &(&(kmem_cache#25-oX (struct super_block))->s_shrink)->list를 tail로 추가함
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x40080a
	// (kmem_cache#25-oX (struct super_block))->s_blocksize: 1024
	// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 10
	// (kmem_cache#25-oX (struct super_block))->s_magic: 0x9fa0
	// (kmem_cache#25-oX (struct super_block))->s_op: &proc_sops
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1
	//
	// (&proc_root)->count: { (2) }
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
	// [pcp0] nr_inodes: 2
	//
	// (kmem_cache#4-oX (struct inode))->i_state: 0
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
	//
	// (kmem_cache#4-oX (struct inode))->i_ino: 1
	// (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->pde: &proc_root
	// (kmem_cache#4-oX (struct inode))->i_mode: 0040555
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
	// (kmem_cache#4-oX (struct inode))->i_op: &proc_root_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_fop: &proc_root_operations
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
	// [pcp0] nr_dentry: 3
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
	// (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
	//
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
	// [pcp0] nr_inodes: 3
	//
	// (kmem_cache#4-oX (struct inode))->i_state: 0
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// (kmem_cache#4-oX (struct inode))->i_ino: 0xF0000001
	// (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_mode: 0120777
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#4-oX (struct inode))->i_op: &proc_self_inode_operations
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
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100080
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->pprev: &(hash 0xXXXXXXXX 에 맞는 list table 주소값)->first
	//
	// ((hash 0xXXXXXXXX 에 맞는 list table 주소값)->first): ((&(kmem_cache#5-oX (struct dentry))->d_hash) | 1)
	//
	// (&init_pid_ns)->proc_self: kmem_cache#5-oX (struct dentry)
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_lockref)->count: 1
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x6040080a
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
	// (&init_pid_ns)->proc_mnt: &(kmem_cache#2-oX (struct mount))->mnt
	//
	// (&(kmem_cache#19-oX (struct pid))->count)->counter: 1
	// (&(kmem_cache#19-oX (struct pid))->tasks[0...2])->first: NULL
	//
	// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->next: NULL
	// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->pprev: &(&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first
	// ((&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first): &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain
	//
	// (&init_pid_ns)->nr_hashed: 0x80000001
	//
	// (kmem_cache#15-oX (struct task_struct))->set_child_tid: NULL
	// (kmem_cache#15-oX (struct task_struct))->clear_child_tid: NULL
	// (kmem_cache#15-oX (struct task_struct))->plug: NULL
	// (kmem_cache#15-oX (struct task_struct))->robust_list: NULL
	//
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->next: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->prev: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	//
	// (kmem_cache#15-oX (struct task_struct))->pi_state_cache: NULL
	//
	// (kmem_cache#15-oX (struct task_struct))->sas_ss_sp: 0
	// (kmem_cache#15-oX (struct task_struct))->sas_ss_size: 0
	//
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 8 bit 값을 clear 수행
	//
	// (kmem_cache#15-oX (struct task_struct))->pid: 1
	// (kmem_cache#15-oX (struct task_struct))->exit_signal: 0
	// (kmem_cache#15-oX (struct task_struct))->group_leader: kmem_cache#15-oX (struct task_struct)
	// (kmem_cache#15-oX (struct task_struct))->tgid: 1
	//
	// (kmem_cache#15-oX (struct task_struct))->pdeath_signal: 0
	// (kmem_cache#15-oX (struct task_struct))->exit_state: 0
	// (kmem_cache#15-oX (struct task_struct))->nr_dirtied: 0
	// (kmem_cache#15-oX (struct task_struct))->nr_dirtied_pause: 32
	// (kmem_cache#15-oX (struct task_struct))->dirty_paused_when: 0
	//
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->next: &(kmem_cache#15-oX (struct task_struct))->thread_group
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->prev: &(kmem_cache#15-oX (struct task_struct))->thread_group
	//
	// (kmem_cache#15-oX (struct task_struct))->task_works: NULL
	//
	// (kmem_cache#15-oX (struct task_struct))->real_parent: &init_task
	// (kmem_cache#15-oX (struct task_struct))->parent_exec_id: 0
	//
	// (init_task의 struct thread_info 주소값)->flags 의 0 bit 값을 clear 수행
	//
	// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->next: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
	// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
	// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->next: &(kmem_cache#15-oX (struct task_struct))->ptraced
	// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->prev: &(kmem_cache#15-oX (struct task_struct))->ptraced
	// (kmem_cache#15-oX (struct task_struct))->jobctl: 0
	// (kmem_cache#15-oX (struct task_struct))->ptrace: 0
	// (kmem_cache#15-oX (struct task_struct))->parent: &init_task
	//
	// (kmem_cache#15-oX (struct task_struct))->pids[0].pid: kmem_cache#19-oX (struct pid)
	//
	// (kmem_cache#15-oX (struct task_struct))->pids[1].pid: &init_struct_pid
	// (kmem_cache#15-oX (struct task_struct))->pids[2].pid: &init_struct_pid
	//
	// (kmem_cache#13-oX (struct signal_struct))->flags: 0x00000040
	// (kmem_cache#13-oX (struct signal_struct))->leader_pid: kmem_cache#19-oX (struct pid)
	// (kmem_cache#13-oX (struct signal_struct))->tty: NULL
	//
	// list head 인 &(&init_task)->children 에 &(kmem_cache#15-oX (struct task_struct))->sibling 을 tail에 연결
	//
	// (&(kmem_cache#15-oX (struct task_struct))->tasks)->next: &init_task.tasks
	// (&(kmem_cache#15-oX (struct task_struct))->tasks)->prev: (&init_task.tasks)->prev
	//
	// core간 write memory barrier 수행
	// ((*((struct list_head __rcu **) (&((&init_task.tasks)->prev)->next)))):
	// (typeof(*&(kmem_cache#15-oX (struct task_struct))->tasks) __force __rcu *)(&(kmem_cache#15-oX (struct task_struct))->tasks);
	//
	// (&init_task.tasks)->prev: &(kmem_cache#15-oX (struct task_struct))->tasks
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->pprev: &(&(&init_struct_pid)->tasks[1])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[1])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->pprev: &(&(&init_struct_pid)->tasks[2])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[2])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node
	//
	// [pcp0] process_counts: 1 로 증가시킴
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->pprev: &(&(kmem_cache#19-oX (struct pid))->tasks[0])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(kmem_cache#19-oX (struct pid))->tasks[0])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node
	//
	// nr_threads: 1
	//
	// total_forks: 1

	// copy_process 에서 한일:
	// struct task_struct 만큼의 메모리를 할당 받음
	// kmem_cache#15-oX (struct task_struct)
	//
	// struct thread_info 를 구성 하기 위한 메모리를 할당 받음 (8K)
	// 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 메모리에 init_task 값을 전부 할당함
	//
	// (kmem_cache#15-oX (struct task_struct))->stack: 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 의 stack의 값을 init_task 의 stack 값에서 전부 복사함
	// 복사된 struct thread_info 의 task 주소값을 할당 받은 kmem_cache#15-oX (struct task_struct)로 변경함
	// *(할당 받은 page 2개의 메로리의 가상 주소): init_thread_info
	// ((struct thread_info *) 할당 받은 page 2개의 메로리의 가상 주소)->task: kmem_cache#15-oX (struct task_struct)
	//
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 1 bit 값을 clear 수행
	//
	// *((unsigned long *)(할당 받은 page 2개의 메로리의 가상 주소 + 1)): 0x57AC6E9D
	//
	// (&(kmem_cache#15-oX (struct task_struct))->usage)->counter: 2
	// (kmem_cache#15-oX (struct task_struct))->splice_pipe: NULL
	// (kmem_cache#15-oX (struct task_struct))->task_frag.page: NULL
	//
	// (&contig_page_data)->node_zones[0].vm_stat[16]: 1 을 더함
	// vmstat.c의 vm_stat[16] 전역 변수에도 1을 더함
	//
	// &(kmem_cache#15-oX (struct task_struct))->pi_lock을 사용한 spinlock 초기화
	// &(kmem_cache#15-oX (struct task_struct))->pi_waiters 리스트 초기화
	// (kmem_cache#15-oX (struct task_struct))->pi_blocked_on: NULL
	//
	// (&init_task)->flags: 0x00200100
	//
	// struct cred 만큼의 메모리를 할당 받음
	// kmem_cache#16-oX (struct cred)
	//
	// kmem_cache#16-oX (struct cred) 에 init_cred 에 있는 맴버값 전부를 복사함
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 1
	// (&(&init_groups)->usage)->counter: 4
	// (&(&root_user)->__count)->counter: 3
	//
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 2
	//
	// (kmem_cache#15-oX (struct task_struct))->cred: kmem_cache#16-oX (struct cred)
	// (kmem_cache#15-oX (struct task_struct))->real_cred: kmem_cache#16-oX (struct cred)
	// (kmem_cache#15-oX (struct task_struct))->did_exec: 0
	// (kmem_cache#15-oX (struct task_struct))->flags: 0x00200040
	//
	// (&(kmem_cache#15-oX (struct task_struct))->children)->next: &(kmem_cache#15-oX (struct task_struct))->children
	// (&(kmem_cache#15-oX (struct task_struct))->children)->prev: &(kmem_cache#15-oX (struct task_struct))->children
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->next: &(kmem_cache#15-oX (struct task_struct))->sibling
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->prev: &(kmem_cache#15-oX (struct task_struct))->sibling
	//
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_lock_nesting: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_unlock_special: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_blocked_node: NULL
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->next: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry
	//
	// (kmem_cache#15-oX (struct task_struct))->vfork_done: NULL
	//
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->magic: 0xdead4ead
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner: 0xffffffff
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner_cpu: 0xffffffff
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list
	//
	// (kmem_cache#15-oX (struct task_struct))->utime: 0
	// (kmem_cache#15-oX (struct task_struct))->stime: 0
	// (kmem_cache#15-oX (struct task_struct))->gtime: 0
	// (kmem_cache#15-oX (struct task_struct))->utimescaled: 0
	// (kmem_cache#15-oX (struct task_struct))->stimescaled: 0
	//
	// &(kmem_cache#15-oX (struct task_struct))->rss_stat 값을 0 으로 초기화 수행
	//
	// (kmem_cache#15-oX (struct task_struct))->default_timer_slack_ns: 50000
	//
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.prof_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.virt_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.sched_exp: 0
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	//
	// (kmem_cache#15-oX (struct task_struct))->start_time 에 현재 시간 값을 가져옴
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_sec: normalized 된 sec 값
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_nsec: normalized 된 nsec 값
	//
	// (kmem_cache#15-oX (struct task_struct))->io_context: NULL
	// (kmem_cache#15-oX (struct task_struct))->audit_context: NULL
	//
	// rcu reference의 값 (&init_task)->cgroups 이 유요한지 체크하고 그 값을 리턴함
	// ((&init_task)->cgroups)->refcount: 1
	// (kmem_cache#15-oX (struct task_struct))->cgroups: (&init_task)->cgroups
	//
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->next: &(kmem_cache#15-oX (struct task_struct))->cg_list
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->prev: &(kmem_cache#15-oX (struct task_struct))->cg_list
	//
	// (kmem_cache#15-oX (struct task_struct))->blocked_on: NULL
	//
	// (&kmem_cache#15-oX (struct task_struct))->on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.exec_start: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.prev_sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.nr_migrations: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.vruntime: 0
	// &(&kmem_cache#15-oX (struct task_struct))->se.group_node의 리스트 초기화
	// &(&kmem_cache#15-oX (struct task_struct))->rt.run_list의 리스트 초기화
	//
	// (kmem_cache#15-oX (struct task_struct))->state: 0
	// (kmem_cache#15-oX (struct task_struct))->prio: 120
	// (kmem_cache#15-oX (struct task_struct))->sched_class: &fair_sched_class
	//
	// 현재의 schedule 시간값과 기존의 (&runqueues)->clock 의 값의 차이값을
	// [pcp0] (&runqueues)->clock, [pcp0] (&runqueues)->clock_task 의 값에 더해 갱신함
	//
	// [pcp0] (&runqueues)->clock: schedule 시간 차이값
	// [pcp0] (&runqueues)->clock_task: schedule 시간 차이값
	//
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (&(kmem_cache#15-oX (struct task_struct))->se)->vruntime: 0x5B8D7E
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->on_cpu: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->preempt_count: 1
	// (&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio: 140
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list
	//
	// (kmem_cache#15-oX (struct task_struct))->sysvsem.undo_list: NULL
	//
	// files_cachep: kmem_cache#12 을 사용하여 struct files_struct 을 위한 메모리를 할당함
	// kmem_cache#12-oX (struct files_struct)
	//
	// (kmem_cache#12-oX (struct files_struct))->count: 1
	//
	// &(kmem_cache#12-oX (struct files_struct))->file_lock을 이용한 spin lock 초기화 수행
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->raw_lock: { { 0 } }
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->magic: 0xdead4ead
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->owner: 0xffffffff
	// ((&(kmem_cache#12-oX (struct files_struct))->file_lock)->rlock)->owner_cpu: 0xffffffff
	//
	// (kmem_cache#12-oX (struct files_struct))->next_fd: 0
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->max_fds: 32
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->close_on_exec: (kmem_cache#12-oX (struct files_struct))->close_on_exec_init
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->open_fds: (kmem_cache#12-oX (struct files_struct))->open_fds_init
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->fd: &(kmem_cache#12-oX (struct files_struct))->fd_array[0]
	//
	// &(&init_files)->file_lock 을 사용하여 spin lock 수행
	//
	// (kmem_cache#12-oX (struct files_struct))->open_fds_init 에 init_files.open_fds_init 값을 복사
	// (kmem_cache#12-oX (struct files_struct))->open_fds_init: NULL
	// (kmem_cache#12-oX (struct files_struct))->close_on_exec_init 에 init_files.close_on_exec_init 값을 복사
	// (kmem_cache#12-oX (struct files_struct))->close_on_exec_init: NULL
	//
	// (&(kmem_cache#12-oX (struct files_struct))->fdtab)->open_fds 의 0~31 bit 를 clear 함
	// (kmem_cache#12-oX (struct files_struct))->fd_array[0...31]: NULL
	// &(kmem_cache#12-oX (struct files_struct))->fd_array[0] 에 값을 size 0 만큼 0 으로 set 함
	//
	// (kmem_cache#12-oX (struct files_struct))->fdt: &(kmem_cache#12-oX (struct files_struct))->fdtab
	//
	// (kmem_cache#15-oX (struct task_struct))->files: kmem_cache#12-oX (struct files_struct)
	//
	// (&init_fs)->users: 2
	//
	// (&init_sighand)->count: { (2) }
	//
	// struct signal_struct 크기 만큼의 메모리를 할당함
	// kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#15-oX (struct task_struct))->signal: kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#13-oX (struct signal_struct))->nr_threads: 1
	// (kmem_cache#13-oX (struct signal_struct))->live: { (1) }
	// (kmem_cache#13-oX (struct signal_struct))->sigcnt: { (1) }
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->task_list를 사용한 list 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->curr_target: kmem_cache#15-oX (struct task_struct)
	//
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->next: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->prev: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer의 값을 0으로 초기화
	// (&(kmem_cache#13-oX (struct signal_struct))->real_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// RB Tree의 &(&(kmem_cache#13-oX (struct signal_struct))->real_timer)->node 를 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer.function: it_real_fn
	// (kmem_cache#13-oX (struct signal_struct))->rlim 에 (&init_signals)->rlim 값을 전부 복사함
	// &(kmem_cache#13-oX (struct signal_struct))->cputimer.lock 을 사용한 spinlock 초기화 수행
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->activity: 0
	// &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_lock을 사용한 spinlock 초기화
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj: 0
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj_min: 0
	// (kmem_cache#13-oX (struct signal_struct))->has_child_subreaper: 0
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->count: 1
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->onwer: NULL
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->magic: &(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex
	//
	// (kmem_cache#15-oX (struct task_struct))->min_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->maj_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->nvcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->nivcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->last_switch_count: 0
	// (kmem_cache#15-oX (struct task_struct))->mm: NULL
	//
	// (&init_nsproxy)->count: { (2) }
	//
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context 의 값을 0으로 초기화 함
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183) 의 값을 0으로 초기화 함
	//
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r4: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r5: kernel_init
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)->uregs[16]: 0x00000013
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.pc: ret_from_fork
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.sp: ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->tp_value[1]: TPIDRURW의 읽은 값
	//
	// struct pid 만큼의 메모리를 할당 받음
	// kmem_cache#19-oX (struct pid)
	//
	// (kmem_cache#19-oX (struct pid))->level: 0
	//
	// 기존에 할당받은 pidmap의 메모리 값
	// (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX
	// kmem_cache#25-oX 의 2 bit 의 값을 1 으로 set
	// (&(&init_pid_ns)->pidmap[0])->nr_free: { (0x7FFE) }
	// &(&init_pid_ns)->last_pid 을 2 로 변경함
	//
	// (kmem_cache#19-oX (struct pid))->numbers[0].nr: 2
	// (kmem_cache#19-oX (struct pid))->numbers[0].ns: &init_pid_ns
	//
	// (&(kmem_cache#19-oX (struct pid))->count)->counter: 1
	//
	// (&(kmem_cache#19-oX (struct pid))->tasks[0...2])->first: NULL
	//
	// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->next: NULL
	// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->pprev: &(&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first
	// ((&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first): &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain
	//
	// (&init_pid_ns)->nr_hashed: 0x80000002
	//
	// (kmem_cache#15-oX (struct task_struct))->set_child_tid: NULL
	// (kmem_cache#15-oX (struct task_struct))->clear_child_tid: NULL
	// (kmem_cache#15-oX (struct task_struct))->plug: NULL
	// (kmem_cache#15-oX (struct task_struct))->robust_list: NULL
	//
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->next: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->prev: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	//
	// (kmem_cache#15-oX (struct task_struct))->pi_state_cache: NULL
	//
	// (kmem_cache#15-oX (struct task_struct))->sas_ss_sp: 0
	// (kmem_cache#15-oX (struct task_struct))->sas_ss_size: 0
	//
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 8 bit 값을 clear 수행
	//
	// (kmem_cache#15-oX (struct task_struct))->pid: 2
	// (kmem_cache#15-oX (struct task_struct))->exit_signal: 0
	// (kmem_cache#15-oX (struct task_struct))->group_leader: kmem_cache#15-oX (struct task_struct)
	// (kmem_cache#15-oX (struct task_struct))->tgid: 2
	//
	// (kmem_cache#15-oX (struct task_struct))->pdeath_signal: 0
	// (kmem_cache#15-oX (struct task_struct))->exit_state: 0
	// (kmem_cache#15-oX (struct task_struct))->nr_dirtied: 0
	// (kmem_cache#15-oX (struct task_struct))->nr_dirtied_pause: 32
	// (kmem_cache#15-oX (struct task_struct))->dirty_paused_when: 0
	//
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->next: &(kmem_cache#15-oX (struct task_struct))->thread_group
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->prev: &(kmem_cache#15-oX (struct task_struct))->thread_group
	//
	// (kmem_cache#15-oX (struct task_struct))->task_works: NULL
	//
	// (kmem_cache#15-oX (struct task_struct))->real_parent: &init_task
	// (kmem_cache#15-oX (struct task_struct))->parent_exec_id: 0
	//
	// (init_task의 struct thread_info 주소값)->flags 의 0 bit 값을 clear 수행
	//
	// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->next: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
	// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
	// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->next: &(kmem_cache#15-oX (struct task_struct))->ptraced
	// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->prev: &(kmem_cache#15-oX (struct task_struct))->ptraced
	// (kmem_cache#15-oX (struct task_struct))->jobctl: 0
	// (kmem_cache#15-oX (struct task_struct))->ptrace: 0
	// (kmem_cache#15-oX (struct task_struct))->parent: &init_task
	//
	// (kmem_cache#15-oX (struct task_struct))->pids[0].pid: kmem_cache#19-oX (struct pid)
	//
	// (kmem_cache#15-oX (struct task_struct))->pids[1].pid: &init_struct_pid
	// (kmem_cache#15-oX (struct task_struct))->pids[2].pid: &init_struct_pid
	//
	// (kmem_cache#13-oX (struct signal_struct))->flags: 0x00000040
	// (kmem_cache#13-oX (struct signal_struct))->leader_pid: kmem_cache#19-oX (struct pid)
	// (kmem_cache#13-oX (struct signal_struct))->tty: NULL
	//
	// list head 인 &(&init_task)->children 에 &(kmem_cache#15-oX (struct task_struct))->sibling 을 tail에 연결
	//
	// (&(kmem_cache#15-oX (struct task_struct))->tasks)->next: &init_task.tasks
	// (&(kmem_cache#15-oX (struct task_struct))->tasks)->prev: (&init_task.tasks)->prev
	//
	// core간 write memory barrier 수행
	// ((*((struct list_head __rcu **) (&((&init_task.tasks)->prev)->next)))):
	// (typeof(*&(kmem_cache#15-oX (struct task_struct))->tasks) __force __rcu *)(&(kmem_cache#15-oX (struct task_struct))->tasks);
	//
	// (&init_task.tasks)->prev: &(kmem_cache#15-oX (struct task_struct))->tasks
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->pprev: &(&(&init_struct_pid)->tasks[1])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[1])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->pprev: &(&(&init_struct_pid)->tasks[2])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[2])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node
	//
	// [pcp0] process_counts: 1 로 증가시킴
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->pprev: &(&(kmem_cache#19-oX (struct pid))->tasks[0])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(kmem_cache#19-oX (struct pid))->tasks[0])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node
	//
	// nr_threads: 2
	//
	// total_forks: 2

// 2017/06/10 종료
// 2017/06/17 시작

	/*
	 * Do this prior waking up the new thread - the thread pointer
	 * might get invalid after that point, if the thread exits quickly.
	 */
	// p: kmem_cache#15-oX (struct task_struct), IS_ERR(kmem_cache#15-oX (struct task_struct)): 0
	// p: kmem_cache#15-oX (struct task_struct), IS_ERR(kmem_cache#15-oX (struct task_struct)): 0
	if (!IS_ERR(p)) {
		struct completion vfork;

		// current: &init_task, p: kmem_cache#15-oX (struct task_struct)
		// current: &init_task, p: kmem_cache#15-oX (struct task_struct)
		trace_sched_process_fork(current, p);

		// p: kmem_cache#15-oX (struct task_struct), task_pid_vnr(kmem_cache#15-oX (struct task_struct)): 1
		// p: kmem_cache#15-oX (struct task_struct), task_pid_vnr(kmem_cache#15-oX (struct task_struct)): 2
		nr = task_pid_vnr(p);
		// nr: 1
		// nr: 2

		// clone_flags: 0x00800B00, CLONE_PARENT_SETTID: 0x00100000
		// clone_flags: 0x00800700, CLONE_PARENT_SETTID: 0x00100000
		if (clone_flags & CLONE_PARENT_SETTID)
			put_user(nr, parent_tidptr);

		// clone_flags: 0x00800B00, CLONE_VFORK: 0x00004000
		// clone_flags: 0x00800700, CLONE_VFORK: 0x00004000
		if (clone_flags & CLONE_VFORK) {
			p->vfork_done = &vfork;
			init_completion(&vfork);
			get_task_struct(p);
		}

		// p: kmem_cache#15-oX (struct task_struct)
		// p: kmem_cache#15-oX (struct task_struct) -pid: 2
		wake_up_new_task(p);

		// wake_up_new_task 에서 한일:
		// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
		// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
		// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
		// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
		// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
		// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
		//
		// (kmem_cache#15-oX (struct task_struct))->se.avg.decay_count: 0
		// (kmem_cache#15-oX (struct task_struct))->se.avg.runnable_avg_sum: 현재 task의 남아 있는 수행 시간량 / 1024
		// (kmem_cache#15-oX (struct task_struct))->se.avg.runnable_avg_period: 현재 task의 남아 있는 수행 시간량 / 1024
		// (&(kmem_cache#15-oX (struct task_struct))->se)->avg.load_avg_contrib:
		// 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
		//
		// [pcp0] (&runqueues)->clock: 현재의 schedule 시간값
		// [pcp0] (&runqueues)->clock_task: 현재의 schedule 시간값
		//
		// (&(kmem_cache#15-oX (struct task_struct))->se)->vruntime: 0x4B8D7E
		//
		// (&(kmem_cache#15-oX (struct task_struct))->se)->avg.last_runnable_update: 현재의 schedule 시간값
		// [pcp0] (&(&runqueues)->cfs)->runnable_load_avg: 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
		//
		// decays: 현재의 schedule 시간값>> 20 값이 0이 아닌 상수 값이라 가정하고 분석 진행
		//
		// [pcp0] (&(&runqueues)->cfs)->blocked_load_avg: 0
		// [pcp0] (&(&(&runqueues)->cfs)->decay_counter)->counter: 2
		// [pcp0] (&(&runqueues)->cfs)->last_decay: 현재의 schedule 시간값>> 20
		//
		// (&(&root_task_group)->load_avg)->counter: 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
		// [pcp0] (&(&runqueues)->cfs)->tg_load_contrib: 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
		//
		// [pcp0] (&(&(&runqueues)->cfs)->load)->weight: 2048
		// [pcp0] (&(&(&runqueues)->cfs)->load)->inv_weight: 0
		// [pcp0] (&(&runqueues)->load)->weight: 1024
		// [pcp0] (&(&runqueues)->load)->inv_weight: 0
		// [pcp0] &(&runqueues)->cfs_tasks 란 list head에 &(&(kmem_cache#15-oX (struct task_struct))->se)->group_node 를 추가함
		// [pcp0] (&(&runqueues)->cfs)->nr_running: 1
		//
		// [pcp0] (&(&runqueues)->cfs)->rb_leftmost: &(&(kmem_cache#15-oX (struct task_struct))->se)->run_node
		//
		// (&(&(kmem_cache#15-oX (struct task_struct))->se)->run_node)->__rb_parent_color: NULL
		// (&(&(kmem_cache#15-oX (struct task_struct))->se)->run_node)->rb_left: NULL
		// (&(&(kmem_cache#15-oX (struct task_struct))->se)->run_node)->rb_right: NULL
		// [pcp0] (&(&runqueues)->cfs)->tasks_timeline.rb_node: &(&(kmem_cache#15-oX (struct task_struct))->se
		//
		/*
		// rb tree 의 root인 [pcp0] &(&(&runqueues)->cfs)->tasks_timeline 에
		// rb node인 &(&(kmem_cache#15-oX (struct task_struct))->se)->run_node 가 추가되어 rb tree 구성
		//
		//                            task ID: 1-b
		//                            /           \
		*/
		// (&(kmem_cache#15-oX (struct task_struct))->se)->on_rq: 1
		//
		// list head인 [pcp0] &(&runqueues)->leaf_cfs_rq_list에 [pcp0] &(&(&runqueues)->cfs)->leaf_cfs_rq_list 을 tail에 추가함
		//
		// [pcp0] (&(&(&runqueues)->cfs)->leaf_cfs_rq_list)->next: [pcp0] &(&runqueues)->leaf_cfs_rq_list
		// [pcp0] (&(&(&runqueues)->cfs)->leaf_cfs_rq_list)->prev: [pcp0] (&(&runqueues)->leaf_cfs_rq_list)->prev
		//
		// core간 write memory barrier 수행
		// ((*((struct list_head __rcu **) (&(([pcp0] &(&runqueues)->leaf_cfs_rq_list)->prev)->next)))):
		// (typeof(*[pcp0] &(&(&runqueues)->cfs)->leaf_cfs_rq_list) __force __rcu *)([pcp0] &(&(&runqueues)->cfs)->leaf_cfs_rq_list);
		//
		// [pcp0] (&(&runqueues)->leaf_cfs_rq_list)->prev: [pcp0] &(&(&runqueues)->cfs)->leaf_cfs_rq_list
		//
		// [pcp0] (&(&runqueues)->cfs)->on_list: 1
		//
		// [pcp0] (&(&runqueues)->cfs)->blocked_load_avg: 0
		// (&(&(&runqueues)->cfs)->decay_counter)->counter: 현재의 schedule 시간값>> 20 + 1 + 시간값x
		// [pcp0] (&(&runqueues)->cfs)->last_decay: 현재의 schedule 시간값 + 시간값x >> 20
		//
		// [pcp0] (&(&runqueues)->cfs)->h_nr_running: 2
		//
		// delta: 현재의 schedule 시간 변화값은 signed 로 변경시 0 보다 큰 값으로 가정하고 코드 분석 진행
		//
		// (&(&(kmem_cache#15-oX (struct task_struct))->se)->avg)->last_runnable_update: 현재의 schedule 시간값
		//
		// delta + delta_w 값이 1024 보다 작은 값이라고 가정하고 코드 분석 진행
		//
		// (&(&(kmem_cache#15-oX (struct task_struct))->se)->avg)->runnable_avg_sum:
		// 현재 task의 남아 있는 수행 시간량 / 1024 + 현재의 schedule 시간 변화값
		// (&(&(kmem_cache#15-oX (struct task_struct))->se)->avg)->runnable_avg_period:
		// 현재 task의 남아 있는 수행 시간량 / 1024 + 현재의 schedule 시간 변화값
		//
		// (kmem_cache#15-oX (struct task_struct))->on_rq: 1

// 2017/05/20 종료
// 2017/05/24 시작

		/* forking complete and child started to run, tell ptracer */
		// trace: 0
		if (unlikely(trace))
			ptrace_event(trace, nr);

		// clone_flags: 0x00800B00, CLONE_VFORK: 0x00004000
		if (clone_flags & CLONE_VFORK) {
			if (!wait_for_vfork_done(p, &vfork))
				ptrace_event(PTRACE_EVENT_VFORK_DONE, nr);
		}
	} else {
		nr = PTR_ERR(p);
	}

	// nr: 1
	return nr;
	// return 1
}

/*
 * Create a kernel thread.
 */
// ARM10C 20160827
// kernel_init, NULL, 0x00000A00
// ARM10C 20170524
// kthreadd, NULL, 0x00000600
pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags)
{
	// flags: 0x00000A00, CLONE_VM: 0x00000100, CLONE_UNTRACED: 0x00800000,
	// fn: kernel_init, arg: NULL
	// do_fork(0x00800B00, kernel_init, NULL, NULL, NULL): 1
	//
	// flags: 0x00000600, CLONE_VM: 0x00000100, CLONE_UNTRACED: 0x00800000,
	// fn: kthreadd, arg: NULL
	return do_fork(flags|CLONE_VM|CLONE_UNTRACED, (unsigned long)fn,
		(unsigned long)arg, NULL, NULL);
	// return 1

	// do_fork 에서 한일:
	// struct task_struct 만큼의 메모리를 할당 받음
	// kmem_cache#15-oX (struct task_struct)
	//
	// struct thread_info 를 구성 하기 위한 메모리를 할당 받음 (8K)
	// 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 메모리에 init_task 값을 전부 할당함
	//
	// (kmem_cache#15-oX (struct task_struct))->stack: 할당 받은 page 2개의 메로리의 가상 주소
	//
	// 할당 받은 kmem_cache#15-oX (struct task_struct) 의 stack의 값을 init_task 의 stack 값에서 전부 복사함
	// 복사된 struct thread_info 의 task 주소값을 할당 받은 kmem_cache#15-oX (struct task_struct)로 변경함
	// *(할당 받은 page 2개의 메로리의 가상 주소): init_thread_info
	// ((struct thread_info *) 할당 받은 page 2개의 메로리의 가상 주소)->task: kmem_cache#15-oX (struct task_struct)
	//
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 1 bit 값을 clear 수행
	//
	// *((unsigned long *)(할당 받은 page 2개의 메로리의 가상 주소 + 1)): 0x57AC6E9D
	//
	// (&(kmem_cache#15-oX (struct task_struct))->usage)->counter: 2
	// (kmem_cache#15-oX (struct task_struct))->splice_pipe: NULL
	// (kmem_cache#15-oX (struct task_struct))->task_frag.page: NULL
	//
	// (&contig_page_data)->node_zones[0].vm_stat[16]: 1 을 더함
	// vmstat.c의 vm_stat[16] 전역 변수에도 1을 더함
	//
	// &(kmem_cache#15-oX (struct task_struct))->pi_lock을 사용한 spinlock 초기화
	// &(kmem_cache#15-oX (struct task_struct))->pi_waiters 리스트 초기화
	// (kmem_cache#15-oX (struct task_struct))->pi_blocked_on: NULL
	//
	// (&init_task)->flags: 0x00200100
	// (&init_task)->flags: 0x00200100
	//
	// struct cred 만큼의 메모리를 할당 받음
	// kmem_cache#16-oX (struct cred)
	//
	// kmem_cache#16-oX (struct cred) 에 init_cred 에 있는 맴버값 전부를 복사함
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 1
	// (&(&init_groups)->usage)->counter: 3
	// (&(&root_user)->__count)->counter: 2
	// (&(&root_user)->processes)->counter: 2
	//
	// (&(kmem_cache#16-oX (struct cred))->usage)->counter: 2
	//
	// (kmem_cache#15-oX (struct task_struct))->cred: kmem_cache#16-oX (struct cred)
	// (kmem_cache#15-oX (struct task_struct))->real_cred: kmem_cache#16-oX (struct cred)
	// (kmem_cache#15-oX (struct task_struct))->did_exec: 0
	// (kmem_cache#15-oX (struct task_struct))->flags: 0x00200040
	//
	// (&(kmem_cache#15-oX (struct task_struct))->children)->next: &(kmem_cache#15-oX (struct task_struct))->children
	// (&(kmem_cache#15-oX (struct task_struct))->children)->prev: &(kmem_cache#15-oX (struct task_struct))->children
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->next: &(kmem_cache#15-oX (struct task_struct))->sibling
	// (&(kmem_cache#15-oX (struct task_struct))->sibling)->prev: &(kmem_cache#15-oX (struct task_struct))->sibling
	//
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_lock_nesting: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_read_unlock_special: 0
	// (kmem_cache#15-oX (struct task_struct))->rcu_blocked_node: NULL
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->next: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry
	// (&(kmem_cache#15-oX (struct task_struct))->rcu_node_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->rcu_node_entry
	//
	// (kmem_cache#15-oX (struct task_struct))->vfork_done: NULL
	//
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->raw_lock: { { 0 } }
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->magic: 0xdead4ead
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner: 0xffffffff
	// (&(kmem_cache#15-oX (struct task_struct))->alloc_lock)->owner_cpu: 0xffffffff
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pending)->list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pending)->list
	//
	// (kmem_cache#15-oX (struct task_struct))->utime: 0
	// (kmem_cache#15-oX (struct task_struct))->stime: 0
	// (kmem_cache#15-oX (struct task_struct))->gtime: 0
	// (kmem_cache#15-oX (struct task_struct))->utimescaled: 0
	// (kmem_cache#15-oX (struct task_struct))->stimescaled: 0
	//
	// &(kmem_cache#15-oX (struct task_struct))->rss_stat 값을 0 으로 초기화 수행
	//
	// (kmem_cache#15-oX (struct task_struct))->default_timer_slack_ns: 50000
	//
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.prof_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.virt_exp: 0
	// (kmem_cache#15-oX (struct task_struct))->cputime_expires.sched_exp: 0
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[0])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[0]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[1])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[1]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->next: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	// (&(kmem_cache#15-oX (struct task_struct))->cpu_timers[2])->prev: &(kmem_cache#15-oX (struct task_struct))->cpu_timers[2]
	//
	// (kmem_cache#15-oX (struct task_struct))->start_time 에 현재 시간 값을 가져옴
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_sec: 현재의 sec 값 + 현재의 nsec 값 / 1000000000L
	// (&(kmem_cache#15-oX (struct task_struct))->real_start_time)->tv_nsec: 현재의 nsec 값 % 1000000000L
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_sec: normalized 된 sec 값
	// (kmem_cache#15-oX (struct task_struct))->real_start_time.tv_nsec: normalized 된 nsec 값
	//
	// (kmem_cache#15-oX (struct task_struct))->io_context: NULL
	// (kmem_cache#15-oX (struct task_struct))->audit_context: NULL
	//
	// rcu reference의 값 (&init_task)->cgroups 이 유요한지 체크하고 그 값을 리턴함
	// ((&init_task)->cgroups)->refcount: 1
	// (kmem_cache#15-oX (struct task_struct))->cgroups: (&init_task)->cgroups
	//
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->next: &(kmem_cache#15-oX (struct task_struct))->cg_list
	// (&(kmem_cache#15-oX (struct task_struct))->cg_list)->prev: &(kmem_cache#15-oX (struct task_struct))->cg_list
	//
	// (kmem_cache#15-oX (struct task_struct))->blocked_on: NULL
	//
	// (&kmem_cache#15-oX (struct task_struct))->on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.on_rq: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.exec_start: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.prev_sum_exec_runtime: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.nr_migrations: 0
	// (&kmem_cache#15-oX (struct task_struct))->se.vruntime: 0
	// &(&kmem_cache#15-oX (struct task_struct))->se.group_node의 리스트 초기화
	// &(&kmem_cache#15-oX (struct task_struct))->rt.run_list의 리스트 초기화
	//
	// (kmem_cache#15-oX (struct task_struct))->state: 0
	// (kmem_cache#15-oX (struct task_struct))->prio: 120
	// (kmem_cache#15-oX (struct task_struct))->sched_class: &fair_sched_class
	//
	// 현재의 schedule 시간값과 기존의 (&runqueues)->clock 의 값의 차이값을
	// [pcp0] (&runqueues)->clock, [pcp0] (&runqueues)->clock_task 의 값에 더해 갱신함
	//
	// [pcp0] (&runqueues)->clock: schedule 시간 차이값
	// [pcp0] (&runqueues)->clock_task: schedule 시간 차이값
	//
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (&(kmem_cache#15-oX (struct task_struct))->se)->vruntime: 0x5B8D7E
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->on_cpu: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->preempt_count: 1
	// (&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio: 140
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->prio_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->next: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list
	// (&(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list)->prev: &(&(kmem_cache#15-oX (struct task_struct))->pushable_tasks)->node_list
	//
	// (kmem_cache#15-oX (struct task_struct))->sysvsem.undo_list: NULL
	//
	// (&(&init_files)->count)->counter: 2
	//
	// (&init_fs)->users: 3
	//
	// struct sighand_struct 만큼의 메모리를 할당 받음
	// kmem_cache#14-oX (struct sighand_struct)
	//
	// (kmem_cache#15-oX (struct task_struct))->sighand: kmem_cache#14-oX (struct sighand_struct)
	// (&(kmem_cache#14-oX (struct sighand_struct))->count)->counter: 1
	// (&init_sighand)->action 의 값을 (kmem_cache#14-oX (struct sighand_struct))->action 에 복사함
	//
	// struct signal_struct 크기 만큼의 메모리를 할당함
	// kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#15-oX (struct task_struct))->signal: kmem_cache#13-oX (struct signal_struct)
	//
	// (kmem_cache#13-oX (struct signal_struct))->nr_threads: 1
	// (kmem_cache#13-oX (struct signal_struct))->live: { (1) }
	// (kmem_cache#13-oX (struct signal_struct))->sigcnt: { (1) }
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->lock을 사용한 spinlock 초기화
	// &(&(kmem_cache#13-oX (struct signal_struct))->wait_chldexit)->task_list를 사용한 list 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->curr_target: kmem_cache#15-oX (struct task_struct)
	//
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[0]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->signal)->sig[1]: 0
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->shared_pending)->list
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->next: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	// (&(kmem_cache#13-oX (struct signal_struct))->posix_timers)->prev: &(kmem_cache#13-oX (struct signal_struct))->posix_timers
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer의 값을 0으로 초기화
	// (&(kmem_cache#13-oX (struct signal_struct))->real_timer)->base: [pcp0] &(&hrtimer_bases)->clock_base[0]
	// RB Tree의 &(&(kmem_cache#13-oX (struct signal_struct))->real_timer)->node 를 초기화
	//
	// (kmem_cache#13-oX (struct signal_struct))->real_timer.function: it_real_fn
	// (kmem_cache#13-oX (struct signal_struct))->rlim 에 (&init_signals)->rlim 값을 전부 복사함
	// &(kmem_cache#13-oX (struct signal_struct))->cputimer.lock 을 사용한 spinlock 초기화 수행
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[0]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[1]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->next: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2])->prev: &(kmem_cache#13-oX (struct signal_struct))->cpu_timers[2]
	// (&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->activity: 0
	// &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_lock을 사용한 spinlock 초기화
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->group_rwsem)->wait_list
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj: 0
	// (kmem_cache#13-oX (struct signal_struct))->oom_score_adj_min: 0
	// (kmem_cache#13-oX (struct signal_struct))->has_child_subreaper: 0
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->count: 1
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->next: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list)->prev: &(&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->wait_list
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->onwer: NULL
	// (&(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex)->magic: &(kmem_cache#13-oX (struct signal_struct))->cred_guard_mutex
	//
	// (kmem_cache#15-oX (struct task_struct))->min_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->maj_flt: 0
	// (kmem_cache#15-oX (struct task_struct))->nvcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->nivcsw: 0
	// (kmem_cache#15-oX (struct task_struct))->last_switch_count: 0
	// (kmem_cache#15-oX (struct task_struct))->mm: NULL
	//
	// (&init_nsproxy)->count: { (3) }
	//
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context 의 값을 0으로 초기화 함
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183) 의 값을 0으로 초기화 함
	//
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r4: 0
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.r5: kernel_init
	// ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)->uregs[16]: 0x00000013
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.pc: ret_from_fork
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu_context.sp: ((struct pt_regs *)(kmem_cache#15-oX (struct task_struct))->stack + 8183)
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->tp_value[1]: TPIDRURW의 읽은 값
	//
	// struct pid 만큼의 메모리를 할당 받음
	// kmem_cache#19-oX (struct pid)
	//
	// (kmem_cache#19-oX (struct pid))->level: 0
	//
	// page 사이즈 만큼의 메모리를 할당 받음: kmem_cache#25-oX
	//
	// (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX
	// kmem_cache#25-oX 의 1 bit 의 값을 1 으로 set
	// (&(&init_pid_ns)->pidmap[0])->nr_free: { (0x7FFF) }
	// &(&init_pid_ns)->last_pid 을 1 로 변경함
	//
	// (kmem_cache#19-oX (struct pid))->numbers[0].nr: 1
	// (kmem_cache#19-oX (struct pid))->numbers[0].ns: &init_pid_ns
	//
	// struct mount의 메모리를 할당 받음 kmem_cache#2-oX (struct mount)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&mnt_id_ida)->idr)->id_free 이 idr object new 3번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 4         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&mnt_id_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 4)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 8
	//
	// (&mnt_id_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&mnt_id_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&mnt_id_ida)->idr)->layers: 1
	// (&(&mnt_id_ida)->idr)->id_free: (idr object new 0)
	// (&(&mnt_id_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 4 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 5
	//
	// (kmem_cache#2-oX (struct mount))->mnt_id: 4
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 4) 의 memory 공간을 반환함
	//
	// mnt_id_start: 5
	//
	// (kmem_cache#2-oX (struct mount))->mnt_devname: kmem_cache#30-oX: "proc"
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
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-oX를 1 개를 할당 받음
	//
	// (&(&unnamed_dev_ida)->idr)->id_free 이 idr object new 4번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object new 4         | idr object new 0     | idr object 6         | idr object 5         | .... | idr object 0     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object new 0 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL     |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&unnamed_dev_ida)->idr)->id_free: kmem_cache#21-oX (idr object new 4)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 8
	//
	// (&unnamed_dev_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&unnamed_dev_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&unnamed_dev_ida)->idr)->layers: 1
	// (&(&unnamed_dev_ida)->idr)->id_free: (idr object new 0)
	// (&(&unnamed_dev_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 4 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 5
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object new 4) 의 memory 공간을 반환함
	//
	// unnamed_dev_start: 5
	//
	// (kmem_cache#25-oX (struct super_block))->s_dev: 4
	// (kmem_cache#25-oX (struct super_block))->s_bdi: &noop_backing_dev_info
	// (kmem_cache#25-oX (struct super_block))->s_fs_info: &init_pid_ns
	// (kmem_cache#25-oX (struct super_block))->s_type: &proc_fs_type
	// (kmem_cache#25-oX (struct super_block))->s_id: "proc"
	//
	// list head인 &super_blocks 에 (kmem_cache#25-oX (struct super_block))->s_list을 tail에 추가
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->next: NULL
	// (&(&proc_fs_type)->fs_supers)->first: &(kmem_cache#25-oX (struct super_block))->s_instances
	// (&(kmem_cache#25-oX (struct super_block))->s_instances)->pprev: &(&(&proc_fs_type)->fs_supers)->first
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->flags: 0
	// (&(kmem_cache#25-oX (struct super_block))->s_shrink)->nr_deferred: kmem_cache#30-oX
	// head list인 &shrinker_list에 &(&(kmem_cache#25-oX (struct super_block))->s_shrink)->list를 tail로 추가함
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x40080a
	// (kmem_cache#25-oX (struct super_block))->s_blocksize: 1024
	// (kmem_cache#25-oX (struct super_block))->s_blocksize_bits: 10
	// (kmem_cache#25-oX (struct super_block))->s_magic: 0x9fa0
	// (kmem_cache#25-oX (struct super_block))->s_op: &proc_sops
	// (kmem_cache#25-oX (struct super_block))->s_time_gran: 1
	//
	// (&proc_root)->count: { (2) }
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
	// [pcp0] nr_inodes: 2
	//
	// (kmem_cache#4-oX (struct inode))->i_state: 0
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
	//
	// (kmem_cache#4-oX (struct inode))->i_ino: 1
	// (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->pde: &proc_root
	// (kmem_cache#4-oX (struct inode))->i_mode: 0040555
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#4-oX (struct inode))->__i_nlink: 2
	// (kmem_cache#4-oX (struct inode))->i_op: &proc_root_inode_operations
	// (kmem_cache#4-oX (struct inode))->i_fop: &proc_root_operations
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
	// [pcp0] nr_dentry: 3
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
	// (kmem_cache#25-oX (struct super_block))->s_root: kmem_cache#5-oX (struct dentry)
	//
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
	// [pcp0] nr_inodes: 3
	//
	// (kmem_cache#4-oX (struct inode))->i_state: 0
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->next: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// &(kmem_cache#4-oX (struct inode))->i_sb_list->prev: &(kmem_cache#4-oX (struct inode))->i_sb_list
	// (kmem_cache#4-oX (struct inode))->i_ino: 0xF0000001
	// (kmem_cache#4-oX (struct inode))->i_mtime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_atime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_ctime: 현재시간값
	// (kmem_cache#4-oX (struct inode))->i_mode: 0120777
	// (kmem_cache#4-oX (struct inode))->i_uid: 0
	// (kmem_cache#4-oX (struct inode))->i_gid: 0
	// (kmem_cache#4-oX (struct inode))->i_op: &proc_self_inode_operations
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
	// (kmem_cache#5-oX (struct dentry))->d_flags: 0x00100080
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->next: NULL
	// (&(kmem_cache#5-oX (struct dentry))->d_hash)->pprev: &(hash 0xXXXXXXXX 에 맞는 list table 주소값)->first
	//
	// ((hash 0xXXXXXXXX 에 맞는 list table 주소값)->first): ((&(kmem_cache#5-oX (struct dentry))->d_hash) | 1)
	//
	// (&init_pid_ns)->proc_self: kmem_cache#5-oX (struct dentry)
	//
	// (&(kmem_cache#5-oX (struct dentry))->d_lockref)->count: 1
	//
	// (kmem_cache#25-oX (struct super_block))->s_flags: 0x6040080a
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
	// (&init_pid_ns)->proc_mnt: &(kmem_cache#2-oX (struct mount))->mnt
	//
	// (&(kmem_cache#19-oX (struct pid))->count)->counter: 1
	// (&(kmem_cache#19-oX (struct pid))->tasks[0...2])->first: NULL
	//
	// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->next: NULL
	// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->pprev: &(&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first
	// ((&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first): &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain
	//
	// (&init_pid_ns)->nr_hashed: 0x80000001
	//
	// (kmem_cache#15-oX (struct task_struct))->set_child_tid: NULL
	// (kmem_cache#15-oX (struct task_struct))->clear_child_tid: NULL
	// (kmem_cache#15-oX (struct task_struct))->plug: NULL
	// (kmem_cache#15-oX (struct task_struct))->robust_list: NULL
	//
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->next: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	// (&(kmem_cache#15-oX (struct task_struct))->pi_state_list)->prev: &(kmem_cache#15-oX (struct task_struct))->pi_state_list
	//
	// (kmem_cache#15-oX (struct task_struct))->pi_state_cache: NULL
	//
	// (kmem_cache#15-oX (struct task_struct))->sas_ss_sp: 0
	// (kmem_cache#15-oX (struct task_struct))->sas_ss_size: 0
	//
	// (((struct thread_info *)(할당 받은 page 2개의 메로리의 가상 주소))->flags 의 8 bit 값을 clear 수행
	//
	// (kmem_cache#15-oX (struct task_struct))->pid: 1
	// (kmem_cache#15-oX (struct task_struct))->exit_signal: 0
	// (kmem_cache#15-oX (struct task_struct))->group_leader: kmem_cache#15-oX (struct task_struct)
	// (kmem_cache#15-oX (struct task_struct))->tgid: 1
	//
	// (kmem_cache#15-oX (struct task_struct))->pdeath_signal: 0
	// (kmem_cache#15-oX (struct task_struct))->exit_state: 0
	// (kmem_cache#15-oX (struct task_struct))->nr_dirtied: 0
	// (kmem_cache#15-oX (struct task_struct))->nr_dirtied_pause: 32
	// (kmem_cache#15-oX (struct task_struct))->dirty_paused_when: 0
	//
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->next: &(kmem_cache#15-oX (struct task_struct))->thread_group
	// (&(kmem_cache#15-oX (struct task_struct))->thread_group)->prev: &(kmem_cache#15-oX (struct task_struct))->thread_group
	//
	// (kmem_cache#15-oX (struct task_struct))->task_works: NULL
	//
	// (kmem_cache#15-oX (struct task_struct))->real_parent: &init_task
	// (kmem_cache#15-oX (struct task_struct))->parent_exec_id: 0
	//
	// (init_task의 struct thread_info 주소값)->flags 의 0 bit 값을 clear 수행
	//
	// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->next: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
	// (&(kmem_cache#15-oX (struct task_struct))->ptrace_entry)->prev: &(kmem_cache#15-oX (struct task_struct))->ptrace_entry
	// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->next: &(kmem_cache#15-oX (struct task_struct))->ptraced
	// (&(kmem_cache#15-oX (struct task_struct))->ptraced)->prev: &(kmem_cache#15-oX (struct task_struct))->ptraced
	// (kmem_cache#15-oX (struct task_struct))->jobctl: 0
	// (kmem_cache#15-oX (struct task_struct))->ptrace: 0
	// (kmem_cache#15-oX (struct task_struct))->parent: &init_task
	//
	// (kmem_cache#15-oX (struct task_struct))->pids[0].pid: kmem_cache#19-oX (struct pid)
	//
	// (kmem_cache#15-oX (struct task_struct))->pids[1].pid: &init_struct_pid
	// (kmem_cache#15-oX (struct task_struct))->pids[2].pid: &init_struct_pid
	//
	// (kmem_cache#13-oX (struct signal_struct))->flags: 0x00000040
	// (kmem_cache#13-oX (struct signal_struct))->leader_pid: kmem_cache#19-oX (struct pid)
	// (kmem_cache#13-oX (struct signal_struct))->tty: NULL
	//
	// list head 인 &(&init_task)->children 에 &(kmem_cache#15-oX (struct task_struct))->sibling 을 tail에 연결
	//
	// (&(kmem_cache#15-oX (struct task_struct))->tasks)->next: &init_task.tasks
	// (&(kmem_cache#15-oX (struct task_struct))->tasks)->prev: (&init_task.tasks)->prev
	//
	// core간 write memory barrier 수행
	// ((*((struct list_head __rcu **) (&((&init_task.tasks)->prev)->next)))):
	// (typeof(*&(kmem_cache#15-oX (struct task_struct))->tasks) __force __rcu *)(&(kmem_cache#15-oX (struct task_struct))->tasks);
	//
	// (&init_task.tasks)->prev: &(kmem_cache#15-oX (struct task_struct))->tasks
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->pprev: &(&(&init_struct_pid)->tasks[1])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[1])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node)->pprev: &(&(&init_struct_pid)->tasks[2])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[2])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[2])->node
	//
	// [pcp0] process_counts: 1 로 증가시킴
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node)->pprev: &(&(kmem_cache#19-oX (struct pid))->tasks[0])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(kmem_cache#19-oX (struct pid))->tasks[0])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[0])->node
	//
	// nr_threads: 1
	//
	// total_forks: 1
	//
	// (kmem_cache#15-oX (struct task_struct))->se.cfs_rq: [pcp0] &(&runqueues)->cfs
	// (kmem_cache#15-oX (struct task_struct))->se.parent: NULL
	// (kmem_cache#15-oX (struct task_struct))->rt.rt_rq: [pcp0] &(&runqueues)->rt
	// (kmem_cache#15-oX (struct task_struct))->rt.parent: NULL
	// ((struct thread_info *)(kmem_cache#15-oX (struct task_struct))->stack)->cpu: 0
	// (kmem_cache#15-oX (struct task_struct))->wake_cpu: 0
	//
	// (kmem_cache#15-oX (struct task_struct))->se.avg.decay_count: 0
	// (kmem_cache#15-oX (struct task_struct))->se.avg.runnable_avg_sum: 현재 task의 남아 있는 수행 시간량 / 1024
	// (kmem_cache#15-oX (struct task_struct))->se.avg.runnable_avg_period: 현재 task의 남아 있는 수행 시간량 / 1024
	// (&(kmem_cache#15-oX (struct task_struct))->se)->avg.load_avg_contrib:
	// 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
	//
	// [pcp0] (&runqueues)->clock: 현재의 schedule 시간값
	// [pcp0] (&runqueues)->clock_task: 현재의 schedule 시간값
	//
	// (&(kmem_cache#15-oX (struct task_struct))->se)->vruntime: 0x4B8D7E
	//
	// (&(kmem_cache#15-oX (struct task_struct))->se)->avg.last_runnable_update: 현재의 schedule 시간값
	// [pcp0] (&(&runqueues)->cfs)->runnable_load_avg: 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
	//
	// decays: 현재의 schedule 시간값>> 20 값이 0이 아닌 상수 값이라 가정하고 분석 진행
	//
	// [pcp0] (&(&runqueues)->cfs)->blocked_load_avg: 0
	// [pcp0] (&(&(&runqueues)->cfs)->decay_counter)->counter: 2
	// [pcp0] (&(&runqueues)->cfs)->last_decay: 현재의 schedule 시간값>> 20
	//
	// (&(&root_task_group)->load_avg)->counter: 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
	// [pcp0] (&(&runqueues)->cfs)->tg_load_contrib: 현재 task의 남아 있는 수행 시간량 / (현재 task의 남아 있는 수행 시간량 / 1024 + 1)
	//
	// [pcp0] (&(&(&runqueues)->cfs)->load)->weight: 2048
	// [pcp0] (&(&(&runqueues)->cfs)->load)->inv_weight: 0
	// [pcp0] (&(&runqueues)->load)->weight: 1024
	// [pcp0] (&(&runqueues)->load)->inv_weight: 0
	// [pcp0] &(&runqueues)->cfs_tasks 란 list head에 &(&(kmem_cache#15-oX (struct task_struct))->se)->group_node 를 추가함
	// [pcp0] (&(&runqueues)->cfs)->nr_running: 1
	//
	// [pcp0] (&(&runqueues)->cfs)->rb_leftmost: &(&(kmem_cache#15-oX (struct task_struct))->se)->run_node
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->run_node)->__rb_parent_color: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->run_node)->rb_left: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->run_node)->rb_right: NULL
	// [pcp0] (&(&runqueues)->cfs)->tasks_timeline.rb_node: &(&(kmem_cache#15-oX (struct task_struct))->se
	//
	/*
	// rb tree 의 root인 [pcp0] &(&(&runqueues)->cfs)->tasks_timeline 에
	// rb node인 &(&(kmem_cache#15-oX (struct task_struct))->se)->run_node 가 추가되어 rb tree 구성
	//
	//                            task ID: 1-b
	//                            /           \
	*/
	// (&(kmem_cache#15-oX (struct task_struct))->se)->on_rq: 1
	//
	// list head인 [pcp0] &(&runqueues)->leaf_cfs_rq_list에 [pcp0] &(&(&runqueues)->cfs)->leaf_cfs_rq_list 을 tail에 추가함
	//
	// [pcp0] (&(&(&runqueues)->cfs)->leaf_cfs_rq_list)->next: [pcp0] &(&runqueues)->leaf_cfs_rq_list
	// [pcp0] (&(&(&runqueues)->cfs)->leaf_cfs_rq_list)->prev: [pcp0] (&(&runqueues)->leaf_cfs_rq_list)->prev
	//
	// core간 write memory barrier 수행
	// ((*((struct list_head __rcu **) (&(([pcp0] &(&runqueues)->leaf_cfs_rq_list)->prev)->next)))):
	// (typeof(*[pcp0] &(&(&runqueues)->cfs)->leaf_cfs_rq_list) __force __rcu *)([pcp0] &(&(&runqueues)->cfs)->leaf_cfs_rq_list);
	//
	// [pcp0] (&(&runqueues)->leaf_cfs_rq_list)->prev: [pcp0] &(&(&runqueues)->cfs)->leaf_cfs_rq_list
	//
	// [pcp0] (&(&runqueues)->cfs)->on_list: 1
	//
	// [pcp0] (&(&runqueues)->cfs)->blocked_load_avg: 0
	// (&(&(&runqueues)->cfs)->decay_counter)->counter: 현재의 schedule 시간값>> 20 + 1 + 시간값x
	// [pcp0] (&(&runqueues)->cfs)->last_decay: 현재의 schedule 시간값 + 시간값x >> 20
	//
	// [pcp0] (&(&runqueues)->cfs)->h_nr_running: 2
	//
	// delta: 현재의 schedule 시간 변화값은 signed 로 변경시 0 보다 큰 값으로 가정하고 코드 분석 진행
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->avg)->last_runnable_update: 현재의 schedule 시간값
	//
	// delta + delta_w 값이 1024 보다 작은 값이라고 가정하고 코드 분석 진행
	//
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->avg)->runnable_avg_sum:
	// 현재 task의 남아 있는 수행 시간량 / 1024 + 현재의 schedule 시간 변화값
	// (&(&(kmem_cache#15-oX (struct task_struct))->se)->avg)->runnable_avg_period:
	// 현재 task의 남아 있는 수행 시간량 / 1024 + 현재의 schedule 시간 변화값
	//
	// (kmem_cache#15-oX (struct task_struct))->on_rq: 1
}

#ifdef __ARCH_WANT_SYS_FORK
SYSCALL_DEFINE0(fork)
{
#ifdef CONFIG_MMU
	return do_fork(SIGCHLD, 0, 0, NULL, NULL);
#else
	/* can not support in nommu mode */
	return(-EINVAL);
#endif
}
#endif

#ifdef __ARCH_WANT_SYS_VFORK
SYSCALL_DEFINE0(vfork)
{
	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, 0, 
			0, NULL, NULL);
}
#endif

#ifdef __ARCH_WANT_SYS_CLONE
#ifdef CONFIG_CLONE_BACKWARDS
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,
		 int __user *, parent_tidptr,
		 int, tls_val,
		 int __user *, child_tidptr)
#elif defined(CONFIG_CLONE_BACKWARDS2)
SYSCALL_DEFINE5(clone, unsigned long, newsp, unsigned long, clone_flags,
		 int __user *, parent_tidptr,
		 int __user *, child_tidptr,
		 int, tls_val)
#elif defined(CONFIG_CLONE_BACKWARDS3)
SYSCALL_DEFINE6(clone, unsigned long, clone_flags, unsigned long, newsp,
		int, stack_size,
		int __user *, parent_tidptr,
		int __user *, child_tidptr,
		int, tls_val)
#else
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,
		 int __user *, parent_tidptr,
		 int __user *, child_tidptr,
		 int, tls_val)
#endif
{
	return do_fork(clone_flags, newsp, 0, parent_tidptr, child_tidptr);
}
#endif

#ifndef ARCH_MIN_MMSTRUCT_ALIGN
// ARM10C 20150919
// ARCH_MIN_MMSTRUCT_ALIGN: 0
#define ARCH_MIN_MMSTRUCT_ALIGN 0
#endif

static void sighand_ctor(void *data)
{
	struct sighand_struct *sighand = data;

	spin_lock_init(&sighand->siglock);
	init_waitqueue_head(&sighand->signalfd_wqh);
}

// ARM10C 20150919
void __init proc_caches_init(void)
{
	// sizeof(struct sighand_struct): 1324 bytes,
	// SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_PANIC: 0x00040000UL, SLAB_DESTROY_BY_RCU: 0x00080000UL, SLAB_NOTRACK: 0x00000000UL
	// kmem_cache_create("sighand_cache", 1324, 0, 0xc2000, sighand_ctor): kmem_cache#14
	sighand_cachep = kmem_cache_create("sighand_cache",
			sizeof(struct sighand_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_DESTROY_BY_RCU|
			SLAB_NOTRACK, sighand_ctor);
	// sighand_cachep: kmem_cache#14

	// sizeof(struct signal_struct): 536 bytes,
	// SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_PANIC: 0x00040000UL, SLAB_NOTRACK: 0x00000000UL
	// kmem_cache_create("signal_cache", 536, 0, 0x42000, NULL): kmem_cache#13
	signal_cachep = kmem_cache_create("signal_cache",
			sizeof(struct signal_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);
	// signal_cachep: kmem_cache#13

	// sizeof(struct files_struct): 188 bytes,
	// SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_PANIC: 0x00040000UL, SLAB_NOTRACK: 0x00000000UL
	// kmem_cache_create("files_cache", 188, 0, 0x42000, NULL): kmem_cache#12
	files_cachep = kmem_cache_create("files_cache",
			sizeof(struct files_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);
	// files_cachep: kmem_cache#12

	// sizeof(struct fs_struct): 48 bytes,
	// SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_PANIC: 0x00040000UL, SLAB_NOTRACK: 0x00000000UL
	// kmem_cache_create("fs_cache", 48, 0, 0x42000, NULL): kmem_cache#11
	fs_cachep = kmem_cache_create("fs_cache",
			sizeof(struct fs_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);
	// fs_cachep: kmem_cache#11
	/*
	 * FIXME! The "sizeof(struct mm_struct)" currently includes the
	 * whole struct cpumask for the OFFSTACK case. We could change
	 * this to *only* allocate as much of it as required by the
	 * maximum number of CPU's we can ever have.  The cpumask_allocation
	 * is at the end of the structure, exactly for that reason.
	 */
	// sizeof(struct mm_struct): 428 bytes, ARCH_MIN_MMSTRUCT_ALIGN: 0
	// SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_PANIC: 0x00040000UL, SLAB_NOTRACK: 0x00000000UL
	// kmem_cache_create("mm_struct", 428, 0, 0x42000, NULL): kmem_cache#10
	mm_cachep = kmem_cache_create("mm_struct",
			sizeof(struct mm_struct), ARCH_MIN_MMSTRUCT_ALIGN,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);
	// mm_cachep: kmem_cache#10

	// SLAB_PANIC: 0x00040000UL
	// KMEM_CACHE(vm_area_struct, 0x00040000):
	// kmem_cache_create("vm_area_struct", sizeof(struct vm_area_struct), __alignof__(struct vm_area_struct), (0x00040000), NULL): kmem_cache#9
	vm_area_cachep = KMEM_CACHE(vm_area_struct, SLAB_PANIC);
	// vm_area_cachep: kmem_cache#9

	mmap_init();

	// mmap_init에서 한일:
	// (&(&(&(&vm_committed_as)->lock)->wait_lock)->rlock)->raw_lock: { { 0 } }
	// (&(&(&(&vm_committed_as)->lock)->wait_lock)->rlock)->magic: 0xdead4ead
	// (&(&(&(&vm_committed_as)->lock)->wait_lock)->rlock)->owner: 0xffffffff
	// (&(&(&(&vm_committed_as)->lock)->wait_lock)->rlock)->owner_cpu: 0xffffffff
	// (&(&vm_committed_as)->list)->next: &(&vm_committed_as)->list
	// (&(&vm_committed_as)->list)->prev: &(&vm_committed_as)->list
	// (&vm_committed_as)->count: 0
	// (&vm_committed_as)->counters: kmem_cache#26-o0 에서 할당된 4 bytes 메모리 주소
	// list head 인 &percpu_counters에 &(&vm_committed_as)->list를 연결함

// 2015/09/19 종료
// 2015/10/03 시작

	nsproxy_cache_init();

	// nsproxy_cache_init에서 한일:
	// nsproxy_cachep: kmem_cache#8
}

/*
 * Check constraints on flags passed to the unshare system call.
 */
static int check_unshare_flags(unsigned long unshare_flags)
{
	if (unshare_flags & ~(CLONE_THREAD|CLONE_FS|CLONE_NEWNS|CLONE_SIGHAND|
				CLONE_VM|CLONE_FILES|CLONE_SYSVSEM|
				CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWNET|
				CLONE_NEWUSER|CLONE_NEWPID))
		return -EINVAL;
	/*
	 * Not implemented, but pretend it works if there is nothing to
	 * unshare. Note that unsharing CLONE_THREAD or CLONE_SIGHAND
	 * needs to unshare vm.
	 */
	if (unshare_flags & (CLONE_THREAD | CLONE_SIGHAND | CLONE_VM)) {
		/* FIXME: get_task_mm() increments ->mm_users */
		if (atomic_read(&current->mm->mm_users) > 1)
			return -EINVAL;
	}

	return 0;
}

/*
 * Unshare the filesystem structure if it is being shared
 */
static int unshare_fs(unsigned long unshare_flags, struct fs_struct **new_fsp)
{
	struct fs_struct *fs = current->fs;

	if (!(unshare_flags & CLONE_FS) || !fs)
		return 0;

	/* don't need lock here; in the worst case we'll do useless copy */
	if (fs->users == 1)
		return 0;

	*new_fsp = copy_fs_struct(fs);
	if (!*new_fsp)
		return -ENOMEM;

	return 0;
}

/*
 * Unshare file descriptor table if it is being shared
 */
static int unshare_fd(unsigned long unshare_flags, struct files_struct **new_fdp)
{
	struct files_struct *fd = current->files;
	int error = 0;

	if ((unshare_flags & CLONE_FILES) &&
	    (fd && atomic_read(&fd->count) > 1)) {
		*new_fdp = dup_fd(fd, &error);
		if (!*new_fdp)
			return error;
	}

	return 0;
}

/*
 * unshare allows a process to 'unshare' part of the process
 * context which was originally shared using clone.  copy_*
 * functions used by do_fork() cannot be used here directly
 * because they modify an inactive task_struct that is being
 * constructed. Here we are modifying the current, active,
 * task_struct.
 */
SYSCALL_DEFINE1(unshare, unsigned long, unshare_flags)
{
	struct fs_struct *fs, *new_fs = NULL;
	struct files_struct *fd, *new_fd = NULL;
	struct cred *new_cred = NULL;
	struct nsproxy *new_nsproxy = NULL;
	int do_sysvsem = 0;
	int err;

	/*
	 * If unsharing a user namespace must also unshare the thread.
	 */
	if (unshare_flags & CLONE_NEWUSER)
		unshare_flags |= CLONE_THREAD | CLONE_FS;
	/*
	 * If unsharing a thread from a thread group, must also unshare vm.
	 */
	if (unshare_flags & CLONE_THREAD)
		unshare_flags |= CLONE_VM;
	/*
	 * If unsharing vm, must also unshare signal handlers.
	 */
	if (unshare_flags & CLONE_VM)
		unshare_flags |= CLONE_SIGHAND;
	/*
	 * If unsharing namespace, must also unshare filesystem information.
	 */
	if (unshare_flags & CLONE_NEWNS)
		unshare_flags |= CLONE_FS;

	err = check_unshare_flags(unshare_flags);
	if (err)
		goto bad_unshare_out;
	/*
	 * CLONE_NEWIPC must also detach from the undolist: after switching
	 * to a new ipc namespace, the semaphore arrays from the old
	 * namespace are unreachable.
	 */
	if (unshare_flags & (CLONE_NEWIPC|CLONE_SYSVSEM))
		do_sysvsem = 1;
	err = unshare_fs(unshare_flags, &new_fs);
	if (err)
		goto bad_unshare_out;
	err = unshare_fd(unshare_flags, &new_fd);
	if (err)
		goto bad_unshare_cleanup_fs;
	err = unshare_userns(unshare_flags, &new_cred);
	if (err)
		goto bad_unshare_cleanup_fd;
	err = unshare_nsproxy_namespaces(unshare_flags, &new_nsproxy,
					 new_cred, new_fs);
	if (err)
		goto bad_unshare_cleanup_cred;

	if (new_fs || new_fd || do_sysvsem || new_cred || new_nsproxy) {
		if (do_sysvsem) {
			/*
			 * CLONE_SYSVSEM is equivalent to sys_exit().
			 */
			exit_sem(current);
		}

		if (new_nsproxy)
			switch_task_namespaces(current, new_nsproxy);

		task_lock(current);

		if (new_fs) {
			fs = current->fs;
			spin_lock(&fs->lock);
			current->fs = new_fs;
			if (--fs->users)
				new_fs = NULL;
			else
				new_fs = fs;
			spin_unlock(&fs->lock);
		}

		if (new_fd) {
			fd = current->files;
			current->files = new_fd;
			new_fd = fd;
		}

		task_unlock(current);

		if (new_cred) {
			/* Install the new user namespace */
			commit_creds(new_cred);
			new_cred = NULL;
		}
	}

bad_unshare_cleanup_cred:
	if (new_cred)
		put_cred(new_cred);
bad_unshare_cleanup_fd:
	if (new_fd)
		put_files_struct(new_fd);

bad_unshare_cleanup_fs:
	if (new_fs)
		free_fs_struct(new_fs);

bad_unshare_out:
	return err;
}

/*
 *	Helper to unshare the files of the current task.
 *	We don't want to expose copy_files internals to
 *	the exec layer of the kernel.
 */

int unshare_files(struct files_struct **displaced)
{
	struct task_struct *task = current;
	struct files_struct *copy = NULL;
	int error;

	error = unshare_fd(CLONE_FILES, &copy);
	if (error || !copy) {
		*displaced = NULL;
		return error;
	}
	*displaced = task->files;
	task_lock(task);
	task->files = copy;
	task_unlock(task);
	return 0;
}
