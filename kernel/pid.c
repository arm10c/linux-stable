/*
 * Generic pidhash and scalable, time-bounded PID allocator
 *
 * (C) 2002-2003 Nadia Yvette Chambers, IBM
 * (C) 2004 Nadia Yvette Chambers, Oracle
 * (C) 2002-2004 Ingo Molnar, Red Hat
 *
 * pid-structures are backing objects for tasks sharing a given ID to chain
 * against. There is very little to them aside from hashing them and
 * parking tasks using given ID's on a list.
 *
 * The hash is always changed with the tasklist_lock write-acquired,
 * and the hash is only accessed with the tasklist_lock at least
 * read-acquired, so there's no additional SMP locking needed here.
 *
 * We have a list of bitmap pages, which bitmaps represent the PID space.
 * Allocating and freeing PIDs is completely lockless. The worst-case
 * allocation scenario when all but one out of 1 million PIDs possible are
 * allocated already: the scanning of 32 list entries and at most PAGE_SIZE
 * bytes. The typical fastpath is a single successful setbit. Freeing is O(1).
 *
 * Pid namespaces:
 *    (C) 2007 Pavel Emelyanov <xemul@openvz.org>, OpenVZ, SWsoft Inc.
 *    (C) 2007 Sukadev Bhattiprolu <sukadev@us.ibm.com>, IBM
 *     Many thanks to Oleg Nesterov for comments and help
 *
 */

#include <linux/mm.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/rculist.h>
#include <linux/bootmem.h>
#include <linux/hash.h>
#include <linux/pid_namespace.h>
#include <linux/init_task.h>
#include <linux/syscalls.h>
#include <linux/proc_ns.h>
#include <linux/proc_fs.h>

// ARM10C 20161203
// pidhash_shift: 4
// upid->nr: (&(kmem_cache#19-oX (struct pid))->numbers[0])->nr: 1,
// upid->ns: (&(kmem_cache#19-oX (struct pid))->numbers[0])->ns: &init_pid_ns
// ARM10C 20170624
// pidhash_shift: 4
// nr: 2, ns: &init_pid_ns
#define pid_hashfn(nr, ns)	\
	hash_long((unsigned long)nr + (unsigned long)ns, pidhash_shift)

// ARM10C 20140322
// ARM10C 20161203
// ARM10C 20170624
// sizeof(struct hlist_head): 4 bytes
static struct hlist_head *pid_hash;
// ARM10C 20140322
// ARM10C 20161203
static unsigned int pidhash_shift = 4;
// ARM10C 20160903
// ARM10C 20161105
// ARM10C 20161203
// ARM10C 20170610
// INIT_STRUCT_PID:
// {
//     .count        = { (1) },
//     .tasks        = {
//         { .first = NULL },
//         { .first = NULL },
//         { .first = NULL },
//     },
//     .level        = 0,
//     .numbers      = { {
//         .nr        = 0,
//         .ns        = &init_pid_ns,
//         .pid_chain    = { .next = NULL, .pprev = NULL },
//     }, }
// }
struct pid init_struct_pid = INIT_STRUCT_PID;

// ARM10C 20150912
// ARM10C 20161105
// PID_MAX_DEFAULT: 0x8000
int pid_max = PID_MAX_DEFAULT;

// ARM10C 20150912
// RESERVED_PIDS: 300
#define RESERVED_PIDS		300

// ARM10C 20150912
// RESERVED_PIDS: 300
int pid_max_min = RESERVED_PIDS + 1;
// ARM10C 20150912
// PID_MAX_LIMIT: 0x8000
int pid_max_max = PID_MAX_LIMIT;

static inline int mk_pid(struct pid_namespace *pid_ns,
		struct pidmap *map, int off)
{
	return (map - pid_ns->pidmap)*BITS_PER_PAGE + off;
}

#define find_next_offset(map, off)					\
		find_next_zero_bit((map)->page, BITS_PER_PAGE, off)

/*
 * PID-map pages start out as NULL, they get allocated upon
 * first use and are never deallocated. This way a low pid_max
 * value does not cause lots of bitmaps to be allocated, but
 * the scheme scales to up to 4 million PIDs, runtime.
 */
// ARM10C 20150912
// ARM10C 20160903
// ARM10C 20161105
// ARM10C 20161112
// ARM10C 20161203
// ARM10C 20170610
// ARM10C 20170624
struct pid_namespace init_pid_ns = {
	.kref = {
		.refcount       = ATOMIC_INIT(2),
	},
	// BITS_PER_PAGE: 0x8000, ATOMIC_INIT(0x8000): 0x8000
	// PIDMAP_ENTRIES: 1
	.pidmap = {
		[ 0 ... PIDMAP_ENTRIES-1] = { ATOMIC_INIT(BITS_PER_PAGE), NULL }
	},
	.last_pid = 0,
	// PIDNS_HASH_ADDING: 0x80000000
	.nr_hashed = PIDNS_HASH_ADDING,
	.level = 0,
	.child_reaper = &init_task,
	.user_ns = &init_user_ns,
	.proc_inum = PROC_PID_INIT_INO,
};
EXPORT_SYMBOL_GPL(init_pid_ns);

/*
 * Note: disable interrupts while the pidmap_lock is held as an
 * interrupt might come in and do read_lock(&tasklist_lock).
 *
 * If we don't disable interrupts there is a nasty deadlock between
 * detach_pid()->free_pid() and another cpu that does
 * spin_lock(&pidmap_lock) followed by an interrupt routine that does
 * read_lock(&tasklist_lock);
 *
 * After we clean up the tasklist_lock and know there are no
 * irq handlers that take it we can leave the interrupts enabled.
 * For now it is easier to be safe than to prove it can't happen.
 */

// ARM10C 20161112
// ARM10C 20161203
// DEFINE_SPINLOCK(pidmap_lock):
// spinlock_t pidmap_lock =
// (spinlock_t )
// { { .rlock =
//     {
//       .raw_lock = { { 0 } },
//       .magic = 0xdead4ead,
//       .owner_cpu = -1,
//       .owner = 0xffffffff,
//     }
// } }
static  __cacheline_aligned_in_smp DEFINE_SPINLOCK(pidmap_lock);

static void free_pidmap(struct upid *upid)
{
	int nr = upid->nr;
	struct pidmap *map = upid->ns->pidmap + nr / BITS_PER_PAGE;
	int offset = nr & BITS_PER_PAGE_MASK;

	clear_bit(offset, map->page);
	atomic_inc(&map->nr_free);
}

/*
 * If we started walking pids at 'base', is 'a' seen before 'b'?
 */
// ARM10C 20161112
// base: 0, last_write: 0, pid: 1
static int pid_before(int base, int a, int b)
{
	/*
	 * This is the same as saying
	 *
	 * (a - base + MAXUINT) % MAXUINT < (b - base + MAXUINT) % MAXUINT
	 * and that mapping orders 'a' and 'b' with respect to 'base'.
	 */
	// a: 0, base: 0, b: 1
	return (unsigned)(a - base) < (unsigned)(b - base);
	// return 1
}

/*
 * We might be racing with someone else trying to set pid_ns->last_pid
 * at the pid allocation time (there's also a sysctl for this, but racing
 * with this one is OK, see comment in kernel/pid_namespace.c about it).
 * We want the winner to have the "later" value, because if the
 * "earlier" value prevails, then a pid may get reused immediately.
 *
 * Since pids rollover, it is not sufficient to just pick the bigger
 * value.  We have to consider where we started counting from.
 *
 * 'base' is the value of pid_ns->last_pid that we observed when
 * we started looking for a pid.
 *
 * 'pid' is the pid that we eventually found.
 */
// ARM10C 20161112
// pid_ns: &init_pid_ns, last: 0, pid: 1
// ARM10C 20170610
// pid_ns: &init_pid_ns, last: 1, pid: 2
static void set_last_pid(struct pid_namespace *pid_ns, int base, int pid)
{
	int prev;

	// base: 0
	int last_write = base;
	// last_write: 0

	do {
		// last_write: 0
		prev = last_write;
		// prev: 0

		// &pid_ns->last_pid: &(&init_pid_ns)->last_pid: 0, prev: 0, pid: 1
		// cmpxchg(&(&init_pid_ns)->last_pid, 0, 1): 0
		last_write = cmpxchg(&pid_ns->last_pid, prev, pid);
		// last_write: 0

		// cmpxchg 에서 한일:
		// &(&init_pid_ns)->last_pid 을 1 로 변경함

		// base: 0, prev: 0, last_write: 0, pid: 1, pid_before(0, 0, 1): 1
	} while ((prev != last_write) && (pid_before(base, last_write, pid)));
}

// ARM10C 20161105
// tmp: &init_pid_ns
// ARM10C 20170610
// tmp: &init_pid_ns
static int alloc_pidmap(struct pid_namespace *pid_ns)
{
	// pid_ns->last_pid: (&init_pid_ns)->last_pid: 0
	// pid_ns->last_pid: (&init_pid_ns)->last_pid: 1
	int i, offset, max_scan, pid, last = pid_ns->last_pid;
	// last: 0
	// last: 1

	struct pidmap *map;

	// last: 0
	// last: 1
	pid = last + 1;
	// pid: 1
	// pid: 2

	// pid: 1, pid_max: 0x8000
	// pid: 2, pid_max: 0x8000
	if (pid >= pid_max)
		pid = RESERVED_PIDS;

	// pid: 1, PID_MAX_DEFAULT: 0x8000, BITS_PER_PAGE_MASK: 0x7FFF
	// pid: 2, PID_MAX_DEFAULT: 0x8000, BITS_PER_PAGE_MASK: 0x7FFF
	offset = pid & BITS_PER_PAGE_MASK;
	// offset: 1
	// offset: 2

	// pid: 1, BITS_PER_PAGE: 0x8000
	// &pid_ns->pidmap[0]: &(&init_pid_ns)->pidmap[0]
	// pid: 2, BITS_PER_PAGE: 0x8000
	// &pid_ns->pidmap[0]: &(&init_pid_ns)->pidmap[0]
	map = &pid_ns->pidmap[pid/BITS_PER_PAGE];
	// map: &(&init_pid_ns)->pidmap[0]
	// map: &(&init_pid_ns)->pidmap[0]

	/*
	 * If last_pid points into the middle of the map->page we
	 * want to scan this bitmap block twice, the second time
	 * we start with offset == 0 (or RESERVED_PIDS).
	 */
	// pid_max: 0x8000, BITS_PER_PAGE: 0x8000, DIV_ROUND_UP(0x8000, 0x8000): 1, offset: 1
	// pid_max: 0x8000, BITS_PER_PAGE: 0x8000, DIV_ROUND_UP(0x8000, 0x8000): 1, offset: 2
	max_scan = DIV_ROUND_UP(pid_max, BITS_PER_PAGE) - !offset;
	// max_scan: 1
	// max_scan: 1

// 2016/11/05 종료
// 2016/11/12 시작

	// max_scan: 1
	// max_scan: 1
	for (i = 0; i <= max_scan; ++i) {
		// map->page: (&(&init_pid_ns)->pidmap[0])->page: NULL
		// map->page: (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX
		if (unlikely(!map->page)) {
			// PAGE_SIZE: 0x1000, GFP_KERNEL: 0xD0
			// kzalloc(0x1000, 0xD0): kmem_cache#25-oX
			void *page = kzalloc(PAGE_SIZE, GFP_KERNEL);
			// page: kmem_cache#25-oX

			/*
			 * Free the page if someone raced with us
			 * installing it:
			 */
			spin_lock_irq(&pidmap_lock);

			// spin_lock_irq 에서 한일:
			// pidmap_lock 을 사용한 spin lock 수행

			// map->page: (&(&init_pid_ns)->pidmap[0])->page: NULL
			if (!map->page) {
				// map->page: (&(&init_pid_ns)->pidmap[0])->page: NULL, page: kmem_cache#25-oX
				map->page = page;
				// map->page: (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX

				// page: kmem_cache#25-oX
				page = NULL;
				// page: NULL
			}
			spin_unlock_irq(&pidmap_lock);

			// spin_unlock_irq 에서 한일:
			// pidmap_lock 을 사용한 spin unlock 수행

			// page: NULL
			kfree(page);

			// map->page: (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX
			if (unlikely(!map->page))
				break;
		}

		// &map->nr_free: &(&(&init_pid_ns)->pidmap[0])->nr_free,
		// atomic_read(&(&(&init_pid_ns)->pidmap[0])->nr_free): 0x8000
		// &map->nr_free: &(&(&init_pid_ns)->pidmap[0])->nr_free,
		// atomic_read(&(&(&init_pid_ns)->pidmap[0])->nr_free): 0x7FFF
		if (likely(atomic_read(&map->nr_free))) {
			for ( ; ; ) {
				// offset: 1, map->page: (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX
				// test_and_set_bit(1, kmem_cache#25-oX): 0
				// offset: 2, map->page: (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX
				// test_and_set_bit(2, kmem_cache#25-oX): 0
				if (!test_and_set_bit(offset, map->page)) {
					// test_and_set_bit 에서 한일:
					// kmem_cache#25-oX 의 1 bit 의 값을 1 으로 set 하고 이전 값 0 을 읽어서 리턴함

					// test_and_set_bit 에서 한일:
					// kmem_cache#25-oX 의 2 bit 의 값을 1 으로 set 하고 이전 값 0 을 읽어서 리턴함

					// &map->nr_free: &(&(&init_pid_ns)->pidmap[0])->nr_free
					// &map->nr_free: &(&(&init_pid_ns)->pidmap[0])->nr_free
					atomic_dec(&map->nr_free);

					// atomic_dec 에서 한일:
					// (&(&init_pid_ns)->pidmap[0])->nr_free: { (0x7FFF) }

					// atomic_dec 에서 한일:
					// (&(&init_pid_ns)->pidmap[0])->nr_free: { (0x7FFE) }

					// pid_ns: &init_pid_ns, last: 0, pid: 1
					// pid_ns: &init_pid_ns, last: 1, pid: 2
					set_last_pid(pid_ns, last, pid);

					// set_last_pid 에서 한일:
					// &(&init_pid_ns)->last_pid 을 1 로 변경함

					// set_last_pid 에서 한일:
					// &(&init_pid_ns)->last_pid 을 2 로 변경함

					// pid: 1
					// pid: 2
					return pid;
					// return 1
					// return 2
				}
				offset = find_next_offset(map, offset);
				if (offset >= BITS_PER_PAGE)
					break;
				pid = mk_pid(pid_ns, map, offset);
				if (pid >= pid_max)
					break;
			}
		}
		if (map < &pid_ns->pidmap[(pid_max-1)/BITS_PER_PAGE]) {
			++map;
			offset = 0;
		} else {
			map = &pid_ns->pidmap[0];
			offset = RESERVED_PIDS;
			if (unlikely(last == offset))
				break;
		}
		pid = mk_pid(pid_ns, map, offset);
	}
	return -1;
}

int next_pidmap(struct pid_namespace *pid_ns, unsigned int last)
{
	int offset;
	struct pidmap *map, *end;

	if (last >= PID_MAX_LIMIT)
		return -1;

	offset = (last + 1) & BITS_PER_PAGE_MASK;
	map = &pid_ns->pidmap[(last + 1)/BITS_PER_PAGE];
	end = &pid_ns->pidmap[PIDMAP_ENTRIES];
	for (; map < end; map++, offset = 0) {
		if (unlikely(!map->page))
			continue;
		offset = find_next_bit((map)->page, BITS_PER_PAGE, offset);
		if (offset < BITS_PER_PAGE)
			return mk_pid(pid_ns, map, offset);
	}
	return -1;
}

// ARM10C 20150718
// vc->vt_pid: (kmem_cache#25-oX)->vt_pid: NULL
void put_pid(struct pid *pid)
{
	struct pid_namespace *ns;

	// vc->vt_pid: (kmem_cache#25-oX)->vt_pid: NULL
	if (!pid)
		return;
		// return 수행

	ns = pid->numbers[pid->level].ns;
	if ((atomic_read(&pid->count) == 1) ||
	     atomic_dec_and_test(&pid->count)) {
		kmem_cache_free(ns->pid_cachep, pid);
		put_pid_ns(ns);
	}
}
EXPORT_SYMBOL_GPL(put_pid);

static void delayed_put_pid(struct rcu_head *rhp)
{
	struct pid *pid = container_of(rhp, struct pid, rcu);
	put_pid(pid);
}

void free_pid(struct pid *pid)
{
	/* We can be called with write_lock_irq(&tasklist_lock) held */
	int i;
	unsigned long flags;

	spin_lock_irqsave(&pidmap_lock, flags);
	for (i = 0; i <= pid->level; i++) {
		struct upid *upid = pid->numbers + i;
		struct pid_namespace *ns = upid->ns;
		hlist_del_rcu(&upid->pid_chain);
		switch(--ns->nr_hashed) {
		case 2:
		case 1:
			/* When all that is left in the pid namespace
			 * is the reaper wake up the reaper.  The reaper
			 * may be sleeping in zap_pid_ns_processes().
			 */
			wake_up_process(ns->child_reaper);
			break;
		case PIDNS_HASH_ADDING:
			/* Handle a fork failure of the first process */
			WARN_ON(ns->child_reaper);
			ns->nr_hashed = 0;
			/* fall through */
		case 0:
			schedule_work(&ns->proc_work);
			break;
		}
	}
	spin_unlock_irqrestore(&pidmap_lock, flags);

	for (i = 0; i <= pid->level; i++)
		free_pidmap(pid->numbers + i);

	call_rcu(&pid->rcu, delayed_put_pid);
}

// ARM10C 20161105
// p->nsproxy->pid_ns_for_children: (&init_nsproxy)->pid_ns_for_children: &init_pid_ns
// ARM10C 20170610
// p->nsproxy->pid_ns_for_children: (&init_nsproxy)->pid_ns_for_children: &init_pid_ns
struct pid *alloc_pid(struct pid_namespace *ns)
{
	struct pid *pid;
	enum pid_type type;
	int i, nr;
	struct pid_namespace *tmp;
	struct upid *upid;

	// ns->pid_cachep: (&init_pid_ns)->pid_cachep: kmem_cache#19, GFP_KERNEL: 0xD0
	// kmem_cache_alloc(kmem_cache#19, 0xD0): kmem_cache#19-oX (struct pid)
	// ns->pid_cachep: (&init_pid_ns)->pid_cachep: kmem_cache#19, GFP_KERNEL: 0xD0
	// kmem_cache_alloc(kmem_cache#19, 0xD0): kmem_cache#19-oX (struct pid)
	pid = kmem_cache_alloc(ns->pid_cachep, GFP_KERNEL);
	// pid: kmem_cache#19-oX (struct pid)
	// pid: kmem_cache#19-oX (struct pid)

	// pid: kmem_cache#19-oX (struct pid)
	// pid: kmem_cache#19-oX (struct pid)
	if (!pid)
		goto out;

	// ns: &init_pid_ns
	// ns: &init_pid_ns
	tmp = ns;
	// tmp: &init_pid_ns
	// tmp: &init_pid_ns

	// pid->level: (kmem_cache#19-oX (struct pid))->level, ns->level: (&init_pid_ns)->level: 0
	// pid->level: (kmem_cache#19-oX (struct pid))->level, ns->level: (&init_pid_ns)->level: 0
	pid->level = ns->level;
	// pid->level: (kmem_cache#19-oX (struct pid))->level: 0
	// pid->level: (kmem_cache#19-oX (struct pid))->level: 0

	// ns->level: (&init_pid_ns)->level: 0
	// ns->level: (&init_pid_ns)->level: 0
	for (i = ns->level; i >= 0; i--) {
		// tmp: &init_pid_ns
		// alloc_pidmap(&init_pid_ns): 1
		// tmp: &init_pid_ns
		// alloc_pidmap(&init_pid_ns): 2
		nr = alloc_pidmap(tmp);
		// nr: 1
		// nr: 2

		// alloc_pidmap 에서 한일:
		// page 사이즈 만큼의 메모리를 할당 받음: kmem_cache#25-oX
		//
		// (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX
		// kmem_cache#25-oX 의 1 bit 의 값을 1 으로 set
		// (&(&init_pid_ns)->pidmap[0])->nr_free: { (0x7FFF) }
		// &(&init_pid_ns)->last_pid 을 1 로 변경함

		// alloc_pidmap 에서 한일:
		// 기존에 할당받은 pidmap의 메모리 값
		// (&(&init_pid_ns)->pidmap[0])->page: kmem_cache#25-oX
		// kmem_cache#25-oX 의 2 bit 의 값을 1 으로 set
		// (&(&init_pid_ns)->pidmap[0])->nr_free: { (0x7FFE) }
		// &(&init_pid_ns)->last_pid 을 2 로 변경함

		// nr: 1
		// nr: 2
		if (nr < 0)
			goto out_free;

		// i: 0, pid->numbers[0].nr: (kmem_cache#19-oX (struct pid))->numbers[0].nr, nr: 1
		// i: 0, pid->numbers[0].nr: (kmem_cache#19-oX (struct pid))->numbers[0].nr, nr: 2
		pid->numbers[i].nr = nr;
		// pid->numbers[0].nr: (kmem_cache#19-oX (struct pid))->numbers[0].nr: 1
		// pid->numbers[0].nr: (kmem_cache#19-oX (struct pid))->numbers[0].nr: 2

		// i: 0, pid->numbers[0].ns: (kmem_cache#19-oX (struct pid))->numbers[0].ns, tmp: &init_pid_ns
		// i: 0, pid->numbers[0].ns: (kmem_cache#19-oX (struct pid))->numbers[0].ns, tmp: &init_pid_ns
		pid->numbers[i].ns = tmp;
		// pid->numbers[0].ns: (kmem_cache#19-oX (struct pid))->numbers[0].ns: &init_pid_ns
		// pid->numbers[0].ns: (kmem_cache#19-oX (struct pid))->numbers[0].ns: &init_pid_ns

		// tmp: &init_pid_ns, tmp->parent: (&init_pid_ns)->parent: NULL
		// tmp: &init_pid_ns, tmp->parent: (&init_pid_ns)->parent: NULL
		tmp = tmp->parent;
		// tmp: NULL
		// tmp: NULL
	}

	// pid: kmem_cache#19-oX (struct pid)
	// is_child_reaper(kmem_cache#19-oX (struct pid)): 1
	// pid: kmem_cache#19-oX (struct pid)
	// is_child_reaper(kmem_cache#19-oX (struct pid)): 0
	if (unlikely(is_child_reaper(pid))) {
		// ns: &init_pid_ns, pid_ns_prepare_proc(&init_pid_ns): 0
		if (pid_ns_prepare_proc(ns))
			goto out_free;

		// pid_ns_prepare_proc 에서 한일:
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
	}

	// ns: &init_pid_ns
	// ns: &init_pid_ns
	get_pid_ns(ns);

	// &pid->count: &(kmem_cache#19-oX (struct pid))->count
	// &pid->count: &(kmem_cache#19-oX (struct pid))->count
	atomic_set(&pid->count, 1);

	// atomic_set 에서 한일:
	// (&(kmem_cache#19-oX (struct pid))->count)->counter: 1

	// atomic_set 에서 한일:
	// (&(kmem_cache#19-oX (struct pid))->count)->counter: 1

	// PIDTYPE_MAX: 3
	// PIDTYPE_MAX: 3
	for (type = 0; type < PIDTYPE_MAX; ++type)
		// type: 0, &pid->tasks[0]: &(kmem_cache#19-oX (struct pid))->tasks[0]
		// type: 0, &pid->tasks[0]: &(kmem_cache#19-oX (struct pid))->tasks[0]
		INIT_HLIST_HEAD(&pid->tasks[type]);

		// INIT_HLIST_HEAD 에서 한일:
		// (&(kmem_cache#19-oX (struct pid))->tasks[0])->first: NULL
		
		// type: 1...2 loop 수행

		// INIT_HLIST_HEAD 에서 한일:
		// (&(kmem_cache#19-oX (struct pid))->tasks[0])->first: NULL
		
		// type: 1...2 loop 수행

	// pid->numbers: (kmem_cache#19-oX (struct pid))->numbers, ns->level: (&init_pid_ns)->level: 0
	// pid->numbers: (kmem_cache#19-oX (struct pid))->numbers, ns->level: (&init_pid_ns)->level: 0
	upid = pid->numbers + ns->level;
	// upid: &(kmem_cache#19-oX (struct pid))->numbers[0]
	// upid: &(kmem_cache#19-oX (struct pid))->numbers[0]

	spin_lock_irq(&pidmap_lock);

	// spin_lock_irq 에서 한일:
	// pidmap_lock 을 사용한 spin lock 수행

	// spin_lock_irq 에서 한일:
	// pidmap_lock 을 사용한 spin lock 수행

	// ns->nr_hashed: (&init_pid_ns)->nr_hashed: 0x80000000, PIDNS_HASH_ADDING: 0x80000000
	// ns->nr_hashed: (&init_pid_ns)->nr_hashed: 0x80000000, PIDNS_HASH_ADDING: 0x80000000
	if (!(ns->nr_hashed & PIDNS_HASH_ADDING))
		goto out_unlock;

	// upid: &(kmem_cache#19-oX (struct pid))->numbers[0], pid->numbers: (kmem_cache#19-oX (struct pid))->numbers
	// upid: &(kmem_cache#19-oX (struct pid))->numbers[0], pid->numbers: (kmem_cache#19-oX (struct pid))->numbers
	for ( ; upid >= pid->numbers; --upid) {
		// &upid->pid_chain: &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain
		// upid->nr: (&(kmem_cache#19-oX (struct pid))->numbers[0])->nr: 1,
		// upid->ns: (&(kmem_cache#19-oX (struct pid))->numbers[0])->ns: &init_pid_ns,
		// pid_hashfn(1, &init_pid_ns): 계산된 hash index 값
		// pid_hash: pid hash를 위한 메모리 공간을 16kB, &pid_hash: &(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값]
		// &upid->pid_chain: &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain
		// upid->nr: (&(kmem_cache#19-oX (struct pid))->numbers[0])->nr: 2,
		// upid->ns: (&(kmem_cache#19-oX (struct pid))->numbers[0])->ns: &init_pid_ns,
		// pid_hashfn(2, &init_pid_ns): 계산된 hash index 값
		// pid_hash: pid hash를 위한 메모리 공간을 16kB, &pid_hash: &(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값]
		hlist_add_head_rcu(&upid->pid_chain,
				&pid_hash[pid_hashfn(upid->nr, upid->ns)]);

		// hlist_add_head_rcu 에서 한일:
		// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->next: NULL
		// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->pprev: &(&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first
		// ((&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first): &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain

		// hlist_add_head_rcu 에서 한일:
		// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->next: NULL
		// (&(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain)->pprev: &(&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first
		// ((&(pid hash를 위한 메모리 공간을 16kB)[계산된 hash index 값])->first): &(&(kmem_cache#19-oX (struct pid))->numbers[0])->pid_chain

		// upid->ns: (&(kmem_cache#19-oX (struct pid))->numbers[0])->ns: &init_pid_ns
		// upid->ns->nr_hashed: (&init_pid_ns)->nr_hashed: 0x80000000
		// upid->ns: (&(kmem_cache#19-oX (struct pid))->numbers[0])->ns: &init_pid_ns
		// upid->ns->nr_hashed: (&init_pid_ns)->nr_hashed: 0x80000000
		upid->ns->nr_hashed++;
		// upid->ns->nr_hashed: (&init_pid_ns)->nr_hashed: 0x80000001
		// upid->ns->nr_hashed: (&init_pid_ns)->nr_hashed: 0x80000002
	}
	spin_unlock_irq(&pidmap_lock);

	// spin_unlock_irq 에서 한일:
	// pidmap_lock 을 사용한 spin unlock 수행

	// spin_unlock_irq 에서 한일:
	// pidmap_lock 을 사용한 spin unlock 수행

out:
	// pid: kmem_cache#19-oX (struct pid)
	// pid: kmem_cache#19-oX (struct pid)
	return pid;
	// return kmem_cache#19-oX (struct pid)
	// return kmem_cache#19-oX (struct pid)

out_unlock:
	spin_unlock_irq(&pidmap_lock);
out_free:
	while (++i <= ns->level)
		free_pidmap(pid->numbers + i);

	kmem_cache_free(ns->pid_cachep, pid);
	pid = NULL;
	goto out;
}

void disable_pid_allocation(struct pid_namespace *ns)
{
	spin_lock_irq(&pidmap_lock);
	ns->nr_hashed &= ~PIDNS_HASH_ADDING;
	spin_unlock_irq(&pidmap_lock);
}

// ARM10C 20170624
// nr: 2, ns: &init_pid_ns
struct pid *find_pid_ns(int nr, struct pid_namespace *ns)
{
	struct upid *pnr;

	// nr: 2, ns: &init_pid_ns, pid_hashfn(2, &init_pid_ns): 계산된 hash index 값
	// hlist_first_rcu(&pid_hash[계산된 hash index 값]): &(&pid_hash[계산된 hash index 값])->first
	// hlist_entry_safe(&(&pid_hash[계산된 hash index 값])->first, struct upid, pid_chain): &(kmem_cache#19-oX (struct pid))->numbers[0] (pid 2)
	hlist_for_each_entry_rcu(pnr,
			&pid_hash[pid_hashfn(nr, ns)], pid_chain)
	// for (pnr = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(&pid_hash[계산된 hash index 값])), typeof(*(pnr)), pid_chain);
	//      pnr; pnr = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(&(pnr)->pid_chain)), typeof(*(pnr)), pid_chain))

		// pnr: &(kmem_cache#19-oX (struct pid))->numbers[0] (pid 2)

		// pnr->nr: (&(kmem_cache#19-oX (struct pid))->numbers[0])->nr: 2, nr: 2,
		// pnr->ns: (&(kmem_cache#19-oX (struct pid))->numbers[0])->ns: &init_pid_ns, ns: &init_pid_ns
		if (pnr->nr == nr && pnr->ns == ns)
			// pnr: &(kmem_cache#19-oX (struct pid))->numbers[0] (pid 2), ns->level: (&init_pid_ns)->level: 0
			// container_of(&(kmem_cache#19-oX (struct pid))->numbers[0] (pid 2), struct pid, numbers[0]): kmem_cache#19-oX (struct pid)
			return container_of(pnr, struct pid,
					numbers[ns->level]);
			// return kmem_cache#19-oX (struct pid)

	return NULL;
}
EXPORT_SYMBOL_GPL(find_pid_ns);

struct pid *find_vpid(int nr)
{
	return find_pid_ns(nr, task_active_pid_ns(current));
}
EXPORT_SYMBOL_GPL(find_vpid);

/*
 * attach_pid() must be called with the tasklist_lock write-held.
 */
// ARM10C 20161210
// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PGID: 1
// ARM10C 20161210
// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_SID: 2
// ARM10C 20161210
// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PID: 0
// ARM10C 20170610
// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PGID: 1
// ARM10C 20170610
// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_SID: 2
// ARM10C 20170610
// p: kmem_cache#15-oX (struct task_struct), PIDTYPE_PID: 1
void attach_pid(struct task_struct *task, enum pid_type type)
{
	// type: 1, &task->pids[1]: &(kmem_cache#15-oX (struct task_struct))->pids[1]
	struct pid_link *link = &task->pids[type];
	// link: &(kmem_cache#15-oX (struct task_struct))->pids[1]

	// &link->node: &(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node,
	// type: 1, link->pid: (&(kmem_cache#15-oX (struct task_struct))->pids[1])->pid: &init_struct_pid,
	// &link->pid->tasks[1]: &(&init_struct_pid)->tasks[1]
	hlist_add_head_rcu(&link->node, &link->pid->tasks[type]);

	// hlist_add_head_rcu 에서 한일:
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->next: NULL
	// (&(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node)->pprev: &(&(&init_struct_pid)->tasks[1])->first
	//
	// ((*((struct hlist_node __rcu **)(&(&(&init_struct_pid)->tasks[1])->first)))): &(&(kmem_cache#15-oX (struct task_struct))->pids[1])->node
}

static void __change_pid(struct task_struct *task, enum pid_type type,
			struct pid *new)
{
	struct pid_link *link;
	struct pid *pid;
	int tmp;

	link = &task->pids[type];
	pid = link->pid;

	hlist_del_rcu(&link->node);
	link->pid = new;

	for (tmp = PIDTYPE_MAX; --tmp >= 0; )
		if (!hlist_empty(&pid->tasks[tmp]))
			return;

	free_pid(pid);
}

void detach_pid(struct task_struct *task, enum pid_type type)
{
	__change_pid(task, type, NULL);
}

void change_pid(struct task_struct *task, enum pid_type type,
		struct pid *pid)
{
	__change_pid(task, type, pid);
	attach_pid(task, type);
}

/* transfer_pid is an optimization of attach_pid(new), detach_pid(old) */
void transfer_pid(struct task_struct *old, struct task_struct *new,
			   enum pid_type type)
{
	new->pids[type].pid = old->pids[type].pid;
	hlist_replace_rcu(&old->pids[type].node, &new->pids[type].node);
}

// ARM10C 20170624
// kmem_cache#19-oX (struct pid) (pid 2), PIDTYPE_PID: 0
struct task_struct *pid_task(struct pid *pid, enum pid_type type)
{
	struct task_struct *result = NULL;
	// result: NULL

// 2017/06/24 종료

	if (pid) {
		struct hlist_node *first;
		first = rcu_dereference_check(hlist_first_rcu(&pid->tasks[type]),
					      lockdep_tasklist_lock_is_held());
		if (first)
			result = hlist_entry(first, struct task_struct, pids[(type)].node);
	}
	return result;
}
EXPORT_SYMBOL(pid_task);

/*
 * Must be called under rcu_read_lock().
 */
// ARM10C 20170624
// pid: 2, &init_pid_ns
struct task_struct *find_task_by_pid_ns(pid_t nr, struct pid_namespace *ns)
{
	// rcu_read_lock_held(): 1
	rcu_lockdep_assert(rcu_read_lock_held(),
			   "find_task_by_pid_ns() needs rcu_read_lock()"
			   " protection"); // null function

	// nr: 2, ns: &init_pid_ns, find_pid_ns(2, &init_pid_ns): kmem_cache#19-oX (struct pid) (pid 2), PIDTYPE_PID: 0
	return pid_task(find_pid_ns(nr, ns), PIDTYPE_PID);
}

struct task_struct *find_task_by_vpid(pid_t vnr)
{
	return find_task_by_pid_ns(vnr, task_active_pid_ns(current));
}

struct pid *get_task_pid(struct task_struct *task, enum pid_type type)
{
	struct pid *pid;
	rcu_read_lock();
	if (type != PIDTYPE_PID)
		task = task->group_leader;
	pid = get_pid(task->pids[type].pid);
	rcu_read_unlock();
	return pid;
}
EXPORT_SYMBOL_GPL(get_task_pid);

struct task_struct *get_pid_task(struct pid *pid, enum pid_type type)
{
	struct task_struct *result;
	rcu_read_lock();
	result = pid_task(pid, type);
	if (result)
		get_task_struct(result);
	rcu_read_unlock();
	return result;
}
EXPORT_SYMBOL_GPL(get_pid_task);

struct pid *find_get_pid(pid_t nr)
{
	struct pid *pid;

	rcu_read_lock();
	pid = get_pid(find_vpid(nr));
	rcu_read_unlock();

	return pid;
}
EXPORT_SYMBOL_GPL(find_get_pid);

// ARM10C 20161217
// task->pids[0].pid: (kmem_cache#15-oX (struct task_struct))->pids[0].pid: kmem_cache#19-oX (struct pid), ns: &init_pid_ns
// ARM10C 20170617
// task->pids[0].pid: (kmem_cache#15-oX (struct task_struct))->pids[0].pid: kmem_cache#19-oX (struct pid), ns: &init_pid_ns
pid_t pid_nr_ns(struct pid *pid, struct pid_namespace *ns)
{
	struct upid *upid;
	pid_t nr = 0;
	// nr: 0
	// nr: 0

	// pid: kmem_cache#19-oX (struct pid), ns->level: (&init_pid_ns)->level: 0, pid->level: (kmem_cache#19-oX (struct pid))->level: 0
	// pid: kmem_cache#19-oX (struct pid), ns->level: (&init_pid_ns)->level: 0, pid->level: (kmem_cache#19-oX (struct pid))->level: 0
	if (pid && ns->level <= pid->level) {
		// ns->level: (&init_pid_ns)->level: 0, &pid->numbers[0]: &(kmem_cache#19-oX (struct pid))->numbers[0]
		// ns->level: (&init_pid_ns)->level: 0, &pid->numbers[0]: &(kmem_cache#19-oX (struct pid))->numbers[0]
		upid = &pid->numbers[ns->level];
		// upid: &(kmem_cache#19-oX (struct pid))->numbers[0]
		// upid: &(kmem_cache#19-oX (struct pid))->numbers[0]

		// upid->ns: (&(kmem_cache#19-oX (struct pid))->numbers[0])->ns: &init_pid_ns, ns: &init_pid_ns
		// upid->ns: (&(kmem_cache#19-oX (struct pid))->numbers[0])->ns: &init_pid_ns, ns: &init_pid_ns
		if (upid->ns == ns)
			// nr: 0, upid->nr: (&(kmem_cache#19-oX (struct pid))->numbers[0])->nr: 1
			// nr: 0, upid->nr: (&(kmem_cache#19-oX (struct pid))->numbers[0])->nr: 2
			nr = upid->nr;
			// nr: 1
			// nr: 2
	}
	// nr: 1
	// nr: 2
	return nr;
	// return 1
	// return 2
}
EXPORT_SYMBOL_GPL(pid_nr_ns);

pid_t pid_vnr(struct pid *pid)
{
	return pid_nr_ns(pid, task_active_pid_ns(current));
}
EXPORT_SYMBOL_GPL(pid_vnr);

// ARM10C 20161217
// tsk: kmem_cache#15-oX (struct task_struct), PIDTYPE_PID: 0, NULL
// ARM10C 20170617
// tsk: kmem_cache#15-oX (struct task_struct), PIDTYPE_PID: 0, NULL
pid_t __task_pid_nr_ns(struct task_struct *task, enum pid_type type,
			struct pid_namespace *ns)
{
	pid_t nr = 0;
	// nr: 0
	// nr: 0

	rcu_read_lock();

	// rcu_read_lock 에서 한일:
	// (&init_task)->rcu_read_lock_nesting: 1

	// rcu_read_lock 에서 한일:
	// (&init_task)->rcu_read_lock_nesting: 1

	// nr: 0
	// nr: 0
	if (!ns)
		// current: &init_task, task_active_pid_ns(&init_task): &init_pid_ns
		// current: &init_task, task_active_pid_ns(&init_task): &init_pid_ns
		ns = task_active_pid_ns(current);
		// ns: &init_pid_ns
		// ns: &init_pid_ns

	// task: kmem_cache#15-oX (struct task_struct), pid_alive(kmem_cache#15-oX (struct task_struct)): 1
	// task: kmem_cache#15-oX (struct task_struct), pid_alive(kmem_cache#15-oX (struct task_struct)): 1
	if (likely(pid_alive(task))) {
		// type: 0, PIDTYPE_PID: 0
		// type: 0, PIDTYPE_PID: 0
		if (type != PIDTYPE_PID)
			task = task->group_leader;

		// type: 0, task->pids[0].pid: (kmem_cache#15-oX (struct task_struct))->pids[0].pid: kmem_cache#19-oX (struct pid), ns: &init_pid_ns
		// pid_nr_ns(kmem_cache#19-oX (struct pid), &init_pid_ns): 1
		// type: 0, task->pids[0].pid: (kmem_cache#15-oX (struct task_struct))->pids[0].pid: kmem_cache#19-oX (struct pid), ns: &init_pid_ns
		// pid_nr_ns(kmem_cache#19-oX (struct pid), &init_pid_ns): 2
		nr = pid_nr_ns(task->pids[type].pid, ns);
		// nr: 1
		// nr: 2
	}
	rcu_read_unlock();

	// rcu_read_unlock 에서 한일:
	// (&init_task)->rcu_read_lock_nesting: 0

	// rcu_read_unlock 에서 한일:
	// (&init_task)->rcu_read_lock_nesting: 0

	// nr: 1
	// nr: 2
	return nr;
	// return 1
	// return 2
}
EXPORT_SYMBOL(__task_pid_nr_ns);

pid_t task_tgid_nr_ns(struct task_struct *tsk, struct pid_namespace *ns)
{
	return pid_nr_ns(task_tgid(tsk), ns);
}
EXPORT_SYMBOL(task_tgid_nr_ns);

// ARM10C 20160903
// current: &init_task
// ARM10C 20161217
// current: &init_task
// ARM10C 20170617
// current: &init_task
struct pid_namespace *task_active_pid_ns(struct task_struct *tsk)
{
	// tsk: &init_task, task_pid(&init_task): &init_struct_pid
	// ns_of_pid(&init_struct_pid): &init_pid_ns
	return ns_of_pid(task_pid(tsk));
	// return &init_pid_ns
}
EXPORT_SYMBOL_GPL(task_active_pid_ns);

/*
 * Used by proc to find the first pid that is greater than or equal to nr.
 *
 * If there is a pid at nr this function is exactly the same as find_pid_ns.
 */
struct pid *find_ge_pid(int nr, struct pid_namespace *ns)
{
	struct pid *pid;

	do {
		pid = find_pid_ns(nr, ns);
		if (pid)
			break;
		nr = next_pidmap(ns, nr);
	} while (nr > 0);

	return pid;
}

/*
 * The pid hash table is scaled according to the amount of memory in the
 * machine.  From a minimum of 16 slots up to 4096 slots at one gigabyte or
 * more.
 */
// ARM10C 20140322
void __init pidhash_init(void)
{
	unsigned int i, pidhash_size;

	// sizeof(*pid_hash): 4, HASH_EARLY: 0x00000001, HASH_SMALL: 0x00000002, pidhash_shift: 4
	pid_hash = alloc_large_system_hash("PID", sizeof(*pid_hash), 0, 18,
					   HASH_EARLY | HASH_SMALL,
					   &pidhash_shift, NULL,
					   0, 4096);
	// pid hash를 위한 메모리 공간을 16kB만큼 할당 받고, pidhash_shift 가 12로 변경됨

	// pidhash_shift: 12
	pidhash_size = 1U << pidhash_shift;
	// pidhash_size : 4096 : 1 << 12
	
	for (i = 0; i < pidhash_size; i++)
		INIT_HLIST_HEAD(&pid_hash[i]);
	// 4096개의 hash 리스트를 만듬
}

// ARM10C 20150912
void __init pidmap_init(void)
{
	/* Veryify no one has done anything silly */
	// PID_MAX_LIMIT: 0x8000, PIDNS_HASH_ADDING: 0x80000000
	BUILD_BUG_ON(PID_MAX_LIMIT >= PIDNS_HASH_ADDING);

	/* bump default and minimum pid_max based on number of cpus */
	// pid_max: 0x8000, pid_max_max: 0x8000, PIDS_PER_CPU_DEFAULT: 1024,
	// num_possible_cpus(): 4, max_t(int, 0x8000, 4 * 1024): 0x8000
	pid_max = min(pid_max_max, max_t(int, pid_max,
				PIDS_PER_CPU_DEFAULT * num_possible_cpus()));
	// pid_max: 0x8000

	// pid_max_min: 301, PIDS_PER_CPU_MIN: 8, num_possible_cpus(): 4
	// max_t(int, 301, 8 * 4): 301
	pid_max_min = max_t(int, pid_max_min,
				PIDS_PER_CPU_MIN * num_possible_cpus());
	// pid_max_min: 301

	// pid_max: 0x8000, pid_max_min: 301
	pr_info("pid_max: default: %u minimum: %u\n", pid_max, pid_max_min);
	// "pid_max: default: 0x8000 minimum: 0x12d\n"

	// PAGE_SIZE: 0x1000, GFP_KERNEL: 0xD0, kzalloc(0x1000, GFP_KERNEL: 0xD0): kmem_cache#23-oX
	init_pid_ns.pidmap[0].page = kzalloc(PAGE_SIZE, GFP_KERNEL);
	// init_pid_ns.pidmap[0].page: kmem_cache#23-oX

	/* Reserve PID 0. We never call free_pidmap(0) */
	// init_pid_ns.pidmap[0].page: kmem_cache#23-oX
	// set_bit(0, kmem_cache#23-oX): *(kmem_cache#23-oX): 0x1
	set_bit(0, init_pid_ns.pidmap[0].page);
	
	// set_bit에서 한일:
	// pid 0의 pidmap의 page map table의 메모리 주소를 가지고 있는 page에
	// 0 bit 값을 1로 바꾸어 pid 0 의 pidmap을 reserve함

	// init_pid_ns.pidmap[0].nr_free: 0x8000
	atomic_dec(&init_pid_ns.pidmap[0].nr_free);

	// atomic_dec에서 한일:
	// init_pid_ns.pidmap[0].nr_free: 0x7fff

	// SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_PANIC: 0x00040000UL
	// KMEM_CACHE(pid, 0x00042000):
	// kmem_cache_create("pid", sizeof(struct pid), __alignof__(struct pid), (0x00042000), NULL): kmem_cache#19
	init_pid_ns.pid_cachep = KMEM_CACHE(pid,
			SLAB_HWCACHE_ALIGN | SLAB_PANIC);
	// init_pid_ns.pid_cachep: kmem_cache#19
}
