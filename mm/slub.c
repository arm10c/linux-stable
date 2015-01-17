/*
 * SLUB: A slab allocator that limits cache line use instead of queuing
 * objects in per cpu and per node lists.
 *
 * The allocator synchronizes using per slab locks or atomic operatios
 * and only uses a centralized lock to manage a pool of partial slabs.
 *
 * (C) 2007 SGI, Christoph Lameter
 * (C) 2011 Linux Foundation, Christoph Lameter
 */

#include <linux/mm.h>
#include <linux/swap.h> /* struct reclaim_state */
#include <linux/module.h>
#include <linux/bit_spinlock.h>
#include <linux/interrupt.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include "slab.h"
#include <linux/proc_fs.h>
#include <linux/notifier.h>
#include <linux/seq_file.h>
#include <linux/kmemcheck.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/mempolicy.h>
#include <linux/ctype.h>
#include <linux/debugobjects.h>
#include <linux/kallsyms.h>
#include <linux/memory.h>
#include <linux/math64.h>
#include <linux/fault-inject.h>
#include <linux/stacktrace.h>
#include <linux/prefetch.h>
#include <linux/memcontrol.h>

#include <trace/events/kmem.h>

#include "internal.h"

/*
 * Lock order:
 *   1. slab_mutex (Global Mutex)
 *   2. node->list_lock
 *   3. slab_lock(page) (Only on some arches and for debugging)
 *
 *   slab_mutex
 *
 *   The role of the slab_mutex is to protect the list of all the slabs
 *   and to synchronize major metadata changes to slab cache structures.
 *
 *   The slab_lock is only used for debugging and on arches that do not
 *   have the ability to do a cmpxchg_double. It only protects the second
 *   double word in the page struct. Meaning
 *	A. page->freelist	-> List of object free in a page
 *	B. page->counters	-> Counters of objects
 *	C. page->frozen		-> frozen state
 *
 *   If a slab is frozen then it is exempt from list management. It is not
 *   on any list. The processor that froze the slab is the one who can
 *   perform list operations on the page. Other processors may put objects
 *   onto the freelist but the processor that froze the slab is the only
 *   one that can retrieve the objects from the page's freelist.
 *
 *   The list_lock protects the partial and full list on each node and
 *   the partial slab counter. If taken then no new slabs may be added or
 *   removed from the lists nor make the number of partial slabs be modified.
 *   (Note that the total number of slabs is an atomic value that may be
 *   modified without taking the list lock).
 *
 *   The list_lock is a centralized lock and thus we avoid taking it as
 *   much as possible. As long as SLUB does not have to handle partial
 *   slabs, operations can continue without any centralized lock. F.e.
 *   allocating a long series of objects that fill up slabs does not require
 *   the list lock.
 *   Interrupts are disabled during allocation and deallocation in order to
 *   make the slab allocator safe to use in the context of an irq. In addition
 *   interrupts are disabled to ensure that the processor does not change
 *   while handling per_cpu slabs, due to kernel preemption.
 *
 * SLUB assigns one slab for allocation to each processor.
 * Allocations only occur from these slabs called cpu slabs.
 *
 * Slabs with free elements are kept on a partial list and during regular
 * operations no list for full slabs is used. If an object in a full slab is
 * freed then the slab will show up again on the partial lists.
 * We track full slabs for debugging purposes though because otherwise we
 * cannot scan all objects.
 *
 * Slabs are freed when they become empty. Teardown and setup is
 * minimal so we rely on the page allocators per cpu caches for
 * fast frees and allocs.
 *
 * Overloading of page flags that are otherwise used for LRU management.
 *
 * PageActive 		The slab is frozen and exempt from list processing.
 * 			This means that the slab is dedicated to a purpose
 * 			such as satisfying allocations for a specific
 * 			processor. Objects may be freed in the slab while
 * 			it is frozen but slab_free will then skip the usual
 * 			list operations. It is up to the processor holding
 * 			the slab to integrate the slab into the slab lists
 * 			when the slab is no longer needed.
 *
 * 			One use of this flag is to mark slabs that are
 * 			used for allocations. Then such a slab becomes a cpu
 * 			slab. The cpu slab may be equipped with an additional
 * 			freelist that allows lockless access to
 * 			free objects in addition to the regular freelist
 * 			that requires the slab lock.
 *
 * PageError		Slab requires special handling due to debug
 * 			options set. This moves	slab handling out of
 * 			the fast path and disables lockless freelists.
 */

// ARM10C 20140419
// s: &boot_kmem_cache_node
// ARM10C 20140614
// ARM10C 20140621
// ARM10C 20140628
// s: &boot_kmem_cache
static inline int kmem_cache_debug(struct kmem_cache *s)
{
#ifdef CONFIG_SLUB_DEBUG // CONFIG_SLUB_DEBUG=y
	// s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_DEBUG_FLAGS: 0x210D00
	// s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_DEBUG_FLAGS: 0x210D00
	return unlikely(s->flags & SLAB_DEBUG_FLAGS);
	// return 0
	// return 0
#else
	return 0;
#endif
}

// ARM10C 20140419
// s: &boot_kmem_cache_node
// ARM10C 20140614
// ARM10C 20140621
// s: &boot_kmem_cache
// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// ARM10C 20140726
// s: &kmem_cache#30
// ARM10C 20140726
// s: &kmem_cache#23
// ARM10C 20140920
// s: &kmem_cache#21
static inline bool kmem_cache_has_cpu_partial(struct kmem_cache *s)
{
#ifdef CONFIG_SLUB_CPU_PARTIAL // CONFIG_SLUB_CPU_PARTIAL=y
	// s: &boot_kmem_cache_node, kmem_cache_debug(&boot_kmem_cache_node): 0
	// s: &boot_kmem_cache, kmem_cache_debug(&boot_kmem_cache): 0
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// kmem_cache_debug(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address): 0
	return !kmem_cache_debug(s);
	// return 1
	// return 1
	// return 1
#else
	return false;
#endif
}

/*
 * Issues still to be resolved:
 *
 * - Support PAGE_ALLOC_DEBUG. Should be easy to do.
 *
 * - Variable sizing of the per node arrays
 */

/* Enable to test recovery from slab corruption on boot */
#undef SLUB_RESILIENCY_TEST

/* Enable to log cmpxchg failures */
#undef SLUB_DEBUG_CMPXCHG

/*
 * Mininum number of partial slabs. These will be left on the partial
 * lists even if they are empty. kmem_cache_shrink may reclaim them.
 */
// ARM10C 20140419
#define MIN_PARTIAL 5

/*
 * Maximum number of desirable partial slabs.
 * The existence of more partial slabs makes kmem_cache_shrink
 * sort the partial list by the number of objects in use.
 */
// ARM10C 20140726
#define MAX_PARTIAL 10

// ARM10C 20140524
// SLAB_DEBUG_FREE: 0x00000100UL, SLAB_RED_ZONE: 0x00000400UL
// SLAB_POISON: 0x00000800UL, SLAB_STORE_USER: 0x00010000UL
// DEBUG_DEFAULT_FLAGS: 0x10d00
#define DEBUG_DEFAULT_FLAGS (SLAB_DEBUG_FREE | SLAB_RED_ZONE | \
				SLAB_POISON | SLAB_STORE_USER)

/*
 * Debugging flags that require metadata to be stored in the slab.  These get
 * disabled when slub_debug=O is used and a cache's min order increases with
 * metadata.
 */
#define DEBUG_METADATA_FLAGS (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER)

/*
 * Set of flags that will prevent slab merging
 */
// ARM10C 20140920
// SLAB_RED_ZONE: 0x00000400UL, SLAB_POISON: 0x00000800UL
// SLAB_STORE_USER: 0x00010000UL, SLAB_TRACE: 0x00200000UL
// SLAB_DESTROY_BY_RCU: 0x00080000UL, SLAB_NOLEAKTRACE: 0x00800000UL
// SLAB_FAILSLAB: 0x00000000UL
// SLUB_NEVER_MERGE: 0xA90C00
#define SLUB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
		SLAB_TRACE | SLAB_DESTROY_BY_RCU | SLAB_NOLEAKTRACE | \
		SLAB_FAILSLAB)

// ARM10C 20140920
// SLAB_DEBUG_FREE: 0x00000100UL, SLAB_RECLAIM_ACCOUNT: 0x00020000UL
// SLAB_CACHE_DMA: 0x00004000UL SLAB_NOTRACK: 0x00000000UL
// SLUB_MERGE_SAME: 0x24100
#define SLUB_MERGE_SAME (SLAB_DEBUG_FREE | SLAB_RECLAIM_ACCOUNT | \
		SLAB_CACHE_DMA | SLAB_NOTRACK)

// ARM10C 20140419
#define OO_SHIFT	16
// ARM10C 20140419
// OO_SHIFT: 16
// OO_MASK: 0xFFFF
#define OO_MASK		((1 << OO_SHIFT) - 1)
// ARM10C 20140419
// MAX_OBJS_PER_PAGE: 0x7fff
#define MAX_OBJS_PER_PAGE	32767 /* since page.objects is u15 */

/* Internal SLUB flags */
// ARM10C 20140419
// ARM10C 20140531
#define __OBJECT_POISON		0x80000000UL /* Poison object */
#define __CMPXCHG_DOUBLE	0x40000000UL /* Use cmpxchg_double */

#ifdef CONFIG_SMP // CONFIG_SMP=y
// ARM10C 20140726
static struct notifier_block slab_notifier;
#endif

/*
 * Tracking user of a slab.
 */
#define TRACK_ADDRS_COUNT 16
struct track {
	unsigned long addr;	/* Called from address */
#ifdef CONFIG_STACKTRACE
	unsigned long addrs[TRACK_ADDRS_COUNT];	/* Called from address */
#endif
	int cpu;		/* Was running on cpu */
	int pid;		/* Pid context */
	unsigned long when;	/* When did the operation occur */
};

enum track_item { TRACK_ALLOC, TRACK_FREE };

#ifdef CONFIG_SYSFS
static int sysfs_slab_add(struct kmem_cache *);
static int sysfs_slab_alias(struct kmem_cache *, const char *);
static void sysfs_slab_remove(struct kmem_cache *);
static void memcg_propagate_slab_attrs(struct kmem_cache *s);
#else
static inline int sysfs_slab_add(struct kmem_cache *s) { return 0; }
static inline int sysfs_slab_alias(struct kmem_cache *s, const char *p)
							{ return 0; }
static inline void sysfs_slab_remove(struct kmem_cache *s) { }

static inline void memcg_propagate_slab_attrs(struct kmem_cache *s) { }
#endif

// ARM10C 20140621
// s: &boot_kmem_cache_node, ALLOC_FROM_PARTIAL: 7
// ARM10C 20140628
// s: &boot_kmem_cache, ALLOC_SLAB: 8
// ARM10C 20140705
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// CPUSLAB_FLUSH: 13
// ARM10C 20140705
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// tail: DEACTIVATE_TO_HEAD: 15
// ARM10C 20140712
// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
// CPUSLAB_FLUSH: 13
// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, ALLOC_FASTPATH: 0
// ARM10C 20141206
// s: kmem_cache#30, FREE_FASTPATH: 2
static inline void stat(const struct kmem_cache *s, enum stat_item si)
{
#ifdef CONFIG_SLUB_STATS // CONFIG_SLUB_STATS=n
	__this_cpu_inc(s->cpu_slab->stat[si]);
#endif
}

/********************************************************************
 * 			Core slab cache functions
 *******************************************************************/

// ARM10C 20140531
// s: &boot_kmem_cache_node, node: 0
// ARM10C 20140614
// s: &boot_kmem_cache_node, searchnode: 0
// ARM10C 20140628
// s: &boot_kmem_cache, searchnode: 0
// ARM10C 20140705
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, 0
// ARM10C 20140712
// s: UNMOVABLE인 page 의 object의 시작 virtual address + 128, 0
// ARM10C 20140712
// UNMOVABLE인 page 의 object의 시작 virtual address + 128, 0
// ARM10C 20140719
// &UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, 0
static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node)
{
	// node: 0, s->node: (&boot_kmem_cache_node)->node[0]
	// node: 0, s->node: (&boot_kmem_cache)->node[0]
	// node: 0, s->node: (&boot_kmem_cache 용 object 주소)->node[0]
	// node: 0, s->node: (&boot_kmem_cache_node 용 object 주소)->node[0]
	return s->node[node];
	// return (&boot_kmem_cache_node)->node[0]
	// return (&boot_kmem_cache)->node[0]
	// return (&boot_kmem_cache 용 object 주소)->node[0]
	// return (&boot_kmem_cache_node 용 object 주소)->node[0]
}

/* Verify that a pointer has an address that is valid within a slab page */
static inline int check_valid_pointer(struct kmem_cache *s,
				struct page *page, const void *object)
{
	void *base;

	if (!object)
		return 1;

	base = page_address(page);
	if (object < base || object >= base + page->objects * s->size ||
		(object - base) % s->size) {
		return 0;
	}

	return 1;
}

// ARM10C 20140531
// kmem_cache_node: &boot_kmem_cache_node,
// n: UNMOVABLE인 page 의 object의 시작 virtual address
// ARM10C 20140621
// s: &boot_kmem_cache_node, freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
// ARM10C 20140628
// s: &boot_kmem_cache, freelist: UNMOVABLE인 page(boot_kmem_cache) 의 object의 시작 virtual address
// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
// freelist: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address + 3840
// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840,
static inline void *get_freepointer(struct kmem_cache *s, void *object)
{
	// object: UNMOVABLE인 page 의 object의 시작 virtual address
	// s->offset: (&boot_kmem_cache_node)->offset: 0
	return *(void **)(object + s->offset);
	// object: UNMOVABLE인 page 의 object의 시작 virtual address
}

// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// next_object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712,
static void prefetch_freepointer(const struct kmem_cache *s, void *object)
{
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712,
	// s->offset: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->offset: 0
	prefetch(object + s->offset);
	// cache table에 page 주소를 넣음
}

// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840,
static inline void *get_freepointer_safe(struct kmem_cache *s, void *object)
{
	void *p;

#ifdef CONFIG_DEBUG_PAGEALLOC // CONFIG_DEBUG_PAGEALLOC=n
	probe_kernel_read(&p, (void **)(object + s->offset), sizeof(p));
#else
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840,
	// get_freepointer(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712
	p = get_freepointer(s, object);
	// p: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712
#endif
	// p: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712
	return p;
	// return UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712
}

// ARM10C 20140531
// s: &boot_kmem_cache_node, last: UNMOVABLE인 page 의 virtual address
// p: UNMOVABLE인 page 의 virtual address
// ARM10C 20140628
// s: &boot_kmem_cache, last: UNMOVABLE인 page 의 virtual address(boot_kmem_cache),
// p: UNMOVABLE인 page 의 virtual address(boot_kmem_cache)
// ARM10C 20140705
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128,
// prior: NULL
// ARM10C 20140705
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
// old.freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
// ARM10C 20140712
// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
// UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address + 3840,
// prior: NULL
// ARM10C 20140712
// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
// freelist: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address + 3712,
// prior: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3840
// ARM10C 20141206
// s: kmem_cache#30, object: kmem_cache#30-o11,
// c->freelist: ((kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)->freelist
static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
{
	// object: UNMOVABLE인 page 의 virtual address
	// s->offset: (&boot_kmem_cache_node)->offset: 0
	// fp: UNMOVABLE인 page 의 virtual address
	// object: UNMOVABLE인 page 의 virtual address(boot_kmem_cache)
	// s->offset: (&boot_kmem_cache_node)->offset: 0
	// fp: UNMOVABLE인 page 의 virtual address(boot_kmem_cache)
	*(void **)(object + s->offset) = fp;
	// object: UNMOVABLE인 page 의 virtual address(boot_kmem_cache)
}

/* Loop over all objects in a slab */
// ARM10C 20140531
// s: &boot_kmem_cache_node,
// start: UNMOVABLE인 page 의 virtual address
// page->objects: 64
//
// for_each_object(p, &boot_kmem_cache_node, UNMOVABLE인 page 의 virtual address, 64):
// for (p = (UNMOVABLE인 page 의 virtual address);
//      p < (UNMOVABLE인 page 의 virtual address) + (64) * (&boot_kmem_cache_node)->size;
//	p += (&boot_kmem_cache_node)->size)
//
// ARM10C 20140628
// for_each_object(p, &boot_kmem_cache, UNMOVABLE인 page 의 virtual address(boot_kmem_cache), 32):
// for (p = (UNMOVABLE인 page 의 virtual address(boot_kmem_cache));
//      p < (UNMOVABLE인 page 의 virtual address(boot_kmem_cache)) + (32) * (&boot_kmem_cache)->size;
//      p += (&boot_kmem_cache)->size)
#define for_each_object(__p, __s, __addr, __objects) \
	for (__p = (__addr); __p < (__addr) + (__objects) * (__s)->size;\
			__p += (__s)->size)

/* Determine object index from a given position */
static inline int slab_index(void *p, struct kmem_cache *s, void *addr)
{
	return (p - addr) / s->size;
}

// ARM10C 20140621
// s: &boot_kmem_cache_node
// ARM10C 20140628
// s: &boot_kmem_cache
// ARM10C 20140712
// s: &boot_kmem_cache_node
// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
static inline size_t slab_ksize(const struct kmem_cache *s)
{
#ifdef CONFIG_SLUB_DEBUG // CONFIG_SLUB_DEBUG=y
	/*
	 * Debugging requires use of the padding between object
	 * and whatever may come after it.
	 */
	// s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_RED_ZONE: 0x00000400UL, SLAB_POISON: 0x00000800UL
	// s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_RED_ZONE: 0x00000400UL, SLAB_POISON: 0x00000800UL
	if (s->flags & (SLAB_RED_ZONE | SLAB_POISON))
		return s->object_size;

#endif
	/*
	 * If we have the need to store the freelist pointer
	 * back there or track user information then we can
	 * only use the space before that information.
	 */
	// s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_DESTROY_BY_RCU: 0x00080000UL, SLAB_STORE_USER: 0x00010000UL
	// s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_DESTROY_BY_RCU: 0x00080000UL, SLAB_STORE_USER: 0x00010000UL
	if (s->flags & (SLAB_DESTROY_BY_RCU | SLAB_STORE_USER))
		return s->inuse;
	/*
	 * Else we can use all the padding etc for the allocation
	 */
	// s->size: boot_kmem_cache_node.size: 64
	// s->size: boot_kmem_cache.size: 128
	return s->size;
	// return 64
	// return 128
}

// ARM10C 20140419
// slub_max_order: 3, size: 64, reserved: 0
// min_order: 0, size: 64, reserved: 0
// ARM10C 20140614
// slub_max_order: 3, size: 128, reserved: 0
// min_order: 0, size: 128, reserved: 0
// ARM10C 20140726
// slub_max_order: 3, size: 4096, reserved: 0
// min_order: 0, size: 4096, reserved: 0
// ARM10C 20140726
// order: 3, OO_SHIFT: 16, size: 4096, reserved: 0
// ARM10C 20140726
// order: 1, OO_SHIFT: 16, size: 4096, reserved: 0
// ARM10C 20140920
// slub_max_order: 3, size: 1080, reserved: 0
// ARM10C 20140920
// min_order: 0, size: 1080, reserved: 0
static inline int order_objects(int order, unsigned long size, int reserved)
{
	// order: 3, PAGE_SIZE: 0x1000, (0x1000 << 3): 0x8000, reserved: 0, size: 64
	// order: 0, PAGE_SIZE: 0x1000, (0x1000 << 0): 0x1000, reserved: 0, size: 64
	// ARM10C 20140614
	// order: 3, PAGE_SIZE: 0x1000, (0x1000 << 3): 0x8000, reserved: 0, size: 128
	// order: 0, PAGE_SIZE: 0x1000, (0x1000 << 0): 0x1000, reserved: 0, size: 128
	// ARM10C 20140726
	// order: 3, PAGE_SIZE: 0x1000, (0x1000 << 3): 0x8000, reserved: 0, size: 4096
	// order: 0, PAGE_SIZE: 0x1000, (0x1000 << 0): 0x1000, reserved: 0, size: 4096
	// order: 3, PAGE_SIZE: 0x1000, (0x1000 << 3): 0x8000, reserved: 0, size: 4096
	// order: 1, PAGE_SIZE: 0x1000, (0x1000 << 1): 0x2000, reserved: 0, size: 4096
	// order: 3, PAGE_SIZE: 0x1000, (0x1000 << 3): 0x8000, reserved: 0, size: 1080
	// order: 0, PAGE_SIZE: 0x1000, (0x1000 << 0): 0x1000, reserved: 0, size: 1080
	return ((PAGE_SIZE << order) - reserved) / size;
	// return 0x200
	// return 0x40
	// ARM10C 20140614
	// return 0x100
	// return 0x20
	// ARM10C 20140726
	// return 0x8
	// return 0x1
	// return 0x8
	// return 0x2
	// return 0x1e
	// return 0x3
}

// ARM10C 20140419
// order: 0, size: 64, s->reserved: boot_kmem_cache_node.reserved: 0
// ARM10C 20140614
// order: 0, size: 128, s->reserved: boot_kmem_cache.reserved: 0
// ARM10C 20140726
// order: 0, size: 64, s->reserved: kmem_cache#30.reserved: 0
// ARM10C 20140726
// order: 3, size: 4096, s->reserved: kmem_cache#23.reserved: 0
// ARM10C 20140726
// order: 1, size: 4096, s->reserved: kmem_cache#23.reserved: 0
// ARM10C 20140920
// order: 3, size: 1080, s->reserved: kmem_cache#21.reserved: 0
// ARM10C 20140920
// order: 0, size: 1080, s->reserved: kmem_cache#21.reserved: 0
static inline struct kmem_cache_order_objects oo_make(int order,
		unsigned long size, int reserved)
{
	struct kmem_cache_order_objects x = {
		// order: 0, OO_SHIFT: 16, size: 64, reserved: 0
		// order_objects(0, 64, 0): 0x40
		// order: 0, OO_SHIFT: 16, size: 128, reserved: 0
		// order_objects(0, 128, 0): 0x20
		// order: 0, OO_SHIFT: 16, size: 64, reserved: 0
		// order_objects(0, 64, 0): 0x40
		// order: 3, OO_SHIFT: 16, size: 4096, reserved: 0
		// order_objects(3, 4096, 0): 0x8
		// order: 1, OO_SHIFT: 16, size: 4096, reserved: 0
		// order_objects(1, 4096, 0): 0x2
		// order: 3, OO_SHIFT: 16, size: 1080, reserved: 0
		// order_objects(3, 1080, 0): 0x1e
		// order: 0, OO_SHIFT: 16, size: 1080, reserved: 0
		// order_objects(0, 1080, 0): 0x3
		(order << OO_SHIFT) + order_objects(order, size, reserved)
	};
	// x.x: 0x00040
	// x.x: 0x00020
	// x.x: 0x00040
	// x.x: 0x30008
	// x.x: 0x10002
	// x.x: 0x3001e
	// x.x: 0x00003

	return x;
}

// ARM10C 20140426
// oo: boot_kmem_cache_node.oo
// ARM10C 20140524
// ARM10C 20140628
// oo: boot_kmem_cache.oo
static inline int oo_order(struct kmem_cache_order_objects x)
{
	// x.x: boot_kmem_cache_node.oo.x: 64, OO_SHIFT: 16
	// x.x: boot_kmem_cache.oo.x: 32, OO_SHIFT: 16
	return x.x >> OO_SHIFT;
	// return 0
	// return 0
}

// ARM10C 20140419
// boot_kmem_cache_node.oo.x: 64
// ARM10C 20140614
// ARM10C 20140628
// boot_kmem_cache.oo.x: 32
// ARM10C 20140726
// kmem_cache#23.oo.x: 0x30008
static inline int oo_objects(struct kmem_cache_order_objects x)
{

	// boot_kmem_cache_node.oo.x: 64, OO_MASK: 0xFFFF
	// boot_kmem_cache.oo.x: 32, OO_MASK: 0xFFFF
	// kmem_cache#23.oo.x: 0x30008, OO_MASK: 0xFFFF
	return x.x & OO_MASK;
	// return 64
	// return 32
	// return 8
}

/*
 * Per slab locking using the pagelock
 */
// ARM10C 20140621
// page: MIGRATE_UNMOVABLE인 page
static __always_inline void slab_lock(struct page *page)
{
	// PG_locked: 0, page->flags: (MIGRATE_UNMOVABLE인 page)->flags
	bit_spin_lock(PG_locked, &page->flags);
}

// ARM10C 20140621
// page: MIGRATE_UNMOVABLE인 page
static __always_inline void slab_unlock(struct page *page)
{
	// PG_locked: 0, page->flags: (MIGRATE_UNMOVABLE인 page)->flags
	__bit_spin_unlock(PG_locked, &page->flags);
}

/* Interrupts must be disabled (for the fallback code to work right) */
// ARM10C 20140621
// s: &boot_kmem_cache_node, page: MIGRATE_UNMOVABLE인 page,
// freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
// counters: 0x400001, new.freelist: NULL, new.counters: 0x80400040,
// "acquire_slab"
// ARM10C 20140705
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// page: UNMOVABLE인 page (boot_kmem_cache), prior: NULL, counters: 0x80200020
// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128, new.counters: 0x8020001f,
// "drain percpu freelist"
// ARM10C 20140705
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// page: UNMOVABLE인 page (boot_kmem_cache),
// old.freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968, old.counters: 0x80200002,
// new.freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968, new.counters: 0x00200001,
// "unfreezing slab"
// ARM10C 20140712
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache),
// old.freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968, old.counters: 0x200001,
// new.freelist: NULL, new.counters: 0x80200020,
// "acquire_slab"
// ARM10C 20140712
// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
// page: UNMOVABLE인 page,
// old.freelist: NULL, old.counters: 0x80400040,
// new.freelist: UNMOVABLE인 page의 object의 시작 virtual address + 128, new.counters: 0x8040003f,
// "drain percpu freelist"
// ARM10C 20140712
// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
// page: UNMOVABLE인 page,
// old.freelist: UNMOVABLE인 page 의 시작 virtual address + 3968, old.counters: 0x80400003
// new.freelist: UNMOVABLE인 page 의 시작 virtual address + 4032, new.counters: 0x00400002
// "unfreezing slab"
static inline bool __cmpxchg_double_slab(struct kmem_cache *s, struct page *page,
		void *freelist_old, unsigned long counters_old,
		void *freelist_new, unsigned long counters_new,
		const char *n)
{
	// irqs_disabled(): 1
	// irqs_disabled(): 1
	// irqs_disabled(): 1
	// irqs_disabled(): 1
	// irqs_disabled(): 1
	// irqs_disabled(): 1
	VM_BUG_ON(!irqs_disabled());

// CONFIG_HAVE_CMPXCHG_DOUBLE=n, CONFIG_HAVE_ALIGNED_STRUCT_PAGE=n
#if defined(CONFIG_HAVE_CMPXCHG_DOUBLE) && \
    defined(CONFIG_HAVE_ALIGNED_STRUCT_PAGE)
	if (s->flags & __CMPXCHG_DOUBLE) {
		if (cmpxchg_double(&page->freelist, &page->counters,
			freelist_old, counters_old,
			freelist_new, counters_new))
		return 1;
	} else
#endif
	{
		// page: MIGRATE_UNMOVABLE인 page
		// page: UNMOVABLE인 page (boot_kmem_cache)
		// page: UNMOVABLE인 page (boot_kmem_cache)
		// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
		// page: MIGRATE_UNMOVABLE인 page
		// page: MIGRATE_UNMOVABLE인 page
		slab_lock(page);
		// preempt count 증가 후 memory barrier 적용
		// preempt count 증가 후 memory barrier 적용
		// preempt count 증가 후 memory barrier 적용
		// preempt count 증가 후 memory barrier 적용
		// preempt count 증가 후 memory barrier 적용
		// preempt count 증가 후 memory barrier 적용

		// page: UNMOVABLE인 page
		// page->freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64,
		// freelist_old: UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// page->counters: 0x400001, counters_old: 0x400001
		// page: UNMOVABLE인 page (boot_kmem_cache)
		// page->freelist: (UNMOVABLE인 page (boot_kmem_cache))->freelist: NULL, freelist_old: NULL,
		// page->counters: 0x80200020, counters_old: 0x80200020
		// page: UNMOVABLE인 page (boot_kmem_cache)
		// page->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
		// freelist_old: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
		// page->counters: 0x80200001, counters_old: 0x80200001
		// page: UNMOVABLE인 page (boot_kmem_cache)
		// page->freelist: (UNMOVABLE인 page (boot_kmem_cache))->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
		// freelist_old: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
		// page->counters: 0x00200001, counters_old: 0x00200001
		// page: UNMOVABLE인 page
		// page->freelist: (UNMOVABLE인 page)->freelist: NULL, freelist_old: NULL
		// page->counters: 0x80400040, counters_old: 0x80400040
		// page: UNMOVABLE인 page
		// page->freelist: UNMOVABLE인 page 의 시작 virtual address + 3968,
		// freelist_old: UNMOVABLE인 page 의 시작 virtual address + 3968
		// page->counters: 0x80400003, counters_old: 0x80400003
		if (page->freelist == freelist_old &&
					page->counters == counters_old) {
			// freelist_new: NULL
			// freelist_new: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128
			// freelist_new: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
			// freelist_new: NULL
			// freelist_new: UNMOVABLE인 page 의 object의 시작 virtual address + 128
			// freelist_new: UNMOVABLE인 page 의 시작 virtual address + 4032
			page->freelist = freelist_new;
			// page->freelist: NULL
			// page->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128
			// page->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
			// page->freelist: NULL
			// page->freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 128
			// page->freelist: UNMOVABLE인 page 의 시작 virtual address + 4032

			// page->counters: 0x400001, counters_new: 0x80400040
			// page->counters: 0x80200020, counters_new: 0x8020001f
			// page->counters: 0x80200001, counters_new: 0x00200000
			// page->counters: 0x00200001, counters_new: 0x80200020
			// page->counters: 0x80400040, counters_new: 0x8040003f
			// page->counters: 0x80400003, counters_new: 0x00400002
			page->counters = counters_new;
			// page->counters: 0x80400040
			// page->counters: 0x8020001f
			// page->counters: 0x00200000
			// page->counters: 0x80200020
			// page->counters: 0x8040003f
			// page->counters: 0x00400002

			// page: MIGRATE_UNMOVABLE인 page
			// page: UNMOVABLE인 page (boot_kmem_cache)
			// page: UNMOVABLE인 page (boot_kmem_cache)
			// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
			// page: MIGRATE_UNMOVABLE인 page
			// page: MIGRATE_UNMOVABLE인 page
			slab_unlock(page);
			// (MIGRATE_UNMOVABLE인 page)->flags 의 bit 0을 클리어함
			// dmb(ish)를 사용하여 공유 자원 (MIGRATE_UNMOVABLE인 page)->flags 값을 갱신
			// memory barrier 적용 후 preempt count 감소 시킴
			// (MIGRATE_UNMOVABLE인 page(boot_kmem_cache))->flags 의 bit 0을 클리어함
			// dmb(ish)를 사용하여 공유 자원 (MIGRATE_UNMOVABLE인 page(boot_kmem_cache))->flags 값을 갱신
			// memory barrier 적용 후 preempt count 감소 시킴
			// (MIGRATE_UNMOVABLE인 page(boot_kmem_cache))->flags 의 bit 0을 클리어함
			// dmb(ish)를 사용하여 공유 자원 (MIGRATE_UNMOVABLE인 page(boot_kmem_cache))->flags 값을 갱신
			// memory barrier 적용 후 preempt count 감소 시킴
			// (MIGRATE_UNMOVABLE인 page(boot_kmem_cache))->flags 의 bit 0을 클리어함
			// dmb(ish)를 사용하여 공유 자원 (MIGRATE_UNMOVABLE인 page(boot_kmem_cache))->flags 값을 갱신
			// memory barrier 적용 후 preempt count 감소 시킴
			// (MIGRATE_UNMOVABLE인 page)->flags 의 bit 0을 클리어함
			// dmb(ish)를 사용하여 공유 자원 (MIGRATE_UNMOVABLE인 page)->flags 값을 갱신
			// memory barrier 적용 후 preempt count 감소 시킴
			// (MIGRATE_UNMOVABLE인 page)->flags 의 bit 0을 클리어함
			// dmb(ish)를 사용하여 공유 자원 (MIGRATE_UNMOVABLE인 page)->flags 값을 갱신
			// memory barrier 적용 후 preempt count 감소 시킴

			return 1;
			// return 1
			// return 1
			// return 1
			// return 1
			// return 1
			// return 1
		}
		slab_unlock(page);
	}

	cpu_relax();
	stat(s, CMPXCHG_DOUBLE_FAIL);

#ifdef SLUB_DEBUG_CMPXCHG
	printk(KERN_INFO "%s %s: cmpxchg double redo ", n, s->name);
#endif

	return 0;
}

static inline bool cmpxchg_double_slab(struct kmem_cache *s, struct page *page,
		void *freelist_old, unsigned long counters_old,
		void *freelist_new, unsigned long counters_new,
		const char *n)
{
#if defined(CONFIG_HAVE_CMPXCHG_DOUBLE) && \
    defined(CONFIG_HAVE_ALIGNED_STRUCT_PAGE)
	if (s->flags & __CMPXCHG_DOUBLE) {
		if (cmpxchg_double(&page->freelist, &page->counters,
			freelist_old, counters_old,
			freelist_new, counters_new))
		return 1;
	} else
#endif
	{
		unsigned long flags;

		local_irq_save(flags);
		slab_lock(page);
		if (page->freelist == freelist_old &&
					page->counters == counters_old) {
			page->freelist = freelist_new;
			page->counters = counters_new;
			slab_unlock(page);
			local_irq_restore(flags);
			return 1;
		}
		slab_unlock(page);
		local_irq_restore(flags);
	}

	cpu_relax();
	stat(s, CMPXCHG_DOUBLE_FAIL);

#ifdef SLUB_DEBUG_CMPXCHG
	printk(KERN_INFO "%s %s: cmpxchg double redo ", n, s->name);
#endif

	return 0;
}

#ifdef CONFIG_SLUB_DEBUG // CONFIG_SLUB_DEBUG=y
/*
 * Determine a map of object in use on a page.
 *
 * Node listlock must be held to guarantee that the page does
 * not vanish from under us.
 */
static void get_map(struct kmem_cache *s, struct page *page, unsigned long *map)
{
	void *p;
	void *addr = page_address(page);

	for (p = page->freelist; p; p = get_freepointer(s, p))
		set_bit(slab_index(p, s, addr), map);
}

/*
 * Debug settings:
 */
#ifdef CONFIG_SLUB_DEBUG_ON // CONFIG_SLUB_DEBUG_ON=n
static int slub_debug = DEBUG_DEFAULT_FLAGS;
#else
// ARM10C 20140419
static int slub_debug;
#endif

// ARM10C 20140419
static char *slub_debug_slabs;
// ARM10C 20140419
static int disable_higher_order_debug;

/*
 * Object debugging
 */
static void print_section(char *text, u8 *addr, unsigned int length)
{
	print_hex_dump(KERN_ERR, text, DUMP_PREFIX_ADDRESS, 16, 1, addr,
			length, 1);
}

static struct track *get_track(struct kmem_cache *s, void *object,
	enum track_item alloc)
{
	struct track *p;

	if (s->offset)
		p = object + s->offset + sizeof(void *);
	else
		p = object + s->inuse;

	return p + alloc;
}

static void set_track(struct kmem_cache *s, void *object,
			enum track_item alloc, unsigned long addr)
{
	struct track *p = get_track(s, object, alloc);

	if (addr) {
#ifdef CONFIG_STACKTRACE
		struct stack_trace trace;
		int i;

		trace.nr_entries = 0;
		trace.max_entries = TRACK_ADDRS_COUNT;
		trace.entries = p->addrs;
		trace.skip = 3;
		save_stack_trace(&trace);

		/* See rant in lockdep.c */
		if (trace.nr_entries != 0 &&
		    trace.entries[trace.nr_entries - 1] == ULONG_MAX)
			trace.nr_entries--;

		for (i = trace.nr_entries; i < TRACK_ADDRS_COUNT; i++)
			p->addrs[i] = 0;
#endif
		p->addr = addr;
		p->cpu = smp_processor_id();
		p->pid = current->pid;
		p->when = jiffies;
	} else
		memset(p, 0, sizeof(struct track));
}

// ARM10C 20140531
// kmem_cache_node: &boot_kmem_cache_node,
// n: UNMOVABLE인 page 의 object의 시작 virtual address
static void init_tracking(struct kmem_cache *s, void *object)
{
	// s->flags: (&boot_kmem_cache_node)->flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_STORE_USER: 0x00010000UL
	if (!(s->flags & SLAB_STORE_USER))
		return;
		// return 수행

	set_track(s, object, TRACK_FREE, 0UL);
	set_track(s, object, TRACK_ALLOC, 0UL);
}

static void print_track(const char *s, struct track *t)
{
	if (!t->addr)
		return;

	printk(KERN_ERR "INFO: %s in %pS age=%lu cpu=%u pid=%d\n",
		s, (void *)t->addr, jiffies - t->when, t->cpu, t->pid);
#ifdef CONFIG_STACKTRACE
	{
		int i;
		for (i = 0; i < TRACK_ADDRS_COUNT; i++)
			if (t->addrs[i])
				printk(KERN_ERR "\t%pS\n", (void *)t->addrs[i]);
			else
				break;
	}
#endif
}

static void print_tracking(struct kmem_cache *s, void *object)
{
	if (!(s->flags & SLAB_STORE_USER))
		return;

	print_track("Allocated", get_track(s, object, TRACK_ALLOC));
	print_track("Freed", get_track(s, object, TRACK_FREE));
}

static void print_page_info(struct page *page)
{
	printk(KERN_ERR
	       "INFO: Slab 0x%p objects=%u used=%u fp=0x%p flags=0x%04lx\n",
	       page, page->objects, page->inuse, page->freelist, page->flags);

}

static void slab_bug(struct kmem_cache *s, char *fmt, ...)
{
	va_list args;
	char buf[100];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	printk(KERN_ERR "========================================"
			"=====================================\n");
	printk(KERN_ERR "BUG %s (%s): %s\n", s->name, print_tainted(), buf);
	printk(KERN_ERR "----------------------------------------"
			"-------------------------------------\n\n");

	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
}

static void slab_fix(struct kmem_cache *s, char *fmt, ...)
{
	va_list args;
	char buf[100];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	printk(KERN_ERR "FIX %s: %s\n", s->name, buf);
}

static void print_trailer(struct kmem_cache *s, struct page *page, u8 *p)
{
	unsigned int off;	/* Offset of last byte */
	u8 *addr = page_address(page);

	print_tracking(s, p);

	print_page_info(page);

	printk(KERN_ERR "INFO: Object 0x%p @offset=%tu fp=0x%p\n\n",
			p, p - addr, get_freepointer(s, p));

	if (p > addr + 16)
		print_section("Bytes b4 ", p - 16, 16);

	print_section("Object ", p, min_t(unsigned long, s->object_size,
				PAGE_SIZE));
	if (s->flags & SLAB_RED_ZONE)
		print_section("Redzone ", p + s->object_size,
			s->inuse - s->object_size);

	if (s->offset)
		off = s->offset + sizeof(void *);
	else
		off = s->inuse;

	if (s->flags & SLAB_STORE_USER)
		off += 2 * sizeof(struct track);

	if (off != s->size)
		/* Beginning of the filler is the free pointer */
		print_section("Padding ", p + off, s->size - off);

	dump_stack();
}

static void object_err(struct kmem_cache *s, struct page *page,
			u8 *object, char *reason)
{
	slab_bug(s, "%s", reason);
	print_trailer(s, page, object);
}

static void slab_err(struct kmem_cache *s, struct page *page,
			const char *fmt, ...)
{
	va_list args;
	char buf[100];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	slab_bug(s, "%s", buf);
	print_page_info(page);
	dump_stack();
}

// ARM10C 20140531
// kmem_cache_node: &boot_kmem_cache_node,
// n: UNMOVABLE인 page 의 object의 시작 virtual address,
// SLUB_RED_ACTIVE: 0xcc
static void init_object(struct kmem_cache *s, void *object, u8 val)
{
	// object: UNMOVABLE인 page 의 object의 시작 virtual address
	u8 *p = object;
	// p: UNMOVABLE인 page 의 object의 시작 virtual address

	// s->flags: (&boot_kmem_cache_node)->flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// __OBJECT_POISON: 0x80000000UL
	if (s->flags & __OBJECT_POISON) {
		memset(p, POISON_FREE, s->object_size - 1);
		p[s->object_size - 1] = POISON_END;
	}

	// s->flags: (&boot_kmem_cache_node)->flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_RED_ZONE: 0x00000400UL
	if (s->flags & SLAB_RED_ZONE)
		memset(p + s->object_size, val, s->inuse - s->object_size);
}

static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
						void *from, void *to)
{
	slab_fix(s, "Restoring 0x%p-0x%p=0x%x\n", from, to - 1, data);
	memset(from, data, to - from);
}

static int check_bytes_and_report(struct kmem_cache *s, struct page *page,
			u8 *object, char *what,
			u8 *start, unsigned int value, unsigned int bytes)
{
	u8 *fault;
	u8 *end;

	fault = memchr_inv(start, value, bytes);
	if (!fault)
		return 1;

	end = start + bytes;
	while (end > fault && end[-1] == value)
		end--;

	slab_bug(s, "%s overwritten", what);
	printk(KERN_ERR "INFO: 0x%p-0x%p. First byte 0x%x instead of 0x%x\n",
					fault, end - 1, fault[0], value);
	print_trailer(s, page, object);

	restore_bytes(s, what, value, fault, end);
	return 0;
}

/*
 * Object layout:
 *
 * object address
 * 	Bytes of the object to be managed.
 * 	If the freepointer may overlay the object then the free
 * 	pointer is the first word of the object.
 *
 * 	Poisoning uses 0x6b (POISON_FREE) and the last byte is
 * 	0xa5 (POISON_END)
 *
 * object + s->object_size
 * 	Padding to reach word boundary. This is also used for Redzoning.
 * 	Padding is extended by another word if Redzoning is enabled and
 * 	object_size == inuse.
 *
 * 	We fill with 0xbb (RED_INACTIVE) for inactive objects and with
 * 	0xcc (RED_ACTIVE) for objects in use.
 *
 * object + s->inuse
 * 	Meta data starts here.
 *
 * 	A. Free pointer (if we cannot overwrite object on free)
 * 	B. Tracking data for SLAB_STORE_USER
 * 	C. Padding to reach required alignment boundary or at mininum
 * 		one word if debugging is on to be able to detect writes
 * 		before the word boundary.
 *
 *	Padding is done using 0x5a (POISON_INUSE)
 *
 * object + s->size
 * 	Nothing is used beyond s->size.
 *
 * If slabcaches are merged then the object_size and inuse boundaries are mostly
 * ignored. And therefore no slab options that rely on these boundaries
 * may be used with merged slabcaches.
 */

static int check_pad_bytes(struct kmem_cache *s, struct page *page, u8 *p)
{
	unsigned long off = s->inuse;	/* The end of info */

	if (s->offset)
		/* Freepointer is placed after the object. */
		off += sizeof(void *);

	if (s->flags & SLAB_STORE_USER)
		/* We also have user information there */
		off += 2 * sizeof(struct track);

	if (s->size == off)
		return 1;

	return check_bytes_and_report(s, page, p, "Object padding",
				p + off, POISON_INUSE, s->size - off);
}

/* Check the pad bytes at the end of a slab page */
static int slab_pad_check(struct kmem_cache *s, struct page *page)
{
	u8 *start;
	u8 *fault;
	u8 *end;
	int length;
	int remainder;

	if (!(s->flags & SLAB_POISON))
		return 1;

	start = page_address(page);
	length = (PAGE_SIZE << compound_order(page)) - s->reserved;
	end = start + length;
	remainder = length % s->size;
	if (!remainder)
		return 1;

	fault = memchr_inv(end - remainder, POISON_INUSE, remainder);
	if (!fault)
		return 1;
	while (end > fault && end[-1] == POISON_INUSE)
		end--;

	slab_err(s, page, "Padding overwritten. 0x%p-0x%p", fault, end - 1);
	print_section("Padding ", end - remainder, remainder);

	restore_bytes(s, "slab padding", POISON_INUSE, end - remainder, end);
	return 0;
}

static int check_object(struct kmem_cache *s, struct page *page,
					void *object, u8 val)
{
	u8 *p = object;
	u8 *endobject = object + s->object_size;

	if (s->flags & SLAB_RED_ZONE) {
		if (!check_bytes_and_report(s, page, object, "Redzone",
			endobject, val, s->inuse - s->object_size))
			return 0;
	} else {
		if ((s->flags & SLAB_POISON) && s->object_size < s->inuse) {
			check_bytes_and_report(s, page, p, "Alignment padding",
				endobject, POISON_INUSE,
				s->inuse - s->object_size);
		}
	}

	if (s->flags & SLAB_POISON) {
		if (val != SLUB_RED_ACTIVE && (s->flags & __OBJECT_POISON) &&
			(!check_bytes_and_report(s, page, p, "Poison", p,
					POISON_FREE, s->object_size - 1) ||
			 !check_bytes_and_report(s, page, p, "Poison",
				p + s->object_size - 1, POISON_END, 1)))
			return 0;
		/*
		 * check_pad_bytes cleans up on its own.
		 */
		check_pad_bytes(s, page, p);
	}

	if (!s->offset && val == SLUB_RED_ACTIVE)
		/*
		 * Object and freepointer overlap. Cannot check
		 * freepointer while object is allocated.
		 */
		return 1;

	/* Check free pointer validity */
	if (!check_valid_pointer(s, page, get_freepointer(s, p))) {
		object_err(s, page, p, "Freepointer corrupt");
		/*
		 * No choice but to zap it and thus lose the remainder
		 * of the free objects in this slab. May cause
		 * another error because the object count is now wrong.
		 */
		set_freepointer(s, p, NULL);
		return 0;
	}
	return 1;
}

static int check_slab(struct kmem_cache *s, struct page *page)
{
	int maxobj;

	VM_BUG_ON(!irqs_disabled());

	if (!PageSlab(page)) {
		slab_err(s, page, "Not a valid slab page");
		return 0;
	}

	maxobj = order_objects(compound_order(page), s->size, s->reserved);
	if (page->objects > maxobj) {
		slab_err(s, page, "objects %u > max %u",
			s->name, page->objects, maxobj);
		return 0;
	}
	if (page->inuse > page->objects) {
		slab_err(s, page, "inuse %u > max %u",
			s->name, page->inuse, page->objects);
		return 0;
	}
	/* Slab_pad_check fixes things up after itself */
	slab_pad_check(s, page);
	return 1;
}

/*
 * Determine if a certain object on a page is on the freelist. Must hold the
 * slab lock to guarantee that the chains are in a consistent state.
 */
static int on_freelist(struct kmem_cache *s, struct page *page, void *search)
{
	int nr = 0;
	void *fp;
	void *object = NULL;
	unsigned long max_objects;

	fp = page->freelist;
	while (fp && nr <= page->objects) {
		if (fp == search)
			return 1;
		if (!check_valid_pointer(s, page, fp)) {
			if (object) {
				object_err(s, page, object,
					"Freechain corrupt");
				set_freepointer(s, object, NULL);
			} else {
				slab_err(s, page, "Freepointer corrupt");
				page->freelist = NULL;
				page->inuse = page->objects;
				slab_fix(s, "Freelist cleared");
				return 0;
			}
			break;
		}
		object = fp;
		fp = get_freepointer(s, object);
		nr++;
	}

	max_objects = order_objects(compound_order(page), s->size, s->reserved);
	if (max_objects > MAX_OBJS_PER_PAGE)
		max_objects = MAX_OBJS_PER_PAGE;

	if (page->objects != max_objects) {
		slab_err(s, page, "Wrong number of objects. Found %d but "
			"should be %d", page->objects, max_objects);
		page->objects = max_objects;
		slab_fix(s, "Number of objects adjusted.");
	}
	if (page->inuse != page->objects - nr) {
		slab_err(s, page, "Wrong object count. Counter is %d but "
			"counted were %d", page->inuse, page->objects - nr);
		page->inuse = page->objects - nr;
		slab_fix(s, "Object count adjusted.");
	}
	return search == NULL;
}

static void trace(struct kmem_cache *s, struct page *page, void *object,
								int alloc)
{
	if (s->flags & SLAB_TRACE) {
		printk(KERN_INFO "TRACE %s %s 0x%p inuse=%d fp=0x%p\n",
			s->name,
			alloc ? "alloc" : "free",
			object, page->inuse,
			page->freelist);

		if (!alloc)
			print_section("Object ", (void *)object,
					s->object_size);

		dump_stack();
	}
}

/*
 * Hooks for other subsystems that check memory allocations. In a typical
 * production configuration these hooks all should produce no code at all.
 */
static inline void kmalloc_large_node_hook(void *ptr, size_t size, gfp_t flags)
{
	kmemleak_alloc(ptr, size, 1, flags);
}

static inline void kfree_hook(const void *x)
{
	kmemleak_free(x);
}

// ARM10C 20140614
// s: &boot_kmem_cache_node, gfpflags: GFP_KERNEL: 0xD0
// ARM10C 20140628
// s: &boot_kmem_cache, gfpflags: __GFP_ZERO: 0x8000
// ARM10C 20140705
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000
// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000
static inline int slab_pre_alloc_hook(struct kmem_cache *s, gfp_t flags)
{
	// flags: GFP_KERNEL: 0xD0, gfp_allowed_mask: 0x1ffff2f
	// flags: __GFP_ZERO: 0x8000, gfp_allowed_mask: 0x1ffff2f
	// flags: __GFP_ZERO: 0x8000, gfp_allowed_mask: 0x1ffff2f
	// flags: __GFP_ZERO: 0x8000, gfp_allowed_mask: 0x1ffff2f
	flags &= gfp_allowed_mask;
	// flags: 0x0
	// flags: 0x8000
	// flags: 0x8000
	// flags: 0x8000

	// flags: 0x0
	// flags: 0x8000
	// flags: 0x8000
	// flags: 0x8000
	lockdep_trace_alloc(flags); // null function

	// flags: 0x0, __GFP_WAIT: 0x10u
	// flags: 0x8000, __GFP_WAIT: 0x10u
	// flags: 0x8000, __GFP_WAIT: 0x10u
	// flags: 0x8000, __GFP_WAIT: 0x10u
	might_sleep_if(flags & __GFP_WAIT);

	// s->object_size: boot_kmem_cache_node.object_size: 44,
	// flags: 0x0, s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// should_failslab(44, 0, 0x00002000UL): 0
	// s->object_size: boot_kmem_cache.object_size: 116,
	// flags: 0x8000, s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// should_failslab(116, 0, 0x00002000UL): 0
	// s->object_size: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->object_size: 116,
	// flags: 0x8000, s->flags: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// should_failslab(116, 0, 0x00002000UL): 0
	// s->object_size: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->object_size: 116,
	// flags: 0x8000, s->flags: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// should_failslab(116, 0, 0x00002000UL): 0
	return should_failslab(s->object_size, flags, s->flags);
	// return 0
	// return 0
	// return 0
	// return 0
}

// ARM10C 20140621
// s: &boot_kmem_cache_node, gfpflags: GFP_KERNEL: 0xD0,
// object: UNMOVABLE인 page 의 object의 시작 virtual address + 64
// ARM10C 20140628
// s: &boot_kmem_cache, gfpflags: __GFP_ZERO: 0x8000,
// object: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
// ARM10C 20140712
// s: &boot_kmem_cache_node, gfpflags: __GFP_ZERO: 0x8000,
// object: UNMOVABLE인 page 의 object의 시작 virtual address + 128
// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000,
// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840,
static inline void slab_post_alloc_hook(struct kmem_cache *s,
					gfp_t flags, void *object)
{
	// flags: GFP_KERNEL: 0xD0, gfp_allowed_mask: 0x1ffff2f
	// flags: __GFP_ZERO: 0x8000, gfp_allowed_mask: 0x1ffff2f
	// flags: __GFP_ZERO: 0x8000, gfp_allowed_mask: 0x1ffff2f
	// flags: __GFP_ZERO: 0x8000, gfp_allowed_mask: 0x1ffff2f
	flags &= gfp_allowed_mask;
	// flags: 0
	// flags: 0x8000
	// flags: 0x8000
	// flags: 0x8000

	// s: &boot_kmem_cache_node, flags: 0, object: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// slab_ksize(&boot_kmem_cache_node): 64
	// s: &boot_kmem_cache, flags: 0x8000, object: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// slab_ksize(&boot_kmem_cache): 128
	// s: &boot_kmem_cache_node, flags: 0x8000, object: UNMOVABLE인 page 의 object의 시작 virtual address + 128
	// slab_ksize(&boot_kmem_cache_node): 64
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, flags: __GFP_ZERO: 0x8000,
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840,
	// slab_ksize(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address): 128
	kmemcheck_slab_alloc(s, flags, object, slab_ksize(s)); // null function

	// object: UNMOVABLE인 page 의 object의 시작 virtual address + 64,
	// s->object_size: boot_kmem_cache_node.object_size: 44,
	// s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, flags: 0
	// object: object: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// s->object_size: boot_kmem_cache.object_size: 116,
	// s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, flags: 0
	// object: UNMOVABLE인 page 의 object의 시작 virtual address + 128,
	// s->object_size: boot_kmem_cache_node.object_size: 44,
	// s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, flags: 0
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840,
	// s->object_size: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->object_size: 116,
	// s->flags: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address).flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, flags: 0
	kmemleak_alloc_recursive(object, s->object_size, 1, s->flags, flags); // null function
}

// ARM10C 20141206
// s: kmem_cache#30, x: kmem_cache#30-o11
static inline void slab_free_hook(struct kmem_cache *s, void *x)
{
	// x: kmem_cache#30-o11, s->flags: (kmem_cache#30)->flags
	kmemleak_free_recursive(x, s->flags); // null function

	/*
	 * Trouble is that we may no longer disable interrupts in the fast path
	 * So in order to make the debug calls that expect irqs to be
	 * disabled we need to disable interrupts temporarily.
	 */
#if defined(CONFIG_KMEMCHECK) || defined(CONFIG_LOCKDEP) // CONFIG_KMEMCHECK=n, CONFIG_LOCKDEP=n
	{
		unsigned long flags;

		local_irq_save(flags);
		kmemcheck_slab_free(s, x, s->object_size);
		debug_check_no_locks_freed(x, s->object_size);
		local_irq_restore(flags);
	}
#endif
	// s->flags: (kmem_cache#30)->flags: 0, SLAB_DEBUG_OBJECTS: 0x00000000UL
	if (!(s->flags & SLAB_DEBUG_OBJECTS))
		// x: kmem_cache#30-o11, s->object_size: (kmem_cache#30)->object_size
		debug_check_no_obj_freed(x, s->object_size); // null function
}

/*
 * Tracking of fully allocated slabs for debugging purposes.
 *
 * list_lock must be held.
 */
static void add_full(struct kmem_cache *s,
	struct kmem_cache_node *n, struct page *page)
{
	if (!(s->flags & SLAB_STORE_USER))
		return;

	list_add(&page->lru, &n->full);
}

/*
 * list_lock must be held.
 */
static void remove_full(struct kmem_cache *s, struct page *page)
{
	if (!(s->flags & SLAB_STORE_USER))
		return;

	list_del(&page->lru);
}

/* Tracking of the number of slabs for debugging purposes */
static inline unsigned long slabs_node(struct kmem_cache *s, int node)
{
	struct kmem_cache_node *n = get_node(s, node);

	return atomic_long_read(&n->nr_slabs);
}

static inline unsigned long node_nr_slabs(struct kmem_cache_node *n)
{
	return atomic_long_read(&n->nr_slabs);
}

// ARM10C 20140531
// s: &boot_kmem_cache_node, page: migratetype이 MIGRATE_UNMOVABLE인 page
// page_to_nid(migratetype이 MIGRATE_UNMOVABLE인 page): 0, page->objects: 64
// kmem_cache_node: &boot_kmem_cache_node, node: 0, page->objects: 64
// ARM10C 20140628
// s: &boot_kmem_cache, page: migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache),
// page_to_nid(migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache)): 0, page->objects: 32
static inline void inc_slabs_node(struct kmem_cache *s, int node, int objects)
{
	// s: &boot_kmem_cache_node, node: 0
	// get_node(&boot_kmem_cache_node, 0): (&boot_kmem_cache_node)->node[0]: NULL
	// s: &boot_kmem_cache_node, node: 0
	// get_node(&boot_kmem_cache_node, 0): (&boot_kmem_cache_node)->node[0]:
	// UNMOVABLE인 page 의 object의 시작 virtual address
	// s: &boot_kmem_cache, node: 0
	// get_node(&boot_kmem_cache, 0): (&boot_kmem_cache)->node[0]:
	// UNMOVABLE인 page 의 object의 시작 virtual address + 64
	struct kmem_cache_node *n = get_node(s, node);
	// n: &(&boot_kmem_cache_node)->node[0]: NULL
	// n: &(&boot_kmem_cache_node)->node[0]: UNMOVABLE인 page 의 object의 시작 virtual address
	// n: &(&boot_kmem_cache)->node[0]: UNMOVABLE인 page 의 object의 시작 virtual address + 64

	/*
	 * May be called early in order to allocate a slab for the
	 * kmem_cache_node structure. Solve the chicken-egg
	 * dilemma by deferring the increment of the count during
	 * bootstrap (see early_kmem_cache_node_alloc).
	 */
	// n: &(&boot_kmem_cache_node)->node[0]: NULL
	// n: &(&boot_kmem_cache_node)->node[0]: UNMOVABLE인 page 의 object의 시작 virtual address
	// n: &(&boot_kmem_cache)->node[0]: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	if (likely(n)) {
		// n->nr_slabs: 0
		// n->nr_slabs: 0
		atomic_long_inc(&n->nr_slabs);
		// n->nr_slabs: 1
		// n->nr_slabs: 1

		// objects: 64, n->total_objects: 0
		// objects: 32, n->total_objects: 0
		atomic_long_add(objects, &n->total_objects);
		// n->total_objects: 64
		// n->total_objects: 32
	}
	// kmem_cache_node 가 완성된 이후에 nr_slabs, total_objects 가 증가될 것으로 예상됨
	// kmem_cache_node 가 완성된 이후에 nr_slabs, total_objects 를 증가시킴
	// kmem_cache_node 가 완성된 이후에 nr_slabs, total_objects 를 증가시킴
}
static inline void dec_slabs_node(struct kmem_cache *s, int node, int objects)
{
	struct kmem_cache_node *n = get_node(s, node);

	atomic_long_dec(&n->nr_slabs);
	atomic_long_sub(objects, &n->total_objects);
}

/* Object debug checks for alloc/free paths */
// ARM10C 20140531
// s: &boot_kmem_cache_node, page: UNMOVABLE인 page
// object: UNMOVABLE인 page 의 virtual address
// ARM10C 20140628
// s: &boot_kmem_cache, page: UNMOVABLE인 page(boot_kmem_cache)
// object: UNMOVABLE인 page 의 virtual address(boot_kmem_cache)
static void setup_object_debug(struct kmem_cache *s, struct page *page,
								void *object)
{
	// s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_STORE_USER: 0x00010000UL, SLAB_RED_ZONE: 0x00000400UL, __OBJECT_POISON: 0x80000000UL
	// 0x00010000 |  0x00000400 | 0x80000000: 0x80010400
	// s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_STORE_USER: 0x00010000UL, SLAB_RED_ZONE: 0x00000400UL, __OBJECT_POISON: 0x80000000UL
	// 0x00010000 |  0x00000400 | 0x80000000: 0x80010400
	if (!(s->flags & (SLAB_STORE_USER|SLAB_RED_ZONE|__OBJECT_POISON)))
		return;
		// return 수행
		// return 수행

	init_object(s, object, SLUB_RED_INACTIVE);
	init_tracking(s, object);
}

static noinline int alloc_debug_processing(struct kmem_cache *s,
					struct page *page,
					void *object, unsigned long addr)
{
	if (!check_slab(s, page))
		goto bad;

	if (!check_valid_pointer(s, page, object)) {
		object_err(s, page, object, "Freelist Pointer check fails");
		goto bad;
	}

	if (!check_object(s, page, object, SLUB_RED_INACTIVE))
		goto bad;

	/* Success perform special debug activities for allocs */
	if (s->flags & SLAB_STORE_USER)
		set_track(s, object, TRACK_ALLOC, addr);
	trace(s, page, object, 1);
	init_object(s, object, SLUB_RED_ACTIVE);
	return 1;

bad:
	if (PageSlab(page)) {
		/*
		 * If this is a slab page then lets do the best we can
		 * to avoid issues in the future. Marking all objects
		 * as used avoids touching the remaining objects.
		 */
		slab_fix(s, "Marking all objects used");
		page->inuse = page->objects;
		page->freelist = NULL;
	}
	return 0;
}

static noinline struct kmem_cache_node *free_debug_processing(
	struct kmem_cache *s, struct page *page, void *object,
	unsigned long addr, unsigned long *flags)
{
	struct kmem_cache_node *n = get_node(s, page_to_nid(page));

	spin_lock_irqsave(&n->list_lock, *flags);
	slab_lock(page);

	if (!check_slab(s, page))
		goto fail;

	if (!check_valid_pointer(s, page, object)) {
		slab_err(s, page, "Invalid object pointer 0x%p", object);
		goto fail;
	}

	if (on_freelist(s, page, object)) {
		object_err(s, page, object, "Object already free");
		goto fail;
	}

	if (!check_object(s, page, object, SLUB_RED_ACTIVE))
		goto out;

	if (unlikely(s != page->slab_cache)) {
		if (!PageSlab(page)) {
			slab_err(s, page, "Attempt to free object(0x%p) "
				"outside of slab", object);
		} else if (!page->slab_cache) {
			printk(KERN_ERR
				"SLUB <none>: no slab for object 0x%p.\n",
						object);
			dump_stack();
		} else
			object_err(s, page, object,
					"page slab pointer corrupt.");
		goto fail;
	}

	if (s->flags & SLAB_STORE_USER)
		set_track(s, object, TRACK_FREE, addr);
	trace(s, page, object, 0);
	init_object(s, object, SLUB_RED_INACTIVE);
out:
	slab_unlock(page);
	/*
	 * Keep node_lock to preserve integrity
	 * until the object is actually freed
	 */
	return n;

fail:
	slab_unlock(page);
	spin_unlock_irqrestore(&n->list_lock, *flags);
	slab_fix(s, "Object at 0x%p not freed", object);
	return NULL;
}

static int __init setup_slub_debug(char *str)
{
	slub_debug = DEBUG_DEFAULT_FLAGS;
	if (*str++ != '=' || !*str)
		/*
		 * No options specified. Switch on full debugging.
		 */
		goto out;

	if (*str == ',')
		/*
		 * No options but restriction on slabs. This means full
		 * debugging for slabs matching a pattern.
		 */
		goto check_slabs;

	if (tolower(*str) == 'o') {
		/*
		 * Avoid enabling debugging on caches if its minimum order
		 * would increase as a result.
		 */
		disable_higher_order_debug = 1;
		goto out;
	}

	slub_debug = 0;
	if (*str == '-')
		/*
		 * Switch off all debugging measures.
		 */
		goto out;

	/*
	 * Determine which debug features should be switched on
	 */
	for (; *str && *str != ','; str++) {
		switch (tolower(*str)) {
		case 'f':
			slub_debug |= SLAB_DEBUG_FREE;
			break;
		case 'z':
			slub_debug |= SLAB_RED_ZONE;
			break;
		case 'p':
			slub_debug |= SLAB_POISON;
			break;
		case 'u':
			slub_debug |= SLAB_STORE_USER;
			break;
		case 't':
			slub_debug |= SLAB_TRACE;
			break;
		case 'a':
			slub_debug |= SLAB_FAILSLAB;
			break;
		default:
			printk(KERN_ERR "slub_debug option '%c' "
				"unknown. skipped\n", *str);
		}
	}

check_slabs:
	if (*str == ',')
		slub_debug_slabs = str + 1;
out:
	return 1;
}

__setup("slub_debug", setup_slub_debug);


// ARM10C 20140419
// s->size: boot_kmem_cache_node.size: 44, flags: SLAB_HWCACHE_ALIGN: 0x00002000UL,
// s->name: boot_kmem_cache_node.name: "kmem_cache_node, s->ctor: boot_kmem_cache_node.ctor: NULL
// ARM10C 20140614
// s->size: boot_kmem_cache.size: 116, flags: SLAB_HWCACHE_ALIGN: 0x00002000UL,
// s->name: boot_kmem_cache.name: "kmem_cache", s->ctor: boot_kmem_cache.ctor: NULL
// ARM10C 20140726
// s->size: kmem_cache#30.size: 64, flags: 0,
// s->name: kmem_cache#30.name: NULL, s->ctor: kmem_cache#30.ctor: NULL
// ARM10C 20140920
// size: 1080, flags: SLAB_PANIC: 0x00040000UL, name: "idr_layer_cache"
static unsigned long kmem_cache_flags(unsigned long object_size,
	unsigned long flags, const char *name,
	void (*ctor)(void *))
{
	/*
	 * Enable debugging if selected on the kernel commandline.
	 */
	// slub_debug: 0, slub_debug_slabs: NULL
	if (slub_debug && (!slub_debug_slabs || (name &&
		!strncmp(slub_debug_slabs, name, strlen(slub_debug_slabs)))))
		flags |= slub_debug;

	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	return flags;
	// return SLAB_HWCACHE_ALIGN: 0x00002000UL
}
#else
static inline void setup_object_debug(struct kmem_cache *s,
			struct page *page, void *object) {}

static inline int alloc_debug_processing(struct kmem_cache *s,
	struct page *page, void *object, unsigned long addr) { return 0; }

static inline struct kmem_cache_node *free_debug_processing(
	struct kmem_cache *s, struct page *page, void *object,
	unsigned long addr, unsigned long *flags) { return NULL; }

static inline int slab_pad_check(struct kmem_cache *s, struct page *page)
			{ return 1; }
static inline int check_object(struct kmem_cache *s, struct page *page,
			void *object, u8 val) { return 1; }
static inline void add_full(struct kmem_cache *s, struct kmem_cache_node *n,
					struct page *page) {}
static inline void remove_full(struct kmem_cache *s, struct page *page) {}
static inline unsigned long kmem_cache_flags(unsigned long object_size,
	unsigned long flags, const char *name,
	void (*ctor)(void *))
{
	return flags;
}
#define slub_debug 0

#define disable_higher_order_debug 0

static inline unsigned long slabs_node(struct kmem_cache *s, int node)
							{ return 0; }
static inline unsigned long node_nr_slabs(struct kmem_cache_node *n)
							{ return 0; }
static inline void inc_slabs_node(struct kmem_cache *s, int node,
							int objects) {}
static inline void dec_slabs_node(struct kmem_cache *s, int node,
							int objects) {}

static inline void kmalloc_large_node_hook(void *ptr, size_t size, gfp_t flags)
{
	kmemleak_alloc(ptr, size, 1, flags);
}

static inline void kfree_hook(const void *x)
{
	kmemleak_free(x);
}

static inline int slab_pre_alloc_hook(struct kmem_cache *s, gfp_t flags)
							{ return 0; }

static inline void slab_post_alloc_hook(struct kmem_cache *s, gfp_t flags,
		void *object)
{
	kmemleak_alloc_recursive(object, s->object_size, 1, s->flags,
		flags & gfp_allowed_mask);
}

static inline void slab_free_hook(struct kmem_cache *s, void *x)
{
	kmemleak_free_recursive(x, s->flags);
}

#endif /* CONFIG_SLUB_DEBUG */

/*
 * Slab allocation and freeing
 */
// ARM10C 20140426
// alloc_gfp: 0x1200, node: 0, oo: boot_kmem_cache_node.oo
// ARM10C 20140628
// alloc_gfp: 0x1200, node: -1, oo: boot_kmem_cache.oo
static inline struct page *alloc_slab_page(gfp_t flags, int node,
					struct kmem_cache_order_objects oo)
{
	// oo: boot_kmem_cache_node.oo
	// oo: boot_kmem_cache.oo
	int order = oo_order(oo);
	// order: 0
	// order: 0

	// flags: 0x1200, __GFP_NOTRACK: 0x200000u
	// flags: 0x1200, __GFP_NOTRACK: 0x200000u
	flags |= __GFP_NOTRACK;
	// flags: 0x201200
	// flags: 0x201200

	// node: 0, NUMA_NO_NODE: -1
	// node: -1, NUMA_NO_NODE: -1
	if (node == NUMA_NO_NODE)
		// flags: 0x201200, order: 0
		return alloc_pages(flags, order);
		// return migratetype이 MIGRATE_UNMOVABLE인 page
	else
		// node: 0, flags: 0x201200, order: 0
		return alloc_pages_exact_node(node, flags, order);
		// page: migratetype이 MIGRATE_UNMOVABLE인 page
}

// ARM10C 20140426
// s: &boot_kmem_cache_node, flags: GFP_NOWAIT: 0, node: 0
// ARM10C 20140628
// s: &boot_kmem_cache, flags: GFP_NOWAIT: 0, node: -1
static struct page *allocate_slab(struct kmem_cache *s, gfp_t flags, int node)
{
	struct page *page;
	// s->oo: boot_kmem_cache_node.oo
	// s->oo: boot_kmem_cache.oo
	struct kmem_cache_order_objects oo = s->oo;
	// oo: boot_kmem_cache_node.oo
	// oo: boot_kmem_cache.oo
	gfp_t alloc_gfp;

	// flags: GFP_NOWAIT: 0, gfp_allowed_mask: 0x1ffff2f
	// flags: GFP_NOWAIT: 0, gfp_allowed_mask: 0x1ffff2f
	flags &= gfp_allowed_mask;
	// flags: GFP_NOWAIT: 0
	// flags: GFP_NOWAIT: 0

	// flags: GFP_NOWAIT: 0, __GFP_WAIT: 0x10u
	// flags: GFP_NOWAIT: 0, __GFP_WAIT: 0x10u
	if (flags & __GFP_WAIT)
		local_irq_enable();

	// s->allocflags: boot_kmem_cache_node.allocflags: 0
	// s->allocflags: boot_kmem_cache.allocflags: 0
	flags |= s->allocflags;
	// flags: GFP_NOWAIT: 0
	// flags: GFP_NOWAIT: 0

	/*
	 * Let the initial higher-order allocation fail under memory pressure
	 * so we fall-back to the minimum order allocation.
	 */
	// flags: GFP_NOWAIT: 0, __GFP_NOWARN: 0x200u, __GFP_NORETRY: 0x1000u
	// __GFP_NOFAIL: 0x800u
	// flags: GFP_NOWAIT: 0, __GFP_NOWARN: 0x200u, __GFP_NORETRY: 0x1000u
	// __GFP_NOFAIL: 0x800u
	alloc_gfp = (flags | __GFP_NOWARN | __GFP_NORETRY) & ~__GFP_NOFAIL;
	// alloc_gfp: 0x1200
	// alloc_gfp: 0x1200

	// alloc_gfp: 0x1200, node: 0, oo: boot_kmem_cache_node.oo
	// alloc_gfp: 0x1200, node: -1, oo: boot_kmem_cache.oo
	page = alloc_slab_page(alloc_gfp, node, oo);
	// page: migratetype이 MIGRATE_UNMOVABLE인 page
	// page: migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache)

	if (unlikely(!page)) {
		oo = s->min;
		/*
		 * Allocation may have failed due to fragmentation.
		 * Try a lower order alloc if possible
		 */
		page = alloc_slab_page(flags, node, oo);

		if (page)
			stat(s, ORDER_FALLBACK);
	}

	// kmemcheck_enabled: 0, page: migratetype이 MIGRATE_UNMOVABLE인 page
	// s->flags: (&boot_kmem_cache_node)->flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_NOTRACK: 0x00000000UL, DEBUG_DEFAULT_FLAGS: 0x10d00
	// kmemcheck_enabled: 0, page: migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	// s->flags: (&boot_kmem_cache)->flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_NOTRACK: 0x00000000UL, DEBUG_DEFAULT_FLAGS: 0x10d00
	if (kmemcheck_enabled && page
		&& !(s->flags & (SLAB_NOTRACK | DEBUG_DEFAULT_FLAGS))) {
		int pages = 1 << oo_order(oo);

		kmemcheck_alloc_shadow(page, oo_order(oo), flags, node);

		/*
		 * Objects from caches that have a constructor don't get
		 * cleared when they're allocated, so we need to do it here.
		 */
		if (s->ctor)
			kmemcheck_mark_uninitialized_pages(page, pages);
		else
			kmemcheck_mark_unallocated_pages(page, pages);
	}

	// flags: GFP_NOWAIT: 0, __GFP_WAIT: 0x10u
	// flags: GFP_NOWAIT: 0, __GFP_WAIT: 0x10u
	if (flags & __GFP_WAIT)
		local_irq_disable();

	// page: migratetype이 MIGRATE_UNMOVABLE인 page
	// page: migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	if (!page)
		return NULL;

	// oo: boot_kmem_cache_node.oo, oo_objects(boot_kmem_cache_node.oo): 64
	// oo: boot_kmem_cache.oo, oo_objects(boot_kmem_cache.oo): 32
	page->objects = oo_objects(oo);
	// page->objects: 64, page->_mapcount: 0x00400000
	// page->objects: 32, page->_mapcount: 0x00200000

	// page: migratetype이 MIGRATE_UNMOVABLE인 page
	// page_zone(migratetype이 MIGRATE_UNMOVABLE인 page):
	// &(&contig_page_data)->node_zones[ZONE_NORMAL]
	// s->flags: (&boot_kmem_cache_node)->flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_RECLAIM_ACCOUNT: 0x00020000UL, NR_SLAB_RECLAIMABLE: 13, NR_SLAB_UNRECLAIMABLE: 14
	// oo: boot_kmem_cache_node.oo, oo_order(boot_kmem_cache_node.oo): 0
	//
	// &(&contig_page_data)->node_zones[ZONE_NORMAL], NR_SLAB_UNRECLAIMABLE: 14, 1
	//
	// page: migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	// page_zone(migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache)):
	// &(&contig_page_data)->node_zones[ZONE_NORMAL]
	// s->flags: (&boot_kmem_cache)->flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_RECLAIM_ACCOUNT: 0x00020000UL, NR_SLAB_RECLAIMABLE: 13, NR_SLAB_UNRECLAIMABLE: 14
	// oo: boot_kmem_cache.oo, oo_order(boot_kmem_cache.oo): 0
	//
	// &(&contig_page_data)->node_zones[ZONE_NORMAL], NR_SLAB_UNRECLAIMABLE: 14, 1
	mod_zone_page_state(page_zone(page),
		(s->flags & SLAB_RECLAIM_ACCOUNT) ?
		NR_SLAB_RECLAIMABLE : NR_SLAB_UNRECLAIMABLE,
		1 << oo_order(oo));
	// zone->vm_stat[14]: (&contig_page_data)->node_zones[ZONE_NORMAL].vm_stat[14]: 1
	// NR_SLAB_UNRECLAIMABLE: 14, vm_stat[14]: 1
	// zone->vm_stat[14]: (&contig_page_data)->node_zones[ZONE_NORMAL].vm_stat[14]: 2
	// NR_SLAB_UNRECLAIMABLE: 14, vm_stat[14]: 2

	// page: migratetype이 MIGRATE_UNMOVABLE인 page
	// page: migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	return page;
}

// ARM10C 20140531
// s: &boot_kmem_cache_node, page: UNMOVABLE인 page
// last: UNMOVABLE인 page 의 virtual address
// ARM10C 20140628
// s: &boot_kmem_cache, page: UNMOVABLE인 page(boot_kmem_cache),
// last: UNMOVABLE인 page 의 virtual address(boot_kmem_cache)
static void setup_object(struct kmem_cache *s, struct page *page,
				void *object)
{
	// s: &boot_kmem_cache_node, page: UNMOVABLE인 page
	// object: UNMOVABLE인 page 의 virtual address
	// s: &boot_kmem_cache, page: UNMOVABLE인 page(boot_kmem_cache)
	// object: UNMOVABLE인 page 의 virtual address(boot_kmem_cache)
	setup_object_debug(s, page, object);

	// s->ctor: boot_kmem_cache_node.ctor: NULL
	// s->ctor: boot_kmem_cache.ctor: NULL
	if (unlikely(s->ctor))
		s->ctor(object);
}

// ARM10C 20140426
// kmem_cache_node: &boot_kmem_cache_node, GFP_NOWAIT: 0, node: 0
// ARM10C 20140628
// s: &boot_kmem_cache, flags: __GFP_ZERO: 0x8000, node: -1
static struct page *new_slab(struct kmem_cache *s, gfp_t flags, int node)
{
	struct page *page;
	void *start;
	void *last;
	void *p;
	int order;

	// flags: GFP_NOWAIT: 0, GFP_SLAB_BUG_MASK: 0xfe000005
	// flags: __GFP_ZERO: 0x8000, GFP_SLAB_BUG_MASK: 0xfe000005
	BUG_ON(flags & GFP_SLAB_BUG_MASK);

	// s: &boot_kmem_cache_node, flags: GFP_NOWAIT: 0, node: 0
	// GFP_RECLAIM_MASK: 0x13ef0, GFP_CONSTRAINT_MASK: 0x60000
	// s: &boot_kmem_cache, flags: __GFP_ZERO: 0x8000, node: -1
	// GFP_RECLAIM_MASK: 0x13ef0, GFP_CONSTRAINT_MASK: 0x60000
	page = allocate_slab(s,
		flags & (GFP_RECLAIM_MASK | GFP_CONSTRAINT_MASK), node);
	// page: migratetype이 MIGRATE_UNMOVABLE인 page
	// page: migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache)

	if (!page)
		goto out;

	// page: migratetype이 MIGRATE_UNMOVABLE인 page
	// compound_order(page): 0
	// page: migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	// compound_order(page): 0
	order = compound_order(page);
	// free_pages_check에서 page->flags의 NR_PAGEFLAGS 만큼의 하위 비트를 전부 지워줌
	// order: 0
	// order: 0

// 2014/05/24 종료
// 2014/05/31 시작

	// s: &boot_kmem_cache_node, page: migratetype이 MIGRATE_UNMOVABLE인 page,
	// page_to_nid(migratetype이 MIGRATE_UNMOVABLE인 page): 0, page->objects: 64
	// s: &boot_kmem_cache, page: migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache),
	// page_to_nid(migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache)): 0, page->objects: 32
	inc_slabs_node(s, page_to_nid(page), page->objects);

	// inc_slabs_node(&boot_kmem_cache)에서 한일:
	// 이전에 할당 받은 MIGRATE_UNMOVABLE인 page의 두번째 object의 맴버 필드값을 변경
	// n->nr_slabs: 1
	// n->total_objects: 32

	// s: &boot_kmem_cache_node, order: 0
	// s: &boot_kmem_cache, order: 0
	memcg_bind_pages(s, order); // null function

	// page: migratetype이 MIGRATE_UNMOVABLE인 page, s: &boot_kmem_cache_node
	// page: migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache), s: &boot_kmem_cache
	page->slab_cache = s;
	// page->slab_cache: &boot_kmem_cache_node
	// page->slab_cache: &boot_kmem_cache

	// page: migratetype이 MIGRATE_UNMOVABLE인 page
	// page: migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	__SetPageSlab(page);
	// page->flags에 7 (PG_slab) bit를 set
	// page->flags에 7 (PG_slab) bit를 set

	// page->pfmemalloc: 0
	// page->pfmemalloc: 0
	if (page->pfmemalloc)
		SetPageSlabPfmemalloc(page);

	// page: migratetype이 MIGRATE_UNMOVABLE인 page
	//       이 코드 이후 부터는 UNMOVABLE인 page
	// page_address(UNMOVABLE인 page): UNMOVABLE인 page 의 virtual address
	// page: migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	//       이 코드 이후 부터는 UNMOVABLE인 page (boot_kmem_cache)
	// page_address(UNMOVABLE인 page (boot_kmem_cache)): UNMOVABLE인 page (boot_kmem_cache)의 virtual address
	start = page_address(page);
	// start: UNMOVABLE인 page 의 virtual address
	// start: UNMOVABLE인 page (boot_kmem_cache)의 virtual address

	// s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_POISON: 0x00000800UL
	// s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_POISON: 0x00000800UL
	if (unlikely(s->flags & SLAB_POISON))
		memset(start, POISON_INUSE, PAGE_SIZE << order);

	// start: UNMOVABLE인 page 의 virtual address
	// start: UNMOVABLE인 page (boot_kmem_cache)의 virtual address
	last = start;
	// last: UNMOVABLE인 page 의 virtual address
	// last: UNMOVABLE인 page (boot_kmem_cache)의 virtual address

	// s: &boot_kmem_cache_node,
	// start: UNMOVABLE인 page 의 virtual address
	// page->objects: 64
	// s: &boot_kmem_cache,
	// start: UNMOVABLE인 page (boot_kmem_cache)의 virtual address
	// page->objects: 32
	for_each_object(p, s, start, page->objects) {
	// for (p = (UNMOVABLE인 page 의 virtual address);
	//      p < (UNMOVABLE인 page 의 virtual address) + (64) * (&boot_kmem_cache_node)->size;
	//	p += (&boot_kmem_cache_node)->size)

	// for (p = (UNMOVABLE인 page (boot_kmem_cache)의 virtual address);
	//      p < (UNMOVABLE인 page (boot_kmem_cache)의 virtual address) + (32) * (&boot_kmem_cache)->size;
	//	p += (&boot_kmem_cache)->size)

		// [1] [loop 1] p: UNMOVABLE인 page 의 virtual address
		// [1] [loop 1] (&boot_kmem_cache_node)->size: 64
		// [1] [loop 2] p: UNMOVABLE인 page 의 virtual address + 64
		// [1] [loop 2] (&boot_kmem_cache_node)->size: 64

		// [2] [loop 1] p: UNMOVABLE인 page (boot_kmem_cache)의 virtual address
		// [2] [loop 1] (&boot_kmem_cache)->size: 128
		// [2] [loop 2] p: UNMOVABLE인 page (boot_kmem_cache)의 virtual address + 128
		// [2] [loop 2] (&boot_kmem_cache)->size: 128

		// [1] [loop 1] s: &boot_kmem_cache_node, page: UNMOVABLE인 page,
		// [1] [loop 1] last: UNMOVABLE인 page 의 virtual address
		// [1] [loop 2] s: &boot_kmem_cache_node, page: UNMOVABLE인 page,
		// [1] [loop 2] last: UNMOVABLE인 page 의 virtual address
		// [2] [loop 1] s: &boot_kmem_cache, page: UNMOVABLE인 page(boot_kmem_cache),
		// [2] [loop 1] last: UNMOVABLE인 page (boot_kmem_cache)의 virtual address
		// [2] [loop 2] s: &boot_kmem_cache, page: UNMOVABLE인 page(boot_kmem_cache),
		// [2] [loop 2] last: UNMOVABLE인 page (boot_kmem_cache) 의 virtual address
		setup_object(s, page, last);

		// [1] [loop 1] s: &boot_kmem_cache_node, last: UNMOVABLE인 page 의 virtual address,
		// [1] [loop 1] p: UNMOVABLE인 page 의 virtual address
		// [1] [loop 2] s: &boot_kmem_cache_node, last: UNMOVABLE인 page 의 virtual address,
		// [1] [loop 2] p: UNMOVABLE인 page 의 virtual address + 64
		// [2] [loop 1] s: &boot_kmem_cache, last: UNMOVABLE인 page (boot_kmem_cache)의 virtual address,
		// [2] [loop 1] p: UNMOVABLE인 page 의 virtual address(boot_kmem_cache)
		// [2] [loop 2] s: &boot_kmem_cache, last: UNMOVABLE인 page (boot_kmem_cache)의 virtual address,
		// [2] [loop 2] p: UNMOVABLE인 page (boot_kmem_cache)의 virtual address + 128
		set_freepointer(s, last, p);
		// [1] [loop 1] last에 p 주소를 mapping 함
		// [1] [loop 2] last에 p 주소를 mapping 함
		// [2] [loop 1] last에 p 주소를 mapping 함
		// [2] [loop 2] last에 p 주소를 mapping 함

		// [1] [loop 1] p: UNMOVABLE인 page 의 virtual address
		// [1] [loop 2] p: UNMOVABLE인 page 의 virtual address + 64
		// [2] [loop 1] p: UNMOVABLE인 page (boot_kmem_cache)의 virtual address
		// [2] [loop 2] p: UNMOVABLE인 page (boot_kmem_cache)의 virtual address + 128
		last = p;
		// [1] [loop 1] last: UNMOVABLE인 page 의 virtual addres
		// [1] [loop 2] last: UNMOVABLE인 page 의 virtual addres + 64
		// [2] [loop 1] last: UNMOVABLE인 page (boot_kmem_cache)의 virtual addres
		// [2] [loop 2] last: UNMOVABLE인 page (boot_kmem_cache)의 virtual addres + 128

		// [1] [loop 3..64] 수행
		// [2] [loop 3..32] 수행
	}

	// for_each_object가 하는일:
	// 다음 object의 시작주소를 현재 object의 내부(freepointer) 에 저장을 하는데
	// 그 위치는 s->offset에 의해 결정되어 저장됨
	//
	// 예시:
	// s->offset이 0이고 slab object 시작 주소가 0x10001000 일 경우
	// -------------------------------------------------------------------------------------------------------------------------------------
	// | Slab object 0          | Slab object 1          | Slab object 2          | Slab object 3          | .... | Slab object 63         |
	// -------------------------------------------------------------------------------------------------------------------------------------
	// | object start address:  | object start address:  | object start address:  | object start address:  |      | object start address:  |
	// | 0x10001000             | 0x10001040             | 0x10001080             | 0x100010C0             | .... | 0x10001fc0             |
	// -------------------------------------------------------------------------------------------------------------------------------------
	// | freepointer | data     | freepointer | data     | freepointer | data     | freepointer | data     | .... | freepointer | data     |
	// -------------------------------------------------------------------------------------------------------------------------------------
	// | 0x10001040  | 60 Bytes | 0x10001080  | 60 Bytes | 0x100010C0  | 60 Bytes | 0x10001100  | 60 Bytes | .... | null        | 60 Bytes |
	// -------------------------------------------------------------------------------------------------------------------------------------

	// s: &boot_kmem_cache_node, page: UNMOVABLE인 page
	// last: UNMOVABLE인 page 의 virtual address + 0x1000 - 64
	// s: &boot_kmem_cache, page: UNMOVABLE인 page (boot_kmem_cache)
	// last: UNMOVABLE인 page (boot_kmem_cache)의 virtual address + 0x1000 - 128
	setup_object(s, page, last);

	// s: &boot_kmem_cache_node
	// last: UNMOVABLE인 page 의 virtual address + 0x1000 - 64
	// s: &boot_kmem_cache
	// last: UNMOVABLE인 page (boot_kmem_cache)의 virtual address + 0x1000 - 128
	set_freepointer(s, last, NULL);

	// 마지막 object의 내부 freepointer는 null 초기화함

	// start: UNMOVABLE인 page 의 virtual address
	// start: UNMOVABLE인 page (boot_kmem_cache)의 virtual address
	page->freelist = start;
	// page->freelist: UNMOVABLE인 page 의 virtual address
	// page->freelist: UNMOVABLE인 page (boot_kmem_cache)의 virtual address

	// page의 freelist 맴버는 slab의 object의 시작주소를 가리킴

	// page->objects: 64
	// page->objects: 32
	page->inuse = page->objects;
	// page->inuse: 64
	// page->inuse: 32

	// page의 objects 맴버는 slab의 object의 총 갯수
	// page의 inuse 맴버는 slab의 free상태인 object의 총 갯수

	page->frozen = 1;
	// page->frozen: 1
	// page->frozen: 1
out:
	// page: UNMOVABLE인 page
	// page: UNMOVABLE인 page (boot_kmem_cache)
	return page;
}

static void __free_slab(struct kmem_cache *s, struct page *page)
{
	int order = compound_order(page);
	int pages = 1 << order;

	if (kmem_cache_debug(s)) {
		void *p;

		slab_pad_check(s, page);
		for_each_object(p, s, page_address(page),
						page->objects)
			check_object(s, page, p, SLUB_RED_INACTIVE);
	}

	kmemcheck_free_shadow(page, compound_order(page));

	mod_zone_page_state(page_zone(page),
		(s->flags & SLAB_RECLAIM_ACCOUNT) ?
		NR_SLAB_RECLAIMABLE : NR_SLAB_UNRECLAIMABLE,
		-pages);

	__ClearPageSlabPfmemalloc(page);
	__ClearPageSlab(page);

	memcg_release_pages(s, order);
	page_mapcount_reset(page);
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += pages;
	__free_memcg_kmem_pages(page, order);
}

// ARM10C 20140419
// sizeof(((struct page *)NULL)->lru): 8, sizeof(struct rcu_head): 8
// need_reserve_slab_rcu: 0
#define need_reserve_slab_rcu						\
	(sizeof(((struct page *)NULL)->lru) < sizeof(struct rcu_head))

static void rcu_free_slab(struct rcu_head *h)
{
	struct page *page;

	if (need_reserve_slab_rcu)
		page = virt_to_head_page(h);
	else
		page = container_of((struct list_head *)h, struct page, lru);

	__free_slab(page->slab_cache, page);
}

static void free_slab(struct kmem_cache *s, struct page *page)
{
	if (unlikely(s->flags & SLAB_DESTROY_BY_RCU)) {
		struct rcu_head *head;

		if (need_reserve_slab_rcu) {
			int order = compound_order(page);
			int offset = (PAGE_SIZE << order) - s->reserved;

			VM_BUG_ON(s->reserved != sizeof(*head));
			head = page_address(page) + offset;
		} else {
			/*
			 * RCU free overloads the RCU head over the LRU
			 */
			head = (void *)&page->lru;
		}

		call_rcu(head, rcu_free_slab);
	} else
		__free_slab(s, page);
}

static void discard_slab(struct kmem_cache *s, struct page *page)
{
	dec_slabs_node(s, page_to_nid(page), page->objects);
	free_slab(s, page);
}

/*
 * Management of partially allocated slabs.
 *
 * list_lock must be held.
 */
// ARM10C 20140531
// n: UNMOVABLE인 page 의 object의 시작 virtual address,
// page: UNMOVABLE인 page, DEACTIVATE_TO_HEAD: 15
// ARM10C 20140705
// n: (&boot_kmem_cache 용 object 주소)->node[0]:
// boot_kmem_cache_node 로 할당 받은 2 번째 object의 주소,
// page: UNMOVABLE인 page (boot_kmem_cache),
// tail: DEACTIVATE_TO_HEAD: 15
// ARM10C 20140712
// n: (&boot_kmem_cache_node 용 object 주소)->node[0]:
// boot_kmem_cache_node 로 할당 받은 1 번째 object의 주소,
// page: UNMOVABLE인 page,
// tail: DEACTIVATE_TO_HEAD: 15
static inline void add_partial(struct kmem_cache_node *n,
				struct page *page, int tail)
{
	// n: UNMOVABLE인 page 의 object의 시작 virtual address,
	// n: UNMOVABLE인 page 의 object의 시작 virtual address + 64,
	// n: UNMOVABLE인 page 의 object의 시작 virtual address,

	// n->nr_partial: 0
	// n->nr_partial: 0
	// n->nr_partial: 0
	n->nr_partial++;
	// n->nr_partial: 1
	// n->nr_partial: 1
	// n->nr_partial: 1

	// tail: DEACTIVATE_TO_HEAD: 15, DEACTIVATE_TO_TAIL: 16
	// tail: DEACTIVATE_TO_HEAD: 15, DEACTIVATE_TO_TAIL: 16
	// tail: DEACTIVATE_TO_HEAD: 15, DEACTIVATE_TO_TAIL: 16
	if (tail == DEACTIVATE_TO_TAIL)
		list_add_tail(&page->lru, &n->partial);
	else
		// page->lru: (UNMOVABLE인 page)->lru, n->partial: NULL
		// page->lru: (UNMOVABLE인 page (boot_kmem_cache))->lru, n->partial: NULL
		// page->lru: (UNMOVABLE인 page)->lru, n->partial: NULL
		list_add(&page->lru, &n->partial);
		// n->partial에 (UNMOVABLE인 page)->lru 가 추가됨
		// n->partial에 (UNMOVABLE인 page (boot_kmem_cache))->lru 가 추가됨
		// n->partial에 (UNMOVABLE인 page)->lru 가 추가됨
}

/*
 * list_lock must be held.
 */
// ARM10C 20140621
// n: (&boot_kmem_cache_node)->node[0], page: MIGRATE_UNMOVABLE인 page
// ARM10C 20140719
// n: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->node[0], page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
static inline void remove_partial(struct kmem_cache_node *n,
					struct page *page)
{
	// page->lru: (MIGRATE_UNMOVABLE인 page)->lru
	// page->lru: (MIGRATE_UNMOVABLE인 page (boot_kmem_cache))->lru
	list_del(&page->lru);
	// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
	// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page (boot_kmem_cache))->lru 를 삭제

	// n: UNMOVABLE인 page 의 object의 시작 virtual address
	// n: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address

	// n->nr_partial: 1
	// n->nr_partial: 1
	n->nr_partial--;
	// n->nr_partial: 0
	// n->nr_partial: 0
}

/*
 * Remove slab from the partial list, freeze it and
 * return the pointer to the freelist.
 *
 * Returns a list of objects or NULL if it fails.
 *
 * Must hold list_lock since we modify the partial list.
 */
// ARM10C 20140621
// s: &boot_kmem_cache_node, n: (&boot_kmem_cache_node)->node[0],
// page: MIGRATE_UNMOVABLE인 page, 1, objects
// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// n: (&boot_kmem_cache 용 object 주소)->node[0],
// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache), 1, objects
static inline void *acquire_slab(struct kmem_cache *s,
		struct kmem_cache_node *n, struct page *page,
		int mode, int *objects)
{
	void *freelist;
	unsigned long counters;
	struct page new;

	/*
	 * Zap the freelist and set the frozen bit.
	 * The old freelist is the list of objects for the
	 * per cpu allocation list.
	 */
	// page->freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// page->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	freelist = page->freelist;
	// freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968

	// page->objects: 64, page->inuse: 1, page->frozen: 0 값에 의해
	// page->counters: 0x400001 값으로 해석됨
	// page->objects: 32, page->inuse: 1, page->frozen: 0 값에 의해
	// page->counters: 0x00200001 값으로 해석됨
	counters = page->counters;
	// counters: 0x400001
	// counters: 0x00200001
	new.counters = counters;
	// new.counters: 0x400001
	// new.counters: 0x00200001

	// new.objects: 64, new.inuse: 1
	// new.objects: 32, new.inuse: 1
	*objects = new.objects - new.inuse;
	// *objects: 63
	// *objects: 31

	// mode: 1
	// mode: 1
	if (mode) {
		// new.inuse: 1, page->objects: 64
		// new.inuse: 1, page->objects: 32
		new.inuse = page->objects;
		// new.inuse: 64, new.counters: 0x400040
		// new.inuse: 32, new.counters: 0x200020

		new.freelist = NULL;
		// new.freelist: NULL
		// new.freelist: NULL
	} else {
		new.freelist = freelist;
	}

	// new.frozen: 0
	// new.frozen: 0
	VM_BUG_ON(new.frozen);

	// new.frozen: 0
	// new.frozen: 0
	new.frozen = 1;
	// new.frozen: 1, new.counters: 0x80400040
	// new.frozen: 1, new.counters: 0x80200020
	

	// s: &boot_kmem_cache_node, page: MIGRATE_UNMOVABLE인 page,
	// freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// counters: 0x400001, new.freelist: NULL, new.counters: 0x80400040, "acquire_slab"
	// __cmpxchg_double_slab(&boot_kmem_cache_node, MIGRATE_UNMOVABLE인 page,
	// UNMOVABLE인 page 의 object의 시작 virtual address + 64, 0x400001, NULL, 0x80400040
	// "acquire_slab"): 1
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache),
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// counters: 0x200001, new.freelist: NULL, new.counters: 0x80200020, "acquire_slab"
	// __cmpxchg_double_slab(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, MIGRATE_UNMOVABLE인 page (boot_kmem_cache),
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968, 0x200001, NULL, 0x80200020, "acquire_slab"): 1
	if (!__cmpxchg_double_slab(s, page,
			freelist, counters,
			new.freelist, new.counters,
			"acquire_slab"))
		return NULL;

	// __cmpxchg_double_slab에서 한일:
	// MIGRATE_UNMOVABLE인 page의 멤버 필드 값
	// page->freelist: NULL
	// page->counters: 0x80400040
	// 로 변경함

	// __cmpxchg_double_slab에서 한일:
	// MIGRATE_UNMOVABLE인 page (boot_kmem_cache) 의 멤버 필드 값
	// page->freelist: NULL
	// page->counters: 0x80200020
	// 로 변경함

	// n: (&boot_kmem_cache_node)->node[0], page: MIGRATE_UNMOVABLE인 page
	// n: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->node[0], page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	// n: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->node[0], page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	remove_partial(n, page);
	// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
	// n->nr_partial: 0
	// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page (boot_kmem_cache))->lru 를 삭제
	// n->nr_partial: 0

	// freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	WARN_ON(!freelist);

	// freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	return freelist;
	// return UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// return UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
}

static void put_cpu_partial(struct kmem_cache *s, struct page *page, int drain);
static inline bool pfmemalloc_match(struct page *page, gfp_t gfpflags);

/*
 * Try to allocate a partial slab from a specific node.
 */
// ARM10C 20140614
// s: &boot_kmem_cache_node, (&boot_kmem_cache_node)->node[0],
// c: (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋),
// flags: GFP_KERNEL: 0xD0
// ARM10C 20140628
// s: &boot_kmem_cache, (&boot_kmem_cache)->node[0],
// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋),
// flags: __GFP_ZERO: 0x8000
// ARM10C 20140719
// s: &UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, (&boot_kmem_cache 용 object 주소)->node[0],
// c: (&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋),
// flages: __GFP_ZERO: 0x8000
static void *get_partial_node(struct kmem_cache *s, struct kmem_cache_node *n,
				struct kmem_cache_cpu *c, gfp_t flags)
{
	struct page *page, *page2;
	void *object = NULL;
	int available = 0;
	int objects;

	/*
	 * Racy check. If we mistakenly see no partial slabs then we
	 * just allocate an empty slab. If we mistakenly try to get a
	 * partial slab and there is none available then get_partials()
	 * will return NULL.
	 */
	// n: (&boot_kmem_cache_node)->node[0]: UNMOVABLE인 page 의 object의 시작 virtual address,
	// n->nr_partial: ((&boot_kmem_cache_node)->node[0])->nr_partial: 1
	// n: (&boot_kmem_cache)->node[0]: UNMOVABLE인 page 의 object의 시작 virtual address + 64,
	// n->nr_partial: ((&boot_kmem_cache)->node[0])->nr_partial: 0
	// n: (&boot_kmem_cache 용 object 주소)->node[0]: UNMOVABLE인 page 의 object의 시작 virtual address + 64,
	// n->nr_partial: ((&boot_kmem_cache 용 object 주소)->node[0])->nr_partial: 1
	if (!n || !n->nr_partial)
		return NULL;
		// return NULL

	// early_kmem_cache_node_alloc에서 (&boot_kmem_cache_node)->node[0] 값을 설정함

	// n->list_lock: ((&boot_kmem_cache_node)->node[0])->list_lock
	// n->list_lock: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->node[0])->list_lock
	spin_lock(&n->list_lock);
	// ((&boot_kmem_cache_node)->node[0])->list_lock의 spinlock 획득
	// ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->node[0])->list_lock의 spinlock 획득

// 2014/06/14 종료
// 2014/06/21 시작

	list_for_each_entry_safe(page, page2, &n->partial, lru) {
	// for (page = list_first_entry(&n->partial, typeof(*page), lru),
	//      page2 = list_next_entry(page, lru);
	//      &page->lru != (&n->partial);
	//      page = page2, page2 = list_next_entry(page2, lru))

		// page: MIGRATE_UNMOVABLE인 page, page2: page lru의 offset 만큼 계산된 주소
		// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache), page2: page lru의 offset 만큼 계산된 주소

		void *t;

		// page: MIGRATE_UNMOVABLE인 page, flags: GFP_KERNEL: 0xD0
		// pfmemalloc_match(MIGRATE_UNMOVABLE인 page, GFP_KERNEL: 0xD0): 1
		// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache), flags: __GFP_ZERO: 0x8000
		// pfmemalloc_match(MIGRATE_UNMOVABLE인 page (boot_kmem_cache), __GFP_ZERO: 0x8000): 1
		if (!pfmemalloc_match(page, flags))
			continue;

		// s: &boot_kmem_cache_node, n: (&boot_kmem_cache_node)->node[0],
		// page: MIGRATE_UNMOVABLE인 page, object: NULL
		// acquire_slab(&boot_kmem_cache_node, (&boot_kmem_cache_node)->node[0], MIGRATE_UNMOVABLE인 page, 1, objects):
		// UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
		// n: (&boot_kmem_cache 용 object 주소)->node[0],
		// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache), object: NULL
		// acquire_slab(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
		// (&boot_kmem_cache 용 object 주소)->node[0], MIGRATE_UNMOVABLE인 page (boot_kmem_cache), 1, objects):
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
		t = acquire_slab(s, n, page, object == NULL, &objects);
		// t: UNMOVABLE인 page 의 object의 시작 virtual address + 64, objects: 63
		// t: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968, objects: 31

		// acquire_slab 이 한일?:
		// 다음 object의 주소를 받아옴
		// UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// MIGRATE_UNMOVABLE인 page의 멤버 필드 값 변경
		// page->freelist: NULL
		// page->counters: 0x80400040
		// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
		// n->nr_partial: 0

		// acquire_slab 이 한일?:
		// 다음 object의 주소를 받아옴
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
		// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)의 멤버 필드 값 변경
		// page->freelist: NULL
		// page->counters: 0x80200020
		// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
		// n->nr_partial: 0

		// t: UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// t: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
		if (!t)
			break;

		// available: 0, objects: 63
		// available: 0, objects: 31
		available += objects;
		// available: 63
		// available: 31

		// object: NULL
		// object: NULL
		if (!object) {
			// c->page: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page,
			// page: MIGRATE_UNMOVABLE인 page
			// c->page: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
			// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page,
			// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
			c->page = page;
			// c->page: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
			// MIGRATE_UNMOVABLE인 page
			// c->page: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
			// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
			// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)

			// s: &boot_kmem_cache_node, ALLOC_FROM_PARTIAL: 7
			// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, ALLOC_FROM_PARTIAL: 7
			stat(s, ALLOC_FROM_PARTIAL); // null function

			// object: NULL, t: UNMOVABLE인 page 의 object의 시작 virtual address + 64
			// object: NULL, t: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
			object = t;
			// object: UNMOVABLE인 page 의 object의 시작 virtual address + 64
			// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
		} else {
			put_cpu_partial(s, page, 0);
			stat(s, CPU_PARTIAL_NODE);
		}

		// s: &boot_kmem_cache_node,
		// kmem_cache_has_cpu_partial(&boot_kmem_cache_node): 1,
		// available: 63, s->cpu_partial: boot_kmem_cache_node.cpu_partial: 30
		// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
		// kmem_cache_has_cpu_partial(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address): 1,
		// available: 31, s->cpu_partial: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->.cpu_partial: 30
		if (!kmem_cache_has_cpu_partial(s)
			|| available > s->cpu_partial / 2)
			break;
			// break 로 loop 탈출
			// break 로 loop 탈출
	}

	// n->list_lock: ((&boot_kmem_cache_node)->node[0])->list_lock
	// n->list_lock: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->node[0])->list_lock
	spin_unlock(&n->list_lock);
	// ((&boot_kmem_cache_node)->node[0])->list_lock의 spinlock 해제
	// ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->node[0])->list_lock의 spinlock 해제

	// object: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	return object;
	// return UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// return UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
}

/*
 * Get a page from somewhere. Search in increasing NUMA distances.
 */
// ARM10C 20140628
// s: &boot_kmem_cache, flags: __GFP_ZERO: 0x8000,
// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
static void *get_any_partial(struct kmem_cache *s, gfp_t flags,
		struct kmem_cache_cpu *c)
{
#ifdef CONFIG_NUMA // CONFIG_NUMA=n
	struct zonelist *zonelist;
	struct zoneref *z;
	struct zone *zone;
	enum zone_type high_zoneidx = gfp_zone(flags);
	void *object;
	unsigned int cpuset_mems_cookie;

	/*
	 * The defrag ratio allows a configuration of the tradeoffs between
	 * inter node defragmentation and node local allocations. A lower
	 * defrag_ratio increases the tendency to do local allocations
	 * instead of attempting to obtain partial slabs from other nodes.
	 *
	 * If the defrag_ratio is set to 0 then kmalloc() always
	 * returns node local objects. If the ratio is higher then kmalloc()
	 * may return off node objects because partial slabs are obtained
	 * from other nodes and filled up.
	 *
	 * If /sys/kernel/slab/xx/defrag_ratio is set to 100 (which makes
	 * defrag_ratio = 1000) then every (well almost) allocation will
	 * first attempt to defrag slab caches on other nodes. This means
	 * scanning over all nodes to look for partial slabs which may be
	 * expensive if we do it every time we are trying to find a slab
	 * with available objects.
	 */
	if (!s->remote_node_defrag_ratio ||
			get_cycles() % 1024 > s->remote_node_defrag_ratio)
		return NULL;

	do {
		cpuset_mems_cookie = get_mems_allowed();
		zonelist = node_zonelist(slab_node(), flags);
		for_each_zone_zonelist(zone, z, zonelist, high_zoneidx) {
			struct kmem_cache_node *n;

			n = get_node(s, zone_to_nid(zone));

			if (n && cpuset_zone_allowed_hardwall(zone, flags) &&
					n->nr_partial > s->min_partial) {
				object = get_partial_node(s, n, c, flags);
				if (object) {
					/*
					 * Return the object even if
					 * put_mems_allowed indicated that
					 * the cpuset mems_allowed was
					 * updated in parallel. It's a
					 * harmless race between the alloc
					 * and the cpuset update.
					 */
					put_mems_allowed(cpuset_mems_cookie);
					return object;
				}
			}
		}
	} while (!put_mems_allowed(cpuset_mems_cookie));
#endif
	return NULL;
	// return NULL
}

/*
 * Get a partial page, lock it and return it.
 */
// ARM10C 20140614
// s: &boot_kmem_cache_node, flags: GFP_KERNEL: 0xD0, node: -1,
// c: (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
// ARM10C 20140628
// s: &boot_kmem_cache, flags: __GFP_ZERO: 0x8000, node: -1,
// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
// ARM10C 20140719
// s: &UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, flags: __GFP_ZERO: 0x8000, node: -1,
// c: (&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
static void *get_partial(struct kmem_cache *s, gfp_t flags, int node,
		struct kmem_cache_cpu *c)
{
	void *object;
	// node: -1, NUMA_NO_NODE: -1, numa_node_id(): 0
	// node: -1, NUMA_NO_NODE: -1, numa_node_id(): 0
	// node: -1, NUMA_NO_NODE: -1, numa_node_id(): 0
	int searchnode = (node == NUMA_NO_NODE) ? numa_node_id() : node;
	// searchnode: 0
	// searchnode: 0
	// searchnode: 0

	// s: &boot_kmem_cache_node, searchnode: 0
	// get_node(&boot_kmem_cache_node, 0): (&boot_kmem_cache_node)->node[0],
	// c: (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋),
	// flags: GFP_KERNEL: 0xD0
	// get_partial_node(&boot_kmem_cache_node, (&boot_kmem_cache_node)->node[0],
	// (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋), GFP_KERNEL: 0xD0):
	// UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// s: &boot_kmem_cache, searchnode: 0
	// get_node(&boot_kmem_cache, 0): (&boot_kmem_cache)->node[0],
	// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋),
	// flags: __GFP_ZERO: 0x8000
	// get_partial_node(&boot_kmem_cache, (&boot_kmem_cache)->node[0],
	// (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋), __GFP_ZERO: 0x8000):
	// NULL
	// s: &UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, searchnode: 0
	// get_node(&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, 0): (&boot_kmem_cache 용 object 주소)->node[0],
	// c: (&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋),
	// flags: __GFP_ZERO: 0x8000
	// get_partial_node(&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, (&boot_kmem_cache 용 object 주소)->node[0],
	// (&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋), __GFP_ZERO: 0x8000):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	object = get_partial_node(s, get_node(s, searchnode), c, flags);
	// object: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// object: NULL
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968

	// get_partial_node 가 한일:
	// 다음 object의 주소를 받아옴
	// UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// MIGRATE_UNMOVABLE인 page의 멤버 필드 값 변경
	// page->freelist: NULL
	// page->counters: 0x80400040
	// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
	// n->nr_partial: 0
	// c->page: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page

	// get_partial_node 가 한일:
	// n->nr_partial 값으로 null를 리턴함

	// get_partial_node 가 한일:
	// 다음 object의 주소를 받아옴
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)의 멤버 필드 값 변경
	// page->freelist: NULL
	// page->counters: 0x80200020
	// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
	// n->nr_partial: 0
	// c->page: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)

	// node: -1, NUMA_NO_NODE: -1
	// node: -1, NUMA_NO_NODE: -1
	// node: -1, NUMA_NO_NODE: -1
	if (object || node != NUMA_NO_NODE)
		// object: UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
		return object;
		// return UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// return UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968

	// s: &boot_kmem_cache, flags: __GFP_ZERO: 0x8000,
	// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// get_any_partial(&boot_kmem_cache, __GFP_ZERO: 0x8000,
	// (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)): NULL
	return get_any_partial(s, flags, c);
	// return NULL
}

#ifdef CONFIG_PREEMPT // CONFIG_PREEMPT=y
/*
 * Calculate the next globally unique transaction for disambiguiation
 * during cmpxchg. The transactions start with the cpu number and are then
 * incremented by CONFIG_NR_CPUS.
 */
// ARM10C 20140621
// CONFIG_NR_CPUS: 4
// roundup_pow_of_two(4): 4
// TID_STEP: 4
#define TID_STEP  roundup_pow_of_two(CONFIG_NR_CPUS)
#else
/*
 * No preemption supported therefore also no need to check for
 * different cpus.
 */
#define TID_STEP 1
#endif

// ARM10C 20140621
// c->tid: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 0
// ARM10C 20140628
// c->tid: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 0
// ARM10C 20140705
// c->tid: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 4
// ARM10C 20140712
// c->tid: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 8
// ARM10C 20140719
// c->tid: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 12
static inline unsigned long next_tid(unsigned long tid)
{
	// tid: 0, TID_STEP: 4
	return tid + TID_STEP;
	// return 4
}

static inline unsigned int tid_to_cpu(unsigned long tid)
{
	return tid % TID_STEP;
}

static inline unsigned long tid_to_event(unsigned long tid)
{
	return tid / TID_STEP;
}

static inline unsigned int init_tid(int cpu)
{
	return cpu;
}

static inline void note_cmpxchg_failure(const char *n,
		const struct kmem_cache *s, unsigned long tid)
{
#ifdef SLUB_DEBUG_CMPXCHG
	unsigned long actual_tid = __this_cpu_read(s->cpu_slab->tid);

	printk(KERN_INFO "%s %s: cmpxchg redo ", n, s->name);

#ifdef CONFIG_PREEMPT
	if (tid_to_cpu(tid) != tid_to_cpu(actual_tid))
		printk("due to cpu change %d -> %d\n",
			tid_to_cpu(tid), tid_to_cpu(actual_tid));
	else
#endif
	if (tid_to_event(tid) != tid_to_event(actual_tid))
		printk("due to cpu running other code. Event %ld->%ld\n",
			tid_to_event(tid), tid_to_event(actual_tid));
	else
		printk("for unknown reason: actual=%lx was=%lx target=%lx\n",
			actual_tid, tid, next_tid(tid));
#endif
	stat(s, CMPXCHG_DOUBLE_CPU_FAIL);
}

// ARM10C 20140607
// s: &boot_kmem_cache_node
// ARM10C 20140621
// s: &boot_kmem_cache
// ARM10C 20140726
// s: &kmem_cache#30
static void init_kmem_cache_cpus(struct kmem_cache *s)
{
	int cpu;

	// nr_cpu_ids: 4, cpu_possible_mask: cpu_possible_bits[1]
	// cpumask_next((-1), cpu_possible_bits[1]): 0
	for_each_possible_cpu(cpu)
	// for ((cpu) = -1; (cpu) = cpumask_next((cpu), (cpu_possible_mask)), (cpu) < nr_cpu_ids; )
		// s->cpu_slab: (&boot_kmem_cache_node)->cpu_slab: 0xc0502d00, cpu: 0
		// per_cpu_ptr((&boot_kmem_cache_node)->cpu_slab, 0):
		// (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의 pcpu_base_addr의 옵셋)
		// init_tid(0): 0
		// s->cpu_slab: (&boot_kmem_cache)->cpu_slab: 0xc0502d10, cpu: 0
		// per_cpu_ptr((&boot_kmem_cache)->cpu_slab, 0):
		// (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의 pcpu_base_addr의 옵셋)
		// init_tid(0): 0
		// s->cpu_slab: (&kmem_cache#30)->cpu_slab: 0xc0502d20, cpu: 0
		// per_cpu_ptr((&kmem_cache#30)->cpu_slab, 0):
		// (&kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의 pcpu_base_addr의 옵셋)
		// init_tid(0): 0
		per_cpu_ptr(s->cpu_slab, cpu)->tid = init_tid(cpu);
		// ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 0
		// ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 0
		// ((&kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 0

		// 할당받은 pcpu 들의 16 byte 공간에 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정
}

/*
 * Remove the cpu slab
 */
// ARM10C 20140705
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// c->page: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
// UNMOVABLE인 page (boot_kmem_cache),
// c->freelist: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128
// ARM10C 20140712
// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
// c->page: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
// UNMOVABLE인 page,
// c->freelist: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
// UNMOVABLE인 page 의 object의 시작 virtual address + 128
static void deactivate_slab(struct kmem_cache *s, struct page *page,
				void *freelist)
{
	enum slab_modes { M_NONE, M_PARTIAL, M_FULL, M_FREE };
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// page: UNMOVABLE인 page (boot_kmem_cache)
	// page_to_nid(UNMOVABLE인 page (boot_kmem_cache)): 0
	// get_node(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, 0):
	// (&boot_kmem_cache 용 object 주소)->node[0]
	//
	// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
	// page: UNMOVABLE인 page
	// page_to_nid(UNMOVABLE인 page): 0
	// get_node(UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968, 0):
	// (&boot_kmem_cache_node 용 object 주소)->node[0]
	struct kmem_cache_node *n = get_node(s, page_to_nid(page));
	// n: (&boot_kmem_cache 용 object 주소)->node[0]
	// n: (&boot_kmem_cache_node 용 object 주소)->node[0]
	int lock = 0;
	// lock: 0
	// lock: 0
	enum slab_modes l = M_NONE, m = M_NONE;
	// l: M_NONE: 0,  m: M_NONE: 0
	// l: M_NONE: 0,  m: M_NONE: 0
	void *nextfree;
	int tail = DEACTIVATE_TO_HEAD;
	// tail: DEACTIVATE_TO_HEAD: 15
	// tail: DEACTIVATE_TO_HEAD: 15
	struct page new;
	struct page old;

	// page->freelist: (UNMOVABLE인 page (boot_kmem_cache))->freelist: NULL
	// page->freelist: (UNMOVABLE인 page)->freelist: NULL
	if (page->freelist) {
		stat(s, DEACTIVATE_REMOTE_FREES);

		tail = DEACTIVATE_TO_TAIL;
	}

	/*
	 * Stage one: Free all available per cpu objects back
	 * to the page freelist while it is still frozen. Leave the
	 * last one.
	 *
	 * There is no need to take the list->lock because the page
	 * is still frozen.
	 */
	// [boot_kmem_cache 로 호출]
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128
	// get_freepointer(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 256
	// nextfree: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 256
	//
	// [UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968 로 호출]
	// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
	// freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 128,
	// get_freepointer(UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
	// UNMOVABLE인 page 의 object의 시작 virtual address + 128):
	// UNMOVABLE인 page 의 시작 virtual address + 192
	// nextfree: UNMOVABLE인 page 의 시작 virtual address + 192
	while (freelist && (nextfree = get_freepointer(s, freelist))) {
		void *prior;
		unsigned long counters;

		// [loop 1] freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128
		// [loop 1] nextfree: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 256
		// [loop 2] freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 256
		// [loop 2] nextfree: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 384
		//
		// [loop 1] freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 128
		// [loop 1] nextfree: UNMOVABLE인 page 의 object의 시작 virtual address + 192
		// [loop 2] freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 192
		// [loop 2] nextfree: UNMOVABLE인 page 의 object의 시작 virtual address + 256

		do {
			// [loop 1] page->freelist: NULL
			// [loop 2] page->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128
			//
			// [loop 1] page->freelist: NULL
			// [loop 2] page->freelist: UNMOVABLE인 page 의 시작 virtual address + 128
			prior = page->freelist;
			// [loop 1] prior: NULL
			// [loop 2] prior: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128
			//
			// [loop 1] prior: NULL
			// [loop 2] prior: UNMOVABLE인 page 의 시작 virtual address + 128

			// [loop 1] page->counters: (UNMOVABLE인 page (boot_kmem_cache))->counters: 0x80200020
			// [loop 2] page->counters: (UNMOVABLE인 page (boot_kmem_cache))->counters: 0x8020001f
			//
			// [loop 1] page->counters: (UNMOVABLE인 page)->counters: 0x80400040
			// [loop 2] page->counters: (UNMOVABLE인 page)->counters: 0x8040003f
			counters = page->counters;
			// [loop 1] counters: 0x80200020
			// [loop 2] counters: 0x8020001f
			//
			// [loop 1] counters: 0x80400040
			// [loop 2] counters: 0x8040003f

			// [loop 1] s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
			// [loop 1] freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128,
			// [loop 1] prior: NULL
			// [loop 2] s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
			// [loop 2] freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 256,
			// [loop 2] prior: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128
			//
			// [loop 1] s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
			// [loop 1] freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 128,
			// [loop 1] prior: NULL
			// [loop 2] s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
			// [loop 2] freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 192,
			// [loop 2] prior: UNMOVABLE인 page 의 시작 virtual address + 128
			set_freepointer(s, freelist, prior);
			// [loop 1] freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128: NULL
			// [loop 1] UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128 의 다음 object를 가리키는 주소의 값을
			// [loop 1] NULL로 세팅
			// [loop 2] freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 256:
			// [loop 2] UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128,
			// [loop 2] UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 256 의 다음 object를 가리키는 주소의 값을
			// [loop 2] 이전 object 주소로 세팅
			//
			// [loop 1] freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 128: NULL
			// [loop 1] UNMOVABLE인 page 의 object의 시작 virtual address + 128의 다음 object를 가리키는 주소의 값을
			// [loop 1] NULL로 세팅
			// [loop 2] freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 192:
			// [loop 2] UNMOVABLE인 page 의 시작 virtual address + 128,
			// [loop 2] UNMOVABLE인 page 의 object의 시작 virtual address + 192의 다음 object를 가리키는 주소의 값을
			// [loop 2] 이전 object 주소로 세팅

			// [loop 1] counters: 0x80200020
			// [loop 2] counters: 0x8020001f
			//
			// [loop 1] counters: 0x80400040
			// [loop 2] counters: 0x8040003f
			new.counters = counters;
			// [loop 1] new.counters: 0x80200020
			// [loop 2] new.counters: 0x8020001f
			//
			// [loop 1] new.counters: 0x80400040
			// [loop 2] new.counters: 0x8040003f

			// [loop 1] new.inuse: 32, new.counters: 0x80200020
			// [loop 2] new.inuse: 31, new.counters: 0x8020001f
			//
			// [loop 1] new.inuse: 64, new.counters: 0x80400040
			// [loop 2] new.inuse: 63, new.counters: 0x8040003f
			new.inuse--;
			// [loop 1] new.inuse: 31, new.counters: 0x8020001f
			// [loop 2] new.inuse: 30, new.counters: 0x8020001e
			//
			// [loop 1] new.inuse: 63, new.counters: 0x8040003f
			// [loop 2] new.inuse: 62, new.counters: 0x8040003e

			// [loop 1] new.frozen: 1
			// [loop 2] new.frozen: 1
			//
			// [loop 1] new.frozen: 1
			// [loop 2] new.frozen: 1
			VM_BUG_ON(!new.frozen);

			// [loop 1] s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
			// [loop 1] page: UNMOVABLE인 page (boot_kmem_cache),
			// [loop 1] prior: NULL, counters: 0x80200020,
			// [loop 1] freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128,
			// [loop 1] new.counters: 0x8020001f,
			// [loop 1] "drain percpu freelist"
			// [loop 1] __cmpxchg_double_slab(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
			// [loop 1] UNMOVABLE인 page (boot_kmem_cache), NULL, 0x80200020, UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128,
			// [loop 1] 0x8020001f, "drain percpu freelist"): 1
			// [loop 1] UNMOVABLE인 page (boot_kmem_cache)의 필드 맴버 값 변경
			// [loop 1] (UNMOVABLE인 page (boot_kmem_cache))->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128
			// [loop 1] (UNMOVABLE인 page (boot_kmem_cache))->counters: 0x8020001f
			//
			// [loop 2] s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
			// [loop 2] page: UNMOVABLE인 page (boot_kmem_cache),
			// [loop 2] prior: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128, counters: 0x8020001f,
			// [loop 2] freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 256,
			// [loop 2] new.counters: 0x8020001e,
			// [loop 2] "drain percpu freelist"
			// [loop 2] __cmpxchg_double_slab(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
			// [loop 2] UNMOVABLE인 page (boot_kmem_cache), UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128,
			// [loop 2] 0x8020001f, UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 256, 0x8020001e, "drain percpu freelist"): 1
			// [loop 2] UNMOVABLE인 page (boot_kmem_cache)의 필드 맴버 값 변경
			// [loop 2] (UNMOVABLE인 page (boot_kmem_cache))->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 256
			// [loop 2] (UNMOVABLE인 page (boot_kmem_cache))->counters: 0x8020001e
			//
			// [loop 1] s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
			// [loop 1] page: UNMOVABLE인 page,
			// [loop 1] prior: NULL, counters: 0x80400040,
			// [loop 1] freelist: UNMOVABLE인 page의 object의 시작 virtual address + 128,
			// [loop 1] new.counters: 0x8040003f,
			// [loop 1] "drain percpu freelist"
			// [loop 1] __cmpxchg_double_slab(UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
			// [loop 1] UNMOVABLE인 page, NULL, 0x80400040, UNMOVABLE인 page 의 object의 시작 virtual address + 128,
			// [loop 1] 0x8040003f, "drain percpu freelist"): 1
			// [loop 1] UNMOVABLE인 page 의 필드 맴버 값 변경
			// [loop 1] (UNMOVABLE인 page)->freelist: UNMOVABLE인 page 의 시작 virtual address + 128
			// [loop 1] (UNMOVABLE인 page)->counters: 0x8040003f
			//
			// [loop 2] s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
			// [loop 2] page: UNMOVABLE인 page,
			// [loop 2] prior: UNMOVABLE인 page 의 시작 virtual address + 128, counters: 0x8040003f,
			// [loop 2] freelist: UNMOVABLE인 page 의 시작 virtual address + 192,
			// [loop 2] new.counters: 0x8040003e,
			// [loop 2] "drain percpu freelist"
			// [loop 2] __cmpxchg_double_slab(UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
			// [loop 2] UNMOVABLE인 page, UNMOVABLE인 page 의 시작 virtual address + 128,
			// [loop 2] 0x8040003f, UNMOVABLE인 page 의 시작 virtual address + 192, 0x8040003e, "drain percpu freelist"): 1
			// [loop 2] UNMOVABLE인 page 의 필드 맴버 값 변경
			// [loop 2] (UNMOVABLE인 page)->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 192
			// [loop 2] (UNMOVABLE인 page))->counters: 0x8040003e
		} while (!__cmpxchg_double_slab(s, page,
			prior, counters,
			freelist, new.counters,
			"drain percpu freelist"));

		// [loop 1] nextfree: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 256
		// [loop 2] nextfree: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 384
		//
		// [loop 1] nextfree: UNMOVABLE인 page 의 object의 시작 virtual address + 192
		// [loop 2] nextfree: UNMOVABLE인 page 의 object의 시작 virtual address + 256
		freelist = nextfree;
		// [loop 1] freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 256
		// [loop 2] freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 384
		//
		// [loop 1] freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 192
		// [loop 2] freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 256

		// [loop 3 .. 30] 번 수행
		//
		// [loop 3 .. 62] 번 수행
	}

	// [boot_kmem_cache 로 호출]
	// 위의 루프에서 한일:
	// UNMOVABLE인 page (boot_kmem_cache) 의 사용하지 않는 첫 번째 object의 freepointer 값을 NULL 로 변경,
	// 나머지 object들의 freepointer 값을 이전 object들의 주소로 변경
	// UNMOVABLE인 page (boot_kmem_cache) 의 맴버필드 변경
	// (UNMOVABLE인 page (boot_kmem_cache))->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3840
	// (UNMOVABLE인 page (boot_kmem_cache))->counters: 0x80200002
	//
	// [UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968 로 호출]
	// 위의 루프에서 한일:
	// UNMOVABLE인 page 의 사용하지 않는 뒤에서 부터 첫 번째 object의 freepointer 값을 NULL 로 변경,
	// 나머지 object들의 freepointer 값을 이전 object들의 주소로 변경
	// UNMOVABLE인 page 의 맴버필드 변경
	// (UNMOVABLE인 page)->freelist: UNMOVABLE인 page 의 시작 virtual address + 3968
	// (UNMOVABLE인 page)->counters: 0x80400003

	/*
	 * Stage two: Ensure that the page is unfrozen while the
	 * list presence reflects the actual number of objects
	 * during unfreeze.
	 *
	 * We setup the list membership and then perform a cmpxchg
	 * with the count. If there is a mismatch then the page
	 * is not unfrozen but the page is on the wrong list.
	 *
	 * Then we restart the process which may have to remove
	 * the page from the list that we just put it on again
	 * because the number of objects in the slab may have
	 * changed.
	 */
redo:

	// page->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3840
	// page->freelist: UNMOVABLE인 page 의 시작 virtual address + 3968
	old.freelist = page->freelist;
	// old.freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3840
	// old.freelist: UNMOVABLE인 page 의 시작 virtual address + 3968

	// page->counters: (UNMOVABLE인 page (boot_kmem_cache))->counters: 0x80200002
	// page->counters: (UNMOVABLE인 page)->counters: 0x80400003
	old.counters = page->counters;
	// old.counters: 0x80200002
	// old.counters: 0x80400003

	// old.frozen: 1
	// old.frozen: 1
	VM_BUG_ON(!old.frozen);

	/* Determine target state of the slab */
	// old.counters: 0x80200002
	// old.counters: 0x80400003
	new.counters = old.counters;
	// new.counters: 0x80200002
	// new.counters: 0x80400003

	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// freelist: UNMOVABLE인 page 의 시작 virtual address + 4032
	if (freelist) {
		// new.inuse: 2
		// new.inuse: 3
		new.inuse--;
		// new.inuse: 1, new.counters: 0x80200001
		// new.inuse: 2, new.counters: 0x80400002

		// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
		// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
		// old.freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3840
		//
		// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
		// freelist: UNMOVABLE인 page 의 시작 virtual address + 4032
		// old.freelist: UNMOVABLE인 page 의 시작 virtual address + 3968
		set_freepointer(s, freelist, old.freelist);
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968 의 다음 object를 가리키는 주소의 값을
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3840 로 세팅
		// freepointer의 주소를 이전 object 주소로 변경
		// UNMOVABLE인 page 의 시작 virtual address + 4032의 다음 object를 가리키는 주소의 값을
		// UNMOVABLE인 page 의 시작 virtual address + 3968
		// freepointer의 주소를 이전 object 주소로 변경

		// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
		// freelist: UNMOVABLE인 page 의 시작 virtual address + 4032
		new.freelist = freelist;
		// new.freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
		// new.freelist: UNMOVABLE인 page 의 시작 virtual address + 4032
	} else
		new.freelist = old.freelist;


	// 에제:
	// s->offset이 0이고 slab object 시작 주소가 0x10001000 일 경우
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | Slab object 0  (사용중) | Slab object 1           | Slab object 2           | Slab object 3           | .... | Slab object 31          |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | object start address:   | object start address:   | object start address:   | object start address:   |      | object start address:   |
	// | 0x10001000              | 0x10001080              | 0x10001100              | 0x10001180              | .... | 0x10001f80              |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | freepointer | data      | freepointer | data      | freepointer | data      | freepointer | data      | .... | freepointer | data      |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | 0x10001080  | 124 Bytes | null        | 124 Bytes | 0x10001080  | 124 Bytes | 0x10001100  | 124 Bytes | .... | 0x10001f00  | 124 Bytes |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	//
	// 에제:
	// s->offset이 0이고 slab object 시작 주소가 0x10001000 일 경우
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | Slab object 0 (사용중) | Slab object 1 (사용중) | Slab object 2          | Slab object 3          | Slab object 3          | .... | Slab object 63         |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | object start address:  | object start address:  | object start address:  | object start address:  | object start address:  |      | object start address:  |
	// | 0x10001000             | 0x10001040             | 0x10001080             | 0x100010C0             | 0x10001100             | .... | 0x10001fc0             |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | freepointer | data     | freepointer | data     | freepointer | data     | freepointer | data     | freepointer | data     | .... | freepointer | data     |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | (덮어씀)    | 60 Bytes | (덮어씀)    | 60 Bytes | null        | 60 Bytes | 0x10001080  | 60 Bytes | 0x100010C0  | 60 Bytes | .... | 0x10001f80  | 60 Bytes |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------

	// new.frozen: 1
	// new.frozen: 1
	new.frozen = 0;
	// new.frozen: 0, new.counters: 0x00200001
	// new.frozen: 0, new.counters: 0x00400002

	// n: (&boot_kmem_cache 용 object 주소)->node[0]:
	// boot_kmem_cache_node 로 할당 받은 2 번째 object의 주소
	//
	// n: (&boot_kmem_cache_node 용 object 주소)->node[0]:
	// boot_kmem_cache_node 로 할당 받은 1 번째 object의 주소

	// new.inuse: 1, n->nr_partial: 0, s->min_partial: (&boot_kmem_cache 용 object 주소)->min_partial: 5
	// new.freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// new.inuse: 2, n->nr_partial: 0, s->min_partial: (&boot_kmem_cache 용 object 주소)->min_partial: 5
	// new.freelist: UNMOVABLE인 page 의 시작 virtual address + 4032
	if (!new.inuse && n->nr_partial > s->min_partial)
		m = M_FREE;
	else if (new.freelist) {
		// m: M_NONE: 0
		// m: M_NONE: 0
		m = M_PARTIAL;
		// m: M_PARTIAL: 1
		// m: M_PARTIAL: 1

		// lock: 0
		// lock: 0
		if (!lock) {
			// lock: 0
			// lock: 0
			lock = 1;
			// lock: 1
			// lock: 1
			/*
			 * Taking the spinlock removes the possiblity
			 * that acquire_slab() will see a slab page that
			 * is frozen
			 */
			spin_lock(&n->list_lock);
			// n->list_lock 을 이용한 spin_lock 획득
			// n->list_lock 을 이용한 spin_lock 획득
		}
	} else {
		m = M_FULL;
		if (kmem_cache_debug(s) && !lock) {
			lock = 1;
			/*
			 * This also ensures that the scanning of full
			 * slabs from diagnostic functions will not see
			 * any frozen slabs.
			 */
			spin_lock(&n->list_lock);
		}
	}

	// l: M_NONE: 0, m: M_PARTIAL: 1
	// l: M_NONE: 0, m: M_PARTIAL: 1
	if (l != m) {

		// l: M_NONE: 0, m: M_PARTIAL: 1
		// l: M_NONE: 0, m: M_PARTIAL: 1
		if (l == M_PARTIAL)

			remove_partial(n, page);

		else if (l == M_FULL)

			remove_full(s, page);

		if (m == M_PARTIAL) {

			// n: (&boot_kmem_cache 용 object 주소)->node[0]:
			// boot_kmem_cache_node 로 할당 받은 2 번째 object의 주소,
			// page: UNMOVABLE인 page (boot_kmem_cache),
			// tail: DEACTIVATE_TO_HEAD: 15
			// n: (&boot_kmem_cache_node 용 object 주소)->node[0]:
			// boot_kmem_cache_node 로 할당 받은 1 번째 object의 주소,
			// page: UNMOVABLE인 page,
			// tail: DEACTIVATE_TO_HEAD: 15
			add_partial(n, page, tail);
			// add_partial 한일:
			// n->nr_partial: 1
			// n->partial에 (UNMOVABLE인 page (boot_kmem_cache))->lru 가 추가됨
			// add_partial 한일:
			// n->nr_partial: 1
			// n->partial에 (UNMOVABLE인 page)->lru 가 추가됨

			// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
			// tail: DEACTIVATE_TO_HEAD: 15
			// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
			// tail: DEACTIVATE_TO_HEAD: 15
			stat(s, tail);

		} else if (m == M_FULL) {

			stat(s, DEACTIVATE_FULL);
			add_full(s, n, page);

		}
	}

	// l: M_NONE: 0, m: M_PARTIAL: 1
	// l: M_NONE: 0, m: M_PARTIAL: 1
	l = m;
	// l: M_PARTIAL: 1
	// l: M_PARTIAL: 1

	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// page: UNMOVABLE인 page (boot_kmem_cache),
	// old.freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3840
	// old.counters: 0x80200002
	// new.freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// new.counters: 0x00200001
	// "unfreezing slab"
	// __cmpxchg_double_slab(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// UNMOVABLE인 page (boot_kmem_cache), UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3840,
	// 0x80200002, UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
	// 0x00200001, "unfreezing slab"): 1
	// UNMOVABLE인 page (boot_kmem_cache)의 필드 맴버 값 변경
	// (UNMOVABLE인 page (boot_kmem_cache))->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// (UNMOVABLE인 page (boot_kmem_cache))->counters: 0x00200001
	//
	// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
	// page: UNMOVABLE인 page,
	// old.freelist: UNMOVABLE인 page 의 시작 virtual address + 3968
	// old.counters: 0x80400003
	// new.freelist: UNMOVABLE인 page 의 시작 virtual address + 4032
	// new.counters: 0x00400002
	// "unfreezing slab"
	// __cmpxchg_double_slab(UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
	// UNMOVABLE인 page, UNMOVABLE인 page 의 시작 virtual address + 3968,
	// 0x80400003, UNMOVABLE인 page 의 시작 virtual address + 4032,
	// 0x00400002, "unfreezing slab"): 1
	// UNMOVABLE인 page)의 필드 맴버 값 변경
	// (UNMOVABLE인 page)->freelist: UNMOVABLE인 page 의 시작 virtual address + 4032
	// (UNMOVABLE인 page)->counters: 0x00400002
	if (!__cmpxchg_double_slab(s, page,
				old.freelist, old.counters,
				new.freelist, new.counters,
				"unfreezing slab"))
		goto redo;

	// lock: 1
	// lock: 1
	if (lock)
		spin_unlock(&n->list_lock);
		// n->list_lock 을 이용한 spin_lock 해재
		// n->list_lock 을 이용한 spin_lock 해재

	// m: M_PARTIAL: 1
	// m: M_PARTIAL: 1
	if (m == M_FREE) {
		stat(s, DEACTIVATE_EMPTY);
		discard_slab(s, page);
		stat(s, FREE_SLAB);
	}
}

/*
 * Unfreeze all the cpu partial slabs.
 *
 * This function must be called with interrupts disabled
 * for the cpu using c (or some other guarantee must be there
 * to guarantee no concurrent accesses).
 */
// ARM10C 20140705
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// c: (&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
// ARM10C 20140712
// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
// c: (&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
static void unfreeze_partials(struct kmem_cache *s,
		struct kmem_cache_cpu *c)
{
#ifdef CONFIG_SLUB_CPU_PARTIAL // CONFIG_SLUB_CPU_PARTIAL=y
	struct kmem_cache_node *n = NULL, *n2 = NULL;
	struct page *page, *discard_page = NULL;

	// c->partial: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->partial: NULL
	// page: NULL
	// c->partial: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->partial: NULL
	// page: NULL
	while ((page = c->partial)) {
		struct page new;
		struct page old;

		c->partial = page->next;

		n2 = get_node(s, page_to_nid(page));
		if (n != n2) {
			if (n)
				spin_unlock(&n->list_lock);

			n = n2;
			spin_lock(&n->list_lock);
		}

		do {

			old.freelist = page->freelist;
			old.counters = page->counters;
			VM_BUG_ON(!old.frozen);

			new.counters = old.counters;
			new.freelist = old.freelist;

			new.frozen = 0;

		} while (!__cmpxchg_double_slab(s, page,
				old.freelist, old.counters,
				new.freelist, new.counters,
				"unfreezing slab"));

		if (unlikely(!new.inuse && n->nr_partial > s->min_partial)) {
			page->next = discard_page;
			discard_page = page;
		} else {
			add_partial(n, page, DEACTIVATE_TO_TAIL);
			stat(s, FREE_ADD_PARTIAL);
		}
	}

	// n: NULL
	// n: NULL
	if (n)
		spin_unlock(&n->list_lock);

	// discard_page: NULL
	// discard_page: NULL
	while (discard_page) {
		page = discard_page;
		discard_page = discard_page->next;

		stat(s, DEACTIVATE_EMPTY);
		discard_slab(s, page);
		stat(s, FREE_SLAB);
	}
#endif
}

/*
 * Put a page that was just frozen (in __slab_free) into a partial page
 * slot if available. This is done without interrupts disabled and without
 * preemption disabled. The cmpxchg is racy and may put the partial page
 * onto a random cpus partial slot.
 *
 * If we did not find a slot then simply move all the partials to the
 * per node partial list.
 */
static void put_cpu_partial(struct kmem_cache *s, struct page *page, int drain)
{
#ifdef CONFIG_SLUB_CPU_PARTIAL
	struct page *oldpage;
	int pages;
	int pobjects;

	do {
		pages = 0;
		pobjects = 0;
		oldpage = this_cpu_read(s->cpu_slab->partial);

		if (oldpage) {
			pobjects = oldpage->pobjects;
			pages = oldpage->pages;
			if (drain && pobjects > s->cpu_partial) {
				unsigned long flags;
				/*
				 * partial array is full. Move the existing
				 * set to the per node partial list.
				 */
				local_irq_save(flags);
				unfreeze_partials(s, this_cpu_ptr(s->cpu_slab));
				local_irq_restore(flags);
				oldpage = NULL;
				pobjects = 0;
				pages = 0;
				stat(s, CPU_PARTIAL_DRAIN);
			}
		}

		pages++;
		pobjects += page->objects - page->inuse;

		page->pages = pages;
		page->pobjects = pobjects;
		page->next = oldpage;

	} while (this_cpu_cmpxchg(s->cpu_slab->partial, oldpage, page)
								!= oldpage);
#endif
}

// ARM10C 20140705
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// c: (&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
// ARM10C 20140712
// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
// c: (&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
static inline void flush_slab(struct kmem_cache *s, struct kmem_cache_cpu *c)
{
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// CPUSLAB_FLUSH: 13
	// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
	// CPUSLAB_FLUSH: 13
	stat(s, CPUSLAB_FLUSH);

	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// c->page: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// UNMOVABLE인 page (boot_kmem_cache),
	// c->freelist: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128
	// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
	// c->page: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// UNMOVABLE인 page,
	// c->freelist: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
	// UNMOVABLE인 page 의 object의 시작 virtual address + 128
	deactivate_slab(s, c->page, c->freelist);

	// [boot_kmem_cache 로 호출]
	// deactivate_slab에서 한일:
	// UNMOVABLE인 page (boot_kmem_cache)의 필드 맴버 값 변경
	// (UNMOVABLE인 page (boot_kmem_cache))->counters: 0x00200001
	// (UNMOVABLE인 page (boot_kmem_cache))->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	//
	// (UNMOVABLE인 page (boot_kmem_cache)) 의 object들의 freepointer 값 변경
	// (사용하지 않는 첫 번째 object의 freepointer 값을 NULL 로 변경, 나머지 object들의 freepointer 값을 이전 object들의 주소로 변경)
	//
	// 에) s->offset이 0이고 slab object 시작 주소가 0x10001000 일 경우
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | Slab object 0 (사용중)  | Slab object 1           | Slab object 2           | Slab object 3           | .... | Slab object 31          |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | object start address:   | object start address:   | object start address:   | object start address:   |      | object start address:   |
	// | 0x10001000              | 0x10001080              | 0x10001100              | 0x10001180              | .... | 0x10001f80              |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | freepointer | data      | freepointer | data      | freepointer | data      | freepointer | data      | .... | freepointer | data      |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | 0x10001080  | 124 Bytes | null        | 124 Bytes | 0x10001080  | 124 Bytes | 0x10001100  | 124 Bytes | .... | 0x10001f00  | 124 Bytes |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	//
	// n: (&boot_kmem_cache 용 object 주소)->node[0]:
	// boot_kmem_cache_node 로 할당 받은 2 번째 object의 주소
	// n->nr_partial: 1
	// n->partial에 (UNMOVABLE인 page (boot_kmem_cache))->lru 가 추가됨
	//
	// [UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968 로 호출]
	// deactivate_slab에서 한일:
	// UNMOVABLE인 page 의 필드 맴버 값 변경
	// (UNMOVABLE인 page)->counters: 0x00400002
	// (UNMOVABLE인 page)->freelist: UNMOVABLE인 page 의 시작 virtual address + 4032
	//
	// (UNMOVABLE인 page) 의 object들의 freepointer 값 변경
	// (사용하지 않는 첫 번째 object의 freepointer 값을 NULL 로 변경, 나머지 object들의 freepointer 값을 이전 object들의 주소로 변경)
	//
	// 에) s->offset이 0이고 slab object 시작 주소가 0x10001000 일 경우
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | Slab object 0 (사용중) | Slab object 1 (사용중) | Slab object 2          | Slab object 3          | Slab object 3          | .... | Slab object 63         |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | object start address:  | object start address:  | object start address:  | object start address:  | object start address:  |      | object start address:  |
	// | 0x10001000             | 0x10001040             | 0x10001080             | 0x100010C0             | 0x10001100             | .... | 0x10001fc0             |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | freepointer | data     | freepointer | data     | freepointer | data     | freepointer | data     | freepointer | data     | .... | freepointer | data     |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | (덮어씀)    | 60 Bytes | (덮어씀)    | 60 Bytes | null        | 60 Bytes | 0x10001080  | 60 Bytes | 0x100010C0  | 60 Bytes | .... | 0x10001f80  | 60 Bytes |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	//
	// n: (&boot_kmem_cache_node 용 object 주소)->node[0]:
	// boot_kmem_cache_node 로 할당 받은 1 번째 object의 주소
	// n->nr_partial: 1
	// n->partial에 (UNMOVABLE인 page)->lru 가 추가됨

	// c->tid: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 4
	// next_tid(4): 8
	// c->tid: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 4
	// next_tid(4): 8
	c->tid = next_tid(c->tid);
	// c->tid: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 8
	// c->tid: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 8

	c->page = NULL;
	// c->page: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: NULL
	// c->page: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: NULL

	c->freelist = NULL;
	// c->freelist: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist: NULL
	// c->freelist: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist: NULL
}

/*
 * Flush cpu slab.
 *
 * Called from IPI handler with interrupts disabled.
 */
// ARM10C 20140705
// IPI: Inter-processor interrupt (IPI)
// a special case of interrupt that is generated by one processor to interrupt another processor in a multiprocessor system.
//
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// smp_processor_id(): 0
// ARM10C 20140712
// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
// smp_processor_id(): 0
static inline void __flush_cpu_slab(struct kmem_cache *s, int cpu)
{
	// s->cpu_slab: (&boot_kmem_cache 용 object 주소)->cpu_slab: 0xc0502d10, cpu: 0
	// per_cpu_ptr(0xc0502d10, 0):
	// (&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// s->cpu_slab: (UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968)->cpu_slab: 0xc0502d00, cpu: 0
	// per_cpu_ptr(0xc0502d00, 0):
	// (&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);
	// c: (&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c: (&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)

	// c: (&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c: (&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	if (likely(c)) {
		// c->page: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
		// UNMOVABLE인 page (boot_kmem_cache)
		// c->page: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
		// UNMOVABLE인 page
		if (c->page)
			// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
			// c: (&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
			// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
			// c: (&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
			flush_slab(s, c);

			// [boot_kmem_cache 로 호출]
			// flush_slab 이 한일:
			// UNMOVABLE인 page (boot_kmem_cache)의 필드 맴버 값 변경
			// (UNMOVABLE인 page (boot_kmem_cache))->counters: 0x00200001
			// (UNMOVABLE인 page (boot_kmem_cache))->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
			//
			// (UNMOVABLE인 page (boot_kmem_cache)) 의 object들의 freepointer 값 변경
			// (사용하지 않는 첫 번째 object의 freepointer 값을 NULL 로 변경, 나머지 object들의 freepointer 값을 이전 object들의 주소로 변경)
			//
			// 에) s->offset이 0이고 slab object 시작 주소가 0x10001000 일 경우
			// ------------------------------------------------------------------------------------------------------------------------------------------
			// | Slab object 0 (사용중)  | Slab object 1           | Slab object 2           | Slab object 3           | .... | Slab object 31          |
			// ------------------------------------------------------------------------------------------------------------------------------------------
			// | object start address:   | object start address:   | object start address:   | object start address:   |      | object start address:   |
			// | 0x10001000              | 0x10001080              | 0x10001100              | 0x10001180              | .... | 0x10001f80              |
			// ------------------------------------------------------------------------------------------------------------------------------------------
			// | freepointer | data      | freepointer | data      | freepointer | data      | freepointer | data      | .... | freepointer | data      |
			// ------------------------------------------------------------------------------------------------------------------------------------------
			// | 0x10001080  | 124 Bytes | null        | 124 Bytes | 0x10001080  | 124 Bytes | 0x10001100  | 124 Bytes | .... | 0x10001f00  | 124 Bytes |
			// ------------------------------------------------------------------------------------------------------------------------------------------
			//
			// n: (&boot_kmem_cache 용 object 주소)->node[0]:
			// boot_kmem_cache_node 로 할당 받은 2 번째 object의 주소
			// n->nr_partial: 1
			// n->partial에 (UNMOVABLE인 page (boot_kmem_cache))->lru 가 추가됨
			//
			// c: (&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
			// c->tid: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 8
			// c->page: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: NULL
			// c->freelist: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist: NULL
			//
			// [UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968 로 호출]
			// flush_slab 이 한일:
			// UNMOVABLE인 page 의 필드 맴버 값 변경
			// (UNMOVABLE인 page)->counters: 0x00400002
			// (UNMOVABLE인 page)->freelist: UNMOVABLE인 page 의 시작 virtual address + 4032
			//
			// (UNMOVABLE인 page) 의 object들의 freepointer 값 변경
			// (사용하지 않는 첫 번째 object의 freepointer 값을 NULL 로 변경, 나머지 object들의 freepointer 값을 이전 object들의 주소로 변경)
			//
			// 에) s->offset이 0이고 slab object 시작 주소가 0x10001000 일 경우
			// --------------------------------------------------------------------------------------------------------------------------------------------------------------
			// | Slab object 0 (사용중) | Slab object 1 (사용중) | Slab object 2          | Slab object 3          | Slab object 3          | .... | Slab object 63         |
			// --------------------------------------------------------------------------------------------------------------------------------------------------------------
			// | object start address:  | object start address:  | object start address:  | object start address:  | object start address:  |      | object start address:  |
			// | 0x10001000             | 0x10001040             | 0x10001080             | 0x100010C0             | 0x10001100             | .... | 0x10001fc0             |
			// --------------------------------------------------------------------------------------------------------------------------------------------------------------
			// | freepointer | data     | freepointer | data     | freepointer | data     | freepointer | data     | freepointer | data     | .... | freepointer | data     |
			// --------------------------------------------------------------------------------------------------------------------------------------------------------------
			// | (덮어씀)    | 60 Bytes | (덮어씀)    | 60 Bytes | null        | 60 Bytes | 0x10001080  | 60 Bytes | 0x100010C0  | 60 Bytes | .... | 0x10001f80  | 60 Bytes |
			// --------------------------------------------------------------------------------------------------------------------------------------------------------------
			//
			// n: (&boot_kmem_cache_node 용 object 주소)->node[0]:
			// boot_kmem_cache_node 로 할당 받은 1 번째 object의 주소
			// n->nr_partial: 1
			// n->partial에 (UNMOVABLE인 page)->lru 가 추가됨
			//
			// c: (&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
			// c->tid: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 8
			// c->page: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: NULL
			// c->freelist: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist: NULL

		// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
		// c: (&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
		// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
		// c: (&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
		unfreeze_partials(s, c);
	}
}

static void flush_cpu_slab(void *d)
{
	struct kmem_cache *s = d;

	__flush_cpu_slab(s, smp_processor_id());
}

static bool has_cpu_slab(int cpu, void *info)
{
	struct kmem_cache *s = info;
	struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);

	return c->page || c->partial;
}

static void flush_all(struct kmem_cache *s)
{
	on_each_cpu_cond(has_cpu_slab, flush_cpu_slab, s, 1, GFP_ATOMIC);
}

/*
 * Check if the objects in a per cpu structure fit numa
 * locality expectations.
 */
// ARM10C 20140614
// page: 0, node: -1
// ARM10C 20140705
// MIGRATE_UNMOVABLE인 page, -1
static inline int node_match(struct page *page, int node)
{
#ifdef CONFIG_NUMA // CONFIG_NUMA=n
	if (!page || (node != NUMA_NO_NODE && page_to_nid(page) != node))
		return 0;
#endif
	return 1;
}

static int count_free(struct page *page)
{
	return page->objects - page->inuse;
}

static unsigned long count_partial(struct kmem_cache_node *n,
					int (*get_count)(struct page *))
{
	unsigned long flags;
	unsigned long x = 0;
	struct page *page;

	spin_lock_irqsave(&n->list_lock, flags);
	list_for_each_entry(page, &n->partial, lru)
		x += get_count(page);
	spin_unlock_irqrestore(&n->list_lock, flags);
	return x;
}

static inline unsigned long node_nr_objs(struct kmem_cache_node *n)
{
#ifdef CONFIG_SLUB_DEBUG
	return atomic_long_read(&n->total_objects);
#else
	return 0;
#endif
}

static noinline void
slab_out_of_memory(struct kmem_cache *s, gfp_t gfpflags, int nid)
{
	int node;

	printk(KERN_WARNING
		"SLUB: Unable to allocate memory on node %d (gfp=0x%x)\n",
		nid, gfpflags);
	printk(KERN_WARNING "  cache: %s, object size: %d, buffer size: %d, "
		"default order: %d, min order: %d\n", s->name, s->object_size,
		s->size, oo_order(s->oo), oo_order(s->min));

	if (oo_order(s->min) > get_order(s->object_size))
		printk(KERN_WARNING "  %s debugging increased min order, use "
		       "slub_debug=O to disable.\n", s->name);

	for_each_online_node(node) {
		struct kmem_cache_node *n = get_node(s, node);
		unsigned long nr_slabs;
		unsigned long nr_objs;
		unsigned long nr_free;

		if (!n)
			continue;

		nr_free  = count_partial(n, count_free);
		nr_slabs = node_nr_slabs(n);
		nr_objs  = node_nr_objs(n);

		printk(KERN_WARNING
			"  node %d: slabs: %ld, objs: %ld, free: %ld\n",
			node, nr_slabs, nr_objs, nr_free);
	}
}

// ARM10C 20140614
// s: &boot_kmem_cache_node, gfpflags: GFP_KERNEL: 0xD0, node: -1,
// &c: &(&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
// ARM10C 20140628
// s: &boot_kmem_cache, gfpflags: __GFP_ZERO: 0x8000, node: -1,
// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000, node: -1,
// c: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
static inline void *new_slab_objects(struct kmem_cache *s, gfp_t flags,
			int node, struct kmem_cache_cpu **pc)
{
	void *freelist;
	// *pc: (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// *pc: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// *pc: (&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	struct kmem_cache_cpu *c = *pc;
	// c: (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c: (&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	struct page *page;

	// s: &boot_kmem_cache_node, flags: GFP_KERNEL: 0xD0, node: -1,
	// c: (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// get_partial(&boot_kmem_cache_node, GFP_KERNEL: 0xD0, -1,
	// (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)):
	// UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// s: &boot_kmem_cache, flags: __GFP_ZERO: 0x8000, node: -1,
	// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// get_partial(&boot_kmem_cache, __GFP_ZERO: 0x8000, -1,
	// (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)):
	// NULL
	// s: &UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, flags: __GFP_ZERO: 0x8000, node: -1,
	// c: (&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// get_partial(&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, __GFP_ZERO: 0x8000, -1,
	// (&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	freelist = get_partial(s, flags, node, c);
	// freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// freelist: NULL
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968

	// get_partial(&boot_kmem_cache_node)이 한일:
	// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
	// page->counters: 0x80400040
	// page->inuse: 64
	// page->objects: 64
	// page->frozen: 1
	// page->freelist: NULL
	// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
	// n->nr_partial: 0
	// c->page: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page

	// get_partial(&boot_kmem_cache)이 한일:
	// n->nr_partial 값으로 null를 리턴함

	// get_partial(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)이 한일:
	// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
	// page->counters: 0x80200020
	// page->inuse: 32
	// page->objects: 32
	// page->frozen: 1
	// page->freelist: NULL
	// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page (boot_kmem_cache))->lru 를 삭제
	// n->nr_partial: 0
	// c->page: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)

	// freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// freelist: NULL
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	if (freelist)
		// freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
		return freelist;
		// return UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// return UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968

	// s: &boot_kmem_cache, flags: __GFP_ZERO: 0x8000, node: -1
	page = new_slab(s, flags, node);
	// page: UNMOVABLE인 page (boot_kmem_cache)

	// new_slab한일:
	// migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache) 할당 받음
	// 이전에 할당 받은 MIGRATE_UNMOVABLE인 page의 두번째 object의 맴버 필드값을 변경
	// n->nr_slabs: 1
	// n->total_objects: 32
	// page->slab_cache: &boot_kmem_cache주소를 set
	// slab 의 objects 들의 freepointer를 맵핑함
	// 새로 받은 page의 맴버 필드 값 세팅
	// page->freelist: UNMOVABLE인 page (boot_kmem_cache)의 virtual address
	// page->inuse: 32
	// page->frozen: 1
	// page->flags에 7 (PG_slab) bit를 set

	// page: UNMOVABLE인 page (boot_kmem_cache)
	if (page) {
		// s->cpu_slab: (&boot_kmem_cache)->cpu_slab: 0xc0502d10
		// __this_cpu_ptr(0xc0502d10):
		// (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))
		c = __this_cpu_ptr(s->cpu_slab);
		// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))

		// pcpu_populate_chunk에서 kmem_cache_cpu의 맵버 필드를 0 으로 초기화함

		// c->page: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)))->page: 0
		if (c->page)
			flush_slab(s, c);

		/*
		 * No other reference to the page yet so we can
		 * muck around with it freely without cmpxchg
		 */
		// page->freelist: UNMOVABLE인 page (boot_kmem_cache)의 virtual address
		freelist = page->freelist;
		// freelist: UNMOVABLE인 page (boot_kmem_cache)의 virtual address

		// page->freelist: UNMOVABLE인 page (boot_kmem_cache)의 virtual address
		page->freelist = NULL;
		// page->freelist: NULL

		// s: &boot_kmem_cache, ALLOC_SLAB: 8
		stat(s, ALLOC_SLAB); // null function

		// c->page: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)))->page: 0,
		// page: UNMOVABLE인 page (boot_kmem_cache)
		c->page = page;
		// c->page: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)))->page:
		// UNMOVABLE인 page (boot_kmem_cache)

		// *pc: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋),
		// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))
		*pc = c;
		// *pc: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	} else
		freelist = NULL;

	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 virtual address
	return freelist;
	// return UNMOVABLE인 page (boot_kmem_cache)의 virtual address
}

// ARM10C 20140621
// page: MIGRATE_UNMOVABLE인 page, flags: GFP_KERNEL: 0xD0
// ARM10C 20140628
// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache), gfpflags: __GFP_ZERO: 0x8000
// ARM10C 20140719
// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache), flags: __GFP_ZERO: 0x8000
static inline bool pfmemalloc_match(struct page *page, gfp_t gfpflags)
{
	// page: MIGRATE_UNMOVABLE인 page,
	// PageSlabPfmemalloc(MIGRATE_UNMOVABLE인 page): 0
	if (unlikely(PageSlabPfmemalloc(page)))
		return gfp_pfmemalloc_allowed(gfpflags);

	return true;
	// return true
}

/*
 * Check the page->freelist of a page and either transfer the freelist to the
 * per cpu freelist or deactivate the page.
 *
 * The page is still frozen if the return value is not NULL.
 *
 * If this function returns NULL then the page has been unfrozen.
 *
 * This function must be called with interrupt disabled.
 */
static inline void *get_freelist(struct kmem_cache *s, struct page *page)
{
	struct page new;
	unsigned long counters;
	void *freelist;

	do {
		freelist = page->freelist;
		counters = page->counters;

		new.counters = counters;
		VM_BUG_ON(!new.frozen);

		new.inuse = page->objects;
		new.frozen = freelist != NULL;

	} while (!__cmpxchg_double_slab(s, page,
		freelist, counters,
		NULL, new.counters,
		"get_freelist"));

	return freelist;
}

/*
 * Slow path. The lockless freelist is empty or we need to perform
 * debugging duties.
 *
 * Processing is still very fast if new objects have been freed to the
 * regular freelist. In that case we simply take over the regular freelist
 * as the lockless freelist and zap the regular freelist.
 *
 * If that is not working then we fall back to the partial lists. We take the
 * first element of the freelist as the object to allocate now and move the
 * rest of the freelist to the lockless freelist.
 *
 * And if we were unable to get a new slab from the partial slab lists then
 * we need to allocate a new slab. This is the slowest path since it involves
 * a call to the page allocator and the setup of a new slab.
 */
// ARM10C 20140614
// s: &boot_kmem_cache_node, gfpflags: GFP_KERNEL: 0xD0, node: -1, addr: _RET_IP_,
// c: (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
// ARM10C 20140628
// s: &boot_kmem_cache, gfpflags: __GFP_ZERO: 0x8000, node: -1, addr: _RET_IP_,
// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000, node: -1, addr: _RET_IP_,
// c: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000, node: -1, addr: _RET_IP_,
// c: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
			  unsigned long addr, struct kmem_cache_cpu *c)
{
	void *freelist;
	struct page *page;
	unsigned long flags;

	local_irq_save(flags);
	// cpsr을 flags에 저장
	// cpsr을 flags에 저장
	// cpsr을 flags에 저장
	// cpsr을 flags에 저장

#ifdef CONFIG_PREEMPT // CONFIG_PREEMPT=y
	/*
	 * We may have been preempted and rescheduled on a different
	 * cpu before disabling interrupts. Need to reload cpu area
	 * pointer.
	 */
	// s->cpu_slab: (&boot_kmem_cache_node)->cpu_slab: 0xc0502d00
	// __this_cpu_ptr((&boot_kmem_cache_node)->cpu_slab: 0xc0502d00):
	// (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// s->cpu_slab: (&boot_kmem_cache)->cpu_slab: 0xc0502d10
	// __this_cpu_ptr((&boot_kmem_cache)->cpu_slab: 0xc0502d10):
	// (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// s->cpu_slab: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab: 0xc0502d10
	// __this_cpu_ptr((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab: 0xc0502d10):
	// (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// s->cpu_slab: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab: 0xc0502d10
	// __this_cpu_ptr((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab: 0xc0502d10):
	// (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	c = this_cpu_ptr(s->cpu_slab);
	// c: (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
#endif
	// c->page: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: 0
	// c->page: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: 0
	// c->page: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: 0
	// c->page: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: 0
	page = c->page;
	// page: 0
	// page: 0
	// page: 0
	// page: 0

	// page: 0
	// page: 0
	// page: 0
	// page: 0
	if (!page)
		goto new_slab;
		// new_slab 심볼로 이동
		// new_slab 심볼로 이동
		// new_slab 심볼로 이동
		// new_slab 심볼로 이동
redo:

	if (unlikely(!node_match(page, node))) {
		stat(s, ALLOC_NODE_MISMATCH);
		deactivate_slab(s, page, c->freelist);
		c->page = NULL;
		c->freelist = NULL;
		goto new_slab;
	}

	/*
	 * By rights, we should be searching for a slab page that was
	 * PFMEMALLOC but right now, we are losing the pfmemalloc
	 * information when the page leaves the per-cpu allocator
	 */
	if (unlikely(!pfmemalloc_match(page, gfpflags))) {
		deactivate_slab(s, page, c->freelist);
		c->page = NULL;
		c->freelist = NULL;
		goto new_slab;
	}

	/* must check again c->freelist in case of cpu migration or IRQ */
	freelist = c->freelist;
	if (freelist)
		goto load_freelist;

	stat(s, ALLOC_SLOWPATH);

	freelist = get_freelist(s, page);

	if (!freelist) {
		c->page = NULL;
		stat(s, DEACTIVATE_BYPASS);
		goto new_slab;
	}

	stat(s, ALLOC_REFILL);

load_freelist:
	/*
	 * freelist is pointing to the list of objects to be used.
	 * page is pointing to the page from which the objects are obtained.
	 * That page must be frozen for per cpu allocations to work.
	 */
	// c->page: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page
	// c->page: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	// c->page: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)

	// (MIGRATE_UNMOVABLE인 page)->frozen: 1
	// (MIGRATE_UNMOVABLE인 page(boot_kmem_cache))->frozen: 1
	// (MIGRATE_UNMOVABLE인 page(boot_kmem_cache))->frozen: 1
	VM_BUG_ON(!c->page->frozen);

	// s: &boot_kmem_cache_node, freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// c->freelist: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist
	// get_freepointer(&boot_kmem_cache_node, UNMOVABLE인 page 의 object의 시작 virtual address + 64):
	// UNMOVABLE인 page 의 object의 시작 virtual address + 128
	// s: &boot_kmem_cache, freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address
	// c->freelist: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist
	// get_freepointer(&boot_kmem_cache, UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// c->freelist: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist
	// get_freepointer(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3840
	c->freelist = get_freepointer(s, freelist);
	// c->freelist: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
	// UNMOVABLE인 page 의 object의 시작 virtual address + 128
	// c->freelist: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128
	// c->freelist: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3840

	// c->tid: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 0
	// next_tid(0): 4
	// c->tid: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 0
	// next_tid(0): 4
	// c->tid: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 8
	// next_tid(8): 12
	c->tid = next_tid(c->tid);
	// c->tid: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 4
	// c->tid: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 4
	// c->tid: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 12

	local_irq_restore(flags);
	// flags에 저장된 cpsr 을 복원
	// flags에 저장된 cpsr 을 복원
	// flags에 저장된 cpsr 을 복원

	// freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	return freelist;
	// return UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// return UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// return UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968

new_slab:

	// c->partial: (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)->partial: 0
	// c->partial: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)->partial: 0
	// c->partial: (&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)->partial: 0
	if (c->partial) {
		page = c->page = c->partial;
		c->partial = page->next;
		stat(s, CPU_PARTIAL_ALLOC);
		c->freelist = NULL;
		goto redo;
	}

	// s: &boot_kmem_cache_node, gfpflags: GFP_KERNEL: 0xD0, node: -1,
	// c: (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// new_slab_objects(&boot_kmem_cache_node, GFP_KERNEL: 0xD0, -1,
	// (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)):
	// UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// s: &boot_kmem_cache, gfpflags: __GFP_ZERO: 0x8000, node: -1,
	// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// new_slab_objects(&boot_kmem_cache, __GFP_ZERO: 0x8000, -1,
	// (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)):
	// UNMOVABLE인 page (boot_kmem_cache)의 virtual address
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000, node: -1,
	// c: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// new_slab_objects(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, __GFP_ZERO: 0x8000, -1,
	// (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	freelist = new_slab_objects(s, gfpflags, node, &c);
	// freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 virtual address
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968

	// new_slab_objects(&boot_kmem_cache_node)이 한일:
	// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
	// (UNMOVABLE인 page 의 object의 시작 virtual address + 64)
	// page->counters: 0x80400040
	// page->inuse: 64
	// page->objects: 64
	// page->frozen: 1
	// page->freelist: NULL
	// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
	// n->nr_partial: 0
	// c->page: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page
	
	// new_slab_objects(&boot_kmem_cache)이 한일:
	// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
	// migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache) 할당 받음
	// (UNMOVABLE인 page (boot_kmem_cache)의 virtual address)
	// 이전에 할당 받은 MIGRATE_UNMOVABLE인 page의 두번째 object의 맴버 필드값을 변경
	// n->nr_slabs: 1
	// n->total_objects: 32
	// 새로 받은 page의 맴버 필드 값 세팅
	// slab 의 objects 들의 freepointer를 맵핑함
	// page->slab_cache: &boot_kmem_cache주소를 set
	// page->freelist: NULL
	// page->inuse: 32
	// page->frozen: 1
	// page->flags에 7 (PG_slab) bit를 set

	// new_slab_objects(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)이 한일:
	// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
	// (UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968)
	// UNMOVABLE인 page (boot_kmem_cache)의 맴버 필드 값 세팅
	// page->freelist: NULL
	// page->counters: 0x80200020
	// page->inuse: 32
	// page->objects: 32
	// page->frozen: 1
	// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page (boot_kmem_cache))->lru 를 삭제
	// n->nr_partial: 0
	// c->page: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)

	// freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 virtual address
	// freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	if (unlikely(!freelist)) {
		if (!(gfpflags & __GFP_NOWARN) && printk_ratelimit())
			slab_out_of_memory(s, gfpflags, node);

		local_irq_restore(flags);
		return NULL;
	}

	// c->page: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page
	// c->page: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	// c->page: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	page = c->page;
	// page: MIGRATE_UNMOVABLE인 page
	// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache)

	// s: &boot_kmem_cache_node, kmem_cache_debug(&boot_kmem_cache_node): 0
	// page: MIGRATE_UNMOVABLE인 page, gfpflags: GFP_KERNEL: 0xD0
	// pfmemalloc_match(MIGRATE_UNMOVABLE인 page, GFP_KERNEL: 0xD0): 1
	// s: &boot_kmem_cache, kmem_cache_debug(&boot_kmem_cache): 0
	// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache), gfpflags: __GFP_ZERO: 0x8000
	// pfmemalloc_match(MIGRATE_UNMOVABLE인 page(boot_kmem_cache), __GFP_ZERO: 0x8000): 1
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// kmem_cache_debug(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address): 0
	// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache), gfpflags: __GFP_ZERO: 0x8000
	// pfmemalloc_match(MIGRATE_UNMOVABLE인 page(boot_kmem_cache), __GFP_ZERO: 0x8000): 1
	if (likely(!kmem_cache_debug(s) && pfmemalloc_match(page, gfpflags)))
		goto load_freelist;
		// load_freelist 심볼로 점프
		// load_freelist 심볼로 점프
		// load_freelist 심볼로 점프

	/* Only entered in the debug case */
	if (kmem_cache_debug(s) &&
			!alloc_debug_processing(s, page, freelist, addr))
		goto new_slab;	/* Slab failed checks. Next slab needed */

	deactivate_slab(s, page, get_freepointer(s, freelist));
	c->page = NULL;
	c->freelist = NULL;
	local_irq_restore(flags);
	return freelist;
}

/*
 * Inlined fastpath so that allocation functions (kmalloc, kmem_cache_alloc)
 * have the fastpath folded into their functions. So no function call
 * overhead for requests that can be satisfied on the fastpath.
 *
 * The fastpath works by first checking if the lockless freelist can be used.
 * If not then __slab_alloc is called for slow processing.
 *
 * Otherwise we can simply pick the next object from the lockless free list.
 */
// ARM10C 20140614
// s: &boot_kmem_cache_node, gfpflags: GFP_KERNEL: 0xD0, NUMA_NO_NODE: -1, _RET_IP_
// ARM10C 20140628
// s: &boot_kmem_cache, gfpflags: __GFP_ZERO: 0x8000, NUMA_NO_NODE: -1, _RET_IP_
// ARM10C 20140705
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// gfpflags: __GFP_ZERO: 0x8000, NUMA_NO_NODE: -1, _RET_IP_
// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
// gfpflags: __GFP_ZERO: 0x8000, NUMA_NO_NODE: -1, _RET_IP_
static __always_inline void *slab_alloc_node(struct kmem_cache *s,
		gfp_t gfpflags, int node, unsigned long addr)
{
	void **object;
	struct kmem_cache_cpu *c;
	struct page *page;
	unsigned long tid;

	// s: &boot_kmem_cache_node, gfpflags: GFP_KERNEL: 0xD0
	// slab_pre_alloc_hook(&boot_kmem_cache_node, 0xD0): 0
	// s: &boot_kmem_cache, gfpflags: __GFP_ZERO: 0x8000
	// slab_pre_alloc_hook(&boot_kmem_cache, 0x8000): 0
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000
	// slab_pre_alloc_hook(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, 0x8000): 0
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000
	// slab_pre_alloc_hook(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, 0x8000): 0
	if (slab_pre_alloc_hook(s, gfpflags))
		return NULL;

	// s: &boot_kmem_cache_node, gfpflags: GFP_KERNEL: 0xD0
	// memcg_kmem_get_cache(&boot_kmem_cache_node, 0xD0): &boot_kmem_cache_node
	// s: &boot_kmem_cache, gfpflags: __GFP_ZERO: 0x8000
	// memcg_kmem_get_cache(&boot_kmem_cache, 0x8000): &boot_kmem_cache
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000
	// memcg_kmem_get_cache(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, 0x8000):
	// UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000
	// memcg_kmem_get_cache(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, 0x8000):
	// UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	s = memcg_kmem_get_cache(s, gfpflags);
	// s: &boot_kmem_cache_node
	// s: &boot_kmem_cache
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
redo:
	/*
	 * Must read kmem_cache cpu data via this cpu ptr. Preemption is
	 * enabled. We may switch back and forth between cpus while
	 * reading from one cpu area. That does not matter as long
	 * as we end up on the original cpu again when doing the cmpxchg.
	 *
	 * Preemption is disabled for the retrieval of the tid because that
	 * must occur from the current processor. We cannot allow rescheduling
	 * on a different processor between the determination of the pointer
	 * and the retrieval of the tid.
	 */
	preempt_disable();
	// 선점 카운트 증가, barrier 적용
	// 선점 카운트 증가, barrier 적용
	// 선점 카운트 증가, barrier 적용
	// 선점 카운트 증가, barrier 적용

	// s->cpu_slab: (&boot_kmem_cache_node)->cpu_slab: 0xc0502d00
	// __this_cpu_ptr((&boot_kmem_cache_node)->cpu_slab: 0xc0502d00):
	// (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// s->cpu_slab: (&boot_kmem_cache)->cpu_slab: 0xc0502d10
	// __this_cpu_ptr((&boot_kmem_cache)->cpu_slab: 0xc0502d10):
	// (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// s->cpu_slab: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab: 0xc0502d10
	// __this_cpu_ptr((&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab: 0xc0502d10):
	// (&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab
	// + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// s->cpu_slab: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab: 0xc0502d10
	// __this_cpu_ptr((&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab: 0xc0502d10):
	// (&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab
	// + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	c = __this_cpu_ptr(s->cpu_slab);
	// c: (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c: (&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab
	// + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c: (&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab
	// + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)

	/*
	 * The transaction ids are globally unique per cpu and per operation on
	 * a per cpu queue. Thus they can be guarantee that the cmpxchg_double
	 * occurs on the right processor and that there was no operation on the
	 * linked list in between.
	 */
	// c->tid: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 0
	// c->tid: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 0
	// c->tid: ((&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab
	// + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 8
	// c->tid: ((&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab
	// + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 12
	tid = c->tid;
	// tid: 0
	// tid: 0
	// tid: 8
	// tid: 12

	preempt_enable();
	// barrier 적용, 선점 카운트 감소, should_resched 수행
	// barrier 적용, 선점 카운트 감소, should_resched 수행
	// barrier 적용, 선점 카운트 감소, should_resched 수행
	// barrier 적용, 선점 카운트 감소, should_resched 수행

	// c->freelist: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist: 0
	// c->freelist: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist: 0
	// c->freelist: ((&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] +__per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist: NULL
	// c->freelist: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
	object = c->freelist;
	// object: 0
	// object: 0
	// object: NULL
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840

	// c->page: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: 0
	// c->page: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: 0
	// c->page: ((&UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: NULL
	// c->page: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	page = c->page;
	// page: 0
	// page: 0
	// page: NULL
	// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache)

	// c->freelist, c->page 의 값을 초기화?:
	// pcpu_populate_chunk에서 초기화 하고 왔음

	// object: 0, page: 0, node: -1, node_match(0, -1): 1
	// object: 0, page: 0, node: -1, node_match(0, -1): 1
	// object: 0, page: 0, node: -1, node_match(0, -1): 1
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840,
	// page: MIGRATE_UNMOVABLE인 page (boot_kmem_cache), node: -1, node_match(0, -1): 1
	if (unlikely(!object || !node_match(page, node)))
		// s: &boot_kmem_cache_node, gfpflags: GFP_KERNEL: 0xD0, node: -1, addr: _RET_IP_,
		// c: (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
		// __slab_alloc(&boot_kmem_cache_node, GFP_KERNEL: 0xD0, -1, _RET_IP_,
		// (&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)):
		// UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// s: &boot_kmem_cache, gfpflags: __GFP_ZERO: 0x8000, node: -1, addr: _RET_IP_,
		// c: (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
		// __slab_alloc(&boot_kmem_cache, __GFP_ZERO: 0x8000, -1, _RET_IP_,
		// (&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)):
		// UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
		// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000, node: -1, addr: _RET_IP_,
		// c: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
		// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
		// __slab_alloc(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, __GFP_ZERO: 0x8000, -1, _RET_IP_,
		// (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)):
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
		// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000, node: -1, addr: _RET_IP_,
		// c: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
		// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
		// __slab_alloc(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, __GFP_ZERO: 0x8000, -1, _RET_IP_,
		// (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)):
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 128
		object = __slab_alloc(s, gfpflags, node, addr, c);
		// object: UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// object: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
		// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
		
		// __slab_alloc(&boot_kmem_cache_node)이 한일:
		// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
		// (UNMOVABLE인 page 의 object의 시작 virtual address + 64)
		// page->counters: 0x80400040
		// page->inuse: 64
		// page->objects: 64
		// page->frozen: 1
		// page->freelist: NULL
		// c->page: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
		// MIGRATE_UNMOVABLE인 page
		// c->freelist: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
		// UNMOVABLE인 page 의 object의 시작 virtual address + 128
		// c->tid: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 4
		// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
		// n->nr_partial: 0
		
		// __slab_alloc(&boot_kmem_cache)이 한일:
		// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
		// migratetype이 MIGRATE_UNMOVABLE인 page (boot_kmem_cache) 할당 받음
		// (UNMOVABLE인 page (boot_kmem_cache)의 virtual address)
		// 이전에 할당 받은 MIGRATE_UNMOVABLE인 page의 두번째 object의 맴버 필드값을 변경
		// n->nr_slabs: 1
		// n->total_objects: 32
		// slab 의 objects 들의 freepointer를 맵핑함
		// 새로 받은 page의 맴버 필드 값 세팅
		// page->slab_cache: &boot_kmem_cache주소를 set
		// page->freelist: NULL
		// page->inuse: 32
		// page->frozen: 1
		// page->flags에 7 (PG_slab) bit를 set
		// c->page: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
		// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
		// c->freelist: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 128
		// c->tid: ((&boot_kmem_cache)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 4

// 2014/07/05 종료
// 2014/07/12 시작

		// __slab_alloc(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)이 한일:
		// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
		// (UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968)
		// UNMOVABLE인 page (boot_kmem_cache)의 맴버 필드 값 세팅
		// page->freelist: NULL
		// page->counters: 0x80200020
		// page->inuse: 32
		// page->frozen: 1
		// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page (boot_kmem_cache))->lru 를 삭제
		// n->nr_partial: 0
		// c->page: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
		// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
		// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
		// c->freelist: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
		// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
		// c->tid: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
		// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 12
	else {
		// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
		// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840,
		// get_freepointer_safe(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840):
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712
		void *next_object = get_freepointer_safe(s, object);
		// next_object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712

		/*
		 * The cmpxchg will only match if there was no additional
		 * operation and if we are on the right processor.
		 *
		 * The cmpxchg does the following atomically (without lock
		 * semantics!)
		 * 1. Relocate first pointer to the current per cpu area.
		 * 2. Verify that tid and freelist have not been changed
		 * 3. If they were not changed replace tid and freelist
		 *
		 * Since this is without lock semantics the protection is only
		 * against code executing on this cpu *not* from access by
		 * other cpus.
		 */
		// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
		// s->cpu_slab: (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab: 0xc0502d10
		//
		// s->cpu_slab->freelist: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840,
		// s->cpu_slab->tid: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 12,
		// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840,
		// tid: 12,
		// next_object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712,
		// next_tid(12): 16
		// this_cpu_cmpxchg_double(((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist,
		// ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid,
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840, 12,
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712, 16):
		// freelist와 tid 값을 변경함
		// s->cpu_slab->freelist: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
		// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712,
		// s->cpu_slab->tid: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 12,
		// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840,
		// tid: 16,
		if (unlikely(!this_cpu_cmpxchg_double(
				s->cpu_slab->freelist, s->cpu_slab->tid,
				object, tid,
				next_object, next_tid(tid)))) {

			note_cmpxchg_failure("slab_alloc", s, tid);
			goto redo;
		}

		// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
		// next_object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712
		prefetch_freepointer(s, next_object);
		// cache table에 UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3712 page 주소를 넣음

		// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, ALLOC_FASTPATH: 0
		stat(s, ALLOC_FASTPATH);
	}

	// gfpflags: GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u
	// object: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// gfpflags: __GFP_ZERO: 0x8000, __GFP_ZERO: 0x8000u
	// object: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// gfpflags: __GFP_ZERO: 0x8000, __GFP_ZERO: 0x8000u
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// gfpflags: __GFP_ZERO: 0x8000, __GFP_ZERO: 0x8000u
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
	if (unlikely(gfpflags & __GFP_ZERO) && object)
		// object: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
		// s->object_size: boot_kmem_cache.object_size: 116
		// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
		// s->object_size: (UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address)->object_size: 116
		// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
		// s->object_size: (UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address)->object_size: 116
		memset(object, 0, s->object_size);
		// object를 0 으로 초기화 수행
		// object를 0 으로 초기화 수행
		// object를 0 으로 초기화 수행

	// s: &boot_kmem_cache_node, gfpflags: GFP_KERNEL: 0xD0,
	// object: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// s: &boot_kmem_cache, gfpflags: __GFP_ZERO: 0x8000,
	// object: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// s: &boot_kmem_cache_node, gfpflags: __GFP_ZERO: 0x8000,
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000,
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
	slab_post_alloc_hook(s, gfpflags, object);

	// object: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// object: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// object: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
	return object;
	// return UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// return UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// return UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// return UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
}

// ARM10C 20140614
// s: &boot_kmem_cache_node, gfpflags: GFP_KERNEL: 0xD0, _RET_IP_
// ARM10C 20140628
// s: &boot_kmem_cache, gfpflags: __GFP_ZERO: 0x8000, _RET_IP_
// ARM10C 20140705
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000, _RET_IP_
// ARM10C 20140719
// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000
// ARM10C 20140726
// s: kmem_cache#30, gfpflags: GFP_NOWAIT: 0, _RET_IP_
// ARM10C 20140920
// s: kmem_cache#30, gfpflags: GFP_KERNEL: 0xD0, _RET_IP_
// ARM10C 20141206
// s: kmem_cache#26, flags: 0x80D0, _RET_IP_
static __always_inline void *slab_alloc(struct kmem_cache *s,
		gfp_t gfpflags, unsigned long addr)
{
	// s: &boot_kmem_cache_node, gfpflags: GFP_KERNEL: 0xD0, NUMA_NO_NODE: -1, _RET_IP_
	// slab_alloc_node(&boot_kmem_cache_node, GFP_KERNEL: 0xD0, -1, _RET_IP_):
	// UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// s: &boot_kmem_cache, gfpflags: __GFP_ZERO: 0x8000, NUMA_NO_NODE: -1, _RET_IP_
	// slab_alloc_node(&boot_kmem_cache, __GFP_ZERO: 0x8000, -1, _RET_IP_):
	// UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// gfpflags: __GFP_ZERO: 0x8000, NUMA_NO_NODE: -1, _RET_IP_
	// slab_alloc_node(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// __GFP_ZERO: 0x8000, -1, _RET_IP_):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// gfpflags: __GFP_ZERO: 0x8000, NUMA_NO_NODE: -1, _RET_IP_
	// slab_alloc_node(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// __GFP_ZERO: 0x8000, -1, _RET_IP_):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840,
	// s: kmem_cache#30, gfpflags: GFP_NOWAIT: 0, NUMA_NO_NODE: -1, _RET_IP_
	// slab_alloc_node(kmem_cache#30, GFP_NOWAIT: 0, -1, _RET_IP_):
	// UNMOVABLE인 page (kmem_cache#30)의 시작 virtual address (kmem_cache#30-o0)
	return slab_alloc_node(s, gfpflags, NUMA_NO_NODE, addr);
	// return UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// return UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// return UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// return UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840,
	// return UNMOVABLE인 page (kmem_cache#30)의 시작 virtual address (kmem_cache#30-o0)
	//
	// kmem_cache#30-o0 의미:
	// kmem_cache#30가 관리하는 UNMOVABLE인 page (kmem_cache#30)의 object 들 중에 1 번째 object의 주소를 의미함
}

// ARM10C 20140614
// s: &boot_kmem_cache_node, flags: GFP_KERNEL: 0xD0
// ARM10C 20140628
// k: &boot_kmem_cache, flags: 0x8000
// ARM10C 20140705
// k: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, flags: __GFP_ZERO: 0x8000u
// ARM10C 20140719
// k: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, flags: __GFP_ZERO: 0x8000u
// ARM10C 20140726
// s: kmem_cache#26, flags: 0x80D0
// ARM10C 20140809
// s: kmem_cache#30, flags: 0x8000
// ARM10C 20141004
// s: kmem_cache#28, 0x80D0
// ARM10C 20141004
// radix_tree_node_cachep: kmem_cache#20, gfp_mask: GFP_KERNEL: 0xD0
void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
{
	// s: &boot_kmem_cache_node, gfpflags: GFP_KERNEL: 0xD0
	// slab_alloc(&boot_kmem_cache_node, GFP_KERNEL: 0xD0): UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// s: &boot_kmem_cache, gfpflags: __GFP_ZERO: 0x8000
	// slab_alloc(&boot_kmem_cache, __GFP_ZERO: 0x8000): UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000
	// slab_alloc(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, __GFP_ZERO: 0x8000):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, gfpflags: __GFP_ZERO: 0x8000
	// slab_alloc(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, __GFP_ZERO: 0x8000):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
	// s: kmem_cache#26, gfpflags: GFP_KERNEL | __GFP_ZERO: 0x80D0
	// slab_alloc(kmem_cache#26, GFP_KERNEL | __GFP_ZERO: 0x80D0):
	// UNMOVABLE인 page 1(kmem_cache#6)의 시작 virtual address
	// s: kmem_cache#30, gfpflags: __GFP_ZERO: 0x8000
	// slab_alloc(kmem_cache#30, __GFP_ZERO: 0x8000):
	// UNMOVABLE인 page (kmem_cache#30)의 시작 virtual address
	void *ret = slab_alloc(s, gfpflags, _RET_IP_);
	// ret: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// ret: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// ret: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// ret: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
	// ret: UNMOVABLE인 page (kmem_cache#26)의 시작 virtual address (kmem_cache#26-o0)
	// ret: UNMOVABLE인 page (kmem_cache#30)의 시작 virtual address (kmem_cache#30-o9)

	// ret: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// s->object_size: boot_kmem_cache_node.object_size: 44,
	// s->size: boot_kmem_cache_node.size: 64,
	// gfpflags: GFP_KERNEL: 0xD0
	// ret: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// s->object_size: boot_kmem_cache.object_size: 116,
	// s->size: boot_kmem_cache.size: 128,
	// gfpflags: __GFP_ZERO: 0x8000
	// ret: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// s->object_size: (UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address)->object_size: 116,
	// s->size: (UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address)->size: 128,
	// gfpflags: __GFP_ZERO: 0x8000
	// ret: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
	// s->object_size: (UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address)->object_size: 116,
	// s->size: (UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address)->size: 128,
	// gfpflags: __GFP_ZERO: 0x8000
	// ret: kmem_cache#26-o0
	// s->object_size: (kmem_cache#26)->object_size: 512,
	// s->size: (kmem_cache#26)->size: 512,
	// gfpflags: GFP_KERNEL | __GFP_ZERO: 0x80D0
	// ret: kmem_cache#30-o9
	// s->object_size: (kmem_cache#30)->object_size: 52,
	// s->size: (kmem_cache#30)->size: 64,
	// gfpflags: __GFP_ZERO: 0x8000
	trace_kmem_cache_alloc(_RET_IP_, ret, s->object_size,
				s->size, gfpflags);

	// ret: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// ret: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// ret: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// ret: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
	// ret: kmem_cache#26-o0
	// ret: kmem_cache#30-o9
	return ret;
	// return UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// return UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// return UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// return UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
	// return kmem_cache#26-o0
	// return kmem_cache#30-o9
}
EXPORT_SYMBOL(kmem_cache_alloc);

#ifdef CONFIG_TRACING
void *kmem_cache_alloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
{
	void *ret = slab_alloc(s, gfpflags, _RET_IP_);
	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags);
	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc_trace);
#endif

#ifdef CONFIG_NUMA
void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
{
	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_);

	trace_kmem_cache_alloc_node(_RET_IP_, ret,
				    s->object_size, s->size, gfpflags, node);

	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc_node);

#ifdef CONFIG_TRACING
void *kmem_cache_alloc_node_trace(struct kmem_cache *s,
				    gfp_t gfpflags,
				    int node, size_t size)
{
	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_);

	trace_kmalloc_node(_RET_IP_, ret,
			   size, s->size, gfpflags, node);
	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc_node_trace);
#endif
#endif

/*
 * Slow patch handling. This may still be called frequently since objects
 * have a longer lifetime than the cpu slabs in most processing loads.
 *
 * So we still attempt to reduce cache line usage. Just take the slab
 * lock and free the item. If there is no additional partial page
 * handling required then we can return immediately.
 */
static void __slab_free(struct kmem_cache *s, struct page *page,
			void *x, unsigned long addr)
{
	void *prior;
	void **object = (void *)x;
	int was_frozen;
	struct page new;
	unsigned long counters;
	struct kmem_cache_node *n = NULL;
	unsigned long uninitialized_var(flags);

	stat(s, FREE_SLOWPATH);

	if (kmem_cache_debug(s) &&
		!(n = free_debug_processing(s, page, x, addr, &flags)))
		return;

	do {
		if (unlikely(n)) {
			spin_unlock_irqrestore(&n->list_lock, flags);
			n = NULL;
		}
		prior = page->freelist;
		counters = page->counters;
		set_freepointer(s, object, prior);
		new.counters = counters;
		was_frozen = new.frozen;
		new.inuse--;
		if ((!new.inuse || !prior) && !was_frozen) {

			if (kmem_cache_has_cpu_partial(s) && !prior)

				/*
				 * Slab was on no list before and will be
				 * partially empty
				 * We can defer the list move and instead
				 * freeze it.
				 */
				new.frozen = 1;

			else { /* Needs to be taken off a list */

	                        n = get_node(s, page_to_nid(page));
				/*
				 * Speculatively acquire the list_lock.
				 * If the cmpxchg does not succeed then we may
				 * drop the list_lock without any processing.
				 *
				 * Otherwise the list_lock will synchronize with
				 * other processors updating the list of slabs.
				 */
				spin_lock_irqsave(&n->list_lock, flags);

			}
		}

	} while (!cmpxchg_double_slab(s, page,
		prior, counters,
		object, new.counters,
		"__slab_free"));

	if (likely(!n)) {

		/*
		 * If we just froze the page then put it onto the
		 * per cpu partial list.
		 */
		if (new.frozen && !was_frozen) {
			put_cpu_partial(s, page, 1);
			stat(s, CPU_PARTIAL_FREE);
		}
		/*
		 * The list lock was not taken therefore no list
		 * activity can be necessary.
		 */
                if (was_frozen)
                        stat(s, FREE_FROZEN);
                return;
        }

	if (unlikely(!new.inuse && n->nr_partial > s->min_partial))
		goto slab_empty;

	/*
	 * Objects left in the slab. If it was not on the partial list before
	 * then add it.
	 */
	if (!kmem_cache_has_cpu_partial(s) && unlikely(!prior)) {
		if (kmem_cache_debug(s))
			remove_full(s, page);
		add_partial(n, page, DEACTIVATE_TO_TAIL);
		stat(s, FREE_ADD_PARTIAL);
	}
	spin_unlock_irqrestore(&n->list_lock, flags);
	return;

slab_empty:
	if (prior) {
		/*
		 * Slab on the partial list.
		 */
		remove_partial(n, page);
		stat(s, FREE_REMOVE_PARTIAL);
	} else
		/* Slab must be on the full list */
		remove_full(s, page);

	spin_unlock_irqrestore(&n->list_lock, flags);
	stat(s, FREE_SLAB);
	discard_slab(s, page);
}

/*
 * Fastpath with forced inlining to produce a kfree and kmem_cache_free that
 * can perform fastpath freeing without additional function calls.
 *
 * The fastpath is only possible if we are freeing to the current cpu slab
 * of this processor. This typically the case if we have just allocated
 * the item before.
 *
 * If fastpath is not possible then fall back to __slab_free where we deal
 * with all sorts of special processing.
 */
// ARM10C 20141206
// page->slab_cache: (kmem_cache#30-o11의 page 주소)->slab_cache,
// page: kmem_cache#30-o11의 page 주소, object: kmem_cache#30-o11, _RET_IP_
static __always_inline void slab_free(struct kmem_cache *s,
			struct page *page, void *x, unsigned long addr)
{
	// x: kmem_cache#30-o11
	void **object = (void *)x;
	// object: kmem_cache#30-o11

	struct kmem_cache_cpu *c;
	unsigned long tid;

	// s: kmem_cache#30, x: kmem_cache#30-o11
	slab_free_hook(s, x);

redo:
	/*
	 * Determine the currently cpus per cpu slab.
	 * The cpu may change afterward. However that does not matter since
	 * data is retrieved via this pointer. If we are on the same cpu
	 * during the cmpxchg then the free will succedd.
	 */
	preempt_disable();
	// 선점 비활성화 수행

	// NOTE:
	// s->cpu_slab: (kmem_cache#30)->cpu_slab:
	// struct kmem_cache_cpu 자료구조를 사용하기 위해 할당받은 pcp 16 byte 메모리 공간

	// s->cpu_slab: (kmem_cache#30)->cpu_slab
	// __this_cpu_ptr((kmem_cache#30)->cpu_slab):
	// (kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋
	c = __this_cpu_ptr(s->cpu_slab);
	// c: (kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋

	// c->tid: ((kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)->tid
	tid = c->tid;
	// tid: XX (추적불가)

	preempt_enable();
	// 선점 활성화 수행

	// NOTE:
	// likely(page == c->page)는 likely로 싸여 있는 것으로 보아
	// page == c->page 가 같을 확율이 높다고 판단됨. page, c->page 값이 같다고 보고 코드 분석 진행

	// page: kmem_cache#30-o11의 page 주소,
	// c->page: ((kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)->page
	if (likely(page == c->page)) {
		// s: kmem_cache#30, object: kmem_cache#30-o11,
		// c->freelist: ((kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)->freelist
		set_freepointer(s, object, c->freelist);
		// kmem_cache#30-o11의 freepointer의 값을
		// ((kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)->freelist 값으로 세팅

		// s->cpu_slab->freelist: (kmem_cache#30)->cpu_slab->freelist,
		// s->cpu_slab->tid: (kmem_cache#30)->cpu_slab->tid,
		// c->freelist: ((kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)->freelist,
		// tid: XX, object: kmem_cache#30-o11, next_tid(tid): XX
		// this_cpu_cmpxchg_double((kmem_cache#30)->cpu_slab->freelist, (kmem_cache#30)->cpu_slab->tid,
		// ((kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)->freelist,
		// XX, kmem_cache#30-o11, XX): 1
		if (unlikely(!this_cpu_cmpxchg_double(
				s->cpu_slab->freelist, s->cpu_slab->tid,
				c->freelist, tid,
				object, next_tid(tid)))) {

			note_cmpxchg_failure("slab_free", s, tid);
			goto redo;
		}
		// this_cpu_cmpxchg_double에서 한일:
		// 값 s->cpu_slab->freelist와 c->freelist를 비교, 값 s->cpu_slab->tid와 tid을 비교 하여
		// 같을 경우에 s->cpu_slab->freelist와 s->cpu_slab->tid을 각각 object, next_tid(tid) 값으로 갱신하여
		// freelist와 tid 값을 변경함

		// s: kmem_cache#30, FREE_FASTPATH: 2
		stat(s, FREE_FASTPATH); // null function
	} else
		__slab_free(s, page, x, addr);

}

void kmem_cache_free(struct kmem_cache *s, void *x)
{
	s = cache_from_obj(s, x);
	if (!s)
		return;
	slab_free(s, virt_to_head_page(x), x, _RET_IP_);
	trace_kmem_cache_free(_RET_IP_, x);
}
EXPORT_SYMBOL(kmem_cache_free);

/*
 * Object placement in a slab is made very easy because we always start at
 * offset 0. If we tune the size of the object to the alignment then we can
 * get the required alignment by putting one properly sized object after
 * another.
 *
 * Notice that the allocation order determines the sizes of the per cpu
 * caches. Each processor has always one slab available for allocations.
 * Increasing the allocation order reduces the number of times that slabs
 * must be moved on and off the partial lists and is therefore a factor in
 * locking overhead.
 */

/*
 * Mininum / Maximum order of slab pages. This influences locking overhead
 * and slab fragmentation. A higher order reduces the number of partial slabs
 * and increases the number of allocations possible without having to
 * take the list_lock.
 */
// ARM10C 20140419
// ARM10C 20140726
static int slub_min_order;
// ARM10C 20140419
// ARM10C 20140726
// PAGE_ALLOC_COSTLY_ORDER: 3
// slub_max_order: 3
static int slub_max_order = PAGE_ALLOC_COSTLY_ORDER;
// ARM10C 20140419
static int slub_min_objects;

/*
 * Merge control. If this is set then no merging of slab caches will occur.
 * (Could be removed. This was introduced to pacify the merge skeptics.)
 */
// ARM10C 20140920
static int slub_nomerge;

/*
 * Calculate the order of allocation given an slab object size.
 *
 * The order of allocation has significant impact on performance and other
 * system components. Generally order 0 allocations should be preferred since
 * order 0 does not cause fragmentation in the page allocator. Larger objects
 * be problematic to put into order 0 slabs because there may be too much
 * unused space left. We go to a higher order if more than 1/16th of the slab
 * would be wasted.
 *
 * In order to reach satisfactory performance we must ensure that a minimum
 * number of objects is in one slab. Otherwise we may generate too much
 * activity on the partial lists which requires taking the list_lock. This is
 * less a concern for large slabs though which are rarely used.
 *
 * slub_max_order specifies the order where we begin to stop considering the
 * number of objects in a slab as critical. If we reach slub_max_order then
 * we try to keep the page order as low as possible. So we accept more waste
 * of space in favor of a small page order.
 *
 * Higher order allocations also allow the placement of more objects in a
 * slab and thereby reduce object handling overhead. If the user has
 * requested a higher mininum order then we start with that one instead of
 * the smallest order which will fit the object.
 */
// ARM10C 20140419
// size: 64, min_objects: 16, slub_max_order: 3
// fraction: 16, reserved: 0
// ARM10C 20140614
// size: 128, min_objects: 16, slub_max_order: 3
// fraction: 16, reserved: 0
// ARM10C 20140726
// size: 4096, min_objects: 8, slub_max_order: 3
// fraction: 16, reserved: 0
// ARM10C 20140920
// size: 1080, min_objects: 16, slub_max_order: 3
// fraction: 16, reserved: 0
static inline int slab_order(int size, int min_objects,
				int max_order, int fract_leftover, int reserved)
{
	int order;
	int rem;
	// slub_min_order: 0
	// slub_min_order: 0
	// slub_min_order: 0
	// slub_min_order: 0
	int min_order = slub_min_order;
	// min_order: 0
	// min_order: 0
	// min_order: 0
	// min_order: 0

	// min_order: 0, size: 64, reserved: 0
	// order_objects(0, 64, 0): 0x40, MAX_OBJS_PER_PAGE: 32767 (0x7fff)
	// min_order: 0, size: 192, reserved: 0
	// order_objects(0, 128, 0): 0x20, MAX_OBJS_PER_PAGE: 32767 (0x7fff)
	// min_order: 0, size: 4096, reserved: 0
	// order_objects(0, 4096, 0): 0x1, MAX_OBJS_PER_PAGE: 32767 (0x7fff)
	// min_order: 0, size: 1080, reserved: 0
	// order_objects(0, 1080, 0): 0x3, MAX_OBJS_PER_PAGE: 32767 (0x7fff)
	if (order_objects(min_order, size, reserved) > MAX_OBJS_PER_PAGE)
		return get_order(size * MAX_OBJS_PER_PAGE) - 1;

	// order_objects 하는 일:
	// 현재 order 에서 reserved를 제외한 공간에서 요청된 size를 가진 사용할 수있는 object의 수를 구함

	// min_order: 0, min_objects: 16, size: 64, fls(0x3ff): 10, PAGE_SHIFT: 12
	// order: 0, max_order: 3
	// min_order: 0, min_objects: 16, size: 128, fls(0x7ff): 11, PAGE_SHIFT: 12
	// order: 0, max_order: 3
	// min_order: 0, min_objects: 8, size: 4096, fls(0x7fff): 15, PAGE_SHIFT: 12
	// order: 3, max_order: 3
	// min_order: 0, min_objects: 16, size: 1080, fls(0x437f): 15, PAGE_SHIFT: 12
	// order: 3, max_order: 3
	for (order = max(min_order,
				fls(min_objects * size - 1) - PAGE_SHIFT);
			order <= max_order; order++) {
		// PAGE_SIZE: 0x1000, order: 0
		// PAGE_SIZE: 0x1000, order: 0
		// PAGE_SIZE: 0x1000, order: 3
		// PAGE_SIZE: 0x1000, order: 3
		unsigned long slab_size = PAGE_SIZE << order;
		// slab_size: 0x1000
		// slab_size: 0x1000
		// slab_size: 0x8000
		// slab_size: 0x8000

		// slab_size: 0x1000, min_objects: 16, size: 64, reserved: 0
		// slab_size: 0x1000, min_objects: 16, size: 128, reserved: 0
		// slab_size: 0x8000, min_objects: 8, size: 4096, reserved: 0
		// slab_size: 0x8000, min_objects: 16, size: 1080, reserved: 0
		if (slab_size < min_objects * size + reserved)
			continue;

		// slab_size: 0x1000, reserved: 0, size: 64
		// slab_size: 0x1000, reserved: 0, size: 128
		// slab_size: 0x8000, reserved: 0, size: 4096
		// slab_size: 0x8000, reserved: 0, size: 1080
		rem = (slab_size - reserved) % size;
		// rem: 0
		// rem: 0
		// rem: 0
		// rem: 368

		// rem: 0, slab_size: 0x1000, fract_leftover: 16
		// rem: 0, slab_size: 0x1000, fract_leftover: 16
		// rem: 0, slab_size: 0x8000, fract_leftover: 16
		// rem: 368, slab_size: 0x8000, fract_leftover: 16
		if (rem <= slab_size / fract_leftover)
			break;
			// 빠져나감
			// 빠져나감
			// 빠져나감
			// 빠져나감
		
		// if (rem <= slab_size / fract_leftover) 의미?:
		// slab object를 나누고 남은 나머지의 공간이 slab_size의 fract_leftover 로 나눈 값보다 크면
		// 메모리 내부 단편화 문제 발생함. 그럴바에는 order 올려서 내부 단편화를 없애도록 함
	}

	// max(min_order, fls(min_objects * size - 1) - PAGE_SHIFT) 의미?:
	// 최소 min_objects개수와 size 를 곱한 계산 결과에 따른 buddy order의 값을 구함

	// order: 0
	// order: 0
	// order: 3
	// order: 3
	return order;
	// return 0
	// return 0
	// return 3
	// return 3
}

// ARM10C 20140419
// size: 64, s->reserved: boot_kmem_cache_node.reserved: 0
// ARM10C 20140614
// size: 128, s->reserved: boot_kmem_cache.reserved: 0
// ARM10C 20140726
// size: 64, s->reserved: kmem_cache#30.reserved: 0
// ARM10C 20140726
// size: 4096, s->reserved: kmem_cache#23.reserved: 0
// ARM10C 20140920
// size: 1080, s->reserved: kmem_cache#21.reserved: 0
static inline int calculate_order(int size, int reserved)
{
	int order;
	int min_objects;
	int fraction;
	int max_objects;

	/*
	 * Attempt to find best configuration for a slab. This
	 * works by first attempting to generate a layout with
	 * the best configuration and backing off gradually.
	 *
	 * First we reduce the acceptable waste in a slab. Then
	 * we reduce the minimum objects required in a slab.
	 */
	// slub_min_objects: 0
	// slub_min_objects: 0
	// slub_min_objects: 0
	// slub_min_objects: 0
	// slub_min_objects: 0
	min_objects = slub_min_objects;
	// min_objects: 0
	// min_objects: 0
	// min_objects: 0
	// min_objects: 0
	// min_objects: 0

	if (!min_objects)
		// nr_cpu_ids: 4, fls(4): 3
		// nr_cpu_ids: 4, fls(4): 3
		// nr_cpu_ids: 4, fls(4): 3
		// nr_cpu_ids: 4, fls(4): 3
		// nr_cpu_ids: 4, fls(4): 3
		min_objects = 4 * (fls(nr_cpu_ids) + 1);
		// min_objects: 16
		// min_objects: 16
		// min_objects: 16
		// min_objects: 16
		// min_objects: 16

	// slub_max_order: 3, size: 64, reserved: 0
	// slub_max_order: 3, size: 128, reserved: 0
	// slub_max_order: 3, size: 64, reserved: 0
	// slub_max_order: 3, size: 4096, reserved: 0
	// slub_max_order: 3, size: 1080, reserved: 0
	max_objects = order_objects(slub_max_order, size, reserved);
	// max_objects: 0x200
	// max_objects: 0x100
	// max_objects: 0x200
	// max_objects: 0x8
	// max_objects: 0x1e
	
	// min_objects: 16, max_objects: 0x200
	// min_objects: 16, max_objects: 0x100
	// min_objects: 16, max_objects: 0x200
	// min_objects: 16, max_objects: 0x8
	// min_objects: 16, max_objects: 0x1e
	min_objects = min(min_objects, max_objects);
	// min_objects: 16
	// min_objects: 16
	// min_objects: 16
	// min_objects: 8
	// min_objects: 16

	// min_objects: 16
	// min_objects: 16
	// min_objects: 16
	// min_objects: 8
	// min_objects: 16
	while (min_objects > 1) {
		fraction = 16;

		// fraction: 16
		// fraction: 16
		// fraction: 16
		// fraction: 16
		// fraction: 16
		while (fraction >= 4) {
			// size: 64, min_objects: 16, slub_max_order: 3
			// fraction: 16, reserved: 0
			// size: 128, min_objects: 16, slub_max_order: 3
			// fraction: 16, reserved: 0
			// size: 64, min_objects: 16, slub_max_order: 3
			// fraction: 16, reserved: 0
			// size: 4096, min_objects: 8, slub_max_order: 3
			// fraction: 16, reserved: 0
			// size: 1080, min_objects: 16, slub_max_order: 3
			// fraction: 16, reserved: 0
			order = slab_order(size, min_objects,
					slub_max_order, fraction, reserved);
			// order: 0
			// order: 0
			// order: 0
			// order: 3
			// order: 3

			// order: 0, slub_max_order: 3
			// order: 0, slub_max_order: 3
			// order: 0, slub_max_order: 3
			// order: 3, slub_max_order: 3
			// order: 3, slub_max_order: 3
			if (order <= slub_max_order)
				// order: 0
				// order: 0
				// order: 0
				// order: 3
				// order: 3
				return order;
				// return 0
				// return 0
				// return 0
				// return 3
				// return 3

			fraction /= 2;

			// fraction /= 2 의 의미?:
			// 내부 단편화를 줄이기 위해 사용하는 fraction을 줄여서 계산된
			// order 값이 max_order 값보다 작도록 함
		}
		min_objects--;

		// min_objects-- 의 의미?:
		// fraction 값을 줄여도 계산된 order가 max_order 보다 클 경우 min_objects 수를 줄임
	}


	/*
	 * We were unable to place multiple objects in a slab. Now
	 * lets see if we can place a single object there.
	 */
	order = slab_order(size, 1, slub_max_order, 1, reserved);
	if (order <= slub_max_order)
		return order;

	// slab의 object 를 1 개만 요청하여 사용하도록함
	// 계산된 order가 slub_max_order 보다 크다면 최대 order 조건을
	// MAX_ORDER로 주어 다시 order를 계산

	/*
	 * Doh this slab cannot be placed using slub_max_order.
	 */
	order = slab_order(size, 1, MAX_ORDER, 1, reserved);
	if (order < MAX_ORDER)
		return order;
	return -ENOSYS;
}

// ARM10C 20140531
// n: UNMOVABLE인 page 의 object의 시작 virtual address
// ARM10C 20140621
// n: UNMOVABLE인 page 의 object의 시작 virtual address + 64
// ARM10C 20140726
// n: kmem_cache_node#63
// ARM10C 20140920
// n: kmem_cache_node#54
static void
init_kmem_cache_node(struct kmem_cache_node *n)
{
	// n: UNMOVABLE인 page 의 object의 시작 virtual address
	// n: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// n: kmem_cache_node#63

	n->nr_partial = 0;
	// n->nr_partial: 0

	spin_lock_init(&n->list_lock);
	// n->list_lock: spinlock 초기화 수행

	INIT_LIST_HEAD(&n->partial);
	// n->partial: 리스트 초기화

#ifdef CONFIG_SLUB_DEBUG // CONFIG_SLUB_DEBUG=y
	atomic_long_set(&n->nr_slabs, 0);
	// n->nr_slabs: 0

	atomic_long_set(&n->total_objects, 0);
	// n->total_objects: 0

	INIT_LIST_HEAD(&n->full);
	// n->full: 리스트 초기화
#endif
}

// ARM10C 20140531
// s: &boot_kmem_cache_node
// ARM10C 20140621
// s: &boot_kmem_cache
// ARM10C 20140726
// s: &kmem_cache#30
// ARM10C 20140726
// s: &kmem_cache#23
// ARM10C 20140920
// s: &kmem_cache#21
static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
{
	// PERCPU_DYNAMIC_EARLY_SIZE: 0x3000, KMALLOC_SHIFT_HIGH: 13
	// sizeof(struct kmem_cache_cpu): 16 bytes
	BUILD_BUG_ON(PERCPU_DYNAMIC_EARLY_SIZE <
			KMALLOC_SHIFT_HIGH * sizeof(struct kmem_cache_cpu));

	/*
	 * Must align to double word boundary for the double cmpxchg
	 * instructions to work; see __pcpu_double_call_return_bool().
	 */
	// s->cpu_slab: (&boot_kmem_cache_node)->cpu_slab
	// sizeof(struct kmem_cache_cpu): 16 bytes, sizeof(void *): 8 bytes
	// __alloc_percpu(16, 8): 0xc0502d00
	// s->cpu_slab: (&boot_kmem_cache)->cpu_slab
	// sizeof(struct kmem_cache_cpu): 16 bytes, sizeof(void *): 8 bytes
	// __alloc_percpu(16, 8): 0xc0502d10
	// s->cpu_slab: (&kmem_cache#30)->cpu_slab
	// sizeof(struct kmem_cache_cpu): 16 bytes, sizeof(void *): 8 bytes
	// __alloc_percpu(16, 8): 0xc0502d20
	// s->cpu_slab: (&kmem_cache#23)->cpu_slab
	// sizeof(struct kmem_cache_cpu): 16 bytes, sizeof(void *): 8 bytes
	// __alloc_percpu(16, 8): 0xc0502d90
	// s->cpu_slab: (&kmem_cache#21)->cpu_slab
	// sizeof(struct kmem_cache_cpu): 16 bytes, sizeof(void *): 8 bytes
	// __alloc_percpu(16, 8): 0xc0502db0
	s->cpu_slab = __alloc_percpu(sizeof(struct kmem_cache_cpu),
				     2 * sizeof(void *));
	// s->cpu_slab: (&boot_kmem_cache_node)->cpu_slab: 0xc0502d00
	// s->cpu_slab: (&boot_kmem_cache)->cpu_slab: 0xc0502d10
	// s->cpu_slab: (&kmem_cache#30)->cpu_slab: 0xc0502d20
	// s->cpu_slab: (&kmem_cache#23)->cpu_slab: 0xc0502d90
	// s->cpu_slab: (&kmem_cache#21)->cpu_slab: 0xc0502db0

	// s->cpu_slab: (&boot_kmem_cache_node)->cpu_slab: 0xc0502d00
	// s->cpu_slab: (&boot_kmem_cache)->cpu_slab: 0xc0502d10
	// s->cpu_slab: (&kmem_cache#30)->cpu_slab: 0xc0502d20
	// s->cpu_slab: (&kmem_cache#23)->cpu_slab: 0xc0502d90
	// s->cpu_slab: (&kmem_cache#21)->cpu_slab: 0xc0502db0
	if (!s->cpu_slab)
		return 0;

	// s: &boot_kmem_cache_node
	// s: &boot_kmem_cache
	// s: &kmem_cache#30
	// s: &kmem_cache#23
	// s: &kmem_cache#21
	init_kmem_cache_cpus(s);
	// 할당받은 pcpu 들의 16 byte 공간에 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정
	// 할당받은 pcpu 들의 16 byte 공간에 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정
	// 할당받은 pcpu 들의 16 byte 공간에 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정
	// 할당받은 pcpu 들의 16 byte 공간에 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정
	// 할당받은 pcpu 들의 16 byte 공간에 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

	return 1;
	// return 1
	// return 1
	// return 1
	// return 1
	// return 1
}

// ARM10C 20140419
// ARM10C 20140426
// ARM10C 20140614
static struct kmem_cache *kmem_cache_node;

/*
 * No kmalloc_node yet so do it by hand. We know that this is the first
 * slab on the node for this slabcache. There are no concurrent accesses
 * possible.
 *
 * Note that this function only works on the kmem_cache_node
 * when allocating for the kmem_cache_node. This is used for bootstrapping
 * memory on a fresh node that has no slab structures yet.
 */
// ARM10C 20140426
// node: 0
static void early_kmem_cache_node_alloc(int node)
{
	struct page *page;
	struct kmem_cache_node *n;

	// kmem_cache_node->size: boot_kmem_cache_node.size: 64, sizeof(struct kmem_cache_node): 44 bytes
	BUG_ON(kmem_cache_node->size < sizeof(struct kmem_cache_node));

	// kmem_cache_node: &boot_kmem_cache_node, GFP_NOWAIT: 0, node: 0
	page = new_slab(kmem_cache_node, GFP_NOWAIT, node);
	// new_slab이 한일:
	// migratetype이 MIGRATE_UNMOVABLE인 page 할당 받음
	// page 맴버를 셋팅함
	// page->slab_cache: &boot_kmem_cache_node 주소를 set
	// page->flags에 7 (PG_slab) bit를 set
	// slab 의 objects 들의 freepointer를 맵핑함
	// kmem_cache_node 가 완성된 이후에 nr_slabs, total_objects 가 증가될 것으로 예상됨
	// page->freelist: UNMOVABLE인 page 의 virtual address
	// page->inuse: 64
	// page->frozen: 1

	// page: UNMOVABLE인 page
	BUG_ON(!page);

	// page: UNMOVABLE인 page, page_to_nid(UNMOVABLE인 page): 0, node: 0
	if (page_to_nid(page) != node) {
		printk(KERN_ERR "SLUB: Unable to allocate memory from "
				"node %d\n", node);
		printk(KERN_ERR "SLUB: Allocating a useless per node structure "
				"in order to be able to continue\n");
	}

	// page->freelist: UNMOVABLE인 page 의 object의 시작 virtual address
	n = page->freelist;
	// n: UNMOVABLE인 page 의 object의 시작 virtual address

	BUG_ON(!n);

	// kmem_cache_node: &boot_kmem_cache_node,
	// n: UNMOVABLE인 page 의 object의 시작 virtual address
	page->freelist = get_freepointer(kmem_cache_node, n);
	// page->freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64

	// get_freepointer 하는일:
	// slab object에 매핑 되어 있는 다음 object의 주소를 가져옴

	// page->inuse: 64
	page->inuse = 1;
	// page->inuse: 1

	// page의 inuse 맴버는 현재 사용하고 있는 object의 수를 의미함

	// page->frozen: 1
	page->frozen = 0;
	// page->frozen: 0

	// node: 0, kmem_cache_node->node: (&boot_kmem_cache_node)->node[0]: NULL
	// n: UNMOVABLE인 page 의 object의 시작 virtual address
	kmem_cache_node->node[node] = n;
	// kmem_cache_node->node: (&boot_kmem_cache_node)->node[0]: UNMOVABLE인 page 의 object의 시작 virtual address

#ifdef CONFIG_SLUB_DEBUG // CONFIG_SLUB_DEBUG=y
	// kmem_cache_node: &boot_kmem_cache_node,
	// n: UNMOVABLE인 page 의 object의 시작 virtual address,
	// SLUB_RED_ACTIVE: 0xcc
	init_object(kmem_cache_node, n, SLUB_RED_ACTIVE);

	// kmem_cache_node: &boot_kmem_cache_node,
	// n: UNMOVABLE인 page 의 object의 시작 virtual address
	init_tracking(kmem_cache_node, n);
#endif

	// n: UNMOVABLE인 page 의 object의 시작 virtual address
	init_kmem_cache_node(n);
	// n->nr_partial: 0
	// n->list_lock: spinlock 초기화 수행
	// n->partial: 리스트 초기화
	// n->nr_slabs: 0
	// n->total_objects: 0
	// n->full: 리스트 초기화
	// 할당받은 slab object를 kmem_cache_node 로 사용하고
	// kmem_cache_node의 멤버 필드를 초기화함

	// page: UNMOVABLE인 page
	// kmem_cache_node: &boot_kmem_cache_node, node: 0, page->objects: 64
	inc_slabs_node(kmem_cache_node, node, page->objects);
	// n->nr_slabs: 1, n->total_objects: 64 로 set

	// n: UNMOVABLE인 page 의 object의 시작 virtual address,
	// page: UNMOVABLE인 page, DEACTIVATE_TO_HEAD: 15
	add_partial(n, page, DEACTIVATE_TO_HEAD);
	// n->nr_partial: 1 로 set
	// kmem_cache_node의 partial 맴버에 현재 page의 lru 리스트를 추가함
}

static void free_kmem_cache_nodes(struct kmem_cache *s)
{
	int node;

	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n = s->node[node];

		if (n)
			kmem_cache_free(kmem_cache_node, n);

		s->node[node] = NULL;
	}
}

// ARM10C 20140426
// s: &boot_kmem_cache_node
// ARM10C 20140614
// s: &boot_kmem_cache
// ARM10C 20140726
// s: &kmem_cache#30
// ARM10C 20140726
// s: &kmem_cache#23
// ARM10C 20140920
// s: &kmem_cache#21
static int init_kmem_cache_nodes(struct kmem_cache *s)
{
	int node;

	// N_NORMAL_MEMORY: 2
	for_each_node_state(node, N_NORMAL_MEMORY) {
	// for ( (node) = 0; (node) == 0; (node) = 1)

		struct kmem_cache_node *n;

		// slab_state: DOWN: 0
		// slab_state: PARTIAL: 1, DOWN: 0
		// slab_state: PARTIAL: 1, DOWN: 0
		// slab_state: PARTIAL: 1, DOWN: 0
		// slab_state: UP: 4, DOWN: 0
		if (slab_state == DOWN) {
			// node: 0
			early_kmem_cache_node_alloc(node);
			// early_kmem_cache_node_alloc에서 한일:
			// migratetype이 MIGRATE_UNMOVABLE인 page 할당 받음
			// page 맴버를 셋팅함
			// page->slab_cache: &boot_kmem_cache_node 주소를 set
			// page->flags에 7 (PG_slab) bit를 set
			// page->freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
			// page->inuse: 1, page->frozen: 0 page 맴버를 셋팅함
			// slab 의 objects 들의 freepointer를 맵핑함
			// 할당받은 slab object를 kmem_cache_node 로 사용하고 kmem_cache_node의 멤버 필드를 초기화함
			// (UNMOVABLE인 page 의 object의 시작 virtual address (kmem_cache_node#0))
			// (kmem_cache_node#0)->nr_partial: 1
			// (kmem_cache_node#0)->list_lock: spinlock 초기화 수행
			// (kmem_cache_node#0)->slabs: 1,
			// (kmem_cache_node#0)->total_objects: 64 로 세팅함
			// (kmem_cache_node#0)->full: 리스트 초기화
			// (kmem_cache_node#0)의 partial 맴버에 현재 page의 lru 리스트를 추가함
			continue;
		}

		// kmem_cache_node: &boot_kmem_cache_node, GFP_KERNEL: 0xD0, node: 0
		// kmem_cache_alloc_node(&boot_kmem_cache_node, GFP_KERNEL: 0xD0, 0):
		// UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// kmem_cache_node: kmem_cache#31, GFP_KERNEL: 0xD0, node: 0
		// kmem_cache_alloc_node(kmem_cache#31, GFP_KERNEL: 0xD0, 0):
		// UNMOVABLE인 page 의 시작 virtual address + 4032
		// kmem_cache_node: kmem_cache#31, GFP_KERNEL: 0xD0, node: 0
		// kmem_cache_alloc_node(kmem_cache#31, GFP_KERNEL: 0xD0, 0):
		// UNMOVABLE인 page 의 시작 virtual address + 3968
		// kmem_cache_node: kmem_cache#31, GFP_KERNEL: 0xD0, node: 0
		// kmem_cache_alloc_node(kmem_cache#31, GFP_KERNEL: 0xD0, 0):
		// kmem_cache_node#54
		n = kmem_cache_alloc_node(kmem_cache_node,
						GFP_KERNEL, node);
		// n: UNMOVABLE인 page 의 object의 시작 virtual address + 64 (kmem_cache_node#1)
		// n: UNMOVABLE인 page 의 object의 시작 virtual address + 4032 (kmem_cache_node#63)
		// n: UNMOVABLE인 page 의 object의 시작 virtual address + 3968 (kmem_cache_node#62)
		// n: UNMOVABLE인 page 의 object의 시작 virtual address + 3456 (kmem_cache_node#54)

		// UNMOVABLE인 page (boot_kmem_cache_node)의 시작 virtual address + 4032 를
		// kmem_cache_node 용 63번째 object 인데 주석 추가의 용의성을 위해
		// kmem_cache_node#63 부르기로 함

		// kmem_cache_alloc_node 한일?
		// MIGRATE_UNMOVABLE인 page 할당 받아 쪼개놓은 object들에서 object를 1개 할당받음
		// (UNMOVABLE인 page 의 object의 시작 virtual address + 64 (kmem_cache_node#1))
		// page->counters: 0x80400040
		// page->inuse: 64
		// page->objects: 64
		// page->frozen: 1
		// page->freelist: NULL
		// c->freelist: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
		// UNMOVABLE인 page 의 object의 시작 virtual address + 128
		// c->tid: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 4
		// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
		// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
		// n->nr_partial: 0

		// kmem_cache_alloc_node 한일?
		// MIGRATE_UNMOVABLE인 page 할당 받아 쪼개놓은 object들에서 object를 1개 할당받음
		// (UNMOVABLE인 page 의 object의 시작 virtual address + 4032 (kmem_cache_node#63))
		// page->counters: 0x80400040
		// page->inuse: 64
		// page->objects: 64
		// page->frozen: 1
		// page->freelist: NULL
		// c->freelist: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
		// UNMOVABLE인 page 의 object의 시작 virtual address + 3968
		// c->tid: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 12
		// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
		// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
		// n->nr_partial: 0

		// kmem_cache_alloc_node 한일?
		// MIGRATE_UNMOVABLE인 page 할당 받아 쪼개놓은 object들에서 object를 1개 할당받음
		// (UNMOVABLE인 page 의 object의 시작 virtual address + 3968 (kmem_cache_node#62))
		// page->counters: 0x80400040
		// page->inuse: 64
		// page->objects: 64
		// page->frozen: 1
		// page->freelist: NULL
		// c->freelist: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
		// UNMOVABLE인 page 의 object의 시작 virtual address + 3904
		// c->tid: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 16
		// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
		// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
		// n->nr_partial: 0

		// kmem_cache_alloc_node 한일?
		// MIGRATE_UNMOVABLE인 page 할당 받아 쪼개놓은 object들에서 object를 1개 할당받음
		// (UNMOVABLE인 page 의 object의 시작 virtual address + 3456 (kmem_cache_node#54))
		// page->counters: 0x80400040
		// page->inuse: 64
		// page->objects: 64
		// page->frozen: 1
		// page->freelist: NULL
		// c->freelist: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
		// UNMOVABLE인 page 의 object의 시작 virtual address + 3392
		// c->tid: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 48
		// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
		// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
		// n->nr_partial: 0

		// n: UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// n: kmem_cache_node#63
		// n: kmem_cache_node#62
		// n: kmem_cache_node#54
		if (!n) {
			free_kmem_cache_nodes(s);
			return 0;
		}

		// node: 0, s->node[0]: boot_kmem_cache.node[0]
		// n: UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// node: 0, s->node[0]: kmem_cache#30.node[0]
		// n: kmem_cache_node#63
		// node: 0, s->node[0]: kmem_cache#23.node[0]
		// n: kmem_cache_node#62
		// node: 0, s->node[0]: kmem_cache#21.node[0]
		// n: kmem_cache_node#54
		s->node[node] = n;
		// s->node[0]: boot_kmem_cache.node[0]: UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// s->node[0]: kmem_cache#30.node[0]: kmem_cache_node#63
		// s->node[0]: kmem_cache#23.node[0]: kmem_cache_node#62
		// s->node[0]: kmem_cache#21.node[0]: kmem_cache_node#54

		// n: UNMOVABLE인 page 의 object의 시작 virtual address + 64
		// n: kmem_cache_node#63
		// n: kmem_cache_node#62
		// n: kmem_cache_node#54
		init_kmem_cache_node(n);
		// n->nr_partial: 0
		// n->list_lock: spinlock 초기화 수행
		// n->partial: 리스트 초기화
		// n->nr_slabs: 0
		// n->total_objects: 0
		// n->full: 리스트 초기화
		// 할당받은 slab object를 kmem_cache_node 로 사용하고
		// kmem_cache_node의 멤버 필드를 초기화함
	}
	return 1;
	// return 1 수행
	// return 1 수행
	// return 1 수행
	// return 1 수행
	// return 1 수행
}

// ARM10C 20140419
// s: &boot_kmem_cache_node, 3
// ARM10C 20140614
// s: &boot_kmem_cache, 3
// ARM10C 20140726
// s: &kmem_cache#30, 3
// ARM10C 20140726
// s: &kmem_cache#23, 6
// ARM10C 20140920
// s: &kmem_cache#21, 5
static void set_min_partial(struct kmem_cache *s, unsigned long min)
{
	// min: 3, MIN_PARTIAL: 5
	// min: 3, MIN_PARTIAL: 5
	// min: 3, MIN_PARTIAL: 5
	// min: 6, MIN_PARTIAL: 5, MAX_PARTIAL: 10
	// min: 5, MIN_PARTIAL: 5, MAX_PARTIAL: 10
	if (min < MIN_PARTIAL)
		min = MIN_PARTIAL;
		// min : 5
		// min : 5
		// min : 5
	else if (min > MAX_PARTIAL)
		min = MAX_PARTIAL;

	// s->min_partial: boot_kmem_cache_node.min_partial: 0, min: 5
	// s->min_partial: boot_kmem_cache.min_partial: 0, min: 5
	// s->min_partial: kmem_cache#30.min_partial: 0, min: 5
	// s->min_partial: kmem_cache#23.min_partial: 0, min: 6
	// s->min_partial: kmem_cache#21.min_partial: 0, min: 5
	s->min_partial = min;
	// s->min_partial: boot_kmem_cache_node.min_partial: 5
	// s->min_partial: boot_kmem_cache.min_partial: 5
	// s->min_partial: kmem_cache#30.min_partial: 5
	// s->min_partial: kmem_cache#23.min_partial: 6
	// s->min_partial: kmem_cache#21.min_partial: 5
}

/*
 * calculate_sizes() determines the order and the distribution of data within
 * a slab object.
 */
// ARM10C 20140419
// s: &boot_kmem_cache_node, -1
// ARM10C 20140614
// s: &boot_kmem_cache, -1
// ARM10C 20140726
// s: &kmem_cache#30, -1
// ARM10C 20140726
// s: &kmem_cache#23, -1
// ARM10C 20140920
// s: &kmem_cache#21, -1
static int calculate_sizes(struct kmem_cache *s, int forced_order)
{
	// s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN
	// s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN
	// s->flags: kmem_cache#30.flags: 0
	// s->flags: kmem_cache#23.flags: 0
	// s->flags: kmem_cache#21.flags: SLAB_PANIC: 0x00040000UL
	unsigned long flags = s->flags;
	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// flags: 0
	// flags: 0
	// flags: SLAB_PANIC: 0x00040000UL

	// s->object_size: boot_kmem_cache_node.object_size: 44
	// s->object_size: boot_kmem_cache.object_size: 116
	// s->object_size: kmem_cache#30.object_size: 64
	// s->object_size: kmem_cache#23.object_size: 4096
	// s->object_size: kmem_cache#21.object_size: 1076
	unsigned long size = s->object_size;
	// size: 44
	// size: 116
	// size: 64
	// size: 4096
	// size: 1076
	int order;

	/*
	 * Round up object size to the next word boundary. We can only
	 * place the free pointer at word boundaries and this determines
	 * the possible location of the free pointer.
	 */
	// size: 44, sizeof(void *): 4
	// size: 116, sizeof(void *): 4
	// size: 64, sizeof(void *): 4
	// size: 4096, sizeof(void *): 4
	// size: 1076, sizeof(void *): 4
	size = ALIGN(size, sizeof(void *));
	// size: 44
	// size: 116
	// size: 64
	// size: 4096
	// size: 1076

#ifdef CONFIG_SLUB_DEBUG // CONFIG_SLUB_DEBUG=y
	/*
	 * Determine if we can poison the object itself. If the user of
	 * the slab may touch the object after free or before allocation
	 * then we should never poison the object itself.
	 */

	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_POISON: 0x00000800UL
	// SLAB_DESTROY_BY_RCU: 0x00080000UL
	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_POISON: 0x00000800UL
	// SLAB_DESTROY_BY_RCU: 0x00080000UL
	// flags: 0, SLAB_POISON: 0x00000800UL, SLAB_DESTROY_BY_RCU: 0x00080000UL
	// flags: 0, SLAB_POISON: 0x00000800UL, SLAB_DESTROY_BY_RCU: 0x00080000UL
	// flags: SLAB_PANIC: 0x00040000UL, SLAB_POISON: 0x00000800UL, SLAB_DESTROY_BY_RCU: 0x00080000UL
	if ((flags & SLAB_POISON) && !(flags & SLAB_DESTROY_BY_RCU) &&
			!s->ctor)
		s->flags |= __OBJECT_POISON;
	else
		// s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
		// __OBJECT_POISON : 0x80000000UL
		// s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
		// __OBJECT_POISON : 0x80000000UL
		// s->flags: kmem_cache#30.flags: 0, __OBJECT_POISON : 0x80000000UL
		// s->flags: kmem_cache#23.flags: 0, __OBJECT_POISON : 0x80000000UL
		// s->flags: kmem_cache#21.flags: SLAB_PANIC: 0x00040000UL, __OBJECT_POISON : 0x80000000UL
		s->flags &= ~__OBJECT_POISON;
		// s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
		// s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
		// s->flags: kmem_cache#30.flags: 0
		// s->flags: kmem_cache#23.flags: 0
		// s->flags: kmem_cache#21.flags: SLAB_PANIC: 0x00040000UL


	/*
	 * If we are Redzoning then check if there is some space between the
	 * end of the object and the free pointer. If not then add an
	 * additional word to have some bytes to store Redzone information.
	 */
	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_RED_ZONE: 0x00000400UL, size: 44,
	// s->object_size: boot_kmem_cache_node.object_size: 44
	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_RED_ZONE: 0x00000400UL, size: 116,
	// s->object_size: boot_kmem_cache.object_size: 116
	// flags: 0, SLAB_RED_ZONE: 0x00000400UL, size: 64,
	// s->object_size: kmem_cache#30.object_size: 64
	// flags: 0, SLAB_RED_ZONE: 0x00000400UL, size: 4096,
	// s->object_size: kmem_cache#23.object_size: 4096
	// flags: SLAB_PANIC: 0x00040000UL, SLAB_RED_ZONE: 0x00000400UL, size: 1076,
	// s->object_size: kmem_cache#21.object_size: 1076
	if ((flags & SLAB_RED_ZONE) && size == s->object_size)
		size += sizeof(void *);
#endif

	/*
	 * With that we have determined the number of bytes in actual use
	 * by the object. This is the potential offset to the free pointer.
	 */
	// s->inuse: boot_kmem_cache_node.inuse: 0, size: 44
	// s->inuse: boot_kmem_cache.inuse: 0, size: 116
	// s->inuse: kmem_cache#30.inuse: 0, size: 64
	// s->inuse: kmem_cache#23.inuse: 0, size: 4096
	// s->inuse: kmem_cache#21.inuse: 0, size: 1076
	s->inuse = size;
	// s->inuse: boot_kmem_cache_node.inuse: 44
	// s->inuse: boot_kmem_cache.inuse: 116
	// s->inuse: kmem_cache#30.inuse: 64
	// s->inuse: kmem_cache#23.inuse: 4096
	// s->inuse: kmem_cache#21.inuse: 1076

	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_DESTROY_BY_RCU: 0x00080000UL,
	// SLAB_POISON: 0x00000800UL, s->ctor: boot_kmem_cache_node.ctor: NULL
	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_DESTROY_BY_RCU: 0x00080000UL,
	// SLAB_POISON: 0x00000800UL, s->ctor: boot_kmem_cache.ctor: NULL
	// flags: 0, SLAB_DESTROY_BY_RCU: 0x00080000UL,
	// SLAB_POISON: 0x00000800UL, s->ctor: kmem_cache#30.ctor: NULL
	// flags: 0, SLAB_DESTROY_BY_RCU: 0x00080000UL,
	// SLAB_POISON: 0x00000800UL, s->ctor: kmem_cache#23.ctor: NULL
	// flags: SLAB_PANIC: 0x00040000UL, SLAB_DESTROY_BY_RCU: 0x00080000UL,
	// SLAB_POISON: 0x00000800UL, s->ctor: kmem_cache#21.ctor: NULL
	if (((flags & (SLAB_DESTROY_BY_RCU | SLAB_POISON)) ||
		s->ctor)) {
		/*
		 * Relocate free pointer after the object if it is not
		 * permitted to overwrite the first word of the object on
		 * kmem_cache_free.
		 *
		 * This is the case if we do RCU, have a constructor or
		 * destructor or are poisoning the objects.
		 */
		s->offset = size;
		size += sizeof(void *);
	}

#ifdef CONFIG_SLUB_DEBUG // CONFIG_SLUB_DEBUG=y
	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_STORE_USER: 0x00010000UL
	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_STORE_USER: 0x00010000UL
	// flags: 0, SLAB_STORE_USER: 0x00010000UL
	// flags: 0, SLAB_STORE_USER: 0x00010000UL
	// flags: SLAB_PANIC: 0x00040000UL, SLAB_STORE_USER: 0x00010000UL
	if (flags & SLAB_STORE_USER)
		/*
		 * Need to store information about allocs and frees after
		 * the object.
		 */
		size += 2 * sizeof(struct track);

	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_RED_ZONE: 0x00000400UL
	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, SLAB_RED_ZONE: 0x00000400UL
	// flags: 0, SLAB_RED_ZONE: 0x00000400UL
	// flags: 0, SLAB_RED_ZONE: 0x00000400UL
	// flags: SLAB_PANIC: 0x00040000UL, SLAB_RED_ZONE: 0x00000400UL
	if (flags & SLAB_RED_ZONE)
		/*
		 * Add some empty padding so that we can catch
		 * overwrites from earlier objects rather than let
		 * tracking information or the free pointer be
		 * corrupted if a user writes before the start
		 * of the object.
		 */
		size += sizeof(void *);
#endif

	/*
	 * SLUB stores one object immediately after another beginning from
	 * offset 0. In order to align the objects we have to simply size
	 * each object to conform to the alignment.
	 */
	// size: 44, s->align: boot_kmem_cache_node.align: 64
	// size: 116, s->align: boot_kmem_cache.align: 64
	// size: 64, s->align: kmem_cache#30.align: 64
	// size: 4096, s->align: kmem_cache#23.align: 64
	// size: 1076, s->align: kmem_cache#21.align: 8
	size = ALIGN(size, s->align);
	// size: 64
	// size: 128
	// size: 64
	// size: 4096
	// size: 1080

	// s->size: boot_kmem_cache_node.size: 44, size: 64
	// s->size: boot_kmem_cache.size: 116, size: 128
	// s->size: kmem_cache#30.size: 64, size: 64
	// s->size: kmem_cache#23.size: 4096, size: 4096
	// s->size: kmem_cache#21.size: 1076, size: 1080
	s->size = size;
	// s->size: boot_kmem_cache_node.size: 64
	// s->size: boot_kmem_cache.size: 128
	// s->size: kmem_cache#30.size: 64
	// s->size: kmem_cache#23.size: 4096
	// s->size: kmem_cache#21.size: 1080
	
	// forced_order: -1
	// forced_order: -1
	// forced_order: -1
	// forced_order: -1
	// forced_order: -1
	if (forced_order >= 0)
		order = forced_order;
	else
		// size: 64, s->reserved: boot_kmem_cache_node.reserved: 0
		// size: 128, s->reserved: boot_kmem_cache.reserved: 0
		// size: 64, s->reserved: kmem_cache#30.reserved: 0
		// size: 4096, s->reserved: kmem_cache#23.reserved: 0
		// size: 1080, s->reserved: kmem_cache#21.reserved: 0
		order = calculate_order(size, s->reserved);
		// order: 0
		// order: 0
		// order: 0
		// order: 3
		// order: 3

		// calculate_order가 하는일?:
		// 내부 단편화 문제를 고려하여 최적의 order를 계산함

	if (order < 0)
		return 0;

	// s->allocflags: boot_kmem_cache_node.allocflags: 0
	// s->allocflags: boot_kmem_cache.allocflags: 0
	// s->allocflags: kmem_cache#30.allocflags: 0
	// s->allocflags: kmem_cache#23.allocflags: 0
	// s->allocflags: kmem_cache#21.allocflags: 0
	s->allocflags = 0;
	// s->allocflags: boot_kmem_cache_node.allocflags: 0
	// s->allocflags: boot_kmem_cache.allocflags: 0
	// s->allocflags: kmem_cache#30.allocflags: 0
	// s->allocflags: kmem_cache#23.allocflags: 0
	// s->allocflags: kmem_cache#21.allocflags: 0

	// order: 0
	// order: 0
	// order: 0
	// order: 3
	// order: 3
	if (order)
		// s->allocflags: kmem_cache#23.allocflags: 0, __GFP_COMP: 0x4000u
		// s->allocflags: kmem_cache#21.allocflags: 0, __GFP_COMP: 0x4000u
		s->allocflags |= __GFP_COMP;
		// s->allocflags: kmem_cache#23.allocflags: 0x4000
		// s->allocflags: kmem_cache#21.allocflags: 0x4000

	// s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_CACHE_DMA: 0x00004000UL
	// s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_CACHE_DMA: 0x00004000UL
	// s->flags: kmem_cache#30.flags: 0, SLAB_CACHE_DMA: 0x00004000UL
	// s->flags: kmem_cache#23.flags: 0, SLAB_CACHE_DMA: 0x00004000UL
	// s->flags: kmem_cache#21.flags: SLAB_PANIC: 0x00040000UL, SLAB_CACHE_DMA: 0x00004000UL
	if (s->flags & SLAB_CACHE_DMA)
		s->allocflags |= GFP_DMA;

	// s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_RECLAIM_ACCOUNT: 0x00020000UL
	// s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// SLAB_RECLAIM_ACCOUNT: 0x00020000UL
	// s->flags: kmem_cache#30.flags: 0, SLAB_RECLAIM_ACCOUNT: 0x00020000UL
	// s->flags: kmem_cache#23.flags: 0, SLAB_RECLAIM_ACCOUNT: 0x00020000UL
	// s->flags: kmem_cache#21.flags: SLAB_PANIC: 0x00040000UL, SLAB_RECLAIM_ACCOUNT: 0x00020000UL
	if (s->flags & SLAB_RECLAIM_ACCOUNT)
		s->allocflags |= __GFP_RECLAIMABLE;

	/*
	 * Determine the number of objects per slab
	 */
	// order: 0, size: 64, s->reserved: boot_kmem_cache_node.reserved: 0
	// order: 0, size: 128, s->reserved: boot_kmem_cache.reserved: 0
	// order: 0, size: 64, s->reserved: kmem_cache#30.reserved: 0
	// order: 3, size: 4096, s->reserved: kmem_cache#23.reserved: 0
	// order: 3, size: 1080, s->reserved: kmem_cache#21.reserved: 0
	s->oo = oo_make(order, size, s->reserved);
	// s->oo: boot_kmem_cache_node.oo.x: 0x00040
	// s->oo: boot_kmem_cache.oo.x: 0x00020
	// s->oo: kmem_cache#30.oo.x: 0x00040
	// s->oo: kmem_cache#23.oo.x: 0x30008
	// s->oo: kmem_cache#21.oo.x: 0x3001e
	
	// size: 64, get_order(64): 0, s->reserved: boot_kmem_cache_node.reserved: 0
	// size: 128, get_order(128): 0, s->reserved: boot_kmem_cache.reserved: 0
	// size: 64, get_order(64): 0, s->reserved: kmem_cache#30.reserved: 0
	// size: 4096, get_order(4096): 1, s->reserved: kmem_cache#23.reserved: 0
	// size: 1080, get_order(1080): 0, s->reserved: kmem_cache#21.reserved: 0
	s->min = oo_make(get_order(size), size, s->reserved);
	// s->min: boot_kmem_cache_node.min.x: 0x00040
	// s->min: boot_kmem_cache.min.x: 0x00020
	// s->min: kmem_cache#30.min.x: 0x00040
	// s->min: kmem_cache#23.min.x: 0x10002
	// s->min: kmem_cache#21.min.x: 0x00003
	
	// s->oo: boot_kmem_cache_node.oo, s->max: boot_kmem_cache_node.max
	// oo_objects(boot_kmem_cache_node.oo): 64, oo_objects(boot_kmem_cache_node.max): 0
	// s->oo: boot_kmem_cache.oo, s->max: boot_kmem_cache.max
	// oo_objects(boot_kmem_cache.oo): 32, oo_objects(boot_kmem_cache.max): 0
	// s->oo: kmem_cache#30.oo, s->max: kmem_cache#30.max
	// oo_objects(kmem_cache#30.oo): 64, oo_objects(kmem_cache#30.max): 0
	// s->oo: kmem_cache#23.oo, s->max: kmem_cache#23.max
	// oo_objects(kmem_cache#23.oo): 8, oo_objects(kmem_cache#23.max): 0
	// s->oo: kmem_cache#21.oo, s->max: kmem_cache#21.max
	// oo_objects(kmem_cache#21.oo): 0x1e, oo_objects(kmem_cache#21.max): 0
	if (oo_objects(s->oo) > oo_objects(s->max))
		// s->oo: boot_kmem_cache_node.oo.x: 0x00040
		// s->oo: boot_kmem_cache.oo.x: 0x00020
		// s->oo: kmem_cache#30.oo.x: 0x00040
		// s->oo: kmem_cache#23.oo.x: 0x30008
		// s->oo: kmem_cache#21.oo.x: 0x3001e
		s->max = s->oo;
		// s->max: boot_kmem_cache_node.max.x: 0x00040
		// s->max: boot_kmem_cache.max.x: 0x00020
		// s->max: kmem_cache#30.max.x: 0x00040
		// s->max: kmem_cache#23.max.x: 0x30008
		// s->max: kmem_cache#21.max.x: 0x3001e

	// s->oo: boot_kmem_cache_node.oo, oo_objects(boot_kmem_cache_node.oo): 64
	// s->oo: boot_kmem_cache.oo, oo_objects(boot_kmem_cache.oo): 32
	// s->oo: kmem_cache#30.oo, oo_objects(kmem_cache#30.oo): 64
	// s->oo: kmem_cache#23.oo, oo_objects(kmem_cache#23.oo): 8
	// s->oo: kmem_cache#21.oo, oo_objects(kmem_cache#21.oo): 0x1e
	return !!oo_objects(s->oo);
	// return 1
	// return 1
	// return 1
	// return 1
	// return 1
}

// ARM10C 20140419
// s: &boot_kmem_cache_node, flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
// ARM10C 20140614
// s: &boot_kmem_cache, flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
// ARM10C 20140726
// s: &kmem_cache#30, flags: 0
// ARM10C 20140726
// s: &kmem_cache#23 flags: 0
// ARM10C 20140920
// s: &kmem_cache#21, flags: SLAB_PANIC: 0x00040000UL
static int kmem_cache_open(struct kmem_cache *s, unsigned long flags)
{
	// s->size: boot_kmem_cache_node.size: 44, flags: SLAB_HWCACHE_ALIGN: 0x00002000UL,
	// s->name: boot_kmem_cache_node.name: "kmem_cache_node", s->ctor: boot_kmem_cache_node.ctor: NULL
	// s->size: boot_kmem_cache.size: 116, flags: SLAB_HWCACHE_ALIGN: 0x00002000UL,
	// s->name: boot_kmem_cache.name: "kmem_cache", s->ctor: boot_kmem_cache.ctor: NULL
	// s->size: kmem_cache#30.size: 64, flags: 0,
	// s->name: kmem_cache#30.name: NULL, s->ctor: kmem_cache#30.ctor: NULL
	// s->size: kmem_cache#23.size: 64, flags: 0,
	// s->name: kmem_cache#23.name: NULL, s->ctor: kmem_cache#23.ctor: NULL
	// s->size: kmem_cache#21.size: 1076, flags: SLAB_PANIC: 0x00040000UL,
	// s->name: kmem_cache#21.name: "idr_layer_cache", s->ctor: kmem_cache#21.ctor: NULL
	s->flags = kmem_cache_flags(s->size, flags, s->name, s->ctor);
	// s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// s->flags: kmem_cache#30.flags: 0
	// s->flags: kmem_cache#23.flags: 0
	// s->flags: kmem_cache#21.flags: SLAB_PANIC: 0x00040000UL

	// s->reserved: boot_kmem_cache_node.reserved: 0
	// s->reserved: boot_kmem_cache.reserved: 0
	// s->reserved: kmem_cache#30.reserved: 0
	// s->reserved: kmem_cache#23.reserved: 0
	// s->reserved: kmem_cache#21.reserved: 0
	s->reserved = 0;
	// s->reserved: boot_kmem_cache_node.reserved: 0
	// s->reserved: boot_kmem_cache.reserved: 0
	// s->reserved: kmem_cache#30.reserved: 0
	// s->reserved: kmem_cache#23.reserved: 0
	// s->reserved: kmem_cache#21.reserved: 0

	// need_reserve_slab_rcu: 0, s->flags: boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN
	// need_reserve_slab_rcu: 0, s->flags: boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN
	// need_reserve_slab_rcu: 0, s->flags: kmem_cache#30.flags: 0
	// need_reserve_slab_rcu: 0, s->flags: kmem_cache#23.flags: 0
	// need_reserve_slab_rcu: 0, s->flags: kmem_cache#21.flags: SLAB_PANIC: 0x00040000UL
	if (need_reserve_slab_rcu && (s->flags & SLAB_DESTROY_BY_RCU))
		s->reserved = sizeof(struct rcu_head);

	// s: &boot_kmem_cache_node, -1, calculate_sizes(&boot_kmem_cache_node, -1): 1
	// s: &boot_kmem_cache, -1, calculate_sizes(&boot_kmem_cache, -1): 1
	// s: &kmem_cache#30, -1, calculate_sizes(&kmem_cache#30, -1): 1
	// s: &kmem_cache#23, -1, calculate_sizes(&kmem_cache#23, -1): 1
	// s: &kmem_cache#21, -1, calculate_sizes(&kmem_cache#21, -1): 1
	if (!calculate_sizes(s, -1))
		goto error;

	// calculate_sizes가 하는일?:
	// object size 값에 맞게 내부 단편화 문제를 고려하여 최적의 order를 계산함
	// kmem_cache의 맴버 inuse, size, allocflags, min, oo, max 값을 초기화해줌

	// disable_higher_order_debug: 0
	// disable_higher_order_debug: 0
	// disable_higher_order_debug: 0
	// disable_higher_order_debug: 0
	// disable_higher_order_debug: 0
	if (disable_higher_order_debug) {
		/*
		 * Disable debugging flags that store metadata if the min slab
		 * order increased.
		 */
		if (get_order(s->size) > get_order(s->object_size)) {
			s->flags &= ~DEBUG_METADATA_FLAGS;
			s->offset = 0;
			if (!calculate_sizes(s, -1))
				goto error;
		}
	}

// CONFIG_HAVE_CMPXCHG_DOUBLE=n, CONFIG_HAVE_ALIGNED_STRUCT_PAGE=n
#if defined(CONFIG_HAVE_CMPXCHG_DOUBLE) && \
    defined(CONFIG_HAVE_ALIGNED_STRUCT_PAGE)
	if (system_has_cmpxchg_double() && (s->flags & SLAB_DEBUG_FLAGS) == 0)
		/* Enable fast mode */
		s->flags |= __CMPXCHG_DOUBLE;
#endif

	/*
	 * The larger the object size is, the more pages we want on the partial
	 * list to avoid pounding the page allocator excessively.
	 */
	// s->size: boot_kmem_cache_node.size: 64, ilog2(64): 6
	// s: &boot_kmem_cache_node, 3
	// s->size: boot_kmem_cache.size: 128, ilog2(128): 7
	// s: &boot_kmem_cache, 3
	// s->size: kmem_cache#30.size: 64, ilog2(64): 6
	// s: &kmem_cache#30, 3
	// s->size: kmem_cache#23.size: 4096, ilog2(4096): 12
	// s: &kmem_cache#23, 6
	// s->size: kmem_cache#21.size: 1080, ilog2(1080): 10
	// s: &kmem_cache#21, 5
	set_min_partial(s, ilog2(s->size) / 2);
	// boot_kmem_cache_node.min_partial: 5
	// boot_kmem_cache.min_partial: 5
	// kmem_cache#30.min_partial: 5
	// kmem_cache#23.min_partial: 6
	// kmem_cache#21.min_partial: 5

	/*
	 * cpu_partial determined the maximum number of objects kept in the
	 * per cpu partial lists of a processor.
	 *
	 * Per cpu partial lists mainly contain slabs that just have one
	 * object freed. If they are used for allocation then they can be
	 * filled up again with minimal effort. The slab will never hit the
	 * per node partial lists and therefore no locking will be required.
	 *
	 * This setting also determines
	 *
	 * A) The number of objects from per cpu partial slabs dumped to the
	 *    per node list when we reach the limit.
	 * B) The number of objects in cpu partial slabs to extract from the
	 *    per node list when we run out of per cpu objects. We only fetch
	 *    50% to keep some capacity around for frees.
	 */

	// s: &boot_kmem_cache_node, kmem_cache_has_cpu_partial(&boot_kmem_cache_node): 1
	// s->size: boot_kmem_cache_node.size: 64, PAGE_SIZE: 0x1000
	// s: &boot_kmem_cache, kmem_cache_has_cpu_partial(&boot_kmem_cache): 1
	// s->size: boot_kmem_cache.size: 128, PAGE_SIZE: 0x1000
	// s: &kmem_cache#30, kmem_cache_has_cpu_partial(&kmem_cache#30): 1
	// s->size: kmem_cache#30.size: 64, PAGE_SIZE: 0x1000
	// s: &kmem_cache#23, kmem_cache_has_cpu_partial(&kmem_cache#23): 1
	// s->size: kmem_cache#23.size: 4096, PAGE_SIZE: 0x1000
	// s: &kmem_cache#21, kmem_cache_has_cpu_partial(&kmem_cache#21): 1
	// s->size: kmem_cache#21.size: 1080, PAGE_SIZE: 0x1000
	if (!kmem_cache_has_cpu_partial(s))
		s->cpu_partial = 0;
	else if (s->size >= PAGE_SIZE)
		// s->cpu_partial: kmem_cache#23.cpu_partial: 0
		s->cpu_partial = 2;
		// s->cpu_partial: kmem_cache#23.cpu_partial: 2
	else if (s->size >= 1024)
		// s->cpu_partial: kmem_cache#21.cpu_partial: 0
		s->cpu_partial = 6;
		// s->cpu_partial: kmem_cache#21.cpu_partial: 6
	else if (s->size >= 256)
		s->cpu_partial = 13;
	else
		// s->cpu_partial: boot_kmem_cache_node.cpu_partial: 0
		// s->cpu_partial: boot_kmem_cache.cpu_partial: 0
		// s->cpu_partial: kmem_cache#30.cpu_partial: 0
		s->cpu_partial = 30;
		// boot_kmem_cache_node.cpu_partial: 30
		// boot_kmem_cache.cpu_partial: 30
		// kmem_cache#30.cpu_partial: 30

// 2014/04/19 종료
// 2014/04/26 시작

#ifdef CONFIG_NUMA // CONFIG_NUMA=n
	s->remote_node_defrag_ratio = 1000;
#endif
	// s: &boot_kmem_cache_node, init_kmem_cache_nodes(&boot_kmem_cache_node): 1
	// s: &boot_kmem_cache, init_kmem_cache_nodes(&boot_kmem_cache): 1
	// s: &kmem_cache#30, init_kmem_cache_nodes(&kmem_cache#30): 1
	// s: &kmem_cache#23, init_kmem_cache_nodes(&kmem_cache#23): 1
	// s: &kmem_cache#21, init_kmem_cache_nodes(&kmem_cache#21): 1
	if (!init_kmem_cache_nodes(s))
		goto error;

	// init_kmem_cache_nodes(&boot_kmem_cache_node) 가 한일:
	// migratetype이 MIGRATE_UNMOVABLE인 page 할당 받음
	// page 맴버를 셋팅함
	// page->slab_cache: &boot_kmem_cache_node 주소를 set
	// page->flags에 7 (PG_slab) bit를 set
	// page->freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// page->inuse: 1, page->frozen: 0 page 맴버를 셋팅함
	// slab 의 objects 들의 freepointer를 맵핑함
	// 할당받은 slab object를 kmem_cache_node 로 사용하고 kmem_cache_node의 멤버 필드를 초기화함
	// (UNMOVABLE인 page 의 object의 시작 virtual address (kmem_cache_node#0))
	// (kmem_cache_node#0)->nr_partial: 1
	// (kmem_cache_node#0)->list_lock: spinlock 초기화 수행
	// (kmem_cache_node#0)->slabs: 1,
	// (kmem_cache_node#0)->total_objects: 64 로 세팅함
	// (kmem_cache_node#0)->full: 리스트 초기화
	// (kmem_cache_node#0)의 partial 맴버에 현재 page의 lru 리스트를 추가함

	// init_kmem_cache_nodes(&boot_kmem_cache) 가 한일:
	// MIGRATE_UNMOVABLE인 page 할당 받아 쪼개놓은 object들에서 object를 1개 할당받음
	// (UNMOVABLE인 page 의 object의 시작 virtual address + 64 (kmem_cache_node#1))
	// page->counters: 0x80400040
	// page->inuse: 64
	// page->objects: 64
	// page->frozen: 1
	// page->freelist: NULL
	// c->freelist: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
	// UNMOVABLE인 page 의 object의 시작 virtual address + 128
	// c->tid: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 4
	// 1번째 object:
	// (kmem_cache_node#0)->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
	// (kmem_cache_node#0)->nr_partial: 0
	// 2번째 object:
	// (kmem_cache_node#1)->nr_partial: 0
	// (kmem_cache_node#1)->list_lock: spinlock 초기화 수행
	// (kmem_cache_node#1)->slabs: 0,
	// (kmem_cache_node#1)->total_objects: 0 로 세팅함
	// (kmem_cache_node#1)->full: 리스트 초기화

	// init_kmem_cache_nodes(&kmem_cache#30) 가 한일:
	// MIGRATE_UNMOVABLE인 page 할당 받아 쪼개놓은 object들에서 object를 1개 할당받음
	// (UNMOVABLE인 page 의 object의 시작 virtual address + 4032 (kmem_cache_node#63))
	// page->counters: 0x80400040
	// page->inuse: 64
	// page->objects: 64
	// page->frozen: 1
	// page->freelist: NULL
	// c->freelist: ((&kmem_cache#31)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
	// UNMOVABLE인 page 의 object의 시작 virtual address + 3968
	// c->tid: ((&kmem_cache#31)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 12
	// 2번째 object:
	// (kmem_cache_node#1)->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
	// (kmem_cache_node#1)->nr_partial: 0
	// 64번째 object:
	// (kmem_cache_node#63)->nr_partial: 0
	// (kmem_cache_node#63)->list_lock: spinlock 초기화 수행
	// (kmem_cache_node#63)->slabs: 0,
	// (kmem_cache_node#63)->total_objects: 0 로 세팅함
	// (kmem_cache_node#63)->full: 리스트 초기화

	// init_kmem_cache_nodes(&kmem_cache#23) 가 한일:
	// MIGRATE_UNMOVABLE인 page 할당 받아 쪼개놓은 object들에서 object를 1개 할당받음
	// (UNMOVABLE인 page 의 object의 시작 virtual address + 3968 (kmem_cache_node#62))
	// page->counters: 0x80400040
	// page->inuse: 64
	// page->objects: 64
	// page->frozen: 1
	// page->freelist: NULL
	// c->freelist: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
	// UNMOVABLE인 page 의 object의 시작 virtual address + 3904
	// c->tid: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 16
	// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
	// 63번째 object:
	// (kmem_cache_node#62)->nr_partial: 0
	// (kmem_cache_node#62)->list_lock: spinlock 초기화 수행
	// (kmem_cache_node#62)->slabs: 0,
	// (kmem_cache_node#62)->total_objects: 0 로 세팅함
	// (kmem_cache_node#62)->full: 리스트 초기화

	// init_kmem_cache_nodes(&kmem_cache#21) 가 한일:
	// MIGRATE_UNMOVABLE인 page 할당 받아 쪼개놓은 object들에서 object를 1개 할당받음
	// (UNMOVABLE인 page 의 object의 시작 virtual address + 3456 (kmem_cache_node#54))
	// page->counters: 0x80400040
	// page->inuse: 64
	// page->objects: 64
	// page->frozen: 1
	// page->freelist: NULL
	// c->freelist: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
	// UNMOVABLE인 page 의 object의 시작 virtual address + 3392
	// c->tid: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 48
	// object를 위한 page 의 사용 하지 않은 다음 object의 시작 virtual address 를 가져옴
	// 55번째 object:
	// (kmem_cache_node#54)->nr_partial: 0
	// (kmem_cache_node#54)->list_lock: spinlock 초기화 수행
	// (kmem_cache_node#54)->slabs: 0,
	// (kmem_cache_node#54)->total_objects: 0 로 세팅함
	// (kmem_cache_node#54)->full: 리스트 초기화

	// s: &boot_kmem_cache_node, alloc_kmem_cache_cpus(&boot_kmem_cache_node): 1
	// s: &boot_kmem_cache, alloc_kmem_cache_cpus(&boot_kmem_cache): 1
	// s: &kmem_cache#30, alloc_kmem_cache_cpus(&kmem_cache#30): 1
	// s: &kmem_cache#23, alloc_kmem_cache_cpus(&kmem_cache#23): 1
	// s: &kmem_cache#21, alloc_kmem_cache_cpus(&kmem_cache#21): 1
	if (alloc_kmem_cache_cpus(s))
		// alloc_kmem_cache_cpus(&boot_kmem_cache_node) 한일:
		// 할당받은 pcpu 들의 16 byte 공간 (&boot_kmem_cache_node)->cpu_slab 에
		// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

		// alloc_kmem_cache_cpus(&boot_kmem_cache) 한일:
		// 할당받은 pcpu 들의 16 byte 공간 (&boot_kmem_cache)->cpu_slab 에
		// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

		// alloc_kmem_cache_cpus(&kmem_cache#30) 한일:
		// 할당받은 pcpu 들의 16 byte 공간 (&kmem_cache#30)->cpu_slab 에
		// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

		// alloc_kmem_cache_cpus(&kmem_cache#23) 한일:
		// 할당받은 pcpu 들의 16 byte 공간 (&kmem_cache#23)->cpu_slab 에
		// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

		// alloc_kmem_cache_cpus(&kmem_cache#21) 한일:
		// 할당받은 pcpu 들의 16 byte 공간 (&kmem_cache#21)->cpu_slab 에
		// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정
		return 0;
		// return 0
		// return 0
		// return 0
		// return 0
		// return 0

	free_kmem_cache_nodes(s);
error:
	if (flags & SLAB_PANIC)
		panic("Cannot create slab %s size=%lu realsize=%u "
			"order=%u offset=%u flags=%lx\n",
			s->name, (unsigned long)s->size, s->size,
			oo_order(s->oo), s->offset, flags);
	return -EINVAL;
}

static void list_slab_objects(struct kmem_cache *s, struct page *page,
							const char *text)
{
#ifdef CONFIG_SLUB_DEBUG
	void *addr = page_address(page);
	void *p;
	unsigned long *map = kzalloc(BITS_TO_LONGS(page->objects) *
				     sizeof(long), GFP_ATOMIC);
	if (!map)
		return;
	slab_err(s, page, text, s->name);
	slab_lock(page);

	get_map(s, page, map);
	for_each_object(p, s, addr, page->objects) {

		if (!test_bit(slab_index(p, s, addr), map)) {
			printk(KERN_ERR "INFO: Object 0x%p @offset=%tu\n",
							p, p - addr);
			print_tracking(s, p);
		}
	}
	slab_unlock(page);
	kfree(map);
#endif
}

/*
 * Attempt to free all partial slabs on a node.
 * This is called from kmem_cache_close(). We must be the last thread
 * using the cache and therefore we do not need to lock anymore.
 */
static void free_partial(struct kmem_cache *s, struct kmem_cache_node *n)
{
	struct page *page, *h;

	list_for_each_entry_safe(page, h, &n->partial, lru) {
		if (!page->inuse) {
			remove_partial(n, page);
			discard_slab(s, page);
		} else {
			list_slab_objects(s, page,
			"Objects remaining in %s on kmem_cache_close()");
		}
	}
}

/*
 * Release all resources used by a slab cache.
 */
static inline int kmem_cache_close(struct kmem_cache *s)
{
	int node;

	flush_all(s);
	/* Attempt to free all objects */
	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n = get_node(s, node);

		free_partial(s, n);
		if (n->nr_partial || slabs_node(s, node))
			return 1;
	}
	free_percpu(s->cpu_slab);
	free_kmem_cache_nodes(s);
	return 0;
}

int __kmem_cache_shutdown(struct kmem_cache *s)
{
	int rc = kmem_cache_close(s);

	if (!rc) {
		/*
		 * We do the same lock strategy around sysfs_slab_add, see
		 * __kmem_cache_create. Because this is pretty much the last
		 * operation we do and the lock will be released shortly after
		 * that in slab_common.c, we could just move sysfs_slab_remove
		 * to a later point in common code. We should do that when we
		 * have a common sysfs framework for all allocators.
		 */
		mutex_unlock(&slab_mutex);
		sysfs_slab_remove(s);
		mutex_lock(&slab_mutex);
	}

	return rc;
}

/********************************************************************
 *		Kmalloc subsystem
 *******************************************************************/

static int __init setup_slub_min_order(char *str)
{
	get_option(&str, &slub_min_order);

	return 1;
}

__setup("slub_min_order=", setup_slub_min_order);

static int __init setup_slub_max_order(char *str)
{
	get_option(&str, &slub_max_order);
	slub_max_order = min(slub_max_order, MAX_ORDER - 1);

	return 1;
}

__setup("slub_max_order=", setup_slub_max_order);

static int __init setup_slub_min_objects(char *str)
{
	get_option(&str, &slub_min_objects);

	return 1;
}

__setup("slub_min_objects=", setup_slub_min_objects);

static int __init setup_slub_nomerge(char *str)
{
	slub_nomerge = 1;
	return 1;
}

__setup("slub_nomerge", setup_slub_nomerge);

// ARM10C 20141206
// 512, flags: 0x80D0
// ARM10C 20150117
// 0, flags: 0x80D0
void *__kmalloc(size_t size, gfp_t flags)
{
	struct kmem_cache *s;
	void *ret;

	// size: 512, KMALLOC_MAX_CACHE_SIZE: 0x2000
	// size: 0, KMALLOC_MAX_CACHE_SIZE: 0x2000
	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE))
		return kmalloc_large(size, flags);

	// size: 512, flags: 0x80D0
	// kmalloc_slab(512, 0x80D0): kmem_cache#26
	// size: 0, flags: 0x80D0
	// kmalloc_slab(0, 0x80D0): ((void *)16)
	s = kmalloc_slab(size, flags);
	// s: kmem_cache#26
	// s: ((void *)16)

	// s: kmem_cache#26
	// s: ((void *)16)
	// ZERO_OR_NULL_PTR(((void *)16)): 1
	if (unlikely(ZERO_OR_NULL_PTR(s)))
		// s: ((void *)16)
		return s;
		// return ((void *)16)

	// s: kmem_cache#26, flags: 0x80D0
	// slab_alloc(kmem_cache#26, 0x80D0): kmem_cache#26-oX
	ret = slab_alloc(s, flags, _RET_IP_);
	// ret: kmem_cache#26-oX

	// ret: kmem_cache#26-oX, size: 512, s->size: (kmem_cache#26)->size: 512, flags: 0x80D0
	trace_kmalloc(_RET_IP_, ret, size, s->size, flags);

	// ret: kmem_cache#26-oX
	return ret;
	// return kmem_cache#26-oX
}
EXPORT_SYMBOL(__kmalloc);

#ifdef CONFIG_NUMA
static void *kmalloc_large_node(size_t size, gfp_t flags, int node)
{
	struct page *page;
	void *ptr = NULL;

	flags |= __GFP_COMP | __GFP_NOTRACK | __GFP_KMEMCG;
	page = alloc_pages_node(node, flags, get_order(size));
	if (page)
		ptr = page_address(page);

	kmalloc_large_node_hook(ptr, size, flags);
	return ptr;
}

void *__kmalloc_node(size_t size, gfp_t flags, int node)
{
	struct kmem_cache *s;
	void *ret;

	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE)) {
		ret = kmalloc_large_node(size, flags, node);

		trace_kmalloc_node(_RET_IP_, ret,
				   size, PAGE_SIZE << get_order(size),
				   flags, node);

		return ret;
	}

	s = kmalloc_slab(size, flags);

	if (unlikely(ZERO_OR_NULL_PTR(s)))
		return s;

	ret = slab_alloc_node(s, flags, node, _RET_IP_);

	trace_kmalloc_node(_RET_IP_, ret, size, s->size, flags, node);

	return ret;
}
EXPORT_SYMBOL(__kmalloc_node);
#endif

size_t ksize(const void *object)
{
	struct page *page;

	if (unlikely(object == ZERO_SIZE_PTR))
		return 0;

	page = virt_to_head_page(object);

	if (unlikely(!PageSlab(page))) {
		WARN_ON(!PageCompound(page));
		return PAGE_SIZE << compound_order(page);
	}

	return slab_ksize(page->slab_cache);
}
EXPORT_SYMBOL(ksize);

// ARM10C 20141129
// desc: kmem_cache#30-o11 (cortex_a15_gic)
// ARM10C 20141220
// desc: kmem_cache#30-o10 (exynos4210_combiner)
void kfree(const void *x)
{
	struct page *page;

	// x: kmem_cache#30-o11
	void *object = (void *)x;
	// object: kmem_cache#30-o11

	// _RET_IP_: __builtin_return_address(0), object: kmem_cache#30-o11
	trace_kfree(_RET_IP_, x);

	// x: kmem_cache#30-o11, ZERO_OR_NULL_PTR(kmem_cache#30-o11): 0
	if (unlikely(ZERO_OR_NULL_PTR(x)))
		return;

	// x: kmem_cache#30-o11
	// virt_to_head_page(kmem_cache#30-o11): kmem_cache#30-o11의 page 주소
	page = virt_to_head_page(x);
	// page: kmem_cache#30-o11의 page 주소

	// page: kmem_cache#30-o11의 page 주소
	// PageSlab(kmem_cache#30-o11의 page 주소): 1
	if (unlikely(!PageSlab(page))) {
		BUG_ON(!PageCompound(page));
		kfree_hook(x);
		__free_memcg_kmem_pages(page, compound_order(page));
		return;
	}

// 2014/11/29 종료
// 2014/12/06 시작

	// page->slab_cache: (kmem_cache#30-o11의 page 주소)->slab_cache,
	// page: kmem_cache#30-o11의 page 주소, object: kmem_cache#30-o11
	slab_free(page->slab_cache, page, object, _RET_IP_);

	// slab_free에서 한일:
	// (kmem_cache#30)->cpu_slab: struct kmem_cache_cpu 자료구조를 사용하기 위해 할당받은 pcp 16 byte 메모리 공간을 구하여
	// kmem_cache#30-o11의 freepointer의 값을
	// ((kmem_cache#30)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)->freelist 값으로 세팅
	// 값 s->cpu_slab->freelist와 c->freelist를 비교, 값 s->cpu_slab->tid와 tid을 비교 하여
	// 같을 경우에 s->cpu_slab->freelist와 s->cpu_slab->tid을 각각 object, next_tid(tid) 값으로 갱신하여
	// freelist와 tid 값을 변경함
	// kmem_cache_cpu의 freelist, tid 의 값을 변경함
}
EXPORT_SYMBOL(kfree);

/*
 * kmem_cache_shrink removes empty slabs from the partial lists and sorts
 * the remaining slabs by the number of items in use. The slabs with the
 * most items in use come first. New allocations will then fill those up
 * and thus they can be removed from the partial lists.
 *
 * The slabs with the least items are placed last. This results in them
 * being allocated from last increasing the chance that the last objects
 * are freed in them.
 */
int kmem_cache_shrink(struct kmem_cache *s)
{
	int node;
	int i;
	struct kmem_cache_node *n;
	struct page *page;
	struct page *t;
	int objects = oo_objects(s->max);
	struct list_head *slabs_by_inuse =
		kmalloc(sizeof(struct list_head) * objects, GFP_KERNEL);
	unsigned long flags;

	if (!slabs_by_inuse)
		return -ENOMEM;

	flush_all(s);
	for_each_node_state(node, N_NORMAL_MEMORY) {
		n = get_node(s, node);

		if (!n->nr_partial)
			continue;

		for (i = 0; i < objects; i++)
			INIT_LIST_HEAD(slabs_by_inuse + i);

		spin_lock_irqsave(&n->list_lock, flags);

		/*
		 * Build lists indexed by the items in use in each slab.
		 *
		 * Note that concurrent frees may occur while we hold the
		 * list_lock. page->inuse here is the upper limit.
		 */
		list_for_each_entry_safe(page, t, &n->partial, lru) {
			list_move(&page->lru, slabs_by_inuse + page->inuse);
			if (!page->inuse)
				n->nr_partial--;
		}

		/*
		 * Rebuild the partial list with the slabs filled up most
		 * first and the least used slabs at the end.
		 */
		for (i = objects - 1; i > 0; i--)
			list_splice(slabs_by_inuse + i, n->partial.prev);

		spin_unlock_irqrestore(&n->list_lock, flags);

		/* Release empty slabs */
		list_for_each_entry_safe(page, t, slabs_by_inuse, lru)
			discard_slab(s, page);
	}

	kfree(slabs_by_inuse);
	return 0;
}
EXPORT_SYMBOL(kmem_cache_shrink);

static int slab_mem_going_offline_callback(void *arg)
{
	struct kmem_cache *s;

	mutex_lock(&slab_mutex);
	list_for_each_entry(s, &slab_caches, list)
		kmem_cache_shrink(s);
	mutex_unlock(&slab_mutex);

	return 0;
}

static void slab_mem_offline_callback(void *arg)
{
	struct kmem_cache_node *n;
	struct kmem_cache *s;
	struct memory_notify *marg = arg;
	int offline_node;

	offline_node = marg->status_change_nid_normal;

	/*
	 * If the node still has available memory. we need kmem_cache_node
	 * for it yet.
	 */
	if (offline_node < 0)
		return;

	mutex_lock(&slab_mutex);
	list_for_each_entry(s, &slab_caches, list) {
		n = get_node(s, offline_node);
		if (n) {
			/*
			 * if n->nr_slabs > 0, slabs still exist on the node
			 * that is going down. We were unable to free them,
			 * and offline_pages() function shouldn't call this
			 * callback. So, we must fail.
			 */
			BUG_ON(slabs_node(s, offline_node));

			s->node[offline_node] = NULL;
			kmem_cache_free(kmem_cache_node, n);
		}
	}
	mutex_unlock(&slab_mutex);
}

static int slab_mem_going_online_callback(void *arg)
{
	struct kmem_cache_node *n;
	struct kmem_cache *s;
	struct memory_notify *marg = arg;
	int nid = marg->status_change_nid_normal;
	int ret = 0;

	/*
	 * If the node's memory is already available, then kmem_cache_node is
	 * already created. Nothing to do.
	 */
	if (nid < 0)
		return 0;

	/*
	 * We are bringing a node online. No memory is available yet. We must
	 * allocate a kmem_cache_node structure in order to bring the node
	 * online.
	 */
	mutex_lock(&slab_mutex);
	list_for_each_entry(s, &slab_caches, list) {
		/*
		 * XXX: kmem_cache_alloc_node will fallback to other nodes
		 *      since memory is not yet available from the node that
		 *      is brought up.
		 */
		n = kmem_cache_alloc(kmem_cache_node, GFP_KERNEL);
		if (!n) {
			ret = -ENOMEM;
			goto out;
		}
		init_kmem_cache_node(n);
		s->node[nid] = n;
	}
out:
	mutex_unlock(&slab_mutex);
	return ret;
}

static int slab_memory_callback(struct notifier_block *self,
				unsigned long action, void *arg)
{
	int ret = 0;

	switch (action) {
	case MEM_GOING_ONLINE:
		ret = slab_mem_going_online_callback(arg);
		break;
	case MEM_GOING_OFFLINE:
		ret = slab_mem_going_offline_callback(arg);
		break;
	case MEM_OFFLINE:
	case MEM_CANCEL_ONLINE:
		slab_mem_offline_callback(arg);
		break;
	case MEM_ONLINE:
	case MEM_CANCEL_OFFLINE:
		break;
	}
	if (ret)
		ret = notifier_from_errno(ret);
	else
		ret = NOTIFY_OK;
	return ret;
}

// ARM10C 20140607
static struct notifier_block slab_memory_callback_nb = {
	.notifier_call = slab_memory_callback,
	// SLAB_CALLBACK_PRI: 1
	.priority = SLAB_CALLBACK_PRI,
};

/********************************************************************
 *			Basic setup of slabs
 *******************************************************************/

/*
 * Used for early kmem_cache structures that were allocated using
 * the page allocator. Allocate them properly then fix up the pointers
 * that may be pointing to the wrong kmem_cache structure.
 */

// ARM10C 20140628
// &boot_kmem_cache
// ARM10C 20140705
// &boot_kmem_cache_node
static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
{
	int node;
	// kmem_cache: &boot_kmem_cache, GFP_NOWAIT: 0
	// kmem_cache_zalloc(&boot_kmem_cache, GFP_NOWAIT: 0):
	// UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// kmem_cache: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// GFP_NOWAIT: 0,
	// kmem_cache_zalloc(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, GFP_NOWAIT: 0):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	struct kmem_cache *s = kmem_cache_zalloc(kmem_cache, GFP_NOWAIT);
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968

	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// static_cache: &boot_kmem_cache,
	// kmem_cache->object_size: boot_kmem_cache.object_size: 116
	// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// static_cache: &boot_kmem_cache_node,
	// kmem_cache->object_size: (UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968)->object_size: 116
	memcpy(s, static_cache, kmem_cache->object_size);
	// boot_kmem_cache에 세팅된 멤버 필드 값을 전부 할당 받은 object로 복사함
	// boot_kmem_cache_node에 세팅된 멤버 필드 값을 전부 할당 받은 object로 복사함

// 2014/06/28 종료
// 2014/07/05 시작

	/*
	 * This runs very early, and only the boot processor is supposed to be
	 * up.  Even if it weren't true, IRQs are not up so we couldn't fire
	 * IPIs around.
	 */
	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// smp_processor_id(): 0
	// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968,
	// smp_processor_id(): 0
	__flush_cpu_slab(s, smp_processor_id());

	// [boot_kmem_cache 로 호출]
	// __flush_cpu_slab 한일:
	// UNMOVABLE인 page (boot_kmem_cache)의 필드 맴버 값 변경
	// (UNMOVABLE인 page (boot_kmem_cache))->counters: 0x00200001
	// (UNMOVABLE인 page (boot_kmem_cache))->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	//
	// (UNMOVABLE인 page (boot_kmem_cache)) 의 object들의 freepointer 값 변경
	// (사용하지 않는 첫 번째 object의 freepointer 값을 NULL 로 변경, 나머지 object들의 freepointer 값을 이전 object들의 주소로 변경)
	//
	// 에) s->offset이 0이고 slab object 시작 주소가 0x10001000 일 경우
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | Slab object 0 (사용중)  | Slab object 1           | Slab object 2           | Slab object 3           | .... | Slab object 31          |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | object start address:   | object start address:   | object start address:   | object start address:   |      | object start address:   |
	// | 0x10001000              | 0x10001080              | 0x10001100              | 0x10001180              | .... | 0x10001f80              |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | freepointer | data      | freepointer | data      | freepointer | data      | freepointer | data      | .... | freepointer | data      |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | (덮어씀)    | 124 Bytes | null        | 124 Bytes | 0x10001080  | 124 Bytes | 0x10001100  | 124 Bytes | .... | 0x10001f00  | 124 Bytes |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	//
	// n: (&boot_kmem_cache 용 object 주소)->node[0]:
	// boot_kmem_cache_node 로 할당 받은 page의 2 번째 object의 주소
	// n->nr_partial: 1
	// n->partial에 (UNMOVABLE인 page (boot_kmem_cache))->lru 가 추가됨
	//
	// c: (&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c->tid: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 8
	// c->page: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: NULL
	// c->freelist: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist: NULL
	//
	// [UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968 로 호출]
	// __flush_cpu_slab 한일:
	// UNMOVABLE인 page 의 필드 맴버 값 변경
	// (UNMOVABLE인 page)->counters: 0x00400002
	// (UNMOVABLE인 page)->freelist: UNMOVABLE인 page 의 시작 virtual address + 4032
	//
	// (UNMOVABLE인 page) 의 object들의 freepointer 값 변경
	// (사용하지 않는 첫 번째 object의 freepointer 값을 NULL 로 변경, 나머지 object들의 freepointer 값을 이전 object들의 주소로 변경)
	//
	// 에) s->offset이 0이고 slab object 시작 주소가 0x10001000 일 경우
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | Slab object 0 (사용중) | Slab object 1 (사용중) | Slab object 2          | Slab object 3          | Slab object 3          | .... | Slab object 63         |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | object start address:  | object start address:  | object start address:  | object start address:  | object start address:  |      | object start address:  |
	// | 0x10001000             | 0x10001040             | 0x10001080             | 0x100010C0             | 0x10001100             | .... | 0x10001fc0             |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | freepointer | data     | freepointer | data     | freepointer | data     | freepointer | data     | freepointer | data     | .... | freepointer | data     |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | (덮어씀)    | 60 Bytes | (덮어씀)    | 60 Bytes | null        | 60 Bytes | 0x10001080  | 60 Bytes | 0x100010C0  | 60 Bytes | .... | 0x10001f80  | 60 Bytes |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	//
	// n: (&boot_kmem_cache_node 용 object 주소)->node[0]:
	// boot_kmem_cache_node 로 할당 받은 1 번째 object의 주소
	// n->nr_partial: 1
	// n->partial에 (UNMOVABLE인 page)->lru 가 추가됨
	//
	// c: (&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c->tid: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 8
	// c->page: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: NULL
	// c->freelist: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist: NULL

	for_each_node_state(node, N_NORMAL_MEMORY) {
	// for ( (node) = 0; (node) == 0; (node) = 1)

		// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, node: 0
		// get_node(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, 0):
		// (&boot_kmem_cache 용 object 주소)->node[0]: boot_kmem_cache_node 로 할당 받은 2 번째 object의 주소
		// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968, node: 0
		// get_node(UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968, 0):
		// (&boot_kmem_cache_node 용 object 주소)->node[0]: boot_kmem_cache_node 로 할당 받은 1 번째 object의 주소
		struct kmem_cache_node *n = get_node(s, node);
		// n: boot_kmem_cache_node 로 할당 받은 page의 2 번째 object의 주소
		// n: boot_kmem_cache_node 로 할당 받은 page의 1 번째 object의 주소

		struct page *p;

		// n: boot_kmem_cache_node 로 할당 받은 page의 2 번째 object의 주소
		// n: boot_kmem_cache_node 로 할당 받은 page의 1 번째 object의 주소
		if (n) {
			list_for_each_entry(p, &n->partial, lru)
			// for (p = list_first_entry(&n->partial, typeof(*p), lru);
			//      &p->lru != (&n->partial); p = list_next_entry(p, lru))

				// p: UNMOVABLE인 page (boot_kmem_cache)
				// p: UNMOVABLE인 page

				// p->slab_cache: (UNMOVABLE인 page (boot_kmem_cache))->slab_cache
				// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
				// p->slab_cache: (UNMOVABLE인 page)->slab_cache
				// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
				p->slab_cache = s;
				// p->slab_cache: (UNMOVABLE인 page (boot_kmem_cache))->slab_cache:
				// UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
				// p->slab_cache: (UNMOVABLE인 page)->slab_cache:
				// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968

#ifdef CONFIG_SLUB_DEBUG // CONFIG_SLUB_DEBUG=y
			list_for_each_entry(p, &n->full, lru)
			// for (p = list_first_entry(&n->full, typeof(*p), lru);
			//      &p->lru != (&n->full); p = list_next_entry(p, lru))

				p->slab_cache = s;
#endif
		}
	}

	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	list_add(&s->list, &slab_caches);
	// slab_caches 의 list에 (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->list를 등록
	// slab_caches 의 list에 (UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968)->list를 등록

	// s: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	return s;
	// return UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// return UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
}

// ARM10C 20140419
void __init kmem_cache_init(void)
{
	static __initdata struct kmem_cache boot_kmem_cache,
		boot_kmem_cache_node;

	// debug_guardpage_minorder(): 0
	if (debug_guardpage_minorder())
		slub_max_order = 0;

	// kmem_cache_node: NULL
	kmem_cache_node = &boot_kmem_cache_node;
	// kmem_cache_node: &boot_kmem_cache_node

	// kmem_cache: NULL
	kmem_cache = &boot_kmem_cache;
	// kmem_cache: &boot_kmem_cache

	// &boot_kmem_cache_node, "kmem_cache_node", sizeof(struct kmem_cache_node): 44 byte,
	// SLAB_HWCACHE_ALIGN: 0x00002000UL
	// create_boot_cache(&boot_kmem_cache_node, "kmem_cache_node", 44, 0x00002000UL)
	create_boot_cache(kmem_cache_node, "kmem_cache_node",
		sizeof(struct kmem_cache_node), SLAB_HWCACHE_ALIGN);

	// create_boot_cache의 kmem_cache_node가 한일:
	// boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// boot_kmem_cache_node.reserved: 0
	// boot_kmem_cache_node.min_partial: 5
	// boot_kmem_cache_node.cpu_partial: 30
	// boot_kmem_cache_node.refcount: -1
	//
	// migratetype이 MIGRATE_UNMOVABLE인 page 할당 받음
	// page 맴버를 셋팅함
	// page->slab_cache: &boot_kmem_cache_node 주소를 set
	// page->flags에 7 (PG_slab) bit를 set
	// page->freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// page->inuse: 1, page->frozen: 0 page 맴버를 셋팅함
	// slab 의 objects 들의 freepointer를 맵핑함
	// 할당받은 slab object를 kmem_cache_node 로 사용하고 kmem_cache_node의 멤버 필드를 초기화함
	// kmem_cache_node->nr_partial: 1
	// kmem_cache_node->list_lock: spinlock 초기화 수행
	// kmem_cache_node->slabs: 1, kmem_cache_node->total_objects: 64 로 세팀함
	// kmem_cache_node->full: 리스트 초기화
	// kmem_cache_node의 partial 맴버에 현재 page의 lru 리스트를 추가함
	//
	// kmem_cache_node: &boot_kmem_cache_node 임
	//
	// 할당받은 pcpu 들의 16 byte 공간 (&boot_kmem_cache_node)->cpu_slab 에
	// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

	register_hotmemory_notifier(&slab_memory_callback_nb); // null function

	/* Able to allocate the per node structures */
	// slab_state: DOWN
	slab_state = PARTIAL;
	// slab_state: PARTIAL

	// slab_state 의미:
	// slab을 초기화한 단계를 나타냄, PARTIAL은 kmem_cache_node 만 사용이 가능함

// 2014/06/07 종료
// 2014/06/14 시작

	// kmem_cache: &boot_kmem_cache,
	// offsetof(struct kmem_cache, node): 112, nr_node_ids: 1
	// sizeof(struct kmem_cache_node *): 4 SLAB_HWCACHE_ALIGN: 0x00002000UL
	// create_boot_cache(&boot_kmem_cache, "kmem_cache", 116, 0x00002000UL)
	create_boot_cache(kmem_cache, "kmem_cache",
			offsetof(struct kmem_cache, node) +
				nr_node_ids * sizeof(struct kmem_cache_node *),
		       SLAB_HWCACHE_ALIGN);

	// create_boot_cache(&boot_kmem_cache) 가 한일:
	// boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// boot_kmem_cache.reserved: 0
	// boot_kmem_cache.min_partial: 5
	// boot_kmem_cache.cpu_partial: 30
	// boot_kmem_cache.refcount: -1
	//
	// 할당 받아 놓은 migratetype이 MIGRATE_UNMOVABLE인 page 를 사용
	// page 맴버를 셋팅함
	// page->counters: 0x80200020
	// page->inuse: 32
	// page->objects: 32
	// page->frozen: 1
	// page->freelist: NULL
	// 할당받은 slab object를 kmem_cache_node 로 사용하고 kmem_cache_node의 멤버 필드를 초기화함
	// 첫번째 object:
	// kmem_cache_node->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
	// kmem_cache_node->nr_partial: 0
	// 두번째 object:
	// kmem_cache_node->nr_partial: 0
	// kmem_cache_node->list_lock: spinlock 초기화 수행
	// kmem_cache_node->slabs: 0, kmem_cache_node->total_objects: 0 로 세팀함
	// kmem_cache_node->full: 리스트 초기화
	//
	// kmem_cache_node 가 boot_kmem_cache.node[0]에 할당됨
	//
	// 할당받은 pcpu 들의 16 byte 공간 (&boot_kmem_cache)->cpu_slab 에
	// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

	kmem_cache = bootstrap(&boot_kmem_cache);
	// kmem_cache: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address

	// bootstrap(&boot_kmem_cache) 에서 한일:
	// UNMOVABLE인 page (boot_kmem_cache) 를 할당 받음
	// UNMOVABLE인 page (boot_kmem_cache) 를 할당 받은 page의 첫 번째 object에
	// boot_kmem_cache에 세팅된 멤버 필드 값을 전부 할당 받은 object로 복사함
	//
	// UNMOVABLE인 page (boot_kmem_cache)의 필드 맴버 값 변경
	// (UNMOVABLE인 page (boot_kmem_cache))->counters: 0x00200001
	// (UNMOVABLE인 page (boot_kmem_cache))->freelist: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	//
	// (UNMOVABLE인 page (boot_kmem_cache)) 의 object들의 freepointer 값 변경
	// (사용하지 않는 첫 번째 object의 freepointer 값을 NULL 로 변경, 나머지 object들의 freepointer 값을 이전 object들의 주소로 변경)
	//
	// 에) s->offset이 0이고 slab object 시작 주소가 0x10001000 일 경우
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | Slab object 0 (사용중)  | Slab object 1           | Slab object 2           | Slab object 3           | .... | Slab object 31          |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | object start address:   | object start address:   | object start address:   | object start address:   |      | object start address:   |
	// | 0x10001000              | 0x10001080              | 0x10001100              | 0x10001180              | .... | 0x10001f80              |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | freepointer | data      | freepointer | data      | freepointer | data      | freepointer | data      | .... | freepointer | data      |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	// | (덮어씀)    | 124 Bytes | null        | 124 Bytes | 0x10001080  | 124 Bytes | 0x10001100  | 124 Bytes | .... | 0x10001f00  | 124 Bytes |
	// ------------------------------------------------------------------------------------------------------------------------------------------
	//
	// n: (&boot_kmem_cache 용 object 주소)->node[0]:
	// boot_kmem_cache_node 로 할당 받은 page의 2 번째 object의 주소
	// n->nr_partial: 1
	// n->partial에 (UNMOVABLE인 page (boot_kmem_cache))->lru 가 추가됨
	//
	// c: (&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c->tid: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 8
	// c->page: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: NULL
	// c->freelist: ((&boot_kmem_cache 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist: NULL
	//
	// p->slab_cache: (UNMOVABLE인 page (boot_kmem_cache))->slab_cache:
	// UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	//
	// slab_caches 의 list에 (UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->list를 등록

	/*
	 * Allocate kmem_cache_node properly from the kmem_cache slab.
	 * kmem_cache_node is separately allocated so no need to
	 * update any list pointers.
	 */
	kmem_cache_node = bootstrap(&boot_kmem_cache_node);
	// kmem_cache_node: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968

	// bootstrap(UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968) 에서 한일:
	// 할당 받아 놓은 UNMOVABLE인 page (boot_kmem_cache)를 할당 받은 page의 32 번째 object에
	// boot_kmem_cache_node에 세팅된 멤버 필드 값을 전부 할당 받은 object로 복사함
	//
	// UNMOVABLE인 page (boot_kmem_cache)의 맴버 필드 값 세팅
	// page->freelist: NULL
	// page->counters: 0x80200020
	// page->inuse: 32
	// page->frozen: 1
	//
	// n->partial에 연결된 (MIGRATE_UNMOVABLE인 page (boot_kmem_cache))->lru 를 삭제
	// n->nr_partial: 0
	//
	// c->page: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page:
	// MIGRATE_UNMOVABLE인 page (boot_kmem_cache)
	// c->freelist: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
	// c->tid: ((UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address)->cpu_slab +
	// (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 12
	//
	// kmem_cache용 slab의 사용 상태
	// 에) s->offset이 0이고 slab object 시작 주소가 0x10001000 일 경우
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | Slab object 0  (사용중) | Slab object 1           | Slab object 2           | .... | Slab object 29          | Slab object 30          | Slab object 31 (사용중) |
	// | [boot_kmem_cache]       |                         |                         |      |                         |                         | [boot_kmem_cache_node]  |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | object start address:   | object start address:   | object start address:   |      | object start address:   | object start address:   | object start address:   |
	// | 0x10001000              | 0x10001080              | 0x10001100              | .... | 0x10001e80              | 0x10001f00              | 0x10001f80              |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | freepointer | data      | freepointer | data      | freepointer | data      | .... | freepointer | data      | freepointer | data      | freepointer | data      |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | (덮어씀)    | 124 Bytes | null        | 124 Bytes | 0x10001080  | 124 Bytes | .... | 0x10001e00  | 124 Bytes | 0x10001e80  | 124 Bytes | (덮어씀)    | 124 Bytes |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------------
	//
	// UNMOVABLE인 page 의 필드 맴버 값 변경
	// (UNMOVABLE인 page)->counters: 0x00400002
	// (UNMOVABLE인 page)->freelist: UNMOVABLE인 page 의 시작 virtual address + 4032
	//
	// (UNMOVABLE인 page) 의 object들의 freepointer 값 변경
	// (사용하지 않는 첫 번째 object의 freepointer 값을 NULL 로 변경, 나머지 object들의 freepointer 값을 이전 object들의 주소로 변경)
	//
	// kmem_cache_node용 slab의 사용 상태
	// 에) s->offset이 0이고 slab object 시작 주소가 0x10001000 일 경우
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | Slab object 0 (사용중) | Slab object 1 (사용중) | Slab object 2          | Slab object 3          | Slab object 3          | .... | Slab object 63         |
	// | [boot_kmem_cache_node] | [boot_kmem_cache]      |                        |                       |                         |      |                        |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | object start address:  | object start address:  | object start address:  | object start address:  | object start address:  |      | object start address:  |
	// | 0x10001000             | 0x10001040             | 0x10001080             | 0x100010C0             | 0x10001100             | .... | 0x10001fc0             |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | freepointer | data     | freepointer | data     | freepointer | data     | freepointer | data     | freepointer | data     | .... | freepointer | data     |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	// | (덮어씀)    | 60 Bytes | (덮어씀)    | 60 Bytes | null        | 60 Bytes | 0x10001080  | 60 Bytes | 0x100010C0  | 60 Bytes | .... | 0x10001f80  | 60 Bytes |
	// --------------------------------------------------------------------------------------------------------------------------------------------------------------
	//
	// n: (&boot_kmem_cache_node 용 object 주소)->node[0]:
	// boot_kmem_cache_node 로 할당 받은 1 번째 object의 주소
	// n->nr_partial: 1
	// n->partial에 (UNMOVABLE인 page)->lru 가 추가됨
	//
	// c: (&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋)
	// c->tid: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 8
	// c->page: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->page: NULL
	// c->freelist: ((&boot_kmem_cache_node 용 object 주소)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist: NULL
	//
	// p->slab_cache: (UNMOVABLE인 page)->slab_cache:
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	//
	// slab_caches 의 list에 (UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968)->list를 등록

// 2014/07/12 종료
// 2014/07/19 시작

	/* Now we can use the kmem_cache to allocate kmalloc slabs */
	create_kmalloc_caches(0);

	// create_kmalloc_caches 가 한일:
	// 배열 size_index[] 값을 변경, kmalloc_caches[] 값을 채워줌
	//
	// size_index[0 .. 6]: 6
	// size_index[8 .. 11]: 7
	//
	// kmem_cache object를 1개 할당받음
	// kmem_cache_node object를 1개 할당받음
	// kmem_cache 의 refcount 가 1로 set
	// slab_caches에 kmem_cache의 list 추가
	//
	// kmalloc_caches[6]:
	// # order: 0, object size: 64
	// kmem_cache#30
	// - kmem_cache#30->allocflags: 0
	// - kmem_cache#30->oo.x: 0x40
	// - kmem_cache#30->min.x: 0x40
	// - kmem_cache#30->max.x: 0x40
	// - kmem_cache#30->min_partial: 5
	// - kmem_cache#30->cpu_partial: 30
	// - kmem_cache#30->name: "kmalloc-64"
	// kmem_cache_node#63
	//
	// kmalloc_caches[7]:
	// # order: 0, object size: 128
	// kmem_cache#29
	// - kmem_cache#29->allocflags: 0
	// - kmem_cache#29->oo.x: 0x20
	// - kmem_cache#29->min.x: 0x20
	// - kmem_cache#29->max.x: 0x20
	// - kmem_cache#29->min_partial: 5
	// - kmem_cache#29->cpu_partial: 30
	// - kmem_cache#29->name: "kmalloc-128"
	// kmem_cache_node#62
	//
	// kmalloc_caches[2]:
	// # order: 0, object size: 192
	// kmem_cache#28
	// - kmem_cache#28->allocflags: 0
	// - kmem_cache#28->oo.x: 0x15
	// - kmem_cache#28->min.x: 0x15
	// - kmem_cache#28->max.x: 0x15
	// - kmem_cache#28->min_partial: 5
	// - kmem_cache#28->cpu_partial: 30
	// - kmem_cache#28->name: "kmalloc-192"
	// kmem_cache_node#61
	//
	// kmalloc_caches[8]:
	// # order: 0, object size: 256
	// kmem_cache#27
	// - kmem_cache#27->allocflags: 0
	// - kmem_cache#27->oo.x: 0x10
	// - kmem_cache#27->min.x: 0x10
	// - kmem_cache#27->max.x: 0x10
	// - kmem_cache#27->min_partial: 5
	// - kmem_cache#27->cpu_partial: 13
	// - kmem_cache#27->name: "kmalloc-256"
	// kmem_cache_node#60
	//
	// kmalloc_caches[9]:
	// # order: 1, object size: 512
	// kmem_cache#26
	// - kmem_cache#26->allocflags: __GFP_COMP (0x4000)
	// - kmem_cache#26->oo.x: 0x10010
	// - kmem_cache#26->min.x: 0x8
	// - kmem_cache#26->max.x: 0x10010
	// - kmem_cache#26->min_partial: 5
	// - kmem_cache#26->cpu_partial: 13
	// - kmem_cache#26->name: "kmalloc-512"
	// kmem_cache_node#59
	//
	// kmalloc_caches[10]:
	// # order: 2, object size: 1024
	// kmem_cache#25
	// - kmem_cache#25->allocflags: __GFP_COMP (0x4000)
	// - kmem_cache#25->oo.x: 0x20020
	// - kmem_cache#25->min.x: 0x4
	// - kmem_cache#25->max.x: 0x20020
	// - kmem_cache#25->min_partial: 5
	// - kmem_cache#25->cpu_partial: 6
	// - kmem_cache#25->name: "kmalloc-1024"
	// kmem_cache_node#58
	//
	// kmalloc_caches[11]:
	// # order: 3, object size: 2048
	// kmem_cache#24
	// - kmem_cache#24->allocflags: __GFP_COMP (0x4000)
	// - kmem_cache#24->oo.x: 0x30010
	// - kmem_cache#24->min.x: 0x2
	// - kmem_cache#24->max.x: 0x30010
	// - kmem_cache#24->min_partial: 5
	// - kmem_cache#24->cpu_partial: 6
	// - kmem_cache#24->name: "kmalloc-2048"
	// kmem_cache_node#57
	//
	// kmalloc_caches[12]:
	// # order: 3, object size: 4096
	// kmem_cache#23
	// - kmem_cache#23->allocflags: __GFP_COMP (0x4000)
	// - kmem_cache#23->oo.x: 0x30008
	// - kmem_cache#23->min.x: 0x10002
	// - kmem_cache#23->max.x: 0x30008
	// - kmem_cache#23->min_partial: 6
	// - kmem_cache#23->cpu_partial: 2
	// - kmem_cache#23->name: "kmalloc-4096"
	// kmem_cache_node#56
	//
	// kmalloc_caches[13]:
	// # order: 3, object size: 8192
	// kmem_cache#22
	// - kmem_cache#22->allocflags: __GFP_COMP (0x4000)
	// - kmem_cache#22->oo.x: 0x30004
	// - kmem_cache#22->min.x: 0x10001
	// - kmem_cache#22->max.x: 0x30004
	// - kmem_cache#22->min_partial: 6
	// - kmem_cache#22->cpu_partial: 2
	// - kmem_cache#22->name: "kmalloc-8192"
	// kmem_cache_node#55
	//
	// slab_state: UP
 
#ifdef CONFIG_SMP // CONFIG_SMP=y
	register_cpu_notifier(&slab_notifier);
	// (&cpu_chain)->head: slab_notifier 포인터 대입
	// (&slab_notifier)->next은 (&page_alloc_cpu_notify_nb)->next로 대입
#endif

	// KERN_INFO: "\001" "6", cache_line_size(): 64
	// slub_min_order: 0, slub_max_order: 3, slub_min_objects: 0
	// nr_cpu_ids: 4, nr_node_ids: 1
	printk(KERN_INFO
		"SLUB: HWalign=%d, Order=%d-%d, MinObjects=%d,"
		" CPUs=%d, Nodes=%d\n",
		cache_line_size(),
		slub_min_order, slub_max_order, slub_min_objects,
		nr_cpu_ids, nr_node_ids);
	// "SLUB: HWalign=64, Order=0-3, MinObjects=0," " CPUs=4, Nodes=1"
}

void __init kmem_cache_init_late(void)
{
}

/*
 * Find a mergeable slab cache
 */
// ARM10C 20140920
// s: &kmalloc_caches[11]
static int slab_unmergeable(struct kmem_cache *s)
{
	// slub_nomerge: 0, s->flags: (&kmalloc_caches[11])->flags: 0, SLUB_NEVER_MERGE: 0xA90C00
	if (slub_nomerge || (s->flags & SLUB_NEVER_MERGE))
		return 1;

	// s->ctor: (&kmalloc_caches[11])->ctor: NULL
	if (s->ctor)
		return 1;

	/*
	 * We may have set a slab to be unmergeable during bootstrap.
	 */
	// s->refcount: (&kmalloc_caches[11])->refcount: 1
	if (s->refcount < 0)
		return 1;

	return 0;
	// return 0
}

// ARM10C 20140920
// memcg: NULL, size: 1076, align: 0, flags: SLAB_PANIC: 0x00040000UL, name: "idr_layer_cache", ctor: NULL
static struct kmem_cache *find_mergeable(struct mem_cgroup *memcg, size_t size,
		size_t align, unsigned long flags, const char *name,
		void (*ctor)(void *))
{
	struct kmem_cache *s;

	// slub_nomerge: 0, flags: SLAB_PANIC: 0x00040000UL, SLUB_NEVER_MERGE: 0xA90C00
	if (slub_nomerge || (flags & SLUB_NEVER_MERGE))
		return NULL;

	// ctor: NULL
	if (ctor)
		return NULL;

	// size: 1076, sizeof(void *): 4
	size = ALIGN(size, sizeof(void *));
	// size: 1076

	// flags: SLAB_PANIC: 0x00040000UL, align: 0, size: 1076
	// calculate_alignment(SLAB_PANIC: 0x00040000UL, 0, 1076): 8
	align = calculate_alignment(flags, align, size);
	// align: 8

	// size: 1076, align: 8
	size = ALIGN(size, align);
	// size: 1080

	// size: 1080, flags: SLAB_PANIC: 0x00040000UL, name: "idr_layer_cache"
	flags = kmem_cache_flags(size, flags, name, NULL);
	// flags: SLAB_PANIC: 0x00040000UL

	list_for_each_entry(s, &slab_caches, list) {
	// for (s = list_first_entry(&slab_caches, typeof(*s), list);
	//      &s->list != (&slab_caches); s = list_next_entry(s, list))

		// s: &kmalloc_caches[11]

		// NOTE:
		// slab_caches에 연결된 kmem_cache들 중 현재 size: 1080에 맞는 kmem_cache를 선택

		// s: &kmalloc_caches[11]
		// slab_unmergeable(&kmalloc_caches[11]): 0
		if (slab_unmergeable(s))
			continue;

		// size: 1080, s->size: (&kmalloc_caches[11])->size: 2048
		if (size > s->size)
			continue;

		// flags: SLAB_PANIC: 0x00040000UL, SLUB_MERGE_SAME: 0x24100
		// s->flags: (&kmalloc_caches[11])->flags: 0
		if ((flags & SLUB_MERGE_SAME) != (s->flags & SLUB_MERGE_SAME))
				continue;
		/*
		 * Check if alignment is compatible.
		 * Courtesy of Adrian Drzewiecki
		 */
		// s->size: (&kmalloc_caches[11])->size: 2048, align: 8
		if ((s->size & ~(align - 1)) != s->size)
			continue;

		// s->size: (&kmalloc_caches[11])->size: 2048, size: 1080, sizeof(void *): 4
		if (s->size - size >= sizeof(void *))
			continue;
			// continue 수행

		if (!cache_match_memcg(s, memcg))
			continue;

		return s;
	}
	// &slab_caches 에 등록된 kmem_cache 중 size: 1080 에 적합한 것을 찾지 못함

	return NULL;
	// return NULL
}

// ARM10C 20140920
// memcg: NULL, name: "idr_layer_cache", size: 1076, align: 0, flags: SLAB_PANIC: 0x00040000UL, ctor: NULL
struct kmem_cache *
__kmem_cache_alias(struct mem_cgroup *memcg, const char *name, size_t size,
		   size_t align, unsigned long flags, void (*ctor)(void *))
{
	struct kmem_cache *s;

	// memcg: NULL, size: 1076, align: 0, flags: SLAB_PANIC: 0x00040000UL, name: "idr_layer_cache", ctor: NULL
	// find_mergeable(NULL, 1076, 0, SLAB_PANIC: 0x00040000UL, "idr_layer_cache", NULL): NULL
	s = find_mergeable(memcg, size, align, flags, name, ctor);
	// s: NULL

	// s: NULL
	if (s) {
		s->refcount++;
		/*
		 * Adjust the object sizes so that we clear
		 * the complete object on kzalloc.
		 */
		s->object_size = max(s->object_size, (int)size);
		s->inuse = max_t(int, s->inuse, ALIGN(size, sizeof(void *)));

		if (sysfs_slab_alias(s, name)) {
			s->refcount--;
			s = NULL;
		}
	}

	// s: NULL
	return s;
	// return NULL
}

// ARM10C 20140419
// s: &boot_kmem_cache_node, flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
// ARM10C 20140614
// s: &boot_kmem_cache, flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
// ARM10C 20140726
// s: &kmem_cache#30, flags: 0
// ARM10C 20140726
// s: &kmem_cache#23, flags: 0
// ARM10C 20140920
// s: kmem_cache#21, flags: SLAB_PANIC: 0x00040000UL
int __kmem_cache_create(struct kmem_cache *s, unsigned long flags)
{
	int err;

	// s: &boot_kmem_cache_node, flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// kmem_cache_open(&boot_kmem_cache_node, 0x00002000UL): 0
	// s: &boot_kmem_cache, flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// kmem_cache_open(&boot_kmem_cache, 0x00002000UL): 0
	// s: &kmem_cache#30, flags: 0
	// kmem_cache_open(&kmem_cache#30, 0): 0
	// s: &kmem_cache#23, flags: 0
	// kmem_cache_open(&kmem_cache#23, 0): 0
	// s: &kmem_cache#21, flags: SLAB_PANIC: 0x00040000UL
	// kmem_cache_open(&kmem_cache#21, SLAB_PANIC: 0x00040000UL): 0
	err = kmem_cache_open(s, flags);
	// err: 0
	// err: 0
	// err: 0
	// err: 0
	// err: 0

// 2014/06/21 종료
// 2014/06/28 시작

	// kmem_cache_open(&boot_kmem_cache_node) 가 한일:
	// boot_kmem_cache_node.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// boot_kmem_cache_node.reserved: 0
	// boot_kmem_cache_node.min_partial: 5
	// boot_kmem_cache_node.cpu_partial: 30
	//
	// migratetype이 MIGRATE_UNMOVABLE인 page 할당 받음
	// page 맴버를 셋팅함
	// page->slab_cache: &boot_kmem_cache_node 주소를 set
	// page->flags에 7 (PG_slab) bit를 set
	// page->freelist: UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// page->inuse: 1, page->frozen: 0 page 맴버를 셋팅함
	// slab 의 objects 들의 freepointer를 맵핑함
	// 할당받은 slab object를 kmem_cache_node 로 사용하고 kmem_cache_node의 멤버 필드를 초기화함
	// (UNMOVABLE인 page 의 object의 시작 virtual address (kmem_cache_node#0))
	// (kmem_cache_node#0)->nr_partial: 1
	// (kmem_cache_node#0)->list_lock: spinlock 초기화 수행
	// (kmem_cache_node#0)->slabs: 1, kmem_cache_node->total_objects: 64 로 세팀함
	// (kmem_cache_node#0)->full: 리스트 초기화
	// (kmem_cache_node#0)의 partial 맴버에 현재 page의 lru 리스트를 추가함
	//
	// kmem_cache_node#0 가 boot_kmem_cache_node.node[0]에 할당됨
	//
	// 할당받은 pcpu 들의 16 byte 공간 (&boot_kmem_cache_node)->cpu_slab 에
	// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

	// kmem_cache_open(&boot_kmem_cache) 가 한일:
	// boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// boot_kmem_cache.reserved: 0
	// boot_kmem_cache.min_partial: 5
	// boot_kmem_cache.cpu_partial: 30
	//
	// MIGRATE_UNMOVABLE인 page 할당 받아 쪼개놓은 object들에서 object를 1개 할당받음
	// (UNMOVABLE인 page 의 object의 시작 virtual address + 64 (kmem_cache_node#1))
	// page 맴버를 셋팅함
	// page->counters: 0x80400040
	// page->inuse: 64
	// page->objects: 64
	// page->frozen: 1
	// page->freelist: NULL
	// c->freelist: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->freelist:
	// UNMOVABLE인 page 의 object의 시작 virtual address + 128
	// c->tid: ((&boot_kmem_cache_node)->cpu_slab + (pcpu_unit_offsets[0] + __per_cpu_start에서의pcpu_base_addr의 옵셋))->tid: 4
	// 할당받은 slab object를 kmem_cache_node 로 사용하고 kmem_cache_node의 멤버 필드를 초기화함
	// 1번째 object:
	// (kmem_cache_node#0)->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
	// (kmem_cache_node#0)->nr_partial: 0
	// 2번째 object:
	// (kmem_cache_node#1)->nr_partial: 0
	// (kmem_cache_node#1)->list_lock: spinlock 초기화 수행
	// (kmem_cache_node#1)->slabs: 0,
	// (kmem_cache_node#1)->total_objects: 0 로 세팀함
	// (kmem_cache_node#1)->full: 리스트 초기화
	//
	// kmem_cache_node#1 가 boot_kmem_cache.node[0]에 할당됨
	//
	// 할당받은 pcpu 들의 16 byte 공간 (&boot_kmem_cache)->cpu_slab 에
	// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

	// kmem_cache_open(&kmem_cache#30) 가 한일:
	// kmem_cache#30.flags: 0
	// kmem_cache#30.reserved: 0
	// kmem_cache#30.min_partial: 5
	// kmem_cache#30.cpu_partial: 30
	//
	// 할당 받아 놓은 migratetype이 MIGRATE_UNMOVABLE인 page 를 사용
	// page 맴버를 셋팅함
	// page->counters: 0x80400040
	// page->inuse: 64
	// page->objects: 64
	// page->frozen: 1
	// page->freelist: NULL
	// MIGRATE_UNMOVABLE인 page 할당 받아 쪼개놓은 object들에서 object를 1개 할당받음
	// (UNMOVABLE인 page 의 object의 시작 virtual address + 4032 (kmem_cache_node#63))
	// 2번째 object:
	// (kmem_cache_node#1)->partial에 연결된 (MIGRATE_UNMOVABLE인 page)->lru 를 삭제
	// (kmem_cache_node#1)->nr_partial: 0
	// 64번째 object:
	// (kmem_cache_node#63)->nr_partial: 0
	// (kmem_cache_node#63)->list_lock: spinlock 초기화 수행
	// (kmem_cache_node#63)->slabs: 0, kmem_cache_node->total_objects: 0 로 세팀함
	// (kmem_cache_node#63)->full: 리스트 초기화
	//
	// kmem_cache_node#63 가 kmem_cache#30.node[0]에 할당됨
	//
	// 할당받은 pcpu 들의 16 byte 공간 (&kmem_cache#30)->cpu_slab 에
	// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

	// kmem_cache_open(&kmem_cache#23) 가 한일:
	// kmem_cache#23.flags: 0
	// kmem_cache#23.reserved: 0
	// kmem_cache#23.min_partial: 6
	// kmem_cache#23.cpu_partial: 2
	//
	// 할당 받아 놓은 migratetype이 MIGRATE_UNMOVABLE인 page 를 사용
	// page 맴버를 셋팅함
	// page->counters: 0x80400040
	// page->inuse: 64
	// page->objects: 64
	// page->frozen: 1
	// page->freelist: NULL
	// MIGRATE_UNMOVABLE인 page 할당 받아 쪼개놓은 object들에서 object를 1개 할당받음
	// (UNMOVABLE인 page 의 object의 시작 virtual address + 3968 (kmem_cache_node#62))
	// 63번째 object:
	// (kmem_cache_node#62)->nr_partial: 0
	// (kmem_cache_node#62)->list_lock: spinlock 초기화 수행
	// (kmem_cache_node#62)->slabs: 0,
	// (kmem_cache_node#62)->total_objects: 0 로 세팀함
	// (kmem_cache_node#62)->full: 리스트 초기화
	//
	// kmem_cache_node#62 가 kmem_cache#23.node[0]에 할당됨
	//
	// 할당받은 pcpu 들의 16 byte 공간 (&kmem_cache#23)->cpu_slab 에
	// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

	// kmem_cache_open(&kmem_cache#21) 가 한일:
	// kmem_cache#21.flags: SLAB_PANIC: 0x00040000UL
	// kmem_cache#21.reserved: 0
	// kmem_cache#21.min_partial: 5
	// kmem_cache#21.cpu_partial: 6
	//
	// 할당 받아 놓은 migratetype이 MIGRATE_UNMOVABLE인 page 를 사용
	// page 맴버를 셋팅함
	// page->counters: 0x80400040
	// page->inuse: 64
	// page->objects: 64
	// page->frozen: 1
	// page->freelist: NULL
	// MIGRATE_UNMOVABLE인 page 할당 받아 쪼개놓은 object들에서 object를 1개 할당받음
	// (UNMOVABLE인 page 의 object의 시작 virtual address + 3456 (kmem_cache_node#54))
	// 55번째 object:
	// (kmem_cache_node#54)->nr_partial: 0
	// (kmem_cache_node#54)->list_lock: spinlock 초기화 수행
	// (kmem_cache_node#54)->slabs: 0,
	// (kmem_cache_node#54)->total_objects: 0 로 세팀함
	// (kmem_cache_node#54)->full: 리스트 초기화
	//
	// kmem_cache_node#54 가 kmem_cache#21.node[0]에 할당됨
	//
	// 할당받은 pcpu 들의 16 byte 공간 (&kmem_cache#21)->cpu_slab 에
	// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정


	// err: 0
	// err: 0
	// err: 0
	// err: 0
	// err: 0
	if (err)
		return err;

	/* Mutex is not taken during early boot */
	// slab_state: DOWN: 0, UP: 4
	// slab_state: PARTIAL: 1, UP: 4
	// slab_state: PARTIAL: 1, UP: 4
	// slab_state: PARTIAL: 1, UP: 4
	// slab_state: UP: 4, UP: 4
	if (slab_state <= UP)
		return 0;
		// return 0
		// return 0
		// return 0
		// return 0
		// return 0

	memcg_propagate_slab_attrs(s);
	mutex_unlock(&slab_mutex);
	err = sysfs_slab_add(s);
	mutex_lock(&slab_mutex);

	if (err)
		kmem_cache_close(s);

	return err;
}

#ifdef CONFIG_SMP // CONFIG_SMP=y
/*
 * Use the cpu notifier to insure that the cpu slabs are flushed when
 * necessary.
 */
static int slab_cpuup_callback(struct notifier_block *nfb,
		unsigned long action, void *hcpu)
{
	long cpu = (long)hcpu;
	struct kmem_cache *s;
	unsigned long flags;

	switch (action) {
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		mutex_lock(&slab_mutex);
		list_for_each_entry(s, &slab_caches, list) {
			local_irq_save(flags);
			__flush_cpu_slab(s, cpu);
			local_irq_restore(flags);
		}
		mutex_unlock(&slab_mutex);
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

// ARM10C 20140726
static struct notifier_block slab_notifier = {
	.notifier_call = slab_cpuup_callback
};

#endif

// ARM10C 20140726
// len: 12, gfp: GFP_NOWAIT: 0, _RET_IP_
// ARM10C 20140920
// len: 16, gfp: GFP_KERNEL: 0xD0, _RET_IP_
void *__kmalloc_track_caller(size_t size, gfp_t gfpflags, unsigned long caller)
{
	struct kmem_cache *s;
	void *ret;

	// size: 12, KMALLOC_MAX_CACHE_SIZE: 0x2000
	// size: 16, KMALLOC_MAX_CACHE_SIZE: 0x2000
	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE))
		return kmalloc_large(size, gfpflags);

	// size: 12, gfpflags: GFP_NOWAIT: 0
	// kmalloc_slab(12, 0): kmem_cache#30
	// size: 16, gfpflags: GFP_KERNEL: 0xD0
	// kmalloc_slab(16, 0xD0): kmem_cache#30
	s = kmalloc_slab(size, gfpflags);
	// s: kmem_cache#30
	// s: kmem_cache#30

	// s: kmem_cache#30, ZERO_OR_NULL_PTR(kmem_cache#30): 0
	// s: kmem_cache#30, ZERO_OR_NULL_PTR(kmem_cache#30): 0
	if (unlikely(ZERO_OR_NULL_PTR(s)))
		return s;

	// s: kmem_cache#30, gfpflags: GFP_NOWAIT: 0, _RET_IP_
	// slab_alloc(kmem_cache#30, GFP_NOWAIT: 0, _RET_IP_):
	// UNMOVABLE인 page (kmem_cache#30)의 시작 virtual address (kmem_cache#30-o0)
	// s: kmem_cache#30, gfpflags: GFP_KERNEL: 0xD0, _RET_IP_
	// slab_alloc(kmem_cache#30, GFP_NOWAIT: 0, _RET_IP_):
	// kmem_cache#30-oX
	ret = slab_alloc(s, gfpflags, caller);
	// ret: kmem_cache#30-o0
	// ret: kmem_cache#30-o17

	/* Honor the call site pointer we received. */
	trace_kmalloc(caller, ret, size, s->size, gfpflags);

	// ret: kmem_cache#30-o0
	// ret: kmem_cache#30-o17
	return ret;
	// return kmem_cache#30-o0
	// return kmem_cache#30-o17
}

#ifdef CONFIG_NUMA
void *__kmalloc_node_track_caller(size_t size, gfp_t gfpflags,
					int node, unsigned long caller)
{
	struct kmem_cache *s;
	void *ret;

	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE)) {
		ret = kmalloc_large_node(size, gfpflags, node);

		trace_kmalloc_node(caller, ret,
				   size, PAGE_SIZE << get_order(size),
				   gfpflags, node);

		return ret;
	}

	s = kmalloc_slab(size, gfpflags);

	if (unlikely(ZERO_OR_NULL_PTR(s)))
		return s;

	ret = slab_alloc_node(s, gfpflags, node, caller);

	/* Honor the call site pointer we received. */
	trace_kmalloc_node(caller, ret, size, s->size, gfpflags, node);

	return ret;
}
#endif

#ifdef CONFIG_SYSFS
static int count_inuse(struct page *page)
{
	return page->inuse;
}

static int count_total(struct page *page)
{
	return page->objects;
}
#endif

#ifdef CONFIG_SLUB_DEBUG
static int validate_slab(struct kmem_cache *s, struct page *page,
						unsigned long *map)
{
	void *p;
	void *addr = page_address(page);

	if (!check_slab(s, page) ||
			!on_freelist(s, page, NULL))
		return 0;

	/* Now we know that a valid freelist exists */
	bitmap_zero(map, page->objects);

	get_map(s, page, map);
	for_each_object(p, s, addr, page->objects) {
		if (test_bit(slab_index(p, s, addr), map))
			if (!check_object(s, page, p, SLUB_RED_INACTIVE))
				return 0;
	}

	for_each_object(p, s, addr, page->objects)
		if (!test_bit(slab_index(p, s, addr), map))
			if (!check_object(s, page, p, SLUB_RED_ACTIVE))
				return 0;
	return 1;
}

static void validate_slab_slab(struct kmem_cache *s, struct page *page,
						unsigned long *map)
{
	slab_lock(page);
	validate_slab(s, page, map);
	slab_unlock(page);
}

static int validate_slab_node(struct kmem_cache *s,
		struct kmem_cache_node *n, unsigned long *map)
{
	unsigned long count = 0;
	struct page *page;
	unsigned long flags;

	spin_lock_irqsave(&n->list_lock, flags);

	list_for_each_entry(page, &n->partial, lru) {
		validate_slab_slab(s, page, map);
		count++;
	}
	if (count != n->nr_partial)
		printk(KERN_ERR "SLUB %s: %ld partial slabs counted but "
			"counter=%ld\n", s->name, count, n->nr_partial);

	if (!(s->flags & SLAB_STORE_USER))
		goto out;

	list_for_each_entry(page, &n->full, lru) {
		validate_slab_slab(s, page, map);
		count++;
	}
	if (count != atomic_long_read(&n->nr_slabs))
		printk(KERN_ERR "SLUB: %s %ld slabs counted but "
			"counter=%ld\n", s->name, count,
			atomic_long_read(&n->nr_slabs));

out:
	spin_unlock_irqrestore(&n->list_lock, flags);
	return count;
}

static long validate_slab_cache(struct kmem_cache *s)
{
	int node;
	unsigned long count = 0;
	unsigned long *map = kmalloc(BITS_TO_LONGS(oo_objects(s->max)) *
				sizeof(unsigned long), GFP_KERNEL);

	if (!map)
		return -ENOMEM;

	flush_all(s);
	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n = get_node(s, node);

		count += validate_slab_node(s, n, map);
	}
	kfree(map);
	return count;
}
/*
 * Generate lists of code addresses where slabcache objects are allocated
 * and freed.
 */

struct location {
	unsigned long count;
	unsigned long addr;
	long long sum_time;
	long min_time;
	long max_time;
	long min_pid;
	long max_pid;
	DECLARE_BITMAP(cpus, NR_CPUS);
	nodemask_t nodes;
};

struct loc_track {
	unsigned long max;
	unsigned long count;
	struct location *loc;
};

static void free_loc_track(struct loc_track *t)
{
	if (t->max)
		free_pages((unsigned long)t->loc,
			get_order(sizeof(struct location) * t->max));
}

static int alloc_loc_track(struct loc_track *t, unsigned long max, gfp_t flags)
{
	struct location *l;
	int order;

	order = get_order(sizeof(struct location) * max);

	l = (void *)__get_free_pages(flags, order);
	if (!l)
		return 0;

	if (t->count) {
		memcpy(l, t->loc, sizeof(struct location) * t->count);
		free_loc_track(t);
	}
	t->max = max;
	t->loc = l;
	return 1;
}

static int add_location(struct loc_track *t, struct kmem_cache *s,
				const struct track *track)
{
	long start, end, pos;
	struct location *l;
	unsigned long caddr;
	unsigned long age = jiffies - track->when;

	start = -1;
	end = t->count;

	for ( ; ; ) {
		pos = start + (end - start + 1) / 2;

		/*
		 * There is nothing at "end". If we end up there
		 * we need to add something to before end.
		 */
		if (pos == end)
			break;

		caddr = t->loc[pos].addr;
		if (track->addr == caddr) {

			l = &t->loc[pos];
			l->count++;
			if (track->when) {
				l->sum_time += age;
				if (age < l->min_time)
					l->min_time = age;
				if (age > l->max_time)
					l->max_time = age;

				if (track->pid < l->min_pid)
					l->min_pid = track->pid;
				if (track->pid > l->max_pid)
					l->max_pid = track->pid;

				cpumask_set_cpu(track->cpu,
						to_cpumask(l->cpus));
			}
			node_set(page_to_nid(virt_to_page(track)), l->nodes);
			return 1;
		}

		if (track->addr < caddr)
			end = pos;
		else
			start = pos;
	}

	/*
	 * Not found. Insert new tracking element.
	 */
	if (t->count >= t->max && !alloc_loc_track(t, 2 * t->max, GFP_ATOMIC))
		return 0;

	l = t->loc + pos;
	if (pos < t->count)
		memmove(l + 1, l,
			(t->count - pos) * sizeof(struct location));
	t->count++;
	l->count = 1;
	l->addr = track->addr;
	l->sum_time = age;
	l->min_time = age;
	l->max_time = age;
	l->min_pid = track->pid;
	l->max_pid = track->pid;
	cpumask_clear(to_cpumask(l->cpus));
	cpumask_set_cpu(track->cpu, to_cpumask(l->cpus));
	nodes_clear(l->nodes);
	node_set(page_to_nid(virt_to_page(track)), l->nodes);
	return 1;
}

static void process_slab(struct loc_track *t, struct kmem_cache *s,
		struct page *page, enum track_item alloc,
		unsigned long *map)
{
	void *addr = page_address(page);
	void *p;

	bitmap_zero(map, page->objects);
	get_map(s, page, map);

	for_each_object(p, s, addr, page->objects)
		if (!test_bit(slab_index(p, s, addr), map))
			add_location(t, s, get_track(s, p, alloc));
}

static int list_locations(struct kmem_cache *s, char *buf,
					enum track_item alloc)
{
	int len = 0;
	unsigned long i;
	struct loc_track t = { 0, 0, NULL };
	int node;
	unsigned long *map = kmalloc(BITS_TO_LONGS(oo_objects(s->max)) *
				     sizeof(unsigned long), GFP_KERNEL);

	if (!map || !alloc_loc_track(&t, PAGE_SIZE / sizeof(struct location),
				     GFP_TEMPORARY)) {
		kfree(map);
		return sprintf(buf, "Out of memory\n");
	}
	/* Push back cpu slabs */
	flush_all(s);

	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n = get_node(s, node);
		unsigned long flags;
		struct page *page;

		if (!atomic_long_read(&n->nr_slabs))
			continue;

		spin_lock_irqsave(&n->list_lock, flags);
		list_for_each_entry(page, &n->partial, lru)
			process_slab(&t, s, page, alloc, map);
		list_for_each_entry(page, &n->full, lru)
			process_slab(&t, s, page, alloc, map);
		spin_unlock_irqrestore(&n->list_lock, flags);
	}

	for (i = 0; i < t.count; i++) {
		struct location *l = &t.loc[i];

		if (len > PAGE_SIZE - KSYM_SYMBOL_LEN - 100)
			break;
		len += sprintf(buf + len, "%7ld ", l->count);

		if (l->addr)
			len += sprintf(buf + len, "%pS", (void *)l->addr);
		else
			len += sprintf(buf + len, "<not-available>");

		if (l->sum_time != l->min_time) {
			len += sprintf(buf + len, " age=%ld/%ld/%ld",
				l->min_time,
				(long)div_u64(l->sum_time, l->count),
				l->max_time);
		} else
			len += sprintf(buf + len, " age=%ld",
				l->min_time);

		if (l->min_pid != l->max_pid)
			len += sprintf(buf + len, " pid=%ld-%ld",
				l->min_pid, l->max_pid);
		else
			len += sprintf(buf + len, " pid=%ld",
				l->min_pid);

		if (num_online_cpus() > 1 &&
				!cpumask_empty(to_cpumask(l->cpus)) &&
				len < PAGE_SIZE - 60) {
			len += sprintf(buf + len, " cpus=");
			len += cpulist_scnprintf(buf + len,
						 PAGE_SIZE - len - 50,
						 to_cpumask(l->cpus));
		}

		if (nr_online_nodes > 1 && !nodes_empty(l->nodes) &&
				len < PAGE_SIZE - 60) {
			len += sprintf(buf + len, " nodes=");
			len += nodelist_scnprintf(buf + len,
						  PAGE_SIZE - len - 50,
						  l->nodes);
		}

		len += sprintf(buf + len, "\n");
	}

	free_loc_track(&t);
	kfree(map);
	if (!t.count)
		len += sprintf(buf, "No data\n");
	return len;
}
#endif

#ifdef SLUB_RESILIENCY_TEST
static void resiliency_test(void)
{
	u8 *p;

	BUILD_BUG_ON(KMALLOC_MIN_SIZE > 16 || KMALLOC_SHIFT_HIGH < 10);

	printk(KERN_ERR "SLUB resiliency testing\n");
	printk(KERN_ERR "-----------------------\n");
	printk(KERN_ERR "A. Corruption after allocation\n");

	p = kzalloc(16, GFP_KERNEL);
	p[16] = 0x12;
	printk(KERN_ERR "\n1. kmalloc-16: Clobber Redzone/next pointer"
			" 0x12->0x%p\n\n", p + 16);

	validate_slab_cache(kmalloc_caches[4]);

	/* Hmmm... The next two are dangerous */
	p = kzalloc(32, GFP_KERNEL);
	p[32 + sizeof(void *)] = 0x34;
	printk(KERN_ERR "\n2. kmalloc-32: Clobber next pointer/next slab"
			" 0x34 -> -0x%p\n", p);
	printk(KERN_ERR
		"If allocated object is overwritten then not detectable\n\n");

	validate_slab_cache(kmalloc_caches[5]);
	p = kzalloc(64, GFP_KERNEL);
	p += 64 + (get_cycles() & 0xff) * sizeof(void *);
	*p = 0x56;
	printk(KERN_ERR "\n3. kmalloc-64: corrupting random byte 0x56->0x%p\n",
									p);
	printk(KERN_ERR
		"If allocated object is overwritten then not detectable\n\n");
	validate_slab_cache(kmalloc_caches[6]);

	printk(KERN_ERR "\nB. Corruption after free\n");
	p = kzalloc(128, GFP_KERNEL);
	kfree(p);
	*p = 0x78;
	printk(KERN_ERR "1. kmalloc-128: Clobber first word 0x78->0x%p\n\n", p);
	validate_slab_cache(kmalloc_caches[7]);

	p = kzalloc(256, GFP_KERNEL);
	kfree(p);
	p[50] = 0x9a;
	printk(KERN_ERR "\n2. kmalloc-256: Clobber 50th byte 0x9a->0x%p\n\n",
			p);
	validate_slab_cache(kmalloc_caches[8]);

	p = kzalloc(512, GFP_KERNEL);
	kfree(p);
	p[512] = 0xab;
	printk(KERN_ERR "\n3. kmalloc-512: Clobber redzone 0xab->0x%p\n\n", p);
	validate_slab_cache(kmalloc_caches[9]);
}
#else
#ifdef CONFIG_SYSFS
static void resiliency_test(void) {};
#endif
#endif

#ifdef CONFIG_SYSFS
enum slab_stat_type {
	SL_ALL,			/* All slabs */
	SL_PARTIAL,		/* Only partially allocated slabs */
	SL_CPU,			/* Only slabs used for cpu caches */
	SL_OBJECTS,		/* Determine allocated objects not slabs */
	SL_TOTAL		/* Determine object capacity not slabs */
};

#define SO_ALL		(1 << SL_ALL)
#define SO_PARTIAL	(1 << SL_PARTIAL)
#define SO_CPU		(1 << SL_CPU)
#define SO_OBJECTS	(1 << SL_OBJECTS)
#define SO_TOTAL	(1 << SL_TOTAL)

static ssize_t show_slab_objects(struct kmem_cache *s,
			    char *buf, unsigned long flags)
{
	unsigned long total = 0;
	int node;
	int x;
	unsigned long *nodes;

	nodes = kzalloc(sizeof(unsigned long) * nr_node_ids, GFP_KERNEL);
	if (!nodes)
		return -ENOMEM;

	if (flags & SO_CPU) {
		int cpu;

		for_each_possible_cpu(cpu) {
			struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab,
							       cpu);
			int node;
			struct page *page;

			page = ACCESS_ONCE(c->page);
			if (!page)
				continue;

			node = page_to_nid(page);
			if (flags & SO_TOTAL)
				x = page->objects;
			else if (flags & SO_OBJECTS)
				x = page->inuse;
			else
				x = 1;

			total += x;
			nodes[node] += x;

			page = ACCESS_ONCE(c->partial);
			if (page) {
				node = page_to_nid(page);
				if (flags & SO_TOTAL)
					WARN_ON_ONCE(1);
				else if (flags & SO_OBJECTS)
					WARN_ON_ONCE(1);
				else
					x = page->pages;
				total += x;
				nodes[node] += x;
			}
		}
	}

	lock_memory_hotplug();
#ifdef CONFIG_SLUB_DEBUG
	if (flags & SO_ALL) {
		for_each_node_state(node, N_NORMAL_MEMORY) {
			struct kmem_cache_node *n = get_node(s, node);

			if (flags & SO_TOTAL)
				x = atomic_long_read(&n->total_objects);
			else if (flags & SO_OBJECTS)
				x = atomic_long_read(&n->total_objects) -
					count_partial(n, count_free);
			else
				x = atomic_long_read(&n->nr_slabs);
			total += x;
			nodes[node] += x;
		}

	} else
#endif
	if (flags & SO_PARTIAL) {
		for_each_node_state(node, N_NORMAL_MEMORY) {
			struct kmem_cache_node *n = get_node(s, node);

			if (flags & SO_TOTAL)
				x = count_partial(n, count_total);
			else if (flags & SO_OBJECTS)
				x = count_partial(n, count_inuse);
			else
				x = n->nr_partial;
			total += x;
			nodes[node] += x;
		}
	}
	x = sprintf(buf, "%lu", total);
#ifdef CONFIG_NUMA
	for_each_node_state(node, N_NORMAL_MEMORY)
		if (nodes[node])
			x += sprintf(buf + x, " N%d=%lu",
					node, nodes[node]);
#endif
	unlock_memory_hotplug();
	kfree(nodes);
	return x + sprintf(buf + x, "\n");
}

#ifdef CONFIG_SLUB_DEBUG
static int any_slab_objects(struct kmem_cache *s)
{
	int node;

	for_each_online_node(node) {
		struct kmem_cache_node *n = get_node(s, node);

		if (!n)
			continue;

		if (atomic_long_read(&n->total_objects))
			return 1;
	}
	return 0;
}
#endif

#define to_slab_attr(n) container_of(n, struct slab_attribute, attr)
#define to_slab(n) container_of(n, struct kmem_cache, kobj)

struct slab_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kmem_cache *s, char *buf);
	ssize_t (*store)(struct kmem_cache *s, const char *x, size_t count);
};

#define SLAB_ATTR_RO(_name) \
	static struct slab_attribute _name##_attr = \
	__ATTR(_name, 0400, _name##_show, NULL)

#define SLAB_ATTR(_name) \
	static struct slab_attribute _name##_attr =  \
	__ATTR(_name, 0600, _name##_show, _name##_store)

static ssize_t slab_size_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->size);
}
SLAB_ATTR_RO(slab_size);

static ssize_t align_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->align);
}
SLAB_ATTR_RO(align);

static ssize_t object_size_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->object_size);
}
SLAB_ATTR_RO(object_size);

static ssize_t objs_per_slab_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", oo_objects(s->oo));
}
SLAB_ATTR_RO(objs_per_slab);

static ssize_t order_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	unsigned long order;
	int err;

	err = kstrtoul(buf, 10, &order);
	if (err)
		return err;

	if (order > slub_max_order || order < slub_min_order)
		return -EINVAL;

	calculate_sizes(s, order);
	return length;
}

static ssize_t order_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", oo_order(s->oo));
}
SLAB_ATTR(order);

static ssize_t min_partial_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%lu\n", s->min_partial);
}

static ssize_t min_partial_store(struct kmem_cache *s, const char *buf,
				 size_t length)
{
	unsigned long min;
	int err;

	err = kstrtoul(buf, 10, &min);
	if (err)
		return err;

	set_min_partial(s, min);
	return length;
}
SLAB_ATTR(min_partial);

static ssize_t cpu_partial_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%u\n", s->cpu_partial);
}

static ssize_t cpu_partial_store(struct kmem_cache *s, const char *buf,
				 size_t length)
{
	unsigned long objects;
	int err;

	err = kstrtoul(buf, 10, &objects);
	if (err)
		return err;
	if (objects && !kmem_cache_has_cpu_partial(s))
		return -EINVAL;

	s->cpu_partial = objects;
	flush_all(s);
	return length;
}
SLAB_ATTR(cpu_partial);

static ssize_t ctor_show(struct kmem_cache *s, char *buf)
{
	if (!s->ctor)
		return 0;
	return sprintf(buf, "%pS\n", s->ctor);
}
SLAB_ATTR_RO(ctor);

static ssize_t aliases_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->refcount - 1);
}
SLAB_ATTR_RO(aliases);

static ssize_t partial_show(struct kmem_cache *s, char *buf)
{
	return show_slab_objects(s, buf, SO_PARTIAL);
}
SLAB_ATTR_RO(partial);

static ssize_t cpu_slabs_show(struct kmem_cache *s, char *buf)
{
	return show_slab_objects(s, buf, SO_CPU);
}
SLAB_ATTR_RO(cpu_slabs);

static ssize_t objects_show(struct kmem_cache *s, char *buf)
{
	return show_slab_objects(s, buf, SO_ALL|SO_OBJECTS);
}
SLAB_ATTR_RO(objects);

static ssize_t objects_partial_show(struct kmem_cache *s, char *buf)
{
	return show_slab_objects(s, buf, SO_PARTIAL|SO_OBJECTS);
}
SLAB_ATTR_RO(objects_partial);

static ssize_t slabs_cpu_partial_show(struct kmem_cache *s, char *buf)
{
	int objects = 0;
	int pages = 0;
	int cpu;
	int len;

	for_each_online_cpu(cpu) {
		struct page *page = per_cpu_ptr(s->cpu_slab, cpu)->partial;

		if (page) {
			pages += page->pages;
			objects += page->pobjects;
		}
	}

	len = sprintf(buf, "%d(%d)", objects, pages);

#ifdef CONFIG_SMP
	for_each_online_cpu(cpu) {
		struct page *page = per_cpu_ptr(s->cpu_slab, cpu) ->partial;

		if (page && len < PAGE_SIZE - 20)
			len += sprintf(buf + len, " C%d=%d(%d)", cpu,
				page->pobjects, page->pages);
	}
#endif
	return len + sprintf(buf + len, "\n");
}
SLAB_ATTR_RO(slabs_cpu_partial);

static ssize_t reclaim_account_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_RECLAIM_ACCOUNT));
}

static ssize_t reclaim_account_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	s->flags &= ~SLAB_RECLAIM_ACCOUNT;
	if (buf[0] == '1')
		s->flags |= SLAB_RECLAIM_ACCOUNT;
	return length;
}
SLAB_ATTR(reclaim_account);

static ssize_t hwcache_align_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_HWCACHE_ALIGN));
}
SLAB_ATTR_RO(hwcache_align);

#ifdef CONFIG_ZONE_DMA
static ssize_t cache_dma_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_CACHE_DMA));
}
SLAB_ATTR_RO(cache_dma);
#endif

static ssize_t destroy_by_rcu_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_DESTROY_BY_RCU));
}
SLAB_ATTR_RO(destroy_by_rcu);

static ssize_t reserved_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->reserved);
}
SLAB_ATTR_RO(reserved);

#ifdef CONFIG_SLUB_DEBUG
static ssize_t slabs_show(struct kmem_cache *s, char *buf)
{
	return show_slab_objects(s, buf, SO_ALL);
}
SLAB_ATTR_RO(slabs);

static ssize_t total_objects_show(struct kmem_cache *s, char *buf)
{
	return show_slab_objects(s, buf, SO_ALL|SO_TOTAL);
}
SLAB_ATTR_RO(total_objects);

static ssize_t sanity_checks_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_DEBUG_FREE));
}

static ssize_t sanity_checks_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	s->flags &= ~SLAB_DEBUG_FREE;
	if (buf[0] == '1') {
		s->flags &= ~__CMPXCHG_DOUBLE;
		s->flags |= SLAB_DEBUG_FREE;
	}
	return length;
}
SLAB_ATTR(sanity_checks);

static ssize_t trace_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_TRACE));
}

static ssize_t trace_store(struct kmem_cache *s, const char *buf,
							size_t length)
{
	s->flags &= ~SLAB_TRACE;
	if (buf[0] == '1') {
		s->flags &= ~__CMPXCHG_DOUBLE;
		s->flags |= SLAB_TRACE;
	}
	return length;
}
SLAB_ATTR(trace);

static ssize_t red_zone_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_RED_ZONE));
}

static ssize_t red_zone_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	if (any_slab_objects(s))
		return -EBUSY;

	s->flags &= ~SLAB_RED_ZONE;
	if (buf[0] == '1') {
		s->flags &= ~__CMPXCHG_DOUBLE;
		s->flags |= SLAB_RED_ZONE;
	}
	calculate_sizes(s, -1);
	return length;
}
SLAB_ATTR(red_zone);

static ssize_t poison_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_POISON));
}

static ssize_t poison_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	if (any_slab_objects(s))
		return -EBUSY;

	s->flags &= ~SLAB_POISON;
	if (buf[0] == '1') {
		s->flags &= ~__CMPXCHG_DOUBLE;
		s->flags |= SLAB_POISON;
	}
	calculate_sizes(s, -1);
	return length;
}
SLAB_ATTR(poison);

static ssize_t store_user_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_STORE_USER));
}

static ssize_t store_user_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	if (any_slab_objects(s))
		return -EBUSY;

	s->flags &= ~SLAB_STORE_USER;
	if (buf[0] == '1') {
		s->flags &= ~__CMPXCHG_DOUBLE;
		s->flags |= SLAB_STORE_USER;
	}
	calculate_sizes(s, -1);
	return length;
}
SLAB_ATTR(store_user);

static ssize_t validate_show(struct kmem_cache *s, char *buf)
{
	return 0;
}

static ssize_t validate_store(struct kmem_cache *s,
			const char *buf, size_t length)
{
	int ret = -EINVAL;

	if (buf[0] == '1') {
		ret = validate_slab_cache(s);
		if (ret >= 0)
			ret = length;
	}
	return ret;
}
SLAB_ATTR(validate);

static ssize_t alloc_calls_show(struct kmem_cache *s, char *buf)
{
	if (!(s->flags & SLAB_STORE_USER))
		return -ENOSYS;
	return list_locations(s, buf, TRACK_ALLOC);
}
SLAB_ATTR_RO(alloc_calls);

static ssize_t free_calls_show(struct kmem_cache *s, char *buf)
{
	if (!(s->flags & SLAB_STORE_USER))
		return -ENOSYS;
	return list_locations(s, buf, TRACK_FREE);
}
SLAB_ATTR_RO(free_calls);
#endif /* CONFIG_SLUB_DEBUG */

#ifdef CONFIG_FAILSLAB
static ssize_t failslab_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_FAILSLAB));
}

static ssize_t failslab_store(struct kmem_cache *s, const char *buf,
							size_t length)
{
	s->flags &= ~SLAB_FAILSLAB;
	if (buf[0] == '1')
		s->flags |= SLAB_FAILSLAB;
	return length;
}
SLAB_ATTR(failslab);
#endif

static ssize_t shrink_show(struct kmem_cache *s, char *buf)
{
	return 0;
}

static ssize_t shrink_store(struct kmem_cache *s,
			const char *buf, size_t length)
{
	if (buf[0] == '1') {
		int rc = kmem_cache_shrink(s);

		if (rc)
			return rc;
	} else
		return -EINVAL;
	return length;
}
SLAB_ATTR(shrink);

#ifdef CONFIG_NUMA
static ssize_t remote_node_defrag_ratio_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->remote_node_defrag_ratio / 10);
}

static ssize_t remote_node_defrag_ratio_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	unsigned long ratio;
	int err;

	err = kstrtoul(buf, 10, &ratio);
	if (err)
		return err;

	if (ratio <= 100)
		s->remote_node_defrag_ratio = ratio * 10;

	return length;
}
SLAB_ATTR(remote_node_defrag_ratio);
#endif

#ifdef CONFIG_SLUB_STATS
static int show_stat(struct kmem_cache *s, char *buf, enum stat_item si)
{
	unsigned long sum  = 0;
	int cpu;
	int len;
	int *data = kmalloc(nr_cpu_ids * sizeof(int), GFP_KERNEL);

	if (!data)
		return -ENOMEM;

	for_each_online_cpu(cpu) {
		unsigned x = per_cpu_ptr(s->cpu_slab, cpu)->stat[si];

		data[cpu] = x;
		sum += x;
	}

	len = sprintf(buf, "%lu", sum);

#ifdef CONFIG_SMP
	for_each_online_cpu(cpu) {
		if (data[cpu] && len < PAGE_SIZE - 20)
			len += sprintf(buf + len, " C%d=%u", cpu, data[cpu]);
	}
#endif
	kfree(data);
	return len + sprintf(buf + len, "\n");
}

static void clear_stat(struct kmem_cache *s, enum stat_item si)
{
	int cpu;

	for_each_online_cpu(cpu)
		per_cpu_ptr(s->cpu_slab, cpu)->stat[si] = 0;
}

#define STAT_ATTR(si, text) 					\
static ssize_t text##_show(struct kmem_cache *s, char *buf)	\
{								\
	return show_stat(s, buf, si);				\
}								\
static ssize_t text##_store(struct kmem_cache *s,		\
				const char *buf, size_t length)	\
{								\
	if (buf[0] != '0')					\
		return -EINVAL;					\
	clear_stat(s, si);					\
	return length;						\
}								\
SLAB_ATTR(text);						\

STAT_ATTR(ALLOC_FASTPATH, alloc_fastpath);
STAT_ATTR(ALLOC_SLOWPATH, alloc_slowpath);
STAT_ATTR(FREE_FASTPATH, free_fastpath);
STAT_ATTR(FREE_SLOWPATH, free_slowpath);
STAT_ATTR(FREE_FROZEN, free_frozen);
STAT_ATTR(FREE_ADD_PARTIAL, free_add_partial);
STAT_ATTR(FREE_REMOVE_PARTIAL, free_remove_partial);
STAT_ATTR(ALLOC_FROM_PARTIAL, alloc_from_partial);
STAT_ATTR(ALLOC_SLAB, alloc_slab);
STAT_ATTR(ALLOC_REFILL, alloc_refill);
STAT_ATTR(ALLOC_NODE_MISMATCH, alloc_node_mismatch);
STAT_ATTR(FREE_SLAB, free_slab);
STAT_ATTR(CPUSLAB_FLUSH, cpuslab_flush);
STAT_ATTR(DEACTIVATE_FULL, deactivate_full);
STAT_ATTR(DEACTIVATE_EMPTY, deactivate_empty);
STAT_ATTR(DEACTIVATE_TO_HEAD, deactivate_to_head);
STAT_ATTR(DEACTIVATE_TO_TAIL, deactivate_to_tail);
STAT_ATTR(DEACTIVATE_REMOTE_FREES, deactivate_remote_frees);
STAT_ATTR(DEACTIVATE_BYPASS, deactivate_bypass);
STAT_ATTR(ORDER_FALLBACK, order_fallback);
STAT_ATTR(CMPXCHG_DOUBLE_CPU_FAIL, cmpxchg_double_cpu_fail);
STAT_ATTR(CMPXCHG_DOUBLE_FAIL, cmpxchg_double_fail);
STAT_ATTR(CPU_PARTIAL_ALLOC, cpu_partial_alloc);
STAT_ATTR(CPU_PARTIAL_FREE, cpu_partial_free);
STAT_ATTR(CPU_PARTIAL_NODE, cpu_partial_node);
STAT_ATTR(CPU_PARTIAL_DRAIN, cpu_partial_drain);
#endif

static struct attribute *slab_attrs[] = {
	&slab_size_attr.attr,
	&object_size_attr.attr,
	&objs_per_slab_attr.attr,
	&order_attr.attr,
	&min_partial_attr.attr,
	&cpu_partial_attr.attr,
	&objects_attr.attr,
	&objects_partial_attr.attr,
	&partial_attr.attr,
	&cpu_slabs_attr.attr,
	&ctor_attr.attr,
	&aliases_attr.attr,
	&align_attr.attr,
	&hwcache_align_attr.attr,
	&reclaim_account_attr.attr,
	&destroy_by_rcu_attr.attr,
	&shrink_attr.attr,
	&reserved_attr.attr,
	&slabs_cpu_partial_attr.attr,
#ifdef CONFIG_SLUB_DEBUG
	&total_objects_attr.attr,
	&slabs_attr.attr,
	&sanity_checks_attr.attr,
	&trace_attr.attr,
	&red_zone_attr.attr,
	&poison_attr.attr,
	&store_user_attr.attr,
	&validate_attr.attr,
	&alloc_calls_attr.attr,
	&free_calls_attr.attr,
#endif
#ifdef CONFIG_ZONE_DMA
	&cache_dma_attr.attr,
#endif
#ifdef CONFIG_NUMA
	&remote_node_defrag_ratio_attr.attr,
#endif
#ifdef CONFIG_SLUB_STATS
	&alloc_fastpath_attr.attr,
	&alloc_slowpath_attr.attr,
	&free_fastpath_attr.attr,
	&free_slowpath_attr.attr,
	&free_frozen_attr.attr,
	&free_add_partial_attr.attr,
	&free_remove_partial_attr.attr,
	&alloc_from_partial_attr.attr,
	&alloc_slab_attr.attr,
	&alloc_refill_attr.attr,
	&alloc_node_mismatch_attr.attr,
	&free_slab_attr.attr,
	&cpuslab_flush_attr.attr,
	&deactivate_full_attr.attr,
	&deactivate_empty_attr.attr,
	&deactivate_to_head_attr.attr,
	&deactivate_to_tail_attr.attr,
	&deactivate_remote_frees_attr.attr,
	&deactivate_bypass_attr.attr,
	&order_fallback_attr.attr,
	&cmpxchg_double_fail_attr.attr,
	&cmpxchg_double_cpu_fail_attr.attr,
	&cpu_partial_alloc_attr.attr,
	&cpu_partial_free_attr.attr,
	&cpu_partial_node_attr.attr,
	&cpu_partial_drain_attr.attr,
#endif
#ifdef CONFIG_FAILSLAB
	&failslab_attr.attr,
#endif

	NULL
};

static struct attribute_group slab_attr_group = {
	.attrs = slab_attrs,
};

static ssize_t slab_attr_show(struct kobject *kobj,
				struct attribute *attr,
				char *buf)
{
	struct slab_attribute *attribute;
	struct kmem_cache *s;
	int err;

	attribute = to_slab_attr(attr);
	s = to_slab(kobj);

	if (!attribute->show)
		return -EIO;

	err = attribute->show(s, buf);

	return err;
}

static ssize_t slab_attr_store(struct kobject *kobj,
				struct attribute *attr,
				const char *buf, size_t len)
{
	struct slab_attribute *attribute;
	struct kmem_cache *s;
	int err;

	attribute = to_slab_attr(attr);
	s = to_slab(kobj);

	if (!attribute->store)
		return -EIO;

	err = attribute->store(s, buf, len);
#ifdef CONFIG_MEMCG_KMEM
	if (slab_state >= FULL && err >= 0 && is_root_cache(s)) {
		int i;

		mutex_lock(&slab_mutex);
		if (s->max_attr_size < len)
			s->max_attr_size = len;

		/*
		 * This is a best effort propagation, so this function's return
		 * value will be determined by the parent cache only. This is
		 * basically because not all attributes will have a well
		 * defined semantics for rollbacks - most of the actions will
		 * have permanent effects.
		 *
		 * Returning the error value of any of the children that fail
		 * is not 100 % defined, in the sense that users seeing the
		 * error code won't be able to know anything about the state of
		 * the cache.
		 *
		 * Only returning the error code for the parent cache at least
		 * has well defined semantics. The cache being written to
		 * directly either failed or succeeded, in which case we loop
		 * through the descendants with best-effort propagation.
		 */
		for_each_memcg_cache_index(i) {
			struct kmem_cache *c = cache_from_memcg_idx(s, i);
			if (c)
				attribute->store(c, buf, len);
		}
		mutex_unlock(&slab_mutex);
	}
#endif
	return err;
}

static void memcg_propagate_slab_attrs(struct kmem_cache *s)
{
#ifdef CONFIG_MEMCG_KMEM
	int i;
	char *buffer = NULL;

	if (!is_root_cache(s))
		return;

	/*
	 * This mean this cache had no attribute written. Therefore, no point
	 * in copying default values around
	 */
	if (!s->max_attr_size)
		return;

	for (i = 0; i < ARRAY_SIZE(slab_attrs); i++) {
		char mbuf[64];
		char *buf;
		struct slab_attribute *attr = to_slab_attr(slab_attrs[i]);

		if (!attr || !attr->store || !attr->show)
			continue;

		/*
		 * It is really bad that we have to allocate here, so we will
		 * do it only as a fallback. If we actually allocate, though,
		 * we can just use the allocated buffer until the end.
		 *
		 * Most of the slub attributes will tend to be very small in
		 * size, but sysfs allows buffers up to a page, so they can
		 * theoretically happen.
		 */
		if (buffer)
			buf = buffer;
		else if (s->max_attr_size < ARRAY_SIZE(mbuf))
			buf = mbuf;
		else {
			buffer = (char *) get_zeroed_page(GFP_KERNEL);
			if (WARN_ON(!buffer))
				continue;
			buf = buffer;
		}

		attr->show(s->memcg_params->root_cache, buf);
		attr->store(s, buf, strlen(buf));
	}

	if (buffer)
		free_page((unsigned long)buffer);
#endif
}

static const struct sysfs_ops slab_sysfs_ops = {
	.show = slab_attr_show,
	.store = slab_attr_store,
};

static struct kobj_type slab_ktype = {
	.sysfs_ops = &slab_sysfs_ops,
};

static int uevent_filter(struct kset *kset, struct kobject *kobj)
{
	struct kobj_type *ktype = get_ktype(kobj);

	if (ktype == &slab_ktype)
		return 1;
	return 0;
}

static const struct kset_uevent_ops slab_uevent_ops = {
	.filter = uevent_filter,
};

static struct kset *slab_kset;

#define ID_STR_LENGTH 64

/* Create a unique string id for a slab cache:
 *
 * Format	:[flags-]size
 */
static char *create_unique_id(struct kmem_cache *s)
{
	char *name = kmalloc(ID_STR_LENGTH, GFP_KERNEL);
	char *p = name;

	BUG_ON(!name);

	*p++ = ':';
	/*
	 * First flags affecting slabcache operations. We will only
	 * get here for aliasable slabs so we do not need to support
	 * too many flags. The flags here must cover all flags that
	 * are matched during merging to guarantee that the id is
	 * unique.
	 */
	if (s->flags & SLAB_CACHE_DMA)
		*p++ = 'd';
	if (s->flags & SLAB_RECLAIM_ACCOUNT)
		*p++ = 'a';
	if (s->flags & SLAB_DEBUG_FREE)
		*p++ = 'F';
	if (!(s->flags & SLAB_NOTRACK))
		*p++ = 't';
	if (p != name + 1)
		*p++ = '-';
	p += sprintf(p, "%07d", s->size);

#ifdef CONFIG_MEMCG_KMEM
	if (!is_root_cache(s))
		p += sprintf(p, "-%08d",
				memcg_cache_id(s->memcg_params->memcg));
#endif

	BUG_ON(p > name + ID_STR_LENGTH - 1);
	return name;
}

static int sysfs_slab_add(struct kmem_cache *s)
{
	int err;
	const char *name;
	int unmergeable = slab_unmergeable(s);

	if (unmergeable) {
		/*
		 * Slabcache can never be merged so we can use the name proper.
		 * This is typically the case for debug situations. In that
		 * case we can catch duplicate names easily.
		 */
		sysfs_remove_link(&slab_kset->kobj, s->name);
		name = s->name;
	} else {
		/*
		 * Create a unique name for the slab as a target
		 * for the symlinks.
		 */
		name = create_unique_id(s);
	}

	s->kobj.kset = slab_kset;
	err = kobject_init_and_add(&s->kobj, &slab_ktype, NULL, name);
	if (err) {
		kobject_put(&s->kobj);
		return err;
	}

	err = sysfs_create_group(&s->kobj, &slab_attr_group);
	if (err) {
		kobject_del(&s->kobj);
		kobject_put(&s->kobj);
		return err;
	}
	kobject_uevent(&s->kobj, KOBJ_ADD);
	if (!unmergeable) {
		/* Setup first alias */
		sysfs_slab_alias(s, s->name);
		kfree(name);
	}
	return 0;
}

static void sysfs_slab_remove(struct kmem_cache *s)
{
	if (slab_state < FULL)
		/*
		 * Sysfs has not been setup yet so no need to remove the
		 * cache from sysfs.
		 */
		return;

	kobject_uevent(&s->kobj, KOBJ_REMOVE);
	kobject_del(&s->kobj);
	kobject_put(&s->kobj);
}

/*
 * Need to buffer aliases during bootup until sysfs becomes
 * available lest we lose that information.
 */
struct saved_alias {
	struct kmem_cache *s;
	const char *name;
	struct saved_alias *next;
};

static struct saved_alias *alias_list;

static int sysfs_slab_alias(struct kmem_cache *s, const char *name)
{
	struct saved_alias *al;

	if (slab_state == FULL) {
		/*
		 * If we have a leftover link then remove it.
		 */
		sysfs_remove_link(&slab_kset->kobj, name);
		return sysfs_create_link(&slab_kset->kobj, &s->kobj, name);
	}

	al = kmalloc(sizeof(struct saved_alias), GFP_KERNEL);
	if (!al)
		return -ENOMEM;

	al->s = s;
	al->name = name;
	al->next = alias_list;
	alias_list = al;
	return 0;
}

static int __init slab_sysfs_init(void)
{
	struct kmem_cache *s;
	int err;

	mutex_lock(&slab_mutex);

	slab_kset = kset_create_and_add("slab", &slab_uevent_ops, kernel_kobj);
	if (!slab_kset) {
		mutex_unlock(&slab_mutex);
		printk(KERN_ERR "Cannot register slab subsystem.\n");
		return -ENOSYS;
	}

	slab_state = FULL;

	list_for_each_entry(s, &slab_caches, list) {
		err = sysfs_slab_add(s);
		if (err)
			printk(KERN_ERR "SLUB: Unable to add boot slab %s"
						" to sysfs\n", s->name);
	}

	while (alias_list) {
		struct saved_alias *al = alias_list;

		alias_list = alias_list->next;
		err = sysfs_slab_alias(al->s, al->name);
		if (err)
			printk(KERN_ERR "SLUB: Unable to add boot slab alias"
					" %s to sysfs\n", al->name);
		kfree(al);
	}

	mutex_unlock(&slab_mutex);
	resiliency_test();
	return 0;
}

__initcall(slab_sysfs_init);
#endif /* CONFIG_SYSFS */

/*
 * The /proc/slabinfo ABI
 */
#ifdef CONFIG_SLABINFO
void get_slabinfo(struct kmem_cache *s, struct slabinfo *sinfo)
{
	unsigned long nr_slabs = 0;
	unsigned long nr_objs = 0;
	unsigned long nr_free = 0;
	int node;

	for_each_online_node(node) {
		struct kmem_cache_node *n = get_node(s, node);

		if (!n)
			continue;

		nr_slabs += node_nr_slabs(n);
		nr_objs += node_nr_objs(n);
		nr_free += count_partial(n, count_free);
	}

	sinfo->active_objs = nr_objs - nr_free;
	sinfo->num_objs = nr_objs;
	sinfo->active_slabs = nr_slabs;
	sinfo->num_slabs = nr_slabs;
	sinfo->objects_per_slab = oo_objects(s->oo);
	sinfo->cache_order = oo_order(s->oo);
}

void slabinfo_show_stats(struct seq_file *m, struct kmem_cache *s)
{
}

ssize_t slabinfo_write(struct file *file, const char __user *buffer,
		       size_t count, loff_t *ppos)
{
	return -EIO;
}
#endif /* CONFIG_SLABINFO */
