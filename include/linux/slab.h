/*
 * Written by Mark Hemment, 1996 (markhe@nextd.demon.co.uk).
 *
 * (C) SGI 2006, Christoph Lameter
 * 	Cleaned up and restructured to ease the addition of alternative
 * 	implementations of SLAB allocators.
 * (C) Linux Foundation 2008-2013
 *      Unified interface for all slab allocators
 */

#ifndef _LINUX_SLAB_H
#define	_LINUX_SLAB_H

#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/workqueue.h>


/*
 * Flags to pass to kmem_cache_create().
 * The ones marked DEBUG are only valid if CONFIG_SLAB_DEBUG is set.
 */
// ARM10C 20140419
// ARM10C 20140524
#define SLAB_DEBUG_FREE		0x00000100UL	/* DEBUG: Perform (expensive) checks on free */
// ARM10C 20140419
// ARM10C 20140524
// ARM10C 20140531
// ARM10C 20140621
// ARM10C 20140920
// SLAB_RED_ZONE: 0x00000400UL
#define SLAB_RED_ZONE		0x00000400UL	/* DEBUG: Red zone objs in a cache */
// ARM10C 20140419
// ARM10C 20140524
// ARM10C 20140531
// ARM10C 20140621
// ARM10C 20140920
// SLAB_POISON: 0x00000800UL
#define SLAB_POISON		0x00000800UL	/* DEBUG: Poison objects */
// ARM10C 20140419
// ARM10C 20140607
// ARM10C 20140920
// SLAB_HWCACHE_ALIGN: 0x00002000UL
#define SLAB_HWCACHE_ALIGN	0x00002000UL	/* Align objs on cache lines */
// ARM10C 20140920
// SLAB_CACHE_DMA: 0x00004000UL
#define SLAB_CACHE_DMA		0x00004000UL	/* Use GFP_DMA memory */
// ARM10C 20140419
// ARM10C 20140524
// ARM10C 20140531
// ARM10C 20140621
// ARM10C 20140920
// SLAB_STORE_USER: 0x00010000UL
#define SLAB_STORE_USER		0x00010000UL	/* DEBUG: Store the last owner for bug hunting */
// ARM10C 20140920
// ARM10C 20141004
// SLAB_PANIC: 0x00040000UL
#define SLAB_PANIC		0x00040000UL	/* Panic if kmem_cache_create() fails */
/*
 * SLAB_DESTROY_BY_RCU - **WARNING** READ THIS!
 *
 * This delays freeing the SLAB page by a grace period, it does _NOT_
 * delay object freeing. This means that if you do kmem_cache_free()
 * that memory location is free to be reused at any time. Thus it may
 * be possible to see another object there in the same RCU grace period.
 *
 * This feature only ensures the memory location backing the object
 * stays valid, the trick to using this is relying on an independent
 * object validation pass. Something like:
 *
 *  rcu_read_lock()
 * again:
 *  obj = lockless_lookup(key);
 *  if (obj) {
 *    if (!try_get_ref(obj)) // might fail for free objects
 *      goto again;
 *
 *    if (obj->key != key) { // not the object we expected
 *      put_ref(obj);
 *      goto again;
 *    }
 *  }
 *  rcu_read_unlock();
 *
 * This is useful if we need to approach a kernel structure obliquely,
 * from its address obtained without the usual locking. We can lock
 * the structure to stabilize it and check it's still at the given address,
 * only if we can be sure that the memory has not been meanwhile reused
 * for some other kind of object (which our subsystem's lock might corrupt).
 *
 * rcu_read_lock before reading the address, then rcu_read_unlock after
 * taking the spinlock within the structure expected at that address.
 */
// ARM10C 20140419
// ARM10C 20140621
// ARM10C 20140920
// SLAB_DESTROY_BY_RCU: 0x00080000UL
#define SLAB_DESTROY_BY_RCU	0x00080000UL	/* Defer freeing slabs to RCU */
#define SLAB_MEM_SPREAD		0x00100000UL	/* Spread some memory over cpuset */
// ARM10C 20140419
// ARM10C 20140920
// SLAB_TRACE: 0x00200000UL
#define SLAB_TRACE		0x00200000UL	/* Trace allocations and frees */

/* Flag to prevent checks on free */
#ifdef CONFIG_DEBUG_OBJECTS // CONFIG_DEBUG_OBJECTS=n
# define SLAB_DEBUG_OBJECTS	0x00400000UL
#else
// ARM10C 20140920
// ARM10C 20141206
// SLAB_DEBUG_OBJECTS: 0x00000000UL
# define SLAB_DEBUG_OBJECTS	0x00000000UL
#endif

// ARM10C 20140920
// SLAB_NOLEAKTRACE: 0x00800000UL
#define SLAB_NOLEAKTRACE	0x00800000UL	/* Avoid kmemleak tracing */

/* Don't track use of uninitialized memory */
#ifdef CONFIG_KMEMCHECK // CONFIG_KMEMCHECK=n
# define SLAB_NOTRACK		0x01000000UL
#else
// ARM10C 20140524
// ARM10C 20140920
// SLAB_NOTRACK: 0x00000000UL
# define SLAB_NOTRACK		0x00000000UL
#endif
#ifdef CONFIG_FAILSLAB // CONFIG_FAILSLAB=n
# define SLAB_FAILSLAB		0x02000000UL	/* Fault injection mark */
#else
// ARM10C 20140920
// SLAB_FAILSLAB: 0x00000000UL
# define SLAB_FAILSLAB		0x00000000UL
#endif

/* The following flags affect the page allocator grouping pages by mobility */
// ARM10C 20140524
// ARM10C 20140920
// ARM10C 20141004
// SLAB_RECLAIM_ACCOUNT: 0x00020000UL
#define SLAB_RECLAIM_ACCOUNT	0x00020000UL		/* Objects are reclaimable */
// ARM10C 20140920
// SLAB_RECLAIM_ACCOUNT: 0x00020000UL
// SLAB_TEMPORARY: 0x00020000UL
#define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
/*
 * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
 *
 * Dereferencing ZERO_SIZE_PTR will lead to a distinct access fault.
 *
 * ZERO_SIZE_PTR can be passed to kfree though in the same way that NULL can.
 * Both make kfree a no-op.
 */
// ARM10C 20140726
// ARM10C 20150117
// ZERO_SIZE_PTR: ((void *)16)
#define ZERO_SIZE_PTR ((void *)16)

// ARM10C 20140726
// ZERO_SIZE_PTR: 16
// s: kmem_cache#30
// ARM10C 20141129
// x: kmem_cache#30-o11
// ARM10C 20141206
// s: kmem_cache#26
// ARM10C 20150117
// s: ((void *)16)
#define ZERO_OR_NULL_PTR(x) ((unsigned long)(x) <= \
				(unsigned long)ZERO_SIZE_PTR)

#include <linux/kmemleak.h>

struct mem_cgroup;
/*
 * struct kmem_cache related prototypes
 */
void __init kmem_cache_init(void);
int slab_is_available(void);

// ARM10C 20140920
struct kmem_cache *kmem_cache_create(const char *, size_t, size_t,
			unsigned long,
			void (*)(void *));
// ARM10C 20140920
// ARM10C 20141004
struct kmem_cache *
kmem_cache_create_memcg(struct mem_cgroup *, const char *, size_t, size_t,
			unsigned long, void (*)(void *), struct kmem_cache *);
void kmem_cache_destroy(struct kmem_cache *);
int kmem_cache_shrink(struct kmem_cache *);
void kmem_cache_free(struct kmem_cache *, void *);

/*
 * Please use this macro to create slab caches. Simply specify the
 * name of the structure and maybe some flags that are listed above.
 *
 * The alignment of the struct determines object alignment. If you
 * f.e. add ____cacheline_aligned_in_smp to the struct declaration
 * then the objects will be properly aligned in SMP configurations.
 */
#define KMEM_CACHE(__struct, __flags) kmem_cache_create(#__struct,\
		sizeof(struct __struct), __alignof__(struct __struct),\
		(__flags), NULL)

/*
 * Common kmalloc functions provided by all allocators
 */
void * __must_check __krealloc(const void *, size_t, gfp_t);
void * __must_check krealloc(const void *, size_t, gfp_t);
void kfree(const void *);
void kzfree(const void *);
size_t ksize(const void *);

/*
 * Some archs want to perform DMA into kmalloc caches and need a guaranteed
 * alignment larger than the alignment of a 64-bit integer.
 * Setting ARCH_KMALLOC_MINALIGN in arch headers allows that.
 */
// ARM10C 20140419
// ARCH_DMA_MINALIGN: 64
#if defined(ARCH_DMA_MINALIGN) && ARCH_DMA_MINALIGN > 8
// ARM10C 20140419
// ARCH_DMA_MINALIGN: 64
// ARCH_KMALLOC_MINALIGN: 64
#define ARCH_KMALLOC_MINALIGN ARCH_DMA_MINALIGN
// ARM10C 20140719
// ARM10C 20140726
// ARCH_DMA_MINALIGN: 64
// KMALLOC_MIN_SIZE: 64
#define KMALLOC_MIN_SIZE ARCH_DMA_MINALIGN
// ARM10C 20140719
// ARCH_DMA_MINALIGN: 64
// KMALLOC_SHIFT_LOW: 6
#define KMALLOC_SHIFT_LOW ilog2(ARCH_DMA_MINALIGN)
#else
#define ARCH_KMALLOC_MINALIGN __alignof__(unsigned long long)
#endif

#ifdef CONFIG_SLOB
/*
 * Common fields provided in kmem_cache by all slab allocators
 * This struct is either used directly by the allocator (SLOB)
 * or the allocator must include definitions for all fields
 * provided in kmem_cache_common in their definition of kmem_cache.
 *
 * Once we can do anonymous structs (C11 standard) we could put a
 * anonymous struct definition in these allocators so that the
 * separate allocations in the kmem_cache structure of SLAB and
 * SLUB is no longer needed.
 */
struct kmem_cache {
	unsigned int object_size;/* The original size of the object */
	unsigned int size;	/* The aligned/padded/added on size  */
	unsigned int align;	/* Alignment as calculated */
	unsigned long flags;	/* Active flags on the slab */
	const char *name;	/* Slab name for sysfs */
	int refcount;		/* Use counter */
	void (*ctor)(void *);	/* Called on object slot creation */
	struct list_head list;	/* List of all slab caches on the system */
};

#endif /* CONFIG_SLOB */

/*
 * Kmalloc array related definitions
 */

#ifdef CONFIG_SLAB // CONFIG_SLAB=n
/*
 * The largest kmalloc size supported by the SLAB allocators is
 * 32 megabyte (2^25) or the maximum allocatable page order if that is
 * less than 32 MB.
 *
 * WARNING: Its not easy to increase this value since the allocators have
 * to do various tricks to work around compiler limitations in order to
 * ensure proper constant folding.
 */
#define KMALLOC_SHIFT_HIGH	((MAX_ORDER + PAGE_SHIFT - 1) <= 25 ? \
				(MAX_ORDER + PAGE_SHIFT - 1) : 25)
#define KMALLOC_SHIFT_MAX	KMALLOC_SHIFT_HIGH
#ifndef KMALLOC_SHIFT_LOW
#define KMALLOC_SHIFT_LOW	5
#endif
#endif

#ifdef CONFIG_SLUB // CONFIG_SLUB=y
/*
 * SLUB allocates up to order 2 pages directly and otherwise
 * passes the request to the page allocator.
 */
// ARM10C 20140531
// ARM10C 20140719
// ARM10C 20140726
// PAGE_SHIFT: 12
// KMALLOC_SHIFT_HIGH: 13
#define KMALLOC_SHIFT_HIGH	(PAGE_SHIFT + 1)
#define KMALLOC_SHIFT_MAX	(MAX_ORDER + PAGE_SHIFT)
#ifndef KMALLOC_SHIFT_LOW
#define KMALLOC_SHIFT_LOW	3
#endif
#endif

#ifdef CONFIG_SLOB
/*
 * SLOB passes all page size and larger requests to the page allocator.
 * No kmalloc array is necessary since objects of different sizes can
 * be allocated from the same page.
 */
#define KMALLOC_SHIFT_MAX	30
#define KMALLOC_SHIFT_HIGH	PAGE_SHIFT
#ifndef KMALLOC_SHIFT_LOW
#define KMALLOC_SHIFT_LOW	3
#endif
#endif

/* Maximum allocatable size */
// ARM10C 20140726
// KMALLOC_SHIFT_MAX: 30
// KMALLOC_MAX_SIZE: 0x40000000
#define KMALLOC_MAX_SIZE	(1UL << KMALLOC_SHIFT_MAX)
/* Maximum size for which we actually use a slab cache */
// ARM10C 20140726
// ARM10C 20141004
// ARM10C 20141206
// KMALLOC_SHIFT_HIGH: 13
// KMALLOC_MAX_CACHE_SIZE: 0x2000
#define KMALLOC_MAX_CACHE_SIZE	(1UL << KMALLOC_SHIFT_HIGH)
/* Maximum order allocatable via the slab allocagtor */
#define KMALLOC_MAX_ORDER	(KMALLOC_SHIFT_MAX - PAGE_SHIFT)

/*
 * Kmalloc subsystem.
 */
#ifndef KMALLOC_MIN_SIZE
#define KMALLOC_MIN_SIZE (1 << KMALLOC_SHIFT_LOW)
#endif

#ifndef CONFIG_SLOB
extern struct kmem_cache *kmalloc_caches[KMALLOC_SHIFT_HIGH + 1];
#ifdef CONFIG_ZONE_DMA
extern struct kmem_cache *kmalloc_dma_caches[KMALLOC_SHIFT_HIGH + 1];
#endif

/*
 * Figure out which kmalloc slab an allocation of a certain size
 * belongs to.
 * 0 = zero alloc
 * 1 =  65 .. 96 bytes
 * 2 = 120 .. 192 bytes
 * n = 2^(n-1) .. 2^n -1
 */
// ARM10C 20140726
// size: 512
// ARM10C 20140809
// size: 52
// ARM10C 20141004
// size: 156
// ARM10C 20141004
// size: 16
// ARM10C 20141025
// size: 32
// ARM10C 20141025
// size: 52
// ARM10C 20141206
// size: 1076
// ARM10C 20150110
// size: 3076
static __always_inline int kmalloc_index(size_t size)
{
	// size: 512
	// size: 52
	// size: 156
	// size: 16
	// size: 32
	// size: 52
	// size: 1076
	// size: 3076
	if (!size)
		return 0;

	// size: 512, KMALLOC_MIN_SIZE: 64
	// size: 52, KMALLOC_MIN_SIZE: 64
	// size: 156, KMALLOC_MIN_SIZE: 64
	// size: 16, KMALLOC_MIN_SIZE: 64
	// size: 32, KMALLOC_MIN_SIZE: 64
	// size: 52, KMALLOC_MIN_SIZE: 64
	// size: 1076, KMALLOC_MIN_SIZE: 64
	// size: 3076, KMALLOC_MIN_SIZE: 64
	if (size <= KMALLOC_MIN_SIZE)
		// KMALLOC_SHIFT_LOW: 6
		// KMALLOC_SHIFT_LOW: 6
		// KMALLOC_SHIFT_LOW: 6
		// KMALLOC_SHIFT_LOW: 6
		return KMALLOC_SHIFT_LOW;
		// return 6
		// return 6
		// return 6
		// return 6

	// size: 512, KMALLOC_MIN_SIZE: 64
	// size: 156, KMALLOC_MIN_SIZE: 64
	// size: 1076, KMALLOC_MIN_SIZE: 64
	// size: 3076, KMALLOC_MIN_SIZE: 64
	if (KMALLOC_MIN_SIZE <= 32 && size > 64 && size <= 96)
		return 1;

	// size: 512, KMALLOC_MIN_SIZE: 64
	// size: 156, KMALLOC_MIN_SIZE: 64
	// size: 1076, KMALLOC_MIN_SIZE: 64
	// size: 3076, KMALLOC_MIN_SIZE: 64
	if (KMALLOC_MIN_SIZE <= 64 && size > 128 && size <= 192)
		return 2;
		// return 2

	// size: 512
	// size: 156
	// size: 1076
	// size: 3076
	if (size <=          8) return 3;
	if (size <=         16) return 4;
	if (size <=         32) return 5;
	if (size <=         64) return 6;
	if (size <=        128) return 7;
	if (size <=        256) return 8;
	// size: 512
	if (size <=        512) return 9;
	// return 9
	if (size <=       1024) return 10;
	// size: 1076
	if (size <=   2 * 1024) return 11;
	// return 11
	// size: 3076
	if (size <=   4 * 1024) return 12;
	// return 12
	if (size <=   8 * 1024) return 13;
	if (size <=  16 * 1024) return 14;
	if (size <=  32 * 1024) return 15;
	if (size <=  64 * 1024) return 16;
	if (size <= 128 * 1024) return 17;
	if (size <= 256 * 1024) return 18;
	if (size <= 512 * 1024) return 19;
	if (size <= 1024 * 1024) return 20;
	if (size <=  2 * 1024 * 1024) return 21;
	if (size <=  4 * 1024 * 1024) return 22;
	if (size <=  8 * 1024 * 1024) return 23;
	if (size <=  16 * 1024 * 1024) return 24;
	if (size <=  32 * 1024 * 1024) return 25;
	if (size <=  64 * 1024 * 1024) return 26;
	BUG();

	/* Will never be reached. Needed because the compiler may complain */
	return -1;
}
#endif /* !CONFIG_SLOB */

void *__kmalloc(size_t size, gfp_t flags);
void *kmem_cache_alloc(struct kmem_cache *, gfp_t flags);

#ifdef CONFIG_NUMA // CONFIG_NUMA=n
void *__kmalloc_node(size_t size, gfp_t flags, int node);
void *kmem_cache_alloc_node(struct kmem_cache *, gfp_t flags, int node);
#else
static __always_inline void *__kmalloc_node(size_t size, gfp_t flags, int node)
{
	return __kmalloc(size, flags);
}

// ARM10C 20140614
// kmem_cache_node: &boot_kmem_cache_node, GFP_KERNEL: 0xD0, node: 0
// ARM10C 20140726
// kmem_cache_node: kmem_cache#31, GFP_KERNEL: 0xD0, node: 0
// ARM10C 20141004
// s: kmem_cache#28, gfpflags: 0x80D0, node: 0
// ARM10C 20141025
// s: kmem_cache#30, gfpflags: 0x80D0, node: -1
static __always_inline void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node)
{
	// s: &boot_kmem_cache_node, flags: GFP_KERNEL: 0xD0
	// kmem_cache_alloc(&boot_kmem_cache_node, GFP_KERNEL: 0xD0):
	// UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// s: &kmem_cache#31, flags: GFP_KERNEL: 0xD0
	// kmem_cache_alloc(&kmem_cache#31, GFP_KERNEL: 0xD0):
	// UNMOVABLE인 page 의 시작 virtual address + 4032
	// s: &kmem_cache#28, flags: 0x80D0
	// kmem_cache_alloc(&kmem_cache#28, 0x80D0): kmem_cache#28-o0
	return kmem_cache_alloc(s, flags);
	// return UNMOVABLE인 page 의 object의 시작 virtual address + 64
	// return UNMOVABLE인 page 의 시작 virtual address + 4032
	// return kmem_cache#28-o0
}
#endif

#ifdef CONFIG_TRACING // CONFIG_TRACING=n
extern void *kmem_cache_alloc_trace(struct kmem_cache *, gfp_t, size_t);

#ifdef CONFIG_NUMA
extern void *kmem_cache_alloc_node_trace(struct kmem_cache *s,
					   gfp_t gfpflags,
					   int node, size_t size);
#else
static __always_inline void *
kmem_cache_alloc_node_trace(struct kmem_cache *s,
			      gfp_t gfpflags,
			      int node, size_t size)
{
	return kmem_cache_alloc_trace(s, gfpflags, size);
}
#endif /* CONFIG_NUMA */

#else /* CONFIG_TRACING */
// ARM10C 20140726
// kmalloc_caches[9]: kmem_cache#26, flags: 0x80D0, size: 512
// ARM10C 20140809
// kmalloc_caches[6]: kmem_cache#30, flags: 0x8000, size: 52
// ARM10C 20141004
// kmalloc_caches[6]: kmem_cache#30, flags: 0x80D0, size: 16
static __always_inline void *kmem_cache_alloc_trace(struct kmem_cache *s,
		gfp_t flags, size_t size)
{
	// s: kmem_cache#26, flags: 0x80D0
	// s: kmem_cache#30, flags: 0x8000
	// s: kmem_cache#30, flags: 0x80D0
	return kmem_cache_alloc(s, flags);
	// return kmem_cache#26-o0
	// return kmem_cache#30-o9
	// return kmem_cache#30-o10
}

// ARM10C 20141004
// kmalloc_caches[2]: kmem_cache#28, flags: 0x80D0, node: 0, size: 156
// ARM10C 20141025
// kmalloc_caches[6]: kmem_cache#30, flags: 0x80D0, node: -1, size: 32
// ARM10C 20141025
// kmalloc_caches[6]: kmem_cache#30, flags: 0xD0, node: -1, size: 52
// ARM10C 20141206
// kmalloc_caches[11]: kmem_cache#24, flags: 0x80D0, node: -1, size: 1076
static __always_inline void *
kmem_cache_alloc_node_trace(struct kmem_cache *s,
			      gfp_t gfpflags,
			      int node, size_t size)
{
	// s: kmem_cache#28, gfpflags: 0x80D0, node: 0
	// kmem_cache_alloc_node(kmem_cache#28, 0x80D0, 0): kmem_cache#28-o0
	// s: kmem_cache#30, gfpflags: 0x80D0, node: -1
	// kmem_cache_alloc_node(kmem_cache#30, 0x80D0, -1): kmem_cache#30-oX
	// s: kmem_cache#30, gfpflags: 0xD0, node: -1
	// kmem_cache_alloc_node(kmem_cache#30, 0xD0, -1): kmem_cache#30-oX
	// s: kmem_cache#24, gfpflags: 0x80D0, node: -1
	// kmem_cache_alloc_node(kmem_cache#30, 0xD0, -1): kmem_cache#24-o0
	return kmem_cache_alloc_node(s, gfpflags, node);
	// return kmem_cache#28-o0
	// return kmem_cache#30-oX
	// return kmem_cache#30-oX
	// return kmem_cache#24-o0
}
#endif /* CONFIG_TRACING */

#ifdef CONFIG_SLAB
#include <linux/slab_def.h>
#endif

// ARM10C 20140419
#ifdef CONFIG_SLUB // CONFIG_SLUB = y
#include <linux/slub_def.h>
#endif

static __always_inline void *
kmalloc_order(size_t size, gfp_t flags, unsigned int order)
{
	void *ret;

	flags |= (__GFP_COMP | __GFP_KMEMCG);
	ret = (void *) __get_free_pages(flags, order);
	kmemleak_alloc(ret, size, 1, flags);
	return ret;
}

#ifdef CONFIG_TRACING
extern void *kmalloc_order_trace(size_t size, gfp_t flags, unsigned int order);
#else
static __always_inline void *
kmalloc_order_trace(size_t size, gfp_t flags, unsigned int order)
{
	return kmalloc_order(size, flags, order);
}
#endif

static __always_inline void *kmalloc_large(size_t size, gfp_t flags)
{
	unsigned int order = get_order(size);
	return kmalloc_order_trace(size, flags, order);
}

/**
 * kmalloc - allocate memory
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate.
 *
 * kmalloc is the normal method of allocating memory
 * for objects smaller than page size in the kernel.
 *
 * The @flags argument may be one of:
 *
 * %GFP_USER - Allocate memory on behalf of user.  May sleep.
 *
 * %GFP_KERNEL - Allocate normal kernel ram.  May sleep.
 *
 * %GFP_ATOMIC - Allocation will not sleep.  May use emergency pools.
 *   For example, use this inside interrupt handlers.
 *
 * %GFP_HIGHUSER - Allocate pages from high memory.
 *
 * %GFP_NOIO - Do not do any I/O at all while trying to get memory.
 *
 * %GFP_NOFS - Do not make any fs calls while trying to get memory.
 *
 * %GFP_NOWAIT - Allocation will not sleep.
 *
 * %GFP_THISNODE - Allocate node-local memory only.
 *
 * %GFP_DMA - Allocation suitable for DMA.
 *   Should only be used for kmalloc() caches. Otherwise, use a
 *   slab created with SLAB_DMA.
 *
 * Also it is possible to set different flags by OR'ing
 * in one or more of the following additional @flags:
 *
 * %__GFP_COLD - Request cache-cold pages instead of
 *   trying to return cache-warm pages.
 *
 * %__GFP_HIGH - This allocation has high priority and may use emergency pools.
 *
 * %__GFP_NOFAIL - Indicate that this allocation is in no way allowed to fail
 *   (think twice before using).
 *
 * %__GFP_NORETRY - If memory is not immediately available,
 *   then give up at once.
 *
 * %__GFP_NOWARN - If allocation fails, don't issue any warnings.
 *
 * %__GFP_REPEAT - If allocation fails initially, try once more before failing.
 *
 * There are other flags available as well, but these are not intended
 * for general use, and so are not documented here. For a full list of
 * potential flags, always refer to linux/gfp.h.
 */
// ARM10C 20140726
// size: 512, GFP_KERNEL | __GFP_ZERO: 0x80D0
// ARM10C 20140809
// size: 52, GFP_NOWAIT | __GFP_ZERO: 0x8000u
// ARM10C 20141004
// size: 16, GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u
// ARM10C 20150110
// size: 3076, GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u
static __always_inline void *kmalloc(size_t size, gfp_t flags)
{
	// size: 512
	// size: 52
	// size: 16
	// size: 3076
	if (__builtin_constant_p(size)) {
		// size: 512, KMALLOC_MAX_CACHE_SIZE: 0x2000
		// size: 52, KMALLOC_MAX_CACHE_SIZE: 0x2000
		// size: 16, KMALLOC_MAX_CACHE_SIZE: 0x2000
		// size: 3076, KMALLOC_MAX_CACHE_SIZE: 0x2000
		if (size > KMALLOC_MAX_CACHE_SIZE)
			return kmalloc_large(size, flags);

#ifndef CONFIG_SLOB // CONFIG_SLOB=n
		// flags: 0x80D0, GFP_DMA: 0x01u
		// flags: 0x8000, GFP_DMA: 0x01u
		// flags: 0x80D0, GFP_DMA: 0x01u
		// flags: 0x80D0, GFP_DMA: 0x01u
		if (!(flags & GFP_DMA)) {
			// size: 512, kmalloc_index(512): 9
			// size: 52, kmalloc_index(52): 6
			// size: 16, kmalloc_index(16): 6
			// size: 3076, kmalloc_index(3076): 12
			int index = kmalloc_index(size);
			// index: 9
			// index: 6
			// index: 6
			// index: 12

			// index: 9
			// index: 6
			// index: 6
			// index: 12
			if (!index)
				return ZERO_SIZE_PTR;

			// index: 9, kmalloc_caches[9]: kmem_cache#26, flags: 0x80D0, size: 512
			// index: 6, kmalloc_caches[6]: kmem_cache#30, flags: 0x8000, size: 52
			// index: 6, kmalloc_caches[6]: kmem_cache#30, flags: 0x80D0, size: 16
			// index: 12, kmalloc_caches[12]: kmem_cache#23, flags: 0x80D0, size: 3076
			return kmem_cache_alloc_trace(kmalloc_caches[index],
					flags, size);
			// return kmem_cache#26-o0
			// return kmem_cache#30-o9
			// return kmem_cache#30-o10
			// return kmem_cache#23-o0
		}
#endif
	}
	return __kmalloc(size, flags);
}

/*
 * Determine size used for the nth kmalloc cache.
 * return size or 0 if a kmalloc cache for that
 * size does not exist
 */
// ARM10C 20140726
// i: 2
static __always_inline int kmalloc_size(int n)
{
#ifndef CONFIG_SLOB // CONFIG_SLOB=n
	// n: 2
	if (n > 2)
		return 1 << n;

	// n: 2
	if (n == 1 && KMALLOC_MIN_SIZE <= 32)
		return 96;

	// n: 2, KMALLOC_MIN_SIZE: 64
	if (n == 2 && KMALLOC_MIN_SIZE <= 64)
		return 192;
		// return 192
#endif
	return 0;
}

// ARM10C 20141004
// size: 156, flags: 0x80D0, node: 0
// ARM10C 20141025
// size: 32, flags: GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u, node: -1
// ARM10C 20141025
// sizeof(struct vmap_area): 52 bytes, gfp_mask: GFP_KERNEL: 0xD0, node: -1
// ARM10C 20141206
// size: 1076, flags: GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u, node: 0
static __always_inline void *kmalloc_node(size_t size, gfp_t flags, int node)
{
#ifndef CONFIG_SLOB // CONFIG_SLOB=n
	// size: 156, KMALLOC_MAX_CACHE_SIZE: 0x2000, flags: 0x80D0, GFP_DMA: 0x01u
	// size: 32, KMALLOC_MAX_CACHE_SIZE: 0x2000, flags: 0x80D0, GFP_DMA: 0x01u
	// size: 52, KMALLOC_MAX_CACHE_SIZE: 0x2000, flags: 0xD0, GFP_DMA: 0x01u
	// size: 1076, KMALLOC_MAX_CACHE_SIZE: 0x2000, flags: 0xD0, GFP_DMA: 0x01u
	if (__builtin_constant_p(size) &&
		size <= KMALLOC_MAX_CACHE_SIZE && !(flags & GFP_DMA)) {
		// size: 156, kmalloc_index(156): 2
		// size: 32, kmalloc_index(32): 6
		// size: 52, kmalloc_index(52): 6
		// size: 1076, kmalloc_index(1076): 11
		int i = kmalloc_index(size);
		// i: 2
		// i: 6
		// i: 6
		// i: 11

		// i: 2
		// i: 6
		// i: 6
		// i: 11
		if (!i)
			return ZERO_SIZE_PTR;

		// i: 2, kmalloc_caches[2]: kmem_cache#28, flags: 0x80D0, node: 0, size: 156
		// kmem_cache_alloc_node_trace(kmem_cache#28, 0x80D0, 0, 156): kmem_cache#28-o0
		// i: 6, kmalloc_caches[6]: kmem_cache#30, flags: 0x80D0, node: -1, size: 32
		// kmem_cache_alloc_node_trace(kmem_cache#30, 0x80D0, 0, 32): kmem_cache#30-oX
		// i: 6, kmalloc_caches[6]: kmem_cache#30, flags: 0xD0, node: -1, size: 52
		// kmem_cache_alloc_node_trace(kmem_cache#30, 0xD0, 0, 52): kmem_cache#30-oX
		// i: 11, kmalloc_caches[11]: kmem_cache#24, flags: 0x80D0, node: -1, size: 1076
		// kmem_cache_alloc_node_trace(kmem_cache#24, 0x80D0, 0, 1076): kmem_cache#24-o0
		return kmem_cache_alloc_node_trace(kmalloc_caches[i],
						flags, node, size);
		// return kmem_cache#28-o0
		// return kmem_cache#30-oX
		// return kmem_cache#30-oX
		// return kmem_cache#24-o0
	}
#endif
	return __kmalloc_node(size, flags, node);
}

/*
 * Setting ARCH_SLAB_MINALIGN in arch headers allows a different alignment.
 * Intended for arches that get misalignment faults even for 64 bit integer
 * aligned buffers.
 */
#ifndef ARCH_SLAB_MINALIGN
#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
#endif
/*
 * This is the main placeholder for memcg-related information in kmem caches.
 * struct kmem_cache will hold a pointer to it, so the memory cost while
 * disabled is 1 pointer. The runtime cost while enabled, gets bigger than it
 * would otherwise be if that would be bundled in kmem_cache: we'll need an
 * extra pointer chase. But the trade off clearly lays in favor of not
 * penalizing non-users.
 *
 * Both the root cache and the child caches will have it. For the root cache,
 * this will hold a dynamically allocated array large enough to hold
 * information about the currently limited memcgs in the system.
 *
 * Child caches will hold extra metadata needed for its operation. Fields are:
 *
 * @memcg: pointer to the memcg this cache belongs to
 * @list: list_head for the list of all caches in this memcg
 * @root_cache: pointer to the global, root cache, this cache was derived from
 * @dead: set to true after the memcg dies; the cache may still be around.
 * @nr_pages: number of pages that belongs to this cache.
 * @destroy: worker to be called whenever we are ready, or believe we may be
 *           ready, to destroy this cache.
 */
struct memcg_cache_params {
	bool is_root_cache;
	union {
		struct kmem_cache *memcg_caches[0];
		struct {
			struct mem_cgroup *memcg;
			struct list_head list;
			struct kmem_cache *root_cache;
			bool dead;
			atomic_t nr_pages;
			struct work_struct destroy;
		};
	};
};

int memcg_update_all_caches(int num_memcgs);

struct seq_file;
int cache_show(struct kmem_cache *s, struct seq_file *m);
void print_slabinfo_header(struct seq_file *m);

/**
 * kmalloc_array - allocate memory for an array.
 * @n: number of elements.
 * @size: element size.
 * @flags: the type of memory to allocate (see kmalloc).
 */
// ARM10C 20141206
// n: 32, size: 16, 0x80D0
// ARM10C 20150117
// n: 0, size: 4, flags: GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u
static inline void *kmalloc_array(size_t n, size_t size, gfp_t flags)
{
	// size: 16, n: 32, SIZE_MAX: 0xFFFFFFFF
	// size: 4, n: 0, SIZE_MAX: 0xFFFFFFFF
	if (size != 0 && n > SIZE_MAX / size)
		return NULL;

	// n: 32, size: 16, flags: 0x80D0
	// __kmalloc(512, 0x80D0): kmem_cache#26-oX
	// n: 0, size: 4, flags: 0x80D0
	// __kmalloc(0, 0x80D0): ((void *)16)
	return __kmalloc(n * size, flags);
	// return kmem_cache#26-oX
	// return ((void *)16)
}

/**
 * kcalloc - allocate memory for an array. The memory is set to zero.
 * @n: number of elements.
 * @size: element size.
 * @flags: the type of memory to allocate (see kmalloc).
 */
// ARM10C 20141206
// max_nr: 32, sizeof(struct combiner_chip_data): 16 bytes, GFP_KERNEL: 0xD0
// ARM10C 20150117
// clk->num_parents: (kmem_cache#29-oX)->num_parents: 0, sizeof(char *): 4, GFP_KERNEL: 0xD0
// ARM10C 20150117
// clk->num_parents: (kmem_cache#29-oX (apll))->num_parents: 1, sizeof(char *): 4, GFP_KERNEL: 0xD0
static inline void *kcalloc(size_t n, size_t size, gfp_t flags)
{
	// n: 32, size: 16, flags: GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u
	// kmalloc_array(32, 16,  0x80D0): kmem_cache#26-oX
	// n: 0, size: 4, flags: GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u
	// kmalloc_array(0, 4,  0x80D0): ((void *)16)
	return kmalloc_array(n, size, flags | __GFP_ZERO);
	// return kmem_cache#26-oX
	// return ((void *)16)
}

/*
 * kmalloc_track_caller is a special version of kmalloc that records the
 * calling function of the routine calling it for slab leak tracking instead
 * of just the calling function (confusing, eh?).
 * It's useful when the call to kmalloc comes from a widely-used standard
 * allocator where we care about the real place the memory allocation
 * request comes from.
 */
// CONFIG_DEBUG_SLAB=n, CONFIG_SLUB=y, CONFIG_SLAB=n, CONFIG_TRACING=n CONFIG_SLOB=n
#if defined(CONFIG_DEBUG_SLAB) || defined(CONFIG_SLUB) || \
	(defined(CONFIG_SLAB) && defined(CONFIG_TRACING)) || \
	(defined(CONFIG_SLOB) && defined(CONFIG_TRACING))
extern void *__kmalloc_track_caller(size_t, gfp_t, unsigned long);
// ARM10C 20140726
// len: 12, gfp: GFP_NOWAIT: 0
// ARM10C 20140920
// len: 16, gfp: GFP_KERNEL: 0xD0
#define kmalloc_track_caller(size, flags) \
	__kmalloc_track_caller(size, flags, _RET_IP_)
#else
#define kmalloc_track_caller(size, flags) \
	__kmalloc(size, flags)
#endif /* DEBUG_SLAB */

#ifdef CONFIG_NUMA
/*
 * kmalloc_node_track_caller is a special version of kmalloc_node that
 * records the calling function of the routine calling it for slab leak
 * tracking instead of just the calling function (confusing, eh?).
 * It's useful when the call to kmalloc_node comes from a widely-used
 * standard allocator where we care about the real place the memory
 * allocation request comes from.
 */
#if defined(CONFIG_DEBUG_SLAB) || defined(CONFIG_SLUB) || \
	(defined(CONFIG_SLAB) && defined(CONFIG_TRACING)) || \
	(defined(CONFIG_SLOB) && defined(CONFIG_TRACING))
extern void *__kmalloc_node_track_caller(size_t, gfp_t, int, unsigned long);
#define kmalloc_node_track_caller(size, flags, node) \
	__kmalloc_node_track_caller(size, flags, node, \
			_RET_IP_)
#else
#define kmalloc_node_track_caller(size, flags, node) \
	__kmalloc_node(size, flags, node)
#endif

#else /* CONFIG_NUMA */

#define kmalloc_node_track_caller(size, flags, node) \
	kmalloc_track_caller(size, flags)

#endif /* CONFIG_NUMA */

/*
 * Shortcuts
 */
// ARM10C 20140628
// kmem_cache: &boot_kmem_cache, GFP_NOWAIT: 0
// ARM10C 20140705
// kmem_cache: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, GFP_NOWAIT: 0
// ARM10C 20140719
// kmem_cache: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, GFP_NOWAIT: 0
// ARM10C 20140920
// kmem_cache: kmem_cache#0, GFP_KERNEL: 0xD0
static inline void *kmem_cache_zalloc(struct kmem_cache *k, gfp_t flags)
{
	// k: &boot_kmem_cache, flags: GFP_NOWAIT: 0, __GFP_ZERO: 0x8000u
	// kmem_cache_alloc(&boot_kmem_cache, __GFP_ZERO: 0x8000u):
	// UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// k: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, flags: GFP_NOWAIT: 0, __GFP_ZERO: 0x8000u
	// kmem_cache_alloc(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, __GFP_ZERO: 0x8000u):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// k: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, flags: GFP_NOWAIT: 0, __GFP_ZERO: 0x8000u
	// kmem_cache_alloc(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, __GFP_ZERO: 0x8000u):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
	// k: kmem_cache#0, flags: GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u
	// kmem_cache_alloc(kmem_cache#0,, __GFP_ZERO: 0x80D0):
	// kmem_cache#21
	return kmem_cache_alloc(k, flags | __GFP_ZERO);
	// return UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address
	// return UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 3968
	// return UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
	// return kmem_cache#21
}

/**
 * kzalloc - allocate memory. The memory is set to zero.
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate (see kmalloc).
 */
// ARM10C 20140726
// size: 512, GFP_KERNEL: 0xD0
// ARM10C 20140809
// sizeof(struct vmap_area): 52 bytes, GFP_NOWAIT: 0
// ARM10C 20141004
// sizeof(struct intc_desc): 16 bytes, GFP_KERNEL: 0xD0
// ARM10C 20141011
// sizeof(struct intc_desc): 16 bytes, GFP_KERNEL: 0xD0
// ARM10C 20141122
// sizeof(struct cpumask): 4, GFP_KERNEL: 0xD0
// ARM10C 20150110
// 472, GFP_KERNEL: 0xD0
// ARM10C 20150110
// 3076, GFP_KERNEL: 0xD0
// ARM10C 20150110
// sizeof(struct of_clk_provider): 20 bytes, GFP_KERNEL: 0xD0
// ARM10C 20150110
// sizeof(struct clk_fixed_rate): 13 bytes, GFP_KERNEL: 0xD0
// ARM10C 20150117
// sizeof(struct clk): 66 bytes, GFP_KERNEL: 0xD0
// ARM10C 20150117
// size: 56, GFP_KERNEL: 0xD0
// ARM10C 20150117
// sizeof(struct samsung_clk_pll): 28 bytes, GFP_KERNEL: 0xD0
static inline void *kzalloc(size_t size, gfp_t flags)
{
	// size: 512, GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u
	// size: 52, GFP_NOWAIT: 0x0, __GFP_ZERO: 0x8000u
	// size: 16, GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u
	// size: 3076, GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u
	// size: 66, GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u
	return kmalloc(size, flags | __GFP_ZERO);
	// return kmem_cache#26-o0
	// return kmem_cache#30-o9
	// return kmem_cache#30-o10
	// return kmem_cache#23-o0
	// return kmem_cache#29-o0
}

/**
 * kzalloc_node - allocate zeroed memory from a particular memory node.
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate (see kmalloc).
 * @node: memory node from which to allocate
 */
// ARM10C 20141004
// sizeof(struct irq_desc): 156 bytes, gfp: GFP_KERNEL: 0xD0, node: 0
// ARM10C 20141025
// sizeof(*area): 32, gfp_mask: GFP_KERNEL: 0xD0, node: -1
// ARM10C 20141101
// sizeof(*area): 32, gfp_mask: GFP_KERNEL: 0xD0, node: -1
// ARM10C 20141122
// 692, GFP_KERNEL: 0xD0, 0
// ARM10C 20141206
// 1076, GFP_KERNEL: 0xD0, 0
static inline void *kzalloc_node(size_t size, gfp_t flags, int node)
{
	// size: 156, flags: GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u, node: 0
	// kmalloc_node(156, 0x80D0, 0): kmem_cache#28-o0
	// size: 32, flags: GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u, node: -1
	// kmalloc_node(32, 0x80D0, -1): kmem_cache#30-oX
	// size: 692, flags: GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u, node: 0
	// kmalloc_node(692, 0x80D0, 0): kmem_cache#25-o0
	// size: 1076, flags: GFP_KERNEL: 0xD0, __GFP_ZERO: 0x8000u, node: 0
	// kmalloc_node(1076, 0x80D0, 0): kmem_cache#24-o0
	return kmalloc_node(size, flags | __GFP_ZERO, node);
	// return kmem_cache#28-o0
	// return kmem_cache#30-oX
	// return kmem_cache#25-o0
	// return kmem_cache#24-o0
}

/*
 * Determine the size of a slab object
 */
static inline unsigned int kmem_cache_size(struct kmem_cache *s)
{
	return s->object_size;
}

void __init kmem_cache_init_late(void);

#endif	/* _LINUX_SLAB_H */
