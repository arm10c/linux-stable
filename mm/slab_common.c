/*
 * Slab allocator functions that are independent of the allocator strategy
 *
 * (C) 2012 Christoph Lameter <cl@linux.com>
 */
#include <linux/slab.h>

#include <linux/mm.h>
#include <linux/poison.h>
#include <linux/interrupt.h>
#include <linux/memory.h>
#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/page.h>
#include <linux/memcontrol.h>
#include <trace/events/kmem.h>

#include "slab.h"

// ARM10C 20131207
// ARM10C 20140426
// ARM10C 20140607
enum slab_state slab_state;
// ARM10C 20140705
// ARM10C 20140712
// ARM10C 20140726
// ARM10C 20140920
LIST_HEAD(slab_caches);
// ARM10C 20140920
DEFINE_MUTEX(slab_mutex);
// ARM10C 20140419
// ARM10C 20140628
// ARM10C 20140920
struct kmem_cache *kmem_cache;

#ifdef CONFIG_DEBUG_VM // CONFIG_DEBUG_VM=n
static int kmem_cache_sanity_check(struct mem_cgroup *memcg, const char *name,
				   size_t size)
{
	struct kmem_cache *s = NULL;

	if (!name || in_interrupt() || size < sizeof(void *) ||
		size > KMALLOC_MAX_SIZE) {
		pr_err("kmem_cache_create(%s) integrity check failed\n", name);
		return -EINVAL;
	}

	list_for_each_entry(s, &slab_caches, list) {
		char tmp;
		int res;

		/*
		 * This happens when the module gets unloaded and doesn't
		 * destroy its slab cache and no-one else reuses the vmalloc
		 * area of the module.  Print a warning.
		 */
		res = probe_kernel_address(s->name, tmp);
		if (res) {
			pr_err("Slab cache with size %d has lost its name\n",
			       s->object_size);
			continue;
		}

#if !defined(CONFIG_SLUB) || !defined(CONFIG_SLUB_DEBUG_ON)
		/*
		 * For simplicity, we won't check this in the list of memcg
		 * caches. We have control over memcg naming, and if there
		 * aren't duplicates in the global list, there won't be any
		 * duplicates in the memcg lists as well.
		 */
		if (!memcg && !strcmp(s->name, name)) {
			pr_err("%s (%s): Cache name already exists.\n",
			       __func__, name);
			dump_stack();
			s = NULL;
			return -EINVAL;
		}
#endif
	}

	WARN_ON(strchr(name, ' '));	/* It confuses parsers */
	return 0;
}
#else
// ARM10C 20140920
static inline int kmem_cache_sanity_check(struct mem_cgroup *memcg,
					  const char *name, size_t size)
{
	return 0;
}
#endif

#ifdef CONFIG_MEMCG_KMEM
int memcg_update_all_caches(int num_memcgs)
{
	struct kmem_cache *s;
	int ret = 0;
	mutex_lock(&slab_mutex);

	list_for_each_entry(s, &slab_caches, list) {
		if (!is_root_cache(s))
			continue;

		ret = memcg_update_cache_size(s, num_memcgs);
		/*
		 * See comment in memcontrol.c, memcg_update_cache_size:
		 * Instead of freeing the memory, we'll just leave the caches
		 * up to this point in an updated state.
		 */
		if (ret)
			goto out;
	}

	memcg_update_array_size(num_memcgs);
out:
	mutex_unlock(&slab_mutex);
	return ret;
}
#endif

/*
 * Figure out what the alignment of the objects will be given a set of
 * flags, a user specified alignment and the size of the objects.
 */
// ARM10C 20140419
// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, ARCH_KMALLOC_MINALIGN: 64, size: 44
// ARM10C 20140614
// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, ARCH_KMALLOC_MINALIGN: 64, size: 116
// ARM10C 20140726
// flags: 0, ARCH_KMALLOC_MINALIGN: 64, size: 4096
// ARM10C 20140920
// flags: SLAB_PANIC: 0x00040000UL, align: 0, size: 1076
unsigned long calculate_alignment(unsigned long flags,
		unsigned long align, unsigned long size)
{
	/*
	 * If the user wants hardware cache aligned objects then follow that
	 * suggestion if the object is sufficiently large.
	 *
	 * The hardware cache alignment cannot override the specified
	 * alignment though. If that is greater then use it.
	 */
	// flags: SLAB_HWCACHE_ALIGN
	// flags: 0
	// flags: SLAB_PANIC: 0x00040000UL
	if (flags & SLAB_HWCACHE_ALIGN) {
		// cache_line_size(): 64
		unsigned long ralign = cache_line_size();
		// ralign: 64

		// size : 44, ralign: 64
		// size : 116, ralign: 64
		while (size <= ralign / 2)
			ralign /= 2;

		// align: 64, ralign: 64
		align = max(align, ralign);
		// align: 64
	}

	// align: 64, ARCH_SLAB_MINALIGN: 8
	// align: 64, ARCH_SLAB_MINALIGN: 8
	// align: 0, ARCH_SLAB_MINALIGN: 8
	if (align < ARCH_SLAB_MINALIGN)
		// align: 0, ARCH_SLAB_MINALIGN: 8
		align = ARCH_SLAB_MINALIGN;
		// align: 8

	// align: 64, sizeof(void *): 4
	// align: 64, sizeof(void *): 4
	// align: 8, sizeof(void *): 4
	return ALIGN(align, sizeof(void *));
	// return 64
	// return 64
	// return 8
}


/*
 * kmem_cache_create - Create a cache.
 * @name: A string which is used in /proc/slabinfo to identify this cache.
 * @size: The size of objects to be created in this cache.
 * @align: The required alignment for the objects.
 * @flags: SLAB flags
 * @ctor: A constructor for the objects.
 *
 * Returns a ptr to the cache on success, NULL on failure.
 * Cannot be called within a interrupt, but can be interrupted.
 * The @ctor is run when new pages are allocated by the cache.
 *
 * The flags are
 *
 * %SLAB_POISON - Poison the slab with a known test pattern (a5a5a5a5)
 * to catch references to uninitialised memory.
 *
 * %SLAB_RED_ZONE - Insert `Red' zones around the allocated memory to check
 * for buffer overruns.
 *
 * %SLAB_HWCACHE_ALIGN - Align the objects in this cache to a hardware
 * cacheline.  This can be beneficial if you're counting cycles as closely
 * as davem.
 */

// ARM10C 20140920
// NULL, name: "idr_layer_cache", size: 1076, align: 0, flags: SLAB_PANIC: 0x00040000UL, ctor: NULL, NULL
// ARM10C 20141004
// name: "radix_tree_node", size: 296, align: 0, flags: 0x00060000UL, ctor: radix_tree_node_ctor
struct kmem_cache *
kmem_cache_create_memcg(struct mem_cgroup *memcg, const char *name, size_t size,
			size_t align, unsigned long flags, void (*ctor)(void *),
			struct kmem_cache *parent_cache)
{
	struct kmem_cache *s = NULL;
	// s: NULL

	int err = 0;
	// err: 0

	get_online_cpus();
	// cpu_hotplug.refcount: 1

	mutex_lock(&slab_mutex);
	// &slab_mutex를 사용한 mutex lock 수행

	// memcg: NULL, name: "idr_layer_cache", size: 1076
	// kmem_cache_sanity_check(NULL, "idr_layer_cache", 1076): 0
	if (!kmem_cache_sanity_check(memcg, name, size) == 0)
		goto out_locked;

	/*
	 * Some allocators will constraint the set of valid flags to a subset
	 * of all flags. We expect them to define CACHE_CREATE_MASK in this
	 * case, and we'll just provide them with a sanitized version of the
	 * passed flags.
	 */
	// flags: SLAB_PANIC: 0x00040000UL, CACHE_CREATE_MASK: 0xAF6D00
	flags &= CACHE_CREATE_MASK;
	// flags: SLAB_PANIC: 0x00040000UL

	// memcg: NULL, name: "idr_layer_cache", size: 1076, align: 0, flags: SLAB_PANIC: 0x00040000UL, ctor: NULL
	// __kmem_cache_alias(NULL, "idr_layer_cache", 1076, 0, SLAB_PANIC: 0x00040000UL, NULL): NULL
	s = __kmem_cache_alias(memcg, name, size, align, flags, ctor);
	// s: NULL

	// s: NULL
	if (s)
		goto out_locked;

	// kmem_cache: kmem_cache#0, GFP_KERNEL: 0xD0
	// kmem_cache_zalloc(kmem_cache#0, GFP_KERNEL: 0xD0): kmem_cache#21
	s = kmem_cache_zalloc(kmem_cache, GFP_KERNEL);
	// s: kmem_cache#21

	// s: kmem_cache#21
	if (s) {
		// s->object_size: (kmem_cache#21)->object_size,
		// s->size: (kmem_cache#21)->size, size: 1076
		s->object_size = s->size = size;
		// s->object_size: (kmem_cache#21)->object_size: 1076
		// s->size: (kmem_cache#21)->size: 1076

		// s->align: (kmem_cache#21)->align,
		// flags: SLAB_PANIC: 0x00040000UL, align: 0, size: 1076
		// calculate_alignment(SLAB_PANIC: 0x00040000UL, 0, 1076): 8
		s->align = calculate_alignment(flags, align, size);
		// s->align: (kmem_cache#21)->align: 8

		// s->ctor: (kmem_cache#21)->ctor, ctor: NULL
		s->ctor = ctor;
		// s->ctor: (kmem_cache#21)->ctor: NULL

		// memcg: NULL, s: kmem_cache#21, parent_cache: NULL
		// memcg_register_cache(NULL, kmem_cache#21, NULL): 0
		if (memcg_register_cache(memcg, s, parent_cache)) {
			kmem_cache_free(kmem_cache, s);
			err = -ENOMEM;
			goto out_locked;
		}

		// s->name: (kmem_cache#21)->name, name: "idr_layer_cache", GFP_KERNEL: 0xD0
		// kstrdup("idr_layer_cache", GFP_KERNEL: 0xD0): kmem_cache#30-o17: "idr_layer_cache"
		s->name = kstrdup(name, GFP_KERNEL);
		// s->name: (kmem_cache#21)->name: kmem_cache#30-o17: "idr_layer_cache"

		// s->name: (kmem_cache#21)->name: kmem_cache#30-o17: "idr_layer_cache"
		if (!s->name) {
			kmem_cache_free(kmem_cache, s);
			err = -ENOMEM;
			goto out_locked;
		}

		// s: kmem_cache#21, flags: SLAB_PANIC: 0x00040000UL
		// __kmem_cache_create(&kmem_cache#21, SLAB_PANIC: 0x00040000UL): 0
		err = __kmem_cache_create(s, flags);
		// err: 0

		// __kmem_cache_open(&kmem_cache#21) 가 한일:
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
		if (!err) {
			// s->refcount: (kmem_cache#21)->refcount
			s->refcount = 1;
			// s->refcount: (kmem_cache#21)->refcount: 1

			// s->list: (kmem_cache#21)->list
			list_add(&s->list, &slab_caches);
			// slab_caches 의 list에 (kmem_cache#21)->list를 등록

			// memcg: NULL, s: kmem_cache#21
			memcg_cache_list_add(memcg, s); // null function
		} else {
			kfree(s->name);
			kmem_cache_free(kmem_cache, s);
		}
	} else
		err = -ENOMEM;

out_locked:
	mutex_unlock(&slab_mutex);
	// &slab_mutex를 사용한 mutex lock 해제

	put_online_cpus();
	// cpu_hotplug.refcount: 0

	// err: 0
	if (err) {

		if (flags & SLAB_PANIC)
			panic("kmem_cache_create: Failed to create slab '%s'. Error %d\n",
				name, err);
		else {
			printk(KERN_WARNING "kmem_cache_create(%s) failed with error %d",
				name, err);
			dump_stack();
		}

		return NULL;
	}

	// s: kmem_cache#21
	return s;
	// return kmem_cache#21
}

// ARM10C 20140920
// "idr_layer_cache", sizeof(struct idr_layer): 1076 bytes, 0, SLAB_PANIC: 0x00040000UL, NULL
// ARM10C 20141004
// "radix_tree_node", sizeof(struct radix_tree_node): 296 bytes, 0, 0x00060000UL, radix_tree_node_ctor
struct kmem_cache *
kmem_cache_create(const char *name, size_t size, size_t align,
		  unsigned long flags, void (*ctor)(void *))
{
	// name: "idr_layer_cache", size: 1076, align: 0, flags: SLAB_PANIC: 0x00040000UL, ctor: NULL
	// kmem_cache_create_memcg(NULL, "idr_layer_cache", 1076, 0, SLAB_PANIC: 0x00040000UL, NULL): kmem_cache#21
	// name: "radix_tree_node", size: 296, align: 0, flags: 0x00060000UL, ctor: radix_tree_node_ctor
	// kmem_cache_create_memcg(NULL, "radix_tree_node", 296, 0, 0x00060000UL, radix_tree_node_ctor): kmem_cache#20
	return kmem_cache_create_memcg(NULL, name, size, align, flags, ctor, NULL);
	// return kmem_cache#21
	// return kmem_cache#20
}
EXPORT_SYMBOL(kmem_cache_create);

void kmem_cache_destroy(struct kmem_cache *s)
{
	/* Destroy all the children caches if we aren't a memcg cache */
	kmem_cache_destroy_memcg_children(s);

	get_online_cpus();
	mutex_lock(&slab_mutex);
	s->refcount--;
	if (!s->refcount) {
		list_del(&s->list);

		if (!__kmem_cache_shutdown(s)) {
			mutex_unlock(&slab_mutex);
			if (s->flags & SLAB_DESTROY_BY_RCU)
				rcu_barrier();

			memcg_release_cache(s);
			kfree(s->name);
			kmem_cache_free(kmem_cache, s);
		} else {
			list_add(&s->list, &slab_caches);
			mutex_unlock(&slab_mutex);
			printk(KERN_ERR "kmem_cache_destroy %s: Slab cache still has objects\n",
				s->name);
			dump_stack();
		}
	} else {
		mutex_unlock(&slab_mutex);
	}
	put_online_cpus();
}
EXPORT_SYMBOL(kmem_cache_destroy);

// ARM10C 20131207
// ARM10C 20140607
// ARM10C 20140726
int slab_is_available(void)
{
	return slab_state >= UP;
}

#ifndef CONFIG_SLOB // CONFIG_SLOB=n
/* Create a cache during boot when no slab services are available yet */
// ARM10C 20140419
// &boot_kmem_cache_node, "kmem_cache_node", sizeof(struct kmem_cache_node): 44 byte,
// SLAB_HWCACHE_ALIGN: 0x00002000UL
// ARM10C 20140614
// &boot_kmem_cache, "kmem_cache", 116, SLAB_HWCACHE_ALIGN: 0x00002000UL
// ARM10C 20140726
// s: kmem_cache#30, name: NULL, size: 64, flags: 0
// ARM10C 20140726
// s: kmem_cache#23, name: NULL, size: 4096, flags: 0
void __init create_boot_cache(struct kmem_cache *s, const char *name, size_t size,
		unsigned long flags)
{
	int err;

	// s->name: boot_kmem_cache_node.name: NULL
	// s->name: boot_kmem_cache.name: NULL
	// s->name: kmem_cache#30.name: NULL
	// s->name: kmem_cache#23.name: NULL
	s->name = name;
	// s->name: boot_kmem_cache_node.name: "kmem_cache_node"
	// s->name: boot_kmem_cache.name: "kmem_cache"
	// s->name: kmem_cache#30.name: NULL
	// s->name: kmem_cache#23.name: NULL

	// s->size: boot_kmem_cache_node.size: 0
	// s->object_size: boot_kmem_cache_node.object_size: 0
	// s->size: boot_kmem_cache.size: 0
	// s->object_size: boot_kmem_cache.object_size: 0
	// s->size: kmem_cache#30.size: 0
	// s->object_size: kmem_cache#30.object_size: 0
	// s->size: kmem_cache#23.size: 0
	// s->object_size: kmem_cache#23.object_size: 0
	s->size = s->object_size = size;
	// s->size: boot_kmem_cache_node.size: 44
	// s->object_size: boot_kmem_cache_node.object_size: 44
	// s->size: boot_kmem_cache.size: 116
	// s->object_size: boot_kmem_cache.object_size: 116
	// s->size: kmem_cache#30.size: 64
	// s->object_size: kmem_cache#30.object_size: 64
	// s->size: kmem_cache#23.size: 4096
	// s->object_size: kmem_cache#23.object_size: 4096
	
	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, ARCH_KMALLOC_MINALIGN: 64, size: 44
	// s->align: boot_kmem_cache_node.align: 0
	// flags: SLAB_HWCACHE_ALIGN: 0x00002000UL, ARCH_KMALLOC_MINALIGN: 64, size: 116
	// s->align: boot_kmem_cache.align: 0
	// flags: 0, ARCH_KMALLOC_MINALIGN: 64, size: 64
	// s->align: kmem_cache#30.align: 0
	// flags: 0, ARCH_KMALLOC_MINALIGN: 64, size: 4096
	// s->align: kmem_cache#23.align: 0
	s->align = calculate_alignment(flags, ARCH_KMALLOC_MINALIGN, size);
	// s->align: boot_kmem_cache_node.align: 64
	// s->align: boot_kmem_cache.align: 64
	// s->align: kmem_cache#30.align: 64
	// s->align: kmem_cache#23.align: 64
	
	// s: &boot_kmem_cache_node, flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// __kmem_cache_create(&boot_kmem_cache_node, 0x00002000UL): 0
	// s: &boot_kmem_cache, flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// __kmem_cache_create(&boot_kmem_cache, 0x00002000UL): 0
	// s: &kmem_cache#30, flags: 0
	// __kmem_cache_create(&kmem_cache#30, 0): 0
	// s: &kmem_cache#23, flags: 0
	// __kmem_cache_create(&kmem_cache#23, 0): 0
	err = __kmem_cache_create(s, flags);
	// err: 0
	// err: 0
	// err: 0
	// err: 0

	// __kmem_cache_create(&boot_kmem_cache_node) 가 한일:
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
	// kmem_cache_node#0의 partial 맴버에 현재 page의 lru 리스트를 추가함
	//
	// kmem_cache_node#0 가 boot_kmem_cache_node.node[0]에 할당됨
	//
	// 할당받은 pcpu 들의 16 byte 공간 (&boot_kmem_cache_node)->cpu_slab 에
	// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

	// __kmem_cache_create(&boot_kmem_cache) 가 한일:
	// boot_kmem_cache.flags: SLAB_HWCACHE_ALIGN: 0x00002000UL
	// boot_kmem_cache.reserved: 0
	// boot_kmem_cache.min_partial: 5
	// boot_kmem_cache.cpu_partial: 30
	//
	// 할당 받아 놓은 migratetype이 MIGRATE_UNMOVABLE인 page 를 사용
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
	// (kmem_cache_node#1)->slabs: 0, kmem_cache_node->total_objects: 0 로 세팀함
	// (kmem_cache_node#1)->full: 리스트 초기화
	//
	// kmem_cache_node#1 가 boot_kmem_cache.node[0]에 할당됨
	//
	// 할당받은 pcpu 들의 16 byte 공간 (&boot_kmem_cache)->cpu_slab 에
	// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

	// __kmem_cache_create(&kmem_cache#30) 가 한일:
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
	// (kmem_cache_node#63)->slabs: 0,
	// (kmem_cache_node#63)->total_objects: 0 로 세팀함
	// (kmem_cache_node#63)->full: 리스트 초기화
	//
	// kmem_cache_node#63 가 kmem_cache#30.node[0]에 할당됨
	//
	// 할당받은 pcpu 들의 16 byte 공간 (&kmem_cache#30)->cpu_slab 에
	// 각 cpu에 사용하는 kmem_cache_cpu의 tid 맵버를 설정

	// __kmem_cache_create(&kmem_cache#23) 가 한일:
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

	// err: 0
	// err: 0
	// err: 0
	// err: 0
	if (err)
		panic("Creation of kmalloc slab %s size=%zu failed. Reason %d\n",
					name, size, err);

	// s->refcount: boot_kmem_cache_node.refcount
	// s->refcount: boot_kmem_cache.refcount
	// s->refcount: kmem_cache#30.refcount
	// s->refcount: kmem_cache#23.refcount
	s->refcount = -1;	/* Exempt from merging for now */
	// s->refcount: boot_kmem_cache_node.refcount: -1
	// s->refcount: boot_kmem_cache.refcount: -1
	// s->refcount: kmem_cache#30.refcount: -1
	// s->refcount: kmem_cache#23.refcount: -1
}

// ARM10C 20140719
// NULL, 64, 0
// ARM10C 20140726
// NULL, 4096, 0
struct kmem_cache *__init create_kmalloc_cache(const char *name, size_t size,
				unsigned long flags)
{
	// kmem_cache: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// GFP_NOWAIT: 0
	// kmem_cache_zalloc(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, 0):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840
	// kmem_cache: UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address,
	// GFP_NOWAIT: 0
	// kmem_cache_zalloc(UNMOVABLE인 page (boot_kmem_cache)의 object의 시작 virtual address, 0):
	// UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 2944
	struct kmem_cache *s = kmem_cache_zalloc(kmem_cache, GFP_NOWAIT);
	// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840 (kmem_cache#30)
	// s: UNMOVABLE인 page (boot_kmem_cache)의 시작 virtual address + 2944 (kmem_cache#23)

	// UNMOVABLE인 page (boot_kmem_cache)의 시작 object의 virtual address + 3840 를
	// kmem_cache 용 30번째 object 인데 주석 추가의 용의성을 위해
	// kmem_cache#30 부르기로 함

// 2014/07/19 종료
// 2014/07/26 시작

	// s: kmem_cache#30
	// s: kmem_cache#23
	if (!s)
		panic("Out of memory when creating slab %s\n", name);

	// s: kmem_cache#30, name: NULL, size: 64, flags: 0
	// s: kmem_cache#23, name: NULL, size: 4096, flags: 0
	create_boot_cache(s, name, size, flags);

	// &s->list: &kmem_cache#30->list
	// &s->list: &kmem_cache#23->list
	list_add(&s->list, &slab_caches);
	// slab_caches에 &kmem_cache#30->list 추가
	// slab_caches에 &kmem_cache#23->list 추가

	// &s->refcount: &kmem_cache#30->refcount: -1
	// &s->refcount: &kmem_cache#23->refcount: -1
	s->refcount = 1;
	// &s->refcount: &kmem_cache#30->refcount: 1
	// &s->refcount: &kmem_cache#23->refcount: 1

	// s: kmem_cache#30
	// s: kmem_cache#23
	return s;
	// return kmem_cache#30
	// return kmem_cache#23
}

// ARM10C 20140719
// KMALLOC_SHIFT_HIGH: 13
struct kmem_cache *kmalloc_caches[KMALLOC_SHIFT_HIGH + 1];
EXPORT_SYMBOL(kmalloc_caches);

#ifdef CONFIG_ZONE_DMA
struct kmem_cache *kmalloc_dma_caches[KMALLOC_SHIFT_HIGH + 1];
EXPORT_SYMBOL(kmalloc_dma_caches);
#endif

/*
 * Conversion table for small slabs sizes / 8 to the index in the
 * kmalloc array. This is necessary for slabs < 192 since we have non power
 * of two cache sizes there. The size of larger slabs can be determined using
 * fls.
 */
// ARM10C 20140719
static s8 size_index[24] = {
	3,	/* 8 */
	4,	/* 16 */
	5,	/* 24 */
	5,	/* 32 */
	6,	/* 40 */
	6,	/* 48 */
	6,	/* 56 */
	6,	/* 64 */
	1,	/* 72 */
	1,	/* 80 */
	1,	/* 88 */
	1,	/* 96 */
	7,	/* 104 */
	7,	/* 112 */
	7,	/* 120 */
	7,	/* 128 */
	2,	/* 136 */
	2,	/* 144 */
	2,	/* 152 */
	2,	/* 160 */
	2,	/* 168 */
	2,	/* 176 */
	2,	/* 184 */
	2	/* 192 */
};

// ARM10C 20140719
// i: 8
// ARM10C 20140726
// size: 12
// ARM10C 20140920
// size: 16
static inline int size_index_elem(size_t bytes)
{
	// bytes: 8
	// bytes: 12
	// bytes: 16
	return (bytes - 1) / 8;
	// return 0
	// return 1
	// return 1
}

/*
 * Find the kmem_cache structure that serves a given size of
 * allocation
 */
// ARM10C 20140726
// size: 12, gfpflags: GFP_NOWAIT: 0
// ARM10C 20140920
// size: 16, gfpflags: GFP_KERNEL: 0xD0
// ARM10C 20141206
// size: 512, flags: 0x80D0
// ARM10C 20150117
// size: 0, flags: 0x80D0
struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags)
{
	int index;

	// size: 12, KMALLOC_MAX_SIZE: 0x40000000
	// size: 16, KMALLOC_MAX_SIZE: 0x40000000
	// size: 512, KMALLOC_MAX_SIZE: 0x40000000
	// size: 0, KMALLOC_MAX_SIZE: 0x40000000
	if (unlikely(size > KMALLOC_MAX_SIZE)) {
		WARN_ON_ONCE(!(flags & __GFP_NOWARN));
		return NULL;
	}

	// size: 12
	// size: 16
	// size: 512
	// size: 0
	if (size <= 192) {
		// size: 12
		// size: 16
		// size: 0
		if (!size)
			// ZERO_SIZE_PTR: ((void *)16)
			return ZERO_SIZE_PTR;
			// return ((void *)16)

		// size: 12, size_index_elem(12): 1, size_index[1]: 6
		// size: 16, size_index_elem(16): 1, size_index[1]: 6
		index = size_index[size_index_elem(size)];
		// index: 6
		// index: 6
	} else
		// size: 512
		// fls(511): 9
		index = fls(size - 1);
		// index: 9

#ifdef CONFIG_ZONE_DMA // CONFIG_ZONE_DMA=n
	if (unlikely((flags & GFP_DMA)))
		return kmalloc_dma_caches[index];

#endif
	// index: 6, kmalloc_caches[6]: kmem_cache#30
	// index: 6, kmalloc_caches[6]: kmem_cache#30
	// index: 9, kmalloc_caches[9]: kmem_cache#26
	return kmalloc_caches[index];
	// return kmem_cache#30
	// return kmem_cache#30
	// return kmem_cache#26
}

/*
 * Create the kmalloc array. Some of the regular kmalloc arrays
 * may already have been created because they were needed to
 * enable allocations for slab creation.
 */
// ARM10C 20140719
// flags: 0
void __init create_kmalloc_caches(unsigned long flags)
{
	int i;

	/*
	 * Patch up the size_index table if we have strange large alignment
	 * requirements for the kmalloc array. This is only the case for
	 * MIPS it seems. The standard arches will not generate any code here.
	 *
	 * Largest permitted alignment is 256 bytes due to the way we
	 * handle the index determination for the smaller caches.
	 *
	 * Make sure that nothing crazy happens if someone starts tinkering
	 * around with ARCH_KMALLOC_MINALIGN
	 */
	// KMALLOC_MIN_SIZE: 64
	BUILD_BUG_ON(KMALLOC_MIN_SIZE > 256 ||
		(KMALLOC_MIN_SIZE & (KMALLOC_MIN_SIZE - 1)));

	// KMALLOC_MIN_SIZE: 64
	for (i = 8; i < KMALLOC_MIN_SIZE; i += 8) {
		// i: 8, size_index_elem(8): 0
		int elem = size_index_elem(i);
		// elem: 0

		// elem: 0, ARRAY_SIZE(size_index): 24
		if (elem >= ARRAY_SIZE(size_index))
			break;

		// elem: 0, KMALLOC_SHIFT_LOW: 6
		size_index[elem] = KMALLOC_SHIFT_LOW;
		// size_index[0]: 6
	}
	// 루프 수행 결과
	// size_index[0 .. 6]: 6

	// KMALLOC_MIN_SIZE: 64
	if (KMALLOC_MIN_SIZE >= 64) {
		/*
		 * The 96 byte size cache is not used if the alignment
		 * is 64 byte.
		 */
		for (i = 64 + 8; i <= 96; i += 8)
			// i: 72, size_index_elem(72): 8
			size_index[size_index_elem(i)] = 7;
			// size_index[8]: 7

		// 루프 수행 결과
		// size_index[8 .. 11]: 7
	}

	// KMALLOC_MIN_SIZE: 64
	if (KMALLOC_MIN_SIZE >= 128) {
		/*
		 * The 192 byte sized cache is not used if the alignment
		 * is 128 byte. Redirect kmalloc to use the 256 byte cache
		 * instead.
		 */
		for (i = 128 + 8; i <= 192; i += 8)
			size_index[size_index_elem(i)] = 8;
	}

	// KMALLOC_SHIFT_LOW: 6, KMALLOC_SHIFT_HIGH: 13
	for (i = KMALLOC_SHIFT_LOW; i <= KMALLOC_SHIFT_HIGH; i++) {
		// i: 6, kmalloc_caches[6]: NULL
		// i: 7, kmalloc_caches[7]: NULL
		// i: 12, kmalloc_caches[12]: NULL
		if (!kmalloc_caches[i]) {

			// i: 6, flags: 0, create_kmalloc_cache(NULL, 64, 0): kmem_cache#30
			// i: 7, flags: 0, create_kmalloc_cache(NULL, 128, 0): kmem_cache#29
			// i: 12, flags: 0, create_kmalloc_cache(NULL, 4096, 0): kmem_cache#23
			kmalloc_caches[i] = create_kmalloc_cache(NULL,
							1 << i, flags);
			// kmalloc_caches[6]: kmem_cache#30
			// kmalloc_caches[7]: kmem_cache#29
			// kmalloc_caches[12]: kmem_cache#23
		}

		/*
		 * Caches that are not of the two-to-the-power-of size.
		 * These have to be created immediately after the
		 * earlier power of two caches
		 */
		// KMALLOC_MIN_SIZE: 64, i: 6, kmalloc_caches[1]: NULL
		// KMALLOC_MIN_SIZE: 64, i: 7, kmalloc_caches[1]: NULL
		// KMALLOC_MIN_SIZE: 64, i: 12, kmalloc_caches[1]: NULL
		if (KMALLOC_MIN_SIZE <= 32 && !kmalloc_caches[1] && i == 6)
			kmalloc_caches[1] = create_kmalloc_cache(NULL, 96, flags);

		// KMALLOC_MIN_SIZE: 64, i: 6, kmalloc_caches[1]: NULL
		// KMALLOC_MIN_SIZE: 64, i: 7, kmalloc_caches[2]: NULL
		// KMALLOC_MIN_SIZE: 64, i: 12, kmalloc_caches[2]: NULL
		if (KMALLOC_MIN_SIZE <= 64 && !kmalloc_caches[2] && i == 7)
			// i: 7, flags: 0, create_kmalloc_cache(NULL, 192, 0): kmem_cache#28
			kmalloc_caches[2] = create_kmalloc_cache(NULL, 192, flags);
			// kmalloc_caches[2]: kmem_cache#28
		
		// loop i = 8 9 10 11 13 수행 (skip)
	}

	// 위 loop 에서 한일:
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
	// kmem_cache_node#55

	/* Kmalloc array is now usable */
	// slab_state: PARTIAL
	slab_state = UP;
	// slab_state: UP

	// KMALLOC_SHIFT_HIGH: 13
	for (i = 0; i <= KMALLOC_SHIFT_HIGH; i++) {
		// i: 0, kmalloc_caches[0]: NULL
		// i: 2, kmalloc_caches[2]: kmem_cache#28
		struct kmem_cache *s = kmalloc_caches[i];
		// i: 0, s: NULL
		// i: 2, s: kmem_cache#28
		char *n;

		// i: 0, s: NULL
		// i: 2, s: kmem_cache#28
		if (s) {
			// GFP_NOWAIT: 0, i: 2, kmalloc_size(2): 192
			// kasprintf(GFP_NOWAIT: 0, "kmalloc-%d", 192): kmem_cache#30-o0
			n = kasprintf(GFP_NOWAIT, "kmalloc-%d", kmalloc_size(i));
			// n: kmem_cache#30-o0

			// n: kmem_cache#30-o0
			BUG_ON(!n);

			// s->name: kmem_cache#28->name: NULL, n: kmem_cache#2-o1
			s->name = n;
			// s->name: kmem_cache#28->name: kmem_cache#30-o0: "kmalloc-192"
		}

		// loop i = 1 3 .. 13 수행 (skip)
	}

	// kmalloc_caches[0] kmalloc_caches[1], kmalloc_caches[3], kmalloc_caches[4], kmalloc_caches[5]
	// 는 값이 null 이므로 skip
	// kmalloc_caches[6]:  kmem_cache#30->name: "kmalloc-64"
	// kmalloc_caches[7]:  kmem_cache#29->name: "kmalloc-128"
	// kmalloc_caches[2]:  kmem_cache#28->name: "kmalloc-192"
	// kmalloc_caches[8]:  kmem_cache#27->name: "kmalloc-256"
	// kmalloc_caches[9]:  kmem_cache#26->name: "kmalloc-512"
	// kmalloc_caches[10]: kmem_cache#25->name: "kmalloc-1024"
	// kmalloc_caches[11]: kmem_cache#24->name: "kmalloc-2048"
	// kmalloc_caches[12]: kmem_cache#23->name: "kmalloc-4096"
	// kmalloc_caches[13]: kmem_cache#22->name: "kmalloc-8192"

#ifdef CONFIG_ZONE_DMA // CONFIG_ZONE_DMA=n
	for (i = 0; i <= KMALLOC_SHIFT_HIGH; i++) {
		struct kmem_cache *s = kmalloc_caches[i];

		if (s) {
			int size = kmalloc_size(i);
			char *n = kasprintf(GFP_NOWAIT,
				 "dma-kmalloc-%d", size);

			BUG_ON(!n);
			kmalloc_dma_caches[i] = create_kmalloc_cache(n,
				size, SLAB_CACHE_DMA | flags);
		}
	}
#endif
}
#endif /* !CONFIG_SLOB */

#ifdef CONFIG_TRACING
void *kmalloc_order_trace(size_t size, gfp_t flags, unsigned int order)
{
	void *ret = kmalloc_order(size, flags, order);
	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << order, flags);
	return ret;
}
EXPORT_SYMBOL(kmalloc_order_trace);
#endif

#ifdef CONFIG_SLABINFO

#ifdef CONFIG_SLAB
#define SLABINFO_RIGHTS (S_IWUSR | S_IRUSR)
#else
#define SLABINFO_RIGHTS S_IRUSR
#endif

void print_slabinfo_header(struct seq_file *m)
{
	/*
	 * Output format version, so at least we can change it
	 * without _too_ many complaints.
	 */
#ifdef CONFIG_DEBUG_SLAB
	seq_puts(m, "slabinfo - version: 2.1 (statistics)\n");
#else
	seq_puts(m, "slabinfo - version: 2.1\n");
#endif
	seq_puts(m, "# name            <active_objs> <num_objs> <objsize> "
		 "<objperslab> <pagesperslab>");
	seq_puts(m, " : tunables <limit> <batchcount> <sharedfactor>");
	seq_puts(m, " : slabdata <active_slabs> <num_slabs> <sharedavail>");
#ifdef CONFIG_DEBUG_SLAB
	seq_puts(m, " : globalstat <listallocs> <maxobjs> <grown> <reaped> "
		 "<error> <maxfreeable> <nodeallocs> <remotefrees> <alienoverflow>");
	seq_puts(m, " : cpustat <allochit> <allocmiss> <freehit> <freemiss>");
#endif
	seq_putc(m, '\n');
}

static void *s_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	mutex_lock(&slab_mutex);
	if (!n)
		print_slabinfo_header(m);

	return seq_list_start(&slab_caches, *pos);
}

void *slab_next(struct seq_file *m, void *p, loff_t *pos)
{
	return seq_list_next(p, &slab_caches, pos);
}

void slab_stop(struct seq_file *m, void *p)
{
	mutex_unlock(&slab_mutex);
}

static void
memcg_accumulate_slabinfo(struct kmem_cache *s, struct slabinfo *info)
{
	struct kmem_cache *c;
	struct slabinfo sinfo;
	int i;

	if (!is_root_cache(s))
		return;

	for_each_memcg_cache_index(i) {
		c = cache_from_memcg_idx(s, i);
		if (!c)
			continue;

		memset(&sinfo, 0, sizeof(sinfo));
		get_slabinfo(c, &sinfo);

		info->active_slabs += sinfo.active_slabs;
		info->num_slabs += sinfo.num_slabs;
		info->shared_avail += sinfo.shared_avail;
		info->active_objs += sinfo.active_objs;
		info->num_objs += sinfo.num_objs;
	}
}

int cache_show(struct kmem_cache *s, struct seq_file *m)
{
	struct slabinfo sinfo;

	memset(&sinfo, 0, sizeof(sinfo));
	get_slabinfo(s, &sinfo);

	memcg_accumulate_slabinfo(s, &sinfo);

	seq_printf(m, "%-17s %6lu %6lu %6u %4u %4d",
		   cache_name(s), sinfo.active_objs, sinfo.num_objs, s->size,
		   sinfo.objects_per_slab, (1 << sinfo.cache_order));

	seq_printf(m, " : tunables %4u %4u %4u",
		   sinfo.limit, sinfo.batchcount, sinfo.shared);
	seq_printf(m, " : slabdata %6lu %6lu %6lu",
		   sinfo.active_slabs, sinfo.num_slabs, sinfo.shared_avail);
	slabinfo_show_stats(m, s);
	seq_putc(m, '\n');
	return 0;
}

static int s_show(struct seq_file *m, void *p)
{
	struct kmem_cache *s = list_entry(p, struct kmem_cache, list);

	if (!is_root_cache(s))
		return 0;
	return cache_show(s, m);
}

/*
 * slabinfo_op - iterator that generates /proc/slabinfo
 *
 * Output layout:
 * cache-name
 * num-active-objs
 * total-objs
 * object size
 * num-active-slabs
 * total-slabs
 * num-pages-per-slab
 * + further values on SMP and with statistics enabled
 */
static const struct seq_operations slabinfo_op = {
	.start = s_start,
	.next = slab_next,
	.stop = slab_stop,
	.show = s_show,
};

static int slabinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &slabinfo_op);
}

static const struct file_operations proc_slabinfo_operations = {
	.open		= slabinfo_open,
	.read		= seq_read,
	.write          = slabinfo_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init slab_proc_init(void)
{
	proc_create("slabinfo", SLABINFO_RIGHTS, NULL,
						&proc_slabinfo_operations);
	return 0;
}
module_init(slab_proc_init);
#endif /* CONFIG_SLABINFO */
