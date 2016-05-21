/*
 *  linux/drivers/base/map.c
 *
 * (C) Copyright Al Viro 2002,2003
 *	Released under GPL v2.
 *
 * NOTE: data structure needs to be changed.  It works, but for large dev_t
 * it will be too slow.  It is isolated, though, so these changes will be
 * local to that file.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/kdev_t.h>
#include <linux/kobject.h>
#include <linux/kobj_map.h>

// ARM10C 20160521
// sizeof(struct probe): 28 bytes
// sizeof(struct kobj_map): 1024 bytes
struct kobj_map {
	struct probe {
		struct probe *next;
		dev_t dev;
		unsigned long range;
		struct module *owner;
		kobj_probe_t *get;
		int (*lock)(dev_t, void *);
		void *data;
	} *probes[255];
	struct mutex *lock;
};

int kobj_map(struct kobj_map *domain, dev_t dev, unsigned long range,
	     struct module *module, kobj_probe_t *probe,
	     int (*lock)(dev_t, void *), void *data)
{
	unsigned n = MAJOR(dev + range - 1) - MAJOR(dev) + 1;
	unsigned index = MAJOR(dev);
	unsigned i;
	struct probe *p;

	if (n > 255)
		n = 255;

	p = kmalloc(sizeof(struct probe) * n, GFP_KERNEL);

	if (p == NULL)
		return -ENOMEM;

	for (i = 0; i < n; i++, p++) {
		p->owner = module;
		p->get = probe;
		p->lock = lock;
		p->dev = dev;
		p->range = range;
		p->data = data;
	}
	mutex_lock(domain->lock);
	for (i = 0, p -= n; i < n; i++, p++, index++) {
		struct probe **s = &domain->probes[index % 255];
		while (*s && (*s)->range < range)
			s = &(*s)->next;
		p->next = *s;
		*s = p;
	}
	mutex_unlock(domain->lock);
	return 0;
}

void kobj_unmap(struct kobj_map *domain, dev_t dev, unsigned long range)
{
	unsigned n = MAJOR(dev + range - 1) - MAJOR(dev) + 1;
	unsigned index = MAJOR(dev);
	unsigned i;
	struct probe *found = NULL;

	if (n > 255)
		n = 255;

	mutex_lock(domain->lock);
	for (i = 0; i < n; i++, index++) {
		struct probe **s;
		for (s = &domain->probes[index % 255]; *s; s = &(*s)->next) {
			struct probe *p = *s;
			if (p->dev == dev && p->range == range) {
				*s = p->next;
				if (!found)
					found = p;
				break;
			}
		}
	}
	mutex_unlock(domain->lock);
	kfree(found);
}

struct kobject *kobj_lookup(struct kobj_map *domain, dev_t dev, int *index)
{
	struct kobject *kobj;
	struct probe *p;
	unsigned long best = ~0UL;

retry:
	mutex_lock(domain->lock);
	for (p = domain->probes[MAJOR(dev) % 255]; p; p = p->next) {
		struct kobject *(*probe)(dev_t, int *, void *);
		struct module *owner;
		void *data;

		if (p->dev > dev || p->dev + p->range - 1 < dev)
			continue;
		if (p->range - 1 >= best)
			break;
		if (!try_module_get(p->owner))
			continue;
		owner = p->owner;
		data = p->data;
		probe = p->get;
		best = p->range - 1;
		*index = dev - p->dev;
		if (p->lock && p->lock(dev, data) < 0) {
			module_put(owner);
			continue;
		}
		mutex_unlock(domain->lock);
		kobj = probe(dev, index, data);
		/* Currently ->owner protects _only_ ->probe() itself. */
		module_put(owner);
		if (kobj)
			return kobj;
		goto retry;
	}
	mutex_unlock(domain->lock);
	return NULL;
}

// ARM10C 20160521
// base_probe, &chrdevs_lock
struct kobj_map *kobj_map_init(kobj_probe_t *base_probe, struct mutex *lock)
{
	// sizeof(struct kobj_map): 1024 bytes, GFP_KERNEL: 0xD0
	// kmalloc(1024, GFP_KERNEL: 0xD0): kmem_cache#26-oX (struct kobj_map)
	struct kobj_map *p = kmalloc(sizeof(struct kobj_map), GFP_KERNEL);
	// p: kmem_cache#26-oX (struct kobj_map)

	// sizeof(struct probe): 28 bytes, GFP_KERNEL: 0xD0
	// kzalloc(28, GFP_KERNEL: 0xD0): kmem_cache#30-oX (struct probe)
	struct probe *base = kzalloc(sizeof(*base), GFP_KERNEL);
	// base: kmem_cache#30-oX (struct probe)

	int i;

	// p: kmem_cache#26-oX (struct kobj_map), base: kmem_cache#30-oX (struct probe)
	if ((p == NULL) || (base == NULL)) {
		kfree(p);
		kfree(base);
		return NULL;
	}

	// base->dev: (kmem_cache#30-oX (struct probe))->dev
	base->dev = 1;
	// base->dev: (kmem_cache#30-oX (struct probe))->dev: 1

	// base->range: (kmem_cache#30-oX (struct probe))->range
	base->range = ~0;
	// base->range: (kmem_cache#30-oX (struct probe))->range: 0xFFFFFFFF

	// base->get: (kmem_cache#30-oX (struct probe))->get
	base->get = base_probe;
	// base->get: (kmem_cache#30-oX (struct probe))->get: base_probe

	for (i = 0; i < 255; i++)
		// i: 0, p->probes[0]: (kmem_cache#26-oX (struct kobj_map))->probes[0], base: kmem_cache#30-oX (struct probe)
		p->probes[i] = base;
		// i: 0, p->probes[0]: (kmem_cache#26-oX (struct kobj_map))->probes[0]: kmem_cache#30-oX (struct probe)
		
		// i: 1...255 loop 수행

	// p->lock: (kmem_cache#26-oX (struct kobj_map))->lock, lock: &chrdevs_lock
	p->lock = lock;
	// p->lock: (kmem_cache#26-oX (struct kobj_map))->lock: &chrdevs_lock

	// p: kmem_cache#26-oX (struct kobj_map)
	return p;
	// return kmem_cache#26-oX (struct kobj_map)
}
