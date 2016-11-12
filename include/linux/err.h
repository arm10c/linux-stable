#ifndef _LINUX_ERR_H
#define _LINUX_ERR_H

#include <linux/compiler.h>

#include <asm/errno.h>

/*
 * Kernel pointers have redundant information, so we can use a
 * scheme where we can return either an error code or a dentry
 * pointer with the same return value.
 *
 * This should be a per-architecture thing, to allow different
 * error and pointer decisions.
 */
#define MAX_ERRNO	4095

#ifndef __ASSEMBLY__

// ARM10C 20140222
// ARM10C 20141025
// ARM10C 20141122
// ARM10C 20150620
// ARM10C 20150822
// ARM10C 20151219
// ARM10C 20160109
// ARM10C 20160319
// ARM10C 20160326
// ARM10C 20160514
// -MAX_ERRNO: 0xFFFFF001
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

// ARM10C 20150321
// ARM10C 20150328
// -ENOENT: -2
// ARM10C 20160109
// -EINVAL: -22
// ARM10C 20160702
// -ENOENT: -2
// ARM10C 20160702
// -ENOMEM: -12
// ARM10C 20160702
// err: 0
static inline void * __must_check ERR_PTR(long error)
{
	// -ENOENT: -2
	// -EINVAL: -22
	return (void *) error;
	// 0xfffffffe
	// 0xffffffea
}

// ARM10C 20160702
// 0xfffffffe
static inline long __must_check PTR_ERR(__force const void *ptr)
{
	// ptr: 0xfffffffe
	return (long) ptr;
	// return -2
}

// ARM10C 20140222
// ARM10C 20141025
// ARM10C 20150117
// clk: kmem_cache#29-oX
// ARM10C 20150124
// clk: kmem_cache#29-oX (apll)
// ARM10C 20150328
// clk: kmem_cache#29-oX (fin_pll)
// ARM10C 20150822
// css: &root_task_group.css
// ARM10C 20150822
// css: &root_cpuacct.css
// ARM10C 20151121
// sb: kmem_cache#25-oX (struct super_block)
// ARM10C 20151219
// root: kmem_cache#5-oX (struct dentry)
// ARM10C 20160109
// &(kmem_cache#2-oX (struct mount))->mnt
// ARM10C 20160109
// sysfs_mnt: &(kmem_cache#2-oX (struct mount))->mnt
// ARM10C 20160319
// s: kmem_cache#25-oX (struct super_block)
// ARM10C 20160326
// shm_mnt: &(kmem_cache#2-oX (struct mount))->mnt
// ARM10C 20160514
// new_ns: kmem_cache#30-oX (struct mnt_namespace)
// ARM10C 20160521
// ns: kmem_cache#30-oX (struct mnt_namespace)
// ARM10C 20160702
// subdir: 0xfffffffe
// ARM10C 20160702
// subdir: kmem_cache#29-oX
// ARM10C 20161112
// sb: kmem_cache#25-oX (struct super_block),
static inline long __must_check IS_ERR(__force const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

// ARM10C 20150117
// clk->parent: (kmem_cache#29-oX (apll))->parent: NULL
static inline long __must_check IS_ERR_OR_NULL(__force const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

/**
 * ERR_CAST - Explicitly cast an error-valued pointer to another pointer type
 * @ptr: The pointer to cast.
 *
 * Explicitly cast an error-valued pointer to another pointer type in such a
 * way as to make it clear that's what's going on.
 */
static inline void * __must_check ERR_CAST(__force const void *ptr)
{
	/* cast away the const */
	return (void *) ptr;
}

static inline int __must_check PTR_ERR_OR_ZERO(__force const void *ptr)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	else
		return 0;
}

/* Deprecated */
#define PTR_RET(p) PTR_ERR_OR_ZERO(p)

#endif

#endif /* _LINUX_ERR_H */
