/*
 *  linux/lib/kasprintf.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <stdarg.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* Simplified asprintf. */
// ARM10C 20140726
// gfp: GFP_NOWAIT: 0, fmt: "kmalloc-%d", ap: 192
// ARM10C 20160109
// GFP_KERNEL: 0xD0, fmt: "%s", vargs: "fs"
char *kvasprintf(gfp_t gfp, const char *fmt, va_list ap)
{
	unsigned int len;
	char *p;
	va_list aq;

	// ap: "fs"
	va_copy(aq, ap);

	// va_copy에서 한일:
	// aq: "fs"

	// fmt: "%s", aq: "fs"
	// vsnprintf(NULL, 0, "%s", "fs"): 2
	len = vsnprintf(NULL, 0, fmt, aq);
	// len: 11 "kmalloc-192"의 길이
	// len: 2

	// aq: "fs"
	va_end(aq);

	// va_end에서 한일:
	// aq: NULL

	// len: 11, gfp: GFP_NOWAIT: 0
	// kmalloc_track_caller(12, GFP_NOWAIT: 0): kmem_cache#30-o0
	// len: 2, GFP_KERNEL: 0xD0
	p = kmalloc_track_caller(len+1, gfp);
	// p: kmem_cache#30-o0
	// p: kmem_cache#30-oX

	// p: kmem_cache#30-o0
	// p: kmem_cache#30-oX
	if (!p)
		return NULL;

	// p: kmem_cache#30-oX, len: 2, fmt: "%s", ap: "fs"
	vsnprintf(p, len+1, fmt, ap);

	// vsnprintf에서 한일:
	// p: kmem_cache#30-oX: "fs"

	// p: kmem_cache#30-o0
	// p: kmem_cache#30-oX: "fs"
	return p;
	// return kmem_cache#30-o0
	// return kmem_cache#30-oX: "fs"
}
EXPORT_SYMBOL(kvasprintf);

// ARM10C 20140726
// GFP_NOWAIT: 0, "kmalloc-%d", 192
char *kasprintf(gfp_t gfp, const char *fmt, ...)
{
	va_list ap;
	char *p;

	va_start(ap, fmt);

	// gfp: GFP_NOWAIT: 0, fmt: "kmalloc-%d", ap: 192
	// kvasprintf(GFP_NOWAIT: 0, "kmalloc-%d", 192): kmem_cache#30-o0
	p = kvasprintf(gfp, fmt, ap);
	// p: kmem_cache#30-o0

	va_end(ap);

	// p: kmem_cache#30-o0
	return p;
	// return kmem_cache#30-o0
}
EXPORT_SYMBOL(kasprintf);
