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
char *kvasprintf(gfp_t gfp, const char *fmt, va_list ap)
{
	unsigned int len;
	char *p;
	va_list aq;

	va_copy(aq, ap);
	len = vsnprintf(NULL, 0, fmt, aq);
	// len: 11 "kmalloc-192"의 길이
	va_end(aq);

	// len: 11, gfp: GFP_NOWAIT: 0
	// kmalloc_track_caller(12, GFP_NOWAIT: 0): kmem_cache#30-o0
	p = kmalloc_track_caller(len+1, gfp);
	// p: kmem_cache#30-o0

	if (!p)
		return NULL;

	vsnprintf(p, len+1, fmt, ap);

	// p: kmem_cache#30-o0
	return p;
	// return kmem_cache#30-o0
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
