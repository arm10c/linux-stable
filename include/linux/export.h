#ifndef _LINUX_EXPORT_H
#define _LINUX_EXPORT_H
/*
 * Export symbols from the kernel to modules.  Forked from module.h
 * to reduce the amount of pointless cruft we feed to gcc when only
 * exporting a simple symbol or two.
 *
 * Try not to add #includes here.  It slows compilation and makes kernel
 * hackers place grumpy comments in header files.
 */

/* Some toolchains use a `_' prefix for all user symbols. */
#ifdef CONFIG_HAVE_UNDERSCORE_SYMBOL_PREFIX // CONFIG_HAVE_UNDERSCORE_SYMBOL_PREFIX=n
#define __VMLINUX_SYMBOL(x) _##x
#define __VMLINUX_SYMBOL_STR(x) "_" #x
#else
#define __VMLINUX_SYMBOL(x) x
/*
// ARM10C 20140405
*/
#define __VMLINUX_SYMBOL_STR(x) #x
#endif

/* Indirect, so macros are expanded before pasting. */
#define VMLINUX_SYMBOL(x) __VMLINUX_SYMBOL(x)
/*
// ARM10C 20140405
*/
#define VMLINUX_SYMBOL_STR(x) __VMLINUX_SYMBOL_STR(x)

#ifndef __ASSEMBLY__
struct kernel_symbol
{
	unsigned long value;
	const char *name;
};

#ifdef MODULE
extern struct module __this_module;
#define THIS_MODULE (&__this_module)
#else
#define THIS_MODULE ((struct module *)0)
#endif

#ifdef CONFIG_MODULES // CONFIG_MODULES=y

#ifndef __GENKSYMS__
#ifdef CONFIG_MODVERSIONS // CONFIG_MODVERSIONS=n
/* Mark the CRC weak since genksyms apparently decides not to
 * generate a checksums for some symbols */
#define __CRC_SYMBOL(sym, sec)					\
	extern void *__crc_##sym __attribute__((weak));		\
	static const unsigned long __kcrctab_##sym		\
	__used							\
	__attribute__((section("___kcrctab" sec "+" #sym), unused))	\
	= (unsigned long) &__crc_##sym;
#else
// ARM10C 20140405
#define __CRC_SYMBOL(sym, sec)
#endif

/* For every exported symbol, place a struct in the __ksymtab section */
// ARM10C 20140405
// __CRC_SYMBOL(vm_event_states, ""):
// VMLINUX_SYMBOL_STR(vm_event_states): "vm_event_states"
// __used: __attribute__((__used__))
//
// __EXPORT_SYMBOL(vm_event_states, ""):
// extern typeof(vm_event_states) vm_event_states;
// static const char __kstrtab_vm_event_states[]
// __attribute__((section("__ksymtab_strings"), aligned(1)))
// = "vm_event_states";
// static const struct kernel_symbol __ksymtab_vm_event_states
// __attribute__((__used__))
// __attribute__((section("___ksymtab" "" "+" "vm_event_states"), unused))
// = { (unsigned long)&vm_event_states, __kstrtab_vm_event_states }
//
// ARM10C 20140412
// __CRC_SYMBOL(vm_stat, ""):
// VMLINUX_SYMBOL_STR(vm_stat): "vm_stat"
// __used: __attribute__((__used__))
//
// __EXPORT_SYMBOL(vm_stat, ""):
// extern typeof(vm_stat) vm_stat;
// static const char __kstrtab_vm_stat[]
// __attribute__((section("__ksymtab_strings"), aligned(1)))
// = "vm_stat";
// static const struct kernel_symbol __ksymtab_vm_stat
// __attribute__((__used__))
// __attribute__((section("___ksymtab" "" "+" "vm_stat"), unused))
// = { (unsigned long)&vm_stat, __kstrtab_vm_stat }
#define __EXPORT_SYMBOL(sym, sec)				\
	extern typeof(sym) sym;					\
	__CRC_SYMBOL(sym, sec)					\
	static const char __kstrtab_##sym[]			\
	__attribute__((section("__ksymtab_strings"), aligned(1))) \
	= VMLINUX_SYMBOL_STR(sym);				\
	static const struct kernel_symbol __ksymtab_##sym	\
	__used							\
	__attribute__((section("___ksymtab" sec "+" #sym), unused))	\
	= { (unsigned long)&sym, __kstrtab_##sym }

// ARM10C 20140405
// __EXPORT_SYMBOL(vm_event_states, ""):
// extern typeof(vm_event_states) vm_event_states;
// static const char __kstrtab_vm_event_states[]
// __attribute__((section("__ksymtab_strings"), aligned(1)))
// = "vm_event_states";
// static const struct kernel_symbol __ksymtab_vm_event_states
// __attribute__((__used__))
// __attribute__((section("___ksymtab" "" "+" "vm_event_states"), unused))
// = { (unsigned long)&vm_event_states, __kstrtab_vm_event_states }
//
// EXPORT_SYMBOL(vm_event_states):
// extern typeof(vm_event_states) vm_event_states;
// static const char __kstrtab_vm_event_states[]
// __attribute__((section("__ksymtab_strings"), aligned(1)))
// = "vm_event_states";
// static const struct kernel_symbol __ksymtab_vm_event_states
// __attribute__((__used__))
// __attribute__((section("___ksymtab" "" "+" "vm_event_states"), unused))
// = { (unsigned long)&vm_event_states, __kstrtab_vm_event_states }
//
// ARM10C 20140412
// EXPORT_SYMBOL(vm_stat):
// extern typeof(vm_stat) vm_stat;
// static const char __kstrtab_vm_stat[]
// __attribute__((section("__ksymtab_strings"), aligned(1)))
// = "vm_stat";
// static const struct kernel_symbol __ksymtab_vm_stat
// __attribute__((__used__))
// __attribute__((section("___ksymtab" "" "+" "vm_stat"), unused))
// = { (unsigned long)&vm_stat, __kstrtab_vm_stat }
#define EXPORT_SYMBOL(sym)					\
	__EXPORT_SYMBOL(sym, "")

#define EXPORT_SYMBOL_GPL(sym)					\
	__EXPORT_SYMBOL(sym, "_gpl")

#define EXPORT_SYMBOL_GPL_FUTURE(sym)				\
	__EXPORT_SYMBOL(sym, "_gpl_future")

#ifdef CONFIG_UNUSED_SYMBOLS
#define EXPORT_UNUSED_SYMBOL(sym) __EXPORT_SYMBOL(sym, "_unused")
#define EXPORT_UNUSED_SYMBOL_GPL(sym) __EXPORT_SYMBOL(sym, "_unused_gpl")
#else
#define EXPORT_UNUSED_SYMBOL(sym)
#define EXPORT_UNUSED_SYMBOL_GPL(sym)
#endif

#endif	/* __GENKSYMS__ */

#else /* !CONFIG_MODULES... */

#define EXPORT_SYMBOL(sym)
#define EXPORT_SYMBOL_GPL(sym)
#define EXPORT_SYMBOL_GPL_FUTURE(sym)
#define EXPORT_UNUSED_SYMBOL(sym)
#define EXPORT_UNUSED_SYMBOL_GPL(sym)

#endif /* CONFIG_MODULES */
#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_EXPORT_H */
