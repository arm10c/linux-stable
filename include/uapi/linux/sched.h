#ifndef _UAPI_LINUX_SCHED_H
#define _UAPI_LINUX_SCHED_H

/*
 * cloning flags:
 */
// ARM10C 20161203
// CSIGNAL: 0x000000ff
#define CSIGNAL		0x000000ff	/* signal mask to be sent at exit */
// ARM10C 20160827
// ARM10C 20161203
// CLONE_VM: 0x00000100
#define CLONE_VM	0x00000100	/* set if VM shared between processes */
// ARM10C 20160827
// ARM10C 20161105
// ARM10C 20170524
// CLONE_FS: 0x00000200
#define CLONE_FS	0x00000200	/* set if fs info shared between processes */
// ARM10C 20161029
// ARM10C 20170524
// CLONE_FILES: 0x00000400
#define CLONE_FILES	0x00000400	/* set if open files shared between processes */
// ARM10C 20160827
// ARM10C 20160903
// ARM10C 20161105
// CLONE_SIGHAND: 0x00000800
#define CLONE_SIGHAND	0x00000800	/* set if signal handlers and blocked signals shared */
// ARM10C 20161203
// CLONE_PTRACE: 0x00002000
#define CLONE_PTRACE	0x00002000	/* set if we want to let tracing continue on the child too */
// ARM10C 20161203
// ARM10C 20161217
// ARM10C 20170524
// CLONE_VFORK: 0x00004000
#define CLONE_VFORK	0x00004000	/* set if the parent wants the child to wake it up on mm_release */
// ARM10C 20160827
// ARM10C 20161203
// CLONE_PARENT: 0x00008000
#define CLONE_PARENT	0x00008000	/* set if we want to have the same parent as the cloner */
// ARM10C 20160827
// ARM10C 20160910
// ARM10C 20161008
// ARM10C 20161105
// ARM10C 20161203
// ARM10C 20161217
// CLONE_THREAD: 0x00010000
#define CLONE_THREAD	0x00010000	/* Same thread group? */
// ARM10C 20160827
// ARM10C 20161105
// CLONE_NEWNS: 0x00020000
#define CLONE_NEWNS	0x00020000	/* New namespace group? */
// ARM10C 20161029
// CLONE_SYSVSEM: 0x00040000
#define CLONE_SYSVSEM	0x00040000	/* share system V SEM_UNDO semantics */
// ARM10C 20161105
// CLONE_SETTLS: 0x00080000
#define CLONE_SETTLS	0x00080000	/* create a new TLS for the child */
// ARM10C 20161217
// CLONE_PARENT_SETTID: 0x00100000
#define CLONE_PARENT_SETTID	0x00100000	/* set the TID in the parent */
// ARM10C 20161203
// CLONE_CHILD_CLEARTID: 0x00200000
#define CLONE_CHILD_CLEARTID	0x00200000	/* clear the TID in the child */
#define CLONE_DETACHED		0x00400000	/* Unused, ignored */
// ARM10C 20160827
// CLONE_UNTRACED: 0x00800000
#define CLONE_UNTRACED		0x00800000	/* set if the tracing process can't force CLONE_PTRACE on this clone */
// ARM10C 20161203
// CLONE_CHILD_SETTID: 0x01000000
#define CLONE_CHILD_SETTID	0x01000000	/* set the TID in the child */
/* 0x02000000 was previously the unused CLONE_STOPPED (Start in stopped state)
   and is now available for re-use. */
// ARM10C 20161105
// CLONE_NEWUTS: 0x04000000
#define CLONE_NEWUTS		0x04000000	/* New utsname group? */
// ARM10C 20161105
// CLONE_NEWIPC: 0x08000000
#define CLONE_NEWIPC		0x08000000	/* New ipcs */
// ARM10C 20160827
// ARM10C 20160903
// ARM10C 20160910
// CLONE_NEWUSER: 0x10000000
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
// ARM10C 20160903
// ARM10C 20161105
// CLONE_NEWPID: 0x20000000
#define CLONE_NEWPID		0x20000000	/* New pid namespace */
// ARM10C 20161105
// CLONE_NEWNET: 0x40000000
#define CLONE_NEWNET		0x40000000	/* New network namespace */
#define CLONE_IO		0x80000000	/* Clone io context */

/*
 * Scheduling policies
 */
// ARM10C 20140913
// ARM10C 20150808
// ARM10C 20170520
// SCHED_NORMAL: 0
#define SCHED_NORMAL		0
#define SCHED_FIFO		1
#define SCHED_RR		2
#define SCHED_BATCH		3
/* SCHED_ISO: reserved but not implemented yet */
// ARM10C 20140913
// ARM10C 20170520
// SCHED_IDLE: 5
#define SCHED_IDLE		5
/* Can be ORed in to make sure the process is reverted back to SCHED_NORMAL on fork */
#define SCHED_RESET_ON_FORK     0x40000000


#endif /* _UAPI_LINUX_SCHED_H */
