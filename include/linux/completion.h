#ifndef __LINUX_COMPLETION_H
#define __LINUX_COMPLETION_H

/*
 * (C) Copyright 2001 Linus Torvalds
 *
 * Atomic wait-for-completion handler data structures.
 * See kernel/sched/completion.c for details.
 */

#include <linux/wait.h>

/*
 * struct completion - structure used to maintain state for a "completion"
 *
 * This is the opaque structure used to maintain the state for a "completion".
 * Completions currently use a FIFO to queue threads that have to wait for
 * the "completion" event.
 *
 * See also:  complete(), wait_for_completion() (and friends _timeout,
 * _interruptible, _interruptible_timeout, and _killable), init_completion(),
 * reinit_completion(), and macros DECLARE_COMPLETION(),
 * DECLARE_COMPLETION_ONSTACK().
 */
// ARM10C 20150919
// ARM10C 20160409
// ARM10C 20160910
// ARM10C 20161217
// sizeof(struct completion): 28 bytes
struct completion {
	unsigned int done;
	wait_queue_head_t wait;
};

// ARM10C 20160409
// __WAIT_QUEUE_HEAD_INITIALIZER((done)
// {
//     .lock            = (spinlock_t )
//                        { { .rlock =
//                            {
//                              .raw_lock = { { 0 } },
//                              .magic = 0xdead4ead,
//                              .owner_cpu = -1,
//                              .owner = 0xffffffff,
//                            }
//                        } }
//     .task_list       = { &(done).task_list, &(done).task_list }
// }
//
// #define COMPLETION_INITIALIZER(done):
// { 0,
//   {
//     .lock            = (spinlock_t )
//                        { { .rlock =
//                            {
//                              .raw_lock = { { 0 } },
//                              .magic = 0xdead4ead,
//                              .owner_cpu = -1,
//                              .owner = 0xffffffff,
//                            }
//                        } }
//     .task_list       = { &(done).task_list, &(done).task_list }
//   }.wait
// }
#define COMPLETION_INITIALIZER(work) \
	{ 0, __WAIT_QUEUE_HEAD_INITIALIZER((work).wait) }

#define COMPLETION_INITIALIZER_ONSTACK(work) \
	({ init_completion(&work); work; })

/**
 * DECLARE_COMPLETION - declare and initialize a completion structure
 * @work:  identifier for the completion structure
 *
 * This macro declares and initializes a completion structure. Generally used
 * for static declarations. You should use the _ONSTACK variant for automatic
 * variables.
 */
// ARM10C 20160409
// COMPLETION_INITIALIZER(done):
// { 0,
//   {
//     .lock            = (spinlock_t )
//                        { { .rlock =
//                            {
//                              .raw_lock = { { 0 } },
//                              .magic = 0xdead4ead,
//                              .owner_cpu = -1,
//                              .owner = 0xffffffff,
//                            }
//                        } }
//     .task_list       = { &(done).task_list, &(done).task_list }
//   }.wait
// }
//
// #define DECLARE_COMPLETION(done):
// struct completion done =
// { 0,
//   {
//     .lock            = (spinlock_t )
//                        { { .rlock =
//                            {
//                              .raw_lock = { { 0 } },
//                              .magic = 0xdead4ead,
//                              .owner_cpu = -1,
//                              .owner = 0xffffffff,
//                            }
//                        } }
//     .task_list       = { &(done).task_list, &(done).task_list }
//   }.wait
// }
#define DECLARE_COMPLETION(work) \
	struct completion work = COMPLETION_INITIALIZER(work)

/*
 * Lockdep needs to run a non-constant initializer for on-stack
 * completions - so we use the _ONSTACK() variant for those that
 * are on the kernel stack:
 */
/**
 * DECLARE_COMPLETION_ONSTACK - declare and initialize a completion structure
 * @work:  identifier for the completion structure
 *
 * This macro declares and initializes a completion structure on the kernel
 * stack.
 */
#ifdef CONFIG_LOCKDEP // CONFIG_LOCKDEP=n
# define DECLARE_COMPLETION_ONSTACK(work) \
	struct completion work = COMPLETION_INITIALIZER_ONSTACK(work)
#else
// ARM10C 20160409
// DECLARE_COMPLETION(done)
// struct completion done =
// { 0,
//   {
//     .lock            = (spinlock_t )
//                        { { .rlock =
//                            {
//                              .raw_lock = { { 0 } },
//                              .magic = 0xdead4ead,
//                              .owner_cpu = -1,
//                              .owner = 0xffffffff,
//                            }
//                        } }
//     .task_list       = { &(done).task_list, &(done).task_list }
//   }.wait
// }
//
// #define DECLARE_COMPLETION_ONSTACK(done):
// struct completion done =
// { 0,
//   {
//     .lock            = (spinlock_t )
//                        { { .rlock =
//                            {
//                              .raw_lock = { { 0 } },
//                              .magic = 0xdead4ead,
//                              .owner_cpu = -1,
//                              .owner = 0xffffffff,
//                            }
//                        } }
//     .task_list       = { &(done).task_list, &(done).task_list }
//   }.wait
// }
# define DECLARE_COMPLETION_ONSTACK(work) DECLARE_COMPLETION(work)
#endif

/**
 * init_completion - Initialize a dynamically allocated completion
 * @x:  pointer to completion structure that is to be initialized
 *
 * This inline function will initialize a dynamically created completion
 * structure.
 */
static inline void init_completion(struct completion *x)
{
	x->done = 0;
	init_waitqueue_head(&x->wait);
}

/**
 * reinit_completion - reinitialize a completion structure
 * @x:  pointer to completion structure that is to be reinitialized
 *
 * This inline function should be used to reinitialize a completion structure so it can
 * be reused. This is especially important after complete_all() is used.
 */
static inline void reinit_completion(struct completion *x)
{
	x->done = 0;
}

extern void wait_for_completion(struct completion *);
extern void wait_for_completion_io(struct completion *);
extern int wait_for_completion_interruptible(struct completion *x);
extern int wait_for_completion_killable(struct completion *x);
extern unsigned long wait_for_completion_timeout(struct completion *x,
						   unsigned long timeout);
extern unsigned long wait_for_completion_io_timeout(struct completion *x,
						    unsigned long timeout);
extern long wait_for_completion_interruptible_timeout(
	struct completion *x, unsigned long timeout);
extern long wait_for_completion_killable_timeout(
	struct completion *x, unsigned long timeout);
extern bool try_wait_for_completion(struct completion *x);
extern bool completion_done(struct completion *x);

extern void complete(struct completion *);
extern void complete_all(struct completion *);

#endif
