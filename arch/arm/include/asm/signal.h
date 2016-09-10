#ifndef _ASMARM_SIGNAL_H
#define _ASMARM_SIGNAL_H

#include <uapi/asm/signal.h>

/* Most things should be clean enough to redefine this at will, if care
   is taken to make libc match.  */

// ARM10C 20150919
// _NSIG: 64
#define _NSIG		64
// ARM10C 20150919
// _NSIG_BPW: 32
#define _NSIG_BPW	32
// ARM10C 20150919
// ARM10C 20160910
// _NSIG: 64
// _NSIG_BPW: 32
// _NSIG_WORDS: 2
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

typedef unsigned long old_sigset_t;		/* at least 32 bits */

// ARM10C 20150919
// ARM10C 20160910
// _NSIG_WORDS: 2
// sizeof(struct sigset_t): 8 bytes
typedef struct {
	unsigned long sig[_NSIG_WORDS];
} sigset_t;

#define __ARCH_HAS_SA_RESTORER

#include <asm/sigcontext.h>
#endif
