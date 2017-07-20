#ifndef __ASM_GENERIC_PARAM_H
#define __ASM_GENERIC_PARAM_H

#include <uapi/asm-generic/param.h>

# undef HZ
// ARM10C 20140830
// ARM10C 20140913
// ARM10C 20140920
// ARM10C 20150103
// ARM10C 20150418
// ARM10C 20150509
// ARM10C 20150516
// ARM10C 20150530
// ARM10C 20150704
// ARM10C 20150718
// ARM10C 20150808
// ARM10C 20170720
// CONFIG_HZ: 100
// HZ: 100
# define HZ		CONFIG_HZ	/* Internal kernel timer frequency */
// ARM10C 20150103
// USER_HZ: 100
# define USER_HZ	100		/* some user interfaces are */
# define CLOCKS_PER_SEC	(USER_HZ)       /* in "ticks" like times() */
#endif /* __ASM_GENERIC_PARAM_H */
