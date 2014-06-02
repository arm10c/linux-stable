#ifndef _LINUX_PFN_H_
#define _LINUX_PFN_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>
#endif

// ARM10C 20140222
// PAGE_SIZE: 0x1000
// PAGE_MASK: 0xFFFFF000
// PFN_ALIGN(60): 0x1000 (0x3C+0xFFF : 0x103B & FFFFF000)
#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
// ARM10C 20131207
// ARM10C 20140419
// PAGE_SIZE: 0x1000
// PAGE_SHIFT: 12
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
// ARM10C 20131214
// ARM10C 20140419
// PAGE_SHIFT: 12
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
// ARM10C 20131207
// ARM10C 20140531
// PAGE_SHIFT: 12
#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)

#endif
