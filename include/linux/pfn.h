#ifndef _LINUX_PFN_H_
#define _LINUX_PFN_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>
#endif

#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
// ARM10C 20131207
// PAGE_SIZE: 0x1000
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
// ARM10C 20131207
// PAGE_SHIFT: 12
#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)

#endif
