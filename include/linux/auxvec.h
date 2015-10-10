#ifndef _LINUX_AUXVEC_H
#define _LINUX_AUXVEC_H

#include <uapi/linux/auxvec.h>

// ARM10C 20150919
// AT_VECTOR_SIZE_BASE: 20
#define AT_VECTOR_SIZE_BASE 20 /* NEW_AUX_ENT entries in auxiliary table */
  /* number of "#define AT_.*" above, minus {AT_NULL, AT_IGNORE, AT_NOTELF} */
#endif /* _LINUX_AUXVEC_H */
