#ifndef _ASM_GENERIC_ERRNO_BASE_H
#define _ASM_GENERIC_ERRNO_BASE_H

// ARM10C 20131019
#define	EPERM		 1	/* Operation not permitted */
// ARM10C 20150321
// ARM10C 20150328
// ARM10C 20160702
// ENOENT: 2
#define	ENOENT		 2	/* No such file or directory */
#define	ESRCH		 3	/* No such process */
#define	EINTR		 4	/* Interrupted system call */
#define	EIO		 5	/* I/O error */
#define	ENXIO		 6	/* No such device or address */
#define	E2BIG		 7	/* Argument list too long */
#define	ENOEXEC		 8	/* Exec format error */
#define	EBADF		 9	/* Bad file number */
#define	ECHILD		10	/* No child processes */
// ARM10C 20151107
// ARM10C 20151114
// ARM10C 20160116
// ARM10C 20160213
// ARM10C 20160903
// ARM10C 20160910
// EAGAIN: 11
#define	EAGAIN		11	/* Try again */
// ARM10C 20151031
// ARM10C 20151114
// ARM10C 20160319
// ARM10C 20160625
// ARM10C 20160702
// ARM10C 20160903
// ENOMEM: 12
#define	ENOMEM		12	/* Out of memory */
#define	EACCES		13	/* Permission denied */
#define	EFAULT		14	/* Bad address */
#define	ENOTBLK		15	/* Block device required */
// ARM10C 20160409
// EBUSY: 16
#define	EBUSY		16	/* Device or resource busy */
// ARM10C 20141115
// ARM10C 20141122
// ARM10C 20160123
// EEXIST: 17
#define	EEXIST		17	/* File exists */
#define	EXDEV		18	/* Cross-device link */
// ARM10C 20150627
// ENODEV: 19
#define	ENODEV		19	/* No such device */
#define	ENOTDIR		20	/* Not a directory */
#define	EISDIR		21	/* Is a directory */
// ARM10C 20141213
// ARM10C 20150321
// ARM10C 20160109
// EINVAL: 22
#define	EINVAL		22	/* Invalid argument */
#define	ENFILE		23	/* File table overflow */
#define	EMFILE		24	/* Too many open files */
#define	ENOTTY		25	/* Not a typewriter */
#define	ETXTBSY		26	/* Text file busy */
#define	EFBIG		27	/* File too large */
// ARM10C 20160730
// ENOSPC: 28
#define	ENOSPC		28	/* No space left on device */
#define	ESPIPE		29	/* Illegal seek */
#define	EROFS		30	/* Read-only file system */
#define	EMLINK		31	/* Too many links */
#define	EPIPE		32	/* Broken pipe */
#define	EDOM		33	/* Math argument out of domain of func */
#define	ERANGE		34	/* Math result not representable */

#endif
