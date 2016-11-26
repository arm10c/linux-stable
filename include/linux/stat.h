#ifndef _LINUX_STAT_H
#define _LINUX_STAT_H


#include <asm/stat.h>
#include <uapi/linux/stat.h>

// ARM10C 20160319
// ARM10C 20160611
// ARM10C 20161126
// S_IRWXU: 00700
// S_IRWXG: 00070
// S_IRWXO: 00007
// S_IRWXUGO: 00777
#define S_IRWXUGO	(S_IRWXU|S_IRWXG|S_IRWXO)
// ARM10C 20160611
// S_ISUID: 0004000
// S_ISGID: 0002000
// S_ISVTX: 0001000
// S_IRWXUGO: 00777
// S_IALLUGO: 0007777
#define S_IALLUGO	(S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)
// ARM10C 20151205
// ARM10C 20160116
// ARM10C 20160604
// ARM10C 20160604
// ARM10C 20160611
// ARM10C 20160702
// ARM10C 20161112
// S_IRUSR: 00400
// S_IRGRP: 00040
// S_IROTH: 00004
// S_IRUGO: 00444
#define S_IRUGO		(S_IRUSR|S_IRGRP|S_IROTH)
// ARM10C 20160604
// ARM10C 20160702
// S_IWUSR: 00200
// S_IWGRP: 00020
// S_IWOTH: 00002
// S_IWUGO: 00222
#define S_IWUGO		(S_IWUSR|S_IWGRP|S_IWOTH)
// ARM10C 20151205
// ARM10C 20160116
// ARM10C 20160604
// ARM10C 20160611
// ARM10C 20160702
// ARM10C 20161112
// S_IXUSR: 00100
// S_IXGRP: 00010
// S_IXOTH: 00001
// S_IXUGO: 00111
#define S_IXUGO		(S_IXUSR|S_IXGRP|S_IXOTH)

#define UTIME_NOW	((1l << 30) - 1l)
#define UTIME_OMIT	((1l << 30) - 2l)

#include <linux/types.h>
#include <linux/time.h>
#include <linux/uidgid.h>

struct kstat {
	u64		ino;
	dev_t		dev;
	umode_t		mode;
	unsigned int	nlink;
	kuid_t		uid;
	kgid_t		gid;
	dev_t		rdev;
	loff_t		size;
	struct timespec  atime;
	struct timespec	mtime;
	struct timespec	ctime;
	unsigned long	blksize;
	unsigned long long	blocks;
};

#endif
