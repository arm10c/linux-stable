#ifndef _ASM_GENERIC_RESOURCE_H
#define _ASM_GENERIC_RESOURCE_H

#include <uapi/asm-generic/resource.h>


/*
 * boot-time rlimit defaults for the init task:
 */
// ARM10C 20160903
// RLIM_INFINITY: 0xFFFFFFFF
// _STK_LIM: 0x800000
// _STK_LIM_MAX: 0xFFFFFFFF
// INR_OPEN_CUR: 0x400
// INR_OPEN_MAX: 0x1000
// MLOCK_LIMIT: 0x10000
// MQ_BYTES_MAX: 0xC8000
// RLIMIT_CPU: 0
// RLIMIT_FSIZE: 1
// RLIMIT_DATA: 2
// RLIMIT_STACK: 3
// RLIMIT_CORE: 4
// RLIMIT_RSS: 5
// RLIMIT_NPROC: 6
// RLIMIT_NOFILE: 7
// RLIMIT_MEMLOCK: 8
// RLIMIT_AS: 9
// RLIMIT_LOCKS: 10
// RLIMIT_SIGPENDING: 11
// RLIMIT_MSGQUEUE: 12
// RLIMIT_NICE: 13
// RLIMIT_RTPRIO: 14
// RLIMIT_RTTIME: 15
//
// #define INIT_RLIMITS:
// {
//     [0]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//     [1]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//     [2]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//     [3]    = {    0x800000,  0xFFFFFFFF },
//     [4]    = {           0,  0xFFFFFFFF },
//     [5]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//     [6]    = {           0,           0 },
//     [7]    = {       0x400,      0x1000 },
//     [8]    = {     0x10000,     0x10000 },
//     [9]    = {  0xFFFFFFFF,  0xFFFFFFFF },
//     [10]   = {  0xFFFFFFFF,  0xFFFFFFFF },
//     [11]   = {           0,           0 },
//     [12]   = {     0xC8000,     0xC8000 },
//     [13]   = {           0,           0 },
//     [14]   = {           0,           0 },
//     [15]   = {  0xFFFFFFFF,  0xFFFFFFFF },
// }
#define INIT_RLIMITS							\
{									\
	[RLIMIT_CPU]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_FSIZE]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_DATA]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_STACK]		= {       _STK_LIM,   _STK_LIM_MAX },	\
	[RLIMIT_CORE]		= {              0,  RLIM_INFINITY },	\
	[RLIMIT_RSS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_NPROC]		= {              0,              0 },	\
	[RLIMIT_NOFILE]		= {   INR_OPEN_CUR,   INR_OPEN_MAX },	\
	[RLIMIT_MEMLOCK]	= {    MLOCK_LIMIT,    MLOCK_LIMIT },	\
	[RLIMIT_AS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_LOCKS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_SIGPENDING]	= { 		0,	       0 },	\
	[RLIMIT_MSGQUEUE]	= {   MQ_BYTES_MAX,   MQ_BYTES_MAX },	\
	[RLIMIT_NICE]		= { 0, 0 },				\
	[RLIMIT_RTPRIO]		= { 0, 0 },				\
	[RLIMIT_RTTIME]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
}

#endif
