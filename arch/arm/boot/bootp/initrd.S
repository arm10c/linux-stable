	.type	initrd_start,#object
	.globl	initrd_start
// ARM10C 20150801
initrd_start:
	.incbin	INITRD
	.globl	initrd_end
initrd_end:
