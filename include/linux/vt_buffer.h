/*
 *	include/linux/vt_buffer.h -- Access to VT screen buffer
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 *
 *	This is a set of macros and functions which are used in the
 *	console driver and related code to access the screen buffer.
 *	In most cases the console works with simple in-memory buffer,
 *	but when handling hardware text mode consoles, we store
 *	the foreground console directly in video memory.
 */

#ifndef _LINUX_VT_BUFFER_H_
#define _LINUX_VT_BUFFER_H_


#if defined(CONFIG_VGA_CONSOLE) || defined(CONFIG_MDA_CONSOLE)
#include <asm/vga.h>
#endif

#ifndef VT_BUF_HAVE_RW
// ARM10C 20150718
// c: 0x120, s: kmem_cache#22-oX
// ARM10C 20150725
// softcursor_original: 0, vc->vc_pos: (kmem_cache#25-oX)->vc_pos: kmem_cache#22-oX
#define scr_writew(val, addr) (*(addr) = (val))
// ARM10C 20150725
// vc->vc_pos: (kmem_cache#25-oX)->vc_pos: kmem_cache#22-oX
#define scr_readw(addr) (*(addr))
#define scr_memcpyw(d, s, c) memcpy(d, s, c)
#define scr_memmovew(d, s, c) memmove(d, s, c)
#define VT_BUF_HAVE_MEMCPYW
#define VT_BUF_HAVE_MEMMOVEW
#endif

#ifndef VT_BUF_HAVE_MEMSETW
// ARM10C 20150718
// start: kmem_cache#22-oX,
// vc->vc_video_erase_char: (kmem_cache#25-oX)->vc_video_erase_char: 0x120, 4800
// ARM10C 20150725
// vc->vc_video_erase_char: (kmem_cache#25-oX)->vc_video_erase_char: 0x120, count: 2400
static inline void scr_memsetw(u16 *s, u16 c, unsigned int count)
{
	// count: 4800
	count /= 2;
	// count: 2400

	// count: 2400
	while (count--)
		// c: 0x120, s: kmem_cache#22-oX
		scr_writew(c, s++);

		// scr_writew에서 한일:
		// *(kmem_cache#22-oX): 0x120
		
		// count: 2399...1 까지 루프 수행
	
	// 위 loop에서 한일:
	// *(kmem_cache#22-oX + 0): 0x120
	// *(kmem_cache#22-oX + 1): 0x120
	// *(kmem_cache#22-oX + 2): 0x120
	// *(kmem_cache#22-oX + 3): 0x120
	// ...
	// *(kmem_cache#22-oX + 2399): 0x120
}
#endif

#ifndef VT_BUF_HAVE_MEMCPYW
static inline void scr_memcpyw(u16 *d, const u16 *s, unsigned int count)
{
	count /= 2;
	while (count--)
		scr_writew(scr_readw(s++), d++);
}
#endif

#ifndef VT_BUF_HAVE_MEMMOVEW
static inline void scr_memmovew(u16 *d, const u16 *s, unsigned int count)
{
	if (d < s)
		scr_memcpyw(d, s, count);
	else {
		count /= 2;
		d += count;
		s += count;
		while (count--)
			scr_writew(scr_readw(--s), --d);
	}
}
#endif

#endif
