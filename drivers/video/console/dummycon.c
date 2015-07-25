/*
 *  linux/drivers/video/dummycon.c -- A dummy console driver
 *
 *  To be used if there's no other console driver (e.g. for plain VGA text)
 *  available, usually until fbcon takes console over.
 */

#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/console.h>
#include <linux/vt_kern.h>
#include <linux/screen_info.h>
#include <linux/init.h>
#include <linux/module.h>

/*
 *  Dummy console driver
 */

#if defined(__arm__)
// ARM10C 20150718
// screen_info.orig_video_cols: 80
// DUMMY_COLUMNS: 80
#define DUMMY_COLUMNS	screen_info.orig_video_cols
// ARM10C 20150718
// screen_info.orig_video_lines: 30
// DUMMY_ROWS: 30
#define DUMMY_ROWS	screen_info.orig_video_lines
#elif defined(__hppa__)
/* set by Kconfig. Use 80x25 for 640x480 and 160x64 for 1280x1024 */
#define DUMMY_COLUMNS	CONFIG_DUMMY_CONSOLE_COLUMNS
#define DUMMY_ROWS	CONFIG_DUMMY_CONSOLE_ROWS
#else
#define DUMMY_COLUMNS	80
#define DUMMY_ROWS	25
#endif

// ARM10C 20150704
static const char *dummycon_startup(void)
{
    return "dummy device";
    // return &"dummy device"
}

// ARM10C 20150718
// kmem_cache#25-oX, 1
static void dummycon_init(struct vc_data *vc, int init)
{
    // vc->vc_can_do_color: (kmem_cache#25-oX)->vc_can_do_color
    vc->vc_can_do_color = 1;
    // vc->vc_can_do_color: (kmem_cache#25-oX)->vc_can_do_color: 1

    // init: 1
    if (init) {
        // vc->vc_cols: (kmem_cache#25-oX)->vc_cols, DUMMY_COLUMNS: 80
	vc->vc_cols = DUMMY_COLUMNS;
        // vc->vc_cols: (kmem_cache#25-oX)->vc_cols: 80

        // vc->vc_rows: (kmem_cache#25-oX)->vc_rows, DUMMY_ROWS: 30
	vc->vc_rows = DUMMY_ROWS;
        // vc->vc_rows: (kmem_cache#25-oX)->vc_rows: 30
    } else
	vc_resize(vc, DUMMY_COLUMNS, DUMMY_ROWS);
}

// ARM10C 20150718
// vc: kmem_cache#25-oX, color_table
// ARM10C 20150725
// vc: kmem_cache#25-oX, CM_ERASE: 2
static int dummycon_dummy(void)
{
    return 0;
}

// ARM10C 20150718
// ARM10C 20150725
// DUMMY: (void *)dummycon_dummy
#define DUMMY	(void *)dummycon_dummy

/*
 *  The console `switch' structure for the dummy console
 *
 *  Most of the operations are dummies.
 */

// ARM10C 20140215
// ARM10C 20150704
// ARM10C 20150718
// DUMMY: 0
const struct consw dummy_con = {
    // THIS_MODULE: NULL
    .owner =		THIS_MODULE,
    .con_startup =	dummycon_startup,
    .con_init =		dummycon_init,
    .con_deinit =	DUMMY,
    .con_clear =	DUMMY,
    .con_putc =		DUMMY,
    .con_putcs =	DUMMY,
    .con_cursor =	DUMMY,
    .con_scroll =	DUMMY,
    .con_bmove =	DUMMY,
    .con_switch =	DUMMY,
    .con_blank =	DUMMY,
    .con_font_set =	DUMMY,
    .con_font_get =	DUMMY,
    .con_font_default =	DUMMY,
    .con_font_copy =	DUMMY,
    // DUMMY: (void *)dummycon_dummy
    .con_set_palette =	DUMMY,
    .con_scrolldelta =	DUMMY,
};
