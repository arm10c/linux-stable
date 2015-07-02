#ifndef _CONSOLE_CMDLINE_H
#define _CONSOLE_CMDLINE_H

// ARM10C 20150627
struct console_cmdline
{
	char	name[8];			/* Name of the driver	    */
	int	index;				/* Minor dev. to use	    */
	char	*options;			/* Options for the driver   */
#ifdef CONFIG_A11Y_BRAILLE_CONSOLE // CONFIG_A11Y_BRAILLE_CONSOLE=n
	char	*brl_options;			/* Options for braille driver */
#endif
};

#endif
