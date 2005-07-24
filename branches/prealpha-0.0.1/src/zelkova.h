/*
 *----------------------------------------------------------------------------
 *
 * Zelkova - A Firewall and Intrusion Prevention System on Linux Kernel
 *
 * Copyright (C) 2005 Dongsu Park <advance@dongsu.pe.kr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 *
 * $Id$
 *----------------------------------------------------------------------------
 */

/*! \file */

#include <linux/ioctl.h>

/* version dependencies have been confined to a separate file */


/*
 * Macros to help debugging
 */

#undef ZKDEBUG

#ifdef ZELKOVA_DEBUG
# ifdef __KERNEL__
	/* This one if debugging is on, and kernel space */
#  define ZKDEBUG(fmt, args...) printk(KERN_DEBUG "zelkova: " fmt, ##args)
# else
	/* This one for user space */
#  define ZKDEBUG(fmt, args...) fprintf(stderr, fmt, ##args)
# endif
#else
# define ZKDEBUG(fmt, args...)	/* not debugging: nothing */
#endif

#define ZELKOVA_MODNAME	"zelkova"

#ifndef ZELKOVA_MAJOR
#define ZELKOVA_MAJOR	0	/* dynamic major by default */
#endif

#ifndef ZELKOVA_NR_DEVS
#define ZELKOVA_NR_DEVS	2
#endif

/*
 * split minors in two parts
 */
#define TYPE(dev)	(MINOR(dev) >> 4)	/* high nibble */
#define NUM(dev)	(MINOR(dev) & 0xf)	/* low nibble */

#ifndef min
# define min(a,b)	((a)<(b) ? (a) : (b))
#endif

/*
 * Ioctl definitions
 */

/* Use 'z' as magic number */
#define ZELKOVA_IOC_MAGIC	'z'
#define ZELKOVA_IOCRESET	_IO(ZELKOVA_IOC_MAGIC, 0)

#define FILTER_IOCTL		'f'

/*
 */

#define ZELKOVA_IOC_MAXNR	1

#define DEV_ZELKOVA			0
#define DEV_ACCT			1

#define DEV_MAX				1
