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

#define __NO_VERSION__

#include <linux/kernel.h>			/* printk() */

#include "zelkova.h"

/*!
 *---------------------------------------------------------------------------
 *
 * \fn static int zelkova_ioctl_filter(uint cmd, void *data, int mode)
 * \brief Process data exchange operations
 * \param 
 * Date: 19 Jul, 2005
 *  Process data exchange operations between kernel module and
 *  another applications.
 *
 *---------------------------------------------------------------------------
 */

int zelkova_ioctl_filter(uint cmd, void *data, int mode)
{
	return 0;
}

