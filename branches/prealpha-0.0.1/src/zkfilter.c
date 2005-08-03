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

/** @file zkfilter.c
 * Manages filter rules and sessions
 */

#define __NO_VERSION__

#include <linux/kernel.h>			/* printk() */
#include <asm/uaccess.h>			/* copy_to_user(), copy_from_user() */
#include <linux/netfilter_ipv4/lockhelp.h>	/* *_LOCK, *_UNLOCK */

DECLARE_RWLOCK(spd_lock);	/* A lock with SPD root and static SPD */

void	*spdroot;		/* FIS-tree root */

/**
 *---------------------------------------------------------------------------
 *
 * @fn     int func1(void)
 * @brief  Brief description
 * @param  NONE
 * @return >=0 if normal, <0 if abnormal.
 * @date   25 Jul, 2005
 * @see    NONE
 *
 *  Detailed description
 *
 *---------------------------------------------------------------------------
 */

