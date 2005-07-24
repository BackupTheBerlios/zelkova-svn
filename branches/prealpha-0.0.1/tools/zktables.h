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

#ifndef __ZKTABLES_H__
#define __ZKTABLES_H__

/* This macro must check for *c == 0 since isspace(0) has unreliable behavior
 * on some systems */
#define ZK_SKIPWS(c) \
	while (*(c) && isspace ((unsigned char) *(c))) c++;

typedef struct zk_buffer {
	char	*data;		/* pointer to data */
	char	*dptr;		/* current read/write position */
	size_t	dsize;		/* length of data */
	int		destroy;	/* destroy `data' when done? */
} zk_buffer_t;

#endif	/* __ZKTABLES_H__ */
