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

/** @file zkpktinfo.h
 * Defines variables, constants, structures and function declarations
 * for zkpktinfo_t
 */

#ifndef __ZKPKTINFO_H__
#define __ZKPKTINFO_H__

#include "fistree.h"

struct zkipsess;

/* zkpktinfo_t */

typedef struct zkpktinfo {
	int				zpi_out;		/* outbound = 1, inbound = 0 */
	int				zpi_dir;		/* request on session = 0, response on session = 1 */
	struct sk_buff	*zpi_buff;	/* original sk_buff block */

	fisrule_t		*zpi_rule;		/* selected rule */
	struct zkipsess	*zpi_sess;		/* selected session */

	uint8_t			zpi_hlen;		/* IP header length */
	uint8_t			zpi_reserved1;	/* Not Used */
	uint16_t		zpi_offset;		/* fragment offset */

	union {
		uint32_t	id[MAX_FISTREE_DIM];	/* classification id. */
		uint16_t	pd[MAX_FISTREE_DIM << 1];	/* (protocol/port) */
	} zpi_i;

	uint32_t		zpi_hv;			/* session hash vector */

	struct net_device	*zpi_ifp;	/* pointer to the network interface */
	struct sk_buff	*zpi_fragbuff;	/* fragments with the same session */
	uint32_t		zpi_ipopt;		/* arranged IP options */
} zkpktinfo_t;

#endif	/* __ZKPKTINFO_H__ */
