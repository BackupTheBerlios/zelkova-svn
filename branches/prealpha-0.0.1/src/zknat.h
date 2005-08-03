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

/** @file zknat.h
 * Manages NAT sessions
 */

#ifndef __ZKNAT_H__
#define __ZKNAT_H__

#include "zelkova.h"

/* zknat_t */

typedef struct zknat {
	fisrule_t		*nat_rule;		/* Pointer to fisrule_t */

	uint32_t		nat_oaddr[2];	/* IP addr before trans. (BEGIN, END) (host order) */
	uint32_t		nat_xaddr[2];	/* IP addr after trans. (BEGIN, END) (host order) */

	/* NAPT only */
	uint16_t		nat_xport[2];	/* Port num after trans. (BEGIN, END) (host order) */

	uint32_t		nat_flag;		/* Flags */
} zknat_t;

/* zknat_t::nat_flag */

#define NAT_NORMALNAT	0x00000001	/* Normal NAT */

#define NAT_ONETOONE	0x00000010	/* 1:1 mapping with only IP address */
#define NAT_ELIMINATED	0x00000020	/* Rule in order to eliminate a NAT rule */
#define NAT_REVERSE		0x00000040	/* Reverse NAT */

#ifdef __KERNEL__
DECLARE_RWLOCK_EXTERN(nat_lock);
#endif	/* __KERNEL__ */


/* natroot[0] : for redirect NAT
 * natroot[1] : for normal NAT
 */
#define NAT_REDIR		0	/* redirect NAT index */
#define NAT_NORMAL		1	/* normal NAT index */

extern void		*natroot[2];	/* NAT FIS-tree root */
extern zkspd_t	staticnat[2];	/* static NAT rule */


#endif	/* __ZKNAT_H__ */
