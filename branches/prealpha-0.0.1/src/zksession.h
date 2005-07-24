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

#ifndef __ZKSESSION_H__
#define __ZKSESSION_H__

#include "zelkova.h"

/* zkipsess_t */

typedef struct zkipsess {
	struct zkipsess		*zis_prev;	/* The previous node of linked list */
	struct zkipsess		*zis_next;	/* The next node of linked list */

	struct zkipsess		*zis_hnext;	/* The next node of hash chain */

	union {
		uint32_t		id[MAX_FISTREE_DIM];	/* classification id. */
		uint16_t		pd[MAX_FISTREE_DIM << 1];	/* (protocol/port) */
	} zis_i;

	uint32_t			zis_hv;		/* session hash vector */

	uint32_t			zis_flag;	/* flags */
	uint32_t			zis_pass;	/* filtering action */
	uint32_t			zis_age;	/* age value of session table entry */

	fisrule_t			*zis_rule;	/* The selected rule */

	uint32_t			zis_ruleid;	/* rule id. (32bit integer) */
} zkipsess_t;

#define			zis_id		zis_i.id
#define			zis_pd		zis_i.pd

#endif	/* __ZKSESSION_H__ */
