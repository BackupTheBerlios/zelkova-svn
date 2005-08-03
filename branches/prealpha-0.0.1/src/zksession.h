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

/** @file zksession.h
 * Define variables, constants, structures, and function declarations
 * for the session table module.
 */

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

	struct zkipsess		*zis_natsess[2];	/* Connected NAT session */

	uint32_t			zis_oifid;	/* ID of the outbound interface(for NAT query) */

	uint32_t			zis_ruleid;	/* rule id. (32bit integer) */

	atomic_t			zis_refcnt;	/* reference count.(for filtering session) */
} zkipsess_t;

#define			zis_id		zis_i.id
#define			zis_pd		zis_i.pd

/* zkipsess_t::zis_flag */

#define IS_ISTOTRUSTED		0x00000001	/**< ? */
#define IS_REDIRECTNAT		0x00000010	/**< Is it a redirect NAT session? */
#define IS_NORMALNAT		0x00000020	/**< Is it a normal NAT session? */
#define IS_NAT				0x00000030	/**< Is it a normal NAT session? */


#define MAX_ZKIPSESS	262139		/**< IP session table size. (< 256K) */


/*
 * Function Declarations
 */
void ipsess_syncrule(void);
void zkipsess_delete(zkipsess_t *is);
void zkipsess_deletenat(zkipsess_t *is);
void zkipsess_destroy(zkipsess_t *is);

#ifdef __KERNEL__

/* ipsess_release(): Decrement the reference count by one
 * If the reference count has reached 0, destroy the session entry.
 */

static inline void ipsess_release(zkipsess_t *is)
{
	if (atomic_dec_and_test(&is->zis_refcnt)) {
		zkipsess_destroy(is);
	}
}

#endif	/* __KERNEL__ */

#endif	/* __ZKSESSION_H__ */
