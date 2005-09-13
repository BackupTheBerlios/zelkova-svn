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

#include "zelkova.h"

static fisrule_t	defaultrule[2];	/* the default rules
									 * (used when FIS-tree lookup fails) */

DECLARE_RWLOCK(spd_lock);	/* A lock with SPD root and static SPD */

zkspd_t	staticspd;		/* static Security Policy Database */
void	*spdroot;		/* FIS-tree root */

/**
 *---------------------------------------------------------------------------
 *
 * @fn     void filter_init(void)
 * @brief  Initialize informations of the packet filter SPD
 * @param  NONE
 * @return NONE
 * @date   13 Sep, 2005
 * @see    NONE
 *
 *  Initialize informations of the packet filter SPD
 *
 *---------------------------------------------------------------------------
 */

void filter_init(void)
{
	static zkact_t	action[2];		/* default action */
	int				i, j;

	WRITE_LOCK(&spd_lock);

	/* Initialize spdroot of the FIS-tree */
	spdroot = NULL;

	/* Initialize staticspd */
	memset(&staticspd, 0x00, sizeof(staticspd));

	WRITE_UNLOCK(&spd_lock);

	/* Initialize the default rule and the default action */
	memset(defaultrule, 0x00, sizeof(defaultrule));
	memset(action, 0x00, sizeof(action));

	for (i = 0; i < SIZEOFARR(action); i++) {
		for (j = DIM_SRCADDR; j <= DIM_MAX; j++) {
			point2interval(&defaultrule[i].field[j], 0);
		}

		defaultrule[i].action = &action[i];
		action[i].act_rule = &defaultrule[i];
		action[i].act_pass = ACT_LOG;
	}

	/* Drop inbound packets by default,
	 * while allow outbound packets by default. */

	action[1].act_pass |= (ACT_ALLOW | ACT_ALLOWFRAG);
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     void filter_clean(void)
 * @brief  Destroy informations of the packet filter SPD
 * @param  NONE
 * @return NONE
 * @date   13 Sep, 2005
 * @see    NONE
 *
 *  Destroy informations of the packet filter SPD
 *
 *---------------------------------------------------------------------------
 */

void filter_clean(void)
{
	WRITE_LOCK(&spd_lock);

	if (spdroot != NULL) {
		FISTREE_CLEAN(spdroot);
		spdroot = NULL;
	}

	if (staticspd.spd_nelem > 0) {
		KFREES(staticspd.spd_table);
		KFREES(staticspd.spd_act);

		staticspd.spd_table		= NULL;
		staticspd.spd_act		= NULL;
		staticspd.spd_nelem		= 0;
		staticspd.spd_precnt	= 0;
	}

	WRITE_UNLOCK(&spd_lock);
}
