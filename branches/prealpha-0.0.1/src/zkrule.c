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

/** @file zkrule.c
 * Modules which manage fisrule, zkspd, zkact, etc.
 */

#define __NO_VERSION__

#include <linux/kernel.h>			/* printk() */
#include <asm/uaccess.h>			/* copy_to_user(), copy_from_user() */
#include <linux/netfilter_ipv4/lockhelp.h>	/* *_LOCK, *_UNLOCK */

#include "zelkova.h"

static DECLARE_RWLOCK(rule_lock);	/**< A lock with the dynamic rule list */

zkdfrule_t		rule_g_head;	/**< Pointer to the global linked list for dynamic rules */

/**
 *---------------------------------------------------------------------------
 *
 * @fn     void zkdfrule_syncrule(zkspd_t *spd)
 * @brief  Insert a dynamic rule into a new FIS-tree
 * @param  spd: SPD rule to be inserted
 * @return NONE
 * @date   27 Jul, 2005
 * @see    NONE
 *
 *   Insert a dynamic rule into a new FIS-tree
 *---------------------------------------------------------------------------
 */

void zkdfrule_syncrule(zkspd_t *spd)
{
	zkdfrule_t		*dfrule;
	zkdfrule_t		*next;
	zkact_t		*action, *paction;

	WRITE_LOCK(&rule_lock);

	dfrule = rule_g_head.dfrule_next;

	while (dfrule != &rule_g_head) {
		next	= dfrule->dfrule_next;
		action	= &dfrule->dfrule_act;

		/* A dynamic rule MUST have a parent rule.
		 * Otherwise it has to be vanished. */

		if ((paction = zkspd_getactbyid(spd, action->act_pid)) == NULL) {
			zkdfrule_delete(dfrule);

			action->act_parent = NULL;
			goto next;
		}

next:
		dfrule = next;
	}

	WRITE_UNLOCK(&rule_lock);
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     void zkdfrule_delete(zkdfrule_t *dfrule)
 * @brief  Deletes a dynamic rule and deallocate the memory it had before.
 * @param  dfrule: Dynamic rule to be deleted
 * @return NONE
 * @date   27 Jul, 2005
 * @see    NONE
 *
 *   Deletes a dynamic rule and deallocate the memory it had before.
 *---------------------------------------------------------------------------
 */

void zkdfrule_delete(zkdfrule_t *dfrule)
{
	/* First, removes a input dynamic rule from the global linked list.
	 * NOTE: Dynamic rules are not be aging like sessions, so you have to
	 *       remove the rule explicitly.
	 */

	dfrule->dfrule_prev->dfrule_next = dfrule->dfrule_next;
	dfrule->dfrule_next->dfrule_prev = dfrule->dfrule_prev;

	/* NOTE: In case of spdroot, you have to lock before calling
	 * zkdfrule_delete() */

	/* Deallocate memories */
	KFREES(dfrule);
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     void zkspd_clean(zkspd_t *spd)
 * @brief  Remove the whole SPD table
 * @param  spd: SPD rule to be deleted
 * @return NONE
 * @date   27 Jul, 2005
 * @see    NONE
 *
 *  Remove all the entries in the whole SPD table.
 *
 *---------------------------------------------------------------------------
 */

void zkspd_clean(zkspd_t *spd)
{
	int			i, j;
	zkdfrule_t	*dfrule;

	if (spd->spd_nelem == 0) {
		return;
	}

	for (i = 0; i < spd->spd_nelem; i++) {
		for (j = 0; j < MAX_FISTREE_DIM; j++) {
			if (spd->spd_table[i].field[j].type != INTERVAL_RANGESET) {
				continue;
			}

			if (spd->spd_table[i].field[j].r.set.nelem <= 0) {
				continue;
			}

			KFREES(spd->spd_table[i].field[j].r.set.table);
		}
	}

	KFREES(spd->spd_table);

	if ((spd->spd_flag & SPD_NAT)) {
		KFREES(spd->spd_nat);
		KFREES(spd->spd_policy);
	}
	else {
		KFREES(spd->spd_act);
		KFREES(spd->spd_policy);

		/* Clean up the spd_prerule list */

		if (spd->spd_precnt > 0) {
			dfrule = spd->spd_prerule;

			while (dfrule != NULL) {
				spd->spd_prerule = dfrule->dfrule_bnext;

				KFREES(dfrule);

				dfrule = spd->spd_prerule;
			}
		}
	}
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     zkact_t *zkspd_getactbyid(zkspd_t *spd, uint32_t id)
 * @brief  Get an action of the main static rule by a policy ID.
 * @param  spd: SPD rule list which includes the action to be returned
 * @param  id: id of SPD rule to be deleted
 * @return NONE
 * @date   27 Jul, 2005
 * @see    NONE
 *
 *  Get an action of the main static rule by a policy ID.
 *
 *---------------------------------------------------------------------------
 */

zkact_t *zkspd_getactbyid(zkspd_t *spd, uint32_t id)
{
	int			i;

	/* NOTE: Do not lock here. Instead we lock before calling this func. */

	for (i = spd->spd_precnt; i < spd->spd_nelem; i++) {
		if (spd->spd_act[i].act_pid == id) {
			return &spd->spd_act[i];
		}
	}

	return NULL;
}
