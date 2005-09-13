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

/** @file zksession.c
 * Manages the session table
 */

#define __NO_VERSION__

#include <linux/kernel.h>			/* printk() */
#include <asm/uaccess.h>			/* copy_to_user(), copy_from_user() */
#include <linux/netfilter_ipv4/lockhelp.h>	/* *_LOCK, *_UNLOCK */

#include "zkfilter.h"
#include "zknat.h"
#include "zksession.h"


static DECLARE_RWLOCK(ipsess_lock);	/**< A lock with the session table */

static zkipsess_t	zis_g_head;	/**< Pointer to the global linked list for IP session */
static zkipsess_t	zns_g_head;	/**< Pointer to the global linked list for NAT session */

static zkipsess_t	*zis_hash[MAX_ZKIPSESS];	/**< IP session hash table */

static atomic_t		nipsess;	/**< Total number of sessions in zis_hash */

int					ns_num = 0;	/**< Total number of NAT sessions */

static void ipsess_substituterule(zkipsess_t *is, fisrule_t *rule);

/**
 *---------------------------------------------------------------------------
 *
 * @fn     void ipsess_syncrule(void)
 * @brief  Make the IP session table be compatible with the rule table
 * @param  NONE
 * @return NONE
 * @date   27 Jul, 2005
 * @see    NONE
 *
 *  Make the IP session table be compatible with the rule table
 *
 *---------------------------------------------------------------------------
 */

void ipsess_syncrule(void)
{
	zkipsess_t		*is;
	zkipsess_t		*next;
	fisrule_t		*rule = NULL;

	WRITE_LOCK(&ipsess_lock);

	is = zis_g_head.zis_next;

	/* NOTE: The lock with spdroot is enabled before calling ipsess_syncrule()*/
	while (is != &zis_g_head) {
		next = is->zis_next;

		rule = FISTREE_QUERY(spdroot, is->zis_id);

		if (rule != NULL) {
			if (rule != is->zis_rule) {
				ipsess_substituterule(is, rule);
			}
		}
		else {
			/* Delete this session since the matching rule is destroyed */
			zkipsess_delete(is);
		}

		is = next;
	}

	WRITE_UNLOCK(&ipsess_lock);
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static void ipsess_substituterule(zkipsess_t *is, fisrule_t *rule)
 * @brief  Substitute the rule in 'is' with a new rule
 * @param  is: session table entry to be substituted
 * @param  rule: rule to be inserted
 * @return NONE
 * @date   28 Jul, 2005
 * @see    NONE
 *
 *  Substitute the rule linked within 'is' with a new rule
 *
 *---------------------------------------------------------------------------
 */

static void ipsess_substituterule(zkipsess_t *is, fisrule_t *rule)
{
	zkact_t		*action = rule->action;
	fisrule_t	*natrule;
	void		*root;
	int			needtolog = 0;
	uint32_t	ifid;

	/* Write a log message if a rule action is modified */
	if ((action->act_pass & ACT_LOG)) {
		if (is->zis_pass != action->act_pass || is->zis_ruleid != action->act_pid) {
			needtolog++;
		}
	}


	/* The session of drop policy does not query any normal NAT rules.
	 * Therefore we query a normal NAT rule if the current policy is changed,
	 * and if a non-NAT session becomes a NAT session, delete the session.
	 */

	if (!(is->zis_pass & ACT_ALLOW) && (action->act_pass & ACT_ALLOW)) {
		if ((root = natroot[NAT_NORMAL]) != NULL) {
			ifid = is->zis_id[DIM_IFID];
			is->zis_id[DIM_IFID] = is->zis_oifid;

			if ((natrule = FISTREE_QUERY(root, is->zis_id)) != NULL) {
				if (!(((zknat_t *)natrule->action)->nat_flag & NAT_ELIMINATED)) {
					zkipsess_delete(is);
					return;
				}
			}

			/* Restore the network interface field value */

			is->zis_id[DIM_IFID] = ifid;
		}
	}

	/* Now we have found a new rule, so assign appropriate fields to vars. */

	is->zis_pass	= action->act_pass;
	is->zis_rule	= rule;
	is->zis_ruleid	= action->act_pid;

	/* Write logs */
	if (needtolog) {
/*        sweeplog_session(is, " (CHANGED)");*/
	}
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     void zkipsess_delete(zkipsess_t *is)
 * @brief  Delete an IP session entry
 * @param  is: session table entry to be deleted
 * @return NONE
 * @date   28 Jul, 2005
 * @see    NONE
 *
 *  Delete an IP session entry. If the reference count value is not 0, 
 *  Do not delete the entry really and just release hash table connections
 *  and update statistics.
 *
 *---------------------------------------------------------------------------
 */

void zkipsess_delete(zkipsess_t *is)
{
	zkipsess_t	*hold;

	/* Write logs */

/*    if ((is->zis_pass & ACT_LOG)) {*/
/*        sweeplog_session_delete(is);*/
/*    }*/

	/* Fetch a session entry from the global linked list */
	is->zis_prev->zis_next = is->zis_next;
	is->zis_next->zis_prev = is->zis_prev;

	/* Remove from the hash table */

	hold = zis_hash[is->zis_hv];

	if (hold == is) {
		zis_hash[is->zis_hv] = is->zis_hnext;
	}
	else {
		while (hold->zis_hnext != is) {
			hold = hold->zis_hnext;
		}

		hold->zis_hnext = is->zis_hnext;
	}

	atomic_dec(&nipsess);

	/* Delete NAT sessions */
	if (is->zis_natsess[NAT_REDIR] != NULL) {
		zkipsess_deletenat(is->zis_natsess[NAT_REDIR]);
	}

	if (is->zis_natsess[NAT_NORMAL] != NULL) {
		zkipsess_deletenat(is->zis_natsess[NAT_NORMAL]);
	}

	/* */

	ipsess_release(is);
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     void zkipsess_deletenat(zkipsess_t *is)
 * @brief  Delete an IP NAT session entry
 * @param  is: session table entry to be deleted
 * @return NONE
 * @date   28 Jul, 2005
 * @see    NONE
 *
 *  Delete an IP NAT session entry. 
 *
 *---------------------------------------------------------------------------
 */

void zkipsess_deletenat(zkipsess_t *is)
{
	zkipsess_t		*hold;

	ns_num--;

	/* Fetch a NAT session from the global linked list */
	is->zis_prev->zis_next = is->zis_next;
	is->zis_next->zis_prev = is->zis_prev;

	/* Fetch a NAT session from the hash table */

	hold = zis_hash[is->zis_hv];

	if (hold == is) {
		zis_hash[is->zis_hv] = is->zis_hnext;
	}
	else {
		while (hold->zis_hnext != is) {
			hold = hold->zis_hnext;
		}

		hold->zis_hnext = is->zis_hnext;
	}

}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     void zkipsess_destroy(zkipsess_t *is)
 * @brief  Destroy an IP NAT session entry
 * @param  is: session table entry to be deleted
 * @return NONE
 * @date   28 Jul, 2005
 * @see    NONE
 *
 *  Destroy an IP NAT session entry.
 *  That means we deallocate memory of the session entry as well as we remove
 *  the entry from the session table.
 *
 *---------------------------------------------------------------------------
 */

void zkipsess_destroy(zkipsess_t *is)
{
	/* Destroy NAT session if it is connected */

	if (!(is->zis_flag & IS_NAT)) {
		if (is->zis_natsess[NAT_REDIR] != NULL) {
			zkipsess_destroy(is->zis_natsess[NAT_REDIR]);
		}

		if (is->zis_natsess[NAT_NORMAL] != NULL) {
			zkipsess_destroy(is->zis_natsess[NAT_NORMAL]);
		}
	}

	/* Deallocate memories */
	KFREES(is);
}
