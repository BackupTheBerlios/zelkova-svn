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

/** @file ioctl.c
 * Defines ioctl operations in the zelkova kernel module
 */

#define __NO_VERSION__

#include <linux/kernel.h>			/* printk() */
#include <asm/uaccess.h>			/* copy_to_user(), copy_from_user() */
#include <linux/netfilter_ipv4/lockhelp.h>	/* *_LOCK, *_UNLOCK */

#include "zelkova.h"
#include "zksession.h"
#include "fistree/fistree.h"


/* zk_filter_stat_t */

typedef struct zk_filter_stat {
	uint64_t		zkfs_nallow[2];	/* Number of allowed packets */
	uint64_t		zkfs_ndrop[2];		/* Number of dropped packets */
	zkspd_t		*zkfs_staticspd;	/* Pointer to a static SPD */
} zk_filter_stat_t;


/*
 * Global variables
 */

zk_filter_stat_t	zkfr_stat;	/* inbound/outbound filter statistics */

DECLARE_RWLOCK_EXTERN(spd_lock);	/* R/W lock with SPD root and static SPD */

/*
 * Extern variables
 */
extern void		*spdroot;		/* FIS-tree root */

/**
 *---------------------------------------------------------------------------
 *
 * @fn static int zelkova_ioctl_filter(uint cmd, void *data, int mode)
 * @brief Process data exchange operations
 * @param uint cmd
 * @param void *data
 * @param int mode
 * @date 25 Jul, 2005
 *
 *  Process data exchange operations between kernel module and
 *  another applications.
 *
 *---------------------------------------------------------------------------
 */

int zelkova_ioctl_filter(uint cmd, void *data, int mode)
{
	static zkdfrule_t	*prerule = NULL;
	static int			precnt = 0;

	fisrule_t			*rule, frule;
	zkspd_t			zkspd;
	zkact_t			*zkact;
	zk_policy_t			*po;
	zkdfrule_t			*zkdfrule;
	void				*root, *oldroot;
	fistree_range_t		*rangetable;
	size_t				rangesize;
	int					i, j;

	ZKDEBUG("'%c'/0x%02x\n", (char)_IOC_TYPE(cmd), (unsigned int)_IOC_NR(cmd));

	switch(cmd) {
	case SIOCGETFR:
		/* copy filter rule informations from kernel-level to user-level */

		copy_to_user(data, &zkfr_stat, sizeof(zkfr_stat));
		break;

	case SIOCSETFR:
		/* Set filter rules from user-level to kernel-level */

		copy_from_user(&zkspd, data, sizeof(zkspd_t));

		zkspd.spd_precnt	= 0;
		zkspd.spd_flag		= 0;

		/* Set spdroot with NULL if SPD entry doesn't exist AND precnt == 0
		 * Leave alone staticspd.
		 */
		if (zkspd.spd_nelem == 0 && precnt == 0) {
			spdroot = NULL;
			break;
		}

		/* Allocate new memories for rule structures */
		KMALLOCS(rule, fisrule_t *, sizeof(fisrule_t) * (zkspd.spd_nelem + precnt));
		if (rule == NULL) {
			return -ENOMEM;
		}

		KMALLOCS(zkact, zkact_t *, sizeof(zkact_t) * (zkspd.spd_nelem + precnt));
		if (rule == NULL) {
			KFREES(rule);
			return -ENOMEM;
		}

		if (zkspd.spd_nelem > 0) {
			KMALLOCS(po, zk_policy_t *, sizeof(zk_policy_t) * zkspd.spd_nelem);

			if (po == NULL) {
				KFREES(rule);
				KFREES(zkact);
				return -ENOMEM;
			}
		}
		else {
			po = NULL;
		}

		/* pre-static rule table
		 * We should interate index by reverse order because prerule is
		 * constructed as a linked list of stack-type
		 */
		zkdfrule = prerule;

		for (i = precnt - 1; i >= 0; i--) {
			memcpy(&rule[i], &zkdfrule->dfrule_rule, sizeof(fisrule_t));
			memcpy(&rule[i], &zkdfrule->dfrule_rule, sizeof(fisrule_t));

			/* Traverse linked list with link to brother nodes */
			zkdfrule = zkdfrule->dfrule_bnext;
		}

		/* Copy the real static rule table from user memory to kernel memory */

		if (zkspd.spd_nelem > 0) {
			copy_from_user(rule + precnt,  zkspd.spd_table, sizeof(fisrule_t) * zkspd.spd_nelem);
			copy_from_user(zkact + precnt, zkspd.spd_act, sizeof(zkact_t) * zkspd.spd_nelem);
			copy_from_user(po,             zkspd.spd_policy, sizeof(zk_policy_t) * zkspd.spd_nelem);
		}

		/* Increase the number of all rules */
		zkspd.spd_nelem += precnt;

		/* Process range with the type of INTERNVAL_RANGESET.
		 * Here we assume that existing rules do not have INTERNAL_RANGESET
		 * attributes at all.
		 */

		for (i = precnt; i < zkspd.spd_nelem; i++) {
			for (j = 0; j < MAX_FISTREE_DIM; j++) {
				if (rule[i].field[j].type == INTERVAL_RANGESET) {
					rangesize = sizeof(fistree_range_t) * rule[i].field[j].r.set.nelem;

					KMALLOCS(rangetable, fistree_range_t *, rangesize);
					if (rangetable == NULL) {
						rule[i].field[j].type = 0;
						break;
					}

					copy_from_user(rangetable, rule[i].field[j].r.set.table, rangesize);
				}
			} /* for(j) */
		} /* for(i) */

		/* Assign each member of zkspd */
		zkspd.spd_table		= rule;
		zkspd.spd_act		= zkact;
/*        zkspd.spd_policy	= po;*/
		zkspd.spd_prerule	= NULL;
		zkspd.spd_precnt	= precnt;

		/* If rangeset is not allocated since it ran out of memory,
		 * Clean SPD correctly and return an error.
		 */

		for (i = precnt; i < zkspd.spd_nelem; i++) {
			/* Skip inactivated rules */
			if (rule[i].cost == 0) {
				continue;
			}

			for (j = 0; j < MAX_FISTREE_DIM; j++) {
				if (rule[i].field[j].type == 0) {
					zkspd_clean(&zkspd);
					return -ENOMEM;
				}
			}

			/* Link each policy table. */
			zkact[i].act_policy = &po[i - precnt];
		}

		/* Initialize for rule[] and act[] arrays */

		for (i = 0; i < zkspd.spd_nelem; i++) {
			rule[i].refcnt = 0;
			rule[i].action = &zkact[i];

			zkact[i].act_rule	= &rule[i];
			zkact[i].act_parent	= NULL;
			zkact[i].act_hits	= 0;
			zkact[i].act_pkts	= 0;
			zkact[i].act_bytes	= 0;
		}

		/* Now we make a FIS-tree for static rules */
		root = FISTREE_MAKE(rule, zkspd.spd_nelem);
		if (root == NULL) {
			zkspd_clean(&zkspd);
			return -ENOMEM;
		}

		WRITE_LOCK(&spd_lock);

		/* Reassign the root of FIS-tree and the SPD table */

		oldroot = spdroot;
		spdroot = root;

		zkdfrule_syncrule(&zkspd);	/* Insert dynamic rules into the new FIS-tree */
		ipsess_syncrule();		/* Make the session table be compatible with the new FIS-tree */

		/* Remove the old FIS-tree */
		if (oldroot != NULL) {
			FISTREE_CLEAN(oldroot);
		}

		WRITE_UNLOCK(&spd_lock);

		break;

	default:
		break;
	}

	return 0;
}

