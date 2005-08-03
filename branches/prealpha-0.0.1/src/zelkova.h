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

/** @file zelkova.h
 * Defines all variables, constants, and function declarations of Zelkova
 */

#ifndef __ZELKOVA_H__
#define __ZELKOVA_H__

#include <linux/ioctl.h>
#include <linux/slab.h>

#include "fistree/fistree.h"		/* fisrule_t */

/* version dependencies have been confined to a separate file */


/*
 * Macros to help debugging
 */

#undef ZKDEBUG

#ifdef ZELKOVA_DEBUG
# ifdef __KERNEL__
	/* This one if debugging is on, and kernel space */
#  define ZKDEBUG(fmt, args...) printk(KERN_DEBUG "zelkova: " fmt, ##args)
# else
	/* This one for user space */
#  define ZKDEBUG(fmt, args...) fprintf(stderr, fmt, ##args)
# endif
#else
# define ZKDEBUG(fmt, args...)	/* not debugging: nothing */
#endif

#define ZELKOVA_MODNAME	"zelkova"	/**< The name of Linux kernel module file */

#ifndef ZELKOVA_MAJOR
#define ZELKOVA_MAJOR	0	/**< Dynamic major by default */
#endif

#ifndef ZELKOVA_NR_DEVS
#define ZELKOVA_NR_DEVS	2	/**< Number of device files */
#endif

/*
 * split minors in two parts
 */
#define TYPE(dev)	(MINOR(dev) >> 4)	/**< high nibble of minor bitstring */
#define NUM(dev)	(MINOR(dev) & 0xf)	/**< low nibble of minor bitstring */

#ifndef min
# define min(a,b)	((a)<(b) ? (a) : (b))	/**< Choose the minimum value */
#endif

#define KMALLOCS(a, b, c)	(a) = (b)kmalloc((c), GFP_ATOMIC)
#define KFREES(x)			kfree(x)

/*
 * Ioctl definitions
 */

/* Use 'z' as magic number */
#define ZELKOVA_IOC_MAGIC	'z'
#define ZELKOVA_IOCRESET	_IO(ZELKOVA_IOC_MAGIC, 0)

#define FILTER_IOCTL		'f'

#define SIOCGETFR			_IOR(FILTER_IOCTL, 0x00, sizeof(int *))
#define SIOCSETFR			_IOW(FILTER_IOCTL, 0x00, sizeof(int *))

/*
 */

#define ZELKOVA_IOC_MAXNR	1

#define DEV_ZELKOVA			0
#define DEV_ACCT			1

#define DEV_MAX				1


/* Policy variables */

#ifndef MAX_IFNAME
# define MAX_IFNAME			16
#endif

#define MAX_SRCNET			20
#define MAX_DSTNET			20
#define MAX_SVCOBJ			32
#define MAX_POLICY_COMMENT	64

/* zk_policy_t
 * :User-level firewall policy
 */

typedef struct zk_policy {
	uint32_t	id;					/* Policy ID */
	uint16_t	action;				/* Action (Allow/Drop/Reject) */
	uint16_t	reserved;			/* NOT USED */

	uint32_t	flags;				/* Flags */

	char		ifn[MAX_IFNAME];		/* Name of the interface */

	char		srcnet[MAX_SRCNET];		/* Name of source network object */
	char		dstnet[MAX_DSTNET];		/* Name of destination network object */

	char		svcobj[MAX_SVCOBJ];		/* Name of service object */

	char		comment[MAX_POLICY_COMMENT];	/* Comments about this policy */
} zk_policy_t;


/* zkact_t
 * :Actions linked with filter rules
 */

typedef struct zkact {
	fisrule_t		*act_rule;		/* Pointer to fisrule_t */

	uint32_t		act_pass;		/* Filtering action. Allow/Drop/Reject */
	uint32_t		act_pid;		/* Policy id., simply a 32-bits number */

	struct zkact	*act_parent;	/* parent */

	uint32_t		act_hits;		/* hit counts of FIS-tree queries */
	uint32_t		act_pkts;		/* packet counts */
	uint64_t		act_bytes;		/* byte counts */

    zk_policy_t		*act_policy;	/* Policy fetched from DB */
} zkact_t;

/* zkact_t::act_pass */

#define ACT_ALLOW		0x00000001	/* Allow or not? */
#define ACT_ALLOWFRAG	0x00000002	/* Allow fragment packets? */

#define ACT_LOG			0x00001000	/* Write logs or not? */

/* zkdfrule_t
 * :Structure which deals with a fisrule_t member and a zkact_t member.
 * NOTE: The dfrule_rule member have to stand on the top of zkdfrule_t,
 *       otherwise memory deallocations become real headaches.
 */

typedef struct zkdfrule {
	fisrule_t		dfrule_rule;	/* rule */
	zkact_t		dfrule_act;		/* action */

	struct zkdfrule	*dfrule_prev;	/* Previous node of linked list */
	struct zkdfrule	*dfrule_next;	/* Next node of linked list */

	struct zkdfrule	*dfrule_bnext;	/* Brother node of linked list */
} zkdfrule_t;


/* zkspd_t
 * :Manages SPD(ruleset) in one structure
 */

typedef struct zkspd {
	fisrule_t		*spd_table;		/* SPD table */

	union {
		zkact_t	*act;			/* The action linked to the SPD entry */
		struct nat	*nat;			/* The action linked to the NAT policy */
	} spd_action;

	void			*spd_policy;	/* Policy table fetched from DB */
	zkdfrule_t		*spd_prerule;	/* List for default allow rules */

	uint32_t		spd_nelem;		/* Size of the table (number of elements) */
	uint32_t		spd_precnt;		/* Number of default allow rules (ex. TCP port #443 is opened */
	uint32_t		spd_flag;		/* flags */
} zkspd_t;

#define spd_act		spd_action.act
#define spd_nat		spd_action.nat

/* zkspd_t::spd_flag */

#define SPD_NORMALNAT	0x000000001
#define SPD_NAT			0x000000002

/*
 * Function declarations
 */

/* (in zkrule.c) */
void zkdfrule_syncrule(zkspd_t *spd);
void zkdfrule_delete(zkdfrule_t *dfrule);
void zkspd_clean(zkspd_t *spd);
zkact_t *zkspd_getactbyid(zkspd_t *spd, uint32_t id);

#endif	/* __ZELKOVA_H__ */
