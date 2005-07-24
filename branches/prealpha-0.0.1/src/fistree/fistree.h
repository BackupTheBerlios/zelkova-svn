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

#ifndef __FISTREE_H__
#define __FISTREE_H__

/*
 * Implementation of FIS-tree
 *
 * FIS-tree, which is used to efficiently construct rules for Zelkova packet
 * filter, is derived from two papers below.
 *
 * "Tradeoffs for Packet Classification" by Anja Feldmann, S. Muthukrishnan, in INFOCOM, 2000.
 * "Algorithms for Packet Classification" by Pankaj Gupta, Nick McKeown, in IEEE Network, 2001.
 *
 * NOTE: The level of FIS-tree is determined by (m = t ^ l) according to above papers.
 * (m is the number of elementary intervals, t is the in-degree of FIS-tree)
 * The smaller level l is, the more memory spaces systems require.
 * Therefore I have to let l = 1, and t = m, in order to improve query speeds
 * and to implement more efficiently.
 *
 *  - knecht <knecht@postech.ac.kr>
 */


/*
 * FIS-tree rules and each interval
 *
 * Each interval is differentiated by key, which is stated in the Range
 * Location problem.
 * If keys are series of {a0, a1, ... , an}, then intervals are like below.
 *
 * {[0 <= x < a0], [a0 <= x < a1], ..., [an-1 <= x < an], [an <= x]}.
 *
 * Each intervals are expressed as (begin, end), which is a couple of starting
 * point and end point. That means, an interval ranges as [begin <= x < end].
 *
 * Let there is a 32-bit value. Then begin values are {0, 1, 2, ..., (2^32 -
 * 1)} and end values are {1, 2, 3, ..., (2^32 - 1), 0}.
 * It is important to notice that end value '0' means the maximal value
 * (which means 'infinite' conceptually).
 *
 * Therefore an interval [ANY ~ ANY] is expressed as (0, 0).
 * Beware that the key value '0' is not included in FIS-tree itself,
 * but included in the parent node of FIS-tree(root of FIS-tree).
 */

/* range of addresses, ..., etc. */

typedef struct fistree_range {
	uint32_t		begin;	/* start point */
	uint32_t		end;	/* end point */
} fistree_range_t;

/* set of ranges */

typedef struct fistree_rangeset {
	fistree_range_t		*table;	/* range table */
	size_t				nelem;	/* size of table (number of elements) */
} fistree_rangeset_t;

/* interval (range, set of ranges, ..., etc.) */

typedef struct fistree_interval {
	uint32_t		type;	/* type of interval */
	union {
		fistree_range_t		one;	/* range */
		fistree_rangeset_t	set;	/* range set */
	} r;
} fistree_interval_t;

#define INTERVAL_ANYTOANY	0x00000001
#define INTERVAL_RANGEONE	0x00000002
#define INTERVAL_RANGESET	0x00000004

/*
 * Rules
 */

#ifndef MAX_FISTREE_DIM
#define MAX_FISTREE_DIM		5
#endif

/*
 * Each static rule have to be included in an arbitrary SPD structure
 * as an array. This array is assumed to be sorted by ascending order of
 * absolute values of rule costs.
 */

#ifndef FISTREE_RULE
#define FISTREE_RULE

typedef struct fisrule {
	fistree_interval_t	field[MAX_FISTREE_DIM];
	void				*action;
	int					cost;
	int					refcnt;
	int					is_bidirect;	/* is this a bidirectional rule? */
	fistree_interval_t	inversefield[MAX_FISTREE_DIM];	/* an inverse rule */
} fisrule_t;

#endif	/* FISTREE_RULE */

#endif	/* __FISTREE_H__ */
