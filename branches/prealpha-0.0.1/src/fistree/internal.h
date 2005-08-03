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

/**
 * @file internal.h
 * Declares basic structures and defines to be used only in the FIS-tree module
 */

#ifndef __FISTREE_INTERNAL_H__
#define __FISTREE_INTERNAL_H__

/* fisruleset_t */

typedef struct fisruleset {
	struct fisruleset	*next;
	fisrule_t			*rule;
} fisruleset_t;


/*
 * FIS-tree node
 * : Should be aligned by 32 bytes in order to get L2 cache effects
 */

typedef struct fisnode {
	int			cost;	/**< Choose the minimum value between base canonical cost and delta canonical cost. */

	void		*nextRL;	/**< Root of next degree's (2,4)-tree */

	struct fisnode	*parent;	/**< The parent node of FIS-tree. */

	/* @var   rule
	 * @brief Pointer to the chosen rule
	 *
	 * Choose this rule as the minimum value between baserule and the rule
	 * of delta canonical set. If two variables have the same value, the rule
	 * of delta canonical set is chosen. NULL if not on top degree.
	 */
	fisrule_t		*rule;

	fisruleset_t	*delta;	/**< delta canonical set */

	/* @var   basecost
	 * @brief base canonical cost
	 *
	 * The possible minimum value. It is the same as the cost value
	 * of nextproj[1].
	 */

	int				basecost;

	fisrule_t		*baserule;	/**< The rule chosen by base canonical set. */

	int				refcnt;		/**< Reference count */
} fisnode_t;


/* 
 * TODO: Summary of projection table
 */
#define INVERT(idx)			(-(idx) - 1)
#define INDEX(idx)			(((idx) >= 0) ? (idx) : -((idx) + 1))
#define FIELD(rule, dim, idx)	(((idx) >= 0) ? &((rule)[(idx)]).field[(dim)] : &((rule)[-((idx) + 1)]).inversefield[(dim)])

#define WORST_COST		2147483647		/**< (2^31 - 1) */

#endif	/* __FISTREE_INTERNAL_H__ */
