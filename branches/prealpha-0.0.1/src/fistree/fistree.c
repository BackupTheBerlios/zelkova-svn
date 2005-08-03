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

/** @file fistree.c
 * Manages FIS-tree modules
 */

#define __NO_VERSION__

#include <linux/types.h>			/* size_t */
#include <linux/slab.h>				/* kmalloc */

#include "fistree.h"
#include "tftree.h"
#include "internal.h"


typedef union {
	void		*next;		/* next node */
	tfnode_t	t;			/* 32 bytes item */
	fisnode_t	f;			/* 32 bytes item */
} afree_t;


static tfnode_t *fistree_makeRL(fisrule_t *rule, int *proj, int dim, int maxdim);
static int *fistree_makenextproj(fisrule_t *rule, int *proj, int dim, uint32_t begin, uint32_t end);
static tfnode_t *fistree_setfistree(fisrule_t *rule, int *proj, int dim, int maxdim, uint32_t begin, uint32_t end, tfnode_t *node, fisnode_t *rootf);
static void fistree_cleanRL(tfnode_t *node);
static void fistree_cleanfistree(fisnode_t *node);
static void ruleset_clean(fisruleset_t *set);


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static inline int interval_include_range(fistree_interval_t *interval, uint32_t begin, uint32_t end)
 * @brief  Determine whether (begin, end) range is included within interval
 * @param  interval: 
 * @param  begin:
 * @param  end:
 * @return <0 or >=0
 * @date   29 Jul, 2005
 * @see    fistree_clean(), fistree_makeRL()
 *
 *  Determine whether (begin, end) range is included within the given interval.
 *
 *---------------------------------------------------------------------------
 */
static inline int interval_include_range(fistree_interval_t * interval, uint32_t begin, uint32_t end)
{
	fistree_range_t		*range;
	int					nrange;
	int					i;

	switch (interval->type) {
	case INTERVAL_ANYTOANY:
		return (begin == 0 && end == 0);

	case INTERVAL_RANGEONE:
		return ((interval->r.one.begin <= begin) && ((interval->r.one.end == 0) || (interval->r.one.end >= end && end > 0)));
	case INTERVAL_RANGESET:
		range = interval->r.set.table;
		nrange = interval->r.set.nelem;

		for (i = 0; i < nrange; i++) {
			if ((range[i].begin <= begin) && ((range[i].end == 0) || (range[i].end >= end && end > 0))) {
				break;
			}
		}

		return (i < nrange);
	default:
		return 0;	/* FATAL: unreachable here */
	}
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     void *fistree_make(fisrule_t *rule, int maxdim, int nelem)
 * @brief  Make a FIS-tree and a (2,4)-tree
 * @param  fisrule_t *rule: 
 * @param  int maxdim:
 * @param  int nelem:
 * @return Returns a pointer to FIS-tree if normal, NULL if abnormal.
 * @date   25 Jul, 2005
 * @see    fistree_clean(), fistree_makeRL()
 *
 *  Make a FIS-tree and a (2,4)-tree which deals with the RL problem.
 *
 *---------------------------------------------------------------------------
 */
void *fistree_make(fisrule_t *rule, int maxdim, int nelem)
{
	tfnode_t		*rootRL;
	int				*proj;
	int				i, j;

	if (nelem == 0) {
		return NULL;
	}

	/* Make a initial projection rule table.
	 * If there exists a rule with a negative cost value, we skip the rule
	 * because it is a pseudo rule. We allocate memories by a double size
	 * of nelem in order to deal with bidirectional rules.
	 */

/*    KMALLOCS(proj, int *, sizeof(int) * (nelem * 2 + 1));*/
	proj = (int *)kmalloc(sizeof(int) * (nelem * 2 + 1), GFP_ATOMIC);
	if (proj == NULL) {
		return NULL;
	}

	j = 1;

	/* Static rule has a value range from 1 to (2^31 - 1) */

	for (i = 0; i < nelem; i++) {
		if (rule[i].cost > 0) {
			proj[j++] = i;
			proj[j++] = INVERT(i);
		}
	}

	proj[0] = (j - 1);

	/* Make a FIS-tree and get a root of (2,4)-tree for the RL problem. */
	rootRL = fistree_makeRL(rule, proj, 0, maxdim);

	/* Remove the first projection rule table */
	kfree(proj);

	return (void *)rootRL;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static fisnode_t *fistree_makefistree(fisrule_t *rule, int *proj, int dim, int maxdim, uint32_t begin, uint32_t end, fisnode_t *parent)
 * @brief  Make a FIS-tree node within the given range.
 * @param  fisrule_t *rule: 
 * @param  int *proj:
 * @param  int dim:
 * @param  int maxdim:
 * @param  uint32_t begin:
 * @param  uint32_t end:
 * @param  fisnode_t parent:
 * @return Returns a pointer to the FIS-tree
 * @date   29 Jul, 2005
 * @see    fistree_make(), fistree_makeRL()
 *
 *  Make a FIS-tree node within the given range.
 *
 *---------------------------------------------------------------------------
 */
static fisnode_t *fistree_makefistree(fisrule_t *rule, int *proj, int dim, int maxdim, uint32_t begin, uint32_t end, fisnode_t *parent)
{
	fisnode_t		*node;
	int				*nextproj;

	/* Get a new node */
	if ((node = (fisnode_t *)kmalloc(sizeof(fisnode_t), GFP_ATOMIC)) == NULL) {
		return NULL;
	}

	/* Get a rule table to be projected onto the next dimension. */
	nextproj = fistree_makenextproj(rule, proj, dim, begin, end);
	if (nextproj == NULL) {
		kfree(node);
	}

	/* If rule tables exist, record the highest cost among them. */

	if (nextproj[0] > 0) {
		node->cost = node->basecost = rule[INDEX(nextproj[1])].cost;

		/* If it is not the top dimension,
		 * make a tree for the RL problem of next dimension.
		 */
		if (dim == maxdim) {
			node->rule = node->baserule = &rule[INDEX(nextproj[1])];
			rule[INDEX(nextproj[1])].refcnt++;
		}
		else {
			node->nextRL = fistree_makeRL(rule, nextproj, dim + 1, maxdim);
		}
	}
	else {
		node->cost = node->basecost = WORST_COST;
	}

	/* Deallocate memories of nextproj since it is not needed any more. */
	kfree(nextproj);

	/* Assign the parent node pointer */
	if (parent != NULL) {
		node->parent = parent;
		parent->refcnt++;
	}
	else {
		node->parent = NULL;
	}

	/* Increase the reference count */
	node->refcnt++;

	return node;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static int *fistree_makenextproj(fisrule_t *rule, int *proj, int dim, uint32_t begin, uint32_t end)
 * @brief  Make a rule table to be projected onto the next dimension
 * @param  fisrule_t *rule: 
 * @param  int *proj:
 * @param  int dim:
 * @param  uint32_t begin:
 * @param  uint32_t end:
 * @return Returns a pointer to the next projection number.
 * @date   29 Jul, 2005
 * @see    fistree_make(), fistree_makefistree()
 *
 *  Make a rule table to be projected onto the next dimension.
 *
 *---------------------------------------------------------------------------
 */
static int *fistree_makenextproj(fisrule_t *rule, int *proj, int dim, uint32_t begin, uint32_t end)
{
	int			*nextproj;
	int			nextsize = 0;
	int			i, j;

	/* Phase 1: Count whole range */

	for (i = 1; i <= proj[0]; i++) {
		if (interval_include_range(FIELD(rule, dim, proj[i]), begin, end)) {
			nextsize++;
		}
	}

	/* Make a projection rule table */
	if ((nextproj = (int *)kmalloc(sizeof(int) * (nextsize + 1), GFP_ATOMIC)) == NULL) {
		return NULL;
	}

	nextproj[0] = nextsize;
	j = 1;

	/* If matching rules do not exist, just return. */
	if (nextsize == 0) {
		return nextproj;
	}

	/* Phase 2: Fill out whole table to be projected. */
	for (i = 1; i <= proj[0]; i++) {
		if (interval_include_range(FIELD(rule, dim, proj[i]), begin, end)) {
			nextproj[j++] = proj[i];
		}
	}

	return nextproj;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static tfnode_t *fistree_makeRL(fisrule_t *rule, int *proj, int dim, int maxdim)
 * @brief  Make a (2,4)-tree
 * @param  fisrule_t *rule: 
 * @param  int *proj:
 * @param  int dim:
 * @param  int maxdim:
 * @return Returns a pointer to the root of (2,4)-tree
 * @date   28 Jul, 2005
 * @see    fistree_make()
 *
 *  Make a FIS-tree and a (2,4)-tree which deals with the RL problem.
 *
 *---------------------------------------------------------------------------
 */
static tfnode_t *fistree_makeRL(fisrule_t *rule, int *proj, int dim, int maxdim)
{
	fisnode_t	*rootf;
	tfnode_t	*rootRL = NULL, *hold;
	fistree_interval_t	*interval;
	uint32_t	*point;
	int			npoint;
	int			i;

	/* Construct the FIS-tree root */
	rootf = fistree_makefistree(rule, proj, dim, maxdim, 0, 0, NULL);
	if (rootf == NULL) {
		return NULL;
	}

	rootf->refcnt = 0;

	/* Make a (2,4)-tree in order to solve RL(Range Location) problems */
	for (i = 1; i <= proj[0]; i++) {
		interval = FIELD(rule, dim, proj[i]);

		if ((interval->type & INTERVAL_ANYTOANY)) {
			/* ANY ~ ANY */
			continue;
		}
		else if ((interval->type & INTERVAL_RANGEONE)) {
			/* Deals with one range */
			point = &interval->r.one.begin;
			npoint = 2;
		}
		else if ((interval->type & INTERVAL_RANGESET)) {
			/* Deals with a set of range */
			point = (uint32_t *)interval->r.set.table;
			npoint = (int)interval->r.set.nelem << 1;
		}
		else {
			return NULL;
		}

		if ((hold = tftree_make(rootRL, point, npoint)) != NULL) {
			rootRL = hold;
		}
		else {
			/* Allocation failed. */
			fistree_cleanRL(rootRL);

			return NULL;
		}
	}

	/* If it is a NULL (2,4)-tree */
	if (rootRL == NULL) {
		rootRL = tftree_insert(NULL, 0);

		if (rootRL == NULL) {
			fistree_cleanfistree(rootf);

			return NULL;
		}

		rootRL->LLC = (void *)rootf;
		rootf->refcnt++;

		return rootRL;
	}

	/* Do fistree_setfistree() at all leaves of next dimension's projection */

	return fistree_setfistree(rule, proj, dim, maxdim, 0, 0, rootRL, rootf);
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static tfnode_t *fistree_setfistree(fisrule_t *rule, int *proj, int dim, int maxdim, uint32_t begin, uint32_t end, tfnode_t *node, fisnode_t *rootf)
 * @brief  Assign each leaf of FIS-tree into each leaf of (2,4)-tree
 * @param  fisrule_t *rule: 
 * @param  int *proj:
 * @param  int dim:
 * @param  int maxdim:
 * @param  uint32_t begin:
 * @param  uint32_t end:
 * @param  tfnode_t *node:
 * @param  fisnode_t *rootf:
 * @return Returns a pointer to the root of (2,4)-tree
 * @date   03 Aug, 2005
 * @see    fistree_makeRL()
 *
 *  Assign each leaf of FIS-tree into each leaf of (2,4)-tree
 *
 *---------------------------------------------------------------------------
 */
static tfnode_t *fistree_setfistree(fisrule_t *rule, int *proj, int dim, int maxdim, uint32_t begin, uint32_t end, tfnode_t *node, fisnode_t *rootf)
{
	if (TFNODE_ISLEAF(node)) {
		/* Connect each leaf of FIS-tree into each leaf of (2,4)-tree. */

		if ((node->flag & TFNODE_FLAG_1KEY)) {
			node->LLC = fistree_makefistree(rule, proj, dim, maxdim, begin, node->LKEY, rootf);
			node->LMC = fistree_makefistree(rule, proj, dim, maxdim, node->LKEY, end, rootf);
		}
		else if ((node->flag & TFNODE_FLAG_2KEY)) {
			node->LLC = fistree_makefistree(rule, proj, dim, maxdim, begin, node->LKEY, rootf);
			node->LMC = fistree_makefistree(rule, proj, dim, maxdim, node->LKEY, node->MKEY, rootf);
			node->RMC = fistree_makefistree(rule, proj, dim, maxdim, node->MKEY, end, rootf);
		}
		else {
			node->LLC = fistree_makefistree(rule, proj, dim, maxdim, begin, node->LKEY, rootf);
			node->LMC = fistree_makefistree(rule, proj, dim, maxdim, node->LKEY, node->MKEY, rootf);
			node->RMC = fistree_makefistree(rule, proj, dim, maxdim, node->MKEY, node->RKEY, rootf);
			node->RRC = fistree_makefistree(rule, proj, dim, maxdim, node->RKEY, end, rootf);
		}
	}
	else {
		/* If it isn't a leaf, do setfistree() with itself recursively. */

		if ((node->flag & TFNODE_FLAG_1KEY)) {
			fistree_setfistree(rule, proj, dim, maxdim, begin, node->LKEY, node->LLC, rootf);
			fistree_setfistree(rule, proj, dim, maxdim, node->LKEY, end, node->LMC, rootf);
		}
		else if ((node->flag & TFNODE_FLAG_2KEY)) {
			fistree_setfistree(rule, proj, dim, maxdim, begin, node->LKEY, node->LLC, rootf);
			fistree_setfistree(rule, proj, dim, maxdim, node->LKEY, node->MKEY, node->LMC, rootf);
			fistree_setfistree(rule, proj, dim, maxdim, node->MKEY, end, node->RMC, rootf);
		}
		else {
			fistree_setfistree(rule, proj, dim, maxdim, begin, node->LKEY, node->LLC, rootf);
			fistree_setfistree(rule, proj, dim, maxdim, node->LKEY, node->MKEY, node->LMC, rootf);
			fistree_setfistree(rule, proj, dim, maxdim, node->MKEY, node->RKEY, node->RMC, rootf);
			fistree_setfistree(rule, proj, dim, maxdim, node->RKEY, end, node->RRC, rootf);
		}
	}

	return node;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static void fistree_cleanfistree(fisnode_t *node)
 * @brief  Deallocate memories of the whole FIS-tree
 * @param  node: The node to be deallocated
 * @return NONE
 * @date   29 Jul, 2005
 * @see    fistree_clean()
 *
 *  Deallocate memories of the whole FIS-tree.
 *
 *---------------------------------------------------------------------------
 */
static void fistree_cleanfistree(fisnode_t *node)
{
	/* Remove the parent node */
	if (node->parent != NULL) {
		fistree_cleanfistree(node->parent);
	}

	node->refcnt--;

	/* Remove myself */
	if (node->refcnt == 0) {
		if (node->nextRL != NULL) {
			fistree_clean(node->nextRL);
		}

		if (node->delta != NULL) {
			ruleset_clean(node->delta);
		}

		kfree(node);
	}
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static void fistree_cleanRL(tfnode_t *node)
 * @brief  Destroy the whole (2,4)-tree
 * @param  node: The node of (2,4)-tree to be destroyed
 * @return NONE
 * @date   29 Jul, 2005
 * @see    fistree_clean()
 *
 *  Destroy the whole (2,4)-tree
 *
 *---------------------------------------------------------------------------
 */
static void fistree_cleanRL(tfnode_t *node)
{
	if (TFNODE_ISLEAF(node)) {

		/* Remove each node of FIS-trees */

		if (node->LLC != NULL) {
			fistree_cleanfistree((fisnode_t *)node->LLC);
		}

		if (node->LMC != NULL) {
			fistree_cleanfistree((fisnode_t *)node->LMC);
		}

		if (node->RMC != NULL) {
			fistree_cleanfistree((fisnode_t *)node->RMC);
		}

		if (node->RRC != NULL) {
			fistree_cleanfistree((fisnode_t *)node->RRC);
		}
	}
	else {
		/* Remove each child of myself */
		if (node->LLC != NULL) {
			fistree_cleanRL((tfnode_t *)node->LLC);
		}

		if (node->LMC != NULL) {
			fistree_cleanRL((tfnode_t *)node->LMC);
		}

		if (node->RMC != NULL) {
			fistree_cleanRL((tfnode_t *)node->RMC);
		}

		if (node->RRC != NULL) {
			fistree_cleanRL((tfnode_t *)node->RRC);
		}
	}

	/* Finally remove myself */
	kfree(node);
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     void fistree_clean(void *node)
 * @brief  Deallocate memories of the whole (2,4)-tree
 * @param  node: The node to be deallocated
 * @return NONE
 * @date   28 Jul, 2005
 * @see    fistree_make()
 *
 *  Deallocate memories of the whole (2,4)-tree for the FIS-tree and
 *  the RL problem
 *
 *---------------------------------------------------------------------------
 */
void fistree_clean(void *node)
{
	if (TFNODE_ISNULL((tfnode_t *)node)) {
		if (((tfnode_t *)node)->LLC != NULL) {
			fistree_cleanfistree((fisnode_t *)((tfnode_t *)node)->LLC);

			/* Remove myself */

			kfree(node);
		}
		else {
			fistree_cleanRL((tfnode_t *)node);
		}
	}
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     fisrule_t *fistree_query(void *root, uint32_t value[], int maxdim)
 * @brief  Query rule with an input value
 * @param  root: Root of FIS-tree
 * @param  value: Value to be used with query
 * @param  maxdim: Maximum dimension of FIS-tree
 * @return NONE
 * @date   28 Jul, 2005
 * @see    NONE
 *
 *  Query rule in FIS-tree with an input value
 *
 *---------------------------------------------------------------------------
 */
fisrule_t *fistree_query(void *root, uint32_t value[], int maxdim)
{
	fisrule_t		*rule = NULL;
	fisnode_t		*parent[MAX_FISTREE_DIM] = { NULL };
	fisnode_t		*leaf;
	tfnode_t		*RL;
	int				cost = WORST_COST;
	int				dim = 0;

	RL = (tfnode_t *)root;

	while (dim >= 0) {
		if (parent[dim] != NULL) {
			/* Query a rule in FIS-tree with this node, if the parent stack is
			 * not empty.
			 */

			leaf = parent[dim];
			parent[dim] = NULL;

			if (leaf->cost < cost) {
				if (dim == maxdim) {
					cost = leaf->cost;
					rule = leaf->rule;
					RL = NULL;
					dim--;
				}
				else {
					RL = leaf->nextRL;
					dim++;
				}
			}
			else {
				RL = NULL;
				dim--;
			}
		}
		else if (RL == NULL) {
			/* No more RL problems, then go on to the previous dimension. */
			dim--;
		}
		else if (TFNODE_ISNULL(RL)) {
			/* If (2,4)-tree is NULL, that means there exists the FIS-tree node
			 * of ANY ~ ANY.
			 */

			leaf = (fisnode_t *)RL->LLC;

			if (leaf->cost < cost) {
				if (dim == maxdim) {
					cost = leaf->cost;
					rule = leaf->rule;
					RL = NULL;
					dim--;
				}
				else {
					RL = leaf->nextRL;
					dim++;
				}
			}
			else {
				RL = NULL;
				dim--;
			}
		}
		else {
			/* Now we solve the RL(Range Location) problem. */
			while (!TFNODE_ISLEAF(RL)) {
				RL = TFNODE_NEXTCHILD(RL, value[dim]);
			}

			leaf = (fisnode_t *)TFNODE_NEXTCHILD(RL, value[dim]);

			/* Record parent node on the parent stack */

			parent[dim] = leaf->parent;

			/* Query a rule into FIS-tree */

			if (leaf->cost < cost) {
				if (dim == maxdim) {
					cost = leaf->cost;
					rule = leaf->rule;
				}
				else {
					RL = leaf->nextRL;
					dim++;
				}
			}
		}

	}/* while(dim) */

	return rule;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static void ruleset_clean(fisruleset_t *set)
 * @brief  Destroy the input ruleset
 * @param  set: The ruleset to be destroyed
 * @return NONE
 * @date   29 Jul, 2005
 * @see    NONE
 *
 *  Destroy the input ruleset
 *
 *---------------------------------------------------------------------------
 */
static void ruleset_clean(fisruleset_t *set)
{
	fisruleset_t	*hold = set;

	while (hold != NULL) {
		set = hold->next;

		kfree(hold);

		hold = set;
	}
}
