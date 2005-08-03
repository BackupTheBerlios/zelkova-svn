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

/** @file tftree.c
 * Manages (2,4)-tree modules
 */

#define __NO_VERSION__

#include <linux/types.h>			/* size_t */
#include <linux/slab.h>				/* kmalloc */

#include "fistree.h"
#include "tftree.h"

static void tftree_clean(tfnode_t *root);

/**
 *---------------------------------------------------------------------------
 *
 * @fn     tfnode_t *tftree_parent(tfnode_t *root, tfnode_t *node)
 * @brief  Return the parent node of input node
 * @param  root: root node of (2,4)-tree
 * @param  node: input node
 * @return return the parent node if success, return the leaf node if error.
 * @date   03 Aug, 2005
 * @see    NONE
 *
 *  Return the parent node of input node.
 *
 *---------------------------------------------------------------------------
 */

tfnode_t *tftree_parent(tfnode_t *root, tfnode_t *node)
{
	tfnode_t		*nc;

	while (!TFNODE_ISLEAF(root)) {
		nc = TFNODE_NEXTCHILD(root, node->LKEY);

		if (nc == node) {
			return root;
		}
		else {
			root = nc;
		}
	}

	return root;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     tfnode_t *tftree_merge(tfnode_t *parent, tfnode_t *child)
 * @brief  Merge a child node with only 1 key into the parent node.
 * @param  parent: parent node to be merged
 * @param  child: input child node
 * @return return the merged parent node.
 * @date   03 Aug, 2005
 * @see    NONE
 *
 *  Merge a child node with only 1 key into the parent node.
 *  ('0' valued keys and duplicated keys should not exist.)
 *
 *---------------------------------------------------------------------------
 */

tfnode_t *tftree_merge(tfnode_t *parent, tfnode_t *child)
{
	tfnode_t	*childs[5], *lchild, *rchild;
	uint32_t	keys[4];

	if ((parent->flag & TFNODE_FLAG_0KEY)) {

		parent->LKEY	= child->LKEY;
		parent->LLC		= child->LLC;
		parent->LMC		= child->LMC;

		parent->flag &= ~TFNODE_FLAG_NKEY;
		parent->flag |= ~TFNODE_FLAG_1KEY;
	}
	else if ((parent->flag & TFNODE_FLAG_1KEY)) {
		if (child->LKEY < parent->LKEY) {

			keys[0]	= child->LKEY;
			keys[1]	= parent->LKEY;

			childs[0]	= child->LLC;
			childs[1]	= child->LMC;
			childs[2]	= parent->LMC;
		}
		else {
			/* child->LKEY >= parent->LKEY */

			keys[0]	= parent->LKEY;
			keys[1]	= child->LKEY;

			childs[0]	= parent->LLC;
			childs[1]	= child->LLC;
			childs[2]	= child->LMC;
		}

		/* parent {k0, k1} has c0, c1, and c2 */

		parent->LKEY	= keys[0];
		parent->MKEY	= keys[1];

		parent->LLC	= childs[0];
		parent->LMC	= childs[1];
		parent->RMC	= childs[2];

		parent->flag &= ~TFNODE_FLAG_NKEY;
		parent->flag |= TFNODE_FLAG_2KEY;
	}
	else if ((parent->flag & TFNODE_FLAG_2KEY)) {
		if (child->LKEY < parent->LKEY) {
			/* child->LKEY < parent->LKEY < parent->MKEY */

			keys[0]	= child->LKEY;
			keys[1]	= parent->LKEY;
			keys[2]	= parent->MKEY;

			childs[0]	= child->LLC;
			childs[1]	= child->LMC;
			childs[2]	= parent->LMC;
			childs[3]	= parent->RMC;
		}
		else if (child->LKEY < parent->MKEY) {
			/* parent->LKEY < child->LKEY < parent->MKEY */

			keys[0]	= parent->LKEY;
			keys[1]	= child->LKEY;
			keys[2]	= parent->MKEY;

			childs[0]	= parent->LLC;
			childs[1]	= child->LLC;
			childs[2]	= child->LMC;
			childs[3]	= parent->RMC;
		}
		else {
			/* parent->LKEY < parent->MKEY < child->LKEY */

			keys[0]	= parent->LKEY;
			keys[1]	= parent->MKEY;
			keys[2]	= child->LKEY;

			childs[0]	= parent->LLC;
			childs[1]	= parent->LMC;
			childs[2]	= child->LLC;
			childs[3]	= child->LMC;
		}

		/* parent {k0, k1, k2} have c0, c1, c2, and c3 */

		parent->LKEY	= keys[0];
		parent->MKEY	= keys[1];
		parent->RKEY	= keys[2];

		parent->LLC	= childs[0];
		parent->LMC	= childs[1];
		parent->RMC	= childs[2];
		parent->RRC	= childs[3];

		parent->flag &= ~TFNODE_FLAG_NKEY;
		parent->flag |= TFNODE_FLAG_3KEY;
	}
	else {
		/* If the memory allocation failed, quit this function immediately */

		if ((lchild = (tfnode_t *)kmalloc(sizeof(tfnode_t), GFP_ATOMIC)) == NULL) {
			return parent;
		}

		if ((rchild = (tfnode_t *)kmalloc(sizeof(tfnode_t), GFP_ATOMIC)) == NULL) {
			return parent;
		}

		if (child->LKEY < parent->LKEY) {
			/* child->LKEY < parent->LKEY < parent->MKEY < parent->RKEY */

			keys[0]	= child->LKEY;
			keys[1]	= parent->LKEY;
			keys[2]	= parent->MKEY;
			keys[3]	= parent->RKEY;

			childs[0]	= child->LLC;
			childs[1]	= child->LMC;
			childs[2]	= parent->LMC;
			childs[3]	= parent->RMC;
			childs[4]	= parent->RRC;
		}
		else if (child->LKEY < parent->MKEY) {
			/* parent->LKEY < child->LKEY < parent->MKEY < parent->RKEY */

			keys[0]	= parent->LKEY;
			keys[1]	= child->LKEY;
			keys[2]	= parent->MKEY;
			keys[3]	= parent->RKEY;

			childs[0]	= parent->LLC;
			childs[1]	= child->LLC;
			childs[2]	= child->LMC;
			childs[3]	= parent->RMC;
			childs[4]	= parent->RRC;
		}
		else if (child->LKEY < parent->RKEY) {
			/* parent->LKEY < parent->MKEY < child->LKEY < parent->RKEY */

			keys[0]	= parent->LKEY;
			keys[1]	= parent->MKEY;
			keys[2]	= child->LKEY;
			keys[3]	= parent->RKEY;

			childs[0]	= parent->LLC;
			childs[1]	= parent->LMC;
			childs[2]	= child->LLC;
			childs[3]	= child->LMC;
			childs[4]	= parent->RRC;
		}
		else {
			/* parent->LKEY < parent->MKEY < parent->RKEY < child->LKEY */

			keys[0]	= parent->LKEY;
			keys[1]	= parent->MKEY;
			keys[2]	= parent->RKEY;
			keys[3]	= child->LKEY;

			childs[0]	= parent->LLC;
			childs[1]	= parent->LMC;
			childs[2]	= parent->RMC;
			childs[3]	= child->LLC;
			childs[4]	= child->LMC;
		}

		/* parent {k2}
		 * lchild {k0, k1} has c0, c1, and c2.
		 * rchild {k3} has c3 and c4.
		 */

		lchild->LKEY	= keys[0];
		lchild->MKEY	= keys[1];
		rchild->LKEY	= keys[3];
		parent->LKEY	= keys[2];

		lchild->LLC	= childs[0];
		lchild->LMC	= childs[1];
		lchild->RMC	= childs[2];
		rchild->LLC	= childs[3];
		rchild->LMC	= childs[4];
		parent->LLC	= lchild;
		parent->LMC	= rchild;

		lchild->flag |= TFNODE_FLAG_2KEY;
		rchild->flag |= TFNODE_FLAG_1KEY;
		parent->flag &= ~TFNODE_FLAG_NKEY;
		parent->flag |= TFNODE_FLAG_1KEY;

		parent->MKEY	= 0;
		parent->RKEY	= 0;
		parent->RMC		= NULL;
		parent->RRC		= NULL;

		/* If the parent was a leaf, parent doesn't become a leaf any more.
		 * Newly made lchild and rchild become leaves.
		 */
		if (TFNODE_ISLEAF(parent)) {
			parent->flag &= ~TFNODE_FLAG_LEAF;
			lchild->flag |= TFNODE_FLAG_LEAF;
			rchild->flag |= TFNODE_FLAG_LEAF;
		}
	}

	kfree(child);

	return parent;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     tfnode_t *tftree_insert(tfnode_t *root, uint32_t key)
 * @brief  Add an input key into the (2,4)-tree
 * @param  root: root node of (2,4)-tree
 * @param  key: input key
 * @return return the pointer of root node if success, NULL if error.
 * @date   03 Aug, 2005
 * @see    NONE
 *
 *  Add an input key into the (2,4)-tree.
 *
 *---------------------------------------------------------------------------
 */

tfnode_t *tftree_insert(tfnode_t *root, uint32_t key)
{
	tfnode_t		*hold;

	/* First make a node for a new key */
	if ((hold = (tfnode_t *)kmalloc(sizeof(tfnode_t), GFP_ATOMIC)) == NULL) {
		return NULL;
	}

	hold->LKEY = key;
	hold->flag |= TFNODE_FLAG_1KEY;

	/* If root node is NULL, the node which is just made becomes root node.
	 * If key is 0, current node becomes NULL.
	 */
	if (root == NULL) {
		if (key == 0) {
			hold->flag |= TFNODE_FLAG_NULL;
		}
		else {
			hold->flag |= TFNODE_FLAG_LEAF;
		}

		return hold;
	}

	/* Merge the new node into the whole tree. */
	hold = tftree_merge(tftree_parent(root, hold), hold);

	/* If the current node has only one key, that means this node is just
	 * made with the 'full of room' situation.
	 */
	while ((hold->flag & TFNODE_FLAG_1KEY)) {
		if (hold == root) {
			break;
		}

		/* Merge the new node */
		hold = tftree_merge(tftree_parent(root, hold), hold);
	}

	return root;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     tfnode_t *tftree_node(tfnode_t *root, uint32_t key)
 * @brief  Check if a node which has the input key
 * @param  root: root node of (2,4)-tree
 * @param  key: input key
 * @return return the pointer of node if found, NULL if not found.
 * @date   03 Aug, 2005
 * @see    NONE
 *
 *  Check if a node which has the input key.
 *
 *---------------------------------------------------------------------------
 */

tfnode_t *tftree_node(tfnode_t *root, uint32_t key)
{
	while (root != NULL) {
		if (TFNODE_HASKEY(root, key)) {
			return root;
		}
		else {
			root = TFNODE_NEXTCHILD(root, key);
		}
	}

	return NULL;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     tfnode_t *tftree_make(tfnode_t *root, uint32_t *keys, int nelem)
 * @brief  Add input keys into the (2,4)-tree
 * @param  root: root node of (2,4)-tree
 * @param  keys: input keys
 * @param  nelem: number of keys
 * @return return the root node if success, NULL if error.
 * @date   03 Aug, 2005
 * @see    NONE
 *
 *  Add input keys into the (2,4)-tree.
 *
 *---------------------------------------------------------------------------
 */

tfnode_t *tftree_make(tfnode_t *root, uint32_t *keys, int nelem)
{
	tfnode_t	*hold;
	int			i;

	for (i = 0; i < nelem; i++) {
		if (keys[i] != 0 && tftree_node(root, keys[i]) == NULL) {
			if ((hold = tftree_insert(root, keys[i])) != NULL) {
				root = hold;
			}
			else {
				/* Allocation has failed. */
				tftree_clean(root);

				return NULL;
			}
		}
	}

	return root;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static void tftree_clean(tfnode_t *root)
 * @brief  Delete the whole (2,4)-tree
 * @param  root: root node of (2,4)-tree
 * @return return the root node if success, NULL if error.
 * @date   03 Aug, 2005
 * @see    NONE
 *
 *  Delete the whole (2,4)-tree
 *
 *---------------------------------------------------------------------------
 */

static void tftree_clean(tfnode_t *root)
{

	if (root == NULL) {
		return;
	}

	if (!TFNODE_ISLEAF(root)) {
		tftree_clean(root->LLC);
		tftree_clean(root->LMC);
		tftree_clean(root->RMC);
		tftree_clean(root->RRC);
	}

	kfree(root);
}
