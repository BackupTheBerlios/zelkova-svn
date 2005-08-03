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
 * @file tftree.h
 * Declares basic structures and defines to be used to construct the (2,4)-tree
 */

#ifndef __FISTREE_TFTREE_H__
#define __FISTREE_TFTREE_H__

/* (2,4)-tree exists in order to solve the RL(Range Location) problem of
 * FIS-tree. Each node of (2,4)-tree is aligned for 32 bytes so that L2 cache
 * effect is expressed.
 */

typedef struct tfnode {
	void			*LLC;	/* if (k < LKEY) */
	void			*LMC;	/* else if (k < MKEY) */
	void			*RMC;	/* else if (k < RKEY) */
	void			*RRC;	/* else */

	uint32_t		LKEY;	/* left key */
	uint32_t		MKEY;	/* middle key */
	uint32_t		RKEY;	/* right key */

	uint32_t		flag;	/* flag */
} tfnode_t;

#define TFNODE_FLAG_NULL	0x00000001
#define TFNODE_FLAG_LEAF	0x00000002
#define TFNODE_FLAG_0KEY	0x00000010
#define TFNODE_FLAG_1KEY	0x00000020
#define TFNODE_FLAG_2KEY	0x00000040
#define TFNODE_FLAG_3KEY	0x00000080
#define TFNODE_FLAG_NKEY	0x000000f0

#define TFNODE_ISNULL(node)	((node)->flag & TFNODE_FLAG_NULL)
#define TFNODE_ISLEAF(node)	((node)->flag & TFNODE_FLAG_LEAF)

#define TFNODE_NEXTCHILD(node, key) (((key) < (node)->LKEY) ? (node)->LLC \
									: (((node)->flag & TFNODE_FLAG_1KEY) ? (node)->LMC \
									: (((key) < (node)->MKEY) ? (node)->LMC \
									: (((node)->flag & TFNODE_FLAG_2KEY) ? (node)->RMC \
									: (((key) < (node)->RKEY) ? (node)->RMC \
									: (node)->RRC)))))

#define TFNODE_HASKEY(node, key)	(((key) == (node)->LKEY) \
									|| (((node)->flag & (TFNODE_FLAG_2KEY | TFNODE_FLAG_3KEY)) && (key) == (node)->MKEY) \
									|| (((node)->flag & (TFNODE_FLAG_3KEY)) && (key) == (node)->RKEY))

tfnode_t *tftree_make(tfnode_t *root, uint32_t *keys, int nelem);
tfnode_t *tftree_insert(tfnode_t *root, uint32_t key);

#endif	/* __FISTREE_TFTREE_H__ */
