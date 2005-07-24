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

#include <stdio.h>		/* stderr */
#include <stdlib.h>		/* EXIT_FAILURE */
#include <unistd.h>		/* getopt() */

static void usage(char *progname);
static void procfile(char *name, char *file);


/*!
 *---------------------------------------------------------------------------
 *
 * \fn int main(int argc, char *argv[])
 * \brief The main function of zktables utility
 * \param int argc
 * \param char *argv[]
 * \date 24 Jul, 2005
 *
 *  If an user executes this utility, she starts from this function.
 *  Gets commands, arguments, and options with zelkova rules.
 *
 *---------------------------------------------------------------------------
 */

int main(int argc, char *argv[])
{
	int c;

	if (argc < 2)
		usage(argv[0]);

	while ((c = getopt(argc, argv, "fh")) != -1) {
		switch (c) {
			case '?':
				usage(argv[0]);
				break;
			case 'f':
				procfile(argv[0], optarg);
			case 'h':
				usage(argv[0]);
				break;
			default:
				break;
		}
	}

	return 0;
}


/*!
 *---------------------------------------------------------------------------
 *
 * \fn static void usage(char *progname)
 * \brief Shows a brief usage message
 * \param char *progname
 * \date 24 Jul, 2005
 *
 *  If an user passes too few argumets to this utility,
 *  shows a brief usage message to the user.
 *
 *---------------------------------------------------------------------------
 */

static void usage(char *progname)
{
	fprintf(stderr, "USAGE: %s [options] [command] [arguments]\n", progname);
	exit(EXIT_FAILURE);
}


/*!
 *---------------------------------------------------------------------------
 *
 * \fn static void procfile(char *name, char *file)
 * \brief Processes the input rule file
 * \param char *name
 * \param char *file
 * \date 24 Jul, 2005
 *
 *  Processes the input rule file
 *
 *---------------------------------------------------------------------------
 */

static void procfile(char *name, char *file)
{
/*    (void) opendevice();*/

/*    initparse();*/
/*    zk_parsefile();*/
}

