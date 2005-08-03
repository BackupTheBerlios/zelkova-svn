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

/** @file */

#include <stdio.h>		/* stderr */

#include "zktables.h"

#define MAX_RCFILE_LINE		256

/**
 *---------------------------------------------------------------------------
 *
 * @fn char *zk_readline(char *s, size_t *size, FILE *fp, int *line)
 * @brief Reads a line from given rc file of zelkova
 * @param char *s
 * @param size_t *size
 * @param FILE *fp
 * @param int *line
 * @date 24 Jul, 2005
 *
 *  Reads a line from `fp' into the dynamically allocated `s',
 *  increasing `s' if necessary. The ending "\n" or "\r\n" is removed.
 *  If a line ends with "\", this char and the linefeed is removed,
 *  and the next line is read too.
 *
 *---------------------------------------------------------------------------
 */

char *zk_readline(char *s, size_t *size, FILE *fp, int *line)
{
	size_t	offset = 0;
	char	*ch;
	int		c;

	if (!s) {
		s = (char *)malloc(MAX_RCFILE_LINE);
		*size = MAX_RCFILE_LINE;
	}

	while (1) {
		if (fgets(s + offset, *size - offset, fp) == NULL) {
			free ((void **) &s);
			return NULL;
		}

		if ((ch = strchr(s + offset, '\n')) != NULL) {
			(*line)++;
			*ch = 0;

			if (ch > s && *(ch - 1) == '\r') {
				ch--;
				*ch = 0;
			}

			if (ch == s || *(ch - 1) != '\\') {
				return s;
			}

			offset = ch - s - 1;
		}
		else {
			/* We want to know if the char at the current point in the input
			 * stream is EOF. feof() will only tell us if we have already
			 * hit EOF, not if the next character is EOF. So we need to read
			 * in the next character and manually check if it is EOF.
			 */
			c = getc(fp);

			if (c == EOF) {
				/* The last line of fp isn't \n terminated */
				(*line)++;
				return s;
			}
			else {
				ungetc(c, fp);	/* undo our damage */

				offset = *size - 1;	/* overwrite the terminating 0 */
				*size += MAX_RCFILE_LINE;

				realloc ((void **) &s, *size);
			}
		} /* if(ch) */
	} /* while(1) */
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn int zk_parse_rcline(const char *line, zk_buffer_t *token, zk_buffer_t *err)
 * @brief Parses lines of a zelkova rc file 
 * @param const char *line: command to execute
 * @param zk_buffer_t *token: scratch buffer to be used by parser. Caller should free
 *               token->data when finished. This variable exists in order to
 *               avoid allocation and deallocation of a lot of memory if we
 *               are parsing many lines. Caller can pass in the memory to
 *               use, which avoids creation of new space for every call to
 *               this function.
 * @param zk_buffer_t err: where to write error messages
 * @date 24 Jul, 2005
 *
 *  Parses lines of a zelkova rc file.
 *
 *---------------------------------------------------------------------------
 */

int zk_parse_rcline(const char *line, zk_buffer_t *token, zk_buffer_t *err)
{
	int				i, r = -1;
	zk_buffer_t		expn;

	memset (&expn, 0, sizeof(expn));
	expn.data = expn.dptr = (char *)line;
	expn.dsize = strlen(line);

	*err->data = 0;

	ZK_SKIPWS(expn.dptr);

	while (*expn.dptr) {
		if (*expn.dptr == '#') {
			break;	/* This line is a comment */
		}

		/* TODO: extract commands, arguments, and options */
	}

	r = 0;

finish:
	if (expn.destroy) {
		free(&expn.data);
	}

	return r;
}
