/*
    Copyright (C) 2001,2002,2009,2012 Bernhard R. Link <brlink@debian.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Please tell me, if you find errors or mistakes.

Based on parts of the GNU C Library:

   Common code for file-based database parsers in nss_files module.
   Copyright (C) 1996, 1997, 1998, 1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
*/
#define _GNU_SOURCE 1
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <nss.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <grp.h>

#include "s_config.h"

enum nss_status _nss_extrausers_setgrent(void);
enum nss_status _nss_extrausers_endgrent(void);
enum nss_status _nss_extrausers_getgrent_r(struct group *gr, char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_extrausers_getgrnam_r(const char *name, struct group *gr, char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_extrausers_getgrgid_r(const gid_t gid, struct group *gr, char *buffer, size_t buflen, int *errnop);

static FILE *groupsfile = NULL;

/* from clib/nss */
static inline char **parse_list(char *line, char *data, size_t datalen, int *errnop) {
	char *eol, **list, **p;

	if (line >= data && line < (char *) data + datalen)
		/* Find the end of the line buffer, we will use the space in DATA after
		 *        it for storing the vector of pointers.  */
		eol = strchr(line, '\0') + 1;
	else
		/* LINE does not point within DATA->linebuffer, so that space is
		 *        not being used for scratch space right now.  We can use all of
		 *               it for the pointer vector storage.  */
		eol = data;
	/* Adjust the pointer so it is aligned for storing pointers.  */
	eol += __alignof__(char *) - 1;
	eol -= (eol - (char *)0) % __alignof__(char *);
	/* We will start the storage here for the vector of pointers.  */
	list = (char **)eol;

	p = list;
	while (1)
	{
		char *elt;

		if ((size_t) ((char *)&p[1] - (char *)data) > datalen)
		{
			/* We cannot fit another pointer in the buffer.  */
			*errnop = ERANGE;
			return NULL;
		}
		if (*line == '\0')
			break;

		/* Skip leading white space.  This might not be portable but useful.  */
		while (isspace(*line))
			++line;

		elt = line;
		while (1) {
			if (*line == '\0' || *line == ',' ) {
				/* End of the next entry.  */
				if (line > elt)
					/* We really found some data.  */
					*p++ = elt;

				/* Terminate string if necessary.  */
				if (*line != '\0')
					*line++ = '\0';
				break;
			}
			++line;
		}
	}
	*p = NULL;

	return list;
}

#define TOCOLON(p, h) { \
	while (*p && *p != ':') \
		p++; \
	h=p; \
	if (*p) \
		p++; \
	*h='\0'; h--; \
	while (isspace(*h)) { \
		*h='\0'; h--; \
	} \
}

static inline enum nss_status g_search(FILE *stream, const char *name, const gid_t gid, struct group *gr, int *errnop, char *buffer, size_t buflen) {
	char *p, *h;
	gid_t t_gid;
	char *t_name, *t_passwd;
	char **t_mem;
	off_t last_position;

	if (gid != 0 && gid < MINGID) {
		*errnop = ENOENT;
		return NSS_STATUS_NOTFOUND;
	}

	last_position = ftello(stream);
	flockfile(stream);
	while (1)  {
		buffer[buflen - 1] = '\xff';
		p = fgets_unlocked(buffer, buflen, stream);
		if (p == NULL) {
			if (feof_unlocked(stream)) {
				funlockfile(stream);
				*errnop = ENOENT;
				return NSS_STATUS_NOTFOUND;
			} else {
				funlockfile(stream);
				*errnop = errno;
				return NSS_STATUS_UNAVAIL;
			}
		}
		h = index(p, '\n');
		if (buffer[buflen - 1] != '\xff' || h == NULL) {
			funlockfile(stream);
			*errnop = ERANGE;
			fseeko(stream, last_position, SEEK_SET);
			return NSS_STATUS_TRYAGAIN;
		}
		while (isspace(*h) && h != p) {
			*h = '\0';
			h--;
		}
		/* Ignore comments */
		if (*p == '#')
			continue;

		/* extract name */
		while (isspace(*p))
			++p;
		/* Ignore empty lines */
		if (*p == '\0')
			continue;
		t_name = p;
		TOCOLON(p, h);
		if (name && strcmp(name, t_name) != 0)
			continue;
		/* passwd (should be "x" or "" or something...) */
		while (isspace(*p))
			++p;
		t_passwd = p;
		TOCOLON(p, h);
		/* extract gid */
		t_gid = strtol(p, &h, 10);
		if (*h != ':') {
			funlockfile(stream);
			*errnop = 0;
			return NSS_STATUS_UNAVAIL;
		}
		if (gid != 0 && gid != t_gid) {
			continue;
		}
		if (t_gid < MINGID) {
			continue;
		}
		p = h;
		/* extract members */
		h++; // Over ':'
		t_mem = parse_list(h, buffer, buflen, errnop);
		if (t_mem == NULL){
			funlockfile(stream);
			fseeko(stream, last_position, SEEK_SET);
			return NSS_STATUS_TRYAGAIN;
		}
		funlockfile(stream);
		*errnop = 0;
		gr->gr_name = t_name;
		gr->gr_passwd = t_passwd;
		gr->gr_gid = t_gid;
		gr->gr_mem = t_mem;
		return NSS_STATUS_SUCCESS;
	}
}


enum nss_status _nss_extrausers_setgrent(void) {
	groupsfile = fopen(GROUPSFILE, "r");
	if (groupsfile == NULL)
		return NSS_STATUS_UNAVAIL;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_extrausers_endgrent(void) {
	if (groupsfile != NULL) {
		fclose(groupsfile);
		groupsfile = NULL;
	}
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_extrausers_getgrent_r(struct group *gr, char *buffer, size_t buflen, int *errnop) {
	*errnop = 0;
	if (groupsfile == NULL)
		return NSS_STATUS_UNAVAIL;

	return g_search(groupsfile, NULL, 0, gr, errnop, buffer, buflen);
}


enum nss_status _nss_extrausers_getgrnam_r(const char *name, struct group *gr, char *buffer, size_t buflen, int *errnop) {
	enum nss_status e;
	FILE *f;

	*errnop = 0;

	if (gr == NULL || name == NULL)
		return NSS_STATUS_UNAVAIL;

	f = fopen(GROUPSFILE, "r");
	if (f == NULL) {
		*errnop = errno;
		return NSS_STATUS_UNAVAIL;
	}

	e = g_search(f, name, 0, gr, errnop, buffer, buflen);
	fclose(f);
	return e;
}

enum nss_status _nss_extrausers_getgrgid_r(const gid_t gid, struct group *gr, char *buffer, size_t buflen, int *errnop) {
	enum nss_status e;
	FILE *f;
	*errnop = 0;
	if (gr == NULL)
		return NSS_STATUS_UNAVAIL;
	if (gid == 0 || gid < MINGID)
		return NSS_STATUS_NOTFOUND;

	f = fopen(GROUPSFILE, "r");
	if (f == NULL) {
		*errnop = errno;
		return NSS_STATUS_UNAVAIL;
	}

	e = g_search(f, NULL, gid, gr, errnop, buffer, buflen);
	fclose(f);
	return e;
}
