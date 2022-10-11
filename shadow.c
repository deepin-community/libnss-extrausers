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

#include <stdlib.h>
#include <stdio.h>
#include <nss.h>
#include <string.h>
#include <shadow.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include "s_config.h"

enum nss_status _nss_extrausers_getspent_r(struct spwd *, char *, size_t, int *);
enum nss_status _nss_extrausers_getspnam_r(const char *, struct spwd *, char *, size_t, int *);
enum nss_status _nss_extrausers_setspent(void);
enum nss_status _nss_extrausers_endspent(void);

static enum nss_status shadow_search(FILE *stream, const char *name, struct spwd *spw, char *buffer, size_t buflen, int *errnop);

enum nss_status _nss_extrausers_getspnam_r(const char *name, struct spwd *spw, char *buffer, size_t buflen, int *errnop) {
	FILE *stream;
	enum nss_status s;

	if (spw == NULL || name == NULL)
	{
		*errnop = EPERM;
		return NSS_STATUS_UNAVAIL;
	}

	stream = fopen(SHADOWFILE, "r");
	if( stream == NULL ) {
		*errnop = errno;
		return NSS_STATUS_UNAVAIL;
	}
	flockfile(stream);
	s = shadow_search(stream, name, spw, buffer, buflen, errnop);
	funlockfile(stream);
	fclose(stream);
	return s;
}

static FILE *shadowfile = NULL;

enum nss_status _nss_extrausers_setspent(void) {

	if (shadowfile != NULL) {
		fclose(shadowfile);
		shadowfile = NULL;
	}
	shadowfile = fopen(SHADOWFILE, "r");
	if (shadowfile == NULL) {
		return NSS_STATUS_UNAVAIL;
	}

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_extrausers_endspent(void) {

	if (shadowfile != NULL) {
		fclose(shadowfile);
		shadowfile = NULL;
	}
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_extrausers_getspent_r(struct spwd *spw, char *buffer, size_t buflen, int *errnop) {
	enum nss_status s;

	if (spw == NULL) {
		*errnop = EPERM;
		return NSS_STATUS_UNAVAIL;
	}

	if (shadowfile == NULL) {
		shadowfile = fopen(SHADOWFILE, "r");
		if( shadowfile == NULL ) {
			*errnop = errno;
			return NSS_STATUS_UNAVAIL;
		}
	}
	flockfile(shadowfile);
	s = shadow_search(shadowfile, NULL, spw, buffer, buflen, errnop);
	funlockfile(shadowfile);
	return s;
}

static enum nss_status shadow_search(FILE *stream, const char *name, struct spwd *spw, char *buffer, size_t buflen, int *errnop) {
#define CHECKCOLON if(*p != ':' ) { \
				*errnop = 0; \
				return NSS_STATUS_UNAVAIL; \
			} else { \
			*(p++) = '\0'; \
			}
#define TOCOLON(p, h) { while( *p && *p != ':' ) p++; CHECKCOLON }
	char *p, *h;
	char *t_namp, *t_pwdp;
	long int t_lstchg, t_min, t_max, t_warn, t_inact, t_expire;
	unsigned long int t_flag;
	while( 1 ) {
		buffer[buflen - 1] = '\xff';
		p = fgets_unlocked(buffer, buflen, stream);
		if( p == NULL ) {
			if( feof_unlocked(stream) ) {
				*errnop = ENOENT;
				return NSS_STATUS_NOTFOUND;
			} else {
				*errnop = errno;
				return NSS_STATUS_UNAVAIL;
			}
		}
		h = index(p, '\n');
		if( buffer[buflen - 1] != '\xff' || h == NULL ) {
			*errnop = ERANGE;
			return NSS_STATUS_TRYAGAIN;
		}
		while( isspace(*h) && h >= p) {
			*h = '\0';
			h--;
		}
		/* Ignore comments */
		if( *p == '#')
			continue;

		/* extract name */
		while (isspace(*p))
			++p;
		/* Ignore empty lines */
		if (*p == '\0')
			continue;
		t_namp = p;
		TOCOLON(p, h);
		if( name && strcmp(name, t_namp) != 0 )
			continue;
		/* passwd */
		while (isspace(*p))
			++p;
		t_pwdp = p;
		TOCOLON(p, h);
		/* extract day of last changes */
		#define PARSE_NUMBER(var) \
			if (*p == ':') { \
				var = -1; \
				*(p++) = '\0'; \
		       	} else { \
				var = strtol(p, &h, 10); \
				p = h; \
				CHECKCOLON; \
			}
		PARSE_NUMBER(t_lstchg);
		/* extract min */
		PARSE_NUMBER(t_min);
		/* extract max */
		PARSE_NUMBER(t_max);
		/* extract days of warning */
		PARSE_NUMBER(t_warn);
		/* extract days of inactivity */
		PARSE_NUMBER(t_inact);
		/* extract day of expire */
		PARSE_NUMBER(t_expire);
		#undef PARSE_NUMBER
		/* extract reserved flags */
		t_flag = strtoul(p, &h, 10);
		if( *h != '\0' ) {
			*errnop = 0;
			return NSS_STATUS_UNAVAIL;
		} else if (p == h)
			t_flag = -1;
		*errnop = 0;
		spw->sp_namp = t_namp;
		spw->sp_pwdp = t_pwdp;
		spw->sp_lstchg = t_lstchg;
		spw->sp_min = t_min;
		spw->sp_max = t_max;
		spw->sp_warn = t_warn;
		spw->sp_inact = t_inact;
		spw->sp_expire = t_expire;
		spw->sp_flag = t_flag;
		return NSS_STATUS_SUCCESS;
	}
}
