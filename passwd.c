/*
    Copyright (C) 2001,2002,2009,2010,2012 Bernhard R. Link <brlink@debian.org>

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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <nss.h>
#include <pwd.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include "s_config.h"

enum nss_status _nss_extrausers_getpwuid_r(uid_t, struct passwd *, char *, size_t, int *);
enum nss_status _nss_extrausers_setpwent(void);
enum nss_status _nss_extrausers_endpwent(void);
enum nss_status _nss_extrausers_getpwnam_r(const char *, struct passwd *, char *, size_t, int *);
enum nss_status _nss_extrausers_getpwent_r(struct passwd *, char *, size_t, int *);

static enum nss_status p_search(FILE *f, const char *name, const uid_t uid, struct passwd *pw, int *errnop, char *buffer, size_t buflen);

static inline enum nss_status p_search(FILE *f, const char *name, const uid_t uid, struct passwd *pw, int *errnop, char *buffer, size_t buflen) {
#define SANEQUIT {funlockfile(stream); if (f==NULL) fclose(stream);}
#define TOCOLON(p, h) { while (*p && *p != ':') \
				p++; \
			h=p; \
			if(!*p) { \
				SANEQUIT \
				*errnop = 0; \
				return NSS_STATUS_UNAVAIL; \
			} \
			p++; \
			*h='\0'; \
			h--; \
			}
	FILE *stream = f;
	char *p, *h;
	uid_t t_uid;
	gid_t t_gid;
	char *t_name, *t_passwd, *t_gecos, *t_shell, *t_dir;

	if (stream == NULL) {
		stream = fopen(USERSFILE, "r");
		if (stream == NULL) {
			*errnop = errno;
			return NSS_STATUS_UNAVAIL;
		}
	}
	flockfile(stream);
	while (1) {
		buffer[buflen - 1] = '\xff';
		p = fgets_unlocked(buffer, buflen, stream);
		if (p == NULL) {
			if (feof_unlocked(stream)) {
				SANEQUIT
				*errnop = ENOENT;
				return NSS_STATUS_NOTFOUND;
			} else {
				*errnop = errno;
				SANEQUIT
				return NSS_STATUS_UNAVAIL;
			}
		}
		h = index(p, '\n');
		if (buffer[buflen - 1] != '\xff' || h == NULL) {
			SANEQUIT
			*errnop = ERANGE;
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
		if (name && strcmp(name, t_name)!=0)
			continue;
		/* passwd (should be "x" or "!!" or something...) */
		while (isspace(*p))
			++p;
		t_passwd = p;
		TOCOLON(p, h);
		/* extract uid */
		t_uid = strtol(p, &h, 10);
		if (*h != ':') {
			SANEQUIT
			*errnop = 0;
			return NSS_STATUS_UNAVAIL;
		}
		if (t_uid < MINUID) {
			continue;
		}
		if (uid != 0 && uid != t_uid) {
			continue;
		}
		p = ++h;
		/* extract gid */
		t_gid = strtol(p, &h, 10);
		if (*h != ':') {
			SANEQUIT
			*errnop = 0;
			return NSS_STATUS_UNAVAIL;
		}
# ifdef USERSGID
		if (t_gid < MINGID && t_gid != USERSGID) {
# else
		if (t_gid < MINGID) {
# endif
			continue;
		}
		p = ++h;
		/* extract gecos */
		while (isspace(*p))
			++p;
		t_gecos = p;
		TOCOLON(p, h);
		/* extract dir */
		while (isspace(*p))
			++p;
		t_dir = p;
		TOCOLON(p, h);
		/* extract shell */
		while (isspace(*p))
			++p;
		t_shell = p;
		if (index(p, ':') != NULL) {
			SANEQUIT
			*errnop = 0;
			return NSS_STATUS_UNAVAIL;
		}

		SANEQUIT
		*errnop = 0;
		pw->pw_name = t_name;
		pw->pw_uid = t_uid;
		pw->pw_passwd = t_passwd;
		pw->pw_gid = t_gid;
		pw->pw_gecos = t_gecos;
		pw->pw_dir = t_dir;
		pw->pw_shell = t_shell;
		return NSS_STATUS_SUCCESS;
	}
}

enum nss_status _nss_extrausers_getpwuid_r(uid_t uid, struct passwd *result, char *buf, size_t buflen, int *errnop) {
	*errnop = 0;
	if (result)
		return p_search(NULL, NULL, uid, result, errnop, buf, buflen);
	else
		return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_extrausers_getpwnam_r(const char *name, struct passwd *result, char *buf, size_t buflen, int *errnop) {
	*errnop = 0;
	if (result)
		return p_search(NULL, name, 0, result, errnop, buf, buflen);
	else
		return NSS_STATUS_UNAVAIL;
}

static FILE *usersfile = NULL;

enum nss_status _nss_extrausers_setpwent(void) {

	if (usersfile != NULL)
	{
		fclose(usersfile);
		usersfile = NULL;
	}
	usersfile = fopen(USERSFILE, "r");
	if (usersfile == NULL)
	{
		return NSS_STATUS_UNAVAIL;
	}

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_extrausers_endpwent(void) {

	if (usersfile != NULL)
	{
		fclose(usersfile);
		usersfile = NULL;
	}
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_extrausers_getpwent_r(struct passwd *pw, char *buffer, size_t buflen, int *errnop) {
	*errnop = -1;

	if (pw == NULL)
		return NSS_STATUS_UNAVAIL;
	if (usersfile == NULL)
		return NSS_STATUS_UNAVAIL;

  	return p_search(usersfile, NULL, 0, pw, errnop, buffer, buflen);
}

