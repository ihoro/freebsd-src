/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 SkunkWerks GmbH
 *
 * This software was developed by Igor Ostapenko <igoro@FreeBSD.org>
 * under sponsorship from SkunkWerks GmbH.
 */

#include <sys/param.h>
#include <sys/_bitset.h>
#include <sys/bitset.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/kernel.h>
#include <sys/mount.h>
#include <sys/malloc.h>
#include <sys/jail.h>
#include <sys/osd.h>
#include <sys/proc.h>

/*
 * Buffer limit
 *
 * The hard limit is the actual value used during setting or modification. The
 * soft limit is used solely by the security.jail.param.meta and .env sysctl. If
 * the hard limit is decreased, the soft limit may remain higher to ensure that
 * previously set meta strings can still be correctly interpreted by end-user
 * interfaces, such as jls(8).
 */

static uint32_t jm_maxbufsize_hard = 4096;
static uint32_t jm_maxbufsize_soft = 4096;

static int
jm_sysctl_meta_maxbufsize(SYSCTL_HANDLER_ARGS)
{
	int error;
	uint32_t newmax = 0;

	/* only reading */

	if (req->newptr == NULL) {
		sx_slock(&allprison_lock);
		error = SYSCTL_OUT(req, &jm_maxbufsize_hard,
		    sizeof(jm_maxbufsize_hard));
		sx_sunlock(&allprison_lock);

		return (error);
	}

	/* reading and writing */

	sx_xlock(&allprison_lock);

	error = SYSCTL_OUT(req, &jm_maxbufsize_hard,
	    sizeof(jm_maxbufsize_hard));
	if (error != 0)
		goto end;

	error = SYSCTL_IN(req, &newmax, sizeof(newmax));
	if (error != 0)
		goto end;

	jm_maxbufsize_hard = newmax;
	if (jm_maxbufsize_hard >= jm_maxbufsize_soft)
		jm_maxbufsize_soft = jm_maxbufsize_hard;
	else if (TAILQ_EMPTY(&allprison))
		/*
		 * For now, this is the simplest way to
		 * avoid O(n) iteration over all prisons in
		 * case of a large n.
		 */
		jm_maxbufsize_soft = jm_maxbufsize_hard;

end:
	sx_xunlock(&allprison_lock);
	return (error);
}
SYSCTL_PROC(_security_jail, OID_AUTO, meta_maxbufsize,
    CTLTYPE_U32 | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    jm_sysctl_meta_maxbufsize, "IU",
    "Maximum buffer size of each meta and env");


/* Allowed chars */

#define NCHARS	256
BITSET_DEFINE(charbitset, NCHARS);
static struct charbitset allowedchars;

static int
jm_sysctl_meta_allowedchars(SYSCTL_HANDLER_ARGS)
{
	int error;
	unsigned char chars[NCHARS];
	int len = 0;
	const bool readonly = req->newptr == NULL;

	readonly ? sx_slock(&allprison_lock) : sx_xlock(&allprison_lock);

	if (!BIT_ISFULLSET(NCHARS, &allowedchars))
		for (size_t i = 1; i < NCHARS; i++) {
			if (!BIT_ISSET(NCHARS, i, &allowedchars))
				continue;
			chars[len] = i;
			len++;
		}
	chars[len] = 0;

	error = sysctl_handle_string(oidp, chars, arg2, req);

	if (!readonly) {
		if (chars[0] == 0) {
			BIT_FILL(NCHARS, &allowedchars);
		} else {
			BIT_ZERO(NCHARS, &allowedchars);
			for (size_t i = 0; i < NCHARS; i++) {
				if (chars[i] == 0)
					break;
				BIT_SET(NCHARS, chars[i], &allowedchars);
			}
		}
	}

	readonly ? sx_sunlock(&allprison_lock) : sx_xunlock(&allprison_lock);

	return (error);
}
SYSCTL_PROC(_security_jail, OID_AUTO, meta_allowedchars,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, NCHARS,
    jm_sysctl_meta_allowedchars, "A",
    "The single-byte chars allowed to be used for meta and env"
    " (empty string means all chars are allowed)");


/* Jail parameter announcement */

static int
jm_sysctl_param_meta(SYSCTL_HANDLER_ARGS)
{
	uint32_t soft;

	sx_slock(&allprison_lock);
	soft = jm_maxbufsize_soft;
	sx_sunlock(&allprison_lock);

	return (sysctl_jail_param(oidp, arg1, soft, req));
}
SYSCTL_PROC(_security_jail_param, OID_AUTO, meta,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    jm_sysctl_param_meta, "A,keyvalue",
    "Jail meta information hidden from the jail");
SYSCTL_PROC(_security_jail_param, OID_AUTO, env,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    jm_sysctl_param_meta, "A,keyvalue",
    "Jail meta information readable by the jail");


/* OSD -- generic */

struct meta {
	char *name;
	u_int osd_slot;
	osd_method_t methods[PR_MAXMETHOD];
};

static int
jm_osd_method_set(void *obj, void *data, struct meta *meta)
{
	struct prison *pr = obj;
	struct vfsoptlist *opts = data;
	int len = 0;
	char *osd;
	char *prevosd;
	int error;

	/* Check the option presence and its len before buf allocation */
	error = vfs_getopt(opts, meta->name, (void **)&osd, &len);
	if (error == ENOENT)
		return (0);
	if (error != 0)
		return (error);
	if (len < 1)
		return (EINVAL);

	sx_assert(&allprison_lock, SA_LOCKED);

	/* Check buffer size limit */
	if (len > 1 && len > jm_maxbufsize_hard) /* len includes '\0' char */
		return (EFBIG);

	/* Check allowed chars */
	for (size_t i = 0; i < len; i++) {
		if (osd[i] == 0)
			continue;
		if (!BIT_ISSET(NCHARS, osd[i], &allowedchars))
			return (EINVAL);
	}

	/* Prepare a new buf */
	osd = NULL;
	if (len > 1) {
		osd = malloc(len, M_PRISON, M_WAITOK);
		error = vfs_copyopt(opts, meta->name, osd, len);
		if (error != 0) {
			free(osd, M_PRISON);
			return (error);
		}
		osd[len] = '\0'; /* the reading logic may rely on this */
	}

	/* Swap bufs */
	mtx_lock(&pr->pr_mtx);
	prevosd = osd_jail_get(pr, meta->osd_slot);
	error = osd_jail_set(pr, meta->osd_slot, osd);
	mtx_unlock(&pr->pr_mtx);

	if (error != 0)
		prevosd = osd;

	free(prevosd, M_PRISON);

	return (error);
}

static int
jm_osd_method_get(void *obj, void *data, struct meta *meta)
{
	struct prison *pr = obj;
	struct vfsoptlist *opts = data;
	struct vfsopt *opt;
	char *osd = NULL;
	char empty = '\0';
	int error = 0;
	bool locked = false;
	const char *key = NULL;
	size_t keylen = 0;
	const char *p;

	TAILQ_FOREACH(opt, opts, link) {
		if (strstr(opt->name, meta->name) != opt->name)
			continue;
		if (opt->name[strlen(meta->name)] != '.' &&
		    opt->name[strlen(meta->name)] != '\0')
			continue;

		opt->seen = 1;

		if (!locked) {
			mtx_lock(&pr->pr_mtx);
			locked = true;
			osd = osd_jail_get(pr, meta->osd_slot);
			if (osd == NULL)
				osd = &empty;
		}

		/* Provide full metadata */
		if (strcmp(opt->name, meta->name) == 0) {
			if (strlcpy(opt->value, osd, opt->len) >= opt->len) {
				error = EINVAL;
				break;
			}
			continue;
		}

		/* Extract specific key=value\n */
		p = osd;
		key = opt->name + strlen(meta->name) + 1;
		keylen = strlen(key);
		while ((p = strstr(p, key)) != NULL) {
			if ((p == osd || *(p - 1) == '\n')
			    && p[keylen] == '=') {
				if (strlcpy(opt->value, p + keylen + 1,
				    MIN(opt->len, strchr(p + keylen + 1, '\n') -
				    (p + keylen + 1) + 1)) >= opt->len) {
					error = EINVAL;
					break;
				}
			}
			p += keylen;
		}
	}

	if (locked)
		mtx_unlock(&pr->pr_mtx);

	return (error);
}

static int
jm_osd_method_check(void *obj __unused, void *data, struct meta *meta)
{
	struct vfsoptlist *opts = data;
	char *value = NULL;
	int error;
	int len = 0;

	/* Check the option presence */
	error = vfs_getopt(opts, meta->name, (void **)&value, &len);
	if (error == ENOENT)
		return (0);
	if (error != 0)
		return (error);

	if (len < 1)
		return (EINVAL);
	if (value == NULL)
		return (EINVAL);

	return (0);
}

static void
jm_osd_destructor(void *osd)
{
	free(osd, M_PRISON);
}


/* OSD -- meta */

static struct meta meta;

static inline int
jm_osd_method_set_meta(void *obj, void *data)
{
	return (jm_osd_method_set(obj, data, &meta));
}

static inline int
jm_osd_method_get_meta(void *obj, void *data)
{
	return (jm_osd_method_get(obj, data, &meta));
}

static inline int
jm_osd_method_check_meta(void *obj, void *data)
{
	return (jm_osd_method_check(obj, data, &meta));
}

static struct meta meta = {
	.name = "meta",
	.osd_slot = 0,
	.methods = {
		[PR_METHOD_SET] =	jm_osd_method_set_meta,
		[PR_METHOD_GET] =	jm_osd_method_get_meta,
		[PR_METHOD_CHECK] =	jm_osd_method_check_meta,
	}
};


/* OSD -- env */

static struct meta env;

static inline int
jm_osd_method_set_env(void *obj, void *data)
{
	return (jm_osd_method_set(obj, data, &env));
}

static inline int
jm_osd_method_get_env(void *obj, void *data)
{
	return (jm_osd_method_get(obj, data, &env));
}

static inline int
jm_osd_method_check_env(void *obj, void *data)
{
	return (jm_osd_method_check(obj, data, &env));
}

static struct meta env = {
	.name = "env",
	.osd_slot = 0,
	.methods = {
		[PR_METHOD_SET] =	jm_osd_method_set_env,
		[PR_METHOD_GET] =	jm_osd_method_get_env,
		[PR_METHOD_CHECK] =	jm_osd_method_check_env,
	}
};


/* A jail can read its 'env' */

static int
jm_sysctl_env(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	char empty = '\0';
	char *tmpbuf;
	size_t outlen;
	int error = 0;

	pr = req->td->td_ucred->cr_prison;

	mtx_lock(&pr->pr_mtx);
	arg1 = osd_jail_get(pr, env.osd_slot);
	if (arg1 == NULL) {
		tmpbuf = &empty;
		outlen = 1;
	} else {
		outlen = strlen(arg1) + 1;
		if (req->oldptr != NULL) {
			tmpbuf = malloc(outlen, M_PRISON, M_NOWAIT);
			error = (tmpbuf == NULL) ? ENOMEM : 0;
			if (error == 0)
				memcpy(tmpbuf, arg1, outlen);
		}
	}
	mtx_unlock(&pr->pr_mtx);

	if (error != 0)
		return (error);

	if (req->oldptr == NULL)
		SYSCTL_OUT(req, NULL, outlen);
	else {
		SYSCTL_OUT(req, tmpbuf, outlen);
		if (tmpbuf != &empty)
			free(tmpbuf, M_PRISON);
	}

	return (error);
}
SYSCTL_PROC(_security_jail, OID_AUTO, env,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE,
    0, 0, jm_sysctl_env, "A", "Meta information provided by parent jail");


/* Setup and tear down */

static int
jm_sysinit(void *arg __unused)
{
	/* Default set of allowed chars */

	BIT_ZERO(NCHARS, &allowedchars);

	/* Base64 */
	for (size_t i = 0x41; i <= 0x5A; i++)	/* A-Z */
		BIT_SET(NCHARS, i, &allowedchars);
	for (size_t i = 0x61; i <= 0x7A; i++)	/* a-z */
		BIT_SET(NCHARS, i, &allowedchars);
	for (size_t i = 0x30; i <= 0x39; i++)	/* 0-9 */
		BIT_SET(NCHARS, i, &allowedchars);
	BIT_SET(NCHARS, 0x2B, &allowedchars);	/* + */
	BIT_SET(NCHARS, 0x2F, &allowedchars);	/* / */
	BIT_SET(NCHARS, 0x3D, &allowedchars);	/* = */

	/* key=value\n format */
	BIT_SET(NCHARS, 0x0A, &allowedchars);	/* LF */
	BIT_SET(NCHARS, 0x0D, &allowedchars);	/* CR */

	/* Extra */
	BIT_SET(NCHARS, 0x09, &allowedchars);	/* HT */
	BIT_SET(NCHARS, 0x20, &allowedchars);	/* SP */
	BIT_SET(NCHARS, 0x2C, &allowedchars);	/* , */
	BIT_SET(NCHARS, 0x2D, &allowedchars);	/* - */
	BIT_SET(NCHARS, 0x2E, &allowedchars);	/* . */
	BIT_SET(NCHARS, 0x3A, &allowedchars);	/* : */
	BIT_SET(NCHARS, 0x40, &allowedchars);	/* @ */
	BIT_SET(NCHARS, 0x5F, &allowedchars);	/* _ */


	meta.osd_slot = osd_jail_register(jm_osd_destructor, meta.methods);
	env.osd_slot = osd_jail_register(jm_osd_destructor, env.methods);

	return (0);
}

static int
jm_sysuninit(void *arg __unused)
{
	osd_jail_deregister(meta.osd_slot);
	osd_jail_deregister(env.osd_slot);

	return (0);
}

SYSINIT(jailmeta, SI_SUB_DRIVERS, SI_ORDER_ANY, jm_sysinit, NULL);
SYSUNINIT(jailmeta, SI_SUB_DRIVERS, SI_ORDER_ANY, jm_sysuninit, NULL);
