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
	if (error == 0 && newmax < 1)
		error = EINVAL;
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

	for (size_t i = 1; i < NCHARS; i++) {
		if (!BIT_ISSET(NCHARS, i, &allowedchars))
			continue;
		chars[len] = i;
		len++;
	}
	chars[len] = 0;

	error = sysctl_handle_string(oidp, chars, arg2, req);

	if (!readonly) {
		BIT_ZERO(NCHARS, &allowedchars);
		for (size_t i = 0; i < NCHARS; i++) {
			if (chars[i] == 0)
				break;
			BIT_SET(NCHARS, chars[i], &allowedchars);
		}
	}

	readonly ? sx_sunlock(&allprison_lock) : sx_xunlock(&allprison_lock);

	return (error);
}
SYSCTL_PROC(_security_jail, OID_AUTO, meta_allowedchars,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, NCHARS,
    jm_sysctl_meta_allowedchars, "A",
    "The single-byte chars allowed to be used for meta and env");


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
    jm_sysctl_param_meta, "A", "Jail meta information hidden from the jail");
SYSCTL_PROC(_security_jail_param, OID_AUTO, env,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    jm_sysctl_param_meta, "A", "Jail meta information readable by the jail");


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
	char *osd_addr;
	char *osd_addr_old;
	int error;

	/* Check the option presence and its len before buf allocation */
	error = vfs_getopt(opts, meta->name, (void **)&osd_addr, &len);
	if (error == ENOENT)
		return (0);
	if (error != 0)
		return (error);
	if (len < 1)
		return (EINVAL);

	sx_assert(&allprison_lock, SA_LOCKED);

	/* Check buffer size limit */
	if (len > jm_maxbufsize_hard) /* len includes '\0' char */
		return (EFBIG);

	/* Check allowed chars */
	for (size_t i = 0; i < len; i++) {
		if (osd_addr[i] == 0)
			continue;
		if (!BIT_ISSET(NCHARS, osd_addr[i], &allowedchars))
			return (EINVAL);
	}

	/* Prepare a new buf */
	osd_addr = NULL;
	if (len > 1) {
		osd_addr = malloc(len, M_PRISON, M_WAITOK);
		error = vfs_copyopt(opts, meta->name, osd_addr, len);
		if (error != 0) {
			free(osd_addr, M_PRISON);
			return (error);
		}
	}

	/* Swap bufs */
	mtx_lock(&pr->pr_mtx);
	osd_addr_old = osd_jail_get(pr, meta->osd_slot);
	error = osd_jail_set(pr, meta->osd_slot, osd_addr);
	mtx_unlock(&pr->pr_mtx);

	if (error != 0)
		osd_addr_old = osd_addr;

	free(osd_addr_old, M_PRISON);

	return (error);
}

static int
jm_osd_method_get(void *obj, void *data, struct meta *meta)
{
	struct prison *pr = obj;
	struct vfsoptlist *opts = data;
	char *osd_addr = NULL;
	char empty = '\0';
	int error;

	/* Check the option presence to avoid unnecessary locking */
	error = vfs_getopt(opts, meta->name, NULL, NULL);
	if (error == ENOENT)
		return (0);
	if (error != 0)
		return (error);

	mtx_lock(&pr->pr_mtx);
	osd_addr = osd_jail_get(pr, meta->osd_slot);
	if (osd_addr == NULL)
		error = vfs_setopts(opts, meta->name, &empty);
	else
		error = vfs_setopts(opts, meta->name, osd_addr);
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
jm_osd_destructor(void *osd_addr)
{
	free(osd_addr, M_PRISON);
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
	/* HT, LF, CR */
	BIT_SET(NCHARS, 0x09, &allowedchars);
	BIT_SET(NCHARS, 0x0A, &allowedchars);
	BIT_SET(NCHARS, 0x0D, &allowedchars);
	/* 7bit printable */
	for (size_t i = 0x20; i <= 0x7E; i++)
		BIT_SET(NCHARS, i, &allowedchars);

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
