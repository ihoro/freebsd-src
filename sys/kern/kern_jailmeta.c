/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 SkunkWerks GmbH
 *
 * This software was developed by Igor Ostapenko <igoro@FreeBSD.org>
 * under sponsorship from SkunkWerks GmbH.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/mount.h>
#include <sys/malloc.h>
#include <sys/jail.h>
#include <sys/osd.h>
#include <sys/proc.h>


#define JM_PARAM_NAME	"meta"


/* Buffer limit */

static uint32_t jm_maxbufsize = 4096;
SYSCTL_U32(_security_jail, OID_AUTO, meta_maxbufsize,
    CTLFLAG_RW, &jm_maxbufsize, 0, "Maximum meta buffer size.");


/* Jail parameter announcement */

static int
jm_sysctl_jail_param_meta(SYSCTL_HANDLER_ARGS)
{
	return (sysctl_jail_param(oidp, arg1, jm_maxbufsize, req));
}
SYSCTL_PROC(_security_jail_param, OID_AUTO, meta,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    jm_sysctl_jail_param_meta, "A", "Jail meta info");


/* OSD */

static u_int jm_osd_slot;

static int
jm_osd_method_set(void *obj, void *data)
{
	struct prison *pr = obj;
	struct vfsoptlist *opts = data;
	int len = 0;
	char *osd_addr;
	char *osd_addr_old;
	int error;

	/* Check the option presence and its len before buf allocation */
	error = vfs_getopt(opts, JM_PARAM_NAME, NULL, &len);
	if (error != 0)
		return (0);
	if (len > jm_maxbufsize) /* len includes '\0' char */
		return (EFBIG);
	if (len < 1)
		return (EINVAL);

	/* Prepare a new buf */
	if (len > 1) {
		osd_addr = malloc(len, M_PRISON, M_WAITOK);
		error = vfs_copyopt(opts, JM_PARAM_NAME, osd_addr, len);
		if (error != 0) {
			free(osd_addr, M_PRISON);
			return (error);
		}
	} else {
		osd_addr = NULL;
	}

	/* Swap bufs */
	mtx_lock(&pr->pr_mtx);
	osd_addr_old = osd_jail_get(pr, jm_osd_slot);
	error = osd_jail_set(pr, jm_osd_slot, osd_addr);
	mtx_unlock(&pr->pr_mtx);

	if (error != 0)
		osd_addr_old = osd_addr;

	free(osd_addr_old, M_PRISON);

	return (error);
}

static int
jm_osd_method_get(void *obj, void *data)
{
	struct prison *pr = obj;
	struct vfsoptlist *opts = data;
	char *osd_addr = NULL;
	char empty = '\0';
	int error;

	/* Check the option presence to avoid unnecessary locking */
	error = vfs_getopt(opts, JM_PARAM_NAME, NULL, NULL);
	if (error != 0)
		return (0);

	mtx_lock(&pr->pr_mtx);
	osd_addr = osd_jail_get(pr, jm_osd_slot);
	if (osd_addr == NULL)
		error = vfs_setopts(opts, JM_PARAM_NAME, &empty);
	else
		error = vfs_setopts(opts, JM_PARAM_NAME, osd_addr);
	mtx_unlock(&pr->pr_mtx);

	return (error);
}

static int
jm_osd_method_check(void *obj __unused, void *data)
{
	struct vfsoptlist *opts = data;
	char *meta = NULL;
	int error;
	int len = 0;

	/* Check the option presence */
	error = vfs_getopt(opts, JM_PARAM_NAME, (void **)&meta, &len);
	if (error == ENOENT)
		return (0);
	if (error != 0)
		return (error);

	if (len < 1)
		return (EINVAL);
	if (meta == NULL)
		return (EINVAL);

	return (0);
}

static void
jm_osd_destructor(void *osd_addr)
{
	free(osd_addr, M_PRISON);
}


/* A jail can read its own meta */

static int
jm_sysctl_security_jail_meta(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	char empty = '\0';
	char *tmpbuf;
	size_t outlen;
	int error = 0;

	pr = req->td->td_ucred->cr_prison;

	mtx_lock(&pr->pr_mtx);
	arg1 = osd_jail_get(pr, jm_osd_slot);
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
SYSCTL_PROC(_security_jail, OID_AUTO, meta,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE,
    0, 0, jm_sysctl_security_jail_meta, "A", "Jail meta info");


/* Setup and tear down */

static int
jm_sysinit(void *arg __unused)
{
	osd_method_t methods[PR_MAXMETHOD] = {
		[PR_METHOD_SET] = jm_osd_method_set,
		[PR_METHOD_GET] = jm_osd_method_get,
		[PR_METHOD_CHECK] = jm_osd_method_check,
	};

	jm_osd_slot = osd_jail_register(jm_osd_destructor, methods);

	return (0);
}

static int
jm_sysuninit(void *arg __unused)
{
	osd_jail_deregister(jm_osd_slot);

	return (0);
}

SYSINIT(jailmeta, SI_SUB_DRIVERS, SI_ORDER_ANY, jm_sysinit, NULL);
SYSUNINIT(jailmeta, SI_SUB_DRIVERS, SI_ORDER_ANY, jm_sysuninit, NULL);
