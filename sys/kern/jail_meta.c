/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Igor Ostapenko <pm@igoro.pro>
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

#include <sys/systm.h> /* TODO: it was added for printf only */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/malloc.h>
#include <sys/jail.h>
#include <sys/osd.h>

static u_int jm_osd_slot;

#define JAILMETAMAXLEN 4096

SYSCTL_JAIL_PARAM_STRING(, meta, CTLFLAG_RW, JAILMETAMAXLEN, "Jail meta info");

static void
jm_osd_destructor(void *osd_addr)
{
	free(osd_addr, M_PRISON);
}

/* TODO: it looks we should do nothing on create phase, anyway set is called
 * right after create.
 * The only useful thing could be to pre-allocate osd slot, probably.
 * But be ready for a case if a jail was created before the module loaded. */
static int
jm_osd_method_create(void *obj, void *data)
{
	struct prison *pr = obj;
	struct vfsoptlist *opts = data;
	char *opt_addr;
	int opt_len; /* TODO: is it provided w/o NULL char? */
	char *osd_addr;
	void **rsv;
	int error;

	error = vfs_getopt(opts, "meta", (void **)&opt_addr, &opt_len);
	if (error != 0)
		return (0);
	/* printf("_create: opt_meta=%s, len=%d | ", opt_meta, len); */

	/* TODO: check for JAILMETAMAXLEN */

	osd_addr = malloc(opt_len + 1, M_PRISON, M_WAITOK);
	memcpy(osd_addr, opt_addr, opt_len);
	osd_addr[opt_len] = '\0';

	rsv = osd_reserve(jm_osd_slot);
	/* TODO: what if rsv is NULL? */
	mtx_lock(&pr->pr_mtx);
	(void) osd_jail_set_reserved(pr, jm_osd_slot, rsv, osd_addr);
	/* printf("_create: osd_meta=%s | ", osd_meta); */
	mtx_unlock(&pr->pr_mtx);

	/* TODO: remember about osd_free_reserved() */

	return (0);
}

static int
jm_osd_method_set(void *obj, void *data)
{
	struct prison *pr = obj;
	struct vfsoptlist *opts = data;
	int opt_len; /* TODO: is it provided w/o NULL char? */
	char *osd_addr;
	char *osd_addr_old;
	int error;

	/* TODO: is there a better way? */
	error = vfs_getopt(opts, "meta", NULL, &opt_len);
	if (error != 0)
		return (0);

	/* TODO: check for JAILMETAMAXLEN */

	osd_addr = malloc(opt_len + 1, M_PRISON, M_WAITOK);
	error = vfs_copyopt(opts, "meta", osd_addr, opt_len);
	if (error != 0) {
		free(osd_addr, M_PRISON);
		return (error);
	}
	osd_addr[opt_len] = '\0';

	mtx_lock(&pr->pr_mtx);
	osd_addr_old = osd_jail_get(pr, jm_osd_slot);
	/* TODO: consider a case if kldload jail_meta is done after a jail is created
	 * let's do _reserve each time? */
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
	char *osd_addr;
	char empty = '\0';

	mtx_lock(&pr->pr_mtx);
	osd_addr = osd_jail_get(pr, jm_osd_slot);
	/* printf("_get: osd_meta=%s | ", osd_addr); */
	if (osd_addr == NULL)
		/* TODO: error = */ vfs_setopts(opts, "meta", &empty);
	else
		/* TODO: error = */ vfs_setopts(opts, "meta", osd_addr);
	mtx_unlock(&pr->pr_mtx);

	return (0);
}

static int
jm_osd_method_check(void *obj __unused, void *data)
{
	struct vfsoptlist *opts = data;
	char *meta;
	int error __unused;
	int len;

	error = vfs_getopt(opts, "meta", (void **)&meta, &len);

	/* TODO: check max len, return error if bad */

	return (0);
}

static int
jm_mod_load(void *arg __unused)
{
	osd_method_t methods[PR_MAXMETHOD] = {
		[PR_METHOD_CREATE] = jm_osd_method_create,
		[PR_METHOD_SET] = jm_osd_method_set,
		[PR_METHOD_GET] = jm_osd_method_get,
		[PR_METHOD_CHECK] = jm_osd_method_check,
	};

	jm_osd_slot = osd_jail_register(jm_osd_destructor, methods);

	return (0);
}

static int
jm_mod_unload(void *arg __unused)
{
	osd_jail_deregister(jm_osd_slot);

	return (0);
}

static int
jm_modevent(module_t mod __unused, int event, void *arg)
{
	int error = 0;

	switch (event) {
	case MOD_LOAD:
		error = jm_mod_load(arg);
		break;
	case MOD_UNLOAD:
		error = jm_mod_unload(arg);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static moduledata_t jm_mod = {
	"jail_meta",
	jm_modevent,
	NULL
};

DECLARE_MODULE(jail_meta, jm_mod, SI_SUB_DRIVERS, SI_ORDER_ANY); /* TODO: which system should be used? */
MODULE_VERSION(jail_meta, 1);
