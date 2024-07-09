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

#include "opt_inet.h"
#include "opt_inet6.h"

#include <machine/atomic.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/vnet.h>
#include <net/pfil.h>

SYSCTL_NODE(_net, OID_AUTO, dummymbuf, 0, NULL,
    "Dummy mbuf sysctl");

#define RULES_MAXLEN	512
VNET_DEFINE_STATIC(char, rules[RULES_MAXLEN]) = "";
#define V_rules	VNET(rules)
SYSCTL_STRING(_net_dummymbuf, OID_AUTO, rules, CTLFLAG_RW | CTLFLAG_VNET,
    &VNET_NAME(rules), RULES_MAXLEN,
    "{inet | inet6 | ether} {in | out} <ifname> <opname>[ args...];"
    " ...;");

VNET_DEFINE_STATIC(counter_u64_t, hits);
#define V_hits	VNET(hits)
SYSCTL_PROC(_net_dummymbuf, OID_AUTO, hits,
    CTLTYPE_U64 | CTLFLAG_MPSAFE | CTLFLAG_STATS | CTLFLAG_RW | CTLFLAG_VNET,
    &VNET_NAME(hits), 0, sysctl_handle_counter_u64,
    "QU", "Number of times a rule has been applied");

VNET_DEFINE_STATIC(bool, dmb_pfil_inited);
#define V_dmb_pfil_inited	VNET(dmb_pfil_inited)

VNET_DEFINE_STATIC(pfil_hook_t, dmb_pfil_inet_hook);
#define V_dmb_pfil_inet_hook	VNET(dmb_pfil_inet_hook)

struct op;
typedef struct mbuf * (*op_fn_t)(struct mbuf *, struct op *);
struct op {
	int pfil_type;
	int pfil_dir;
	char ifname[IFNAMSIZ];
	op_fn_t fn;
	const char *args;
};

static struct mbuf *
dmb_m_head(struct mbuf *m, struct op *op)
{
	struct mbuf *n;
	int count;

	count = (int)strtol(op->args, NULL, 10);
	if (count < 0 || count > MCLBYTES)
		goto bad;

	if (!(m->m_flags & M_PKTHDR))
		goto bad;
	if (m->m_pkthdr.len <= 0)
		return (m);
	if (count >= m->m_pkthdr.len)
		count = m->m_pkthdr.len - 1;

	if ((n = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR)) == NULL)
		goto bad;

	m_move_pkthdr(n, m);
	m_copydata(m, 0, count, n->m_ext.ext_buf);
	n->m_len = count;

	m_adj(m, count);
	n->m_next = m;

	return (n);

bad:
	m_freem(m);
	return (NULL);
}

static bool
read_op(const char **cur, struct op *op)
{
	// {inet | inet6 | ether} {in | out} <ifname> <opname>[ args...];

	while (**cur == ' ')
		(*cur)++;
	char *delim = strchr(*cur, ';');
	if (delim == NULL)
		return (false);

	// pfil_type
	if (strstr(*cur, "inet6") == *cur) {
		op->pfil_type = PFIL_TYPE_IP6;
		*cur += strlen("inet6");
	} else if (strstr(*cur, "inet") == *cur) {
		op->pfil_type = PFIL_TYPE_IP4;
		*cur += strlen("inet");
	} else if (strstr(*cur, "ethernet")) {
		op->pfil_type = PFIL_TYPE_ETHERNET;
		*cur += strlen("ethernet");
	} else {
		return (false);
	}
	while (**cur == ' ')
		(*cur)++;

	// pfil_dir
	if (strstr(*cur, "in") == *cur) {
		op->pfil_dir = PFIL_IN;
		*cur += strlen("in");
	} else if (strstr(*cur, "out") == *cur) {
		op->pfil_dir = PFIL_OUT;
		*cur += strlen("out");
	} else {
		return (false);
	}
	while (**cur == ' ')
		(*cur)++;

	// ifname
	char *sp = strchr(*cur, ' ');
	if (sp == NULL || sp > delim)
		return (false);
	size_t len = sp - *cur;
	if (len >= sizeof(op->ifname))
		return (false);
	strncpy(op->ifname, *cur, len);
	op->ifname[len] = 0;
	*cur = sp;
	while (**cur == ' ')
		(*cur)++;

	// opname
	if (strstr(*cur, "head") == *cur) {
		op->fn = dmb_m_head;
		*cur += strlen("head");
	} else {
		return (false);
	}
	while (**cur == ' ')
		(*cur)++;

	// args
	if (*cur > delim)
		return (false);
	op->args = *cur;

	*cur = delim + 1;

	return (true);
}

static pfil_return_t
dmb_pfil_inet_mbuf_chk(struct mbuf **mp, struct ifnet *ifp, int flags,
    void *ruleset, struct inpcb *inp)
{
	// TODO: serialize read/write of the rules
	struct mbuf *m = *mp;
	const char *cursor = V_rules;
	bool parsed;
	struct op op;

	while ((parsed = read_op(&cursor, &op))) {
		if (op.pfil_type == PFIL_TYPE_IP4 &&
		    (flags & op.pfil_dir) == op.pfil_dir &&
		    strcmp(op.ifname, ifp->if_xname) == 0) {
			m = op.fn(m, &op);
			if (m == NULL) {
				// TODO: provide feedback
				break;
			}
			counter_u64_add(V_hits, 1);
		}
		if (strlen(cursor) == 0)
			break;
	}
	if (!parsed) {
		// TODO: provide feedback
		m_freem(m);
		m = NULL;
	}
	if (m == NULL) {
		*mp = NULL;
		return (PFIL_DROPPED);
	}

	if (m != *mp) {
		*mp = m;
		return (PFIL_REALLOCED);
	}

	return (PFIL_PASS);
}

static void
dmb_pfil_init(void)
{
	if (atomic_load_bool(&V_dmb_pfil_inited))
		return;

#ifdef INET
	struct pfil_hook_args pha = {
		.pa_version = PFIL_VERSION,
		.pa_modname = "dummymbuf",
		.pa_type = PFIL_TYPE_IP4,
		.pa_flags = PFIL_IN | PFIL_OUT,
		.pa_mbuf_chk = dmb_pfil_inet_mbuf_chk,
		.pa_rulname = "inet",
	};
	V_dmb_pfil_inet_hook = pfil_add_hook(&pha);
#endif

	atomic_store_bool(&V_dmb_pfil_inited, true);
}

static void
dmb_pfil_uninit(void)
{
	if (!atomic_load_bool(&V_dmb_pfil_inited))
		return;

#ifdef INET
	pfil_remove_hook(V_dmb_pfil_inet_hook);
#endif

	atomic_store_bool(&V_dmb_pfil_inited, false);
}

static void
dmb_vnet_init(void *unused __unused)
{
	V_hits = counter_u64_alloc(M_WAITOK);
	dmb_pfil_init();
}
VNET_SYSINIT(dmb_vnet_init, SI_SUB_PROTO_PFIL, SI_ORDER_ANY,
    dmb_vnet_init, NULL);

static void
dmb_vnet_uninit(void *unused __unused)
{
	dmb_pfil_uninit();
	counter_u64_free(V_hits);
}
VNET_SYSUNINIT(dmb_vnet_uninit, SI_SUB_PROTO_PFIL, SI_ORDER_ANY,
    dmb_vnet_uninit, NULL);

static int
dmb_modevent(module_t mod __unused, int event, void *arg __unused)
{
	int error = 0;

	switch (event) {
	case MOD_LOAD:
	case MOD_UNLOAD:
	case MOD_SHUTDOWN:
	case MOD_QUIESCE:
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}

static moduledata_t dmb_mod = {
	"dummymbuf",
	dmb_modevent,
	NULL
};

// TODO: conf/options update? opt_dummymbuf.h?
// TODO: inet6 support
// TODO: ethernet support
DECLARE_MODULE(dummymbuf, dmb_mod, SI_SUB_PROTO_PFIL, SI_ORDER_ANY);
MODULE_VERSION(dummymbuf, 1);
