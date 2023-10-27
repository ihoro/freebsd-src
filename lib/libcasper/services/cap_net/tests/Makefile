
.include <src.opts.mk>

ATF_TESTS_C=	net_test

TEST_METADATA+=	execenv_jail="ip4=inherit ip6=inherit"

.if ${MK_CASPER} != "no"
LIBADD+=	casper
LIBADD+=	cap_net
CFLAGS+=-DWITH_CASPER
.endif
LIBADD+=	nv

WARNS?=		3

.include <bsd.test.mk>
