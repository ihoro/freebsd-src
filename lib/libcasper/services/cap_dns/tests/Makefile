
.include <src.opts.mk>

ATF_TESTS_C=	dns_test

TEST_METADATA+=	execenv_jail="ip4=inherit ip6=inherit"

.if ${MK_CASPER} != "no"
LIBADD+=	casper
LIBADD+=	cap_dns
CFLAGS+=-DWITH_CASPER
.endif
LIBADD+=	nv

.include <bsd.test.mk>
