
.include <bsd.own.mk>

ATF_TESTS_C=	functional
TEST_METADATA.functional+=	timeout=15
TEST_METADATA.functional+=	execenv_jail="ip4=inherit ip6=inherit"

LIBADD=	util
CSTD=	c11

.include <bsd.test.mk>
