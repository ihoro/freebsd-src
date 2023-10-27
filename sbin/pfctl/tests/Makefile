
PACKAGE=	tests

ATF_TESTS_C=	pfctl_test
ATF_TESTS_SH=	macro

TEST_METADATA.pfctl_test+=	execenv_jail="ip4=inherit ip6=inherit"

LIBADD+=	sbuf
SUBDIR+=	files
WARNS=6

.include <bsd.test.mk>
