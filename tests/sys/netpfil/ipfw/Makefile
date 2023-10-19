PACKAGE=	tests

TESTSDIR=       ${TESTSBASE}/sys/netpfil/ipfw

ATF_TESTS_SH+=	fwd \
		divert

# Tests reuse jail names and so cannot run in parallel.
TEST_METADATA+=	is_exclusive=true

${PACKAGE}FILES+=	fwd_inetd.conf

.include <bsd.test.mk>
