
PACKAGE=	tests

ATF_TESTS_SH+=	\
        basic

${PACKAGE}FILES+=	\
		utils.subr

TEST_METADATA+=	execenv_jail="vnet \"exec.prepare=kldload -n if_epair\""

.include <bsd.test.mk>
