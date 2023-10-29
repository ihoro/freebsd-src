
PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/vm

ATF_TESTS_C+=	mlock_test \
		mmap_test \
		page_fault_signal \
		shared_shadow_inval_test

TEST_METADATA.mlock_test+=			execenv_jail="allow.mlock"
TEST_METADATA.shared_shadow_inval_test+=	execenv_jail="allow.mlock"

BINDIR=		${TESTSDIR}
ATF_TESTS_SH+=	mmap_map_32bit_test
PROGS+=		mmap_map_32bit_helper

SUBDIR=		soxstack
TESTS_SUBDIRS+=	stack

SUBDIR_DEPEND_stack=soxstack

.include <bsd.test.mk>
