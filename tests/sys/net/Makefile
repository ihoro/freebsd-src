
PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/net
BINDIR=		${TESTSDIR}

ATF_TESTS_C+=	if_epair
TEST_METADATA.if_epair+=	execenv_jail="vnet \"exec.prepare=kldload -n if_epair\""
ATF_TESTS_SH+=	if_epair_test
TEST_METADATA.if_epair_test+=	execenv_jail="vnet \"exec.prepare=kldload -n if_epair\""
ATF_TESTS_SH+=	if_bridge_test
TEST_METADATA.if_bridge_test+=	required_programs="python",execenv_jail="vnet"
ATF_TESTS_SH+=	if_clone_test
ATF_TESTS_SH+=	if_gif
TEST_METADATA.if_gif+=		execenv_jail="vnet \"exec.prepare=kldload -n if_epair\""
ATF_TESTS_SH+=	if_lagg_test
TEST_METADATA.if_lagg_test+=	execenv_jail="vnet \"exec.prepare=kldload -n if_epair if_lagg\""
ATF_TESTS_SH+=	if_stf
TEST_METADATA.if_stf+=		execenv_jail="vnet \"exec.prepare=kldload -n if_epair\""
ATF_TESTS_SH+=	if_tun_test
TEST_METADATA.if_tun_test+=	execenv_jail="vnet \"exec.prepare=kldload -n if_epair\""
ATF_TESTS_SH+=	if_vlan
TEST_METADATA.if_vlan+=		execenv="host"
ATF_TESTS_SH+=	if_wg
TEST_METADATA.if_wg+=		execenv="host"

TESTS_SUBDIRS+=	if_ovpn
TESTS_SUBDIRS+=	routing

# The tests are written to be run in parallel, but doing so leads to random
# panics.  I think it's because the kernel's list of interfaces isn't properly
# locked.
TEST_METADATA+=	is_exclusive=true

${PACKAGE}FILES+=	\
		dhclient_pcp.conf \
		pcp.py \
		stp.py

${PACKAGE}FILESMODE_pcp.py=		0555
${PACKAGE}FILESMODE_stp.py=		0555

MAN=
PROGS+=		randsleep

CFLAGS+=        -I${.CURDIR:H:H}

.include <bsd.test.mk>
