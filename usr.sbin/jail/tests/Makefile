
PACKAGE=        tests

ATF_TESTS_SH+=  jail_basic_test

${PACKAGE}FILES+=	commands.jail.conf
# The different test cases create jails with the same name.
TEST_METADATA+= is_exclusive="true"

TEST_METADATA+=	execenv="host"

.include <bsd.test.mk>
