ATF_TESTS_SH+=	syslogd_test
# Several syslogd listening on the same port prevent parallel operation
TEST_METADATA+=	is_exclusive="true"

TEST_METADATA+=	execenv="host"

.include <bsd.test.mk>
