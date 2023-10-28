
ATF_TESTS_SH+=	ls_tests
# This seems like overkill, but the idea in mind is that all of the testcases
# should be runnable as !root
TEST_METADATA.ls_tests+=	required_user="unprivileged"
TEST_METADATA.ls_tests+=	required_files="/usr/bin/awk /usr/bin/nc /usr/bin/sort"
TEST_METADATA.ls_tests+=	execenv="host"

.include <bsd.test.mk>
