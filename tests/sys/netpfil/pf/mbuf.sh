#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2024 Igor Ostapenko <pm@igoro.pro>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

. $(atf_get_srcdir)/utils.subr

dummymbuf_init()
{
	if ! kldstat -q -m dummymbuf; then
		atf_skip "This test requires dummymbuf"
	fi
}

ipfw_init()
{
	if ! kldstat -q -m ipfw; then
		atf_skip "This test requires ipfw"
	fi
}

assert_ipfw_is_off()
{
	if kldstat -q -m ipfw; then
		atf_skip "This test is for the case when ipfw is not loaded"
	fi
}

atf_test_case "ipfwoff_ip4_in_mbuf_len" "cleanup"
ipfwoff_ip4_in_mbuf_len_head()
{
	atf_set descr 'Test that pf can handle the first mbuf with m_len < sizeof(struct ip), with ipfw disabled'
	atf_set require.user root
}
ipfwoff_ip4_in_mbuf_len_body()
{
	local ipfwon=$1

	pft_init
	dummymbuf_init
	test $ipfwon && ipfw_init || assert_ipfw_is_off

	epair=$(vnet_mkepair)
	ifconfig ${epair}a 192.0.2.1/24 up

	# Set up a simple jail with one interface
	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.2/24 up
	test $ipfwon && jexec alcatraz ipfw add 65534 allow all from any to any

	# Sanity check
	atf_check -s exit:0 -o ignore ping -c3 192.0.2.2

	# Should be denied
	echo '
		block
	' | jexec alcatraz pfctl -ef-
	atf_check -s not-exit:0 -o ignore ping -c1 192.0.2.2

	# Should be allowed by from/to addresses
	echo '
		block
		pass in from 192.0.2.1 to 192.0.2.2
	' | jexec alcatraz pfctl -ef-
	atf_check -s exit:0 -o ignore ping -c1 192.0.2.2

	# Should still work for m_len=0
	jexec alcatraz pfilctl link -i dummymbuf:inet inet
	jexec alcatraz sysctl net.dummymbuf.rules='inet in epair0b pull-head 0;'
	atf_check_equal "0" "$(jexec alcatraz sysctl -n net.dummymbuf.hits)"
	atf_check -s exit:0 -o ignore ping -c1 192.0.2.2
	atf_check_equal "1" "$(jexec alcatraz sysctl -n net.dummymbuf.hits)"

	# m_len=1
	jexec alcatraz sysctl net.dummymbuf.rules='inet in epair0b pull-head 1;'
	atf_check -s exit:0 -o ignore ping -c1 192.0.2.2
	atf_check_equal "2" "$(jexec alcatraz sysctl -n net.dummymbuf.hits)"

	# m_len=19
	jexec alcatraz sysctl net.dummymbuf.rules='inet in epair0b pull-head 19;'
	atf_check -s exit:0 -o ignore ping -c1 192.0.2.2
	atf_check_equal "3" "$(jexec alcatraz sysctl -n net.dummymbuf.hits)"
}
ipfwoff_ip4_in_mbuf_len_cleanup()
{
	pft_cleanup
}

atf_test_case "ipfwon_ip4_in_mbuf_len" "cleanup"
ipfwon_ip4_in_mbuf_len_head()
{
	atf_set descr 'Test that pf can handle the first mbuf with m_len < sizeof(struct ip), with ipfw enabled'
	atf_set require.user root
}
ipfwon_ip4_in_mbuf_len_body()
{
	ipfwoff_ip4_in_mbuf_len_body "ipfwon"
}
ipfwon_ip4_in_mbuf_len_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "ipfwoff_ip4_in_mbuf_len"
	atf_add_test_case "ipfwon_ip4_in_mbuf_len"
}
