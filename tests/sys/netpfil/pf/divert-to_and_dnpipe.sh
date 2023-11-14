#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2023 Igor Ostapenko <pm@igoro.pro>
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

#
# Test case naming legend:
# in - inbound
# div - diverted
# out - outbound
# dn - delayed by dummynet
# ipfwon - with ipfw enabled, which allows all
# ipfwoff - with ipfw disabled
#

. $(atf_get_srcdir)/utils.subr

divert_init()
{
	if ! kldstat -q -m ipdivert; then
		atf_skip "This test requires ipdivert"
	fi
}

dummynet_init()
{
	if ! kldstat -q -m dummynet; then
		atf_skip "This test requires dummynet"
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

atf_test_case "ipfwoff_in_dn_in_div_in_out_dn_out_div_out" "cleanup"
ipfwoff_in_dn_in_div_in_out_dn_out_div_out_head()
{
	atf_set descr 'Test inbound > delayed+diverted > outbound > delayed+diverted > outbound | network terminated'
	atf_set require.user root
}
ipfwoff_in_dn_in_div_in_out_dn_out_div_out_body()
{
	local ipfwon

	pft_init
	divert_init
	dummynet_init
	test "$1" == "ipfwon" && ipfwon="yes"
	test $ipfwon && ipfw_init || assert_ipfw_is_off

	epair=$(vnet_mkepair)
	vnet_mkjail alcatraz ${epair}b
	ifconfig ${epair}a 192.0.2.1/24 up
	ifconfig ${epair}a ether 02:00:00:00:00:01
	jexec alcatraz ifconfig ${epair}b 192.0.2.2/24 up
	test $ipfwon && jexec alcatraz ipfw add 65534 allow all from any to any

	# Sanity check
	atf_check -s exit:0 -o ignore ping -c3 192.0.2.2

	# a) ping should time out due to very narrow dummynet pipes {

	jexec alcatraz dnctl pipe 1001 config bw 1Byte/s
	jexec alcatraz dnctl pipe 1002 config bw 1Byte/s

	jexec alcatraz pfctl -e
	pft_set_rules alcatraz \
		"ether pass in from 02:00:00:00:00:01 l3 all dnpipe 1001" \
		"ether pass out to 02:00:00:00:00:01 l3 all dnpipe 1002 " \
		"pass all" \
		"pass in inet proto icmp icmp-type echoreq divert-to 127.0.0.1 port 1001 no state" \
		"pass out inet proto icmp icmp-type echorep divert-to 127.0.0.1 port 1002 no state"

	jexec alcatraz $(atf_get_srcdir)/divapp 1001 divert-back &
	indivapp_pid=$!
	jexec alcatraz $(atf_get_srcdir)/divapp 1002 divert-back &
	outdivapp_pid=$!
	# Wait for the divappS to be ready
	sleep 1

	atf_check -s not-exit:0 -o ignore ping -c1 -s56 -t1 192.0.2.2

	wait $indivapp_pid
	atf_check_not_equal 0 $?
	wait $outdivapp_pid
	atf_check_not_equal 0 $?

	# }

	# b) ping should NOT time out due to wide enough dummynet pipes {

	jexec alcatraz dnctl pipe 2001 config bw 100KByte/s
	jexec alcatraz dnctl pipe 2002 config bw 100KByte/s

	jexec alcatraz pfctl -e
	pft_set_rules alcatraz \
		"ether pass in from 02:00:00:00:00:01 l3 all dnpipe 2001" \
		"ether pass out to 02:00:00:00:00:01 l3 all dnpipe 2002 " \
		"pass all" \
		"pass in inet proto icmp icmp-type echoreq divert-to 127.0.0.1 port 2001 no state" \
		"pass out inet proto icmp icmp-type echorep divert-to 127.0.0.1 port 2002 no state"

	jexec alcatraz $(atf_get_srcdir)/divapp 2001 divert-back &
	indivapp_pid=$!
	jexec alcatraz $(atf_get_srcdir)/divapp 2002 divert-back &
	outdivapp_pid=$!
	# Wait for the divappS to be ready
	sleep 1

	atf_check -s exit:0 -o ignore ping -c1 -s56 -t1 192.0.2.2

	wait $indivapp_pid
	atf_check_equal 0 $?
	wait $outdivapp_pid
	atf_check_equal 0 $?

	# }
}
ipfwoff_in_dn_in_div_in_out_dn_out_div_out_cleanup()
{
	pft_cleanup
}

atf_test_case "ipfwon_in_dn_in_div_in_out_dn_out_div_out" "cleanup"
ipfwon_in_dn_in_div_in_out_dn_out_div_out_head()
{
	atf_set descr 'Test inbound > delayed+diverted > outbound > delayed+diverted > outbound | network terminated, with ipfw enabled'
	atf_set require.user root
}
ipfwon_in_dn_in_div_in_out_dn_out_div_out_body()
{
	ipfwoff_in_dn_in_div_in_out_dn_out_div_out_body "ipfwon"
}
ipfwon_in_dn_in_div_in_out_dn_out_div_out_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "ipfwoff_in_dn_in_div_in_out_dn_out_div_out"
	atf_add_test_case "ipfwon_in_dn_in_div_in_out_dn_out_div_out"
}
