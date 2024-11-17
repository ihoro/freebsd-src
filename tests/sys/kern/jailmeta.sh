#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2024 SkunkWerks GmbH
#
# This software was developed by Igor Ostapenko <igoro@FreeBSD.org>
# under sponsorship from SkunkWerks GmbH.
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

setup()
{
	if [ $(sysctl -n security.jail.meta_maxbufsize) -lt 10 ]; then
		atf_skip "sysctl security.jail.meta_maxbufsize must be 10+ for testing."
	fi
}

atf_test_case "jail_create" "cleanup"
jail_create_head()
{
	atf_set descr 'Test that meta can be set upon jail creation with jail(8)'
}
jail_create_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j jail1

	atf_check -s exit:0 \
	    jail -c name=jail1 persist meta="a b c"

	atf_check -s exit:0 -o inline:"a b c\n" \
	    jls -j jail1 meta
}
jail_create_cleanup()
{
	jail -r jail1
	return 0
}

atf_test_case "jail_modify" "cleanup"
jail_modify_head()
{
	atf_set descr 'Test that meta can be modified after jail creation with jail(8)'
}
jail_modify_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j jail1

	atf_check -s exit:0 \
	    jail -c name=jail1 persist meta="a	b	c"

	atf_check -s exit:0 -o inline:"a	b	c\n" \
	    jls -j jail1 meta

	atf_check -s exit:0 \
	    jail -m name=jail1 meta="t1=A t2=B"

	atf_check -s exit:0 -o inline:"t1=A t2=B\n" \
	    jls -j jail1 meta
}
jail_modify_cleanup()
{
	jail -r jail1
	return 0
}

atf_test_case "jail_add" "cleanup"
jail_add_head()
{
	atf_set descr 'Test that meta can be added to an existing jail with jail(8)'
}
jail_add_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j jail1

	atf_check -s exit:0 \
	    jail -c name=jail1 persist host.hostname=jail1

	atf_check -s exit:0 -o inline:'""\n' \
	    jls -j jail1 meta

	atf_check -s exit:0 \
	    jail -m name=jail1 meta="$(jot 3 1 3)"

	atf_check -s exit:0 -o inline:"1\n2\n3\n" \
	    jls -j jail1 meta
}
jail_add_cleanup()
{
	jail -r jail1
	return 0
}

atf_test_case "jls_libxo" "cleanup"
jls_libxo_head()
{
	atf_set descr 'Test that meta can be read with jls(8) using libxo'
}
jls_libxo_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j jail1

	atf_check -s exit:0 \
	    jail -c name=jail1 persist meta="a b c"

	atf_check -s exit:0 -o inline:'{"__version": "2", "jail-information": {"jail": [{"name":"jail1","meta":"a b c"}]}}\n' \
	    jls -j jail1 --libxo json name meta
}
jls_libxo_cleanup()
{
	jail -r jail1
	return 0
}

atf_test_case "flua_create" "cleanup"
flua_create_head()
{
	atf_set descr 'Test that meta can be set upon jail creation with flua'
}
flua_create_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j jail1

	atf_check -s exit:0 \
	    /usr/libexec/flua -ljail -e 'jail.setparams("jail1", {["meta"]="t1 t2=v2", ["persist"]="true"}, jail.CREATE)'

	atf_check -s exit:0 -o inline:"t1 t2=v2\n" \
	    /usr/libexec/flua -ljail -e 'jid, res = jail.getparams("jail1", {"meta"}); print(res["meta"])'
}
flua_create_cleanup()
{
	jail -r jail1
	return 0
}

atf_test_case "flua_modify" "cleanup"
flua_modify_head()
{
	atf_set descr 'Test that meta can be changed with flua after jail creation'
}
flua_modify_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j jail1

	atf_check -s exit:0 \
	    jail -c name=jail1 persist meta="ABC"

	atf_check -s exit:0 -o inline:"ABC\n" \
	    jls -j jail1 meta

	atf_check -s exit:0 \
	    /usr/libexec/flua -ljail -e 'jail.setparams("jail1", {["meta"]="t1 t2=v"}, jail.UPDATE)'

	atf_check -s exit:0 -o inline:"t1 t2=v\n" \
	    jls -j jail1 meta
}
flua_modify_cleanup()
{
	jail -r jail1
	return 0
}

atf_init_test_cases()
{
	atf_add_test_case "jail_create"
	atf_add_test_case "jail_modify"
	atf_add_test_case "jail_add"
#	atf_add_test_case "jail_reset"

	atf_add_test_case "jls_libxo"

	atf_add_test_case "flua_create"
	atf_add_test_case "flua_modify"
#	atf_add_test_case "flua_add"
#
#	atf_add_test_case "inc_maxbufsize"
#	atf_add_test_case "dec_maxbufsize"
}
