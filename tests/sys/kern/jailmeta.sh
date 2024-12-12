#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2024 SkunkWerks GmbH
#
# This software was developed by Igor Ostapenko <igoro@FreeBSD.org>
# under sponsorship from SkunkWerks GmbH.
#

setup()
{
	if [ $(sysctl -n security.jail.meta_maxsize) -lt 10 ]; then
		atf_skip "sysctl security.jail.meta_maxsize must be 10+ for testing."
	fi
}

atf_test_case "jail_create" "cleanup"
jail_create_head()
{
	atf_set descr 'Test that meta can be set upon jail creation with jail(8)'
	atf_set require.user root
	atf_set execenv jail
}
jail_create_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j jail1

	atf_check -s exit:0 \
	    jail -c name=jail1 persist meta="a b c" env="C B A"

	atf_check -s exit:0 -o inline:"a b c\n" \
	    jls -j jail1 meta
	atf_check -s exit:0 -o inline:"C B A\n" \
	    jls -j jail1 env
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
	atf_set require.user root
	atf_set execenv jail
}
jail_modify_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j jail1

	atf_check -s exit:0 \
	    jail -c name=jail1 persist meta="a	b	c" env="internal"

	atf_check -s exit:0 -o inline:"a	b	c\n" \
	    jls -j jail1 meta
	atf_check -s exit:0 -o inline:"internal\n" \
	    jls -j jail1 env

	atf_check -s exit:0 \
	    jail -m name=jail1 meta="t1=A t2=B" env="internal2"

	atf_check -s exit:0 -o inline:"t1=A t2=B\n" \
	    jls -j jail1 meta
	atf_check -s exit:0 -o inline:"internal2\n" \
	    jls -j jail1 env
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
	atf_set require.user root
	atf_set execenv jail
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
	atf_check -s exit:0 -o inline:'""\n' \
	    jls -j jail1 env

	atf_check -s exit:0 \
	    jail -m name=jail1 meta="$(jot 3 1 3)" env="$(jot 2 11 12)"

	atf_check -s exit:0 -o inline:"1\n2\n3\n" \
	    jls -j jail1 meta
	atf_check -s exit:0 -o inline:"11\n12\n" \
	    jls -j jail1 env
}
jail_add_cleanup()
{
	jail -r jail1
	return 0
}

atf_test_case "jail_reset" "cleanup"
jail_reset_head()
{
	atf_set descr 'Test that meta can be reset to an empty string with jail(8)'
	atf_set require.user root
	atf_set execenv jail
}
jail_reset_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j jail1

	atf_check -s exit:0 \
	    jail -c name=jail1 persist meta="123" env="456"

	atf_check -s exit:0 -o inline:"123\n" \
	    jls -j jail1 meta
	atf_check -s exit:0 -o inline:"456\n" \
	    jls -j jail1 env

	atf_check -s exit:0 \
	    jail -m name=jail1 meta= env=

	atf_check -s exit:0 -o inline:'""\n' \
	    jls -j jail1 meta
	atf_check -s exit:0 -o inline:'""\n' \
	    jls -j jail1 env
}
jail_reset_cleanup()
{
	jail -r jail1
	return 0
}

atf_test_case "jls_libxo" "cleanup"
jls_libxo_head()
{
	atf_set descr 'Test that meta can be read with jls(8) using libxo'
	atf_set require.user root
	atf_set execenv jail
}
jls_libxo_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j jail1

	atf_check -s exit:0 \
	    jail -c name=jail1 persist meta="a b c" env="1 2 3"

	atf_check -s exit:0 -o inline:'{"__version": "2", "jail-information": {"jail": [{"name":"jail1","meta":"a b c"}]}}\n' \
	    jls -j jail1 --libxo json name meta
	atf_check -s exit:0 -o inline:'{"__version": "2", "jail-information": {"jail": [{"env":"1 2 3"}]}}\n' \
	    jls -j jail1 --libxo json env
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
	atf_set require.user root
	atf_set execenv jail
}
flua_create_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j jail1

	atf_check -s exit:0 \
	    /usr/libexec/flua -ljail -e 'jail.setparams("jail1", {["meta"]="t1 t2=v2", ["env"]="secret", ["persist"]="true"}, jail.CREATE)'

	atf_check -s exit:0 -o inline:"t1 t2=v2\n" \
	    /usr/libexec/flua -ljail -e 'jid, res = jail.getparams("jail1", {"meta"}); print(res["meta"])'
	atf_check -s exit:0 -o inline:"secret\n" \
	    /usr/libexec/flua -ljail -e 'jid, res = jail.getparams("jail1", {"env"}); print(res["env"])'
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
	atf_set require.user root
	atf_set execenv jail
}
flua_modify_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j jail1

	atf_check -s exit:0 \
	    jail -c name=jail1 persist meta="ABC" env="123"

	atf_check -s exit:0 -o inline:"ABC\n" \
	    jls -j jail1 meta
	atf_check -s exit:0 -o inline:"123\n" \
	    jls -j jail1 env

	atf_check -s exit:0 \
	    /usr/libexec/flua -ljail -e 'jail.setparams("jail1", {["meta"]="t1 t2=v", ["env"]="4"}, jail.UPDATE)'

	atf_check -s exit:0 -o inline:"t1 t2=v\n" \
	    jls -j jail1 meta
	atf_check -s exit:0 -o inline:"4\n" \
	    jls -j jail1 env
}
flua_modify_cleanup()
{
	jail -r jail1
	return 0
}

atf_test_case "readable_from_jail" "cleanup"
readable_from_jail_head()
{
	atf_set descr 'Test that a jail can read its internal meta parameter via sysctl(8)'
	atf_set require.user root
	atf_set execenv jail
}
readable_from_jail_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j jail1

	atf_check -s exit:0 \
	    jail -c name=jail1 persist meta="a b c" env="internal data"

	atf_check -s exit:0 -o inline:"a b c\n" \
	    jls -j jail1 meta
	atf_check -s exit:0 -o inline:"internal data\n" \
	    jls -j jail1 env

	atf_check -s exit:0 -o inline:"internal data\n" \
	    jexec jail1 sysctl -n security.jail.env
}
readable_from_jail_cleanup()
{
	jail -r jail1
	return 0
}

atf_test_case "not_inheritable" "cleanup"
not_inheritable_head()
{
	atf_set descr 'Test that a jail does not inherit meta parameter from its parent jail'
	atf_set require.user root
	atf_set execenv jail
}
not_inheritable_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j parent

	atf_check -s exit:0 \
	    jail -c name=parent children.max=1 persist meta="parent-ext" env="parent-int"

	jexec parent jail -c name=child persist

	atf_check -s exit:0 -o inline:"parent-ext\n" \
	    jls -j parent meta
	atf_check -s exit:0 -o inline:'""\n' \
	    jls -j parent.child meta

	atf_check -s exit:0 -o inline:"parent-int\n" \
	    jexec parent sysctl -n security.jail.env
	atf_check -s exit:0 -o inline:"\n" \
	    jexec parent.child sysctl -n security.jail.env
}
not_inheritable_cleanup()
{
	jail -r parent.child
	jail -r parent
	return 0
}

atf_test_case "maxsize" "cleanup"
maxsize_head()
{
	atf_set descr 'Test that meta buffer maximum size can be changed via sysctl from prison0'
	atf_set require.user root
}
maxsize_body()
{
	setup

	jn=jailmeta_maxsize

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j $jn

	# the size counts string length and the trailing \0 char
	origmax=$(sysctl -n security.jail.meta_maxsize)

	# must be fine with current max
	atf_check -s exit:0 \
	    jail -c name=$jn persist meta="$(printf %$((origmax-1))s)"
	atf_check -s exit:0 -o inline:"${origmax}\n" \
	    jls -j $jn meta | wc -c
	#
	atf_check -s exit:0 \
	    jail -m name=$jn env="$(printf %$((origmax-1))s)"
	atf_check -s exit:0 -o inline:"${origmax}\n" \
	    jls -j $jn env | wc -c

	# should not allow exceeding current max
	atf_check -s not-exit:0 -e match:"too large" \
	    jail -m name=$jn meta="$(printf %${origmax}s)"
	#
	atf_check -s not-exit:0 -e match:"too large" \
	    jail -m name=$jn env="$(printf %${origmax}s)"

	# should allow the same size with increased max
	newmax=$((origmax + 1))
	sysctl security.jail.meta_maxsize=$newmax
	atf_check -s exit:0 \
	    jail -m name=$jn meta="$(printf %${origmax}s)"
	atf_check -s exit:0 -o inline:"${origmax}\n" \
	    jls -j $jn meta | wc -c
	#
	atf_check -s exit:0 \
	    jail -m name=$jn env="$(printf %${origmax}s)"
	atf_check -s exit:0 -o inline:"${origmax}\n" \
	    jls -j $jn env | wc -c

	# decrease back to the original max
	sysctl security.jail.meta_maxsize=$origmax
	atf_check -s not-exit:0 -e match:"too large" \
	    jail -m name=$jn meta="$(printf %${origmax}s)"
	#
	atf_check -s not-exit:0 -e match:"too large" \
	    jail -m name=$jn env="$(printf %${origmax}s)"

	# the previously set long meta is still readable as is
	# due to the soft limit remains higher than the hard limit
	atf_check_equal '${newmax}' '$(sysctl -n security.jail.param.meta)'
	atf_check_equal '${newmax}' '$(sysctl -n security.jail.param.env)'
	atf_check -s exit:0 -o inline:"${origmax}\n" \
	    jls -j $jn meta | wc -c
	#
	atf_check -s exit:0 -o inline:"${origmax}\n" \
	    jls -j $jn env | wc -c
}
maxsize_cleanup()
{
	jail -r jailmeta_maxsize
	return 0
}

atf_init_test_cases()
{
	atf_add_test_case "jail_create"
	atf_add_test_case "jail_modify"
	atf_add_test_case "jail_add"
	atf_add_test_case "jail_reset"

	atf_add_test_case "jls_libxo"

	atf_add_test_case "flua_create"
	atf_add_test_case "flua_modify"

	atf_add_test_case "readable_from_jail"
	atf_add_test_case "not_inheritable"

	atf_add_test_case "maxsize"
}
