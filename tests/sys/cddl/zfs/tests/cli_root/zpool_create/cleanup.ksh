#!/usr/local/bin/ksh93 -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

. $STF_SUITE/include/libtest.kshlib
. $STF_SUITE/tests/cli_root/zpool_create/zpool_create.kshlib

clean_blockfile "$TESTDIR $TESTDIR0 $TESTDIR1"

for pool in $TESTPOOL2 $TESTPOOL1 $TESTPOOL; do
	if poolexists $pool; then
		destroy_pool $pool
	fi
done

cleanup_devices $DISKS

log_pass
