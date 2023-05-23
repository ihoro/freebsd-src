#!/bin/sh

# Quick check to make sure all emails in the branch are good
# Anything with noreply in the address

bad=$(git log --prety="%ae" "$@" | grep noreply)
if [ -n "${bad}" ] ; then
    echo "Found the following bad email addresses: ${bad}"
    exit 1
fi
exit 0
