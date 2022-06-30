#!/bin/sh -e

# Alpine Wall test script
# Copyright (C) 2012-2022 Kaarle Ritvanen
# See LICENSE file for license details


cd "$(dirname "$0")"

export LUA_PATH="./?.lua;;"
LUA=lua${LUA_VERSION}
AWALL="$LUA ./awall-cli"

GEN_POLICIES=

for cls in mandatory optional private; do
    eval "export AWALL_PATH_$(echo $cls | tr a-z A-Z)=test/$cls"
    mkdir -p test/$cls
    for script in test/$cls/*.lua; do
	[ -f $script ] || continue
	policy=${script%.lua}.json
	GEN_POLICIES="$GEN_POLICIES $policy"
	$LUA $script > $policy
    done
done

POLICIES=$(ls test/optional/*.json | sed -E 's:^.*/([^/]+).json$:\1:')

for pol in $POLICIES; do
    $AWALL disable $pol 2>/dev/null
done

[ "$1" = translate ] && rm -f test/output/*/ipset-*

RC=0
for pol in $POLICIES; do
    dir=test/output/$pol
    mkdir -p $dir

    $AWALL enable $pol
    $AWALL ${1:-diff} -o $dir || RC=1
    $AWALL disable $pol
done

rm $GEN_POLICIES

exit $RC
