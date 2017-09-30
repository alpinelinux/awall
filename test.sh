#!/bin/sh -e

# Alpine Wall test script
# Copyright (C) 2012-2017 Kaarle Ritvanen
# See LICENSE file for license details


cd "$(dirname "$0")"

export LUA_PATH="./?.lua;;"
LUA=lua${LUA_VERSION}

for cls in mandatory optional private; do
    eval "export AWALL_PATH_$(echo $cls | tr a-z A-Z)=test/$cls"
    mkdir -p test/$cls
    for script in test/$cls/*.lua; do
        [ -f "$script" ] && $LUA "$script" > "${script%.lua}.json"
    done
done

exec $LUA ./awall-cli ${1:-diff} -o test/output
