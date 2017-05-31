#!/bin/sh -e

# Alpine Wall test script
# Copyright (C) 2012-2017 Kaarle Ritvanen
# See LICENSE file for license details


cd "$(dirname "$0")"

export LUA_PATH="./?.lua;;"

for cls in mandatory optional private; do
    eval "export AWALL_PATH_$(echo $cls | tr a-z A-Z)=test/$cls"
    mkdir -p test/$cls
done

exec lua${LUA_VERSION} ./awall-cli ${1:-diff} -o test/output
