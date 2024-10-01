--[[
Address family module for Alpine Wall
Copyright (C) 2012-2024 Kaarle Ritvanen
See LICENSE file for license details
]]--

local M = {DOMAIN_PATTERN='[%.%w-]+'}

local keys = require('awall.util').keys
local stat = require('posix').stat

local procfiles = {inet='raw', inet6='raw6'}

M.ALL = keys(procfiles)
table.sort(M.ALL)

function M.isactive(family) return stat('/proc/net/'..procfiles[family]) end

function M.identify(addr, context)
	for _, pattern in ipairs{
		{'inet', '[%.%d/-]+'},
		{'domain', M.DOMAIN_PATTERN},
		{'inet6', '[:%x/-]+'}
	} do
		if addr:match('^'..pattern[2]..'$') then return pattern[1] end
	end
	context:error('Malformed host specification: '..addr)
end

return M

-- vim: ts=4
