--[[
Dependency order resolver for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--

local util = require('awall.util')
local contains = util.contains
local sortedkeys = util.sortedkeys

return function(items)
	local visited = {}
	local res = {}

	local function visit(key)
		if contains(res, key) then return end
		if visited[key] then return key end
		visited[key] = true

		local after = util.list(items[key].after)
		for _, k in sortedkeys(items) do
			if contains(items[k].before, key) then table.insert(after, k) end
		end
		for i, k in ipairs(after) do
			if items[k] then
				local ek = visit(k)
				if ek ~= nil then return ek end
			end
		end

		table.insert(res, key)
	end

	for _, k in sortedkeys(items) do
		local ek = visit(k)
		if ek ~= nil then return ek end
	end

	return res
end

-- vim: ts=4
