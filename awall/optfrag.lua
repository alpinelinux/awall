--[[
Option fragment module for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--


local M = {}

local FAMILIES = require('awall.family').ALL

local util = require('awall.util')
local map = util.map

local function ffrags(families)
	return map(families, function(f) return {family=f} end)
end

function M.combinations(of1, ...)
	local arg = {...}

	if #arg == 0 then return of1 end

	if not of1 then return M.combinations(...) end

	local of2 = arg[1]
	table.remove(arg, 1)
	if not of2 then return M.combinations(of1, table.unpack(arg)) end

	local res = {}
	for i, x in ipairs(of1) do
		for i, y in ipairs(of2) do

			local of = {}
			for k, v in pairs(x) do
				if k ~= 'match' then of[k] = v end
			end

			local match = true
			for k, v in pairs(y) do
				if k ~= 'match' then
					if of[k] and v ~= of[k] then
						match = false
						break
					end
					of[k] = v
				end
			end

			if match then
				if x.match then
					if y.match then of.match = x.match..' '..y.match
					else of.match = x.match end
				else of.match = y.match end
				table.insert(res, of)
			end
		end
	end

	return M.combinations(res, table.unpack(arg))
end

function M.expandfamilies(ofrags, families)
	return M.combinations(
		ffrags(families and util.list(families) or FAMILIES), ofrags
	)
end

function M.prune(...)
	local arg = {...}
	local families = {}

	for i, ofrags in ipairs(arg) do
		families[i] = {}
		for _, ofrag in ipairs(ofrags) do
			if not ofrag.family then
				families[i] = false
				break
			end
			families[i][ofrag.family] = true
		end
	end

	local ff
	for _, f in ipairs(families) do
		ff = M.combinations(ff, f and ffrags(util.keys(f)) or nil)
	end
	return table.unpack(
		map(arg, function(ofs) return M.combinations(ofs, ff) end)
	)
end

return M

-- vim: ts=4
