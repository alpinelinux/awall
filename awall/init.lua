--[[
Alpine Wall main module
Copyright (C) 2012-2024 Kaarle Ritvanen
See LICENSE file for license details
]]--


local M = {}

local class = require('awall.class')
local IPSet = require('awall.ipset')
local iptables = require('awall.iptables')
local combinations = require('awall.optfrag').combinations
M.PolicySet = require('awall.policy')
local util = require('awall.util')

local startswith = require('stringy').startswith


M.Config = class()

function M.Config:init(policyconfig)

	self.objects = policyconfig:expand()
	self.model = policyconfig.model

	local dedicated = self.objects.variable.awall_dedicated_chains
	self.iptables = iptables.IPTables()
	self.ruleset = (
		dedicated and iptables.PartialIPTablesRuleset or
		iptables.IPTablesRuleset
	)(self.iptables)
	self.prefix = dedicated and 'awall-' or ''

	local actions = {}

	local function insertrules(trules, obj)
		for _, trule in ipairs(trules) do
			local t = self.ruleset.rules[trule.family][trule.table][
				self.prefix..trule.chain
			]
			local opts = self:ofragcmd(trule)

			if trule.target then
				local acfrag = {
					family=trule.family,
					table=trule.table,
					chain=trule.target
				}
				local key = self:ofragloc(acfrag)
				if not actions[key] then
					actions[key] = true
					if startswith(trule.target, 'custom:') then
						local name = trule.target:sub(8, -1)
						local rules = (self.objects.custom or {})[name]
						if not rules then
							obj:error('Invalid custom chain: '..name)
						end
						insertrules(
							combinations(util.list(rules), {acfrag}), rules
						)
					else
						insertrules(combinations(self.model.actions, {acfrag}))
					end
				end
			end

			if trule.position == 'prepend' then table.insert(t, 1, opts)
			else table.insert(t, opts) end
		end
	end

	for _, stage in self.model:stages() do
		local cls = self:loadclass(stage)
		if cls then
			local objs = self.objects[stage]
			if objs then
				for k, v in pairs(objs) do objs[k] = cls.morph(v, self) end
			end
		end
	end

	for _, stage in self.model:stages() do
		if self:loadclass(stage) then
			for _, rule in ipairs(self.objects[stage] or {}) do
				insertrules(rule:trules(), rule)
			end
		else
			local r = self.model:rules(stage)
			if r then
				if type(r) == 'function' then r = r(self.objects) end
				if r then
					assert(type(r) == 'table')
					insertrules(r)
				end
			end
		end
	end

	self.ipset = IPSet(self.objects.ipset)
end

function M.Config:loadclass(name) return self.model:loadclass(name) end

function M.Config:ofragloc(of)
	return of.family..'/'..of.table..'/'..self.prefix..of.chain
end

function M.Config:ofragcmd(of)
	local target = ''
	if of.target then
		target = '-j '..(
			util.startswithupper(of.target) and '' or self.prefix
		)..of.target
	end
	return (of.match and of.match..' ' or '')..target
end

function M.Config:print()
	self.ipset:print()
	io.write('\n')
	self.ruleset:print()
end

function M.Config:dump(dir)
	self.ipset:dump(dir and dir..'/ipset-' or '/etc/ipset.d/')
	self.ruleset:dump(dir or '/etc/iptables')
end

function M.Config:test()
	self.ipset:create()
	self.ruleset:test()
end

function M.Config:activate()
	self:test()
	self.ruleset:activate()
end

function M.Config:fwenabled() return self.iptables:isenabled() end
function M.Config:backup() self.iptables:backup() end
function M.Config:revert() self.iptables:revert() end
function M.Config:flush() self.ruleset:flush() end
function M.Config:flushall() self.iptables:flush() end


return M

-- vim: ts=4
