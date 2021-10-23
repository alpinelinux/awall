--[[
Packet logging module for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--


local resolve = require('awall.host').resolve

local model = require('awall.model')
local class = model.class

local schema = require('awall.schema')

local combinations = require('awall.optfrag').combinations
local util = require('awall.util')


local LogLimit = class(model.Limit)

function LogLimit:init(...)
	util.setdefault(self, 'src-mask', false)
	LogLimit.super(self):init(...)
end


local Log = class(model.ConfigObject)

function Log:optfrags()
	local mode = self.mode
	if mode == 'none' then return {} end
	if not (mode or self.mirror) then mode = 'log' end

	local selector, ofrags

	for i, sel in ipairs{'every', 'limit', 'probability'} do
		local value = self[sel]
		if value then
			if selector then
				self:error('Cannot combine '..sel..' with '..selector)
			end
			selector = sel

			if sel == 'every' then
				ofrags = {
					{
						match='-m statistic --mode nth --every '..value..
						' --packet 0'
					}
				}
			elseif sel == 'limit' then
				ofrags = self:create(LogLimit, value, 'loglimit'):limitofrags()
			elseif sel == 'probability' then
				ofrags = {
					{match='-m statistic --mode random --probability '..value}
				}
			else assert(false) end
		end
	end

	local targets = {}

	if mode then
		local optmap = (
			{
				log={level='level', prefix='prefix'},
				nflog={
					group='group',
					prefix='prefix',
					range='size',
					threshold='threshold'
				},
				ulog={
					group='nlgroup',
					prefix='prefix',
					range='cprange',
					threshold='qthreshold'
				}
			}
		)[mode]
		if not optmap then self:error('Invalid logging mode: '..mode) end

		local target = mode:upper()
		for _, s in util.sortedkeys(optmap) do
			local value = self[s]
			if value then
				if s == 'prefix' then value = util.quote(value) end
				target = target..' --'..mode..'-'..optmap[s]..' '..value
			end
		end

		table.insert(
			targets, {family=mode == 'ulog' and 'inet' or nil, target=target}
		)
	end

	for _, addr in resolve(self.mirror, self) do
		table.insert(
			targets, {family=addr[1], target='TEE --gateway '..addr[2]}
		)
	end

	return combinations(ofrags, targets)
end

function Log.get(rule, spec, default)
	if spec == nil then spec = default end
	if spec == false then return end
	if spec == true then spec = '_default' end
	return rule.root.log[spec] or rule:error('Invalid log: '..spec)
end


local LogRule = class(model.Rule)

function LogRule:init(...)
	LogRule.super(self):init(...)
	self.log = Log.get(self, self.log, true)
end

function LogRule:position() return 'prepend' end

function LogRule:mangleoptfrags(ofrags)
	return combinations(ofrags, self.log:optfrags())
end


return {
	export={
		log={
			schema=schema.Record{
				every=schema.Optional(schema.PositiveInteger),
				group=schema.Optional(schema.UInt(16)),
				level=schema.Optional(
					schema.OneOf(
						schema.NonNegativeInteger(7),
						'emerg',
						'alert',
						'crit',
						'error',
						'warning',
						'notice',
						'info',
						'debug'
					)
				),
				limit=schema.Optional(schema.Limit()),
				mirror=schema.List(schema.String),
				mode=schema.Optional(
					schema.OneOf('log', 'nflog', 'none', 'ulog')
				),
				prefix=schema.Optional(schema.String),
				probability=schema.Optional(schema.NumberFrom(0, 1)),
				range=schema.Optional(schema.UInt(32)),
				threshold=schema.Optional(schema.PositiveInteger)
			},
			class=Log
		},
		['packet-log']={
			schema=schema.Rule{log=schema.Optional(schema.String)},
			class=LogRule,
			after='%filter-after'
		}
	}
}

-- vim: ts=4
