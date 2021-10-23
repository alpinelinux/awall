--[[
Packet marking module for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--


local model = require('awall.model')
local class = model.class

local optfrag = require('awall.optfrag')
local combinations = optfrag.combinations

local schema = require('awall.schema')
local list = require('awall.util').list


local MarkRule = class(model.Rule)

function MarkRule:init(...)
	MarkRule.super(self):init(...)
	if not self.mark then self:error('Mark not specified') end
end

function MarkRule:table() return 'mangle' end

function MarkRule:target() return 'MARK --set-mark '..self.mark end


local RouteTrackRule = class(MarkRule)

function RouteTrackRule:mangleoptfrags(ofrags)
	return self:combine(
		combinations(ofrags, {{match='-m mark --mark 0'}}),
		{{}, {target='CONNMARK --save-mark'}},
		'mark'
	)
end


local function restoremark(config)
	if list(config['route-track'])[1] then
		return optfrag.expandfamilies(
			combinations(
				{{chain='OUTPUT'}, {chain='PREROUTING'}},
				{
					{
						table='mangle',
						match='-m connmark ! --mark 0',
						target='CONNMARK --restore-mark'
					}
				}
			)
		)
	end
end


local MarkSchema = schema.Rule{mark=schema.UInt(32)}

return {
	export={
		mark={schema=MarkSchema, class=MarkRule},
		['route-track']={
			schema=MarkSchema, class=RouteTrackRule, before='mark'
		},
		['%mark-restore']={rules=restoremark, before='route-track'}
	}
}

-- vim: ts=4
