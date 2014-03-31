--[[
Packet marking module for Alpine Wall
Copyright (C) 2012-2014 Kaarle Ritvanen
See LICENSE file for license details
]]--


module(..., package.seeall)

local model = require('awall.model')
local class = model.class

local combinations = require('awall.optfrag').combinations
local util = require('awall.util')


local MarkRule = class(model.Rule)

function MarkRule:init(...)
   model.Rule.init(self, ...)
   if not self.mark then self:error('Mark not specified') end
end

function MarkRule:table() return 'mangle' end

function MarkRule:target() return 'MARK --set-mark '..self.mark end


local RouteTrackRule = class(MarkRule)

function RouteTrackRule:target() return self:newchain('mark') end

function RouteTrackRule:servoptfrags()
   return combinations(
      MarkRule.servoptfrags(self),
      {{opts='-m mark --mark 0'}}
   )
end

function RouteTrackRule:extraoptfrags()
   return {{chain=self:target(), target=MarkRule.target(self)},
	   {chain=self:target(), target='CONNMARK --save-mark'}}
end


local function restoremark(config)
   if util.list(config['route-track'])[1] then
      return combinations(
	 {{family='inet'}, {family='inet6'}},
	 {{chain='OUTPUT'}, {chain='PREROUTING'}},
	 {
	    {
	       table='mangle',
	       opts='-m connmark ! --mark 0',
	       target='CONNMARK --restore-mark'
	    }
	 }
      )
   end
end


export = {
   mark={class=MarkRule},
   ['route-track']={class=RouteTrackRule, before='mark'},
   ['%mark-restore']={rules=restoremark, before='route-track'}
}
