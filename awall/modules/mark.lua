--[[
Packet marking module for Alpine Wall
Copyright (C) 2012-2014 Kaarle Ritvanen
See LICENSE file for license details
]]--


local model = require('awall.model')
local class = model.class

local combinations = require('awall.optfrag').combinations
local list = require('awall.util').list


local MarkRule = class(model.Rule)

function MarkRule:init(...)
   MarkRule.super(self):init(...)
   if not self.mark then self:error('Mark not specified') end
end

function MarkRule:table() return 'mangle' end

function MarkRule:target() return 'MARK --set-mark '..self.mark end


local RouteTrackRule = class(MarkRule)

function RouteTrackRule:target() return self:uniqueid('mark') end

function RouteTrackRule:servoptfrags()
   return combinations(
      RouteTrackRule.super(self):servoptfrags(), {{opts='-m mark --mark 0'}}
   )
end

function RouteTrackRule:extraoptfrags()
   return {
      {chain=self:target(), target=RouteTrackRule.super(self).target()},
      {chain=self:target(), target='CONNMARK --save-mark'}
   }
end


local function restoremark(config)
   if list(config['route-track'])[1] then
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


return {
   export={
      mark={class=MarkRule},
      ['route-track']={class=RouteTrackRule, before='mark'},
      ['%mark-restore']={rules=restoremark, before='route-track'}
   }
}
