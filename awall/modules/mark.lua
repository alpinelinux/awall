--[[
Packet marking module for Alpine Wall
Copyright (C) 2012-2013 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall.model'
require 'awall.optfrag'
require 'awall.util'

local model = awall.model


local MarkRule = model.class(model.Rule)

function MarkRule:table() return 'mangle' end

function MarkRule:target()
   if not self.mark then self:error('Mark not specified') end
   return 'MARK --set-mark '..self.mark
end


local RouteTrackRule = model.class(MarkRule)

function RouteTrackRule:target() return self:newchain('mark') end

function RouteTrackRule:servoptfrags()
   return awall.optfrag.combinations(MarkRule.servoptfrags(self),
				     {{opts='-m mark --mark 0'}})
end

function RouteTrackRule:extraoptfrags()
   return {{chain=self:target(), target=MarkRule.target(self)},
	   {chain=self:target(), target='CONNMARK --save-mark'}}
end


local function rt(config)
   local res = {}
   if awall.util.list(config['route-track'])[1] then
      for i, family in ipairs({'inet', 'inet6'}) do
	 for i, chain in ipairs({'OUTPUT', 'PREROUTING'}) do
	    table.insert(res,
			 {family=family,
			  table='mangle',
			  chain=chain,
			  opts='-m connmark ! --mark 0',
			  target='CONNMARK --restore-mark'})
	 end
      end
   end
   return res
end

export = {
   mark={class=MarkRule},
   ['route-track']={class=RouteTrackRule, before='mark'},
   ['%mark-rt']={rules=rt, before='route-track'}
}
