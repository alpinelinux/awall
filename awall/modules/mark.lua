--[[
Packet marking module for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall.model'
require 'awall.optfrag'
require 'awall.util'

local model = awall.model


local MarkRule = model.class(model.ForwardOnlyRule)

function MarkRule:table() return 'mangle' end

function MarkRule:target()
   if not self.mark then self:error('Mark not specified') end
   return 'MARK --set-mark '..self.mark
end


local RouteTrackRule = model.class(MarkRule)

function RouteTrackRule:target()
   if not self['mark-target'] then
      self['mark-target'] = self:newchain('mark')
   end
   return self['mark-target']
end

function RouteTrackRule:servoptfrags()
   return awall.optfrag.combinations(MarkRule.servoptfrags(self),
				     {{opts='-m mark --mark 0'}})
end

function RouteTrackRule:extraoptfrags()
   return {{chain=self:target(), opts='-j '..MarkRule.target(self)},
	   {chain=self:target(), opts='-j CONNMARK --save-mark'}}
end


classes = {{'route-track', RouteTrackRule},
	   {'mark', MarkRule}}

defrules = {}

function defrules.pre(config)
   local res = {}
   if awall.util.list(config['route-track'])[1] then
      for i, family in ipairs({'inet', 'inet6'}) do
	 for i, chain in ipairs({'OUTPUT', 'PREROUTING'}) do
	    table.insert(res,
			 {family=family,
			  table='mangle',
			  chain=chain,
			  opts='-m connmark ! --mark 0 -j CONNMARK --restore-mark'})
	 end
      end
   end
   return res
end
