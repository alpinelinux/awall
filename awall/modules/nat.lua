--[[
NAT module for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall.model'

local model = awall.model


local NATRule = model.class(model.ForwardOnlyRule)

function NATRule:trules()
   local res = {}
   for i, ofrags in ipairs(model.ForwardOnlyRule.trules(self)) do
      if ofrags.family == 'inet' then table.insert(res, ofrags) end
   end
   return res
end

function NATRule:table() return 'nat' end

function NATRule:chain() return self.params.chain end

function NATRule:target()
   if self.action then return model.ForwardOnlyRule.target(self) end

   local target
   if self['ip-range'] then
      target = self.params.target..' --to-'..self.params.subject..' '..self['ip-range']
   else target = self.params.deftarget end

   if self['port-range'] then target = target..':'..self['port-range'] end
   return target
end


local DNATRule = model.class(NATRule)

function DNATRule:init(...)
   NATRule.init(self, unpack(arg))
   self.params = {forbidif='out', subject='destination',
		  chain='PREROUTING', target='DNAT', deftarget='REDIRECT'}
end


local SNATRule = model.class(NATRule)

function SNATRule:init(...)
   NATRule.init(self, unpack(arg))
   self.params = {forbidif='in', subject='source',
		  chain='POSTROUTING', target='SNAT', deftarget='MASQUERADE'}
end


classes = {{'dnat', DNATRule},
	   {'snat', SNATRule}}

defrules = {}
