--[[
NAT module for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall.model'
require 'awall.util'

local model = awall.model


local NATRule = model.class(model.Rule)

function NATRule:init(context)
   model.Rule.init(self, context)
   for i, dir in ipairs({'in', 'out'}) do
      if awall.util.contains(self[dir], model.fwzone) then
	 error('NAT rules not allowed for firewall zone')
      end
   end
end

function NATRule:defaultzones() return {nil} end

function NATRule:checkzoneoptfrag(ofrag)
   if ofrag[self.params.forbidif] then
      error('Cannot specify '..self.params.forbidif..'bound interface for '..target..' rule')
   end
end

function NATRule:trules()
   local res = {}
   for i, ofrags in ipairs(model.Rule.trules(self)) do
      if ofrags.family == 'inet' then table.insert(res, ofrags) end
   end
   return res
end

function NATRule:table() return 'nat' end

function NATRule:chain() return self.params.chain end

function NATRule:target()
   if not self['ip-range'] then error('IP range not defined for NAT rule') end
   local target = self.params.target..' --to-'..self.params.subject..' '..self['ip-range']
   if self['port-range'] then target = target..':'..self['port-range'] end
   return target
end


local DNATRule = model.class(NATRule)

function DNATRule:init(context)
   NATRule.init(self, context)
   self.params = {forbidif='out', subject='destination',
		  chain='PREROUTING', target='DNAT'}
end


local SNATRule = model.class(NATRule)

function SNATRule:init(context)
   NATRule.init(self, context)
   self.params = {forbidif='in', subject='source',
		  chain='POSTROUTING', target='SNAT'}
end

function SNATRule:target()
   if self['ip-range'] then return NATRule.target(self) end
   return 'MASQUERADE'..(self['port-range'] and ' --to-ports '..self['port-range'] or '')
end


classmap = {dnat=DNATRule, snat=SNATRule}

-- TODO configuration of the ipset via JSON config
defrules = {{family='inet', table='nat', chain='POSTROUTING',
	     opts='-m set --match-set awall-masquerade src -j awall-masquerade'},
	    {family='inet', table='nat', chain='awall-masquerade',
	     opts='-m set ! --match-set awall-masquerade dst -j MASQUERADE'}}
