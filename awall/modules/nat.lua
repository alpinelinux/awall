--[[
NAT module for Alpine Wall
Copyright (C) 2012-2015 Kaarle Ritvanen
See LICENSE file for license details
]]--


local model = require('awall.model')
local class = model.class

local contains = require('awall.util').contains


local NATRule = class(model.Rule)

-- alpine v2.4 compatibility
function NATRule:init(...)
   NATRule.super(self):init(...)
   local attrs = {['ip-range']='to-addr', ['port-range']='to-port'}
   for old, new in pairs(attrs) do
      if not self[new] and self[old] then
	 self:warning(old..' deprecated in favor of '..new)
	 self[new] = self[old]
      end
   end
end

function NATRule:trules()
   local res = {}
   for i, ofrags in ipairs(NATRule.super(self):trules()) do
      if not contains(self.params.chains, ofrags.chain) then
	 self:error('Inappropriate zone definitions for a '..self.params.target..' rule')
      end
      if ofrags.family == 'inet' then table.insert(res, ofrags) end
   end
   return res
end

function NATRule:table() return 'nat' end

function NATRule:target()
   local target = NATRule.super(self):target()

   if not target then
      local addr = self['to-addr']
      if addr then
	 target = self.params.target..' --to-'..self.params.subject..' '..addr
      else target = self.params.deftarget end

      if self['to-port'] then
	 target = target..(addr and ':' or ' --to-ports ')..self['to-port']
      end
   end

   return target
end


local DNATRule = class(NATRule)

function DNATRule:init(...)
   DNATRule.super(self):init(...)
   self.params = {
      forbidif='out',
      subject='destination',
      chains={'OUTPUT', 'PREROUTING'},
      target='DNAT',
      deftarget='REDIRECT'
   }
end


local SNATRule = class(NATRule)

function SNATRule:init(...)
   SNATRule.super(self):init(...)
   self.params = {
      forbidif='in',
      subject='source',
      chains={'INPUT', 'POSTROUTING'},
      target='SNAT',
      deftarget='MASQUERADE'
   }
end


return {export={dnat={class=DNATRule}, snat={class=SNATRule}}}
