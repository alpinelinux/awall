--[[
NAT module for Alpine Wall
Copyright (C) 2012-2020 Kaarle Ritvanen
See LICENSE file for license details
]]--


local identify = require('awall.family').identify
local resolveunique = require('awall.host').resolveunique

local model = require('awall.model')
local class = model.class

local expandfamilies = require('awall.optfrag').expandfamilies

local util = require('awall.util')
local setdefault = util.setdefault


local NATRule = class(model.Rule)

function NATRule:init(...)
   NATRule.super(self):init(...)

   -- alpine v2.4 compatibility
   local attrs = {['ip-range']='to-addr', ['port-range']='to-port'}
   for old, new in pairs(attrs) do
      if not self[new] and self[old] then
	 self:warning(old..' deprecated in favor of '..new)
	 self[new] = self[old]
      end
   end

   if not self.family then
      for _, addr in util.listpairs(self['to-addr']) do
	 local family = identify(addr)
	 if family ~= 'domain' then
	    table.insert(setdefault(self, 'family', {}), family)
	 end
      end
      setdefault(self, 'family', 'inet')
   end
end

function NATRule:porttrans() return self['to-port'] end

function NATRule:mangleoptfrags(ofrags)
   ofrags = expandfamilies(ofrags, self.family)
   if self:customtarget() or self:target() then return ofrags end

   local addrs = self['to-addr'] and resolveunique(
      self['to-addr'], self.family, self
   ) or {}

   for _, ofrag in ipairs(ofrags) do
      if not ofrag.target then
	 local addr = addrs[ofrag.family]
	 local target

	 if addr then
	    if self['to-port'] and addr:find(':') then addr = '['..addr..']' end
	    target = self.params.target..' --to-'..self.params.subject..' '..addr
	 else target = self.params.deftarget end

	 if self['to-port'] then
	    target = target..(addr and ':' or ' --to-ports ')..self['to-port']
	 end

	 ofrag.target = target
      end
   end

   return ofrags
end

function NATRule:trulefilter(rule)
   if not util.contains(self.params.chains, rule.chain) then
      self:error(
         'Inappropriate zone definitions for a '..self.params.target..' rule'
      )
   end
   return true
end

function NATRule:table() return 'nat' end


local DNATRule = class(NATRule)

function DNATRule:init(...)
   DNATRule.super(self):init(...)
   self.params = {
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
      subject='source',
      chains={'INPUT', 'POSTROUTING'},
      target='SNAT',
      deftarget='MASQUERADE'
   }
end

function SNATRule:trulefilter(rule)
   if rule.chain == 'INPUT' and rule.target == 'MASQUERADE' then
      self:error('Must specify translation address for inbound traffic')
   end
   return SNATRule.super(self):trulefilter(rule)
end


return {export={dnat={class=DNATRule}, snat={class=SNATRule}}}
