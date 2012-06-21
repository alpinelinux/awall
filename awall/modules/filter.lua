--[[
Filter module for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall'
require 'awall.host'
require 'awall.model'
require 'awall.optfrag'
require 'awall.util'

local model = awall.model

local Filter = model.class(model.Rule)

function Filter:defaultzones()
   return self.dnat and {nil} or model.Rule.defaultzones(self)
end

function Filter:destoptfrags()
   local ofrags = model.Rule.destoptfrags(self)
   if not self.dnat then return ofrags end

   ofrags = awall.optfrag.combinations(ofrags, {{family='inet6'}}) or {}
   local natof = model.Zone.morph({addr=self.dnat}):optfrags('out')
   assert(#natof == 1)
   table.insert(ofrags, natof[1])
   return ofrags
end

function Filter:trules()
   local res = {}

   if self.dnat then
      if not self.dest then
	 error('Destination address must be specified with DNAT')
      end
      if string.find(self.dnat, '/') then
	 error('DNAT target cannot be a network address')
      end
      for i, attr in ipairs({'ipsec', 'ipset'}) do
	 if self[attr] then
	    error('dnat and '..attr..' options cannot be used simultaneously')
	 end
      end

      local dnataddr
      for i, addr in ipairs(awall.host.resolve(self.dnat)) do
	 if addr[1] == 'inet' then
	    if dnataddr then
	       error(self.dnat..' resolves to multiple IPv4 addresses')
	    end
	    dnataddr = addr[2]
	 end
      end
      if not dnataddr then
	 error(self.dnat..' does not resolve to any IPv4 address')
      end

      local dnat = {['ip-range']=dnataddr}
      for i, attr in ipairs({'in', 'src', 'dest', 'service'}) do
	 dnat[attr] = self[attr]
      end

      if not awall.classmap.dnat then error('NAT module not installed') end

      awall.util.extend(res, awall.classmap.dnat.morph(dnat,
						       self.context):trules())
   end

   awall.util.extend(res, model.Rule.trules(self))

   return res
end

function Filter:limit()
   local res
   for i, limit in ipairs({'conn-limit', 'flow-limit'}) do
      if self[limit] then
	 if res then
	    error('Cannot specify multiple limits for a single filter rule')
	 end
	 res = limit
      end
   end
   return res
end

function Filter:position()
   return self:limit() == 'flow-limit' and 'prepend' or 'append'
end

function Filter:target()
   if not self:limit() then return model.Rule.target(self) end
   if not self['limit-target'] then self['limit-target'] = self:newchain('limit') end
   return self['limit-target']
end

function Filter:extraoptfrags()
   local res = {}
   local limit = self:limit()
   if limit then
      if self.action ~= 'accept' then
	 error('Cannot specify limit for '..self.action..' filter')
      end
      local optbase = '-m recent --name '..self:target()
      table.insert(res, {chain=self:target(),
			 opts=optbase..' --update --hitcount '..self[limit].count..' --seconds '..self[limit].interval..' -j LOGDROP'})
      table.insert(res, {chain=self:target(),
			 opts=optbase..' --set -j ACCEPT'})
   end
   return res
end



local Policy = model.class(Filter)

function Policy:servoptfrags() return nil end


classes = {{'filter', Filter},
	   {'policy', Policy}}

defrules = {pre={}, ['post-filter']={}}

for i, family in ipairs({'inet', 'inet6'}) do
   for i, target in ipairs({'DROP', 'REJECT'}) do
      for i, opts in ipairs({'-m limit --limit 1/second -j LOG', '-j '..target}) do
	 table.insert(defrules.pre,
		      {family=family,
		       table='filter',
		       chain='LOG'..target,
		       opts=opts})
      end
   end

   for i, chain in ipairs({'FORWARD', 'INPUT', 'OUTPUT'}) do
      table.insert(defrules.pre,
		   {family=family,
		    table='filter',
		    chain=chain,
		    opts='-m state --state RELATED,ESTABLISHED -j ACCEPT'})
   end

   for i, chain in ipairs({'INPUT', 'OUTPUT'}) do
      table.insert(defrules.pre,
		   {family=family,
		    table='filter',
		    chain=chain,
		    opts='-'..string.lower(string.sub(chain, 1, 1))..' lo -j ACCEPT'})
   end
end

for i, chain in ipairs({'INPUT', 'OUTPUT'}) do
   table.insert(defrules['post-filter'],
		{family='inet6',
		 table='filter',
		 chain=chain,
		 opts='-p icmpv6 -j ACCEPT'})
end
