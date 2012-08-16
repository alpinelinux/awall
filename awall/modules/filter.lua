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
local combinations = awall.optfrag.combinations

local Filter = model.class(model.Rule)

function Filter:defaultzones()
   return self.dnat and {nil} or model.Rule.defaultzones(self)
end

function Filter:destoptfrags()
   local ofrags = model.Rule.destoptfrags(self)
   if not self.dnat then return ofrags end

   ofrags = combinations(ofrags, {{family='inet6'}})
   local natof = self:create(model.Zone, {addr=self.dnat}):optfrags('out')
   assert(#natof == 1)
   table.insert(ofrags, natof[1])
   return ofrags
end

function Filter:trules()
   local res = {}

   local function extrarules(cls, extra)
      local params = {}
      for i, attr in ipairs({'in', 'out', 'src', 'dest',
			     'ipset', 'ipsec', 'service'}) do
	 params[attr] = self[attr]
      end
      if extra then for k, v in pairs(extra) do params[k] = v end end
      return awall.util.extend(res, self:create(cls, params):trules())
   end

   if self.dnat then
      if self.action ~= 'accept' then
	 self:error('dnat option not allowed with '..self.action..' action')
      end
      if not self.dest then
	 self:error('Destination address must be specified with DNAT')
      end
      if string.find(self.dnat, '/') then
	 self:error('DNAT target cannot be a network address')
      end
      for i, attr in ipairs({'ipsec', 'ipset'}) do
	 if self[attr] then
	    self:error('dnat and '..attr..' options cannot be used simultaneously')
	 end
      end

      local dnataddr
      for i, addr in ipairs(awall.host.resolve(self.dnat, self)) do
	 if addr[1] == 'inet' then
	    if dnataddr then
	       self:error(self.dnat..' resolves to multiple IPv4 addresses')
	    end
	    dnataddr = addr[2]
	 end
      end
      if not dnataddr then
	 self:error(self.dnat..' does not resolve to any IPv4 address')
      end

      extrarules('dnat', {['ip-range']=dnataddr, out=nil})
   end

   if self.action == 'tarpit' then extrarules('no-track') end

   awall.util.extend(res, model.Rule.trules(self))

   return res
end

function Filter:limit()
   local res
   for i, limit in ipairs({'conn-limit', 'flow-limit'}) do
      if self[limit] then
	 if res then
	    self:error('Cannot specify multiple limits for a single filter rule')
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
   return self:newchain('limit')
end

function Filter:extraoptfrags()
   local res = {}
   local limit = self:limit()
   if limit then
      if self.action ~= 'accept' then
	 self:error('Cannot specify limit for '..self.action..' filter')
      end
      local optbase = '-m recent --name '..self:target()
      table.insert(res, {chain=self:target(),
			 opts=optbase..' --update --hitcount '..self[limit].count..' --seconds '..self[limit].interval,
			 target='logdrop'})
      table.insert(res, {chain=self:target(),
			 opts=optbase..' --set',
			 target='ACCEPT'})
   end
   return res
end



local Policy = model.class(Filter)

function Policy:servoptfrags() return nil end


classes = {{'filter', Filter},
	   {'policy', Policy}}


defrules = {}

local dar = combinations({{chain='FORWARD'}, {chain='INPUT'}, {chain='OUTPUT'}},
			 {{opts='-m state --state RELATED,ESTABLISHED'}})
for i, chain in ipairs({'INPUT', 'OUTPUT'}) do
   table.insert(dar,
		{chain=chain,
		 opts='-'..string.lower(string.sub(chain, 1, 1))..' lo'})
end
defrules.pre = combinations(combinations(dar,
					 {{table='filter', target='ACCEPT'}}),
			    {{family='inet'}, {family='inet6'}})

defrules['post-filter'] = combinations({{family='inet6',
					 table='filter',
					 opts='-p icmpv6',
					 target='ACCEPT'}},
				       {{chain='INPUT'}, {chain='OUTPUT'}})


achains = {}

local limitedlog = {opts='-m limit --limit 1/second', target='LOG'}
for i, target in ipairs({'drop', 'reject'}) do
   util.extend(achains,
	       combinations({{chain='log'..target}},
			    {limitedlog, {target=string.upper(target)}}))
end
util.extend(achains,
	    combinations({{chain='tarpit'}},
			 {limitedlog,
			  {opts='-p tcp', target='TARPIT'},
			  {target='DROP'}}))
