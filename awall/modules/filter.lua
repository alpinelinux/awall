--[[
Filter module for Alpine Wall
Copyright (C) 2012-2013 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall'
require 'awall.host'
require 'awall.model'
require 'awall.object'
require 'awall.optfrag'
require 'awall.util'

local model = awall.model
local combinations = awall.optfrag.combinations
local extend = awall.util.extend


local Log = awall.object.class()

function Log:matchopts()
   return self.limit and '-m limit --limit '..self.limit..'/second'
end

function Log:target()
   local mode = self.mode or 'log'
   local prefix = self.prefix and ' --'..mode..'-prefix '..self.prefix or ''
   return string.upper(mode)..prefix
end


local Filter = model.class(model.Rule)

function Filter:init(...)
   model.Rule.init(self, unpack(arg))

   -- alpine v2.4 compatibility
   if util.contains({'logdrop', 'logreject'}, self.action) then
      self:warning('Deprecated action: '..self.action)
      self.action = string.sub(self.action, 4, -1)
   end

   local function log(spec, default)
      if spec == nil then spec = default end
      if spec == false then return end
      if spec == true then spec = '_default' end
      return self.root.log[spec] or self:error('Invalid log: '..spec)
   end

   self.log = log(self.log, self.action ~= 'accept')
   local limit = self:limit()
   if limit then self[limit].log = log(self[limit].log, true) end
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
      return extend(res, self:create(cls, params):trules())
   end

   if self.dnat then
      if self.action ~= 'accept' then
	 self:error('dnat option not allowed with '..self.action..' action')
      end
      if self['no-track'] then
	 self:error('dnat option not allowed with no-track')
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

      extrarules('dnat', {['to-addr']=dnataddr, out=nil})
   end

   if self.action == 'tarpit' or self['no-track'] then
      extrarules('no-track')
   end

   extend(res, model.Rule.trules(self))

   if self['no-track'] and self.action == 'accept' then
      extrarules('no-track', {reverse=true})
      extrarules('filter', {reverse=true, action='accept', log=false})
   end

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
   if self:limit() then return self:newchain('limit') end
   if self.log then return self:newchain('log'..self.action) end
   return model.Rule.target(self)
end

function Filter:extraoptfrags()
   local res = {}

   local function logchain(action, log, target)
      extend(res, combinations({{chain=self:newchain('log'..action)}},
			       {{opts=log:matchopts(), target=log:target()},
				{target=target}}))
   end

   local limit = self:limit()
   if limit then
      if self.action ~= 'accept' then
	 self:error('Cannot specify limit for '..self.action..' filter')
      end

      local chain = self:newchain('limit')
      local limitlog = self[limit].log

      extend(res,
	     combinations({{chain=chain,
			    opts='-m recent --name '..chain}},
			  {{opts='--update --hitcount '..self[limit].count..' --seconds '..self[limit].interval,
				target=limitlog and self:newchain('logdrop') or 'DROP'},
			     {opts='--set',
			      target=self.log and self:newchain('log'..self.action) or 'ACCEPT'}}))

      if limitlog then logchain('drop', limitlog, 'DROP') end
   end

   if self.log then logchain(self.action, self.log, model.Rule.target(self)) end
   
   return res
end



local Policy = model.class(Filter)

function Policy:servoptfrags() return nil end


local fchains = {{chain='FORWARD'}, {chain='INPUT'}, {chain='OUTPUT'}}

local dar = combinations(fchains,
			 {{opts='-m conntrack --ctstate RELATED,ESTABLISHED'}})
for i, chain in ipairs({'INPUT', 'OUTPUT'}) do
   table.insert(dar,
		{chain=chain,
		 opts='-'..string.lower(string.sub(chain, 1, 1))..' lo'})
end
dar = combinations(
   dar,
   {{table='filter', target='ACCEPT'}},
   {{family='inet'}, {family='inet6'}}
)

local icmp = {{family='inet', table='filter', opts='-p icmp'}}
local icmp6 = {{family='inet6', table='filter', opts='-p icmpv6'}}
local ir = combinations(
   icmp6,
   {{chain='INPUT'}, {chain='OUTPUT'}},
   {{target='ACCEPT'}}
)
extend(ir, combinations(icmp6, {{chain='FORWARD', target='icmp-routing'}}))
extend(ir, combinations(icmp, fchains, {{target='icmp-routing'}}))

local function icmprules(ofrag, oname, types)
   extend(
      ir,
      combinations(ofrag,
		   {{chain='icmp-routing', target='ACCEPT'}},
		   util.map(types,
			    function(t)
			       return {opts='--'..oname..' '..t}
			    end))
   )
end
icmprules(icmp, 'icmp-type', {3, 11, 12})
icmprules(icmp6, 'icmpv6-type', {1, 2, 3, 4})

export = {
   filter={class=Filter, before={'dnat', 'no-track'}},
   log={class=Log},
   policy={class=Policy, after='%filter-after'},
   ['%filter-before']={rules=dar, before='filter'},
   ['%filter-after']={rules=ir, after='filter'}
}

achains = combinations({{chain='tarpit'}},
		       {{opts='-p tcp', target='TARPIT'},
			{target='DROP'}})

