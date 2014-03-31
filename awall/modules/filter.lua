--[[
Filter module for Alpine Wall
Copyright (C) 2012-2014 Kaarle Ritvanen
See LICENSE file for license details
]]--


local resolve = require('awall.host')

local model = require('awall.model')
local class = model.class
local Rule = model.Rule

local combinations = require('awall.optfrag').combinations

local util = require('awall.util')
local contains = util.contains
local extend = util.extend
local listpairs = util.listpairs

local RECENT_MAX_COUNT = 20


local RelatedRule = class(Rule)

function RelatedRule:servoptfrags()
   local helpers = {}
   for i, serv in listpairs(self.service) do
      for i, sdef in listpairs(serv) do
	 local helper = sdef['ct-helper']
	 if helper then
	    helpers[helper] = {
	       family=sdef.family,
	       opts='-m conntrack --ctstate RELATED -m helper --helper '..helper
	    }
	 end
      end
   end
   return util.values(helpers)
end

function RelatedRule:target() return 'ACCEPT' end


local Filter = class(Rule)

function Filter:init(...)
   Filter.super(self):init(...)

   if not self.action then self.action = 'accept' end

   -- alpine v2.4 compatibility
   if contains({'logdrop', 'logreject'}, self.action) then
      self:warning('Deprecated action: '..self.action)
      self.action = self.action:sub(4, -1)
   end

   local log = require('awall').loadclass('log').get
   self.log = log(self, self.log, self.action ~= 'accept')

   local limit = self:limit()
   if limit then
      if type(self[limit]) ~= 'table' then
	 self[limit] = {count=self[limit]}
      end
      self[limit].log = log(self, self[limit].log, true)
   end
end

function Filter:destoptfrags()
   local ofrags = Filter.super(self):destoptfrags()
   if not self.dnat then return ofrags end

   ofrags = combinations(ofrags, {{family='inet6'}})
   local natof = self:create(model.Zone, {addr=self.dnat}):optfrags('out')
   assert(#natof == 1)
   table.insert(ofrags, natof[1])
   return ofrags
end

function Filter:trules()
   local res = {}

   local function extrarules(cls, extra, src)
      if not src then src = self end
      local params = {}
      for i, attr in ipairs(
	 {'in', 'out', 'src', 'dest', 'ipset', 'ipsec', 'service'}
      ) do
	 params[attr] = src[attr]
      end
      util.update(params, extra)
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
      if self.dnat:find('/') then
	 self:error('DNAT target cannot be a network address')
      end
      for i, attr in ipairs({'ipsec', 'ipset'}) do
	 if self[attr] then
	    self:error('dnat and '..attr..' options cannot be used simultaneously')
	 end
      end

      local dnataddr
      for i, addr in ipairs(resolve(self.dnat, self)) do
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

   extend(res, Filter.super(self):trules())

   if self.action == 'accept' then
      local nr = #res

      if self.related then
	 for i, rule in listpairs(self.related) do
	    extrarules(RelatedRule, {service=self.service}, rule)
	 end
      else
	 -- TODO avoid creating unnecessary RELATED rules by introducing
	 -- helper direction attributes to service definitions
	 extrarules(RelatedRule)
	 extrarules(RelatedRule, {reverse=true})
      end

      if self['no-track'] then
	 if #res > nr then
	    self:error('Tracking required by service')
	 end
	 extrarules('no-track', {reverse=true})
	 extrarules('filter', {reverse=true, action='accept', log=false})
      end
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

function Filter:actiontarget()
   if self.action == 'tarpit' then return 'tarpit' end
   if contains({'accept', 'drop', 'reject'}, self.action) then
      return self.action:upper()
   end
   self:error('Invalid filter action: '..self.action)
end

function Filter:target()
   if self:limit() then return self:newchain('limit') end
   if self.log then return self:newchain('log'..self.action) end
   return self:actiontarget()
end

function Filter:extraoptfrags()
   local res = {}

   local function logchain(log, action, target)
      if not log then return target end
      local chain = self:newchain('log'..action)
      extend(
	 res,
	 combinations({{chain=chain}}, {log:optfrag(), {target=target}})
      )
      return chain
   end

   local limit = self:limit()
   if limit then
      if self.action ~= 'accept' then
	 self:error('Cannot specify limit for '..self.action..' filter')
      end

      local chain = self:newchain('limit')
      local limitlog = self[limit].log
      local count = self[limit].count
      local interval = self[limit].interval or 1

      if count > RECENT_MAX_COUNT then
	 count = math.ceil(count / interval)
	 interval = 1
      end

      local ofrags
      if count > RECENT_MAX_COUNT then
	 ofrags = {
	    {
	       opts='-m hashlimit --hashlimit-upto '..count..'/second --hashlimit-burst '..count..' --hashlimit-mode srcip --hashlimit-name '..chain,
	       target=logchain(self.log, 'accept', 'ACCEPT')
	    },
	    {target='DROP'}
	 }
	 if limitlog then table.insert(ofrags, 2, limitlog:optfrag()) end
      else
	 ofrags = combinations(
	    {{opts='-m recent --name '..chain}},
	    {
	       {
		  opts='--update --hitcount '..count..' --seconds '..interval,
		  target=logchain(limitlog, 'drop', 'DROP')
	       },
	       {opts='--set', target='ACCEPT'}
	    }
	 )
	 if self.log then table.insert(ofrags, 2, self.log:optfrag()) end
      end

      extend(res, combinations({{chain=chain}}, ofrags))

   else logchain(self.log, self.action, self:actiontarget()) end
   
   return res
end



local Policy = class(Filter)

function Policy:servoptfrags() return nil end


local fchains = {{chain='FORWARD'}, {chain='INPUT'}, {chain='OUTPUT'}}

local function stateful(config)
   local res = {}

   for i, family in ipairs{'inet', 'inet6'} do

      local er = combinations(
	 fchains,
	 {{opts='-m conntrack --ctstate ESTABLISHED'}}
      )
      for i, chain in ipairs({'INPUT', 'OUTPUT'}) do
	 table.insert(
	    er, {chain=chain, opts='-'..chain:sub(1, 1):lower()..' lo'}
	 )
      end
      extend(
	 res,
	 combinations(er, {{family=family, table='filter', target='ACCEPT'}})
      )

      -- TODO avoid creating unnecessary CT rules by inspecting the
      -- filter rules' target families and chains
      local visited = {}
      local ofrags = {}
      for i, rule in listpairs(config.filter) do
	 for i, serv in listpairs(rule.service) do
	    if not visited[serv] then
	       for i, sdef in listpairs(serv) do
		  if sdef['ct-helper'] then
		     local of = combinations(
			Rule.morph{service={sdef}}:servoptfrags(),
			{{family=family}}
		     )
		     if of[1] then
			assert(#of == 1)
			of[1].target = 'CT --helper '..sdef['ct-helper']
			table.insert(ofrags, of[1])
		     end
		  end
	       end
	       visited[serv] = true
	    end
	 end
      end
      extend(
	 res,
	 combinations(
	    {{table='raw'}},
	    {{chain='PREROUTING'}, {chain='OUTPUT'}},
	    ofrags
	 )
      )
   end

   return res
end

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

return {
   export={
      filter={class=Filter, before={'dnat', 'no-track'}},
      policy={class=Policy, after='%filter-after'},
      ['%filter-before']={rules=stateful, before='filter'},
      ['%filter-after']={rules=ir, after='filter'}
   },
   achains=combinations(
      {{chain='tarpit'}}, {{opts='-p tcp', target='TARPIT'}, {target='DROP'}}
   )
}
