--[[
Base data model for Alpine Wall
Copyright (C) 2012-2015 Kaarle Ritvanen
See LICENSE file for license details
]]--


local M = {}


local loadclass = require('awall').loadclass
M.class = require('awall.class')
local resolve = require('awall.host')
local builtin = require('awall.iptables').builtin

local optfrag = require('awall.optfrag')
local combinations = optfrag.combinations

local raise = require('awall.uerror').raise

local util = require('awall.util')
local contains = util.contains
local extend = util.extend
local filter = util.filter
local join = util.join
local listpairs = util.listpairs
local maplist = util.maplist
local setdefault = util.setdefault


local startswith = require('stringy').startswith


M.ConfigObject = M.class()

function M.ConfigObject:init(context, location)
   if context then
      self.context = context
      self.root = context.objects
   end
   self.location = location

   self.extraobjs = {}
   self.uniqueids = {}
end

function M.ConfigObject:create(cls, params, label, index)
   local key
   if label then
      key = label..(index or '')
      local obj = self.extraobjs[key]
      if obj then return obj end
   end

   if type(cls) == 'string' then
      local name = cls
      cls = loadclass(cls)
      if not cls then
	 self:error('Support for '..name..' objects not installed')
      end
   end

   if type(params) ~= 'table' then params = {params} end
   params.label = join(self.label, '-', label)

   local obj = cls.morph(params, self.context, self.location)
   if key then self.extraobjs[key] = obj end
   return obj
end

function M.ConfigObject:uniqueid(key)
   if not key then key = '' end
   if self.uniqueids[key] then return self.uniqueids[key] end

   local lastid = setdefault(self.context, 'lastid', {})
   local res = join(key, '-', self.label)
   lastid[res] = setdefault(lastid, res, -1) + 1
   res = res..'-'..lastid[res]

   self.uniqueids[key] = res
   return res
end

function M.ConfigObject:error(msg) raise(self.location..': '..msg) end

function M.ConfigObject:warning(msg)
   io.stderr:write(self.location..': '..msg..'\n')
end

function M.ConfigObject:trules() return {} end

function M.ConfigObject:info()
   local res = {}
   for i, trule in ipairs(self:trules()) do
      table.insert(res, {'  '..optfrag.location(trule), optfrag.command(trule)})
   end
   return res
end


M.Zone = M.class(M.ConfigObject)

function M.Zone:optfrags(dir)
   local iopt, aopt, iprop, aprop
   if dir == 'in' then
      iopt, aopt, iprop, aprop = 'i', 's', 'in', 'src'
   elseif dir == 'out' then
      iopt, aopt, iprop, aprop = 'o', 'd', 'out', 'dest'
   else assert(false) end

   local aopts = nil
   if self.addr then
      aopts = {}
      for i, hostdef in listpairs(self.addr) do
	 for i, addr in ipairs(resolve(hostdef, self)) do
	    table.insert(aopts,
			 {family=addr[1],
			  [aprop]=addr[2],
			  opts='-'..aopt..' '..addr[2]})
	 end
      end
   end

   return combinations(
      maplist(
	 self.iface,
	 function(x) return {[iprop]=x, opts='-'..iopt..' '..x} end
      ),
      aopts
   )
end


M.fwzone = M.Zone()


local IPSet = M.class(M.ConfigObject)

function IPSet:init(...)
   IPSet.super(self):init(...)

   if not self.type then self:error('Type not defined') end

   if startswith(self.type, 'bitmap:') then
      if not self.range then self:error('Range not defined') end
      self.options = {self.type, 'range', self.range}
      self.family = 'inet'

   elseif startswith(self.type, 'hash:') then
      if not self.family then self:error('Family not defined') end
      self.options = {self.type, 'family', self.family}

   elseif self.type == 'list:set' then self.options = {self.type}

   else self:error('Invalid type: '..self.type) end
end


M.Rule = M.class(M.ConfigObject)


function M.Rule:init(...)
   M.Rule.super(self):init(...)

   for i, prop in ipairs({'in', 'out'}) do
      self[prop] = self[prop] and maplist(
	 self[prop],
	 function(z)
	    if type(z) ~= 'string' then return z end
	    return z == '_fw' and M.fwzone or
	       self.root.zone[z] or
	       self:error('Invalid zone: '..z)
	 end
      )
   end

   if self.service then
      if not self.label and type(self.service) == 'string' then
	 self.label = self.service
      end

      self.service = util.list(self.service)

      for i, serv in ipairs(self.service) do
	 if type(serv) == 'string' then
	    self.service[i] = self.root.service[serv] or
	       self:error('Invalid service: '..serv)
	 end
	 for i, sdef in listpairs(self.service[i]) do
	    if not sdef.proto then self:error('Protocol not defined') end
	    sdef.proto = (
	       {[1]='icmp', [6]='tcp', [17]='udp', [58]='ipv6-icmp'}
            )[sdef.proto] or sdef.proto
	 end
      end
   end
end


function M.Rule:direction(dir)
   if dir == 'in' then return self.reverse and 'out' or 'in' end
   if dir == 'out' then return self.reverse and 'in' or 'out' end
   self:error('Invalid direction: '..dir)
end


function M.Rule:zoneoptfrags()

   local function zonepair(zin, zout)

      local function zofs(zone, dir)
	 if not zone then return zone end
	 return zone:optfrags(dir)
      end

      local chain, ofrags

      if zin == M.fwzone or zout == M.fwzone then
	 if zin == zout then return {} end
	 local dir, z = 'in', zin
	 if zin == M.fwzone then dir, z = 'out', zout end
	 chain = dir:upper()..'PUT'
	 ofrags = zofs(z, dir)

      elseif not zin or not zout then

	 if zin then
	    chain = 'PREROUTING'
	    ofrags = zofs(zin, 'in')

	 elseif zout then
	    chain = 'POSTROUTING'
	    ofrags = zofs(zout, 'out')
	 end

      else
	 chain = 'FORWARD'
	 ofrags = combinations(zofs(zin, 'in'), zofs(zout, 'out'))

	 if ofrags and not zout['route-back'] then
	    ofrags = filter(
	       ofrags,
	       function(of)
		  return not (of['in'] and of.out and of['in'] == of.out)
	       end
	    )
	 end
      end

      return combinations(ofrags,
			  chain and {{chain=chain}} or {{chain='PREROUTING'},
							{chain='OUTPUT'}})
   end

   local res = {}
   local izones = self[self:direction('in')] or {}
   local ozones = self[self:direction('out')] or {}

   for i = 1,math.max(1, table.maxn(izones)) do
      for j = 1,math.max(1, table.maxn(ozones)) do
	 extend(res, zonepair(izones[i], ozones[j]))
      end
   end

   return res
end


function M.Rule:servoptfrags()

   if not self.service then return end

   local fports = {inet={}, inet6={}}
   local res = {}

   for i, serv in ipairs(self.service) do
      for i, sdef in listpairs(serv) do
	 if contains({'tcp', 'udp'}, sdef.proto) then
	    for family, ports in pairs(fports) do
	       if not sdef.family or family == sdef.family then

		  local new = not ports[sdef.proto]
		  if new then ports[sdef.proto] = {} end

		  if new or ports[sdef.proto][1] then
		     if sdef.port then
			extend(
			   ports[sdef.proto],
			   maplist(
			      sdef.port,
			      function(p) return tostring(p):gsub('-', ':') end
			   )
			)
		     else ports[sdef.proto] = {} end
		  end
	       end
	    end

	 else

	    local opts = '-p '..sdef.proto
	    local family = nil

	    -- TODO multiple ICMP types per rule
	    local oname
	    if sdef.proto == 'icmp' then
	       family = 'inet'
	       oname = 'icmp-type'
	    elseif contains({'ipv6-icmp', 'icmpv6'}, sdef.proto) then
	       family = 'inet6'
	       oname = 'icmpv6-type'
	    elseif sdef.type or sdef['reply-type'] then
	       self:error('Type specification not valid with '..sdef.proto)
	    end

	    if sdef.family then
	       if not family then family = sdef.family
	       elseif family ~= sdef.family then
		  self:error(
		     'Protocol '..sdef.proto..' is incompatible with '..sdef.family
		  )
	       end
	    end

	    if sdef.type then
	       opts = opts..' --'..oname..' '..(
		  self.reverse and sdef['reply-type'] or sdef.type
	       )
	    end
	    table.insert(res, {family=family, opts=opts})
	 end
      end
   end

   local popt = ' --'..(self.reverse and 's' or 'd')..'port'
   for family, pports in pairs(fports) do
      local ofrags = {}

      for proto, ports in pairs(pports) do
	 local propt = '-p '..proto

	 if ports[1] then
	    local len = #ports
	    repeat
	       local opts

	       if len == 1 then
		  opts = propt..popt..' '..ports[1]
		  len = 0

	       else
		  opts = propt..' -m multiport'..popt..'s '
		  local pc = 0
		  repeat
		     local sep = pc == 0 and '' or ','
		     local port = ports[1]
		     
		     pc = pc + (port:find(':') and 2 or 1)
		     if pc > 15 then break end
		     
		     opts = opts..sep..port
		     
		     table.remove(ports, 1)
		     len = len - 1
		  until len == 0
	       end

	       table.insert(ofrags, {opts=opts})
	    until len == 0

	 else table.insert(ofrags, {opts=propt}) end
      end

      extend(res, combinations(ofrags, {{family=family}}))
   end

   return res
end

function M.Rule:destoptfrags()
   return self:create(M.Zone, {addr=self.dest}):optfrags(self:direction('out'))
end

function M.Rule:table() return 'filter' end

function M.Rule:position() return 'append' end

function M.Rule:target()
   -- alpine v2.7 compatibility
   if self.action == 'accept' then
      self:warning("'accept' action deprecated in favor of 'exclude'")
      self.action = 'exclude'
   end

   if self.action == 'exclude' then return 'ACCEPT' end
   if self.action and self.action ~= 'include' then
      self:error('Invalid action: '..self.action)
   end
end


function M.Rule:trules()

   local function tag(ofrags, tag, value)
      for i, ofrag in ipairs(ofrags) do
	 assert(not ofrag[tag])
	 ofrag[tag] = value
      end
   end

   local families

   local function setfamilies(ofrags)
      if ofrags then
	 families = {}
	 for i, ofrag in ipairs(ofrags) do
	    if not ofrag.family then
	       families = nil
	       return
	    end
	    table.insert(families, ofrag.family)
	 end
      else families = nil end
   end

   local function ffilter(ofrags)
      if not ofrags or not ofrags[1] or not families then return ofrags end
      return filter(
	 ofrags,
	 function(of)
	    return not of.family or contains(families, of.family)
	 end
      )
   end

   local res = self:zoneoptfrags()

   if self.ipset then
      local ipsetofrags = {}
      for i, ipset in listpairs(self.ipset) do
	 if not ipset.name then self:error('Set name not defined') end

	 local setdef = self.root.ipset and self.root.ipset[ipset.name]
	 if not setdef then self:error('Invalid set name') end

	 if not ipset.args then
	    self:error('Set direction arguments not defined')
	 end

	 local setopts = '-m set --match-set '..ipset.name..' '
	 setopts = setopts..table.concat(util.map(util.list(ipset.args),
						  function(a)
						     if self:direction(a) == 'in' then
							return 'src'
						     end
						     return 'dst'
						  end),
					 ',')
	 table.insert(ipsetofrags, {family=setdef.family, opts=setopts})
      end
      res = combinations(res, ipsetofrags)
   end

   if self.ipsec then
      res = combinations(res,
			 {{opts='-m policy --pol ipsec --dir '..self:direction(self.ipsec)}})
   end

   res = combinations(res, self:servoptfrags())

   setfamilies(res)

   local addrofrags = combinations(
      self:create(M.Zone, {addr=self.src}):optfrags(self:direction('in')),
      self:destoptfrags()
   )
   local combined = res

   if addrofrags then
      addrofrags = ffilter(addrofrags)
      setfamilies(addrofrags)
      res = ffilter(res)

      combined = {}
      for i, ofrag in ipairs(res) do
	 local aofs = combinations(addrofrags, {{family=ofrag.family}})
	 local cc = combinations({ofrag}, aofs)
	 if #cc < #aofs then
	    combined = nil
	    break
	 end
	 extend(combined, cc)
      end
   end

   local target
   if combined then
      target = self:target()
      res = combined
   else target = self:uniqueid('address') end

   tag(res, 'position', self:position())

   res = combinations(res, {{target=target}})

   if not combined then
      extend(
	 res,
	 combinations(addrofrags, {{chain=target, target=self:target()}})
      )
   end

   extend(res, self:extraoptfrags())

   local tbl = self:table()

   local function convertchains(ofrags)
      local res = {}

      for i, ofrag in ipairs(ofrags) do

	 if contains(builtin[tbl], ofrag.chain) then table.insert(res, ofrag)
	 else
	    local ofs, recursive
	    if ofrag.chain == 'PREROUTING' then
	       ofs = {{chain='FORWARD'}, {chain='INPUT'}}
	    elseif ofrag.chain == 'POSTROUTING' then
	       ofs = {{chain='FORWARD'}, {chain='OUTPUT'}}
	       recursive = true
	    elseif ofrag.chain == 'INPUT' then
	       ofs = {{opts='-m addrtype --dst-type LOCAL', chain='PREROUTING'}}
	    elseif ofrag.chain == 'FORWARD' then
	       ofs = {
		  {opts='-m addrtype ! --dst-type LOCAL', chain='PREROUTING'}
	       }
	    end

	    if ofs then
	       ofrag.chain = nil
	       ofs = combinations(ofs, {ofrag})
	       if recursive then ofs = convertchains(ofs) end
	       extend(res, ofs)

	    else table.insert(res, ofrag) end
	 end
      end

      return res
   end

   res = convertchains(ffilter(res))
   tag(res, 'table', tbl, false)

   local function checkzof(ofrag, dir, chains)
      if ofrag[dir] and contains(chains, ofrag.chain) then
	 self:error('Cannot specify '..dir..'bound interface ('..ofrag[dir]..')')
      end
   end

   for i, ofrag in ipairs(res) do
      checkzof(ofrag, 'in', {'OUTPUT', 'POSTROUTING'})
      checkzof(ofrag, 'out', {'INPUT', 'PREROUTING'})
   end
   
   return combinations(res, ffilter({{family='inet'}, {family='inet6'}}))
end

function M.Rule:extraoptfrags() return {} end


M.Limit = M.class(M.ConfigObject)

function M.Limit:init(...)
   M.Limit.super(self):init(...)

   if not self.count then
      if not self[1] then
	 self:error('Packet count not defined for limit')
      end
      self.count = self[1]
   end

   setdefault(self, 'interval', 1)

   if type(setdefault(self, 'mask', {})) == 'number' then
      self.mask = {src=self.mask}
   end
   for _, family in ipairs{'inet', 'inet6'} do
      setdefault(self.mask, family, util.copy(self.mask))
      for _, attr in ipairs{'src', 'dest'} do
	 local mask = setdefault(
	    self.mask[family],
	    attr,
	    ({src=({inet=32, inet6=128})[family], dest=0})[attr]
	 )
	 if mask > 0 then
	    self.mask[family].mode =
	       self.mask[family].mode and true or {attr, mask}
	 end
      end
   end
end

function M.Limit:rate() return self.count / self.interval end

function M.Limit:intrate() return math.ceil(self:rate()) end

function M.Limit:limitofrags(name)
   local rate = self:rate()
   local unit
   for _, quantum in ipairs{
      {1, 'second'}, {60, 'minute'}, {60, 'hour'}, {24, 'day'}
   } do
      rate = rate * quantum[1]
      unit = quantum[2]
      if rate >= 1 then break end
   end
   rate = math.ceil(rate)..'/'..unit

   local ofrags = {}

   for _, family in ipairs{'inet', 'inet6'} do
      local keys = {}
      local maskopts = ''
      for _, attr in ipairs{'src', 'dest'} do
	 local mask = self.mask[family][attr]
	 if mask > 0 then
	    local opt = ({src='src', dest='dst'})[attr]
	    table.insert(keys, opt..'ip')
	    maskopts = maskopts..' --hashlimit-'..opt..'mask '..mask
	 end
      end

      table.insert(
	 ofrags,
	 {
	    family=family,
	    opts=keys[1] and
	       '-m hashlimit --hashlimit-upto '..rate..' --hashlimit-burst '..
	       self:intrate()..' --hashlimit-mode '..table.concat(keys, ',')..
	       maskopts..' --hashlimit-name '..(name or self:uniqueid()) or
	       '-m limit --limit '..rate
	 }
      )
   end

   return ofrags
end


M.export = {zone={class=M.Zone}, ipset={class=IPSet, before='%modules'}}

return M
