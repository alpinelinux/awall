--[[
Base data model for Alpine Wall
Copyright (C) 2012-2017 Kaarle Ritvanen
See LICENSE file for license details
]]--


local M = {}


local loadclass = require('awall').loadclass
M.class = require('awall.class')
local resolve = require('awall.host')
local builtin = require('awall.iptables').builtin

local optfrag = require('awall.optfrag')
local FAMILIES = optfrag.FAMILIES
local combinations = optfrag.combinations

local raise = require('awall.uerror').raise

local util = require('awall.util')
local contains = util.contains
local copy = util.copy
local extend = util.extend
local filter = util.filter
local join = util.join
local listpairs = util.listpairs
local map = util.map
local maplist = util.maplist
local setdefault = util.setdefault
local sortedkeys = util.sortedkeys


local startswith = require('stringy').startswith


local ADDRLEN = {inet=32, inet6=128}


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
   util.printmsg(self.location..': '..msg)
end

function M.ConfigObject:trules() return {} end

function M.ConfigObject:info()
   local rules = {}
   for _, trule in ipairs(self:trules()) do
      local loc = optfrag.location(trule)
      table.insert(
	 setdefault(rules, loc, {}), {'  '..loc, optfrag.command(trule)}
      )
   end

   local res = {}
   for _, loc in sortedkeys(rules) do extend(res, rules[loc]) end
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
	    table.insert(
	       aopts,
	       {family=addr[1], [aprop]=addr[2], match='-'..aopt..' '..addr[2]}
	    )
	 end
      end
   end

   local popt
   if self.ipsec ~= nil then
      popt = {
	 {
	    match='-m policy --dir '..dir..' --pol '..
	       (self.ipsec and 'ipsec' or 'none')
	 }
      }
   end

   return combinations(
      maplist(
	 self.iface,
	 function(x) return {[iprop]=x, match='-'..iopt..' '..x} end
      ),
      aopts,
      popt
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

   -- alpine v3.4 compatibility
   if self.ipsec then
      if not contains({'in', 'out'}, self.ipsec) then
	 self:error('Invalid ipsec policy direction')
      end
      self:warning('ipsec deprecated in rules, define in zones instead')
      local zones = self[self.ipsec]
      if zones then
	 self[self.ipsec] = maplist(
	    zones,
	    function(z)
	       return self:create(
		  M.Zone, {iface=z.iface, addr=z.addr, ipsec=true}
	       )
	    end
	 )
      else self[self.ipsec] = {self:create(M.Zone, {ipsec=true})} end
      self.ipsec = nil
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

   for i = 1,math.max(1, #izones) do
      for j = 1,math.max(1, #ozones) do
	 extend(res, zonepair(izones[i], ozones[j]))
      end
   end

   return res
end


function M.Rule:servoptfrags()

   if not self.service then return end

   local res = {}

   local fports = {}
   map(FAMILIES, function(f) fports[f] = {} end)

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
	    table.insert(res, {family=family, match=opts})
	 end
      end
   end

   local popt = ' --'..(self.reverse and 's' or 'd')..'port'
   for _, family in sortedkeys(fports) do
      local ofrags = {}
      local pports = fports[family]

      for _, proto in sortedkeys(pports) do
	 local propt = '-p '..proto
	 local ports = pports[proto]

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

	       table.insert(ofrags, {match=opts})
	    until len == 0

	 else table.insert(ofrags, {match=propt}) end
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


function M.Rule:combine(ofs1, ofs2, key, unique)

   local function connect()
      local chain = self:uniqueid(key)
      local function setvar(name)
	 return function(of)
	    local res = copy(of)
	    setdefault(res, name, chain)
	    return res
	 end
      end

      return extend(map(ofs1, setvar('target')), map(ofs2, setvar('chain')))
   end

   local chainless = filter(ofs2, function(of) return not of.chain end)
   local created
   local res = {}

   for _, of in ipairs(ofs1) do
      if of.target == nil then

	 local ofs = combinations(chainless, {{family=of.family}})
	 assert(#ofs > 0)

	 local comb = combinations({of}, ofs)
	 if #comb < #ofs then return connect() end

	 if unique then
	    if #self:convertchains{of} > 1 then return connect() end

	    for _, c in ipairs(comb) do
	       if c.family then
	          if not created then created = {}
		  elseif created == true or created[c.family] then
		     return connect()
		  end
		  created[c.family] = true
	       else
	          if created then return connect() end
		  created = true
	       end
	    end
	 end

	 extend(res, comb)

      else table.insert(res, of) end
   end

   return extend(res, filter(ofs2, function(of) return of.chain end))
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

   local ofrags = self:zoneoptfrags()

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
	 table.insert(ipsetofrags, {family=setdef.family, match=setopts})
      end
      ofrags = combinations(ofrags, ipsetofrags)
   end

   if self.string then
      if type(self.string) == 'string' then
	 self.string = {match=self.string}
      end
      if not self.string.match then self:error('String match not defined') end
      setdefault(self.string, 'algo', 'bm')

      local opts = '-m string --string '..util.quote(self.string.match)

      for _, attr in ipairs{'algo', 'from', 'to'} do
	 if self.string[attr] then
	    opts = opts..' --'..attr..' '..self.string[attr]
	 end
      end

      ofrags = combinations(ofrags, {{match=opts}})
   end

   if self.match then ofrags = combinations(ofrags, {{match=self.match}}) end

   ofrags = combinations(ofrags, self:servoptfrags())

   tag(ofrags, 'position', self:position())

   setfamilies(ofrags)

   local addrofrags = combinations(
      self:create(M.Zone, {addr=self.src}):optfrags(self:direction('in')),
      self:destoptfrags()
   )
   if addrofrags then
      addrofrags = ffilter(addrofrags)
      setfamilies(addrofrags)
      ofrags = self:combine(ffilter(ofrags), addrofrags, 'address')
   end

   ofrags = self:mangleoptfrags(ofrags)

   local custom = self:customtarget()
   for _, ofrag in ipairs(ofrags) do
      setdefault(ofrag, 'target', custom or self:target())
   end

   ofrags = self:convertchains(ffilter(ofrags))
   tag(ofrags, 'table', self:table(), false)

   local function checkzof(ofrag, dir, chains)
      if ofrag[dir] and contains(chains, ofrag.chain) then
	 self:error('Cannot specify '..dir..'bound interface ('..ofrag[dir]..')')
      end
   end

   for i, ofrag in ipairs(ofrags) do
      checkzof(ofrag, 'in', {'OUTPUT', 'POSTROUTING'})
      checkzof(ofrag, 'out', {'INPUT', 'PREROUTING'})
   end
   
   ofrags = filter(
      combinations(ofrags, ffilter(optfrag.FAMILYFRAGS)),
      function(r) return self:trulefilter(r) end
   )

   local extra = self:extratrules(ofrags)
   if custom and extra[1] then self:error('Custom action not allowed here') end
   return extend(ofrags, extra)
end

function M.Rule:customtarget()
   if self.action then
      local as = self.action:sub(1, 1)
      if as == as:upper() or startswith(self.action, 'custom:') then
	 return self.action
      end
   end
end

function M.Rule:mangleoptfrags(ofrags) return ofrags end

function M.Rule:trulefilter(rule) return true end

function M.Rule:extratrules(rules) return {} end

function M.Rule:convertchains(ofrags)
   local res = {}

   for _, ofrag in ipairs(ofrags) do

      if contains(builtin[self:table()], ofrag.chain) then
	 table.insert(res, ofrag)

      else
	 local ofs, recursive
	 if ofrag.chain == 'PREROUTING' then
	    ofs = {{chain='FORWARD'}, {chain='INPUT'}}
	 elseif ofrag.chain == 'POSTROUTING' then
	    ofs = {{chain='FORWARD'}, {chain='OUTPUT'}}
	    recursive = true
	 elseif ofrag.chain == 'INPUT' then
	    ofs = {{match='-m addrtype --dst-type LOCAL', chain='PREROUTING'}}
	 elseif ofrag.chain == 'FORWARD' then
	    ofs = {{match='-m addrtype ! --dst-type LOCAL', chain='PREROUTING'}}
	 end

	 if ofs then
	    local of = copy(ofrag)
	    of.chain = nil
	    ofs = combinations(ofs, {of})
	    if recursive then ofs = self:convertchains(ofs) end
	    extend(res, ofs)

	 else table.insert(res, ofrag) end
      end
   end

   return res
end

function M.Rule:extrarules(label, cls, options)
   local params = {}

   for _, attr in ipairs(
      extend(
         {'in', 'out', 'src', 'dest', 'ipset', 'string', 'match', 'service'},
	 options.attrs
      )
   ) do
      params[attr] = (options.src or self)[attr]
   end

   util.update(params, options.update)
   if options.discard then params[options.discard] = nil end

   return self:create(cls, params, label, options.index):trules()
end


M.Maskable = M.class(M.ConfigObject)

function M.Maskable:init(...)
   M.Maskable.super(self):init(...)

   -- alpine v3.5 compatibility
   if self.mask then
      self:warning(
	 "'mask' attribute is deprecated, please use 'src-mask' and 'dest-mask'"
      )
      self['src-mask'] = {}
      self['dest-mask'] = {}
      if type(self.mask) == 'number' then self.mask = {src=self.mask} end
      for _, family in ipairs(FAMILIES) do
	 setdefault(self.mask, family, copy(self.mask))
	 for _, attr in ipairs{'src', 'dest'} do
	    self[attr..'-mask'][family] = self.mask[family][attr] or
	       ({src=ADDRLEN[family], dest=0})[attr]
	 end
      end
   end

   self:initmask()
end

function M.Maskable:initmask()
   setdefault(self, 'src-mask', not self['dest-mask'])
   setdefault(self, 'dest-mask', false)

   for _, addr in ipairs{'src', 'dest'} do
      local mask = addr..'-mask'
      if type(self[mask]) ~= 'table' then
	 local m = self[mask]
	 self[mask] = {}
	 map(FAMILIES, function(f) self[mask][f] = m end)
      end
      for _, family in ipairs(FAMILIES) do
	 local value = self[mask][family]
	 if not value then self[mask][family] = 0
	 elseif value == true then self[mask][family] = ADDRLEN[family] end
      end
   end
end

function M.Maskable:recentmask(name)
   local res = {}

   for _, family in ipairs(FAMILIES) do
      local addr, len
      for _, a in ipairs{'src', 'dest'} do
	 local mask = self[a..'-mask'][family]
	 if mask > 0 then
	    if addr then return end
	    addr = a
	    len = mask
	 end
      end
      if not addr then return end

      local mask = ''

      if family == 'inet' then
	 local octet
	 for i = 0, 3 do
	    if len <= i * 8 then octet = 0
	    elseif len > i * 8 + 7 then octet = 255
	    else octet = 256 - 2^(8 - len % 8) end
	    mask = util.join(mask, '.', octet)
	 end

      elseif family == 'inet6' then
	 while len > 0 do
	    if #mask % 5 == 4 then mask = mask..':' end
	    mask = mask..('%x'):format(16 - 2^math.max(0, 4 - len))
	    len = len - 4
	 end
	 while #mask % 5 < 4 do mask = mask..'0' end
	 if #mask < 39 then mask = mask..'::' end

      else assert(false) end

      table.insert(
	 res,
	 {
	    family=family,
	    match='-m recent --name '..
	       (self.name and 'user:'..self.name or name)..' --r'..
	       ({src='source', dest='dest'})[addr]..' --mask '..mask
	 }
      )
   end

   return res
end


M.Limit = M.class(M.Maskable)

function M.Limit:init(...)
   setdefault(self, 'count', self[1] or 1)
   setdefault(self, 'interval', 1)

   M.Limit.super(self):init(...)
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

   for _, family in ipairs(FAMILIES) do
      local keys = {}
      local maskopts = ''
      for _, addr in ipairs{'src', 'dest'} do
	 local mask = self[addr..'-mask'][family]
	 if mask > 0 then
	    local opt = ({src='src', dest='dst'})[addr]
	    table.insert(keys, opt..'ip')
	    maskopts = maskopts..' --hashlimit-'..opt..'mask '..mask
	 end
      end

      table.insert(
	 ofrags,
	 {
	    family=family,
	    match=keys[1] and
	       '-m hashlimit --hashlimit-upto '..rate..' --hashlimit-burst '..
	       self:intrate()..' --hashlimit-mode '..table.concat(keys, ',')..
	       maskopts..' --hashlimit-name '..(name or self:uniqueid()) or
	       '-m limit --limit '..rate
	 }
      )
   end

   return ofrags
end


M.export = {
   custom={class=M.ConfigObject},
   ipset={class=IPSet, before='%modules'},
   zone={class=M.Zone}
}

return M
