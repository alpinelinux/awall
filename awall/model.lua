--[[
Base data model for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall'
require 'awall.host'
require 'awall.util'
require 'awall.optfrag'

local util = awall.util
local combinations = awall.optfrag.combinations


function class(base)
   local cls = {}
   local mt = {__index = cls}

   if base then setmetatable(cls, {__index = base}) end

   function cls.new(...)
      local inst = arg[1] and arg[1] or {}
      cls.morph(inst)
      return inst
   end

   function cls:morph()
      setmetatable(self, mt)
      self:init()
   end

   return cls
end

Object = class()
function Object:init() end
function Object:trules() return {} end


Zone = class(Object)

function Zone:optfrags(dir)
   local iopt, aopt, iprop, aprop
   if dir == 'in' then
      iopt, aopt, iprop, aprop = 'i', 's', 'in', 'src'
   elseif dir == 'out' then
      iopt, aopt, iprop, aprop = 'o', 'd', 'out', 'dest'
   else assert(false) end

   local aopts = {}
   for i, hostdef in util.listpairs(self.addr) do
      for i, addr in ipairs(awall.host.resolve(hostdef)) do
	 table.insert(aopts,
		      {family=addr[1],
		       [aprop]=addr[2],
		       opts='-'..aopt..' '..addr[2]})
      end
   end
   if not aopts[1] then aopts = nil end

   return combinations(util.maplist(self.iface,
				    function(x)
				       return {[iprop]=x,
					       opts='-'..iopt..' '..x}
				    end),
		       aopts)
end


fwzone = Zone.new()


Rule = class(Object)


function Rule:init()
   local config = awall.config

   for i, prop in ipairs({'in', 'out'}) do
      self[prop] = self[prop] and util.maplist(self[prop],
					       function(z)
						  return z == '_fw' and fwzone or
						     config.zone[z] or
						     error('Invalid zone: '..z)
					       end) or self:defaultzones()
   end

   if self.service then
      if type(self.service) == 'string' then self.label = self.service end
      self.service = util.maplist(self.service,
				  function(s)
				     return config.service[s] or error('Invalid service: '..s)
				  end)
   end
end

function Rule:defaultzones() return {nil, fwzone} end


function Rule:checkzoneoptfrag(ofrag) end


function Rule:zoneoptfrags()

   function zonepair(zin, zout)
      assert(zin ~= zout or not zin)

      function zofs(zone, dir)
	 if not zone then return zone end
	 local ofrags = zone:optfrags(dir)
	 util.map(ofrags, function(x) self:checkzoneoptfrag(x) end)
	 return ofrags
      end

      local chain, ofrags

      if zin == fwzone or zout == fwzone then
	 local dir, z = 'in', zin
	 if zin == fwzone then dir, z = 'out', zout end
	 chain = string.upper(dir)..'PUT'
	 ofrags = zofs(z, dir)

      else
	 chain = 'FORWARD'
	 ofrags = combinations(zofs(zin, 'in'),
			       zofs(zout, 'out'))
      end

      if not ofrags then ofrags = {{}} end

      for i, ofrag in ipairs(ofrags) do ofrag.fchain = chain end

      return ofrags
   end

   local res = {}

   for i = 1,math.max(1, table.maxn(self['in'])) do
      izone = self['in'][i]
      for i = 1,math.max(1, table.maxn(self.out)) do
	 ozone = self.out[i]
	 if izone ~= ozone or not izone then
	    util.extend(res, zonepair(izone, ozone))
	 end
      end
   end

   return res
end


function Rule:servoptfrags()

   if not self.service then return end

   function containskey(tbl, key)
      for k, v in pairs(tbl) do if k == key then return true end end
      return false
   end

   local ports = {}
   local res = {}

   for i, serv in ipairs(self.service) do
      for i, sdef in util.listpairs(serv) do
	 if not sdef.proto then error('Protocol not defined') end

	 if util.contains({6, 'tcp', 17, 'udp'}, sdef.proto) then
	    local new = not containskey(ports, sdef.proto)
	    if new then ports[sdef.proto] = {} end

	    if new or ports[sdef.proto][1] then
	       if sdef.port then
		  util.extend(ports[sdef.proto], sdef.port)
	       else ports[sdef.proto] = {} end
	    end

	 else

	    local opts = '-p '..sdef.proto
	    local family = nil

	    if sdef.type then
	       -- TODO multiple ICMP types per rule
	       local oname
	       if util.contains({1, 'icmp'}, sdef.proto) then
		  family = 'inet'
		  oname = 'icmp-type'
	       elseif util.contains({58, 'ipv6-icmp', 'icmpv6'}, sdef.proto) then
		  family = 'inet6'
		  oname = 'icmpv6-type'
	       else error('Type specification not valid with '..sdef.proto) end
	       opts = opts..' --'..oname..' '..sdef.type
	    end

	    table.insert(res, {family=family, opts=opts})
	 end
      end
   end

   for proto, plist in pairs(ports) do
      local opts = '-p '..proto
      local len = table.maxn(plist)

      if len == 1 then
	 opts = opts..' --dport '..plist[1]
      elseif len > 1 then
	 opts = opts..' -m multiport --dports '
	 for i, port in ipairs(plist) do
	    if i > 1 then opts = opts..',' end
	    opts = opts..port
	 end
      end

      table.insert(res, {opts=opts})
   end

   return res
end

function Rule:table() return 'filter' end

function Rule:chain() return nil end

function Rule:position() return 'append' end

function Rule:target()
   if not self.action then error('Action not defined') end
   return string.upper(self.action)
end


function Rule:trules()

   function tag(ofrags, tag, value)
      for i, ofrag in ipairs(ofrags) do
	 assert(not ofrag[tag])
	 ofrag[tag] = value
      end
   end

   local families

   function setfamilies(ofrags)
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

   function ffilter(ofrags)
      if not ofrags or not ofrags[1] or not families then return ofrags end
      local res = {}
      for i, ofrag in util.listpairs(ofrags) do
	 if not ofrag.family or util.contains(families, ofrag.family) then
	    table.insert(res, ofrag)
	 end
      end
      return res
   end

   function appendtarget(ofrag, target)
      ofrag.opts = (ofrag.opts and ofrag.opts..' ' or '')..'-j '..target
   end

   local res = self:zoneoptfrags()

   if self.ipset then
      local ipsetofrags = {}
      for i, ipset in util.listpairs(self.ipset) do
	 if not ipset.name then error('Set name not defined') end

	 local setdef = awall.config.ipset and awall.config.ipset[ipset.name]
	 if not setdef then error('Invalid set name') end

	 if not ipset.args then
	    error('Set direction arguments not defined')
	 end

	 local setopts = '-m set --match-set '..ipset.name..' '
	 for i, arg in util.listpairs(ipset.args) do
	    if i > 1 then setopts = setopts..',' end
	    if arg == 'in' then setopts = setopts..'src'
	    elseif arg == 'out' then setopts = setopts..'dst'
	    else error('Invalid set direction argument') end
	 end
	 table.insert(ipsetofrags, {family=setdef.family, opts=setopts})
      end
      res = combinations(res, ipsetofrags)
   end

   if self.ipsec then
      res = combinations(res, {{opts='-m policy --pol ipsec --dir '..self.ipsec}})
   end

   res = combinations(res, self:servoptfrags())

   setfamilies(res)
   tag(res, 'chain', self:chain())

   local addrofrags = combinations(Zone.new({addr=self.src}):optfrags('in'),
				   Zone.new({addr=self.dest}):optfrags('out'))

   if addrofrags then
      addrofrags = ffilter(addrofrags)
      setfamilies(addrofrags)
      res = ffilter(res)
   end

   local addrchain = false
   for i, ofrag in ipairs(res) do
      if not ofrag.chain then ofrag.chain = ofrag.fchain end
      addrchain = addrchain or (self.src and ofrag.src) or (self.dest and ofrag.dest)
   end

   local target
   if addrchain then
      target = self:newchain('address')
   else
      target = self:target()
      if addrofrags then res = combinations(res, addrofrags) end
   end

   tag(res, 'position', self:position())

   for i, ofrag in ipairs(res) do appendtarget(ofrag, target) end

   if addrchain then
      for i, ofrag in ipairs(addrofrags) do
	 ofrag.chain = target
	 appendtarget(ofrag, self:target())
	 table.insert(res, ofrag)
      end      
   end

   util.extend(res, ffilter(self:extraoptfrags()))

   tag(res, 'table', self:table(), false)
   
   return combinations(res, ffilter({{family='inet'}, {family='inet6'}}))
end

function Rule:extraoptfrags() return {} end

local lastid = {}
function Rule:newchain(base)
   if self.label then base = base..'-'..self.label end
   if not lastid[base] then lastid[base] = -1 end
   lastid[base] = lastid[base] + 1
   return base..'-'..lastid[base]
end


classmap = {zone=Zone}

defrules = {}
