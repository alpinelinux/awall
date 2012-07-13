--[[
Base data model for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall'
require 'awall.host'
require 'awall.util'
require 'awall.object'
require 'awall.optfrag'

local util = awall.util
local combinations = awall.optfrag.combinations

class = awall.object.class


ConfigObject = class(awall.object.Object)

function ConfigObject:init(context, location)
   if context then
      self.context = context
      self.root = context.input
   end
   self.location = location
end

function ConfigObject:create(cls, params)
   return cls.morph(params, self.context, self.location)
end

function ConfigObject:error(msg) error(self.location..': '..msg) end

function ConfigObject:trules() return {} end


Zone = class(ConfigObject)

function Zone:optfrags(dir)
   local iopt, aopt, iprop, aprop
   if dir == 'in' then
      iopt, aopt, iprop, aprop = 'i', 's', 'in', 'src'
   elseif dir == 'out' then
      iopt, aopt, iprop, aprop = 'o', 'd', 'out', 'dest'
   else assert(false) end

   local aopts = nil
   if self.addr then
      aopts = {}
      for i, hostdef in util.listpairs(self.addr) do
	 for i, addr in ipairs(awall.host.resolve(hostdef, self)) do
	    table.insert(aopts,
			 {family=addr[1],
			  [aprop]=addr[2],
			  opts='-'..aopt..' '..addr[2]})
	 end
      end
   end

   return combinations(util.maplist(self.iface,
				    function(x)
				       return {[iprop]=x,
					       opts='-'..iopt..' '..x}
				    end),
		       aopts)
end


fwzone = Zone.new()


Rule = class(ConfigObject)


function Rule:init(...)
   ConfigObject.init(self, unpack(arg))

   for i, prop in ipairs({'in', 'out'}) do
      self[prop] = self[prop] and util.maplist(self[prop],
					       function(z)
						  if type(z) ~= 'string' then return z end
						  return z == '_fw' and fwzone or
						     self.root.zone[z] or
						     self:error('Invalid zone: '..z)
					       end) or self:defaultzones()
   end

   if self.service then
      if type(self.service) == 'string' then self.label = self.service end
      self.service = util.maplist(self.service,
				  function(s)
				     if type(s) ~= 'string' then return s end
				     return self.root.service[s] or self:error('Invalid service: '..s)
				  end)
   end
end

function Rule:defaultzones() return {nil, fwzone} end


function Rule:checkzoneoptfrag(ofrag) end


function Rule:zoneoptfrags()

   local function zonepair(zin, zout)

      local function zofs(zone, dir)
	 if not zone then return zone end
	 local ofrags = zone:optfrags(dir)
	 util.map(ofrags, function(x) self:checkzoneoptfrag(x) end)
	 return ofrags
      end

      local chain, ofrags

      if zin == fwzone or zout == fwzone then
	 if zin == zout then return {} end
	 local dir, z = 'in', zin
	 if zin == fwzone then dir, z = 'out', zout end
	 chain = string.upper(dir)..'PUT'
	 ofrags = zofs(z, dir)

      else
	 chain = 'FORWARD'
	 ofrags = combinations(zofs(zin, 'in'), zofs(zout, 'out'))

	 if ofrags then
	    ofrags = util.filter(ofrags,
				 function(of)
				    return not (of['in'] and of.out and
						of['in'] == of.out)
				 end)
	 end
      end

      if not ofrags then ofrags = {{}} end

      for i, ofrag in ipairs(ofrags) do ofrag.fchain = chain end

      return ofrags
   end

   local res = {}

   for i = 1,math.max(1, table.maxn(self['in'])) do
      for j = 1,math.max(1, table.maxn(self.out)) do
	 util.extend(res, zonepair(self['in'][i], self.out[j]))
      end
   end

   return res
end


function Rule:servoptfrags()

   if not self.service then return end

   local function containskey(tbl, key)
      for k, v in pairs(tbl) do if k == key then return true end end
      return false
   end

   local ports = {}
   local res = {}

   for i, serv in ipairs(self.service) do
      for i, sdef in util.listpairs(serv) do
	 if not sdef.proto then self:error('Protocol not defined') end

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

	    -- TODO multiple ICMP types per rule
	    local oname
	    if util.contains({1, 'icmp'}, sdef.proto) then
	       family = 'inet'
	       oname = 'icmp-type'
	    elseif util.contains({58, 'ipv6-icmp', 'icmpv6'}, sdef.proto) then
	       family = 'inet6'
	       oname = 'icmpv6-type'
	    elseif sdef.type then
	       self:error('Type specification not valid with '..sdef.proto)
	    end
	    if sdef.type then opts = opts..' --'..oname..' '..sdef.type end

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

function Rule:destoptfrags()
   return self:create(Zone, {addr=self.dest}):optfrags('out')
end

function Rule:table() return 'filter' end

function Rule:chain() return nil end

function Rule:position() return 'append' end

function Rule:target()
   if not self.action then self:error('Action not defined') end
   return string.upper(self.action)
end


function Rule:trules()

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
      return util.filter(ofrags,
			 function(of)
			    return not of.family or util.contains(families,
								  of.family)
			 end)
   end

   local function appendtarget(ofrag, target)
      ofrag.opts = (ofrag.opts and ofrag.opts..' ' or '')..'-j '..target
   end

   local res = self:zoneoptfrags()

   if self.ipset then
      local ipsetofrags = {}
      for i, ipset in util.listpairs(self.ipset) do
	 if not ipset.name then self:error('Set name not defined') end

	 local setdef = self.root.ipset and self.root.ipset[ipset.name]
	 if not setdef then self:error('Invalid set name') end

	 if not ipset.args then
	    self:error('Set direction arguments not defined')
	 end

	 local setopts = '-m set --match-set '..ipset.name..' '
	 for i, arg in util.listpairs(ipset.args) do
	    if i > 1 then setopts = setopts..',' end
	    if arg == 'in' then setopts = setopts..'src'
	    elseif arg == 'out' then setopts = setopts..'dst'
	    else self:error('Invalid set direction argument') end
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

   local addrofrags = combinations(self:create(Zone, {addr=self.src}):optfrags('in'),
				   self:destoptfrags())

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
      res = combinations(res, addrofrags)
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

function Rule:newchain(base)
   if not self.context.lastid then self.context.lastid = {} end
   local lastid = self.context.lastid

   if self.label then base = base..'-'..self.label end
   if not lastid[base] then lastid[base] = -1 end
   lastid[base] = lastid[base] + 1
   return base..'-'..lastid[base]
end


classes = {{'zone', Zone}}
defrules = {}
