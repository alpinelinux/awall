--[[
Filter module for Alpine Wall
Copyright (C) 2012-2017 Kaarle Ritvanen
See LICENSE file for license details
]]--


local loadclass = require('awall').loadclass
local resolve = require('awall.host')

local model = require('awall.model')
local class = model.class
local Rule = model.Rule

local optfrag = require('awall.optfrag')
local combinations = optfrag.combinations

local util = require('awall.util')
local contains = util.contains
local extend = util.extend
local listpairs = util.listpairs
local setdefault = util.setdefault


local function initmask(obj)
   for _, attr in ipairs{'src-mask', 'dest-mask'} do
      if obj[attr] then
	 obj:error('Attribute not allowed with a named limit: '..attr)
      end
   end

   local limits = obj.root.limit
   obj[(obj.addr or 'src')..'-mask'] = limits and limits[obj.name] or true
end


local RECENT_MAX_COUNT = 20

local FilterLimit = class(model.Limit)

function FilterLimit:initmask()
   if self.name then initmask(self)
   elseif self.update ~= nil then
      self:error('Attribute allowed only with named limits: update')
   end

   FilterLimit.super(self):initmask()

   if self.name and not self:recentofrags() then
      self:error('Attribute allowed only with low-rate limits: name')
   end
end

function FilterLimit:recentofrags(name)
   local count = self.count
   local interval = self.interval

   if count > RECENT_MAX_COUNT then
      count = self:intrate()
      interval = 1
   end

   if count > RECENT_MAX_COUNT then return end

   local update = self.update ~= false

   local ofs = self:recentmask(name)
   if not ofs then return end

   return combinations(
      ofs,
      {
	 {match='--'..(update and 'update' or 'rcheck')..' --hitcount '..
	     count..' --seconds '..interval}
      }
   ), update and combinations(ofs, {{match='--set'}}) or nil
end


local LimitReference = class(model.Maskable)

function LimitReference:initmask()
   if not self.name then
      if not self[1] then self:error('Limit name not defined') end
      self.name = self[1]
   end
   initmask(self)

   LimitReference.super(self):initmask()
end

function LimitReference:recentofrags()
   local ofs = self:recentmask()
   return ofs and combinations(ofs, {{match='--set'}}) or
      self:error('Invalid address mask for limit')
end


local TranslatingRule = class(Rule)

function TranslatingRule:init(...)
   TranslatingRule.super(self):init(...)
   if type(self.dnat) == 'string' then self.dnat = {addr=self.dnat} end
end

function TranslatingRule:destoptfrags()
   local ofrags = TranslatingRule.super(self):destoptfrags()
   if not self.dnat then return ofrags end

   ofrags = combinations(ofrags, {{family='inet6'}})
   local natof = self:create(
      model.Zone, {addr=self.dnat.addr}
   ):optfrags(self:direction('out'))
   assert(#natof == 1)
   table.insert(ofrags, natof[1])
   return ofrags
end

function TranslatingRule:servoptfrags()
   local ofrags = TranslatingRule.super(self):servoptfrags()
   if not (self.dnat and self.dnat.port) then return ofrags end

   ofrags = combinations(ofrags, {{family='inet6'}})

   local protos = {}
   for _, serv in listpairs(self.service) do
      for _, sdef in listpairs(serv) do
	 if sdef.family ~= 'inet6' then
	    if not contains({'tcp', 'udp'}, sdef.proto) then
	       self:error('Cannot do port translation for '..sdef.proto)
	    end
	    protos[sdef.proto] = true
	 end
      end
   end
   for proto, _ in pairs(protos) do
      extend(
	 ofrags,
	 combinations(
	    self:create(
	       model.Rule, {service={proto=proto, port=self.dnat.port}}
	    ):servoptfrags(),
	    {{family='inet'}}
	 )
      )
   end

   return ofrags
end


local LoggingRule = class(TranslatingRule)

function LoggingRule:init(...)
   LoggingRule.super(self):init(...)
   setdefault(self, 'action', 'accept')

   local custom = self:customtarget()
   if type(self.log) ~= 'table' then
      self.log = loadclass('log').get(
	 self, self.log, not custom and self:logdefault()
      )
   end
   if custom and self.log then
      self:error('Logging not allowed with custom action: '..self.action)
   end
end

function LoggingRule:logdefault() return false end

function LoggingRule:target() return 'ACCEPT' end

function LoggingRule:actofrags(log, target)
   local res = log and log:optfrags() or {}
   if target ~= nil then table.insert(res, {target=target}) end
   return res
end

function LoggingRule:combinelog(ofrags, log, action, target)
   local actions = self:actofrags(log, target)
   return actions[1] and
      self:combine(ofrags, actions, 'log'..action, log and log:target()) or
      ofrags
end

function LoggingRule:mangleoptfrags(ofrags)
   return self:customtarget() and ofrags or
      self:combinelog(ofrags, self.log, self.action, self:target())
end


local RelatedRule = class(TranslatingRule)

function RelatedRule:servoptfrags()
   local helpers = {}
   for i, serv in listpairs(self.service) do
      for i, sdef in listpairs(serv) do
	 local helper = sdef['ct-helper']
	 if helper then
	    helpers[helper] = {
	       family=sdef.family,
	       match='-m conntrack --ctstate RELATED -m helper --helper '..
	          helper
	    }
	 end
      end
   end
   return util.values(helpers)
end

function RelatedRule:target() return 'ACCEPT' end


local Filter = class(LoggingRule)

function Filter:init(...)
   local ul = self['update-limit']
   if ul then setdefault(self, 'action', 'pass') end

   Filter.super(self):init(...)

   -- alpine v2.4 compatibility
   if contains({'logdrop', 'logreject'}, self.action) then
      self:warning('Deprecated action: '..self.action)
      self.action = self.action:sub(4, -1)
   end

   local limit = self:limit()
   if limit then
      if limit == 'conn-limit' and self['no-track'] then
	 self:error('Tracking required with connection limit')
      end
      if type(self[limit]) ~= 'table' then
	 self[limit] = {count=self[limit]}
      end
      self[limit].log = loadclass('log').get(self, self[limit].log, true)
   end

   if ul and self.action ~= 'pass' then
      self:error('Cannot specify action with update-limit')
   end
end

function Filter:updatelimit()
   local ul = util.copy(self['update-limit'])

   if type(ul) == 'table' then
      if not contains({'conn', 'flow'}, setdefault(ul, 'measure', 'conn')) then
	 self:error('Invalid value for measure: '..ul.measure)
      end

      if self['no-track'] and ul.measure == 'conn' then
	 self:error('Tracking required when measuring connection rate')
      end
   end

   return ul and self:create(LimitReference, ul, 'update-limit')
end

function Filter:extratrules()
   local res = {}

   local function extrarules(label, cls, options)
      options = options or {}
      options.attrs = 'dnat'
      extend(res, self:extrarules(label, cls, options))
   end

   if self.dnat then
      if self.action ~= 'accept' then
	 self:error('dnat option not allowed with '..self.action..' action')
      end
      if self['no-track'] then
	 self:error('dnat option not allowed with no-track')
      end
      if self.ipset then
	 self:error('dnat and ipset options cannot be used simultaneously')
      end

      if self.dnat.addr:find('/') then
	 self:error('DNAT target cannot be a network address')
      end

      local dnataddr
      for i, addr in ipairs(resolve(self.dnat.addr, self)) do
	 if addr[1] == 'inet' then
	    if dnataddr then
	       self:error(
		  self.dnat.addr..' resolves to multiple IPv4 addresses'
	       )
	    end
	    dnataddr = addr[2]
	 end
      end
      if not dnataddr then
	 self:error(self.dnat.addr..' does not resolve to any IPv4 address')
      end

      extrarules(
	 'dnat',
	 'dnat',
	 {
	    update={['to-addr']=dnataddr, ['to-port']=self.dnat.port},
	    discard='out'
	 }
      )
   end

   if self.action == 'tarpit' or self['no-track'] then
      extrarules('no-track', 'no-track')
   end

   if self.action == 'accept' then
      if self:position() == 'prepend' then
	 extrarules('final', LoggingRule, {update={log=self.log}})
      end

      local nr = #res

      if self.related then
	 for i, rule in listpairs(self.related) do
	    extrarules(
	       'related',
	       RelatedRule,
	       {index=i, src=rule, update={service=self.service}}
	    )
	 end
      else
	 -- TODO avoid creating unnecessary RELATED rules by introducing
	 -- helper direction attributes to service definitions
	 extrarules('related', RelatedRule)
	 extrarules('related-reply', RelatedRule, {update={reverse=true}})
      end

      if self['no-track'] then
	 if #res > nr then
	    self:error('Tracking required by service')
	 end
	 extrarules('no-track-reply', 'no-track', {update={reverse=true}})
	 extrarules('reply', 'filter', {update={reverse=true}})
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
   local ul = self:updatelimit()
   return not self['no-track'] and (
      self:limit() == 'flow-limit' or (ul and ul.measure == 'flow')
   ) and 'prepend' or 'append'
end

function Filter:logdefault()
   return contains({'drop', 'reject', 'tarpit'}, self.action)
end

function Filter:target()
   if self.action == 'pass' then return end
   if self.action ~= 'accept' and not self:logdefault() then
      self:error('Invalid filter action: '..self.action)
   end
   return self.action == 'tarpit' and 'tarpit' or self.action:upper()
end

function Filter:mangleoptfrags(ofrags)
   local limit = self:limit()
   local ul = self:updatelimit()

   if not limit then
      if ul then
	 ofrags = self:combine(ofrags, ul:recentofrags())
      end
      return Filter.super(self):mangleoptfrags(ofrags)
   end

   local function incompatible(item)
      self:error('Limit incompatible with '..item)
   end

   if ul then incompatible('update-limit') end

   if self:customtarget() or self:logdefault() then
      incompatible('action: '..self.action)
   end

   local limitchain = self:uniqueid('limit')
   local limitlog = self[limit].log
   local limitobj = self:create(FilterLimit, self[limit], 'limit')

   local ofs
   local final = self:position() == 'append'
   local target = self:target()
   local ft = final and target
   local pl = not target and self.log

   local cofs, sofs = limitobj:recentofrags(limitchain)

   if cofs then
      ofs = self:combinelog(cofs, limitlog, 'drop', 'DROP')

      local nxt
      if ft then
	 extend(ofs, self:actofrags(self.log))
	 nxt = target
      elseif sofs and not (pl and pl:target()) then nxt = false end
      extend(ofs, combinations(sofs, self:actofrags(pl, nxt)))

   else
      if pl then incompatible('action or log') end

      local limofs = limitobj:limitofrags(limitchain)
      ofs = ft and Filter.super(self):mangleoptfrags(limofs) or
	 combinations(limofs, {{target='RETURN'}})

      extend(ofs, self:actofrags(limitlog, 'DROP'))
   end

   return self:combine(ofrags, ofs, 'limit', true)
end


local Policy = class(Filter)

function Policy:servoptfrags() return nil end


local fchains = {{chain='FORWARD'}, {chain='INPUT'}, {chain='OUTPUT'}}

local function stateful(config)
   local res = {}

   for _, family in ipairs(optfrag.FAMILIES) do

      local er = combinations(
	 fchains,
	 {{match='-m conntrack --ctstate ESTABLISHED'}}
      )
      for i, chain in ipairs({'INPUT', 'OUTPUT'}) do
	 table.insert(
	    er, {chain=chain, match='-'..chain:sub(1, 1):lower()..' lo'}
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

local icmp = {{family='inet', table='filter', match='-p icmp'}}
local icmp6 = {{family='inet6', table='filter', match='-p icmpv6'}}
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
      combinations(
         ofrag,
	 {{chain='icmp-routing', target='ACCEPT'}},
	 util.map(types, function(t) return {match='--'..oname..' '..t} end)
      )
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
      {{chain='tarpit'}}, {{match='-p tcp', target='TARPIT'}, {target='DROP'}}
   )
}
