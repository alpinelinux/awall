--[[
Alpine Wall main module
Copyright (C) 2012-2014 Kaarle Ritvanen
See LICENSE file for license details
]]--

module(..., package.seeall)

require 'lfs'
require 'stringy'

require 'awall.dependency'
require 'awall.ipset'
require 'awall.iptables'
require 'awall.model'
require 'awall.object'
require 'awall.optfrag'
require 'awall.policy'
require 'awall.util'

local optfrag = awall.optfrag


local events
local procorder
local achains

function loadmodules(path)
   events = {}
   achains = {}

   local function readmetadata(mod)
      local export = mod.export or {}
      for name, target in pairs(export) do events[name] = target end

      for name, opts in pairs(mod.achains or {}) do
	 assert(not achains[name])
	 achains[name] = opts
      end

      return awall.util.keys(export)
   end

   readmetadata(model)

   local cdir = lfs.currentdir()
   if path then lfs.chdir(path) end

   local modules = {}
   for modfile in lfs.dir((path or '/usr/share/lua/5.1')..'/awall/modules') do
      if stringy.endswith(modfile, '.lua') then
	 table.insert(modules, 'awall.modules.'..modfile:sub(1, -5))
      end
   end
   table.sort(modules)

   local imported = {}
   for i, name in ipairs(modules) do
      require(name)
      awall.util.extend(imported, readmetadata(package.loaded[name]))
   end

   lfs.chdir(cdir)

   events['%modules'] = {before=imported}
   procorder = awall.dependency.order(events)
end

function loadclass(path)
   assert(path:sub(1, 1) ~= '%')
   return events[path] and events[path].class
end


PolicySet = policy.PolicySet


Config = object.class()

function Config:init(policyconfig)

   self.objects = policyconfig:expand()
   self.iptables = iptables.IPTables()

   local acfrags = {}

   local function insertrules(trules)
      for i, trule in ipairs(trules) do
	 local t = self.iptables.config[trule.family][trule.table][trule.chain]
	 local opts = (trule.opts and trule.opts..' ' or '')..'-j '..trule.target

	 local acfrag = {family=trule.family,
			 table=trule.table,
			 chain=trule.target}
	 acfrags[optfrag.location(acfrag)] = acfrag

	 if trule.position == 'prepend' then
	    table.insert(t, 1, opts)
	 else
	    table.insert(t, opts)
	 end
      end
   end

   for i, path in ipairs(procorder) do
      if path:sub(1, 1) ~= '%' then
	 local objs = self.objects[path]
	 if objs then
	    for k, v in pairs(objs) do
	       objs[k] = events[path].class.morph(
		  v,
		  self,
		  path..' '..k..' ('..policyconfig.source[path][k]..')'
	       )
	    end
	 end
      end
   end

   for i, event in ipairs(procorder) do
      if event:sub(1, 1) == '%' then
	 local r = events[event].rules
	 if r then
	    if type(r) == 'function' then r = r(self.objects) end
	    if r then
	       assert(type(r) == 'table')
	       insertrules(r)
	    end
	 end
      elseif self.objects[event] then
	 for i, rule in ipairs(self.objects[event]) do
	    insertrules(rule:trules())
	 end
      end
   end

   local ofrags = {}
   for k, v in pairs(acfrags) do table.insert(ofrags, v) end
   insertrules(optfrag.combinations(achains, ofrags))

   self.ipset = ipset.IPSet(self.objects.ipset)
end

function Config:print()
   self.ipset:print()
   print()
   self.iptables:print()
end

function Config:dump(dir)
   self.ipset:dump(dir or '/etc/ipset.d')
   self.iptables:dump(dir or '/etc/iptables')
end

function Config:test()
   self.ipset:create()
   self.iptables:test()
end

function Config:activate()
   self:test()
   self.iptables:activate()
end
