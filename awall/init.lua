--[[
Alpine Wall main module
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--

module(..., package.seeall)

require 'lfs'
require 'stringy'

require 'awall.ipset'
require 'awall.iptables'
require 'awall.model'
require 'awall.object'
require 'awall.policy'
require 'awall.util'


local procorder
local defrules

function loadmodules(path)
   classmap = {}
   procorder = {}
   defrules = {}

   local function readmetadata(mod)
      for i, clsdef in ipairs(mod.classes) do
	 local path, cls = unpack(clsdef)
	 classmap[path] = cls
	 table.insert(procorder, path)
      end
      for phase, rules in pairs(mod.defrules) do
	 if not defrules[phase] then defrules[phase] = {} end
	 util.extend(defrules[phase], rules)
      end
   end

   readmetadata(model)

   local cdir = lfs.currentdir()
   if path then lfs.chdir(path) end

   for modfile in lfs.dir((path or '/usr/share/lua/5.1')..'/awall/modules') do
      if stringy.endswith(modfile, '.lua') then
	 local name = 'awall.modules.'..string.sub(modfile, 1, -5)
	 require(name)
	 readmetadata(package.loaded[name])
      end
   end

   lfs.chdir(cdir)
end


PolicySet = policy.PolicySet


Config = object.class(object.Object)

function Config:init(policyconfig)

   self.input = policyconfig:expand()
   self.iptables = iptables.IPTables.new()

   local function insertrules(trules)
      for i, trule in ipairs(trules) do
	 local t = self.iptables.config[trule.family][trule.table][trule.chain]
	 if trule.position == 'prepend' then
	    table.insert(t, 1, trule.opts)
	 else
	    table.insert(t, trule.opts)
	 end
      end
   end

   local function insertdefrules(phase)
      if defrules[phase] then insertrules(defrules[phase]) end
   end

   for i, path in ipairs(procorder) do
      if self.input[path] then
	 util.map(self.input[path],
		  function(obj) return classmap[path].morph(obj, self) end)
      end
   end

   insertdefrules('pre')

   for i, path in ipairs(procorder) do
      if self.input[path] then
	 for i, rule in ipairs(self.input[path]) do
	    insertrules(rule:trules())
	 end
      end
      insertdefrules('post-'..path)
   end

   self.ipset = ipset.IPSet.new(self.input.ipset)
end

function Config:dump(iptdir, ipsfile)
   self.ipset:dump(ipsfile or '/etc/ipset.d/awall')
   self.iptables:dump(iptdir or '/etc/iptables')
end

function Config:test()
   self.ipset:create()
   self.iptables:test()
end

function Config:activate()
   self:test()
   self.iptables:activate()
end
