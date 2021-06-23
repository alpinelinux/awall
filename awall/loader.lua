--[[
Policy data model loader for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--


local class = require('awall.class')
local resolve = require('awall.dependency')

local util = require('awall.util')
local extend = util.extend


local posix = require('posix')
local chdir = posix.chdir

local endswith = require('stringy').endswith


local Model = class()

function Model:init(path)
   self._stages = {}
   self.actions = {}

   local function readmetadata(mod)
      local export = mod.export or {}
      for name, target in pairs(export) do self._stages[name] = target end

      extend(self.actions, mod.achains)

      return util.keys(export)
   end

   readmetadata(require('awall.model'))

   local cdir = posix.getcwd()
   if path then assert(chdir(path)) end

   local modules = {}
   for _, modfile in ipairs(
      posix.dir((path or '/usr/share')..'/awall/modules')
   ) do
      if endswith(modfile, '.lua') then
	 table.insert(modules, 'awall.modules.'..modfile:sub(1, -5))
      end
   end
   table.sort(modules)

   local imported = {}
   for _, name in ipairs(modules) do
      extend(imported, readmetadata(require(name)))
   end

   assert(chdir(cdir))

   self._stages['%modules'] = {before=imported}
end

function Model:stages()
   if not self.procorder then self.procorder = resolve(self._stages) end
   return ipairs(self.procorder)
end

function Model:property(key, prop)
   local stage = key:sub(1, 1) ~= '%' and self._stages[key]
   return stage and stage[prop]
end

function Model:schema(name) return self:property(name, 'schema') end

function Model:loadclass(name) return self:property(name, 'class') end

function Model:rules(stage) return self._stages[stage].rules end


return Model
