--[[
Packet logging module for Alpine Wall
Copyright (C) 2012-2014 Kaarle Ritvanen
See LICENSE file for license details
]]--


local model = require('awall.model')
local class = model.class

local combinations = require('awall.optfrag').combinations
local setdefault = require('awall.util').setdefault


local LogLimit = class(model.Limit)

function LogLimit:init(...)
   setdefault(self, 'mask', 0)
   LogLimit.super(self):init(...)
end


local Log = class(model.ConfigObject)

function Log:matchofrags()
   local selector, ofrags

   for i, sel in ipairs{'every', 'limit', 'probability'} do
      local value = self[sel]
      if value then
	 if selector then
	    self:error('Cannot combine '..sel..' with '..selector)
	 end
	 selector = sel

	 if sel == 'every' then
	    ofrags = {
	       {opts='-m statistic --mode nth --every '..value..' --packet 0'}
	    }
	 elseif sel == 'limit' then
	    ofrags = self:create(LogLimit, value, 'loglimit'):limitofrags()
	 elseif sel == 'probability' then
	    ofrags = {{opts='-m statistic --mode random --probability '..value}}
	 else assert(false) end
      end
   end

   if self.mode == 'ulog' then
      ofrags = combinations({{family='inet'}}, ofrags)
   end

   return ofrags
end

function Log:target()
   local optmap = {
      log={level='level', prefix='prefix'},
      nflog={
	 group='group',
	 prefix='prefix',
	 range='range',
	 threshold='threshold'
      },
      ulog={
	 group='nlgroup',
	 prefix='prefix',
	 range='cprange',
	 threshold='qthreshold'
      }
   }

   local mode = self.mode or 'log'
   if not optmap[mode] then self:error('Invalid logging mode: '..mode) end

   local res = mode:upper()
   for s, t in pairs(optmap[mode]) do
      if self[s] then res = res..' --'..mode..'-'..t..' '..self[s] end
   end
   return res
end

function Log:optfrags()
   return combinations(self:matchofrags(), {{target=self:target()}})
end

function Log.get(rule, spec, default)
   if spec == nil then spec = default end
   if spec == false then return end
   if spec == true then spec = '_default' end
   return rule.root.log[spec] or rule:error('Invalid log: '..spec)
end


local LogRule = class(model.Rule)

function LogRule:init(...)
   LogRule.super(self):init(...)
   self.log = Log.get(self, self.log, true)
end

function LogRule:position() return 'prepend' end

function LogRule:servoptfrags()
   return combinations(
      LogRule.super(self):servoptfrags(), self.log:matchofrags()
   )
end

function LogRule:target() return self.log:target() end


return {
   export={
      log={class=Log}, ['packet-log']={class=LogRule, after='%filter-after'}
   }
}
