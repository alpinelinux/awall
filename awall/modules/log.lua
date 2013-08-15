--[[
Packet logging module for Alpine Wall
Copyright (C) 2012-2013 Kaarle Ritvanen
See LICENSE file for license details
]]--


module(..., package.seeall)

local model = require('awall.model')
local Rule = model.Rule

local combinations = require('awall.optfrag').combinations


local Log = model.class(model.ConfigObject)

function Log:matchofrag()
   local selector, opts

   for i, sel in ipairs{'every', 'limit', 'probability'} do
      local value = self[sel]
      if value then
	 if selector then
	    self:error('Cannot combine '..sel..' with '..selector)
	 end
	 selector = sel

	 if sel == 'every' then
	    opts = '-m statistic --mode nth --every '..value..' --packet 0'
	 elseif sel == 'limit' then
	    opts = '-m limit --limit '..value..'/second'
	 elseif sel == 'probability' then
	    opts = '-m statistic --mode random --probability '..value
	 else assert(false) end
      end
   end

   return {family=self.mode == 'ulog' and 'inet' or nil, opts=opts}
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

   local res = string.upper(mode)
   for s, t in pairs(optmap[mode]) do
      if self[s] then res = res..' --'..mode..'-'..t..' '..self[s] end
   end
   return res
end

function Log:optfrag()
   local res = self:matchofrag()
   res.target = self:target()
   return res
end

function Log.get(rule, spec, default)
   if spec == nil then spec = default end
   if spec == false then return end
   if spec == true then spec = '_default' end
   return rule.root.log[spec] or rule:error('Invalid log: '..spec)
end


local LogRule = model.class(Rule)

function LogRule:init(...)
   Rule.init(self, unpack(arg))
   self.log = Log.get(self, self.log, true)
end

function LogRule:position() return 'prepend' end

function LogRule:servoptfrags()
   return combinations(Rule.servoptfrags(self), {self.log:matchofrag()})
end

function LogRule:target() return self.log:target() end

export = {
   log={class=Log},
   ['packet-log']={class=LogRule, after='%filter-after'}
}
