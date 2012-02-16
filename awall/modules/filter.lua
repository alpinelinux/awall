--[[
Filter module for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall.model'
local model = awall.model

local Filter = model.class(model.Rule)

function Filter:limit()
   local res
   for i, limit in ipairs({'conn-limit', 'flow-limit'}) do
      if self[limit] then
	 if res then
	    error('Cannot specify multiple limits for a single filter rule')
	 end
	 res = limit
      end
   end
   return res
end

function Filter:position()
   return self:limit() == 'flow-limit' and 'prepend' or 'append'
end

function Filter:target()
   if not self:limit() then return model.Rule.target(self) end
   if not self['limit-target'] then self['limit-target'] = model.newchain() end
   return self['limit-target']
end

function Filter:extraoptfrags()
   local res = {}
   local limit = self:limit()
   if limit then
      if self.action ~= 'accept' then
	 error('Cannot specify limit for '..self.action..' filter')
      end
      local optbase = '-m recent --name '..self:target()
      table.insert(res, {chain=self:target(),
			 opts=optbase..' --update --hitcount '..self[limit].count..' --seconds '..self[limit].interval..' -j LOGDROP'})
      table.insert(res, {chain=self:target(),
			 opts=optbase..' --set -j ACCEPT'})
   end
   return res
end



local Policy = model.class(Filter)

function Policy:servoptfrags() return nil end


classmap = {policy=Policy, filter=Filter}

defrules = {}
for i, family in ipairs({'ip4', 'ip6'}) do
   for i, target in ipairs({'DROP', 'REJECT'}) do
      for i, opts in ipairs({'-m limit --limit 1/second -j LOG', '-j '..target}) do
	 table.insert(defrules,
		      {family=family,
		       table='filter',
		       chain='LOG'..target,
		       opts=opts})
      end
   end
   for i, chain in ipairs({'FORWARD', 'INPUT'}) do
      table.insert(defrules,
		   {family=family,
		    table='filter',
		    chain=chain,
		    opts='-m state --state RELATED,ESTABLISHED -j ACCEPT'})
   end
end
