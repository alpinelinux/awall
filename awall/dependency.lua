--[[
Dependency order resolver for Alpine Wall
Copyright (C) 2012-2014 Kaarle Ritvanen
See LICENSE file for license details
]]--

local util = require('awall.util')
local contains = util.contains

return function(items)
   local visited = {}
   local res = {}

   local function visit(key)
      if contains(res, key) then return end
      if visited[key] then return key end
      visited[key] = true

      local after = util.list(items[key].after)
      for k, v in pairs(items) do
	 if contains(v.before, key) then table.insert(after, k) end
      end
      for i, k in ipairs(after) do
	 if items[k] then
	    local ek = visit(k)
	    if ek ~= nil then return ek end
	 end
      end

      table.insert(res, key)
   end

   for i, k in util.sortedkeys(items) do
      local ek = visit(k)
      if ek ~= nil then return ek end
   end

   return res
end
