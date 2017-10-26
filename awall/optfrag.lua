--[[
Option fragment module for Alpine Wall
Copyright (C) 2012-2017 Kaarle Ritvanen
See LICENSE file for license details
]]--


local M = {}

M.FAMILIES = {'inet', 'inet6'}
M.FAMILYFRAGS = require('awall.util').map(
   M.FAMILIES, function(f) return {family=f} end
)

function M.combinations(of1, ...)
   local arg = {...}

   if #arg == 0 then return of1 end

   if not of1 then return M.combinations(...) end

   local of2 = arg[1]
   table.remove(arg, 1)
   if not of2 then return M.combinations(of1, table.unpack(arg)) end

   local res = {}
   for i, x in ipairs(of1) do
      for i, y in ipairs(of2) do

	 local of = {}
	 for k, v in pairs(x) do
	    if k ~= 'match' then of[k] = v end
	 end

	 local match = true
	 for k, v in pairs(y) do
	    if k ~= 'match' then
	       if of[k] and v ~= of[k] then
		  match = false
		  break
	       end
	       of[k] = v
	    end
	 end

	 if match then
	    if x.match then
	       if y.match then of.match = x.match..' '..y.match
	       else of.match = x.match end
	    else of.match = y.match end
	    table.insert(res, of)
	 end
      end
   end

   return M.combinations(res, table.unpack(arg))
end

function M.location(of) return of.family..'/'..of.table..'/'..of.chain end

function M.command(of)
   return (of.match and of.match..' ' or '')..
      (of.target and '-j '..of.target or '')
end

return M
