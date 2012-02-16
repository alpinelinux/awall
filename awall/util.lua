--[[
Utility module for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

local function list(var)
   if not var then return {} end
   if type(var) ~= 'table' then return {var} end
   if not next(var) then return {} end
   return var[1] and var or {var}
end

function listpairs(var)
   return ipairs(list(var))
end

function map(var, func)
   local res = {}
   for k, v in pairs(var) do res[k] = func(v) end
   return res
end

function maplist(var, func)
   if not var then return var end
   return map(list(var), func)
end

function contains(tbl, value)
   for k, v in pairs(tbl) do if v == value then return true end end
   return false
end

function extend(tbl1, tbl2)
   for i, var in listpairs(tbl2) do table.insert(tbl1, var) end
end
