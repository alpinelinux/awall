--[[
Utility module for Alpine Wall
Copyright (C) 2012-2014 Kaarle Ritvanen
See LICENSE file for license details
]]--


local M = {}

function M.split(s, sep)
   if s == '' then return {} end
   local res = {}
   while true do
      local si, ei = s:find(sep, 1, true)
      if not si then
	 table.insert(res, s)
	 return res
      end
      table.insert(res, s:sub(1, si - 1))
      s = s:sub(ei + 1, -1)
   end
end

function M.list(var)
   if not var then return {} end
   if type(var) ~= 'table' then return {var} end
   if not next(var) then return {} end
   return var[1] and var or {var}
end

function M.listpairs(var) return ipairs(M.list(var)) end

function M.filter(var, func)
   local res = {}
   for i, v in ipairs(var) do if func(v) then table.insert(res, v) end end
   return res
end

function M.map(var, func)
   local res = {}
   for k, v in pairs(var) do res[k] = func(v) end
   return res
end

function M.maplist(var, func)
   if not var then return var end
   return M.map(M.list(var), func)
end

function M.contains(tbl, value)
   for k, v in M.listpairs(tbl) do if v == value then return true end end
   return false
end

function M.keys(tbl)
   local res = {}
   for k, v in pairs(tbl) do table.insert(res, k) end
   return res
end

function M.values(tbl)
   local res = {}
   for k, v in pairs(tbl) do table.insert(res, v) end
   return res   
end

function M.sortedkeys(tbl)
   local res = M.keys(tbl)
   table.sort(res)
   return ipairs(res)
end

function M.extend(tbl1, tbl2)
   for i, var in M.listpairs(tbl2) do table.insert(tbl1, var) end
end

function M.update(tbl1, tbl2)
   if tbl2 then for k, v in pairs(tbl2) do tbl1[k] = v end end
   return tbl1
end

function M.setdefault(t, k, v)
   if t[k] == nil then t[k] = v end
   return t[k]
end

function M.copy(tbl) return M.update({}, tbl) end

function M.compare(a, b)
   local t = type(a)
   if t ~= type(b) then return false end
   if t ~= 'table' then return a == b end

   local keys = {}
   for k, v in pairs(a) do
      if not M.compare(v, b[k]) then return false end
      table.insert(keys, k)
   end
   for k, v in pairs(b) do
      if not M.contains(keys, k) then return false end
   end
   return true
end

function M.join(a, sep, b)
   local comps = {}
   local function add(s)
      if not s then return end
      s = tostring(s)
      if s > '' then table.insert(comps, s) end
   end
   add(a)
   add(b)
   if comps[1] then return table.concat(comps, sep) end
end


function M.printtabulars(tables)
   local colwidth = {}
   for i, tbl in ipairs(tables) do
      for j, row in ipairs(tbl) do
	 for k, col in ipairs(row) do
	    colwidth[k] = math.max(colwidth[k] or 0, col:len())
	 end
      end
   end
   for i, tbl in ipairs(tables) do
      for j, row in ipairs(tbl) do
	 for k = 1,#row do
	    if k > 1 then io.write('  ') end
	    io.write(row[k])
	    if k < #row then
	       for l = 1,colwidth[k] - row[k]:len() do io.write(' ') end
	    end
	 end
	 io.write('\n')
      end
      io.write('\n')
   end
end

function M.printtabular(tbl) M.printtabulars({tbl}) end

return M
