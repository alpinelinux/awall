--[[
Option fragment module for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
See LICENSE file for license details
]]--


module(..., package.seeall)

function combinations(of1, ...)
   if #arg == 0 then return of1 end

   if not of1 then return combinations(unpack(arg)) end

   local of2 = arg[1]
   table.remove(arg, 1)
   if not of2 then return combinations(of1, unpack(arg)) end

   local res = {}
   for i, x in ipairs(of1) do
      for i, y in ipairs(of2) do

	 local of = {}
	 for k, v in pairs(x) do
	    if k ~= 'opts' then of[k] = v end
	 end

	 local match = true
	 for k, v in pairs(y) do
	    if k ~= 'opts' then
	       if of[k] and v ~= of[k] then
		  match = false
		  break
	       end
	       of[k] = v
	    end
	 end

	 if match then
	    if x.opts then
	       if y.opts then of.opts = x.opts..' '..y.opts
	       else of.opts = x.opts end
	    else of.opts = y.opts end
	    table.insert(res, of)
	 end
      end
   end

   return combinations(res, unpack(arg))
end

function location(of) return of.family..'/'..of.table..'/'..of.chain end
