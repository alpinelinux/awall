--[[
Option fragment module for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

function combinations(of1, of2)
   if not of1 then
      if not of2 then return nil end
      return of2
   end
   if not of2 then return of1 end

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

   return res
end

function location(of) return of.family..'/'..of.table..'/'..of.chain end
