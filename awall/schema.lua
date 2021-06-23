--[[
Policy schema checker for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--


local schema = require('schema')
local Map = schema.Map
local String = schema.String

local M = {String=String, Record=schema.Record}

function M.Optional(sch)
   return function(data, path)
      if data ~= nil then return sch(data, path) end
   end
end

M.Map = M.Optional(Map(String, schema.Any))

function M.List(elements)
   return M.Optional(
      function(data, path)
         local sch = elements
	 if type(data) == 'table' and data[1] then
	    sch = Map(
	       schema.AllOf(schema.Integer, schema.PositiveNumber), elements
	    )
	 end
	 return sch(data, path)
      end
   )
end

function M.check(data, s)
   local err = schema.CheckSchema(data, s)
   return err and '\n'..schema.FormatOutput(err)
end

return M
