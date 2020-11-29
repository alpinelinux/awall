--[[
Policy schema checker for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--


local schema = require('schema')
local Optional = schema.Optional
local String = schema.String

local M = {
   Map=Optional(schema.Map(String, schema.Any)),
   Optional=Optional,
   String=String,
   Record=schema.Record
}

function M.List(elements)
   return Optional(
      schema.OneOf(
	 elements,
	 schema.Map(
	    schema.AllOf(schema.PositiveNumber, schema.Integer), elements
	 )
      )
   )
end

function M.check(data, s)
   local err = schema.CheckSchema(data, s)
   return err and '\n'..schema.FormatOutput(err)
end

return M
