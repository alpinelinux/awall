--[[
Policy schema checker for Alpine Wall
Copyright (C) 2012-2022 Kaarle Ritvanen
See LICENSE file for license details
]]--

local FAMILIES = require('awall.family').ALL
local update = require('awall.util').update

local schema = require('schema')
local AllOf = schema.AllOf
local Boolean = schema.Boolean
local Error = schema.Error
local Integer = schema.Integer
local Map = schema.Map
local NumberFrom = schema.NumberFrom
local OneOf = schema.OneOf
local PositiveNumber = schema.PositiveNumber
local Record = schema.Record
local String = schema.String

local M = {
	AllOf=AllOf,
	Boolean=Boolean,
	Collection=schema.Collection,
	Error=Error,
	Family=OneOf(table.unpack(FAMILIES)),
	Integer=Integer,
	Nil=schema.Nil,
	NumberFrom=NumberFrom,
	OneOf=OneOf,
	String=String,
	Record=Record
}

function M.Optional(sch)
	return function(data, path)
		if data ~= nil then return sch(data, path) end
	end
end

function M.MultiType(schemata, msg)
	return function(data, path)
		local sch = schemata[type(data)]
		if sch then return sch(data, path) end
		return Error(path..' '..msg, path)
	end
end

function M.NonNegativeInteger(max)
	return AllOf(Integer, max and NumberFrom(0, max) or NonNegativeNumber)
end

M.PositiveInteger = AllOf(Integer, PositiveNumber)

function M.UInt(bits) return M.NonNegativeInteger(2^bits - 1) end

M.PortRange = M.MultiType(
	{
		number=M.UInt(16),
		string=function(data, path)
			local ports = {data:match('(%d+)-(%d+)$')}
			if #ports < 2 then
				return Error('Invalid port range at '..path..': '..data, path)
			end
			for _, port in ipairs(ports) do
				local err = M.UInt(16)(tonumber(port), path)
				if err then return err end
			end
		end
	},
	'must be port or port range'
)

local MaskLength = M.NonNegativeInteger(128)

M.MaskSpec = M.MultiType(
	{boolean=Boolean, number=MaskLength, table=Map(M.Family, MaskLength)},
	'must be boolean, integer or object keyed by address families'
)

function M.Limit(extra)
	return M.MultiType(
		{
			number=M.NonNegativeInteger(),
			table=Record(
				update(
					{
						count=M.Optional(M.NonNegativeInteger()),
						['dest-mask']=M.Optional(M.MaskSpec),
						interval=M.Optional(M.PositiveInteger),
						['src-mask']=M.Optional(M.MaskSpec)
					},
					extra
				)
			)
		},
		'is not a valid limit'
	)
end

M.Map = M.Optional(Map(String, schema.Any))

function M.List(elements)
	return M.Optional(
		function(data, path)
			local sch = elements
			if type(data) == 'table' and data[1] then
				sch = Map(M.PositiveInteger, elements)
			end
			return sch(data, path)
		end
	)
end

function M.Rule(extra)
	return Record(
		update(
			{
				action=M.Optional(M.String),
				dest=M.List(M.String),
				ipset=M.List(
					Record{args=M.List(OneOf('in', 'out')), name=M.String}
				),
				['in']=M.List(M.String),
				match=M.Optional(M.String),
				out=M.List(M.String),
				service=M.List(M.String),
				src=M.List(M.String),
				string=M.Optional(
					M.MultiType(
						{
							string=M.String,
							table=Record{
								algo=M.Optional(OneOf('bm', 'kmp')),
								from=M.Optional(M.PositiveInteger),
								match=M.String,
								to=M.Optional(M.PositiveInteger)
							}
						},
						'must be match string or descriptor object'
					)
				)
			},
			extra
		)
	)
end

function M.check(data, s)
	local err = schema.CheckSchema(data, s)
	return err and '\n'..schema.FormatOutput(err)
end

return M

-- vim: ts=4
