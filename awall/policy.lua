--[[
Policy file handling for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--


local resolve = require('awall.dependency')
local class = require('awall.class')
local loader = require('awall.loader')
local schema = require('awall.schema')
local raise = require('awall.uerror').raise

local util = require('awall.util')
local contains = util.contains
local listpairs = util.listpairs
local printmsg = util.printmsg
local setdefault = util.setdefault


local posix = require('posix')


local policyattrs = {
	after=schema.List(schema.String),
	before=schema.List(schema.String),
	description=schema.Optional(schema.String),
	import=schema.List(schema.String),
	variable=schema.Map
}

local function _raise(name, msg) raise(name..': '..msg) end


local PolicyConfig = class()

function PolicyConfig:init(policies, modpath)
	local order = resolve(policies)
	if type(order) ~= 'table' then
		raise('Circular ordering directives: '..order)
	end

	self.model = loader(modpath)

	local function initdata(attr)
		for _, tbl in ipairs{'data', 'source', 'index'} do
			setdefault(self, tbl, {})[attr] = {}
		end
	end
	initdata('variable')
	for _, attr in self.model:stages() do
		if self.model:schema(attr) then initdata(attr) end
	end

	for _, name in ipairs(order) do
		for attr, objs in pairs(policies[name]) do
			if self.data[attr] then

				if type(objs) ~= 'table' then
					_raise(
						name, 'Top-level attribute '..attr..' must be a table'
					)
				end

				local cls = self.model:loadclass(attr)

				if cls and cls.append then
					local list = util.list(objs)
					local last = #self.data[attr]
					util.extend(self.data[attr], list)
					for i = 1,#list do
						local j = last + i
						self.source[attr][j] = name
						self.index[attr][j] = i
					end

				else
					for k, v in pairs(objs) do
						if type(k) ~= 'string' then
							_raise(
								name, 'Name required for '..attr..' definitions'
							)
						end
						self.data[attr][k] = v
						self.source[attr][k] = name
						self.index[attr][k] = k
					end
				end

			elseif not policyattrs[attr] then
				_raise(name, 'Unknown top-level attribute: '..attr)
			end
		end
	end
end

function PolicyConfig:expand()

	local function expand(value, visited)
		if type(value) == 'table' then
			return util.map(value, function(v) return expand(v, visited) end)
		end
		if type(value) ~= 'string' then return value end

		while true do
			local si, ei, name = value:find('%$(%a[%w_]*)')
			if not si then
				if value == '' then return end
				return value
			end

			if visited[name] then
				raise('Circular variable definition: '..name)
			end

			local var = self.data.variable[name]
			if var == nil then raise('Invalid variable reference: '..name) end
			var = expand(var, util.update({name=true}, visited))

			if si == 1 and ei == value:len() then return var end
			if not contains({'number', 'string'}, type(var)) then
				raise('Attempted to concatenate complex variable: '..name)
			end
			value = value:sub(1, si - 1)..var..value:sub(ei + 1, -1)
		end
	end

	local res = expand(self.data, {})
	local errors = {}
	for attr, objs in pairs(res) do
		if attr ~= 'variable' then
			for k, v in pairs(objs) do
				local src = self.source[attr][k]
				local index = self.index[attr][k]

				local err = schema.check(
					{[attr]={[index]=v}},
					schema.Collection(
						schema.Collection(self.model:schema(attr))
					)
				)
				if err then errors[src] = setdefault(errors, src, '')..err end

				if type(v) == 'table' then
					setmetatable(v, {location=src..': '..attr..'.'..index})
				end
			end
		end
	end

	if next(errors) then
		local check = res.variable.awall_schema_check
		if check ~= false then
			local msg = ''
			for src, err in pairs(errors) do
				msg = msg..(msg == '' and '' or '\n')..src..':'..err
			end
			if check then raise(msg)
			else
				printmsg('Warning: Some policies did not pass schema check')
				printmsg(msg)
			end
		end
	end

	return res
end


local Policy = class()

function Policy:init() self.enabled = self.type == 'mandatory' end

function Policy:error(msg) _raise(self.name, msg) end

function Policy:load()
	local file = io.open(self.path)
	if not file then raise('Unable to read policy file '..self.path) end

	-- Lua 5.2 compatibility: prefix with *
	local data = file:read('*a')

	file:close()

	local success, res = pcall(self.decode, data)
	if not success then raise(res..' while parsing '..self.path) end

	local err = schema.check(res, schema.Record(policyattrs, true))
	if err then self:error(err) end
	return res
end

function Policy:checkoptional()
	if self.type ~= 'optional' then self:error('Not an optional policy') end
end

function Policy:enable()
	self:checkoptional()
	if self.enabled then printmsg('Policy already enabled: '..self.name)
	else assert(posix.link(self.path, self.confdir..'/'..self.fname, true)) end
end

function Policy:disable()
	self:checkoptional()
	if self.enabled then assert(os.remove(self.confdir..'/'..self.fname))
	else printmsg('Policy already disabled: '..self.name) end
end


local defdirs = {
	mandatory={'/etc/awall', '/usr/share/awall/mandatory'},
	optional={'/etc/awall/optional', '/usr/share/awall/optional'},
	private={'/etc/awall/private', '/usr/share/awall/private'}
}

local PolicySet = class()

function PolicySet:init(dirs)
	local confdir = (dirs.mandatory or defdirs.mandatory)[1]
	local decoder = {
		json={mod="cjson", func="decode"},
		yaml={mod="lyaml", func="load"},
		toml={mod="toml", func="parse"},
	}
	self.policies = {}

	for i, cls in ipairs{'private', 'optional', 'mandatory'} do
		for i, dir in ipairs(dirs[cls] or defdirs[cls]) do
			for _, fname in ipairs(posix.dir(dir)) do
				local si, ei, name, suff = fname:find(
					'^([%w-]+)%.([jyt][sao][om][nl])$'
				) -- json|yaml|toml

				if name and suff and decoder[suff] then
					local pol = self.policies[name]
					local decmod = require(decoder[suff].mod)

					local path = dir..'/'..fname
					if path:sub(1, 1) ~= '/' then
						path = posix.getcwd()..'/'..path
					end

					local loc = posix.realpath(path)

					if pol then
						if pol.loc ~= loc then
							raise('Duplicate policy name: '..name)
						end

						if dir == confdir and pol.type == 'optional' then
							pol.enabled = true
						else pol.type = cls end

					else
						self.policies[name] = Policy.morph{
							name=name,
							type=cls,
							path=path,
							fname=fname,
							loc=loc,
							confdir=confdir,
							decode=decmod[decoder[suff].func]
						}
					end
				end
			end
		end
	end
end

function PolicySet:_load()

	local res = {['%defaults']={}}

	local function require(policy)
		if res[policy.name] then return end

		local data = policy:load()
		res[policy.name] = data

		if not data.after then
			data.after = {}
			for _, name in listpairs(data.import) do
				if not contains(data.before, name) then
					table.insert(data.after, name)
				end
			end
		end

		if not contains(data.before, '%defaults') then
			data.after = util.list(data.after)
			table.insert(data.after, '%defaults')
		end

		for _, name in listpairs(data.import) do
			if name:sub(1, 1) ~= '%' then
				local pol = self.policies[name]
				if not pol then policy:error('Cannot import policy '..name) end
				require(pol)
			end
		end
	end

	for name, policy in pairs(self.policies) do
		if policy.enabled then require(policy) end
	end

	return res
end

function PolicySet:active() return util.keys(self:_load()) end

function PolicySet:load(modpath) return PolicyConfig(self:_load(), modpath) end


return PolicySet

-- vim: ts=4
