--[[
Policy file handling for Alpine Wall
Copyright (C) 2012-2021 Kaarle Ritvanen
See LICENSE file for license details
]]--


local resolve = require('awall.dependency')
local class = require('awall.class')
local raise = require('awall.uerror').raise

local util = require('awall.util')
local contains = util.contains
local keys = util.keys
local listpairs = util.listpairs
local map = util.map
local printmsg = util.printmsg


local posix = require('posix')


local PolicyConfig = class()

function PolicyConfig:init(policies)
   local order = resolve(policies)
   if type(order) ~= 'table' then
      raise('Circular ordering directives: '..order)
   end

   self.data = {}
   self.source = {}

   for _, name in ipairs(order) do
      for attr, objs in pairs(policies[name]) do
	 if not contains(
	    {'description', 'import', 'after', 'before'}, attr
	 ) then
	    if type(objs) ~= 'table' then
	       raise('Invalid top-level attribute: '..attr..' ('..name..')')
	    end

	    util.setdefault(self.source, attr, {})

	    if not self.data[attr] then
	       self.data[attr] = objs
	       for k, v in pairs(objs) do self.source[attr][k] = name end

	    else
	       local fk = next(self.data[attr])
	       map(
		  keys(objs),
		  function(k)
		     if type(k) ~= type(fk) then
			raise(
			   'Type mismatch in '..attr..' definitions ('..
			      name..', '..self.source[attr][fk]..')'
			)
		     end
		  end
	       )

	       if objs[1] then
		  local last = #self.data[attr]
		  util.extend(self.data[attr], objs)
		  for i = 1,#objs do self.source[attr][last + i] = name end

	       else
		  for k, v in pairs(objs) do
		     self.data[attr][k] = v
		     self.source[attr][k] = name
		  end
	       end
	    end
	 end
      end
   end
end

function PolicyConfig:expand()

   local function expand(value)
      if type(value) == 'table' then return map(value, expand) end

      local visited = {}
      local pattern = '%$(%a[%w_]*)'
      
      while type(value) == 'string' do
	 local si, ei, name = value:find(pattern)
	 if not si then break end
	 
	 if contains(visited, name) then
	    raise('Circular variable definition: '..name)
	 end
	 table.insert(visited, name)
	 
	 local var = self.data.variable[name]
	 if var == nil then raise('Invalid variable reference: '..name) end
	 
	 if si == 1 and ei == value:len() then value = util.copy(var)
	 elseif contains({'number', 'string'}, type(var)) then
	    value = value:sub(1, si - 1)..var..value:sub(ei + 1, -1)
	 else
	    raise('Attempted to concatenate complex variable: '..name)
	 end
      end

      if value == '' then return end
      return value
   end

   return expand(self.data)
end


local Policy = class()

function Policy:init() self.enabled = self.type == 'mandatory' end

function Policy:load()
   local file = io.open(self.path)
   if not file then raise('Unable to read policy file '..self.path) end

   -- Lua 5.2 compatibility: prefix with *
   local data = file:read('*a')

   file:close()

   local success, res = pcall(self.decode, data)
   if success then return res end
   raise(res..' while parsing '..self.path)
end

function Policy:checkoptional()
   if self.type ~= 'optional' then
      raise('Not an optional policy: '..self.name)
   end
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
      json = { mod="cjson", func="decode" },
      yaml = { mod="lyaml", func="load" },
      toml = { mod="toml", func="parse" },
   }
   self.policies = {}

   for i, cls in ipairs{'private', 'optional', 'mandatory'} do
      for i, dir in ipairs(dirs[cls] or defdirs[cls]) do
	 for _, fname in ipairs(posix.dir(dir)) do
	    local si, ei, name, suff = fname:find('^([%w-]+)%.([jyt][sao][om][nl])$') -- json|yaml|toml

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
	    if not pol then
	       raise('Invalid policy reference from '..policy.name..': '..name)
	    end
	    require(pol)
	 end
      end
   end

   for name, policy in pairs(self.policies) do
      if policy.enabled then require(policy) end
   end

   return res
end

function PolicySet:active() return keys(self:_load()) end

function PolicySet:load() return PolicyConfig(self:_load()) end


return PolicySet
