--[[
Policy file handling for Alpine Wall
Copyright (C) 2012-2014 Kaarle Ritvanen
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


local json = require('cjson')
local posix = require('posix')


local PolicyConfig = class()

function PolicyConfig:init(data, source, policies)
   self.data = data
   self.source = source
   self.policies = policies
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
	 
	 if si == 1 and ei == value:len() then value = var
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
   local data = file:read('*all')
   file:close()

   local success, res = pcall(json.decode, data)
   if success then return res end
   raise(res..' while parsing '..self.path)
end

function Policy:checkoptional()
   if self.type ~= 'optional' then raise('Not an optional policy: '..name) end
end

function Policy:enable()
   self:checkoptional()
   if self.enabled then raise('Policy already enabled: '..self.name) end   
   assert(posix.link(self.path, self.confdir..'/'..self.fname, true))
end

function Policy:disable()
   self:checkoptional()
   if not self.enabled then raise('Policy already disabled: '..self.name) end
   assert(os.remove(self.confdir..'/'..self.fname))
end


local defdirs = {
   mandatory={'/etc/awall', '/usr/share/awall/mandatory'},
   optional={'/etc/awall/optional', '/usr/share/awall/optional'},
   private={'/etc/awall/private', '/usr/share/awall/private'}
}

local PolicySet = class()

function PolicySet:init(dirs)
   local confdir = (dirs.mandatory or defdirs.mandatory)[1]
   self.policies = {}

   for i, cls in ipairs{'private', 'optional', 'mandatory'} do
      for i, dir in ipairs(dirs[cls] or defdirs[cls]) do
	 for _, fname in ipairs(posix.dir(dir)) do
	    local si, ei, name = fname:find('^([%w-]+)%.json$')
	    if name then
	       local pol = self.policies[name]

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
		     confdir=confdir
		  }
	       end
	    end
	 end
      end
   end
end


function PolicySet:load()

   local imported = {['%defaults']={}}
   
   local function require(policy)
      if imported[policy.name] then return end

      local data = policy:load()
      imported[policy.name] = data

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

      for i, name in listpairs(data.import) do
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


   local order = resolve(imported)
   if type(order) ~= 'table' then
      raise('Circular ordering directives: '..order)
   end


   local input = {}
   local source = {}

   for i, name in ipairs(order) do
      for cls, objs in pairs(imported[name]) do
	 if not contains(
	    {'description', 'import', 'after', 'before'},
	    cls
	 ) then
	    if type(objs) ~= 'table' then
	       raise('Invalid top-level attribute: '..cls..' ('..name..')')
	    end

	    util.setdefault(source, cls, {})

	    if not input[cls] then
	       input[cls] = objs
	       for k, v in pairs(objs) do source[cls][k] = name end

	    else
	       local fk = next(input[cls])
	       map(
		  keys(objs),
		  function(k)
		     if type(k) ~= type(fk) then
			raise(
			   'Type mismatch in '..cls..' definitions ('..
			      name..', '..source[cls][fk]..')'
			)
		     end
		  end
	       )

	       if objs[1] then
		  local last = #input[cls]
		  util.extend(input[cls], objs)
		  for i = 1,#objs do source[cls][last + i] = name end

	       else
		  for k, v in pairs(objs) do
		     input[cls][k] = v
		     source[cls][k] = name
		  end
	       end
	    end
	 end
      end
   end

   return PolicyConfig(input, source, keys(imported))
end

return PolicySet
