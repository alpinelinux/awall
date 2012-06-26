--[[
Policy file handling for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--

module(..., package.seeall)

require 'json'
require 'lfs'
require 'lpc'

require 'awall.object'
require 'awall.util'

local object = awall.object
local util = awall.util


local PolicyConfig = object.class(object.Object)

function PolicyConfig:init(data)
   self.data = data
end

function PolicyConfig:eval(value)
   local visited = {}
   local pattern = '%$(%a[%w_]*)'
	 
   while type(value) == 'string' and string.find(value, pattern) do
      local si, ei, name = string.find(value, pattern)
	    
      if util.contains(visited, name) then
	 error('Circular variable definition: '..name)
      end
      table.insert(visited, name)
	    
      local var = self.data.variable[name]
      if not var then error('Invalid variable reference: '..name) end
	    
      if si == 1 and ei == string.len(value) then value = var
      elseif util.contains({'number', 'string'}, type(var)) then
	 value = string.sub(value, 1, si - 1)..var..string.sub(value, ei + 1, -1)
      else
	 error('Attempted to concatenate complex variable: '..name)
      end
   end
   
   return value ~= '' and value or nil
end

function PolicyConfig:variables()
   local res = {}
   for name, value in pairs(self.data.variable or {}) do
      res[name] = self:eval('$'..name)
   end
   return res
end

function PolicyConfig:expand()

   local function expand(obj)
      for k, v in pairs(obj) do
	 if type(v) == 'table' then expand(v)
	 else obj[k] = self:eval(v) end
      end
   end
   
   for k, v in pairs(self.data) do
      if k ~= 'variable' then expand(v) end
   end

   return self.data
end



local function open(name, dirs)
   if not string.match(name, '^[%w-]+$') then
      error('Invalid characters in policy name: '..name)
   end
   for i, dir in ipairs(dirs) do
      local path = dir..'/'..name..'.json'
      file = io.open(path)
      if file then return file, path end
   end
end

local function find(name, dirs)
   local file, path = open(name, dirs)
   if file then file:close() end
   return path
end

local function list(dirs)
   local allnames = {}
   local res = {}

   for i, dir in ipairs(dirs) do
      local names = {}
      local paths = {}

      for fname in lfs.dir(dir) do
	 local si, ei, name = string.find(fname, '^([%w-]+)%.json$')
	 if name then
	    if util.contains(allnames, name) then
	       error('Duplicate policy name: '..name)
	    end
	    table.insert(allnames, name)

	    table.insert(names, name)
	    paths[name] = dir..'/'..fname
	 end
      end

      table.sort(names)
      for i, name in ipairs(names) do
	 table.insert(res, {name, paths[name]})
      end
   end

   return res
end


PolicySet = object.class(object.Object)

function PolicySet:init(confdirs, importdirs)
   self.autodirs = confdirs or {'/usr/share/awall/mandatory', '/etc/awall'}
   self.confdir = self.autodirs[#self.autodirs]
   self.importdirs = importdirs or {'/usr/share/awall/optional'}
end


function PolicySet:loadJSON(name, fname)
   local file
   if fname then
      file = io.open(fname)
   else
      file, fname = open(name, self.importdirs)
   end
   if not file then error('Import failed: '..name) end

   local data = ''
   for line in file:lines() do data = data..line end
   file:close()

   local success, res = pcall(json.decode, data)
   if success then return res end
   error(res..' while parsing '..fname)
end


function PolicySet:load()
   
   local input = {}
   local required = {}
   local imported = {}

   local function import(name, fname)

      if util.contains(imported, name) then return end
      if util.contains(required, name) then
	 error('Circular import: '..name)
      end

      local data = self:loadJSON(name, fname)

      table.insert(required, name)
      for i, iname in util.listpairs(data.import) do import(iname) end
      table.insert(imported, name)
      
      for cls, objs in pairs(data) do
	 if not util.contains({'description', 'import'},
			      cls) then
	    if not input[cls] then input[cls] = objs
	    elseif objs[1] then util.extend(input[cls], objs)
	    else
	       for k, v in pairs(objs) do input[cls][k] = v end
	    end
	 end
      end
   end

   for i, pol in ipairs(list(self.autodirs)) do import(unpack(pol)) end

   return PolicyConfig.new(input), imported
end


function PolicySet:findsymlink(name)
   local symlink = find(name, {self.confdir})
   if symlink and lfs.symlinkattributes(symlink).mode ~= 'link' then
      error('Not an optional policy: '..name)
   end
   return symlink
end

function PolicySet:enable(name)
   if self:findsymlink(name) then error('Policy already enabled: '..name)
   else
      local target = find(name, self.importdirs)
      if not target then error('Policy not found: '..name) end
      if string.sub(target, 1, 1) ~= '/' then
	 target = lfs.currentdir()..'/'..target
      end

      local pid, stdin, stdout = lpc.run('ln', '-s', target, self.confdir)
      stdin:close()
      stdout:close()
      assert(lpc.wait(pid) == 0)
   end
end

function PolicySet:disable(name)
   local symlink = self:findsymlink(name)
   if not symlink then error('Policy not enabled: '..name) end
   assert(os.remove(symlink))
end

function PolicySet:list()
   local config, imported = self:load()
   local pols = list(self.importdirs)
   local i = 0

   return function()
	     i = i + 1
	     if i > #pols then return end
	     local name = pols[i][1]

	     local status
	     if self:findsymlink(name) then status = 'enabled'
	     elseif util.contains(imported, name) then status = 'required'
	     else status = 'disabled' end

	     return name, status, self:loadJSON(name, pols[i][2]).description
	  end
end
