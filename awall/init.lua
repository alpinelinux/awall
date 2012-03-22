--[[
Alpine Wall main module
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--

module(..., package.seeall)

require 'json'
require 'lfs'
require 'stringy'

require 'awall.ipset'
require 'awall.iptables'
require 'awall.model'
require 'awall.util'


confdirs = {'/usr/share/awall', '/etc/awall'}
iptdir = '/etc/iptables'
ipsfile = '/etc/ipset.d/awall'


local modules = {package.loaded['awall.model']}

function loadmodules(path)
   for modfile in lfs.dir((path or '/usr/share/lua/5.1')..'/awall/modules') do
      if stringy.endswith(modfile, '.lua') then
	 local name = 'awall.modules.'..string.sub(modfile, 1, -5)
	 require(name)
	 table.insert(modules, package.loaded[name])
      end
   end
end


local function readconfig()

   local config = {}
   local iptables = awall.iptables.new()
   local context = {input=config, iptables=iptables}

   for i, dir in ipairs(confdirs) do
      local fnames = {}
      for fname in lfs.dir(dir) do table.insert(fnames, fname) end
      table.sort(fnames)

      for i, fname in ipairs(fnames) do
	 if string.sub(fname, 1, 1) ~= '.' then
	    local data = ''
	    for line in io.lines(dir..'/'..fname) do data = data..line end
	    data = json.decode(data)
	    
	    for cls, objs in pairs(data) do
	       if not config[cls] then config[cls] = objs
	       elseif objs[1] then util.extend(config[cls], objs)
	       else
		  for k, v in pairs(objs) do config[cls][k] = v end
	       end
	    end
	 end
      end
   end


   function expandvars(obj)
      for k, v in pairs(obj) do
	 if type(v) == 'table' then
	    expandvars(v)

	 else
	    local visited = {}
	    local val = v

	    while type(val) == 'string' and string.sub(val, 1, 1) == '$' do
	       local name = string.sub(val, 2, -1)
		  
	       if util.contains(visited, name) then
		  error('Circular variable definition: '..name)
	       end
	       table.insert(visited, name)
		  
	       val = config.variable[name]
	       if not val then error('Invalid variable reference: '..name) end
	    end

	    obj[k] = val
	 end
      end
   end

   expandvars(config)


   function insertrule(trule)
      local t = iptables.config[trule.family][trule.table][trule.chain]
      if trule.position == 'prepend' then
	 table.insert(t, 1, trule.opts)
      else
	 table.insert(t, trule.opts)
      end
   end

   local locations = {}

   for i, mod in ipairs(modules) do
      for path, cls in pairs(mod.classmap) do
	 if config[path] then	    
	    awall.util.map(config[path],
			   function(obj) return cls.morph(obj, context) end)
	    table.insert(locations, config[path])
	 end
      end

      for i, rule in ipairs(mod.defrules) do insertrule(rule) end
   end


   for i, location in ipairs(locations) do
      for i, rule in ipairs(location) do
	 for i, trule in ipairs(rule:trules()) do insertrule(trule) end
      end
   end

   context.ipset = awall.ipset.new(config.ipset)

   return context
end

function dump()
   local context = readconfig()
   context.ipset:dump(ipsfile)
   context.iptables:dump(iptdir)
end

function test()
   local context = readconfig()
   context.ipset:create()
   context.iptables:test()
end
