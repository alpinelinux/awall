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
require 'awall.object'
require 'awall.util'


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


Config = awall.object.class(awall.object.Object)

function Config:init(confdirs)

   self.input = {}
   self.iptables = awall.iptables.new()

   for i, dir in ipairs(confdirs or {'/usr/share/awall', '/etc/awall'}) do
      local fnames = {}
      for fname in lfs.dir(dir) do table.insert(fnames, fname) end
      table.sort(fnames)

      for i, fname in ipairs(fnames) do
	 if string.sub(fname, 1, 1) ~= '.' then
	    local data = ''
	    for line in io.lines(dir..'/'..fname) do data = data..line end
	    data = json.decode(data)
	    
	    for cls, objs in pairs(data) do
	       if not self.input[cls] then self.input[cls] = objs
	       elseif objs[1] then util.extend(self.input[cls], objs)
	       else
		  for k, v in pairs(objs) do self.input[cls][k] = v end
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
		  
	       val = self.input.variable[name]
	       if not val then error('Invalid variable reference: '..name) end
	    end

	    obj[k] = val
	 end
      end
   end

   expandvars(self.input)


   function insertrule(trule)
      local t = self.iptables.config[trule.family][trule.table][trule.chain]
      if trule.position == 'prepend' then
	 table.insert(t, 1, trule.opts)
      else
	 table.insert(t, trule.opts)
      end
   end

   local locations = {}

   for i, mod in ipairs(modules) do
      for path, cls in pairs(mod.classmap) do
	 if self.input[path] then	    
	    awall.util.map(self.input[path],
			   function(obj) return cls.morph(obj, self) end)
	    table.insert(locations, self.input[path])
	 end
      end

      for i, rule in ipairs(mod.defrules) do insertrule(rule) end
   end


   for i, location in ipairs(locations) do
      for i, rule in ipairs(location) do
	 for i, trule in ipairs(rule:trules()) do insertrule(trule) end
      end
   end

   self.ipset = awall.ipset.new(self.input.ipset)
end

function Config:dump(iptdir, ipsfile)
   self.ipset:dump(ipsfile or '/etc/ipset.d/awall')
   self.iptables:dump(iptdir or '/etc/iptables')
end

function Config:test()
   self.ipset:create()
   self.iptables:test()
end
