--[[
Alpine Wall main module
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--

module(..., package.seeall)

require 'json'
require 'lfs'

require 'awall.iptables'
require 'awall.util'


local modules = {}

local testmode = arg[0] ~= '/usr/sbin/awall'

local modpath = testmode and '.' or '/usr/share/lua/5.1'
for line in io.popen('cd '..modpath..' && ls awall/model.lua awall/modules/*.lua'):lines() do
   local name = string.gsub(string.sub(line, 1, -5), '/', '.')
   require(name)
   table.insert(modules, package.loaded[name])
end


function translate()

   config = {}

   local confdirs = testmode and {'config'} or {'/usr/share/awall',
						'/etc/awall'}

   for i, dir in ipairs(confdirs) do
      for fname in lfs.dir(dir) do
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

   function insertrule(trule)
      local t = awall.iptables.config[trule.family][trule.table][trule.chain]
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
	    awall.util.map(config[path], cls.morph)
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

   awall.iptables.dump()

end
