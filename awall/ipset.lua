--[[
Ipset file dumper for Alpine Wall
Copyright (C) 2012 Kaarle Ritvanen
Licensed under the terms of GPL2
]]--


module(..., package.seeall)

require 'awall.object'

IPSet = awall.object.class(awall.object.Object)

function IPSet:init(config) self.config = config or {} end

function IPSet:options(name)
   local ipset = self.config[name]
   if not ipset.type then ipset:error('Type not defined') end
   if not ipset.family then ipset:error('Family not defined') end
   return {ipset.type, 'family', ipset.family}
end

function IPSet:dumpfile(name, ipsfile)
   ipsfile:write('# ipset '..name..'\n')
   ipsfile:write(table.concat(self:options(name), ' '))
   ipsfile:write('\n')
end

function IPSet:create()
   for name, ipset in pairs(self.config) do
      local pid = lpc.run('ipset', '-!', 'create', name,
			  unpack(self:options(name)))
      if lpc.wait(pid) ~= 0 then
	 io.stderr:write('ipset creation failed: '..name)
      end
   end
end

function IPSet:print()
   for name, ipset in pairs(self.config) do
      self:dumpfile(name, io.stdout)
      io.stdout:write('\n')
   end
end

function IPSet:dump(ipsdir)
   for name, ipset in pairs(self.config) do
      local fname = ipsdir..'/'..name
      local file = io.open(fname)
      if not file then
	 file = io.open(fname, 'w')
	 self:dumpfile(name, file)
      end
      file:close()
   end
end
