--[[
Ipset file dumper for Alpine Wall
Copyright (C) 2012-2013 Kaarle Ritvanen
See LICENSE file for license details
]]--


module(..., package.seeall)

require 'awall.object'

IPSet = awall.object.class()

function IPSet:init(config) self.config = config or {} end

function IPSet:dumpfile(name, ipsfile)
   ipsfile:write('# ipset '..name..'\n')
   ipsfile:write(table.concat(self.config[name].options, ' '))
   ipsfile:write('\n')
end

function IPSet:create()
   for name, ipset in pairs(self.config) do
      local pid = lpc.run('ipset', '-!', 'create', name,
			  unpack(ipset.options))
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
